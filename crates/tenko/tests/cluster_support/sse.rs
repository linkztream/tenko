//! An event-stream reader that behaves like the web UI's `EventStream`
//! (`ui/src/api/events.ts`): it reads `GET /api/v1/events?topics=...` with the session of
//! the lab, records every event with its id (a store revision), and when the stream ends
//! or the controller goes away it connects again, to the next controller of its list, with
//! `Last-Event-ID` set to the last id it saw, so the server replays what it missed or sends
//! a `reset`.

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::Value;

use super::lab::ClusterLab;

/// One event as the reader received it.
#[derive(Debug, Clone)]
pub struct SseRecord {
    /// The event name: the topic, `reset` or `shutdown`.
    pub event: String,
    /// The event id, a store revision for store events.
    pub id: Option<String>,
    /// The data as JSON (`null` when it is not JSON).
    pub data: Value,
    /// The controller it came from.
    pub via: String,
    /// When it arrived.
    pub at: Instant,
}

#[derive(Default)]
struct Shared {
    events: Mutex<Vec<SseRecord>>,
    connections: Mutex<Vec<String>>,
    stopping: AtomicBool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running reader; it stops when dropped.
pub struct SseClient {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl ClusterLab {
    /// An event-stream reader for `topics` (comma-separated) that starts on controller
    /// `id` and moves on to the other controllers of the lab in turn when its stream
    /// breaks.
    pub fn sse_client(&self, id: u64, topics: &str) -> SseClient {
        let first = self.url(id);
        let mut bases = vec![first.clone()];
        bases.extend(self.urls().into_iter().filter(|url| *url != first));
        let shared = Arc::new(Shared::default());
        let task = self.http().runtime().spawn(read(
            self.http().client().clone(),
            bases,
            self.cookie().to_owned(),
            topics.to_owned(),
            Arc::clone(&shared),
        ));
        SseClient { shared, task }
    }
}

impl SseClient {
    /// Every event so far.
    pub fn events(&self) -> Vec<SseRecord> {
        lock(&self.shared.events).clone()
    }

    /// The numeric ids of the events so far.
    pub fn ids(&self) -> BTreeSet<u64> {
        lock(&self.shared.events)
            .iter()
            .filter_map(|event| event.id.as_deref()?.parse().ok())
            .collect()
    }

    /// The number of `reset` events so far.
    pub fn resets(&self) -> usize {
        lock(&self.shared.events)
            .iter()
            .filter(|event| event.event == "reset")
            .count()
    }

    /// The controllers the reader connected to, in order (one entry per connection).
    pub fn connections(&self) -> Vec<String> {
        lock(&self.shared.connections).clone()
    }

    /// Waits until `check` accepts the events so far; the lab's diagnostics on a timeout.
    #[track_caller]
    pub fn wait_for(
        &self,
        lab: &ClusterLab,
        what: &str,
        limit: Duration,
        check: impl Fn(&[SseRecord]) -> bool,
    ) {
        lab.wait_for(what, limit, || check(&lock(&self.shared.events)));
    }
}

impl Drop for SseClient {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        self.task.abort();
    }
}

async fn read(
    client: reqwest::Client,
    bases: Vec<String>,
    cookie: String,
    topics: String,
    shared: Arc<Shared>,
) {
    let mut last: Option<String> = None;
    let mut attempt = 0_usize;
    while !shared.stopping.load(Ordering::SeqCst) {
        let base = &bases[attempt % bases.len()];
        let mut request = client
            .get(format!("{base}/api/v1/events?topics={topics}"))
            .header("Cookie", &cookie)
            .timeout(Duration::from_secs(3600));
        if let Some(id) = &last {
            request = request.header("Last-Event-ID", id);
        }
        if let Ok(mut response) = request.send().await
            && response.status().as_u16() == 200
        {
            lock(&shared.connections).push(base.clone());
            let mut buffer = String::new();
            while let Ok(Some(bytes)) = response.chunk().await {
                buffer.push_str(&String::from_utf8_lossy(&bytes).replace("\r\n", "\n"));
                while let Some(record) = take_event(&mut buffer, base) {
                    if let Some(id) = &record.id {
                        last = Some(id.clone());
                    }
                    lock(&shared.events).push(record);
                }
            }
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Parses one complete event out of the buffer; comments are skipped.
fn take_event(buffer: &mut String, via: &str) -> Option<SseRecord> {
    loop {
        let end = buffer.find("\n\n")?;
        let block: String = buffer[..end].to_owned();
        buffer.drain(..end + 2);
        let mut event = String::new();
        let mut id = None;
        let mut data = Vec::new();
        let mut any = false;
        for line in block.lines() {
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            any = true;
            match field {
                "event" => value.clone_into(&mut event),
                "id" => id = Some(value.to_owned()),
                "data" => data.push(value.to_owned()),
                _ => {}
            }
        }
        if any {
            if event.is_empty() {
                "message".clone_into(&mut event);
            }
            let data = data.join("\n");
            return Some(SseRecord {
                event,
                id,
                data: serde_json::from_str(&data).unwrap_or(Value::Null),
                via: via.to_owned(),
                at: Instant::now(),
            });
        }
    }
}
