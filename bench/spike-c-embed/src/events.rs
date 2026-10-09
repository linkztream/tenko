//! Live updates: a broadcast hub with a replay ring, and two SSE endpoints.
//!
//! Design:
//! - Each published event is encoded once into its SSE wire frame (`Bytes`). Fan-out to
//!   N clients is N refcount increments plus N socket writes; nothing is formatted per
//!   client.
//! - `tokio::sync::broadcast` carries `Arc<EventRecord>`. A slow client that falls more
//!   than `channel_capacity` events behind gets `Lagged`; it is sent a `reset` event
//!   (refetch state) instead of being buffered without bound.
//! - The last `ring_capacity` events are kept for `Last-Event-ID` replay. Subscribing and
//!   taking the replay snapshot happen under the same lock that publishing holds while it
//!   appends and sends, so a reconnecting client sees no gap and no duplicate.
//! - Event ids start at the boot time in microseconds since the Unix epoch, so ids keep
//!   increasing across restarts and an id from a previous process is detected as a gap
//!   instead of being misread as a recent event.
//! - Keep-alive comments come from one timer task that broadcasts a shared frame, not from
//!   a timer per connection.
//! - Shutdown is a broadcast message: every stream sends a `shutdown` event and ends, which
//!   lets the HTTP server's graceful shutdown complete.
//! - Optional coalescing (`--coalesce-ms`): events are queued and one flusher task
//!   broadcasts everything published within a tick as one `Batch`, so the per-client cost
//!   (one wake-up and one socket write) is paid per tick instead of per event.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use bytes::{Bytes, BytesMut};
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::broadcast::{self, error::RecvError};

const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

const HELLO: &[u8] = b"retry: 3000\n: connected\n\n";
const KEEPALIVE_FRAME: Bytes = Bytes::from_static(b": keep-alive\n\n");
const SHUTDOWN_FRAME: Bytes = Bytes::from_static(b"event: shutdown\ndata: {}\n\n");
const RESET_GAP: &[u8] = b"event: reset\ndata: {\"reason\":\"gap\"}\n\n";
const RESET_LAGGED: Bytes = Bytes::from_static(b"event: reset\ndata: {\"reason\":\"lagged\"}\n\n");

/// One published event.
pub struct EventRecord {
    pub id: u64,
    pub name: Box<str>,
    /// Compact JSON, guaranteed to be a single line.
    pub data: Box<str>,
    /// The complete SSE frame: `id: ..\nevent: ..\ndata: ..\n\n`.
    pub frame: Bytes,
}

/// Events published within one coalescing tick, sent to every client as one write.
pub struct Batch {
    /// The frames of all `records`, concatenated.
    pub frame: Bytes,
    pub records: Vec<Arc<EventRecord>>,
}

#[derive(Clone)]
pub enum Msg {
    Event(Arc<EventRecord>),
    Batch(Arc<Batch>),
    KeepAlive,
    Shutdown,
}

struct Ring {
    events: VecDeque<Arc<EventRecord>>,
    capacity: usize,
    next_id: u64,
    /// Highest id that has been handed to the broadcast channel. Replay never goes past
    /// it, so an event waiting in `pending` is delivered exactly once, by the next flush.
    sent_upto: u64,
    /// Coalescing mode only: events published since the last flush.
    pending: Vec<Arc<EventRecord>>,
}

/// What a new subscriber must be sent before live events.
pub enum Replay {
    /// No `Last-Event-ID`, or the client is up to date.
    Nothing,
    /// Events newer than the client's `Last-Event-ID`, oldest first.
    Events(Vec<Arc<EventRecord>>),
    /// The id is unknown or too old for the ring: the client must refetch its state.
    Reset,
}

pub struct Hub {
    tx: broadcast::Sender<Msg>,
    ring: Mutex<Ring>,
    shutting_down: AtomicBool,
    /// When set, `publish` only queues; a flusher task broadcasts one `Batch` per tick.
    coalesce: bool,
}

impl Hub {
    #[cfg(test)]
    pub fn new(channel_capacity: usize, ring_capacity: usize) -> Arc<Self> {
        Self::with_coalescing(channel_capacity, ring_capacity, false)
    }

    /// `coalesce = true` requires [`Hub::spawn_flusher`].
    pub fn with_coalescing(
        channel_capacity: usize,
        ring_capacity: usize,
        coalesce: bool,
    ) -> Arc<Self> {
        let (tx, _) = broadcast::channel(channel_capacity);
        let boot_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX / 2));
        Arc::new(Self {
            tx,
            ring: Mutex::new(Ring {
                events: VecDeque::with_capacity(ring_capacity),
                capacity: ring_capacity.max(1),
                next_id: boot_micros,
                sent_upto: boot_micros - 1,
                pending: Vec::new(),
            }),
            shutting_down: AtomicBool::new(false),
            coalesce,
        })
    }

    /// Publishes an event. `data` must be single-line JSON. Returns the id and the number
    /// of subscribers it was (or, when coalescing, will be) handed to.
    pub fn publish(&self, name: &str, data: String) -> (u64, usize) {
        let mut ring = self.ring.lock().expect("ring lock");
        let id = ring.next_id;
        ring.next_id += 1;
        let mut frame = BytesMut::with_capacity(32 + name.len() + data.len());
        frame.extend_from_slice(b"id: ");
        frame.extend_from_slice(id.to_string().as_bytes());
        frame.extend_from_slice(b"\nevent: ");
        frame.extend_from_slice(name.as_bytes());
        frame.extend_from_slice(b"\ndata: ");
        frame.extend_from_slice(data.as_bytes());
        frame.extend_from_slice(b"\n\n");
        let record = Arc::new(EventRecord {
            id,
            name: name.into(),
            data: data.into(),
            frame: frame.freeze(),
        });
        if ring.events.len() == ring.capacity {
            ring.events.pop_front();
        }
        ring.events.push_back(Arc::clone(&record));
        if self.coalesce {
            ring.pending.push(record);
            return (id, self.tx.receiver_count());
        }
        ring.sent_upto = id;
        let receivers = self.tx.send(Msg::Event(record)).unwrap_or(0);
        drop(ring);
        (id, receivers)
    }

    /// Coalescing mode: broadcasts everything published since the last flush as one batch.
    pub fn flush(&self) {
        let mut ring = self.ring.lock().expect("ring lock");
        let Some(last) = ring.pending.last().map(|r| r.id) else {
            return;
        };
        let records = std::mem::take(&mut ring.pending);
        let mut frame = BytesMut::with_capacity(records.iter().map(|r| r.frame.len()).sum());
        for r in &records {
            frame.extend_from_slice(&r.frame);
        }
        ring.sent_upto = last;
        let _ = self.tx.send(Msg::Batch(Arc::new(Batch {
            frame: frame.freeze(),
            records,
        })));
    }

    /// Spawns the coalescing flusher (one timer for all clients).
    pub fn spawn_flusher(self: &Arc<Self>, period: Duration) {
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while !hub.is_shutting_down() {
                tick.tick().await;
                hub.flush();
            }
        });
    }

    /// Subscribes to live events and computes the replay for `last_event_id` atomically
    /// with respect to `publish`.
    pub fn subscribe(&self, last_event_id: Option<&str>) -> (broadcast::Receiver<Msg>, Replay) {
        let ring = self.ring.lock().expect("ring lock");
        let rx = self.tx.subscribe();
        let replay = match last_event_id {
            None => Replay::Nothing,
            Some(raw) => match raw.trim().parse::<u64>() {
                Err(_) => Replay::Reset,
                Ok(last) => {
                    // Events after `sent_upto` are still pending and reach this receiver
                    // through the next flush.
                    let newest = ring.sent_upto;
                    if last == newest {
                        Replay::Nothing
                    } else if last > newest {
                        Replay::Reset
                    } else {
                        match ring.events.front() {
                            Some(oldest) if last + 1 >= oldest.id => {
                                let skip =
                                    usize::try_from(last + 1 - oldest.id).unwrap_or(usize::MAX);
                                Replay::Events(
                                    ring.events
                                        .iter()
                                        .skip(skip)
                                        .take_while(|e| e.id <= newest)
                                        .cloned()
                                        .collect(),
                                )
                            }
                            _ => Replay::Reset,
                        }
                    }
                }
            },
        };
        drop(ring);
        (rx, replay)
    }

    pub fn keepalive(&self) {
        let _ = self.tx.send(Msg::KeepAlive);
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.flush();
        let _ = self.tx.send(Msg::Shutdown);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Spawns the single keep-alive timer.
    pub fn spawn_keepalive(self: &Arc<Self>, period: Duration) {
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                if hub.is_shutting_down() {
                    break;
                }
                hub.keepalive();
            }
        });
    }
}

fn last_event_id(headers: &HeaderMap) -> Option<&str> {
    headers.get(LAST_EVENT_ID).map(|v| v.to_str().unwrap_or(""))
}

fn unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "shutting down\n").into_response()
}

/// `GET /api/events`: SSE with frames pre-encoded at publish time.
pub async fn events_raw(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if hub.is_shutting_down() {
        return unavailable();
    }
    let (rx, replay) = hub.subscribe(last_event_id(&headers));
    let mut first = BytesMut::from(HELLO);
    match replay {
        Replay::Nothing => {}
        Replay::Reset => first.extend_from_slice(RESET_GAP),
        Replay::Events(events) => {
            for e in events {
                first.extend_from_slice(&e.frame);
            }
        }
    }
    // State: (first chunk not yet sent, receiver, finished).
    let stream = stream::unfold(
        (Some(first.freeze()), rx, false),
        |(first, mut rx, done)| async move {
            if let Some(chunk) = first {
                return Some((Ok::<_, Infallible>(chunk), (None, rx, done)));
            }
            if done {
                return None;
            }
            let chunk = match rx.recv().await {
                Ok(Msg::Event(e)) => e.frame.clone(),
                Ok(Msg::Batch(b)) => b.frame.clone(),
                Ok(Msg::KeepAlive) => KEEPALIVE_FRAME,
                Ok(Msg::Shutdown) => return Some((Ok(SHUTDOWN_FRAME), (None, rx, true))),
                Err(RecvError::Lagged(_)) => RESET_LAGGED,
                Err(RecvError::Closed) => return None,
            };
            Some((Ok(chunk), (None, rx, false)))
        },
    );
    let mut res = Response::new(Body::from_stream(stream));
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    res
}

fn to_axum_event(e: &EventRecord) -> Event {
    Event::default()
        .id(e.id.to_string())
        .event(&*e.name)
        .data(&*e.data)
}

/// `GET /api/events/axum`: the same semantics with axum's `Sse` response type and its
/// per-connection `KeepAlive` timer. Kept for comparison: every event is formatted once
/// per client.
pub async fn events_axum(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if hub.is_shutting_down() {
        return unavailable();
    }
    let (rx, replay) = hub.subscribe(last_event_id(&headers));
    let mut first: VecDeque<Event> = VecDeque::new();
    first.push_back(
        Event::default()
            .retry(Duration::from_secs(3))
            .comment("connected"),
    );
    match replay {
        Replay::Nothing => {}
        Replay::Reset => {
            first.push_back(Event::default().event("reset").data("{\"reason\":\"gap\"}"))
        }
        Replay::Events(events) => first.extend(events.iter().map(|e| to_axum_event(e))),
    }
    let stream = stream::unfold((first, rx, false), |(mut first, mut rx, done)| async move {
        if let Some(ev) = first.pop_front() {
            return Some((Ok::<_, Infallible>(ev), (first, rx, done)));
        }
        if done {
            return None;
        }
        loop {
            let ev = match rx.recv().await {
                Ok(Msg::Event(e)) => to_axum_event(&e),
                Ok(Msg::Batch(b)) => {
                    first.extend(b.records.iter().map(|e| to_axum_event(e)));
                    match first.pop_front() {
                        Some(ev) => ev,
                        None => continue,
                    }
                }
                Ok(Msg::KeepAlive) => continue,
                Ok(Msg::Shutdown) => {
                    return Some((
                        Ok(Event::default().event("shutdown").data("{}")),
                        (first, rx, true),
                    ));
                }
                Err(RecvError::Lagged(_)) => Event::default()
                    .event("reset")
                    .data("{\"reason\":\"lagged\"}"),
                Err(RecvError::Closed) => return None,
            };
            return Some((Ok(ev), (first, rx, false)));
        }
    });
    let sse = Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    );
    let mut res = sse.into_response();
    res.headers_mut()
        .insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    res
}

fn default_event_name() -> String {
    "message".to_owned()
}

#[derive(Deserialize)]
pub struct EmitBody {
    #[serde(default = "default_event_name")]
    event: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// An event name is 1..=64 characters of `[A-Za-z0-9._:-]`, so it can never break the
/// line-based SSE framing.
fn valid_event_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// `POST /api/events/emit` (test hook): broadcasts `{"event": .., "data": ..}`.
pub async fn emit(State(hub): State<Arc<Hub>>, Json(body): Json<EmitBody>) -> Response {
    if !valid_event_name(&body.event) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid event name"})),
        )
            .into_response();
    }
    // serde_json's compact writer escapes control characters, so the output is one line.
    let data = serde_json::to_string(&body.data).unwrap_or_else(|_| "null".to_owned());
    let (id, receivers) = hub.publish(&body.event, data);
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"id": id, "receivers": receivers})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(r: &Replay) -> Vec<u64> {
        match r {
            Replay::Events(v) => v.iter().map(|e| e.id).collect(),
            Replay::Nothing => vec![],
            Replay::Reset => vec![u64::MAX],
        }
    }

    #[test]
    fn replay_window() {
        let hub = Hub::new(16, 4);
        let first = hub.publish("t", "1".into()).0;
        for i in 2..=6 {
            hub.publish("t", i.to_string());
        }
        // Ring holds first+2 ..= first+5.
        let (_, r) = hub.subscribe(None);
        assert!(matches!(r, Replay::Nothing));
        let (_, r) = hub.subscribe(Some(&(first + 5).to_string()));
        assert!(matches!(r, Replay::Nothing));
        let (_, r) = hub.subscribe(Some(&(first + 3).to_string()));
        assert_eq!(ids(&r), vec![first + 4, first + 5]);
        let (_, r) = hub.subscribe(Some(&(first + 1).to_string()));
        assert_eq!(ids(&r), vec![first + 2, first + 3, first + 4, first + 5]);
        let (_, r) = hub.subscribe(Some(&first.to_string()));
        assert!(matches!(r, Replay::Reset), "older than the ring");
        let (_, r) = hub.subscribe(Some(&(first + 99).to_string()));
        assert!(matches!(r, Replay::Reset), "id from the future");
        let (_, r) = hub.subscribe(Some("garbage"));
        assert!(matches!(r, Replay::Reset));
    }

    #[test]
    fn coalescing() {
        let hub = Hub::with_coalescing(16, 8, true);
        let (mut rx, _) = hub.subscribe(None);
        let a = hub.publish("t", "1".into()).0;
        let b = hub.publish("t", "2".into()).0;
        assert!(rx.try_recv().is_err(), "nothing is sent before the flush");
        // A client that saw `a` cannot exist yet: `a` was never sent.
        let (_, r) = hub.subscribe(Some(&a.to_string()));
        assert!(matches!(r, Replay::Reset));
        let (mut late, r) = hub.subscribe(Some(&(a - 1).to_string()));
        assert!(
            matches!(r, Replay::Nothing),
            "pending events come with the flush, not the replay"
        );
        hub.flush();
        for rx in [&mut rx, &mut late] {
            let Ok(Msg::Batch(batch)) = rx.try_recv() else {
                panic!("expected a batch")
            };
            assert_eq!(
                batch.records.iter().map(|r| r.id).collect::<Vec<_>>(),
                vec![a, b]
            );
            assert_eq!(
                &batch.frame[..],
                format!("id: {a}\nevent: t\ndata: 1\n\nid: {b}\nevent: t\ndata: 2\n\n").as_bytes()
            );
        }
        let (_, r) = hub.subscribe(Some(&a.to_string()));
        assert_eq!(ids(&r), vec![b]);
        hub.flush();
        assert!(rx.try_recv().is_err(), "an empty flush sends nothing");
    }

    #[test]
    fn frame_format() {
        let hub = Hub::new(16, 4);
        let (mut rx, _) = hub.subscribe(None);
        let (id, n) = hub.publish("lease.updated", "{\"a\":1}".into());
        assert_eq!(n, 1);
        let Ok(Msg::Event(e)) = rx.try_recv() else {
            panic!("expected event")
        };
        assert_eq!(
            &e.frame[..],
            format!("id: {id}\nevent: lease.updated\ndata: {{\"a\":1}}\n\n").as_bytes()
        );
    }

    #[test]
    fn event_names() {
        assert!(valid_event_name("lease.updated"));
        assert!(valid_event_name("dns:zone-1_x"));
        assert!(!valid_event_name(""));
        assert!(!valid_event_name("a\nb"));
        assert!(!valid_event_name("a b"));
        assert!(!valid_event_name(&"x".repeat(65)));
    }
}
