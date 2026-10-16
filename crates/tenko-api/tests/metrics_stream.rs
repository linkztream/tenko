//! The acceptance of the `metrics` topic (WP3.5, OPS-20): 100 event streams on the topic
//! against a running server receive one snapshot per second each, from one aggregation per
//! second, over a window of about five seconds. The aggregations are counted against the
//! time that passed between the two readings of the counters, not against the nominal
//! window: under the load of a full parallel test run the window stretches (on Windows the
//! CPU reading alone starts a PowerShell process), and the claim is a rate. The CPU time of
//! the process is measured and printed (not asserted): once with 100 streams on another
//! topic, the publisher asleep, and once with 100 streams on `metrics`. Run with
//! `--no-capture` to read it.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_api::{
    ServerConfig,
    sse::metrics::{MetricsPublisher, NoSources, Sampler},
    state::AppState,
};
use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService, TrustedProxies};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time::timeout,
};

const STREAMS: usize = 100;
const WINDOW: Duration = Duration::from_secs(5);
const WAIT: Duration = Duration::from_secs(20);

/// Plain HTTP from every source (Lab) without rate limits: 100 streams from one address.
fn lab_config() -> ServerConfig {
    let mode = TlsMode::ReverseProxy {
        trusted_proxies: "192.0.2.1".parse::<TrustedProxies>().expect("proxies"),
        proxy_protocol: false,
        public_host: "ddi.example.test".to_owned(),
    };
    let tls = TlsService::new(mode, TlsPolicy::default()).expect("tls service");
    let mut config = ServerConfig::new(
        vec!["127.0.0.1:0".parse().expect("addr")],
        tls,
        TlsPolicy::default(),
    );
    config.lab_plain_http = true;
    config.http.rate_limit.enabled = false;
    config
}

/// A stream reader: counts the `metrics` events it receives until the task is aborted.
struct Reader {
    events: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

async fn open(addr: SocketAddr, topics: &str) -> Reader {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "GET /api/v1/events?topics={topics} HTTP/1.1\r\nHost: ddi.example.test\r\nAccept: text/event-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut head = Vec::new();
    timeout(WAIT, async {
        while !head.windows(13).any(|window| window == b": connected\n\n") {
            let mut chunk = [0_u8; 4096];
            let n = stream.read(&mut chunk).await.expect("read");
            assert!(n > 0, "closed: {}", String::from_utf8_lossy(&head));
            head.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("the stream opens");
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    let events = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&events);
    let task = tokio::spawn(async move {
        const NEEDLE: &[u8] = b"event: metrics\n";
        let mut carry: Vec<u8> = Vec::new();
        let mut chunk = vec![0_u8; 64 * 1024];
        loop {
            let Ok(n) = stream.read(&mut chunk).await else {
                return;
            };
            if n == 0 {
                return;
            }
            carry.extend_from_slice(&chunk[..n]);
            let found = carry
                .windows(NEEDLE.len())
                .filter(|window| *window == NEEDLE)
                .count();
            counted.fetch_add(found as u64, Ordering::Relaxed);
            // Keep a tail shorter than the needle, so no event is counted twice.
            let keep = carry.len().min(NEEDLE.len() - 1);
            carry.drain(..carry.len() - keep);
        }
    });
    Reader { events, task }
}

/// The CPU time of this process in milliseconds, user and system: from `/proc/self/stat`
/// on Linux, from PowerShell on Windows; `None` elsewhere.
fn cpu_ms() -> Option<f64> {
    if cfg!(target_os = "linux") {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        let ticks: f64 =
            fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
        // USER_HZ is 100 on every Linux the product supports.
        Some(ticks * 10.0)
    } else if cfg!(windows) {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-Process -Id {}).TotalProcessorTime.TotalMilliseconds",
                    std::process::id()
                ),
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .replace(',', ".")
            .parse()
            .ok()
    } else {
        None
    }
}

/// Opens [`STREAMS`] streams on `topics`.
async fn open_all(addr: SocketAddr, topics: &str) -> Vec<Reader> {
    let mut readers = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        readers.push(open(addr, topics).await);
    }
    readers
}

/// Waits [`WINDOW`]; returns the CPU time of the process over it, if measured, and its
/// length.
async fn measure() -> (Option<f64>, Duration) {
    let before = cpu_ms();
    let started = Instant::now();
    tokio::time::sleep(WINDOW).await;
    let elapsed = started.elapsed();
    let after = cpu_ms();
    (before.zip(after).map(|(a, b)| b - a), elapsed)
}

/// The whole seconds an interval of `elapsed` can hold ticks of one second at: from one
/// fewer than its whole seconds to one more than its rounded-up seconds, because the first
/// and the last tick may fall just inside or just outside it. For a window of 5.0 s that is
/// 4 to 6, the bounds of a run on an idle machine.
fn ticks_in(elapsed: Duration) -> std::ops::RangeInclusive<u64> {
    let seconds = elapsed.as_secs_f64();
    // Whole seconds of a test window: far below the range where the casts lose anything.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (low, high) = (seconds.floor() as u64, seconds.ceil() as u64);
    low.saturating_sub(1)..=high + 1
}

fn counts(readers: &[Reader]) -> Vec<u64> {
    readers
        .iter()
        .map(|reader| reader.events.load(Ordering::Relaxed))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hundred_streams_get_one_snapshot_per_second_from_one_aggregation() {
    let state = AppState::default();
    let server = tenko_api::start(lab_config(), state.clone())
        .await
        .expect("server starts");
    let addr = server.local_addrs()[0];
    let sampler = Sampler::new(state.clone(), Arc::new(NoSources));
    let publisher = Arc::new(MetricsPublisher::new(&state, sampler, None));
    let (stop_tx, stop) = watch::channel(false);
    let task = Arc::clone(&publisher).spawn(stop);

    // 100 streams on another topic: the publisher sleeps.
    let idle = open_all(addr, "jobs").await;
    let (idle_cpu, _) = measure().await;
    assert_eq!(publisher.ticks(), 0, "nobody listens to the metrics");
    assert_eq!(publisher.sampler().taken(), 0);
    for reader in idle {
        reader.task.abort();
    }

    // 100 streams on the topic: once each has its first snapshot, count over the window.
    let readers = open_all(addr, "metrics").await;
    timeout(WAIT, async {
        while counts(&readers).contains(&0) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every stream gets a first snapshot");
    // The counters are read at the two ends of `elapsed`, with the CPU readings outside it.
    let cpu_before = cpu_ms();
    let started = Instant::now();
    let (ticks_before, taken_before) = (publisher.ticks(), publisher.sampler().taken());
    let events_before = counts(&readers);
    tokio::time::sleep(WINDOW).await;
    let ticks = publisher.ticks() - ticks_before;
    let taken = publisher.sampler().taken() - taken_before;
    let per_stream: Vec<u64> = counts(&readers)
        .iter()
        .zip(&events_before)
        .map(|(after, before)| after - before)
        .collect();
    let elapsed = started.elapsed();
    let busy_cpu = cpu_before.zip(cpu_ms()).map(|(a, b)| b - a);
    let seconds = elapsed.as_secs_f64();
    let min = per_stream.iter().min().copied().unwrap_or_default();
    let max = per_stream.iter().max().copied().unwrap_or_default();
    println!(
        "metrics acceptance: {STREAMS} streams over {seconds:.2} s: {ticks} aggregations, {taken} samples, {min} to {max} events per stream, {} events in all",
        per_stream.iter().sum::<u64>()
    );
    match (idle_cpu, busy_cpu) {
        (Some(idle), Some(busy)) => println!(
            "metrics acceptance: CPU of the process: {idle:.0} ms with {STREAMS} streams on jobs, {busy:.0} ms with {STREAMS} streams on metrics ({:.1} % and {:.1} % of one core)",
            idle / seconds / 10.0,
            busy / seconds / 10.0
        ),
        _ => println!("metrics acceptance: the CPU time is not measured on this platform"),
    }
    // One aggregation per second whatever the number of streams, and one sample per tick.
    let expected = ticks_in(elapsed);
    assert!(
        expected.contains(&ticks),
        "{ticks} aggregations in {seconds:.2} s, expected {expected:?}"
    );
    assert!(
        taken <= ticks + 1,
        "{taken} samples for {ticks} aggregations"
    );
    // Every stream gets every snapshot: as many as there were aggregations, give or take
    // the one in flight when the counters were read.
    assert!(
        per_stream
            .iter()
            .all(|events| events.abs_diff(ticks) <= 1 && expected.contains(events)),
        "events per stream for {ticks} aggregations: {per_stream:?}"
    );

    for reader in readers {
        reader.task.abort();
    }
    stop_tx.send(true).expect("stop");
    timeout(WAIT, task)
        .await
        .expect("the publisher stops")
        .expect("no panic");
    server.shutdown();
    timeout(WAIT, server.wait())
        .await
        .expect("shutdown in time")
        .expect("clean shutdown");
}
