//! The query log under pressure: many threads record at once while the writer drains, and
//! every entry is either written or counted as dropped; recording never waits for the disk.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, QueryTransport};
use tenko_dns::{
    log::{QueryLogEntry, QueryLogSink},
    querylog::{self, LogFilter, LogSettings, LogWriter},
};

#[test]
fn every_entry_is_written_or_counted_and_recording_never_waits() {
    let dir = std::env::temp_dir().join(format!("tenko-drain-{}", uuid::Uuid::now_v7()));
    let writer = LogWriter::start(LogSettings::new(&dir)).expect("writer");
    let sink = writer.sink();
    let threads = 8;
    let per_thread = 20_000u64;
    let workers: Vec<_> = (0..threads)
        .map(|thread| {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                let qname = DnsName::new(&format!("t{thread}.example.test"))
                    .expect("name")
                    .to_wire();
                let mut slowest = Duration::ZERO;
                for n in 0..per_thread {
                    let started = Instant::now();
                    sink.record(&QueryLogEntry {
                        at_micros: 1_792_000_000_000_000 + n,
                        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, thread)),
                        transport: QueryTransport::Udp,
                        qname: &qname,
                        qtype: 1,
                        rcode: 0,
                        view: None,
                        blocked: None,
                        cached: false,
                        duration_micros: 10,
                        // WP10.1: the resolution of the log line.
                        resolution: None,
                        subqueries: 0,
                    });
                    slowest = slowest.max(started.elapsed());
                }
                slowest
            })
        })
        .collect();
    let slowest = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .max()
        .unwrap_or_default();
    writer.stop();
    let total = u64::from(threads) * per_thread;
    assert_eq!(sink.written() + sink.dropped(), total);
    // A record holds the ring's lock for one copy, never a write. Only a bound a loaded test
    // host keeps for certain is asserted; the unit test with no writer at all proves that
    // recording never waits for room.
    assert!(slowest < Duration::from_secs(2), "{slowest:?}");
    let mut cursor = None;
    let mut read = 0;
    loop {
        let page =
            querylog::read(&dir, cursor.as_deref(), 1_000, &LogFilter::default()).expect("page");
        read += page.lines.len() as u64;
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(read, sink.written());
    let _ = fs::remove_dir_all(PathBuf::from(&dir));
}
