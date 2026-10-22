//! Tests of the query log: the drain, the formats, pseudonyms, sampling, pages, filters,
//! retention, recovery and the kill switch.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, QueryTransport, Rtype};

use super::{writer::Writer, *};

fn settings(dir: &Path) -> LogSettings {
    LogSettings {
        days: 7,
        size_mb: 64,
        ..LogSettings::new(dir)
    }
}

fn entry(qname: &[u8], client: IpAddr, at_micros: u64) -> QueryLogEntry<'_> {
    QueryLogEntry {
        at_micros,
        client,
        transport: QueryTransport::Udp,
        qname,
        qtype: 1,
        rcode: 0,
        view: None,
        blocked: None,
        cached: false,
        duration_micros: 42,
        // WP10.1: the resolution of the log line.
        resolution: None,
        subqueries: 0,
    }
}

fn wire(name: &str) -> Vec<u8> {
    DnsName::new(name).expect("name").to_wire()
}

/// 2026-10-15 in microseconds, a few hours into the UTC day.
const NOW: u64 = 1_792_000_000_000_000;
const DAY: u64 = 86_400_000_000;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn write_lines(settings: LogSettings, names: &[&str], client: IpAddr) {
    write_at(settings, names, client, NOW);
}

fn write_at(settings: LogSettings, names: &[&str], client: IpAddr, at: u64) {
    let writer = LogWriter::start(settings).expect("start");
    let sink = writer.sink();
    for (n, name) in names.iter().enumerate() {
        let qname = wire(name);
        sink.record(&entry(&qname, client, at + n as u64));
    }
    writer.stop();
}

fn all(dir: &Path) -> Vec<LogLine> {
    read(dir, None, 1_000, &LogFilter::default())
        .expect("page")
        .lines
}

fn names(lines: &[LogLine]) -> Vec<&str> {
    lines.iter().map(|line| line.qname.as_str()).collect()
}

#[test]
fn lines_are_written_and_read_back_newest_first_in_pages() {
    let dir = tempdir();
    let names: Vec<String> = (0..25).map(|n| format!("host-{n}.example.test")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    write_lines(settings(dir.path()), &refs, CLIENT);
    let none = LogFilter::default();
    let first = read(dir.path(), None, 10, &none).expect("first page");
    assert_eq!(first.lines.len(), 10);
    assert_eq!(first.lines[0].qname, "host-24.example.test");
    assert_eq!(first.lines[0].rtype, Rtype::A);
    assert_eq!(first.lines[0].duration_micros, 42);
    let second = read(dir.path(), first.next.as_deref(), 10, &none).expect("second page");
    assert_eq!(second.lines[0].qname, "host-14.example.test");
    let third = read(dir.path(), second.next.as_deref(), 10, &none).expect("third page");
    assert_eq!(third.lines.len(), 5);
    assert_eq!(third.lines[4].qname, "host-0.example.test");
    assert_eq!(third.next, None);
}

#[test]
fn clients_are_pseudonymised_by_default_and_stable_across_a_restart() {
    let dir = tempdir();
    write_lines(
        settings(dir.path()),
        &["a.example.test", "b.example.test"],
        CLIENT,
    );
    write_lines(settings(dir.path()), &["c.example.test"], CLIENT);
    let lines = all(dir.path());
    let pseudonym = lines[0].client.clone().expect("a client");
    assert!(
        pseudonym.starts_with("p:") && pseudonym.len() == 18,
        "{pseudonym}"
    );
    assert!(
        lines
            .iter()
            .all(|line| line.client.as_deref() == Some(&*pseudonym)),
        "stable within the day, also after the writer restarted: {lines:?}"
    );
    for name in segments(dir.path()).expect("segments") {
        let text = fs::read_to_string(dir.path().join(name)).expect("segment");
        assert!(!text.contains("192.0.2.7"));
    }
    let keys = keys::Keys::load(dir.path());
    assert_eq!(keys.days().collect::<Vec<_>>(), [day_of(NOW)]);
}

#[test]
fn a_pseudonym_changes_with_the_day() {
    let dir = tempdir();
    write_at(settings(dir.path()), &["a.example.test"], CLIENT, NOW);
    write_at(settings(dir.path()), &["b.example.test"], CLIENT, NOW + DAY);
    let lines = all(dir.path());
    assert_eq!(names(&lines), ["b.example.test", "a.example.test"]);
    assert_ne!(lines[0].client, lines[1].client);
    assert_eq!(
        segments(dir.path()).expect("segments").len(),
        2,
        "a segment per day"
    );
}

#[test]
fn the_client_can_be_written_as_its_address_or_not_at_all() {
    let plain = tempdir();
    write_lines(
        LogSettings {
            client: ClientField::Address,
            ..settings(plain.path())
        },
        &["a.example.test"],
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
    );
    assert_eq!(all(plain.path())[0].client.as_deref(), Some("2001:db8::7"));

    let hidden = tempdir();
    write_lines(
        LogSettings {
            client: ClientField::Hidden,
            ..settings(hidden.path())
        },
        &["a.example.test"],
        CLIENT,
    );
    assert_eq!(all(hidden.path())[0].client, None);
    let name = &segments(hidden.path()).expect("segments")[0];
    let text = fs::read_to_string(hidden.path().join(name)).expect("segment");
    assert!(!text.contains("client"), "{text}");
    assert!(
        !hidden.path().join(keys::KEYS_FILE).exists(),
        "no key is made"
    );
}

#[test]
fn sampling_keeps_one_query_in_n() {
    let dir = tempdir();
    let names: Vec<String> = (0..20).map(|n| format!("h{n}.example.test")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    write_lines(
        LogSettings {
            sample: 4,
            ..settings(dir.path())
        },
        &refs,
        CLIENT,
    );
    assert_eq!(all(dir.path()).len(), 5);
}

#[test]
fn the_name_filter_matches_a_name_and_the_names_under_it() {
    let dir = tempdir();
    write_lines(
        settings(dir.path()),
        &[
            "example.test",
            "www.example.test",
            "badexample.test",
            "WWW.Sub.Example.Test",
            "other.test",
        ],
        CLIENT,
    );
    let filter = LogFilter {
        qname: Some("EXAMPLE.test.".to_owned()),
        ..LogFilter::default()
    };
    let page = read(dir.path(), None, 10, &filter).expect("page");
    assert_eq!(
        names(&page.lines),
        ["www.sub.example.test", "www.example.test", "example.test"]
    );
}

#[test]
fn the_client_filter_takes_a_pseudonym_or_an_address() {
    let dir = tempdir();
    let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    write_lines(settings(dir.path()), &["a.example.test"], CLIENT);
    write_lines(settings(dir.path()), &["b.example.test"], other);
    let lines = all(dir.path());
    let pseudonym = lines[1].client.clone().expect("pseudonym");
    let by = |client: &str| {
        let filter = LogFilter {
            client: Some(client.to_owned()),
            ..LogFilter::default()
        };
        names(&read(dir.path(), None, 10, &filter).expect("page").lines)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(by(&pseudonym), ["a.example.test"]);
    assert_eq!(
        by(&pseudonym.to_ascii_uppercase().replace("P:", "p:")),
        ["a.example.test"]
    );
    assert_eq!(by("192.0.2.7"), ["a.example.test"]);
    assert_eq!(by("::ffff:198.51.100.9"), ["b.example.test"]);
    assert_eq!(by("203.0.113.1"), Vec::<String>::new());
    let bad = LogFilter {
        client: Some("somebody".to_owned()),
        ..LogFilter::default()
    };
    assert!(matches!(
        read(dir.path(), None, 10, &bad),
        Err(ReadError::Filter(_))
    ));
}

#[test]
fn the_rcode_and_time_filters_apply() {
    let dir = tempdir();
    let writer = LogWriter::start(settings(dir.path())).expect("start");
    let sink = writer.sink();
    for (n, rcode) in [0u16, 3, 3, 2].into_iter().enumerate() {
        let qname = wire(&format!("q{n}.example.test"));
        let mut line = entry(&qname, CLIENT, NOW + n as u64 * 1_000_000);
        line.rcode = rcode;
        sink.record(&line);
    }
    writer.stop();
    let nx = LogFilter {
        rcode: Some(3),
        ..LogFilter::default()
    };
    assert_eq!(
        names(&read(dir.path(), None, 10, &nx).expect("page").lines),
        ["q2.example.test", "q1.example.test"]
    );
    let at = |micros: u64| Timestamp::from_unix_nanos(i128::from(micros) * 1_000).expect("time");
    let window = LogFilter {
        from: Some(at(NOW + 1_000_000)),
        until: Some(at(NOW + 2_000_000)),
        ..LogFilter::default()
    };
    assert_eq!(
        names(&read(dir.path(), None, 10, &window).expect("page").lines),
        ["q2.example.test", "q1.example.test"]
    );
    let backwards = LogFilter {
        from: Some(at(NOW + 2_000_000)),
        until: Some(at(NOW)),
        ..LogFilter::default()
    };
    assert!(matches!(backwards.validate(), Err(ReadError::Filter(_))));
}

#[test]
fn a_bad_cursor_is_refused_and_an_empty_directory_reads_empty() {
    let dir = tempdir();
    let none = LogFilter::default();
    assert_eq!(
        read(dir.path(), Some("x"), 10, &none),
        Err(ReadError::Cursor)
    );
    assert_eq!(
        read(dir.path(), Some("../queries-1.jsonl:4"), 10, &none),
        Err(ReadError::Cursor)
    );
    assert_eq!(
        read(dir.path(), Some("queries-1.txt:4"), 10, &none),
        Err(ReadError::Cursor)
    );
    assert_eq!(
        read(&dir.path().join("missing"), None, 10, &none),
        Ok(LogPage::default())
    );
}

#[test]
fn a_ring_nobody_drains_takes_every_entry_and_drops_without_waiting() {
    // No writer at all: a sink that waited for room would never return.
    let dir = tempdir();
    let log = detached(settings(dir.path()), 2);
    let qname = wire("a.example.test");
    for n in 0..10_000 {
        log.record(&entry(&qname, CLIENT, NOW + n));
    }
    assert_eq!(log.dropped(), 9_998);
}

#[test]
fn a_full_ring_drops_and_counts_without_waiting() {
    let dir = tempdir();
    let log = detached(settings(dir.path()), 2);
    let qname = wire("a.example.test");
    let before = DROPPED.get();
    for _ in 0..5 {
        log.record(&entry(&qname, CLIENT, NOW));
    }
    assert_eq!(log.dropped(), 3);
    assert!(DROPPED.get() >= before + 3);
    assert_eq!(
        log.ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .filled()
            .len(),
        2
    );
}

#[test]
fn the_kill_switch_stops_logging_and_survives_a_restart() {
    let dir = tempdir();
    let writer = LogWriter::start(settings(dir.path())).expect("start");
    let sink = writer.sink();
    let qname = wire("before.example.test");
    sink.record(&entry(&qname, CLIENT, NOW));
    sink.set_stopped(true).expect("stop");
    assert!(dir.path().join(STOPPED_MARKER).exists());
    let qname = wire("while.example.test");
    sink.record(&entry(&qname, CLIENT, NOW + 1));
    assert_eq!(
        sink.dropped(),
        0,
        "a stopped log drops nothing, it takes nothing"
    );
    writer.stop();
    let again = LogWriter::start(settings(dir.path())).expect("restart");
    assert!(again.sink().figures().stopped);
    again.sink().set_stopped(false).expect("start");
    assert!(!dir.path().join(STOPPED_MARKER).exists());
    let qname = wire("after.example.test");
    again.sink().record(&entry(&qname, CLIENT, NOW + 2));
    again.stop();
    assert_eq!(
        names(&all(dir.path())),
        ["after.example.test", "before.example.test"]
    );
}

#[test]
fn a_failing_disk_drops_and_counts_and_the_log_recovers() {
    let dir = tempdir();
    let logs = dir.path().join("log");
    let writer = LogWriter::start(settings(&logs)).expect("start");
    let sink = writer.sink();
    // The directory turns into a file: every segment fails to open, as on a full disk.
    fs::remove_dir_all(&logs).expect("remove");
    fs::write(&logs, b"in the way").expect("block");
    let qname = wire("lost.example.test");
    for n in 0..100 {
        sink.record(&entry(&qname, CLIENT, NOW + n));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while sink.dropped() < 100 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(sink.dropped(), 100);
    assert!(sink.figures().write_errors >= 1);
    fs::remove_file(&logs).expect("unblock");
    fs::create_dir_all(&logs).expect("directory");
    let qname = wire("kept.example.test");
    sink.record(&entry(&qname, CLIENT, NOW + 200));
    writer.stop();
    assert_eq!(sink.written(), 1);
    assert_eq!(names(&all(&logs)), ["kept.example.test"]);
}

#[test]
fn retention_removes_the_oldest_segments_beyond_the_size_and_their_keys() {
    let dir = tempdir();
    for n in 0..5u64 {
        let name = format!("{SEGMENT_PREFIX}{:020}.jsonl", NOW + n * DAY);
        fs::write(dir.path().join(name), vec![b'x'; 600 * 1024]).expect("segment");
    }
    let mut keys = keys::Keys::load(dir.path());
    for n in 0..5u64 {
        keys.key_for(day_of(NOW) + n, &mut |error| panic!("{error}"));
    }
    drop(keys);
    let mut writer = Writer::new(LogSettings {
        size_mb: 2,
        ..settings(dir.path())
    });
    writer.retention();
    let mut left = segments(dir.path()).expect("segments");
    left.sort();
    // 3 MB on disk, 2 MB allowed: the two oldest go.
    assert_eq!(left.len(), 3);
    assert_eq!(segment_micros(&left[0]), Some(NOW + 2 * DAY));
    let kept: Vec<u64> = keys::Keys::load(dir.path()).days().collect();
    assert_eq!(kept, [day_of(NOW) + 2, day_of(NOW) + 3, day_of(NOW) + 4]);
}

#[test]
fn an_unfinished_tail_is_cut_off_at_start() {
    let dir = tempdir();
    write_lines(settings(dir.path()), &["a.example.test"], CLIENT);
    let name = segments(dir.path()).expect("segments").remove(0);
    let path = dir.path().join(&name);
    let mut bytes = fs::read(&path).expect("segment");
    let whole = bytes.len();
    bytes.extend_from_slice(b"{\"at\":\"2026-");
    fs::write(&path, &bytes).expect("damage");
    writer::recover(dir.path()).expect("recover");
    assert_eq!(fs::read(&path).expect("segment").len(), whole);
    assert_eq!(names(&all(dir.path())), ["a.example.test"]);
}

#[test]
fn a_dnstap_segment_is_read_back_and_its_tail_recovered() {
    let dir = tempdir();
    write_lines(
        LogSettings {
            format: LogFormat::Dnstap,
            identity: "node-1".to_owned(),
            version: "0.0.1".to_owned(),
            ..settings(dir.path())
        },
        &["a.example.test", "b.example.test"],
        CLIENT,
    );
    let lines = all(dir.path());
    assert_eq!(names(&lines), ["b.example.test", "a.example.test"]);
    let client = lines[0].client.clone().expect("pseudonym");
    assert!(client.starts_with("p:") && client.len() == 10, "{client}");
    assert_eq!(lines[0].duration_micros, 42);
    let by_address = LogFilter {
        client: Some("192.0.2.7".to_owned()),
        ..LogFilter::default()
    };
    assert_eq!(
        read(dir.path(), None, 10, &by_address)
            .expect("page")
            .lines
            .len(),
        2
    );
    let name = segments(dir.path()).expect("segments").remove(0);
    let path = dir.path().join(&name);
    let mut bytes = fs::read(&path).expect("segment");
    // Drop the STOP frame and half a data frame, as a crash would leave it.
    bytes.truncate(bytes.len() - 12);
    let damaged = bytes.len();
    bytes.extend_from_slice(&[0, 0, 0, 200, 1, 2, 3]);
    fs::write(&path, &bytes).expect("damage");
    writer::recover(dir.path()).expect("recover");
    let bytes = fs::read(&path).expect("segment");
    assert_eq!(
        bytes.len(),
        damaged + 12,
        "cut and closed with a STOP frame"
    );
    assert_eq!(all(dir.path()).len(), 2);
}

/// A temporary directory removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    let path = std::env::temp_dir().join(format!(
        "tenko-querylog-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    fs::create_dir_all(&path).expect("temporary directory");
    TempDir(path)
}
