//! Tests of the JSON-lines query log: writing, pseudonyms, sampling, pages and retention.

use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn settings(dir: &Path) -> LogSettings {
    LogSettings {
        dir: dir.to_path_buf(),
        days: 7,
        size_mb: 64,
        sample: 1,
        pseudonymise: true,
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
    }
}

fn wire(name: &str) -> Vec<u8> {
    DnsName::new(name).expect("name").to_wire()
}

const NOW: u64 = 1_792_000_000_000_000;

fn write_lines(settings: LogSettings, names: &[&str], client: IpAddr) {
    let writer = LogWriter::start(settings).expect("start");
    let sink = writer.sink();
    for (n, name) in names.iter().enumerate() {
        let qname = wire(name);
        sink.record(&entry(&qname, client, NOW + n as u64));
    }
    writer.stop();
}

#[test]
fn lines_are_written_and_read_back_newest_first_in_pages() {
    let dir = tempdir();
    let names: Vec<String> = (0..25).map(|n| format!("host-{n}.example.test")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    write_lines(
        settings(dir.path()),
        &refs,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
    );
    let first = read(dir.path(), None, 10, None).expect("first page");
    assert_eq!(first.lines.len(), 10);
    assert_eq!(first.lines[0].qname, "host-24.example.test");
    assert_eq!(first.lines[0].rtype, Rtype::A);
    assert_eq!(first.lines[0].duration_micros, 42);
    let second = read(dir.path(), first.next.as_deref(), 10, None).expect("second page");
    assert_eq!(second.lines[0].qname, "host-14.example.test");
    let third = read(dir.path(), second.next.as_deref(), 10, None).expect("third page");
    assert_eq!(third.lines.len(), 5);
    assert_eq!(third.lines[4].qname, "host-0.example.test");
    assert_eq!(third.next, None);
}

#[test]
fn clients_are_pseudonymised_unless_switched_off() {
    let dir = tempdir();
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    write_lines(
        settings(dir.path()),
        &["a.example.test", "b.example.test"],
        client,
    );
    let page = read(dir.path(), None, 10, None).expect("page");
    let pseudonym = &page.lines[0].client;
    assert!(
        pseudonym.starts_with("p:") && pseudonym.len() == 18,
        "{pseudonym}"
    );
    assert_eq!(&page.lines[1].client, pseudonym, "stable within the day");
    let text = fs::read_to_string(dir.path().join(&segments(dir.path()).expect("segments")[0]))
        .expect("segment");
    assert!(!text.contains("192.0.2.7"));

    let plain = tempdir();
    let mut open = settings(plain.path());
    open.pseudonymise = false;
    write_lines(open, &["a.example.test"], client);
    let page = read(plain.path(), None, 10, None).expect("page");
    assert_eq!(page.lines[0].client, "192.0.2.7");
}

#[test]
fn sampling_keeps_one_query_in_n() {
    let dir = tempdir();
    let mut sampled = settings(dir.path());
    sampled.sample = 4;
    let names: Vec<String> = (0..20).map(|n| format!("h{n}.example.test")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    write_lines(sampled, &refs, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let page = read(dir.path(), None, 100, None).expect("page");
    assert_eq!(page.lines.len(), 5);
}

#[test]
fn the_query_name_filter_is_a_prefix_without_case() {
    let dir = tempdir();
    write_lines(
        settings(dir.path()),
        &["www.example.test", "mail.example.test", "WWW2.example.test"],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );
    let page = read(dir.path(), None, 10, Some("WWW")).expect("page");
    let names: Vec<&str> = page.lines.iter().map(|line| line.qname.as_str()).collect();
    assert_eq!(names, ["www2.example.test", "www.example.test"]);
}

#[test]
fn a_bad_cursor_is_refused_and_an_empty_directory_reads_empty() {
    let dir = tempdir();
    assert_eq!(
        read(dir.path(), Some("x"), 10, None),
        Err(ReadError::Cursor)
    );
    assert_eq!(
        read(dir.path(), Some("../queries-1.jsonl:4"), 10, None),
        Err(ReadError::Cursor)
    );
    assert_eq!(
        read(&dir.path().join("missing"), None, 10, None),
        Ok(LogPage::default())
    );
}

#[test]
fn a_full_ring_drops_and_counts() {
    let log = FileLog {
        ring: Mutex::new(Ring::new(2)),
        sample: 1,
        seen: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        written: AtomicU64::new(0),
    };
    let qname = wire("a.example.test");
    for _ in 0..5 {
        log.record(&entry(&qname, IpAddr::V4(Ipv4Addr::LOCALHOST), NOW));
    }
    assert_eq!(log.dropped(), 3);
    let mut out = Vec::new();
    log.ring
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .drain_into(&mut out);
    assert_eq!(out.len(), 2);
}

#[test]
fn retention_removes_the_oldest_segments_beyond_the_size() {
    let dir = tempdir();
    for n in 0..5 {
        let name = format!("{SEGMENT_PREFIX}{n:020}{SEGMENT_SUFFIX}");
        fs::write(dir.path().join(name), vec![b'x'; 600 * 1024]).expect("segment");
    }
    let mut writer = Writer::new(LogSettings {
        size_mb: 2,
        ..settings(dir.path())
    });
    writer.retention();
    let mut left = segments(dir.path()).expect("segments");
    left.sort();
    // 3 MB on disk, 2 MB allowed: the two oldest go, the newest always stays.
    assert_eq!(left.len(), 3);
    assert!(left[0].ends_with(&format!("{:020}{SEGMENT_SUFFIX}", 2)));
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
