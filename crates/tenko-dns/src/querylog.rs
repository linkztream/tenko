//! The query log as a local file of JSON lines (plan section 2.9, DNS-26, TGL-15): the
//! [`QueryLogSink`] of the `dns` role when `[dns.log] enabled = true`, and the reader behind
//! the command `dns.log.read`.
//!
//! - **On the query path** [`FileLog::record`] samples (1 in `sample`), copies the entry into
//!   a preallocated ring of fixed-size slots under a short lock, and drops it (counted) when
//!   the ring is full. Nothing is allocated, nothing waits for the disk.
//! - **The writer** is a thread of its own: every 100 ms it takes what the ring holds and
//!   appends one JSON line per query to the current segment `queries-<micros>.jsonl` in the
//!   log directory, then flushes, so a reader only ever sees whole lines. With
//!   pseudonymisation on (the default) the client address is replaced by a keyed hash,
//!   `p:` and 16 hexadecimal digits, under a random key that is replaced every day (UTC)
//!   and never written down: the same client has the same pseudonym within a day only.
//! - **Retention**: a segment holds at most a sixteenth of `size_mb` (1 to 8 MiB); after
//!   each new segment, and once a minute, segments older than `days` are removed, then the
//!   oldest until the directory holds at most `size_mb`.
//! - **Reading** ([`read`]) goes newest first, a page at a time, with a cursor that names a
//!   segment and an offset in it.
//!
//! dnstap frame streams (`format = "dnstap"`) are not written yet (WP5.4).

use std::{
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    Timestamp,
    dns::{BlockListId, DnsName, QueryTransport, Rtype, ViewId},
};

use crate::log::{QueryLogEntry, QueryLogSink};

/// Slots of the ring between the query path and the writer.
pub const RING_SLOTS: usize = 8_192;

/// How often the writer empties the ring.
const DRAIN_EVERY: Duration = Duration::from_millis(100);

/// How often the writer applies the retention without a new segment.
const RETENTION_EVERY: Duration = Duration::from_secs(60);

/// The file name prefix and suffix of a segment.
const SEGMENT_PREFIX: &str = "queries-";
const SEGMENT_SUFFIX: &str = ".jsonl";

const MIB: u64 = 1024 * 1024;

/// The settings of the file log (`[dns.log]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSettings {
    /// The directory of the segments.
    pub dir: PathBuf,
    /// Days a segment is kept.
    pub days: u32,
    /// Octets the directory may hold, in MiB.
    pub size_mb: u64,
    /// One query in `sample` is logged (1: every query).
    pub sample: u32,
    /// Replace client addresses with a daily keyed hash.
    pub pseudonymise: bool,
}

impl LogSettings {
    /// The largest segment.
    fn segment_bytes(&self) -> u64 {
        (self.size_mb.saturating_mul(MIB) / 16).clamp(MIB, 8 * MIB)
    }
}

/// One line of the log, as written and as read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// When the query arrived.
    pub at: Timestamp,
    /// The client: its address, or its pseudonym (`p:` and 16 hexadecimal digits).
    pub client: String,
    /// The transport.
    pub transport: QueryTransport,
    /// The query name.
    pub qname: String,
    /// The query type.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The RCODE answered.
    pub rcode: u16,
    /// The view that matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
    /// The list that blocked the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<BlockListId>,
    /// Answered from the cache.
    pub cached: bool,
    /// Microseconds from arrival to answer.
    pub duration_micros: u32,
}

#[derive(Clone, Copy)]
struct Slot {
    at_micros: u64,
    client: IpAddr,
    transport: QueryTransport,
    qname: [u8; 255],
    qname_len: u8,
    qtype: u16,
    rcode: u16,
    view: Option<ViewId>,
    blocked: Option<BlockListId>,
    cached: bool,
    duration_micros: u32,
}

impl Slot {
    const EMPTY: Slot = Slot {
        at_micros: 0,
        client: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        transport: QueryTransport::Udp,
        qname: [0; 255],
        qname_len: 0,
        qtype: 0,
        rcode: 0,
        view: None,
        blocked: None,
        cached: false,
        duration_micros: 0,
    };

    fn fill(&mut self, entry: &QueryLogEntry<'_>) {
        let len = entry.qname.len().min(self.qname.len());
        self.qname[..len].copy_from_slice(&entry.qname[..len]);
        self.qname_len = u8::try_from(len).unwrap_or(u8::MAX);
        self.at_micros = entry.at_micros;
        self.client = entry.client;
        self.transport = entry.transport;
        self.qtype = entry.qtype;
        self.rcode = entry.rcode;
        self.view = entry.view;
        self.blocked = entry.blocked;
        self.cached = entry.cached;
        self.duration_micros = entry.duration_micros;
    }
}

struct Ring {
    slots: Box<[Slot]>,
    head: usize,
    len: usize,
}

impl Ring {
    fn new(capacity: usize) -> Self {
        Self {
            slots: vec![Slot::EMPTY; capacity.max(1)].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    /// Moves the slots out into `out` (which keeps its capacity across drains).
    fn drain_into(&mut self, out: &mut Vec<Slot>) {
        let capacity = self.slots.len();
        for offset in 0..self.len {
            out.push(self.slots[(self.head + offset) % capacity]);
        }
        self.head = (self.head + self.len) % capacity;
        self.len = 0;
    }
}

/// The query log sink that writes JSON lines; see the module documentation.
pub struct FileLog {
    ring: Mutex<Ring>,
    sample: u64,
    seen: AtomicU64,
    dropped: AtomicU64,
    written: AtomicU64,
}

impl std::fmt::Debug for FileLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLog")
            .field("sample", &self.sample)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl QueryLogSink for FileLog {
    fn record(&self, entry: &QueryLogEntry<'_>) {
        if self.sample > 1
            && !self
                .seen
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(self.sample)
        {
            return;
        }
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        let capacity = ring.slots.len();
        if ring.len == capacity {
            drop(ring);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let at = (ring.head + ring.len) % capacity;
        ring.slots[at].fill(entry);
        ring.len += 1;
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl FileLog {
    /// Lines written since the start.
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

/// The running writer of a [`FileLog`].
#[derive(Debug)]
pub struct LogWriter {
    log: Arc<FileLog>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    dir: PathBuf,
}

impl LogWriter {
    /// Creates the directory and starts the writer thread.
    ///
    /// # Errors
    ///
    /// The directory cannot be created, or the thread cannot be started.
    pub fn start(settings: LogSettings) -> io::Result<Self> {
        fs::create_dir_all(&settings.dir)?;
        let log = Arc::new(FileLog {
            ring: Mutex::new(Ring::new(RING_SLOTS)),
            sample: u64::from(settings.sample.max(1)),
            seen: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            written: AtomicU64::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let dir = settings.dir.clone();
        let thread = {
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("dns-query-log".to_owned())
                .spawn(move || Writer::new(settings).run(&log, &stop))?
        };
        Ok(Self {
            log,
            stop,
            thread: Some(thread),
            dir,
        })
    }

    /// The sink for the query path.
    pub fn sink(&self) -> Arc<FileLog> {
        Arc::clone(&self.log)
    }

    /// The directory of the segments.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes what the ring holds and stops the thread.
    pub fn stop(mut self) {
        self.finish();
    }

    fn finish(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        self.finish();
    }
}

struct Segment {
    file: io::BufWriter<fs::File>,
    bytes: u64,
}

struct Writer {
    settings: LogSettings,
    segment: Option<Segment>,
    key: [u8; 32],
    key_day: u64,
    line: String,
    last_retention: SystemTime,
}

fn unix_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(u64::MAX)
}

impl Writer {
    fn new(settings: LogSettings) -> Self {
        Self {
            settings,
            segment: None,
            key: [0; 32],
            key_day: u64::MAX,
            line: String::with_capacity(512),
            last_retention: UNIX_EPOCH,
        }
    }

    fn run(mut self, log: &FileLog, stop: &AtomicBool) {
        let mut batch: Vec<Slot> = Vec::with_capacity(RING_SLOTS);
        loop {
            let stopping = stop.load(Ordering::Relaxed);
            log.ring
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drain_into(&mut batch);
            if !batch.is_empty() {
                match self.write(&batch) {
                    Ok(()) => {
                        log.written.fetch_add(
                            u64::try_from(batch.len()).unwrap_or(u64::MAX),
                            Ordering::Relaxed,
                        );
                    }
                    Err(error) => {
                        log.dropped.fetch_add(
                            u64::try_from(batch.len()).unwrap_or(u64::MAX),
                            Ordering::Relaxed,
                        );
                        tracing::warn!(%error, dir = %self.settings.dir.display(), "the DNS query log could not be written");
                        self.segment = None;
                    }
                }
                batch.clear();
            }
            let due =
                !matches!(self.last_retention.elapsed(), Ok(since) if since < RETENTION_EVERY);
            if due {
                self.retention();
            }
            if stopping {
                return;
            }
            std::thread::sleep(DRAIN_EVERY);
        }
    }

    fn pseudonym(&mut self, client: IpAddr, at_micros: u64) -> String {
        let day = at_micros / 86_400_000_000;
        if day != self.key_day {
            // A failing generator keeps the previous key one more day.
            if aws_lc_rs::rand::fill(&mut self.key).is_ok() || self.key_day == u64::MAX {
                self.key_day = day;
            }
        }
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.key);
        let tag = match client.to_canonical() {
            IpAddr::V4(v4) => aws_lc_rs::hmac::sign(&key, &v4.octets()),
            IpAddr::V6(v6) => aws_lc_rs::hmac::sign(&key, &v6.octets()),
        };
        let mut out = String::with_capacity(18);
        out.push_str("p:");
        for byte in &tag.as_ref()[..8] {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn line_of(&mut self, slot: &Slot) -> LogLine {
        let qname = DnsName::from_wire(&slot.qname[..usize::from(slot.qname_len)])
            .map_or_else(|_| "?".to_owned(), |(name, _)| name.to_string());
        let client = if self.settings.pseudonymise {
            self.pseudonym(slot.client, slot.at_micros)
        } else {
            slot.client.to_canonical().to_string()
        };
        LogLine {
            at: Timestamp::from_unix_nanos(i128::from(slot.at_micros) * 1_000)
                .unwrap_or(Timestamp::UNIX_EPOCH),
            client,
            transport: slot.transport,
            qname,
            rtype: Rtype(slot.qtype),
            rcode: slot.rcode,
            view: slot.view,
            blocked: slot.blocked,
            cached: slot.cached,
            duration_micros: slot.duration_micros,
        }
    }

    fn open_segment(&mut self) -> io::Result<()> {
        let path = self.settings.dir.join(format!(
            "{SEGMENT_PREFIX}{:020}{SEGMENT_SUFFIX}",
            unix_micros()
        ));
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        self.segment = Some(Segment {
            file: io::BufWriter::with_capacity(64 * 1024, file),
            bytes: 0,
        });
        self.retention();
        Ok(())
    }

    fn write(&mut self, batch: &[Slot]) -> io::Result<()> {
        let limit = self.settings.segment_bytes();
        for slot in batch {
            let line = self.line_of(slot);
            self.line.clear();
            // Serialising these fields cannot fail.
            if let Ok(text) = serde_json::to_string(&line) {
                self.line.push_str(&text);
            }
            self.line.push('\n');
            let size = u64::try_from(self.line.len()).unwrap_or(u64::MAX);
            let full = self
                .segment
                .as_ref()
                .is_none_or(|segment| segment.bytes > 0 && segment.bytes + size > limit);
            if full {
                if let Some(mut segment) = self.segment.take() {
                    segment.file.flush()?;
                }
                self.open_segment()?;
            }
            if let Some(segment) = &mut self.segment {
                segment.file.write_all(self.line.as_bytes())?;
                segment.bytes += size;
            }
        }
        if let Some(segment) = &mut self.segment {
            segment.file.flush()?;
        }
        Ok(())
    }

    /// Removes segments older than `days`, then the oldest beyond `size_mb`; the newest
    /// segment always stays.
    fn retention(&mut self) {
        self.last_retention = SystemTime::now();
        let Ok(mut segments) = segments(&self.settings.dir) else {
            return;
        };
        segments.sort();
        let newest = segments.pop();
        let max_age = Duration::from_secs(u64::from(self.settings.days) * 86_400);
        let mut kept = Vec::new();
        for name in segments {
            let path = self.settings.dir.join(&name);
            let old = fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > max_age);
            if old {
                let _ = fs::remove_file(&path);
            } else {
                kept.push(name);
            }
        }
        let size_of =
            |name: &String| fs::metadata(self.settings.dir.join(name)).map_or(0, |meta| meta.len());
        let mut total: u64 =
            kept.iter().map(size_of).sum::<u64>() + newest.as_ref().map_or(0, size_of);
        let limit = self.settings.size_mb.saturating_mul(MIB);
        for name in kept {
            if total <= limit {
                break;
            }
            total = total.saturating_sub(size_of(&name));
            let _ = fs::remove_file(self.settings.dir.join(&name));
        }
    }
}

/// The segment file names of a directory, unsorted.
fn segments(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(SEGMENT_PREFIX) && name.ends_with(SEGMENT_SUFFIX) {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// One page of the log, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogPage {
    /// The lines.
    pub lines: Vec<LogLine>,
    /// The cursor of the next (older) page, if there may be one.
    pub next: Option<String>,
}

/// Why the log could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The cursor is not one this log handed out.
    #[error("the cursor is not valid")]
    Cursor,
    /// The directory or a segment could not be read.
    #[error("the query log could not be read: {0}")]
    Io(String),
}

fn parse_cursor(cursor: &str) -> Option<(String, u64)> {
    let (name, offset) = cursor.rsplit_once(':')?;
    let valid = name.starts_with(SEGMENT_PREFIX)
        && name.ends_with(SEGMENT_SUFFIX)
        && !name.contains(['/', '\\']);
    valid.then_some(())?;
    Some((name.to_owned(), offset.parse().ok()?))
}

/// Reads up to `limit` lines, newest first, from `cursor` (or the newest line), keeping
/// those whose query name starts with `qname` (ignoring case) when it is given.
///
/// # Errors
///
/// [`ReadError::Cursor`] for a malformed cursor, [`ReadError::Io`] when the directory
/// cannot be read.
pub fn read(
    dir: &Path,
    cursor: Option<&str>,
    limit: usize,
    qname: Option<&str>,
) -> Result<LogPage, ReadError> {
    let start = match cursor {
        Some(cursor) => Some(parse_cursor(cursor).ok_or(ReadError::Cursor)?),
        None => None,
    };
    let mut names = match segments(dir) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(ReadError::Io(error.to_string())),
    };
    names.sort();
    names.reverse();
    if let Some((name, _)) = &start {
        names.retain(|candidate| candidate <= name);
    }
    let prefix = qname.map(str::to_ascii_lowercase);
    let mut page = LogPage::default();
    for (position, name) in names.iter().enumerate() {
        let bytes = match fs::read(dir.join(name)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ReadError::Io(error.to_string())),
        };
        // Only whole lines: a line the writer has not finished has no newline yet.
        let mut end = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |at| at + 1);
        if let Some((cursor_name, offset)) = &start
            && cursor_name == name
        {
            end = end.min(usize::try_from(*offset).unwrap_or(usize::MAX));
        }
        while end > 0 {
            let line_start = bytes[..end - 1]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |at| at + 1);
            let text = &bytes[line_start..end - 1];
            end = line_start;
            let Ok(line) = serde_json::from_slice::<LogLine>(text) else {
                continue;
            };
            if prefix
                .as_deref()
                .is_some_and(|prefix| !line.qname.to_ascii_lowercase().starts_with(prefix))
            {
                continue;
            }
            page.lines.push(line);
            if page.lines.len() >= limit {
                let more = end > 0 || position + 1 < names.len();
                page.next = more.then(|| format!("{name}:{end}"));
                return Ok(page);
            }
        }
    }
    Ok(page)
}

#[cfg(test)]
mod tests;
