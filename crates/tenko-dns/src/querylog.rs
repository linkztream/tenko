//! The query log as local files (plan section 2.9, DNS-26, TGL-15, P2-Q7): the
//! [`QueryLogSink`] of the `dns` role when the log is on, the writer thread that drains it,
//! and the reader behind the command `dns.log.read` (`docs/dns-querylog.md`).
//!
//! - **On the query path** [`FileLog::record`] samples (1 in `sample`), copies the entry into
//!   a preallocated ring of fixed-size slots under a short lock, and drops it (counted in
//!   [`FileLog::dropped`] and `tenko_dns_log_dropped_total`) when the ring is full. Nothing is
//!   allocated, nothing waits for the disk. A stopped log ([`FileLog::set_stopped`], the
//!   kill switch) returns at once.
//! - **The writer** ([`writer`]) is a thread of its own. Every 100 ms it swaps the ring with
//!   an empty one (the lock is held for the swap only) and appends the entries to the
//!   current segment in the log directory, in JSON lines (`queries-<micros>.jsonl`) or in
//!   dnstap frame streams (`queries-<micros>.dnstap`, [`dnstap`]), and flushes. A batch that
//!   cannot be written (a full disk, a removed directory) is dropped and counted; the error
//!   is logged at most once a minute, and the next batch opens a new segment.
//! - **Rotation and retention**: a segment holds at most a sixteenth of `size_mb` (1 to
//!   8 MiB) and one UTC day. At start, after each new segment and once a minute, segments
//!   older than `days` are removed, then the oldest until the directory holds at most
//!   `size_mb`; the open segment stays. At start an unfinished tail of the newest segment
//!   (a crash in the middle of a write) is cut off.
//! - **The client** is written as its address, as a pseudonym, or not at all
//!   ([`ClientField`]). A pseudonym is an HMAC-SHA-256 of the address under a random key of
//!   the UTC day ([`keys`]); the keys are kept in the log directory for as long as a segment
//!   of their day is, so a pseudonym is stable within a day, also across a restart, and the
//!   reader can find an address's queries in old files.
//! - **Reading** ([`read`]) goes newest first, a page at a time, with a cursor that names a
//!   segment and an offset in it, and filters by name suffix, client, RCODE and time.

pub mod dnstap;
pub mod keys;
mod read;
mod ring;
pub mod writer;

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    Timestamp,
    dns::{BlockListId, QueryTransport, Rtype, ViewId},
    metrics::{Counter, Registry},
};

pub use read::{LogFilter, LogPage, MAX_SCAN_BYTES, ReadError, read};
use ring::Ring;
pub use writer::LogWriter;

use crate::log::{QueryLogEntry, QueryLogSink};

/// Slots of the ring between the query path and the writer.
pub const RING_SLOTS: usize = 8_192;

/// The file name prefix of a segment.
pub const SEGMENT_PREFIX: &str = "queries-";

/// The name of the marker file of a stopped log (the kill switch survives a restart).
pub const STOPPED_MARKER: &str = "stopped";

const MIB: u64 = 1024 * 1024;

/// Entries dropped by every query log of the process: `tenko_dns_log_dropped_total`.
pub static DROPPED: Counter = Counter::new(crate::metrics::LOG_DROPPED);

/// Registers [`DROPPED`] with the process registry (the role's start step).
pub fn register_metrics(registry: &Registry) {
    registry.register(&DROPPED);
}

/// The file format of the log (`[dns.log] format`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line (`.jsonl`).
    #[default]
    Jsonl,
    /// dnstap protobuf messages in a Frame Streams file (`.dnstap`).
    Dnstap,
}

impl LogFormat {
    /// The file name suffix of a segment of this format.
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Jsonl => ".jsonl",
            Self::Dnstap => ".dnstap",
        }
    }

    /// The format of a segment file name, if it is one.
    pub fn of_segment(name: &str) -> Option<Self> {
        let rest = name.strip_prefix(SEGMENT_PREFIX)?;
        let format = [Self::Jsonl, Self::Dnstap]
            .into_iter()
            .find(|format| rest.ends_with(format.suffix()))?;
        let digits = &rest[..rest.len() - format.suffix().len()];
        (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())).then_some(format)
    }

    /// The name in the settings.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Dnstap => "dnstap",
        }
    }
}

/// What the log keeps of the client (TGL-15).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientField {
    /// A keyed hash of the address under the key of the day (the default in every profile).
    #[default]
    Pseudonym,
    /// The address itself.
    Address,
    /// Nothing: no client field at all.
    Hidden,
}

impl ClientField {
    /// The name in the status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pseudonym => "pseudonym",
            Self::Address => "address",
            Self::Hidden => "hidden",
        }
    }
}

/// The settings of the file log (`[dns.log]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSettings {
    /// The directory of the segments.
    pub dir: PathBuf,
    /// The file format.
    pub format: LogFormat,
    /// Days a segment is kept.
    pub days: u32,
    /// Octets the directory may hold, in MiB.
    pub size_mb: u64,
    /// One query in `sample` is logged (1: every query).
    pub sample: u32,
    /// What is kept of the client.
    pub client: ClientField,
    /// The dnstap identity: the node's name.
    pub identity: String,
    /// The dnstap version: the Tenko version.
    pub version: String,
}

impl LogSettings {
    /// Settings with the defaults of the Home profile in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            format: LogFormat::Jsonl,
            days: 7,
            size_mb: 256,
            sample: 1,
            client: ClientField::Pseudonym,
            identity: String::new(),
            version: String::new(),
        }
    }

    /// The largest segment.
    pub(crate) fn segment_bytes(&self) -> u64 {
        (self.size_mb.saturating_mul(MIB) / 16).clamp(MIB, 8 * MIB)
    }
}

/// One line of the log, as written in JSON lines and as read back from either format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// When the query arrived.
    pub at: Timestamp,
    /// The client: its address, or its pseudonym (`p:` and hexadecimal digits); absent when
    /// the log keeps no client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
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
    #[serde(default)]
    pub cached: bool,
    /// Microseconds from arrival to answer.
    pub duration_micros: u32,
}

/// The counters and the state of a log, for `dns.stats` and the node status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogFigures {
    /// Entries written to a segment since the start.
    pub written: u64,
    /// Entries dropped since the start: a full ring or a failed write.
    pub dropped: u64,
    /// Batches that could not be written since the start.
    pub write_errors: u64,
    /// The kill switch is set: nothing is logged.
    pub stopped: bool,
    /// The file format.
    pub format: LogFormat,
    /// What is kept of the client.
    pub client: ClientField,
    /// One query in `sample` is logged.
    pub sample: u32,
    /// Days a segment is kept.
    pub days: u32,
    /// MiB the directory may hold.
    pub size_mb: u64,
}

/// The query log sink; see the module documentation.
pub struct FileLog {
    ring: Mutex<Ring>,
    sample: u64,
    seen: AtomicU64,
    dropped: AtomicU64,
    written: AtomicU64,
    write_errors: AtomicU64,
    stopped: AtomicBool,
    settings: LogSettings,
}

impl std::fmt::Debug for FileLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLog")
            .field("dir", &self.settings.dir)
            .field("sample", &self.sample)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .field("stopped", &self.stopped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl QueryLogSink for FileLog {
    fn record(&self, entry: &QueryLogEntry<'_>) {
        if self.stopped.load(Ordering::Relaxed) {
            return;
        }
        if self.sample > 1
            && !self
                .seen
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(self.sample)
        {
            return;
        }
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        if ring.push(entry) {
            return;
        }
        drop(ring);
        self.dropped.fetch_add(1, Ordering::Relaxed);
        DROPPED.inc();
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl FileLog {
    fn new(settings: LogSettings, capacity: usize) -> Self {
        let stopped = settings.dir.join(STOPPED_MARKER).exists();
        Self {
            ring: Mutex::new(Ring::new(capacity)),
            sample: u64::from(settings.sample.max(1)),
            seen: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            written: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            stopped: AtomicBool::new(stopped),
            settings,
        }
    }

    /// Lines written since the start.
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// The directory of the segments.
    pub fn dir(&self) -> &Path {
        &self.settings.dir
    }

    /// The settings the log runs with.
    pub fn settings(&self) -> &LogSettings {
        &self.settings
    }

    /// The kill switch is set.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Sets or clears the kill switch: a stopped log takes no entry from the query path.
    /// The state is kept as the marker file `stopped` in the log directory, so it survives
    /// a restart of the node until the log is started again.
    ///
    /// # Errors
    ///
    /// The marker cannot be written or removed; the state in memory is changed anyway.
    pub fn set_stopped(&self, stopped: bool) -> io::Result<()> {
        self.stopped.store(stopped, Ordering::Relaxed);
        let marker = self.settings.dir.join(STOPPED_MARKER);
        if stopped {
            fs::write(
                &marker,
                b"the query log was stopped through the node command dns.log.stop\n",
            )
        } else {
            match fs::remove_file(&marker) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            }
        }
    }

    /// The counters and the state.
    pub fn figures(&self) -> LogFigures {
        LogFigures {
            written: self.written(),
            dropped: self.dropped(),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            stopped: self.is_stopped(),
            format: self.settings.format,
            client: self.settings.client,
            sample: self.settings.sample.max(1),
            days: self.settings.days,
            size_mb: self.settings.size_mb,
        }
    }

    /// Counts a batch the writer could not write.
    fn lost(&self, entries: usize) {
        let entries = u64::try_from(entries).unwrap_or(u64::MAX);
        self.dropped.fetch_add(entries, Ordering::Relaxed);
        self.write_errors.fetch_add(1, Ordering::Relaxed);
        DROPPED.add(entries);
    }

    fn wrote(&self, entries: usize) {
        self.written.fetch_add(
            u64::try_from(entries).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

/// A sink and its settings, without a writer thread: for tests of the drain.
#[doc(hidden)]
pub fn detached(settings: LogSettings, capacity: usize) -> Arc<FileLog> {
    Arc::new(FileLog::new(settings, capacity))
}

/// The segment file names of a directory, unsorted.
pub(crate) fn segments(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if LogFormat::of_segment(name).is_some() {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// The microseconds in a segment's name: when it was opened.
pub(crate) fn segment_micros(name: &str) -> Option<u64> {
    let format = LogFormat::of_segment(name)?;
    name[SEGMENT_PREFIX.len()..name.len() - format.suffix().len()]
        .parse()
        .ok()
}

/// The UTC day of a time in microseconds since 1970.
pub(crate) const fn day_of(micros: u64) -> u64 {
    micros / 86_400_000_000
}

#[cfg(test)]
mod tests;
