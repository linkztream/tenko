//! The observation buffer of a probe (OPS-28).
//!
//! A probe collects observation batches on its network segment and sends them to the
//! controller. A site keeps working across controller outages, so the probe keeps every
//! batch on disk until the controller has confirmed it. The buffer survives restarts of the
//! node and of the controller, hands the batches back oldest first, and is bounded in size.
//!
//! The buffer is payload-agnostic. It stores opaque byte payloads (the caller encodes a
//! protobuf message), gives each one a sequence number within an epoch, and returns them in
//! sequence order. Exactly one consumer, the sender task, calls [`ObservationBuffer::peek`]
//! and [`ObservationBuffer::ack`]; any task may call [`ObservationBuffer::push`]. Delivery is
//! at least once: a batch peeked but not acknowledged before a restart is peeked again, and
//! the receiver is expected to ignore a repeated `(epoch, sequence)`.
//!
//! The API is synchronous and does blocking file I/O. Callers on an async runtime run it in
//! `tokio::task::spawn_blocking`. [`ObservationBuffer`] is cheap to clone, and every clone
//! shares the same state.
//!
//! # Layout
//!
//! Everything lives in the buffer directory ([`BufferConfig::dir`]):
//!
//! | Name | Contents |
//! |---|---|
//! | `epoch` | the epoch, a UUID as hyphenated text and a newline |
//! | `next` | the next sequence number as decimal text and a newline |
//! | `<sequence>.batch` | one batch; the sequence is 20 zero-padded decimal digits |
//! | `<sequence>.corrupt` | a batch that failed verification, set aside for inspection |
//! | `incoming/<name>.batch` | a raw payload dropped by another process |
//! | `incoming/<name>.rejected` | an incoming payload that is larger than the batch limit |
//!
//! Sequences start at 1 and are never reused, not even after every batch has been
//! acknowledged and the buffer has been reopened: `next` is rewritten after every push, and
//! at open the next sequence is the largest of the value in `next`, the highest batch
//! sequence plus one, and 1. The epoch is created with a UUIDv7 when the directory is first
//! opened. A receiver that sees a new epoch knows the numbering started over.
//!
//! # File format
//!
//! A batch file is a 44-byte header followed by the payload:
//!
//! | Offset | Size | Contents |
//! |---|---|---|
//! | 0 | 4 | the magic `TKB1` |
//! | 4 | 8 | the payload length, unsigned, big-endian |
//! | 12 | 32 | the SHA-256 digest of the payload |
//! | 44 | n | the payload |
//!
//! The size a batch counts for in the limits is the length of its file. Payloads dropped into
//! `incoming/` are raw, without a header: the adopting process adds it.
//!
//! Every file is written atomically: the data goes to `<final name>.tmp`, is synced to disk,
//! and is renamed onto the final name. A crash therefore leaves either the old file or the
//! new one, plus possibly a stray `.tmp` file, which the next [`ObservationBuffer::open`]
//! deletes. On Unix the directories are created with mode 0700 and the files with 0600.
//!
//! `open` reads only the names and sizes of the files. The contents are verified when a batch
//! reaches the head of the queue: a missing file is skipped, and a file whose magic, length
//! or digest does not match (a torn or damaged file) is renamed to `<sequence>.corrupt`,
//! counted, and skipped.
//!
//! # Ordering and eviction
//!
//! Batches are returned in ascending sequence order, which is the order of the pushes. The
//! buffer is bounded by [`BufferConfig::max_batches`] and [`BufferConfig::max_bytes`]. When a
//! push exceeds either limit, the oldest batches are deleted, never the one just written,
//! until both limits hold again. An evicted batch is lost; it is counted in
//! [`BufferStats::dropped`] and logged once per push. Dropping the oldest data keeps the most
//! recent picture of the segment, which is what a controller wants after an outage.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use uuid::Uuid;

/// The default limit for the total size of the batch files: 64 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The default limit for the number of buffered batches.
pub const DEFAULT_MAX_BATCHES: usize = 10_000;

/// The default limit for the size of one payload: 16 MiB.
pub const DEFAULT_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// The magic at the start of every batch file.
const MAGIC: [u8; 4] = *b"TKB1";

/// Size of a SHA-256 digest.
const DIGEST_LEN: usize = 32;

/// Size of the batch header: magic, payload length and SHA-256 digest.
const HEADER_LEN: usize = 4 + 8 + DIGEST_LEN;

/// Number of digits in the sequence part of a batch file name.
const SEQUENCE_DIGITS: usize = 20;

const EPOCH_FILE: &str = "epoch";
const NEXT_FILE: &str = "next";
const INCOMING_DIR: &str = "incoming";
const BATCH_EXT: &str = "batch";
const TMP_EXT: &str = "tmp";
const CORRUPT_EXT: &str = "corrupt";
const REJECTED_EXT: &str = "rejected";

/// A temporary file in `incoming/` younger than this may still be in the middle of a write.
const STALE_TMP_AGE: Duration = Duration::from_secs(60 * 60);

/// Settings of an [`ObservationBuffer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferConfig {
    /// The buffer directory. It is created when it does not exist.
    pub dir: PathBuf,
    /// The limit for the total size of the batch files, headers included.
    pub max_bytes: u64,
    /// The limit for the number of buffered batches.
    pub max_batches: usize,
    /// The largest payload [`ObservationBuffer::push`] accepts.
    pub max_batch_bytes: usize,
}

impl BufferConfig {
    /// Settings for the directory `dir` with the default limits.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            max_bytes: DEFAULT_MAX_BYTES,
            max_batches: DEFAULT_MAX_BATCHES,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
        }
    }

    /// Checks that the limits are usable.
    fn validate(&self) -> Result<(), BufferError> {
        if self.max_bytes == 0 {
            return Err(BufferError::Config {
                reason: "max_bytes must be greater than zero".to_owned(),
            });
        }
        if self.max_batches == 0 {
            return Err(BufferError::Config {
                reason: "max_batches must be greater than zero".to_owned(),
            });
        }
        if to_u64(self.max_batch_bytes) > self.max_bytes {
            return Err(BufferError::Config {
                reason: format!(
                    "max_batch_bytes ({}) must not be greater than max_bytes ({})",
                    self.max_batch_bytes, self.max_bytes
                ),
            });
        }
        Ok(())
    }
}

/// Errors of the observation buffer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BufferError {
    /// A file operation failed.
    #[error("observation buffer {path}: {reason}")]
    Io {
        /// The file or directory the operation was about.
        path: String,
        /// What the operating system said.
        reason: String,
    },
    /// A payload is larger than [`BufferConfig::max_batch_bytes`].
    #[error("an observation batch of {size} bytes is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The size of the payload.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The settings are not usable.
    #[error("invalid observation buffer settings: {reason}")]
    Config {
        /// Which setting is wrong and why.
        reason: String,
    },
}

impl tenko_core::Coded for BufferError {
    fn code(&self) -> &'static str {
        match self {
            BufferError::Io { .. } => "cluster.buffer.io",
            BufferError::TooLarge { .. } => "cluster.buffer.too_large",
            BufferError::Config { .. } => "cluster.buffer.config",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            BufferError::Io { .. } | BufferError::Config { .. } => 500,
            BufferError::TooLarge { .. } => 413,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            BufferError::Io { path, .. } => BTreeMap::from([("path", path.clone())]),
            BufferError::TooLarge { size, limit } => {
                BTreeMap::from([("size", size.to_string()), ("limit", limit.to_string())])
            }
            BufferError::Config { .. } => BTreeMap::new(),
        }
    }
}

/// The oldest buffered batch, as returned by [`ObservationBuffer::peek`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The sequence number of the batch within the epoch of the buffer.
    pub sequence: u64,
    /// The payload, as it was pushed.
    pub payload: Vec<u8>,
}

/// A snapshot of the state of an [`ObservationBuffer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferStats {
    /// The epoch of the buffer.
    pub epoch: Uuid,
    /// The number of buffered batches.
    pub batches: u64,
    /// The total size of the batch files, headers included.
    pub bytes: u64,
    /// The number of batches evicted since the buffer was opened.
    pub dropped: u64,
    /// The number of damaged batch files set aside since the buffer was opened.
    pub corrupt: u64,
    /// The sequence of the oldest buffered batch.
    pub oldest: Option<u64>,
    /// The sequence of the newest buffered batch.
    pub newest: Option<u64>,
}

/// A durable, size-bounded queue of observation batches. See the [module](self)
/// documentation.
#[derive(Clone)]
pub struct ObservationBuffer {
    inner: Arc<Inner>,
}

struct Inner {
    config: BufferConfig,
    epoch: Uuid,
    state: Mutex<State>,
    notify: Notify,
}

/// The in-memory index of the buffer directory.
struct State {
    /// Sequence to file size, oldest first.
    index: BTreeMap<u64, u64>,
    /// The sequence the next push gets.
    next: u64,
    /// The sum of the sizes in `index`.
    bytes: u64,
    dropped: u64,
    corrupt: u64,
}

impl State {
    fn insert(&mut self, sequence: u64, size: u64) {
        if let Some(previous) = self.index.insert(sequence, size) {
            self.bytes = self.bytes.saturating_sub(previous);
        }
        self.bytes = self.bytes.saturating_add(size);
    }

    fn remove(&mut self, sequence: u64) -> Option<u64> {
        let size = self.index.remove(&sequence)?;
        self.bytes = self.bytes.saturating_sub(size);
        Some(size)
    }

    fn oldest(&self) -> Option<u64> {
        self.index.keys().next().copied()
    }

    fn newest(&self) -> Option<u64> {
        self.index.keys().next_back().copied()
    }
}

impl fmt::Debug for ObservationBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservationBuffer")
            .field("dir", &self.inner.config.dir)
            .field("stats", &self.stats())
            .finish()
    }
}

impl ObservationBuffer {
    /// Opens the buffer in `config.dir`, creating the directory and the epoch when they do
    /// not exist.
    ///
    /// Stray temporary files from an interrupted write are deleted. An epoch file that cannot
    /// be read or is not a UUID is replaced by a new epoch; the batches are kept. The batch
    /// files are indexed by name and size only; their contents are verified by
    /// [`ObservationBuffer::peek`].
    ///
    /// # Errors
    ///
    /// [`BufferError::Config`] when the limits are unusable, [`BufferError::Io`] when the
    /// directory cannot be created, read or written.
    pub fn open(config: BufferConfig) -> Result<Self, BufferError> {
        config.validate()?;
        create_dir_private(&config.dir)?;
        remove_stray_tmp(&config.dir)?;
        let epoch = load_or_create_epoch(&config.dir)?;
        let index = scan_batches(&config.dir)?;
        let recorded = read_next(&config.dir);
        let after_highest = index
            .keys()
            .next_back()
            .map_or(0, |sequence| sequence.saturating_add(1));
        let next = recorded.max(after_highest).max(1);
        let bytes = index
            .values()
            .fold(0_u64, |total, size| total.saturating_add(*size));
        let state = State {
            index,
            next,
            bytes,
            dropped: 0,
            corrupt: 0,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                epoch,
                state: Mutex::new(state),
                notify: Notify::new(),
            }),
        })
    }

    /// The epoch of this buffer. It changes only when the epoch file is lost.
    pub fn epoch(&self) -> Uuid {
        self.inner.epoch
    }

    /// Appends a payload and returns its sequence number.
    ///
    /// When the buffer then exceeds [`BufferConfig::max_batches`] or
    /// [`BufferConfig::max_bytes`], the oldest batches are evicted, never the one just
    /// written. A push wakes a task waiting in [`ObservationBuffer::changed`].
    ///
    /// # Errors
    ///
    /// [`BufferError::TooLarge`] when the payload exceeds [`BufferConfig::max_batch_bytes`]
    /// (nothing is written), [`BufferError::Io`] when a file cannot be written.
    pub fn push(&self, payload: &[u8]) -> Result<u64, BufferError> {
        let sequence = {
            let mut state = self.lock();
            self.push_locked(&mut state, payload)?
        };
        self.inner.notify.notify_one();
        Ok(sequence)
    }

    /// Returns the oldest batch without removing it.
    ///
    /// A batch whose file has disappeared is dropped from the index. A batch whose file fails
    /// verification is renamed to `<sequence>.corrupt`, counted in [`BufferStats::corrupt`],
    /// and skipped. Returns `None` when no batch is left.
    ///
    /// # Errors
    ///
    /// [`BufferError::Io`] when the file of the oldest batch cannot be read.
    pub fn peek(&self) -> Result<Option<Pending>, BufferError> {
        let mut state = self.lock();
        while let Some(sequence) = state.oldest() {
            let path = self.batch_path(sequence);
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tracing::warn!(
                        path = %path.display(),
                        "an observation batch file is missing; it is skipped"
                    );
                    state.remove(sequence);
                    continue;
                }
                Err(error) => return Err(io_error(&path, &error)),
            };
            match decode(&bytes) {
                Ok(payload) => {
                    return Ok(Some(Pending {
                        sequence,
                        payload: payload.to_vec(),
                    }));
                }
                Err(reason) => {
                    set_aside(&path, reason);
                    state.corrupt = state.corrupt.saturating_add(1);
                    state.remove(sequence);
                }
            }
        }
        Ok(None)
    }

    /// Removes the batch with this sequence. A sequence that is not buffered (already
    /// acknowledged, evicted, or never used) is not an error.
    ///
    /// # Errors
    ///
    /// [`BufferError::Io`] when the file exists but cannot be deleted; the batch then stays
    /// buffered and the call can be repeated.
    pub fn ack(&self, sequence: u64) -> Result<(), BufferError> {
        let mut state = self.lock();
        if !state.index.contains_key(&sequence) {
            return Ok(());
        }
        remove_file_if_present(&self.batch_path(sequence))?;
        state.remove(sequence);
        Ok(())
    }

    /// A snapshot of the counters and the sequence range.
    pub fn stats(&self) -> BufferStats {
        let state = self.lock();
        BufferStats {
            epoch: self.inner.epoch,
            batches: to_u64(state.index.len()),
            bytes: state.bytes,
            dropped: state.dropped,
            corrupt: state.corrupt,
            oldest: state.oldest(),
            newest: state.newest(),
        }
    }

    /// Waits until a batch has been pushed or adopted since the last call.
    ///
    /// The wake-up is stored when nobody waits, so a push between a [`peek`](Self::peek) that
    /// found the buffer empty and the call to `changed` is not lost. Several pushes in a row
    /// count as one change; the consumer is expected to drain the buffer after each wake-up.
    pub async fn changed(&self) {
        self.inner.notify.notified().await;
    }

    /// Drops a payload into `<dir>/incoming` for the process that owns the buffer in `dir` to
    /// adopt with [`ObservationBuffer::adopt_incoming`]. Meant for a second process on the
    /// same host, such as a diagnostic command; it does not need an open buffer. Returns the
    /// path of the new file.
    ///
    /// # Errors
    ///
    /// [`BufferError::Io`] when the file cannot be written.
    pub fn drop_incoming(dir: &Path, payload: &[u8]) -> Result<PathBuf, BufferError> {
        let incoming = dir.join(INCOMING_DIR);
        create_dir_private(&incoming)?;
        let name = Uuid::now_v7().simple().to_string();
        let tmp = incoming.join(format!("{name}.{TMP_EXT}"));
        let target = incoming.join(format!("{name}.{BATCH_EXT}"));
        write_atomic(&tmp, &target, &[payload])?;
        Ok(target)
    }

    /// Adopts the payloads that other processes dropped into `incoming/`.
    ///
    /// The files are taken in the order of their names (a UUIDv7 name sorts by creation
    /// time), pushed like any other batch, so the limits and the eviction rule apply, and then
    /// deleted. A file larger than [`BufferConfig::max_batch_bytes`] is renamed to
    /// `<name>.rejected` and not counted. A `.tmp` file older than one hour is deleted; a
    /// younger one may still be written and is left alone. A crash between the push and the
    /// deletion adopts the file a second time. Returns the number of payloads adopted and
    /// wakes [`ObservationBuffer::changed`] when it is not zero.
    ///
    /// # Errors
    ///
    /// [`BufferError::Io`] when the directory cannot be read or a file cannot be read or
    /// pushed. Payloads adopted before the failure stay adopted.
    pub fn adopt_incoming(&self) -> Result<usize, BufferError> {
        let incoming = self.inner.config.dir.join(INCOMING_DIR);
        let entries = match fs::read_dir(&incoming) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(io_error(&incoming, &error)),
        };
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&incoming, &error))?;
            let path = entry.path();
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            match path.extension().and_then(|extension| extension.to_str()) {
                Some(BATCH_EXT) => files.push(path),
                Some(TMP_EXT) => remove_stale_tmp(&path),
                _ => {}
            }
        }
        files.sort();

        let mut adopted = 0;
        let mut failure = None;
        for path in &files {
            match self.adopt_file(path) {
                Ok(true) => adopted += 1,
                Ok(false) => {}
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if adopted > 0 {
            self.inner.notify.notify_one();
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(adopted),
        }
    }

    /// Adopts one incoming file. Returns whether it became a batch.
    fn adopt_file(&self, path: &Path) -> Result<bool, BufferError> {
        let limit = self.inner.config.max_batch_bytes;
        let size = match fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_error(path, &error)),
        };
        if size > to_u64(limit) {
            tracing::warn!(
                path = %path.display(),
                size,
                limit,
                "an incoming observation batch is larger than the limit; it was rejected"
            );
            fs::rename(path, path.with_extension(REJECTED_EXT))
                .map_err(|error| io_error(path, &error))?;
            return Ok(false);
        }
        let payload = match fs::read(path) {
            Ok(payload) => payload,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_error(path, &error)),
        };
        {
            let mut state = self.lock();
            self.push_locked(&mut state, &payload)?;
        }
        remove_file_if_present(path)?;
        Ok(true)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn batch_path(&self, sequence: u64) -> PathBuf {
        self.inner.config.dir.join(batch_file_name(sequence))
    }

    /// The body of a push, with the lock held.
    fn push_locked(&self, state: &mut State, payload: &[u8]) -> Result<u64, BufferError> {
        let config = &self.inner.config;
        if payload.len() > config.max_batch_bytes {
            return Err(BufferError::TooLarge {
                size: payload.len(),
                limit: config.max_batch_bytes,
            });
        }
        let sequence = state.next;
        let path = self.batch_path(sequence);
        write_atomic(&tmp_path(&path), &path, &[&encode_header(payload), payload])?;
        if let Err(error) = write_next(&config.dir, sequence.saturating_add(1)) {
            // Without the counter on disk the sequence could be handed out twice after a
            // restart, so the push fails as a whole.
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        state.next = sequence.saturating_add(1);
        state.insert(sequence, to_u64(HEADER_LEN + payload.len()));
        self.evict_locked(state, sequence);
        Ok(sequence)
    }

    /// Deletes the oldest batches while a limit is exceeded. The batch `keep` stays.
    fn evict_locked(&self, state: &mut State, keep: u64) {
        let config = &self.inner.config;
        let mut evicted = 0_u64;
        while state.index.len() > config.max_batches || state.bytes > config.max_bytes {
            let Some(oldest) = state.oldest().filter(|oldest| *oldest != keep) else {
                break;
            };
            state.remove(oldest);
            if let Err(error) = remove_file_if_present(&self.batch_path(oldest)) {
                tracing::warn!(%error, "an evicted observation batch could not be deleted");
            }
            evicted += 1;
        }
        if evicted > 0 {
            state.dropped = state.dropped.saturating_add(evicted);
            tracing::warn!(
                evicted,
                dir = %config.dir.display(),
                "the observation buffer is full; the oldest batches were dropped"
            );
        }
    }
}

/// Renames a damaged batch file to `<sequence>.corrupt`.
fn set_aside(path: &Path, reason: &str) {
    let aside = path.with_extension(CORRUPT_EXT);
    match fs::rename(path, &aside) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            moved_to = %aside.display(),
            reason,
            "an observation batch is damaged; it was set aside"
        ),
        Err(error) => tracing::warn!(
            path = %path.display(),
            reason,
            %error,
            "an observation batch is damaged and could not be set aside; it is skipped"
        ),
    }
}

/// Reads or creates the epoch.
fn load_or_create_epoch(dir: &Path) -> Result<Uuid, BufferError> {
    let path = dir.join(EPOCH_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => match Uuid::parse_str(text.trim()) {
            Ok(epoch) => return Ok(epoch),
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "the observation buffer epoch is not a UUID; a new epoch is started"
            ),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            path = %path.display(),
            %error,
            "the observation buffer epoch cannot be read; a new epoch is started"
        ),
    }
    let epoch = Uuid::now_v7();
    let text = format!("{}\n", epoch.hyphenated());
    write_atomic(&tmp_path(&path), &path, &[text.as_bytes()])?;
    Ok(epoch)
}

/// Reads the persisted next sequence. A missing or unreadable file counts as zero: the
/// batch files then decide.
fn read_next(dir: &Path) -> u64 {
    let path = dir.join(NEXT_FILE);
    let Ok(text) = fs::read_to_string(&path) else {
        return 0;
    };
    text.trim().parse().unwrap_or_else(|_| {
        tracing::warn!(
            path = %path.display(),
            "the next-sequence file is not a number; it is ignored"
        );
        0
    })
}

fn write_next(dir: &Path, next: u64) -> Result<(), BufferError> {
    let path = dir.join(NEXT_FILE);
    let text = format!("{next}\n");
    write_atomic(&tmp_path(&path), &path, &[text.as_bytes()])
}

/// Deletes the stray `*.tmp` files of an interrupted write in the buffer directory.
fn remove_stray_tmp(dir: &Path) -> Result<(), BufferError> {
    let entries = fs::read_dir(dir).map_err(|error| io_error(dir, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(dir, &error))?;
        let path = entry.path();
        let is_tmp = path
            .extension()
            .is_some_and(|extension| extension == TMP_EXT);
        if is_tmp
            && entry.file_type().is_ok_and(|kind| kind.is_file())
            && let Err(error) = remove_file_if_present(&path)
        {
            tracing::warn!(%error, "a stray temporary file could not be deleted");
        }
    }
    Ok(())
}

/// Deletes an incoming `.tmp` file that is old enough to be abandoned.
fn remove_stale_tmp(path: &Path) {
    let age = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    if age.is_some_and(|age| age > STALE_TMP_AGE)
        && let Err(error) = remove_file_if_present(path)
    {
        tracing::warn!(%error, "a stale incoming temporary file could not be deleted");
    }
}

/// Lists the batch files of the directory as sequence to size.
fn scan_batches(dir: &Path) -> Result<BTreeMap<u64, u64>, BufferError> {
    let mut index = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|error| io_error(dir, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(dir, &error))?;
        let name = entry.file_name();
        let Some(sequence) = name.to_str().and_then(parse_batch_file_name) else {
            continue;
        };
        let metadata = entry
            .metadata()
            .map_err(|error| io_error(&entry.path(), &error))?;
        if metadata.is_file() {
            index.insert(sequence, metadata.len());
        }
    }
    Ok(index)
}

/// The file name of a batch: 20 zero-padded decimal digits and `.batch`.
fn batch_file_name(sequence: u64) -> String {
    format!("{sequence:0SEQUENCE_DIGITS$}.{BATCH_EXT}")
}

/// The sequence of a batch file name, or `None` for any other name.
fn parse_batch_file_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".batch")?;
    if digits.len() != SEQUENCE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The header of a batch file: magic, payload length and SHA-256 digest of the payload.
fn encode_header(payload: &[u8]) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..12].copy_from_slice(&to_u64(payload.len()).to_be_bytes());
    header[12..].copy_from_slice(digest(payload).as_ref());
    header
}

/// Checks the header of a batch file and returns the payload, or says what is wrong.
fn decode(bytes: &[u8]) -> Result<&[u8], &'static str> {
    let Some((header, payload)) = bytes.split_at_checked(HEADER_LEN) else {
        return Err("the file is shorter than the header");
    };
    if header[..4] != MAGIC {
        return Err("the magic does not match");
    }
    let mut length = [0_u8; 8];
    length.copy_from_slice(&header[4..12]);
    if u64::from_be_bytes(length) != to_u64(payload.len()) {
        return Err("the payload length does not match the file");
    }
    let expected = digest(payload);
    if header[12..] != *expected.as_ref() {
        return Err("the payload digest does not match");
    }
    Ok(payload)
}

fn digest(payload: &[u8]) -> aws_lc_rs::digest::Digest {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, payload)
}

/// `<path>.tmp`: the temporary name of a file that is written atomically.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".");
    name.push(TMP_EXT);
    PathBuf::from(name)
}

/// Writes `parts` to `tmp`, syncs the file, and renames it onto `target`.
fn write_atomic(tmp: &Path, target: &Path, parts: &[&[u8]]) -> Result<(), BufferError> {
    write_then_rename(tmp, target, parts).map_err(|error| {
        let _ = fs::remove_file(tmp);
        io_error(target, &error)
    })
}

fn write_then_rename(tmp: &Path, target: &Path, parts: &[&[u8]]) -> io::Result<()> {
    let mut file = create_file_private(tmp)?;
    for part in parts {
        file.write_all(part)?;
    }
    file.sync_all()?;
    // The file must be closed before the rename: Windows refuses to move an open file.
    drop(file);
    fs::rename(tmp, target)
}

fn remove_file_if_present(path: &Path) -> Result<(), BufferError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, &error)),
    }
}

#[cfg(unix)]
fn create_dir_private(path: &Path) -> Result<(), BufferError> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| io_error(path, &error))
}

#[cfg(not(unix))]
fn create_dir_private(path: &Path) -> Result<(), BufferError> {
    fs::create_dir_all(path).map_err(|error| io_error(path, &error))
}

#[cfg(unix)]
fn create_file_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_file_private(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

fn io_error(path: &Path, error: &io::Error) -> BufferError {
    BufferError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// A length as `u64`. A `usize` always fits on the supported targets.
fn to_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_is_magic_length_digest() {
        let payload = b"example payload";
        let header = encode_header(payload);
        assert_eq!(header.len(), 44);
        assert_eq!(&header[..4], b"TKB1");
        assert_eq!(&header[4..12], &15_u64.to_be_bytes());
        assert_eq!(&header[12..], digest(payload).as_ref());
    }

    #[test]
    fn header_of_an_empty_payload() {
        let header = encode_header(b"");
        assert_eq!(&header[4..12], &[0; 8]);
        // The first bytes of the SHA-256 digest of the empty input.
        assert_eq!(&header[12..16], &[0xe3, 0xb0, 0xc4, 0x42]);
    }

    #[test]
    fn decode_returns_the_payload() {
        let payload = b"example payload";
        let mut file = encode_header(payload).to_vec();
        file.extend_from_slice(payload);
        assert_eq!(decode(&file), Ok(&payload[..]));

        let empty = encode_header(b"").to_vec();
        assert_eq!(decode(&empty), Ok(&b""[..]));
    }

    #[test]
    fn decode_rejects_damaged_files() {
        let payload = b"example payload";
        let mut good = encode_header(payload).to_vec();
        good.extend_from_slice(payload);

        assert!(decode(&[]).is_err());
        assert!(decode(&good[..HEADER_LEN - 1]).is_err());
        assert!(
            decode(&good[..HEADER_LEN]).is_err(),
            "header without payload"
        );
        assert!(
            decode(&good[..good.len() - 1]).is_err(),
            "truncated payload"
        );

        let mut extended = good.clone();
        extended.push(0);
        assert!(decode(&extended).is_err(), "trailing byte");

        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(decode(&magic).is_err());

        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 0x01;
        assert!(decode(&flipped).is_err());

        let mut digest_flipped = good;
        digest_flipped[20] ^= 0x01;
        assert!(decode(&digest_flipped).is_err());
    }

    #[test]
    fn batch_file_names_are_zero_padded() {
        assert_eq!(batch_file_name(1), "00000000000000000001.batch");
        assert_eq!(batch_file_name(1234), "00000000000000001234.batch");
        assert_eq!(batch_file_name(u64::MAX), "18446744073709551615.batch");
    }

    #[test]
    fn batch_file_names_sort_by_sequence() {
        let mut names: Vec<String> = [100, 9, 10, 1].into_iter().map(batch_file_name).collect();
        names.sort();
        let parsed: Vec<u64> = names
            .iter()
            .filter_map(|name| parse_batch_file_name(name))
            .collect();
        assert_eq!(parsed, [1, 9, 10, 100]);
    }

    #[test]
    fn batch_file_names_parse_back() {
        for sequence in [0, 1, 42, 1_000_000, u64::MAX] {
            assert_eq!(
                parse_batch_file_name(&batch_file_name(sequence)),
                Some(sequence)
            );
        }
    }

    #[test]
    fn other_names_are_not_batches() {
        for name in [
            "1.batch",
            "00000000000000000001",
            "00000000000000000001.tmp",
            "00000000000000000001.batch.tmp",
            "00000000000000000001.corrupt",
            "0000000000000000000a.batch",
            "000000000000000000001.batch",
            "+0000000000000000001.batch",
            "99999999999999999999.batch",
            "epoch",
            "next",
            ".batch",
            "",
        ] {
            assert_eq!(parse_batch_file_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn tmp_path_appends_the_extension() {
        assert_eq!(
            tmp_path(Path::new("dir/00000000000000000001.batch")),
            Path::new("dir/00000000000000000001.batch.tmp")
        );
        assert_eq!(tmp_path(Path::new("dir/epoch")), Path::new("dir/epoch.tmp"));
    }

    #[test]
    fn config_defaults() {
        let config = BufferConfig::new("buffer-dir");
        assert_eq!(config.dir, Path::new("buffer-dir"));
        assert_eq!(config.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(config.max_batches, DEFAULT_MAX_BATCHES);
        assert_eq!(config.max_batch_bytes, DEFAULT_MAX_BATCH_BYTES);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn state_tracks_the_byte_total() {
        let mut state = State {
            index: BTreeMap::new(),
            next: 1,
            bytes: 0,
            dropped: 0,
            corrupt: 0,
        };
        state.insert(1, 100);
        state.insert(2, 50);
        assert_eq!(state.bytes, 150);
        assert_eq!(state.oldest(), Some(1));
        assert_eq!(state.newest(), Some(2));
        assert_eq!(state.remove(1), Some(100));
        assert_eq!(state.remove(1), None);
        assert_eq!(state.bytes, 50);
        assert_eq!(state.oldest(), Some(2));
    }

    #[test]
    fn the_buffer_can_move_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ObservationBuffer>();
        assert_send_sync::<BufferError>();
        assert_send_sync::<BufferStats>();
    }
}
