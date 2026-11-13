//! The format version of a store data directory (OPS-23).
//!
//! A data directory records the version of its on-disk format in two places that must
//! agree:
//!
//! | Where | Written | Why |
//! |---|---|---|
//! | The marker file `format` beside `sm.current` | atomically (written aside, synced, renamed) | read before the store opens, so a binary that does not know a newer format refuses it without touching the redb files |
//! | The row `data` of the table `sys.format` inside the store | in the same write batch as each migration | replicated with the data and carried by snapshots and copies, so a snapshot or a restored state file says which format it holds |
//!
//! The format number and the migrations belong to the server binary (`tenko::upgrade`):
//! this module only reads and writes the two records and copies a closed store for a dry
//! run or a backup. A data directory created before format versions existed has neither
//! record; the binary treats it as format 1.
//!
//! The marker is a small text file:
//!
//! ```text
//! tenko-data-format 1
//! written-by 0.1.0
//! ```
//!
//! Only the first line counts; later lines are informational and unknown ones are
//! ignored, so a newer binary may add lines without breaking an older reader.

use std::{
    fmt,
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tenko_core::{Revision, table::TableDef};

use crate::{
    api::{ReadView, ReadViewExt as _, StoreError, WriteBatch},
    layout::{self, INITIAL_FILE, LOG_FILE, POINTER, SNAPSHOTS, sync_dir},
};

/// The marker file in the store directory.
pub const MARKER_FILE: &str = "format";

/// The marker while it is written; renamed over [`MARKER_FILE`] when complete.
pub const MARKER_PART: &str = "format.part";

/// The first word of the marker file.
const MARKER_MAGIC: &str = "tenko-data-format";

/// The table that holds the stored format record under the key `()`.
pub const TABLE: TableDef<(), StoredFormat> = TableDef::new("sys.format");

/// The format record of the marker file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The format version.
    pub version: u32,
    /// The version of the binary that wrote the marker (informational).
    pub written_by: String,
}

impl Marker {
    /// The marker of `version`, written by the binary `written_by`.
    pub fn new(version: u32, written_by: impl Into<String>) -> Self {
        Self {
            version,
            written_by: written_by.into(),
        }
    }

    /// The text of the marker file.
    pub fn encode(&self) -> String {
        format!(
            "{MARKER_MAGIC} {}\nwritten-by {}\n",
            self.version,
            self.written_by.trim()
        )
    }

    /// Reads the text of a marker file.
    ///
    /// # Errors
    ///
    /// The reason, when the first line is not `tenko-data-format <number>`.
    pub fn decode(text: &str) -> Result<Self, String> {
        let mut lines = text.lines().map(str::trim);
        let first = lines.next().unwrap_or_default();
        let version = first
            .strip_prefix(MARKER_MAGIC)
            .map(str::trim)
            .ok_or_else(|| format!("the first line is not `{MARKER_MAGIC} <number>`: {first:?}"))?;
        let version: u32 = version
            .parse()
            .map_err(|_| format!("`{version}` is not a format version"))?;
        if version == 0 {
            return Err("format version 0 does not exist".to_owned());
        }
        let written_by = lines
            .find_map(|line| line.strip_prefix("written-by "))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        Ok(Self {
            version,
            written_by,
        })
    }
}

/// The format record inside the store (table [`TABLE`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFormat {
    /// The format version.
    pub version: u32,
    /// The version of the binary that wrote the record (informational).
    #[serde(default)]
    pub written_by: String,
}

/// Why the format records of a data directory cannot be read or written.
#[derive(Debug)]
pub enum FormatError {
    /// A file operation failed.
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// The marker file exists but cannot be read as a marker.
    InvalidMarker {
        /// The marker file.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// A copy was asked into a directory that is not empty.
    TargetNotEmpty(PathBuf),
    /// The directory holds no store (no `log.redb` and no state file).
    NoStore(PathBuf),
    /// A process has the store open (a running server).
    InUse(PathBuf),
    /// The store refused a read or a write.
    Store(StoreError),
}

impl FormatError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    /// The stable code: `upgrade.io`, `upgrade.marker_invalid`, `upgrade.copy_target`,
    /// `upgrade.no_store`, `upgrade.in_use` or `upgrade.store`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "upgrade.io",
            Self::InvalidMarker { .. } => "upgrade.marker_invalid",
            Self::TargetNotEmpty(_) => "upgrade.copy_target",
            Self::NoStore(_) => "upgrade.no_store",
            Self::InUse(_) => "upgrade.in_use",
            Self::Store(_) => "upgrade.store",
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::InvalidMarker { path, reason } => write!(
                f,
                "the format marker {} cannot be read: {reason}",
                path.display()
            ),
            Self::TargetNotEmpty(path) => {
                write!(f, "{} exists and is not empty", path.display())
            }
            Self::NoStore(path) => write!(
                f,
                "{} holds no store (no log.redb and no state file)",
                path.display()
            ),
            Self::InUse(path) => write!(
                f,
                "{} is open in another process: stop the server before copying or checking its store",
                path.display()
            ),
            Self::Store(error) => write!(f, "the store refused the format record: {error}"),
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for FormatError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Whether `store_dir` holds a store: its Raft log, or a state file without a log (a copy
/// made with `RaftStore::copy_state_to`).
pub fn store_exists(store_dir: &Path) -> bool {
    store_dir.join(LOG_FILE).is_file()
        || store_dir.join(INITIAL_FILE).is_file()
        || store_dir.join(POINTER).is_file()
}

/// Reads the marker file of `store_dir`; `None` when there is none.
///
/// # Errors
///
/// [`FormatError::Io`] when the file exists but cannot be read,
/// [`FormatError::InvalidMarker`] when its content is not a marker.
pub fn read_marker(store_dir: &Path) -> Result<Option<Marker>, FormatError> {
    let path = store_dir.join(MARKER_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => Marker::decode(&text)
            .map(Some)
            .map_err(|reason| FormatError::InvalidMarker { path, reason }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(FormatError::io(&path, error)),
    }
}

/// Writes the marker file of `store_dir` atomically: written aside, synced and renamed
/// over the old marker, so a crash leaves the old or the new marker, never a torn one.
///
/// # Errors
///
/// [`FormatError::Io`] naming the file.
pub fn write_marker(store_dir: &Path, marker: &Marker) -> Result<(), FormatError> {
    fs::create_dir_all(store_dir).map_err(|error| FormatError::io(store_dir, error))?;
    let part = store_dir.join(MARKER_PART);
    {
        let mut file = File::create(&part).map_err(|error| FormatError::io(&part, error))?;
        file.write_all(marker.encode().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| FormatError::io(&part, error))?;
    }
    let target = store_dir.join(MARKER_FILE);
    fs::rename(&part, &target).map_err(|error| FormatError::io(&target, error))?;
    sync_dir(store_dir);
    Ok(())
}

/// Reads the stored format record and the revision that wrote it.
///
/// # Errors
///
/// The store's read error.
pub fn read_stored(view: &dyn ReadView) -> Result<Option<(StoredFormat, Revision)>, StoreError> {
    view.get_typed(&TABLE, &())
}

/// Stages the stored format record in `batch`, with a precondition that the record is
/// still the one at `expected` (`None`: absent), so two writers cannot both migrate.
///
/// # Errors
///
/// [`StoreError::Codec`] if the record cannot be encoded.
pub fn stage_stored(
    batch: &mut WriteBatch,
    expected: Option<Revision>,
    format: &StoredFormat,
) -> Result<(), StoreError> {
    batch.expect_typed(&TABLE, &(), expected);
    batch.put_typed(&TABLE, &(), format)?;
    Ok(())
}

/// What [`copy_closed_store`] copied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// The copied files, relative to the store directory, in copy order.
    pub files: Vec<String>,
    /// Bytes copied.
    pub bytes: u64,
}

/// Copies a store that no process has open from `from` into `to` (created; it must not
/// exist or must be empty): the Raft log, the state file that `sm.current` names (or
/// `sm.redb`) with its pointer, the snapshots and the marker. Every copied file is synced.
/// Never copy the files of an open store: redb files are only consistent when closed. The
/// log and the state file stay locked from the check to the end of the copy, so a server
/// that starts meanwhile cannot open the store until the copy is done: redb waits for the
/// lock on Windows and refuses the open as in use on Linux.
///
/// # Errors
///
/// [`FormatError::NoStore`] without a store ([`store_exists`]), [`FormatError::InUse`] while a process
/// has the store open, [`FormatError::TargetNotEmpty`], [`FormatError::InvalidMarker`] for a
/// pointer that names no state file, or the I/O error.
pub fn copy_closed_store(from: &Path, to: &Path) -> Result<CopyReport, FormatError> {
    let held = hold_closed(from)?;
    if fs::read_dir(to).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(FormatError::TargetNotEmpty(to.to_path_buf()));
    }
    fs::create_dir_all(to).map_err(|error| FormatError::io(to, error))?;
    let mut report = CopyReport::default();
    // Read through the locked handles: on Windows a lock also bars this process's other
    // handles from the file.
    for (name, file) in &held.files {
        report.bytes += copy_from(file, &from.join(name), &to.join(name))?;
        report.files.push(name.clone());
    }
    for name in [POINTER, MARKER_FILE] {
        if from.join(name).is_file() {
            report.bytes += copy_file(&from.join(name), &to.join(name))?;
            report.files.push(name.to_owned());
        }
    }
    let snapshots = from.join(SNAPSHOTS);
    if snapshots.is_dir() {
        let target = to.join(SNAPSHOTS);
        fs::create_dir_all(&target).map_err(|error| FormatError::io(&target, error))?;
        let entries =
            fs::read_dir(&snapshots).map_err(|error| FormatError::io(&snapshots, error))?;
        let mut files: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                !Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("part"))
            })
            .collect();
        files.sort();
        for name in files {
            report.bytes += copy_file(&snapshots.join(&name), &target.join(&name))?;
            report.files.push(format!("{SNAPSHOTS}/{name}"));
        }
        sync_dir(&target);
    }
    sync_dir(to);
    Ok(report)
}

/// Checks that no process has the store of `store_dir` open: redb holds a lock on its files
/// while a database is open (a whole-file lock on Linux, region locks on Windows), so an
/// exclusive lock attempt on the log and the state file fails while a server runs.
///
/// # Errors
///
/// [`FormatError::NoStore`] without a store ([`store_exists`]), [`FormatError::InUse`] naming the locked
/// file, or the I/O error of opening it.
pub fn ensure_closed(store_dir: &Path) -> Result<(), FormatError> {
    hold_closed(store_dir).map(drop)
}

/// The log and the state file of a closed store, each locked until this value drops.
struct Held {
    /// File names relative to the store directory, with their locked handles.
    files: Vec<(String, File)>,
}

/// Locks the log, then the state file the pointer names: once the log is locked no server
/// runs on the directory, so the pointer cannot move before the state file is locked too.
fn hold_closed(store_dir: &Path) -> Result<Held, FormatError> {
    if !store_exists(store_dir) {
        return Err(FormatError::NoStore(store_dir.to_path_buf()));
    }
    let mut files = Vec::new();
    if let Some(log) = lock_existing(&store_dir.join(LOG_FILE))? {
        files.push((LOG_FILE.to_owned(), log));
    }
    let state = active_state_file(store_dir)?;
    if let Some(file) = lock_existing(&store_dir.join(&state))? {
        files.push((state, file));
    }
    Ok(Held { files })
}

/// Opens and locks a file exclusively; `None` when it does not exist.
fn lock_existing(path: &Path) -> Result<Option<File>, FormatError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(FormatError::io(path, error)),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Err(FormatError::InUse(path.to_path_buf())),
        Err(fs::TryLockError::Error(error)) => Err(FormatError::io(path, error)),
    }
}

/// Compacts the log and the state file of a closed store in place (redb keeps the pages it
/// once allocated; this hands back the free ones). For files that are kept as they are,
/// such as the data-directory fixtures of the tests. Returns the bytes saved.
///
/// # Errors
///
/// [`FormatError::NoStore`], [`FormatError::InUse`], or the error of the database.
#[cfg(feature = "raft")]
pub fn compact_closed_store(store_dir: &Path) -> Result<u64, FormatError> {
    let held = hold_closed(store_dir)?;
    let names: Vec<String> = held.files.iter().map(|(name, _)| name.clone()).collect();
    drop(held);
    let size = |path: &Path| fs::metadata(path).map_or(0, |metadata| metadata.len());
    let mut saved = 0;
    for name in names {
        let path = store_dir.join(name);
        let before = size(&path);
        let mut database = redb::Database::open(&path)
            .map_err(|error| FormatError::io(&path, io::Error::other(error)))?;
        while database
            .compact()
            .map_err(|error| FormatError::io(&path, io::Error::other(error)))?
        {}
        drop(database);
        saved += before.saturating_sub(size(&path));
    }
    Ok(saved)
}

/// The total size of the files [`copy_closed_store`] would copy, for a free-space check.
///
/// # Errors
///
/// As [`copy_closed_store`].
pub fn closed_store_bytes(from: &Path) -> Result<u64, FormatError> {
    if !store_exists(from) {
        return Err(FormatError::NoStore(from.to_path_buf()));
    }
    let size = |path: &Path| fs::metadata(path).map_or(0, |metadata| metadata.len());
    let mut bytes = size(&from.join(LOG_FILE)) + size(&from.join(active_state_file(from)?));
    if let Ok(entries) = fs::read_dir(from.join(SNAPSHOTS)) {
        bytes += entries
            .filter_map(Result::ok)
            .map(|entry| entry.metadata().map_or(0, |metadata| metadata.len()))
            .sum::<u64>();
    }
    Ok(bytes)
}

/// The active state file of a store directory ([`layout::active_file`]).
fn active_state_file(dir: &Path) -> Result<String, FormatError> {
    layout::active_file(dir).map_err(|error| {
        let path = layout::pointer(dir);
        if error.kind() == io::ErrorKind::InvalidData {
            FormatError::InvalidMarker {
                path,
                reason: error.to_string(),
            }
        } else {
            FormatError::io(&path, error)
        }
    })
}

/// Copies one file and syncs the copy; returns its size.
fn copy_file(from: &Path, to: &Path) -> Result<u64, FormatError> {
    let file = File::open(from).map_err(|error| FormatError::io(from, error))?;
    copy_from(&file, from, to)
}

/// Copies the open file `source` (named `from`) to `to` with its permissions, before any
/// byte is written (the state file holds the vault's envelopes), and syncs the copy;
/// returns its size.
fn copy_from(mut source: &File, from: &Path, to: &Path) -> Result<u64, FormatError> {
    let permissions = source
        .metadata()
        .map_err(|error| FormatError::io(from, error))?
        .permissions();
    let mut target = File::create(to).map_err(|error| FormatError::io(to, error))?;
    target
        .set_permissions(permissions)
        .map_err(|error| FormatError::io(to, error))?;
    let bytes = io::copy(&mut source, &mut target).map_err(|error| FormatError::io(from, error))?;
    target
        .sync_all()
        .map_err(|error| FormatError::io(to, error))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tenko_core::{Principal, SystemComponent, Timestamp};

    use super::*;
    use crate::{MemStore, ReadConsistency, Store as _};

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-format-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn markers_round_trip_and_ignore_later_lines() {
        let marker = Marker::new(3, "0.4.0");
        assert_eq!(marker.encode(), "tenko-data-format 3\nwritten-by 0.4.0\n");
        assert_eq!(Marker::decode(&marker.encode()), Ok(marker));
        let newer = Marker::decode("tenko-data-format 7\r\nwritten-by 1.0.0\r\nchecksum abc\r\n")
            .expect("a newer marker with an extra line");
        assert_eq!(newer.version, 7);
        assert_eq!(newer.written_by, "1.0.0");
        assert_eq!(
            Marker::decode("tenko-data-format 2\n").expect("no writer"),
            Marker::new(2, "")
        );
    }

    #[test]
    fn invalid_markers_are_refused() {
        for text in [
            "",
            "format 1",
            "tenko-data-format",
            "tenko-data-format x",
            "tenko-data-format 0",
            "tenko-data-format -1",
        ] {
            assert!(Marker::decode(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn markers_are_written_atomically_and_read_back() {
        let dir = temp_dir("marker");
        assert!(read_marker(&dir).expect("no marker").is_none());
        write_marker(&dir, &Marker::new(1, "0.1.0")).expect("write");
        write_marker(&dir, &Marker::new(2, "0.2.0")).expect("overwrite");
        assert_eq!(
            read_marker(&dir).expect("read"),
            Some(Marker::new(2, "0.2.0"))
        );
        assert!(!dir.join(MARKER_PART).exists());
        fs::write(dir.join(MARKER_FILE), "garbage").expect("corrupt");
        let error = read_marker(&dir).expect_err("corrupt marker");
        assert_eq!(error.code(), "upgrade.marker_invalid");
        fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn the_stored_record_is_written_with_a_precondition() {
        let store = MemStore::default();
        let principal = Principal::system(SystemComponent::Store);
        assert!(
            read_stored(
                store
                    .read(ReadConsistency::Local)
                    .await
                    .expect("view")
                    .as_ref()
            )
            .expect("read")
            .is_none()
        );
        let mut batch = WriteBatch::new(principal.clone(), Timestamp::now());
        let first = StoredFormat {
            version: 1,
            written_by: "0.1.0".to_owned(),
        };
        stage_stored(&mut batch, None, &first).expect("stage");
        store.propose(batch).await.expect("first write");
        let (stored, revision) = read_stored(
            store
                .read(ReadConsistency::Local)
                .await
                .expect("view")
                .as_ref(),
        )
        .expect("read")
        .expect("present");
        assert_eq!(stored, first);
        // A second writer that still expects the record to be absent is refused.
        let mut stale = WriteBatch::new(principal.clone(), Timestamp::now());
        stage_stored(&mut stale, None, &first).expect("stage");
        assert!(store.propose(stale).await.is_err());
        let mut next = WriteBatch::new(principal, Timestamp::now());
        let second = StoredFormat {
            version: 2,
            written_by: "0.2.0".to_owned(),
        };
        stage_stored(&mut next, Some(revision), &second).expect("stage");
        store.propose(next).await.expect("bump");
        assert_eq!(
            read_stored(
                store
                    .read(ReadConsistency::Local)
                    .await
                    .expect("view")
                    .as_ref()
            )
            .expect("read")
            .map(|(stored, _)| stored),
            Some(second)
        );
    }

    #[test]
    fn closed_stores_are_copied_with_their_pointer_snapshots_and_marker() {
        let from = temp_dir("copy-from");
        fs::write(from.join("log.redb"), b"log").expect("log");
        fs::write(from.join("sm.redb"), b"stale initial state").expect("stale");
        fs::write(from.join("sm-1a-0.redb"), b"state").expect("state");
        fs::write(from.join("sm.current"), b"sm-1a-0.redb").expect("pointer");
        fs::create_dir_all(from.join("snapshots")).expect("snapshots");
        fs::write(from.join("snapshots/0001.snap"), b"snapshot").expect("snapshot");
        fs::write(from.join("snapshots/0002.snap.part"), b"partial").expect("partial");
        write_marker(&from, &Marker::new(1, "0.1.0")).expect("marker");
        assert_eq!(closed_store_bytes(&from).expect("size"), 3 + 5 + 8 + 7);

        let to = from.with_extension("copy");
        let _ = fs::remove_dir_all(&to);
        let report = copy_closed_store(&from, &to).expect("copy");
        assert_eq!(
            report.files,
            [
                "log.redb",
                "sm-1a-0.redb",
                "sm.current",
                "format",
                "snapshots/0001.snap"
            ]
        );
        assert_eq!(fs::read(to.join("sm-1a-0.redb")).expect("state"), b"state");
        assert!(!to.join("sm.redb").exists(), "only the active state file");
        assert!(!to.join("snapshots/0002.snap.part").exists());
        assert_eq!(
            read_marker(&to).expect("marker").map(|m| m.version),
            Some(1)
        );

        let again = copy_closed_store(&from, &to).expect_err("the target is not empty");
        assert_eq!(again.code(), "upgrade.copy_target");
        fs::remove_dir_all(&to).expect("clean up");
        fs::write(from.join("sm.current"), b"../escape.redb").expect("bad pointer");
        assert!(copy_closed_store(&from, &to).is_err());
        fs::remove_dir_all(&from).expect("clean up");
        let _ = fs::remove_dir_all(&to);
    }

    #[cfg(feature = "raft")]
    #[tokio::test]
    async fn an_open_store_is_in_use_and_a_closed_one_is_copied() {
        let dir = temp_dir("in-use");
        let mut config = crate::raft::RaftStoreConfig::new(dir.join("store"));
        config.fsync_probe_samples = 0;
        let store = crate::raft::RaftStore::open(config).await.expect("open");
        let error = ensure_closed(&dir.join("store")).expect_err("the store is open");
        assert_eq!(error.code(), "upgrade.in_use");
        store.shutdown().await.expect("shutdown");
        drop(store);
        ensure_closed(&dir.join("store")).expect("closed");
        let report = copy_closed_store(&dir.join("store"), &dir.join("copy")).expect("copy");
        assert!(report.files.contains(&"log.redb".to_owned()));
        let mut config = crate::raft::RaftStoreConfig::new(dir.join("copy"));
        config.fsync_probe_samples = 0;
        let copy = crate::raft::RaftStore::open(config)
            .await
            .expect("the copy opens");
        copy.shutdown().await.expect("shutdown");
        drop(copy);
        let _ = fs::remove_dir_all(&dir);
    }

    // The check that the store is closed and the copy are one step: while the copy holds the
    // store, a server that starts cannot open it (redb waits for the lock on Windows and
    // refuses the open on Linux), and once the copy is done it opens. A copy keeps the
    // permissions of the files it copies.
    #[cfg(feature = "raft")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_server_opens_the_store_while_a_copy_holds_it() {
        let dir = temp_dir("held");
        let open = || {
            let mut config = crate::raft::RaftStoreConfig::new(dir.join("store"));
            config.fsync_probe_samples = 0;
            crate::raft::RaftStore::open(config)
        };
        let store = open().await.expect("open");
        store.shutdown().await.expect("shutdown");
        drop(store);

        let held = hold_closed(&dir.join("store")).expect("the store is closed");
        let names: Vec<&str> = held.files.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["log.redb", "sm.redb"]);
        let mut starting = tokio::spawn(open());
        // test-lint: allow deadline a start that is held back passes on any machine; only one that opens the held store in time fails
        let early = tokio::time::timeout(std::time::Duration::from_secs(2), &mut starting).await;
        let waiting = match early {
            Err(_still_waiting) => true,
            Ok(started) => match started.expect("the start task") {
                Ok(_) => panic!("a server opened the store while the copy held it"),
                Err(StoreError::Storage(refused)) => {
                    assert!(refused.contains("already open"), "{refused}");
                    false
                }
                Err(other) => panic!("the start failed for another reason: {other}"),
            },
        };
        drop(held);
        let store = if waiting {
            starting.await.expect("the start task")
        } else {
            open().await
        }
        .expect("the store opens once the copy is done");
        store.shutdown().await.expect("shutdown");
        drop(store);

        let source = dir.join("store/sm.redb");
        let mut permissions = fs::metadata(&source).expect("metadata").permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&source, permissions).expect("read-only source");
        copy_closed_store(&dir.join("store"), &dir.join("copy")).expect("copy");
        assert!(
            fs::metadata(dir.join("copy/sm.redb"))
                .expect("copied")
                .permissions()
                .readonly(),
            "the copy keeps the permissions of its source"
        );
        for path in [source, dir.join("copy/sm.redb")] {
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            #[allow(
                clippy::permissions_set_readonly_false,
                reason = "the test removes its files"
            )]
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions).expect("writable again");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "raft")]
    #[tokio::test]
    async fn an_online_state_copy_opens_as_a_store_at_its_revision() {
        let dir = temp_dir("online-copy");
        let mut config = crate::raft::RaftStoreConfig::new(dir.join("store"));
        config.fsync_probe_samples = 0;
        let store = crate::raft::RaftStore::open(config).await.expect("open");
        let mut batch =
            WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now());
        stage_stored(
            &mut batch,
            None,
            &StoredFormat {
                version: 1,
                written_by: "test".to_owned(),
            },
        )
        .expect("stage");
        let committed = store.propose(batch).await.expect("write");
        let revision = store
            .copy_state_to(&dir.join("copy"))
            .await
            .expect("copy while running");
        assert_eq!(revision, committed.revision);
        assert!(
            store.copy_state_to(&dir.join("copy")).await.is_err(),
            "the target must be empty"
        );
        store.shutdown().await.expect("shutdown");
        drop(store);
        assert!(!dir.join("copy/log.redb").exists());
        let mut config = crate::raft::RaftStoreConfig::new(dir.join("copy"));
        config.fsync_probe_samples = 0;
        let copy = crate::raft::RaftStore::open(config)
            .await
            .expect("the copy opens without a log");
        let view = copy.read(ReadConsistency::Local).await.expect("view");
        assert_eq!(
            read_stored(view.as_ref())
                .expect("read")
                .map(|(stored, _)| stored.version),
            Some(1)
        );
        drop(view);
        // The copy accepts writes: it leads its own one-node cluster.
        let mut batch =
            WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now());
        stage_stored(
            &mut batch,
            Some(committed.revision),
            &StoredFormat {
                version: 2,
                written_by: "test".to_owned(),
            },
        )
        .expect("stage");
        copy.propose(batch).await.expect("write to the copy");
        copy.shutdown().await.expect("shutdown");
        drop(copy);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_directory_is_not_a_store() {
        let dir = temp_dir("empty");
        assert!(!store_exists(&dir));
        let error = copy_closed_store(&dir, &dir.join("copy")).expect_err("no store");
        assert_eq!(error.code(), "upgrade.no_store");
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
