//! Writing a backup (ADR 0016 item 4): a state copy opened as a scratch store, its digest
//! and snapshot, the key generations of the ring, the imported TLS files and the
//! configuration, written as one `TKBK1` file.
//!
//! The live store is only asked for a state copy ([`RaftStore::copy_state_to`]); a stopped
//! store is copied file by file ([`format::copy_closed_store`]). Either copy is opened as a
//! scratch store in a work directory beside the target, so the snapshot that goes into the
//! backup never touches the live store's log or snapshot rotation. The work directory is
//! created by this process alone (mode 0700 on Unix, never an existing path, so no link
//! planted under its name is followed), is removed whatever the outcome, and the backup
//! appears under its final name only once it is complete and synced. The SHA-256 of the
//! finished file and the archive id of its header are part of [`Created`], so that the
//! record and the audit record of a backup name the file beyond its name.
//!
//! An offline backup (`tenko backup create --config …`) runs as the account that owns the
//! data directory; `main` refuses it as root over another account's files
//! ([`crate::exec`], ADR 0023).

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Cursor},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};
use tenko_auth::encoding::hex_encode;
use tenko_core::{NodeId, Timestamp};
use tenko_store::{
    ReadConsistency, ReadViewExt as _, Store as _, format,
    raft::{RaftStore, RaftStoreConfig},
};
use tenko_vault::{KekRing, transfer::TransferredKek};
use zeroize::Zeroizing;

use super::{
    BackupError,
    archive::{
        self, DigestRecord, FORMAT, KdfParams, KekRecord, Lock, Manifest, OriginRecord,
        PART_CONFIG, PART_KEKS, PART_LEASES, PART_SNAPSHOT, PART_TLS_CERT, PART_TLS_KEY,
        PartSource, SnapshotRecord,
    },
};

/// The extension of a backup file.
pub const EXTENSION: &str = "tkbk";

/// The name prefix of backup files; the keep count of the schedule only ever deletes files
/// with this prefix and [`EXTENSION`].
pub const PREFIX: &str = "tenko-backup-";

/// Where the backup goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Into this directory under a generated name.
    Dir(PathBuf),
    /// Exactly this file (it must not exist).
    File(PathBuf),
}

/// What to put into a backup besides the store and the key generations.
#[derive(Debug, Clone, Default)]
pub struct Extras {
    /// The imported certificate chain and key of TLS mode b.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// The configuration file.
    pub config: Option<PathBuf>,
}

/// A key a backup is wrapped to.
pub enum KeyLock {
    /// A passphrase (checked with [`super::keys::check_passphrase`] by the caller).
    Passphrase(Zeroizing<String>),
    /// A recipient.
    Recipient(super::keys::Recipient),
}

impl std::fmt::Debug for KeyLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Passphrase"),
            Self::Recipient(recipient) => write!(f, "Recipient({recipient})"),
        }
    }
}

/// A request to write a backup.
#[derive(Debug)]
pub struct Request {
    /// The keys to wrap the backup to.
    pub locks: Vec<KeyLock>,
    /// The Argon2id parameters of passphrase slots ([`KdfParams::HARDENED`]).
    pub kdf: KdfParams,
    /// Who asked and why.
    pub origin: OriginRecord,
    /// The extra parts.
    pub extras: Extras,
    /// Where to write.
    pub target: Target,
}

/// A backup that was written.
#[derive(Debug, Clone)]
pub struct Created {
    /// The file.
    pub path: PathBuf,
    /// Its size.
    pub bytes: u64,
    /// The archive id of its header, as hex.
    pub archive_id: String,
    /// The SHA-256 of the whole file, as hex.
    pub sha256: String,
    /// Its manifest.
    pub manifest: Manifest,
    /// How long it took.
    pub duration: Duration,
}

impl Created {
    /// The file name.
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// The file name of a backup made at `at` on `node`: `tenko-backup-<UTC>-n<node>.tkbk`.
pub fn file_name(at: Timestamp, node: NodeId) -> String {
    let time = at.0;
    format!(
        "{PREFIX}{:04}{:02}{:02}T{:02}{:02}{:02}Z-n{}.{EXTENSION}",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        node.0
    )
}

/// `dir/name`, or with `-2`, `-3`, … before the extension when two backups of one node fall
/// into the same second.
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let stem = name.strip_suffix(&format!(".{EXTENSION}")).unwrap_or(name);
    (2..100)
        .map(|n| dir.join(format!("{stem}-{n}.{EXTENSION}")))
        .find(|path| !path.exists())
        .unwrap_or(first)
}

/// Whether `name` is a backup file name this module writes.
pub fn is_backup_name(name: &str) -> bool {
    name.starts_with(PREFIX)
        && Path::new(name)
            .extension()
            .is_some_and(|extension| extension == EXTENSION)
}

/// Removes a directory tree when dropped.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn work_dir(parent: &Path) -> Result<WorkDir, BackupError> {
    let dir = parent.join(format!(
        ".tenko-backup-work-{}",
        uuid::Uuid::now_v7().simple()
    ));
    create_private_dir(&dir)?;
    Ok(WorkDir(dir))
}

/// Creates `dir` for this process alone: one component, mode 0700 on Unix, and never an
/// existing path (a link or a directory already there fails with `AlreadyExists`, so
/// nothing planted under the name is followed).
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), BackupError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|error| BackupError::io(dir, error))
}

/// Opens `path` as a new file for writing, mode 0600 on Unix; an existing path, a link
/// included, fails with `AlreadyExists`.
pub(crate) fn create_private_file(path: &Path) -> Result<File, BackupError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| BackupError::io(path, error))
}

/// Refuses a path that exists and is a symbolic link; `Ok(true)` for an existing directory,
/// `Ok(false)` for nothing there.
pub(crate) fn existing_dir_not_link(path: &Path) -> Result<bool, BackupError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BackupError::io(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the path is a symbolic link; refusing to follow it",
            ),
        )),
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(BackupError::io(
            path,
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "the path is a file"),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(BackupError::io(path, error)),
    }
}

fn target_parent(target: &Target) -> PathBuf {
    match target {
        Target::Dir(dir) => dir.clone(),
        Target::File(file) => file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
    }
}

/// Writes a backup of a running store.
///
/// # Errors
///
/// A [`BackupError`]; nothing is left behind.
pub async fn from_live(
    store: &RaftStore,
    ring: &KekRing,
    request: Request,
) -> Result<Created, BackupError> {
    let started = Instant::now();
    let parent = target_parent(&request.target);
    fs::create_dir_all(&parent).map_err(|error| BackupError::io(&parent, error))?;
    let work = work_dir(&parent)?;
    let copy = work.0.join("store");
    store.copy_state_to(&copy).await?;
    from_copy(&work, &copy, store.node_id(), ring, request, started).await
}

/// Writes a backup of a stopped store in `store_dir` that belongs to `node`.
///
/// # Errors
///
/// [`BackupError::InUse`] while a server has the store open, or another [`BackupError`];
/// nothing is left behind.
pub async fn from_closed(
    store_dir: &Path,
    node: NodeId,
    ring: &KekRing,
    request: Request,
) -> Result<Created, BackupError> {
    let started = Instant::now();
    let parent = target_parent(&request.target);
    fs::create_dir_all(&parent).map_err(|error| BackupError::io(&parent, error))?;
    let work = work_dir(&parent)?;
    let copy = work.0.join("store");
    let from = store_dir.to_path_buf();
    let to = copy.clone();
    tokio::task::spawn_blocking(move || format::copy_closed_store(&from, &to))
        .await
        .map_err(|error| BackupError::Internal(error.to_string()))?
        .map_err(|error| match error {
            format::FormatError::InUse { .. } => BackupError::InUse(store_dir.to_path_buf()),
            other => BackupError::Internal(other.to_string()),
        })?;
    from_copy(&work, &copy, node, ring, request, started).await
}

/// The configuration of a scratch store over a copy.
pub(crate) fn scratch_config(dir: &Path, node: NodeId, full_audit: bool) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.node_id = node;
    config.bootstrap = false;
    config.fsync_probe_samples = 0;
    config.verify_full_audit_chain = full_audit;
    config.durability = tenko_store::raft::SmDurability::Deferred {
        checkpoint_interval: Duration::from_secs(1),
    };
    config
}

/// The SHA-256 of the internal CA root in `view`, as hex.
pub(crate) fn ca_fingerprint(
    view: &dyn tenko_store::ReadView,
) -> Result<Option<String>, BackupError> {
    let Some((record, _)) = view.get_typed(&tenko_cluster::ca::tables::CA, &())? else {
        return Ok(None);
    };
    let der = CertificateDer::from_pem_slice(record.cert_pem.as_bytes())
        .map_err(|error| BackupError::check("CA root", error))?;
    Ok(Some(hex_encode(&Sha256::digest(der.as_ref()))))
}

/// The data format the store records (format 1 without a record).
pub(crate) fn stored_format(view: &dyn tenko_store::ReadView) -> Result<u32, BackupError> {
    Ok(format::read_stored(view)?.map_or(1, |(stored, _)| stored.version))
}

/// The generations of `ring`, oldest first and the active one last, with their material.
fn export_ring(ring: &KekRing) -> Result<Vec<TransferredKek>, BackupError> {
    let active = ring.active();
    ring.generations()
        .filter(|kek| kek.id() != active.id())
        .chain(std::iter::once(active))
        .map(|kek| {
            kek.export_material()
                .map(|material| TransferredKek {
                    id: kek.id().to_owned(),
                    material,
                })
                .ok_or_else(|| {
                    BackupError::Internal(format!(
                        "the key generation {} cannot leave its provider",
                        kek.id()
                    ))
                })
        })
        .collect()
}

fn read_extra(path: &Path) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|error| BackupError::io(path, error))
}

async fn from_copy(
    work: &WorkDir,
    copy: &Path,
    node: NodeId,
    ring: &KekRing,
    request: Request,
    started: Instant,
) -> Result<Created, BackupError> {
    let scratch = RaftStore::open(scratch_config(copy, node, false)).await?;
    let described = describe(&scratch, &work.0).await;
    let _ = scratch.shutdown().await;
    drop(scratch);
    let (state, snapshot_file) = described?;

    let generations = export_ring(ring)?;
    let keks = archive::encode_keks(&generations)?;
    drop(generations);
    let tls = match &request.extras.tls {
        Some((cert, key)) => Some((read_extra(cert)?, read_extra(key)?)),
        None => None,
    };
    let config = match &request.extras.config {
        Some(path) => Some(read_extra(path)?),
        None => None,
    };
    let contents = Contents {
        snapshot: snapshot_file,
        keks,
        tls,
        config,
    };
    let created_at = Timestamp::now();
    let manifest = Manifest {
        format: FORMAT.to_owned(),
        created_at,
        tenko_version: crate::version().to_owned(),
        data_format: state.data_format,
        node: node.0,
        voters: state.voters,
        revision: state.digest.revision,
        audit_head: state.audit_head,
        digest: state.digest,
        ca_fingerprint: state.ca_fingerprint,
        snapshot: state.snapshot,
        kek: kek_record(ring),
        parts: contents.entries()?,
        origin: request.origin.clone(),
    };
    let path = match &request.target {
        Target::Dir(dir) => free_name(dir, &file_name(created_at, node)),
        Target::File(file) => file.clone(),
    };
    if path.exists() {
        return Err(BackupError::io(
            &path,
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "the file exists"),
        ));
    }
    // Argon2 and the encryption are CPU work and the writes block: off the async workers.
    let locks = request.locks;
    let kdf = request.kdf;
    let target = path.clone();
    let written_manifest = manifest.clone();
    let (archive_id, sha256) = tokio::task::spawn_blocking(move || {
        write_file(&target, &locks, kdf, &written_manifest, &contents)
    })
    .await
    .map_err(|error| BackupError::Internal(error.to_string()))??;
    let bytes = fs::metadata(&path)
        .map_err(|error| BackupError::io(&path, error))?
        .len();
    Ok(Created {
        path,
        bytes,
        archive_id: hex_encode(&archive_id),
        sha256: hex_encode(&sha256),
        manifest,
        duration: started.elapsed(),
    })
}

/// A writer that hashes everything written through it.
struct Sha256Writer<W: std::io::Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: std::io::Write> std::io::Write for Sha256Writer<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(data)?;
        self.hasher.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The key generation identifiers of `ring`, oldest first and the active one last.
fn kek_record(ring: &KekRing) -> KekRecord {
    let active = ring.active().id().to_owned();
    KekRecord {
        generations: ring
            .generations()
            .filter(|kek| kek.id() != active)
            .map(|kek| kek.id().to_owned())
            .chain(std::iter::once(active.clone()))
            .collect(),
        active,
    }
}

/// Bytes that are wiped when dropped.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

/// The imported certificate chain and key of TLS mode b.
pub(crate) type TlsPair = (Secret, Secret);

/// The parts of a backup, ready to be written.
struct Contents {
    snapshot: PathBuf,
    keks: Zeroizing<Vec<u8>>,
    tls: Option<TlsPair>,
    config: Option<Secret>,
}

impl Contents {
    /// The manifest entries, in stream order.
    fn entries(&self) -> Result<Vec<archive::PartEntry>, BackupError> {
        let mut entries = vec![archive::entry_of_file(PART_SNAPSHOT, &self.snapshot)?];
        entries.push(archive::entry_of(PART_KEKS, &self.keks));
        if let Some((cert, key)) = &self.tls {
            entries.push(archive::entry_of(PART_TLS_CERT, cert));
            entries.push(archive::entry_of(PART_TLS_KEY, key));
        }
        if let Some(config) = &self.config {
            entries.push(archive::entry_of(PART_CONFIG, config));
        }
        entries.push(archive::entry_of(PART_LEASES, &[]));
        Ok(entries)
    }

    /// Readers of the parts, in the order of [`Contents::entries`].
    fn readers(&self) -> Result<Vec<Box<dyn std::io::Read + '_>>, BackupError> {
        let snapshot = BufReader::new(
            File::open(&self.snapshot).map_err(|error| BackupError::io(&self.snapshot, error))?,
        );
        let mut readers: Vec<Box<dyn std::io::Read + '_>> = vec![
            Box::new(snapshot),
            Box::new(Cursor::new(self.keks.as_slice())),
        ];
        if let Some((cert, key)) = &self.tls {
            readers.push(Box::new(Cursor::new(cert.as_slice())));
            readers.push(Box::new(Cursor::new(key.as_slice())));
        }
        if let Some(config) = &self.config {
            readers.push(Box::new(Cursor::new(config.as_slice())));
        }
        readers.push(Box::new(std::io::empty()));
        Ok(readers)
    }
}

/// Writes the file under a `.part` name, syncs it and renames it to `path`; returns the
/// archive id of the header and the SHA-256 of the file.
fn write_file(
    path: &Path,
    locks: &[KeyLock],
    kdf: KdfParams,
    manifest: &Manifest,
    contents: &Contents,
) -> Result<(archive::ArchiveId, [u8; 32]), BackupError> {
    let locks: Vec<Lock<'_>> = locks
        .iter()
        .map(|lock| match lock {
            KeyLock::Passphrase(passphrase) => Lock::Passphrase(passphrase.as_str(), kdf),
            KeyLock::Recipient(recipient) => Lock::Recipient(*recipient),
        })
        .collect();
    let sources: Vec<PartSource<'_>> = manifest
        .parts
        .iter()
        .cloned()
        .zip(contents.readers()?)
        .map(|(entry, reader)| PartSource { entry, reader })
        .collect();
    let part = path.with_extension(format!("{EXTENSION}.part"));
    let written = (|| {
        let file = Sha256Writer {
            inner: create_private_file(&part)?,
            hasher: Sha256::new(),
        };
        let (out, archive_id) = archive::write(
            BufWriter::with_capacity(1 << 20, file),
            &locks,
            manifest,
            sources,
        )?;
        let Sha256Writer {
            inner: file,
            hasher,
        } = out
            .into_inner()
            .map_err(|error| BackupError::io(&part, error.into_error()))?;
        file.sync_all()
            .map_err(|error| BackupError::io(&part, error))?;
        fs::rename(&part, path).map_err(|error| BackupError::io(path, error))?;
        sync_dir(path.parent());
        Ok((archive_id, hasher.finalize().into()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&part);
    }
    written
}

/// Syncs a directory so that a rename in it is durable (best effort; not on Windows).
fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir
        && let Ok(handle) = File::open(dir)
    {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// What a scratch store says about the state it holds.
struct State {
    digest: DigestRecord,
    data_format: u32,
    voters: Vec<u64>,
    audit_head: u64,
    ca_fingerprint: Option<String>,
    snapshot: SnapshotRecord,
}

/// Describes the scratch store and builds its snapshot; returns the snapshot file, moved
/// into the work directory so that it outlives the scratch store.
async fn describe(scratch: &RaftStore, work: &Path) -> Result<(State, PathBuf), BackupError> {
    let digest = scratch.digest(None).await?;
    let status = scratch.status();
    let view = scratch.read(ReadConsistency::Local).await?;
    let data_format = stored_format(view.as_ref())?;
    let ca_fingerprint = ca_fingerprint(view.as_ref())?;
    drop(view);
    let voters = scratch
        .membership()
        .voters
        .iter()
        .map(|node| node.0)
        .collect();
    scratch.snapshot_now().await?;
    let (meta, path) = scratch
        .current_snapshot()
        .ok_or_else(|| BackupError::Internal("the scratch store built no snapshot".to_owned()))?;
    let log_id = meta
        .last_log_id
        .ok_or_else(|| BackupError::Internal("the snapshot covers no log entry".to_owned()))?;
    let target = work.join("store.snapshot");
    fs::rename(&path, &target).map_err(|error| BackupError::io(&target, error))?;
    Ok((
        State {
            digest: DigestRecord {
                revision: digest.revision.0,
                sha256: hex_encode(&digest.sha256),
                tables: digest.tables,
                entries: digest.entries,
            },
            data_format,
            voters,
            audit_head: status.audit_head.0,
            ca_fingerprint,
            snapshot: SnapshotRecord {
                last_log_term: log_id.leader_id.term,
                last_log_node: log_id.leader_id.node_id,
                last_log_index: log_id.index,
                snapshot_id: meta.snapshot_id,
            },
        },
        target,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_sort_by_time_and_are_recognized() {
        let at = Timestamp(time::macros::datetime!(2026-10-11 08:05:09 UTC));
        let name = file_name(at, NodeId(1));
        assert_eq!(name, "tenko-backup-20261011T080509Z-n1.tkbk");
        assert!(is_backup_name(&name));
        assert!(!is_backup_name(
            "tenko-backup-20261011T080509Z-n1.tkbk.part"
        ));
        assert!(!is_backup_name("notes.tkbk"));
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join(&name), b"x").expect("write");
        assert_eq!(
            free_name(dir.path(), &name),
            dir.path().join("tenko-backup-20261011T080509Z-n1-2.tkbk")
        );
    }
}
