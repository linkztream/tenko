//! Checking and restoring a backup (ADR 0016 items 6 to 8).
//!
//! [`check`] (`tenko backup verify`, `tenko backup restore --dry-run`) and [`restore`] run
//! the same sequence; a check runs it in a temporary directory and removes it:
//!
//! 1. open the file: the header, the key slot, the manifest (a wrong passphrase or key
//!    fails here, before anything is written), and refuse a data format this build does
//!    not know; the manifest's limits bound every part before it is read;
//! 2. read every part, checking every chunk and every part hash, and the SHA-256 of the
//!    whole file on the way; the snapshot goes to a file, the small parts stay in memory
//!    (the key generations in zeroizing buffers), parts this build does not know are
//!    checked and discarded;
//! 3. create the store as a learner that was never initialized and install the snapshot
//!    with a membership of one voter, this node, at the term of its last log id; open it
//!    again as a single voter, which verifies the whole audit chain and elects it;
//! 4. compare the store digest with the manifest, open every envelope of `vault.secrets`
//!    with the key generations of the backup, compare the internal CA fingerprint and the
//!    stored data format;
//! 5. a restore then writes the restore notice into the store itself (`backup.restore_pending`),
//!    seals the key generations with the provider of this host, writes the format marker,
//!    the imported TLS files and the configuration (under `restored/`) and the restore
//!    notice `restored.json` that the first start records; the first start finds the
//!    notice in both places, and a notice file that is missing is itself recorded.
//!
//! Everything a restore creates under the data directory is created by this process
//! alone: directories with one `create_dir` (mode 0700 on Unix), files with `create_new`
//! (mode 0600), and a path that already exists as a symbolic link is refused, so no link
//! that was planted in the data directory is followed. That is defense in depth: the
//! command runs as the account that owns the data directory, and `main` refuses it as
//! root over another account's files ([`crate::exec`], ADR 0023 I2).
//!
//! A failed restore removes the store it created and the files it wrote; key generations
//! it already sealed stay (a repeated restore finds them and skips them).

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use openraft::{BasicNode, LeaderId, LogId, Membership, StoredMembership, Vote};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_auth::encoding::hex_encode;
use tenko_core::{
    NodeId, RequestCtx, SystemComponent, Timestamp, secret::VaultEnvelope, table::TableDef,
};
use tenko_store::{
    KeyRange, ReadConsistency, Store as _, WriteBatch, format,
    raft::{RaftStore, network::SNAPSHOT_CHUNK, types::SnapshotMeta},
};
use tenko_vault::{
    KekConfig, KekOptions, KekProtection, KekProvider, KekRing,
    envelope::{self, RowBinding},
    kek::LocalKek,
    tables::SECRETS,
    transfer::TransferredKek,
};
use zeroize::Zeroizing;

use super::{
    BackupError,
    archive::{
        Manifest, PART_CONFIG, PART_KEKS, PART_SNAPSHOT, PART_TLS_CERT, PART_TLS_KEY, PartEntry,
        Reader, SnapshotRecord, Unlock, printable,
    },
    create::{
        Secret, TlsPair, ca_fingerprint, create_private_dir, create_private_file,
        existing_dir_not_link, scratch_config, stored_format,
    },
};
use crate::upgrade::migrations::CURRENT;

/// The restore notice a restore leaves in the data directory for the first start.
pub const NOTICE_FILE: &str = "restored.json";

/// The same notice inside the restored store, written by the restore after the digest
/// check: the first start records the restore from it when the file is gone.
pub const PENDING: TableDef<(), Notice> = TableDef::new("backup.restore_pending");

/// The directory a restore writes the TLS files and the configuration into.
pub const EXTRAS_DIR: &str = "restored";

/// The file a restore writes the configuration of the backup to.
pub const CONFIG_FILE: &str = "tenko.toml";
/// The file a restore writes the imported certificate chain to.
pub const TLS_CERT_FILE: &str = "tls-certificate.pem";
/// The file a restore writes the imported TLS key to.
pub const TLS_KEY_FILE: &str = "tls-key.pem";

/// What [`restore`] leaves for the first start (`restored.json` and [`PENDING`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// When the restore ran.
    pub restored_at: Timestamp,
    /// When the backup was made.
    pub backup_created_at: Timestamp,
    /// The backup file name.
    pub file: String,
    /// The archive id of the backup's header, as hex.
    #[serde(default)]
    pub archive_id: String,
    /// The SHA-256 of the backup file, as hex.
    #[serde(default)]
    pub sha256: String,
    /// The node the backup was made on.
    pub source_node: u64,
    /// The voters of the source then.
    pub source_voters: Vec<u64>,
    /// The revision of the backup.
    pub revision: u64,
    /// The Tenko version that made the backup.
    pub tenko_version: String,
}

/// Where and how to restore.
#[derive(Debug, Clone)]
pub struct Target {
    /// The data directory (empty or without a store).
    pub data_dir: PathBuf,
    /// The store directory inside it.
    pub store_dir: PathBuf,
    /// This node's id.
    pub node: NodeId,
    /// The address peers reach this node at.
    pub address: String,
    /// The key provider of this host.
    pub kek: KekConfig,
    /// Its policy.
    pub kek_options: KekOptions,
}

/// What a check or a restore found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The backup file.
    pub file: PathBuf,
    /// The archive id of its header, as hex; the `sys.backup.create` audit record of the
    /// node that wrote the backup names the same id.
    pub archive_id: String,
    /// The SHA-256 of the whole file, as hex; the same record names it too.
    pub sha256: String,
    /// The kinds of its key slots.
    pub slots: Vec<&'static str>,
    /// The manifest.
    pub manifest: Manifest,
    /// The parts read, in order.
    pub parts: Vec<PartEntry>,
    /// The digest of the installed store matched the manifest.
    pub digest_matches: bool,
    /// Envelopes opened with the key generations of the backup.
    pub envelopes: u64,
    /// The internal CA fingerprint of the installed store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
    /// The node the store was installed for.
    pub node: u64,
    /// Whether this was a check only.
    pub dry_run: bool,
    /// Files the restore wrote besides the store and the key generations.
    pub written: Vec<PathBuf>,
    /// Remarks for the operator.
    pub notes: Vec<String>,
    /// How long it took, in milliseconds.
    pub duration_ms: u64,
}

/// The parts of a backup after reading.
struct Unpacked {
    snapshot: PathBuf,
    generations: Vec<TransferredKek>,
    tls: Option<TlsPair>,
    config: Option<Secret>,
}

/// Removes a path when dropped unless disarmed; also when the thread unwinds.
struct Cleanup(Vec<PathBuf>);

impl Cleanup {
    fn disarm(&mut self) {
        self.0.clear();
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            if path.is_dir() {
                let _ = fs::remove_dir_all(path);
            } else {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Checks a backup completely in a scratch directory under `work_parent` and removes it.
///
/// The scratch directory is created by this process alone (mode 0700 on Unix) and removed
/// on every way out, a panic included.
///
/// # Errors
///
/// The first [`BackupError`] the check meets.
pub async fn check(
    file: &Path,
    unlock: Unlock<'_>,
    work_parent: &Path,
    node: NodeId,
) -> Result<Report, BackupError> {
    let started = Instant::now();
    let work = work_parent.join(format!(
        ".tenko-backup-check-{}",
        uuid::Uuid::now_v7().simple()
    ));
    create_private_dir(&work)?;
    let _cleanup = Cleanup(vec![work.clone()]);
    let (mut report, unpacked) = unpack(file, unlock, &work)?;
    let ring = memory_ring(&unpacked.generations)?;
    let store_dir = work.join("store");
    let store = install(&store_dir, node, "", &report.manifest, &unpacked.snapshot).await?;
    let checked = verify_store(&store, &report.manifest, &ring).await;
    let closed = store.shutdown().await;
    drop(store);
    let (envelopes, fingerprint) = checked?;
    closed?;
    report.digest_matches = true;
    report.envelopes = envelopes;
    report.ca_fingerprint = fingerprint;
    report.node = node.0;
    report.dry_run = true;
    report.duration_ms = millis(started.elapsed());
    Ok(report)
}

/// Restores a backup into `target`, or with `dry_run` checks that it would restore there
/// and writes nothing into it.
///
/// # Errors
///
/// [`BackupError::TargetNotEmpty`] when the data directory holds a store, [`BackupError::Io`]
/// when the store directory, the work directory or `restored/` exists as a symbolic link,
/// or the first [`BackupError`] of the sequence; what the restore wrote is removed again.
pub async fn restore(
    file: &Path,
    unlock: Unlock<'_>,
    target: &Target,
    dry_run: bool,
) -> Result<Report, BackupError> {
    let started = Instant::now();
    if format::store_exists(&target.store_dir) {
        return Err(BackupError::TargetNotEmpty(target.data_dir.clone()));
    }
    check_provider(&target.kek)?;
    if dry_run {
        // The scratch directory goes beside the data directory, or into the system
        // temporary directory when the account that runs the dry run may not write there.
        let parent = target
            .data_dir
            .parent()
            .filter(|parent| parent.is_dir())
            .map_or_else(std::env::temp_dir, Path::to_path_buf);
        let mut report = match check(file, unlock, &parent, target.node).await {
            Err(BackupError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                check(file, unlock, &std::env::temp_dir(), target.node).await?
            }
            checked => checked?,
        };
        report.notes.push(format!(
            "dry run: nothing was written to {}; the key generations would be sealed with the \
             {} provider",
            target.data_dir.display(),
            target.kek.provider_name()
        ));
        add_node_note(&mut report, target.node);
        report.duration_ms = millis(started.elapsed());
        return Ok(report);
    }

    refuse_leftovers(&target.data_dir)?;
    let (mut cleanup, work) = prepare(target)?;
    let _work_cleanup = Cleanup(vec![work.clone()]);
    let (mut report, unpacked) = unpack(file, unlock, &work)?;
    let ring = memory_ring(&unpacked.generations)?;
    let store = install(
        &target.store_dir,
        target.node,
        &target.address,
        &report.manifest,
        &unpacked.snapshot,
    )
    .await?;
    let notice = Notice::of(file, &report);
    let checked = match verify_store(&store, &report.manifest, &ring).await {
        // The store is what the backup recorded: the notice goes into it, after the
        // digest was compared, so that the first start finds it even without the file.
        Ok(checked) => write_pending(&store, &notice).await.map(|()| checked),
        Err(error) => Err(error),
    };
    let closed = store.shutdown().await;
    drop(store);
    let (envelopes, fingerprint) = checked?;
    closed?;

    // The store is complete: seal the key generations with this host's provider. The files
    // written are removed again when a later one fails.
    let mut written = Cleanup(Vec::new());
    let protection = finish(target, &report.manifest, unpacked, &notice, &mut written.0)?;
    cleanup.disarm();
    let written = std::mem::take(&mut written.0);

    report.digest_matches = true;
    report.envelopes = envelopes;
    report.ca_fingerprint = fingerprint;
    report.node = target.node.0;
    report.dry_run = false;
    report.written = written;
    add_restore_notes(&mut report, target.node, protection);
    report.duration_ms = millis(started.elapsed());
    Ok(report)
}

/// Prepares the data directory for a restore and returns the guard that removes the store
/// on failure and the work directory: the data directory itself may be what the
/// configuration names, an administrator's link included; `store` and the work directory
/// inside it are created here, never followed.
fn prepare(target: &Target) -> Result<(Cleanup, PathBuf), BackupError> {
    if !target.data_dir.is_dir() {
        create_private_dir(&target.data_dir)?;
    }
    if !existing_dir_not_link(&target.store_dir)? {
        create_private_dir(&target.store_dir)?;
    }
    let cleanup = Cleanup(vec![target.store_dir.clone()]);
    let work = target
        .data_dir
        .join(format!(".restore-{}", uuid::Uuid::now_v7().simple()));
    create_private_dir(&work)?;
    Ok((cleanup, work))
}

/// The remarks of a finished restore.
fn add_restore_notes(report: &mut Report, node: NodeId, protection: KekProtection) {
    if protection.is_weak() {
        report.notes.push(format!(
            "the key generations are sealed {}: choose a stronger [kek] provider for this host",
            protection.describe()
        ));
    }
    add_node_note(report, node);
    if report.manifest.voters.len() > 1 {
        report.notes.push(format!(
            "the backup comes from a cluster of {} controllers; this controller starts alone, \
             and the others rejoin it with empty data directories (`tenko cluster join`)",
            report.manifest.voters.len()
        ));
    }
    if report.manifest.data_format < CURRENT {
        report.notes.push(format!(
            "the backup holds data format {}; the first start migrates it to {CURRENT}",
            report.manifest.data_format
        ));
    }
}

impl Notice {
    /// The notice of a restore of `file` as `report` read it.
    fn of(file: &Path, report: &Report) -> Self {
        Self {
            restored_at: Timestamp::now(),
            backup_created_at: report.manifest.created_at,
            file: file
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            archive_id: report.archive_id.clone(),
            sha256: report.sha256.clone(),
            source_node: report.manifest.node,
            source_voters: report.manifest.voters.clone(),
            revision: report.manifest.revision,
            tenko_version: report.manifest.tenko_version.clone(),
        }
    }
}

/// Writes the notice into the restored store ([`PENDING`]).
async fn write_pending(store: &RaftStore, notice: &Notice) -> Result<(), BackupError> {
    let ctx = RequestCtx::system(SystemComponent::Backup);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.put_typed(&PENDING, &(), notice)?;
    store.propose(batch).await?;
    Ok(())
}

/// Seals the key generations with this host's provider and writes the format marker, the
/// extra files and the restore notice; returns the protection of the sealed generations.
/// Each file is added to `written` as soon as it exists, so that a failure removes it.
fn finish(
    target: &Target,
    manifest: &Manifest,
    unpacked: Unpacked,
    notice: &Notice,
    written: &mut Vec<PathBuf>,
) -> Result<KekProtection, BackupError> {
    let ids: Vec<String> = unpacked
        .generations
        .iter()
        .map(|kek| kek.id.clone())
        .collect();
    let imported = target
        .kek
        .import_with(&unpacked.generations, &target.kek_options)?;
    if let Some(missing) = ids.iter().find(|id| !imported.contains(id)) {
        return Err(BackupError::check(
            "key generations",
            format!("the generation {missing} did not load after sealing"),
        ));
    }
    let protection = imported.active().protection();
    drop(imported);
    format::write_marker(
        &target.store_dir,
        &format::Marker::new(manifest.data_format, crate::version()),
    )
    .map_err(|error| BackupError::Internal(error.to_string()))?;
    write_extras(&target.data_dir, unpacked.tls, unpacked.config, written)?;
    let notice = serde_json::to_vec_pretty(notice)
        .map_err(|error| BackupError::Internal(error.to_string()))?;
    write_private(&target.data_dir.join(NOTICE_FILE), &notice, written)?;
    Ok(protection)
}

/// Refuses, before anything is written, a data directory that still holds the notice or an
/// extra file of an earlier restore: the files are created only when absent, so the restore
/// would otherwise fail at its end.
fn refuse_leftovers(data_dir: &Path) -> Result<(), BackupError> {
    let extras = data_dir.join(EXTRAS_DIR);
    let paths = [
        data_dir.join(NOTICE_FILE),
        extras.join(TLS_CERT_FILE),
        extras.join(TLS_KEY_FILE),
        extras.join(CONFIG_FILE),
    ];
    match paths
        .into_iter()
        .find(|path| path.symlink_metadata().is_ok())
    {
        Some(path) => Err(BackupError::io(
            &path,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "left by an earlier restore; move it away, then restore again",
            ),
        )),
        None => Ok(()),
    }
}

/// Refuses a provider that cannot take the key generations before any work is done: the
/// `file` provider wraps them under its root key file, which must exist.
fn check_provider(kek: &KekConfig) -> Result<(), BackupError> {
    if let KekConfig::File { path, .. } = kek
        && !path.is_file()
    {
        return Err(BackupError::InvalidKey(format!(
            "the file provider seals the key generations under its key file {}, which does not \
             exist; create it first (32 random bytes, as for a new installation)",
            path.display()
        )));
    }
    Ok(())
}

fn add_node_note(report: &mut Report, node: NodeId) {
    if report.manifest.node != node.0 {
        report.notes.push(format!(
            "the backup was made on node {}; it is restored as node {} ([node] id)",
            report.manifest.node, node.0
        ));
    }
}

/// A reader that hashes everything read through it.
struct Sha256Reader<R: Read> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for Sha256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        Ok(read)
    }
}

/// Opens the file and reads every part into `work` (the snapshot) or memory.
fn unpack(file: &Path, unlock: Unlock<'_>, work: &Path) -> Result<(Report, Unpacked), BackupError> {
    let input = File::open(file).map_err(|error| BackupError::io(file, error))?;
    let input = Sha256Reader {
        inner: input,
        hasher: Sha256::new(),
    };
    let mut reader = Reader::open(BufReader::with_capacity(1 << 20, input), unlock)?;
    let manifest = reader.manifest().clone();
    if manifest.data_format > CURRENT {
        return Err(BackupError::FormatNewer {
            found: manifest.data_format,
            supported: CURRENT,
        });
    }
    let slots = reader.header().slot_kinds();
    let archive_id = hex_encode(&reader.header().archive_id);
    let mut read = ReadParts {
        snapshot: work.join("store.snapshot"),
        generations: None,
        tls_cert: None,
        tls_key: None,
        config: None,
        parts: Vec::new(),
        notes: Vec::new(),
    };
    loop {
        let Some(name) = manifest
            .parts
            .get(read.parts.len())
            .map(|entry| entry.name.clone())
        else {
            reader.next_part(&mut std::io::sink())?;
            break;
        };
        read.next(&mut reader, &name)?;
    }
    let sha256 = hex_encode(&reader.into_inner().into_inner().hasher.finalize());
    let ReadParts {
        snapshot,
        generations,
        tls_cert,
        tls_key,
        config,
        parts,
        notes,
    } = read;
    let generations = generations
        .ok_or_else(|| BackupError::Corrupt("the key generations are missing".to_owned()))?;
    let listed: Vec<&str> = generations.iter().map(|kek| kek.id.as_str()).collect();
    if listed
        != manifest
            .kek
            .generations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(BackupError::Corrupt(
            "the key generations differ from the manifest".to_owned(),
        ));
    }
    let report = Report {
        file: file.to_path_buf(),
        archive_id,
        sha256,
        slots,
        manifest,
        parts,
        digest_matches: false,
        envelopes: 0,
        ca_fingerprint: None,
        node: 0,
        dry_run: true,
        written: Vec::new(),
        notes,
        duration_ms: 0,
    };
    let tls = tls_cert.zip(tls_key);
    Ok((
        report,
        Unpacked {
            snapshot,
            generations,
            tls,
            config,
        },
    ))
}

/// The parts of a backup while they are read.
struct ReadParts {
    snapshot: PathBuf,
    generations: Option<Vec<TransferredKek>>,
    tls_cert: Option<Secret>,
    tls_key: Option<Secret>,
    config: Option<Secret>,
    parts: Vec<PartEntry>,
    notes: Vec<String>,
}

impl ReadParts {
    /// Reads the part `name`, the next one of the manifest. The manifest bounds every part
    /// (`Manifest::validate`) and the reader stops at the declared length; the snapshot
    /// goes to a file of this process alone, the small parts into wiped buffers, parts this
    /// build does not know into nothing.
    fn next<R: Read>(&mut self, reader: &mut Reader<R>, name: &str) -> Result<(), BackupError> {
        let entry = match name {
            PART_SNAPSHOT => {
                let out = create_private_file(&self.snapshot)?;
                let mut out = BufWriter::with_capacity(1 << 20, out);
                let entry = reader.next_part(&mut out)?;
                out.flush()
                    .map_err(|error| BackupError::io(&self.snapshot, error))?;
                entry
            }
            PART_KEKS | PART_TLS_CERT | PART_TLS_KEY | PART_CONFIG => {
                let mut buffer = Zeroizing::new(Vec::new());
                let entry = reader.next_part(&mut *buffer)?;
                match name {
                    PART_KEKS => {
                        self.generations = Some(super::archive::decode_keks(&buffer)?);
                    }
                    PART_TLS_CERT => self.tls_cert = Some(buffer),
                    PART_TLS_KEY => self.tls_key = Some(buffer),
                    _ => self.config = Some(buffer),
                }
                entry
            }
            other => {
                let entry = reader.next_part(&mut std::io::sink())?;
                if other != super::archive::PART_LEASES {
                    self.notes.push(format!(
                        "the part {} is not known to this build; it was checked and skipped",
                        filtered(other)
                    ));
                }
                entry
            }
        };
        self.parts.extend(entry);
        Ok(())
    }
}

/// `text` with every control character replaced, so that a line of a report stays one
/// line of printable characters whatever an archive carries.
pub fn filtered(text: &str) -> String {
    if printable(text, usize::MAX) {
        return text.to_owned();
    }
    text.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// A ring of the backup's generations in memory, the active one last.
fn memory_ring(generations: &[TransferredKek]) -> Result<KekRing, BackupError> {
    let keks = generations
        .iter()
        .map(|kek| {
            LocalKek::new(kek.id.clone(), KekProtection::Memory, &kek.material)
                .map(|kek| Arc::new(kek) as Arc<dyn KekProvider>)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(KekRing::from_generations(keks)?)
}

/// Installs the snapshot into a new store in `store_dir` as the only voter `node`, then
/// opens it as a single voter with the whole audit chain verified.
pub(crate) async fn install(
    store_dir: &Path,
    node: NodeId,
    address: &str,
    manifest: &Manifest,
    snapshot: &Path,
) -> Result<RaftStore, BackupError> {
    let term = manifest.snapshot.last_log_term;
    install_at(store_dir, node, address, &manifest.snapshot, term, snapshot).await
}

/// [`install`] from a snapshot at `position`, with the vote of the install at `vote_term`
/// (at least the snapshot's term): the store's own election then starts the term after it.
/// A forced step of the cluster recovery passes the highest term its copy has seen.
pub(crate) async fn install_at(
    store_dir: &Path,
    node: NodeId,
    address: &str,
    position: &SnapshotRecord,
    vote_term: u64,
    snapshot: &Path,
) -> Result<RaftStore, BackupError> {
    if format::store_exists(store_dir) {
        return Err(BackupError::TargetNotEmpty(store_dir.to_path_buf()));
    }
    let mut learner_config = scratch_config(store_dir, node, false);
    learner_config.address = address.to_owned();
    let learner = RaftStore::open(learner_config.clone()).await?;
    let installed = install_snapshot(&learner, node, address, position, vote_term, snapshot).await;
    let _ = learner.shutdown().await;
    drop(learner);
    installed?;

    let mut config = learner_config;
    config.bootstrap = true;
    config.verify_full_audit_chain = true;
    RaftStore::open(config)
        .await
        .map_err(|error| BackupError::check("the restored store", error))
}

async fn install_snapshot(
    learner: &RaftStore,
    node: NodeId,
    address: &str,
    position: &SnapshotRecord,
    vote_term: u64,
    snapshot: &Path,
) -> Result<(), BackupError> {
    let log_id = LogId::new(
        LeaderId::new(position.last_log_term, position.last_log_node),
        position.last_log_index,
    );
    let members = BTreeMap::from([(node.0, BasicNode::new(address))]);
    let membership = Membership::new(vec![members.keys().copied().collect()], members);
    let meta = SnapshotMeta {
        last_log_id: Some(log_id),
        last_membership: StoredMembership::new(Some(log_id), membership),
        snapshot_id: position.snapshot_id.clone(),
    };
    // The vote of a leader that is not this node: the learner accepts the snapshot as from
    // the leader of that term, and its own election later starts the next term.
    let other = if node.0 == u64::MAX { 0 } else { u64::MAX };
    let vote = Vote::new_committed(vote_term.max(position.last_log_term), other);
    let mut receiver = learner
        .receive_snapshot()
        .map_err(|error| BackupError::io(snapshot, error))?;
    let mut input = File::open(snapshot).map_err(|error| BackupError::io(snapshot, error))?;
    let mut chunk = vec![0u8; SNAPSHOT_CHUNK];
    loop {
        let read = input
            .read(&mut chunk)
            .map_err(|error| BackupError::io(snapshot, error))?;
        if read == 0 {
            break;
        }
        receiver
            .write_chunk(&chunk[..read])
            .await
            .map_err(|error| BackupError::io(snapshot, error))?;
    }
    receiver
        .install(vote, meta)
        .await
        .map_err(|error| BackupError::check("the snapshot install", error))?;
    Ok(())
}

/// The digest, envelope, CA and format checks; returns the envelopes opened and the CA
/// fingerprint.
async fn verify_store(
    store: &RaftStore,
    manifest: &Manifest,
    ring: &KekRing,
) -> Result<(u64, Option<String>), BackupError> {
    let digest = store.digest(None).await?;
    let expected = &manifest.digest;
    if hex_encode(&digest.sha256) != expected.sha256
        || digest.tables != expected.tables
        || digest.entries != expected.entries
    {
        return Err(BackupError::DigestMismatch(format!(
            "the backup recorded {} rows in {} tables, the restored store has {} rows in {} tables \
             with another digest",
            expected.entries, expected.tables, digest.entries, digest.tables
        )));
    }
    let view = store.read(ReadConsistency::Local).await?;
    let format = stored_format(view.as_ref())?;
    if format != manifest.data_format {
        return Err(BackupError::check(
            "data format",
            format!(
                "the store records format {format}, the manifest {}",
                manifest.data_format
            ),
        ));
    }
    let fingerprint = ca_fingerprint(view.as_ref())?;
    if fingerprint != manifest.ca_fingerprint {
        return Err(BackupError::check(
            "internal CA",
            "the CA root differs from the one the backup recorded",
        ));
    }
    let mut envelopes = 0u64;
    let mut after = None;
    loop {
        let range = after
            .clone()
            .map_or_else(KeyRange::all, |key| KeyRange::all().after(key));
        let page = view.scan(&SECRETS, range, 512, false)?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());
        for (key, versioned) in page {
            let sealed = VaultEnvelope::from_bytes(&versioned.value)
                .map_err(|error| BackupError::check("secrets", error))?;
            let row = RowBinding {
                table: &SECRETS,
                key: &key,
            };
            // The value is zeroized when `opened` drops.
            let opened = envelope::open(ring, row, &sealed).map_err(|error| {
                BackupError::check(
                    "secrets",
                    format!(
                        "an envelope wrapped by {} does not open: {error}",
                        sealed.key_id
                    ),
                )
            })?;
            drop(opened);
            envelopes += 1;
        }
    }
    Ok((envelopes, fingerprint))
}

/// Writes `bytes` to a new file of this process alone (mode 0600 on Unix) and adds it to
/// `written` once it exists; an existing path, a link included, is refused.
fn write_private(path: &Path, bytes: &[u8], written: &mut Vec<PathBuf>) -> Result<(), BackupError> {
    let mut file = create_private_file(path)?;
    written.push(path.to_path_buf());
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| BackupError::io(path, error))
}

fn write_extras(
    data_dir: &Path,
    tls: Option<TlsPair>,
    config: Option<Secret>,
    written: &mut Vec<PathBuf>,
) -> Result<(), BackupError> {
    if tls.is_none() && config.is_none() {
        return Ok(());
    }
    let dir = data_dir.join(EXTRAS_DIR);
    // An earlier restore's directory is reused; a link under the name is refused.
    if !existing_dir_not_link(&dir)? {
        create_private_dir(&dir)?;
    }
    if let Some((cert, key)) = tls {
        for (name, bytes) in [(TLS_CERT_FILE, cert), (TLS_KEY_FILE, key)] {
            write_private(&dir.join(name), &bytes, written)?;
        }
    }
    if let Some(config) = config {
        write_private(&dir.join(CONFIG_FILE), &config, written)?;
    }
    Ok(())
}

/// Reads the restore notice file of a data directory (the first start); the file stays
/// until [`clear_notice`].
///
/// # Errors
///
/// [`BackupError::Io`] or a notice that does not parse ([`BackupError::Internal`]).
pub fn take_notice(data_dir: &Path) -> Result<Option<Notice>, BackupError> {
    let path = data_dir.join(NOTICE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(BackupError::io(&path, error)),
    };
    let notice: Notice = serde_json::from_slice(&bytes)
        .map_err(|error| BackupError::Internal(format!("{}: {error}", path.display())))?;
    Ok(Some(notice))
}

/// Removes the restore notice once the first start recorded it; a notice that is gone
/// already is fine.
///
/// # Errors
///
/// [`BackupError::Io`] when the file stays.
pub fn clear_notice(data_dir: &Path) -> Result<(), BackupError> {
    let path = data_dir.join(NOTICE_FILE);
    match fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(BackupError::io(&path, error))
        }
        _ => Ok(()),
    }
}
