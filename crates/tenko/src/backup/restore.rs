//! Checking and restoring a backup (ADR 0016 items 6 to 8).
//!
//! [`check`] (`tenko backup verify`, `tenko backup restore --dry-run`) and [`restore`] run
//! the same sequence; a check runs it in a temporary directory and removes it:
//!
//! 1. open the file: the header, the key slot, the manifest (a wrong passphrase or key
//!    fails here, before anything is written), and refuse a data format this build does
//!    not know;
//! 2. read every part, checking every chunk and every part hash; the snapshot goes to a
//!    file, the small parts stay in memory (the key generations in zeroizing buffers);
//! 3. create the store as a learner that was never initialized and install the snapshot
//!    with a membership of one voter, this node, at the term of its last log id; open it
//!    again as a single voter, which verifies the whole audit chain and elects it;
//! 4. compare the store digest with the manifest, open every envelope of `vault.secrets`
//!    with the key generations of the backup, compare the internal CA fingerprint and the
//!    stored data format;
//! 5. a restore then seals the key generations with the provider of this host, writes the
//!    format marker, the imported TLS files and the configuration (under `restored/`) and
//!    the restore notice `restored.json` that the first start records.
//!
//! A failed restore removes the store it created and the files it wrote; key generations
//! it already sealed stay (a repeated restore finds them and skips them).

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, BufWriter, Read as _, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use openraft::{BasicNode, LeaderId, LogId, Membership, StoredMembership, Vote};
use serde::{Deserialize, Serialize};
use tenko_auth::encoding::hex_encode;
use tenko_core::{NodeId, Timestamp, secret::VaultEnvelope};
use tenko_store::{
    KeyRange, ReadConsistency, Store as _, format,
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
        Manifest, PART_CONFIG, PART_KEKS, PART_LEASES, PART_SNAPSHOT, PART_TLS_CERT, PART_TLS_KEY,
        PartEntry, Reader, Unlock,
    },
    create::{Secret, TlsPair, ca_fingerprint, scratch_config, stored_format},
};
use crate::upgrade::migrations::CURRENT;

/// The restore notice a restore leaves in the data directory for the first start.
pub const NOTICE_FILE: &str = "restored.json";

/// The directory a restore writes the TLS files and the configuration into.
pub const EXTRAS_DIR: &str = "restored";

/// The file a restore writes the configuration of the backup to.
pub const CONFIG_FILE: &str = "tenko.toml";
/// The file a restore writes the imported certificate chain to.
pub const TLS_CERT_FILE: &str = "tls-certificate.pem";
/// The file a restore writes the imported TLS key to.
pub const TLS_KEY_FILE: &str = "tls-key.pem";

/// What [`restore`] leaves for the first start (`restored.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// When the restore ran.
    pub restored_at: Timestamp,
    /// When the backup was made.
    pub backup_created_at: Timestamp,
    /// The backup file name.
    pub file: String,
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

/// Removes a path when dropped unless disarmed.
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
    fs::create_dir_all(&work).map_err(|error| BackupError::io(&work, error))?;
    let _cleanup = Cleanup(vec![work.clone()]);
    let (mut report, unpacked) = unpack(file, unlock, &work)?;
    let ring = memory_ring(&unpacked.generations)?;
    let store_dir = work.join("store");
    let store = install(&store_dir, node, "", &report.manifest, &unpacked.snapshot).await?;
    let checked = verify_store(&store, &report.manifest, &ring).await;
    let _ = store.shutdown().await;
    drop(store);
    let (envelopes, fingerprint) = checked?;
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
/// [`BackupError::TargetNotEmpty`] when the data directory holds a store, or the first
/// [`BackupError`] of the sequence; what the restore wrote is removed again.
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
        let parent = target
            .data_dir
            .parent()
            .filter(|parent| parent.is_dir())
            .map_or_else(std::env::temp_dir, Path::to_path_buf);
        let mut report = check(file, unlock, &parent, target.node).await?;
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

    fs::create_dir_all(&target.data_dir)
        .map_err(|error| BackupError::io(&target.data_dir, error))?;
    let work = target
        .data_dir
        .join(format!(".restore-{}", uuid::Uuid::now_v7().simple()));
    fs::create_dir_all(&work).map_err(|error| BackupError::io(&work, error))?;
    let _work_cleanup = Cleanup(vec![work.clone()]);
    let mut cleanup = Cleanup(vec![target.store_dir.clone()]);
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
    let checked = verify_store(&store, &report.manifest, &ring).await;
    let _ = store.shutdown().await;
    drop(store);
    let (envelopes, fingerprint) = checked?;

    // The store is complete: seal the key generations with this host's provider.
    let (protection, written) = finish(file, target, &report.manifest, unpacked)?;
    cleanup.0.extend(written.iter().cloned());
    cleanup.disarm();

    report.digest_matches = true;
    report.envelopes = envelopes;
    report.ca_fingerprint = fingerprint;
    report.node = target.node.0;
    report.dry_run = false;
    report.written = written;
    if protection.is_weak() {
        report.notes.push(format!(
            "the key generations are sealed {}: choose a stronger [kek] provider for this host",
            protection.describe()
        ));
    }
    add_node_note(&mut report, target.node);
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
    report.duration_ms = millis(started.elapsed());
    Ok(report)
}

/// Seals the key generations with this host's provider and writes the format marker, the
/// extra files and the restore notice; returns the protection of the sealed generations
/// and the files written.
fn finish(
    file: &Path,
    target: &Target,
    manifest: &Manifest,
    unpacked: Unpacked,
) -> Result<(KekProtection, Vec<PathBuf>), BackupError> {
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
    let mut written = write_extras(&target.data_dir, unpacked.tls, unpacked.config)?;
    let notice = Notice {
        restored_at: Timestamp::now(),
        backup_created_at: manifest.created_at,
        file: file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        source_node: manifest.node,
        source_voters: manifest.voters.clone(),
        revision: manifest.revision,
        tenko_version: manifest.tenko_version.clone(),
    };
    let notice_path = target.data_dir.join(NOTICE_FILE);
    write_private(
        &notice_path,
        &serde_json::to_vec_pretty(&notice)
            .map_err(|error| BackupError::Internal(error.to_string()))?,
    )?;
    written.push(notice_path);
    Ok((protection, written))
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

/// Opens the file and reads every part into `work` (the snapshot) or memory.
fn unpack(file: &Path, unlock: Unlock<'_>, work: &Path) -> Result<(Report, Unpacked), BackupError> {
    let input = File::open(file).map_err(|error| BackupError::io(file, error))?;
    let mut reader = Reader::open(BufReader::with_capacity(1 << 20, input), unlock)?;
    let manifest = reader.manifest().clone();
    if manifest.data_format > CURRENT {
        return Err(BackupError::FormatNewer {
            found: manifest.data_format,
            supported: CURRENT,
        });
    }
    let slots = reader.header().slot_kinds();
    let snapshot = work.join("store.snapshot");
    let mut generations = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut config = None;
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    loop {
        let Some(name) = manifest
            .parts
            .get(parts.len())
            .map(|entry| entry.name.clone())
        else {
            reader.next_part(&mut std::io::sink())?;
            break;
        };
        let entry = if name == PART_SNAPSHOT {
            let out = File::create(&snapshot).map_err(|error| BackupError::io(&snapshot, error))?;
            let mut out = BufWriter::with_capacity(1 << 20, out);
            let entry = reader.next_part(&mut out)?;
            out.flush()
                .map_err(|error| BackupError::io(&snapshot, error))?;
            entry
        } else {
            let mut buffer = Zeroizing::new(Vec::new());
            let entry = reader.next_part(&mut *buffer)?;
            match name.as_str() {
                PART_KEKS => generations = Some(super::archive::decode_keks(&buffer)?),
                PART_TLS_CERT => tls_cert = Some(buffer),
                PART_TLS_KEY => tls_key = Some(buffer),
                PART_CONFIG => config = Some(buffer),
                PART_LEASES => {}
                other => notes.push(format!(
                    "the part {other} is not known to this build; it was checked and skipped"
                )),
            }
            entry
        };
        parts.extend(entry);
    }
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
    if format::store_exists(store_dir) {
        return Err(BackupError::TargetNotEmpty(store_dir.to_path_buf()));
    }
    let mut learner_config = scratch_config(store_dir, node, false);
    learner_config.address = address.to_owned();
    let learner = RaftStore::open(learner_config.clone()).await?;
    let installed = install_snapshot(&learner, node, address, manifest, snapshot).await;
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
    manifest: &Manifest,
    snapshot: &Path,
) -> Result<(), BackupError> {
    let position = &manifest.snapshot;
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
    let vote = Vote::new_committed(position.last_log_term, other);
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

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| BackupError::io(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| BackupError::io(path, error))
}

fn write_extras(
    data_dir: &Path,
    tls: Option<TlsPair>,
    config: Option<Secret>,
) -> Result<Vec<PathBuf>, BackupError> {
    if tls.is_none() && config.is_none() {
        return Ok(Vec::new());
    }
    let dir = data_dir.join(EXTRAS_DIR);
    fs::create_dir_all(&dir).map_err(|error| BackupError::io(&dir, error))?;
    let mut written = Vec::new();
    if let Some((cert, key)) = tls {
        for (name, bytes) in [(TLS_CERT_FILE, cert), (TLS_KEY_FILE, key)] {
            let path = dir.join(name);
            write_private(&path, &bytes)?;
            written.push(path);
        }
    }
    if let Some(config) = config {
        let path = dir.join(CONFIG_FILE);
        write_private(&path, &config)?;
        written.push(path);
    }
    Ok(written)
}

/// Reads and removes the restore notice of a data directory (the first start).
///
/// # Errors
///
/// [`BackupError::Io`] or a notice that does not parse ([`BackupError::Internal`]); the
/// file then stays.
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

/// Removes the restore notice once the first start recorded it.
pub fn clear_notice(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(NOTICE_FILE));
}
