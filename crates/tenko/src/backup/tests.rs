//! Backups end to end: a populated store is backed up, checked and restored, also from a
//! member of a three-controller cluster and from a stopped store.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tenko_cluster::ca::{CaPolicy, InternalCa};
use tenko_core::{NodeId, RequestCtx, TableName, principal::SystemComponent};
use tenko_store::{
    KeyRange, ReadConsistency, Store, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, fixture::InProcessCluster},
    testing::ConformanceConfig,
};
use tenko_vault::{
    KekConfig, KekOptions, KekProtection, KekProvider, KekRing, SecretBytes, SecretPurpose,
    SecretRef, SecretSpec, StoreVault, Vault as _, kek::LocalKek,
};
use zeroize::Zeroizing;

use super::{
    BackupError,
    archive::{KdfParams, OriginRecord, Unlock},
    create::{self, Extras, KeyLock, Request, Target},
    keys::BackupKey,
    restore,
};

const PASSPHRASE: &str = "correct horse battery staple";
const ROWS: TableName = TableName::from_static("ipam.backup_test_rows");

fn ring() -> KekRing {
    let keks: Vec<Arc<dyn KekProvider>> = [("mem-00000001", 1u8), ("mem-00000002", 2u8)]
        .into_iter()
        .map(|(id, byte)| {
            Arc::new(
                LocalKek::new(id, KekProtection::Memory, &Zeroizing::new([byte; 32])).expect("kek"),
            ) as Arc<dyn KekProvider>
        })
        .collect();
    KekRing::from_generations(keks).expect("ring")
}

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Backup)
}

fn request(target: Target) -> Request {
    Request {
        locks: vec![KeyLock::Passphrase(Zeroizing::new(PASSPHRASE.to_owned()))],
        kdf: KdfParams {
            memory_kib: 19_456,
            passes: 1,
            lanes: 1,
        },
        origin: OriginRecord {
            reason: "manual".to_owned(),
            by: "system".to_owned(),
        },
        extras: Extras::default(),
        target,
    }
}

/// Rows, secrets and the internal CA; returns the secrets with their values.
async fn populate(store: Arc<dyn Store>, ring: &KekRing) -> Vec<(SecretRef, Vec<u8>)> {
    let mut batch = WriteBatch::for_request(&ctx());
    for index in 0..200u32 {
        batch.put(
            ROWS,
            format!("row-{index:04}").into_bytes(),
            format!("value {index} under 192.0.2.0/24").into_bytes(),
        );
    }
    store.propose(batch).await.expect("rows");
    let vault = StoreVault::open(Arc::clone(&store), ring.clone())
        .await
        .expect("vault");
    let mut secrets = Vec::new();
    for index in 0..5u8 {
        let value = format!("secret value {index}").into_bytes();
        let secret = vault
            .put_operator(
                &ctx(),
                SecretSpec::new(SecretPurpose::from_static("connect.backup_test"))
                    .labelled(format!("secret {index}")),
                SecretBytes::new(value.clone()),
            )
            .await
            .expect("secret");
        secrets.push((secret, value));
    }
    InternalCa::load_or_init(store.as_ref(), &vault, &ctx(), CaPolicy::default())
        .await
        .expect("ca");
    secrets
}

fn store_config(dir: &Path, node: u64) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.node_id = NodeId(node);
    config.fsync_probe_samples = 0;
    config
}

fn plain_kek(data_dir: &Path) -> (KekConfig, KekOptions) {
    // The platform's default provider without any setup (tests only): on Windows DPAPI, on
    // Linux `systemd-creds` without the binary, so generations are plain files with mode 0600.
    let dir = data_dir.join("kek");
    let config: KekConfig = if cfg!(windows) {
        serde_json::from_value(serde_json::json!({ "provider": "dpapi", "dir": dir }))
    } else {
        serde_json::from_value(serde_json::json!({
            "provider": "systemd_creds",
            "dir": dir,
            "tool": data_dir.join("no-such-tool"),
        }))
    }
    .expect("kek config");
    (config, KekOptions::default())
}

fn target(data_dir: &Path, node: u64) -> restore::Target {
    let (kek, kek_options) = plain_kek(data_dir);
    restore::Target {
        data_dir: data_dir.to_path_buf(),
        store_dir: data_dir.join("store"),
        node: NodeId(node),
        address: String::new(),
        kek,
        kek_options,
    }
}

async fn rows(store: &RaftStore) -> usize {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan(&ROWS, KeyRange::all(), 10_000, false)
        .expect("scan")
        .len()
}

/// Opens a restored data directory as `tenko serve` would and reveals every secret.
async fn open_restored(data_dir: &Path, node: u64, secrets: &[(SecretRef, Vec<u8>)]) -> RaftStore {
    let store = RaftStore::open(store_config(&data_dir.join("store"), node))
        .await
        .expect("restored store opens");
    let (kek, options) = plain_kek(data_dir);
    let ring = kek
        .load_with(tenko_vault::KekInit::Require, &options)
        .expect("sealed generations load");
    let vault = StoreVault::open(Arc::new(store.clone()), ring)
        .await
        .expect("vault opens");
    for (secret, value) in secrets {
        let revealed = vault.get_system(&ctx(), *secret).await.expect("secret");
        assert_eq!(revealed.expose(), value.as_slice());
    }
    store
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_restores_with_its_secrets_ca_and_chain() {
    let root = tempfile::tempdir().expect("dir");
    let ring = ring();
    let source = RaftStore::open(store_config(&root.path().join("source"), 1))
        .await
        .expect("source");
    let secrets = populate(Arc::new(source.clone()), &ring).await;
    let created = create::from_live(
        &source,
        &ring,
        request(Target::Dir(root.path().join("backups"))),
    )
    .await
    .expect("backup");
    assert!(create::is_backup_name(&created.file_name()));
    assert_eq!(created.manifest.kek.active, "mem-00000002");
    assert!(created.manifest.ca_fingerprint.is_some());
    let leftovers: Vec<PathBuf> = std::fs::read_dir(root.path().join("backups"))
        .expect("dir")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(
        leftovers,
        std::slice::from_ref(&created.path),
        "no work files stay behind"
    );
    // Writes after the copy are not in the backup.
    let mut later = WriteBatch::for_request(&ctx());
    later.put(ROWS, b"row-later".to_vec(), b"after the backup".to_vec());
    source.propose(later).await.expect("later");
    source.shutdown().await.expect("shutdown");

    let checked = restore::check(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        root.path(),
        NodeId(1),
    )
    .await
    .expect("check");
    assert!(checked.digest_matches);
    assert!(checked.envelopes >= 5, "{}", checked.envelopes);
    assert_eq!(checked.ca_fingerprint, created.manifest.ca_fingerprint);

    let data_dir = root.path().join("restored");
    let dry = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 1),
        true,
    )
    .await
    .expect("dry run");
    assert!(dry.dry_run);
    assert!(!data_dir.join("store").exists(), "a dry run writes nothing");

    let report = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 1),
        false,
    )
    .await
    .expect("restore");
    assert!(!report.dry_run);
    assert!(data_dir.join(restore::NOTICE_FILE).exists());
    let notice = restore::take_notice(&data_dir)
        .expect("notice")
        .expect("some");
    assert_eq!(notice.revision, created.manifest.revision);

    let store = open_restored(&data_dir, 1, &secrets).await;
    assert_eq!(rows(&store).await, 200, "the later write is not restored");
    let mut write = WriteBatch::for_request(&ctx());
    write.put(ROWS, b"row-new".to_vec(), b"after the restore".to_vec());
    store
        .propose(write)
        .await
        .expect("the restored store takes writes");
    store.shutdown().await.expect("shutdown");

    let again = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 1),
        false,
    )
    .await
    .expect_err("a second restore into the same directory");
    assert!(matches!(again, BackupError::TargetNotEmpty(_)), "{again}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn damaged_files_and_wrong_secrets_leave_nothing_behind() {
    let root = tempfile::tempdir().expect("dir");
    let ring = ring();
    let source = RaftStore::open(store_config(&root.path().join("source"), 1))
        .await
        .expect("source");
    populate(Arc::new(source.clone()), &ring).await;
    let key = BackupKey::generate().expect("key");
    let mut backup = request(Target::File(root.path().join("one.tkbk")));
    backup.locks = vec![KeyLock::Recipient(key.recipient())];
    let created = create::from_live(&source, &ring, backup)
        .await
        .expect("backup");
    source.shutdown().await.expect("shutdown");

    let data_dir = root.path().join("restored");
    let error = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 1),
        false,
    )
    .await
    .expect_err("a passphrase does not open a recipient backup");
    assert!(error.is_key_refused());
    assert!(!data_dir.join("store").exists());

    let mut bytes = std::fs::read(&created.path).expect("read");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x40;
    let damaged = root.path().join("damaged.tkbk");
    std::fs::write(&damaged, &bytes).expect("write");
    let error = restore::restore(&damaged, Unlock::Key(&key), &target(&data_dir, 1), false)
        .await
        .expect_err("damaged");
    assert!(matches!(error, BackupError::Corrupt(_)), "{error}");
    assert!(!data_dir.join("store").exists());
    assert!(!data_dir.join(restore::NOTICE_FILE).exists());
    let leftovers = std::fs::read_dir(&data_dir)
        .expect("dir")
        .map(|entry| entry.expect("entry").file_name())
        .filter(|name| name.to_string_lossy().starts_with(".restore-"))
        .count();
    assert_eq!(leftovers, 0);

    restore::check(&created.path, Unlock::Key(&key), root.path(), NodeId(1))
        .await
        .expect("the undamaged file checks");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cluster_member_restores_as_a_single_controller() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let leader = cluster.wait_for_leader().await;
    let ring = ring();
    let secrets = populate(Arc::new(leader.clone()), &ring).await;
    let follower = cluster.a_follower().await;
    let root = tempfile::tempdir().expect("dir");
    // A follower answers once it has applied the leader's writes.
    let revision = leader.status().revision;
    follower
        .digest(Some(revision))
        .await
        .expect("the follower catches up");
    let created = create::from_live(
        &follower,
        &ring,
        request(Target::Dir(root.path().join("backups"))),
    )
    .await
    .expect("backup of a follower");
    assert_eq!(created.manifest.voters, [1, 2, 3]);
    cluster.shutdown().await;

    let data_dir = root.path().join("restored");
    let report = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 7),
        false,
    )
    .await
    .expect("restore");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("cluster of 3"))
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("restored as node 7"))
    );
    let store = open_restored(&data_dir, 7, &secrets).await;
    let membership = store.membership();
    assert_eq!(
        membership.voters.into_iter().collect::<Vec<_>>(),
        [NodeId(7)]
    );
    assert_eq!(rows(&store).await, 200);
    let mut write = WriteBatch::for_request(&ctx());
    write.put(ROWS, b"row-new".to_vec(), b"after the restore".to_vec());
    store
        .propose(write)
        .await
        .expect("a cluster of one takes writes");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_store_is_backed_up_offline_and_a_running_one_is_refused() {
    let root = tempfile::tempdir().expect("dir");
    let ring = ring();
    let store_dir = root.path().join("source");
    let source = RaftStore::open(store_config(&store_dir, 1))
        .await
        .expect("source");
    let secrets = populate(Arc::new(source.clone()), &ring).await;
    let busy = create::from_closed(
        &store_dir,
        NodeId(1),
        &ring,
        request(Target::Dir(root.path().join("backups"))),
    )
    .await
    .expect_err("the store is open");
    assert!(matches!(busy, BackupError::InUse(_)), "{busy}");
    source.shutdown().await.expect("shutdown");
    drop(source);

    let config = root.path().join("tenko.toml");
    std::fs::write(&config, "data_dir = \"/srv/tenko\"\n").expect("config");
    let mut offline = request(Target::Dir(root.path().join("backups")));
    offline.extras.config = Some(config);
    let created = create::from_closed(&store_dir, NodeId(1), &ring, offline)
        .await
        .expect("offline backup");
    assert!(created.manifest.part(super::archive::PART_CONFIG).is_some());

    let data_dir = root.path().join("restored");
    let report = restore::restore(
        &created.path,
        Unlock::Passphrase(PASSPHRASE),
        &target(&data_dir, 1),
        false,
    )
    .await
    .expect("restore");
    let restored_config = data_dir
        .join(restore::EXTRAS_DIR)
        .join(restore::CONFIG_FILE);
    assert!(report.written.contains(&restored_config));
    assert_eq!(
        std::fs::read_to_string(&restored_config).expect("config"),
        "data_dir = \"/srv/tenko\"\n"
    );
    let store = open_restored(&data_dir, 1, &secrets).await;
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_file_key_is_refused_first_and_backups_are_private() {
    let root = tempfile::tempdir().expect("dir");
    let ring = ring();
    let source = RaftStore::open(store_config(&root.path().join("source"), 1))
        .await
        .expect("source");
    populate(Arc::new(source.clone()), &ring).await;
    let created = create::from_live(
        &source,
        &ring,
        request(Target::Dir(root.path().join("backups"))),
    )
    .await
    .expect("backup");
    source.shutdown().await.expect("shutdown");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&created.path)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let data_dir = root.path().join("restored");
    let mut target = target(&data_dir, 1);
    target.kek = KekConfig::File {
        path: root.path().join("missing.key"),
        retired: Vec::new(),
    };
    for dry_run in [true, false] {
        let error = restore::restore(
            &created.path,
            Unlock::Passphrase(PASSPHRASE),
            &target,
            dry_run,
        )
        .await
        .expect_err("no key file");
        assert!(matches!(error, BackupError::InvalidKey(_)), "{error}");
    }
    assert!(!data_dir.exists());
}
