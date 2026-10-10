//! The installation's KEK across controllers (ADR 0014): the KEK state the vault records at
//! start, the R15 alarms, the online rotation in two phases, and the fetch of a missing
//! generation at start. Controllers are simulated in one process: one store (as replication
//! would make it), a key directory and a vault per controller, and peers that answer a
//! fetch from another controller's ring.

mod common;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use common::{audit_of, cleanup, ctx, scratch_dir, spec, value};
use tenko_core::{NodeId, Revision, cluster::LEADER_EPOCH, secret::SecretRef};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, MemStore, MemberStatus, QuorumState, ReadConsistency,
    ReadView, ReadViewExt, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tenko_vault::{
    KekConfig, KekInit, KekOptions, KekProtection, KekRing, MemPeers, StoreVault, Vault,
    VaultError, VaultStart,
    distribution::{KekAdmin, KekPeers, NoPeers, RotationStep, deposed, fetch_missing},
    kek::{KekDir, KekSealer, LocalKek, PlainSealer},
    kek_state::{self, KekState, RotationPhase, VaultAlarmKind},
    transfer::{self, TransferKey},
};
use zeroize::Zeroizing;

/// A store shared by every simulated controller that reports the cluster members the test
/// sets, as the leader's Raft metrics would.
struct ClusterStore {
    inner: MemStore,
    members: Mutex<Vec<MemberStatus>>,
}

impl ClusterStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemStore::default(),
            members: Mutex::new(Vec::new()),
        })
    }

    /// Members: `(node, reachable)`.
    fn set_members(&self, members: &[(u64, bool)]) {
        *self.members.lock().expect("members") = members
            .iter()
            .map(|&(node, reachable)| MemberStatus {
                node: NodeId(node),
                voter: true,
                matched: Some(1),
                lag_entries: Some(0),
                last_contact_ms: reachable.then_some(100),
            })
            .collect();
    }
}

#[async_trait::async_trait]
impl Store for ClusterStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        let mut status = self.inner.status();
        status
            .members
            .clone_from(&self.members.lock().expect("members"));
        if !status.members.is_empty() {
            status.quorum = QuorumState::Healthy;
        }
        status
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// One simulated controller.
struct Controller {
    node: NodeId,
    config: KekConfig,
    options: KekOptions,
    peers: Arc<MemPeers>,
    admin: Arc<KekAdmin>,
}

impl Controller {
    fn vault(&self) -> &Arc<StoreVault> {
        self.admin.vault()
    }
}

fn file_provider(root: &Path) -> (KekConfig, KekOptions) {
    (
        KekConfig::File {
            path: root.join("key").join("kek.key"),
            retired: Vec::new(),
        },
        KekOptions {
            allow_plain: false,
            file_dir: Some(root.join("kek")),
        },
    )
}

async fn start(
    store: &Arc<ClusterStore>,
    node: NodeId,
    root: &Path,
    ring: KekRing,
    source: Option<Arc<StoreVault>>,
) -> Controller {
    let (config, options) = file_provider(root);
    let vault = StoreVault::start(
        Arc::clone(store) as Arc<dyn Store>,
        ring,
        &VaultStart {
            node,
            provider: config.provider_name().to_owned(),
        },
    )
    .await
    .expect("vault start");
    let peers = Arc::new(MemPeers::new(node, source));
    let admin = KekAdmin::new(
        Arc::new(vault),
        config.clone(),
        options.clone(),
        node,
        Arc::clone(&peers) as Arc<dyn KekPeers>,
    );
    Controller {
        node,
        config,
        options,
        peers,
        admin,
    }
}

/// Controller 1, the first of the installation.
async fn first(store: &Arc<ClusterStore>, root: &Path) -> Controller {
    let (config, options) = file_provider(root);
    let ring = config
        .load_with(KekInit::CreateIfMissing, &options)
        .expect("first key");
    start(store, NodeId(1), root, ring, None).await
}

/// A controller that joins with a transfer from `from`.
async fn join(store: &Arc<ClusterStore>, root: &Path, node: u64, from: &Controller) -> Controller {
    let (config, options) = file_provider(root);
    config
        .load_with(KekInit::CreateIfMissing, &options)
        .expect("own root key");
    let key = TransferKey::generate().expect("transfer key");
    let context =
        transfer::join_context(NodeId(node), [u8::try_from(node % 256).expect("byte"); 16]);
    let sealed =
        transfer::seal_ring(&from.vault().ring(), &key.public_key(), &context).expect("seal");
    let received = key
        .open(sealed.format, &sealed.sealed, &context)
        .expect("open");
    let ring = config.import_with(&received, &options).expect("import");
    start(
        store,
        NodeId(node),
        root,
        ring,
        Some(Arc::clone(from.vault())),
    )
    .await
}

async fn state(store: &Arc<ClusterStore>) -> KekState {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    kek_state::read_state(view.as_ref())
        .expect("read")
        .expect("state")
        .0
}

/// Runs the leader's steps and the followers' rounds until the rotation ends.
async fn drive(store: &Arc<ClusterStore>, leader: &Controller, others: &[&Controller]) -> KekState {
    for _ in 0..40 {
        leader.admin.rotation_step(0).await.expect("leader step");
        for other in others {
            other.admin.sync_once().await.expect("follower round");
        }
        let state = state(store).await;
        if !state.rotating() {
            return state;
        }
    }
    panic!(
        "the rotation did not end: {:?}",
        state(store).await.rotation
    );
}

async fn put_secrets(vault: &StoreVault, count: usize) -> Vec<SecretRef> {
    let mut secrets = Vec::new();
    for index in 0..count {
        secrets.push(
            vault
                .put_operator(
                    &ctx(),
                    spec("vault.test_rotation"),
                    value(&format!("v-{index}")),
                )
                .await
                .expect("put"),
        );
    }
    secrets
}

async fn assert_reads(vault: &StoreVault, secrets: &[SecretRef]) {
    for secret in secrets {
        vault.get_system(&ctx(), *secret).await.expect("readable");
    }
}

async fn envelope_ids(store: &Arc<ClusterStore>, secrets: &[SecretRef]) -> Vec<String> {
    let mut ids = Vec::new();
    for secret in secrets {
        ids.push(common::envelope_of(store.as_ref(), *secret).await.key_id);
    }
    ids
}

#[tokio::test]
async fn the_vault_records_the_kek_state_and_protection_at_start() {
    let root = scratch_dir("dist-start");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let state = state(&store).await;
    assert_eq!(state.active, one.vault().ring().active().id());
    assert_eq!(state.generations.len(), 1);
    assert_eq!(state.generations[0].created_by, Some(NodeId(1)));
    let status = one.admin.status().await.expect("status");
    assert_eq!(status.provider, "file");
    assert_eq!(status.protection, KekProtection::PlainFile);
    assert_eq!(status.controllers.len(), 1);
    assert_eq!(status.controllers[0].node, NodeId(1));
    assert!(status.warnings.iter().any(|w| w.code == "vault.kek.weak"));
    let summary = one.admin.summary().expect("cached");
    assert_eq!(summary.active, status.active);
    assert_eq!(summary.generations, 1);
    cleanup(&root);
}

#[tokio::test]
async fn an_online_rotation_reaches_running_members_and_a_stopped_one_fetches_at_start() {
    let root = scratch_dir("dist-rotate");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let secrets = put_secrets(one.vault(), 5).await;
    let two = join(&store, &root.join("c2"), 1001, &one).await;
    let three = join(&store, &root.join("c3"), 1002, &one).await;
    assert_reads(two.vault(), &secrets).await;
    let old = one.vault().ring().active().id().to_owned();
    // Controller 1002 is stopped: the leader cannot reach it.
    store.set_members(&[(1, true), (1001, true), (1002, false)]);
    drop(three);

    one.admin.request_rotation(&ctx()).await.expect("request");
    assert!(matches!(
        one.admin.request_rotation(&ctx()).await,
        Err(VaultError::RotationInProgress)
    ));
    // The leader creates the generation and waits for 1001, which has not fetched it yet.
    assert_eq!(
        one.admin.rotation_step(0).await.expect("create"),
        RotationStep::Advanced
    );
    assert_eq!(
        one.admin.rotation_step(0).await.expect("wait"),
        RotationStep::Idle
    );
    let waiting = state(&store).await;
    let rotation = waiting.rotation.clone().expect("rotation");
    assert_eq!(rotation.phase, RotationPhase::Distributing);
    assert_eq!(rotation.waiting_for, [NodeId(1001)]);
    assert_eq!(rotation.unreachable, [NodeId(1002)]);
    let new = rotation.generation.clone().expect("generation");
    assert_eq!(
        waiting.active, old,
        "nothing is active before every member holds it"
    );

    let done = drive(&store, &one, &[&two]).await;
    let rotation = done.rotation.expect("rotation");
    assert_eq!(rotation.phase, RotationPhase::Done, "{rotation:?}");
    assert_eq!(rotation.rewrapped, 5);
    assert_eq!(done.active, new);
    assert!(done.pending.is_none());
    // Every envelope is under the new generation: the state lists only it.
    assert_eq!(done.generations.len(), 1);
    assert!(done.epoch > waiting.epoch);
    assert_eq!(envelope_ids(&store, &secrets).await, vec![new.clone(); 5]);
    assert_eq!(two.vault().ring().active().id(), new);
    assert!(two.peers.fetches() >= 1);
    assert_reads(two.vault(), &secrets).await;
    // A write on a follower lands under the new generation.
    let later = put_secrets(two.vault(), 1).await;
    assert_eq!(
        envelope_ids(&store, &later).await,
        std::slice::from_ref(&new)
    );
    for action in [
        "vault.kek.rotate_request",
        "vault.kek.activate",
        "vault.kek.rotate",
    ] {
        assert_eq!(audit_of(store.as_ref(), action).await.len(), 1, "{action}");
    }

    // The stopped controller starts again: the cluster step fetches the generation.
    let (config, options) = file_provider(&root.join("c3"));
    let ring = config.load_with(KekInit::Require, &options).expect("load");
    assert!(!ring.contains(&new));
    assert!(matches!(
        StoreVault::open(Arc::clone(&store) as Arc<dyn Store>, ring.clone()).await,
        Err(VaultError::KekUnavailable { .. })
    ));
    let peers = MemPeers::new(NodeId(1002), Some(Arc::clone(one.vault())));
    let ring = fetch_missing(
        store.as_ref(),
        &config,
        &options,
        ring,
        NodeId(1002),
        &peers,
    )
    .await
    .expect("fetch");
    assert!(ring.contains(&new));
    let three = start(&store, NodeId(1002), &root.join("c3"), ring, None).await;
    assert_eq!(three.vault().ring().active().id(), new);
    assert_reads(three.vault(), &secrets).await;
    assert_reads(three.vault(), &later).await;
    cleanup(&root);
}

#[tokio::test]
async fn a_write_that_races_the_activation_is_redone_under_the_new_generation() {
    let root = scratch_dir("dist-race");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let two = join(&store, &root.join("c2"), 1001, &one).await;
    store.set_members(&[(1, true), (1001, true)]);
    one.admin.request_rotation(&ctx()).await.expect("request");
    one.admin.rotation_step(0).await.expect("create");
    two.admin.sync_once().await.expect("fetch and acknowledge");
    // The leader activates; the follower has not seen the change yet.
    one.admin.rotation_step(0).await.expect("activate");
    let new = state(&store).await.active;
    assert_ne!(two.vault().ring().active().id(), new);
    let written = put_secrets(two.vault(), 1).await;
    assert_eq!(
        envelope_ids(&store, &written).await,
        std::slice::from_ref(&new)
    );
    assert_eq!(two.vault().ring().active().id(), new);
    cleanup(&root);
}

#[tokio::test]
async fn a_reachable_member_that_does_not_take_the_generation_fails_the_rotation() {
    let root = scratch_dir("dist-timeout");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let secrets = put_secrets(one.vault(), 2).await;
    let _two = join(&store, &root.join("c2"), 1001, &one).await;
    store.set_members(&[(1, true), (1001, true)]);
    one.admin.set_distribute_timeout(Duration::ZERO);
    let old = state(&store).await.active;
    one.admin.request_rotation(&ctx()).await.expect("request");
    one.admin.rotation_step(0).await.expect("create");
    tokio::time::sleep(Duration::from_millis(5)).await;
    one.admin.rotation_step(0).await.expect("time out");
    let failed = state(&store).await;
    let rotation = failed.rotation.clone().expect("rotation");
    assert_eq!(rotation.phase, RotationPhase::Failed);
    assert_eq!(rotation.waiting_for, [NodeId(1001)]);
    assert!(
        rotation
            .error
            .as_deref()
            .is_some_and(|e| e.contains("1001"))
    );
    assert_eq!(failed.active, old, "nothing changed for the envelopes");
    assert!(failed.pending.is_none());
    assert_eq!(
        failed.abandoned,
        rotation.generation.clone().into_iter().collect::<Vec<_>>()
    );
    // The leader holds the abandoned generation as its newest file; a restart keeps the
    // installation's active generation.
    let reloaded = one
        .config
        .load_with(KekInit::Require, &one.options)
        .expect("reload");
    assert_ne!(reloaded.active().id(), old);
    let restarted = start(&store, NodeId(1), &root.join("c1"), reloaded, None).await;
    assert_eq!(restarted.vault().ring().active().id(), old);
    assert_eq!(envelope_ids(&store, &secrets).await, vec![old.clone(); 2]);
    let status = one.admin.status().await.expect("status");
    assert!(
        status
            .warnings
            .iter()
            .any(|w| w.code == "vault.kek.rotation_failed")
    );
    // A new request is accepted after a failure.
    one.admin.request_rotation(&ctx()).await.expect("again");
    cleanup(&root);
}

#[tokio::test]
async fn a_deposed_leader_cannot_advance_a_rotation() {
    let root = scratch_dir("dist-deposed");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    one.admin.request_rotation(&ctx()).await.expect("request");
    // Another controller took office: the leader epoch moved on.
    let mut batch = WriteBatch::for_request(&ctx());
    batch.bump(LEADER_EPOCH);
    store.propose(batch).await.expect("new term");
    let error = one.admin.rotation_step(0).await.expect_err("fenced");
    assert!(deposed(&error), "{error:?}");
    assert_eq!(
        state(&store).await.rotation.expect("rotation").phase,
        RotationPhase::Requested
    );
    // The new leader continues.
    assert_eq!(
        one.admin.rotation_step(1).await.expect("new term"),
        RotationStep::Advanced
    );
    cleanup(&root);
}

#[tokio::test]
async fn the_services_complete_a_rotation_on_their_own() {
    let root = scratch_dir("dist-services");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let secrets = put_secrets(one.vault(), 3).await;
    let two = join(&store, &root.join("c2"), 1001, &one).await;
    store.set_members(&[(1, true), (1001, true)]);
    let stop = tokio_util::sync::CancellationToken::new();
    let follower = tokio::spawn(Arc::clone(&two.admin).run(stop.clone()));
    let service = one.admin.rotation_service();
    assert_eq!(service.name(), "vault.kek_rotation");
    let leader = {
        let stop = stop.clone();
        tokio::spawn(async move { service.run(0, stop).await })
    };
    one.admin.request_rotation(&ctx()).await.expect("request");
    let mut done = None;
    for _ in 0..200 {
        let state = state(&store).await;
        if state
            .rotation
            .as_ref()
            .is_some_and(|rotation| !rotation.phase.is_running())
        {
            done = Some(state);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let done = done.expect("the rotation ends on its own");
    assert_eq!(
        done.rotation.as_ref().map(|rotation| rotation.phase),
        Some(RotationPhase::Done)
    );
    assert_eq!(
        envelope_ids(&store, &secrets).await,
        vec![done.active.clone(); 3]
    );
    for _ in 0..100 {
        if two.vault().ring().active().id() == done.active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(two.vault().ring().active().id(), done.active);
    stop.cancel();
    follower.await.expect("follower task");
    assert_eq!(leader.await.expect("leader task"), Ok(()));
    cleanup(&root);
}

#[tokio::test]
async fn fetch_missing_contacts_nobody_when_nothing_is_missing() {
    let root = scratch_dir("dist-nothing");
    let store = ClusterStore::new();
    let one = first(&store, &root.join("c1")).await;
    let ring = one.vault().ring().as_ref().clone();
    let ring = fetch_missing(
        store.as_ref(),
        &one.config,
        &one.options,
        ring,
        one.node,
        &NoPeers,
    )
    .await
    .expect("nothing to fetch");
    assert_eq!(ring.active().id(), one.vault().ring().active().id());
    cleanup(&root);
}

/// A stand-in for a sealing mechanism (DPAPI, `systemd-creds`) on every platform.
#[derive(Debug)]
struct Sealed;

impl KekSealer for Sealed {
    fn name(&self) -> &'static str {
        "sealed"
    }

    fn protection(&self) -> KekProtection {
        KekProtection::SystemdCreds { tpm2: true }
    }

    fn seal(&self, _label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(plaintext.iter().rev().copied().collect())
    }

    fn unseal(&self, _label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(sealed.iter().rev().copied().collect()))
    }
}

async fn start_with(store: &Arc<ClusterStore>, ring: KekRing, provider: &str) -> Arc<KekAdmin> {
    let vault = StoreVault::start(
        Arc::clone(store) as Arc<dyn Store>,
        ring,
        &VaultStart {
            node: NodeId(1),
            provider: provider.to_owned(),
        },
    )
    .await
    .expect("start");
    KekAdmin::new(
        Arc::new(vault),
        KekConfig::File {
            path: PathBuf::from("unused"),
            retired: Vec::new(),
        },
        KekOptions::default(),
        NodeId(1),
        Arc::new(NoPeers),
    )
}

#[tokio::test]
async fn a_plain_generation_dropped_beside_a_sealed_one_is_refused_and_alarmed() {
    let root = scratch_dir("dist-r15");
    let dir = root.join("kek");
    let sealed = KekDir::new(&dir, Arc::new(Sealed));
    let first = sealed
        .load(KekInit::CreateIfMissing)
        .expect("sealed generation");
    // Someone who can write the directory drops a plain generation numbered above it.
    KekDir::new(&dir, Arc::new(PlainSealer))
        .allowing_plain(true)
        .create_next()
        .expect("dropped");
    let ring = sealed.load(KekInit::Require).expect("load");
    assert_eq!(ring.active().id(), first.active().id());
    assert_eq!(ring.refused().len(), 1);

    let store = ClusterStore::new();
    let admin = start_with(&store, ring.clone(), "systemd_creds").await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let (alarm, _) = view
        .get_typed(
            &kek_state::tables::ALARMS,
            &kek_state::refused_alarm_key(NodeId(1), 2),
        )
        .expect("read")
        .expect("alarm");
    assert_eq!(alarm.kind, VaultAlarmKind::PlainRefused);
    assert_eq!(alarm.code, "vault.kek.downgrade");
    assert_eq!(alarm.params["generation"], "2");
    let audit = audit_of(store.as_ref(), "vault.kek.downgrade").await;
    assert_eq!(audit.len(), 1);
    let status = admin.status().await.expect("status");
    assert_eq!(status.refused.len(), 1);
    assert!(status.warnings.iter().any(|w| {
        w.code == "vault.kek.downgrade"
            && w.params.get("cause").map(String::as_str) == Some("plain_generation")
    }));
    // Every start raises it again while the file is there.
    start_with(&store, ring, "systemd_creds").await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let (alarm, _) = view
        .get_typed(
            &kek_state::tables::ALARMS,
            &kek_state::refused_alarm_key(NodeId(1), 2),
        )
        .expect("read")
        .expect("alarm");
    assert_eq!(alarm.count, 2);
    cleanup(&root);
}

fn ring_with(protection: KekProtection) -> KekRing {
    let key = Zeroizing::new([7u8; 32]);
    KekRing::new(Arc::new(
        LocalKek::new("cred-1-00c0ffee", protection, &key).expect("kek"),
    ))
}

#[tokio::test]
async fn a_weaker_provider_at_start_raises_the_downgrade_alarm_once() {
    let store = ClusterStore::new();
    let tpm2 = KekProtection::SystemdCreds { tpm2: true };
    start_with(&store, ring_with(tpm2), "systemd_credential").await;
    let alarms = |view: &Arc<dyn ReadView>| {
        view.get_typed(
            &kek_state::tables::ALARMS,
            &kek_state::downgrade_alarm_key(NodeId(1)),
        )
        .expect("read")
        .map(|(alarm, _)| alarm)
    };
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert!(alarms(&view).is_none());

    let admin = start_with(&store, ring_with(KekProtection::PlainFile), "file").await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let alarm = alarms(&view).expect("downgrade alarm");
    assert_eq!(alarm.kind, VaultAlarmKind::KekDowngrade);
    assert_eq!(alarm.params["from"], "systemd_creds_tpm2");
    assert_eq!(alarm.params["to"], "plain_file");
    assert_eq!(
        audit_of(store.as_ref(), "vault.kek.downgrade").await.len(),
        1
    );
    let status = admin.status().await.expect("status");
    assert_eq!(status.strongest, Some(tpm2));
    assert!(
        status
            .warnings
            .iter()
            .any(|w| w.code == "vault.kek.downgrade")
    );

    // The same weaker start again: the warning stays, the alarm is not raised again.
    let admin = start_with(&store, ring_with(KekProtection::PlainFile), "file").await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(alarms(&view).expect("alarm").count, 1);
    assert_eq!(
        audit_of(store.as_ref(), "vault.kek.downgrade").await.len(),
        1
    );
    assert!(
        admin
            .status()
            .await
            .expect("status")
            .warnings
            .iter()
            .any(|w| w.code == "vault.kek.downgrade")
    );

    // Back to the sealed provider: no warning.
    let admin = start_with(&store, ring_with(tpm2), "systemd_credential").await;
    assert!(
        !admin
            .status()
            .await
            .expect("status")
            .warnings
            .iter()
            .any(|w| w.code == "vault.kek.downgrade")
    );
}
