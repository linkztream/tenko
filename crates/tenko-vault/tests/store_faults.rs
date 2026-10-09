//! The vault when the store misbehaves: refused or failed writes change nothing, a reveal
//! never returns a value whose audit record could not be written (IAM-16), and a KEK
//! rotation does not strand an envelope under a KEK it reports as retired.

mod common;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use common::{assert_none, audit_of, ctx, envelope_of, scan_all, spec, stored_row, value, view};
use tenko_core::{
    Revision,
    secret::{SecretRef, VaultEnvelope},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, MemStore, Mutation, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tenko_vault::{KekRing, MemKek, StoreVault, Vault, VaultError, tables};
use tokio::sync::Notify;

/// A rendezvous that holds one write of a secret row until the test lets it go.
#[derive(Default)]
struct Gate {
    reached: Notify,
    release: Notify,
}

/// A store that can be told to refuse every proposal, or to hold the next write of a
/// secret row at a [`Gate`].
struct FaultStore {
    inner: MemStore,
    refuse: AtomicBool,
    gate: Mutex<Option<Arc<Gate>>>,
}

impl FaultStore {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            refuse: AtomicBool::new(false),
            gate: Mutex::new(None),
        }
    }

    fn refuse(&self, refuse: bool) {
        self.refuse.store(refuse, Ordering::SeqCst);
    }

    fn arm(&self, gate: Arc<Gate>) {
        *self.gate.lock().expect("gate lock") = Some(gate);
    }
}

#[async_trait::async_trait]
impl Store for FaultStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(StoreError::NoQuorum);
        }
        let writes_a_secret = batch.mutations.iter().any(
            |mutation| matches!(mutation, Mutation::Put { table, .. } if *table == tables::SECRETS),
        );
        let gate = if writes_a_secret {
            self.gate.lock().expect("gate lock").take()
        } else {
            None
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
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
        self.inner.status()
    }
}

async fn fault_vault(kek: &Arc<MemKek>) -> (MemStore, Arc<FaultStore>, Arc<StoreVault>) {
    let mem = MemStore::default();
    let fault = Arc::new(FaultStore::new(mem.clone()));
    let vault = StoreVault::open(
        Arc::clone(&fault) as Arc<dyn Store>,
        KekRing::new(Arc::clone(kek) as _),
    )
    .await
    .expect("open");
    (mem, fault, Arc::new(vault))
}

#[tokio::test]
async fn reveal_returns_no_value_when_its_audit_record_cannot_be_written() {
    let (mem, fault, vault) = fault_vault(&Arc::new(MemKek::generate("mem-1"))).await;
    let ctx = ctx();
    let operator = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("hunter2"))
        .await
        .expect("put");
    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put");

    fault.refuse(true);
    let result = vault.reveal(&ctx, operator).await;
    assert!(
        matches!(result, Err(VaultError::Store(StoreError::NoQuorum))),
        "{result:?}"
    );
    // A refusal whose audit record is lost is still a refusal, never a value.
    let result = vault.reveal(&ctx, system).await;
    assert!(result.is_err(), "{result:?}");
    fault.refuse(false);

    assert_none(
        &audit_of(&mem, "vault.secret.reveal").await,
        "reveal records from the failed attempts",
    );
    // Once the store is back, the reveal works and is audited.
    let revealed = vault.reveal(&ctx, operator).await.expect("reveal");
    assert_eq!(revealed.expose(), b"hunter2");
    assert_eq!(audit_of(&mem, "vault.secret.reveal").await.len(), 1);
}

#[tokio::test]
async fn failed_writes_change_nothing() {
    let (mem, fault, vault) = fault_vault(&Arc::new(MemKek::generate("mem-1"))).await;
    let ctx = ctx();
    let kept = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("original"))
        .await
        .expect("put");
    let before = stored_row(&mem, kept).await;

    fault.refuse(true);
    assert!(
        vault
            .put_system(&ctx, spec("auth.totp"), value("new"))
            .await
            .is_err()
    );
    assert!(
        vault
            .put_operator(&ctx, spec("connect.proxmox_token"), value("new"))
            .await
            .is_err()
    );
    assert!(vault.replace(&ctx, kept, value("replaced")).await.is_err());
    assert!(vault.rotate_dek(&ctx, kept).await.is_err());
    assert!(vault.delete(&ctx, kept).await.is_err());
    fault.refuse(false);

    let after = stored_row(&mem, kept).await;
    assert_eq!(after.value, before.value);
    assert_eq!(after.revision, before.revision);
    assert_eq!(
        vault.get_system(&ctx, kept).await.expect("get").expose(),
        b"original"
    );
    assert_eq!(vault.list().await.expect("list").len(), 1);
    assert_eq!(audit_of(&mem, "vault.secret.create").await.len(), 1);
    assert_none(
        &audit_of(&mem, "vault.secret.replace").await,
        "replace records",
    );
    assert_none(
        &audit_of(&mem, "vault.secret.delete").await,
        "delete records",
    );
}

#[tokio::test]
async fn a_failed_rotation_leaves_every_envelope_as_it_was_and_can_be_repeated() {
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let (mem, fault, vault) = fault_vault(&mem1).await;
    let ctx = ctx();
    let mut secrets = Vec::new();
    for index in 0..10 {
        let text = format!("value-{index}");
        let secret = vault
            .put_system(&ctx, spec("auth.totp"), value(&text))
            .await
            .expect("put");
        secrets.push((secret, text));
    }
    let before: Vec<_> = {
        let mut rows = Vec::new();
        for (secret, _) in &secrets {
            rows.push(stored_row(&mem, *secret).await.value);
        }
        rows
    };

    fault.refuse(true);
    let error = vault
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect_err("the store refuses the re-wrapped rows");
    assert!(matches!(error, VaultError::Store(StoreError::NoQuorum)));
    fault.refuse(false);

    // Nothing was half-written, and every value is still readable (the vault keeps both
    // KEKs loaded after a rotation attempt).
    for ((secret, text), original) in secrets.iter().zip(&before) {
        assert_eq!(&stored_row(&mem, *secret).await.value, original);
        assert_eq!(
            vault.get_system(&ctx, *secret).await.expect("get").expose(),
            text.as_bytes()
        );
    }
    assert_none(
        &audit_of(&mem, "vault.kek.rotate").await,
        "rotation records",
    );

    // Running it again finishes the job.
    let rotation = vault.rotate_kek(&ctx, mem2.clone()).await.expect("again");
    assert_eq!(rotation.rewrapped, 10);
    assert_eq!(audit_of(&mem, "vault.kek.rotate").await.len(), 1);
    for (secret, _) in &secrets {
        assert_eq!(envelope_of(&mem, *secret).await.key_id, "mem-2");
    }
}

#[tokio::test]
async fn rotation_rewraps_the_key_without_touching_or_hiding_damage_to_the_ciphertext() {
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let (mem, _fault, vault) = fault_vault(&mem1).await;
    let ctx = ctx();
    let mut secrets: Vec<(SecretRef, String)> = Vec::new();
    for index in 0..10 {
        let text = format!("value-{index}");
        let secret = vault
            .put_operator(&ctx, spec("connect.proxmox_token"), value(&text))
            .await
            .expect("put");
        secrets.push((secret, text));
    }
    let victim = secrets[5].0;
    let original = stored_row(&mem, victim).await.value;
    let mut tampered = VaultEnvelope::from_bytes(&original).expect("envelope");
    let mut payload = tampered.payload.to_vec();
    let last = payload.len() - 1;
    payload[last] ^= 0xFF;
    tampered.payload = payload.into();
    common::put_envelope(&mem, victim, &tampered).await;

    // Only the ciphertext was damaged, so unwrapping the data key works and the rotation
    // goes through; the damage stays visible, on read.
    let rotation = vault.rotate_kek(&ctx, mem2.clone()).await.expect("rotate");
    assert_eq!(rotation.rewrapped, 10);
    assert_eq!(
        vault
            .get_system(&ctx, victim)
            .await
            .expect_err("still damaged"),
        VaultError::Integrity
    );
}

#[tokio::test]
async fn a_rotation_stops_at_an_envelope_whose_wrapped_key_is_damaged_and_loses_nothing() {
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let ctx = ctx();
    let (mem_b, _fault_b, vault_b) = fault_vault(&mem1).await;
    let mut ids = Vec::new();
    for index in 0..6 {
        ids.push(
            vault_b
                .put_system(&ctx, spec("auth.totp"), value(&format!("v-{index}")))
                .await
                .expect("put"),
        );
    }
    let target = ids[3];
    let intact = stored_row(&mem_b, target).await.value;
    let mut broken = VaultEnvelope::from_bytes(&intact).expect("envelope");
    let mut payload = broken.payload.to_vec();
    payload[7 + 5] ^= 0x01; // inside the wrapped DEK
    broken.payload = payload.into();
    common::put_envelope(&mem_b, target, &broken).await;

    let error = vault_b
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect_err("a row that cannot be unwrapped stops the rotation");
    assert_eq!(error, VaultError::Integrity);
    for id in &ids {
        assert_eq!(
            envelope_of(&mem_b, *id).await.key_id,
            "mem-1",
            "nothing re-wrapped"
        );
    }
    assert_none(
        &audit_of(&mem_b, "vault.kek.rotate").await,
        "rotation records",
    );
    // Restoring the row lets the rotation complete.
    common::put_raw(&mem_b, target, intact)
        .await
        .expect("restore");
    let rotation = vault_b
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect("rotate");
    assert_eq!(rotation.rewrapped, 6);
}

/// A write that encrypted under the old KEK before a rotation started, but commits after
/// the rotation finished, must not leave the store with an envelope under a KEK that the
/// rotation reported as retired: the operator may delete that KEK as soon as
/// `rotate_kek` returns.
#[tokio::test]
async fn a_write_in_flight_during_rotation_does_not_strand_an_envelope_under_a_retired_kek() {
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let (mem, fault, vault) = fault_vault(&mem1).await;
    let ctx = ctx();
    for index in 0..5 {
        vault
            .put_system(&ctx, spec("auth.totp"), value(&format!("early-{index}")))
            .await
            .expect("put");
    }

    let gate = Arc::new(Gate::default());
    fault.arm(Arc::clone(&gate));
    let writer = {
        let vault = Arc::clone(&vault);
        tokio::spawn(async move {
            vault
                .put_system(&common::ctx(), spec("auth.totp"), value("late"))
                .await
        })
    };
    // The writer has encrypted under mem-1 and is now waiting to commit.
    gate.reached.notified().await;

    let rotation = vault
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect("rotation completes while the write is parked");
    assert_eq!(rotation.retired, ["mem-1"]);

    gate.release.notify_one();
    let late = writer.await.expect("writer task").expect("late write");

    let stranded = envelope_of(&mem, late).await.key_id;
    assert_eq!(
        stranded, "mem-2",
        "the late write is wrapped by {stranded}, which the rotation reported as retired"
    );
    let view = view(&mem).await;
    let under_old = scan_all(view.as_ref(), &tables::SECRETS)
        .iter()
        .filter(|(_, row)| {
            VaultEnvelope::from_bytes(&row.value).is_ok_and(|envelope| envelope.key_id == "mem-1")
        })
        .count();
    assert_eq!(under_old, 0, "envelopes still wrapped by the retired KEK");
}
