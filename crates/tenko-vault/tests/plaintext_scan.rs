//! Acceptance criterion NEVER-01: after a test run no table holds a plaintext marker, and
//! no write batch that the vault proposed carried one.
//!
//! The workload stores secrets of both classes whose values contain a unique marker, then
//! replaces, re-keys, reveals, deletes and rotates the KEK. Every table that the journal
//! ever recorded (plus the store's own tables) is scanned completely, and a spy around the
//! store keeps every batch the vault proposed, including the ones the store rejected.

mod common;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use common::{
    MARKER_PREFIX, assert_none, assert_some, cbor, contains, ctx, scan_all, spec,
    tables_containing, unique_marker, written_tables,
};
use tenko_core::{
    CounterKey, IdempotencyKey, ObjectRef, Revision, TableName, UserId,
    audit::AuditDraft,
    secret::{SecretClass, SecretRef},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, MemStore, ReadConsistency, ReadView, Store, StoreError,
    StoreStatus, WatchFilter, WriteBatch, tables,
};
use tenko_vault::{
    KekRing, MAX_SECRET_LEN, MemKek, SecretBytes, StoreVault, Vault, VaultError,
    tables as vault_tables,
};

const CANARY_VALUES: TableName = TableName::from_static("vault.canary_values");
const CANARY_KEYS: TableName = TableName::from_static("vault.canary_keys");

/// A store that delegates to a [`MemStore`] and remembers every batch it was asked to apply.
struct SpyStore {
    inner: MemStore,
    batches: Mutex<Vec<WriteBatch>>,
    rejected: AtomicUsize,
}

impl SpyStore {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            batches: Mutex::new(Vec::new()),
            rejected: AtomicUsize::new(0),
        }
    }

    fn proposed(&self) -> Vec<WriteBatch> {
        self.batches.lock().expect("spy lock").clone()
    }

    fn rejected(&self) -> usize {
        self.rejected.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Store for SpyStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.batches.lock().expect("spy lock").push(batch.clone());
        let result = self.inner.propose(batch).await;
        if result.is_err() {
            self.rejected.fetch_add(1, Ordering::SeqCst);
        }
        result
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

/// A secret the workload keeps track of: where it is, what class, what it holds now.
struct Entry {
    secret: SecretRef,
    class: SecretClass,
    text: String,
}

async fn create(
    vault: &StoreVault,
    class: SecretClass,
    index: usize,
    text: String,
    owner: ObjectRef,
) -> Entry {
    // A distinct idempotency key per write. The vault's own writes never record it (their
    // random keys and nonces could never replay), so system secrets go through a caller's
    // batch that keeps the key and fills `sys.idempotency`.
    let key = IdempotencyKey::new(format!("create-{class:?}-{index}")).expect("key");
    let ctx = ctx().with_idempotency(key);
    let value = SecretBytes::from(text.clone());
    let secret = match class {
        SecretClass::System => {
            let mut batch = WriteBatch::for_request(&ctx);
            let staged = vault.stage_put(
                &mut batch,
                &ctx,
                SecretClass::System,
                spec("auth.totp").owned_by(owner),
                &value,
            );
            match staged {
                Ok(secret) => vault
                    .store()
                    .propose(batch)
                    .await
                    .map(|_| secret)
                    .map_err(VaultError::from),
                Err(error) => Err(error),
            }
        }
        SecretClass::Operator => {
            vault
                .put_operator(
                    &ctx,
                    spec("connect.proxmox_token")
                        .owned_by(owner)
                        .labelled(format!("label-{index}")),
                    value,
                )
                .await
        }
    }
    .expect("create secret");
    Entry {
        secret,
        class,
        text,
    }
}

/// Runs the whole workload and returns the secrets that are still alive.
async fn workload(vault: &StoreVault, marker: &str) -> Vec<Entry> {
    let mut live = create_secrets(vault, marker).await;
    churn(vault, marker, &mut live).await;
    stage_secrets(vault, marker, &mut live).await;
    rotate_kek_and_continue(vault, marker, &mut live).await;
    live
}

/// Thirty secrets of each class, plus the bare marker and a value made only of markers.
async fn create_secrets(vault: &StoreVault, marker: &str) -> Vec<Entry> {
    let owner = ObjectRef::from(UserId::generate());
    let mut live: Vec<Entry> = Vec::new();
    for index in 0..30 {
        let padding = "pad".repeat(index);
        live.push(
            create(
                vault,
                SecretClass::System,
                index,
                format!("{marker}:system:{index}:{padding}"),
                owner,
            )
            .await,
        );
        live.push(
            create(
                vault,
                SecretClass::Operator,
                index,
                format!("{marker}:operator:{index}:{padding}"),
                owner,
            )
            .await,
        );
    }
    live.push(create(vault, SecretClass::Operator, 100, marker.to_owned(), owner).await);
    live.push(create(vault, SecretClass::System, 101, marker.repeat(1000), owner).await);
    live
}

/// Replacements, DEK rotations, reveals, refused reveals and deletions.
async fn churn(vault: &StoreVault, marker: &str, live: &mut Vec<Entry>) {
    let ctx = ctx();
    for (turn, entry) in live
        .iter_mut()
        .filter(|entry| entry.class == SecretClass::Operator)
        .take(10)
        .enumerate()
    {
        entry.text = format!("{marker}:replaced:{turn}");
        vault
            .replace(&ctx, entry.secret, SecretBytes::from(entry.text.clone()))
            .await
            .expect("replace");
    }
    for entry in live
        .iter()
        .filter(|entry| entry.class == SecretClass::System)
        .take(10)
    {
        vault
            .rotate_dek(&ctx, entry.secret)
            .await
            .expect("rotate_dek");
    }
    for entry in live
        .iter()
        .filter(|entry| entry.class == SecretClass::Operator)
        .skip(5)
        .take(10)
    {
        let revealed = vault.reveal(&ctx, entry.secret).await.expect("reveal");
        assert_eq!(revealed.expose(), entry.text.as_bytes());
    }
    for entry in live
        .iter()
        .filter(|entry| entry.class == SecretClass::System)
        .skip(2)
        .take(5)
    {
        let error = vault.reveal(&ctx, entry.secret).await.expect_err("refused");
        assert!(matches!(error, VaultError::NotRevealable { .. }));
    }
    for class in [SecretClass::System, SecretClass::Operator] {
        for _ in 0..5 {
            let position = live
                .iter()
                .rposition(|entry| entry.class == class)
                .expect("an entry to delete");
            let entry = live.remove(position);
            vault.delete(&ctx, entry.secret).await.expect("delete");
        }
    }
}

/// Batches that carry staged secrets: one commits, one is rejected by the store, and an
/// oversized value never gets as far as a batch.
async fn stage_secrets(vault: &StoreVault, marker: &str, live: &mut Vec<Entry>) {
    let ctx = ctx();

    let mut batch = WriteBatch::for_request(&ctx);
    let text = format!("{marker}:staged");
    let secret = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::Operator,
            spec("connect.proxmox_token").labelled("staged"),
            &SecretBytes::from(text.clone()),
        )
        .expect("stage_put");
    batch.bump(CounterKey::new("vault.test_counter"));
    vault.store().propose(batch).await.expect("staged batch");
    live.push(Entry {
        secret,
        class: SecretClass::Operator,
        text,
    });

    let mut batch = WriteBatch::for_request(&ctx);
    vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::System,
            spec("auth.totp"),
            &SecretBytes::from(format!("{marker}:rejected")),
        )
        .expect("stage_put");
    batch.expect_version(CANARY_VALUES, vec![1], Some(Revision(99)));
    vault
        .store()
        .propose(batch)
        .await
        .expect_err("precondition fails");

    let oversized = SecretBytes::new([marker.as_bytes(), &vec![b'o'; MAX_SECRET_LEN]].concat());
    vault
        .put_operator(&ctx, spec("connect.proxmox_token"), oversized)
        .await
        .expect_err("too large");
}

/// Rotates the KEK, then keeps writing under the new one.
async fn rotate_kek_and_continue(vault: &StoreVault, marker: &str, live: &mut Vec<Entry>) {
    let ctx = ctx();
    let rotation = vault
        .rotate_kek(&ctx, Arc::new(MemKek::generate("mem-2")))
        .await
        .expect("rotate_kek");
    assert_eq!(rotation.active, "mem-2");
    assert_eq!(rotation.rewrapped, live.len());
    for (turn, entry) in live.iter_mut().take(3).enumerate() {
        entry.text = format!("{marker}:after-rotation:{turn}");
        vault
            .replace(&ctx, entry.secret, SecretBytes::from(entry.text.clone()))
            .await
            .expect("replace after rotation");
    }
    let owner = ObjectRef::from(UserId::generate());
    live.push(
        create(
            vault,
            SecretClass::System,
            200,
            format!("{marker}:after-rotation:new"),
            owner,
        )
        .await,
    );
}

#[tokio::test]
async fn no_table_and_no_proposed_batch_holds_the_plaintext() {
    let marker = unique_marker();
    let random_part = marker[MARKER_PREFIX.len()..].to_owned();
    let mem = MemStore::default();
    let spy = Arc::new(SpyStore::new(mem.clone()));
    let vault = StoreVault::open(
        Arc::clone(&spy) as Arc<dyn Store>,
        KekRing::new(Arc::new(MemKek::generate("mem-1"))),
    )
    .await
    .expect("open");

    let live = workload(&vault, &marker).await;

    // The scan is not vacuous: the tables of interest exist and hold rows.
    let view = mem.read(ReadConsistency::Local).await.expect("view");
    let seen = written_tables(view.as_ref());
    let names: Vec<&str> = seen.iter().map(TableName::as_str).collect();
    for expected in [
        "vault.secrets",
        "vault.secret_meta",
        "vault.operator_index",
        "sys.audit",
        "sys.journal",
        "sys.idempotency",
        "sys.counters",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    assert_eq!(
        scan_all(view.as_ref(), &vault_tables::SECRETS).len(),
        live.len()
    );
    assert!(scan_all(view.as_ref(), tables::AUDIT.name()).len() > 100);
    assert!(scan_all(view.as_ref(), tables::JOURNAL.name()).len() > 100);
    assert_some(
        &scan_all(view.as_ref(), &tables::IDEMPOTENCY),
        "idempotency records",
    );
    assert_some(&scan_all(view.as_ref(), &tables::COUNTERS), "counters");

    // The scan target is real: the survivors do decrypt to values that contain the marker.
    for entry in &live {
        let value = vault
            .get_system(&ctx(), entry.secret)
            .await
            .expect("get_system");
        assert_eq!(value.expose(), entry.text.as_bytes());
        assert!(contains(value.expose(), marker.as_bytes()));
    }

    // No key and no value of any table holds the marker, its random part or its prefix.
    for needle in [marker.as_str(), random_part.as_str(), MARKER_PREFIX] {
        let hits = tables_containing(view.as_ref(), needle.as_bytes());
        assert!(hits.is_empty(), "plaintext {needle:?} found in {hits:?}");
    }

    // No batch the vault proposed carried it either, rejected batches included.
    let proposed = spy.proposed();
    assert!(proposed.len() > 100, "only {} batches", proposed.len());
    assert!(
        spy.rejected() >= 1,
        "the rejected batch must have been seen"
    );
    for batch in &proposed {
        let encoded = cbor(batch);
        let debug = format!("{batch:?}");
        for needle in [marker.as_str(), random_part.as_str(), MARKER_PREFIX] {
            assert!(
                !contains(&encoded, needle.as_bytes()),
                "CBOR of a proposed batch holds {needle:?}"
            );
            assert!(
                !debug.contains(needle),
                "Debug of a proposed batch holds {needle:?}"
            );
        }
    }
}

#[tokio::test]
async fn the_scan_does_find_plaintext_when_it_is_there() {
    // Negative control: if a package did put the marker into a table, a batch or the
    // audit log, the machinery above would see it.
    let marker = unique_marker();
    let mem = MemStore::default();
    let spy = SpyStore::new(mem.clone());

    let mut batch = WriteBatch::for_request(&ctx());
    batch.put(CANARY_VALUES, vec![1], marker.clone().into_bytes());
    batch.put(CANARY_KEYS, marker.clone().into_bytes(), vec![2]);
    batch.audit(
        AuditDraft::success(
            tenko_core::audit::AuditAction::from_static("vault.test.leak"),
            vec![],
        )
        .with_context("leak", marker.clone()),
    );
    spy.propose(batch).await.expect("commit");

    let view = mem.read(ReadConsistency::Local).await.expect("view");
    let hits = tables_containing(view.as_ref(), marker.as_bytes());
    let hit_tables: Vec<&str> = hits.iter().map(|(table, _)| table.as_str()).collect();
    for expected in [
        "vault.canary_values",
        "vault.canary_keys",
        "sys.audit",
        "sys.journal",
    ] {
        assert!(
            hit_tables.contains(&expected),
            "{expected} not in {hit_tables:?}"
        );
    }

    let proposed = spy.proposed();
    assert_eq!(proposed.len(), 1);
    assert!(contains(&cbor(&proposed[0]), marker.as_bytes()));
    assert!(format!("{:?}", proposed[0]).contains(&marker));
}

#[tokio::test]
async fn a_secret_that_is_deleted_leaves_no_row_and_no_plaintext_behind() {
    let marker = unique_marker();
    let mem = MemStore::default();
    let spy = Arc::new(SpyStore::new(mem.clone()));
    let vault = StoreVault::open(
        Arc::clone(&spy) as Arc<dyn Store>,
        KekRing::new(Arc::new(MemKek::generate("mem-1"))),
    )
    .await
    .expect("open");
    let ctx = ctx();

    let secret = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token"),
            SecretBytes::from(format!("{marker}:short-lived")),
        )
        .await
        .expect("put");
    vault.reveal(&ctx, secret).await.expect("reveal");
    vault.delete(&ctx, secret).await.expect("delete");

    let view = mem.read(ReadConsistency::Local).await.expect("view");
    assert_none(
        &scan_all(view.as_ref(), &vault_tables::SECRETS),
        "secret rows",
    );
    assert_none(
        &scan_all(view.as_ref(), vault_tables::META.name()),
        "meta rows",
    );
    assert_none(
        &scan_all(view.as_ref(), vault_tables::OPERATOR_INDEX.name()),
        "operator index rows",
    );
    assert_none(
        &tables_containing(view.as_ref(), marker.as_bytes()),
        "tables holding the marker",
    );
    for batch in spy.proposed() {
        assert!(!contains(&cbor(&batch), marker.as_bytes()));
    }
}
