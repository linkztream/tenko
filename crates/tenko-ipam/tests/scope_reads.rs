//! The scope checks of IAM-01 read the anchors index in memory, never the store: a write
//! of a principal limited to a prefix reads the store exactly as often as the same write of
//! a principal that reaches everything, for the plan and for the apply. The counts are
//! printed for the comparison with an earlier build (`--no-capture`).

mod common;

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use common::*;
use tenko_core::{
    Action, Authorizer, Denied, ObjectKind, ObjectRef, PrefixId, Principal, Revision, ScopeFilter,
    ScopeRule,
    ipam::{AssignmentMode, Status},
};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::{AddressPatch, UpdateAddress},
    scope::ScopeIndex,
};
use tenko_store::{
    ChangeStream, Committed, CounterKey, DerivedIndex, KeyRange, Leadership, MemStore,
    ReadConsistency, ReadView, Store, StoreError, StoreStatus, Versioned, WatchFilter, WriteBatch,
};

/// Reads of the store: views opened, and the gets, scans and counters read through them.
#[derive(Default)]
struct Reads {
    views: AtomicU64,
    lookups: AtomicU64,
}

impl Reads {
    fn total(&self) -> (u64, u64) {
        (
            self.views.load(Ordering::SeqCst),
            self.lookups.load(Ordering::SeqCst),
        )
    }
}

struct CountingStore {
    inner: MemStore,
    reads: Arc<Reads>,
}

struct CountingView {
    inner: Arc<dyn ReadView>,
    reads: Arc<Reads>,
}

impl ReadView for CountingView {
    fn revision(&self) -> Revision {
        self.inner.revision()
    }

    fn get(
        &self,
        table: &tenko_core::TableName,
        key: &[u8],
    ) -> Result<Option<Versioned>, StoreError> {
        self.reads.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.get(table, key)
    }

    fn scan(
        &self,
        table: &tenko_core::TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(bytes::Bytes, Versioned)>, StoreError> {
        self.reads.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.scan(table, range, limit, reverse)
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        self.reads.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.counter(counter)
    }
}

#[async_trait::async_trait]
impl Store for CountingStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.reads.views.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(CountingView {
            inner: self.inner.read(consistency).await?,
            reads: Arc::clone(&self.reads),
        }))
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

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// Everything for one prefix; the store is not consulted.
struct OnePrefix(PrefixId);

impl Authorizer for OnePrefix {
    fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
        Ok(())
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::Only(vec![ScopeRule::Prefix {
            id: self.0,
            subtree: true,
        }])
    }
}

/// A host with 20 addresses in 192.0.2.0/24, and the service over a counting store.
async fn world() -> (
    Arc<IpamService>,
    Arc<ScopeIndex>,
    Arc<Reads>,
    PrefixId,
    Vec<tenko_core::AddressId>,
) {
    let reads = Arc::new(Reads::default());
    let store: Arc<dyn Store> = Arc::new(CountingStore {
        inner: MemStore::default(),
        reads: Arc::clone(&reads),
    });
    let index = Arc::new(ScopeIndex::new());
    store
        .register_index(Arc::clone(&index) as _)
        .expect("register the anchors index");
    let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
    let network = prefix(None, "192.0.2.0/24");
    let id = network.id.expect("id");
    let (input, interface) = host("web01", AssignmentMode::Static, Some("00-00-5E-00-53-01"));
    let mut commands = vec![
        IpamCommand::CreatePrefix(network),
        IpamCommand::CreateHost(input),
    ];
    let mut addresses = Vec::new();
    for last in 10..30 {
        let mut assigned = address(None, &format!("192.0.2.{last}"));
        assigned.interface = Some(interface);
        addresses.push(assigned.id.expect("id"));
        commands.push(IpamCommand::CreateAddress(assigned));
    }
    run(&service, commands).await;
    (service, index, reads, id, addresses)
}

fn retire(addresses: &[tenko_core::AddressId]) -> Vec<IpamCommand> {
    addresses
        .iter()
        .map(|id| {
            IpamCommand::UpdateAddress(UpdateAddress {
                id: *id,
                expected: None,
                patch: AddressPatch {
                    status: Some(Status::Reserved),
                    ..AddressPatch::default()
                },
            })
        })
        .collect()
}

#[tokio::test]
async fn the_scope_checks_add_no_store_read_to_a_plan_or_an_apply() {
    // Unscoped: the plan of the preview, then plan and apply.
    let (service, _, reads, _, addresses) = world().await;
    let commands = retire(&addresses[..10]);
    let before = reads.total();
    service
        .preview(&commands, &person(), &PlanOptions::default(), None)
        .await
        .expect("preview");
    let preview_open = delta(before, reads.total());
    let before = reads.total();
    service
        .execute(&commands, &person(), &PlanOptions::default())
        .await
        .expect("execute");
    let apply_open = delta(before, reads.total());

    // Scoped: the same commands through the checked paths of a fresh, identical world.
    let (service, index, reads, prefix, addresses) = world().await;
    let commands = retire(&addresses[..10]);
    let authorizer = OnePrefix(prefix);
    let before = reads.total();
    index
        .preview_checked(
            &service,
            &authorizer,
            &commands,
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect("preview");
    let preview_scoped = delta(before, reads.total());
    let before = reads.total();
    index
        .execute_checked(
            &service,
            &authorizer,
            &commands,
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect("execute");
    let apply_scoped = delta(before, reads.total());

    println!(
        "store reads (views, lookups): preview {preview_open:?} unscoped, {preview_scoped:?} scoped; plan and apply {apply_open:?} unscoped, {apply_scoped:?} scoped"
    );
    assert_eq!(preview_scoped, preview_open, "the scoped plan reads more");
    assert_eq!(
        apply_scoped, apply_open,
        "the scoped plan and apply read more"
    );
}

fn delta(before: (u64, u64), after: (u64, u64)) -> (u64, u64) {
    (after.0 - before.0, after.1 - before.1)
}
