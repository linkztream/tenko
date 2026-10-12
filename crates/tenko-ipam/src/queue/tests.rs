//! Tests of the local queue and of the drain.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tenko_core::{
    Action, AddressId, AuditSeq, AuthStrength, Authorizer, Denied, DenyReason, NodeId, ObjectKind,
    ObjectRef, Principal, RequestCtx, Revision, ScopeFilter, SessionId, SystemComponent, TenantId,
    Timestamp, UserId, VrfId,
    audit::AuditRecord,
    ipam::{Address, PrefixRole},
};
use tenko_store::{
    ChangeStream, Committed, KeyRange, MemStore, QuorumState, ReadConsistency, ReadView,
    ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
    api::tables as store_tables,
};
use uuid::Uuid;

use super::{
    ChangeState, EXPIRY, Fingerprint, LocalQueue, QueueItem, QueuedChange, QueuedRequest,
    SummaryAction, codes, record, summarize,
};
use crate::{
    IpamCommand, IpamService, PlanOptions,
    command::{AddressInput, AddressPatch, PrefixInput, TenantInput, UpdateAddress, VrfInput},
    history::HistoryEntry,
    query,
    tables::ADDRESSES,
};

// ----- fixtures -----------------------------------------------------------------------------

/// A directory that is removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tenko-queue-test-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A `MemStore` that can be told to report an isolated member.
struct GateStore {
    inner: MemStore,
    isolated: AtomicBool,
}

#[async_trait::async_trait]
impl Store for GateStore {
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

    fn register_index(&self, index: Arc<dyn tenko_store::DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        let mut status = self.inner.status();
        if self.isolated.load(Ordering::SeqCst) {
            status.quorum = QuorumState::Isolated {
                since: Timestamp::now(),
                last_contact: None,
                applied: status.revision,
            };
        }
        status
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// An authorizer that refuses everything.
struct DenyAll;

impl Authorizer for DenyAll {
    fn check(
        &self,
        _principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        Err(Denied {
            action,
            object: *object,
            reason: DenyReason::MissingPermission,
        })
    }

    fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
        ScopeFilter::Nothing
    }
}

const NODE: NodeId = NodeId(1);

struct World {
    gate: Arc<GateStore>,
    service: Arc<IpamService>,
    queue: Arc<LocalQueue>,
    _dir: TempDir,
    vrf: VrfId,
    author_id: UserId,
    author: Principal,
    session: SessionId,
    /// An address that exists: 192.0.2.10 in the VRF.
    address: AddressId,
}

fn system_cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Api)
}

fn address_input(vrf: VrfId, id: AddressId, ip: &str) -> AddressInput {
    AddressInput {
        id: Some(id),
        vrf: Some(vrf),
        ip: ip.parse().expect("ip"),
        status: None,
        interface: None,
        dns_name: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

fn describe(id: AddressId, text: &str) -> IpamCommand {
    IpamCommand::UpdateAddress(UpdateAddress {
        id,
        expected: None,
        patch: AddressPatch {
            description: Some(Some(text.to_owned())),
            ..AddressPatch::default()
        },
    })
}

fn set_dns_name(id: AddressId, name: &str) -> IpamCommand {
    IpamCommand::UpdateAddress(UpdateAddress {
        id,
        expected: None,
        patch: AddressPatch {
            dns_name: Some(Some(name.parse().expect("name"))),
            ..AddressPatch::default()
        },
    })
}

impl World {
    async fn new() -> Self {
        let gate = Arc::new(GateStore {
            inner: MemStore::default(),
            isolated: AtomicBool::new(false),
        });
        let service =
            IpamService::with_direct_jobs(Arc::clone(&gate) as Arc<dyn Store>).expect("service");
        let dir = TempDir::new();
        let queue = Arc::new(LocalQueue::open(dir.path().join("queue"), NODE).expect("queue"));
        let tenant = TenantId::generate();
        let vrf = VrfId::generate();
        let address = AddressId::generate();
        let author_id = UserId::generate();
        let session = SessionId::generate();
        let world = Self {
            gate,
            service,
            queue,
            _dir: dir,
            vrf,
            author_id,
            author: Principal::User {
                id: author_id,
                session,
                strength: AuthStrength::Password,
            },
            session,
            address,
        };
        world
            .run(vec![
                IpamCommand::CreateTenant(TenantInput {
                    id: Some(tenant),
                    name: "example".to_owned(),
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreateVrf(VrfInput {
                    id: Some(vrf),
                    tenant: Some(tenant),
                    name: "main".to_owned(),
                    rd: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreatePrefix(PrefixInput {
                    id: None,
                    vrf: Some(vrf),
                    cidr: "192.0.2.0/24".parse().expect("cidr"),
                    role: Some(PrefixRole::Network),
                    status: None,
                    vlan: None,
                    site: None,
                    alarm: None,
                    alloc: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreateAddress(address_input(vrf, address, "192.0.2.10")),
            ])
            .await;
        world
    }

    /// Executes commands directly, as the system.
    async fn run(&self, commands: Vec<IpamCommand>) {
        self.service
            .execute(&commands, &system_cx(), &PlanOptions::default())
            .await
            .expect("execute");
    }

    /// An item built the way the API builds it: planned as the author against the
    /// current state.
    async fn item(&self, id: u128, action: SummaryAction, commands: Vec<IpamCommand>) -> QueueItem {
        let cx = RequestCtx::new(self.author.clone());
        let options = PlanOptions::default();
        let plan = self
            .service
            .preview(&commands, &cx, &options, None)
            .await
            .expect("preview");
        let view = plan.view();
        let queued_at = Timestamp::now();
        QueueItem {
            id: Uuid::from_u128(id),
            queued_at,
            queued_on: NODE,
            expires_at: queued_at.checked_add(EXPIRY).expect("expiry"),
            principal: self.author.clone(),
            request: QueuedRequest {
                method: "PATCH".to_owned(),
                path: "/addresses".to_owned(),
                query: None,
                body: None,
                if_match: None,
            },
            commands,
            options,
            base: plan.base,
            summary: summarize(action, &view).expect("summary"),
            fingerprint: Fingerprint::of_plan(&plan),
            plan: view,
            applying: false,
        }
    }

    fn drainer(&self, authorizer: Option<Arc<dyn Authorizer>>) -> super::Drainer {
        super::Drainer::new(
            Arc::clone(&self.service),
            authorizer,
            None,
            Arc::clone(&self.queue),
        )
    }

    async fn view(&self) -> Arc<dyn ReadView> {
        self.gate
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view")
    }

    async fn address(&self, id: AddressId) -> Option<(Address, Revision)> {
        self.view().await.get_typed(&ADDRESSES, &id).expect("read")
    }

    async fn record(&self, id: Uuid) -> Option<(QueuedChange, Revision)> {
        record::get(self.view().await.as_ref(), id).expect("record")
    }

    async fn history(&self, id: AddressId) -> Vec<HistoryEntry> {
        query::history(self.view().await.as_ref(), id.into(), None, None)
            .expect("history")
            .items
    }

    async fn audit_of(&self, id: AddressId) -> Vec<AuditRecord> {
        let object = ObjectRef::from(id);
        self.view()
            .await
            .scan_typed(&store_tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _): (AuditSeq, AuditRecord, Revision)| record)
            .filter(|record| record.draft.objects.contains(&object))
            .collect()
    }

    fn revision(&self) -> Revision {
        self.gate.status().revision
    }
}

fn no_ids() -> Vec<Uuid> {
    Vec::new()
}

fn on_behalf(author: UserId) -> Principal {
    Principal::System {
        component: SystemComponent::Ipam,
        on_behalf_of: Some(author),
    }
}

// ----- the local queue ----------------------------------------------------------------------

#[tokio::test]
async fn the_local_queue_adds_gets_lists_replaces_and_removes() {
    let world = World::new().await;
    let queue = &world.queue;
    assert!(queue.is_empty().expect("empty"));
    let second = world
        .item(2, SummaryAction::Update, vec![describe(world.address, "b")])
        .await;
    let first = world
        .item(1, SummaryAction::Update, vec![describe(world.address, "a")])
        .await;
    queue.add(&second).expect("add");
    queue.add(&first).expect("add");
    assert_eq!(queue.len().expect("len"), 2);
    assert_eq!(queue.get(first.id).expect("get"), Some(first.clone()));
    assert_eq!(queue.get(Uuid::from_u128(9)).expect("get"), None);
    let listed: Vec<Uuid> = queue
        .list()
        .expect("list")
        .into_iter()
        .map(|item| item.id)
        .collect();
    assert_eq!(listed, vec![first.id, second.id], "oldest first");

    let mut replaced = first.clone();
    replaced.applying = true;
    queue.replace(&replaced).expect("replace");
    assert_eq!(queue.get(first.id).expect("get"), Some(replaced));

    assert!(queue.remove(first.id).expect("remove"));
    assert!(!queue.remove(first.id).expect("remove again"));
    assert_eq!(queue.get(first.id).expect("get"), None);
    assert_eq!(queue.len().expect("len"), 1);
}

#[tokio::test]
async fn a_leftover_temporary_file_is_removed_when_the_queue_opens() {
    let world = World::new().await;
    let item = world
        .item(1, SummaryAction::Update, vec![describe(world.address, "a")])
        .await;
    world.queue.add(&item).expect("add");
    let leftover = world.queue.dir().join(format!("{}.json.tmp", item.id));
    fs::write(&leftover, b"{\"half\":").expect("leftover");
    let reopened = LocalQueue::open(world.queue.dir(), NODE).expect("reopen");
    assert!(!leftover.exists());
    assert_eq!(reopened.list().expect("list"), vec![item]);
}

#[tokio::test]
async fn a_file_that_does_not_decode_is_moved_aside_and_skipped() {
    let world = World::new().await;
    let item = world
        .item(1, SummaryAction::Update, vec![describe(world.address, "a")])
        .await;
    world.queue.add(&item).expect("add");
    let broken_id = Uuid::from_u128(2);
    let broken = world.queue.dir().join(format!("{broken_id}.json"));
    fs::write(&broken, b"not json").expect("broken");
    assert_eq!(world.queue.list().expect("list"), vec![item.clone()]);
    assert!(!broken.exists());
    assert!(
        world
            .queue
            .dir()
            .join(format!("{broken_id}.json.bad"))
            .exists()
    );
    assert_eq!(world.queue.get(broken_id).expect("get"), None);
    assert_eq!(world.queue.len().expect("len"), 1);
}

#[tokio::test]
async fn replacing_a_missing_item_answers_not_found() {
    let world = World::new().await;
    let item = world
        .item(1, SummaryAction::Update, vec![describe(world.address, "a")])
        .await;
    let error = world.queue.replace(&item).expect_err("missing");
    assert_eq!(error.code_str(), codes::NOT_FOUND);
    assert!(world.queue.is_empty().expect("empty"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_directory_is_private_and_so_are_the_item_files() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::new().await;
    let item = world
        .item(1, SummaryAction::Update, vec![describe(world.address, "a")])
        .await;
    world.queue.add(&item).expect("add");
    let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(world.queue.dir()), 0o700);
    assert_eq!(
        mode(&world.queue.dir().join(format!("{}.json", item.id))),
        0o600
    );
}

// ----- the drain ----------------------------------------------------------------------------

#[tokio::test]
async fn an_unchanged_item_applies_on_its_authors_behalf() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "queued while cut off")],
        )
        .await;
    world.queue.add(&item).expect("add");
    let report = world.drainer(None).drain().await.expect("drain");
    assert_eq!(report.applied, vec![item.id]);
    assert_eq!(report.conflicts, no_ids());
    assert_eq!(report.expired, no_ids());
    assert!(!report.interrupted);
    assert!(world.queue.is_empty().expect("empty"), "the file is gone");

    let (address, address_revision) = world.address(world.address).await.expect("address");
    assert_eq!(
        address.meta.description.as_deref(),
        Some("queued while cut off")
    );
    let (change, record_revision) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Applied);
    assert_eq!(change.author, world.author_id);
    assert!(change.conflict.is_none());
    assert_eq!(
        record_revision, address_revision,
        "the record commits with the change"
    );

    let audits: Vec<AuditRecord> = world
        .audit_of(world.address)
        .await
        .into_iter()
        .filter(|record| record.revision == address_revision)
        .collect();
    let audited = audits.len();
    assert!(audited > 0, "the change is audited");
    for audit in audits {
        assert_eq!(audit.principal, on_behalf(world.author_id));
        let context = &audit.draft.details.context;
        assert_eq!(context.get("queued_change"), Some(&item.id.to_string()));
        assert_eq!(context.get("queued_at"), Some(&item.queued_at.to_rfc3339()));
        assert_eq!(context.get("queued_on"), Some(&NODE.to_string()));
        assert_eq!(
            context.get("original_session"),
            Some(&world.session.to_string())
        );
    }
}

#[tokio::test]
async fn a_changed_state_is_a_conflict_and_keeps_the_direct_value() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "queued value")],
        )
        .await;
    world.queue.add(&item).expect("add");
    world
        .run(vec![describe(world.address, "direct value")])
        .await;

    let report = world.drainer(None).drain().await.expect("drain");
    assert_eq!(report.conflicts, vec![item.id]);
    assert_eq!(report.applied, no_ids());
    assert!(world.queue.is_empty().expect("empty"));
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Conflict);
    assert_eq!(
        change
            .conflict
            .as_ref()
            .map(|conflict| conflict.code.as_str()),
        Some(codes::PLAN_CHANGED)
    );
    assert!(change.current_plan.is_some());
    let (address, _) = world.address(world.address).await.expect("address");
    assert_eq!(address.meta.description.as_deref(), Some("direct value"));
}

#[tokio::test]
async fn a_change_of_an_unrelated_field_still_applies() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "queued description")],
        )
        .await;
    world.queue.add(&item).expect("add");
    world
        .run(vec![set_dns_name(world.address, "host.example.test")])
        .await;

    let report = world.drainer(None).drain().await.expect("drain");
    assert_eq!(report.applied, vec![item.id]);
    assert_eq!(report.conflicts, no_ids());
    let (address, _) = world.address(world.address).await.expect("address");
    assert_eq!(
        address.meta.description.as_deref(),
        Some("queued description")
    );
    assert_eq!(
        address
            .dns_name
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("host.example.test")
    );
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Applied);
}

#[tokio::test]
async fn a_create_that_now_collides_is_a_conflict_with_the_planners_code() {
    let world = World::new().await;
    let queued = AddressId::generate();
    let item = world
        .item(
            1,
            SummaryAction::Create,
            vec![IpamCommand::CreateAddress(address_input(
                world.vrf,
                queued,
                "192.0.2.20",
            ))],
        )
        .await;
    world.queue.add(&item).expect("add");
    world
        .run(vec![IpamCommand::CreateAddress(address_input(
            world.vrf,
            AddressId::generate(),
            "192.0.2.20",
        ))])
        .await;

    let report = world.drainer(None).drain().await.expect("drain");
    assert_eq!(report.conflicts, vec![item.id]);
    assert_eq!(report.applied, no_ids());
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Conflict);
    assert_eq!(
        change
            .conflict
            .as_ref()
            .map(|conflict| conflict.code.as_str()),
        Some(crate::codes::ADDRESS_DUPLICATE)
    );
    assert!(world.address(queued).await.is_none());
    assert!(world.queue.is_empty().expect("empty"));
}

#[tokio::test]
async fn lost_rights_turn_the_item_into_a_conflict_and_apply_nothing() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "queued value")],
        )
        .await;
    world.queue.add(&item).expect("add");
    let before = world.revision();
    let drainer = world.drainer(Some(Arc::new(DenyAll)));
    let report = drainer.drain().await.expect("drain");
    assert_eq!(report.conflicts, vec![item.id]);
    assert_eq!(report.applied, no_ids());
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Conflict);
    let code = change.conflict.expect("conflict").code;
    assert!(code.starts_with("auth."), "code {code}");
    let (address, _) = world.address(world.address).await.expect("address");
    assert_eq!(address.meta.description, None);
    assert_eq!(world.history(world.address).await.len(), 1, "creation only");
    assert_eq!(
        world.revision().0,
        before.0 + 1,
        "only the conflict record was written"
    );
    assert!(world.queue.is_empty().expect("empty"));
}

#[tokio::test]
async fn an_expired_item_becomes_an_expired_record() {
    let world = World::new().await;
    let mut item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "too late")],
        )
        .await;
    item.expires_at =
        Timestamp::from_unix_nanos(item.queued_at.unix_nanos() - 3_600_000_000_000).expect("past");
    world.queue.add(&item).expect("add");
    let report = world.drainer(None).drain().await.expect("drain");
    assert_eq!(report.expired, vec![item.id]);
    assert_eq!(report.applied, no_ids());
    assert_eq!(report.conflicts, no_ids());
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Expired);
    assert_eq!(
        change
            .conflict
            .as_ref()
            .map(|conflict| conflict.code.as_str()),
        Some(codes::EXPIRED)
    );
    let (address, _) = world.address(world.address).await.expect("address");
    assert_eq!(address.meta.description, None);
    assert!(world.queue.is_empty().expect("empty"));
}

#[tokio::test]
async fn an_item_replayed_after_a_crash_is_not_applied_twice() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "once")],
        )
        .await;
    world.queue.add(&item).expect("add");
    let drainer = world.drainer(None);
    assert_eq!(drainer.drain().await.expect("drain").applied, vec![item.id]);
    let settled_at = world.revision();
    let history = world.history(world.address).await.len();
    assert_eq!(history, 2, "creation and one change");

    // The process stopped before it removed the file: the item is there again.
    world.queue.add(&item).expect("add again");
    let report = drainer.drain().await.expect("drain again");
    assert_eq!(report.conflicts, no_ids());
    assert_eq!(report.expired, no_ids());
    assert!(!report.interrupted);
    assert_eq!(world.revision(), settled_at, "nothing was written again");
    assert_eq!(world.history(world.address).await.len(), history);
    assert!(
        world.queue.is_empty().expect("empty"),
        "the file is removed"
    );
    let (change, _) = world.record(item.id).await.expect("record");
    assert_eq!(change.state, ChangeState::Applied);
}

#[tokio::test]
async fn nothing_is_settled_while_the_store_does_not_accept_writes() {
    let world = World::new().await;
    let item = world
        .item(
            1,
            SummaryAction::Update,
            vec![describe(world.address, "waits")],
        )
        .await;
    world.queue.add(&item).expect("add");
    world.gate.isolated.store(true, Ordering::SeqCst);
    let before = world.revision();
    let drainer = world.drainer(None);

    let report = drainer.drain().await.expect("drain");
    assert!(report.is_empty());
    assert!(report.interrupted);
    assert_eq!(world.queue.list().expect("list"), vec![item.clone()]);
    assert_eq!(world.revision(), before);
    assert!(world.record(item.id).await.is_none());

    // Once the store accepts writes again the same item settles.
    world.gate.isolated.store(false, Ordering::SeqCst);
    let report = drainer.drain().await.expect("drain");
    assert_eq!(report.applied, vec![item.id]);
    assert!(!report.interrupted);
}
