//! Writes that run after the request that asked for them (IAM-01): the steps of a move
//! and the reconciler's adoptions are checked with the rights their requester (for an
//! adoption, the principal who set the policy) holds when they run, so a scope that shrank
//! or an account that was disabled since the start refuses the write, and a job started
//! under an earlier version (no requester recorded) rolls back.

mod common;
mod reconcile_support;

use std::sync::{Arc, Mutex, PoisonError};

use common::*;
use reconcile_support::{World as ReconcileWorld, at, vm};
use tenko_core::{
    Action, Authorizer, Denied, HostId, NodeId, ObjectKind, ObjectRef, PrefixId, Principal,
    RequestCtx, ScopeFilter, ScopeRule, Timestamp,
    codec::from_cbor,
    ipam::{Address, AssignmentMode, RangeRole},
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, codes,
    command::RangeInput,
    jobs::register_steps,
    moves::{
        self, MoveCleanupStep, MoveControllerStep, MoveIntentStep, MoveRequest, MoveStepParams,
    },
    proposals::{self, AdoptionMode, AdoptionPolicy, IntentProposalKind},
    query,
    reconcile::ReconcilerConfig,
    scope::{ScopeGuard, ScopeIndex},
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, MockClock, StepContext, StepHandler};
use tenko_store::{MemStore, Store};

/// What the requester may do now; system principals reach everything.
#[derive(Debug, Clone)]
enum Rights {
    All,
    Only(Vec<ScopeRule>),
    Disabled,
}

/// An authorizer whose answer for people changes during a test, as the authorizer of
/// `tenko-auth` does when a grant is revoked or an account disabled.
struct Switch(Mutex<Rights>);

impl Switch {
    fn new(rights: Rights) -> Arc<Self> {
        Arc::new(Self(Mutex::new(rights)))
    }

    fn set(&self, rights: Rights) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = rights;
    }
}

impl Authorizer for Switch {
    fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
        Ok(())
    }

    fn scope(&self, principal: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        if matches!(principal, Principal::System { .. }) {
            return ScopeFilter::All;
        }
        match &*self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Rights::All => ScopeFilter::All,
            Rights::Only(rules) => ScopeFilter::Only(rules.clone()),
            Rights::Disabled => ScopeFilter::Nothing,
        }
    }
}

fn under(prefix: PrefixId) -> ScopeRule {
    ScopeRule::Prefix {
        id: prefix,
        subtree: true,
    }
}

/// Moves from 192.0.2.0/24 to 198.51.100.0/24, with 203.0.113.0/24 beside them; the job
/// engine's steps check with `switch`.
struct Moves {
    service: Arc<IpamService>,
    engine: JobEngine,
    store: Arc<dyn Store>,
    switch: Arc<Switch>,
    guard: ScopeGuard,
    source: PrefixId,
    target: PrefixId,
    other: PrefixId,
}

impl Moves {
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let index = Arc::new(ScopeIndex::new());
        store
            .register_index(Arc::clone(&index) as _)
            .expect("register the anchors index");
        let switch = Switch::new(Rights::All);
        let guard = ScopeGuard::new(Arc::clone(&switch) as Arc<dyn Authorizer>, index);
        let clock = Arc::new(MockClock::new(
            "2026-11-11T12:00:00Z".parse::<Timestamp>().expect("time"),
        ));
        let mut engine = JobEngine::with_clock(
            Arc::clone(&store),
            EngineConfig::default(),
            clock as Arc<dyn tenko_jobs::Clock>,
        );
        register_steps(&mut engine, &guard);
        let service = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("service");
        let source = prefix(None, "192.0.2.0/24");
        let target = prefix(None, "198.51.100.0/24");
        let other = prefix(None, "203.0.113.0/24");
        let ids = (
            source.id.expect("id"),
            target.id.expect("id"),
            other.id.expect("id"),
        );
        let pool = RangeInput {
            lease_secs: Some(86_400),
            ..range(
                ids.1,
                "198.51.100.100",
                "198.51.100.199",
                RangeRole::DhcpPool,
            )
        };
        run(
            &service,
            vec![
                IpamCommand::CreatePrefix(source),
                IpamCommand::CreatePrefix(target),
                IpamCommand::CreatePrefix(other),
                IpamCommand::CreateRange(pool),
            ],
        )
        .await;
        Self {
            service,
            engine,
            store,
            switch,
            guard,
            source: ids.0,
            target: ids.1,
            other: ids.2,
        }
    }

    /// A static host with one interface and an address at each of `ips`.
    async fn host(&self, name: &str, ips: &[&str]) -> HostId {
        let (input, interface) = host(name, AssignmentMode::Static, Some("00-00-5E-00-53-01"));
        let id = input.id.expect("id");
        let mut commands = vec![IpamCommand::CreateHost(input)];
        for ip in ips {
            let mut assigned = address(None, ip);
            assigned.interface = Some(interface);
            commands.push(IpamCommand::CreateAddress(assigned));
        }
        run(&self.service, commands).await;
        id
    }

    fn request(&self, objects: Vec<ObjectRef>) -> MoveRequest {
        MoveRequest {
            objects,
            target: self.target,
            timeout_secs: None,
            move_now: false,
            nudge: true,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        }
    }

    async fn submit(&self, host: HostId, cx: &RequestCtx) -> tenko_core::JobId {
        let submitted = self
            .service
            .move_submit(&self.request(vec![host.into()]), cx)
            .await
            .expect("submit");
        submitted.jobs[0].job_id
    }

    async fn drive(&self, job: tenko_core::JobId) -> tenko_jobs::Job {
        self.engine.drive_once(job).await.expect("drive")
    }

    /// Ticks off the four manual steps of a static host's move (DNS, device, L2,
    /// observation) and drives the job after each.
    async fn complete_tasks(&self, job: tenko_core::JobId) -> tenko_jobs::Job {
        let mut last = None;
        for step in 1..=4u16 {
            self.engine
                .complete_manual(job, step, None, &person())
                .await
                .expect("complete");
            last = Some(self.drive(job).await);
            if last.as_ref().is_some_and(|job| job.state.is_terminal()) {
                break;
            }
        }
        last.expect("a job")
    }

    async fn address_at(&self, ip: &str) -> Option<Address> {
        let view = self.service.view(None).await.expect("view");
        query::list::<Address>(
            view.as_ref(),
            &query::ListQuery {
                q: Some(ip.to_owned()),
                deleted: query::Deleted::Include,
                ..query::ListQuery::default()
            },
        )
        .expect("list")
        .items
        .into_iter()
        .find(|a| a.ip.to_string() == ip)
    }

    async fn live(&self, ip: &str) -> bool {
        self.address_at(ip)
            .await
            .is_some_and(|address| !address.meta.is_deleted())
    }
}

fn error_code(job: &tenko_jobs::Job) -> String {
    job.error
        .as_ref()
        .map(|error| error.code.to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_scoped_move_writes_at_each_step_while_the_scope_holds() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    world
        .switch
        .set(Rights::Only(vec![under(world.source), under(world.target)]));
    let job = world.submit(nas, &person()).await;
    assert_eq!(world.drive(job).await.state, JobState::Waiting);
    assert!(
        world.live("198.51.100.10").await,
        "the new address as intent"
    );
    let done = world.complete_tasks(job).await;
    assert_eq!(done.state, JobState::Succeeded, "{:?}", done.error);
    assert!(world.live("198.51.100.10").await);
    assert!(!world.live("192.0.2.10").await, "the old address is gone");
}

#[tokio::test]
async fn a_scope_that_shrinks_before_the_first_write_rolls_the_move_back() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    world
        .switch
        .set(Rights::Only(vec![under(world.source), under(world.target)]));
    let job = world.submit(nas, &person()).await;
    // The grant over the target is revoked before the job's first step runs.
    world.switch.set(Rights::Only(vec![under(world.source)]));
    let ended = world.drive(job).await;
    assert_eq!(ended.state, JobState::RolledBack);
    assert_eq!(error_code(&ended), "auth.out_of_scope");
    assert!(world.address_at("198.51.100.10").await.is_none());
    assert!(world.live("192.0.2.10").await);
}

#[tokio::test]
async fn an_account_disabled_after_the_first_write_stops_the_move_and_its_rollback_restores() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    world
        .switch
        .set(Rights::Only(vec![under(world.source), under(world.target)]));
    let job = world.submit(nas, &person()).await;
    assert_eq!(world.drive(job).await.state, JobState::Waiting);
    assert!(world.live("198.51.100.10").await);
    world.switch.set(Rights::Disabled);
    let ended = world.complete_tasks(job).await;
    assert_eq!(ended.state, JobState::RolledBack);
    assert_eq!(error_code(&ended), "auth.forbidden");
    assert!(
        !world.live("198.51.100.10").await,
        "the rollback removes the new address"
    );
    assert!(world.live("192.0.2.10").await, "the old address stays");
}

#[tokio::test]
#[allow(clippy::result_large_err)] // The connector check of a submit answers a CodedError.
async fn a_move_of_an_address_whose_host_lies_outside_the_scope_is_refused() {
    let world = Moves::new().await;
    // The host also has an address outside the scope: moving its address changes it.
    let nas = world.host("nas01", &["192.0.2.10", "203.0.113.10"]).await;
    let view = world.service.view(None).await.expect("view");
    let moved = query::list::<Address>(
        view.as_ref(),
        &query::ListQuery {
            q: Some("192.0.2.10".to_owned()),
            ..query::ListQuery::default()
        },
    )
    .expect("list")
    .items[0]
        .id;
    drop(view);
    world
        .switch
        .set(Rights::Only(vec![under(world.source), under(world.target)]));
    let request = world.request(vec![moved.into()]);
    // At the request: the preview and the submit check the host.
    let refused = moves::preview_move(
        &world.service,
        &tenko_ipam::vlan::Controllers::default(),
        &request,
        &person(),
        None,
        Some(&world.guard),
    )
    .await
    .expect_err("the host is outside the scope");
    assert_eq!(refused.code_str(), "auth.out_of_scope");
    assert!(
        !refused.to_string().contains(&nas.to_string()),
        "the refusal does not name the host: {refused}"
    );
    let refused = moves::submit_move(
        &world.service,
        &tenko_ipam::vlan::Controllers::default(),
        &request,
        &person(),
        &|_| Ok(()),
        Some(&world.guard),
    )
    .await
    .expect_err("the host is outside the scope");
    assert_eq!(refused.code_str(), "auth.out_of_scope");
    // At the step: a move submitted without the request's check is refused when it runs.
    let job = world
        .service
        .move_submit(&request, &person())
        .await
        .expect("submit")
        .jobs[0]
        .job_id;
    let ended = world.drive(job).await;
    assert_eq!(ended.state, JobState::RolledBack);
    assert_eq!(error_code(&ended), "auth.out_of_scope");
    assert!(world.address_at("198.51.100.10").await.is_none());
    let _ = world.other;
}

#[tokio::test]
async fn a_move_without_a_recorded_requester_rolls_back_with_words_an_operator_can_act_on() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    // A move recorded without its requester, as one started under an earlier version.
    let node = RequestCtx::new(Principal::Node { id: NodeId(7) });
    let job = world.submit(nas, &node).await;
    let ended = world.drive(job).await;
    assert_eq!(ended.state, JobState::RolledBack);
    assert_eq!(error_code(&ended), codes::REQUESTER_UNKNOWN);
    let detail = ended
        .error
        .as_ref()
        .map(|e| e.detail.clone())
        .unwrap_or_default();
    assert!(detail.contains("earlier version"), "{detail}");
    assert!(detail.contains("Start the move again"), "{detail}");
    assert!(world.address_at("198.51.100.10").await.is_none());
    assert!(world.live("192.0.2.10").await);
}

/// The step context of `job`'s step `step`, outside the engine.
fn context(world: &Moves, job: tenko_core::JobId, step: u16) -> StepContext {
    StepContext {
        job,
        step,
        attempt: 1,
        request: RequestCtx::system(tenko_core::SystemComponent::Jobs),
        store: Arc::clone(&world.store),
        deadline: None,
    }
}

#[tokio::test]
async fn an_upgrade_between_the_steps_of_a_move_stops_its_next_write_and_the_rollback_restores() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    let job = world.submit(nas, &person()).await;
    let waiting = world.drive(job).await;
    assert_eq!(waiting.state, JobState::Waiting);
    assert!(world.live("198.51.100.10").await, "the intent step wrote");
    // The steps as an earlier version recorded them: without the requester.
    let index_of = |kind: &str| {
        waiting
            .spec
            .steps
            .iter()
            .position(|step| step.kind.as_str() == kind)
            .expect("the step")
    };
    let cleanup = index_of(moves::steps::CLEANUP);
    let intent = index_of(moves::steps::INTENT);
    let mut params: MoveStepParams =
        from_cbor(&waiting.spec.steps[cleanup].params.0).expect("params");
    assert!(
        params.requester.is_some(),
        "this version records the requester"
    );
    params.requester = None;
    let bytes = tenko_core::codec::to_cbor(&params).expect("encode");
    let cleanup_step = MoveCleanupStep::new(world.guard.clone());
    let refused = cleanup_step
        .execute(
            &bytes,
            &context(&world, job, u16::try_from(cleanup).expect("index")),
        )
        .await
        .expect_err("no requester");
    match &refused {
        tenko_jobs::StepError::Coded(error) => assert_eq!(error.code, codes::REQUESTER_UNKNOWN),
        other => panic!("{other:?}"),
    }
    assert!(world.live("192.0.2.10").await, "the cleanup wrote nothing");
    // The rollback of the intent step undoes it without the requester.
    MoveIntentStep::new(world.guard.clone())
        .compensate(
            &bytes,
            None,
            &context(&world, job, u16::try_from(intent).expect("index")),
        )
        .await
        .expect("the rollback runs");
    assert!(
        !world.live("198.51.100.10").await,
        "the new address is removed"
    );
    assert!(world.live("192.0.2.10").await, "the old address stays");
}

#[tokio::test]
async fn the_network_steps_of_a_move_stop_once_the_requester_is_disabled() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    let job = world.submit(nas, &person()).await;
    let waiting = world.drive(job).await;
    let params = waiting.spec.steps[0].params.0.clone();
    world.switch.set(Rights::Disabled);
    let controllers = tenko_ipam::vlan::Controllers::new();
    let refused = MoveControllerStep::new(Arc::clone(&controllers), world.guard.clone())
        .execute(&params, &context(&world, job, 0))
        .await
        .expect_err("disabled");
    match &refused {
        tenko_jobs::StepError::Coded(error) => assert_eq!(error.code, "auth.forbidden"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_rollback_leaves_an_old_address_that_someone_else_deleted() {
    let world = Moves::new().await;
    let nas = world.host("nas01", &["192.0.2.10"]).await;
    let job = world.submit(nas, &person()).await;
    assert_eq!(world.drive(job).await.state, JobState::Waiting);
    // An administrator deletes the old address while the move waits.
    let old = world.address_at("192.0.2.10").await.expect("old").id;
    run(
        &world.service,
        vec![IpamCommand::Delete {
            object: old.into(),
            expected: None,
            cascade: false,
        }],
    )
    .await;
    world.switch.set(Rights::Disabled);
    let ended = world.complete_tasks(job).await;
    assert_eq!(ended.state, JobState::RolledBack);
    assert!(
        !world.live("198.51.100.10").await,
        "the new address is removed"
    );
    assert!(
        !world.live("192.0.2.10").await,
        "the address the job did not delete stays deleted"
    );
}

// ----- adoptions ------------------------------------------------------------------------

/// A reconciler whose adoptions are checked by `switch`, with P (192.0.2.0/25) and Q
/// (198.51.100.0/24), and a dynamic host whose only address is in Q.
struct Adoptions {
    world: ReconcileWorld,
    switch: Arc<Switch>,
    p: PrefixId,
    q: PrefixId,
}

const DEVICE_MAC: &str = "00:00:5e:00:53:44";

impl Adoptions {
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let index = Arc::new(ScopeIndex::new());
        store
            .register_index(Arc::clone(&index) as _)
            .expect("register the anchors index");
        let switch = Switch::new(Rights::All);
        let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
        service.set_scope_guard(ScopeGuard::new(
            Arc::clone(&switch) as Arc<dyn Authorizer>,
            index,
        ));
        let world = ReconcileWorld::over(store, service, ReconcilerConfig::default());
        let p = prefix(None, "192.0.2.0/25");
        let q = prefix(None, "198.51.100.0/24");
        let (p_id, q_id) = (p.id.expect("id"), q.id.expect("id"));
        let (device, interface) =
            host("device", AssignmentMode::Dynamic, Some("00-00-5E-00-53-44"));
        let mut assigned = address(None, "198.51.100.44");
        assigned.interface = Some(interface);
        run(
            &world.service,
            vec![
                IpamCommand::CreatePrefix(p),
                IpamCommand::CreatePrefix(q),
                IpamCommand::CreateHost(device),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        Self {
            world,
            switch,
            p: p_id,
            q: q_id,
        }
    }

    /// The policy `adopt_all` on P, set by `setter`.
    async fn policy(&self, setter: &RequestCtx) {
        proposals::set_policy(
            &self.world.service,
            self.p,
            Some(AdoptionPolicy {
                mode: AdoptionMode::AdoptAll,
                min_sightings: 1,
                ..AdoptionPolicy::default()
            }),
            setter,
            None,
        )
        .await
        .expect("policy");
    }

    /// The device seen at 192.0.2.44 (inside P), then one reconciler run.
    async fn sighting(&self) -> tenko_ipam::reconcile::ReconcileReport {
        self.world
            .poll(
                vec![vm(
                    "device",
                    Some("device"),
                    Some(DEVICE_MAC),
                    &["192.0.2.44"],
                )],
                at("09:00"),
            )
            .await;
        self.world.reconcile(at("09:01")).await
    }

    async fn device_ip(&self) -> String {
        let view = self.world.service.view(None).await.expect("view");
        let addresses = query::list::<Address>(view.as_ref(), &query::ListQuery::default())
            .expect("list")
            .items;
        addresses
            .iter()
            .find(|address| address.interface.is_some())
            .map(|address| address.ip.to_string())
            .expect("the device's address")
    }
}

#[tokio::test]
async fn an_adoption_is_refused_when_it_changes_a_host_outside_the_setters_scope() {
    let lab = Adoptions::new().await;
    let setter = person();
    lab.switch.set(Rights::Only(vec![under(lab.p)]));
    lab.policy(&setter).await;
    let report = lab.sighting().await;
    let mismatch = lab.world.open(IntentProposalKind::AddressMismatch).await;
    assert_eq!(mismatch.len(), 1, "{report:?}");
    assert_eq!(report.adopted, 0, "{report:?}");
    assert_eq!(report.adoption_failures, 1, "{report:?}");
    assert_eq!(
        lab.device_ip().await,
        "198.51.100.44",
        "the host outside the setter's scope keeps its address"
    );
    let failed = lab.world.open(IntentProposalKind::AddressMismatch).await;
    let recorded = failed[0].adoption_error.clone().unwrap_or_default();
    assert!(recorded.contains("auth.out_of_scope"), "{recorded}");
    let _ = lab.q;
}

#[tokio::test]
async fn an_adoption_applies_when_the_setter_holds_every_object_it_changes() {
    let lab = Adoptions::new().await;
    let setter = person();
    lab.switch
        .set(Rights::Only(vec![under(lab.p), under(lab.q)]));
    lab.policy(&setter).await;
    let report = lab.sighting().await;
    assert_eq!(report.adopted, 1, "{report:?}");
    assert_eq!(lab.device_ip().await, "192.0.2.44");
}

#[tokio::test]
async fn an_adoption_is_refused_once_the_setters_account_is_disabled() {
    let lab = Adoptions::new().await;
    let setter = person();
    lab.policy(&setter).await;
    lab.switch.set(Rights::Disabled);
    let report = lab.sighting().await;
    assert_eq!(report.adopted, 0, "{report:?}");
    assert_eq!(report.adoption_failures, 1, "{report:?}");
    assert_eq!(lab.device_ip().await, "198.51.100.44");
}

#[tokio::test]
async fn a_server_without_the_scope_check_adopts_nothing() {
    // The reconciler test world sets a guard; a bare service has none.
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
    let error = service.scope_guard().expect_err("no guard wired");
    assert_eq!(error.code_str(), codes::SCOPE_UNWIRED);
    assert_eq!(status_of(&error), 500);
}
