//! The short lease before a move and the two times (`docs/moves.md` sections 4 and 5, ADR
//! 0027): the preview's next expected DHCP activity and migration deadline with how they
//! were chosen; the job that marks the client, waits for its renewal with the short
//! lease, changes the network and is verified by the new lease; the rollback that removes
//! the marker before it undoes the network change; the deadline's verification window and
//! its single extension near the end; and the stale marker. The role is a fake port that
//! reports what a test says it saw.

mod common;

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex, PoisonError},
};

use common::*;
use tenko_core::{
    CodedError, HostId, JobId, MacAddr, MessageKey, NodeId, PrefixId, Principal, Revision,
    SystemComponent, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, DdnsState, Lease, LeaseTimes, MovingClient, Scope,
        tables as dhcp_tables,
    },
    ipam::{Address, AssignmentMode, RangeRole, Stamp},
    serde_util::HexBytes,
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService,
    command::RangeInput,
    jobs::register_steps,
    moves::{
        MoveRequest, MoveTimeoutSource,
        clock::MoveClock,
        dhcp::{ClientActivity, DhcpMoves, DhcpRolePort, Released},
        lease,
        timing::{MoveActivitySource, MovePrepare, plus},
    },
    query,
};
use tenko_jobs::{
    Job, JobEngine, JobState, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepState,
};
use tenko_store::{MemStore, ReadConsistency, ReadView, Store, WriteBatch};

const MAC: &str = "00:00:5e:00:53:31";

/// The `dhcp` role as the move sees it: its image is always current, and its activity is
/// what the test sets.
#[derive(Default)]
struct FakeRole {
    activity: Mutex<Option<ClientActivity>>,
}

impl FakeRole {
    fn saw(&self, activity: ClientActivity) {
        *self.activity.lock().unwrap_or_else(PoisonError::into_inner) = Some(activity);
    }
}

#[async_trait::async_trait]
impl DhcpRolePort for FakeRole {
    fn image_revision(&self) -> Revision {
        Revision(u64::MAX / 2)
    }

    async fn release(
        &self,
        _vrf: VrfId,
        _addr: Ipv4Addr,
        _reason: &str,
    ) -> Result<Released, CodedError> {
        Ok(Released::Released)
    }

    fn activity(&self, _job: JobId, _mac: MacAddr) -> Option<ClientActivity> {
        *self.activity.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The manual L2 step of these tests: it "changes the network" at once, and its undo
/// records whether the moving client was still marked then.
#[derive(Default)]
struct L2Probe {
    undone_with_marker: Mutex<Vec<bool>>,
}

struct L2Step(Arc<L2Probe>);

#[async_trait::async_trait]
impl StepHandler for L2Step {
    fn kind(&self) -> StepKind {
        StepKind::from_static("ipam.move.l2")
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(
        &self,
        _params: &[u8],
        _view: &dyn ReadView,
    ) -> Result<StepPreview, StepError> {
        Ok(StepPreview {
            summary: MessageKey::from_static("ipam.move.task.l2"),
            args: std::collections::BTreeMap::default(),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, _params: &[u8], _cx: &StepContext) -> Result<StepOutcome, StepError> {
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let view = cx.store.read(ReadConsistency::Local).await?;
        let marked = lease::marker(view.as_ref(), cx.job)?.is_some();
        self.0
            .undone_with_marker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(marked);
        Ok(())
    }
}

struct World {
    store: Arc<dyn Store>,
    service: Arc<IpamService>,
    engine: JobEngine,
    role: Arc<FakeRole>,
    clock: Arc<MoveClock>,
    l2: Arc<L2Probe>,
    target: PrefixId,
}

impl World {
    /// 192.0.2.0/24 to 198.51.100.0/24, whose pool .100 to .199 is a Tenko scope leasing
    /// for two hours.
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let mut engine = JobEngine::new(Arc::clone(&store), tenko_jobs::EngineConfig::default());
        register_steps(&mut engine);
        let role = Arc::new(FakeRole::default());
        let slot = DhcpMoves::with(Arc::clone(&role) as Arc<dyn DhcpRolePort>);
        tenko_ipam::moves::dhcp::register_steps(&mut engine, &slot);
        let l2 = Arc::new(L2Probe::default());
        engine.register(Arc::new(L2Step(Arc::clone(&l2))));
        let service = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("service");
        let clock = MoveClock::new(Arc::clone(&store), Arc::clone(service.jobs()), slot);
        let source = prefix(None, "192.0.2.0/24");
        let target = prefix(None, "198.51.100.0/24");
        let target_id = target.id.expect("id");
        let pool = RangeInput {
            lease_secs: None,
            ..range(
                target_id,
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
                IpamCommand::CreateRange(pool),
            ],
        )
        .await;
        let world = Self {
            store,
            service,
            engine,
            role,
            clock,
            l2,
            target: target_id,
        };
        world.scope(target_id).await;
        world
    }

    async fn scope(&self, prefix: PrefixId) {
        let now = Timestamp::now();
        let stamp = Stamp::new(now, Principal::system(SystemComponent::Dhcp));
        let scope = Scope {
            v6: None,
            prefix,
            enabled: true,
            lease: Some(LeaseTimes::fixed(7_200)),
            authoritative: None,
            server_id: None,
            ddns: tenko_core::dhcp::DdnsPolicy::default(),
            shared_network: None,
            restricted: false,
            classes: Vec::new(),
            description: None,
            created: stamp.clone(),
            updated: stamp,
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        batch
            .put_typed(&dhcp_tables::SCOPES, &prefix, &scope)
            .expect("scope");
        self.store.propose(batch).await.expect("commit");
    }

    async fn host(&self, name: &str, mode: AssignmentMode, ip: &str) -> HostId {
        let (input, interface) = host(name, mode, Some(MAC));
        let id = input.id.expect("id");
        let mut assigned = address(None, ip);
        assigned.interface = Some(interface);
        run(
            &self.service,
            vec![
                IpamCommand::CreateHost(input),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        id
    }

    fn request(&self, host: HostId, move_now: bool) -> MoveRequest {
        MoveRequest {
            objects: vec![host.into()],
            target: self.target,
            timeout_secs: None,
            move_now,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        }
    }

    async fn address_at(&self, ip: &str) -> Address {
        let view = self.service.view(None).await.expect("view");
        query::list::<Address>(view.as_ref(), &query::ListQuery::default())
            .expect("list")
            .items
            .into_iter()
            .find(|address| address.ip.to_string() == ip)
            .expect("the address")
    }

    /// The client's bound lease of `ip` in `scope` since `cltt` for `secs`.
    async fn lease(&self, vrf: VrfId, scope: PrefixId, ip: &str, cltt: Timestamp, secs: u64) {
        let mac: MacAddr = MAC.parse().expect("mac");
        let lease = Lease {
            addr: ip.parse().expect("ip"),
            vrf,
            scope,
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(mac.octets().to_vec()),
                client_id: None,
            },
            state: BindingState::Active,
            cltt,
            ends: plus(cltt, secs),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: None,
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), cltt);
        batch
            .put_typed(&dhcp_tables::LEASES, &(lease.vrf, lease.addr), &lease)
            .expect("lease");
        self.store.propose(batch).await.expect("commit");
    }

    async fn marker(&self, job: JobId) -> Option<MovingClient> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        lease::marker(view.as_ref(), job)
            .expect("read")
            .map(|(row, _)| row)
    }

    async fn submit(&self, request: &MoveRequest) -> JobId {
        self.service
            .move_submit(request, &person())
            .await
            .expect("submit")
            .jobs[0]
            .job_id
    }

    async fn drive(&self, job: JobId) -> Job {
        self.engine.drive_once(job).await.expect("drive")
    }

    /// Drives the job and completes the manual steps before `kind` as a person, until the
    /// job waits at `kind`.
    async fn drive_to(&self, job: JobId, kind: &str) -> Job {
        loop {
            let state = self.drive(job).await;
            let (index, record) =
                waiting(&state).unwrap_or_else(|| panic!("not waiting: {state:?}"));
            if record.kind.as_str() == kind {
                return state;
            }
            self.engine
                .complete_manual(job, index, None, &person())
                .await
                .expect("complete");
        }
    }
}

fn waiting(job: &Job) -> Option<(u16, &tenko_jobs::StepRecord)> {
    job.steps
        .iter()
        .find(|record| matches!(record.state, StepState::WaitingForManual { .. }))
        .map(|record| (record.index, record))
}

fn deadline(job: &Job, kind: &str) -> Option<Timestamp> {
    job.steps
        .iter()
        .find(|record| record.kind.as_str() == kind)
        .and_then(|record| match &record.state {
            StepState::WaitingForManual { deadline, .. } => *deadline,
            _ => None,
        })
}

fn kinds(item: &tenko_ipam::MoveItem) -> Vec<&str> {
    item.steps.iter().map(|step| step.kind.as_str()).collect()
}

#[tokio::test]
async fn the_preview_shows_the_two_times_and_how_they_were_chosen() {
    let world = World::new().await;
    let printer = world
        .host("printer", AssignmentMode::Reserved, "192.0.2.15")
        .await;
    let old = world.address_at("192.0.2.15").await;
    let cltt = Timestamp::now();
    world
        .lease(old.vrf, PrefixId::generate(), "192.0.2.15", cltt, 3_600)
        .await;

    let preview = world
        .service
        .move_preview(&world.request(printer, false), &person(), None)
        .await
        .expect("preview");
    let item = &preview.items[0];
    assert_eq!(
        kinds(item),
        [
            "dhcp.prepare",
            "ipam.intent",
            "dhcp.reservation",
            "dhcp.short_lease",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );
    let timing = &item.timing;
    // The next renewal is T1 of the client's hour, within the preparation limit.
    assert_eq!(timing.next_activity, Some(plus(cltt, 1_800)));
    assert_eq!(timing.next_activity_source, MoveActivitySource::Lease);
    assert_eq!(timing.lease_end, Some(plus(cltt, 3_600)));
    assert_eq!(timing.prepare, MovePrepare::ShortLease);
    assert_eq!(timing.short_lease_secs, Some(120));
    // The short lease plus the margin is below the floor of 300 s.
    assert_eq!(timing.deadline_secs, 300);
    assert_eq!(timing.deadline_source, MoveTimeoutSource::ShortLease);
    assert_eq!(preview.timeout_secs, 300);

    // "Move now": no wait, and the deadline is the end of the client's lease plus the
    // margin.
    let now = world
        .service
        .move_preview(&world.request(printer, true), &person(), None)
        .await
        .expect("preview");
    assert!(now.move_now);
    let item = &now.items[0];
    assert!(!kinds(item).contains(&"dhcp.short_lease"));
    assert_eq!(item.timing.prepare, MovePrepare::MoveNow);
    assert_eq!(item.timing.short_lease_secs, None);
    assert_eq!(item.timing.deadline_source, MoveTimeoutSource::Lease);
    assert!(
        (3_655..=3_660).contains(&item.timing.deadline_secs),
        "{:?}",
        item.timing
    );
    assert_ne!(now.fingerprint, preview.fingerprint);

    // Without the client's lease, the target pools' default lease.
    let dynamic = world
        .host("camera", AssignmentMode::Dynamic, "192.0.2.40")
        .await;
    let preview = world
        .service
        .move_preview(&world.request(dynamic, false), &person(), None)
        .await
        .expect("preview");
    let timing = &preview.items[0].timing;
    assert_eq!(timing.prepare, MovePrepare::NotServed);
    assert_eq!(timing.next_activity_source, MoveActivitySource::Pool);
    assert_eq!(timing.deadline_source, MoveTimeoutSource::Pool);
    assert_eq!(timing.deadline_secs, 7_260);
}

#[tokio::test]
async fn the_job_marks_waits_for_the_short_lease_moves_and_is_verified_by_the_new_lease() {
    let world = World::new().await;
    let printer = world
        .host("printer", AssignmentMode::Reserved, "192.0.2.15")
        .await;
    let old = world.address_at("192.0.2.15").await;
    let source = PrefixId::generate();
    world
        .lease(old.vrf, source, "192.0.2.15", Timestamp::now(), 3_600)
        .await;
    let job = world.submit(&world.request(printer, false)).await;

    // The marker first, then the wait for the renewal.
    let state = world.drive_to(job, lease::LEASE).await;
    let marker = world.marker(job).await.expect("marked");
    assert_eq!(marker.mac, MAC.parse::<MacAddr>().expect("mac"));
    assert_eq!(marker.short_secs, 120);
    assert_eq!(marker.target, Some(world.target));
    assert_eq!(
        marker.lease.map(|lease| lease.addr),
        Some(Ipv4Addr::new(192, 0, 2, 15))
    );
    assert_eq!(state.steps[0].kind.as_str(), lease::PREPARE);
    assert_eq!(state.steps[0].state, StepState::Done);
    // No renewal yet: the clock lets it wait.
    let round = world
        .clock
        .tick(Timestamp::now(), None)
        .await
        .expect("tick");
    assert_eq!(round.prepared, 0);
    // The client renews and gets the short lease: the network changes.
    world
        .lease(old.vrf, source, "192.0.2.15", Timestamp::now(), 120)
        .await;
    let round = world
        .clock
        .tick(Timestamp::now(), None)
        .await
        .expect("tick");
    assert_eq!(round.prepared, 1);
    let state = world.drive_to(job, "ipam.move.observe").await;
    assert_eq!(deadline(&state, "ipam.move.observe"), None);

    // The clock sets the migration deadline from the short lease.
    let round = world
        .clock
        .tick(Timestamp::now(), None)
        .await
        .expect("tick");
    assert_eq!(round.deadlines, 1);
    let state = world.drive(job).await;
    let started = state
        .steps
        .iter()
        .find(|record| record.kind.as_str() == "ipam.move.observe")
        .and_then(|record| record.started)
        .expect("started");
    assert_eq!(
        deadline(&state, "ipam.move.observe"),
        Some(plus(started, 300))
    );

    // The client holds the prepared address on the target scope: verified.
    world
        .lease(
            old.vrf,
            world.target,
            "198.51.100.15",
            Timestamp::now(),
            7_200,
        )
        .await;
    let round = world
        .clock
        .tick(Timestamp::now(), None)
        .await
        .expect("tick");
    assert_eq!(round.verified, 1);
    let state = world.drive(job).await;
    assert_eq!(state.state, JobState::Succeeded, "{state:?}");
    assert!(world.marker(job).await.is_none(), "the cleanup removed it");
}

#[tokio::test]
async fn the_rollback_removes_the_marker_before_it_undoes_the_network_change() {
    let world = World::new().await;
    let printer = world
        .host("printer", AssignmentMode::Reserved, "192.0.2.15")
        .await;
    let old = world.address_at("192.0.2.15").await;
    world
        .lease(
            old.vrf,
            PrefixId::generate(),
            "192.0.2.15",
            Timestamp::now(),
            3_600,
        )
        .await;
    let job = world.submit(&world.request(printer, false)).await;
    // A person moves it at once (the wait for the short lease completed by hand).
    let state = world.drive_to(job, "ipam.move.observe").await;
    assert!(world.marker(job).await.is_some());
    let (observe, _) = waiting(&state).expect("waiting");
    // The deadline passes.
    world
        .engine
        .set_manual_deadline(
            job,
            observe,
            Timestamp::now(),
            Some("test".to_owned()),
            &person(),
        )
        .await
        .expect("deadline");
    let state = world.drive(job).await;
    assert_eq!(state.state, JobState::RolledBack, "{state:?}");
    assert_eq!(
        state.error.as_ref().map(|error| error.code.as_ref()),
        Some("jobs.step.deadline_passed")
    );
    assert_eq!(
        *world
            .l2
            .undone_with_marker
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        [false],
        "the marker was gone before the L2 change was undone"
    );
    assert!(world.marker(job).await.is_none());
}

#[tokio::test]
async fn the_deadline_follows_the_lease_shortens_on_reconnection_and_extends_once() {
    let world = World::new().await;
    let printer = world
        .host("printer", AssignmentMode::Reserved, "192.0.2.15")
        .await;
    let old = world.address_at("192.0.2.15").await;
    let cltt = Timestamp::now();
    world
        .lease(old.vrf, PrefixId::generate(), "192.0.2.15", cltt, 3_600)
        .await;
    // "Move now": no short lease, the deadline is the end of the client's lease.
    let job = world.submit(&world.request(printer, true)).await;
    let state = world.drive_to(job, "ipam.move.observe").await;
    assert!(waiting(&state).is_some());
    assert!(world.marker(job).await.expect("followed").lease.is_none());
    world
        .clock
        .tick(Timestamp::now(), None)
        .await
        .expect("tick");
    let lease_end = plus(cltt, 3_660);
    assert_eq!(
        deadline(&world.drive(job).await, "ipam.move.observe"),
        Some(lease_end)
    );

    // Near the deadline the client is in the middle of an exchange: once, 60 s more.
    let near = plus(cltt, 3_650);
    world.role.saw(ClientActivity {
        last: Some(plus(cltt, 3_648)),
        on_target: None,
    });
    let round = world.clock.tick(near, None).await.expect("tick");
    assert_eq!(round.extended, 1);
    assert_eq!(
        deadline(&world.drive(job).await, "ipam.move.observe"),
        Some(plus(cltt, 3_720))
    );
    assert!(world.marker(job).await.expect("marker").extended);
    world.role.saw(ClientActivity {
        last: Some(plus(cltt, 3_710)),
        on_target: None,
    });
    let round = world
        .clock
        .tick(plus(cltt, 3_712), None)
        .await
        .expect("tick");
    assert_eq!(round.extended, 0, "only once");

    // The client's exchange on the target network: the short window to verify it.
    let seen = Timestamp::now();
    world.role.saw(ClientActivity {
        last: Some(seen),
        on_target: Some(seen),
    });
    let round = world.clock.tick(seen, None).await.expect("tick");
    assert_eq!(round.windows, 1);
    let state = world.drive(job).await;
    assert_eq!(deadline(&state, "ipam.move.observe"), Some(plus(seen, 90)));
    assert_eq!(state.state, JobState::Waiting);
}

#[tokio::test]
async fn a_marker_whose_job_is_gone_or_ended_is_stale() {
    let world = World::new().await;
    let printer = world
        .host("printer", AssignmentMode::Reserved, "192.0.2.15")
        .await;
    let job = world.submit(&world.request(printer, false)).await;
    world.drive_to(job, "ipam.move.observe").await;
    let row = world.marker(job).await.expect("marked");
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let now = Timestamp::now();
    assert!(!lease::is_stale(view.as_ref(), &row, now).expect("stale"));
    // Past its end, or for a job that does not exist.
    assert!(lease::is_stale(view.as_ref(), &row, plus(row.until, 1)).expect("stale"));
    let orphan = MovingClient {
        job: JobId::generate(),
        ..row
    };
    assert!(lease::is_stale(view.as_ref(), &orphan, now).expect("stale"));
    // A cancel rolls the job back, and the marker goes with it.
    world.engine.cancel(job, &person()).await.expect("cancel");
    assert_eq!(world.drive(job).await.state, JobState::Cancelled);
    assert!(world.marker(job).await.is_none());
}
