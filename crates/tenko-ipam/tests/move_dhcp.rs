//! The DHCP step of a move with Tenko DHCP (IPAM-19, DHCP-16, WP8.1): the preview kind
//! `dhcp.reservation` and the timeout from the scope's lease time, the step that waits
//! until the role's image holds the new reservation, the cleanup that releases the old
//! lease, the compensation, and the observation step confirmed by a lease of the
//! interface's MAC address in the target network. The role is a fake port here; the binary
//! runs the real one in `crates/tenko/tests/acceptance_move.rs` (E25).

mod common;
mod reconcile_support;

use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use common::*;
use tenko_core::{
    CodedError, HostId, JobId, NodeId, PrefixId, Principal, Revision, SystemComponent, Timestamp,
    VrfId,
    dhcp::{BindingState, ClientKey, DdnsState, Lease, LeaseTimes, Scope, tables as dhcp_tables},
    ipam::{Address, AssignmentMode, RangeRole, Stamp},
    serde_util::HexBytes,
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService,
    command::RangeInput,
    jobs::register_steps,
    moves::{
        MoveRequest,
        dhcp::{DhcpMoves, DhcpRolePort, MoveDhcpOutput, MoveDhcpStep, Released, codes},
    },
    observe::{ObserveConfig, dhcp::LeaseFacts},
    query,
    reconcile::ReconcilerConfig,
};
use tenko_jobs::{EngineConfig, Job, JobEngine, JobState, StepState};
use tenko_store::{MemStore, Store, WriteBatch};

const MAC: &str = "00:00:5e:00:53:31";

/// The `dhcp` role as the move sees it: an image revision the test moves, and the releases
/// it was asked for.
#[derive(Default)]
struct FakeRole {
    image: AtomicU64,
    released: Mutex<Vec<(VrfId, Ipv4Addr)>>,
}

impl FakeRole {
    fn released(&self) -> Vec<(VrfId, Ipv4Addr)> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl DhcpRolePort for FakeRole {
    fn image_revision(&self) -> Revision {
        Revision(self.image.load(Ordering::SeqCst))
    }

    async fn release(
        &self,
        vrf: VrfId,
        addr: Ipv4Addr,
        _reason: &str,
    ) -> Result<Released, CodedError> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((vrf, addr));
        Ok(Released::Released)
    }
}

struct Moving {
    world: reconcile_support::World,
    engine: JobEngine,
    role: Arc<FakeRole>,
    source: PrefixId,
    target: PrefixId,
}

impl Moving {
    /// 192.0.2.0/24 to 198.51.100.0/24; the target has a pool .100 to .199 without a lease
    /// time of its own and, with `scope`, a Tenko scope leasing for two hours. The DHCP
    /// step waits at most `wait` for the image.
    async fn new(scope: bool, wait: Duration) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
        register_steps(&mut engine);
        let role = Arc::new(FakeRole::default());
        let slot = DhcpMoves::with(Arc::clone(&role) as Arc<dyn DhcpRolePort>);
        tenko_ipam::moves::dhcp::register_steps(&mut engine, &slot);
        engine.register(Arc::new(MoveDhcpStep::new(slot).with_wait(wait)));
        let service = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("service");
        let world = reconcile_support::World::over(
            Arc::clone(&store),
            service,
            ReconcilerConfig::default(),
        );
        let source = prefix(None, "192.0.2.0/24");
        let target = prefix(None, "198.51.100.0/24");
        let (source_id, target_id) = (source.id.expect("id"), target.id.expect("id"));
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
            &world.service,
            vec![
                IpamCommand::CreatePrefix(source),
                IpamCommand::CreatePrefix(target),
                IpamCommand::CreateRange(pool),
            ],
        )
        .await;
        let moving = Self {
            world,
            engine,
            role,
            source: source_id,
            target: target_id,
        };
        if scope {
            moving.scope(target_id, true).await;
        }
        moving
    }

    /// Writes a scope row for `prefix` (the configuration service's checks are WP7.4's).
    async fn scope(&self, prefix: PrefixId, enabled: bool) {
        let now = Timestamp::now();
        let stamp = Stamp::new(now, Principal::system(SystemComponent::Dhcp));
        let scope = Scope {
            v6: None,
            prefix,
            enabled,
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
        self.world.store.propose(batch).await.expect("commit");
    }

    async fn host(&self, name: &str, mode: AssignmentMode, mac: Option<&str>, ip: &str) -> HostId {
        let (input, interface) = host(name, mode, mac);
        let id = input.id.expect("id");
        let mut assigned = address(None, ip);
        assigned.interface = Some(interface);
        run(
            &self.world.service,
            vec![
                IpamCommand::CreateHost(input),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        id
    }

    fn request(&self, host: HostId) -> MoveRequest {
        MoveRequest {
            objects: vec![host.into()],
            target: self.target,
            timeout_secs: None,
            move_now: false,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        }
    }

    async fn submit(&self, host: HostId) -> JobId {
        let submitted = self
            .world
            .service
            .move_submit(&self.request(host), &person())
            .await
            .expect("submit");
        submitted.jobs[0].job_id
    }

    async fn drive(&self, job: JobId) -> Job {
        self.engine.drive_once(job).await.expect("drive")
    }

    /// Ticks manual steps until the job waits at `kind`, or ends.
    async fn tick_until(&self, job: JobId, kind: &str) -> Job {
        let cx = person();
        loop {
            let state = self.drive(job).await;
            let Some((index, record)) = state
                .steps
                .iter()
                .enumerate()
                .find(|(_, record)| matches!(record.state, StepState::WaitingForManual { .. }))
            else {
                return state;
            };
            if record.kind.as_str() == kind {
                return state;
            }
            self.engine
                .complete_manual(job, u16::try_from(index).expect("index"), None, &cx)
                .await
                .expect("complete");
        }
    }

    async fn address_at(&self, ip: &str) -> Option<Address> {
        let view = self.world.service.view(None).await.expect("view");
        query::list::<Address>(view.as_ref(), &query::ListQuery::default())
            .expect("list")
            .items
            .into_iter()
            .find(|address| address.ip.to_string() == ip)
    }

    /// A bound lease of `mac` at `ip` in `vrf`, as the role's committer writes it.
    async fn lease(&self, vrf: VrfId, scope: PrefixId, ip: &str, mac: &str) -> Lease {
        let now = Timestamp::now();
        let mac: tenko_core::MacAddr = mac.parse().expect("mac");
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
            cltt: now,
            ends: now.checked_add(Duration::from_secs(7_200)).expect("end"),
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
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        batch
            .put_typed(&dhcp_tables::LEASES, &(lease.vrf, lease.addr), &lease)
            .expect("lease");
        self.world.store.propose(batch).await.expect("commit");
        lease
    }
}

fn kinds(item: &tenko_ipam::MoveItem) -> Vec<&str> {
    item.steps.iter().map(|step| step.kind.as_str()).collect()
}

fn step<'a>(job: &'a Job, kind: &str) -> &'a tenko_jobs::StepRecord {
    job.steps
        .iter()
        .find(|record| record.kind.as_str() == kind)
        .unwrap_or_else(|| panic!("no step {kind}"))
}

#[tokio::test]
async fn a_tenko_scope_makes_the_dhcp_step_automatic_and_sets_the_timeout() {
    let moving = Moving::new(true, Duration::from_secs(5)).await;
    let printer = moving
        .host("printer", AssignmentMode::Reserved, Some(MAC), "192.0.2.15")
        .await;
    let bare = moving
        .host("bare", AssignmentMode::Reserved, None, "192.0.2.16")
        .await;
    let nas = moving
        .host(
            "nas",
            AssignmentMode::Static,
            Some("00:00:5e:00:53:32"),
            "192.0.2.17",
        )
        .await;
    let request = MoveRequest {
        objects: vec![printer.into(), bare.into(), nas.into()],
        ..moving.request(printer)
    };
    let preview = moving
        .world
        .service
        .move_preview(&request, &person(), None)
        .await
        .expect("preview");
    // The pool has no lease time of its own: the scope's two hours. Tenko does not serve
    // the old network, so the deadline is that lease plus the margin (docs/moves.md
    // section 5).
    assert_eq!(preview.target.lease_secs, Some(7_200));
    assert_eq!(preview.timeout_secs, 7_260);
    assert_eq!(
        preview.timeout_source,
        tenko_ipam::moves::MoveTimeoutSource::Pool
    );
    let printer_item = &preview.items[0];
    // The target is Tenko's: the job follows the client's DHCP from its first step.
    assert_eq!(
        kinds(printer_item),
        [
            "dhcp.prepare",
            "ipam.intent",
            "dhcp.reservation",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );
    assert!(printer_item.steps[2].automatic);
    assert!(printer_item.steps[2].text.contains("198.51.100.15"));
    // No MAC address and no client identifier: no reservation can exist (IPAM-18).
    assert_eq!(
        kinds(&preview.items[1]),
        [
            "ipam.intent",
            "dhcp.manual",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );
    // A static device stops at its manual step, with Tenko DHCP or without.
    assert_eq!(
        kinds(&preview.items[2]),
        [
            "ipam.intent",
            "device.manual",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );

    // A disabled scope serves nothing: the step is a task again, the timeout the pool's.
    moving.scope(moving.target, false).await;
    let preview = moving
        .world
        .service
        .move_preview(&moving.request(printer), &person(), None)
        .await
        .expect("preview");
    assert_eq!(kinds(&preview.items[0])[1], "dhcp.manual");
    assert_eq!(preview.target.lease_secs, None);
    assert_eq!(preview.timeout_secs, 3_600);
    assert_eq!(
        preview.timeout_source,
        tenko_ipam::moves::MoveTimeoutSource::Default
    );
}

#[tokio::test]
async fn the_step_waits_for_the_image_and_the_cleanup_releases_the_old_lease() {
    let moving = Moving::new(true, Duration::from_secs(10)).await;
    let printer = moving
        .host("printer", AssignmentMode::Reserved, Some(MAC), "192.0.2.15")
        .await;
    let old = moving.address_at("192.0.2.15").await.expect("old");
    // The device holds its old lease (from its reservation in the source scope), and
    // another client holds a lease the move has nothing to do with.
    moving
        .lease(old.vrf, moving.source, "192.0.2.15", MAC)
        .await;
    moving
        .lease(old.vrf, moving.source, "192.0.2.16", "00:00:5e:00:53:39")
        .await;

    // The role's image is behind until the test moves it, a moment after the submit.
    let job = moving.submit(printer).await;
    let role = Arc::clone(&moving.role);
    let bump = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        role.image.store(u64::MAX / 2, Ordering::SeqCst);
    });
    let state = moving.tick_until(job, "ipam.move.l2").await;
    bump.await.expect("bump");
    let dhcp = step(&state, "ipam.move.dhcp");
    assert_eq!(dhcp.state, StepState::Done, "{state:?}");
    let output: MoveDhcpOutput =
        serde_json::from_slice(&dhcp.output.as_ref().expect("output").0).expect("json");
    assert_eq!(output.image_revision, Some(u64::MAX / 2));
    let new = moving.address_at("198.51.100.15").await.expect("new");
    assert!(output.address_revision > 0, "{output:?}");
    assert_eq!(new.interface, old.interface, "both reservations stand");
    assert!(moving.role.released().is_empty(), "nothing released yet");

    // Through the L2 task and the observation by hand, then the cleanup.
    let state = moving.tick_until(job, "none").await;
    assert_eq!(state.state, JobState::Succeeded, "{state:?}");
    assert_eq!(
        moving.role.released(),
        [(old.vrf, Ipv4Addr::new(192, 0, 2, 15))],
        "the old lease of the device, and only it"
    );
    assert!(moving.address_at("192.0.2.15").await.is_none());
    let cleanup = step(&state, "ipam.move.cleanup");
    let output: serde_json::Value =
        serde_json::from_slice(&cleanup.output.as_ref().expect("output").0).expect("json");
    assert_eq!(output["released_old_lease"], true, "{output}");
}

#[tokio::test]
async fn an_image_that_stays_behind_rolls_the_move_back() {
    let moving = Moving::new(true, Duration::from_millis(300)).await;
    let printer = moving
        .host("printer", AssignmentMode::Reserved, Some(MAC), "192.0.2.15")
        .await;
    let job = moving.submit(printer).await;
    let state = moving.tick_until(job, "none").await;
    assert_eq!(state.state, JobState::RolledBack, "{state:?}");
    let error = state.error.as_ref().expect("an error");
    assert_eq!(error.code, codes::NOT_SERVED, "{error:?}");
    assert!(
        moving.address_at("198.51.100.15").await.is_none(),
        "the new address, and with it the new reservation, is gone"
    );
    assert!(moving.address_at("192.0.2.15").await.is_some());
}

#[tokio::test]
async fn a_cancel_releases_a_lease_the_device_took_in_the_target() {
    let moving = Moving::new(true, Duration::from_secs(5)).await;
    moving.role.image.store(u64::MAX / 2, Ordering::SeqCst);
    let printer = moving
        .host("printer", AssignmentMode::Reserved, Some(MAC), "192.0.2.15")
        .await;
    let job = moving.submit(printer).await;
    moving.tick_until(job, "ipam.move.l2").await;
    let new = moving.address_at("198.51.100.15").await.expect("new");
    // The device got its new reservation before the operator gave up.
    moving
        .lease(new.vrf, moving.target, "198.51.100.15", MAC)
        .await;
    moving.engine.cancel(job, &person()).await.expect("cancel");
    let state = moving.drive(job).await;
    assert_eq!(state.state, JobState::Cancelled, "{state:?}");
    assert_eq!(
        moving.role.released(),
        [(new.vrf, Ipv4Addr::new(198, 51, 100, 15))]
    );
    assert!(moving.address_at("198.51.100.15").await.is_none());
    assert!(moving.address_at("192.0.2.15").await.is_some());
}

#[tokio::test]
async fn a_lease_of_the_mac_in_the_target_network_confirms_the_move() {
    let moving = Moving::new(false, Duration::from_secs(5)).await;
    let camera = moving
        .host("camera", AssignmentMode::Dynamic, Some(MAC), "192.0.2.40")
        .await;
    let job = moving.submit(camera).await;
    moving.tick_until(job, "ipam.move.observe").await;
    let vrf = moving.address_at("192.0.2.40").await.expect("old").vrf;
    let facts = LeaseFacts::new(NodeId(1), ObserveConfig::default());
    facts
        .register(moving.world.store.as_ref())
        .expect("register");
    let commit = |lease: Lease| {
        let facts = Arc::clone(&facts);
        let store = Arc::clone(&moving.world.store);
        async move {
            let now = Timestamp::now();
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
            facts.observe(&lease, now, &mut batch).expect("observe");
            store.propose(batch).await.expect("commit");
        }
    };
    let pool_lease = |ip: &str, mac: &str| {
        let now = Timestamp::now();
        let mac: tenko_core::MacAddr = mac.parse().expect("mac");
        Lease {
            addr: ip.parse().expect("ip"),
            vrf,
            scope: moving.target,
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(mac.octets().to_vec()),
                client_id: None,
            },
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: Some("camera".to_owned()),
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        }
    };

    // Another device's lease in the target, and the camera's lease still in the source:
    // neither confirms.
    commit(pool_lease("198.51.100.150", "00:00:5e:00:53:39")).await;
    commit(pool_lease("192.0.2.40", MAC)).await;
    let report = moving.world.reconcile(Timestamp::now()).await;
    assert_eq!(report.moves_confirmed, 0, "{report:?}");
    // A dynamic device gets an address of the pool, not the planned one: the lease of its
    // MAC address in the target network is the sighting.
    commit(pool_lease("198.51.100.151", MAC)).await;
    let report = moving.world.reconcile(Timestamp::now()).await;
    assert_eq!(report.moves_confirmed, 1, "{report:?}");
    let state = moving.drive(job).await;
    assert_eq!(state.state, JobState::Succeeded, "{state:?}");
    let observe = step(&state, "ipam.move.observe");
    assert_eq!(observe.state, StepState::Done);
}
