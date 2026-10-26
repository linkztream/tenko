//! The observation step of a move (IPAM-19) is confirmed by the reconciler when the device
//! shows up at its new address, at ingest or in a later run; a sighting from another MAC
//! address or from before the move does not count. Waiting steps of the engine get the
//! address observations too.

mod common;
mod reconcile_support;

use std::sync::Arc;

use common::*;
use reconcile_support::*;
use tenko_core::{HostId, JobId, Timestamp, ipam::AssignmentMode};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, jobs::register_steps, moves::MoveRequest,
    reconcile::ReconcilerConfig,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, MockClock, StepState};
use tenko_store::{MemStore, Store};

struct Moving {
    world: World,
    engine: JobEngine,
    target: tenko_core::PrefixId,
}

impl Moving {
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let clock = Arc::new(MockClock::new(Timestamp::now()));
        let mut engine = JobEngine::with_clock(
            Arc::clone(&store),
            EngineConfig::default(),
            Arc::clone(&clock) as Arc<dyn tenko_jobs::Clock>,
        );
        register_steps(&mut engine);
        let service = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("service");
        let world = World::over(store, service, ReconcilerConfig::default());
        let source = prefix(None, "192.0.2.0/24");
        let target = prefix(None, "198.51.100.0/24");
        let target_id = target.id.expect("id");
        run(
            &world.service,
            vec![
                IpamCommand::CreatePrefix(source),
                IpamCommand::CreatePrefix(target),
            ],
        )
        .await;
        Self {
            world,
            engine,
            target: target_id,
        }
    }

    async fn host(&self, name: &str, mac: &str, ip: &str) -> HostId {
        let (input, interface) = host(name, AssignmentMode::Dynamic, Some(mac));
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

    /// Starts a move of `host`; the job waits at its first manual step (the L2 change).
    async fn start(&self, host: HostId) -> JobId {
        let request = MoveRequest {
            objects: vec![host.into()],
            target: self.target,
            timeout_secs: None,
            move_now: false,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        };
        let submitted = self
            .world
            .service
            .move_submit(&request, &person())
            .await
            .expect("submit");
        let job = submitted.jobs[0].job_id;
        self.engine.drive_once(job).await.expect("drive");
        job
    }

    /// Starts a move of `host` and ticks its manual steps up to the observation step.
    async fn waiting(&self, host: HostId) -> JobId {
        let job = self.start(host).await;
        self.to_observation(job).await;
        job
    }

    /// Ticks the manual steps of `job` up to the observation step.
    async fn to_observation(&self, job: JobId) {
        let cx = person();
        loop {
            let state = self.engine.drive_once(job).await.expect("drive");
            let (index, record) = state
                .steps
                .iter()
                .enumerate()
                .find(|(_, record)| matches!(record.state, StepState::WaitingForManual { .. }))
                .expect("a manual step");
            if record.kind.as_str() == "ipam.move.observe" {
                return;
            }
            self.engine
                .complete_manual(job, u16::try_from(index).expect("index"), None, &cx)
                .await
                .expect("complete");
        }
    }

    async fn state(&self, job: JobId) -> JobState {
        self.engine.drive_once(job).await.expect("drive").state
    }
}

#[tokio::test]
async fn the_device_at_its_new_address_confirms_the_move_at_ingest() {
    let moving = Moving::new().await;
    let host = moving
        .host("sensor", "00:00:5e:00:53:01", "192.0.2.10")
        .await;
    let job = moving.waiting(host).await;
    let now = Timestamp::now();

    // Another device at the new address, and the device still at the old one: no.
    moving
        .world
        .poll(
            vec![
                vm("other", None, Some("00:00:5e:00:53:02"), &["198.51.100.10"]),
                vm("sensor", None, Some("00:00:5e:00:53:01"), &["192.0.2.10"]),
            ],
            now,
        )
        .await;
    assert_eq!(moving.state(job).await, JobState::Waiting);

    moving
        .world
        .poll(
            vec![vm(
                "sensor",
                None,
                Some("00:00:5e:00:53:01"),
                &["198.51.100.10"],
            )],
            now,
        )
        .await;
    assert_eq!(moving.state(job).await, JobState::Succeeded);
}

#[tokio::test]
async fn a_reconcile_run_confirms_a_move_from_current_facts() {
    let moving = Moving::new().await;
    let host = moving
        .host("printer", "00:00:5e:00:53:03", "192.0.2.30")
        .await;
    let job = moving.start(host).await;
    let vrf = moving.world.default_vrf().await;
    let now = Timestamp::now();
    // The device answers at its new address (through a source that names its VRF) while
    // the job still waits for the L2 task: the ingest has nothing to confirm yet.
    moving
        .world
        .probe(vrf, &[("198.51.100.30", Some("00:00:5e:00:53:03"))], now)
        .await;
    moving.to_observation(job).await;
    assert_eq!(moving.state(job).await, JobState::Waiting);
    let report = moving.world.reconcile(now).await;
    assert_eq!(report.moves_confirmed, 1, "{report:?}");
    assert_eq!(moving.state(job).await, JobState::Succeeded);
    // The device at its new address is intent now: no mismatch, nothing discovered.
    let report = moving.world.reconcile(now).await;
    assert_eq!(report.opened, 0, "{report:?}");
}

#[tokio::test]
async fn a_sighting_from_before_the_move_does_not_count() {
    let moving = Moving::new().await;
    let host = moving
        .host("camera", "00:00:5e:00:53:04", "192.0.2.40")
        .await;
    let job = moving.waiting(host).await;
    let vrf = moving.world.default_vrf().await;
    let earlier = Timestamp::now()
        .unix_nanos()
        .checked_sub(3_600_000_000_000)
        .and_then(|nanos| Timestamp::from_unix_nanos(nanos).ok())
        .expect("time");
    moving
        .world
        .probe(
            vrf,
            &[("198.51.100.40", Some("00:00:5e:00:53:04"))],
            earlier,
        )
        .await;
    let report = moving.world.reconcile(earlier).await;
    assert_eq!(report.moves_confirmed, 0, "{report:?}");
    assert_eq!(moving.state(job).await, JobState::Waiting);
}

#[tokio::test]
async fn a_name_at_the_new_address_does_not_confirm_a_move() {
    let moving = Moving::new().await;
    // A host without a MAC address: any sighting of the new address would confirm it, but a
    // name is not a sighting.
    let (input, interface) = host("kiosk", AssignmentMode::Dynamic, None);
    let id = input.id.expect("id");
    let mut assigned = address(None, "192.0.2.50");
    assigned.interface = Some(interface);
    run(
        &moving.world.service,
        vec![
            IpamCommand::CreateHost(input),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    let job = moving.waiting(id).await;
    let now = Timestamp::now();
    moving
        .world
        .names(&[("198.51.100.50", "kiosk.example.test")], now)
        .await;
    assert_eq!(moving.state(job).await, JobState::Waiting, "not at ingest");
    let report = moving.world.reconcile(now).await;
    assert_eq!(report.moves_confirmed, 0, "nor in a run: {report:?}");
    assert_eq!(moving.state(job).await, JobState::Waiting);
    // An address sighting does.
    let vrf = moving.world.default_vrf().await;
    moving
        .world
        .probe(vrf, &[("198.51.100.50", None)], now)
        .await;
    assert_eq!(moving.state(job).await, JobState::Succeeded);
}
