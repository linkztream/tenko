//! Moves (IPAM-19): the preview rules, the job of each address driven through the job
//! engine with manual completion, rollback on the observation timeout, idempotent submits
//! and job groups.

mod common;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::*;
use tenko_core::{
    HostId, ObjectRef, PrefixId, RequestCtx, Timestamp,
    ipam::{Address, AssignmentMode, Host, RangeRole, Status},
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, PlanOptions, codes,
    command::{HostPatch, RangeInput, UpdateHost},
    jobs::register_steps,
    moves::{self, MoveRequest, MoveSubmitted},
    query,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, MockClock};
use tenko_store::{MemStore, Store};

/// A service over a fresh store with the real job engine on a mock clock.
struct World {
    service: Arc<IpamService>,
    engine: JobEngine,
    clock: Arc<MockClock>,
    target: PrefixId,
    source: PrefixId,
}

impl World {
    /// Source network 192.0.2.0/24, target 198.51.100.0/24 on VLAN 30 with a DHCP pool
    /// .100 to .199 leasing for a day, and 198.51.100.20 used already.
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let clock = Arc::new(MockClock::new(
            "2026-10-09T12:00:00Z".parse::<Timestamp>().expect("time"),
        ));
        let mut engine = JobEngine::with_clock(
            Arc::clone(&store),
            EngineConfig::default(),
            Arc::clone(&clock) as Arc<dyn tenko_jobs::Clock>,
        );
        register_steps(&mut engine);
        let service = IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default())
            .expect("service");
        let source = prefix(None, "192.0.2.0/24");
        let mut target = prefix(None, "198.51.100.0/24");
        let vlan = vlan_input(30);
        target.vlan = vlan.id;
        let (source_id, target_id) = (source.id.expect("id"), target.id.expect("id"));
        let pool = RangeInput {
            lease_secs: Some(86_400),
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
                IpamCommand::CreateVlan(vlan),
                IpamCommand::CreatePrefix(source),
                IpamCommand::CreatePrefix(target),
                IpamCommand::CreateRange(pool),
                IpamCommand::CreateAddress(address(None, "198.51.100.20")),
            ],
        )
        .await;
        Self {
            service,
            engine,
            clock,
            target: target_id,
            source: source_id,
        }
    }

    /// A host with one interface and one address in the source network.
    async fn host(
        &self,
        name: &str,
        mode: AssignmentMode,
        mac: Option<&str>,
        ip: &str,
        dns: bool,
    ) -> HostId {
        let (input, interface) = host(name, mode, mac);
        let id = input.id.expect("id");
        let mut assigned = address(None, ip);
        assigned.interface = Some(interface);
        if dns {
            assigned.dns_name = Some(format!("{name}.example.test").parse().expect("name"));
        }
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

    fn request(&self, objects: Vec<ObjectRef>) -> MoveRequest {
        MoveRequest {
            objects,
            target: self.target,
            timeout_secs: None,
            move_now: false,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        }
    }

    async fn submit(&self, request: &MoveRequest, cx: &RequestCtx) -> MoveSubmitted {
        self.service.move_submit(request, cx).await.expect("submit")
    }

    /// Drives a job until it waits or ends.
    async fn drive(&self, job: tenko_core::JobId) -> tenko_jobs::Job {
        self.engine.drive_once(job).await.expect("drive")
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

    async fn host_of(&self, id: HostId) -> Host {
        let view = self.service.view(None).await.expect("view");
        query::get::<Host>(view.as_ref(), id).expect("host")
    }
}

fn vlan_input(vid: u16) -> tenko_ipam::command::VlanInput {
    tenko_ipam::command::VlanInput {
        id: Some(tenko_core::VlanId::generate()),
        vid,
        vni: None,
        name: format!("vlan{vid}"),
        site: None,
        status: None,
        tags: BTreeSet::new(),
        custom: std::collections::BTreeMap::new(),
        description: None,
    }
}

fn kinds(item: &tenko_ipam::MoveItem) -> Vec<&str> {
    item.steps.iter().map(|s| s.kind.as_str()).collect()
}

#[tokio::test]
async fn the_preview_keeps_the_host_part_and_lists_the_steps_by_mode() {
    let world = World::new().await;
    let nas = world
        .host(
            "nas01",
            AssignmentMode::Static,
            Some("00-00-5E-00-53-01"),
            "192.0.2.10",
            true,
        )
        .await;
    let printer = world
        .host(
            "printer",
            AssignmentMode::Reserved,
            Some("00-00-5E-00-53-02"),
            "192.0.2.150",
            false,
        )
        .await;
    let camera = world
        .host("camera", AssignmentMode::Dynamic, None, "192.0.2.20", false)
        .await;
    let request = world.request(vec![nas.into(), printer.into(), camera.into()]);
    let preview = world
        .service
        .move_preview(&request, &person(), None)
        .await
        .expect("preview");
    assert_eq!(preview.target.vid, Some(30));
    assert_eq!(preview.target.lease_secs, Some(86_400));
    assert_eq!(
        preview.timeout_secs, 86_460,
        "the pools' lease plus the margin: Tenko does not serve the old network"
    );
    assert_eq!(
        preview.timeout_source,
        tenko_ipam::moves::MoveTimeoutSource::Pool
    );
    assert_eq!(preview.parallelism, 4);
    assert_eq!(preview.items.len(), 3);

    let nas_item = &preview.items[0];
    assert_eq!(nas_item.new_ip.to_string(), "198.51.100.10");
    assert!(nas_item.same_host_part);
    assert_eq!(nas_item.reason, None);
    assert_eq!(
        kinds(nas_item),
        [
            "ipam.intent",
            "dns.manual",
            "device.manual",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );
    let dns = nas_item.dns.as_ref().expect("dns");
    assert_eq!(dns.name.as_str(), "nas01.example.test");
    assert_eq!(
        dns.new.map(|ip| ip.to_string()).as_deref(),
        Some("198.51.100.10")
    );
    assert!(nas_item.steps[3].text.contains("VLAN 30"));
    assert!(!nas_item.steps[3].automatic);
    assert!(nas_item.steps[0].automatic && nas_item.steps[5].automatic);

    let printer_item = &preview.items[1];
    assert!(!printer_item.same_host_part);
    assert_eq!(
        printer_item.reason.as_deref(),
        Some(moves::codes::HOST_PART_RESERVED),
        ".150 lies in the DHCP pool"
    );
    assert_eq!(printer_item.new_ip.to_string(), "198.51.100.1");
    assert_eq!(
        kinds(printer_item),
        [
            "ipam.intent",
            "dhcp.manual",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );

    let camera_item = &preview.items[2];
    assert_eq!(
        camera_item.reason.as_deref(),
        Some(moves::codes::HOST_PART_TAKEN)
    );
    assert_eq!(
        camera_item.new_ip.to_string(),
        "198.51.100.2",
        "items never share an address"
    );
    assert_eq!(
        kinds(camera_item),
        ["ipam.intent", "l2.move", "observe", "cleanup"]
    );
    assert_eq!(preview.unacknowledged, Vec::<String>::new());
}

#[tokio::test]
async fn host_parts_outside_the_target_fall_back_to_next_free() {
    let world = World::new().await;
    let small = prefix(None, "203.0.113.0/26");
    let small_id = small.id.expect("id");
    run(&world.service, vec![IpamCommand::CreatePrefix(small)]).await;
    let laptop = world
        .host("laptop", AssignmentMode::Dynamic, None, "192.0.2.64", false)
        .await;
    let request = MoveRequest {
        target: small_id,
        ..world.request(vec![laptop.into()])
    };
    let preview = world
        .service
        .move_preview(&request, &person(), None)
        .await
        .expect("preview");
    let item = &preview.items[0];
    assert_eq!(
        item.reason.as_deref(),
        Some(moves::codes::HOST_PART_OUTSIDE)
    );
    assert_eq!(item.new_ip.to_string(), "203.0.113.1");
    assert_eq!(preview.timeout_secs, 3_600, "no lease on the target");
}

#[tokio::test]
async fn unmanaged_locked_and_misplaced_objects_are_refused() {
    let world = World::new().await;
    let wild = world
        .host("wild", AssignmentMode::Unmanaged, None, "192.0.2.30", false)
        .await;
    let error = world
        .service
        .move_preview(&world.request(vec![wild.into()]), &person(), None)
        .await
        .expect_err("unmanaged");
    assert_eq!(error.code_str(), moves::codes::UNMANAGED);
    assert_eq!(error.coded().status, 422);

    let safe = world
        .host(
            "safe",
            AssignmentMode::Static,
            Some("00-00-5E-00-53-03"),
            "192.0.2.31",
            false,
        )
        .await;
    run(
        &world.service,
        vec![IpamCommand::SetLock {
            host: safe,
            lock: true,
            expected: None,
        }],
    )
    .await;
    let error = world
        .service
        .move_preview(&world.request(vec![safe.into()]), &person(), None)
        .await
        .expect_err("locked");
    assert_eq!(error.code_str(), codes::HOST_LOCKED);
    assert_eq!(error.coded().status, 423);

    let inside = address(None, "198.51.100.40");
    let inside_ref = ObjectRef::from(inside.id.expect("id"));
    run(&world.service, vec![IpamCommand::CreateAddress(inside)]).await;
    let error = world
        .service
        .move_preview(&world.request(vec![inside_ref]), &person(), None)
        .await
        .expect_err("inside");
    assert_eq!(error.code_str(), moves::codes::ALREADY_IN_TARGET);

    let error = world
        .service
        .move_preview(&world.request(vec![world.source.into()]), &person(), None)
        .await
        .expect_err("a prefix");
    assert_eq!(error.code_str(), moves::codes::UNSUPPORTED_OBJECT);
    let error = world
        .service
        .move_preview(&world.request(Vec::new()), &person(), None)
        .await
        .expect_err("empty");
    assert_eq!(error.coded().status, 400);
}

#[tokio::test]
async fn warnings_need_acknowledgement_before_a_submit() {
    let world = World::new().await;
    let nas = world
        .host(
            "nas01",
            AssignmentMode::Static,
            Some("00-00-5E-00-53-01"),
            "192.0.2.10",
            true,
        )
        .await;
    // Another host in the target already answers to the same name.
    let mut twin = address(None, "198.51.100.50");
    twin.dns_name = Some("nas01.example.test".parse().expect("name"));
    run(&world.service, vec![IpamCommand::CreateAddress(twin)]).await;
    let bare = world
        .host("tag", AssignmentMode::Reserved, None, "192.0.2.12", false)
        .await;
    let request = world.request(vec![nas.into(), bare.into()]);
    let preview = world
        .service
        .move_preview(&request, &person(), None)
        .await
        .expect("preview");
    let codes_seen: BTreeSet<&str> = preview.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes_seen.contains(moves::codes::DNS_COLLISION));
    assert!(codes_seen.contains(codes::WARN_RESERVATION_IDENTIFIER));
    assert_eq!(preview.unacknowledged, [moves::codes::DNS_COLLISION]);
    let collision = &preview.items[0].warnings[0];
    assert_eq!(collision.params["proposed"], "nas01-2.example.test");

    let error = world
        .service
        .move_submit(&request, &person())
        .await
        .expect_err("needs acknowledgement");
    assert_eq!(error.code_str(), codes::PLAN_UNACKNOWLEDGED);
    let acknowledged = MoveRequest {
        acknowledge: vec![moves::codes::DNS_COLLISION.to_owned()],
        ..request
    };
    let submitted = world.submit(&acknowledged, &person()).await;
    assert_eq!(submitted.jobs.len(), 2);
}

#[tokio::test]
async fn a_move_runs_its_steps_with_manual_completion_and_cleans_up() {
    let world = World::new().await;
    let nas = world
        .host(
            "nas01",
            AssignmentMode::Static,
            Some("00-00-5E-00-53-01"),
            "192.0.2.10",
            true,
        )
        .await;
    let cx = person();
    let submitted = world.submit(&world.request(vec![nas.into()]), &cx).await;
    let job_id = submitted.jobs[0].job_id;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting, "waits for the DNS task");
    assert_eq!(
        job.spec.group.as_ref().map(ToString::to_string),
        Some(submitted.group.clone())
    );
    assert_eq!(job.spec.group_limit, Some(4));
    let new = world.address_at("198.51.100.10").await.expect("new intent");
    assert_eq!(new.status, Status::Planned);
    assert!(
        world
            .address_at("192.0.2.10")
            .await
            .is_some_and(|a| !a.meta.is_deleted())
    );

    // DNS, device, L2 and observation, ticked off in order.
    for step in 1..=4u16 {
        world
            .engine
            .complete_manual(job_id, step, Some(format!("done {step}")), &cx)
            .await
            .expect("complete");
        let job = world.drive(job_id).await;
        if step < 4 {
            assert_eq!(job.state, JobState::Waiting, "after step {step}");
        } else {
            assert_eq!(job.state, JobState::Succeeded);
        }
    }
    let new = world.address_at("198.51.100.10").await.expect("new");
    assert_eq!(new.status, Status::Active);
    assert!(!new.meta.is_deleted());
    let old = world.address_at("192.0.2.10").await.expect("old");
    assert!(old.meta.is_deleted(), "the old intent is gone");
    let _ = world.source;
}

#[tokio::test]
async fn the_observation_timeout_rolls_the_move_back() {
    let world = World::new().await;
    let printer = world
        .host(
            "printer",
            AssignmentMode::Reserved,
            Some("00-00-5E-00-53-02"),
            "192.0.2.15",
            false,
        )
        .await;
    let cx = person();
    let request = MoveRequest {
        timeout_secs: Some(300),
        ..world.request(vec![printer.into()])
    };
    let submitted = world.submit(&request, &cx).await;
    assert_eq!(submitted.timeout_secs, 300);
    let job_id = submitted.jobs[0].job_id;
    world.drive(job_id).await;
    // DHCP and L2 done; the observation step starts its five minutes now.
    for step in 1..=2u16 {
        world
            .engine
            .complete_manual(job_id, step, None, &cx)
            .await
            .expect("complete");
        world.drive(job_id).await;
    }
    world.clock.advance(Duration::from_secs(299));
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);
    world.clock.advance(Duration::from_secs(2));
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert!(job.error.is_some(), "the reason is on the job");

    let new = world.address_at("198.51.100.15").await.expect("new intent");
    assert!(new.meta.is_deleted(), "the new intent is removed");
    let old = world.address_at("192.0.2.15").await.expect("old");
    assert!(!old.meta.is_deleted(), "the old intent stays");
    let host = world.host_of(printer).await;
    assert!(
        host.meta
            .tags
            .iter()
            .any(|t| t.as_str() == moves::MOVE_FAILED_TAG),
        "the host is marked"
    );

    // A later successful move clears the mark.
    let again = world.submit(&request, &person()).await;
    let job_id = again.jobs[0].job_id;
    world.drive(job_id).await;
    for step in 1..=3u16 {
        world
            .engine
            .complete_manual(job_id, step, None, &cx)
            .await
            .expect("complete");
        world.drive(job_id).await;
    }
    assert_eq!(
        world.engine.job(job_id).await.expect("job").state,
        JobState::Succeeded
    );
    let host = world.host_of(printer).await;
    assert!(
        host.meta
            .tags
            .iter()
            .all(|t| t.as_str() != moves::MOVE_FAILED_TAG)
    );
}

#[tokio::test]
async fn submits_are_idempotent_and_jobs_share_a_group() {
    let world = World::new().await;
    let a = world
        .host("alpha", AssignmentMode::Dynamic, None, "192.0.2.41", false)
        .await;
    let b = world
        .host("bravo", AssignmentMode::Dynamic, None, "192.0.2.42", false)
        .await;
    let key = tenko_core::IdempotencyKey::new("move-2026-10-09-a").expect("key");
    let cx = person().with_idempotency(key.clone());
    let request = MoveRequest {
        parallelism: Some(1),
        ..world.request(vec![a.into(), b.into()])
    };
    let first = world.submit(&request, &cx).await;
    assert!(!first.replayed);
    assert_eq!(first.jobs.len(), 2);
    assert_eq!(first.parallelism, 1);
    let again = world
        .submit(
            &request,
            &RequestCtx::new(cx.principal.clone()).with_idempotency(key.clone()),
        )
        .await;
    assert!(again.replayed);
    assert_eq!(again.jobs, first.jobs);
    assert_eq!(again.group, first.group);
    let other = MoveRequest {
        objects: vec![a.into()],
        ..request.clone()
    };
    let error = world
        .service
        .move_submit(
            &other,
            &RequestCtx::new(cx.principal.clone()).with_idempotency(key),
        )
        .await
        .expect_err("mismatch");
    assert_eq!(error.code_str(), codes::IDEMPOTENCY_MISMATCH);

    for job in &first.jobs {
        let job = world.engine.job(job.job_id).await.expect("job");
        assert_eq!(job.spec.kind.as_str(), moves::MOVE_JOB);
        assert_eq!(job.spec.group_limit, Some(1));
        assert_eq!(
            job.spec.group.as_ref().map(ToString::to_string),
            Some(first.group.clone())
        );
    }
}

#[tokio::test]
async fn range_lease_times_are_validated() {
    let world = World::new().await;
    let bad = RangeInput {
        lease_secs: Some(30),
        ..range(
            world.target,
            "198.51.100.210",
            "198.51.100.219",
            RangeRole::DhcpPool,
        )
    };
    let error = world
        .service
        .execute(
            &[IpamCommand::CreateRange(bad)],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("too short");
    assert_eq!(error.code_str(), codes::VALIDATION);
    let reserved = RangeInput {
        lease_secs: Some(3_600),
        ..range(
            world.target,
            "198.51.100.210",
            "198.51.100.219",
            RangeRole::Reserved,
        )
    };
    let error = world
        .service
        .execute(
            &[IpamCommand::CreateRange(reserved)],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("not a pool");
    assert_eq!(error.code_str(), codes::VALIDATION);
    let _ = UpdateHost {
        id: HostId::generate(),
        expected: None,
        patch: HostPatch::default(),
    };
}
