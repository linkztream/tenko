//! The VLAN provision job (IPAM-03, E7): the preview with the controller's read-back diff,
//! the job driven through the engine against an in-memory network controller (dry run,
//! write, read back), the manual step without a controller, the guardrails and the
//! rollback.

mod common;

use std::{collections::BTreeSet, sync::Arc};

use common::*;
use tenko_core::{
    CodedError, JobId, RequestCtx, Timestamp, VlanId,
    ipam::{Prefix, Status, Vlan},
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, query,
    vlan::{
        ControllerMode, Controllers, NewVlan, NewVlanPrefix, VlanProvisionRequest, codes,
        links::vlan_prefixes,
        memory::{Call, CallKind, MemoryController, MemoryControllers},
        provision,
    },
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, MockClock};
use tenko_store::{MemStore, Store};

/// A service over a fresh store with the real job engine on a mock clock, and a controller
/// slot.
struct World {
    service: Arc<IpamService>,
    engine: JobEngine,
    controllers: Arc<Controllers>,
}

impl World {
    fn new(controllers: Option<MemoryControllers>) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let clock = Arc::new(MockClock::new(
            "2026-10-10T12:00:00Z".parse::<Timestamp>().expect("time"),
        ));
        let mut engine = JobEngine::with_clock(
            Arc::clone(&store),
            EngineConfig::default(),
            clock as Arc<dyn tenko_jobs::Clock>,
        );
        tenko_ipam::jobs::register_steps(&mut engine);
        let slot = Controllers::new();
        if let Some(controllers) = controllers {
            slot.set(controllers);
        }
        tenko_ipam::vlan::register_steps(&mut engine, &slot);
        let service = IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default())
            .expect("service");
        Self {
            service,
            engine,
            controllers: slot,
        }
    }

    async fn preview(
        &self,
        request: &VlanProvisionRequest,
    ) -> Result<tenko_ipam::vlan::VlanProvisionPreview, tenko_ipam::IpamError> {
        provision::preview(&self.service, &self.controllers, request, &person(), None).await
    }

    async fn submit(
        &self,
        request: &VlanProvisionRequest,
        cx: &RequestCtx,
    ) -> Result<tenko_ipam::vlan::VlanProvisionSubmitted, tenko_ipam::IpamError> {
        provision::submit(&self.service, &self.controllers, request, cx).await
    }

    async fn drive(&self, job: JobId) -> tenko_jobs::Job {
        self.engine.drive_once(job).await.expect("drive")
    }

    async fn vlan(&self, id: VlanId) -> Vlan {
        let view = self.service.view(None).await.expect("view");
        query::get::<Vlan>(view.as_ref(), id).expect("vlan")
    }

    async fn prefix(&self, id: tenko_core::PrefixId) -> Prefix {
        let view = self.service.view(None).await.expect("view");
        query::get::<Prefix>(view.as_ref(), id).expect("prefix")
    }
}

fn request(vid: u16, cidr: Option<&str>) -> VlanProvisionRequest {
    VlanProvisionRequest {
        vlan: None,
        create: Some(NewVlan {
            vid,
            name: "IoT".to_owned(),
            site: None,
            vni: None,
            description: Some("devices of the house".to_owned()),
            tags: BTreeSet::new(),
        }),
        prefix: cidr.map(|cidr| NewVlanPrefix {
            cidr: cidr.parse().expect("cidr"),
            vrf: None,
            description: None,
        }),
        connector: None,
        manual: false,
        network_name: None,
        dhcp_relay: vec!["192.0.2.53".parse().expect("ip")],
        acknowledge: Vec::new(),
    }
}

fn step_kinds(preview: &tenko_ipam::vlan::VlanProvisionPreview) -> Vec<&str> {
    preview.steps.iter().map(|s| s.step_kind.as_str()).collect()
}

#[tokio::test]
async fn a_vlan_is_created_in_ipam_and_on_the_controller_after_dry_run_and_read_back() {
    let controller = MemoryController::new("unifi.example.test");
    let id = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let request = request(30, Some("198.51.100.0/24"));

    let preview = world.preview(&request).await.expect("preview");
    assert_eq!(preview.controller.mode, ControllerMode::Automatic);
    assert_eq!(
        preview.controller.connector.as_ref().map(|c| c.id),
        Some(id)
    );
    assert_eq!(
        preview.controller.diff.len(),
        2,
        "{:?}",
        preview.controller.diff
    );
    assert_eq!(preview.controller.network.name, "IoT");
    assert_eq!(
        step_kinds(&preview),
        [
            "ipam.vlan.intent",
            "ipam.vlan.controller",
            "ipam.vlan.activate"
        ]
    );
    assert!(!preview.vlan.existing);
    assert_eq!(preview.vlan.status, Status::Planned);
    let plan = preview.plan.as_ref().expect("an IPAM plan");
    // The VLAN, the prefix, and the default tenant and VRF of a first write.
    assert!(plan.changes.len() >= 2, "{:?}", plan.summary);
    assert_eq!(preview.unacknowledged, Vec::<String>::new());
    assert_eq!(
        memory.snapshot()[0].networks.len(),
        1,
        "a preview writes nothing"
    );

    let submitted = world.submit(&request, &person()).await.expect("submit");
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);

    let vlan = world.vlan(submitted.vlan).await;
    assert_eq!(vlan.status, Status::Active);
    let prefix = world.prefix(submitted.prefix.expect("a prefix")).await;
    assert_eq!(prefix.status, Status::Active);
    assert_eq!(prefix.vlan, Some(submitted.vlan));
    let networks = &memory.snapshot()[0].networks;
    assert!(
        networks
            .iter()
            .any(|n| n.vlan == Some(30) && n.name == "IoT"),
        "{networks:?}"
    );
    // The step planned again, ran a dry run, then wrote.
    let step_calls: Vec<Call> = memory.calls().into_iter().rev().take(3).collect();
    assert_eq!(
        step_calls,
        [
            Call::Apply {
                connector: id,
                vid: 30,
                dry_run: false
            },
            Call::Apply {
                connector: id,
                vid: 30,
                dry_run: true
            },
            Call::Plan {
                connector: id,
                vid: 30
            },
        ]
    );
    let view = world.service.view(None).await.expect("view");
    let linked = vlan_prefixes(view.as_ref(), submitted.vlan, false).expect("prefixes");
    assert_eq!(linked.len(), 1);
}

#[tokio::test]
async fn without_a_controller_the_network_step_is_manual() {
    let world = World::new(None);
    let request = request(40, Some("203.0.113.0/24"));
    let preview = world.preview(&request).await.expect("preview");
    assert_eq!(preview.controller.mode, ControllerMode::Manual);
    assert_eq!(
        preview.controller.reason.as_deref(),
        Some(codes::NO_CONTROLLER)
    );
    assert_eq!(
        step_kinds(&preview),
        ["ipam.vlan.intent", "ipam.vlan.manual", "ipam.vlan.activate"]
    );
    let submitted = world.submit(&request, &person()).await.expect("submit");
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(world.vlan(submitted.vlan).await.status, Status::Planned);
    world
        .engine
        .complete_manual(
            submitted.job_id,
            1,
            Some("created on the switch".to_owned()),
            &person(),
        )
        .await
        .expect("complete");
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    assert_eq!(world.vlan(submitted.vlan).await.status, Status::Active);
}

#[tokio::test]
async fn an_empty_slot_or_an_empty_list_both_mean_no_controller() {
    let world = World::new(Some(MemoryControllers::new(Vec::new())));
    let preview = world.preview(&request(41, None)).await.expect("preview");
    assert_eq!(
        preview.controller.reason.as_deref(),
        Some(codes::NO_CONTROLLER)
    );
    assert_eq!(
        step_kinds(&preview),
        ["ipam.vlan.intent", "ipam.vlan.manual", "ipam.vlan.activate"]
    );
}

#[tokio::test]
async fn the_management_vlan_is_refused_unless_the_network_step_is_manual() {
    let controller = MemoryController::new("lab");
    let world = World::new(Some(MemoryControllers::new(vec![controller])));
    let refused = world
        .preview(&request(10, None))
        .await
        .expect_err("guardrail");
    assert_eq!(refused.code_str(), "connect.guardrail.protected_vlan");
    let refused = world
        .submit(&request(10, None), &person())
        .await
        .expect_err("guardrail on submit");
    assert_eq!(refused.code_str(), "connect.guardrail.protected_vlan");
    let manual = VlanProvisionRequest {
        manual: true,
        ..request(10, None)
    };
    let preview = world.preview(&manual).await.expect("manual preview");
    assert_eq!(
        preview.controller.reason.as_deref(),
        Some(codes::MANUAL_REQUESTED)
    );
    assert_eq!(preview.controller.candidates.len(), 1);
}

#[tokio::test]
async fn a_read_only_connector_shows_its_diff_and_leaves_the_step_to_a_person() {
    let mut controller = MemoryController::new("lab");
    controller.info.writes_enabled = false;
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let request = request(50, None);
    let preview = world.preview(&request).await.expect("preview");
    assert_eq!(preview.controller.mode, ControllerMode::Manual);
    assert_eq!(
        preview.controller.reason.as_deref(),
        Some(codes::CONTROLLER_READ_ONLY)
    );
    assert_eq!(preview.controller.diff.len(), 2);
    assert_eq!(preview.unacknowledged, [codes::CONTROLLER_READ_ONLY]);
    let refused = world
        .submit(&request, &person())
        .await
        .expect_err("unacknowledged");
    assert_eq!(refused.code_str(), "ipam.plan.unacknowledged");
    let acknowledged = VlanProvisionRequest {
        acknowledge: vec![codes::CONTROLLER_READ_ONLY.to_owned()],
        ..request
    };
    let submitted = world
        .submit(&acknowledged, &person())
        .await
        .expect("submit");
    assert_eq!(world.drive(submitted.job_id).await.state, JobState::Waiting);
    assert!(
        !memory
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Apply { .. })),
        "a read-only connector is never asked to write"
    );
}

#[tokio::test]
async fn several_controllers_need_a_choice() {
    let one = MemoryController::new("site-a");
    let two = MemoryController::new("site-b");
    let two_id = two.info.id;
    let memory = MemoryControllers::new(vec![one, two]);
    let world = World::new(Some(memory.clone()));
    let preview = world.preview(&request(60, None)).await.expect("preview");
    assert_eq!(
        preview.controller.reason.as_deref(),
        Some(codes::CONTROLLER_AMBIGUOUS)
    );
    assert_eq!(preview.controller.candidates.len(), 2);
    assert_eq!(preview.unacknowledged, [codes::CONTROLLER_AMBIGUOUS]);
    let named = VlanProvisionRequest {
        connector: Some(two_id),
        ..request(60, None)
    };
    let preview = world.preview(&named).await.expect("preview");
    assert_eq!(preview.controller.mode, ControllerMode::Automatic);
    let submitted = world.submit(&named, &person()).await.expect("submit");
    assert_eq!(
        world.drive(submitted.job_id).await.state,
        JobState::Succeeded
    );
    let unknown = VlanProvisionRequest {
        connector: Some(tenko_core::ConnectorId::generate()),
        ..request(61, None)
    };
    assert_eq!(
        world
            .preview(&unknown)
            .await
            .expect_err("unknown")
            .code_str(),
        codes::CONTROLLER_UNKNOWN
    );
    memory.update(two_id, |c| c.info.enabled = false);
    assert_eq!(
        world
            .preview(&VlanProvisionRequest {
                connector: Some(two_id),
                ..request(62, None)
            })
            .await
            .expect_err("disabled")
            .code_str(),
        codes::CONTROLLER_DISABLED
    );
}

#[tokio::test]
async fn a_controller_that_changed_after_the_submit_rolls_the_job_back() {
    let controller = MemoryController::new("lab");
    let id = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let submitted = world
        .submit(&request(70, Some("198.51.100.0/25")), &person())
        .await
        .expect("submit");
    memory.update(id, |c| {
        c.networks
            .push(tenko_ipam::vlan::controllers::ControllerNetwork {
                id: "net-other".to_owned(),
                name: "Cameras".to_owned(),
                vlan: Some(70),
                subnet: None,
                management: false,
                dhcp: None,
            });
    });
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(
        job.error.as_ref().map(|e| e.code.as_ref()),
        Some(codes::CONTROLLER_CHANGED)
    );
    assert!(world.vlan(submitted.vlan).await.meta.is_deleted());
    assert!(
        world
            .prefix(submitted.prefix.expect("prefix"))
            .await
            .meta
            .is_deleted()
    );
    assert!(
        memory.snapshot()[0]
            .networks
            .iter()
            .any(|n| n.name == "Cameras"),
        "nothing was written"
    );
}

#[tokio::test]
async fn a_failed_write_rolls_back_and_a_read_back_mismatch_is_reported() {
    let controller = MemoryController::new("lab");
    let id = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let submitted = world
        .submit(&request(80, None), &person())
        .await
        .expect("submit");
    memory.fail_next(
        CallKind::Write,
        CodedError::new("connect.unreachable", 502, "the controller went away"),
    );
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert!(world.vlan(submitted.vlan).await.meta.is_deleted());

    memory.update(id, |c| c.drift_after_write = true);
    let submitted = world
        .submit(&request(81, None), &person())
        .await
        .expect("submit");
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    let error = job.error.expect("error");
    assert_eq!(error.code, "connect.verify_mismatch");
    assert!(error.params.contains_key("note"));
}

#[tokio::test]
async fn a_network_that_exists_as_asked_is_only_checked() {
    let controller = MemoryController::new("lab");
    let id = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    memory.update(id, |c| {
        c.networks
            .push(tenko_ipam::vlan::controllers::ControllerNetwork {
                id: "net-iot".to_owned(),
                name: "IoT".to_owned(),
                vlan: Some(90),
                subnet: None,
                management: false,
                dhcp: None,
            });
    });
    let world = World::new(Some(memory.clone()));
    let preview = world.preview(&request(90, None)).await.expect("preview");
    assert_eq!(preview.controller.mode, ControllerMode::Unchanged);
    let submitted = world
        .submit(&request(90, None), &person())
        .await
        .expect("submit");
    assert_eq!(
        world.drive(submitted.job_id).await.state,
        JobState::Succeeded
    );
    assert!(
        !memory
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Apply { .. }))
    );
    // Another name on the same VLAN would change the existing network: acknowledge it.
    let renamed = VlanProvisionRequest {
        network_name: Some("Things".to_owned()),
        ..request(91, None)
    };
    memory.update(id, |c| {
        c.networks
            .push(tenko_ipam::vlan::controllers::ControllerNetwork {
                id: "net-91".to_owned(),
                name: "Old".to_owned(),
                vlan: Some(91),
                subnet: None,
                management: false,
                dhcp: None,
            });
    });
    let preview = world.preview(&renamed).await.expect("preview");
    assert_eq!(preview.unacknowledged, [codes::NETWORK_CHANGES]);
}

#[tokio::test]
async fn an_existing_vlan_is_pushed_to_the_controller_without_ipam_changes() {
    let controller = MemoryController::new("lab");
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let vlan = VlanId::generate();
    run(
        &world.service,
        vec![IpamCommand::CreateVlan(tenko_ipam::command::VlanInput {
            id: Some(vlan),
            vid: 100,
            vni: None,
            name: "Lab".to_owned(),
            site: None,
            status: None,
            tags: BTreeSet::new(),
            custom: std::collections::BTreeMap::new(),
            description: None,
        })],
    )
    .await;
    let push = VlanProvisionRequest {
        vlan: Some(vlan),
        create: None,
        ..request(0, None)
    };
    let preview = world.preview(&push).await.expect("preview");
    assert!(preview.vlan.existing);
    assert!(preview.plan.is_none());
    assert_eq!(step_kinds(&preview), ["ipam.vlan.controller"]);
    let before = world.vlan(vlan).await;
    let submitted = world.submit(&push, &person()).await.expect("submit");
    assert_eq!(
        world.drive(submitted.job_id).await.state,
        JobState::Succeeded
    );
    assert_eq!(world.vlan(vlan).await.meta.revision, before.meta.revision);
    assert!(
        memory.snapshot()[0]
            .networks
            .iter()
            .any(|n| n.vlan == Some(100) && n.name == "Lab")
    );
}

#[tokio::test]
async fn submits_are_idempotent_and_requests_are_validated() {
    let world = World::new(None);
    let key = tenko_core::IdempotencyKey::new("vlan-key-1").expect("key");
    let mut cx = person();
    cx.idempotency = Some(key);
    let first = world
        .submit(&request(110, None), &cx)
        .await
        .expect("submit");
    let again = world
        .submit(&request(110, None), &cx)
        .await
        .expect("replay");
    assert!(again.replayed);
    assert_eq!(again.job_id, first.job_id);
    let other = world
        .submit(&request(111, None), &cx)
        .await
        .expect_err("another request under the key");
    assert_eq!(other.code_str(), "ipam.idempotency_mismatch");

    let both = VlanProvisionRequest {
        vlan: Some(VlanId::generate()),
        ..request(112, None)
    };
    assert_eq!(
        world.preview(&both).await.expect_err("both").code_str(),
        codes::INVALID_REQUEST
    );
    let neither = VlanProvisionRequest {
        create: None,
        ..request(112, None)
    };
    assert_eq!(
        world
            .preview(&neither)
            .await
            .expect_err("neither")
            .code_str(),
        codes::INVALID_REQUEST
    );
    let long = VlanProvisionRequest {
        network_name: Some("x".repeat(65)),
        ..request(112, None)
    };
    assert_eq!(
        world.preview(&long).await.expect_err("long").code_str(),
        codes::INVALID_REQUEST
    );
    // The VLAN exists once its job ran the first step.
    assert_eq!(world.drive(first.job_id).await.state, JobState::Waiting);
    let duplicate = world
        .preview(&request(110, None))
        .await
        .expect_err("the VLAN id exists");
    assert_eq!(duplicate.code_str(), "ipam.vlan.duplicate");
}

#[tokio::test]
async fn the_write_is_undone_when_a_later_step_fails() {
    let controller = MemoryController::new("lab");
    let id = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    let world = World::new(Some(memory.clone()));
    let submitted = world
        .submit(&request(120, None), &person())
        .await
        .expect("submit");
    // No later step of this job can fail on its own, so the network step is compensated
    // directly with the output it recorded, as the engine does in a rollback.
    let job = world.drive(submitted.job_id).await;
    assert_eq!(job.state, JobState::Succeeded);
    let output = job.steps[1].output.clone().expect("output").0;
    let handler = tenko_ipam::vlan::step_handlers(&world.controllers)
        .into_iter()
        .find(|h| h.kind().as_str() == "ipam.vlan.controller")
        .expect("handler");
    let cx = tenko_jobs::StepContext {
        job: submitted.job_id,
        step: 1,
        attempt: 1,
        request: person(),
        store: Arc::clone(world.service.store()),
        deadline: None,
    };
    handler
        .compensate(&[], Some(&output), &cx)
        .await
        .expect("compensate");
    assert!(
        !memory.snapshot()[0]
            .networks
            .iter()
            .any(|n| n.vlan == Some(120)),
        "the write was undone"
    );
    assert!(memory.calls().contains(&Call::Revert {
        connector: id,
        vid: 120
    }));
    memory.fail_next(
        CallKind::Revert,
        CodedError::new("connect.unreachable", 502, "down"),
    );
    let failed = handler.compensate(&[], Some(&output), &cx).await;
    assert_eq!(failed, Err(tenko_jobs::StepError::NotCompensable));
}
