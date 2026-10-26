//! The wait of `ipam.move.nudge` (ADR 0028) on its own: a client the dhcp role sees back on
//! the target network is left alone, a client that does not come back within
//! `reappear_secs` is kicked once, and a step that runs again after an interruption does
//! not kick a second time. The role is a fake port that reports what a test says it saw;
//! the controller is the in-memory one. Data lives in the documentation ranges.

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use tenko_core::{
    CodedError, ConnectorId, JobId, MacAddr, PrefixId, Principal, RequestCtx, Revision,
    SystemComponent, Timestamp, VrfId, codec::to_cbor,
};
use tenko_ipam::{
    moves::{
        MoveAttachment, MoveL2Action, MoveMedium, MoveStepParams,
        dhcp::{ClientActivity, DhcpMoves, DhcpRolePort, Released},
        lease::LeasePlan,
        nudge::{MoveNudgeOutput, MoveNudgeStep, NudgePlan},
        settings::MoveSettings,
        steps::L2StepPlan,
    },
    vlan::{
        Controllers,
        controllers::{AttachmentChange, ControllerClient, NudgeChange},
        memory::{Call, MemoryController, MemoryControllers},
    },
};
use tenko_jobs::{StepContext, StepHandler, StepOutcome};
use tenko_store::{MemStore, Store};

const AP: &str = "ap-1";

fn mac() -> MacAddr {
    "00:00:5e:00:53:21".parse().expect("mac")
}

/// The role: whether it saw the client on the target network (at the time it is asked).
#[derive(Default)]
struct FakeRole {
    back: Mutex<bool>,
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
        let back = *self.back.lock().unwrap_or_else(PoisonError::into_inner);
        back.then(|| ClientActivity {
            last: Some(Timestamp::now()),
            on_target: Some(Timestamp::now()),
        })
    }
}

struct Rig {
    step: MoveNudgeStep,
    memory: MemoryControllers,
    role: Arc<FakeRole>,
    store: Arc<dyn Store>,
    connector: ConnectorId,
}

fn rig() -> Rig {
    let mut controller = MemoryController::new("unifi.example.test");
    controller.info.kick = true;
    controller.clients = vec![ControllerClient {
        mac: mac(),
        ip: Some("203.0.113.21".parse().expect("ip")),
        device: AP.to_owned(),
        port: None,
        ssid: Some("iot.example.test".to_owned()),
        network: Some("net-iot".to_owned()),
        vlan: Some(30),
        name: None,
        management: false,
    }];
    let connector = controller.info.id;
    let memory = MemoryControllers::new(vec![controller]);
    let role = Arc::new(FakeRole::default());
    let step = MoveNudgeStep::new(
        Controllers::with(memory.clone()),
        Some(DhcpMoves::with(Arc::clone(&role) as Arc<dyn DhcpRolePort>)),
    );
    Rig {
        step,
        memory,
        role,
        store: Arc::new(MemStore::default()),
        connector,
    }
}

fn params(connector: ConnectorId, reappear_secs: u32) -> Vec<u8> {
    let target = PrefixId::generate();
    let params = MoveStepParams {
        group: "ipam.move.test".to_owned(),
        requested: tenko_core::AddressId::generate().into(),
        address: tenko_core::AddressId::generate(),
        new_address: tenko_core::AddressId::generate(),
        old_ip: "203.0.113.21".parse().expect("ip"),
        new_ip: "198.51.100.21".parse().expect("ip"),
        vrf: VrfId::generate(),
        prefix: target,
        cidr: "198.51.100.0/24".parse().expect("net"),
        vlan: None,
        vid: Some(30),
        host: None,
        interface: None,
        dns_name: None,
        task: None,
        l2: Some(L2StepPlan {
            connector,
            connector_name: "unifi.example.test".to_owned(),
            mac: mac(),
            change: AttachmentChange::SetClientVlan {
                mac: mac(),
                network: "net-iot".to_owned(),
            },
            attachment: MoveAttachment {
                medium: MoveMedium::Wireless,
                device: AP.to_owned(),
                device_name: "ap1.example.test".to_owned(),
                port: None,
                port_name: None,
                profile: None,
                profile_name: None,
                ssid: Some("home.example.test".to_owned()),
                network: Some("net-home".to_owned()),
                network_name: Some("Home".to_owned()),
                vlan: Some(20),
            },
            action: MoveL2Action::ClientVlan,
            diff: Vec::new(),
            nudge: Some(NudgePlan {
                change: NudgeChange::KickClient { mac: mac() },
                reappear_secs,
            }),
        }),
        dns: None,
        dhcp: None,
        lease: Some(LeasePlan {
            mac: mac(),
            lease: None,
            shorten: false,
            target: Some(target),
            reserved: false,
            request_secs: None,
            pool_secs: None,
            settings: MoveSettings::default(),
        }),
    };
    to_cbor(&params).expect("cbor").to_vec()
}

fn cx(rig: &Rig, attempt: u32) -> StepContext {
    StepContext {
        job: JobId::generate(),
        step: 3,
        attempt,
        request: RequestCtx::new(Principal::system(SystemComponent::Ipam)),
        store: Arc::clone(&rig.store),
        deadline: None,
    }
}

fn output(outcome: StepOutcome) -> MoveNudgeOutput {
    let StepOutcome::Done {
        output: Some(bytes),
    } = outcome
    else {
        panic!("a done step with output");
    };
    serde_json::from_slice(&bytes).expect("json")
}

fn kicks(memory: &MemoryControllers) -> usize {
    memory
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::Nudge { .. }))
        .count()
}

#[tokio::test]
async fn a_client_that_comes_back_by_itself_is_not_kicked() {
    let rig = rig();
    *rig.role.back.lock().expect("lock") = true;
    let started = Instant::now();
    let done = rig
        .step
        .execute(&params(rig.connector, 30), &cx(&rig, 1))
        .await
        .expect("execute");
    assert!(started.elapsed().as_secs() < 5, "no wait once it is back");
    let output = output(done);
    assert_eq!(output.reappeared_by.as_deref(), Some("dhcp"));
    assert!(output.reappeared_at.is_some() && output.report.is_none());
    assert_eq!(kicks(&rig.memory), 0);
}

#[tokio::test]
async fn a_client_that_does_not_come_back_is_kicked_once_after_the_wait() {
    let rig = rig();
    let started = Instant::now();
    let done = rig
        .step
        .execute(&params(rig.connector, 1), &cx(&rig, 1))
        .await
        .expect("execute");
    assert!(started.elapsed().as_millis() >= 900, "it waited");
    let output = output(done);
    assert!(output.reappeared_at.is_none());
    assert!(output.report.is_some());
    assert_eq!(kicks(&rig.memory), 1);
}

#[tokio::test]
async fn a_step_that_runs_again_after_an_interruption_does_not_kick_twice() {
    let rig = rig();
    let done = rig
        .step
        .execute(&params(rig.connector, 0), &cx(&rig, 2))
        .await
        .expect("execute");
    assert!(output(done).interrupted);
    assert_eq!(kicks(&rig.memory), 0);
}

#[tokio::test]
async fn a_refusal_at_the_time_of_the_step_is_no_failure_of_the_move() {
    let rig = rig();
    rig.memory.update(rig.connector, |controller| {
        controller.clients[0].management = true;
    });
    let done = rig
        .step
        .execute(&params(rig.connector, 0), &cx(&rig, 1))
        .await
        .expect("execute");
    let output = output(done);
    assert_eq!(
        output.problem.map(|problem| problem.code),
        Some("connect.guardrail.management_client".to_owned())
    );
}
