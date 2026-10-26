//! The L2 step of a move job (IPAM-19 step 4) driven through the real job engine against the
//! in-memory network controller: the port profile of a wired device, the per-client VLAN of
//! a wireless one, the rollback with and without a usable receipt, the guardrails, a
//! controller with writes off or unreadable, a device that changed since the submit, the
//! plan fingerprint, a bulk move, and the confirmation of the observation step from the
//! controller's client table through the reconciler. Data lives in the documentation ranges.

mod common;
mod reconcile_support;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::*;
use reconcile_support::{World as Reconciling, vm};
use tenko_core::{
    CodedError, ConnectorId, HostId, JobId, MacAddr, ObjectRef, PrefixId, Timestamp,
    ipam::{Address, AssignmentMode, Host, RangeRole, Status},
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamResult, IpamService, MovePreview, MoveSubmitted, codes,
    command::{RangeInput, VlanInput},
    moves::{self, MoveL2Action, MoveL2Output, MoveMedium, MoveRequest},
    query,
    reconcile::ReconcilerConfig,
    vlan::{
        Controllers, DiffEntry,
        controllers::{
            AttachmentChange, ControllerClient, ControllerDevice, ControllerDeviceKind,
            ControllerNetwork, ControllerPortState, ControllerProfile, ControllerWlan,
        },
        memory::{Call, CallKind, MemoryController, MemoryControllers},
    },
};
use tenko_jobs::{
    EngineConfig, Job, JobEngine, JobKind, JobQuery, JobState, ManualTask, MockClock, StepState,
};
use tenko_store::{MemStore, Store};

const SWITCH: &str = "sw-1";
const SWITCH_NAME: &str = "sw1.example.test";
const AP: &str = "ap-1";
const AP_NAME: &str = "ap1.example.test";
const HOME_SSID: &str = "home.example.test";
const IOT_SSID: &str = "iot.example.test";

const INTENT: &str = "ipam.move.intent";
const CONTROLLER: &str = "ipam.move.controller";
const MANUAL_L2: &str = "ipam.move.l2";
const OBSERVE: &str = "ipam.move.observe";
const CLEANUP: &str = "ipam.move.cleanup";
const UNDO_TASK: &str = "jobs.undo.step";

/// A host in IPAM that the controller sees as a client.
struct Device {
    host: HostId,
    mac: MacAddr,
    old_ip: String,
    new_ip: String,
}

/// IPAM with the real job engine on a mock clock, the in-memory network controller behind
/// the move job's slot, and the moves 203.0.113.0/24 (VLAN 20) to 198.51.100.0/24 (VLAN 30).
struct World {
    service: Arc<IpamService>,
    store: Arc<dyn Store>,
    engine: JobEngine,
    clock: Arc<MockClock>,
    memory: MemoryControllers,
    slot: Arc<Controllers>,
    controller: ConnectorId,
    target: PrefixId,
}

fn network(id: &str, name: &str, vid: u16, cidr: &str) -> ControllerNetwork {
    ControllerNetwork {
        id: id.to_owned(),
        name: name.to_owned(),
        vlan: Some(vid),
        subnet: cidr.parse().ok(),
        management: false,
        dhcp: None,
    }
}

fn profile(id: &str, name: &str, native: &str) -> ControllerProfile {
    ControllerProfile {
        id: id.to_owned(),
        name: name.to_owned(),
        native_network: Some(native.to_owned()),
        tagged: Vec::new(),
    }
}

fn managed_device(id: &str, name: &str, kind: ControllerDeviceKind) -> ControllerDevice {
    ControllerDevice {
        id: id.to_owned(),
        name: name.to_owned(),
        model: None,
        mac: None,
        ip: None,
        kind,
        ports: Vec::new(),
    }
}

/// Port 1 is the uplink; ports 2 to 8 are access ports with the home profile.
fn port_state(index: u16) -> ControllerPortState {
    ControllerPortState {
        device: SWITCH.to_owned(),
        index,
        name: Some(format!("Port {index}")),
        profile: (index != 1).then(|| "prof-home".to_owned()),
        native_vlan: Some(if index == 1 { 10 } else { 20 }),
        uplink: index == 1,
        management: false,
        up: true,
    }
}

fn wlan(ssid: &str, vid: u16) -> ControllerWlan {
    ControllerWlan {
        ssid: ssid.to_owned(),
        vlan: Some(vid),
        enabled: true,
        access_points: vec![AP.to_owned()],
    }
}

/// The controller: the management network (VLAN 10) from `MemoryController::new`, the
/// networks Home (VLAN 20) and `IoT` (VLAN 30) with a port profile each, a switch with eight
/// ports, an access point that broadcasts both wireless networks, and no clients yet.
fn home_controller() -> MemoryController {
    let mut controller = MemoryController::new("unifi.example.test");
    controller
        .networks
        .push(network("net-home", "Home", 20, "203.0.113.0/24"));
    controller
        .networks
        .push(network("net-iot", "IoT", 30, "198.51.100.0/24"));
    controller.profiles = vec![
        profile("prof-home", "Home ports", "net-home"),
        profile("prof-iot", "IoT ports", "net-iot"),
        profile("prof-lab", "Lab ports", "net-home"),
    ];
    controller.devices = vec![
        managed_device(SWITCH, SWITCH_NAME, ControllerDeviceKind::Switch),
        managed_device(AP, AP_NAME, ControllerDeviceKind::AccessPoint),
    ];
    controller.ports = (1..=8).map(port_state).collect();
    controller.wlans = vec![wlan(HOME_SSID, 20), wlan(IOT_SSID, 30)];
    controller
}

fn port_mut(controller: &mut MemoryController, index: u16) -> &mut ControllerPortState {
    controller
        .ports
        .iter_mut()
        .find(|port| port.device == SWITCH && port.index == index)
        .expect("port")
}

fn vlan_input(vid: u16) -> VlanInput {
    VlanInput {
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

fn unreachable() -> CodedError {
    CodedError::new("connect.unreachable", 502, "the controller does not answer")
}

fn kinds(item: &tenko_ipam::MoveItem) -> Vec<&str> {
    item.steps.iter().map(|s| s.kind.as_str()).collect()
}

fn step_kinds(job: &Job) -> Vec<&str> {
    job.spec.steps.iter().map(|s| s.kind.as_str()).collect()
}

fn step_index(job: &Job, kind: &str) -> u16 {
    let index = job
        .steps
        .iter()
        .position(|step| step.kind.as_str() == kind)
        .unwrap_or_else(|| panic!("the job has no step {kind}"));
    u16::try_from(index).expect("index")
}

fn step_state<'a>(job: &'a Job, kind: &str) -> &'a StepState {
    &job.steps[usize::from(step_index(job, kind))].state
}

/// The task a step waits for a person to do (a manual task or an undo task).
fn waiting_task(job: &Job, kind: &str) -> ManualTask {
    match step_state(job, kind) {
        StepState::WaitingForManual { task, .. } => task.clone(),
        other => panic!("step {kind} is {other:?}, not waiting for a person"),
    }
}

/// What the controller step kept as its output.
fn l2_output(job: &Job) -> MoveL2Output {
    let record = &job.steps[usize::from(step_index(job, CONTROLLER))];
    let bytes = record
        .output
        .as_ref()
        .expect("the controller step keeps its output");
    serde_json::from_slice(&bytes.0).expect("the output is MoveL2Output JSON")
}

/// The dry-run flag of every `ApplyAttachment` call, in order.
fn applies(calls: &[Call]) -> Vec<bool> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::ApplyAttachment { dry_run, .. } => Some(*dry_run),
            _ => None,
        })
        .collect()
}

fn reverts(calls: &[Call]) -> usize {
    calls
        .iter()
        .filter(|call| matches!(call, Call::RevertAttachment { .. }))
        .count()
}

/// Whether any call asked the controller to plan or apply an attachment change.
fn changed_something(calls: &[Call]) -> bool {
    calls.iter().any(|call| {
        matches!(
            call,
            Call::PlanAttachment { .. } | Call::ApplyAttachment { .. }
        )
    })
}

fn has_tag(host: &Host) -> bool {
    host.meta
        .tags
        .iter()
        .any(|tag| tag.as_str() == moves::MOVE_FAILED_TAG)
}

impl World {
    /// The service, the engine with the IPAM and move steps registered, and the controller
    /// behind the slot. The target 198.51.100.0/24 has a DHCP pool leasing 240 s, so the
    /// observation timeout is the floor of 300 s (the lease plus the margin is less).
    async fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let clock = Arc::new(MockClock::new(Timestamp::now()));
        let controller = home_controller();
        let controller_id = controller.info.id;
        let memory = MemoryControllers::new(vec![controller]);
        let slot = Controllers::with(memory.clone());
        let mut engine = JobEngine::with_clock(
            Arc::clone(&store),
            EngineConfig::default(),
            Arc::clone(&clock) as Arc<dyn tenko_jobs::Clock>,
        );
        tenko_ipam::jobs::register_steps(&mut engine);
        moves::register_steps(&mut engine, &slot);
        let service = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("service");
        let (home, iot) = (vlan_input(20), vlan_input(30));
        let mut source = prefix(None, "203.0.113.0/24");
        source.vlan = home.id;
        let mut target = prefix(None, "198.51.100.0/24");
        target.vlan = iot.id;
        let target_id = target.id.expect("id");
        let pool = RangeInput {
            // With the margin of 60 s the deadline is the floor of 300 s.
            lease_secs: Some(240),
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
                IpamCommand::CreateVlan(home),
                IpamCommand::CreateVlan(iot),
                IpamCommand::CreatePrefix(source),
                IpamCommand::CreatePrefix(target),
                IpamCommand::CreateRange(pool),
            ],
        )
        .await;
        Self {
            service,
            store,
            engine,
            clock,
            memory,
            slot,
            controller: controller_id,
            target: target_id,
        }
    }

    /// A dynamic host `dev<n>` with MAC address 00:00:5e:00:53:<n> and the address
    /// 203.0.113.<n>; its move keeps the host part (198.51.100.<n>).
    async fn ipam_host(&self, n: u8) -> Device {
        let mac_text = format!("00:00:5e:00:53:{n:02x}");
        let old_ip = format!("203.0.113.{n}");
        let (input, interface) = host(&format!("dev{n}"), AssignmentMode::Dynamic, Some(&mac_text));
        let id = input.id.expect("id");
        let mut assigned = address(None, &old_ip);
        assigned.interface = Some(interface);
        run(
            &self.service,
            vec![
                IpamCommand::CreateHost(input),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        Device {
            host: id,
            mac: mac_text.parse().expect("mac"),
            old_ip,
            new_ip: format!("198.51.100.{n}"),
        }
    }

    /// A host that the controller sees on port `port` of the switch, in the Home network.
    async fn wired(&self, n: u8, port: u16) -> Device {
        let device = self.ipam_host(n).await;
        let client = ControllerClient {
            mac: device.mac,
            ip: Some(device.old_ip.parse().expect("ip")),
            device: SWITCH.to_owned(),
            port: Some(port),
            ssid: None,
            network: Some("net-home".to_owned()),
            vlan: Some(20),
            name: Some(format!("dev{n}.example.test")),
            management: false,
        };
        self.edit(|controller| controller.clients.push(client));
        device
    }

    /// A host that the controller sees on the home SSID of the access point.
    async fn wireless(&self, n: u8) -> Device {
        let device = self.ipam_host(n).await;
        let client = ControllerClient {
            mac: device.mac,
            ip: Some(device.old_ip.parse().expect("ip")),
            device: AP.to_owned(),
            port: None,
            ssid: Some(HOME_SSID.to_owned()),
            network: Some("net-home".to_owned()),
            vlan: Some(20),
            name: Some(format!("dev{n}.example.test")),
            management: false,
        };
        self.edit(|controller| controller.clients.push(client));
        device
    }

    /// Changes the controller behind the engine's back.
    fn edit(&self, change: impl FnOnce(&mut MemoryController)) {
        self.memory.update(self.controller, change);
    }

    fn controller_now(&self) -> MemoryController {
        self.memory.snapshot().remove(0)
    }

    fn port(&self, index: u16) -> ControllerPortState {
        self.controller_now()
            .ports
            .into_iter()
            .find(|port| port.device == SWITCH && port.index == index)
            .expect("port")
    }

    fn client(&self, mac: MacAddr) -> ControllerClient {
        self.controller_now()
            .clients
            .into_iter()
            .find(|client| client.mac == mac)
            .expect("client")
    }

    fn request(&self, hosts: &[HostId]) -> MoveRequest {
        MoveRequest {
            objects: hosts.iter().map(|host| ObjectRef::from(*host)).collect(),
            target: self.target,
            timeout_secs: None,
            move_now: false,
            acknowledge: Vec::new(),
            parallelism: None,
            expect_fingerprint: None,
        }
    }

    async fn preview(&self, request: &MoveRequest) -> MovePreview {
        moves::preview_move(&self.service, &self.slot, request, &person(), None)
            .await
            .expect("preview")
    }

    #[allow(clippy::result_large_err)] // The authorization callback answers the port's coded error.
    async fn try_submit(&self, request: &MoveRequest) -> IpamResult<MoveSubmitted> {
        moves::submit_move(&self.service, &self.slot, request, &person(), &|_| Ok(())).await
    }

    async fn submit(&self, request: &MoveRequest) -> MoveSubmitted {
        self.try_submit(request).await.expect("submit")
    }

    /// Drives a job until it waits or ends.
    async fn drive(&self, job: JobId) -> Job {
        self.engine.drive_once(job).await.expect("drive")
    }

    /// Completes the manual step of `kind` by hand.
    async fn complete(&self, job: JobId, kind: &str) {
        let record = self.engine.job(job).await.expect("job");
        self.engine
            .complete_manual(job, step_index(&record, kind), None, &person())
            .await
            .expect("complete");
    }

    /// The calls the controller received since `mark` (a length of `calls()`).
    fn calls_since(&self, mark: usize) -> Vec<Call> {
        self.memory.calls().split_off(mark)
    }

    /// How many move jobs exist.
    async fn move_jobs(&self) -> usize {
        self.engine
            .list(&JobQuery {
                kinds: vec![JobKind::from_static(moves::MOVE_JOB)],
                limit: 100,
                ..JobQuery::default()
            })
            .await
            .expect("list")
            .items
            .len()
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
        fetch::<Host>(&self.service, id).await
    }

    /// The move was undone: the new address is gone, the old one stays and the host is
    /// tagged `move-failed`.
    async fn assert_undone(&self, device: &Device) {
        let new = self
            .address_at(&device.new_ip)
            .await
            .expect("the new address was created");
        assert!(new.meta.is_deleted(), "the new address is removed");
        let old = self.address_at(&device.old_ip).await.expect("old address");
        assert!(!old.meta.is_deleted(), "the old address stays");
        assert!(
            has_tag(&self.host_of(device.host).await),
            "the host carries {}",
            moves::MOVE_FAILED_TAG
        );
    }

    /// The move is done: the new address is active, the old one is gone, the host is clean.
    async fn assert_done(&self, device: &Device) {
        let new = self.address_at(&device.new_ip).await.expect("new address");
        assert!(!new.meta.is_deleted());
        assert_eq!(new.status, Status::Active);
        let old = self.address_at(&device.old_ip).await.expect("old address");
        assert!(old.meta.is_deleted(), "the old address is gone");
        assert!(!has_tag(&self.host_of(device.host).await));
    }

    /// Drives a submitted move whose device changed after the submit: the controller step
    /// refuses with `ipam.move.l2_changed` (409) and writes nothing, and the job rolls back.
    async fn assert_l2_changed(&self, submitted: &MoveSubmitted, device: &Device, what: &str) {
        let job_id = submitted.jobs[0].job_id;
        let mark = self.memory.calls().len();
        let job = self.drive(job_id).await;
        assert_eq!(job.state, JobState::RolledBack);
        let error = job.error.as_ref().expect("the reason is on the job");
        assert_eq!(error.code, moves::codes::L2_CHANGED);
        assert_eq!(error.status, 409);
        assert!(error.detail.contains(what), "{}", error.detail);
        match step_state(&job, CONTROLLER) {
            StepState::Failed { error } => assert_eq!(error.code, moves::codes::L2_CHANGED),
            other => panic!("the controller step is {other:?}"),
        }
        let calls = self.calls_since(mark);
        assert_eq!(
            calls,
            [Call::Attachments {
                connector: self.controller
            }],
            "the step reads the controller and stops"
        );
        assert!(!changed_something(&calls));
        assert_eq!(
            job.steps[usize::from(step_index(&job, CLEANUP))].attempts,
            0
        );
        self.assert_undone(device).await;
    }
}

fn set_port_profile(port: u16, profile: &str) -> AttachmentChange {
    AttachmentChange::SetPortProfile {
        device: SWITCH.to_owned(),
        port,
        profile: profile.to_owned(),
    }
}

fn profile_diff(port: u16, before: &str, after: &str) -> DiffEntry {
    DiffEntry {
        path: format!("devices/{SWITCH}/ports/{port}/profile"),
        before: Some(before.to_owned()),
        after: Some(after.to_owned()),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One device from preview to the finished move, in order.
async fn a_wired_dynamic_host_moves_by_port_profile() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let request = world.request(&[tv.host]);

    // The preview reads the controller once and writes nothing.
    let preview = world.preview(&request).await;
    assert_eq!(
        world.memory.calls(),
        [
            Call::List,
            Call::Attachments {
                connector: world.controller
            }
        ]
    );
    assert_eq!(preview.timeout_secs, 300);
    assert_eq!(preview.unacknowledged, Vec::<String>::new());
    assert_eq!(preview.controllers.len(), 1);
    let item = &preview.items[0];
    let change = set_port_profile(2, "prof-iot");
    assert_eq!(item.new_ip.to_string(), tv.new_ip);
    assert_eq!(item.l2.action, MoveL2Action::PortProfile);
    assert_eq!(item.l2.reason, None);
    assert_eq!(item.l2.problem, None);
    assert_eq!(item.l2.change, Some(change.clone()));
    assert_eq!(item.l2.profile_name.as_deref(), Some("IoT ports"));
    assert_eq!(item.l2.network_name.as_deref(), Some("IoT"));
    assert_eq!(
        item.l2.connector.as_ref().map(|c| c.id),
        Some(world.controller)
    );
    assert_eq!(item.l2.notes, [moves::codes::NOTE_LINK_FLAP]);
    let attachment = item.l2.attachment.as_ref().expect("attachment");
    assert_eq!(attachment.medium, MoveMedium::Wired);
    assert_eq!(attachment.device, SWITCH);
    assert_eq!(attachment.device_name, SWITCH_NAME);
    assert_eq!(attachment.port, Some(2));
    assert_eq!(attachment.port_name.as_deref(), Some("Port 2"));
    assert_eq!(attachment.profile.as_deref(), Some("prof-home"));
    assert_eq!(attachment.profile_name.as_deref(), Some("Home ports"));
    assert_eq!(attachment.network_name.as_deref(), Some("Home"));
    assert_eq!(attachment.vlan, Some(20));
    let diff = vec![profile_diff(2, "Home ports", "IoT ports")];
    assert_eq!(item.l2.diff, diff);
    assert_eq!(
        kinds(item),
        ["ipam.intent", "l2.controller", "observe", "cleanup"]
    );
    assert!(item.steps[1].automatic);
    assert_eq!(item.steps[1].step_kind, CONTROLLER);

    // The submit starts the job; the job runs the controller step and waits at observe.
    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    let mark = world.memory.calls().len();
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(step_kinds(&job), [INTENT, CONTROLLER, OBSERVE, CLEANUP]);
    assert!(
        job.spec
            .targets
            .contains(&ObjectRef::from(world.controller))
    );
    let connector = world.controller;
    assert_eq!(
        world.calls_since(mark),
        [
            Call::Attachments { connector },
            Call::PlanAttachment {
                connector,
                change: change.clone()
            },
            Call::ApplyAttachment {
                connector,
                change: change.clone(),
                dry_run: true
            },
            Call::ApplyAttachment {
                connector,
                change: change.clone(),
                dry_run: false
            },
        ],
        "read, plan, dry run, then the write"
    );
    assert_eq!(job.steps[1].state, StepState::Done);
    assert_eq!(
        waiting_task(&job, OBSERVE).instruction.as_str(),
        "ipam.move.task.observe"
    );

    // The controller has the new profile and the client its new VLAN.
    let port = world.port(2);
    assert_eq!(port.profile.as_deref(), Some("prof-iot"));
    assert_eq!(port.native_vlan, Some(30));
    let client = world.client(tv.mac);
    assert_eq!(client.vlan, Some(30));
    assert_eq!(client.network.as_deref(), Some("net-iot"));

    // The step output keeps the diff and a verified receipt that undoes the write.
    let output = l2_output(&job);
    assert_eq!(output.connector, connector);
    assert_eq!(output.change, change);
    assert_eq!(output.diff, diff);
    assert!(!output.unchanged);
    assert!(!output.unknown_write);
    let receipt = output.receipt.expect("a receipt");
    assert_eq!(receipt.connector, connector);
    assert!(!receipt.dry_run);
    assert!(receipt.verified);
    assert_eq!(receipt.undo_steps, 1);

    // The new address is planned until the device is seen.
    let new = world.address_at(&tv.new_ip).await.expect("new intent");
    assert_eq!(new.status, Status::Planned);

    world.complete(job_id, OBSERVE).await;
    assert_eq!(world.drive(job_id).await.state, JobState::Succeeded);
    world.assert_done(&tv).await;
    assert_eq!(
        applies(&world.memory.calls()),
        [true, false],
        "one dry run and one write in all"
    );
}

#[tokio::test]
async fn a_wireless_host_moves_by_per_client_vlan() {
    let world = World::new().await;
    let phone = world.wireless(12).await;
    let request = world.request(&[phone.host]);

    let preview = world.preview(&request).await;
    let item = &preview.items[0];
    let change = AttachmentChange::SetClientVlan {
        mac: phone.mac,
        network: "net-iot".to_owned(),
    };
    assert_eq!(item.l2.action, MoveL2Action::ClientVlan);
    assert_eq!(item.l2.change, Some(change.clone()));
    assert_eq!(item.l2.ssids, [IOT_SSID]);
    assert_eq!(item.l2.notes, [moves::codes::NOTE_RECONNECT]);
    let attachment = item.l2.attachment.as_ref().expect("attachment");
    assert_eq!(attachment.medium, MoveMedium::Wireless);
    assert_eq!(attachment.device_name, AP_NAME);
    assert_eq!(attachment.ssid.as_deref(), Some(HOME_SSID));
    assert_eq!(attachment.port, None);
    let diff = vec![DiffEntry {
        path: format!("clients/{}/network", phone.mac),
        before: Some("Home".to_owned()),
        after: Some("IoT".to_owned()),
    }];
    assert_eq!(item.l2.diff, diff);
    assert_eq!(
        kinds(item),
        ["ipam.intent", "l2.controller", "observe", "cleanup"]
    );

    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    let mark = world.memory.calls().len();
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    let connector = world.controller;
    assert_eq!(
        world.calls_since(mark),
        [
            Call::Attachments { connector },
            Call::PlanAttachment {
                connector,
                change: change.clone()
            },
            Call::ApplyAttachment {
                connector,
                change: change.clone(),
                dry_run: true
            },
            Call::ApplyAttachment {
                connector,
                change: change.clone(),
                dry_run: false
            },
        ]
    );

    // The override holds the IoT network; the client stays on its SSID.
    let state = world.controller_now();
    assert_eq!(
        state.overrides.get(&phone.mac).map(String::as_str),
        Some("net-iot")
    );
    let client = world.client(phone.mac);
    assert_eq!(client.vlan, Some(30));
    assert_eq!(client.network.as_deref(), Some("net-iot"));
    assert_eq!(client.ssid.as_deref(), Some(HOME_SSID));
    let output = l2_output(&job);
    assert_eq!(output.change, change);
    // The job records the controller's own read-back: it has no override on record, so
    // "before" is empty where the preview showed the network the client is in.
    assert_eq!(
        output.diff,
        [DiffEntry {
            path: format!("clients/{}/network", phone.mac),
            before: None,
            after: Some("IoT".to_owned()),
        }]
    );
    let receipt = output.receipt.expect("a receipt");
    assert!(receipt.verified);
    assert_eq!(
        receipt.undo_steps, 1,
        "the override is cleared on a rollback"
    );

    world.complete(job_id, OBSERVE).await;
    assert_eq!(world.drive(job_id).await.state, JobState::Succeeded);
    world.assert_done(&phone).await;
}

#[tokio::test]
async fn the_observation_deadline_clears_the_per_client_override() {
    let world = World::new().await;
    let phone = world.wireless(12).await;
    let submitted = world.submit(&world.request(&[phone.host])).await;
    let job_id = submitted.jobs[0].job_id;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);
    assert_eq!(world.controller_now().overrides.len(), 1);

    world.clock.advance(Duration::from_secs(301));
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    let connector = world.controller;
    assert_eq!(
        world.memory.calls().last(),
        Some(&Call::RevertAttachment {
            connector,
            change: AttachmentChange::SetClientVlan {
                mac: phone.mac,
                network: "net-iot".to_owned(),
            }
        })
    );
    assert_eq!(
        world.controller_now().overrides.len(),
        0,
        "the override is gone again"
    );
    assert_eq!(*step_state(&job, CONTROLLER), StepState::Compensated);
    world.assert_undone(&phone).await;
}

#[tokio::test]
async fn the_observation_deadline_reverts_the_port_and_rolls_the_move_back() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let request = world.request(&[tv.host]);
    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-iot"));

    world.clock.advance(Duration::from_secs(299));
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);
    assert_eq!(reverts(&world.memory.calls()), 0);
    world.clock.advance(Duration::from_secs(2));
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(
        job.error.as_ref().map(|e| e.code.as_ref()),
        Some("jobs.step.deadline_passed")
    );

    // The receipt's undo step put the old profile back, and the client with it.
    let connector = world.controller;
    let calls = world.memory.calls();
    assert_eq!(reverts(&calls), 1);
    assert_eq!(
        calls.last(),
        Some(&Call::RevertAttachment {
            connector,
            change: set_port_profile(2, "prof-iot")
        }),
        "the revert is the last call"
    );
    let port = world.port(2);
    assert_eq!(port.profile.as_deref(), Some("prof-home"));
    assert_eq!(port.native_vlan, Some(20));
    let client = world.client(tv.mac);
    assert_eq!(client.vlan, Some(20));
    assert_eq!(client.network.as_deref(), Some("net-home"));

    assert_eq!(*step_state(&job, CONTROLLER), StepState::Compensated);
    assert_eq!(*step_state(&job, INTENT), StepState::Compensated);
    assert_eq!(
        job.steps[usize::from(step_index(&job, CLEANUP))].attempts,
        0,
        "the cleanup never ran"
    );
    world.assert_undone(&tv).await;
}

#[tokio::test]
async fn a_revert_that_fails_leaves_a_manual_undo_task() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let submitted = world.submit(&world.request(&[tv.host])).await;
    let job_id = submitted.jobs[0].job_id;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);

    world
        .memory
        .fail_next(CallKind::RevertAttachment, unreachable());
    world.clock.advance(Duration::from_secs(301));
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RollingBack, "waits for a person");
    assert_eq!(reverts(&world.memory.calls()), 1, "the revert was tried");
    let task = waiting_task(&job, CONTROLLER);
    assert_eq!(task.instruction.as_str(), UNDO_TASK);
    assert_eq!(task.args.get("kind").map(String::as_str), Some(CONTROLLER));
    assert_eq!(
        world.port(2).profile.as_deref(),
        Some("prof-iot"),
        "the failed revert left the port as the move set it"
    );
    // The earlier steps are undone without waiting for the person.
    assert_eq!(*step_state(&job, INTENT), StepState::Compensated);
    world.assert_undone(&tv).await;

    // The person puts the port back and completes the task: the rollback ends.
    world.edit(|controller| port_mut(controller, 2).profile = Some("prof-home".to_owned()));
    world.complete(job_id, CONTROLLER).await;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(*step_state(&job, CONTROLLER), StepState::Compensated);
    assert_eq!(reverts(&world.memory.calls()), 1, "no second attempt");
}

#[tokio::test]
async fn a_port_without_a_profile_on_record_asks_a_person_to_undo() {
    let world = World::new().await;
    let tv = world.wired(11, 8).await;
    world.edit(|controller| port_mut(controller, 8).profile = None);
    let request = world.request(&[tv.host]);

    let preview = world.preview(&request).await;
    let item = &preview.items[0];
    assert_eq!(item.l2.action, MoveL2Action::PortProfile);
    assert!(
        item.l2
            .notes
            .contains(&moves::codes::NOTE_NO_UNDO.to_owned()),
        "the preview warns that a rollback asks a person: {:?}",
        item.l2.notes
    );
    assert_eq!(
        item.l2.attachment.as_ref().and_then(|a| a.profile.clone()),
        None
    );

    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(world.port(8).profile.as_deref(), Some("prof-iot"));
    let receipt = l2_output(&job).receipt.expect("a receipt");
    assert!(receipt.verified);
    assert_eq!(receipt.undo_steps, 0, "nothing tells what to put back");

    world.clock.advance(Duration::from_secs(301));
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RollingBack);
    assert_eq!(
        reverts(&world.memory.calls()),
        0,
        "no write without something to put back"
    );
    let task = waiting_task(&job, CONTROLLER);
    assert_eq!(task.instruction.as_str(), UNDO_TASK);
    assert_eq!(task.args.get("kind").map(String::as_str), Some(CONTROLLER));
    assert_eq!(world.port(8).profile.as_deref(), Some("prof-iot"));
    world.assert_undone(&tv).await;

    world.complete(job_id, CONTROLLER).await;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(reverts(&world.memory.calls()), 0);
}

#[tokio::test]
async fn another_profile_on_the_port_after_the_submit_stops_the_controller_step() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let submitted = world.submit(&world.request(&[tv.host])).await;
    world.edit(|controller| port_mut(controller, 2).profile = Some("prof-lab".to_owned()));
    world
        .assert_l2_changed(&submitted, &tv, "another port profile")
        .await;
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-lab"));
}

#[tokio::test]
async fn a_device_on_another_port_after_the_submit_stops_the_controller_step() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let submitted = world.submit(&world.request(&[tv.host])).await;
    world.edit(|controller| {
        for client in &mut controller.clients {
            client.port = Some(5);
        }
    });
    world
        .assert_l2_changed(&submitted, &tv, "the device is on another port")
        .await;
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-home"));
    assert_eq!(world.port(5).profile.as_deref(), Some("prof-home"));
}

#[tokio::test]
async fn another_device_on_the_port_after_the_submit_stops_the_controller_step() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let submitted = world.submit(&world.request(&[tv.host])).await;
    let guest = ControllerClient {
        mac: "00:00:5e:00:53:99".parse().expect("mac"),
        ip: Some("203.0.113.99".parse().expect("ip")),
        device: SWITCH.to_owned(),
        port: Some(2),
        ssid: None,
        network: Some("net-home".to_owned()),
        vlan: Some(20),
        name: None,
        management: false,
    };
    world.edit(|controller| controller.clients.push(guest));
    world
        .assert_l2_changed(&submitted, &tv, "1 other devices are on port 2")
        .await;
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-home"));
}

#[tokio::test]
async fn with_writes_off_a_person_gets_the_exact_change_and_nothing_is_written() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    world.edit(|controller| controller.info.writes_enabled = false);
    let request = world.request(&[tv.host]);

    let preview = world.preview(&request).await;
    assert_eq!(preview.unacknowledged, Vec::<String>::new());
    let item = &preview.items[0];
    assert_eq!(item.l2.action, MoveL2Action::Manual);
    assert_eq!(item.l2.reason.as_deref(), Some(moves::codes::L2_READ_ONLY));
    assert_eq!(item.l2.change, Some(set_port_profile(2, "prof-iot")));
    assert_eq!(item.l2.diff, [profile_diff(2, "Home ports", "IoT ports")]);
    assert_eq!(
        item.l2.connector.as_ref().map(|c| c.writes_enabled),
        Some(false)
    );
    assert_eq!(
        kinds(item),
        ["ipam.intent", "l2.move", "observe", "cleanup"]
    );
    assert!(!item.steps[1].automatic);

    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(step_kinds(&job), [INTENT, MANUAL_L2, OBSERVE, CLEANUP]);
    assert!(
        !job.spec
            .targets
            .contains(&ObjectRef::from(world.controller)),
        "a manual step does not write through the controller"
    );
    let task = waiting_task(&job, MANUAL_L2);
    assert_eq!(task.instruction.as_str(), "ipam.move.task.l2_port");
    assert_eq!(
        task.args.get("device").map(String::as_str),
        Some(SWITCH_NAME)
    );
    assert_eq!(task.args.get("port").map(String::as_str), Some("2"));
    assert_eq!(
        task.args.get("profile").map(String::as_str),
        Some("IoT ports")
    );
    assert!(!changed_something(&world.memory.calls()));
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-home"));

    // The person makes the change on the controller and ticks the steps off.
    world.edit(|controller| port_mut(controller, 2).profile = Some("prof-iot".to_owned()));
    world.complete(job_id, MANUAL_L2).await;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);
    world.complete(job_id, OBSERVE).await;
    assert_eq!(world.drive(job_id).await.state, JobState::Succeeded);
    world.assert_done(&tv).await;
    assert!(!changed_something(&world.memory.calls()));
}

#[tokio::test]
async fn a_device_on_an_uplink_port_is_refused_and_a_person_moves_it() {
    let world = World::new().await;
    let ap = world.wired(11, 1).await;
    let request = world.request(&[ap.host]);

    let preview = world.preview(&request).await;
    let item = &preview.items[0];
    assert_eq!(item.l2.action, MoveL2Action::Manual);
    assert_eq!(
        item.l2.reason.as_deref(),
        Some(moves::codes::L2_REFUSED_REASON)
    );
    let problem = item.l2.problem.as_ref().expect("the refusal");
    assert_eq!(problem.code, "connect.guardrail.uplink");
    assert_eq!(item.l2.change, None);
    assert_eq!(preview.unacknowledged, [moves::codes::L2_REFUSED]);
    let warning = preview
        .warnings
        .iter()
        .find(|w| w.code == moves::codes::L2_REFUSED)
        .expect("the warning");
    assert!(warning.requires_ack && !warning.acknowledged);
    assert_eq!(
        warning.params.get("rule").map(String::as_str),
        Some("connect.guardrail.uplink")
    );
    assert_eq!(
        kinds(item),
        ["ipam.intent", "l2.move", "observe", "cleanup"]
    );

    // Without the acknowledgement nothing starts.
    let error = world
        .try_submit(&request)
        .await
        .expect_err("needs an acknowledgement");
    assert_eq!(error.code_str(), codes::PLAN_UNACKNOWLEDGED);
    assert_eq!(error.coded().status, 409);
    assert_eq!(world.move_jobs().await, 0);

    let acknowledged = MoveRequest {
        acknowledge: vec![moves::codes::L2_REFUSED.to_owned()],
        ..request
    };
    let submitted = world.submit(&acknowledged).await;
    assert_eq!(submitted.jobs.len(), 1);
    assert_eq!(world.move_jobs().await, 1);
    let job = world.drive(submitted.jobs[0].job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(step_kinds(&job), [INTENT, MANUAL_L2, OBSERVE, CLEANUP]);
    let task = waiting_task(&job, MANUAL_L2);
    assert_eq!(task.instruction.as_str(), "ipam.move.task.l2_refused");
    assert_eq!(
        task.args.get("rule").map(String::as_str),
        Some("connect.guardrail.uplink")
    );
    assert!(!changed_something(&world.memory.calls()));
    assert_eq!(world.port(1).profile, None);
}

#[tokio::test]
async fn the_same_plan_has_the_same_fingerprint_and_a_submit_with_it_starts_the_jobs() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let request = world.request(&[tv.host]);

    let first = world.preview(&request).await;
    let second = world.preview(&request).await;
    assert_ne!(first.fingerprint, "");
    assert_eq!(first.fingerprint, second.fingerprint);

    let confirmed = MoveRequest {
        expect_fingerprint: Some(first.fingerprint.clone()),
        ..request.clone()
    };
    let submitted = world.submit(&confirmed).await;
    assert_eq!(submitted.jobs.len(), 1);
    assert_eq!(world.move_jobs().await, 1);

    // A different request has another plan.
    let other = world.wired(12, 3).await;
    let both = world.preview(&world.request(&[tv.host, other.host])).await;
    assert_ne!(both.fingerprint, first.fingerprint);
}

#[tokio::test]
async fn a_changed_controller_makes_the_confirmed_fingerprint_stale() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let request = world.request(&[tv.host]);
    let preview = world.preview(&request).await;

    // Another profile on the port between the preview and the submit.
    world.edit(|controller| port_mut(controller, 2).profile = Some("prof-lab".to_owned()));
    let confirmed = MoveRequest {
        expect_fingerprint: Some(preview.fingerprint.clone()),
        ..request.clone()
    };
    let error = world
        .try_submit(&confirmed)
        .await
        .expect_err("the plan changed");
    assert_eq!(error.code_str(), moves::codes::PLAN_CHANGED);
    assert_eq!(error.coded().status, 409);
    assert_eq!(world.move_jobs().await, 0, "nothing started");
    assert_eq!(world.port(2).profile.as_deref(), Some("prof-lab"));
    assert!(!changed_something(&world.memory.calls()));

    // The new preview shows the new diff and its fingerprint is accepted.
    let fresh = world.preview(&request).await;
    assert_ne!(fresh.fingerprint, preview.fingerprint);
    assert_eq!(
        fresh.items[0].l2.diff,
        [profile_diff(2, "Lab ports", "IoT ports")]
    );
    let submitted = world
        .submit(&MoveRequest {
            expect_fingerprint: Some(fresh.fingerprint),
            ..request
        })
        .await;
    assert_eq!(submitted.jobs.len(), 1);
    assert_eq!(world.move_jobs().await, 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Five jobs from submit to their end, one of them failing.
async fn a_bulk_move_is_one_job_group_and_one_failing_device_does_not_stop_the_others() {
    let world = World::new().await;
    let mut devices = Vec::new();
    for (n, port) in [(21u8, 2u16), (22, 3), (23, 4), (24, 5), (25, 6)] {
        devices.push(world.wired(n, port).await);
    }
    let hosts: Vec<HostId> = devices.iter().map(|d| d.host).collect();
    let request = MoveRequest {
        parallelism: Some(2),
        ..world.request(&hosts)
    };
    let preview = world.preview(&request).await;
    assert_eq!(preview.parallelism, 2);
    assert_eq!(preview.items.len(), 5);
    assert!(
        preview
            .items
            .iter()
            .all(|item| item.l2.action == MoveL2Action::PortProfile)
    );
    let submitted = world.submit(&request).await;
    assert_eq!(submitted.parallelism, 2);
    assert_eq!(submitted.jobs.len(), 5);
    for job in &submitted.jobs {
        let job = world.engine.job(job.job_id).await.expect("job");
        assert_eq!(job.spec.kind.as_str(), moves::MOVE_JOB);
        assert_eq!(job.spec.group_limit, Some(2));
        assert_eq!(
            job.spec.group.as_ref().map(ToString::to_string),
            Some(submitted.group.clone()),
            "one group"
        );
    }

    // The third device's port changes before its controller step.
    world.edit(|controller| port_mut(controller, 4).profile = Some("prof-lab".to_owned()));
    for (index, job) in submitted.jobs.iter().enumerate() {
        let state = world.drive(job.job_id).await.state;
        if index == 2 {
            assert_eq!(state, JobState::RolledBack, "device {index}");
        } else {
            assert_eq!(state, JobState::Waiting, "device {index}");
        }
    }
    let calls = world.memory.calls();
    assert_eq!(
        applies(&calls),
        [true, false].repeat(4),
        "four dry runs and four writes, each write after its dry run"
    );
    for (index, job) in submitted.jobs.iter().enumerate() {
        if index == 2 {
            continue;
        }
        world.complete(job.job_id, OBSERVE).await;
        assert_eq!(
            world.drive(job.job_id).await.state,
            JobState::Succeeded,
            "device {index}"
        );
    }
    for (index, device) in devices.iter().enumerate() {
        if index == 2 {
            world.assert_undone(device).await;
        } else {
            world.assert_done(device).await;
        }
    }
    for port in [2u16, 3, 5, 6] {
        assert_eq!(
            world.port(port).profile.as_deref(),
            Some("prof-iot"),
            "port {port}"
        );
    }
    assert_eq!(world.port(4).profile.as_deref(), Some("prof-lab"));
}

#[tokio::test]
async fn the_controllers_client_table_confirms_the_observation_step() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    let other = world.wired(12, 3).await;
    let mut reconciling = Reconciling::over(
        Arc::clone(&world.store),
        Arc::clone(&world.service),
        ReconcilerConfig::default(),
    );
    reconciling.connector = world.controller;

    let submitted = world.submit(&world.request(&[tv.host])).await;
    let job_id = submitted.jobs[0].job_id;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(
        waiting_task(&job, OBSERVE).instruction.as_str(),
        "ipam.move.task.observe"
    );
    let now = Timestamp::now();

    // The controller still lists the client at its old address: not a sighting of the new one.
    let client = world.client(tv.mac);
    let name = format!("client-{}", client.mac);
    let mac_text = client.mac.to_string();
    reconciling
        .poll(
            vec![vm(&name, None, Some(&mac_text), &[tv.old_ip.as_str()])],
            now,
        )
        .await;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);

    // Another client of the controller at the new address does not count either.
    let other_mac = other.mac.to_string();
    reconciling
        .poll(
            vec![vm(
                "client-other",
                None,
                Some(&other_mac),
                &[tv.new_ip.as_str()],
            )],
            now,
        )
        .await;
    assert_eq!(world.drive(job_id).await.state, JobState::Waiting);

    // The device renews its lease in VLAN 30: the controller's client table shows the new
    // address, and the inventory poll reports the client the way the plugin does.
    let new_ip: std::net::IpAddr = tv.new_ip.parse().expect("ip");
    world.edit(|controller| {
        for client in &mut controller.clients {
            if client.mac == tv.mac {
                client.ip = Some(new_ip);
            }
        }
    });
    let client = world.client(tv.mac);
    assert_eq!(client.vlan, Some(30), "the port profile moved it");
    let seen_ip = client.ip.expect("ip").to_string();
    reconciling
        .poll(
            vec![vm(&name, None, Some(&mac_text), &[seen_ip.as_str()])],
            now,
        )
        .await;
    assert_eq!(world.drive(job_id).await.state, JobState::Succeeded);
    world.assert_done(&tv).await;
}

#[tokio::test]
async fn an_unreadable_controller_leaves_every_device_to_a_person_with_a_warning() {
    let world = World::new().await;
    let one = world.wired(11, 2).await;
    let two = world.wireless(12).await;
    let request = world.request(&[one.host, two.host]);

    world.memory.fail_next(CallKind::Attachments, unreachable());
    let preview = world.preview(&request).await;
    assert_eq!(preview.items.len(), 2);
    for item in &preview.items {
        assert_eq!(item.l2.action, MoveL2Action::Manual);
        assert_eq!(
            item.l2.reason.as_deref(),
            Some(moves::codes::L2_UNAVAILABLE)
        );
        assert_eq!(
            item.l2.problem.as_ref().map(|p| p.code.as_str()),
            Some("connect.unreachable")
        );
        assert_eq!(
            kinds(item),
            ["ipam.intent", "l2.move", "observe", "cleanup"]
        );
    }
    let warning = preview
        .warnings
        .iter()
        .find(|w| w.code == moves::codes::CONTROLLER_UNAVAILABLE)
        .expect("the warning");
    assert!(warning.requires_ack && !warning.acknowledged);
    assert_eq!(
        warning.params.get("error").map(String::as_str),
        Some("connect.unreachable")
    );
    assert_eq!(
        preview.unacknowledged,
        [moves::codes::CONTROLLER_UNAVAILABLE]
    );

    // The submit reads the controller again and needs the acknowledgement as well.
    world.memory.fail_next(CallKind::Attachments, unreachable());
    let error = world
        .try_submit(&request)
        .await
        .expect_err("needs an acknowledgement");
    assert_eq!(error.code_str(), codes::PLAN_UNACKNOWLEDGED);
    assert_eq!(error.coded().status, 409);
    assert_eq!(world.move_jobs().await, 0);

    world.memory.fail_next(CallKind::Attachments, unreachable());
    let acknowledged = MoveRequest {
        acknowledge: vec![moves::codes::CONTROLLER_UNAVAILABLE.to_owned()],
        ..request
    };
    let submitted = world.submit(&acknowledged).await;
    assert_eq!(submitted.jobs.len(), 2);
    for job in &submitted.jobs {
        let job = world.drive(job.job_id).await;
        assert_eq!(job.state, JobState::Waiting);
        assert_eq!(step_kinds(&job), [INTENT, MANUAL_L2, OBSERVE, CLEANUP]);
    }
    assert!(!changed_something(&world.memory.calls()));
}

#[tokio::test]
async fn a_device_in_the_target_vlan_already_has_no_l2_step() {
    let world = World::new().await;
    let tv = world.wired(11, 2).await;
    world.edit(|controller| {
        port_mut(controller, 2).profile = Some("prof-iot".to_owned());
        port_mut(controller, 2).native_vlan = Some(30);
        for client in &mut controller.clients {
            client.network = Some("net-iot".to_owned());
            client.vlan = Some(30);
        }
    });
    let request = world.request(&[tv.host]);

    let preview = world.preview(&request).await;
    let item = &preview.items[0];
    assert_eq!(item.l2.action, MoveL2Action::Unchanged);
    assert_eq!(
        item.l2.reason.as_deref(),
        Some(moves::codes::L2_ALREADY_THERE)
    );
    assert_eq!(item.l2.change, None);
    assert_eq!(kinds(item), ["ipam.intent", "observe", "cleanup"]);
    assert_eq!(preview.unacknowledged, Vec::<String>::new());

    let submitted = world.submit(&request).await;
    let job_id = submitted.jobs[0].job_id;
    let job = world.drive(job_id).await;
    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(step_kinds(&job), [INTENT, OBSERVE, CLEANUP]);
    assert!(!changed_something(&world.memory.calls()));
    world.complete(job_id, OBSERVE).await;
    assert_eq!(world.drive(job_id).await.state, JobState::Succeeded);
    world.assert_done(&tv).await;
    assert!(!changed_something(&world.memory.calls()));
}
