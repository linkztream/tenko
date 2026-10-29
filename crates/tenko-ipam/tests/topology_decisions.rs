//! The root of the topology map (UI-Q10) and the two WLAN rules (U7) through the service:
//! the ranked sources of the root, one finding while they disagree, "Use this" remembered
//! across a restart of the service; the rules on a controller's SSIDs, "Keep on this WLAN"
//! for one host only, the per-SSID policy with the guest default, and the audit records.

mod common;

use std::{
    collections::BTreeSet,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
};

use common::{host, ip, person, prefix, run, service};
use tenko_core::{
    VlanId,
    audit::AuditRecord,
    ipam::{AssignmentMode, Tag},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    command::VlanInput,
    findings::{Finding, FindingAction, FindingArea, FindingKind, FindingLevel, FindingSource},
    topology::{
        DefaultRoute, RootSource, TopologyConfig, TopologyFilter, TopologyService, WlanPolicy,
        stored::{actions, codes},
    },
    vlan::{
        Controllers,
        controllers::{ControllerClient, ControllerDevice, ControllerDeviceKind, ControllerWlan},
        memory::{MemoryController, MemoryControllers},
    },
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, tables::AUDIT};

/// A routing table whose next hops a test sets.
#[derive(Debug, Default)]
struct Route(Mutex<Vec<IpAddr>>);

impl Route {
    fn set(&self, hops: &[&str]) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) =
            hops.iter().map(|hop| ip(hop)).collect();
    }
}

impl DefaultRoute for Route {
    fn next_hops(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<IpAddr>> + Send + '_>> {
        let hops = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Box::pin(async move { hops })
    }
}

fn mac(last: u8) -> String {
    format!("00:00:5e:00:53:{last:02x}")
}

fn device(id: &str, name: &str, kind: ControllerDeviceKind, last: u8) -> ControllerDevice {
    ControllerDevice {
        id: id.to_owned(),
        name: name.to_owned(),
        model: None,
        mac: Some(mac(last).parse().expect("mac")),
        ip: Some(ip(&format!("192.0.2.{last}"))),
        kind,
        ports: Vec::new(),
    }
}

fn wlan(ssid: &str, vlan: u16, guest: bool) -> ControllerWlan {
    ControllerWlan {
        ssid: ssid.to_owned(),
        vlan: Some(vlan),
        enabled: true,
        access_points: vec!["ap-1".to_owned()],
        guest,
    }
}

fn client(last: u8, address: &str, ssid: &str, vlan: u16) -> ControllerClient {
    ControllerClient {
        mac: mac(last).parse().expect("mac"),
        ip: Some(ip(address)),
        device: "ap-1".to_owned(),
        port: None,
        ssid: Some(ssid.to_owned()),
        network: None,
        vlan: Some(vlan),
        name: None,
        management: false,
    }
}

const LAB: &str = "lab.example.test";
const IOT: &str = "iot.example.test";
const GUEST: &str = "guest.example.test";

fn tags(list: &[&str]) -> BTreeSet<Tag> {
    list.iter().map(|tag| Tag::new(tag).expect("tag")).collect()
}

struct World {
    service: Arc<IpamService>,
    store: MemStore,
    controllers: Arc<Controllers>,
    route: Arc<Route>,
    topology: Arc<TopologyService>,
    hosts: std::collections::BTreeMap<&'static str, tenko_core::HostId>,
}

impl World {
    /// A controller with a gateway (`192.0.2.1`), an access point and the SSIDs lab (VLAN
    /// 20), iot (VLAN 30, the IoT role) and guest (VLAN 40, a guest network); hosts on them.
    async fn new() -> Self {
        let (service, store) = service();
        let mut controller = MemoryController::new("unifi.example.test");
        controller.devices = vec![
            device("gw-1", "gateway-a", ControllerDeviceKind::Gateway, 1),
            device("ap-1", "ap-a", ControllerDeviceKind::AccessPoint, 3),
        ];
        controller.wlans = vec![
            wlan(LAB, 20, false),
            wlan(IOT, 30, false),
            wlan(GUEST, 40, true),
        ];
        controller.clients = vec![
            // An IoT device on the lab WLAN: wlan_class.
            client(0x22, "192.0.2.22", LAB, 20),
            // An address of the IoT network on the lab WLAN: wlan_prefix.
            client(0x23, "198.51.100.23", LAB, 20),
            // An IoT device at home: nothing.
            client(0x31, "198.51.100.31", IOT, 30),
            // An IoT device on the guest WLAN, ignored by default.
            client(0x41, "203.0.113.41", GUEST, 40),
            // An unmanaged IoT device on the lab WLAN: nothing.
            client(0x24, "192.0.2.24", LAB, 20),
            // A client that is no host of intent: nothing.
            client(0x25, "192.0.2.25", LAB, 20),
        ];
        let controllers = Controllers::with(MemoryControllers::new(vec![controller]));

        let lab_vlan = VlanId::generate();
        let iot_vlan = VlanId::generate();
        let vlan = |id, vid, name: &str, tags: BTreeSet<Tag>| {
            IpamCommand::CreateVlan(VlanInput {
                id: Some(id),
                vid,
                vni: None,
                name: name.to_owned(),
                site: None,
                status: None,
                tags,
                custom: std::collections::BTreeMap::new(),
                description: None,
            })
        };
        let mut lab_net = prefix(None, "192.0.2.0/24");
        lab_net.vlan = Some(lab_vlan);
        let mut iot_net = prefix(None, "198.51.100.0/24");
        iot_net.vlan = Some(iot_vlan);
        let mut commands = vec![
            vlan(lab_vlan, 20, "Lab", BTreeSet::new()),
            vlan(iot_vlan, 30, "IoT", tags(&["role:iot"])),
            IpamCommand::CreatePrefix(lab_net),
            IpamCommand::CreatePrefix(iot_net),
        ];
        let mut hosts = std::collections::BTreeMap::new();
        for (name, last, mode, class) in [
            ("sensor-a", 0x22, AssignmentMode::Dynamic, true),
            ("laptop-b", 0x23, AssignmentMode::Dynamic, false),
            ("sensor-b", 0x31, AssignmentMode::Dynamic, true),
            ("sensor-c", 0x41, AssignmentMode::Dynamic, true),
            ("plug-d", 0x24, AssignmentMode::Unmanaged, true),
        ] {
            let (mut input, _) = host(name, mode, Some(&mac(last)));
            if class {
                input.tags = tags(&["class:iot"]);
            }
            hosts.insert(name, input.id.expect("id"));
            commands.push(IpamCommand::CreateHost(input));
        }
        run(&service, commands).await;
        let route = Arc::new(Route::default());
        let topology = Self::topology_of(&service, &controllers, &route);
        Self {
            service,
            store,
            controllers,
            route,
            topology,
            hosts,
        }
    }

    fn topology_of(
        service: &Arc<IpamService>,
        controllers: &Arc<Controllers>,
        route: &Arc<Route>,
    ) -> Arc<TopologyService> {
        let topology = TopologyService::new(
            Arc::clone(service),
            Arc::clone(controllers),
            TopologyConfig::default(),
        );
        topology.set_default_route(Arc::clone(route) as Arc<dyn DefaultRoute>);
        topology
    }

    /// A new service over the same store, as after a restart of the server.
    fn restart(&mut self) {
        self.topology = Self::topology_of(&self.service, &self.controllers, &self.route);
    }

    async fn findings(&self) -> Vec<Finding> {
        self.topology.findings(None).await.expect("findings")
    }

    /// The (kind, host name) of the WLAN findings.
    async fn wlan_findings(&self) -> Vec<(FindingKind, String)> {
        let mut out: Vec<(FindingKind, String)> = self
            .findings()
            .await
            .into_iter()
            .filter(|finding| finding.kind != FindingKind::TopologyRoot)
            .map(|finding| (finding.kind, finding.subject.label))
            .collect();
        out.sort();
        out
    }

    async fn audit(&self, action: &str) -> Vec<AuditRecord> {
        let view = self
            .store
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view");
        view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record)
            .filter(|record: &AuditRecord| record.draft.action.as_str() == action)
            .collect()
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one world through every decision in order"
)]
async fn the_wlan_rules_raise_findings_to_review_that_an_exception_and_the_policy_remove() {
    let mut world = World::new().await;
    assert_eq!(
        world.wlan_findings().await,
        [
            (FindingKind::WlanClass, "sensor-a".to_owned()),
            (FindingKind::WlanPrefix, "laptop-b".to_owned()),
        ],
        "the IoT device on the lab WLAN and the address of another network, nothing else"
    );
    let finding = world
        .findings()
        .await
        .into_iter()
        .find(|finding| finding.kind == FindingKind::WlanClass)
        .expect("finding");
    assert_eq!(finding.severity, FindingLevel::Review);
    assert_eq!(finding.area, FindingArea::Topology);
    assert_eq!(finding.source, FindingSource::Topology);
    assert_eq!(finding.action, FindingAction::MoveHost);
    assert_eq!(finding.subject.host, Some(world.hosts["sensor-a"]));
    assert_eq!(finding.params["ssid"], LAB);
    assert_eq!(finding.params["vlan"], "20");
    assert_eq!(finding.params["prefix"], "192.0.2.0/24");
    assert_eq!(finding.params["class"], "iot");
    assert_eq!(finding.params["role"], "other");

    // "Keep on this WLAN" removes the finding of that host only.
    let cx = person();
    let kept = world
        .topology
        .keep(
            &cx,
            world.hosts["sensor-a"],
            LAB,
            Some("a test bench".to_owned()),
            None,
        )
        .await
        .expect("keep");
    assert_eq!(kept.ssid, LAB);
    assert_eq!(
        world.wlan_findings().await,
        [(FindingKind::WlanPrefix, "laptop-b".to_owned())]
    );
    let records = world.audit(actions::EXCEPTION_KEEP).await;
    assert_eq!(records.len(), 1, "one audit record");
    assert!(
        records[0]
            .draft
            .details
            .changes
            .iter()
            .any(|change| change.field == "reason"
                && change.new.as_deref() == Some("a test bench"))
    );
    // A stale If-Match is refused.
    let stale = world
        .topology
        .keep(
            &cx,
            world.hosts["sensor-a"],
            LAB,
            None,
            Some(tenko_core::Revision(1)),
        )
        .await
        .expect_err("stale");
    assert_eq!(stale.code_str(), "ipam.revision_mismatch");

    // The exception survives a restart of the service.
    world.restart();
    assert_eq!(
        world.wlan_findings().await,
        [(FindingKind::WlanPrefix, "laptop-b".to_owned())]
    );

    // The guest SSID is ignored by default; tracked, its IoT device is judged.
    let view = world.topology.ssids(None, None).await.expect("ssids");
    let guest = view
        .ssids
        .iter()
        .find(|entry| entry.ssid == GUEST)
        .expect("guest");
    assert!(guest.guest);
    assert_eq!(guest.policy, WlanPolicy::Ignore);
    assert!(!guest.policy_set);
    let lab = view
        .ssids
        .iter()
        .find(|entry| entry.ssid == LAB)
        .expect("lab");
    assert_eq!(lab.policy, WlanPolicy::Track);
    assert_eq!(lab.clients, 4);
    assert_eq!(lab.findings, 1, "the kept host no longer counts");
    world
        .topology
        .set_policy(&cx, GUEST, WlanPolicy::Track, None)
        .await
        .expect("track");
    assert_eq!(
        world.wlan_findings().await,
        [
            (FindingKind::WlanClass, "sensor-c".to_owned()),
            (FindingKind::WlanPrefix, "laptop-b".to_owned()),
        ]
    );
    // Ignoring the lab WLAN silences its rules.
    world
        .topology
        .set_policy(&cx, LAB, WlanPolicy::Ignore, None)
        .await
        .expect("ignore");
    assert_eq!(
        world.wlan_findings().await,
        [(FindingKind::WlanClass, "sensor-c".to_owned())]
    );
    assert_eq!(world.audit(actions::POLICY_SET).await.len(), 2);
    world
        .topology
        .clear_policy(&cx, LAB, None)
        .await
        .expect("clear");
    world
        .topology
        .forget(&cx, world.hosts["sensor-a"], LAB, None)
        .await
        .expect("forget");
    assert_eq!(
        world.wlan_findings().await.len(),
        3,
        "both rules read the lab again"
    );
    assert_eq!(world.audit(actions::POLICY_CLEAR).await.len(), 1);
    assert_eq!(world.audit(actions::EXCEPTION_CLEAR).await.len(), 1);
    let none = world
        .topology
        .forget(&cx, world.hosts["sensor-a"], LAB, None)
        .await
        .expect_err("gone");
    assert_eq!(none.code_str(), codes::NOT_STORED);
    let long = world
        .topology
        .set_policy(&cx, &"x".repeat(33), WlanPolicy::Track, None)
        .await
        .expect_err("too long");
    assert_eq!(long.code_str(), codes::INVALID);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one world through every source and choice in order"
)]
async fn the_root_follows_the_ranked_sources_and_a_choice_is_remembered_across_a_restart() {
    let mut world = World::new().await;
    let roots = |world: &World| {
        let topology = Arc::clone(&world.topology);
        async move { topology.root(None, None).await.expect("root") }
    };
    // Only the controller manages a gateway: it is the root.
    let decision = roots(&world).await;
    assert_eq!(decision.candidates.len(), 1);
    let root = decision.root.clone().expect("root");
    assert_eq!(root.source, RootSource::Controller);
    assert!(!root.chosen);
    let gateway = root.node.clone().expect("node");
    assert!(!decision.disagree);
    let graph = world
        .topology
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(
        graph.summary.root.and_then(|r| r.node),
        Some(gateway.clone())
    );

    // The default route through the gateway's address agrees.
    world.route.set(&["192.0.2.1"]);
    let decision = roots(&world).await;
    assert_eq!(decision.candidates.len(), 2);
    assert!(!decision.disagree && !decision.open);
    assert!(
        world
            .findings()
            .await
            .iter()
            .all(|finding| finding.kind != FindingKind::TopologyRoot)
    );

    // Another next hop disagrees: one finding to review with Use this.
    world.route.set(&["192.0.2.254", "2001:db8::1"]);
    let decision = roots(&world).await;
    assert!(decision.disagree && decision.open);
    let root_findings: Vec<Finding> = world
        .findings()
        .await
        .into_iter()
        .filter(|finding| finding.kind == FindingKind::TopologyRoot)
        .collect();
    assert_eq!(root_findings.len(), 1);
    let finding = &root_findings[0];
    assert_eq!(finding.action, FindingAction::UseRoot);
    assert_eq!(finding.severity, FindingLevel::Review);
    assert_eq!(finding.params["controller_label"], "gateway-a");
    assert_eq!(finding.params["default_route_ip"], "192.0.2.254");
    assert_eq!(
        decision.root.as_ref().map(|r| r.source),
        Some(RootSource::Controller),
        "without a choice the ranked source draws the map"
    );

    // Use this: the default route.
    let cx = person();
    let chosen = world
        .topology
        .choose_root(&cx, RootSource::DefaultRoute, None)
        .await
        .expect("choose");
    assert!(!chosen.open);
    let root = chosen.root.expect("root");
    assert_eq!(root.source, RootSource::DefaultRoute);
    assert!(root.chosen);
    assert_eq!(world.audit(actions::ROOT_CHOOSE).await.len(), 1);

    // Remembered across a restart: the same disagreement raises nothing.
    world.restart();
    let decision = roots(&world).await;
    assert!(decision.disagree && !decision.open);
    assert_eq!(
        decision.root.map(|r| (r.source, r.chosen)),
        Some((RootSource::DefaultRoute, true))
    );
    assert!(
        world
            .findings()
            .await
            .iter()
            .all(|finding| finding.kind != FindingKind::TopologyRoot)
    );

    // Other candidates raise it again; the map still follows the chosen source.
    world.route.set(&["192.0.2.253"]);
    let decision = roots(&world).await;
    assert!(decision.open);
    assert_eq!(
        decision.root.map(|r| r.source),
        Some(RootSource::DefaultRoute)
    );

    // Without a route, choosing it is refused; forgetting the choice ranks again.
    world.route.set(&[]);
    let refused = world
        .topology
        .choose_root(&cx, RootSource::DefaultRoute, None)
        .await
        .expect_err("no candidate");
    assert_eq!(refused.code_str(), codes::NO_CANDIDATE);
    world.topology.clear_root(&cx, None).await.expect("clear");
    assert_eq!(world.audit(actions::ROOT_CLEAR).await.len(), 1);
    let decision = roots(&world).await;
    assert_eq!(
        decision.root.map(|r| (r.source, r.chosen)),
        Some((RootSource::Controller, false))
    );
}
