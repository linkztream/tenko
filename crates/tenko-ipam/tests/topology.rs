//! The topology graph (IPAM-20, E6): a home lab seen by a network controller, an SNMP
//! probe and a hypervisor inventory, joined with intent; the filters with their context,
//! the view of one node with "what hangs on this port", stable identifiers, the cached
//! service and the scale of a few thousand nodes.

mod common;

use std::{net::IpAddr, sync::Arc, time::Instant};

use common::{address, host, prefix, run, service};
use tenko_core::{
    ConnectorId, MacAddr, NodeId, ObservationId, PrefixId, Revision, Timestamp, VlanId,
    ipam::{Host, Prefix},
    observe::{
        Endpoint, LinkKind, Observation, ObservationSource, Observed, ObservedHost, ProbeMethod,
    },
};
use tenko_ipam::{
    IpamCommand,
    observe::{FactSubject, IngestBatch, ObserveConfig, ObservedFact, ingest, source_key},
    topology::{
        EdgeKind, NodeKind, TopologyConfig, TopologyFilter, TopologyGraph, TopologyService,
        build::{Inputs, Intent, build},
        filter,
    },
    vlan::{
        Controllers,
        controllers::{
            ControllerDevice, ControllerDeviceKind, ControllerNetwork, ControllerPort,
            ControllerTopology, ControllerWlan,
        },
        memory::{CallKind, MemoryController, MemoryControllers},
    },
};

fn mac(last: u8) -> MacAddr {
    format!("00:00:5e:00:53:{last:02x}").parse().expect("mac")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn now() -> Timestamp {
    "2026-10-10T12:00:00Z".parse().expect("time")
}

fn fact(source: &ObservationSource, observed: Observed) -> ObservedFact {
    let subject = FactSubject::of(&observed);
    ObservedFact {
        source: source.clone(),
        source_key: source_key(source),
        subject_key: subject.key(),
        subject,
        observed,
        observation: ObservationId::generate(),
        first_seen: now(),
        last_seen: now(),
        received_at: now(),
        expires_at: None,
        sightings: 1,
        counted_at: None,
        revision: Revision::ZERO,
    }
}

fn end(device: &str, port: Option<&str>) -> Endpoint {
    Endpoint {
        device: device.to_owned(),
        port: port.map(str::to_owned),
    }
}

fn port(index: u16, native: u16, uplink: bool) -> ControllerPort {
    ControllerPort {
        index,
        name: Some(format!("Port {index}")),
        native_vlan: Some(native),
        uplink,
        up: true,
    }
}

fn device(id: &str, name: &str, kind: ControllerDeviceKind, last: u8) -> ControllerDevice {
    ControllerDevice {
        id: id.to_owned(),
        name: name.to_owned(),
        model: Some(format!("{name} model")),
        mac: Some(mac(last)),
        ip: Some(ip(&format!("192.0.2.{last}"))),
        kind,
        ports: Vec::new(),
    }
}

/// The device table of the lab's controller.
fn controller_table(connector: ConnectorId) -> ControllerTopology {
    let mut switch = device("sw-1", "USW-24", ControllerDeviceKind::Switch, 2);
    switch.ports = vec![port(1, 10, true), port(5, 20, false), port(6, 20, false)];
    ControllerTopology {
        connector,
        observed_at: now(),
        devices: vec![
            device("gw-1", "Gateway", ControllerDeviceKind::Gateway, 1),
            switch,
            device("ap-1", "U6-Lite", ControllerDeviceKind::AccessPoint, 3),
        ],
        networks: vec![
            ControllerNetwork {
                id: "net-mgmt".to_owned(),
                name: "Management".to_owned(),
                vlan: Some(10),
                subnet: None,
                management: true,
                dhcp: None,
            },
            ControllerNetwork {
                id: "net-iot".to_owned(),
                name: "IoT".to_owned(),
                vlan: Some(30),
                subnet: None,
                management: false,
                dhcp: None,
            },
        ],
        wlans: vec![ControllerWlan {
            ssid: "iot.example.test".to_owned(),
            vlan: Some(30),
            enabled: true,
            access_points: vec!["ap-1".to_owned()],
        }],
    }
}

struct Lab {
    controller: ConnectorId,
    inputs: Inputs,
    printer: tenko_core::HostId,
    lan: PrefixId,
}

/// The facts of the lab: the controller's links and clients, an SNMP-polled core switch
/// with an LLDP link to the controller's switch, and a hypervisor with a VM and a
/// container; intent knows the printer in 192.0.2.0/24 on VLAN 20.
fn lab() -> Lab {
    let controller = ConnectorId::generate();
    let inventory = ConnectorId::generate();
    let ctl = ObservationSource::NetworkController {
        connector: controller,
    };
    let mut facts = vec![
        fact(
            &ctl,
            Observed::Link {
                a: end("sw-1", Some("1")),
                b: end("gw-1", Some("4")),
                kind: LinkKind::Uplink,
            },
        ),
        fact(
            &ctl,
            Observed::Link {
                a: end("ap-1", None),
                b: end("sw-1", Some("6")),
                kind: LinkKind::Uplink,
            },
        ),
        fact(
            &ctl,
            Observed::Attachment {
                mac: mac(0x10),
                device: "sw-1".to_owned(),
                port: Some("5".to_owned()),
                ssid: None,
                vlan: Some(20),
            },
        ),
        fact(
            &ctl,
            Observed::Attachment {
                mac: mac(0x11),
                device: "ap-1".to_owned(),
                port: None,
                ssid: Some("iot.example.test".to_owned()),
                vlan: Some(30),
            },
        ),
    ];
    facts.extend(probe_and_inventory_facts(inventory));
    let (intent, printer, lan) = lab_intent();
    Lab {
        controller,
        inputs: Inputs {
            facts,
            intent,
            controllers: vec![controller_table(controller)],
            statuses: Vec::new(),
            revision: Revision(7),
            now: now(),
        },
        printer,
        lan,
    }
}

/// The facts of the SNMP probe (a core switch with an LLDP link and a client), the ARP
/// table and the hypervisor inventory.
fn probe_and_inventory_facts(inventory: ConnectorId) -> Vec<ObservedFact> {
    let snmp = ObservationSource::Probe {
        node: NodeId(1),
        method: ProbeMethod::Snmp,
    };
    let arp = ObservationSource::Probe {
        node: NodeId(1),
        method: ProbeMethod::Arp,
    };
    let inv = ObservationSource::Inventory {
        connector: inventory,
    };
    vec![
        fact(
            &snmp,
            Observed::Name {
                ip: ip("192.0.2.4"),
                name: "core-sw".to_owned(),
            },
        ),
        fact(
            &snmp,
            Observed::Link {
                a: end("core-sw", Some("ge-0/0/1")),
                b: end("USW-24", Some("Port 1")),
                kind: LinkKind::Lldp,
            },
        ),
        fact(
            &snmp,
            Observed::Attachment {
                mac: mac(0x12),
                device: "core-sw".to_owned(),
                port: Some("ge-0/0/7".to_owned()),
                ssid: None,
                vlan: Some(20),
            },
        ),
        fact(
            &arp,
            Observed::Address {
                vrf: tenko_core::VrfId::generate(),
                ip: ip("192.0.2.12"),
                mac: Some(mac(0x12)),
            },
        ),
        fact(
            &arp,
            Observed::Vendor {
                mac: mac(0x12),
                vendor: "ICANN, IANA Department".to_owned(),
            },
        ),
        fact(
            &inv,
            Observed::Host(ObservedHost {
                external_id: "node/pve1".to_owned(),
                name: Some("pve1".to_owned()),
                macs: vec![mac(0x12)],
                ips: vec![ip("192.0.2.12")],
                platform: Some("node".to_owned()),
                ..ObservedHost::default()
            }),
        ),
        fact(
            &inv,
            Observed::Host(ObservedHost {
                external_id: "qemu/101".to_owned(),
                name: Some("web01".to_owned()),
                macs: vec![mac(0x13)],
                ips: vec![ip("192.0.2.13")],
                platform: Some("qemu".to_owned()),
                parent: Some("node/pve1".to_owned()),
                ..ObservedHost::default()
            }),
        ),
        fact(
            &inv,
            Observed::Host(ObservedHost {
                external_id: "lxc/200".to_owned(),
                name: Some("dns01".to_owned()),
                macs: vec![mac(0x14)],
                platform: Some("lxc".to_owned()),
                parent: Some("node/pve1".to_owned()),
                ..ObservedHost::default()
            }),
        ),
    ]
}

/// Intent of the lab as model objects: VLAN 20 on 192.0.2.0/24, the printer with its MAC
/// and address.
fn lab_intent() -> (Intent, tenko_core::HostId, PrefixId) {
    use tenko_core::{
        AddressId, HostId, InterfaceId, Principal, SystemComponent, TenantId, VrfId,
        ipam::{
            Address, AllocPolicy, AssignmentMode, Interface, Meta, PrefixRole, Stamp, Status, Vlan,
        },
    };
    let stamp = Stamp::new(now(), Principal::system(SystemComponent::Api));
    let vrf = VrfId::generate();
    let vlan = Vlan {
        id: VlanId::generate(),
        vid: 20,
        vni: None,
        name: "LAN".to_owned(),
        site: None,
        status: Status::Active,
        meta: Meta::new(stamp.clone()),
    };
    let lan = Prefix {
        id: PrefixId::generate(),
        vrf,
        cidr: "192.0.2.0/24".parse().expect("cidr"),
        role: PrefixRole::Network,
        status: Status::Active,
        vlan: Some(vlan.id),
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        dns_reverse: None,
        meta: Meta::new(stamp.clone()),
    };
    let printer = Host {
        id: HostId::generate(),
        tenant: TenantId::generate(),
        name: "printer".parse().expect("name"),
        mode: AssignmentMode::Reserved,
        lock: false,
        site: None,
        decommissioned: None,
        meta: Meta::new(stamp.clone()),
    };
    let interface = Interface {
        id: InterfaceId::generate(),
        host: printer.id,
        name: "eth0".to_owned(),
        mac: Some(mac(0x10)),
        duid: None,
        client_id: None,
        meta: Meta::new(stamp.clone()),
    };
    let address = Address {
        id: AddressId::generate(),
        vrf,
        ip: ip("192.0.2.10"),
        prefix: lan.id,
        status: Status::Active,
        interface: Some(interface.id),
        dns_name: None,
        meta: Meta::new(stamp),
    };
    let ids = (printer.id, lan.id);
    (
        Intent {
            hosts: vec![printer],
            interfaces: vec![interface],
            addresses: vec![address],
            prefixes: vec![lan],
            vlans: vec![vlan],
        },
        ids.0,
        ids.1,
    )
}

fn by_label<'a>(graph: &'a TopologyGraph, label: &str) -> &'a tenko_ipam::topology::TopologyNode {
    graph
        .nodes
        .iter()
        .find(|n| n.label == label)
        .unwrap_or_else(|| {
            panic!(
                "no node {label}: {:?}",
                graph.nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
            )
        })
}

fn labels(graph: &TopologyGraph) -> Vec<&str> {
    let mut out: Vec<&str> = graph.nodes.iter().map(|n| n.label.as_str()).collect();
    out.sort_unstable();
    out
}

fn edge_between(
    graph: &TopologyGraph,
    a: &str,
    b: &str,
) -> Option<tenko_ipam::topology::TopologyEdge> {
    let (a, b) = (by_label(graph, a).id.clone(), by_label(graph, b).id.clone());
    graph
        .edges
        .iter()
        .find(|e| (e.a == a && e.b == b) || (e.a == b && e.b == a))
        .cloned()
}

#[test]
fn the_lab_becomes_one_graph_across_sources_with_intent_joined() {
    let lab = lab();
    let computed = build(&lab.inputs);
    let graph = &computed.graph;
    assert_eq!(
        labels(graph),
        [
            "Gateway",
            "U6-Lite",
            "USW-24",
            "core-sw",
            "dns01",
            "printer",
            "pve1",
            "web01",
            "00:00:5e:00:53:11"
        ]
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    assert_eq!(by_label(graph, "Gateway").kind, NodeKind::Router);
    assert_eq!(by_label(graph, "USW-24").kind, NodeKind::Switch);
    assert_eq!(by_label(graph, "U6-Lite").kind, NodeKind::AccessPoint);
    assert_eq!(by_label(graph, "U6-Lite").ssids, ["iot.example.test"]);
    assert_eq!(by_label(graph, "core-sw").kind, NodeKind::Switch);
    assert_eq!(by_label(graph, "core-sw").ips, [ip("192.0.2.4")]);
    assert_eq!(by_label(graph, "pve1").kind, NodeKind::Hypervisor);
    assert_eq!(
        by_label(graph, "pve1").vendor.as_deref(),
        Some("ICANN, IANA Department")
    );
    assert_eq!(by_label(graph, "web01").kind, NodeKind::Vm);
    assert_eq!(by_label(graph, "dns01").kind, NodeKind::Container);
    let printer = by_label(graph, "printer");
    assert_eq!(printer.kind, NodeKind::Host);
    assert_eq!(printer.host, Some(lab.printer));
    assert_eq!(printer.id, format!("h-{}", lab.printer.uuid().simple()));
    assert_eq!(printer.vlans, [20]);
    assert_eq!(printer.prefixes, [lab.lan]);
    assert_eq!(printer.ips, [ip("192.0.2.10")]);
    assert!(printer.sources.contains(&"intent".to_owned()));
    let sensor = by_label(graph, "00:00:5e:00:53:11");
    assert_eq!(sensor.id, "m-00005e005311");
    assert_eq!(sensor.vlans, [30]);

    let uplink = edge_between(graph, "USW-24", "Gateway").expect("uplink");
    assert_eq!(uplink.kind, EdgeKind::Uplink);
    let lldp = edge_between(graph, "core-sw", "USW-24").expect("LLDP link");
    assert_eq!(lldp.kind, EdgeKind::Lldp);
    let wired = edge_between(graph, "USW-24", "printer").expect("wired");
    assert_eq!(wired.kind, EdgeKind::Wired);
    assert_eq!(
        wired.a,
        by_label(graph, "USW-24").id,
        "the switch is the a side"
    );
    assert_eq!(wired.a_port.as_deref(), Some("5"));
    assert_eq!(wired.vlan, Some(20));
    let wireless = edge_between(graph, "U6-Lite", "00:00:5e:00:53:11").expect("wireless");
    assert_eq!(wireless.kind, EdgeKind::Wireless);
    assert_eq!(wireless.ssid.as_deref(), Some("iot.example.test"));
    let vm = edge_between(graph, "pve1", "web01").expect("vm");
    assert_eq!(vm.kind, EdgeKind::VmHost);
    assert_eq!(
        edge_between(graph, "core-sw", "pve1").expect("wired").kind,
        EdgeKind::Wired
    );
    assert_eq!(graph.summary.nodes, 9);
    assert_eq!(graph.summary.total_edges, graph.edges.len());
    assert_eq!(graph.summary.by_kind["switch"], 2);
    assert_eq!(graph.summary.by_edge_kind["vm_host"], 2);
    let lan = graph
        .summary
        .vlans
        .iter()
        .find(|v| v.vid == 20)
        .expect("vlan 20");
    assert_eq!(lan.name.as_deref(), Some("LAN"));
    assert_eq!(graph.summary.networks.len(), 2);
    assert_eq!(graph.revision, Revision(7));
}

#[test]
fn identifiers_are_stable_across_computations() {
    let lab = lab();
    let one = build(&lab.inputs).graph;
    let mut shuffled = lab.inputs.clone();
    shuffled.facts.reverse();
    let two = build(&shuffled).graph;
    let ids = |g: &TopologyGraph| g.nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>();
    let edges = |g: &TopologyGraph| g.edges.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&one), ids(&two));
    assert_eq!(edges(&one), edges(&two));
}

#[test]
fn expired_facts_and_intent_alone_make_no_nodes() {
    let mut lab = lab();
    for fact in &mut lab.inputs.facts {
        fact.expires_at = Some("2026-10-10T11:00:00Z".parse().expect("time"));
    }
    lab.inputs.controllers.clear();
    let graph = build(&lab.inputs).graph;
    assert_eq!(graph.nodes.len(), 0, "{:?}", labels(&graph));
}

#[test]
fn a_vlan_filter_keeps_its_members_and_the_backbone_that_connects_them() {
    let lab = lab();
    let computed = build(&lab.inputs);
    let vlans = &lab.inputs.intent.vlans;
    let iot = filter::apply(
        &computed,
        &TopologyFilter {
            vlan: Some(30),
            ..TopologyFilter::default()
        },
        vlans,
    );
    assert_eq!(
        labels(&iot),
        [
            "00:00:5e:00:53:11",
            "Gateway",
            "U6-Lite",
            "USW-24",
            "core-sw"
        ]
    );
    assert_eq!(iot.summary.total_nodes, 9);
    assert_eq!(iot.summary.nodes, 5);
    assert!(
        iot.edges
            .iter()
            .all(|e| iot.nodes.iter().any(|n| n.id == e.a) && iot.nodes.iter().any(|n| n.id == e.b))
    );
    let switches = filter::apply(
        &computed,
        &TopologyFilter {
            kinds: vec![NodeKind::Switch],
            ..TopologyFilter::default()
        },
        vlans,
    );
    assert_eq!(labels(&switches), ["USW-24", "core-sw"]);
    assert_eq!(switches.edges.len(), 1, "the LLDP link between them");
    let search = filter::apply(
        &computed,
        &TopologyFilter {
            q: Some("web01".to_owned()),
            ..TopologyFilter::default()
        },
        vlans,
    );
    assert!(labels(&search).contains(&"web01"));
    let within = filter::apply(
        &computed,
        &TopologyFilter {
            within: Some("192.0.2.8/29".parse().expect("net")),
            kinds: vec![NodeKind::Host],
            ..TopologyFilter::default()
        },
        vlans,
    );
    assert_eq!(labels(&within), ["printer"]);
    let cut = filter::apply(
        &computed,
        &TopologyFilter {
            limit: Some(3),
            ..TopologyFilter::default()
        },
        vlans,
    );
    assert!(cut.summary.truncated);
    assert_eq!(cut.nodes.len(), 3);
    assert!(cut.nodes.iter().all(|n| n.kind.is_infrastructure()));
}

#[test]
fn a_port_shows_what_hangs_on_it() {
    let lab = lab();
    let computed = build(&lab.inputs);
    let switch = by_label(&computed.graph, "USW-24").id.clone();
    let ports = filter::ports(&computed, &switch, None);
    let names: Vec<&str> = ports.iter().map(|p| p.port.as_str()).collect();
    assert_eq!(names, ["1", "5", "6", "Port 1"]);
    assert!(ports[0].uplink);
    assert_eq!(ports[0].neighbours[0].label, "Gateway");
    assert_eq!(ports[1].native_vlan, Some(20));
    let five = filter::ports(&computed, &switch, Some("5"));
    assert_eq!(five.len(), 1);
    assert_eq!(five[0].neighbours.len(), 1);
    assert_eq!(five[0].neighbours[0].label, "printer");
    assert_eq!(five[0].neighbours[0].edge_kind, EdgeKind::Wired);
    let by_name = filter::ports(&computed, &switch, Some("Port 5"));
    assert_eq!(
        by_name.len(),
        1,
        "a port is found by its controller name too"
    );
    let neighbours = filter::neighbours(&computed, &switch);
    assert_eq!(neighbours.len(), 4, "{neighbours:?}");
}

#[test]
fn a_few_thousand_clients_are_computed_quickly() {
    let mut lab = lab();
    let ctl = ObservationSource::NetworkController {
        connector: lab.controller,
    };
    for index in 0..3_000u32 {
        let octets = index.to_be_bytes();
        let client = MacAddr::new([0x00, 0x00, 0x5e, 0x10, octets[2], octets[3]]);
        lab.inputs.facts.push(fact(
            &ctl,
            Observed::Attachment {
                mac: client,
                device: if index % 2 == 0 { "sw-1" } else { "ap-1" }.to_owned(),
                port: (index % 2 == 0).then(|| (index % 24 + 1).to_string()),
                ssid: (index % 2 == 1).then(|| "iot.example.test".to_owned()),
                vlan: Some(30),
            },
        ));
    }
    let started = Instant::now();
    let computed = build(&lab.inputs);
    let elapsed = started.elapsed();
    assert_eq!(computed.graph.nodes.len(), 3_009);
    let filtered = filter::apply(
        &computed,
        &TopologyFilter {
            vlan: Some(30),
            ..TopologyFilter::default()
        },
        &lab.inputs.intent.vlans,
    );
    assert_eq!(filtered.nodes.len(), 3_005);
    // A debug build on the development machine computes this in well under a second.
    assert!(elapsed.as_secs() < 10, "{elapsed:?}");
    println!("3,009 nodes in {elapsed:?}");
}

#[tokio::test]
async fn the_service_reads_facts_intent_and_controllers_and_keeps_the_graph() {
    let (service, store) = service();
    let mut controller = MemoryController::new("unifi.example.test");
    let id = controller.info.id;
    let table = controller_table(id);
    controller.devices = table.devices;
    controller.wlans = table.wlans;
    let memory = MemoryControllers::new(vec![controller]);
    let slot = Controllers::with(memory.clone());
    let topology = TopologyService::new(
        Arc::clone(&service),
        Arc::clone(&slot),
        TopologyConfig::default(),
    );

    let lan = prefix(None, "192.0.2.0/24");
    let (printer, interface) = host(
        "printer",
        tenko_core::ipam::AssignmentMode::Reserved,
        Some("00:00:5e:00:53:10"),
    );
    let mut bound = address(None, "192.0.2.10");
    bound.interface = Some(interface);
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(lan),
            IpamCommand::CreateHost(printer.clone()),
            IpamCommand::CreateAddress(bound),
        ],
    )
    .await;
    let source = ObservationSource::NetworkController { connector: id };
    let observed_at = Timestamp::now();
    let batch = IngestBatch {
        source: source.clone(),
        observations: vec![Observation {
            id: ObservationId::generate(),
            source,
            subject: Observed::Attachment {
                mac: mac(0x10),
                device: "sw-1".to_owned(),
                port: Some("5".to_owned()),
                ssid: None,
                vlan: Some(20),
            },
            observed_at,
            received_at: observed_at,
            expires_at: None,
        }],
        complete: true,
        received_at: observed_at,
    };
    let store: Arc<dyn tenko_store::Store> = Arc::new(store);
    ingest(&store, &batch, &ObserveConfig::default())
        .await
        .expect("ingest");

    let graph = topology
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(labels(&graph), ["Gateway", "U6-Lite", "USW-24", "printer"]);
    assert_eq!(graph.summary.controllers.len(), 1);
    assert_eq!(graph.summary.controllers[0].devices, 3);
    let printer_node = by_label(&graph, "printer");
    assert_eq!(printer_node.host, printer.id);
    let view = topology
        .node(&printer_node.id, None, None, None)
        .await
        .expect("node");
    let intent = view.intent.expect("intent");
    assert_eq!(intent.name, "printer");
    assert_eq!(intent.addresses.len(), 1);
    assert_eq!(view.neighbours[0].label, "USW-24");
    assert_eq!(view.neighbours[0].remote_port.as_deref(), Some("5"));
    assert_eq!(view.neighbours[0].port, None);
    let switch = by_label(&graph, "USW-24").id.clone();
    let port = topology
        .node(&switch, Some("5"), None, None)
        .await
        .expect("port");
    assert_eq!(port.ports.len(), 1);
    assert_eq!(port.ports[0].neighbours[0].label, "printer");
    let missing = topology
        .node("m-000000000000", None, None, None)
        .await
        .expect_err("unknown");
    assert_eq!(missing.code_str(), "ipam.topology.not_found");

    // The device tables are kept: a second read does not ask the controller again.
    let reads = memory.calls().len();
    topology
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(memory.calls().len(), reads);
}

#[tokio::test]
async fn a_controller_that_cannot_be_read_is_reported_and_its_facts_still_count() {
    let (service, _store) = service();
    let controller = MemoryController::new("down.example.test");
    let memory = MemoryControllers::new(vec![controller]);
    memory.fail_next(
        CallKind::Topology,
        tenko_core::CodedError::new("connect.unreachable", 502, "no route"),
    );
    let topology = TopologyService::new(
        Arc::clone(&service),
        Controllers::with(memory),
        TopologyConfig {
            controller_retry: std::time::Duration::ZERO,
            min_recompute: std::time::Duration::ZERO,
            ..TopologyConfig::default()
        },
    );
    let graph = topology
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(graph.summary.controllers.len(), 1);
    assert_eq!(
        graph.summary.controllers[0]
            .error
            .as_ref()
            .map(|e| e.code.as_ref()),
        Some("connect.unreachable")
    );
    // A failed read is tried again after the retry interval (zero here).
    let graph = topology
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(graph.summary.controllers[0].error, None);
    let without = TopologyService::new(service, Controllers::new(), TopologyConfig::default());
    let graph = without
        .graph(&TopologyFilter::default(), None, None)
        .await
        .expect("graph");
    assert_eq!(graph.nodes.len(), 0);
}
