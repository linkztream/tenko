//! Computing the graph from facts, intent and the device tables of network controllers.
//!
//! Every thing a source names becomes an **alias**: a host of intent, a device of a
//! controller (by the controller's reference), an inventory host (by its source and
//! external id), a MAC address, a device name of a probe, or an IP address. Facts and
//! intent join aliases that are the same device (union-find): an address fact with one MAC
//! address joins the address and the MAC, an inventory host joins its MAC and IP addresses,
//! a controller device joins its reference, name, MAC and management address, an SNMP name
//! fact joins the polled device's name with its address, and an interface or address of
//! intent joins its MAC or IP address with the host. Each class of joined aliases that a
//! current fact names is a node; intent alone makes no node. The node takes the identifier
//! of its most telling alias (host, controller device, inventory host, MAC, name, address),
//! so it stays the same while the device is seen the same way.
//!
//! Edges come from attachment facts (wired with a port, wireless with an SSID), link facts
//! (LLDP, uplinks, and the wired and wireless links controllers report) and the parent of
//! an inventory host (`vm_host`). Duplicates of several sources become one edge with every
//! source listed.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

use ipnet::IpNet;
use sha2::{Digest as _, Sha256};
use tenko_core::{
    ConnectorId, HostId, MacAddr, PrefixId, Revision, SiteId, Timestamp,
    ipam::{Address, Host, Interface, Prefix, PrefixRole, Vlan},
    observe::{LinkKind, ObservationSource, Observed, ProbeMethod},
    serde_util::to_hex,
};

use super::model::{
    ControllerStatus, EdgeKind, NetworkInView, NodeKind, TopologyEdge, TopologyGraph, TopologyNode,
    TopologySummary,
};
use crate::{
    net::contains_ip,
    observe::ObservedFact,
    vlan::controllers::{ControllerDeviceKind, ControllerPort, ControllerTopology},
};

/// The prefix of the source keys of network controllers (`network_controller:<connector>`).
pub(crate) const CONTROLLER_SOURCE: &str = "network_controller:";

/// The live intent the graph joins in.
#[derive(Debug, Clone, Default)]
pub struct Intent {
    /// Live hosts.
    pub hosts: Vec<Host>,
    /// Live interfaces.
    pub interfaces: Vec<Interface>,
    /// Live addresses.
    pub addresses: Vec<Address>,
    /// Live prefixes.
    pub prefixes: Vec<Prefix>,
    /// Live VLANs.
    pub vlans: Vec<Vlan>,
}

/// Everything the graph is computed from.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Every fact; only current ones count.
    pub facts: Vec<ObservedFact>,
    /// The intent.
    pub intent: Intent,
    /// The device tables of the network controllers that could be read.
    pub controllers: Vec<ControllerTopology>,
    /// Every network controller with its name and the error of its last read.
    pub statuses: Vec<ControllerStatus>,
    /// The revision of the view the facts and intent were read from.
    pub revision: Revision,
    /// The time facts are judged current at.
    pub now: Timestamp,
}

/// The graph and what the node view needs besides it.
#[derive(Debug, Clone, Default)]
pub struct Computed {
    /// The whole graph.
    pub graph: TopologyGraph,
    /// The port tables of controller devices, by node.
    pub ports: HashMap<String, Vec<ControllerPort>>,
    /// The position of each node in `graph.nodes`.
    pub index: HashMap<String, usize>,
    /// The intent the graph was computed from (the WLAN rules read it again).
    pub intent: Intent,
    /// The controllers' tables the graph was computed from.
    pub controllers: Vec<std::sync::Arc<ControllerTopology>>,
}

impl Default for TopologyGraph {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            summary: TopologySummary::default(),
            revision: Revision::ZERO,
        }
    }
}

/// Something a source names. The order is the preference for the node identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Alias {
    Host(HostId),
    Controller(ConnectorId, String),
    Inventory(String, String),
    Mac(MacAddr),
    Name(String),
    Ip(IpAddr),
}

/// Evidence of what a class is, in order of precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Hint {
    Gateway,
    Switch,
    AccessPoint,
    Hypervisor,
    Vm,
    Container,
    WirelessParent,
    WiredParent,
    NetworkDevice,
}

/// Label priorities: the lower, the better.
mod label {
    pub const HOST: u8 = 1;
    pub const CONTROLLER: u8 = 2;
    pub const INVENTORY: u8 = 3;
    pub const PROBE_NAME: u8 = 4;
    pub const DEVICE_STRING: u8 = 5;
}

#[derive(Debug, Default)]
struct Info {
    observed: bool,
    labels: Vec<(u8, String)>,
    hints: BTreeSet<Hint>,
    vendor: Option<String>,
    model: Option<String>,
    os: Option<(u8, String)>,
    sources: BTreeSet<String>,
    last_seen: Option<Timestamp>,
    vlans: BTreeSet<u16>,
    ssids: BTreeSet<String>,
    ports: Vec<ControllerPort>,
    site: Option<SiteId>,
}

#[derive(Debug)]
struct RawEdge {
    kind: EdgeKind,
    a: usize,
    a_port: Option<String>,
    b: usize,
    b_port: Option<String>,
    vlan: Option<u16>,
    ssid: Option<String>,
    source: String,
}

#[derive(Debug, Default)]
struct Builder {
    ids: HashMap<Alias, usize>,
    aliases: Vec<Alias>,
    parent: Vec<usize>,
    info: Vec<Info>,
    edges: Vec<RawEdge>,
}

impl Builder {
    fn alias(&mut self, alias: Alias) -> usize {
        if let Some(&id) = self.ids.get(&alias) {
            return id;
        }
        let id = self.aliases.len();
        self.ids.insert(alias.clone(), id);
        self.aliases.push(alias);
        self.parent.push(id);
        self.info.push(Info::default());
        id
    }

    fn find(&mut self, mut id: usize) -> usize {
        while self.parent[id] != id {
            self.parent[id] = self.parent[self.parent[id]];
            id = self.parent[id];
        }
        id
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            // The smaller alias (the better identifier) stays the root.
            if self.aliases[ra] <= self.aliases[rb] {
                self.parent[rb] = ra;
            } else {
                self.parent[ra] = rb;
            }
        }
    }

    /// Records that `fact` names the alias.
    fn seen(&mut self, id: usize, fact: &ObservedFact) {
        let info = &mut self.info[id];
        info.observed = true;
        info.sources.insert(fact.source_key.clone());
        if info.last_seen.is_none_or(|seen| seen < fact.last_seen) {
            info.last_seen = Some(fact.last_seen);
        }
    }

    fn label(&mut self, id: usize, priority: u8, text: &str) {
        let text = text.trim();
        if !text.is_empty() {
            self.info[id].labels.push((priority, text.to_owned()));
        }
    }

    /// The alias of a device a fact names: a controller's reference for controller
    /// sources, else a MAC address, an IP address or a name.
    fn device(&mut self, source: &ObservationSource, device: &str) -> usize {
        let device = device.trim();
        if let ObservationSource::NetworkController { connector } = source {
            return self.alias(Alias::Controller(*connector, device.to_owned()));
        }
        if let Ok(mac) = device.parse::<MacAddr>()
            && device.len() >= 12
        {
            return self.alias(Alias::Mac(mac));
        }
        if let Ok(ip) = device.parse::<IpAddr>() {
            return self.alias(Alias::Ip(ip));
        }
        let id = self.alias(Alias::Name(device.to_lowercase()));
        self.label(id, label::DEVICE_STRING, device);
        id
    }
}

fn hash12(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0x1f]);
    }
    to_hex(&hasher.finalize()[..6])
}

fn node_id(alias: &Alias) -> String {
    match alias {
        Alias::Host(id) => format!("h-{}", id.uuid().simple()),
        Alias::Controller(connector, device) => {
            format!("c-{}", hash12(&[&connector.to_string(), device]))
        }
        Alias::Inventory(source, external) => format!("i-{}", hash12(&[source, external])),
        Alias::Mac(mac) => format!("m-{}", to_hex(&mac.octets())),
        Alias::Name(name) => format!("n-{}", hash12(&[name])),
        Alias::Ip(ip) => format!("a-{}", hash12(&[&ip.to_string()])),
    }
}

fn edge_kind(kind: LinkKind) -> EdgeKind {
    match kind {
        LinkKind::Lldp => EdgeKind::Lldp,
        LinkKind::Uplink => EdgeKind::Uplink,
        LinkKind::Wired => EdgeKind::Wired,
        LinkKind::Wireless => EdgeKind::Wireless,
    }
}

fn platform_hint(platform: &str) -> Option<Hint> {
    let platform = platform.to_ascii_lowercase();
    if ["lxc", "docker", "podman", "container", "oci"]
        .iter()
        .any(|p| platform.contains(p))
    {
        Some(Hint::Container)
    } else if ["qemu", "kvm", "vm", "hyperv", "vmware", "xen", "bhyve"]
        .iter()
        .any(|p| platform.contains(p))
    {
        Some(Hint::Vm)
    } else {
        None
    }
}

fn kind_of(hints: &BTreeSet<Hint>) -> NodeKind {
    match hints.first() {
        Some(Hint::Gateway) => NodeKind::Router,
        Some(Hint::Switch | Hint::WiredParent) => NodeKind::Switch,
        Some(Hint::AccessPoint | Hint::WirelessParent) => NodeKind::AccessPoint,
        Some(Hint::Hypervisor) => NodeKind::Hypervisor,
        Some(Hint::Vm) => NodeKind::Vm,
        Some(Hint::Container) => NodeKind::Container,
        Some(Hint::NetworkDevice) => NodeKind::Device,
        None => NodeKind::Host,
    }
}

/// The addresses whose current address facts name exactly one MAC address.
fn unambiguous_ips(facts: &[&ObservedFact]) -> HashMap<IpAddr, MacAddr> {
    let mut seen: HashMap<IpAddr, BTreeSet<MacAddr>> = HashMap::new();
    for fact in facts {
        if let Observed::Address {
            ip, mac: Some(mac), ..
        } = &fact.observed
        {
            seen.entry(*ip).or_default().insert(*mac);
        }
    }
    seen.into_iter()
        .filter_map(|(ip, macs)| match macs.len() {
            1 => macs.first().map(|mac| (ip, *mac)),
            _ => None,
        })
        .collect()
}

fn add_controllers(builder: &mut Builder, controllers: &[ControllerTopology]) {
    for topology in controllers {
        let source = format!("network_controller:{}", topology.connector);
        for device in &topology.devices {
            let id = builder.alias(Alias::Controller(topology.connector, device.id.clone()));
            {
                let info = &mut builder.info[id];
                info.observed = true;
                info.sources.insert(source.clone());
                if info
                    .last_seen
                    .is_none_or(|seen| seen < topology.observed_at)
                {
                    info.last_seen = Some(topology.observed_at);
                }
                info.hints.insert(match device.kind {
                    ControllerDeviceKind::Gateway => Hint::Gateway,
                    ControllerDeviceKind::Switch => Hint::Switch,
                    ControllerDeviceKind::AccessPoint => Hint::AccessPoint,
                    ControllerDeviceKind::Other => Hint::NetworkDevice,
                });
                info.model.clone_from(&device.model);
                info.ports.clone_from(&device.ports);
                info.vlans
                    .extend(device.ports.iter().filter_map(|port| port.native_vlan));
            }
            builder.label(id, label::CONTROLLER, &device.name);
            let name = builder.alias(Alias::Name(device.name.trim().to_lowercase()));
            builder.union(id, name);
            if let Some(mac) = device.mac {
                let mac = builder.alias(Alias::Mac(mac));
                builder.union(id, mac);
            }
            if let Some(ip) = device.ip {
                let ip = builder.alias(Alias::Ip(ip));
                builder.union(id, ip);
            }
        }
        for wlan in topology.wlans.iter().filter(|wlan| wlan.enabled) {
            for ap in &wlan.access_points {
                let id = builder.alias(Alias::Controller(topology.connector, ap.clone()));
                builder.info[id].ssids.insert(wlan.ssid.clone());
            }
        }
    }
}

fn add_inventory_host(
    builder: &mut Builder,
    fact: &ObservedFact,
    host: &tenko_core::observe::ObservedHost,
) {
    let id = builder.alias(Alias::Inventory(
        fact.source_key.clone(),
        host.external_id.clone(),
    ));
    builder.seen(id, fact);
    if let Some(name) = &host.name {
        builder.label(id, label::INVENTORY, name);
    }
    if let Some(os) = &host.os {
        builder.info[id].os = Some((1, os.clone()));
    }
    if let Some(hint) = host.platform.as_deref().and_then(platform_hint) {
        builder.info[id].hints.insert(hint);
    }
    for mac in &host.macs {
        let mac = builder.alias(Alias::Mac(*mac));
        builder.union(id, mac);
    }
    for ip in &host.ips {
        let ip = builder.alias(Alias::Ip(*ip));
        builder.union(id, ip);
    }
    if let Some(parent) = &host.parent {
        let parent_id = builder.alias(Alias::Inventory(fact.source_key.clone(), parent.clone()));
        builder.seen(parent_id, fact);
        builder.label(parent_id, label::DEVICE_STRING, parent);
        builder.info[parent_id].hints.insert(Hint::Hypervisor);
        builder.edges.push(RawEdge {
            kind: EdgeKind::VmHost,
            a: parent_id,
            a_port: None,
            b: id,
            b_port: None,
            vlan: None,
            ssid: None,
            source: fact.source_key.clone(),
        });
    }
}

fn add_attachment(
    builder: &mut Builder,
    fact: &ObservedFact,
    mac: MacAddr,
    device: &str,
    port: Option<&String>,
    ssid: Option<&String>,
    vlan: Option<u16>,
) {
    let client = builder.alias(Alias::Mac(mac));
    builder.seen(client, fact);
    let parent = builder.device(&fact.source, device);
    builder.seen(parent, fact);
    if let Some(vlan) = vlan {
        builder.info[client].vlans.insert(vlan);
    }
    if let Some(ssid) = ssid {
        builder.info[client].ssids.insert(ssid.clone());
        builder.info[parent].ssids.insert(ssid.clone());
    }
    let wireless = ssid.is_some();
    builder.info[parent].hints.insert(if wireless {
        Hint::WirelessParent
    } else {
        Hint::WiredParent
    });
    builder.edges.push(RawEdge {
        kind: if wireless {
            EdgeKind::Wireless
        } else {
            EdgeKind::Wired
        },
        a: parent,
        a_port: port.cloned(),
        b: client,
        b_port: None,
        vlan,
        ssid: ssid.cloned(),
        source: fact.source_key.clone(),
    });
}

fn add_facts(builder: &mut Builder, facts: &[&ObservedFact]) {
    let ip_macs = unambiguous_ips(facts);
    for fact in facts {
        match &fact.observed {
            Observed::Host(host) => add_inventory_host(builder, fact, host),
            Observed::Address { ip, mac, .. } => {
                let id = builder.alias(Alias::Ip(*ip));
                builder.seen(id, fact);
                if let Some(mac) = mac {
                    let mac_id = builder.alias(Alias::Mac(*mac));
                    builder.seen(mac_id, fact);
                    if ip_macs.get(ip) == Some(mac) {
                        builder.union(id, mac_id);
                    }
                }
            }
            Observed::Attachment {
                mac,
                device,
                port,
                ssid,
                vlan,
            } => add_attachment(
                builder,
                fact,
                *mac,
                device,
                port.as_ref(),
                ssid.as_ref(),
                *vlan,
            ),
            Observed::Link { a, b, kind } => {
                let a_id = builder.device(&fact.source, &a.device);
                let b_id = builder.device(&fact.source, &b.device);
                builder.seen(a_id, fact);
                builder.seen(b_id, fact);
                for id in [a_id, b_id] {
                    builder.info[id].hints.insert(Hint::NetworkDevice);
                }
                builder.edges.push(RawEdge {
                    kind: edge_kind(*kind),
                    a: a_id,
                    a_port: a.port.clone(),
                    b: b_id,
                    b_port: b.port.clone(),
                    vlan: None,
                    ssid: None,
                    source: fact.source_key.clone(),
                });
            }
            Observed::Name { ip, name, .. } => {
                let id = builder.alias(Alias::Ip(*ip));
                builder.label(id, label::PROBE_NAME, name);
                // The polled device of an SNMP probe goes by its name in the probe's
                // attachments and links.
                if matches!(
                    fact.source,
                    ObservationSource::Probe {
                        method: ProbeMethod::Snmp,
                        ..
                    }
                ) {
                    let name_id = builder.alias(Alias::Name(name.trim().to_lowercase()));
                    builder.union(id, name_id);
                }
            }
            Observed::Vendor { mac, vendor } => {
                let id = builder.alias(Alias::Mac(*mac));
                builder.info[id].vendor = Some(vendor.clone());
            }
            Observed::Os { ip, guess, .. } => {
                let id = builder.alias(Alias::Ip(*ip));
                if builder.info[id].os.is_none() {
                    builder.info[id].os = Some((2, guess.clone()));
                }
            }
            // The controller networks reach the summary from the live topology, not as nodes.
            Observed::Services { .. } | Observed::Network { .. } => {}
        }
    }
}

fn add_intent(builder: &mut Builder, intent: &Intent) {
    let hosts: HashMap<HostId, &Host> = intent.hosts.iter().map(|h| (h.id, h)).collect();
    for host in &intent.hosts {
        let id = builder.alias(Alias::Host(host.id));
        builder.label(id, label::HOST, host.name.as_str());
        builder.info[id].site = host.site;
    }
    let mut interface_hosts = HashMap::new();
    for interface in &intent.interfaces {
        if !hosts.contains_key(&interface.host) {
            continue;
        }
        interface_hosts.insert(interface.id, interface.host);
        if let Some(mac) = interface.mac {
            let host = builder.alias(Alias::Host(interface.host));
            let mac = builder.alias(Alias::Mac(mac));
            builder.union(host, mac);
        }
    }
    for address in &intent.addresses {
        if let Some(host) = address
            .interface
            .and_then(|interface| interface_hosts.get(&interface))
        {
            let host = builder.alias(Alias::Host(*host));
            let ip = builder.alias(Alias::Ip(address.ip));
            builder.union(host, ip);
        }
    }
}

/// The most specific live network of intent for each address.
struct Networks<'a> {
    by_length: Vec<&'a Prefix>,
}

impl<'a> Networks<'a> {
    fn new(prefixes: &'a [Prefix]) -> Self {
        let mut by_length: Vec<&Prefix> = prefixes
            .iter()
            .filter(|p| p.role == PrefixRole::Network)
            .collect();
        by_length.sort_by_key(|p| std::cmp::Reverse(p.cidr.prefix_len()));
        Self { by_length }
    }

    fn of(&self, ip: IpAddr) -> Option<&'a Prefix> {
        self.by_length
            .iter()
            .find(|prefix| contains_ip(&prefix.cidr, ip))
            .copied()
    }
}

fn best_label(labels: &mut [(u8, String)]) -> Option<String> {
    labels.sort();
    labels.first().map(|(_, text)| text.clone())
}

/// The intent a node is joined with: networks by address and VLANs by identifier.
struct Join<'a> {
    networks: Networks<'a>,
    vlans: HashMap<tenko_core::VlanId, &'a Vlan>,
    address_prefix: HashMap<IpAddr, PrefixId>,
    prefixes: HashMap<PrefixId, &'a Prefix>,
}

impl<'a> Join<'a> {
    fn new(intent: &'a Intent) -> Self {
        Self {
            networks: Networks::new(&intent.prefixes),
            vlans: intent.vlans.iter().map(|v| (v.id, v)).collect(),
            address_prefix: intent.addresses.iter().map(|a| (a.ip, a.prefix)).collect(),
            prefixes: intent.prefixes.iter().map(|p| (p.id, p)).collect(),
        }
    }

    /// The network of an address: its own prefix for an address of intent, else the most
    /// specific network that contains it.
    fn network(&self, ip: IpAddr) -> Option<&'a Prefix> {
        self.address_prefix
            .get(&ip)
            .and_then(|id| self.prefixes.get(id).copied())
            .or_else(|| self.networks.of(ip))
    }
}

/// What the aliases of one class say together.
#[derive(Default)]
struct Merged {
    macs: BTreeSet<MacAddr>,
    ips: BTreeSet<IpAddr>,
    host: Option<HostId>,
    labels: Vec<(u8, String)>,
    hints: BTreeSet<Hint>,
    sources: BTreeSet<String>,
    vlans: BTreeSet<u16>,
    ssids: BTreeSet<String>,
    last_seen: Option<Timestamp>,
    model: Option<String>,
    os: Option<(u8, String)>,
    site: Option<SiteId>,
    vendors: BTreeMap<MacAddr, String>,
    ports: Vec<ControllerPort>,
}

impl Merged {
    fn of(builder: &mut Builder, members: &[usize]) -> Self {
        let mut merged = Self::default();
        for &member in members {
            match &builder.aliases[member] {
                Alias::Host(h) => {
                    merged.host = merged.host.or(Some(*h));
                    merged.sources.insert("intent".to_owned());
                }
                Alias::Mac(mac) => {
                    merged.macs.insert(*mac);
                }
                Alias::Ip(ip) => {
                    merged.ips.insert(*ip);
                }
                _ => {}
            }
            let info = &mut builder.info[member];
            if let (Alias::Mac(mac), Some(vendor)) = (&builder.aliases[member], &info.vendor) {
                merged.vendors.insert(*mac, vendor.clone());
            }
            merged.labels.append(&mut info.labels);
            merged.hints.extend(info.hints.iter().copied());
            merged.sources.extend(info.sources.iter().cloned());
            merged.vlans.extend(info.vlans.iter().copied());
            merged.ssids.extend(info.ssids.iter().cloned());
            if let Some(seen) = info.last_seen
                && merged.last_seen.is_none_or(|last| last < seen)
            {
                merged.last_seen = Some(seen);
            }
            if merged.model.is_none() {
                merged.model.clone_from(&info.model);
            }
            if let Some(candidate) = info.os.take()
                && merged
                    .os
                    .as_ref()
                    .is_none_or(|current| candidate.0 < current.0)
            {
                merged.os = Some(candidate);
            }
            merged.site = merged.site.or(info.site);
            if merged.ports.is_empty() && !info.ports.is_empty() {
                merged.ports = std::mem::take(&mut info.ports);
            }
        }
        merged
    }

    /// The node of the class, with the port table of a controller device beside it.
    fn into_node(mut self, id: String, join: &Join<'_>) -> (TopologyNode, Vec<ControllerPort>) {
        let mut prefixes = BTreeSet::new();
        for ip in &self.ips {
            if let Some(prefix) = join.network(*ip) {
                prefixes.insert(prefix.id);
                self.site = self.site.or(prefix.site);
                if let Some(vlan) = prefix.vlan.and_then(|v| join.vlans.get(&v)) {
                    self.vlans.insert(vlan.vid);
                    self.site = self.site.or(vlan.site);
                }
            }
        }
        let vendor = self
            .macs
            .iter()
            .find_map(|mac| self.vendors.get(mac).cloned());
        let first_mac = self.macs.iter().next().copied();
        let first_ip = self.ips.iter().next().copied();
        let label =
            best_label(&mut self.labels).unwrap_or_else(|| match (&vendor, first_mac, first_ip) {
                (Some(vendor), Some(mac), _) => {
                    let octets = mac.octets();
                    format!(
                        "{vendor} {:02x}:{:02x}:{:02x}",
                        octets[3], octets[4], octets[5]
                    )
                }
                (None, Some(mac), _) => mac.to_string(),
                (_, None, Some(ip)) => ip.to_string(),
                _ => id.clone(),
            });
        let node = TopologyNode {
            id,
            kind: kind_of(&self.hints),
            label,
            macs: self.macs.into_iter().collect(),
            ips: self.ips.into_iter().collect(),
            vendor,
            model: self.model,
            os: self.os.map(|(_, text)| text),
            host: self.host,
            subject: first_mac
                .map(|mac| mac.to_string())
                .or_else(|| first_ip.map(|ip| ip.to_string())),
            vlans: self.vlans.into_iter().collect(),
            prefixes: prefixes.into_iter().collect(),
            site: self.site,
            ssids: self.ssids.into_iter().collect(),
            sources: self.sources.into_iter().collect(),
            last_seen: self.last_seen,
        };
        (node, self.ports)
    }
}

/// Computes the graph.
pub fn build(inputs: &Inputs) -> Computed {
    let mut builder = Builder::default();
    let facts: Vec<&ObservedFact> = inputs
        .facts
        .iter()
        .filter(|fact| fact.is_current(inputs.now))
        .collect();
    add_controllers(&mut builder, &inputs.controllers);
    add_facts(&mut builder, &facts);
    add_intent(&mut builder, &inputs.intent);

    let mut classes: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for id in 0..builder.aliases.len() {
        let root = builder.find(id);
        classes.entry(root).or_default().push(id);
    }
    let join = Join::new(&inputs.intent);
    let mut nodes = Vec::new();
    let mut ports = HashMap::new();
    let mut node_of_root: HashMap<usize, String> = HashMap::new();
    for (root, members) in &classes {
        if !members.iter().any(|&m| builder.info[m].observed) {
            continue;
        }
        // The root is the smallest alias of its class (see `Builder::union`).
        let id = node_id(&builder.aliases[*root]);
        let (node, node_ports) = Merged::of(&mut builder, members).into_node(id, &join);
        if !node_ports.is_empty() {
            ports.insert(node.id.clone(), node_ports);
        }
        node_of_root.insert(*root, node.id.clone());
        nodes.push(node);
    }

    let edges = assemble_edges(&mut builder, &node_of_root);
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    let index = nodes
        .iter()
        .enumerate()
        .map(|(position, node)| (node.id.clone(), position))
        .collect();
    let mut networks_in_view: Vec<NetworkInView> = inputs
        .controllers
        .iter()
        .flat_map(|topology| {
            topology.networks.iter().map(|network| NetworkInView {
                connector: topology.connector,
                network: network.clone(),
            })
        })
        .collect();
    networks_in_view.sort_by(|a, b| {
        (a.network.vlan, &a.network.name, a.connector).cmp(&(
            b.network.vlan,
            &b.network.name,
            b.connector,
        ))
    });
    let summary = TopologySummary {
        total_nodes: nodes.len(),
        total_edges: edges.len(),
        controllers: inputs.statuses.clone(),
        networks: networks_in_view,
        computed_at: Some(inputs.now),
        ..TopologySummary::default()
    };
    let mut graph = TopologyGraph {
        nodes,
        edges,
        summary,
        revision: inputs.revision,
    };
    super::filter::summarize(&mut graph, &inputs.intent.vlans);
    Computed {
        graph,
        ports,
        index,
        ..Computed::default()
    }
}

fn assemble_edges(
    builder: &mut Builder,
    node_of_root: &HashMap<usize, String>,
) -> Vec<TopologyEdge> {
    let raw = std::mem::take(&mut builder.edges);
    let mut merged: BTreeMap<(EdgeKind, String, String, String, String), TopologyEdge> =
        BTreeMap::new();
    for edge in raw {
        let (ra, rb) = (builder.find(edge.a), builder.find(edge.b));
        if ra == rb {
            continue;
        }
        let (Some(a), Some(b)) = (node_of_root.get(&ra), node_of_root.get(&rb)) else {
            continue;
        };
        let (mut a, mut a_port, mut b, mut b_port) =
            (a.clone(), edge.a_port, b.clone(), edge.b_port);
        // Links between two devices have no direction: the smaller identifier comes first.
        if matches!(edge.kind, EdgeKind::Lldp | EdgeKind::Uplink) && b < a {
            std::mem::swap(&mut a, &mut b);
            std::mem::swap(&mut a_port, &mut b_port);
        }
        // A client sits on one port of its switch or one access point: several sources
        // reporting it are one edge, whatever they call the port.
        let key = match edge.kind {
            EdgeKind::Wired | EdgeKind::Wireless | EdgeKind::VmHost => (
                edge.kind,
                a.clone(),
                String::new(),
                b.clone(),
                String::new(),
            ),
            EdgeKind::Lldp | EdgeKind::Uplink => (
                edge.kind,
                a.clone(),
                a_port.clone().unwrap_or_default(),
                b.clone(),
                b_port.clone().unwrap_or_default(),
            ),
        };
        let entry = merged.entry(key).or_insert_with(|| TopologyEdge {
            id: format!(
                "e-{}",
                hash12(&[
                    edge.kind.as_str(),
                    &a,
                    a_port.as_deref().unwrap_or_default(),
                    &b,
                    b_port.as_deref().unwrap_or_default(),
                ])
            ),
            kind: edge.kind,
            a: a.clone(),
            a_port: a_port.clone(),
            b: b.clone(),
            b_port: b_port.clone(),
            vlan: edge.vlan,
            ssid: edge.ssid.clone(),
            sources: Vec::new(),
            inferred: false,
        });
        if !entry.sources.contains(&edge.source) {
            entry.sources.push(edge.source);
            entry.sources.sort();
        }
        // A client edge is inferred until a network controller reports it: only a bridge
        // table of a probe names it. LLDP links, uplinks and placements are never inferred.
        entry.inferred = matches!(entry.kind, EdgeKind::Wired | EdgeKind::Wireless)
            && !entry
                .sources
                .iter()
                .any(|source| source.starts_with(CONTROLLER_SOURCE));
        entry.vlan = entry.vlan.or(edge.vlan);
        if entry.ssid.is_none() {
            entry.ssid = edge.ssid;
        }
        if entry.a_port.is_none() {
            entry.a_port = a_port;
        }
        if entry.b_port.is_none() {
            entry.b_port = b_port;
        }
    }
    let mut edges: Vec<TopologyEdge> = merged.into_values().collect();
    edges.sort_by(|x, y| x.id.cmp(&y.id));
    edges
}

/// Whether `ip` lies in `net` (re-exported for the filter).
pub(crate) fn within(net: &IpNet, ip: IpAddr) -> bool {
    contains_ip(net, ip)
}
