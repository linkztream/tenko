//! From Proxmox VE answers to observed hosts, without any I/O.
//!
//! A [`Snapshot`] holds what one page of a poll read, as the API answered it (JSON values,
//! so that a changed or unexpected answer degrades a field instead of failing the poll):
//! `/cluster/resources`, `/cluster/status`, the network configuration of each node, the
//! configuration, guest agent interfaces and container interfaces of each guest, and the SDN
//! vnets and zones. [`hosts`] turns it into hosts:
//!
//! | Host | `external_id` | Addresses | Other facts |
//! |---|---|---|---|
//! | Node | `node/<name>` | IP addresses from `/cluster/status` and the active interfaces of the node's network configuration | OS `Proxmox VE <version>`, platform `proxmox-ve`, tag `status:<status>` |
//! | QEMU guest | `qemu/<vmid>` | MAC addresses of `netN`; IP addresses from the guest agent on those MAC addresses, else the static cloud-init addresses | OS from `ostype`, platform `qemu`, parent `node/<node>`, power state from `status` |
//! | LXC container | `lxc/<vmid>` | MAC addresses of `netN`; IP addresses from the running container's interfaces on those MAC addresses, else the static `ip`/`ip6` | OS from `ostype`, platform `lxc`, parent `node/<node>`, power state from `status` |
//!
//! Guests carry their Proxmox tags as they are, and `status:<status>`, `pool:<pool>`,
//! `template` (when templates are included), `bridge:<name>` or `vnet:<name>` per interface,
//! and `vlan:<id>` (the interface tag, or the tag of a vnet in a VLAN or `QinQ` zone) or
//! `vxlan:<vni>` (a vnet in a VXLAN or EVPN zone). Proxmox tags cannot contain a colon, so
//! they never collide with these.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tenko_core::{
    MacAddr,
    observe::{ObservedHost, PowerState},
};

use crate::net::{self, Nic};

/// What one page of a poll read, as the API answered.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The version of Proxmox VE (`version` of `/version`).
    #[serde(default)]
    pub version: Option<String>,
    /// `/cluster/resources`.
    #[serde(default)]
    pub resources: Vec<Value>,
    /// `/cluster/status`; empty when the token may not read it.
    #[serde(default)]
    pub cluster_status: Vec<Value>,
    /// `/nodes/<node>/network` by node name.
    #[serde(default)]
    pub node_networks: BTreeMap<String, Vec<Value>>,
    /// The answers about each guest, by `external_id` (`qemu/<vmid>`, `lxc/<vmid>`).
    #[serde(default)]
    pub guests: BTreeMap<String, GuestAnswers>,
    /// `/cluster/sdn/vnets`.
    #[serde(default)]
    pub vnets: Vec<Value>,
    /// `/cluster/sdn/zones`.
    #[serde(default)]
    pub zones: Vec<Value>,
}

/// What the API answered about one guest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GuestAnswers {
    /// `/nodes/<node>/<type>/<vmid>/config`.
    #[serde(default)]
    pub config: Option<Value>,
    /// `/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces` (an object with `result`).
    #[serde(default)]
    pub agent: Option<Value>,
    /// `/nodes/<node>/lxc/<vmid>/interfaces` (a list).
    #[serde(default)]
    pub interfaces: Option<Value>,
}

/// Which nodes and guests the inventory reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Only these nodes and their guests; all when empty.
    pub nodes: Vec<String>,
    /// Only guests in these pools; all when empty.
    pub pools: Vec<String>,
    /// Report guests that are not running.
    pub include_stopped: bool,
    /// Report templates.
    pub include_templates: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            pools: Vec::new(),
            include_stopped: true,
            include_templates: false,
        }
    }
}

/// The kind of a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A QEMU virtual machine.
    Qemu,
    /// An LXC container.
    Lxc,
}

impl Kind {
    /// The name in the API (`qemu`, `lxc`).
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Qemu => "qemu",
            Kind::Lxc => "lxc",
        }
    }
}

/// A node of `/cluster/resources`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The node name.
    pub name: String,
    /// `online`, `offline` or `unknown`.
    pub status: Option<String>,
}

impl Node {
    /// Whether the node is online, so that its guests can be asked.
    pub fn online(&self) -> bool {
        self.status.as_deref() == Some("online")
    }

    /// The `external_id` of the node's host.
    pub fn external_id(&self) -> String {
        format!("node/{}", self.name)
    }
}

/// A guest of `/cluster/resources`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guest {
    /// QEMU or LXC.
    pub kind: Kind,
    /// The guest id, unique in the cluster.
    pub vmid: u32,
    /// The node it runs on.
    pub node: String,
    /// Its name (the host name of a container).
    pub name: Option<String>,
    /// `running`, `stopped`, ...
    pub status: Option<String>,
    /// Whether it is a template.
    pub template: bool,
    /// Its pool.
    pub pool: Option<String>,
    /// Its Proxmox tags.
    pub tags: Vec<String>,
}

impl Guest {
    /// The `external_id` of the guest's host.
    pub fn external_id(&self) -> String {
        format!("{}/{}", self.kind.as_str(), self.vmid)
    }

    /// Whether it runs.
    pub fn running(&self) -> bool {
        self.status.as_deref() == Some("running")
    }

    /// The power state the status tells: `running`, or `stopped` (a template too); none
    /// for another status or none at all.
    pub fn power(&self) -> Option<PowerState> {
        match self.status.as_deref() {
            Some("running") => Some(PowerState::Running),
            Some("stopped") => Some(PowerState::Stopped),
            _ => None,
        }
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn number(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn truthy(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_u64().is_some_and(|n| n != 0),
        Some(Value::String(text)) => text.trim() == "1",
        _ => false,
    }
}

/// Whether a node name can go into a request path: Proxmox node names are letters, digits,
/// `-`, `_` and `.`.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.starts_with('.')
}

/// The nodes of `/cluster/resources` that the filter keeps, by name.
pub fn nodes(resources: &[Value], filter: &Filter) -> Vec<Node> {
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    for resource in resources {
        if text(resource, "type") != Some("node") {
            continue;
        }
        let Some(name) = text(resource, "node") else {
            continue;
        };
        if !filter.nodes.is_empty() && !filter.nodes.iter().any(|n| n == name) {
            continue;
        }
        nodes.insert(
            name.to_owned(),
            Node {
                name: name.to_owned(),
                status: text(resource, "status").map(str::to_owned),
            },
        );
    }
    nodes.into_values().collect()
}

/// The guests of `/cluster/resources` that the filter keeps, by guest id; a guest id that
/// appears twice is kept once.
pub fn guests(resources: &[Value], filter: &Filter) -> Vec<Guest> {
    let mut guests: BTreeMap<u32, Guest> = BTreeMap::new();
    for resource in resources {
        let kind = match text(resource, "type") {
            Some("qemu") => Kind::Qemu,
            Some("lxc") => Kind::Lxc,
            _ => continue,
        };
        let Some(vmid) = number(resource, "vmid").and_then(|n| u32::try_from(n).ok()) else {
            continue;
        };
        let Some(node) = text(resource, "node") else {
            continue;
        };
        let guest = Guest {
            kind,
            vmid,
            node: node.to_owned(),
            name: text(resource, "name").map(str::to_owned),
            status: text(resource, "status").map(str::to_owned),
            template: truthy(resource, "template"),
            pool: text(resource, "pool").map(str::to_owned),
            tags: text(resource, "tags")
                .map(|tags| {
                    tags.split([';', ',', ' '])
                        .map(str::trim)
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        };
        let keep = (filter.nodes.is_empty() || filter.nodes.contains(&guest.node))
            && (filter.pools.is_empty()
                || guest
                    .pool
                    .as_ref()
                    .is_some_and(|pool| filter.pools.contains(pool)))
            && (filter.include_stopped || guest.running())
            && (filter.include_templates || !guest.template);
        if keep {
            guests.entry(vmid).or_insert(guest);
        }
    }
    guests.into_values().collect()
}

/// The SDN vnets: their zone and tag, and the zone types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sdn {
    vnets: BTreeMap<String, (Option<String>, Option<u32>)>,
    zones: BTreeMap<String, String>,
}

impl Sdn {
    /// The vnets and zones of a snapshot.
    pub fn of(snapshot: &Snapshot) -> Self {
        let vnets = snapshot
            .vnets
            .iter()
            .filter_map(|vnet| {
                let name = text(vnet, "vnet")?;
                let zone = text(vnet, "zone").map(str::to_owned);
                let tag = number(vnet, "tag").and_then(|n| u32::try_from(n).ok());
                Some((name.to_owned(), (zone, tag)))
            })
            .collect();
        let zones = snapshot
            .zones
            .iter()
            .filter_map(|zone| {
                Some((
                    text(zone, "zone")?.to_owned(),
                    text(zone, "type")?.to_owned(),
                ))
            })
            .collect();
        Self { vnets, zones }
    }

    /// The tags of an interface: its bridge or vnet, and its VLAN or VNI.
    fn tags(&self, nic: &Nic) -> Vec<String> {
        let mut tags = Vec::new();
        if let Some(bridge) = &nic.bridge {
            if let Some((zone, tag)) = self.vnets.get(bridge) {
                tags.push(format!("vnet:{bridge}"));
                let zone_type = zone.as_ref().and_then(|zone| self.zones.get(zone));
                match (zone_type.map(String::as_str), tag) {
                    (Some("vlan" | "qinq"), Some(tag)) if (1..=4094).contains(tag) => {
                        tags.push(format!("vlan:{tag}"));
                    }
                    (Some("vxlan" | "evpn"), Some(tag)) => tags.push(format!("vxlan:{tag}")),
                    _ => {}
                }
            } else {
                tags.push(format!("bridge:{bridge}"));
            }
        }
        if let Some(vlan) = nic.vlan {
            tags.push(format!("vlan:{vlan}"));
        }
        tags
    }
}

/// The host of a node.
pub fn node_host(node: &Node, snapshot: &Snapshot) -> ObservedHost {
    let mut ips: BTreeSet<IpAddr> = BTreeSet::new();
    for entry in &snapshot.cluster_status {
        if text(entry, "type") == Some("node") && text(entry, "name") == Some(node.name.as_str()) {
            ips.extend(text(entry, "ip").and_then(net::parse_address));
        }
    }
    for interface in snapshot
        .node_networks
        .get(&node.name)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if !truthy(interface, "active") {
            continue;
        }
        for key in ["address", "address6", "cidr", "cidr6"] {
            ips.extend(text(interface, key).and_then(net::parse_address));
        }
    }
    let mut tags = Vec::new();
    if let Some(status) = &node.status {
        tags.push(format!("status:{status}"));
    }
    ObservedHost {
        external_id: node.external_id(),
        name: Some(node.name.clone()),
        macs: Vec::new(),
        ips: ips.into_iter().filter(|ip| net::usable(*ip)).collect(),
        os: snapshot
            .version
            .as_deref()
            .map(|version| format!("Proxmox VE {version}")),
        platform: Some("proxmox-ve".to_owned()),
        parent: None,
        tags,
        power: None,
    }
}

/// The addresses that a list of live interfaces reports on the given MAC addresses. Reads
/// the guest agent form (`hardware-address`, `ip-addresses[].ip-address`) and the container
/// form (`hwaddr`, `inet`, `inet6` as text or list).
fn live_addresses(interfaces: &[Value], macs: &[MacAddr]) -> BTreeSet<IpAddr> {
    let mut ips = BTreeSet::new();
    for interface in interfaces {
        let mac = text(interface, "hardware-address")
            .or_else(|| text(interface, "hwaddr"))
            .and_then(net::parse_mac);
        if !mac.is_some_and(|mac| macs.contains(&mac)) {
            continue;
        }
        if let Some(Value::Array(addresses)) = interface.get("ip-addresses") {
            for address in addresses {
                ips.extend(text(address, "ip-address").and_then(net::parse_address));
            }
        }
        for key in ["inet", "inet6"] {
            match interface.get(key) {
                Some(Value::String(address)) => ips.extend(net::parse_address(address)),
                Some(Value::Array(list)) => {
                    ips.extend(
                        list.iter()
                            .filter_map(Value::as_str)
                            .filter_map(net::parse_address),
                    );
                }
                _ => {}
            }
        }
    }
    ips.retain(|ip| net::usable(*ip));
    ips
}

/// The host of a guest, from what the API answered about it (nothing but the resource
/// entry when `answers` is `None`).
pub fn guest_host(guest: &Guest, answers: Option<&GuestAnswers>, sdn: &Sdn) -> ObservedHost {
    let empty = Map::new();
    let config = answers
        .and_then(|answers| answers.config.as_ref())
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let nics = match guest.kind {
        Kind::Qemu => net::qemu_nics(config),
        Kind::Lxc => net::lxc_nics(config),
    };
    let mut macs: Vec<MacAddr> = nics.iter().filter_map(|nic| nic.mac).collect();
    macs.sort();
    macs.dedup();
    let live: Vec<Value> = match guest.kind {
        Kind::Qemu => answers
            .and_then(|answers| answers.agent.as_ref())
            .and_then(|agent| agent.get("result").or(Some(agent)))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Kind::Lxc => answers
            .and_then(|answers| answers.interfaces.as_ref())
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    let mut ips = live_addresses(&live, &macs);
    if ips.is_empty() {
        ips = nics
            .iter()
            .flat_map(|nic| nic.static_ips.iter().copied())
            .filter(|ip| net::usable(*ip))
            .collect();
    }
    let ostype = config.get("ostype").and_then(Value::as_str).unwrap_or("");
    let os = match guest.kind {
        Kind::Qemu => net::qemu_os(ostype),
        Kind::Lxc => net::lxc_os(ostype),
    };
    let mut tags = guest.tags.clone();
    if let Some(status) = &guest.status {
        tags.push(format!("status:{status}"));
    }
    if let Some(pool) = &guest.pool {
        tags.push(format!("pool:{pool}"));
    }
    if guest.template {
        tags.push("template".to_owned());
    }
    for nic in &nics {
        tags.extend(sdn.tags(nic));
    }
    let mut seen = BTreeSet::new();
    tags.retain(|tag| seen.insert(tag.clone()));
    ObservedHost {
        external_id: guest.external_id(),
        name: guest.name.clone(),
        macs,
        ips: ips.into_iter().collect(),
        os,
        platform: Some(guest.kind.as_str().to_owned()),
        parent: Some(format!("node/{}", guest.node)),
        tags,
        power: guest.power(),
    }
}

/// The hosts of one page: the nodes the filter keeps (when `with_nodes`), then the guests of
/// `page` with the answers the snapshot holds for them.
pub fn hosts(
    snapshot: &Snapshot,
    filter: &Filter,
    page: &[Guest],
    with_nodes: bool,
) -> Vec<ObservedHost> {
    let sdn = Sdn::of(snapshot);
    let mut hosts = Vec::with_capacity(page.len() + 4);
    if with_nodes {
        hosts.extend(
            nodes(&snapshot.resources, filter)
                .iter()
                .map(|node| node_host(node, snapshot)),
        );
    }
    hosts.extend(
        page.iter()
            .map(|guest| guest_host(guest, snapshot.guests.get(&guest.external_id()), &sdn)),
    );
    hosts
}

/// Every host of a snapshot in one page: the nodes and every guest the filter keeps.
pub fn build(snapshot: &Snapshot, filter: &Filter) -> Vec<ObservedHost> {
    let guests = guests(&snapshot.resources, filter);
    hosts(snapshot, filter, &guests, true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn snapshot() -> Snapshot {
        serde_json::from_value(json!({
            "version": "9.1.6",
            "resources": [
                {"type": "node", "node": "pve-a", "status": "online", "id": "node/pve-a"},
                {"type": "node", "node": "pve-b", "status": "offline", "id": "node/pve-b"},
                {"type": "qemu", "vmid": 101, "node": "pve-a", "name": "web01", "status": "running", "template": 0, "pool": "lab", "tags": "prod;web"},
                {"type": "lxc", "vmid": "102", "node": "pve-a", "name": "dns01", "status": "running"},
                {"type": "qemu", "vmid": 103, "node": "pve-b", "name": "old01", "status": "stopped"},
                {"type": "qemu", "vmid": 900, "node": "pve-a", "name": "tmpl", "status": "stopped", "template": 1},
                {"type": "storage", "node": "pve-a", "id": "storage/pve-a/local"},
                {"type": "qemu", "node": "pve-a", "name": "no-vmid"}
            ],
            "cluster_status": [
                {"type": "cluster", "name": "lab"},
                {"type": "node", "name": "pve-a", "ip": "192.0.2.2"}
            ],
            "node_networks": {
                "pve-a": [
                    {"iface": "vmbr0", "active": 1, "address": "192.0.2.2", "cidr": "192.0.2.2/24", "address6": "2001:db8::2"},
                    {"iface": "vmbr9", "address": "203.0.113.9"}
                ]
            },
            "guests": {
                "qemu/101": {
                    "config": {"ostype": "l26", "net0": "virtio=00:00:5E:00:53:01,bridge=vnet20", "net1": "virtio=00:00:5E:00:53:02,bridge=vmbr0,tag=30", "agent": "1"},
                    "agent": {"result": [
                        {"name": "lo", "hardware-address": "00:00:00:00:00:00", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}]},
                        {"name": "eth0", "hardware-address": "00:00:5e:00:53:01", "ip-addresses": [
                            {"ip-address": "198.51.100.10", "ip-address-type": "ipv4", "prefix": 24},
                            {"ip-address": "fe80::1", "ip-address-type": "ipv6", "prefix": 64}
                        ]},
                        {"name": "docker0", "hardware-address": "00:00:5e:00:53:99", "ip-addresses": [{"ip-address": "203.0.113.1", "ip-address-type": "ipv4", "prefix": 16}]}
                    ]}
                },
                "lxc/102": {
                    "config": {"ostype": "debian", "net0": "name=eth0,bridge=vmbr0,hwaddr=00:00:5E:00:53:11,ip=192.0.2.11/24,type=veth"},
                    "interfaces": [
                        {"name": "lo", "hwaddr": "00:00:00:00:00:00", "inet": "127.0.0.1/8"},
                        {"name": "eth0", "hwaddr": "00:00:5e:00:53:11", "inet": "192.0.2.11/24", "inet6": "2001:db8::11/64"}
                    ]
                }
            },
            "vnets": [{"vnet": "vnet20", "zone": "lan", "tag": 20}],
            "zones": [{"zone": "lan", "type": "vlan"}]
        }))
        .expect("snapshot")
    }

    #[test]
    fn nodes_and_guests_become_hosts() {
        let hosts = build(&snapshot(), &Filter::default());
        let ids: Vec<&str> = hosts.iter().map(|h| h.external_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "node/pve-a",
                "node/pve-b",
                "qemu/101",
                "lxc/102",
                "qemu/103"
            ]
        );
        let node = &hosts[0];
        assert_eq!(node.os.as_deref(), Some("Proxmox VE 9.1.6"));
        assert_eq!(
            node.ips,
            vec![
                "192.0.2.2".parse::<IpAddr>().expect("ip"),
                "2001:db8::2".parse().expect("ip")
            ]
        );
        assert_eq!(node.tags, ["status:online"]);
        assert_eq!(node.power, None, "a node has no power state");
        let vm = &hosts[2];
        assert_eq!(vm.power, Some(PowerState::Running));
        assert_eq!(vm.name.as_deref(), Some("web01"));
        assert_eq!(vm.macs.len(), 2);
        assert_eq!(vm.ips, vec!["198.51.100.10".parse::<IpAddr>().expect("ip")]);
        assert_eq!(vm.os.as_deref(), Some("Linux"));
        assert_eq!(vm.platform.as_deref(), Some("qemu"));
        assert_eq!(vm.parent.as_deref(), Some("node/pve-a"));
        assert_eq!(
            vm.tags,
            [
                "prod",
                "web",
                "status:running",
                "pool:lab",
                "vnet:vnet20",
                "vlan:20",
                "bridge:vmbr0",
                "vlan:30"
            ]
        );
        let ct = &hosts[3];
        assert_eq!(ct.os.as_deref(), Some("Linux (Debian)"));
        assert_eq!(
            ct.ips,
            vec![
                "192.0.2.11".parse::<IpAddr>().expect("ip"),
                "2001:db8::11".parse().expect("ip")
            ]
        );
        let stopped = &hosts[4];
        assert_eq!(stopped.macs.len(), 0, "no configuration was read");
        assert_eq!(stopped.tags, ["status:stopped"]);
        assert_eq!(stopped.power, Some(PowerState::Stopped));
        assert!(stopped.is_stopped());
    }

    #[test]
    fn filters_keep_nodes_pools_running_guests_and_templates() {
        let snapshot = snapshot();
        let ids = |filter: &Filter| -> Vec<String> {
            build(&snapshot, filter)
                .into_iter()
                .map(|h| h.external_id)
                .collect()
        };
        assert_eq!(
            ids(&Filter {
                nodes: vec!["pve-b".to_owned()],
                ..Filter::default()
            }),
            ["node/pve-b", "qemu/103"]
        );
        assert_eq!(
            ids(&Filter {
                pools: vec!["lab".to_owned()],
                ..Filter::default()
            }),
            ["node/pve-a", "node/pve-b", "qemu/101"]
        );
        assert_eq!(
            ids(&Filter {
                include_stopped: false,
                ..Filter::default()
            }),
            ["node/pve-a", "node/pve-b", "qemu/101", "lxc/102"]
        );
        let with_templates = ids(&Filter {
            include_templates: true,
            ..Filter::default()
        });
        assert!(with_templates.contains(&"qemu/900".to_owned()));
    }

    #[test]
    fn static_addresses_stand_in_when_nothing_live_answers() {
        let mut snapshot = snapshot();
        if let Some(answers) = snapshot.guests.get_mut("lxc/102") {
            answers.interfaces = None;
        }
        let hosts = build(&snapshot, &Filter::default());
        assert_eq!(
            hosts[3].ips,
            vec!["192.0.2.11".parse::<IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn odd_answers_degrade_instead_of_failing() {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "resources": [
                {"type": "qemu", "vmid": -1, "node": "a"},
                {"type": "qemu", "vmid": 5, "node": ""},
                {"type": "qemu", "vmid": 6, "node": "a", "tags": 7, "template": "yes"},
                "not an object",
                {"type": 7}
            ],
            "guests": {"qemu/6": {"config": [1, 2], "agent": {"result": "x"}}},
            "vnets": [{"vnet": 1}],
            "zones": [{}]
        }))
        .expect("snapshot");
        let hosts = build(&snapshot, &Filter::default());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].external_id, "qemu/6");
        assert_eq!(hosts[0].macs.len(), 0);
    }

    #[test]
    fn node_names_for_paths_are_checked() {
        assert!(safe_name("pve-a"));
        assert!(safe_name("node_1.lab"));
        assert!(!safe_name("../x"));
        assert!(!safe_name("a/b"));
        assert!(!safe_name(""));
        assert!(!safe_name(".hidden"));
    }
}
