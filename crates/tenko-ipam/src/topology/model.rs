//! The shapes of the topology graph (IPAM-20): nodes, edges, the summary, the filter and
//! the view of one node with its ports and neighbours.

use std::{collections::BTreeMap, net::IpAddr};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, ConnectorId, HostId, MacAddr, PrefixId, Revision, SiteId, Timestamp, VlanId,
    ipam::AssignmentMode,
};
use utoipa::ToSchema;

use crate::vlan::controllers::ControllerNetwork;

/// What a node is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// A router or gateway.
    Router,
    /// A switch.
    Switch,
    /// A wireless access point.
    AccessPoint,
    /// A hypervisor: the parent of virtual machines or containers.
    Hypervisor,
    /// A virtual machine.
    Vm,
    /// A container.
    Container,
    /// A host or client.
    Host,
    /// A network device that no source classifies, such as an LLDP neighbour.
    Device,
}

impl NodeKind {
    /// Every kind, in the order of the summary.
    pub const ALL: [NodeKind; 8] = [
        NodeKind::Router,
        NodeKind::Switch,
        NodeKind::AccessPoint,
        NodeKind::Hypervisor,
        NodeKind::Vm,
        NodeKind::Container,
        NodeKind::Host,
        NodeKind::Device,
    ];

    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeKind::Router => "router",
            NodeKind::Switch => "switch",
            NodeKind::AccessPoint => "access_point",
            NodeKind::Hypervisor => "hypervisor",
            NodeKind::Vm => "vm",
            NodeKind::Container => "container",
            NodeKind::Host => "host",
            NodeKind::Device => "device",
        }
    }

    /// The kind with this name.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }

    /// Whether the kind forwards traffic for others (the backbone of the map).
    pub const fn is_infrastructure(self) -> bool {
        matches!(
            self,
            NodeKind::Router | NodeKind::Switch | NodeKind::AccessPoint | NodeKind::Device
        )
    }
}

/// What an edge is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A client on a switch port (a bridge table or a controller's port table).
    Wired,
    /// A client associated with an access point.
    Wireless,
    /// An LLDP neighbourship between two devices.
    Lldp,
    /// An uplink a network controller reports.
    Uplink,
    /// A virtual machine or container on its hypervisor.
    VmHost,
}

impl EdgeKind {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Wired => "wired",
            EdgeKind::Wireless => "wireless",
            EdgeKind::Lldp => "lldp",
            EdgeKind::Uplink => "uplink",
            EdgeKind::VmHost => "vm_host",
        }
    }
}

/// A node of the graph: one device as every source sees it, with the intent joined in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologyNode {
    /// Stable identifier: `h-` and the host for a device of intent, `c-` for a device of a
    /// network controller, `i-` for an inventory host, `m-` and the MAC address, `n-` for a
    /// device named by a probe, `a-` for an address.
    pub id: String,
    /// What it is.
    pub kind: NodeKind,
    /// The best name: the host of intent, the controller's name, the inventory name, a
    /// probe's name, the vendor with the MAC address, the MAC or IP address.
    pub label: String,
    /// MAC addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macs: Vec<MacAddr>,
    /// IP addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub ips: Vec<IpAddr>,
    /// The vendor of the first MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// The model a controller reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The operating system an inventory or probe reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// The host of intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// The subject to look the node up across sources (`GET /observations/{subject}`): its
    /// first MAC address, else its first IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// VLAN ids the node is in: client attachments, the VLANs of its networks, the
    /// untagged VLANs of its ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vlans: Vec<u16>,
    /// The most specific networks of intent that hold its addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<PrefixId>,
    /// The site: the host's, else its network's, else its VLAN's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
    /// Wireless networks an access point broadcasts or a client uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssids: Vec<String>,
    /// Source keys of the facts behind the node (`intent` for a host of intent).
    pub sources: Vec<String>,
    /// The latest sighting of any of its facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
}

/// An edge of the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologyEdge {
    /// Stable identifier, from the kind, the ends and their ports.
    pub id: String,
    /// What it is.
    pub kind: EdgeKind,
    /// One end: the switch, access point or hypervisor for client edges.
    pub a: String,
    /// The port at `a`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a_port: Option<String>,
    /// The other end.
    pub b: String,
    /// The port at `b`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b_port: Option<String>,
    /// The VLAN of a client edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// The wireless network of a wireless edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// Source keys of the facts behind the edge.
    pub sources: Vec<String>,
    /// Whether the edge is only inferred from a MAC table (a bridge table of a probe): a
    /// client edge no network controller reports. A MAC address learned on a port says that
    /// the device is somewhere behind it, not that it hangs on it; the map draws such an
    /// edge dashed with a question mark.
    #[serde(default)]
    pub inferred: bool,
}

/// One VLAN in view, for the legend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanInView {
    /// The VLAN id.
    pub vid: u16,
    /// The VLAN object of intent, when one exists (at the node's site or global).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Nodes in it.
    pub nodes: usize,
}

/// How a network controller contributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ControllerStatus {
    /// The connector instance.
    pub connector: ConnectorId,
    /// Its name.
    pub name: String,
    /// When its devices were read; absent when they never were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
    /// Managed devices it reported.
    pub devices: usize,
    /// Whether writes through it are allowed (TGL-20); the map offers no write action under
    /// Hardened while no controller allows them.
    #[serde(default)]
    pub writes_enabled: bool,
    /// Why the last read failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CodedError>,
}

/// A network of a controller with the VLAN it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NetworkInView {
    /// The controller.
    pub connector: ConnectorId,
    /// The network.
    #[serde(flatten)]
    pub network: ControllerNetwork,
}

/// Counts and context of a graph.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologySummary {
    /// Nodes in the answer.
    pub nodes: usize,
    /// Edges in the answer.
    pub edges: usize,
    /// Nodes of the whole graph before filtering.
    pub total_nodes: usize,
    /// Edges of the whole graph before filtering.
    pub total_edges: usize,
    /// Nodes in the answer per kind.
    pub by_kind: BTreeMap<String, usize>,
    /// Edges in the answer per kind.
    pub by_edge_kind: BTreeMap<String, usize>,
    /// The VLANs of the nodes in the answer, by VLAN id.
    pub vlans: Vec<VlanInView>,
    /// The sites of the nodes in the answer.
    pub sites: Vec<SiteId>,
    /// The network controllers and how their last read went.
    pub controllers: Vec<ControllerStatus>,
    /// The networks the controllers report, with their VLANs.
    pub networks: Vec<NetworkInView>,
    /// When the graph was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<Timestamp>,
    /// Whether the answer was cut at the node limit.
    #[serde(default)]
    pub truncated: bool,
    /// The root the map is drawn from (UI-Q10); absent when no source names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<MapRoot>,
}

/// The node the map is drawn from and why (UI-Q10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MapRoot {
    /// The node; absent when the source names an address no node has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The source that names it.
    pub source: super::root::RootSource,
    /// Whether a person chose it ("Use this").
    #[serde(default)]
    pub chosen: bool,
}

/// The graph: nodes, edges and a summary, computed from one store revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologyGraph {
    /// Nodes, by identifier.
    pub nodes: Vec<TopologyNode>,
    /// Edges, by identifier.
    pub edges: Vec<TopologyEdge>,
    /// Counts and context.
    pub summary: TopologySummary,
    /// The store revision the graph was computed from.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// What `GET /topology` keeps. Every member is optional; the members combine with AND.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyFilter {
    /// Nodes of this site.
    pub site: Option<SiteId>,
    /// Nodes in this VLAN.
    pub vlan: Option<u16>,
    /// Nodes with an address inside this network.
    pub within: Option<ipnet::IpNet>,
    /// Nodes of these kinds; when set, neighbours of other kinds are not added.
    pub kinds: Vec<NodeKind>,
    /// Case-insensitive text over the label, MAC and IP addresses, vendor and model.
    pub q: Option<String>,
    /// The most nodes to return.
    pub limit: Option<usize>,
}

impl TopologyFilter {
    /// Whether the filter keeps everything.
    pub fn is_empty(&self) -> bool {
        self.site.is_none()
            && self.vlan.is_none()
            && self.within.is_none()
            && self.kinds.is_empty()
            && self.q.as_deref().is_none_or(|q| q.trim().is_empty())
    }
}

/// A neighbour of a node across one edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Neighbour {
    /// The neighbour.
    pub node: String,
    /// Its label.
    pub label: String,
    /// Its kind.
    pub kind: NodeKind,
    /// The edge.
    pub edge: String,
    /// The kind of the edge.
    pub edge_kind: EdgeKind,
    /// The port on this node's side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// The port on the neighbour's side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<String>,
    /// The VLAN of the edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// The wireless network of the edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// Whether the edge is only inferred from a MAC table ([`TopologyEdge::inferred`]).
    #[serde(default)]
    pub inferred: bool,
}

/// A port of a node and what hangs on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologyPort {
    /// The port as the sources name it.
    pub port: String,
    /// The controller's name of the port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the controller marks it as an uplink.
    #[serde(default)]
    pub uplink: bool,
    /// The untagged VLAN the controller reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_vlan: Option<u16>,
    /// Link state, when a controller reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,
    /// Everything seen behind the port.
    pub neighbours: Vec<Neighbour>,
}

/// An address of intent on a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntentAddress {
    /// The address.
    #[schema(value_type = String)]
    pub ip: IpAddr,
    /// Its network.
    pub prefix: PrefixId,
    /// The network.
    #[schema(value_type = String)]
    pub cidr: ipnet::IpNet,
    /// The VLAN of the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// The VLAN id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vid: Option<u16>,
}

/// The intent behind a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeIntent {
    /// The host.
    pub host: HostId,
    /// Its name.
    pub name: String,
    /// Its assignment mode.
    pub mode: AssignmentMode,
    /// Its live addresses.
    pub addresses: Vec<IntentAddress>,
}

/// One node with its ports, neighbours and intent (`GET /topology/nodes/{id}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopologyNodeView {
    /// The node.
    pub node: TopologyNode,
    /// Its ports with what hangs on each; with `port`, only that port.
    pub ports: Vec<TopologyPort>,
    /// Every neighbour, also those across edges without a port on this side.
    pub neighbours: Vec<Neighbour>,
    /// The host of intent, when the node is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<NodeIntent>,
    /// The store revision of the graph.
    #[schema(value_type = u64)]
    pub revision: Revision,
}
