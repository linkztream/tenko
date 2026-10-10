//! Filtering the graph, its summary, and the view of one node.
//!
//! A filter keeps the nodes that match every given member (site, VLAN, network, kinds,
//! text). Without a kind filter it adds the context that makes the answer readable: the
//! switches, access points, routers and other network devices next to a kept node, and
//! the network devices that connect those (every network device reachable from them over
//! links between network devices). Edges are kept when both ends are.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use tenko_core::ipam::Vlan;

use super::{
    build::{Computed, within},
    model::{
        Neighbour, NodeKind, TopologyEdge, TopologyFilter, TopologyGraph, TopologyNode,
        TopologyPort, VlanInView,
    },
};

/// The default node limit of an answer.
pub const DEFAULT_LIMIT: usize = 5_000;
/// The largest node limit a caller may ask for.
pub const MAX_LIMIT: usize = 20_000;

fn matches(node: &TopologyNode, filter: &TopologyFilter) -> bool {
    if filter.site.is_some_and(|site| node.site != Some(site)) {
        return false;
    }
    if filter.vlan.is_some_and(|vid| !node.vlans.contains(&vid)) {
        return false;
    }
    if let Some(net) = &filter.within
        && !node.ips.iter().any(|ip| within(net, *ip))
    {
        return false;
    }
    if !filter.kinds.is_empty() && !filter.kinds.contains(&node.kind) {
        return false;
    }
    if let Some(q) = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        let q = q.to_lowercase();
        let hit = node.label.to_lowercase().contains(&q)
            || node.macs.iter().any(|mac| mac.to_string().contains(&q))
            || node.ips.iter().any(|ip| ip.to_string().contains(&q))
            || node
                .vendor
                .as_deref()
                .is_some_and(|v| v.to_lowercase().contains(&q))
            || node
                .model
                .as_deref()
                .is_some_and(|m| m.to_lowercase().contains(&q))
            || node.ssids.iter().any(|s| s.to_lowercase().contains(&q));
        if !hit {
            return false;
        }
    }
    true
}

/// The neighbours of every node, by node identifier: (edge position, other node).
fn adjacency(edges: &[TopologyEdge]) -> HashMap<&str, Vec<(usize, &str)>> {
    let mut map: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();
    for (position, edge) in edges.iter().enumerate() {
        map.entry(edge.a.as_str())
            .or_default()
            .push((position, edge.b.as_str()));
        map.entry(edge.b.as_str())
            .or_default()
            .push((position, edge.a.as_str()));
    }
    map
}

/// Applies a filter to the whole graph.
pub fn apply(computed: &Computed, filter: &TopologyFilter, vlans: &[Vlan]) -> TopologyGraph {
    let graph = &computed.graph;
    let limit = filter.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut keep: BTreeSet<&str> = BTreeSet::new();
    if filter.is_empty() {
        keep.extend(graph.nodes.iter().map(|n| n.id.as_str()));
    } else {
        let kind_of: HashMap<&str, NodeKind> = graph
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n.kind))
            .collect();
        let infrastructure = |id: &str| kind_of.get(id).is_some_and(|k| k.is_infrastructure());
        // A hypervisor is the context of its virtual machines and containers.
        let context = |id: &str| {
            kind_of
                .get(id)
                .is_some_and(|k| k.is_infrastructure() || *k == NodeKind::Hypervisor)
        };
        keep.extend(
            graph
                .nodes
                .iter()
                .filter(|n| matches(n, filter))
                .map(|n| n.id.as_str()),
        );
        if filter.kinds.is_empty() {
            let adjacent = adjacency(&graph.edges);
            let mut queue: VecDeque<&str> = VecDeque::new();
            for id in keep.clone() {
                for &(_, other) in adjacent.get(id).map(Vec::as_slice).unwrap_or_default() {
                    if context(other) && keep.insert(other) {
                        queue.push_back(other);
                    }
                }
                if context(id) {
                    queue.push_back(id);
                }
            }
            // The backbone: network devices reachable over links between network devices.
            while let Some(id) = queue.pop_front() {
                for &(_, other) in adjacent.get(id).map(Vec::as_slice).unwrap_or_default() {
                    if infrastructure(other) && keep.insert(other) {
                        queue.push_back(other);
                    }
                }
            }
        }
    }
    let mut truncated = false;
    if keep.len() > limit {
        truncated = true;
        // Network devices first, so the backbone survives the cut.
        let mut ordered: Vec<&TopologyNode> = graph
            .nodes
            .iter()
            .filter(|n| keep.contains(n.id.as_str()))
            .collect();
        ordered.sort_by_key(|n| (!n.kind.is_infrastructure(), n.id.as_str()));
        keep = ordered
            .into_iter()
            .take(limit)
            .map(|n| n.id.as_str())
            .collect();
    }
    let nodes: Vec<TopologyNode> = graph
        .nodes
        .iter()
        .filter(|n| keep.contains(n.id.as_str()))
        .cloned()
        .collect();
    let edges: Vec<TopologyEdge> = graph
        .edges
        .iter()
        .filter(|e| keep.contains(e.a.as_str()) && keep.contains(e.b.as_str()))
        .cloned()
        .collect();
    let mut answer = TopologyGraph {
        nodes,
        edges,
        summary: graph.summary.clone(),
        revision: graph.revision,
    };
    answer.summary.truncated = truncated;
    summarize(&mut answer, vlans);
    answer
}

/// Fills the counts of a graph's summary from its nodes and edges: per kind, per edge
/// kind, the VLANs with their names from intent, and the sites.
pub fn summarize(graph: &mut TopologyGraph, vlans: &[Vlan]) {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut vlan_counts: BTreeMap<u16, usize> = BTreeMap::new();
    let mut sites = BTreeSet::new();
    for node in &graph.nodes {
        *by_kind.entry(node.kind.as_str().to_owned()).or_default() += 1;
        for vid in &node.vlans {
            *vlan_counts.entry(*vid).or_default() += 1;
        }
        if let Some(site) = node.site {
            sites.insert(site);
        }
    }
    let mut by_edge_kind: BTreeMap<String, usize> = BTreeMap::new();
    for edge in &graph.edges {
        *by_edge_kind
            .entry(edge.kind.as_str().to_owned())
            .or_default() += 1;
    }
    graph.summary.nodes = graph.nodes.len();
    graph.summary.edges = graph.edges.len();
    graph.summary.by_kind = by_kind;
    graph.summary.by_edge_kind = by_edge_kind;
    graph.summary.sites = sites.into_iter().collect();
    graph.summary.vlans = vlan_counts
        .into_iter()
        .map(|(vid, nodes)| {
            // A global VLAN names the id when one exists, else the first by name.
            let mut candidates: Vec<&Vlan> = vlans.iter().filter(|v| v.vid == vid).collect();
            candidates
                .sort_by(|a, b| (a.site.is_some(), &a.name).cmp(&(b.site.is_some(), &b.name)));
            let vlan = candidates.first();
            VlanInView {
                vid,
                vlan: vlan.map(|v| v.id),
                name: vlan.map(|v| v.name.clone()),
                nodes,
            }
        })
        .collect();
}

/// The neighbours of a node across every edge, ordered by port and label.
pub fn neighbours(computed: &Computed, id: &str) -> Vec<Neighbour> {
    let graph = &computed.graph;
    let mut out: Vec<Neighbour> = graph
        .edges
        .iter()
        .filter_map(|edge| {
            let (other, port, remote_port) = if edge.a == id {
                (&edge.b, &edge.a_port, &edge.b_port)
            } else if edge.b == id {
                (&edge.a, &edge.b_port, &edge.a_port)
            } else {
                return None;
            };
            let node = computed
                .index
                .get(other.as_str())
                .and_then(|&position| graph.nodes.get(position))?;
            Some(Neighbour {
                node: node.id.clone(),
                label: node.label.clone(),
                kind: node.kind,
                edge: edge.id.clone(),
                edge_kind: edge.kind,
                port: port.clone(),
                remote_port: remote_port.clone(),
                vlan: edge.vlan,
                ssid: edge.ssid.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        (port_order(a.port.as_deref()), &a.label, &a.node).cmp(&(
            port_order(b.port.as_deref()),
            &b.label,
            &b.node,
        ))
    });
    out
}

/// Ports order numerically where they are numbers, else by text; a missing port last.
fn port_order(port: Option<&str>) -> (u8, u64, String) {
    match port {
        None => (2, 0, String::new()),
        Some(text) => match text.parse::<u64>() {
            Ok(number) => (0, number, String::new()),
            Err(_) => (1, 0, text.to_owned()),
        },
    }
}

/// The ports of a node: the controller's port table (with what hangs on each port) and
/// every port its edges name; with `only`, that port alone.
pub fn ports(computed: &Computed, id: &str, only: Option<&str>) -> Vec<TopologyPort> {
    let mut ports: BTreeMap<(u8, u64, String), TopologyPort> = BTreeMap::new();
    if let Some(table) = computed.ports.get(id) {
        for port in table {
            let key = port.index.to_string();
            ports.insert(
                port_order(Some(&key)),
                TopologyPort {
                    port: key,
                    name: port.name.clone(),
                    uplink: port.uplink,
                    native_vlan: port.native_vlan,
                    up: Some(port.up),
                    neighbours: Vec::new(),
                },
            );
        }
    }
    for neighbour in neighbours(computed, id) {
        let Some(port) = neighbour.port.clone() else {
            continue;
        };
        ports
            .entry(port_order(Some(&port)))
            .or_insert_with(|| TopologyPort {
                port: port.clone(),
                name: None,
                uplink: false,
                native_vlan: None,
                up: None,
                neighbours: Vec::new(),
            })
            .neighbours
            .push(neighbour);
    }
    ports
        .into_values()
        .filter(|port| {
            only.is_none_or(|only| {
                port.port == only || port.name.as_deref().is_some_and(|name| name == only)
            })
        })
        .collect()
}
