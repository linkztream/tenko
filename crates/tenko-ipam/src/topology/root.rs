//! The root of the topology map (UI-Q10): the node the map is drawn from.
//!
//! Two sources name it, ranked:
//!
//! 1. **The controller's gateway**, when a network controller manages the gateway: the node a
//!    controller reports as a gateway (a router of the graph; only a controller makes one).
//! 2. **The node's default route**: the next hop of the default route of the host Tenko runs
//!    on, read from its routing table as the service account can ([`DefaultRoute`]); the
//!    node that holds that address, else the address alone.
//!
//! When both name a root and they are not the same node, the sources **disagree**: one
//! finding to review, "Topology root: sources disagree" (area topology), with "Use this" per
//! candidate. The choice is stored ([`super::stored::RootChoice`]) with the candidates on
//! offer; the map then follows the chosen source whenever it names a root, and the finding
//! stays away while the sources offer the same candidates. Without a choice the ranked
//! source decides. An access point is never a root candidate: only a gateway or the next hop
//! of the default route is.

use std::{collections::BTreeMap, future::Future, net::IpAddr, pin::Pin};

use serde::{Deserialize, Serialize};
use tenko_core::{Revision, Timestamp};
use utoipa::ToSchema;

use super::{
    build::CONTROLLER_SOURCE,
    model::{MapRoot, NodeKind, TopologyGraph, TopologyNode},
    stored::RootChoice,
};
use crate::findings::{
    Finding, FindingAction, FindingArea, FindingEvidence, FindingKind, FindingLevel, FindingSource,
    FindingSubject, SubjectKind, map::finding_id,
};

/// A source of the root.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RootSource {
    /// The gateway a network controller manages.
    Controller,
    /// The next hop of this node's default route.
    DefaultRoute,
}

impl RootSource {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RootSource::Controller => "controller",
            RootSource::DefaultRoute => "default_route",
        }
    }
}

/// One candidate for the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RootCandidate {
    /// The source that names it.
    pub source: RootSource,
    /// The node; absent when the next hop is an address no node holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The node's label, else the address.
    pub label: String,
    /// The address: the gateway's first address, or the next hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
}

impl RootCandidate {
    /// The key a choice remembers: `controller:<node>` or `route:<address>`.
    pub fn key(&self) -> String {
        match self.source {
            RootSource::Controller => format!(
                "controller:{}",
                self.node.as_deref().unwrap_or(self.label.as_str())
            ),
            RootSource::DefaultRoute => format!(
                "route:{}",
                self.ip
                    .map_or_else(|| self.label.clone(), |ip| ip.to_string())
            ),
        }
    }
}

/// The root of the map with its sources (`GET /topology/root`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RootDecision {
    /// The candidates, the ranked source first.
    pub candidates: Vec<RootCandidate>,
    /// The root the map is drawn from; absent when no source names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<MapRoot>,
    /// Whether the two sources name different roots.
    pub disagree: bool,
    /// The stored choice, when a person chose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice: Option<RootChoice>,
    /// Whether the sources disagree and no choice covers the candidates on offer: the
    /// finding is raised.
    pub open: bool,
    /// The store revision of the graph.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// Where the next hops of this node's default routes come from: the host's routing table,
/// read without privileges. An implementation answers the next hops ordered by preference
/// (IPv4 first, the lowest metric first), and an empty list when it cannot read them.
pub trait DefaultRoute: Send + Sync + std::fmt::Debug {
    /// The next hops of the default routes.
    fn next_hops(&self) -> Pin<Box<dyn Future<Output = Vec<IpAddr>> + Send + '_>>;
}

/// The gateway a controller manages: a router of the graph that a network controller
/// reports (only a controller makes a router). The first by label and identifier.
fn controller_candidate(graph: &TopologyGraph) -> Option<RootCandidate> {
    graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == NodeKind::Router
                && node
                    .sources
                    .iter()
                    .any(|source| source.starts_with(CONTROLLER_SOURCE))
        })
        .min_by(|a, b| (&a.label, &a.id).cmp(&(&b.label, &b.id)))
        .map(|node| RootCandidate {
            source: RootSource::Controller,
            node: Some(node.id.clone()),
            label: node.label.clone(),
            ip: node.ips.first().copied(),
        })
}

/// The next hop of the default route: the first hop a node holds, else the first hop.
fn route_candidate(graph: &TopologyGraph, hops: &[IpAddr]) -> Option<RootCandidate> {
    let holder = |hop: &IpAddr| -> Option<&TopologyNode> {
        graph
            .nodes
            .iter()
            .filter(|node| node.ips.contains(hop))
            // An access point is never the root, even when it routes.
            .filter(|node| node.kind != NodeKind::AccessPoint)
            .min_by(|a, b| (&a.label, &a.id).cmp(&(&b.label, &b.id)))
    };
    hops.iter()
        .find_map(|hop| {
            holder(hop).map(|node| RootCandidate {
                source: RootSource::DefaultRoute,
                node: Some(node.id.clone()),
                label: node.label.clone(),
                ip: Some(*hop),
            })
        })
        .or_else(|| {
            hops.first().map(|hop| RootCandidate {
                source: RootSource::DefaultRoute,
                node: None,
                label: hop.to_string(),
                ip: Some(*hop),
            })
        })
}

/// Decides the root of `graph` from the sources, the next hops of the default routes and
/// the stored choice.
pub fn decide(graph: &TopologyGraph, hops: &[IpAddr], choice: Option<&RootChoice>) -> RootDecision {
    let candidates: Vec<RootCandidate> =
        [controller_candidate(graph), route_candidate(graph, hops)]
            .into_iter()
            .flatten()
            .collect();
    let disagree = candidates.len() == 2 && candidates[0].node != candidates[1].node;
    let mut keys: Vec<String> = candidates.iter().map(RootCandidate::key).collect();
    keys.sort();
    let chosen = choice.and_then(|choice| {
        candidates
            .iter()
            .find(|candidate| candidate.source == choice.source)
    });
    let root = match chosen {
        Some(candidate) => Some(MapRoot {
            node: candidate.node.clone(),
            source: candidate.source,
            chosen: true,
        }),
        None => candidates.first().map(|candidate| MapRoot {
            node: candidate.node.clone(),
            source: candidate.source,
            chosen: false,
        }),
    };
    let open = disagree && choice.is_none_or(|choice| choice.offered != keys);
    RootDecision {
        candidates,
        root,
        disagree,
        choice: choice.cloned(),
        open,
        revision: graph.revision,
    }
}

/// The code of the root finding.
pub const ROOT_CODE: &str = "ipam.topology.root_disagree";

/// The finding of an open disagreement: "Topology root: sources disagree", to review, with
/// "Use this" per candidate. Its identifier stays the same while the candidates do.
pub fn finding(decision: &RootDecision, now: Timestamp) -> Option<Finding> {
    if !decision.open {
        return None;
    }
    let mut keys: Vec<String> = decision.candidates.iter().map(RootCandidate::key).collect();
    keys.sort();
    let mut params = BTreeMap::new();
    for candidate in &decision.candidates {
        let prefix = candidate.source.as_str();
        params.insert(format!("{prefix}_label"), candidate.label.clone());
        if let Some(node) = &candidate.node {
            params.insert(format!("{prefix}_node"), node.clone());
        }
        if let Some(ip) = candidate.ip {
            params.insert(format!("{prefix}_ip"), ip.to_string());
        }
    }
    let label = decision
        .candidates
        .iter()
        .map(|candidate| candidate.label.as_str())
        .collect::<Vec<_>>()
        .join(" / ");
    Some(Finding {
        id: finding_id(
            FindingSource::Topology,
            &format!("root:{}", super::wlan::digest(&keys.join("|"))),
        ),
        kind: FindingKind::TopologyRoot,
        severity: FindingLevel::Review,
        area: FindingArea::Topology,
        subject: FindingSubject::new(SubjectKind::Node, label.clone()),
        summary: format!(
            "Topology root: the sources disagree ({label}); choose the one the map is drawn from"
        ),
        code: ROOT_CODE.to_owned(),
        params,
        evidence: FindingEvidence {
            id: "root".to_owned(),
            path: "/topology/root".to_owned(),
        },
        action: FindingAction::UseRoot,
        since: now,
        source: FindingSource::Topology,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: NodeKind, ip: &str) -> TopologyNode {
        TopologyNode {
            id: id.to_owned(),
            kind,
            label: id.to_owned(),
            macs: Vec::new(),
            ips: vec![ip.parse().expect("ip")],
            vendor: None,
            model: None,
            os: None,
            host: None,
            subject: None,
            vlans: Vec::new(),
            prefixes: Vec::new(),
            site: None,
            ssids: Vec::new(),
            sources: vec!["network_controller:x".to_owned()],
            last_seen: None,
        }
    }

    #[test]
    fn an_access_point_is_never_a_root_candidate() {
        let graph = TopologyGraph {
            nodes: vec![
                node("ap", NodeKind::AccessPoint, "192.0.2.3"),
                node("gw", NodeKind::Router, "192.0.2.1"),
            ],
            ..TopologyGraph::default()
        };
        let hop: IpAddr = "192.0.2.3".parse().expect("ip");
        let decision = decide(&graph, &[hop], None);
        let route = decision
            .candidates
            .iter()
            .find(|c| c.source == RootSource::DefaultRoute)
            .expect("route");
        assert_eq!(
            route.node, None,
            "the access point that holds the hop is no candidate"
        );
        assert_eq!(route.label, "192.0.2.3");
        assert!(decision.disagree && decision.open);
        assert_eq!(
            decision.root.and_then(|root| root.node).as_deref(),
            Some("gw"),
            "the ranked source draws the map"
        );
        assert!(finding(&decide(&graph, &[], None), Timestamp::now()).is_none());
    }
}
