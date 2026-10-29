//! The topology map (IPAM-20): a computed, source-agnostic graph of routers, switches,
//! access points, hypervisors, virtual machines, containers and hosts, with wired ports,
//! wireless associations, LLDP links, uplinks and virtual machine placement as edges, and
//! the intent (hosts, interfaces, addresses, networks, VLANs) joined in.
//!
//! The graph is never stored: [`build::build`] computes it from one read view (the facts of
//! the observation layer and the live intent) and the device tables of the network
//! controllers, and [`TopologyService`] keeps the result per store revision. `docs/topology.md`
//! describes the model for operators.
//!
//! | Module | Contents |
//! |---|---|
//! | [`model`] | nodes, edges, the summary, the filter, the view of one node |
//! | [`build`] | the computation: aliases joined by facts and intent, nodes, edges |
//! | [`filter`] | filters with their context, the summary counts, ports and neighbours |
//! | [`root`] | the root of the map from the ranked sources (UI-Q10) and its finding |
//! | [`wlan`] | the SSID view and the two WLAN rules with their findings |
//! | [`stored`] | what a person decided: the root, the SSID policies, the WLAN exceptions |
//! | [`service`] | [`TopologyService`]: the cached graph and the controllers' device tables |

pub mod build;
pub mod filter;
pub mod model;
pub mod root;
pub mod service;
pub mod stored;
pub mod wlan;

pub use model::{
    EdgeKind, MapRoot, Neighbour, NodeIntent, NodeKind, TopologyEdge, TopologyFilter,
    TopologyGraph, TopologyNode, TopologyNodeView, TopologyPort, TopologySummary,
};
pub use root::{DefaultRoute, RootCandidate, RootDecision, RootSource};
pub use service::{TopologyConfig, TopologyService, codes};
pub use stored::{RootChoice, StoredWlanPolicy, WlanException, WlanPolicy};
pub use wlan::{SsidClient, SsidEntry, SsidPrefix, SsidView, SsidVlan};
