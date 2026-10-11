//! The topology map: a computed graph of the network, read-only.
//!
//! Area: topology. Owner: WP2.7. Requirements: IPAM-20, CONN-05, CONN-18.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /topology` | 200 [`TopologyGraph`] | 400 `sys.invalid_query`, 403, 404 (a named VLAN or prefix), 503 |
//! | `GET /topology/nodes/{id}` | 200 [`TopologyNodeView`] | 400, 403, 404 `ipam.topology.not_found`, 503 |
//!
//! The graph is computed from the observation layer (attachments, LLDP links, uplinks,
//! wireless associations, inventory hosts with their hypervisor), the device tables of the
//! network controllers (names, kinds, port tables, SSIDs) and the intent (hosts,
//! interfaces, addresses, networks, VLANs); it is never stored. Nodes and edges have
//! stable identifiers. `docs/topology.md` describes the model; `tenko_ipam::topology`
//! the computation.
//!
//! # Filters
//!
//! `GET /topology` takes `site` (a site identifier), `vlan` (a VLAN id, 1 to 4094, or a
//! VLAN identifier), `prefix` (a prefix identifier) or `within` (a network), `kind`
//! (`router`, `switch`, `access_point`, `hypervisor`, `vm`, `container`, `host`, `device`;
//! repeat or separate with commas), `q` (text over the label, MAC and IP addresses,
//! vendor, model and SSIDs) and `limit` (the most nodes, 1 to 20,000, default 5,000). The
//! members combine with AND. Without `kind`, the answer adds the context of the kept nodes:
//! the network devices and hypervisors next to them and the network devices that connect
//! those. `summary.truncated` says when the limit cut the answer (network devices are kept
//! first). `at_least` reads at least at a store revision.
//!
//! # One node
//!
//! `GET /topology/nodes/{id}` answers the node with its ports (the controller's port
//! table and every port its edges name) and what hangs on each port, every neighbour, and
//! the host of intent with its addresses. `port` keeps one port: "what is connected to
//! this port"; it matches the port as the sources name it or the controller's port name.
//!
//! The server adds the topology service (`Arc<tenko_ipam::topology::TopologyService>`) as
//! a request extension; without it both endpoints answer 503 `ipam.topology.unavailable`.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, both endpoints need
//! [`Action::Read`] on observations. A principal whose grants cover only some prefixes or
//! sites (IAM-01) sees the nodes of its readable hosts and of addresses in its readable
//! prefixes, the edges between two such nodes, a summary counted over them, and no
//! controller status or controller networks; network devices that no intent anchors are
//! seen with a global reach only. One node outside the scope answers 403
//! `auth.out_of_scope`.

use std::sync::Arc;

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use tenko_core::{
    Action, CodedError, ObjectKind, PrefixId, Revision, SiteId, VlanId,
    ipam::{Prefix, Vlan},
};
use tenko_ipam::{
    query,
    topology::{
        NodeKind, TopologyFilter, TopologyGraph, TopologyNode, TopologyNodeView, TopologyService,
        codes,
        filter::{MAX_LIMIT, summarize},
        model::VlanInView,
    },
};
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{Ipam, IpamHandle, IpamPath, ReadScope, authorize, new_of};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area.
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_topology))
        .routes(routes!(get_topology_node))
}

/// The topology service of the request, from the `Arc<TopologyService>` extension; 503
/// `ipam.topology.unavailable` when the server did not add one.
pub(crate) struct Topology(pub(crate) Arc<TopologyService>);

impl<S: Send + Sync> FromRequestParts<S> for Topology {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Arc<TopologyService>>()
                .cloned()
                .map(Topology)
                .ok_or_else(|| {
                    ApiError::from_coded_error(
                        CodedError::new(
                            codes::UNAVAILABLE,
                            503,
                            "the topology is not configured on this server",
                        )
                        .with_title("Service unavailable"),
                    )
                }),
        )
    }
}

/// The query of `GET /topology` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct TopologyParams {
    /// Nodes of this site (identifier).
    site: Option<String>,
    /// Nodes in this VLAN: a VLAN id (1 to 4094) or a VLAN identifier.
    vlan: Option<String>,
    /// Nodes with an address in this prefix (identifier).
    prefix: Option<String>,
    /// Nodes with an address inside this network, such as `192.0.2.0/24`.
    within: Option<String>,
    /// Nodes of these kinds: `router`, `switch`, `access_point`, `hypervisor`, `vm`,
    /// `container`, `host`, `device`; repeat the parameter or separate with commas.
    kind: Option<Vec<String>>,
    /// Case-insensitive text over the label, MAC and IP addresses, vendor, model and SSIDs.
    q: Option<String>,
    /// The most nodes to return, 1 to 20,000; 5,000 when absent.
    limit: Option<u32>,
    /// Read at least at this store revision.
    at_least: Option<u64>,
}

/// The query of `GET /topology/nodes/{id}` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct NodeParams {
    /// Only this port: what is connected to it.
    port: Option<String>,
    /// Read at least at this store revision.
    at_least: Option<u64>,
}

/// Reads the filter of `GET /topology`, resolving a named VLAN or prefix from the view.
async fn filter_of(
    filters: &Filters,
    ipam: &tenko_ipam::IpamService,
    at_least: Option<Revision>,
) -> Result<TopologyFilter, ApiError> {
    let kinds = filters
        .all("kind")
        .into_iter()
        .map(|name| {
            NodeKind::parse(&name.to_ascii_lowercase()).ok_or_else(|| {
                ApiError::invalid_query(
                    "kind",
                    format!(
                        "`{name}` is not a node kind; allowed: {}",
                        NodeKind::ALL.map(NodeKind::as_str).join(", ")
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let limit = match filters.parse::<usize>("limit")? {
        Some(limit) if (1..=MAX_LIMIT).contains(&limit) => Some(limit),
        Some(limit) => {
            return Err(ApiError::invalid_query(
                "limit",
                format!("{limit} is outside 1 to {MAX_LIMIT}"),
            ));
        }
        None => None,
    };
    let vlan = match filters.get("vlan")? {
        None => None,
        Some(raw) => match raw.parse::<u16>() {
            Ok(vid) if (1..=4094).contains(&vid) => Some(vid),
            Ok(vid) => {
                return Err(ApiError::invalid_query(
                    "vlan",
                    format!("{vid} is outside 1 to 4094"),
                ));
            }
            Err(_) => {
                let id: VlanId = raw.parse().map_err(|_| {
                    ApiError::invalid_query("vlan", "not a VLAN id or a VLAN identifier")
                })?;
                let view = ipam.view(at_least).await?;
                Some(query::get::<Vlan>(view.as_ref(), id)?.vid)
            }
        },
    };
    let mut within = filters.cidr("within")?;
    if let Some(prefix) = filters.parse::<PrefixId>("prefix")? {
        if within.is_some() {
            return Err(ApiError::invalid_query(
                "prefix",
                "give either `prefix` or `within`",
            ));
        }
        let view = ipam.view(at_least).await?;
        within = Some(query::get::<Prefix>(view.as_ref(), prefix)?.cidr);
    }
    Ok(TopologyFilter {
        site: filters.parse::<SiteId>("site")?,
        vlan,
        within,
        kinds,
        q: filters.get("q")?.map(str::to_owned),
        limit,
    })
}

/// The topology graph, filtered.
#[utoipa::path(
    get,
    path = "/topology",
    tag = "topology",
    operation_id = "get_topology",
    summary = "Get the topology graph",
    params(TopologyParams),
    responses(
        (status = 200, description = "Nodes, edges and a summary", body = TopologyGraph),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The named VLAN or prefix does not exist (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured (`ipam.unavailable`, `ipam.topology.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_topology(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    Topology(topology): Topology,
    filters: Filters,
) -> Result<Json<TopologyGraph>, ApiError> {
    filters.only(&[
        "site", "vlan", "prefix", "within", "kind", "q", "limit", "at_least",
    ])?;
    // Not `filters.page()`: its `limit` is the page size of lists (at most 1,000), while the
    // node limit of the graph goes up to 20,000.
    let at_least = filters.parse::<u64>("at_least")?.map(Revision);
    authorize(&app, &cx, Action::Read, new_of(ObjectKind::Observation))?;
    let filter = filter_of(&filters, &ipam, at_least).await?;
    let graph = topology
        .graph(&filter, at_least, cx.principal.user())
        .await?;
    Ok(Json(match NodeScope::of(&ipam, &cx) {
        Some(scope) => scope.narrow(graph),
        None => graph,
    }))
}

/// What of the topology a principal whose grants cover only some objects sees (IAM-01).
struct NodeScope {
    hosts: ReadScope,
    prefixes: ReadScope,
}

impl NodeScope {
    /// The node scope of the principal; `None` when it reads every observation.
    fn of(ipam: &IpamHandle, cx: &tenko_core::RequestCtx) -> Option<Self> {
        if ipam.read_scope(cx, ObjectKind::Observation).is_all() {
            return None;
        }
        Some(Self {
            hosts: ipam.read_scope(cx, ObjectKind::Host),
            prefixes: ipam.read_scope(cx, ObjectKind::Prefix),
        })
    }

    /// A node with a readable host of intent, or with an address in a readable prefix.
    fn admits(&self, node: &TopologyNode) -> bool {
        node.host
            .is_some_and(|host| self.hosts.admits(&host.into()))
            || node
                .prefixes
                .iter()
                .any(|prefix| self.prefixes.admits(&(*prefix).into()))
    }

    /// The graph with the nodes in scope, the edges between them and a summary counted
    /// over them; controller status and controller networks are left out.
    fn narrow(&self, mut graph: TopologyGraph) -> TopologyGraph {
        graph.nodes.retain(|node| self.admits(node));
        let kept: std::collections::HashSet<&str> =
            graph.nodes.iter().map(|node| node.id.as_str()).collect();
        graph
            .edges
            .retain(|edge| kept.contains(edge.a.as_str()) && kept.contains(edge.b.as_str()));
        let named: std::collections::BTreeMap<u16, VlanInView> = graph
            .summary
            .vlans
            .drain(..)
            .map(|vlan| (vlan.vid, vlan))
            .collect();
        summarize(&mut graph, &[]);
        for vlan in &mut graph.summary.vlans {
            if let Some(known) = named.get(&vlan.vid) {
                vlan.vlan = known.vlan;
                vlan.name.clone_from(&known.name);
            }
        }
        graph.summary.total_nodes = graph.summary.nodes;
        graph.summary.total_edges = graph.summary.edges;
        graph.summary.controllers.clear();
        graph.summary.networks.clear();
        graph
    }
}

/// One node with its ports, neighbours and intent.
#[utoipa::path(
    get,
    path = "/topology/nodes/{id}",
    tag = "topology",
    operation_id = "get_topology_node",
    summary = "Get one topology node with its ports and neighbours",
    params(
        ("id" = String, Path, description = "The node identifier, such as `m-00005e005301`."),
        NodeParams
    ),
    responses(
        (status = 200, description = "The node, its ports with what hangs on each, its neighbours and its intent", body = TopologyNodeView),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No node has this identifier (`ipam.topology.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured (`ipam.unavailable`, `ipam.topology.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_topology_node(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    Topology(topology): Topology,
    IpamPath(id): IpamPath<String>,
    filters: Filters,
) -> Result<Json<TopologyNodeView>, ApiError> {
    filters.only(&["port"])?;
    let at_least = filters.parse::<u64>("at_least")?.map(Revision);
    authorize(&app, &cx, Action::Read, new_of(ObjectKind::Observation))?;
    let port = filters.get("port")?;
    let mut found = topology
        .node(&id, port, at_least, cx.principal.user())
        .await?;
    if let Some(scope) = NodeScope::of(&ipam, &cx) {
        if !scope.admits(&found.node) {
            return Err(tenko_core::Denied {
                action: Action::Read,
                object: new_of(ObjectKind::Observation),
                reason: tenko_core::DenyReason::OutOfScope,
            }
            .into());
        }
        // Neighbours and what hangs on a port are shown when they are in scope too.
        let all = TopologyFilter {
            limit: Some(MAX_LIMIT),
            ..TopologyFilter::default()
        };
        let graph = topology.graph(&all, at_least, cx.principal.user()).await?;
        let visible: std::collections::HashSet<String> = graph
            .nodes
            .iter()
            .filter(|node| scope.admits(node))
            .map(|node| node.id.clone())
            .collect();
        found
            .neighbours
            .retain(|neighbour| visible.contains(&neighbour.node));
        for port in &mut found.ports {
            port.neighbours
                .retain(|neighbour| visible.contains(&neighbour.node));
        }
    }
    Ok(Json(found))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::Value;
    use tenko_core::{
        Authorizer, ObservationId, Timestamp,
        observe::{Endpoint, LinkKind, Observation, ObservationSource, Observed},
    };
    use tenko_ipam::{
        IpamService,
        observe::{IngestBatch, ObserveConfig, ingest},
        topology::{TopologyConfig, TopologyService},
        vlan::{
            Controllers,
            controllers::{ControllerDevice, ControllerDeviceKind, ControllerPort},
            memory::{MemoryController, MemoryControllers},
        },
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::*;
    use crate::{API_BASE, routes::tenancy::testkit::Reply};

    struct Api {
        router: Router,
    }

    impl Api {
        async fn new(state: AppState, topology: bool) -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
            let mut controller = MemoryController::new("unifi.example.test");
            let connector = controller.info.id;
            controller.devices = vec![
                ControllerDevice {
                    id: "sw-1".to_owned(),
                    name: "USW-24".to_owned(),
                    model: None,
                    mac: Some("00:00:5e:00:53:a2".parse().expect("mac")),
                    ip: Some("192.0.2.2".parse().expect("ip")),
                    kind: ControllerDeviceKind::Switch,
                    ports: vec![ControllerPort {
                        index: 5,
                        name: Some("Port 5".to_owned()),
                        native_vlan: Some(20),
                        uplink: false,
                        up: true,
                    }],
                },
                ControllerDevice {
                    id: "ap-1".to_owned(),
                    name: "U6-Lite".to_owned(),
                    model: None,
                    mac: Some("00:00:5e:00:53:a3".parse().expect("mac")),
                    ip: Some("192.0.2.3".parse().expect("ip")),
                    kind: ControllerDeviceKind::AccessPoint,
                    ports: Vec::new(),
                },
            ];
            let slot = Controllers::with(MemoryControllers::new(vec![controller]));
            let service_topology =
                TopologyService::new(Arc::clone(&service), slot, TopologyConfig::default());
            let source = ObservationSource::NetworkController { connector };
            let now = Timestamp::now();
            let observation = |subject| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject,
                observed_at: now,
                received_at: now,
                expires_at: None,
            };
            let batch = IngestBatch {
                source: source.clone(),
                observations: vec![
                    observation(Observed::Attachment {
                        mac: "00:00:5e:00:53:10".parse().expect("mac"),
                        device: "sw-1".to_owned(),
                        port: Some("5".to_owned()),
                        ssid: None,
                        vlan: Some(20),
                    }),
                    observation(Observed::Attachment {
                        mac: "00:00:5e:00:53:11".parse().expect("mac"),
                        device: "ap-1".to_owned(),
                        port: None,
                        ssid: Some("iot.example.test".to_owned()),
                        vlan: Some(30),
                    }),
                    observation(Observed::Link {
                        a: Endpoint {
                            device: "ap-1".to_owned(),
                            port: None,
                        },
                        b: Endpoint {
                            device: "sw-1".to_owned(),
                            port: Some("1".to_owned()),
                        },
                        kind: LinkKind::Uplink,
                    }),
                ],
                complete: true,
                received_at: now,
            };
            ingest(&store, &batch, &ObserveConfig::default())
                .await
                .expect("ingest");
            let (router, _) = OpenApiRouter::<AppState>::new()
                .nest(API_BASE, routes())
                .split_for_parts();
            let mut router = router.with_state(state).layer(Extension(service));
            if topology {
                router = router.layer(Extension(service_topology));
            }
            Self { router }
        }

        async fn get(&self, path: &str) -> Reply {
            let response = self
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("{API_BASE}{path}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = response.status();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .map(|v| v.to_str().expect("text").to_owned())
                .unwrap_or_default();
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            Reply {
                status,
                content_type,
                etag: None,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            }
        }
    }

    fn labels(body: &Value) -> Vec<String> {
        let mut out: Vec<String> = body["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .map(|n| n["label"].as_str().expect("label").to_owned())
            .collect();
        out.sort();
        out
    }

    #[tokio::test]
    async fn the_graph_and_its_filters() {
        let api = Api::new(AppState::default(), true).await;
        let all = api.get("/topology").await;
        all.assert_json(200);
        assert_eq!(
            labels(&all.body),
            [
                "00:00:5e:00:53:10",
                "00:00:5e:00:53:11",
                "U6-Lite",
                "USW-24"
            ]
        );
        assert_eq!(all.body["summary"]["nodes"], 4);
        assert_eq!(all.body["summary"]["by_kind"]["switch"], 1);
        assert_eq!(all.body["summary"]["controllers"][0]["devices"], 2);
        assert!(all.body["revision"].is_u64());
        let iot = api.get("/topology?vlan=30").await;
        iot.assert_json(200);
        assert_eq!(
            labels(&iot.body),
            ["00:00:5e:00:53:11", "U6-Lite", "USW-24"]
        );
        let switches = api.get("/topology?kind=switch,access_point").await;
        assert_eq!(labels(&switches.body), ["U6-Lite", "USW-24"]);
        api.get("/topology?kind=toaster")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/topology?vlan=5000")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/topology?limit=0")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/topology?limit=20001")
            .await
            .assert_problem(400, "sys.invalid_query");
        // The node limit goes beyond the page size of lists.
        api.get("/topology?limit=5000&at_least=1")
            .await
            .assert_json(200);
        api.get("/topology?vlan=0190d1c2-0000-7000-8000-000000000001")
            .await
            .assert_problem(404, "ipam.not_found");
        api.get("/topology?colour=blue")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn a_node_and_what_hangs_on_its_port() {
        let api = Api::new(AppState::default(), true).await;
        let all = api.get("/topology").await;
        let switch = all.body["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .find(|n| n["label"] == "USW-24")
            .expect("switch")["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let node = api.get(&format!("/topology/nodes/{switch}")).await;
        node.assert_json(200);
        assert_eq!(node.body["node"]["kind"], "switch");
        assert_eq!(node.body["neighbours"].as_array().map(Vec::len), Some(2));
        let port = api.get(&format!("/topology/nodes/{switch}?port=5")).await;
        port.assert_json(200);
        assert_eq!(port.body["ports"].as_array().map(Vec::len), Some(1));
        assert_eq!(port.body["ports"][0]["name"], "Port 5");
        assert_eq!(
            port.body["ports"][0]["neighbours"][0]["label"],
            "00:00:5e:00:53:10"
        );
        api.get("/topology/nodes/m-000000000000")
            .await
            .assert_problem(404, "ipam.topology.not_found");
    }

    #[tokio::test]
    async fn unavailable_and_forbidden() {
        let api = Api::new(AppState::default(), false).await;
        api.get("/topology")
            .await
            .assert_problem(503, "ipam.topology.unavailable");
        let state = AppState {
            authorizer: Some(
                crate::routes::tenancy::testkit::Policy::new(false, false) as Arc<dyn Authorizer>
            ),
            ..AppState::default()
        };
        let api = Api::new(state, true).await;
        api.get("/topology")
            .await
            .assert_problem(403, "auth.forbidden");
    }
}
