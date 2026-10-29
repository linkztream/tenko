//! The topology service: the graph of the current store revision, cached, and the device
//! tables of the network controllers, cached with a lifetime.
//!
//! # Caching
//!
//! The graph is computed from one read view and kept with its revision. A read at the
//! same revision with the same controller tables answers the kept graph; a newer revision
//! recomputes it, but at most once per [`TopologyConfig::min_recompute`] unless the caller
//! asks for a revision the kept graph does not reach (`at_least`). Ingest writes often, so
//! the throttle keeps a busy discovery from recomputing on every read.
//!
//! The controllers' device tables come from a live read through the [`Controllers`] port
//! and are kept for [`TopologyConfig::controller_ttl`] ([`TopologyConfig::controller_retry`]
//! after a failed read). A refresh runs in its own task; a
//! read waits for it at most [`TopologyConfig::controller_wait`] and otherwise answers
//! with the tables it has, so a slow controller never holds the map. Links and client
//! attachments do not depend on these tables: they arrive as observations on every
//! scheduled poll.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_core::{
    CodedError, ConnectorId, HostId, RequestCtx, Revision, Timestamp, UserId, codec::encode_key,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use tokio::{sync::watch, time::Instant};

use super::{
    build::{self, Computed, Inputs, Intent},
    filter,
    model::{
        ControllerStatus, IntentAddress, NodeIntent, TopologyFilter, TopologyGraph,
        TopologyNodeView,
    },
    root::{self, DefaultRoute, RootDecision, RootSource},
    stored::{self, Stored, StoredWlanPolicy, WlanException, WlanPolicy},
    wlan::{self, SsidView},
};
use crate::{
    error::{IpamError, IpamResult},
    findings::Finding,
    observe::tables::FACTS,
    service::IpamService,
    tables::{ADDRESSES, HOSTS, INTERFACE_ADDRESSES, INTERFACES, PREFIXES, VLANS},
    vlan::controllers::{ControllerTopology, Controllers},
};

/// Stable codes of the topology.
pub mod codes {
    /// No node has this identifier (404). Params: `id`.
    pub const NOT_FOUND: &str = "ipam.topology.not_found";
    /// The topology service is not configured in this server (503).
    pub const UNAVAILABLE: &str = "ipam.topology.unavailable";
}

/// Limits of the topology service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyConfig {
    /// How long the device tables of a controller are kept (5 minutes, the default poll
    /// interval of connectors).
    pub controller_ttl: Duration,
    /// How long the tables are kept while the read of a controller failed (30 seconds).
    pub controller_retry: Duration,
    /// How long a read waits for a refresh of the device tables.
    pub controller_wait: Duration,
    /// The shortest interval between two computations of the graph.
    pub min_recompute: Duration,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            controller_ttl: Duration::from_secs(300),
            controller_retry: Duration::from_secs(30),
            controller_wait: Duration::from_secs(3),
            min_recompute: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Default)]
struct ControllerState {
    tables: HashMap<ConnectorId, Arc<ControllerTopology>>,
    statuses: Vec<ControllerStatus>,
    refreshed: Option<Instant>,
    in_flight: Option<watch::Receiver<bool>>,
    version: u64,
}

struct Kept {
    revision: Revision,
    version: u64,
    computed_at: Instant,
    computed: Arc<Computed>,
    vlans: Arc<Vec<tenko_core::ipam::Vlan>>,
}

/// The topology of IPAM-20. Cheap to share as `Arc<TopologyService>`.
pub struct TopologyService {
    ipam: Arc<IpamService>,
    controllers: Arc<Controllers>,
    config: TopologyConfig,
    state: Arc<Mutex<ControllerState>>,
    kept: Mutex<Option<Kept>>,
    route: Mutex<Option<Arc<dyn DefaultRoute>>>,
}

impl std::fmt::Debug for TopologyService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologyService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Reads every live row of a table.
fn live<K, V>(
    view: &dyn ReadView,
    table: &tenko_core::table::TableDef<K, V>,
    alive: impl Fn(&V) -> bool,
) -> IpamResult<Vec<V>>
where
    K: tenko_core::codec::KeyCodec,
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    Ok(view
        .scan_typed(table, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, value, _)| value)
        .filter(|value| alive(value))
        .collect())
}

/// The live intent of a view.
fn intent(view: &dyn ReadView) -> IpamResult<Intent> {
    Ok(Intent {
        hosts: live(view, &HOSTS, |h| !h.meta.is_deleted())?,
        interfaces: live(view, &INTERFACES, |i| !i.meta.is_deleted())?,
        addresses: live(view, &ADDRESSES, |a| !a.meta.is_deleted())?,
        prefixes: live(view, &PREFIXES, |p| !p.meta.is_deleted())?,
        vlans: live(view, &VLANS, |v| !v.meta.is_deleted())?,
    })
}

impl TopologyService {
    /// A service over IPAM and the network controllers.
    pub fn new(
        ipam: Arc<IpamService>,
        controllers: Arc<Controllers>,
        config: TopologyConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            ipam,
            controllers,
            config,
            state: Arc::new(Mutex::new(ControllerState::default())),
            kept: Mutex::new(None),
            route: Mutex::new(None),
        })
    }

    /// Sets where the next hops of this node's default routes come from (the second source
    /// of the root, UI-Q10). Without one, only the controller's gateway names the root.
    pub fn set_default_route(&self, route: Arc<dyn DefaultRoute>) {
        *self.route.lock().unwrap_or_else(PoisonError::into_inner) = Some(route);
    }

    /// The next hops of the default routes; none without a reader.
    async fn hops(&self) -> Vec<IpAddr> {
        let route = self
            .route
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match route {
            Some(route) => route.next_hops().await,
            None => Vec::new(),
        }
    }

    /// The network controllers.
    pub fn controllers(&self) -> &Arc<Controllers> {
        &self.controllers
    }

    /// Starts a refresh of the device tables when they are older than their lifetime and
    /// no refresh runs, and waits for the running refresh at most the configured time.
    async fn refresh_controllers(&self, on_behalf_of: Option<UserId>) {
        let Some(port) = self.controllers.get() else {
            return;
        };
        let waiter = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            // A read that failed for a controller is tried again sooner than a good one.
            let lifetime = if state.statuses.iter().any(|s| s.error.is_some()) {
                self.config.controller_retry
            } else {
                self.config.controller_ttl
            };
            let fresh = state.refreshed.is_some_and(|at| at.elapsed() < lifetime);
            match (&state.in_flight, fresh) {
                (Some(running), _) => Some(running.clone()),
                (None, true) => None,
                (None, false) => {
                    let (done, waiter) = watch::channel(false);
                    state.in_flight = Some(waiter.clone());
                    let shared = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        let (tables, statuses) =
                            read_controllers(port.as_ref().as_ref(), on_behalf_of).await;
                        let mut state = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        state.tables = tables;
                        state.statuses = statuses;
                        state.refreshed = Some(Instant::now());
                        state.in_flight = None;
                        state.version += 1;
                        drop(state);
                        let _ = done.send(true);
                    });
                    Some(waiter)
                }
            }
        };
        if let Some(mut waiter) = waiter {
            let _ =
                tokio::time::timeout(self.config.controller_wait, waiter.wait_for(|done| *done))
                    .await;
        }
    }

    /// The whole graph at least at `at_least`, from the cache when it is current.
    async fn computed(
        &self,
        at_least: Option<Revision>,
        on_behalf_of: Option<UserId>,
    ) -> IpamResult<(Arc<Computed>, Arc<Vec<tenko_core::ipam::Vlan>>)> {
        self.refresh_controllers(on_behalf_of).await;
        let (tables, statuses, version) = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            (
                state.tables.values().cloned().collect::<Vec<_>>(),
                state.statuses.clone(),
                state.version,
            )
        };
        let view = self.ipam.view(at_least).await?;
        let revision = view.revision();
        {
            let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(kept) = kept.as_ref() {
                let same = kept.revision == revision && kept.version == version;
                let recent = kept.computed_at.elapsed() < self.config.min_recompute
                    && kept.version == version
                    && at_least.is_none_or(|wanted| kept.revision >= wanted);
                if same || recent {
                    return Ok((Arc::clone(&kept.computed), Arc::clone(&kept.vlans)));
                }
            }
        }
        let facts = view
            .scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, mut fact, revision)| {
                fact.revision = revision;
                fact
            })
            .collect();
        let intent = intent(view.as_ref())?;
        let vlans = Arc::new(intent.vlans.clone());
        let mut tables = tables;
        tables.sort_by_key(|t| t.connector);
        let controllers: Vec<ControllerTopology> =
            tables.iter().map(|t| t.as_ref().clone()).collect();
        let inputs = Inputs {
            facts,
            intent,
            controllers,
            statuses,
            revision,
            now: Timestamp::now(),
        };
        let mut computed = build::build(&inputs);
        computed.intent = inputs.intent;
        computed.controllers = tables;
        let computed = Arc::new(computed);
        *self.kept.lock().unwrap_or_else(PoisonError::into_inner) = Some(Kept {
            revision,
            version,
            computed_at: Instant::now(),
            computed: Arc::clone(&computed),
            vlans: Arc::clone(&vlans),
        });
        Ok((computed, vlans))
    }

    /// The decisions a person stored, read fresh on every call: the graph may be kept for
    /// [`TopologyConfig::min_recompute`], a decision takes effect at once.
    async fn decisions(&self, at_least: Option<Revision>) -> IpamResult<Stored> {
        let view = self.ipam.view(at_least).await?;
        Stored::load(view.as_ref())
    }

    /// The graph, filtered.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn graph(
        &self,
        filter: &TopologyFilter,
        at_least: Option<Revision>,
        on_behalf_of: Option<UserId>,
    ) -> IpamResult<TopologyGraph> {
        let (computed, vlans) = self.computed(at_least, on_behalf_of).await?;
        let stored = self.decisions(at_least).await?;
        let decision = root::decide(&computed.graph, &self.hops().await, stored.root.as_ref());
        let mut graph = filter::apply(&computed, filter, &vlans);
        graph.summary.root = decision.root;
        Ok(graph)
    }

    /// The root of the map with its candidates and the stored choice (UI-Q10).
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn root(
        &self,
        at_least: Option<Revision>,
        on_behalf_of: Option<UserId>,
    ) -> IpamResult<RootDecision> {
        let (computed, _) = self.computed(at_least, on_behalf_of).await?;
        let stored = self.decisions(at_least).await?;
        Ok(root::decide(
            &computed.graph,
            &self.hops().await,
            stored.root.as_ref(),
        ))
    }

    /// "Use this": stores `source` as the root of the map with the candidates on offer now,
    /// and answers the decision after the write.
    ///
    /// # Errors
    ///
    /// 409 `ipam.topology.no_candidate` when the source names no root now, 412
    /// `ipam.revision_mismatch`, the store's errors.
    pub async fn choose_root(
        &self,
        cx: &RequestCtx,
        source: RootSource,
        if_match: Option<Revision>,
    ) -> IpamResult<RootDecision> {
        let decision = self.root(None, cx.principal.user()).await?;
        let Some(candidate) = decision
            .candidates
            .iter()
            .find(|candidate| candidate.source == source)
        else {
            return Err(IpamError::new(
                stored::codes::NO_CANDIDATE,
                409,
                format!("the source {} names no root now", source.as_str()),
            )
            .titled("No such root")
            .param("source", source.as_str()));
        };
        let mut offered: Vec<String> = decision
            .candidates
            .iter()
            .map(root::RootCandidate::key)
            .collect();
        offered.sort();
        let row = stored::choose_root(
            self.ipam.store().as_ref(),
            cx,
            source,
            offered,
            &candidate.label,
            if_match,
        )
        .await?;
        self.root(Some(row.revision), cx.principal.user()).await
    }

    /// Forgets the chosen root.
    ///
    /// # Errors
    ///
    /// 404 `ipam.topology.not_stored`, 412, the store's errors.
    pub async fn clear_root(&self, cx: &RequestCtx, if_match: Option<Revision>) -> IpamResult<()> {
        stored::clear_root(self.ipam.store().as_ref(), cx, if_match).await
    }

    /// The SSID view: every SSID of the controllers with its VLANs and clients.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn ssids(
        &self,
        at_least: Option<Revision>,
        on_behalf_of: Option<UserId>,
    ) -> IpamResult<SsidView> {
        let (computed, _) = self.computed(at_least, on_behalf_of).await?;
        let stored = self.decisions(at_least).await?;
        let evaluation = wlan::evaluate(
            &computed.controllers,
            &computed.intent,
            &stored,
            &computed.graph,
            Timestamp::now(),
        );
        Ok(SsidView {
            ssids: evaluation.ssids,
            revision: computed.graph.revision,
        })
    }

    /// The topology's findings: the root's disagreement and the WLAN rules.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn findings(&self, on_behalf_of: Option<UserId>) -> IpamResult<Vec<Finding>> {
        let (computed, _) = self.computed(None, on_behalf_of).await?;
        let stored = self.decisions(None).await?;
        let now = Timestamp::now();
        let decision = root::decide(&computed.graph, &self.hops().await, stored.root.as_ref());
        let mut out = wlan::evaluate(
            &computed.controllers,
            &computed.intent,
            &stored,
            &computed.graph,
            now,
        )
        .findings;
        out.extend(root::finding(&decision, now));
        Ok(out)
    }

    /// Sets the policy of an SSID.
    ///
    /// # Errors
    ///
    /// See [`stored::set_policy`].
    pub async fn set_policy(
        &self,
        cx: &RequestCtx,
        ssid: &str,
        policy: WlanPolicy,
        if_match: Option<Revision>,
    ) -> IpamResult<StoredWlanPolicy> {
        stored::set_policy(self.ipam.store().as_ref(), cx, ssid, policy, if_match).await
    }

    /// Removes the policy of an SSID.
    ///
    /// # Errors
    ///
    /// See [`stored::clear_policy`].
    pub async fn clear_policy(
        &self,
        cx: &RequestCtx,
        ssid: &str,
        if_match: Option<Revision>,
    ) -> IpamResult<()> {
        stored::clear_policy(self.ipam.store().as_ref(), cx, ssid, if_match).await
    }

    /// "Keep on this WLAN".
    ///
    /// # Errors
    ///
    /// See [`stored::keep`].
    pub async fn keep(
        &self,
        cx: &RequestCtx,
        host: HostId,
        ssid: &str,
        reason: Option<String>,
        if_match: Option<Revision>,
    ) -> IpamResult<WlanException> {
        stored::keep(self.ipam.store().as_ref(), cx, host, ssid, reason, if_match).await
    }

    /// Removes an exception.
    ///
    /// # Errors
    ///
    /// See [`stored::forget`].
    pub async fn forget(
        &self,
        cx: &RequestCtx,
        host: HostId,
        ssid: &str,
        if_match: Option<Revision>,
    ) -> IpamResult<()> {
        stored::forget(self.ipam.store().as_ref(), cx, host, ssid, if_match).await
    }

    /// One node with its ports (only `port` when given), neighbours and intent.
    ///
    /// # Errors
    ///
    /// 404 `ipam.topology.not_found`, or the store's errors.
    pub async fn node(
        &self,
        id: &str,
        port: Option<&str>,
        at_least: Option<Revision>,
        on_behalf_of: Option<UserId>,
    ) -> IpamResult<TopologyNodeView> {
        let (computed, _) = self.computed(at_least, on_behalf_of).await?;
        let node = computed
            .index
            .get(id)
            .and_then(|&position| computed.graph.nodes.get(position))
            .cloned()
            .ok_or_else(|| {
                IpamError::new(
                    codes::NOT_FOUND,
                    404,
                    format!("the topology has no node {id}"),
                )
                .titled("Node not found")
                .param("id", id)
            })?;
        let intent = match node.host {
            Some(host) => {
                let view = self.ipam.view(Some(computed.graph.revision)).await?;
                node_intent(view.as_ref(), host)?
            }
            None => None,
        };
        Ok(TopologyNodeView {
            ports: filter::ports(&computed, id, port),
            neighbours: filter::neighbours(&computed, id),
            node,
            intent,
            revision: computed.graph.revision,
        })
    }
}

/// Reads the device tables of every enabled controller.
async fn read_controllers(
    port: &dyn crate::vlan::controllers::NetworkControllers,
    on_behalf_of: Option<UserId>,
) -> (
    HashMap<ConnectorId, Arc<ControllerTopology>>,
    Vec<ControllerStatus>,
) {
    let mut tables = HashMap::new();
    let mut statuses = Vec::new();
    let list = match port.controllers().await {
        Ok(list) => list,
        Err(error) => {
            tracing::warn!(code = %error.code, detail = %error.detail, "the network controllers could not be listed");
            return (tables, statuses);
        }
    };
    for controller in list.into_iter().filter(|c| c.enabled) {
        match port.topology(controller.id, on_behalf_of).await {
            Ok(topology) => {
                statuses.push(ControllerStatus {
                    connector: controller.id,
                    name: controller.name,
                    observed_at: Some(topology.observed_at),
                    devices: topology.devices.len(),
                    writes_enabled: controller.writes_enabled,
                    error: None,
                });
                tables.insert(controller.id, Arc::new(topology));
            }
            Err(error) => statuses.push(ControllerStatus {
                connector: controller.id,
                name: controller.name,
                observed_at: None,
                devices: 0,
                writes_enabled: controller.writes_enabled,
                error: Some(CodedError {
                    params: std::collections::BTreeMap::default(),
                    errors: Vec::new(),
                    ..error
                }),
            }),
        }
    }
    statuses.sort_by(|a, b| (&a.name, a.connector).cmp(&(&b.name, b.connector)));
    (tables, statuses)
}

/// The host of intent behind a node with its live addresses.
fn node_intent(view: &dyn ReadView, host: tenko_core::HostId) -> IpamResult<Option<NodeIntent>> {
    let Some((host, _)) = view.get_typed(&HOSTS, &host)? else {
        return Ok(None);
    };
    if host.meta.is_deleted() {
        return Ok(None);
    }
    let mut addresses = Vec::new();
    let interfaces = view.scan_typed(
        &crate::tables::HOST_INTERFACES,
        KeyRange::prefix(encode_key(&host.id)),
        usize::MAX,
        false,
    )?;
    for ((_, interface), (), _) in interfaces {
        let live_interface = view
            .get_typed(&INTERFACES, &interface)?
            .is_some_and(|(i, _)| !i.meta.is_deleted());
        if !live_interface {
            continue;
        }
        let bound = view.scan_typed(
            &INTERFACE_ADDRESSES,
            KeyRange::prefix(encode_key(&interface)),
            usize::MAX,
            false,
        )?;
        for ((_, address), (), _) in bound {
            let Some((address, _)) = view.get_typed(&ADDRESSES, &address)? else {
                continue;
            };
            if address.meta.is_deleted() {
                continue;
            }
            let Some((prefix, _)) = view.get_typed(&PREFIXES, &address.prefix)? else {
                continue;
            };
            let vid = match prefix.vlan {
                Some(vlan) => view.get_typed(&VLANS, &vlan)?.map(|(v, _)| v.vid),
                None => None,
            };
            addresses.push(IntentAddress {
                ip: address.ip,
                prefix: prefix.id,
                cidr: prefix.cidr,
                vlan: prefix.vlan,
                vid,
            });
        }
    }
    addresses.sort_by_key(|a| a.ip);
    Ok(Some(NodeIntent {
        host: host.id,
        name: host.name.as_str().to_owned(),
        mode: host.mode,
        addresses,
    }))
}
