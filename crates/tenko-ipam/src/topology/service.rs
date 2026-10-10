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
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_core::{CodedError, ConnectorId, Revision, Timestamp, UserId, codec::encode_key};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use tokio::{sync::watch, time::Instant};

use super::{
    build::{self, Computed, Inputs, Intent},
    filter,
    model::{
        ControllerStatus, IntentAddress, NodeIntent, TopologyFilter, TopologyGraph,
        TopologyNodeView,
    },
};
use crate::{
    error::{IpamError, IpamResult},
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
        })
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
        let mut controllers: Vec<ControllerTopology> =
            tables.iter().map(|t| t.as_ref().clone()).collect();
        controllers.sort_by_key(|t| t.connector);
        let inputs = Inputs {
            facts,
            intent,
            controllers,
            statuses,
            revision,
            now: Timestamp::now(),
        };
        let computed = Arc::new(build::build(&inputs));
        *self.kept.lock().unwrap_or_else(PoisonError::into_inner) = Some(Kept {
            revision,
            version,
            computed_at: Instant::now(),
            computed: Arc::clone(&computed),
            vlans: Arc::clone(&vlans),
        });
        Ok((computed, vlans))
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
        Ok(filter::apply(&computed, filter, &vlans))
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
                    error: None,
                });
                tables.insert(controller.id, Arc::new(topology));
            }
            Err(error) => statuses.push(ControllerStatus {
                connector: controller.id,
                name: controller.name,
                observed_at: None,
                devices: 0,
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
