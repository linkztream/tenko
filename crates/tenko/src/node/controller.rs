//! The `nodes` start step of `tenko serve` on a controller: the internal CA (created here
//! when the API listener does not use it), the node registry with its job step, the
//! controller's certificate on the cluster port, the cluster port itself (always, on demand
//! or off, `[cluster] listen`), the hand-over of probe batches to the reconciler, and the
//! cluster summary and notices of `GET /system/status`.
//!
//! With the peer layer of start step 3 ([`ClusterPeers`]) the step also hands the
//! registry, this controller's identity and its key generations to the controller cluster:
//! on a member, whose cluster port opened in step 3, it attaches the node services to that
//! port; on a single controller it opens the port with the `Raft` and `Cluster` services
//! beside the node services, ready for the first controller that joins, and gives the
//! peer transport the controller's certificate.

use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use futures::{FutureExt as _, StreamExt as _};
use tenko_api::{
    dto::system::{ClusterStatus, StatusWarning},
    sse::{EventData, Topic},
    state::AppState,
};
use tenko_cluster::{
    admin::{ClusterAdmin, QuorumKind, QuorumView},
    ca::{CaPolicy, CertSource, InternalCa, TlsMaterial, TlsResolver, generate_csr},
    error::ClusterError,
    identity::{Credentials, NodePaths},
    kek::VaultKekSource,
    peers::{Peers, VaultIdentity},
    probe::{DiscardProbes, IngestCounts, ProbeBatch, ProbeSink},
    registry::{NodeRegistry, PortDemand, PruneService, RegistryConfig},
    server::{ClusterListener, ClusterService},
};
use tenko_core::cluster::LeaderService;
use tenko_core::{NodeId, RequestCtx, SystemComponent, Timestamp, VrfId};
use tenko_jobs::JobEngine;
use tenko_store::QuorumState;
use tenko_store::{ChangeStream, ReadViewExt as _, Store, WatchFilter};
use tenko_vault::StoreVault;
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    cluster::ClusterPeers,
    config::{ClusterListen, Resolved},
    serve::StartError,
};

/// The notice of nodes that share no protocol major with this controller.
pub const MISMATCH_NOTICE: &str = "cluster.protocol.mismatch";

/// How often the cluster summary of `GET /system/status` is refreshed when nothing under
/// `cluster.*` is written (heartbeats in memory, a listener that opens).
const HEALTH_INTERVAL: Duration = Duration::from_secs(5);
/// The `kind` of the `cluster` event that announces a new cluster summary (no store
/// change, so no revision).
pub const STATUS_EVENT: &str = "cluster.status";
/// The `kind` of the `cluster` event that announces a change of this controller's quorum
/// state (OPS-26); its parameters are `state` (`single`, `healthy`, `electing`,
/// `isolated`) and, when known, `since`, `last_contact` (RFC 3339) and `applied`.
pub const QUORUM_EVENT: &str = "cluster.quorum";
/// How often the revocation list is read again (other controllers revoke too); the prune of
/// expired revocations and old tokens is the leader service `cluster.prune`.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);
/// How often the controller's certificate on the cluster port is checked for renewal.
const CERT_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// What the `cluster` start step needs from the steps before it.
pub struct Parts<'a> {
    /// The validated configuration.
    pub resolved: &'a Resolved,
    /// The store.
    pub store: Arc<dyn Store>,
    /// The vault (the internal CA keeps its key there).
    pub vault: Arc<StoreVault>,
    /// The job engine: every edit of the node registry is an inline job.
    pub engine: JobEngine,
    /// The reconciler that takes the probes' observations; `None` while IPAM is off.
    pub reconciler: Option<Arc<tenko_ipam::reconcile::Reconciler>>,
    /// Turns true when the server stops.
    pub stop: watch::Receiver<bool>,
}

/// The running node transport of a controller.
pub struct Cluster {
    registry: Arc<NodeRegistry>,
    peers: Option<Peers>,
    sink: Arc<dyn ProbeSink>,
    state: Arc<OnceLock<AppState>>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cluster").finish_non_exhaustive()
    }
}

/// Hands probe batches to the reconciler, in the VRF the batch or the node's token names,
/// else the default VRF.
struct ReconcilerSink {
    reconciler: Arc<tenko_ipam::reconcile::Reconciler>,
}

impl ReconcilerSink {
    async fn default_vrf(&self) -> Result<VrfId, ClusterError> {
        let no_vrf = || {
            ClusterError::new(
                "cluster.probe.no_vrf",
                503,
                "the default VRF does not exist yet; complete first-run setup",
            )
        };
        let view = self
            .reconciler
            .ipam()
            .view(None)
            .await
            .map_err(|error| ClusterError::from(error.into_coded()))?;
        let (tenant, _) = view
            .get_typed(&tenko_ipam::tables::TENANT_NAMES, &"default".to_owned())?
            .ok_or_else(no_vrf)?;
        let (vrf, _) = view
            .get_typed(
                &tenko_ipam::tables::VRF_NAMES,
                &(tenant, "default".to_owned()),
            )?
            .ok_or_else(no_vrf)?;
        Ok(vrf)
    }
}

#[async_trait]
impl ProbeSink for ReconcilerSink {
    async fn ingest(
        &self,
        node: NodeId,
        vrf: Option<VrfId>,
        batch: ProbeBatch,
    ) -> Result<IngestCounts, ClusterError> {
        let vrf = match vrf {
            Some(vrf) => vrf,
            None => self.default_vrf().await?,
        };
        let complete = batch.complete;
        let received_at = Timestamp::now();
        let (source, observations) = batch.into_observations(node, vrf, received_at);
        let report = self
            .reconciler
            .ingest(tenko_ipam::observe::IngestBatch {
                source,
                observations,
                complete,
                received_at,
            })
            .await
            .map_err(|error| ClusterError::from(error.into_coded()))?;
        Ok(IngestCounts {
            new: report.new,
            changed: report.changed,
            refreshed: report.refreshed,
            unchanged: report.unchanged,
            gone: report.gone,
            skipped: report.skipped,
        })
    }
}

fn start_error(error: &ClusterError) -> StartError {
    StartError {
        step: "nodes",
        code: error.code().to_owned(),
        message: error.detail().to_owned(),
    }
}

fn addresses(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Starts the node transport of a controller without the controller cluster.
///
/// # Errors
///
/// As [`start_with`].
pub async fn start(parts: Parts<'_>) -> Result<(Cluster, String), StartError> {
    start_with(parts, None).await
}

/// Starts the node transport of a controller, with the peer layer of start step 3.
///
/// # Errors
///
/// A [`StartError`] of the step `nodes`: the CA, the registry, the controller
/// certificate or a cluster port that must listen and cannot.
#[allow(
    clippy::too_many_lines,
    reason = "the start step reads best as one sequence"
)]
pub async fn start_with(
    parts: Parts<'_>,
    peers: Option<ClusterPeers>,
) -> Result<(Cluster, String), StartError> {
    let Parts {
        resolved,
        store,
        vault,
        engine,
        reconciler,
        stop,
    } = parts;
    let section = &resolved.config.cluster;
    let mode = section
        .listen_mode()
        .map_err(|error| StartError::new("nodes", error.code, error.message))?;
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = InternalCa::load_or_init(store.as_ref(), vault.as_ref(), &ctx, CaPolicy::default())
        .await
        .map_err(|error| StartError::coded("nodes", &error))?;
    let default_port = match &mode {
        ClusterListen::OnDemand(addrs) | ClusterListen::Always(addrs) => {
            addrs.first().map_or(8444, SocketAddr::port)
        }
        ClusterListen::Off => 8444,
    };
    let config = RegistryConfig {
        local_node: resolved.node_id,
        heartbeat_secs: section.heartbeat_secs,
        advertise: section.advertise.clone(),
        default_port,
        default_token_ttl: Duration::from_secs(section.enrollment_ttl_secs),
        ..RegistryConfig::new(resolved.node_id)
    };
    let open_port = peers.as_ref().and_then(|peers| peers.port().cloned());
    let registry = match &open_port {
        Some(port) => NodeRegistry::with_port(
            Arc::clone(&store),
            Arc::new(ca),
            config,
            Arc::clone(&port.revocations),
            Arc::clone(&port.sessions),
        ),
        None => NodeRegistry::new(Arc::clone(&store), Arc::new(ca), config),
    };
    registry.register_steps(&engine);
    // Connections recorded by an earlier run of this controller are gone.
    if let Err(error) = registry.clear_own_connections().await {
        tracing::warn!(code = %error.code(), "old connection records could not be removed: {}", error.detail());
    }
    registry.set_node_sync(
        tenko_cluster::node_sync::NodeSync::new(Arc::clone(&store))
            .with_vault(Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>)
            .with_rate_kbps(section.sync_kbps),
    );
    let revoked = registry
        .load_revocations()
        .await
        .map_err(|error| start_error(&error))?;
    let sink: Arc<dyn ProbeSink> = match reconciler {
        Some(reconciler) => Arc::new(ReconcilerSink { reconciler }),
        None => Arc::new(DiscardProbes),
    };
    let layer = peers.as_ref().map(|peers| peers.peers().clone());
    if let Some(layer) = &layer {
        layer.attach_registry(Arc::clone(&registry));
        layer.attach_kek(Arc::new(VaultKekSource::new(Arc::clone(&vault))));
        layer.register_steps(&engine);
    }
    if let Some(port) = &open_port {
        // A member: the cluster port opened in step 3 with the identity under
        // `<data_dir>/node/`; it serves the node services from now on.
        port.nodes.attach(&ClusterService::new(
            Arc::clone(&registry),
            Arc::clone(&sink),
        ));
        registry.set_listening(port.addrs.clone());
        let mut tasks = vec![registry.follow_revocations(stop.clone())];
        tasks.push(tokio::spawn(maintenance(
            Arc::clone(&registry),
            Arc::clone(&vault),
            None,
            stop.clone(),
        )));
        if let Some(layer) = &layer {
            tasks.push(tokio::spawn(renew_identity(
                Arc::clone(&registry),
                layer.clone(),
                Arc::clone(&port.resolver),
                NodePaths::new(&resolved.data_dir),
                stop.clone(),
            )));
        }
        let state = Arc::new(OnceLock::new());
        tasks.push(tokio::spawn(health(
            Arc::clone(&registry),
            Arc::clone(&state),
            layer.as_ref().map(|layer| layer.store().quorum()),
            stop,
        )));
        let nodes = registry
            .list_nodes()
            .await
            .map_err(|error| start_error(&error))?
            .len();
        return Ok((
            Cluster {
                registry,
                peers: layer,
                sink,
                state,
                tasks,
            },
            format!(
                "node services on the cluster port of step 3 ({}), {nodes} node(s) enrolled, {revoked} certificate(s) revoked",
                addresses(&port.addrs)
            ),
        ));
    }
    let material = registry
        .controller_material(vault.as_ref(), &ctx)
        .await
        .map_err(|error| start_error(&error))?;
    let resolver = Arc::new(TlsResolver::default());
    resolver.set(Some(material));
    if let Some(layer) = &layer {
        // The first controller: its peer transport presents the vault-held certificate,
        // which moves to `<data_dir>/node/` when the first peer joins.
        let (chain, key) = registry
            .controller_identity(vault.as_ref(), &ctx)
            .await
            .map_err(|error| start_error(&error))?;
        let client = tenko_cluster::mtls::client_config(registry.ca().root_der(), chain, &key)
            .map_err(|error| start_error(&error))?;
        layer.network().set_tls(client);
        layer.attach_identity(Arc::new(VaultIdentity::new(
            Arc::clone(&registry),
            Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>,
            NodePaths::new(&resolved.data_dir),
            format!("controller-{}", resolved.node_id.0),
        )));
    }
    let in_use = registry
        .in_use(Timestamp::now())
        .await
        .map_err(|error| start_error(&error))?;
    let mut tasks = Vec::new();
    let summary = match mode {
        ClusterListen::Always(addrs) => {
            let listener = ClusterListener::bind(&addrs)
                .await
                .map_err(|error| start_error(&error))?;
            let bound = listener.local_addrs();
            tasks.push(
                listener
                    .serve_with_peers(
                        &registry,
                        Arc::clone(&sink),
                        resolver.clone(),
                        layer.clone(),
                        stop.clone(),
                    )
                    .map_err(|error| start_error(&error))?,
            );
            format!("cluster port on {}", addresses(&bound))
        }
        ClusterListen::OnDemand(addrs) => {
            let (open, summary) = if in_use {
                let listener = ClusterListener::bind(&addrs)
                    .await
                    .map_err(|error| start_error(&error))?;
                let bound = listener.local_addrs();
                let port =
                    OnDemandPort::serve(listener, &registry, &sink, &resolver, layer.as_ref())
                        .map_err(|error| start_error(&error))?;
                (Some(port), format!("cluster port on {}", addresses(&bound)))
            } else {
                (
                    None,
                    format!(
                        "cluster port {} opens with an enrollment token",
                        addresses(&addrs)
                    ),
                )
            };
            tasks.push(tokio::spawn(on_demand(
                Arc::clone(&registry),
                addrs.clone(),
                Arc::clone(&sink),
                resolver.clone(),
                layer.clone(),
                open,
                stop.clone(),
            )));
            summary
        }
        ClusterListen::Off => "cluster port off ([cluster] listen = [])".to_owned(),
    };
    tasks.push(registry.follow_revocations(stop.clone()));
    tasks.push(tokio::spawn(maintenance(
        Arc::clone(&registry),
        Arc::clone(&vault),
        Some(resolver),
        stop.clone(),
    )));
    let state = Arc::new(OnceLock::new());
    tasks.push(tokio::spawn(health(
        Arc::clone(&registry),
        Arc::clone(&state),
        layer.as_ref().map(|layer| layer.store().quorum()),
        stop,
    )));
    let nodes = registry
        .list_nodes()
        .await
        .map_err(|error| start_error(&error))?
        .len();
    Ok((
        Cluster {
            registry,
            peers: layer,
            sink,
            state,
            tasks,
        },
        format!("{summary}, {nodes} node(s) enrolled, {revoked} certificate(s) revoked"),
    ))
}

impl Cluster {
    /// The background tasks, for the server's stop sequence; they end when `stop` turns
    /// true. A second call returns nothing.
    pub fn tasks(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.tasks)
    }

    /// Adds the node registry to the request extensions of the API and reports the
    /// cluster's health through `state`.
    pub fn register(&self, server: &mut tenko_api::ServerConfig, state: &AppState) {
        server.extensions.insert(Arc::clone(&self.registry));
        if let Some(peers) = &self.peers {
            let admin: Arc<dyn ClusterAdmin> = Arc::new(peers.clone());
            server.extensions.insert(admin);
        }
        let _ = self.state.set(state.clone());
    }

    /// The node registry.
    pub fn registry(&self) -> &Arc<NodeRegistry> {
        &self.registry
    }

    /// The leader-only work of the node registry, for the leader supervisor: the hourly
    /// prune of expired revocations and old enrollment tokens (`cluster.prune`).
    pub fn leader_services(&self) -> Vec<Arc<dyn LeaderService>> {
        vec![Arc::new(PruneService::new(Arc::clone(&self.registry)))]
    }

    /// Where probe batches go on this controller: a probe role on the controller node
    /// itself (WP2.3) hands its batches here directly, under this node's id, without the
    /// cluster port.
    pub fn probe_sink(&self) -> Arc<dyn ProbeSink> {
        Arc::clone(&self.sink)
    }
}

/// A cluster port that opened on demand: `close` stops it, `task` ends once the socket is
/// released.
struct OnDemandPort {
    close: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl OnDemandPort {
    /// Serves `listener` until [`OnDemandPort::shut`].
    fn serve(
        listener: ClusterListener,
        registry: &Arc<NodeRegistry>,
        sink: &Arc<dyn ProbeSink>,
        resolver: &Arc<TlsResolver>,
        peers: Option<&Peers>,
    ) -> Result<Self, ClusterError> {
        let (close, closed) = watch::channel(false);
        let task = listener.serve_with_peers(
            registry,
            Arc::clone(sink),
            resolver.clone(),
            peers.cloned(),
            closed,
        )?;
        Ok(Self { close, task })
    }

    /// Stops the port the way the server's stop does (connections drained for a grace
    /// period, then cut) and waits until its sockets are closed.
    async fn shut(self) {
        let _ = self.close.send(true);
        let _ = self.task.await;
    }
}

/// Why [`on_demand_hold`] returned.
#[derive(Debug, PartialEq, Eq)]
enum Hold {
    /// No node is enrolled and no token is waiting.
    Idle,
    /// The server stops.
    Stop,
}

/// The cluster port with `[cluster] listen` not set: opens when an enrollment token is
/// created and closes again when no token is waiting (withdrawn, used or expired) and no
/// node is enrolled. `open` is the port the start step opened already (a token was waiting
/// or a node enrolled at start).
async fn on_demand(
    registry: Arc<NodeRegistry>,
    addrs: Vec<SocketAddr>,
    sink: Arc<dyn ProbeSink>,
    resolver: Arc<TlsResolver>,
    peers: Option<Peers>,
    mut open: Option<OnDemandPort>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let port = if let Some(port) = open.take() {
            port
        } else {
            tokio::select! {
                () = registry.listener_wanted() => {}
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            }
            let served = match ClusterListener::bind(&addrs).await {
                Ok(listener) => {
                    OnDemandPort::serve(listener, &registry, &sink, &resolver, peers.as_ref())
                }
                Err(error) => Err(error),
            };
            match served {
                Ok(port) => {
                    tracing::info!(
                        "cluster port {} opens with an enrollment token",
                        addresses(&addrs)
                    );
                    port
                }
                Err(error) => {
                    // The next token tries again.
                    tracing::error!(code = %error.code(), "{}", error.detail());
                    registry.forget_listener_wanted();
                    continue;
                }
            }
        };
        let hold = on_demand_hold(&registry, &mut stop).await;
        port.shut().await;
        if hold == Hold::Stop {
            return;
        }
        tracing::info!(
            "cluster port {} closed: no enrollment token waiting and no node enrolled",
            addresses(&addrs)
        );
    }
}

/// Waits while the open on-demand port serves something: every write under `cluster.*`
/// (a token created, withdrawn, used or pruned; a node enrolled or revoked) reads the
/// demand again, and so does the expiry of the last waiting token.
async fn on_demand_hold(registry: &NodeRegistry, stop: &mut watch::Receiver<bool>) -> Hold {
    let filter = WatchFilter::namespaces(["cluster"]);
    // Subscribed before the first read, so no write between the two is missed.
    let mut changes = registry.store().watch(None, filter.clone()).ok();
    loop {
        // Forgotten before the read: a token the read does not see yet asks again, and the
        // port reopens at once after it closed.
        registry.forget_listener_wanted();
        let wake = match registry.port_demand(Timestamp::now()).await {
            Ok(PortDemand::Idle) => return Hold::Idle,
            Ok(PortDemand::Until(expires)) => Some(expires.saturating_since(Timestamp::now())),
            Ok(PortDemand::Enrolled) => None,
            Err(error) => {
                tracing::debug!(code = %error.code(), "the cluster port demand could not be read");
                Some(HEALTH_INTERVAL)
            }
        };
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return Hold::Stop,
            () = async {
                match wake {
                    Some(after) => tokio::time::sleep(after).await,
                    None => std::future::pending().await,
                }
            } => {}
            received = next_change(&mut changes) => {
                if received {
                    drain(&mut changes);
                } else {
                    changes = registry.store().watch(None, filter.clone()).ok();
                }
            }
        }
    }
}

/// Reads the revocation list again and renews the controller's certificate on the cluster
/// port when it is due (a single controller: `resolver`; a member's identity under
/// `<data_dir>/node/` is renewed elsewhere). The prune is the leader service
/// `cluster.prune` ([`Cluster::leader_services`]).
async fn maintenance(
    registry: Arc<NodeRegistry>,
    vault: Arc<StoreVault>,
    resolver: Option<Arc<TlsResolver>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut revocations = tokio::time::interval(MAINTENANCE_INTERVAL);
    revocations.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut certificate = tokio::time::interval(CERT_INTERVAL);
    certificate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Both intervals fire at once; the start step just did both.
    revocations.tick().await;
    certificate.tick().await;
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = revocations.tick() => {
                if let Err(error) = registry.load_revocations().await {
                    tracing::warn!(code = %error.code(), "{}", error.detail());
                }
            }
            _ = certificate.tick() => {
                let Some(resolver) = &resolver else {
                    continue;
                };
                let ctx = RequestCtx::system(SystemComponent::Cluster);
                match registry.controller_material(vault.as_ref(), &ctx).await {
                    Ok(material) => resolver.set(Some(material)),
                    Err(error) => tracing::warn!(code = %error.code(), "the cluster port certificate could not be renewed: {}", error.detail()),
                }
            }
        }
    }
}

/// Mirrors the registry's health into `GET /system/status`: the cluster summary and a
/// warning while nodes share no protocol major with this controller.
///
/// The summary is read again as soon as anything under `cluster.*` is written (a node
/// enrolls, connects or disconnects, is revoked, reports another version or a refused
/// handshake: each of these writes the node's record), and every [`HEALTH_INTERVAL`] as
/// the fallback. When the summary or the warning changed, a `cluster` event follows
/// ([`STATUS_EVENT`]): the store's own event of the change can reach the views before the
/// summary is refreshed, so they read the status again on this one and find the new state.
async fn health(
    registry: Arc<NodeRegistry>,
    state: Arc<OnceLock<AppState>>,
    mut quorum: Option<watch::Receiver<QuorumState>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(HEALTH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let filter = WatchFilter::namespaces(["cluster"]);
    let mut changes = registry.store().watch(None, filter.clone()).ok();
    let mut shown: Option<(ClusterStatus, Option<StatusWarning>)> = None;
    let mut shown_quorum: Option<QuorumState> = None;
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = tick.tick() => {}
            open = async {
                match quorum.as_mut() {
                    Some(quorum) => quorum.changed().await.is_ok(),
                    None => std::future::pending().await,
                }
            } => {
                if !open {
                    quorum = None;
                }
            }
            received = next_change(&mut changes) => {
                if received {
                    // A burst of writes (an enrollment writes the node and its token) is one
                    // refresh: take what has arrived already.
                    drain(&mut changes);
                } else {
                    changes = registry.store().watch(None, filter.clone()).ok();
                }
            }
        }
        let Some(state) = state.get() else {
            continue;
        };
        if let Some(current) = quorum.as_ref().map(|quorum| *quorum.borrow())
            && shown_quorum != Some(current)
        {
            shown_quorum = Some(current);
            state.events().publish_system(&quorum_event(current));
        }
        let health = match registry.health().await {
            Ok(health) => health,
            Err(error) => {
                tracing::debug!(code = %error.code(), "the cluster summary could not be read");
                continue;
            }
        };
        let warning = mismatch_warning(&health);
        match &warning {
            Some(warning) => state.set_notice(warning.clone()),
            None => state.clear_notice(MISMATCH_NOTICE),
        }
        let status = ClusterStatus {
            listening: health.listening,
            majors: health.majors,
            nodes: health.nodes,
            connected: health.connected,
            versions: health.versions,
            mismatched: u64::try_from(health.mismatched.len()).unwrap_or(u64::MAX),
        };
        state.set_cluster_status(Some(status.clone()));
        let now = (status, warning);
        if shown.as_ref() != Some(&now) {
            shown = Some(now);
            let mut event = EventData::new(Topic::Cluster, None);
            event.kind = Some(STATUS_EVENT.to_owned());
            state.events().publish_system(&event);
        }
    }
}

/// The `cluster` event of a quorum state ([`QUORUM_EVENT`]).
fn quorum_event(quorum: QuorumState) -> EventData {
    let view = QuorumView::from(quorum);
    let mut event = EventData::new(Topic::Cluster, None);
    event.kind = Some(QUORUM_EVENT.to_owned());
    let state = match view.state {
        QuorumKind::Single => "single",
        QuorumKind::Healthy => "healthy",
        QuorumKind::Electing => "electing",
        QuorumKind::Isolated => "isolated",
    };
    event.params.insert("state".to_owned(), state.to_owned());
    if let Some(since) = view.since {
        event.params.insert("since".to_owned(), since.to_rfc3339());
    }
    if let Some(contact) = view.last_contact {
        event
            .params
            .insert("last_contact".to_owned(), contact.to_rfc3339());
    }
    if let Some(applied) = view.applied {
        event
            .params
            .insert("applied".to_owned(), applied.0.to_string());
    }
    event
}

/// How often a member checks whether its cluster certificate is due for renewal.
const IDENTITY_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Renews the certificate of a member's cluster identity under `<data_dir>/node/` when it
/// is due (a third of its lifetime or 30 days left): a new key and certificate from the
/// internal CA through the registry (the node record keeps both serials until the old one
/// expires), written beside the old pair and switched atomically, then presented to nodes
/// and peers.
async fn renew_identity(
    registry: Arc<NodeRegistry>,
    peers: Peers,
    resolver: Arc<TlsResolver>,
    paths: NodePaths,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(IDENTITY_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = tick.tick() => {}
        }
        if let Err(error) = renew_once(&registry, &peers, &resolver, &paths).await {
            tracing::warn!(code = %error.code(), "the cluster certificate of this controller could not be renewed: {}", error.detail());
        }
    }
}

async fn renew_once(
    registry: &NodeRegistry,
    peers: &Peers,
    resolver: &TlsResolver,
    paths: &NodePaths,
) -> Result<(), ClusterError> {
    let current = Credentials::load(paths)?;
    let now = Timestamp::now();
    if !current.needs_renewal(now) {
        return Ok(());
    }
    let (key, csr) = generate_csr()?;
    let issued = registry
        .renew(current.identity.node, &current.info.serial, &csr, now)
        .await?;
    let renewed = current.renewed(paths, issued.chain, key)?;
    resolver.set(Some(TlsMaterial::from_der(
        renewed.chain.clone(),
        &renewed.key,
        CertSource::Inline,
    )?));
    peers.network().set_tls(renewed.client_config()?);
    tracing::info!(not_after = %renewed.info.not_after, "renewed the cluster certificate of this controller");
    Ok(())
}

/// The warning of nodes that share no protocol major with this controller, if any.
fn mismatch_warning(health: &tenko_cluster::model::ClusterHealth) -> Option<StatusWarning> {
    if health.mismatched.is_empty() {
        return None;
    }
    let detail = health
        .mismatched
        .iter()
        .map(|node| {
            format!(
                "{} (node {}) offers protocol major(s) {}",
                node.name,
                node.node,
                tenko_cluster::version::format_majors(&node.mismatch.majors.theirs)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(StatusWarning {
        code: MISMATCH_NOTICE.to_owned(),
        detail: format!(
            "nodes share no protocol major with this controller, which implements {}: {detail}; upgrade the older side",
            tenko_cluster::version::format_majors(&health.majors)
        ),
        params: [
            ("count".to_owned(), health.mismatched.len().to_string()),
            (
                "nodes".to_owned(),
                health
                    .mismatched
                    .iter()
                    .map(|node| node.node.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
        .into(),
    })
}

/// Waits for the next change set; `false` when the stream ended or failed, or there is none
/// (it is opened again).
async fn next_change(changes: &mut Option<ChangeStream>) -> bool {
    if let Some(stream) = changes {
        matches!(stream.next().await, Some(Ok(_)))
    } else {
        tokio::time::sleep(HEALTH_INTERVAL).await;
        false
    }
}

/// Takes the change sets that have arrived already, without waiting.
fn drain(changes: &mut Option<ChangeStream>) {
    if let Some(stream) = changes {
        while let Some(Some(Ok(_))) = stream.next().now_or_never() {}
    }
}

#[cfg(test)]
mod tests {
    use tenko_cluster::{
        ca::pem_block,
        model::{ClusterHealth, EnrollRequest, MismatchRecord, NewEnrollment, NodeMismatch},
        version::VersionMismatch,
    };
    use tenko_core::Revision;

    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    #[test]
    fn a_refused_handshake_becomes_a_warning_naming_the_nodes() {
        let mut health = ClusterHealth {
            majors: vec![1],
            ..ClusterHealth::default()
        };
        assert_eq!(mismatch_warning(&health), None);
        health.mismatched.push(NodeMismatch {
            node: NodeId(1001),
            name: "probe-dmz".to_owned(),
            mismatch: MismatchRecord {
                majors: VersionMismatch::new(&[1], &[2, 3]),
                at: at("2026-10-10T08:00:00Z"),
                version: "0.9.0".to_owned(),
            },
        });
        let warning = mismatch_warning(&health).expect("a warning");
        assert_eq!(warning.code, MISMATCH_NOTICE);
        assert_eq!(warning.params["count"], "1");
        assert_eq!(warning.params["nodes"], "1001");
        assert!(
            warning
                .detail
                .contains("probe-dmz (node 1001) offers protocol major(s) 2, 3"),
            "{}",
            warning.detail
        );
        assert!(
            warning.detail.contains("which implements 1: probe-dmz"),
            "{}",
            warning.detail
        );
    }

    #[test]
    fn quorum_changes_become_cluster_events() {
        let single = quorum_event(QuorumState::Single);
        assert_eq!(single.topic, Topic::Cluster);
        assert_eq!(single.kind.as_deref(), Some(QUORUM_EVENT));
        assert_eq!(single.params["state"], "single");
        assert_eq!(single.params.len(), 1);
        let isolated = quorum_event(QuorumState::Isolated {
            since: at("2026-10-10T08:00:03Z"),
            last_contact: Some(at("2026-10-10T08:00:00Z")),
            applied: Revision(42),
        });
        assert_eq!(isolated.params["state"], "isolated");
        assert_eq!(isolated.params["since"], "2026-10-10T08:00:03Z");
        assert_eq!(isolated.params["last_contact"], "2026-10-10T08:00:00Z");
        assert_eq!(isolated.params["applied"], "42");
        let electing = quorum_event(QuorumState::Electing {
            since: at("2026-10-10T08:00:01Z"),
        });
        assert_eq!(electing.params["state"], "electing");
        assert!(!electing.params.contains_key("applied"));
    }

    /// A controller's node registry over a memory store, and an on-demand cluster port on
    /// a free loopback port.
    struct OnDemand {
        registry: Arc<NodeRegistry>,
        addr: SocketAddr,
        stop: watch::Sender<bool>,
        task: JoinHandle<()>,
    }

    /// How long a test waits for the port to change before it fails.
    const PORT_WAIT: Duration = Duration::from_secs(20);

    fn system() -> RequestCtx {
        RequestCtx::system(SystemComponent::Cluster)
    }

    impl OnDemand {
        async fn start() -> Self {
            let store = Arc::new(tenko_store::mem::MemStore::default());
            let vault = tenko_vault::MemVault::with_store(Arc::clone(&store));
            let ca = InternalCa::load_or_init(&*store, &vault, &system(), CaPolicy::default())
                .await
                .expect("CA");
            let store: Arc<dyn Store> = store;
            let registry = NodeRegistry::new(store, Arc::new(ca), RegistryConfig::new(NodeId(1)));
            let material = registry
                .controller_material(&vault, &system())
                .await
                .expect("controller certificate");
            let resolver = Arc::new(TlsResolver::default());
            resolver.set(Some(material));
            let addr = std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|listener| listener.local_addr())
                .expect("a free port");
            let (stop, stopped) = watch::channel(false);
            let task = tokio::spawn(on_demand(
                Arc::clone(&registry),
                vec![addr],
                Arc::new(DiscardProbes),
                resolver,
                None,
                None,
                stopped,
            ));
            Self {
                registry,
                addr,
                stop,
                task,
            }
        }

        async fn token(&self) -> (uuid::Uuid, String) {
            let (view, token) = self
                .registry
                .create_enrollment(&system(), NewEnrollment::default())
                .await
                .expect("token");
            (view.id, token.to_text().to_string())
        }

        async fn withdraw(&self, id: uuid::Uuid) {
            self.registry
                .delete_enrollment(&system(), id)
                .await
                .expect("withdraw the token");
        }

        async fn enroll(&self, token: String) {
            let (_, csr) = generate_csr().expect("csr");
            self.registry
                .enroll(
                    &system(),
                    EnrollRequest {
                        token,
                        csr: pem_block("CERTIFICATE REQUEST", &csr),
                        name: Some("probe-lab".to_owned()),
                        roles: Vec::new(),
                        address: Some("192.0.2.20".to_owned()),
                        version: "0.0.1".to_owned(),
                        majors: vec![1],
                    },
                )
                .await
                .expect("enroll");
        }

        /// Waits until the port is open: the registry reports it (the health field
        /// `listening`) and the address cannot be bound by anyone else.
        async fn wait_open(&self, what: &str) {
            let open = || !self.registry.listening().is_empty();
            wait(what, open).await;
            assert!(
                std::net::TcpListener::bind(self.addr).is_err(),
                "{what}: the address is not taken"
            );
        }

        /// Waits until the port is closed: the registry reports no address and the
        /// address can be bound again.
        async fn wait_closed(&self, what: &str) {
            wait(what, || self.registry.listening().is_empty()).await;
            assert!(
                std::net::TcpListener::bind(self.addr).is_ok(),
                "{what}: the address is still taken"
            );
        }

        async fn stop(self) {
            let _ = self.stop.send(true);
            tokio::time::timeout(PORT_WAIT, self.task)
                .await
                .expect("the on-demand port stops")
                .expect("the task ends");
            assert!(std::net::TcpListener::bind(self.addr).is_ok());
        }
    }

    async fn wait(what: &str, check: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + PORT_WAIT;
        while !check() {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_on_demand_port_closes_when_the_last_token_is_withdrawn() {
        let port = OnDemand::start().await;
        port.wait_closed("closed with no token").await;
        let (first, _) = port.token().await;
        port.wait_open("a token opens the port").await;
        let (second, _) = port.token().await;
        port.withdraw(first).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        port.wait_open("a second token keeps the port open").await;
        port.withdraw(second).await;
        port.wait_closed("withdrawing the last token closes the port")
            .await;
        port.token().await;
        port.wait_open("a new token opens the port again").await;
        port.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_enrolled_node_keeps_the_on_demand_port_open() {
        let port = OnDemand::start().await;
        let (id, token) = port.token().await;
        port.wait_open("a token opens the port").await;
        port.enroll(token).await;
        // The used token is gone; the node connects to the port.
        port.withdraw(id).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        port.wait_open("an enrolled node keeps the port open").await;
        port.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_token_closes_the_on_demand_port() {
        let port = OnDemand::start().await;
        // The shortest lifetime, created so long ago that two seconds are left.
        let ttl = tenko_cluster::registry::MIN_TOKEN_TTL;
        let mut cx = system();
        cx.now = Timestamp::now()
            .checked_sub(ttl.saturating_sub(Duration::from_secs(2)))
            .expect("a time");
        port.registry
            .create_enrollment(
                &cx,
                NewEnrollment {
                    expires_in_secs: Some(ttl.as_secs()),
                    ..NewEnrollment::default()
                },
            )
            .await
            .expect("token");
        port.wait_open("a token opens the port").await;
        port.wait_closed("the expiry of the last token closes the port")
            .await;
        port.token().await;
        port.wait_open("a new token opens the port again").await;
        port.stop().await;
    }

    #[tokio::test]
    async fn the_demand_follows_tokens_and_nodes() {
        let port = OnDemand::start().await;
        let now = Timestamp::now();
        assert_eq!(
            port.registry.port_demand(now).await.expect("demand"),
            PortDemand::Idle
        );
        let (_, token) = port.token().await;
        let PortDemand::Until(expires) = port.registry.port_demand(now).await.expect("demand")
        else {
            panic!("a waiting token is a demand until it expires");
        };
        assert!(expires > now);
        assert_eq!(
            port.registry.port_demand(expires).await.expect("demand"),
            PortDemand::Idle,
            "an expired token is no demand"
        );
        port.enroll(token).await;
        assert_eq!(
            port.registry.port_demand(now).await.expect("demand"),
            PortDemand::Enrolled
        );
        port.stop().await;
    }
}
