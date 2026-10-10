//! The `cluster` start step of `tenko serve` on a controller: the internal CA (created here
//! when the API listener does not use it), the node registry with its job step, the
//! controller's certificate on the cluster port, the cluster port itself (always, on demand
//! or off, `[cluster] listen`), the hand-over of probe batches to the reconciler, and the
//! cluster summary and notices of `GET /system/status`.

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
    ca::{CaPolicy, InternalCa, TlsResolver},
    error::ClusterError,
    probe::{DiscardProbes, IngestCounts, ProbeBatch, ProbeSink},
    registry::{NodeRegistry, RegistryConfig},
    server::ClusterListener,
};
use tenko_core::{NodeId, RequestCtx, SystemComponent, Timestamp, VrfId};
use tenko_jobs::JobEngine;
use tenko_store::{ChangeStream, ReadViewExt as _, Store, WatchFilter};
use tenko_vault::StoreVault;
use tokio::{sync::watch, task::JoinHandle};

use crate::{
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
/// How often expired revocations and old tokens are pruned and the revocation list is read
/// again (other controllers revoke too, Slice 3).
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
        step: "cluster",
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

/// Starts the node transport of a controller.
///
/// # Errors
///
/// A [`StartError`] of the step `cluster`: the CA, the registry, the controller
/// certificate or a cluster port that must listen and cannot.
#[allow(
    clippy::too_many_lines,
    reason = "the start step reads best as one sequence"
)]
pub async fn start(parts: Parts<'_>) -> Result<(Cluster, String), StartError> {
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
        .map_err(|error| StartError::new("cluster", error.code, error.message))?;
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = InternalCa::load_or_init(store.as_ref(), vault.as_ref(), &ctx, CaPolicy::default())
        .await
        .map_err(|error| StartError::coded("cluster", &error))?;
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
        default_token_ttl: Duration::from_secs(section.enrolment_ttl_secs),
        ..RegistryConfig::new(resolved.node_id)
    };
    let registry = NodeRegistry::new(Arc::clone(&store), Arc::new(ca), config);
    registry.register_steps(&engine);
    let revoked = registry
        .load_revocations()
        .await
        .map_err(|error| start_error(&error))?;
    let material = registry
        .controller_material(vault.as_ref(), &ctx)
        .await
        .map_err(|error| start_error(&error))?;
    let resolver = Arc::new(TlsResolver::default());
    resolver.set(Some(material));
    let sink: Arc<dyn ProbeSink> = match reconciler {
        Some(reconciler) => Arc::new(ReconcilerSink { reconciler }),
        None => Arc::new(DiscardProbes),
    };
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
                    .serve(&registry, Arc::clone(&sink), resolver.clone(), stop.clone())
                    .map_err(|error| start_error(&error))?,
            );
            format!("cluster port on {}", addresses(&bound))
        }
        ClusterListen::OnDemand(addrs) if in_use => {
            let listener = ClusterListener::bind(&addrs)
                .await
                .map_err(|error| start_error(&error))?;
            let bound = listener.local_addrs();
            tasks.push(
                listener
                    .serve(&registry, Arc::clone(&sink), resolver.clone(), stop.clone())
                    .map_err(|error| start_error(&error))?,
            );
            format!("cluster port on {}", addresses(&bound))
        }
        ClusterListen::OnDemand(addrs) => {
            tasks.push(tokio::spawn(on_demand(
                Arc::clone(&registry),
                addrs.clone(),
                Arc::clone(&sink),
                resolver.clone(),
                stop.clone(),
            )));
            format!(
                "cluster port {} opens with the first enrolment token",
                addresses(&addrs)
            )
        }
        ClusterListen::Off => "cluster port off ([cluster] listen = [])".to_owned(),
    };
    tasks.push(tokio::spawn(maintenance(
        Arc::clone(&registry),
        Arc::clone(&vault),
        resolver,
        stop.clone(),
    )));
    let state = Arc::new(OnceLock::new());
    tasks.push(tokio::spawn(health(
        Arc::clone(&registry),
        Arc::clone(&state),
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
        let _ = self.state.set(state.clone());
    }

    /// The node registry.
    pub fn registry(&self) -> &Arc<NodeRegistry> {
        &self.registry
    }

    /// Where probe batches go on this controller: a probe role on the controller node
    /// itself (WP2.3) hands its batches here directly, under this node's id, without the
    /// cluster port.
    pub fn probe_sink(&self) -> Arc<dyn ProbeSink> {
        Arc::clone(&self.sink)
    }
}

/// Opens the cluster port once an enrolment token asks for it.
async fn on_demand(
    registry: Arc<NodeRegistry>,
    addrs: Vec<SocketAddr>,
    sink: Arc<dyn ProbeSink>,
    resolver: Arc<TlsResolver>,
    mut stop: watch::Receiver<bool>,
) {
    tokio::select! {
        () = registry.listener_wanted() => {}
        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
    }
    let listener = match ClusterListener::bind(&addrs).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(code = %error.code(), "{}", error.detail());
            return;
        }
    };
    match listener.serve(&registry, sink, resolver, stop) {
        Ok(task) => {
            let _ = task.await;
        }
        Err(error) => tracing::error!(code = %error.code(), "{}", error.detail()),
    }
}

/// Prunes expired revocations and old tokens, reads the revocation list again and renews
/// the controller's certificate on the cluster port when it is due.
async fn maintenance(
    registry: Arc<NodeRegistry>,
    vault: Arc<StoreVault>,
    resolver: Arc<TlsResolver>,
    mut stop: watch::Receiver<bool>,
) {
    let mut prune = tokio::time::interval(MAINTENANCE_INTERVAL);
    prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut certificate = tokio::time::interval(CERT_INTERVAL);
    certificate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Both intervals fire at once; the start step just did both.
    prune.tick().await;
    certificate.tick().await;
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = prune.tick() => {
                match registry.prune(Timestamp::now()).await {
                    Ok(0) => {}
                    Ok(count) => tracing::info!(count, "expired revocations and old enrolment tokens removed"),
                    Err(error) => tracing::warn!(code = %error.code(), "{}", error.detail()),
                }
                if let Err(error) = registry.load_revocations().await {
                    tracing::warn!(code = %error.code(), "{}", error.detail());
                }
            }
            _ = certificate.tick() => {
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
/// enrols, connects or disconnects, is revoked, reports another version or a refused
/// handshake: each of these writes the node's record), and every [`HEALTH_INTERVAL`] as
/// the fallback. When the summary or the warning changed, a `cluster` event follows
/// ([`STATUS_EVENT`]): the store's own event of the change can reach the views before the
/// summary is refreshed, so they read the status again on this one and find the new state.
async fn health(
    registry: Arc<NodeRegistry>,
    state: Arc<OnceLock<AppState>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(HEALTH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let filter = WatchFilter::namespaces(["cluster"]);
    let mut changes = registry.store().watch(None, filter.clone()).ok();
    let mut shown: Option<(ClusterStatus, Option<StatusWarning>)> = None;
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = tick.tick() => {}
            received = next_change(&mut changes) => {
                if received {
                    // A burst of writes (an enrolment writes the node and its token) is one
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
            "nodes share no protocol major with this controller, which implements {}:              {detail}; upgrade the older side",
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
