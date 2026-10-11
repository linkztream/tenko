//! Start step 3 of `tenko serve`, `cluster`: the peer layer of this controller.
//!
//! Every controller gets a [`Peers`] layer over its store: the peer transport, write
//! forwarding and the `Raft` and `Cluster` services. What else happens depends on whether
//! the controller is a member of a cluster:
//!
//! - **A single controller** (the only node of its Raft group) has nothing to join. Its
//!   cluster identity is still a system secret of the vault, so the peer transport gets its
//!   credentials in the `nodes` step, which also opens the cluster port as before; the
//!   `Raft` and `Cluster` services ride on that port, ready for the first controller that
//!   joins.
//! - **A member** keeps its identity under `<data_dir>/node/`. The step opens the cluster
//!   port at once (its peers replicate to it while it catches up; the node services answer
//!   `UNAVAILABLE` until the `nodes` step attaches them), then waits until it has applied
//!   what the leader committed (a linearizable read through the leader), at most
//!   `[cluster] catch_up_timeout_secs`; after that it starts isolated and catches up in the
//!   background. Last it fetches key generations it lacks (a rotation while it was
//!   stopped) from its peers, before the vault opens them.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_cluster::{
    ca::{CertSource, TlsMaterial, TlsResolver},
    identity::{Credentials, NodePaths},
    kek::PeerKekFetch,
    mtls::RevocationSet,
    peers::{MAX_APPEND_BYTES, NodeDirIdentity, PeerConfig, PeerNetwork, PeerTimings, Peers},
    server::{ClusterListener, NodeServices, Port},
    session::Sessions,
};
use tenko_core::Role;
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt as _, Store as _,
    raft::{RaftStore, clear_joining},
};
use tenko_vault::{KekRing, distribution};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    config::{ClusterListen, Resolved},
    serve::StartError,
};

/// The cluster port a member opened in step 3, for the `nodes` step.
#[derive(Debug, Clone)]
pub struct OpenPort {
    /// The node services the `nodes` step attaches.
    pub nodes: NodeServices,
    /// The certificate the port presents (renewed by the `nodes` step).
    pub resolver: Arc<TlsResolver>,
    /// The revoked serials the TLS verifier checks (the registry shares them).
    pub revocations: Arc<RevocationSet>,
    /// The connections by node (the registry shares them).
    pub sessions: Arc<Sessions>,
    /// The bound addresses.
    pub addrs: Vec<SocketAddr>,
}

/// What step 3 hands to the later steps: the peer layer, and the cluster port when this
/// controller is a member. Cloning is cheap.
#[derive(Clone)]
pub struct ClusterPeers {
    peers: Peers,
    port: Option<OpenPort>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl std::fmt::Debug for ClusterPeers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterPeers")
            .field("member", &self.port.is_some())
            .finish_non_exhaustive()
    }
}

impl ClusterPeers {
    /// The peer layer.
    pub fn peers(&self) -> &Peers {
        &self.peers
    }

    /// The cluster port this member opened in step 3; `None` on a single controller.
    pub fn port(&self) -> Option<&OpenPort> {
        self.port.as_ref()
    }

    /// The background tasks (the cluster port, the leader's promotion loop), for the
    /// server's stop sequence; a second call returns nothing.
    pub fn tasks(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut *self.tasks.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// What step 3 needs.
pub struct Start<'a> {
    /// The configuration.
    pub resolved: &'a Resolved,
    /// The store of step 2.
    pub store: &'a RaftStore,
    /// The key generations of step 1.
    pub ring: KekRing,
    /// Turns true when the server stops.
    pub stop: watch::Receiver<bool>,
}

fn start_error(code: &str, message: impl Into<String>) -> StartError {
    StartError::new("cluster", code, message)
}

fn cluster_failed(error: &tenko_cluster::error::ClusterError) -> StartError {
    StartError::new("cluster", error.code(), error.detail())
}

/// The address this controller's peers reach its cluster port at: `[node] address`, else
/// the first `[cluster] advertise` entry, else none (the first controller learns it from
/// the first join).
pub fn own_address(resolved: &Resolved) -> String {
    let node = resolved.config.node.address.trim();
    if !node.is_empty() {
        return node.to_owned();
    }
    resolved
        .config
        .cluster
        .advertise
        .first()
        .cloned()
        .unwrap_or_default()
}

/// The peer settings of the configuration.
pub fn peer_config(resolved: &Resolved) -> PeerConfig {
    let section = &resolved.config.cluster;
    let mut config = PeerConfig::new(resolved.node_id, crate::upgrade::migrations::CURRENT);
    config.address = own_address(resolved);
    crate::version().clone_into(&mut config.version);
    config.auto_promote = section.auto_promote;
    config.promote_lag_entries = section.promote_lag_entries;
    config
}

/// The controller identity under `<data_dir>/node/`, if there is one.
fn identity(resolved: &Resolved) -> Result<Option<Credentials>, StartError> {
    let paths = NodePaths::new(&resolved.data_dir);
    if !paths.is_enrolled() {
        return Ok(None);
    }
    let credentials = Credentials::load(&paths).map_err(|error| cluster_failed(&error))?;
    if !credentials.certificate_roles().contains(Role::Controller) {
        return Ok(None);
    }
    if credentials.identity.node != resolved.node_id {
        return Err(start_error(
            "cluster.member.identity",
            format!(
                "the cluster identity in {} belongs to node {}, but [node] id is {}; start with \
                 the configuration that `tenko cluster join` wrote",
                paths.root().display(),
                credentials.identity.node,
                resolved.node_id
            ),
        ));
    }
    Ok(Some(credentials))
}

/// Refuses store limits under which one Raft entry could exceed the largest append
/// request the peer transport sends ([`MAX_APPEND_BYTES`]): such an entry could never
/// replicate.
fn check_entry_limit(store: &RaftStore) -> Result<(), StartError> {
    let coalescer = store.config().coalescer;
    // A batch travels alone when it is larger than an entry; the encoding and the audit
    // drafts add to its payload.
    let largest = coalescer.max_entry_bytes.max(coalescer.max_batch_bytes) * 5 / 4 + 1024 * 1024;
    if largest > MAX_APPEND_BYTES {
        return Err(start_error(
            "cluster.config.batch_limit",
            format!(
                "a Raft entry of up to {largest} bytes cannot replicate within the {MAX_APPEND_BYTES} \
                 bytes of an append request; lower the store's batch and entry limits"
            ),
        ));
    }
    Ok(())
}

/// Runs step 3 and returns the peer layer and the key ring for the vault.
///
/// # Errors
///
/// A [`StartError`] of the step `cluster`: a member without its identity, a cluster port
/// that cannot listen, or key generations that are missing and no member hands over.
#[allow(
    clippy::too_many_lines,
    reason = "the start step reads best as one sequence"
)]
pub async fn start_peers(
    start: Start<'_>,
) -> Result<((ClusterPeers, KekRing), String), StartError> {
    let Start {
        resolved,
        store,
        ring,
        stop,
    } = start;
    let section = &resolved.config.cluster;
    check_entry_limit(store)?;
    store.set_isolation_after(Duration::from_millis(section.isolation_after_ms));
    let network = PeerNetwork::new(resolved.node_id, PeerTimings::from_store(store.config()));
    let credentials = identity(resolved)?;
    let membership = store.membership();
    // A member of a group of several nodes (a joined controller, or the first one after
    // its first join).
    let member = membership.voters.len() + membership.learners.len() > 1;
    if let Some(credentials) = &credentials {
        network.set_tls(
            credentials
                .client_config()
                .map_err(|error| cluster_failed(&error))?,
        );
    }
    let peers = Peers::new(store.clone(), network, peer_config(resolved));
    if let Some(credentials) = &credentials {
        peers.attach_identity(Arc::new(NodeDirIdentity::new(credentials)));
    }
    let tasks = Arc::new(Mutex::new(peers.spawn(stop.clone())));
    if !member {
        let summary = format!(
            "single controller (node {}), nothing to join",
            resolved.node_id
        );
        return Ok((
            (
                ClusterPeers {
                    peers,
                    port: None,
                    tasks,
                },
                ring,
            ),
            summary,
        ));
    }
    let Some(credentials) = credentials else {
        return Err(start_error(
            "cluster.member.no_identity",
            format!(
                "this controller is a member of a cluster but has no cluster identity in {}",
                NodePaths::new(&resolved.data_dir).root().display()
            ),
        ));
    };
    let addrs = match section
        .listen_mode()
        .map_err(|error| StartError::new("cluster", error.code, error.message))?
    {
        ClusterListen::Always(addrs) | ClusterListen::OnDemand(addrs) => addrs,
        ClusterListen::Off => {
            return Err(start_error(
                "cluster.member.port_off",
                "a member of a controller cluster needs its cluster port; remove `listen = []` \
                 from [cluster]",
            ));
        }
    };
    let listener = ClusterListener::bind(&addrs)
        .await
        .map_err(|error| cluster_failed(&error))?;
    let bound = listener.local_addrs();
    let revocations = Arc::new(RevocationSet::new());
    let view = store
        .read(ReadConsistency::Local)
        .await
        .map_err(|error| StartError::coded("cluster", &error))?;
    let revoked = view
        .scan_typed(
            &tenko_cluster::model::tables::REVOCATIONS,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(|error| StartError::coded("cluster", &error))?;
    drop(view);
    revocations.replace(revoked.into_iter().map(|(serial, _, _)| serial));
    let sessions = Sessions::new();
    let nodes = NodeServices::new();
    let certificate = Arc::new(TlsResolver::default());
    certificate.set(Some(
        TlsMaterial::from_der(
            credentials.chain.clone(),
            &credentials.key,
            CertSource::Inline,
        )
        .map_err(|error| StartError::coded("cluster", &error))?,
    ));
    let served = listener
        .serve_port(
            Port {
                ca_root: credentials.ca_root.clone(),
                resolver: Arc::clone(&certificate) as _,
                revocations: Arc::clone(&revocations),
                sessions: Arc::clone(&sessions),
                nodes: nodes.clone(),
                peers: Some(peers.clone()),
            },
            stop,
            || {},
        )
        .map_err(|error| cluster_failed(&error))?;
    tasks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(served);

    let timeout = Duration::from_secs(section.catch_up_timeout_secs);
    let caught_up = catch_up(store, timeout).await;
    let ring = distribution::fetch_missing(
        store,
        &resolved.kek,
        &resolved.kek_options,
        ring,
        resolved.node_id,
        &PeerKekFetch::new(peers.clone()),
    )
    .await
    .map_err(|error| StartError::coded("cluster", &error))?;
    let _ = clear_joining(&resolved.layout().store());
    let status = store.status();
    let membership = store.membership();
    let summary = format!(
        "member of a cluster of {} voter(s) and {} learner(s) (node {}), leader {}, {} at revision {}, cluster port on {}",
        membership.voters.len(),
        membership.learners.len(),
        resolved.node_id,
        status
            .leader
            .map_or_else(|| "unknown".to_owned(), |leader| leader.to_string()),
        if caught_up {
            "caught up"
        } else {
            "isolated, catching up"
        },
        status.revision,
        bound
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !caught_up {
        tracing::warn!(
            timeout_secs = timeout.as_secs(),
            "this controller did not reach the leader within [cluster] catch_up_timeout_secs; \
             it starts isolated and catches up in the background"
        );
    }
    Ok((
        (
            ClusterPeers {
                peers,
                port: Some(OpenPort {
                    nodes,
                    resolver: certificate,
                    revocations,
                    sessions,
                    addrs: bound,
                }),
                tasks,
            },
            ring,
        ),
        summary,
    ))
}

/// Waits until this member has applied everything the leader committed before the call:
/// a linearizable read (through the leader's read index), retried until `timeout`.
pub async fn catch_up(store: &RaftStore, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if store.read(ReadConsistency::Linearizable).await.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
