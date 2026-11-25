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

use std::collections::BTreeMap;
use tenko_cluster::{
    ca::{CertSource, TlsMaterial, TlsResolver},
    identity::{Credentials, NodePaths},
    kek::PeerKekFetch,
    mtls::RevocationSet,
    peers::{MAX_APPEND_BYTES, NodeDirIdentity, PeerConfig, PeerNetwork, PeerTimings, Peers},
    server::{ClusterListener, NodeServices, Port},
    session::Sessions,
};

use tenko_cluster::generation::FenceFile;
use tenko_core::{NodeId, Role};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store as _,
    raft::{RaftStore, clear_joining},
};
use tenko_vault::{KekRing, distribution};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    cluster::recover,
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
    config.data_dir = Some(resolved.data_dir.clone());
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

/// Refuses to start a controller that its own store holds as removed: a revocation names
/// it and no node record does, so every other controller refuses it and it has no
/// certificate to serve with. A controller that was out of contact and never received its
/// removal still has its record, starts and stays cut off.
fn refuse_removed(
    view: &dyn ReadView,
    node: NodeId,
    data_dir: &std::path::Path,
) -> Result<(), StartError> {
    let Some(at) =
        tenko_cluster::registry::removed_at(view, node).map_err(|error| cluster_failed(&error))?
    else {
        return Ok(());
    };
    Err(start_error(
        "cluster.member.removed",
        format!(
            "this controller (node {node}) was removed from the cluster at {}: the other \
             controllers refuse its certificates, and it does not come back with this data \
             directory. To make this host a controller again, move {} aside and join with a \
             new controller token (`tenko cluster join`), which gives it a new node id",
            at.to_rfc3339(),
            data_dir.display()
        ),
    ))
}

/// Whether a controller starts as a member, presenting its identity under
/// `<data_dir>/node/`, rather than as a single controller with the vault's certificate (the
/// states of `tenko_cluster::peers::identity`): a group of several nodes, or a controller
/// alone with an identity under `node/` and a node record (the others were removed) or a
/// forced step's record.
fn starts_as_member(members: usize, identity: bool, forced: bool, recorded: bool) -> bool {
    members > 1 || (identity && (forced || recorded))
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
    network.set_address_map(section.peer_address_map.clone());
    let credentials = identity(resolved)?;
    // A controller that another history of the cluster superseded stays fenced across
    // restarts: the store stops before the peer transport could let it elect.
    if let Some(kept) =
        FenceFile::load(&resolved.data_dir).map_err(|error| cluster_failed(&error))?
    {
        store.fence(kept.kind).await;
    }
    let membership = store.membership();
    // A member of a group of several nodes (a joined controller, or the first one after
    // its first join), or a controller alone that has a node record and its identity under
    // `<data_dir>/node/` (a forced step of the cluster recovery made it the only voter, or
    // the others were removed): it presents that identity, which its record holds, and the
    // superseded controllers dial it at the cluster port of that identity. A controller
    // alone with no record presents the vault's certificate (`node::controller`).
    let (forced, recorded) = {
        let view = store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| StartError::coded("cluster", &error))?;
        refuse_removed(view.as_ref(), resolved.node_id, &resolved.data_dir)?;
        let forced = !view
            .scan_typed(
                &tenko_cluster::generation::GENERATION,
                KeyRange::all(),
                1,
                false,
            )
            .map_err(|error| StartError::coded("cluster", &error))?
            .is_empty();
        let recorded = view
            .get_typed(&tenko_cluster::model::tables::NODES, &resolved.node_id.0)
            .map_err(|error| StartError::coded("cluster", &error))?
            .is_some();
        (forced, recorded)
    };
    let member = starts_as_member(
        membership.voters.len() + membership.learners.len(),
        credentials.is_some(),
        forced,
        recorded,
    );
    if let Some(credentials) = &credentials {
        network.set_tls(
            credentials
                .client_config()
                .map_err(|error| cluster_failed(&error))?,
        );
    }
    let peers = Peers::new(store.clone(), network, peer_config(resolved));
    if let Some(credentials) = &credentials {
        // A single controller's identity is the vault's (`node::controller`), even with an
        // identity under `node/` that its record does not name yet (a first join that
        // stopped before its write).
        if member {
            peers.attach_identity(Arc::new(
                NodeDirIdentity::new(credentials).reloading(NodePaths::new(&resolved.data_dir)),
            ));
        }
        peers.attach_ca_root(credentials.ca_root.clone());
    }
    let pending = recover::pending(&resolved.data_dir);
    peers.hold_record(pending.is_some());
    peers
        .load_generation()
        .await
        .map_err(|error| cluster_failed(&error))?;
    let tasks = Arc::new(Mutex::new(peers.spawn(stop.clone())));
    if let Some(notice) = &pending {
        probe_after_recover(resolved, &peers, notice).await;
    }
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
    let generation = revocations.generation();
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
    revocations.replace(generation, revoked.into_iter().map(|(serial, _, _)| serial));
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
    let announce_stop = stop.clone();
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
    let caught_up = store.fenced().is_none() && catch_up(store, timeout).await;
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
    // The member record says which binary runs here: the leader gates format migrations
    // on it and `tenko cluster upgrade-check` lists it (OPS-08).
    tasks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(tokio::spawn(announce(peers.clone(), announce_stop)));
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

/// What one old voter answered the first start's probe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// It is in contact with a majority of the old voters: the old cluster lives.
    Alive(String),
    /// It answered, without a majority.
    Alone(String),
    /// It answered, but its state cannot be read.
    Unreadable(String),
}

/// How one `Cluster.Members` answer of an old voter reads (section 3.5). An electing voter
/// counts as alone: it cannot know whether its election finds a majority, and one that
/// does answers `healthy` at a later tick of the probe, until its deadline.
fn answer_of(response: &tenko_cluster::proto::v1::MembersResponse) -> Answer {
    let state = response.quorum.as_str();
    match state {
        "healthy" | "single" => Answer::Alive(state.to_owned()),
        "electing" | "isolated" | "fenced" => Answer::Alone(state.to_owned()),
        // A binary that does not report its state: a known leader means a live cluster.
        "" if response.leader_id != 0 => {
            Answer::Alive(format!("follows leader {}", response.leader_id))
        }
        other => Answer::Unreadable(if other.is_empty() {
            "no state reported".to_owned()
        } else {
            format!("state {other}")
        }),
    }
}

/// When this controller's own cluster certificate has expired: every handshake then fails,
/// so silence cannot be told from a live majority, and the probe asks nobody (undecided).
fn own_expiry(resolved: &Resolved) -> Option<tenko_core::Timestamp> {
    Credentials::load(&NodePaths::new(&resolved.data_dir))
        .ok()
        .map(|own| own.info.not_after)
        .filter(|end| *end <= tenko_core::Timestamp::now())
}

/// Logs why a controller whose certificate expired at `end` does not take office.
fn log_expired(end: tenko_core::Timestamp) {
    tracing::error!(
        code = tenko_cluster::generation::codes::MAJORITY_ALIVE,
        "this controller's cluster certificate expired at {end}, so none of the old voters \
         could be asked at this first start after a forced step; it does not take office and \
         refuses writes; check this host's clock first, and if it is right make sure the old \
         voters are stopped, then confirm with `tenko cluster recover --despite-majority` \
         (`--undo` would leave this controller unable to renew its certificate)"
    );
}

/// The first start after a forced step (section 3.5): asks every old voter for its quorum
/// state, speaking for the parent history, for `[cluster] recover_probe_secs`. Takes office
/// (ends the notice) when nobody answers or every answer is without a majority; otherwise
/// keeps the record unsent and fences the store with `cluster.recover.majority_alive`,
/// unless `--despite-majority` was confirmed.
async fn probe_after_recover(resolved: &Resolved, peers: &Peers, notice: &recover::Notice) {
    let deadline = Instant::now() + Duration::from_secs(resolved.config.cluster.recover_probe_secs);
    let claim = recover::parent_claim(notice).render();
    let mut answers: BTreeMap<NodeId, Answer> = BTreeMap::new();
    let expired = own_expiry(resolved);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    while expired.is_none() {
        tick.tick().await;
        // Every voter is asked again at every tick until the deadline: one that answers
        // alone now may be part of a majority that elects a moment later (a power outage
        // ends for everybody at once). Only a live majority ends the probe early.
        for old in &notice.old {
            let call = peers.probe_members(old.node, &old.address, claim.as_deref());
            match tokio::time::timeout(PROBE_CALL, call).await {
                Ok(Some(Ok(response))) => {
                    answers.insert(old.node, answer_of(&response));
                }
                Ok(Some(Err(status))) => {
                    // A refusal that carries another forced history is evidence of it: this
                    // controller does not take office beside it (`--undo` lets it meet that
                    // history as a plain member). Its records are read, never acted on here.
                    if let Some(code) = tenko_cluster::server::code_of(&status) {
                        let answer = refused(code, status.message(), peers.competing(&status));
                        answers.insert(old.node, answer);
                    }
                }
                _ => {}
            }
        }
        let alive = answers
            .values()
            .any(|answer| matches!(answer, Answer::Alive(_)));
        if alive || Instant::now() >= deadline {
            break;
        }
    }
    if let Some(end) = expired.filter(|_| !notice.despite_majority) {
        log_expired(end);
        peers.refuse_office().await;
        return;
    }
    let live = keeping_out(&answers);
    if !live.is_empty() && !notice.despite_majority {
        tracing::error!(
            code = tenko_cluster::generation::codes::MAJORITY_ALIVE,
            controllers = %live.join(", "),
            "the old cluster answered at this first start after a forced step: {}; this \
             controller does not take office and refuses writes; stop it and run `tenko \
             cluster recover --undo` to rejoin the live cluster, or confirm with `tenko \
             cluster recover --despite-majority`",
            live.join(", ")
        );
        peers.refuse_office().await;
        return;
    }
    if let Err(error) = recover::took_office(&resolved.data_dir) {
        // With the notice still there `--undo` would bring the old store back after the
        // old voters met this history: office is not taken.
        tracing::error!(
            "that the forced step took office could not be recorded ({error}); this controller does not take office"
        );
        peers.refuse_office().await;
        return;
    }
    peers.hold_record(false);
    tracing::error!(
        code = tenko_cluster::generation::actions::FORCE.as_str(),
        generation = notice.generation,
        answered = answers.len(),
        "this controller took office as generation {} of the cluster after a forced step; \
         the superseded controllers stop writing when the record reaches them",
        notice.generation
    );
}

/// How a coded refusal of an old voter reads, with `rival`, the other forced history its
/// records name, if any.
fn refused(
    code: &str,
    message: &str,
    rival: Result<Option<String>, tenko_cluster::error::ClusterError>,
) -> Answer {
    match rival {
        Ok(Some(rival)) => Answer::Alive(format!("another history: {rival}")),
        Ok(None) if code == tenko_cluster::generation::codes::SUPERSEDED => {
            Answer::Alone("superseded already".to_owned())
        }
        Ok(None) => Answer::Unreadable(format!("refused with {code}: {message}")),
        Err(error) => Answer::Unreadable(format!(
            "its records could not be checked here: {}",
            error.code()
        )),
    }
}

/// The old voters whose answers keep this controller out of office: a live cluster, or an
/// answer that cannot be read. Silence and a voter alone keep nobody out.
fn keeping_out(answers: &BTreeMap<NodeId, Answer>) -> Vec<String> {
    answers
        .iter()
        .filter_map(|(node, answer)| match answer {
            Answer::Alive(state) => Some(format!("{node} ({state})")),
            Answer::Unreadable(state) => Some(format!("{node} ({state}, undecided)")),
            Answer::Alone(_) => None,
        })
        .collect()
}

/// How long one probe call may take.
const PROBE_CALL: Duration = Duration::from_secs(2);

/// How long a member waits before it tries again to report its binary.
const ANNOUNCE_RETRY: Duration = Duration::from_secs(5);

/// Reports this member's binary in its member record, retrying while there is no quorum,
/// until it succeeds or the server stops.
async fn announce(peers: Peers, mut stop: watch::Receiver<bool>) {
    loop {
        match peers.announce().await {
            Ok(_) => return,
            Err(error) => {
                tracing::debug!(%error, "cannot report this controller's binary yet; retrying");
            }
        }
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            () = tokio::time::sleep(ANNOUNCE_RETRY) => {}
        }
    }
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

#[cfg(test)]
mod tests {
    use tenko_cluster::proto::v1::MembersResponse;

    use super::*;

    /// A controller that answers in an old voter's place with a certificate of another node
    /// keeps the forced controller out of office, alone or beside a live cluster; only
    /// silence lets it take office.
    #[test]
    fn a_refused_certificate_keeps_the_forced_controller_out_of_office() {
        let reason = "the certificate names controller 4, not 2";
        let refused = refused("cluster.peer.unreachable", reason, Ok(None));
        let healthy = answer_of(&MembersResponse {
            quorum: "healthy".to_owned(),
            ..MembersResponse::default()
        });
        assert!(keeping_out(&BTreeMap::new()).is_empty(), "all silent");
        assert_eq!(
            keeping_out(&BTreeMap::from([(NodeId(2), refused.clone())])),
            [format!(
                "2 (refused with cluster.peer.unreachable: {reason}, undecided)"
            )],
            "one refused, the others silent"
        );
        assert_eq!(
            keeping_out(&BTreeMap::from([
                (NodeId(2), refused),
                (NodeId(3), healthy)
            ]))
            .len(),
            2,
            "one refused, one healthy"
        );
    }

    /// The start paths of the identity states: a controller that never joined, or one
    /// restored on a host without its identity, starts single with the vault's certificate;
    /// a member, a cluster that shrank to one, a forced controller and a restore on its own
    /// host start as members with the identity under `node/`.
    #[test]
    fn the_start_path_follows_the_identity_state() {
        // (members, identity under node/, forced, own node record) -> member
        for (members, identity, forced, recorded, member) in [
            (1, false, false, false, false), // never joined
            (1, true, false, false, false),  // first join written, not recorded yet
            (1, false, false, true, false),  // restored on a new host: settles at start
            (3, true, false, true, true),    // joined
            (1, true, false, true, true),    // shrunk to one, or restored on its own host
            (1, true, true, true, true),     // forced
        ] {
            assert_eq!(
                starts_as_member(members, identity, forced, recorded),
                member,
                "{members} members, identity {identity}, forced {forced}, recorded {recorded}"
            );
        }
    }

    /// A controller starts unless its own store holds its removal: the first controller
    /// before its first join (no record, no revocation) and one whose record stands beside
    /// the revocation of a retired key start; one that a revocation names and no record
    /// does is refused with `cluster.member.removed`, the time and what to do.
    #[tokio::test]
    async fn a_controller_that_its_store_holds_as_removed_does_not_start() {
        use tenko_cluster::model::{NodeRecord, ProtocolState, Revocation, tables};
        use tenko_core::{RequestCtx, SystemComponent, Timestamp};
        use tenko_store::{Store, WriteBatch, mem::MemStore};

        let store = MemStore::default();
        let node = NodeId(1002);
        let data = std::path::Path::new("/var/lib/tenko");
        let check = async || {
            let view = store.read(ReadConsistency::Local).await.expect("view");
            refuse_removed(view.as_ref(), node, data)
        };
        check()
            .await
            .expect("the first controller before its first join");

        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let revoked_at = Timestamp::from_unix_nanos(1_700_000_000_000_000_000).expect("time");
        let certificate = tenko_cluster::model::CertificateRef {
            serial: "0a".to_owned(),
            sha256: String::new(),
            not_before: revoked_at,
            not_after: revoked_at,
        };
        let record = NodeRecord {
            id: node,
            name: "controller-1002".to_owned(),
            roles: vec![Role::Controller],
            address: None,
            vrf: None,
            certificate: certificate.clone(),
            serials: vec![certificate],
            enrolled_at: revoked_at,
            enrollment: uuid::Uuid::nil(),
            enrolled_by: None,
            renewed_at: None,
            last_seen: None,
            version: None,
            protocol: ProtocolState::default(),
        };
        let revocation = Revocation {
            node,
            revoked_at,
            not_after: revoked_at,
            controller: true,
        };
        let mut batch = WriteBatch::for_request(&ctx);
        batch
            .put_typed(&tables::NODES, &node.0, &record)
            .expect("record");
        batch
            .put_typed(&tables::REVOCATIONS, &"retired".to_owned(), &revocation)
            .expect("revocation");
        store.propose(batch).await.expect("write");
        check()
            .await
            .expect("a record beside the revocation of a retired key");

        let mut batch = WriteBatch::for_request(&ctx);
        batch.delete_typed(&tables::NODES, &node.0);
        store.propose(batch).await.expect("write");
        let refused = check().await.expect_err("removed");
        assert_eq!(
            (refused.step, refused.code.as_str()),
            ("cluster", "cluster.member.removed")
        );
        for part in [
            revoked_at.to_rfc3339().as_str(),
            "tenko cluster join",
            "/var/lib/tenko",
        ] {
            assert!(refused.message.contains(part), "{}", refused.message);
        }
    }

    /// An answer as a binary sends it: the leader it knows (0 for none) and its state.
    fn answer(quorum: &str, leader: u64) -> Answer {
        answer_of(&MembersResponse {
            leader_id: leader,
            term: 3,
            members: Vec::new(),
            quorum: quorum.to_owned(),
            applied: Some(7),
        })
    }

    /// Only a voter with a leader counts as a live old cluster; an electing one, which
    /// knows no leader, counts as alone until the probe's deadline.
    #[test]
    fn an_old_voter_with_a_leader_counts_as_alive() {
        assert!(matches!(answer("healthy", 1), Answer::Alive(_)));
        assert!(matches!(answer("single", 1), Answer::Alive(_)));
        assert!(matches!(answer("electing", 0), Answer::Alone(_)));
        assert!(matches!(answer("isolated", 0), Answer::Alone(_)));
        assert!(matches!(answer("fenced", 0), Answer::Alone(_)));
        // A binary that reports no state: a known leader is a live cluster.
        assert!(matches!(answer("", 4), Answer::Alive(_)));
        assert!(matches!(answer("", 0), Answer::Unreadable(_)));
        assert!(matches!(answer("later", 0), Answer::Unreadable(_)));
    }
}
