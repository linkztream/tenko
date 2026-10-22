//! The `dhcp` role in the process (plan sections 2.2, 2.10 and 2.12, WP7.5): the serving
//! tables fed from the store, the listeners over them, the status report and the node
//! commands.
//!
//! [`Role::start`] runs in this order, and the role answers only at its end:
//!
//! 1. The in-process feed registers with the store ([`crate::store_feed`]) and gives the
//!    first image of the rows: the configuration, the leases and the IPAM rows.
//! 2. The configuration image ([`crate::config::image::build`]) and the lease table
//!    ([`LeaseIndex`] in a [`SharedLeases`]) are built from that image.
//! 3. The lease store on the replicated store ([`StoreLeases`]) and its committer start;
//!    a commit is applied to the shared table before its ticket completes.
//! 4. The listeners bind and the workers start over the image and the table
//!    ([`DhcpServer::start_with`]). Only now does the node answer, from complete tables.
//! 5. The follower takes the feed's events: a delta's lease rows go into the table at the
//!    delta's revision (the role's own commits are there already; the copy changes
//!    nothing), its configuration rows into the image, which is rebuilt and swapped whole;
//!    a reset (a snapshot install) builds both aside and swaps them together under the
//!    table's write guard ([`DhcpServer::swap`]), carrying over the rows the role
//!    committed after the image's revision.
//!
//! [`Role::stop`] closes the listeners and waits for the workers, then stops the follower
//! and the committer (changes still queued are failed, so no ACK leaves for them).
//!
//! The node's commands ([`commands`]) and its report ([`DhcpStatus`]) go through
//! [`DhcpNode`], the node-command interface: local on the one node of Phase 3, the same
//! kinds over the command stream to a remote `dhcp` node in Phase 5. [`metrics`] registers
//! the engine's per-worker counters and the lazy gauges under the contracts' names.

pub mod commands;
pub mod metrics;
// WP8.1: the role as a move job reaches it.
pub mod moves;

use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    NodeId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseEvent, LeaseEventKind, tables},
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreError, WriteBatch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use self::commands::{CommandResult, Outcome, Output};
use crate::{
    config::image::build,
    feed::{Change, DhcpData, DhcpFeed, FeedError, FeedEvent},
    lease::{
        CommitSettings, LeaseTable as _, SharedLeases, StoreLeases,
        batch::{NoObservations, ObservationHook},
        follow::index_from_data,
        refusal::Finding,
    },
    server::{DhcpServer, ListenerInfo, ServerConfig},
    store_feed::{self, FeedProgress, StoreFeed},
};

/// How long the role waits before it reads a new image after its feed failed.
const FEED_RETRY: Duration = Duration::from_secs(1);

/// What the role starts with.
#[derive(Debug, Clone)]
pub struct RoleSettings {
    /// The listeners, workers and engine settings.
    pub server: ServerConfig,
    /// The committer's limits.
    pub commit: CommitSettings,
    /// Whether a `probe` role runs in the process (conflict detection can run, WP8.5).
    pub probe: bool,
    /// Whether the profile expects conflict detection and warns without a probe
    /// (TGL-16: Hardened).
    pub probe_expected: bool,
}

/// Why the role did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The store could not be read.
    #[error("the DHCP feed: {0}")]
    Feed(String),
    /// A listener could not be bound.
    #[error("a DHCP listener: {0}")]
    Bind(#[source] io::Error),
}

/// The report `dhcp.status` of a node's role.
#[derive(Debug, Clone, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of a report, each a field of the status route"
)]
pub struct DhcpStatus {
    /// The node.
    pub node: NodeId,
    /// Whether the role answers: it runs and has at least one listener.
    pub serving: bool,
    /// Whether the store takes lease writes (P3-Q14).
    pub accepting: bool,
    /// The finding while the store refuses.
    pub refusal: Option<Finding>,
    /// Whether a `probe` role runs in the process.
    pub probe: bool,
    /// Whether the profile expects one (TGL-16).
    pub probe_expected: bool,
    /// The listeners.
    pub listeners: Vec<ListenerInfo>,
    /// The scopes in the image.
    pub scopes: usize,
    /// The leases by binding state.
    pub leases: [(BindingState, usize); 7],
    /// The last commit's time from hand-off to completion.
    pub last_commit: Option<Duration>,
    /// The revision of the configuration image served.
    pub revision: Revision,
    /// Revisions the role's tables are behind the store's newest change of their rows.
    pub lag: u64,
    /// When the role started.
    pub started: Timestamp,
    /// Images installed whole since the start: snapshot installs and the feed's recoveries.
    pub installs: u64,
}

/// A node's DHCP role as the API reaches it: locally in Phase 3.
#[async_trait::async_trait]
pub trait DhcpNode: Send + Sync {
    /// The node.
    fn node(&self) -> NodeId;

    /// The report `dhcp.status`.
    fn status(&self) -> DhcpStatus;

    /// Runs one command of the kinds of [`commands`]; `args` is the CBOR of the kind's
    /// arguments.
    async fn execute(&self, kind: &str, args: &[u8]) -> CommandResult;
}

/// The `dhcp` role of this process, as the API and the metrics read it.
pub struct LocalNode {
    node: NodeId,
    server: RwLock<Option<Arc<DhcpServer<SharedLeases>>>>,
    leases: SharedLeases,
    lease_store: StoreLeases,
    store: Arc<dyn Store>,
    progress: FeedProgress,
    started: Timestamp,
    installs: Arc<AtomicU64>,
    probe: AtomicBool,
    probe_expected: AtomicBool,
    // WP8.1: the observation hook, for the operator's release as for the committer.
    observations: Arc<dyn ObservationHook>,
}

impl std::fmt::Debug for LocalNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNode")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl LocalNode {
    fn server(&self) -> Option<Arc<DhcpServer<SharedLeases>>> {
        self.server
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The lease table.
    pub fn leases(&self) -> &SharedLeases {
        &self.leases
    }

    /// The lease store (its refusal gate and counters).
    pub fn lease_store(&self) -> &StoreLeases {
        &self.lease_store
    }

    /// Follows a change of the profile's expectation of a probe (TGL-16).
    pub fn set_probe_expected(&self, expected: bool) {
        self.probe_expected.store(expected, Ordering::Relaxed);
    }

    /// The counters of the role (`dhcp.stats`).
    pub fn stats(&self) -> commands::DhcpStats {
        let server = self.server();
        commands::DhcpStats {
            engine: server
                .as_ref()
                .map(|server| server.metrics())
                .unwrap_or_default(),
            commits: self.lease_store.stats(),
            queued: self.lease_store.queued(),
            in_flight: server.as_ref().map_or(0, |server| server.in_flight()),
            offers: server.as_ref().map_or(0, |server| server.offers_held()),
            leases: self.leases.read().len(),
        }
    }

    /// Writes `addr` as released by an operator (`dhcp.lease.release`): the row becomes
    /// `released` now, with a history row of kind `reclaimed`, under a version
    /// precondition so that a commit of the role in between makes the release fail rather
    /// than overwrite it.
    async fn release(&self, args: &[u8]) -> CommandResult {
        let args: commands::ReleaseArgs = match tenko_core::codec::from_cbor(args) {
            Ok(args) => args,
            Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
        };
        match self.release_row(&args).await {
            Ok(row) => CommandResult::done(
                format!("the lease of {} is released", row.lease.addr),
                Output::Lease(Box::new(row)),
            ),
            Err(result) => result,
        }
    }

    async fn release_row(
        &self,
        args: &commands::ReleaseArgs,
    ) -> Result<commands::LeaseRow, CommandResult> {
        let now = Timestamp::now();
        let vrf = self.vrf_of(args.vrf, args.addr)?;
        let key = (vrf, args.addr);
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| CommandResult::failed(error.to_string()))?;
        let (lease, revision) = view
            .get_typed(&tables::LEASES, &key)
            .map_err(|error| CommandResult::failed(error.to_string()))?
            .ok_or_else(|| not_found(args.addr))?;
        drop(view);
        if !lease.is_bound(now) {
            return Err(CommandResult::coded(
                Outcome::Rejected,
                tenko_core::dhcp::codes::LEASE_STATE,
                format!(
                    "the lease of {} is {} and holds no binding to release",
                    args.addr,
                    state_name(lease.state)
                ),
            ));
        }
        let mut row = Lease {
            state: BindingState::Released,
            ends: now,
            node: self.node,
            ..lease.clone()
        };
        let event = LeaseEvent::of(&row, LeaseEventKind::Reclaimed, now);
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Dhcp),
            now,
        );
        let encode = |error: StoreError| CommandResult::failed(error.to_string());
        // WP8.1: the release expires the lease's IPAM facts in the same batch.
        if let Some(observed) = self
            .observations
            .observe(&row, Some(&lease), &mut batch)
            .map_err(encode)?
        {
            row.observed_at = Some(observed);
        }
        batch.expect_typed(&tables::LEASES, &key, Some(revision));
        batch
            .put_typed(&tables::LEASES, &key, &row)
            .map_err(encode)?;
        batch
            .put_typed(&tables::HISTORY, &(now, vrf, args.addr), &event)
            .map_err(encode)?;
        match self.store.propose(batch).await {
            Ok(committed) => {
                self.leases.apply_at(row.clone(), committed.revision);
                crate::lease::metrics::HISTORY_WRITTEN
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(self.row_of(row, committed.revision))
            }
            Err(StoreError::PreconditionFailed(_)) => Err(CommandResult::coded(
                Outcome::Rejected,
                tenko_core::dhcp::codes::LEASE_STATE,
                format!(
                    "the lease of {} changed meanwhile; read it again",
                    args.addr
                ),
            )),
            Err(error @ (StoreError::NoQuorum | StoreError::Timeout | StoreError::Storage(_))) => {
                Err(CommandResult::coded(
                    Outcome::Failed,
                    tenko_core::dhcp::codes::STORE_REFUSED,
                    format!("the store refused the release: {error}"),
                ))
            }
            Err(error) => Err(CommandResult::failed(error.to_string())),
        }
    }

    /// The VRF of an address: the one given, else the only VRF in which the table holds
    /// a lease of it.
    fn vrf_of(&self, vrf: Option<VrfId>, addr: Ipv4Addr) -> Result<VrfId, CommandResult> {
        if let Some(vrf) = vrf {
            return Ok(vrf);
        }
        let table = self.leases.read();
        let mut vrfs: Vec<VrfId> = table
            .iter()
            .filter(|lease| lease.addr == addr)
            .map(|lease| lease.vrf)
            .collect();
        vrfs.sort_unstable();
        vrfs.dedup();
        match vrfs.as_slice() {
            [] => Err(not_found(addr)),
            [vrf] => Ok(*vrf),
            _ => Err(CommandResult::rejected(format!(
                "{addr} has leases in {} VRFs; name the VRF",
                vrfs.len()
            ))),
        }
    }

    /// The API's view of a row: its revision, and whether it is the client's reservation.
    fn row_of(&self, lease: Lease, revision: Revision) -> commands::LeaseRow {
        let image = self.server().map(|server| server.image());
        let identity = lease.client.identity();
        // WP8.4: a MAC-keyed reservation holds for a client that sends option 61 too.
        let hardware = tenko_core::dhcp::ClientKey {
            client_id: None,
            ..lease.client.clone()
        }
        .identity();
        let reservation = image
            .as_ref()
            .and_then(|image| image.reservation_of(lease.scope, &identity, &hardware));
        commands::LeaseRow {
            reserved: reservation.is_some_and(|held| held.addr == lease.addr),
            host: reservation.map(|held| held.host),
            revision,
            lease,
        }
    }

    fn list(&self, args: &[u8]) -> CommandResult {
        let args: commands::LeaseListArgs = if args.is_empty() {
            commands::LeaseListArgs::default()
        } else {
            match tenko_core::codec::from_cbor(args) {
                Ok(args) => args,
                Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
            }
        };
        let limit = commands::page_limit(args.limit);
        let (rows, next) = {
            let table = self.leases.read();
            let mut matching: Vec<&Lease> = table
                .iter()
                .filter(|lease| args.matches(lease))
                .filter(|lease| {
                    args.after
                        .is_none_or(|after| (lease.vrf, lease.addr) > after)
                })
                .collect();
            matching.sort_unstable_by_key(|lease| (lease.vrf, lease.addr));
            let next = (matching.len() > limit)
                .then(|| matching.get(limit - 1).map(|lease| (lease.vrf, lease.addr)))
                .flatten();
            let rows: Vec<(Lease, Revision)> = matching
                .into_iter()
                .take(limit)
                .map(|lease| {
                    (
                        lease.clone(),
                        table
                            .row_revision(lease.vrf, lease.addr)
                            .unwrap_or(Revision::ZERO),
                    )
                })
                .collect();
            (rows, next)
        };
        let items: Vec<commands::LeaseRow> = rows
            .into_iter()
            .map(|(lease, revision)| self.row_of(lease, revision))
            .collect();
        CommandResult::done(
            format!("{} lease(s) read", items.len()),
            Output::Leases(commands::LeasePage { items, next }),
        )
    }

    async fn history(&self, args: &[u8]) -> CommandResult {
        let args: commands::HistoryArgs = if args.is_empty() {
            commands::HistoryArgs::default()
        } else {
            match tenko_core::codec::from_cbor(args) {
                Ok(args) => args,
                Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
            }
        };
        let view = match self.store.read(ReadConsistency::Local).await {
            Ok(view) => view,
            Err(error) => return CommandResult::failed(error.to_string()),
        };
        match commands::read_history(view.as_ref(), &args) {
            Ok(page) => CommandResult::done(
                format!("{} lease event(s) read", page.items.len()),
                Output::History(page),
            ),
            Err(error) => CommandResult::failed(error.to_string()),
        }
    }
}

fn not_found(addr: Ipv4Addr) -> CommandResult {
    CommandResult::coded(
        Outcome::Rejected,
        tenko_core::dhcp::codes::LEASE_NOT_FOUND,
        format!("no lease holds {addr}"),
    )
}

/// The stable name of a binding state.
pub fn state_name(state: BindingState) -> &'static str {
    match state {
        BindingState::Free => "free",
        BindingState::Active => "active",
        BindingState::Expired => "expired",
        BindingState::Released => "released",
        BindingState::Abandoned => "abandoned",
        BindingState::Reset => "reset",
        BindingState::Backup => "backup",
    }
}

#[async_trait::async_trait]
impl DhcpNode for LocalNode {
    fn node(&self) -> NodeId {
        self.node
    }

    fn status(&self) -> DhcpStatus {
        let server = self.server();
        let image = server.as_ref().map(|server| server.image());
        let listeners = server
            .as_ref()
            .map(|server| server.listeners().to_vec())
            .unwrap_or_default();
        let gate = self.lease_store.gate();
        let revision = image
            .as_ref()
            .map_or(Revision::ZERO, |image| image.revision());
        let held = self.leases.revision().max(revision);
        DhcpStatus {
            node: self.node,
            serving: server.is_some() && !listeners.is_empty(),
            accepting: !gate.refusing(),
            refusal: gate.finding(),
            probe: self.probe.load(Ordering::Relaxed),
            probe_expected: self.probe_expected.load(Ordering::Relaxed),
            scopes: image.as_ref().map_or(0, |image| image.scopes().len()),
            leases: self.leases.read().counts_by_state(),
            last_commit: server.as_ref().and_then(|server| server.last_commit()),
            revision,
            lag: self.progress.lag(held),
            started: self.started,
            installs: self.installs.load(Ordering::Relaxed),
            listeners,
        }
    }

    async fn execute(&self, kind: &str, args: &[u8]) -> CommandResult {
        match kind {
            commands::LEASES_LIST => self.list(args),
            commands::LEASE_RELEASE => self.release(args).await,
            commands::HISTORY_READ => self.history(args).await,
            commands::STATS => {
                let stats = self.stats();
                CommandResult::done(stats.detail(), Output::Stats(Box::new(stats)))
            }
            other => {
                CommandResult::rejected(format!("`{other}` is not a command of the dhcp role"))
            }
        }
    }
}

/// The running role.
pub struct Role {
    node: Arc<LocalNode>,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Role")
            .field("node", &self.node.node)
            .finish_non_exhaustive()
    }
}

/// Keeps the image and the table equal to the feed's rows.
struct Follower {
    server: Arc<DhcpServer<SharedLeases>>,
    leases: SharedLeases,
    /// The configuration rows (the leases are in the table, not here).
    data: DhcpData,
    held: Revision,
    installs: Arc<AtomicU64>,
}

impl Follower {
    /// Applies a delta: the lease rows into the table at the delta's revision, the
    /// configuration rows into the image, rebuilt and swapped when one changed.
    fn apply(&mut self, delta: &crate::feed::Delta) -> Result<(), FeedError> {
        if delta.from != self.held || delta.to <= delta.from {
            return Err(FeedError::Gap {
                held: self.held,
                from: delta.from,
            });
        }
        let mut configured = false;
        {
            let mut table = self.leases.write();
            for change in &delta.changes {
                match change {
                    Change::Lease((vrf, addr), Some(lease)) => {
                        debug_assert_eq!((lease.vrf, lease.addr), (*vrf, *addr));
                        table.apply_at(lease.clone(), delta.to);
                    }
                    Change::Lease((vrf, addr), None) => {
                        table.take(*vrf, *addr);
                    }
                    other => {
                        self.data.apply_change(other);
                        configured = true;
                    }
                }
            }
            table.advance(delta.to);
        }
        self.leases.changed();
        self.data.revision = delta.to;
        self.held = delta.to;
        if configured {
            self.server.set_image(build(&self.data).image);
            // WP8.5: the stored conflict detection setting (TGL-16).
            follow_conflict_setting(&self.server, &self.data);
        }
        Ok(())
    }

    /// Replaces the image and the table with ones built from `data`, swapped together.
    fn reset(&mut self, mut data: DhcpData) {
        let built = build(&data);
        let mut table = index_from_data(&data);
        data.leases.clear();
        let revision = data.revision;
        self.server.swap(built.image, |held| {
            // The role's own commits after the image's revision stay in the table.
            for (lease, at) in held.rows_after(revision) {
                table.apply_at(lease, at);
            }
            *held = table;
        });
        self.leases.changed();
        // WP8.5: the stored conflict detection setting (TGL-16).
        follow_conflict_setting(&self.server, &data);
        self.data = data;
        self.held = revision;
        self.installs.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%revision, "the dhcp role installed a new image of its rows");
    }

    async fn run(mut self, mut feed: StoreFeed, stop: CancellationToken) {
        loop {
            let event = tokio::select! {
                () = stop.cancelled() => return,
                event = feed.next() => event,
            };
            let outcome = match event {
                Ok(FeedEvent::Delta(delta)) => self.apply(&delta),
                Ok(FeedEvent::Reset(data)) => {
                    self.reset(*data);
                    Ok(())
                }
                Err(error) => Err(error),
            };
            let Err(error) = outcome else {
                continue;
            };
            if !matches!(error, FeedError::Gap { .. }) {
                tracing::warn!(%error, "the dhcp role's feed failed; it keeps serving the rows it holds and reads them again");
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(FEED_RETRY) => {}
                }
            }
            match feed.snapshot().await {
                Ok(data) => self.reset(data),
                Err(error) => {
                    tracing::warn!(%error, "the dhcp role could not read its rows; it keeps serving the rows it holds");
                }
            }
        }
    }
}

// WP8.5: the stored conflict detection setting (TGL-16).
/// Follows `dhcp.settings.conflict_detection` of `data` into the server's conflict
/// detection.
fn follow_conflict_setting(server: &DhcpServer<SharedLeases>, data: &DhcpData) {
    server.conflicts().set_setting(
        data.settings
            .as_ref()
            .and_then(|settings| settings.conflict_detection),
    );
}

impl Role {
    /// Starts the role over `store` as `node`; see the module documentation for the order.
    ///
    /// # Errors
    ///
    /// [`StartError::Feed`] when the store cannot be read, [`StartError::Bind`] when a
    /// listener cannot be bound.
    pub async fn start(
        store: Arc<dyn Store>,
        node: NodeId,
        settings: RoleSettings,
    ) -> Result<Self, StartError> {
        Self::start_observed(store, node, settings, Arc::new(NoObservations)).await
    }

    // WP8.1: the start with the observation hook of the lease batch.
    /// [`Role::start`] with `observations`, the hook that adds the IPAM facts of every lease
    /// change to its batch (plan section 2.8): the committer's changes and the operator's
    /// releases.
    ///
    /// # Errors
    ///
    /// As [`Role::start`].
    pub async fn start_observed(
        store: Arc<dyn Store>,
        node: NodeId,
        settings: RoleSettings,
        observations: Arc<dyn ObservationHook>,
    ) -> Result<Self, StartError> {
        let feed_store = Arc::clone(&store);
        let mut feed = tokio::task::spawn_blocking(move || store_feed::register(feed_store))
            .await
            .map_err(|join| StartError::Feed(join.to_string()))?
            .map_err(|error| StartError::Feed(error.to_string()))?;
        let progress = feed.progress();
        let mut data = feed
            .snapshot()
            .await
            .map_err(|error| StartError::Feed(error.to_string()))?;
        let built = build(&data);
        for warning in &built.warnings {
            tracing::info!(
                ?warning,
                "a reservation of the dhcp role's image has a finding"
            );
        }
        let leases = SharedLeases::new(index_from_data(&data));
        data.leases.clear();
        let held = data.revision;
        let (lease_store, committer) = StoreLeases::with_hook(
            Arc::clone(&store),
            leases.clone(),
            node,
            settings.commit,
            Arc::clone(&observations),
        );
        let stop = CancellationToken::new();
        let committer = tokio::spawn(committer.run(stop.child_token()));
        let mut config = settings.server.clone();
        config.node = node;
        let start_leases = leases.clone();
        let start_store: Arc<dyn crate::store::LeaseStore> = Arc::new(lease_store.clone());
        let image = built.image;
        let started = tokio::task::spawn_blocking(move || {
            DhcpServer::start_with(&config, image, start_leases, start_store, None)
        })
        .await
        .map_err(|join| StartError::Feed(join.to_string()))?;
        let server = match started {
            Ok(server) => Arc::new(server),
            Err(error) => {
                stop.cancel();
                let _ = committer.await;
                return Err(StartError::Bind(error));
            }
        };
        let wake = {
            let lease_store = lease_store.clone();
            let wake = server.waker();
            let stop = stop.child_token();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        () = lease_store.completed() => wake(),
                    }
                }
            })
        };
        // WP8.5: the stored conflict detection setting, and the reports of DECLINEs and
        // conflicts (the audit records and the log lines).
        follow_conflict_setting(&server, &data);
        let reporter = tokio::spawn(crate::conflict::report::run(
            Arc::clone(&store),
            Arc::clone(server.conflicts()),
            settings.server.engine.decline_hold_secs,
            stop.child_token(),
        ));
        let installs = Arc::new(AtomicU64::new(0));
        let follower = Follower {
            server: Arc::clone(&server),
            leases: leases.clone(),
            data,
            held,
            installs: Arc::clone(&installs),
        };
        let follow = tokio::spawn(follower.run(feed, stop.child_token()));
        let node = Arc::new(LocalNode {
            node,
            server: RwLock::new(Some(server)),
            leases,
            lease_store,
            store,
            progress,
            started: Timestamp::now(),
            installs,
            probe: AtomicBool::new(settings.probe),
            probe_expected: AtomicBool::new(settings.probe_expected),
            observations,
        });
        Ok(Self {
            node,
            stop,
            tasks: vec![follow, wake, reporter, committer],
        })
    }

    /// The role as the API and the metrics reach it.
    pub fn node(&self) -> Arc<LocalNode> {
        Arc::clone(&self.node)
    }

    /// Stops answering, then the follower and the committer.
    pub async fn stop(self) {
        let Self { node, stop, tasks } = self;
        let server = node
            .server
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(server) = server {
            // The follower holds a handle too; once it ends, the last one stops the
            // workers (`Drop` joins them).
            stop.cancel();
            let _ = tokio::task::spawn_blocking(move || drop(server)).await;
        }
        stop.cancel();
        for mut task in tasks {
            if tokio::time::timeout(Duration::from_secs(10), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }
}
