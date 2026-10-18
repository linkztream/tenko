//! The report `dns.status` and the local command handlers of the `dns` role (plan sections
//! 2.9 and 2.10, `docs/node-sync.md` section 5).
//!
//! A node's DNS role answers five commands and one report:
//!
//! | Kind | Arguments (CBOR) | What the role does |
//! |---|---|---|
//! | `dns.cache.flush` | [`CacheFlushArgs`] (optional; none flushes all) | Empties the cache, or the entries at or below a name suffix; `done` with the count removed |
//! | `dns.stats` | none | Answers `done` with the counters of the workers, the forwarder, the policy (blocked queries per list and RPZ zone), rate limiting and the query log in its detail |
//! | `dns.log.read` | [`LogReadArgs`] | Answers `done` with a page of the local query log, newest first, filtered, and the cursor of the next page; `rejected` when the log is off or a filter cannot be applied |
//! | `dns.log.stop`, `dns.log.start` | none | The kill switch: the log takes no entry until it is started again (kept across a restart); `rejected` when the log is off |
//! | `dns.status` (report) | | [`DnsStatus`]: serving, the revision held and the lag, zones, RRsets, listeners, the cache's entries and hits, the queries blocked per list and RPZ zone, the problems of stub zones and recursion lists, the start |
//!
//! In Phase 2 the role runs in the controller's own process, so [`LocalNode`] executes a
//! command in place and the API records it as a row of `cluster.node_commands` in the state
//! it reached, through an inline job ([`commit_command`]). Phase 5 sends the same kinds to a
//! remote `dns` node over the command stream, and the routes do not change.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, ObjectRef, RequestCtx, Revision, Timestamp,
    dns::{DnsName, QueryTransport},
};
use tenko_store::WriteBatch;

use crate::{
    catalog::CatalogHandle,
    forward::{ForwardStats, Forwarder},
    querylog::{self, FileLog, LogFigures, LogFilter, LogPage},
    server::Server,
    store_feed::FeedProgress,
    transport::WorkerLayout,
    zone::{Written, ZoneJobs, ZoneResult},
};

/// Empty the node's DNS cache.
pub const CACHE_FLUSH: &str = "dns.cache.flush";
/// Report the role's counters.
pub const STATS: &str = "dns.stats";
/// Read a page of the node's query log.
pub const LOG_READ: &str = "dns.log.read";
/// Stop the node's query log (the kill switch).
pub const LOG_STOP: &str = "dns.log.stop";
/// Start the node's query log again.
pub const LOG_START: &str = "dns.log.start";
/// The name of the role's report.
pub const STATUS: &str = "dns.status";

/// Lines a page of the query log holds at most.
pub const MAX_LOG_PAGE: u32 = 1_000;

/// The arguments of `dns.cache.flush`; empty arguments flush everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheFlushArgs {
    /// Only the names at or below this suffix.
    #[serde(default)]
    pub suffix: Option<String>,
}

/// The arguments of `dns.log.read`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogReadArgs {
    /// The cursor of the page, from the previous page; the newest line when absent.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Lines, 1 to [`MAX_LOG_PAGE`].
    pub limit: u32,
    /// Query names equal to this name or under it.
    #[serde(default)]
    pub qname: Option<String>,
    /// A client: its pseudonym or its address.
    #[serde(default)]
    pub client: Option<String>,
    /// The RCODE answered.
    #[serde(default)]
    pub rcode: Option<u16>,
    /// Queries that arrived at or after this time.
    #[serde(default)]
    pub from: Option<Timestamp>,
    /// Queries that arrived at or before this time.
    #[serde(default)]
    pub until: Option<Timestamp>,
}

impl LogReadArgs {
    /// The reader's filter.
    pub fn filter(&self) -> LogFilter {
        LogFilter {
            qname: self.qname.clone(),
            client: self.client.clone(),
            rcode: self.rcode,
            from: self.from,
            until: self.until,
        }
    }
}

/// One listener of the role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// The local address and port.
    pub address: SocketAddr,
    /// UDP or TCP.
    pub transport: QueryTransport,
    /// UDP workers on it (0 for TCP, which runs on the runtime's threads).
    pub workers: u16,
}

/// The queries one block list or RPZ zone blocked since the role started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedCount {
    /// The list's name, or the RPZ zone's name.
    pub list: String,
    /// Queries blocked.
    pub count: u64,
}

/// The blocked counts of the enabled block lists and the RPZ zones of a catalog, by name.
pub fn blocked_counts(catalog: &CatalogHandle) -> Vec<BlockedCount> {
    let catalog = catalog.load();
    let mut counts: Vec<BlockedCount> = catalog
        .policy()
        .counted()
        .map(|(list, slot)| BlockedCount {
            list: list.to_owned(),
            count: crate::policy::counters::total(slot),
        })
        .collect();
    counts.sort_by(|a, b| a.list.cmp(&b.list));
    counts.dedup_by(|a, b| a.list == b.list);
    counts
}

/// The counters of rate limiting since the process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateCounts {
    /// Responses RRL dropped.
    pub dropped: u64,
    /// Responses RRL sent truncated.
    pub slipped: u64,
    /// Queries the per-client limit dropped.
    pub client_limited: u64,
}

impl RateCounts {
    /// The counters now.
    pub fn read() -> Self {
        use crate::rate::limiter::{
            CLIENT_LIMITED_COUNTER, RRL_DROPPED_COUNTER, RRL_SLIPPED_COUNTER,
        };
        Self {
            dropped: (0..5).map(|kind| RRL_DROPPED_COUNTER.get(kind)).sum(),
            slipped: RRL_SLIPPED_COUNTER.get(),
            client_limited: CLIENT_LIMITED_COUNTER.get(),
        }
    }
}

/// The report `dns.status` of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStatus {
    /// The node.
    pub node: NodeId,
    /// The role answers queries.
    pub serving: bool,
    /// The store revision of the rows the index holds.
    pub revision: Revision,
    /// Revisions between the newest `dns` change of the store and the index.
    pub lag: u64,
    /// Zones served.
    pub zones: u32,
    /// RRsets in the bases of the index (an RRset changed since its zone's base was built
    /// is counted when the base is next rebuilt).
    pub rrsets: u64,
    /// Octets of the bases of the index, a lower bound of its memory
    /// (`IndexStats::base_bytes`).
    pub index_bytes: u64,
    /// The listeners.
    pub listeners: Vec<Listener>,
    /// Entries in the cache.
    pub cache_entries: u64,
    /// Octets the cache accounts for (keys, answers, bookkeeping), a lower bound of its
    /// memory.
    pub cache_bytes: u64,
    /// Answers from the cache since the role started.
    pub cache_hits: u64,
    /// Forwarded queries the cache could not answer since the role started.
    pub cache_misses: u64,
    /// Stale answers since the role started.
    pub cache_stale: u64,
    /// What keeps the resolver side from working as configured: stub zones whose name
    /// servers could not be learnt, views whose recursion access list does not exist.
    pub problems: Vec<String>,
    /// When the role started.
    pub started: Timestamp,
    /// The workers and the TCP side, while the role serves.
    pub layout: Option<WorkerLayout>,
    /// The query log, when it is on.
    pub log: Option<LogFigures>,
    /// Queries blocked per enabled block list and RPZ zone, by name.
    pub blocked: Vec<BlockedCount>,
}

/// The counters `dns.stats` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStats {
    /// The workers and the TCP side, when the role serves.
    pub layout: Option<WorkerLayout>,
    /// The forwarder, when it has upstreams.
    pub forward: Option<ForwardStats>,
    /// The query log's counters and state, when the log is on.
    pub log: Option<LogFigures>,
    /// Queries blocked per enabled block list and RPZ zone, by name.
    pub blocked: Vec<BlockedCount>,
    /// Rate limiting.
    pub rate: RateCounts,
}

impl DnsStats {
    /// One line of English for the command's detail.
    pub fn detail(&self) -> String {
        let mut parts = Vec::new();
        if let Some(layout) = &self.layout {
            let received: u64 = layout.udp.iter().map(|worker| worker.received).sum();
            let sent: u64 = layout.udp.iter().map(|worker| worker.sent).sum();
            let dropped: u64 = layout.udp.iter().map(|worker| worker.dropped).sum();
            let forwarded: u64 = layout.udp.iter().map(|worker| worker.forwarded).sum();
            parts.push(format!(
                "{} UDP worker(s) ({}): {received} received, {sent} sent, {dropped} dropped, \
                 {forwarded} forwarded; TCP: {} open, {} refused",
                layout.udp.len(),
                layout.mode.as_str(),
                layout.tcp_open,
                layout.tcp_refused
            ));
        } else {
            parts.push("not serving".to_owned());
        }
        if let Some(forward) = &self.forward {
            parts.push(format!(
                "forwarder: {} answered, {} failed, {} timed out, {} dropped, {} refused; \
                 cache: {} hit(s), {} miss(es), {} stale, {} prefetched",
                forward.answered,
                forward.failed,
                forward.timeouts,
                forward.dropped,
                forward.refused,
                forward.hits,
                forward.misses,
                forward.stale,
                forward.prefetched
            ));
        }
        if !self.blocked.is_empty() {
            let lists: Vec<String> = self
                .blocked
                .iter()
                .map(|blocked| format!("{} {}", blocked.list, blocked.count))
                .collect();
            parts.push(format!("blocked: {}", lists.join(", ")));
        }
        parts.push(format!(
            "rate limiting: {} dropped, {} slipped, {} client-limited",
            self.rate.dropped, self.rate.slipped, self.rate.client_limited
        ));
        if let Some(log) = &self.log {
            parts.push(format!(
                "query log{}: {} written, {} dropped, {} failed write(s)",
                if log.stopped { " (stopped)" } else { "" },
                log.written,
                log.dropped,
                log.write_errors
            ));
        }
        parts.join("; ")
    }
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Finished.
    Done,
    /// Tried and failed.
    Failed,
    /// Refused: an unknown kind, arguments that do not decode, a log that is off.
    Rejected,
}

/// What a command answered besides its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Nothing.
    None,
    /// The counters (`dns.stats`).
    Stats(Box<DnsStats>),
    /// A page of the query log (`dns.log.read`).
    Log(LogPage),
}

/// The result of one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// How it ended.
    pub outcome: Outcome,
    /// English detail for the command row (at most 2,000 characters).
    pub detail: String,
    /// The answer.
    pub output: Output,
}

impl CommandResult {
    fn done(detail: impl Into<String>, output: Output) -> Self {
        Self {
            outcome: Outcome::Done,
            detail: detail.into(),
            output,
        }
    }

    fn rejected(detail: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Rejected,
            detail: detail.into(),
            output: Output::None,
        }
    }
}

/// A node's DNS role as the API reaches it: locally in Phase 2.
pub trait DnsNode: Send + Sync {
    /// The node.
    fn node(&self) -> NodeId;

    /// The report `dns.status`.
    fn status(&self) -> DnsStatus;

    /// Runs one command of the kinds of this module (blocking: reading the log reads
    /// files). `args` is the CBOR of the kind's arguments.
    fn execute(&self, kind: &str, args: &[u8]) -> CommandResult;
}

/// The `dns` role of this process.
pub struct LocalNode {
    node: NodeId,
    started: Timestamp,
    catalog: CatalogHandle,
    progress: FeedProgress,
    server: Mutex<Option<Server>>,
    forwarder: Option<Arc<Forwarder>>,
    log: Option<(Arc<FileLog>, PathBuf)>,
}

impl std::fmt::Debug for LocalNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNode")
            .field("node", &self.node)
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

impl LocalNode {
    /// The role of `node` serving with `server`.
    pub fn new(
        node: NodeId,
        server: Server,
        progress: FeedProgress,
        forwarder: Option<Arc<Forwarder>>,
        log: Option<(Arc<FileLog>, PathBuf)>,
    ) -> Self {
        Self {
            node,
            started: Timestamp::now(),
            catalog: server.catalog().clone(),
            progress,
            server: Mutex::new(Some(server)),
            forwarder,
            log,
        }
    }

    /// Takes the server out to stop it; the role reports `serving: false` from then on.
    pub fn take_server(&self) -> Option<Server> {
        self.server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The worker layout, while the role serves.
    pub fn layout(&self) -> Option<WorkerLayout> {
        self.server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(Server::layout)
    }

    /// The counters of `dns.stats`.
    pub fn stats(&self) -> DnsStats {
        DnsStats {
            layout: self.layout(),
            forward: self.forwarder.as_ref().map(|forwarder| forwarder.stats()),
            log: self.log.as_ref().map(|(log, _)| log.figures()),
            blocked: blocked_counts(&self.catalog),
            rate: RateCounts::read(),
        }
    }

    fn switch_log(&self, stopped: bool) -> CommandResult {
        let Some((log, _)) = &self.log else {
            return CommandResult::rejected("the query log is off on this node");
        };
        let was = log.is_stopped();
        match log.set_stopped(stopped) {
            Ok(()) => CommandResult::done(
                match (was, stopped) {
                    (false, true) => "the query log is stopped",
                    (true, true) => "the query log was stopped already",
                    (true, false) => "the query log is started again",
                    (false, false) => "the query log was running already",
                },
                Output::None,
            ),
            Err(error) => CommandResult {
                outcome: Outcome::Failed,
                detail: format!(
                    "the query log is {} until the node restarts, but its marker file could                      not be changed: {error}",
                    if stopped { "stopped" } else { "started" }
                ),
                output: Output::None,
            },
        }
    }

    /// The forwarder, when the role has one.
    pub fn forwarder(&self) -> Option<&Arc<Forwarder>> {
        self.forwarder.as_ref()
    }

    fn flush(&self, args: &[u8]) -> CommandResult {
        let args: CacheFlushArgs = if args.is_empty() {
            CacheFlushArgs::default()
        } else {
            match tenko_core::codec::from_cbor(args) {
                Ok(args) => args,
                Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
            }
        };
        let suffix = match args.suffix.as_deref().map(DnsName::new) {
            None => None,
            Some(Ok(suffix)) => Some(suffix),
            Some(Err(error)) => {
                return CommandResult::rejected(format!("the suffix: {error}"));
            }
        };
        let flushed = self
            .forwarder
            .as_ref()
            .and_then(|forwarder| forwarder.flush(suffix.as_ref()));
        match (flushed, &suffix) {
            (None, _) => CommandResult::done("this node keeps no cache", Output::None),
            (Some(flushed), None) => CommandResult::done(
                format!("{} cache entr(ies) removed", flushed.entries),
                Output::None,
            ),
            (Some(flushed), Some(suffix)) => CommandResult::done(
                format!(
                    "{} cache entr(ies) at or below {suffix} removed",
                    flushed.entries
                ),
                Output::None,
            ),
        }
    }

    fn read_log(&self, args: &[u8]) -> CommandResult {
        let Some((_, dir)) = &self.log else {
            return CommandResult::rejected("the query log is off on this node");
        };
        let args: LogReadArgs = match tenko_core::codec::from_cbor(args) {
            Ok(args) => args,
            Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
        };
        let limit = usize::try_from(args.limit.clamp(1, MAX_LOG_PAGE)).unwrap_or(100);
        let filter = args.filter();
        if let Err(error) = filter.validate() {
            return CommandResult::rejected(error.to_string());
        }
        match querylog::read(dir, args.cursor.as_deref(), limit, &filter) {
            Ok(page) => CommandResult::done(
                format!("{} line(s) read", page.lines.len()),
                Output::Log(page),
            ),
            Err(querylog::ReadError::Cursor) => CommandResult::rejected("the cursor is not valid"),
            Err(error @ querylog::ReadError::Filter(_)) => {
                CommandResult::rejected(error.to_string())
            }
            Err(error) => CommandResult {
                outcome: Outcome::Failed,
                detail: error.to_string(),
                output: Output::None,
            },
        }
    }
}

impl DnsNode for LocalNode {
    fn node(&self) -> NodeId {
        self.node
    }

    fn status(&self) -> DnsStatus {
        let catalog = self.catalog.load();
        let stats = catalog.index().stats();
        let revision = catalog.revision();
        let mut listeners = Vec::new();
        let mut layout = None;
        let serving = match self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            Some(server) => {
                let workers = u16::try_from(server.config().udp.workers).unwrap_or(u16::MAX);
                for address in server.udp_addresses() {
                    listeners.push(Listener {
                        address: *address,
                        transport: QueryTransport::Udp,
                        workers,
                    });
                }
                for address in server.tcp_addresses() {
                    listeners.push(Listener {
                        address: *address,
                        transport: QueryTransport::Tcp,
                        workers: 0,
                    });
                }
                for (addresses, transport) in [
                    (server.dot_addresses(), QueryTransport::Dot),
                    (server.doh_addresses(), QueryTransport::Doh),
                ] {
                    for address in addresses {
                        listeners.push(Listener {
                            address: *address,
                            transport,
                            workers: 0,
                        });
                    }
                }
                layout = Some(server.layout());
                true
            }
            None => false,
        };
        let to_u64 = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        let cache = self
            .forwarder
            .as_ref()
            .and_then(|forwarder| forwarder.cache())
            .map(crate::cache::Cache::stats)
            .unwrap_or_default();
        let forward = self
            .forwarder
            .as_ref()
            .map(|forwarder| forwarder.stats())
            .unwrap_or_default();
        let mut problems = Vec::new();
        if let Some(forwarder) = &self.forwarder {
            for stub in forwarder.stubs() {
                if let Some(error) = stub.error {
                    problems.push(format!("stub zone {}: {error}", stub.zone));
                }
            }
            problems.extend(forwarder.recursion_problems());
        }
        DnsStatus {
            node: self.node,
            serving,
            revision,
            lag: self.progress.lag(revision),
            zones: u32::try_from(stats.zones).unwrap_or(u32::MAX),
            rrsets: to_u64(stats.base_rrsets),
            index_bytes: to_u64(stats.base_bytes),
            listeners,
            cache_entries: to_u64(cache.entries),
            cache_bytes: to_u64(cache.bytes),
            cache_hits: forward.hits,
            cache_misses: forward.misses,
            cache_stale: forward.stale,
            problems,
            started: self.started,
            layout,
            log: self.log.as_ref().map(|(log, _)| log.figures()),
            blocked: blocked_counts(&self.catalog),
        }
    }

    fn execute(&self, kind: &str, args: &[u8]) -> CommandResult {
        match kind {
            CACHE_FLUSH => self.flush(args),
            STATS => {
                let stats = self.stats();
                CommandResult::done(stats.detail(), Output::Stats(Box::new(stats)))
            }
            LOG_READ => self.read_log(args),
            LOG_STOP => self.switch_log(true),
            LOG_START => self.switch_log(false),
            other => CommandResult::rejected(format!("`{other}` is not a command of the dns role")),
        }
    }
}

/// Commits the record of a command executed in place (a row of `cluster.node_commands`
/// staged by the caller in `batch`) as an inline job, as every write is (decision Q4 of
/// Phase 1).
///
/// # Errors
///
/// The job's or the store's error.
pub async fn commit_command(
    jobs: &dyn ZoneJobs,
    cx: &RequestCtx,
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
) -> ZoneResult<Written> {
    crate::zone::jobs::commit(jobs, cx, summary, targets, batch).await
}

#[cfg(test)]
mod tests;
