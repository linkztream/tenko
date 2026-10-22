//! The node commands of the `dhcp` role (plan section 2.12, `docs/dhcp.md` section 10).
//!
//! | Kind | Arguments (CBOR) | What the role does |
//! |---|---|---|
//! | `dhcp.leases.list` | [`LeaseListArgs`] (optional) | Answers `done` with a page of the lease table in address order, filtered, and the key after which the next page starts |
//! | `dhcp.lease.release` | [`ReleaseArgs`] | Writes the lease as released by an operator (history kind `reclaimed`); `rejected` with `dhcp.lease.not_found` or `dhcp.lease.state`, `failed` with `dhcp.store_refused` |
//! | `dhcp.history.read` | [`HistoryArgs`] (optional) | Answers `done` with a page of `dhcp.history`, newest first, filtered |
//! | `dhcp.stats` | none | Answers `done` with the engine's counters, the committer's and the table's size |
//!
//! In Phase 3 the role runs in the controller's process, so the API executes a command in
//! place and records it as a row of `cluster.node_commands`; Phase 5 sends the same kinds
//! to a remote `dhcp` node over the command stream.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, MacAddr, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseEvent, LeaseEventKind, tables},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt as _, StoreError};

use crate::{lease::CommitStats, v4::engine::MetricsSnapshot};

/// List a page of the node's leases.
pub const LEASES_LIST: &str = "dhcp.leases.list";
/// Release a lease.
pub const LEASE_RELEASE: &str = "dhcp.lease.release";
/// Read a page of the lease history.
pub const HISTORY_READ: &str = "dhcp.history.read";
/// Report the role's counters.
pub const STATS: &str = "dhcp.stats";
/// The name of the role's report.
pub const STATUS: &str = "dhcp.status";

/// Items a page holds at most.
pub const MAX_PAGE: u32 = 1_000;
/// Items of a page when the arguments name no limit.
pub const DEFAULT_PAGE: u32 = 100;
/// History rows one read looks at before it returns what it found and a cursor.
pub const HISTORY_SCAN: usize = 50_000;

/// The page size for a requested limit (0: the default).
pub fn page_limit(limit: u32) -> usize {
    let limit = if limit == 0 { DEFAULT_PAGE } else { limit };
    usize::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(100)
}

/// The arguments of `dhcp.leases.list`; empty arguments list the first page of every
/// lease.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseListArgs {
    /// Only this scope.
    #[serde(default)]
    pub scope: Option<PrefixId>,
    /// Only this VRF.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// Only this address.
    #[serde(default)]
    pub exact: Option<Ipv4Addr>,
    /// Addresses whose text starts with this.
    #[serde(default)]
    pub addr: Option<String>,
    /// The client's MAC address.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// Host names or FQDNs containing this text, in any case.
    #[serde(default)]
    pub name: Option<String>,
    /// One binding state.
    #[serde(default)]
    pub state: Option<BindingState>,
    /// The page starts after this VRF and address.
    #[serde(default)]
    pub after: Option<(VrfId, Ipv4Addr)>,
    /// Items, 1 to [`MAX_PAGE`]; [`DEFAULT_PAGE`] when 0.
    #[serde(default)]
    pub limit: u32,
}

impl LeaseListArgs {
    /// Whether `lease` passes the filters (the cursor aside).
    pub fn matches(&self, lease: &Lease) -> bool {
        self.scope.is_none_or(|scope| lease.scope == scope)
            && self.vrf.is_none_or(|vrf| lease.vrf == vrf)
            && self.exact.is_none_or(|addr| lease.addr == addr)
            && self
                .addr
                .as_deref()
                .is_none_or(|text| lease.addr.to_string().starts_with(text))
            && self.mac.is_none_or(|mac| mac_of(lease) == Some(mac))
            && self.state.is_none_or(|state| lease.state == state)
            && self.name.as_deref().is_none_or(|text| {
                let text = text.to_lowercase();
                [&lease.hostname, &lease.fqdn]
                    .into_iter()
                    .flatten()
                    .any(|name| name.to_lowercase().contains(&text))
            })
    }
}

/// The MAC address of a lease's client, when it has an Ethernet hardware address.
pub fn mac_of(lease: &Lease) -> Option<MacAddr> {
    let chaddr: [u8; 6] = lease.client.chaddr.0.as_slice().try_into().ok()?;
    (lease.client.htype == 1).then(|| MacAddr::new(chaddr))
}

/// One lease as the commands answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRow {
    /// The row.
    pub lease: Lease,
    /// The revision that wrote it, as the table knows it.
    pub revision: Revision,
    /// Whether the address is the client's reservation.
    pub reserved: bool,
    /// The IPAM host of the client's reservation in the scope.
    pub host: Option<HostId>,
}

/// A page of leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePage {
    /// The leases, by VRF and address.
    pub items: Vec<LeaseRow>,
    /// Where the next page starts, when there is one.
    pub next: Option<(VrfId, Ipv4Addr)>,
}

/// The arguments of `dhcp.lease.release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArgs {
    /// The VRF; the only VRF with a lease of the address when absent.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// The address.
    pub addr: Ipv4Addr,
    /// Why, for the record.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The key of a history row.
pub type HistoryKey = (Timestamp, VrfId, Ipv4Addr);

/// The arguments of `dhcp.history.read`; empty arguments read the newest page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryArgs {
    /// Only this address.
    #[serde(default)]
    pub addr: Option<Ipv4Addr>,
    /// Only this MAC address.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// Only this scope.
    #[serde(default)]
    pub scope: Option<PrefixId>,
    /// Only this kind of event.
    #[serde(default)]
    pub kind: Option<LeaseEventKind>,
    /// Events at or after this time.
    #[serde(default)]
    pub from: Option<Timestamp>,
    /// Events at or before this time.
    #[serde(default)]
    pub to: Option<Timestamp>,
    /// The page starts before this key (the previous page's last).
    #[serde(default)]
    pub before: Option<HistoryKey>,
    /// Items, 1 to [`MAX_PAGE`]; [`DEFAULT_PAGE`] when 0.
    #[serde(default)]
    pub limit: u32,
}

impl HistoryArgs {
    fn matches(&self, event: &LeaseEvent) -> bool {
        self.addr.is_none_or(|addr| event.addr == addr)
            && self.scope.is_none_or(|scope| event.scope == scope)
            && self.kind.is_none_or(|kind| event.kind == kind)
            && self.to.is_none_or(|to| event.at <= to)
            && self.mac.is_none_or(|mac| {
                event.client.htype == 1 && event.client.chaddr.0.as_slice() == mac.octets()
            })
    }
}

/// A page of the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryPage {
    /// The events, newest first.
    pub items: Vec<LeaseEvent>,
    /// Where the next page starts, when there may be one.
    pub next: Option<HistoryKey>,
}

/// Reads a page of `dhcp.history` from `view`, newest first: pages of the table are read
/// backwards and filtered until the page is full, the time `from` is passed, or
/// [`HISTORY_SCAN`] rows were looked at (then the cursor continues where it stopped).
///
/// # Errors
///
/// A storage or decoding failure.
pub fn read_history(view: &dyn ReadView, args: &HistoryArgs) -> Result<HistoryPage, StoreError> {
    let limit = page_limit(args.limit);
    let mut items = Vec::new();
    let mut range = match &args.before {
        Some(before) => KeyRange::all().before(tables::HISTORY.key(before)),
        None => KeyRange::all(),
    };
    let mut seen = 0usize;
    loop {
        let page = view.scan_typed(&tables::HISTORY, range.clone(), 512, true)?;
        let full = page.len() == 512;
        let mut last = None;
        for (key, event, _) in page {
            seen += 1;
            last = Some(key);
            if args.from.is_some_and(|from| event.at < from) {
                return Ok(HistoryPage { items, next: None });
            }
            if args.matches(&event) {
                items.push(event);
                if items.len() == limit {
                    return Ok(HistoryPage { items, next: last });
                }
            }
        }
        let Some(last) = last else {
            return Ok(HistoryPage { items, next: None });
        };
        if !full {
            return Ok(HistoryPage { items, next: None });
        }
        if seen >= HISTORY_SCAN {
            return Ok(HistoryPage {
                items,
                next: Some(last),
            });
        }
        range = KeyRange::all().before(tables::HISTORY.key(&last));
    }
}

/// The counters of `dhcp.stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpStats {
    /// The engine's counters, summed over the workers.
    pub engine: MetricsSnapshot,
    /// The committer's counts.
    pub commits: CommitStats,
    /// Changes waiting in the hand-off queue.
    pub queued: usize,
    /// Replies waiting for their commit.
    pub in_flight: usize,
    /// Offers held.
    pub offers: usize,
    /// Rows in the lease table.
    pub leases: usize,
}

impl DhcpStats {
    /// One line for the command row.
    pub fn detail(&self) -> String {
        format!(
            "discover answered {}, request answered {}, NAKs {}, declines {}, dropped {}; \
             commits {} of {} handed off ({} refused, {} late); {} queued, {} in flight, {} \
             offer(s), {} lease row(s)",
            self.engine.packets("discover", "answered"),
            self.engine.packets("request", "answered"),
            self.engine.naks,
            self.engine.declines,
            self.engine.dropped.iter().sum::<u64>(),
            self.commits.committed,
            self.commits.submitted,
            self.commits.refused,
            self.commits.timed_out,
            self.queued,
            self.in_flight,
            self.offers,
            self.leases,
        )
    }
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Finished.
    Done,
    /// Tried and failed.
    Failed,
    /// Refused: an unknown kind, arguments that do not decode, a lease in the wrong state.
    Rejected,
}

/// What a command answered besides its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Nothing.
    None,
    /// A page of leases.
    Leases(LeasePage),
    /// One lease (the release's result).
    Lease(Box<LeaseRow>),
    /// A page of the history.
    History(HistoryPage),
    /// The counters.
    Stats(Box<DhcpStats>),
}

/// The result of one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// How it ended.
    pub outcome: Outcome,
    /// The stable code of a refusal or failure the API answers with, when there is one
    /// (`dhcp.lease.not_found`, `dhcp.lease.state`, `dhcp.store_refused`).
    pub code: Option<&'static str>,
    /// English detail for the command row (at most 2,000 characters).
    pub detail: String,
    /// The answer.
    pub output: Output,
}

impl CommandResult {
    pub(crate) fn done(detail: impl Into<String>, output: Output) -> Self {
        Self {
            outcome: Outcome::Done,
            code: None,
            detail: detail.into(),
            output,
        }
    }

    pub(crate) fn rejected(detail: impl Into<String>) -> Self {
        Self::coded(Outcome::Rejected, "sys.invalid_request", detail)
    }

    pub(crate) fn failed(detail: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Failed,
            code: None,
            detail: detail.into(),
            output: Output::None,
        }
    }

    pub(crate) fn coded(outcome: Outcome, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            code: Some(code),
            detail: detail.into(),
            output: Output::None,
        }
    }
}
