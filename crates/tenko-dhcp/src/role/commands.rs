//! The node commands of the `dhcp` role (plan section 2.12, `docs/dhcp.md` section 10).
//!
//! | Kind | Arguments (CBOR) | What the role does |
//! |---|---|---|
//! | `dhcp.leases.list` | [`LeaseListArgs`] (optional) | Answers `done` with a page of the lease table in address order, filtered, and the key after which the next page starts |
//! | `dhcp.lease.release` | [`ReleaseArgs`] | Writes the lease as released by an operator (history kind `reclaimed`); `rejected` with `dhcp.lease.not_found` or `dhcp.lease.state`, `failed` with `dhcp.store_refused` |
//! | `dhcp.history.read` | [`HistoryArgs`] (optional) | Answers `done` with a page of `dhcp.history`, newest first, filtered |
//! | `dhcp.lease6.release` | [`Release6Args`] | As `dhcp.lease.release` for a DHCPv6 lease of `dhcp.leases6` |
//! | `dhcp.stats` | none | Answers `done` with the engine's counters, the committer's and the table's size |
//!
//! The list and the history read both families (WP9.4): `dhcp.leases.list` answers the
//! DHCPv4 leases in address order and then the DHCPv6 leases (`dhcp.leases6`), and
//! `dhcp.history.read` merges `dhcp.history` and `dhcp.history6` newest first; the
//! `family` argument reads one of them. Each family keeps its own cursor.
//!
//! In Phase 3 the role runs in the controller's process, so the API executes a command in
//! place and records it as a row of `cluster.node_commands`; Phase 5 sends the same kinds
//! to a remote `dhcp` node over the command stream.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, MacAddr, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, Lease6, Lease6Event, LeaseEvent, LeaseEventKind, tables},
    net::Duid,
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
// WP9.4: the release of a DHCPv6 lease.
/// Release a DHCPv6 lease.
pub const LEASE6_RELEASE: &str = "dhcp.lease6.release";
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
    // WP9.4: the DHCPv6 leases beside the DHCPv4 ones.
    /// Only this family; both when absent.
    #[serde(default)]
    pub family: Option<Family>,
    /// Only this IPv6 address (a DHCPv6 lease).
    #[serde(default)]
    pub exact6: Option<Ipv6Addr>,
    /// Only this client DUID (a DHCPv6 lease).
    #[serde(default)]
    pub duid: Option<Duid>,
    /// Where the DHCPv6 part of the page starts; set once the DHCPv4 leases are read.
    #[serde(default)]
    pub after6: Option<Resume<(VrfId, Ipv6Addr)>>,
}

impl LeaseListArgs {
    /// Whether the DHCPv4 table is read: the family allows it, no DHCPv6-only filter is
    /// set and the cursor is not already in the DHCPv6 part.
    pub fn wants_v4(&self) -> bool {
        self.family != Some(Family::V6)
            && self.exact6.is_none()
            && self.duid.is_none()
            && self.after6.is_none()
    }

    /// Whether the DHCPv6 table is read: the family allows it and no DHCPv4 address is
    /// asked for.
    pub fn wants_v6(&self) -> bool {
        self.family != Some(Family::V4) && self.exact.is_none()
    }

    /// Whether the DHCPv6 `lease` passes the filters (the cursor aside).
    pub fn matches6(&self, lease: &Lease6) -> bool {
        self.scope.is_none_or(|scope| lease.scope == scope)
            && self.vrf.is_none_or(|vrf| lease.vrf == vrf)
            && self.exact6.is_none_or(|addr| lease.addr6() == addr)
            && self
                .addr
                .as_deref()
                .is_none_or(|text| lease.addr6().to_string().starts_with(text))
            && self.mac.is_none_or(|mac| lease.mac() == Some(mac.octets()))
            && self.duid.as_ref().is_none_or(|duid| &lease.duid == duid)
            && self.state.is_none_or(|state| lease.state == state)
            && self.name.as_deref().is_none_or(|text| {
                let text = text.to_lowercase();
                lease
                    .fqdn
                    .as_ref()
                    .is_some_and(|name| name.to_lowercase().contains(&text))
            })
    }

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
    // WP9.4: the correlation of DHCP-11.
    /// The client's DHCPv6 lease of the same MAC address, when the node holds one.
    #[serde(default)]
    pub peer: Option<LeasePeer>,
}

// WP9.4: the rows of the DHCPv6 leases.
/// One DHCPv6 lease as the commands answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease6Row {
    /// The row.
    pub lease: Lease6,
    /// The revision that wrote it, as the table knows it.
    pub revision: Revision,
    /// Whether the address is the client's reservation.
    pub reserved: bool,
    /// The IPAM host of the client's reservation in the scope.
    pub host: Option<HostId>,
    /// The client's DHCPv4 lease of the same MAC address, when the node holds one.
    #[serde(default)]
    pub peer: Option<LeasePeer>,
}

/// The lease of the other family that names the same MAC address (DHCP-11): an active one
/// when there is one, else the one that ends last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePeer {
    /// The VRF.
    pub vrf: VrfId,
    /// The address.
    pub addr: IpAddr,
    /// Its binding state.
    pub state: BindingState,
    /// When that state ends.
    pub ends: Timestamp,
}

impl LeasePeer {
    /// Whether `self` is the better peer than `other`: an active lease before any other,
    /// then the later end.
    pub fn better_than(&self, other: &Self) -> bool {
        let rank = |peer: &Self| (peer.state == BindingState::Active, peer.ends);
        rank(self) > rank(other)
    }
}

/// An address family of the leases and their history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// DHCPv4: `dhcp.leases` and `dhcp.history`.
    V4,
    /// DHCPv6: `dhcp.leases6` and `dhcp.history6`.
    V6,
}

/// Where a family's part of a page continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resume<K> {
    /// From the family's first row (the newest for the history).
    Start,
    /// After this key (before it, for the history).
    From(K),
}

impl<K: Copy> Resume<K> {
    /// The key, when the part does not start at the first row.
    pub fn key(&self) -> Option<K> {
        match self {
            Self::Start => None,
            Self::From(key) => Some(*key),
        }
    }
}

/// A page of leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePage {
    /// The leases, by VRF and address.
    pub items: Vec<LeaseRow>,
    /// Where the next page starts, when there is one.
    pub next: Option<(VrfId, Ipv4Addr)>,
    // WP9.4: the DHCPv6 part, after the DHCPv4 leases.
    /// The DHCPv6 leases, by VRF and address, after the DHCPv4 ones.
    #[serde(default)]
    pub items6: Vec<Lease6Row>,
    /// Where the DHCPv6 part of the next page starts, when the DHCPv4 leases are all read
    /// and DHCPv6 leases remain.
    #[serde(default)]
    pub next6: Option<Resume<(VrfId, Ipv6Addr)>>,
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

// WP9.4: the DHCPv6 lease commands.
/// The arguments of `dhcp.lease6.release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release6Args {
    /// The VRF; the only VRF with a lease of the address when absent.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// The address.
    pub addr: Ipv6Addr,
    /// Why, for the record.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The key of a DHCPv6 history row.
pub type History6Key = (Timestamp, VrfId, Ipv6Addr);

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
    // WP9.4: the DHCPv6 history beside the DHCPv4 one.
    /// Only this family; both when absent.
    #[serde(default)]
    pub family: Option<Family>,
    /// Only this IPv6 address.
    #[serde(default)]
    pub addr6: Option<Ipv6Addr>,
    /// Only this client DUID.
    #[serde(default)]
    pub duid: Option<Duid>,
    /// The DHCPv6 part starts before this key.
    #[serde(default)]
    pub before6: Option<History6Key>,
}

impl HistoryArgs {
    /// Whether `dhcp.history` is read.
    pub fn wants_v4(&self) -> bool {
        self.family != Some(Family::V6) && self.addr6.is_none() && self.duid.is_none()
    }

    /// Whether `dhcp.history6` is read.
    pub fn wants_v6(&self) -> bool {
        self.family != Some(Family::V4) && self.addr.is_none()
    }

    fn matches6(&self, event: &Lease6Event) -> bool {
        self.addr6.is_none_or(|addr| event.addr == addr)
            && self.scope.is_none_or(|scope| event.scope == scope)
            && self.kind.is_none_or(|kind| event.kind == kind)
            && self.to.is_none_or(|to| event.at <= to)
            && self.duid.as_ref().is_none_or(|duid| &event.duid == duid)
            && self
                .mac
                .is_none_or(|mac| duid_mac(event.duid.as_bytes()) == Some(mac.octets()))
    }

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
    // WP9.4: the DHCPv6 events and where each family continues.
    /// The DHCPv6 events, newest first; the page is both lists merged by time.
    #[serde(default)]
    pub items6: Vec<Lease6Event>,
    /// Where the DHCPv4 history of the next page continues; none when it was not read or
    /// is read to its end.
    #[serde(default)]
    pub resume: Option<Resume<HistoryKey>>,
    /// Where the DHCPv6 history of the next page continues, likewise.
    #[serde(default)]
    pub resume6: Option<Resume<History6Key>>,
}

/// The MAC address in a DUID-LLT or DUID-LL of hardware type 1 (RFC 8415 sections 11.2
/// and 11.4).
pub fn duid_mac(duid: &[u8]) -> Option<[u8; 6]> {
    let kind = u16::from_be_bytes([*duid.first()?, *duid.get(1)?]);
    let hardware = u16::from_be_bytes([*duid.get(2)?, *duid.get(3)?]);
    let address = match kind {
        1 => duid.get(8..)?,
        3 => duid.get(4..)?,
        _ => return None,
    };
    if hardware != 1 {
        return None;
    }
    <[u8; 6]>::try_from(address).ok()
}

/// The rows a backwards scan read, with their keys, and where the next scan starts.
type Scanned<K, V> = (Vec<(K, V)>, Option<K>);

/// Reads up to `limit` rows of a history table that `keep` passes, newest first, before
/// `before`: pages of the table are read backwards until the page is full, the time `from`
/// is passed, or [`HISTORY_SCAN`] rows were looked at. Answers the rows with their keys and
/// the key the next read starts before, when there may be more.
fn scan_back<K, V>(
    view: &dyn ReadView,
    table: &tenko_core::table::TableDef<K, V>,
    before: Option<&K>,
    from: Option<Timestamp>,
    at: impl Fn(&V) -> Timestamp,
    keep: impl Fn(&V) -> bool,
    limit: usize,
) -> Result<Scanned<K, V>, StoreError>
where
    K: tenko_core::codec::key::KeyCodec + Clone,
    V: Serialize + serde::de::DeserializeOwned,
{
    let mut items = Vec::new();
    let mut range = match before {
        Some(before) => KeyRange::all().before(table.key(before)),
        None => KeyRange::all(),
    };
    let mut seen = 0usize;
    loop {
        let page = view.scan_typed(table, range.clone(), 512, true)?;
        let full = page.len() == 512;
        let mut last = None;
        for (key, row, _) in page {
            seen += 1;
            last = Some(key.clone());
            if from.is_some_and(|from| at(&row) < from) {
                return Ok((items, None));
            }
            if keep(&row) {
                items.push((key, row));
                if items.len() == limit {
                    return Ok((items, last));
                }
            }
        }
        let Some(last) = last else {
            return Ok((items, None));
        };
        if !full {
            return Ok((items, None));
        }
        if seen >= HISTORY_SCAN {
            return Ok((items, Some(last)));
        }
        range = KeyRange::all().before(table.key(&last));
    }
}

/// The order of the merged history: the time, then the family, the VRF and the address.
type MergeKey = (Timestamp, u8, VrfId, IpAddr);

fn merge4((at, vrf, addr): HistoryKey) -> MergeKey {
    (at, 0, vrf, IpAddr::V4(addr))
}

fn merge6((at, vrf, addr): History6Key) -> MergeKey {
    (at, 1, vrf, IpAddr::V6(addr))
}

/// Where a family continues after a merged page: before the last row it gave when rows it
/// read were left out, where it was before when it gave none, else where its read stopped
/// (none: at its end).
fn resume_of<K: Copy>(
    read: &[(K, impl Sized)],
    taken: usize,
    before: Option<K>,
    next: Option<K>,
) -> Resume<K> {
    if taken < read.len() {
        return match taken.checked_sub(1) {
            Some(last) => Resume::From(read[last].0),
            None => before.map_or(Resume::Start, Resume::From),
        };
    }
    next.map_or(Resume::Start, Resume::From)
}

/// Reads a page of both history tables, newest first, merged by time (WP9.4). Each table
/// is read as [`read_history`] reads `dhcp.history`; a row is answered only when no unread
/// row of the other table can be newer, so the order holds across pages.
///
/// # Errors
///
/// A storage or decoding failure.
pub fn read_history_both(
    view: &dyn ReadView,
    args: &HistoryArgs,
) -> Result<HistoryPage, StoreError> {
    let limit = page_limit(args.limit);
    let (wants4, wants6) = (args.wants_v4(), args.wants_v6());
    let (rows4, next4) = if wants4 {
        scan_back(
            view,
            &tables::HISTORY,
            args.before.as_ref(),
            args.from,
            |event: &LeaseEvent| event.at,
            |event| args.matches(event),
            limit,
        )?
    } else {
        (Vec::new(), None)
    };
    let (rows6, next6) = if wants6 {
        scan_back(
            view,
            &tables::HISTORY6,
            args.before6.as_ref(),
            args.from,
            |event: &Lease6Event| event.at,
            |event| args.matches6(event),
            limit,
        )?
    } else {
        (Vec::new(), None)
    };
    // No unread row of a table is newer than where its read stopped.
    let horizon = [next4.map(merge4), next6.map(merge6)]
        .into_iter()
        .flatten()
        .max();
    let mut merged: Vec<(MergeKey, bool)> = rows4
        .iter()
        .map(|(key, _)| (merge4(*key), false))
        .chain(rows6.iter().map(|(key, _)| (merge6(*key), true)))
        .filter(|(key, _)| horizon.is_none_or(|horizon| *key >= horizon))
        .collect();
    merged.sort_unstable_by_key(|(key, _)| std::cmp::Reverse(*key));
    merged.truncate(limit);
    // Each table's rows are newest first, so the rows taken are a head of each list.
    let taken6 = merged.iter().filter(|(_, six)| *six).count();
    let taken4 = merged.len() - taken6;
    let ended4 = taken4 == rows4.len() && next4.is_none();
    let resume4 = (wants4 && !ended4).then(|| resume_of(&rows4, taken4, args.before, next4));
    let ended6 = taken6 == rows6.len() && next6.is_none();
    let resume6 = (wants6 && !ended6).then(|| resume_of(&rows6, taken6, args.before6, next6));
    let items: Vec<LeaseEvent> = rows4
        .into_iter()
        .take(taken4)
        .map(|(_, event)| event)
        .collect();
    let items6: Vec<Lease6Event> = rows6
        .into_iter()
        .take(taken6)
        .map(|(_, event)| event)
        .collect();
    Ok(HistoryPage {
        items,
        next: resume4.and_then(|resume| resume.key()),
        items6,
        resume: resume4,
        resume6,
    })
}

/// A page of `dhcp.history` alone.
fn v4_page(items: Vec<LeaseEvent>, next: Option<HistoryKey>) -> HistoryPage {
    HistoryPage {
        items,
        next,
        items6: Vec::new(),
        resume: next.map(Resume::From),
        resume6: None,
    }
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
                return Ok(v4_page(items, None));
            }
            if args.matches(&event) {
                items.push(event);
                if items.len() == limit {
                    return Ok(v4_page(items, last));
                }
            }
        }
        let Some(last) = last else {
            return Ok(v4_page(items, None));
        };
        if !full {
            return Ok(v4_page(items, None));
        }
        if seen >= HISTORY_SCAN {
            return Ok(v4_page(items, Some(last)));
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
    /// A page of leases (boxed since WP9.4 made it larger).
    Leases(Box<LeasePage>),
    /// One lease (the release's result).
    Lease(Box<LeaseRow>),
    /// A page of the history (boxed since WP9.4 made it larger).
    History(Box<HistoryPage>),
    // WP9.4: the release of a DHCPv6 lease.
    /// One DHCPv6 lease (the release's result).
    Lease6(Box<Lease6Row>),
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
