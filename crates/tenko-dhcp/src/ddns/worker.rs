//! The DDNS worker (plan section 2.9, ADR 0020 point 5): a leader service that follows the
//! lease rows and writes the names after the commit, never inside it.
//!
//! The worker watches `dhcp.leases` in the store, so every committed change reaches it:
//! a grant or a renewal from the committer, a release, an expiry from `dhcp.expiry`, an
//! operator's reclaim. Nothing runs on the DORA path. For each changed row it builds a
//! [`DdnsRequest`] (add for an active binding, remove otherwise), and takes them in
//! batches:
//!
//! 1. the names each lease should hold ([`plan::desired`]): the scope's DDNS settings, the
//!    zone's DHCP switch with the profile's default, the name rules, IPAM's names;
//! 2. the changes, by the RFC 4703 rules ([`plan::Planner`]), against one view of the
//!    store, from the address's record (`dhcp.ddns_names`, read through to the names an
//!    earlier version left on the lease row): every name it holds that the lease no longer
//!    wants removed, one part per RRset, then the A and DHCID at the forward name and the
//!    PTR in the reverse zone;
//! 3. one change set per zone through the zone service with the origin `dhcp` and the
//!    principal `system:dhcp`, stamped with the time it is written (audited by the zone
//!    service, journalled, so IXFR carries it, and written without a job record), one zone
//!    after another, the zones that take PTRs last, each set fenced to the worker's term
//!    and carrying the record of each of its leases (`settle`), so a name and its record
//!    commit together; the zone service checks each part on the view it plans the set
//!    against and leaves out the parts it refuses, and a PTR is written once its forward
//!    name is; a zone write the store could not take at all is retried with a doubling
//!    backoff (`[dhcp.ddns] retries`, `backoff_ms`), and after that the rest of the batch
//!    fails too; any other refused write fails its zone only, at once;
//! 4. the status batch (`Worker::status`): what no set carried (a record entry nothing was
//!    planned for, a set that changed nothing, the last refusal or failure), counted in
//!    `tenko_dhcp_ddns_total{outcome}`.
//!
//! The worker keeps nothing in memory across batches, so a restart or a change of leader
//! loses nothing, and it never wakes on its own writes. A refusal is not retried until the
//! lease's next change (a renewal), and a failure is retried after a pause. A change of the
//! DHCP configuration or of the zones makes the worker read every lease again.
//!
//! **The budget.** A batch starts when its first lease has waited the short window, but
//! never sooner than a spacing (5 s) after the end of the last batch that proposed a change
//! set, on a monotonic clock: every zone gets at most one change set, and one audit record,
//! in any 5 s, however fast clients come and go, and a lone client after a quiet spacing
//! gets its name after the short window. A batch takes the waiting leases in the order they
//! changed, reads the rows of at most `max_changes` of them, and stops before the first one
//! whose changes would take any zone's set past the zone service's `max_changes`; that lease
//! and the ones after it wait, at the front, for the next batch. A lease is planned whole
//! or not at all, and a set the store finds too large is halved: its first half is written
//! and the other leases wait, their parts in the zones already written on their record.
//!
//! WP9.1: the worker follows `dhcp.leases6` the same way. A DHCPv6 lease writes an AAAA
//! record with the DHCID of its DUID (identifier type 2) and the PTR under `ip6.arpa`; its
//! forward zone is the scope's, else the zone of the first name of the scope's domain list
//! (option 24), and the flags of its option 39 are kept on the row in the layout of option
//! 81, so the rules of [`super::flags`] read them.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt as _;
use tenko_core::{
    Principal, RequestCtx, Revision, SystemComponent, Timestamp, VrfId,
    codec::KeyCodec,
    dhcp::{BindingState, DdnsConflict, DdnsNames, DdnsState, Lease, Lease6, Lease6Kind, tables},
    dns::{DnsName, tables::ZONES},
    serde_util::HexBytes,
    table::TableDef,
};
use tenko_dns::zone::ZoneService;
use tenko_ipam::tables::{ADDRESS_IPS, ADDRESSES};
use tenko_store::{
    ChangeStream, KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError,
    WatchFilter, WriteBatch, fence, fenced_out,
};
use tokio_util::sync::CancellationToken;

use super::{
    DdnsAction, DdnsRequest,
    metrics::{OLDEST, Outcome, QUEUE},
    plan::{self, DdnsProfile, LeaseNames, Planner, Skip, ZoneChanges, Zones},
    record_of,
};
use crate::{config, image::ConfigImage};

/// The address of a lease row: a DHCPv4 row of `dhcp.leases` for an IPv4 address, a DHCPv6
/// row of `dhcp.leases6` for an IPv6 one.
type Key = (VrfId, IpAddr);

/// Reads the profile's DDNS rules from a view of the store (the profile lives in the
/// system settings, which this crate does not read).
pub type ProfileSource = Arc<dyn Fn(&dyn ReadView) -> DdnsProfile + Send + Sync>;

/// The worker's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdnsSettings {
    /// Retries of a zone write the store could not take at all (`[dhcp.ddns] retries`).
    pub retries: u32,
    /// The first pause between them, doubled each time (`[dhcp.ddns] backoff_ms`).
    pub backoff: Duration,
    /// The pause before a failed lease is tried again.
    pub retry_after: Duration,
    /// How long the first changed lease waits for others to join its batch, so that a
    /// burst of commits becomes one change set per zone (ADR 0020 point 5).
    pub window: Duration,
    /// The time from the end of a batch that proposed a change set to the next batch.
    pub spacing: Duration,
}

impl Default for DdnsSettings {
    fn default() -> Self {
        Self {
            retries: 5,
            backoff: Duration::from_secs(1),
            retry_after: Duration::from_secs(30),
            window: Duration::from_millis(100),
            spacing: Duration::from_secs(5),
        }
    }
}

/// The DDNS worker as a leader service (`dhcp.ddns`).
pub struct DdnsService {
    store: Arc<dyn Store>,
    zones: Arc<ZoneService>,
    profile: ProfileSource,
    settings: DdnsSettings,
}

impl std::fmt::Debug for DdnsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdnsService")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// One lease of a batch: its request (none once its row is gone), the names its row holds
/// from an earlier version, its record as the batch read it, and what became of it.
#[derive(Debug)]
struct Lease1 {
    key: Key,
    request: Option<DdnsRequest>,
    legacy: DdnsState,
    marked: Instant,
    record: DdnsNames,
    /// The record row's version as the batch read it.
    version: Option<Revision>,
    /// What only the status batch records: the entries nothing was planned for.
    later: Vec<(Part, Done)>,
    refusal: Option<String>,
    failure: Option<String>,
    note: Option<String>,
    /// Its new forward name waits for a slot.
    waits: bool,
}

/// One part of a lease's plan in a zone write.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// The removal of one RRset of the forward entry with this owner name and DHCID.
    Unforward(DnsName, HexBytes),
    /// The removal of the PTR entry with this name and target.
    Unptr(DnsName, Option<DnsName>),
    /// A forward name written with its DHCID.
    Forward(DnsName, HexBytes),
    /// The PTR written, with the name it points at.
    Ptr(DnsName, Option<DnsName>),
}

/// What became of a part.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Done {
    Written,
    /// The zone refused it: an addition waits for the lease's next change, a removal met
    /// data of another origin, which is no longer the lease's.
    Refused(String),
    /// Not tried: a PTR whose forward name was not written, a set cut in half.
    Waits,
    /// Its zone's write failed: tried again after a pause.
    Failed(String),
}

/// The record after a set's parts: removals first, a forward entry leaving when every
/// removal of it (owner name and DHCID) is gone (written or refused) and the PTR entry when
/// its removal (name and target) is; then a written forward name replaces only the same
/// entry, and a written PTR becomes the one PTR entry.
fn settle(row: &mut DdnsNames, parts: &[(Part, Done)]) {
    let gone = |part: &Part| {
        parts
            .iter()
            .filter(|(other, _)| other == part)
            .all(|(_, done)| matches!(done, Done::Written | Done::Refused(_)))
    };
    for (part, _) in parts {
        match part {
            Part::Unforward(name, dhcid) if gone(part) => {
                row.forward.retain(|(held, by)| (held, by) != (name, dhcid));
            }
            Part::Unptr(name, target)
                if gone(part) && row.ptr.as_ref() == Some(&(name.clone(), target.clone())) =>
            {
                row.ptr = None;
            }
            _ => {}
        }
    }
    for (part, done) in parts {
        match (part, done) {
            (Part::Forward(name, dhcid), Done::Written) => {
                row.put_forward(name.clone(), dhcid.clone());
            }
            (Part::Ptr(name, target), Done::Written) => {
                row.ptr = Some((name.clone(), target.clone()));
            }
            _ => {}
        }
    }
}

/// Stages `row` as `lease`'s record, expected at `version`: deleted when it holds no entry
/// and either the lease row is gone, or it holds no error and the lease row names nothing
/// (no earlier version's names to keep out). Returns whether it was deleted.
fn stage_row(
    batch: &mut WriteBatch,
    lease: &Lease1,
    row: &DdnsNames,
    version: Option<Revision>,
) -> Result<bool, StoreError> {
    let legacy = lease.legacy.forward.is_some() || lease.legacy.reverse.is_some();
    let delete = row.forward.is_empty()
        && row.ptr.is_none()
        && (lease.request.is_none() || (row.last_error.is_none() && !legacy));
    batch.expect_typed(&tables::DDNS_NAMES, &lease.key, version);
    if delete {
        batch.delete_typed(&tables::DDNS_NAMES, &lease.key);
    } else {
        batch.put_typed(&tables::DDNS_NAMES, &lease.key, row)?;
    }
    Ok(delete)
}

/// Calls `each` with every row of `table`, page by page.
fn each_row<K: KeyCodec, V: serde::Serialize + serde::de::DeserializeOwned>(
    view: &dyn ReadView,
    table: &TableDef<K, V>,
    mut each: impl FnMut(K, V),
) -> Result<(), StoreError> {
    let mut range = KeyRange::all();
    loop {
        let page = view.scan_typed(table, range.clone(), crate::lease::follow::PAGE, false)?;
        let full = page.len() == crate::lease::follow::PAGE;
        let Some(last) = page.last().map(|(key, _, _)| table.key(key)) else {
            return Ok(());
        };
        for (key, value, _) in page {
            each(key, value);
        }
        if !full {
            return Ok(());
        }
        range = KeyRange::all().after(last);
    }
}

/// Whether the lease `index` is one of `leases`, a run of the ascending leases of a set.
fn among(leases: &[usize], index: usize) -> bool {
    matches!((leases.first(), leases.last()), (Some(first), Some(last)) if (*first..=*last).contains(&index))
}

/// The request a lease row asks for: add for a binding that holds its address now,
/// remove otherwise; while the clock is not `trusted`, an active row holds it whatever its
/// end says. The DDNS settings are those the class and policy matcher decided at the commit
/// (the row's `ddns_policy`, the settings the reply's option 81 used), else the scope's.
pub fn request_of(
    lease: &Lease,
    image: &ConfigImage,
    now: Timestamp,
    trusted: bool,
) -> DdnsRequest {
    let active = lease.state == BindingState::Active && (!trusted || lease.ends > now);
    // Slice 8 follow-ups: the policy's settings first.
    let policy = lease
        .ddns_policy
        .clone()
        .or_else(|| image.scope(lease.scope).map(|scope| scope.ddns.clone()))
        .unwrap_or_default();
    // A client time after `now` (raised after the clock stepped back) counts from now.
    let lease_secs = u32::try_from(lease.ends.saturating_since(lease.cltt.min(now)).as_secs())
        .unwrap_or(u32::MAX);
    DdnsRequest {
        action: if active && policy.enabled {
            DdnsAction::Add
        } else {
            DdnsAction::Remove
        },
        vrf: lease.vrf,
        scope: lease.scope,
        addr: IpAddr::V4(lease.addr),
        client: lease.client.clone(),
        fqdn: lease.fqdn.clone(),
        hostname: lease.hostname.clone(),
        fqdn_flags: lease.fqdn_flags,
        policy,
        lease_secs,
        ends: lease.ends,
    }
}

// WP9.1: the request of a DHCPv6 lease row.
/// The request a DHCPv6 lease row asks for, by the rules of [`request_of`]; the scope's
/// DDNS settings (classes and policies are DHCPv4 only).
pub fn request_of6(
    lease: &Lease6,
    image: &ConfigImage,
    now: Timestamp,
    trusted: bool,
) -> DdnsRequest {
    let active = lease.state == BindingState::Active && (!trusted || lease.ends > now);
    let policy = image
        .v6()
        .scope(lease.scope)
        .map(|scope| scope.ddns.clone())
        .unwrap_or_default();
    // A client time after `now` (raised after the clock stepped back) counts from now.
    let lease_secs = u32::try_from(lease.ends.saturating_since(lease.cltt.min(now)).as_secs())
        .unwrap_or(u32::MAX);
    DdnsRequest {
        action: if active && policy.enabled {
            DdnsAction::Add
        } else {
            DdnsAction::Remove
        },
        vrf: lease.vrf,
        scope: lease.scope,
        addr: IpAddr::V6(lease.addr6()),
        client: lease.client_key(),
        fqdn: lease.fqdn.clone(),
        hostname: None,
        fqdn_flags: lease.fqdn_flags,
        policy,
        lease_secs,
        ends: lease.ends,
    }
}

/// The zone of the scope's domain name: option 15 of a DHCPv4 scope, the first name of
/// the domain list (option 24) of a DHCPv6 scope.
fn domain_of(image: &ConfigImage, request: &DdnsRequest) -> Option<DnsName> {
    if request.addr.is_ipv6() {
        let value = image.v6().scope(request.scope)?.option(24)?;
        let list = crate::v6::option::DomainList::parse(24, &value.data.0).ok()?;
        let first = list.iter().next()?;
        return DnsName::new(&first.to_string()).ok();
    }
    let value = image.scope(request.scope)?.option(15)?;
    let text = std::str::from_utf8(&value.data.0).ok()?;
    DnsName::new(text.trim_end_matches('\0')).ok()
}

/// Whether IPAM names the address (an address object with a DNS name): such a lease gets
/// no names at all. Whether IPAM gives a lease's name to another address is the planner's
/// check, by name ([`Planner::add`]).
fn ipam_named(view: &dyn ReadView, vrf: VrfId, addr: IpAddr) -> Result<bool, StoreError> {
    let Some((id, _)) = view.get_typed(&ADDRESS_IPS, &(vrf, addr))? else {
        return Ok(false);
    };
    Ok(view
        .get_typed(&ADDRESSES, &id)?
        .is_some_and(|(address, _)| address.dns_name.is_some()))
}

fn retryable(status: u16, code: &str) -> bool {
    status >= 500 || code.starts_with("sys.store") || code == "sys.unavailable"
}

/// What a zone write's error means for the batch; only an outage is tried again in it. The
/// worker sees the zone service's coded error, not the store's error type, so the codes are
/// named here and a test runs every store error through this.
fn failure_of(code: &str, status: u16) -> Failure {
    match code {
        // The zone service's answer to a failed fence ([`tenko_store::fenced_out`]).
        StoreError::PRECONDITION_FAILED if status == 412 => Failure::Deposed,
        StoreError::BATCH_TOO_LARGE => Failure::TooLarge,
        // The store takes no write right now, so the next zone's write would fail the same way.
        StoreError::NO_QUORUM
        | StoreError::TIMEOUT
        | StoreError::SHUTTING_DOWN
        | StoreError::STOPPED
        | StoreError::STORAGE => Failure::Outage,
        // This zone's write only, at once, and its leases come back after the retry pause: a
        // stale write the zone service already planned again, the disk guard, this batch's
        // data, which another try in the batch does not change.
        _ if retryable(status, code) => Failure::Store,
        _ => Failure::Refused,
    }
}

/// The worker's state while it runs.
struct Worker<'a> {
    service: &'a DdnsService,
    epoch: u64,
    image: Option<ConfigImage>,
    /// The changed addresses in the order they changed, each with when.
    dirty: VecDeque<(Key, Instant)>,
    pending: HashSet<Key>,
    /// Failed leases: when they are tried again, and when they first changed.
    retry: Vec<(Instant, Key, Instant)>,
    resync: bool,
    /// No batch starts before this: a spacing after the last that proposed a change set.
    quiet: Option<Instant>,
    /// Another member has taken office: the worker ends.
    deposed: bool,
}

/// Why a zone write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The store refused this zone's write, not tried again in the batch: contention on the
    /// zone, its disk, or the batch's data.
    Store,
    /// The store could take no write (no quorum, a timeout, shutting down or stopped, a
    /// storage failure), after the retries: the other zones of the batch would fail the
    /// same way.
    Outage,
    /// The zone service refused the change set.
    Refused,
    /// Above the store's batch limit.
    TooLarge,
    /// The set's fence failed: another member has taken office.
    Deposed,
}

/// What the writes of a batch did: the outcome of each part by its position, the record
/// version each committed set left a lease's row at (none: deleted), and the parts of sets
/// that wrote nothing, whose record only the status batch writes.
#[derive(Debug, Default)]
struct Wrote {
    done: Vec<Done>,
    versions: HashMap<usize, Option<Revision>>,
    unrecorded: HashSet<usize>,
    proposed: bool,
    deposed: bool,
}

impl DdnsService {
    /// The worker over `store`, writing through `zones`.
    pub fn new(
        store: Arc<dyn Store>,
        zones: Arc<ZoneService>,
        profile: ProfileSource,
        settings: DdnsSettings,
    ) -> Self {
        Self {
            store,
            zones,
            profile,
            settings,
        }
    }

    fn watch(&self, from: tenko_core::Revision) -> Result<ChangeStream, StoreError> {
        let mut names: Vec<tenko_core::TableName> = tables::NODE_TABLES
            .iter()
            .filter(|name| **name != *tables::LEASES_BY_CLIENT.name())
            .cloned()
            .collect();
        names.push(ZONES.name().clone());
        self.store.watch(Some(from), WatchFilter::tables(names))
    }
}

impl<'a> Worker<'a> {
    fn new(service: &'a DdnsService, epoch: u64) -> Self {
        Self {
            service,
            epoch,
            image: None,
            dirty: VecDeque::new(),
            pending: HashSet::new(),
            retry: Vec::new(),
            resync: true,
            quiet: None,
            deposed: false,
        }
    }

    fn mark(&mut self, key: Key) {
        if self.pending.insert(key) {
            self.dirty.push_back((key, Instant::now()));
        }
    }

    /// Puts leases a batch did not write back at the front, in their order, with the time
    /// they changed.
    fn put_back(&mut self, leases: impl DoubleEndedIterator<Item = (Key, Instant)>) {
        for (key, marked) in leases.rev() {
            if self.pending.insert(key) {
                self.dirty.push_front((key, marked));
            }
        }
    }

    /// The waiting leases and the age of the oldest, the failed ones waiting for their retry
    /// included.
    fn gauge(&self) {
        // A gauge takes a float: `set_total` would store the count as the bits of one.
        #[allow(clippy::cast_precision_loss)]
        QUEUE.set((self.dirty.len() + self.retry.len()) as f64);
        let oldest = self
            .dirty
            .front()
            .map(|(_, marked)| *marked)
            .into_iter()
            .chain(self.retry.iter().map(|(_, _, marked)| *marked))
            .min()
            .map_or(0.0, |marked| marked.elapsed().as_secs_f64().floor());
        OLDEST.set(oldest);
    }

    /// How long the waiting leases wait yet: until the first of them has waited the short
    /// window, and never before the quiet time after the last batch that proposed a set.
    fn wait(&self) -> Duration {
        let window = self.service.settings.window;
        let start = self
            .dirty
            .front()
            .map_or_else(Instant::now, |(_, at)| *at + window);
        let start = self.quiet.map_or(start, |quiet| quiet.max(start));
        start.saturating_duration_since(Instant::now())
    }

    /// Reads the configuration image and every lease again; returns the revision read.
    fn reload(&mut self, view: &dyn ReadView) -> Result<tenko_core::Revision, String> {
        let data = config::load::data(view, false).map_err(|error| error.to_string())?;
        self.image = Some(config::image::build(&data).image);
        let failed = |error: StoreError| error.to_string();
        each_row(view, &tables::LEASES, |(vrf, addr), _| {
            self.mark((vrf, IpAddr::V4(addr)));
        })
        .map_err(failed)?;
        // WP9.1: the DHCPv6 rows; a delegated prefix has no name (WP9.2).
        each_row(view, &tables::LEASES6, |(vrf, addr), lease| {
            if lease.kind == Lease6Kind::Na {
                self.mark((vrf, IpAddr::V6(addr)));
            }
        })
        .map_err(failed)?;
        // The records of lease rows deleted while no worker ran.
        each_row(view, &tables::DDNS_NAMES, |key, _| self.mark(key)).map_err(failed)?;
        self.resync = false;
        Ok(view.revision())
    }

    /// Runs until `stop`.
    async fn run(mut self, stop: CancellationToken) -> Result<(), String> {
        let mut watch: Option<ChangeStream> = None;
        loop {
            if stop.is_cancelled() {
                return Ok(());
            }
            if self.resync || watch.is_none() {
                match self.service.store.read(ReadConsistency::Local).await {
                    Ok(view) => match self.reload(view.as_ref()) {
                        Ok(revision) => match self.service.watch(revision) {
                            Ok(stream) => watch = Some(stream),
                            Err(error) => {
                                tracing::warn!(%error, "the DDNS worker cannot watch the leases");
                                watch = None;
                            }
                        },
                        Err(error) => {
                            tracing::warn!(%error, "the DDNS worker cannot read the leases");
                        }
                    },
                    Err(error) => {
                        tracing::warn!(%error, "the DDNS worker cannot read the store");
                    }
                }
                if watch.is_none() {
                    tokio::select! {
                        () = stop.cancelled() => return Ok(()),
                        () = tokio::time::sleep(self.service.settings.backoff) => {}
                    }
                    continue;
                }
            }
            let now = Instant::now();
            let due: Vec<(Key, Instant)> = {
                let (due, later): (Vec<_>, Vec<_>) =
                    self.retry.drain(..).partition(|(at, _, _)| *at <= now);
                self.retry = later;
                due.into_iter()
                    .map(|(_, key, marked)| (key, marked))
                    .collect()
            };
            // A failed lease is older than the ones that changed since: it goes first.
            self.put_back(due.into_iter());
            self.gauge();
            if !self.dirty.is_empty() {
                // The first changed lease waits a moment for others to join its batch, and
                // every batch a spacing after the last that proposed a change set.
                let remaining = self.wait();
                if !remaining.is_zero() {
                    if let Some(stream) = watch.as_mut() {
                        tokio::select! {
                            () = stop.cancelled() => return Ok(()),
                            event = stream.next() => {
                                if !event.is_some_and(|event| self.take(event)) {
                                    watch = None;
                                }
                            }
                            () = tokio::time::sleep(remaining) => {}
                        }
                    } else {
                        tokio::time::sleep(remaining).await;
                    }
                    continue;
                }
                // Take what the watch already delivered before the batch, so that a burst
                // becomes one batch.
                if let Some(stream) = watch.as_mut() {
                    while let Some(Some(event)) = futures::FutureExt::now_or_never(stream.next()) {
                        if !self.take(event) {
                            watch = None;
                            break;
                        }
                    }
                }
                self.batch().await;
                if self.deposed {
                    return Err("the DDNS worker is no longer the leader".to_owned());
                }
                continue;
            }
            let next_retry = self.retry.iter().map(|(at, _, _)| *at).min();
            let sleep = next_retry.map_or(Duration::from_secs(3_600), |at| {
                at.saturating_duration_since(Instant::now())
            });
            let Some(stream) = watch.as_mut() else {
                continue;
            };
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                event = stream.next() => {
                    let alive = event.is_some_and(|event| self.take(event));
                    if !alive {
                        watch = None;
                    }
                }
                () = tokio::time::sleep(sleep) => {}
            }
        }
    }

    /// Takes one watch event; false when the watch must start again.
    fn take(&mut self, event: Result<tenko_store::ChangeSet, tenko_store::WatchError>) -> bool {
        match event {
            Ok(set) => {
                for change in &set.changes {
                    if change.table == *tables::LEASES.name() {
                        if let Ok((vrf, addr)) = tables::LEASES.decode_key(&change.key) {
                            self.mark((vrf, IpAddr::V4(addr)));
                        }
                    } else if change.table == *tables::LEASES6.name() {
                        // WP9.1: a DHCPv6 lease row.
                        if let Ok((vrf, addr)) = tables::LEASES6.decode_key(&change.key) {
                            self.mark((vrf, IpAddr::V6(addr)));
                        }
                    } else {
                        // A configuration row or a zone changed: read everything again.
                        self.resync = true;
                    }
                }
                true
            }
            Err(error) => {
                tracing::info!(%error, "the DDNS worker reads the leases again");
                self.resync = true;
                false
            }
        }
    }

    /// Handles up to one batch of the changed addresses.
    async fn batch(&mut self) {
        let view = match self.service.store.read(ReadConsistency::Local).await {
            Ok(view) => view,
            Err(error) => {
                tracing::warn!(%error, "the DDNS worker cannot read the store");
                tokio::time::sleep(self.service.settings.backoff).await;
                return;
            }
        };
        let now = Timestamp::now();
        let trusted = tenko_core::clock::trusted_now().is_ok();
        // The take rule never plans more leases than the zone service takes changes (a lease
        // that writes plans at least one), so the batch reads no more rows than that.
        let max_changes = self.service.zones.config().max_changes;
        let take = self.dirty.len().min(max_changes.max(1));
        let keys: Vec<(Key, Instant)> = self.dirty.drain(..take).collect();
        for (key, _) in &keys {
            self.pending.remove(key);
        }
        let Some(image) = self.image.as_ref() else {
            return;
        };
        let mut leases = Vec::new();
        let mut failed = Vec::new();
        for (key, marked) in keys {
            match lease_of(view.as_ref(), image, key, marked, now, trusted) {
                Ok(Some(lease)) => leases.push(lease),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker cannot read a lease");
                    failed.push((key, marked));
                }
            }
        }
        self.retry_later(failed);
        self.gauge();
        if !leases.is_empty() {
            self.apply(view.as_ref(), leases, now).await;
            self.gauge();
        }
    }

    /// Leases tried again after the pause.
    fn retry_later(&mut self, leases: impl IntoIterator<Item = (Key, Instant)>) {
        let at = Instant::now() + self.service.settings.retry_after;
        self.retry
            .extend(leases.into_iter().map(|(key, marked)| (at, key, marked)));
    }

    /// Plans and writes one batch of leases, then records what only the status batch can.
    async fn apply(&mut self, view: &dyn ReadView, mut leases: Vec<Lease1>, now: Timestamp) {
        let zones = match Zones::read(view) {
            Ok(zones) => zones,
            Err(error) => {
                tracing::warn!(%error, "the DDNS worker cannot read the zones");
                self.retry_later(leases.into_iter().map(|lease| (lease.key, lease.marked)));
                return;
            }
        };
        let profile = (self.service.profile)(view);
        let max_changes = self.service.zones.config().max_changes;
        let mut planner = Planner::new();
        // The changes of the batch in order, each with its lease and part.
        let mut writes: Vec<(usize, Part, ZoneChanges)> = Vec::new();
        let mut changes_per_zone: HashMap<tenko_core::dns::ZoneId, usize> = HashMap::new();
        let mut taken = leases.len();
        for (index, lease) in leases.iter_mut().enumerate() {
            let image = self.image.as_ref();
            let parts = plan_lease(view, &zones, image, profile, &mut planner, lease);
            let mut adds: HashMap<tenko_core::dns::ZoneId, usize> = HashMap::new();
            for (_, zc) in &parts {
                *adds.entry(zc.zone).or_default() += zc.changes.len();
            }
            let over = adds.iter().any(|(zone, count)| {
                changes_per_zone.get(zone).copied().unwrap_or(0) + count > max_changes
            });
            // The first lease always goes, so that a batch never stalls on one.
            if over && index > 0 {
                taken = index;
                break;
            }
            for (zone, count) in adds {
                *changes_per_zone.entry(zone).or_default() += count;
            }
            writes.extend(parts.into_iter().map(|(part, zc)| (index, part, zc)));
        }
        let waiting = leases.split_off(taken);
        let wrote = self
            .write(&leases, &writes, profile.allows_by_default)
            .await;
        if wrote.proposed {
            self.quiet = Some(Instant::now() + self.service.settings.spacing);
        }
        // The next leader plans every lease again.
        if wrote.deposed {
            self.deposed = true;
            return;
        }
        let mut back = Vec::new();
        for (index, lease) in leases.iter_mut().enumerate() {
            // A lease's parts are together, in the order of the leases.
            let span = writes.partition_point(|(at, _, _)| *at < index)
                ..writes.partition_point(|(at, _, _)| *at <= index);
            let mut written = false;
            let mut removed = false;
            for position in span {
                let ((_, part, _), done) = (&writes[position], &wrote.done[position]);
                match done {
                    Done::Failed(error) => {
                        lease.failure.get_or_insert_with(|| error.clone());
                    }
                    Done::Refused(reason) => {
                        lease.refusal.get_or_insert_with(|| reason.clone());
                    }
                    Done::Waits => lease.waits = true,
                    Done::Written => match part {
                        Part::Forward(..) | Part::Ptr(..) => written = true,
                        Part::Unforward(..) | Part::Unptr(..) => removed = true,
                    },
                }
                if wrote.unrecorded.contains(&position) {
                    lease.later.push((part.clone(), done.clone()));
                }
            }
            if lease.failure.is_some() {
                Outcome::Failed.count();
            } else if lease.waits {
                back.push((lease.key, lease.marked));
            } else if lease.refusal.is_some() {
                Outcome::Refused.count();
            } else if written {
                Outcome::Written.count();
            } else if lease.note.is_some() && !removed {
                Outcome::Skipped.count();
            }
            if removed && lease.failure.is_none() {
                Outcome::Removed.count();
            }
        }
        self.retry_later(
            leases
                .iter()
                .filter(|lease| lease.failure.is_some())
                .map(|lease| (lease.key, lease.marked)),
        );
        back.extend(waiting.into_iter().map(|lease| (lease.key, lease.marked)));
        self.put_back(back.into_iter());
        self.status(&leases, &wrote.versions, now).await;
    }

    /// Writes the zone changes of a batch, one change set per zone and one zone after
    /// another, the zones that take PTRs last: a PTR is tried once its forward name is
    /// written, and a forward name the zone refused refuses its PTR. Each set carries its
    /// leases' records ([`settle`]). A set the store finds too large is halved by its leases
    /// until it fits; the leases cut from it wait. Once the store has been unavailable for
    /// one zone's write after the retries, the later zones of the batch fail with it without a
    /// try; any other failure leaves the others to their own tries ([`failure_of`]). A worker
    /// no longer in office ends its batch. `allows` is the profile's default of the zones'
    /// DHCP switch.
    async fn write(
        &self,
        leases: &[Lease1],
        writes: &[(usize, Part, ZoneChanges)],
        allows: bool,
    ) -> Wrote {
        let mut order: Vec<tenko_core::dns::ZoneId> = Vec::new();
        for (_, _, zc) in writes {
            if !order.contains(&zc.zone) {
                order.push(zc.zone);
            }
        }
        order.sort_by_key(|zone| {
            writes
                .iter()
                .any(|(_, part, zc)| zc.zone == *zone && matches!(part, Part::Ptr(..)))
        });
        let mut wrote = Wrote {
            done: vec![Done::Waits; writes.len()],
            ..Wrote::default()
        };
        // The position of each lease's forward name.
        let forward_of: HashMap<usize, usize> = writes
            .iter()
            .enumerate()
            .filter(|(_, (_, part, _))| matches!(part, Part::Forward(..)))
            .map(|(position, (index, _, _))| (*index, position))
            .collect();
        // The store unavailable after the retries: the rest of the batch fails with it at once.
        let mut outage: Option<String> = None;
        for zone in order {
            let mut parts: Vec<usize> = Vec::new();
            for (position, (index, part, zc)) in writes.iter().enumerate() {
                if zc.zone != zone {
                    continue;
                }
                let forward = forward_of
                    .get(index)
                    .map(|&at| (writes[at].2.zone, wrote.done[at].clone()));
                match (part, forward) {
                    (Part::Ptr(..), Some((_, Done::Refused(reason)))) => {
                        wrote.done[position] = Done::Refused(reason);
                    }
                    (Part::Ptr(..), Some((at, done))) if at != zone && done != Done::Written => {}
                    _ => parts.push(position),
                }
            }
            if let Some(error) = &outage {
                for &position in &parts {
                    wrote.done[position] = Done::Failed(error.clone());
                }
                continue;
            }
            if parts.is_empty() {
                continue;
            }
            // The leases of the set, in order; the set shrinks to the first half of them
            // while the store finds it too large.
            let mut kept: Vec<usize> = parts.iter().map(|&position| writes[position].0).collect();
            kept.dedup();
            let outcome = loop {
                let set: Vec<usize> = parts
                    .iter()
                    .copied()
                    .filter(|&position| among(&kept, writes[position].0))
                    .collect();
                wrote.proposed = true;
                match self.write_zone(zone, leases, writes, &set, allows).await {
                    Err((_, Failure::TooLarge)) if kept.len() > 1 => kept.truncate(kept.len() / 2),
                    outcome => break outcome.map(|written| (set, written)),
                }
            };
            match outcome {
                Ok((set, (revision, staged, refused))) => {
                    for &position in &set {
                        wrote.done[position] = Done::Written;
                    }
                    for (at, reason) in refused {
                        wrote.done[set[at]] = Done::Refused(reason);
                    }
                    match revision {
                        Some(revision) => wrote.versions.extend(
                            staged
                                .into_iter()
                                .map(|(index, deleted)| (index, (!deleted).then_some(revision))),
                        ),
                        None => wrote.unrecorded.extend(set),
                    }
                }
                Err((_, Failure::Deposed)) => {
                    wrote.deposed = true;
                    break;
                }
                Err((error, failure)) => {
                    for &position in &parts {
                        if among(&kept, writes[position].0) {
                            wrote.done[position] = Done::Failed(error.clone());
                        }
                    }
                    if failure == Failure::Outage {
                        outage = Some(error);
                    }
                }
            }
        }
        wrote
    }

    /// One zone write of the parts at `set`, fenced to the worker's term and carrying each
    /// lease's record after the set, with the retries while the store is out: the revision
    /// written (none when the set changed nothing), the leases whose record it staged (and
    /// whether deleted), and the parts the zone refused, by their place in the set.
    #[allow(
        clippy::type_complexity,
        reason = "the three answers of one write, named in the doc"
    )]
    async fn write_zone(
        &self,
        zone: tenko_core::dns::ZoneId,
        leases: &[Lease1],
        writes: &[(usize, Part, ZoneChanges)],
        set: &[usize],
        allows: bool,
    ) -> Result<(Option<Revision>, Vec<(usize, bool)>, Vec<(usize, String)>), (String, Failure)>
    {
        let changes: Vec<Vec<_>> = set
            .iter()
            .map(|&position| writes[position].2.changes.clone())
            .collect();
        let mut staged: Vec<(usize, bool)> = Vec::new();
        // On each attempt, against its view: the record of each lease of the set.
        let mut record = |view: &dyn ReadView,
                          refused: &[usize],
                          batch: &mut WriteBatch|
         -> tenko_dns::zone::ZoneResult<()> {
            staged.clear();
            let refused: HashSet<usize> = refused.iter().copied().collect();
            let mut at = 0;
            for run in set.chunk_by(|a, b| writes[*a].0 == writes[*b].0) {
                let index = writes[run[0]].0;
                let parts: Vec<(Part, Done)> = run
                    .iter()
                    .map(|&position| {
                        let done = if refused.contains(&at) {
                            Done::Refused(String::new())
                        } else {
                            Done::Written
                        };
                        at += 1;
                        (writes[position].1.clone(), done)
                    })
                    .collect();
                let lease = &leases[index];
                let (mut row, version) = record_of(view, lease.key.0, lease.key.1, &lease.legacy)?;
                settle(&mut row, &parts);
                row.updated = Some(Timestamp::now());
                staged.push((index, stage_row(batch, &leases[index], &row, version)?));
            }
            Ok(())
        };
        let settings = self.service.settings;
        let mut pause = settings.backoff;
        let mut attempt = 0;
        loop {
            // A context per attempt: its time stamps the audit record, the RRsets, the
            // serial and the journal entry.
            let cx = RequestCtx::system(SystemComponent::Dhcp);
            match self
                .service
                .zones
                .change_dhcp_names(&cx, zone, &changes, allows, Some(self.epoch), &mut record)
                .await
            {
                Ok((outcome, refused)) => {
                    let refused = refused
                        .into_iter()
                        .map(|(position, error)| {
                            let coded = error.coded();
                            (position, format!("{}: {}", coded.code, coded.detail))
                        })
                        .collect();
                    let revision = outcome.written.map(|written| written.revision);
                    return Ok((revision, staged, refused));
                }
                Err(error) => {
                    let coded = error.coded();
                    let failure = failure_of(&coded.code, coded.status);
                    if failure != Failure::Outage || attempt >= settings.retries {
                        tracing::info!(code = %coded.code, detail = %coded.detail, "a DDNS change set was not written");
                        return Err((format!("{}: {}", coded.code, coded.detail), failure));
                    }
                    attempt += 1;
                    tokio::time::sleep(pause).await;
                    pause = pause.saturating_mul(2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// The status batch: for each lease whose record changes outside the zone sets (entries
    /// nothing was planned for, parts of a set that wrote nothing, a new last error, a row
    /// to delete), its record read again and expected at the version this batch's own sets
    /// left it, else at the batch's; a record that moved meanwhile is planned again.
    async fn status(
        &mut self,
        leases: &[Lease1],
        versions: &HashMap<usize, Option<Revision>>,
        now: Timestamp,
    ) {
        let view = match self.service.store.read(ReadConsistency::Local).await {
            Ok(view) => view,
            Err(error) => {
                tracing::warn!(%error, "the DDNS worker cannot read its records");
                self.retry_later(leases.iter().map(|lease| (lease.key, lease.marked)));
                return;
            }
        };
        let mut rows = Vec::new();
        let mut again = Vec::new();
        for (index, lease) in leases.iter().enumerate() {
            let error = lease
                .failure
                .clone()
                .or_else(|| lease.refusal.clone())
                .or_else(|| lease.note.clone());
            // A row no set of this batch wrote is still written to take in the names an
            // earlier version left on the lease row, and deleted once that row is gone.
            let untouched = !versions.contains_key(&index);
            let take_in = lease.version.is_none()
                && (lease.legacy.forward.is_some() || lease.legacy.reverse.is_some());
            let empty = lease.record.forward.is_empty() && lease.record.ptr.is_none();
            let delete = lease.version.is_some() && lease.request.is_none() && empty;
            if lease.later.is_empty()
                && error == lease.record.last_error
                && !(untouched && (take_in || delete))
            {
                continue;
            }
            let expected = versions.get(&index).copied().unwrap_or(lease.version);
            match record_of(view.as_ref(), lease.key.0, lease.key.1, &lease.legacy) {
                Ok((mut row, version)) if version == expected => {
                    settle(&mut row, &lease.later);
                    if row.last_error != error {
                        (row.last_error, row.updated) = (error, Some(now));
                    }
                    rows.push((index, row, version));
                }
                Ok(_) => again.push((lease.key, lease.marked)),
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker cannot read a record");
                    again.push((lease.key, lease.marked));
                }
            }
        }
        drop(view);
        self.put_back(again.into_iter());
        // A thousand rows of at most about 2.8 KB stay well inside the store's limit.
        for chunk in rows.chunks(1_000) {
            let mut batch =
                WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
            batch.preconditions.push(fence(self.epoch));
            for (index, row, version) in chunk {
                if let Err(error) = stage_row(&mut batch, &leases[*index], row, *version) {
                    tracing::warn!(%error, "the DDNS worker cannot write a record");
                }
            }
            let keys = chunk
                .iter()
                .map(|(index, _, _)| (leases[*index].key, leases[*index].marked));
            match self.service.store.propose(batch).await {
                Ok(_) => {}
                Err(error) if fenced_out(&error) => {
                    self.deposed = true;
                    return;
                }
                // A late commit of the worker's own moved a record: plan those leases again.
                Err(StoreError::PreconditionFailed(_)) => self.put_back(keys),
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker could not record its outcomes");
                    self.retry_later(keys);
                }
            }
        }
    }
}

/// The lease at `key` with its record, or none when neither its row nor a record is left.
fn lease_of(
    view: &dyn ReadView,
    image: &ConfigImage,
    key: Key,
    marked: Instant,
    now: Timestamp,
    trusted: bool,
) -> Result<Option<Lease1>, StoreError> {
    let (request, legacy) = match key.1 {
        IpAddr::V4(addr) => view
            .get_typed(&tables::LEASES, &(key.0, addr))?
            .map(|(lease, _)| (request_of(&lease, image, now, trusted), lease.ddns)),
        // WP9.2: a delegated prefix has no name.
        IpAddr::V6(addr) => view
            .get_typed(&tables::LEASES6, &(key.0, addr))?
            .filter(|(lease, _)| lease.kind == Lease6Kind::Na)
            .map(|(lease, _)| (request_of6(&lease, image, now, trusted), lease.ddns)),
    }
    .unzip();
    let legacy = legacy.unwrap_or_default();
    let (record, version) = record_of(view, key.0, key.1, &legacy)?;
    if request.is_none() && version.is_none() {
        return Ok(None);
    }
    Ok(Some(Lease1 {
        key,
        request,
        record,
        legacy,
        marked,
        version,
        later: Vec::new(),
        refusal: None,
        failure: None,
        note: None,
        waits: false,
    }))
}

/// The parts of one lease's plan from its record: every entry not wanted removed, one part
/// per RRset (an entry nothing is planned for leaves in the status batch), then the forward
/// name and the PTR it wants and does not hold. A new forward entry waits while the client
/// holds two other entries or the row four, and its PTR with it.
#[allow(
    clippy::too_many_lines,
    reason = "one lease: what it wants, its removals, the cap, its additions"
)]
fn plan_lease(
    view: &dyn ReadView,
    zones: &Zones,
    image: Option<&ConfigImage>,
    profile: DdnsProfile,
    planner: &mut Planner,
    lease: &mut Lease1,
) -> Vec<(Part, ZoneChanges)> {
    let mut parts = Vec::new();
    let desired = match &lease.request {
        Some(request) if request.action == DdnsAction::Add => {
            match ipam_named(view, request.vrf, request.addr) {
                Ok(named) => {
                    let lease_names = LeaseNames {
                        addr: request.addr,
                        client: &request.client,
                        fqdn: request.fqdn.as_deref(),
                        hostname: request.hostname.as_deref(),
                        fqdn_flags: request.fqdn_flags,
                        policy: &request.policy,
                        domain: image.and_then(|image| domain_of(image, request)),
                        lease_secs: request.lease_secs,
                    };
                    plan::desired(view, &lease_names, zones, profile, named)
                }
                Err(error) => Err(Skip::Failed(error.to_string())),
            }
        }
        _ => Err(Skip::Quiet(None)),
    };
    let want = match desired {
        Ok(want) => Some(want),
        // The store could not be read: nothing is removed, and the lease is tried again.
        Err(Skip::Failed(error)) => {
            lease.failure = Some(error);
            return parts;
        }
        Err(Skip::Refused(reason)) => {
            lease.refusal = Some(reason);
            None
        }
        Err(Skip::Quiet(note)) => {
            lease.note = note;
            None
        }
    };
    let forward = want
        .as_ref()
        .filter(|want| want.write_a)
        .map(|want| (want.name.clone(), HexBytes(want.dhcid.clone())));
    let ptr = want.as_ref().and_then(|want| {
        let (_, ptr) = want.reverse.as_ref()?;
        Some((ptr.clone(), Some(want.name.clone())))
    });
    let addr = lease.key.1;
    for (name, dhcid) in lease.record.forward.clone() {
        if forward.as_ref() == Some(&(name.clone(), dhcid.clone())) {
            continue;
        }
        match planner.remove_name(view, zones, addr, &name, &dhcid.0) {
            Ok(Some(zc)) => parts.extend(zc.changes.into_iter().map(|change| {
                let part = ZoneChanges {
                    zone: zc.zone,
                    changes: vec![change],
                };
                (Part::Unforward(name.clone(), dhcid.clone()), part)
            })),
            // What an earlier lease of the batch does at the name is not a fact yet: wait.
            Ok(None) if planner.decided(zones, &name) => lease.waits = true,
            Ok(None) => lease
                .later
                .push((Part::Unforward(name, dhcid), Done::Written)),
            Err(error) => lease.failure = Some(error.to_string()),
        }
    }
    if let Some((name, target)) = lease.record.ptr.clone()
        && ptr.as_ref() != Some(&(name.clone(), target.clone()))
    {
        match Planner::remove_ptr(view, zones, &name, target.as_ref()) {
            Ok(Some(zc)) => parts.push((Part::Unptr(name, target), zc)),
            Ok(None) => lease.later.push((Part::Unptr(name, target), Done::Written)),
            Err(error) => lease.failure = Some(error.to_string()),
        }
    }
    let (Some(want), Some(request)) = (want, &lease.request) else {
        return parts;
    };
    let forward_held = forward
        .as_ref()
        .is_none_or(|forward| lease.record.forward.contains(forward));
    let ptr_held = ptr.is_none() || lease.record.ptr == ptr;
    if forward_held && ptr_held {
        return parts;
    }
    if !forward_held {
        let mine = lease
            .record
            .forward
            .iter()
            .filter(|(held, dhcid)| dhcid.0 == super::dhcid::dhcid(&request.client, held))
            .count();
        if mine >= 2 || lease.record.forward.len() >= 4 {
            lease.waits = true;
            return parts;
        }
    }
    let conflict = if profile.always_protect {
        DdnsConflict::Protect
    } else {
        request.policy.conflict
    };
    match planner.add(view, zones, addr, &want, conflict) {
        Ok(plan) => {
            lease.refusal = plan.refusal;
            if let (Some(zc), Some((name, dhcid)), false) = (plan.forward, forward, forward_held) {
                parts.push((Part::Forward(name, dhcid), zc));
            }
            if let (Some(zc), Some((name, target)), false) = (plan.reverse, ptr, ptr_held) {
                parts.push((Part::Ptr(name, target), zc));
            }
        }
        Err(error) => lease.failure = Some(error.to_string()),
    }
    parts
}

#[async_trait::async_trait]
impl tenko_core::cluster::LeaderService for DdnsService {
    fn name(&self) -> &'static str {
        "dhcp.ddns"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let ended = Worker::new(self, epoch).run(stop).await;
        // Only the running worker has a queue: a member that stops leading shows none.
        QUEUE.unset();
        OLDEST.unset();
        ended
    }
}

#[cfg(test)]
mod record_tests;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tenko_core::{PrefixId, Revision, dhcp::LeaseEventKind};

    use super::*;
    use crate::{image::ImageBuilder, lease::PendingChange};

    /// Every error the store can return to a zone write, as the worker sees it through the
    /// zone service: an outage fails the rest of the batch and is the only failure tried
    /// again in the batch. The expectation is a match with no wildcard arm, so a new store
    /// error does not compile here until it has its place.
    #[test]
    fn every_store_error_has_its_place_in_a_batch() {
        let table = tenko_core::TableName::from_static("dns.rrsets");
        let every = [
            StoreError::PreconditionFailed(Vec::new()),
            StoreError::IdempotencyMismatch,
            StoreError::BatchTooLarge { size: 2, limit: 1 },
            StoreError::NoQuorum,
            StoreError::Timeout,
            StoreError::ShuttingDown,
            StoreError::Stopped,
            StoreError::DiskReserve { free: 1, needed: 2 },
            StoreError::Compacted {
                oldest: Revision(1),
            },
            StoreError::ReservedTable {
                table: table.clone(),
            },
            StoreError::PlaintextSecret { table },
            StoreError::Storage(String::new()),
            StoreError::Codec(String::new()),
        ];
        for error in every {
            let expected = match &error {
                StoreError::NoQuorum
                | StoreError::Timeout
                | StoreError::ShuttingDown
                | StoreError::Stopped
                | StoreError::Storage(_) => Failure::Outage,
                StoreError::PreconditionFailed(_)
                | StoreError::IdempotencyMismatch
                | StoreError::Compacted { .. }
                | StoreError::ReservedTable { .. }
                | StoreError::PlaintextSecret { .. }
                | StoreError::Codec(_)
                | StoreError::DiskReserve { .. } => Failure::Store,
                StoreError::BatchTooLarge { .. } => Failure::TooLarge,
            };
            let zone = tenko_dns::zone::ZoneError::from(error.clone());
            let failure = failure_of(&zone.coded().code, zone.coded().status);
            assert_eq!(failure, expected, "{error:?}");
        }
        // The zone's own refusal of the whole set: this zone only, not tried again.
        let refused =
            tenko_dns::zone::ZoneError::zone_not_found(tenko_core::dns::ZoneId::generate());
        let refused = refused.coded();
        assert_eq!(failure_of(&refused.code, refused.status), Failure::Refused);
        // The zone service's failed fence: final.
        assert_eq!(
            failure_of(StoreError::PRECONDITION_FAILED, 412),
            Failure::Deposed
        );
    }

    /// The delta of a set on a record, the table of the design note: what each part's
    /// outcome leaves in the row.
    #[test]
    #[allow(clippy::too_many_lines, reason = "the rows of one table")]
    fn a_record_is_what_it_held_with_each_part_of_the_set_applied() {
        use Done::{Failed, Refused, Waits, Written as W};
        let name = |n: u8| DnsName::new(&format!("h{n}.example.test")).expect("a name");
        let f = |n: u8| (name(n), HexBytes(vec![n]));
        let p = |n: u8| {
            (
                DnsName::new("10.2.0.192.in-addr.arpa").expect("a PTR"),
                Some(name(n)),
            )
        };
        let row = |forward: &[u8], ptr: Option<u8>| DdnsNames {
            forward: forward.iter().map(|&n| f(n)).collect(),
            ptr: ptr.map(p),
            ..DdnsNames::default()
        };
        let un = |n: u8| Part::Unforward(f(n).0, f(n).1);
        let unptr = || Part::Unptr(p(1).0, p(1).1);
        // Another client's entry at the same owner name.
        let other = |n: u8| (name(n), HexBytes(vec![n + 100]));
        let add = |n: u8| Part::Forward(f(n).0, f(n).1);
        let ptr = |n: u8| Part::Ptr(p(n).0, p(n).1);
        let no = || "no".to_owned();
        let table = [
            (
                row(&[], None),
                vec![(add(1), W), (ptr(1), W)],
                row(&[1], Some(1)),
            ),
            (
                row(&[1], Some(1)),
                vec![(add(1), W), (ptr(1), W)],
                row(&[1], Some(1)),
            ),
            (
                row(&[1], Some(1)),
                vec![
                    (un(1), W),
                    (un(1), W),
                    (unptr(), W),
                    (add(2), W),
                    (ptr(2), W),
                ],
                row(&[2], Some(2)),
            ),
            (
                row(&[1], Some(1)),
                vec![
                    (un(1), W),
                    (un(1), W),
                    (unptr(), W),
                    (add(2), Refused(no())),
                    (ptr(2), Refused(no())),
                ],
                row(&[], None),
            ),
            (
                row(&[1], Some(1)),
                vec![(un(1), Refused(no())), (un(1), W)],
                row(&[], Some(1)),
            ),
            (
                row(&[1], Some(1)),
                vec![(un(1), W), (un(1), Refused(no())), (unptr(), Refused(no()))],
                row(&[], None),
            ),
            (
                row(&[1], Some(1)),
                vec![(un(1), Failed(no())), (un(1), Failed(no())), (add(2), W)],
                row(&[1, 2], Some(1)),
            ),
            (
                row(&[1], Some(1)),
                vec![(add(2), W), (unptr(), Waits), (ptr(2), Waits)],
                row(&[1, 2], Some(1)),
            ),
            (row(&[1, 2], None), vec![(add(3), W)], row(&[1, 2, 3], None)),
            (
                row(&[1], Some(1)),
                vec![(un(1), W), (unptr(), W)],
                row(&[], None),
            ),
            // A removal drops only its own entry: not the new client's at the same name,
            // nor a PTR that points elsewhere now.
            (
                DdnsNames {
                    forward: vec![other(1)],
                    ptr: Some(p(2)),
                    ..DdnsNames::default()
                },
                vec![(un(1), W), (unptr(), W)],
                DdnsNames {
                    forward: vec![other(1)],
                    ptr: Some(p(2)),
                    ..DdnsNames::default()
                },
            ),
            // A written name replaces only the same entry.
            (
                row(&[1], None),
                vec![(Part::Forward(other(1).0, other(1).1), W)],
                DdnsNames {
                    forward: vec![f(1), other(1)],
                    ..DdnsNames::default()
                },
            ),
        ];
        for (at, (mut held, parts, expected)) in table.into_iter().enumerate() {
            settle(&mut held, &parts);
            assert_eq!(held, expected, "row {at}");
        }
    }

    #[test]
    fn a_client_time_after_now_gives_the_time_left_as_the_lease_time() {
        let now = Timestamp::now();
        let at = |secs| now.checked_add(Duration::from_secs(secs)).expect("a time");
        // The row's client time was raised a minute past now after the clock stepped back.
        let lease = PendingChange::new(
            LeaseEventKind::Renewed,
            VrfId(uuid::Uuid::nil()),
            PrefixId::generate(),
            Ipv4Addr::new(192, 0, 2, 10),
            1,
            &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
            None,
            BindingState::Active,
            at(60),
            at(3_600),
        )
        .to_lease(tenko_core::NodeId(1), None);
        let image = ImageBuilder::new(Revision(1)).build();
        assert_eq!(request_of(&lease, &image, now, true).lease_secs, 3_600);
    }
}
