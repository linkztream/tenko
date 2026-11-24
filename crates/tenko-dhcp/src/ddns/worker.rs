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
//!    store: what the lease wrote before goes first (another name, another client at the
//!    address, a release or expiry), then the A and DHCID set at the forward name and the
//!    PTR in the reverse zone;
//! 3. one change set per zone through the zone service with the origin `dhcp` and the
//!    principal `system:dhcp`, stamped with the time it is written (audited by the zone
//!    service, journalled, so IXFR carries it, and written without a job record), forward
//!    zones first; the zone service checks each lease's part on the view it plans the set
//!    against and leaves out the parts it refuses, so no lease holds up the others, and a
//!    refused forward name takes its PTR along; a zone write the store refuses is retried
//!    with a doubling backoff (`[dhcp.ddns] retries`, `backoff_ms`), but not one its disk
//!    guard refuses, and once the store has been unavailable for one zone's write the rest
//!    of the batch fails too;
//! 4. the outcome on the lease row (`DdnsState`: the names written, the DHCID, the last
//!    refusal or failure, the time), written with the row's version as precondition so a
//!    newer commit is never overwritten, and counted in `tenko_dhcp_ddns_total{outcome}`.
//!
//! The worker remembers per address what it wrote and for which client (read from the
//! rows' `ddns` at start), so a row that reached it already changed (a new client at the
//! address) still has the old names removed. A refusal is not retried until the lease's
//! next change (a renewal), and a failure is retried after a pause. A change of the
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
//! and the other leases wait, their parts in the zones already written kept.
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
    Principal, RequestCtx, SystemComponent, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, DdnsConflict, DdnsPolicy, DdnsState, Lease, Lease6, Lease6Kind,
        tables,
    },
    dns::{DnsName, tables::ZONES},
    serde_util::HexBytes,
};
use tenko_dns::zone::ZoneService;
use tenko_ipam::tables::{ADDRESS_IPS, ADDRESSES};
use tenko_store::{
    ChangeStream, FailedPrecondition, KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store,
    StoreError, WatchFilter, WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use super::{
    DdnsAction, DdnsRequest,
    metrics::{OLDEST, Outcome, QUEUE},
    plan::{self, DdnsProfile, LeaseNames, Planner, Skip, Written, ZoneChanges, Zones},
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
    /// Retries of a zone write the store refuses (`[dhcp.ddns] retries`).
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

/// What the worker remembers of an address.
#[derive(Debug, Clone)]
struct Memo {
    client: ClientKey,
    written: Written,
    /// The last request handled for the address, so that the worker's own row write (and
    /// a change that alters nothing DDNS reads) is not handled twice.
    handled: Option<DdnsRequest>,
}

/// What became of one lease in a batch.
#[derive(Debug, Default)]
struct Result1 {
    holds: Written,
    refusal: Option<String>,
    failure: Option<String>,
    note: Option<String>,
    removed: bool,
    wrote: bool,
}

/// One part of a lease's plan in a zone write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Part {
    Remove,
    Forward,
    Reverse,
}

fn written_of(state: &DdnsState) -> Written {
    Written {
        forward: state.forward.clone(),
        reverse: state.reverse.clone(),
        dhcid: state.dhcid.as_ref().map(|hex| hex.0.clone()),
    }
}

fn is_empty(written: &Written) -> bool {
    written.forward.is_none() && written.reverse.is_none()
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

/// What a zone write's error means for the batch, and whether the write is tried again in
/// it. The worker sees the zone service's coded error, not the store's error type, so the
/// codes are named here and a test runs every store error through this.
fn failure_of(code: &str, status: u16) -> (Failure, bool) {
    match code {
        StoreError::BATCH_TOO_LARGE => (Failure::TooLarge, false),
        // The store takes no write right now, so the next zone's write would fail the same way.
        StoreError::NO_QUORUM
        | StoreError::TIMEOUT
        | StoreError::SHUTTING_DOWN
        | StoreError::STOPPED
        | StoreError::STORAGE => (Failure::Outage, true),
        // The disk guard refuses growth until someone frees space: each zone's write is
        // refused at once on its own (and trims that zone's journal), and the lease's own
        // retry comes soon enough.
        StoreError::DISK_RESERVE => (Failure::Store, false),
        // This zone's write only: contention, or this batch's data.
        _ if retryable(status, code) => (Failure::Store, true),
        _ => (Failure::Refused, false),
    }
}

/// The worker's state while it runs.
struct Worker<'a> {
    service: &'a DdnsService,
    epoch: u64,
    memory: HashMap<Key, Memo>,
    image: Option<ConfigImage>,
    /// The changed addresses in the order they changed, each with when.
    dirty: VecDeque<(Key, Instant)>,
    pending: HashSet<Key>,
    /// Failed leases: when they are tried again, and when they first changed.
    retry: Vec<(Instant, Key, Instant)>,
    resync: bool,
    /// No batch starts before this: a spacing after the last that proposed a change set.
    quiet: Option<Instant>,
}

/// Why a zone write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The store refused this zone's write, after the retries: contention on the zone, its
    /// disk, or the batch's data.
    Store,
    /// The store could take no write (no quorum, a timeout, shutting down or stopped, a
    /// storage failure), after the retries: the other zones of the batch would fail the
    /// same way.
    Outage,
    /// The zone service refused the change set.
    Refused,
    /// Above the store's batch limit.
    TooLarge,
}

/// What the writes of a batch did besides writing: the parts that failed or that the zone
/// refused, with the reason, and the leases put back to wait, whole.
#[derive(Debug, Default)]
struct Wrote {
    failed: HashMap<(usize, Part), String>,
    refused: HashMap<(usize, Part), String>,
    deferred: HashSet<usize>,
    proposed: bool,
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
            memory: HashMap::new(),
            image: None,
            dirty: VecDeque::new(),
            pending: HashSet::new(),
            retry: Vec::new(),
            resync: true,
            quiet: None,
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
        QUEUE.set(self.dirty.len() as f64);
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
        let mut range = KeyRange::all();
        loop {
            let page = view
                .scan_typed(
                    &tables::LEASES,
                    range.clone(),
                    crate::lease::follow::PAGE,
                    false,
                )
                .map_err(|error| error.to_string())?;
            let full = page.len() == crate::lease::follow::PAGE;
            let Some((last, _, _)) = page.last() else {
                break;
            };
            let last = tables::LEASES.key(last);
            for ((vrf, addr), lease, _) in page {
                let key = (vrf, IpAddr::V4(addr));
                let memo = self.memory.entry(key).or_insert_with(|| Memo {
                    client: lease.client.clone(),
                    written: written_of(&lease.ddns),
                    handled: None,
                });
                memo.handled = None;
                self.mark(key);
            }
            if !full {
                break;
            }
            range = KeyRange::all().after(last);
        }
        // WP9.1: the DHCPv6 rows.
        let mut range = KeyRange::all();
        loop {
            let page = view
                .scan_typed(
                    &tables::LEASES6,
                    range.clone(),
                    crate::lease::follow::PAGE,
                    false,
                )
                .map_err(|error| error.to_string())?;
            let full = page.len() == crate::lease::follow::PAGE;
            let Some((last, _, _)) = page.last() else {
                break;
            };
            let last = tables::LEASES6.key(last);
            for ((vrf, addr), lease, _) in page {
                if lease.kind == Lease6Kind::Pd {
                    continue;
                }
                let key = (vrf, IpAddr::V6(addr));
                let memo = self.memory.entry(key).or_insert_with(|| Memo {
                    client: lease.client_key(),
                    written: written_of(&lease.ddns),
                    handled: None,
                });
                memo.handled = None;
                self.mark(key);
            }
            if !full {
                break;
            }
            range = KeyRange::all().after(last);
        }
        let known: Vec<Key> = self.memory.keys().copied().collect();
        for key in known {
            self.mark(key);
        }
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
            for (key, _) in &due {
                if let Some(memo) = self.memory.get_mut(key) {
                    memo.handled = None;
                }
            }
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
        let mut requests = Vec::new();
        for (key, marked) in &keys {
            // WP9.1: the row of the key's family.
            let row = match key.1 {
                IpAddr::V4(addr) => view
                    .get_typed(&tables::LEASES, &(key.0, addr))
                    .map(|row| row.map(|(lease, _)| request_of(&lease, image, now, trusted))),
                IpAddr::V6(addr) => view
                    .get_typed(&tables::LEASES6, &(key.0, addr))
                    // WP9.2: a delegated prefix has no name.
                    .map(|row| {
                        row.filter(|(lease, _)| lease.kind == Lease6Kind::Na)
                            .map(|(lease, _)| request_of6(&lease, image, now, trusted))
                    }),
            };
            let request = match row {
                Ok(Some(request)) => request,
                Ok(None) => {
                    let Some(memo) = self.memory.get(key) else {
                        continue;
                    };
                    // A deleted row whose names are gone leaves nothing to remember.
                    if is_empty(&memo.written) {
                        self.memory.remove(key);
                        continue;
                    }
                    DdnsRequest {
                        action: DdnsAction::Remove,
                        vrf: key.0,
                        scope: tenko_core::PrefixId::from_uuid(uuid::Uuid::nil()),
                        addr: key.1,
                        client: memo.client.clone(),
                        fqdn: None,
                        hostname: None,
                        fqdn_flags: None,
                        policy: DdnsPolicy::default(),
                        lease_secs: 0,
                        ends: now,
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker cannot read a lease");
                    self.retry.push((
                        Instant::now() + self.service.settings.retry_after,
                        *key,
                        *marked,
                    ));
                    continue;
                }
            };
            // The worker's own outcome on the row, or a change DDNS does not read.
            if self.memory.get(key).and_then(|memo| memo.handled.as_ref()) == Some(&request) {
                continue;
            }
            requests.push((request, *marked));
        }
        self.gauge();
        if requests.is_empty() {
            return;
        }
        self.apply(view.as_ref(), requests, now).await;
        self.gauge();
    }

    /// Plans and writes one batch of requests, then records the outcomes.
    #[allow(
        clippy::too_many_lines,
        reason = "one pass over the batch: plan, write per zone, record"
    )]
    async fn apply(
        &mut self,
        view: &dyn ReadView,
        mut requests: Vec<(DdnsRequest, Instant)>,
        now: Timestamp,
    ) {
        let zones = match Zones::read(view) {
            Ok(zones) => zones,
            Err(error) => {
                tracing::warn!(%error, "the DDNS worker cannot read the zones");
                for (request, marked) in &requests {
                    self.retry.push((
                        Instant::now() + self.service.settings.retry_after,
                        (request.vrf, request.addr),
                        *marked,
                    ));
                }
                return;
            }
        };
        let profile = (self.service.profile)(view);
        let max_changes = self.service.zones.config().max_changes;
        let mut planner = Planner::new();
        let mut results: Vec<Result1> = Vec::with_capacity(requests.len());
        // The changes of the batch in order, each with its lease and part.
        let mut writes: Vec<(usize, Part, ZoneChanges)> = Vec::new();
        let mut changes_per_zone: HashMap<tenko_core::dns::ZoneId, usize> = HashMap::new();
        let mut taken = requests.len();
        for (index, (request, _)) in requests.iter().enumerate() {
            // The lease's own writes, which join the batch's only when every set still fits.
            let mut lease: Vec<(usize, Part, ZoneChanges)> = Vec::new();
            let mut result = Result1::default();
            let memo = self.memory.get(&(request.vrf, request.addr));
            let same_client = memo.is_some_and(|memo| memo.client == request.client);
            let recorded = memo.map(|memo| memo.written.clone()).unwrap_or_default();
            let desired = if request.action == DdnsAction::Add {
                let named = match ipam_named(view, request.vrf, request.addr) {
                    Ok(named) => named,
                    Err(error) => {
                        result.failure = Some(error.to_string());
                        results.push(result);
                        continue;
                    }
                };
                let domain = self
                    .image
                    .as_ref()
                    .and_then(|image| domain_of(image, request));
                let lease = LeaseNames {
                    addr: request.addr,
                    client: &request.client,
                    fqdn: request.fqdn.as_deref(),
                    hostname: request.hostname.as_deref(),
                    fqdn_flags: request.fqdn_flags,
                    policy: &request.policy,
                    domain,
                    lease_secs: request.lease_secs,
                };
                plan::desired(view, &lease, &zones, profile, named)
            } else {
                Err(Skip::Quiet(None))
            };
            // The store could not be read: nothing is removed, and the lease is tried
            // again.
            if let Err(Skip::Failed(error)) = &desired {
                result.failure = Some(error.clone());
                results.push(result);
                continue;
            }
            // Already in place: nothing to write.
            if let Ok(want) = &desired
                && same_client
                && recorded.dhcid.as_deref() == want.write_a.then_some(want.dhcid.as_slice())
                && recorded.forward.as_ref() == want.write_a.then_some(&want.name)
                && recorded.reverse.as_ref() == want.reverse.as_ref().map(|(_, name)| name)
            {
                result.holds = recorded;
                results.push(result);
                continue;
            }
            let keep_forward = desired.as_ref().is_ok_and(|want| {
                same_client
                    && want.write_a
                    && recorded.forward.as_ref() == Some(&want.name)
                    && recorded.dhcid.as_deref() == Some(want.dhcid.as_slice())
            });
            let old = Written {
                forward: if keep_forward {
                    None
                } else {
                    recorded.forward.clone()
                },
                reverse: recorded.reverse.clone().filter(|ptr| {
                    !(same_client
                        && desired.as_ref().is_ok_and(|want| {
                            want.reverse.as_ref().map(|(_, name)| name) == Some(ptr)
                        }))
                }),
                dhcid: recorded.dhcid.clone(),
            };
            if !is_empty(&old) {
                match planner.remove(view, &zones, request.addr, &old) {
                    Ok(changes) => {
                        result.removed = !changes.is_empty();
                        for zc in changes {
                            lease.push((index, Part::Remove, zc));
                        }
                    }
                    Err(error) => result.failure = Some(error.to_string()),
                }
            }
            match desired {
                Ok(want) => {
                    let conflict = if profile.always_protect {
                        DdnsConflict::Protect
                    } else {
                        request.policy.conflict
                    };
                    match planner.add(view, &zones, request.addr, &want, conflict) {
                        Ok(lease_plan) => {
                            result.holds = lease_plan.holds;
                            result.refusal = lease_plan.refusal;
                            if let Some(zc) = lease_plan.forward {
                                lease.push((index, Part::Forward, zc));
                            }
                            if let Some(zc) = lease_plan.reverse {
                                lease.push((index, Part::Reverse, zc));
                            }
                        }
                        Err(error) => result.failure = Some(error.to_string()),
                    }
                }
                Err(Skip::Quiet(note)) => result.note = note,
                Err(Skip::Refused(reason)) => result.refusal = Some(reason),
                Err(Skip::Failed(error)) => result.failure = Some(error),
            }
            let mut adds: HashMap<tenko_core::dns::ZoneId, usize> = HashMap::new();
            for (_, _, zc) in &lease {
                *adds.entry(zc.zone).or_default() += zc.changes.len();
            }
            let over = adds.iter().any(|(zone, count)| {
                changes_per_zone.get(zone).copied().unwrap_or(0) + count > max_changes
            });
            // The first lease always goes, so that a batch never stalls on one.
            if over && !results.is_empty() {
                taken = index;
                break;
            }
            for (zone, count) in adds {
                *changes_per_zone.entry(zone).or_default() += count;
            }
            writes.extend(lease);
            results.push(result);
        }
        let waiting = requests.split_off(taken);
        let wrote = self.write(&writes, profile.allows_by_default).await;
        if wrote.proposed {
            self.quiet = Some(Instant::now() + self.service.settings.spacing);
        }
        for (index, part, _) in &writes {
            let result = &mut results[*index];
            let refusal = wrote.refused.get(&(*index, *part));
            match refusal.or_else(|| wrote.failed.get(&(*index, *part))) {
                None => {
                    if *part != Part::Remove {
                        result.wrote = true;
                    }
                }
                Some(error) => {
                    match part {
                        Part::Forward => {
                            result.holds.forward = None;
                            result.holds.dhcid = None;
                            result.holds.reverse = None;
                        }
                        Part::Reverse => result.holds.reverse = None,
                        Part::Remove => result.removed = false,
                    }
                    // A refusal waits for the lease's next change; a failure is retried.
                    let slot = if refusal.is_some() {
                        &mut result.refusal
                    } else {
                        &mut result.failure
                    };
                    slot.get_or_insert_with(|| error.clone());
                }
            }
        }
        // A forward write that failed takes its PTR with it only when the PTR was in the
        // same zone write; otherwise the PTR stands and is removed with the lease.
        let mut rows = Vec::new();
        let mut back = Vec::new();
        for (index, ((request, marked), mut result)) in
            requests.into_iter().zip(results).enumerate()
        {
            let key = (request.vrf, request.addr);
            // Put back whole: the set it was in was too large for the store.
            if wrote.deferred.contains(&index) {
                back.push((key, marked));
                continue;
            }
            let failed = result.failure.is_some();
            if failed {
                Outcome::Failed.count();
                // What could not be removed is still there.
                if let Some(memo) = self.memory.get(&key)
                    && !result.removed
                    && result.holds.forward.is_none()
                    && result.holds.reverse.is_none()
                    && memo.client == request.client
                {
                    result.holds = memo.written.clone();
                }
                self.retry.push((
                    Instant::now() + self.service.settings.retry_after,
                    key,
                    marked,
                ));
            } else if result.refusal.is_some() {
                Outcome::Refused.count();
            } else if result.wrote {
                Outcome::Written.count();
            } else if result.note.is_some() && !result.removed {
                Outcome::Skipped.count();
            }
            if result.removed && !failed {
                Outcome::Removed.count();
            }
            let state = DdnsState {
                forward: result.holds.forward.clone(),
                reverse: result.holds.reverse.clone(),
                dhcid: result.holds.dhcid.clone().map(HexBytes),
                last_error: result.failure.or(result.refusal).or(result.note),
                updated: Some(now),
            };
            self.memory.insert(
                key,
                Memo {
                    client: request.client.clone(),
                    written: result.holds,
                    handled: Some(request.clone()),
                },
            );
            rows.push((key, request.client, state));
        }
        back.extend(
            waiting
                .into_iter()
                .map(|(request, marked)| ((request.vrf, request.addr), marked)),
        );
        self.put_back(back.into_iter());
        self.record(rows).await;
    }

    /// Writes the zone changes of a batch, one change set per zone, the forward zones first:
    /// the reverse part of a lease whose forward part the zone refused or put back is left
    /// out with it. A set the store finds too large is halved by its leases until it fits;
    /// the leases cut from it wait, whole. Once the store has been unavailable for one
    /// zone's write after the retries, the later zones of the batch fail with it without a
    /// try, so an outage costs one zone's retries a batch; any other failure (contention,
    /// the disk guard, the batch's data) leaves the others to their own tries
    /// ([`failure_of`]). `allows` is the profile's default of the zones' DHCP switch.
    async fn write(&self, writes: &[(usize, Part, ZoneChanges)], allows: bool) -> Wrote {
        let mut order: Vec<tenko_core::dns::ZoneId> = Vec::new();
        for (_, _, zc) in writes {
            if !order.contains(&zc.zone) {
                order.push(zc.zone);
            }
        }
        // Zones that take PTRs go last, so a forward part refused first takes its PTR along.
        order.sort_by_key(|zone| {
            writes
                .iter()
                .any(|(_, part, zc)| zc.zone == *zone && *part == Part::Reverse)
        });
        let mut wrote = Wrote::default();
        // The store unavailable after the retries: the rest of the batch fails with it at once.
        let mut outage: Option<String> = None;
        for zone in order {
            let parts: Vec<&(usize, Part, ZoneChanges)> = writes
                .iter()
                .filter(|(index, part, zc)| {
                    zc.zone == zone
                        && !wrote.deferred.contains(index)
                        && !(*part == Part::Reverse
                            && wrote.refused.contains_key(&(*index, Part::Forward)))
                })
                .collect();
            if let Some(error) = &outage {
                for (index, part, _) in parts {
                    wrote.failed.insert((*index, *part), error.clone());
                }
                continue;
            }
            // The leases of the set, in order; the set shrinks to the first half of them
            // while the store finds it too large.
            let mut leases: Vec<usize> = parts.iter().map(|(index, _, _)| *index).collect();
            leases.dedup();
            let mut kept = leases.len();
            let outcome = loop {
                let set: Vec<&&(usize, Part, ZoneChanges)> = parts
                    .iter()
                    .filter(|(index, _, _)| leases[..kept].contains(index))
                    .collect();
                let changes: Vec<Vec<_>> =
                    set.iter().map(|(_, _, zc)| zc.changes.clone()).collect();
                wrote.proposed = true;
                match self.write_zone(zone, &changes, allows).await {
                    Err((_, Failure::TooLarge)) if kept > 1 => kept /= 2,
                    outcome => break outcome.map(|refused| (set, refused)),
                }
            };
            wrote.deferred.extend(leases[kept..].iter().copied());
            match outcome {
                Ok((set, refused)) => {
                    for (position, reason) in refused {
                        let (index, part, _) = set[position];
                        wrote.refused.insert((*index, *part), reason);
                    }
                }
                Err((error, failure)) => {
                    for (index, part, _) in parts {
                        wrote.failed.insert((*index, *part), error.clone());
                    }
                    if failure == Failure::Outage {
                        outage = Some(error);
                    }
                }
            }
        }
        // A part left out with its refused forward name is refused with it.
        for (index, part, _) in writes {
            if *part == Part::Reverse
                && let Some(reason) = wrote.refused.get(&(*index, Part::Forward)).cloned()
            {
                wrote
                    .refused
                    .entry((*index, Part::Reverse))
                    .or_insert(reason);
            }
        }
        wrote
    }

    /// One zone write with the retries while the store refuses; the parts the zone refused,
    /// by their position, with the reason.
    async fn write_zone(
        &self,
        zone: tenko_core::dns::ZoneId,
        parts: &[Vec<tenko_dns::zone::records::Change>],
        allows: bool,
    ) -> Result<Vec<(usize, String)>, (String, Failure)> {
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
                .change_dhcp_names(&cx, zone, parts, allows)
                .await
            {
                Ok((_, refused)) => {
                    return Ok(refused
                        .into_iter()
                        .map(|(position, error)| {
                            let coded = error.coded();
                            (position, format!("{}: {}", coded.code, coded.detail))
                        })
                        .collect());
                }
                Err(error) => {
                    let coded = error.coded();
                    let (failure, again) = failure_of(&coded.code, coded.status);
                    if !again || attempt >= settings.retries {
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

    /// Records the outcomes on the lease rows, each with the row's version as
    /// precondition; a row that changed meanwhile is read again, and a row of another
    /// client is left alone (its own request follows).
    async fn record(&mut self, rows: Vec<(Key, ClientKey, DdnsState)>) {
        let mut todo = rows;
        for _ in 0..4 {
            if todo.is_empty() {
                return;
            }
            let view = match self.service.store.read(ReadConsistency::Local).await {
                Ok(view) => view,
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker cannot record its outcomes");
                    return;
                }
            };
            let mut batch =
                WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
            batch.preconditions.push(fence(self.epoch));
            let mut staged = Vec::new();
            for (key, client, state) in &todo {
                // WP9.1: the outcome goes to the row of the key's family.
                let staged_one = match key.1 {
                    IpAddr::V4(addr) => {
                        let row_key = (key.0, addr);
                        let Ok(Some((mut lease, revision))) =
                            view.get_typed(&tables::LEASES, &row_key)
                        else {
                            continue;
                        };
                        if lease.client != *client || same_state(&lease.ddns, state) {
                            continue;
                        }
                        lease.ddns = state.clone();
                        batch.expect_typed(&tables::LEASES, &row_key, Some(revision));
                        batch.put_typed(&tables::LEASES, &row_key, &lease).is_ok()
                    }
                    IpAddr::V6(addr) => {
                        let row_key = (key.0, addr);
                        let Ok(Some((mut lease, revision))) =
                            view.get_typed(&tables::LEASES6, &row_key)
                        else {
                            continue;
                        };
                        if lease.client_key() != *client || same_state(&lease.ddns, state) {
                            continue;
                        }
                        lease.ddns = state.clone();
                        batch.expect_typed(&tables::LEASES6, &row_key, Some(revision));
                        batch.put_typed(&tables::LEASES6, &row_key, &lease).is_ok()
                    }
                };
                if staged_one {
                    staged.push((*key, client.clone(), state.clone()));
                }
            }
            drop(view);
            if staged.is_empty() {
                return;
            }
            match self.service.store.propose(batch).await {
                Ok(_) => return,
                Err(StoreError::PreconditionFailed(failures))
                    if failures
                        .iter()
                        .all(|failure| matches!(failure, FailedPrecondition::Version { .. })) =>
                {
                    // Some row moved on; write the rest one by one next round.
                    if staged.len() == 1 {
                        todo = staged;
                    } else {
                        for one in staged {
                            Box::pin(self.record(vec![one])).await;
                        }
                        return;
                    }
                }
                // A reload's outcomes may pass the store's limit: halve them.
                Err(StoreError::BatchTooLarge { .. }) if staged.len() > 1 => {
                    let second = staged.split_off(staged.len() / 2);
                    Box::pin(self.record(staged)).await;
                    Box::pin(self.record(second)).await;
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "the DDNS worker could not record its outcomes");
                    return;
                }
            }
        }
    }
}

/// Whether the outcome held on a row is `state`, apart from its time.
fn same_state(held: &DdnsState, state: &DdnsState) -> bool {
    let mut held = held.clone();
    held.updated = state.updated;
    held == *state
}

#[async_trait::async_trait]
impl tenko_core::cluster::LeaderService for DdnsService {
    fn name(&self) -> &'static str {
        "dhcp.ddns"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        Worker::new(self, epoch).run(stop).await
    }
}

#[cfg(test)]
mod memo_tests;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tenko_core::{PrefixId, Revision, dhcp::LeaseEventKind};

    use super::*;
    use crate::{image::ImageBuilder, lease::PendingChange};

    /// Every error the store can return to a zone write, as the worker sees it through the
    /// zone service: whether it fails the rest of the batch and whether it is tried again in
    /// the batch. The expectation is a match with no wildcard arm, so a new store error does
    /// not compile here until it has its place.
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
            // (fails the rest of the batch, tried again in the batch)
            let expected = match &error {
                StoreError::NoQuorum
                | StoreError::Timeout
                | StoreError::ShuttingDown
                | StoreError::Stopped
                | StoreError::Storage(_) => (true, true),
                StoreError::PreconditionFailed(_)
                | StoreError::IdempotencyMismatch
                | StoreError::Compacted { .. }
                | StoreError::ReservedTable { .. }
                | StoreError::PlaintextSecret { .. }
                | StoreError::Codec(_) => (false, true),
                StoreError::BatchTooLarge { .. } | StoreError::DiskReserve { .. } => (false, false),
            };
            let zone = tenko_dns::zone::ZoneError::from(error.clone());
            let (failure, again) = failure_of(&zone.coded().code, zone.coded().status);
            assert_eq!((failure == Failure::Outage, again), expected, "{error:?}");
        }
        // The zone's own refusal of the whole set: this zone only, not tried again.
        let refused =
            tenko_dns::zone::ZoneError::zone_not_found(tenko_core::dns::ZoneId::generate());
        let refused = refused.coded();
        assert_eq!(
            failure_of(&refused.code, refused.status),
            (Failure::Refused, false)
        );
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
