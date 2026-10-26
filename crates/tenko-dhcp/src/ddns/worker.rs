//! The DDNS worker (plan section 2.9, ADR 0020 point 5): a leader service that follows the
//! lease rows and writes the names after the commit, never inside it.
//!
//! The worker watches `dhcp.leases` in the store, so every committed change reaches it:
//! a grant or a renewal from the committer, a release, an expiry from `dhcp.expiry`, an
//! operator's reclaim. Nothing runs on the DORA path. For each changed row it builds a
//! [`DdnsRequest`] (add for an active binding, remove otherwise) into a [`MemDdnsQueue`]
//! bounded at start (its room grows as it fills, E32), and takes the queue in batches:
//!
//! 1. the names each lease should hold ([`plan::desired`]): the scope's DDNS settings, the
//!    zone's DHCP switch with the profile's default, the name rules, IPAM's names;
//! 2. the changes, by the RFC 4703 rules ([`plan::Planner`]), against one view of the
//!    store: what the lease wrote before goes first (another name, another client at the
//!    address, a release or expiry), then the A and DHCID set at the forward name and the
//!    PTR in the reverse zone;
//! 3. one change set per zone through the zone service with the origin `dhcp` and the
//!    principal `system:dhcp` (audited by the zone service, journalled, so IXFR carries
//!    it); a zone write the store refuses is retried with a doubling backoff
//!    (`[dhcp.ddns] retries`, `backoff_ms`); a change set refused as a whole is applied
//!    lease by lease so one bad lease does not hold up the others;
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
    RequestCtx, SystemComponent, Timestamp, VrfId,
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
    DdnsAction, DdnsQueue as _, DdnsRequest, MemDdnsQueue,
    metrics::{Outcome, QUEUE},
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
    /// Requests the queue holds.
    pub queue: usize,
    /// Leases taken per batch.
    pub batch: usize,
    /// The pause before a failed lease is tried again.
    pub retry_after: Duration,
    /// How long the first changed lease waits for others to join its batch, so that a
    /// burst of commits becomes one change set per zone (ADR 0020 point 5).
    pub window: Duration,
}

impl Default for DdnsSettings {
    fn default() -> Self {
        Self {
            retries: 5,
            backoff: Duration::from_secs(1),
            queue: 65_536,
            batch: 512,
            retry_after: Duration::from_secs(30),
            window: Duration::from_millis(100),
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
/// remove otherwise. The DDNS settings are those the class and policy matcher decided at
/// the commit (the row's `ddns_policy`, the settings the reply's option 81 used), else the
/// scope's.
pub fn request_of(lease: &Lease, image: &ConfigImage, now: Timestamp) -> DdnsRequest {
    let active = lease.state == BindingState::Active && lease.ends > now;
    // Slice 8 follow-ups: the policy's settings first.
    let policy = lease
        .ddns_policy
        .clone()
        .or_else(|| image.scope(lease.scope).map(|scope| scope.ddns.clone()))
        .unwrap_or_default();
    let lease_secs =
        u32::try_from(lease.ends.saturating_since(lease.cltt).as_secs()).unwrap_or(u32::MAX);
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
pub fn request_of6(lease: &Lease6, image: &ConfigImage, now: Timestamp) -> DdnsRequest {
    let active = lease.state == BindingState::Active && lease.ends > now;
    let policy = image
        .v6()
        .scope(lease.scope)
        .map(|scope| scope.ddns.clone())
        .unwrap_or_default();
    let lease_secs =
        u32::try_from(lease.ends.saturating_since(lease.cltt).as_secs()).unwrap_or(u32::MAX);
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

/// Whether IPAM names the address (an address object with a DNS name).
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

/// The worker's state while it runs.
struct Worker<'a> {
    service: &'a DdnsService,
    epoch: u64,
    cx: RequestCtx,
    memory: HashMap<Key, Memo>,
    image: Option<ConfigImage>,
    queue: MemDdnsQueue,
    dirty: VecDeque<Key>,
    pending: HashSet<Key>,
    retry: Vec<(Instant, Key)>,
    resync: bool,
    /// When the oldest waiting address was marked.
    since: Option<Instant>,
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
            cx: RequestCtx::system(SystemComponent::Dhcp),
            memory: HashMap::new(),
            image: None,
            queue: MemDdnsQueue::new(service.settings.queue.max(1)),
            dirty: VecDeque::new(),
            pending: HashSet::new(),
            retry: Vec::new(),
            resync: true,
            since: None,
        }
    }

    fn mark(&mut self, key: Key) {
        if self.pending.insert(key) {
            if self.dirty.is_empty() {
                self.since = Some(Instant::now());
            }
            self.dirty.push_back(key);
        }
    }

    fn gauge(&self) {
        let waiting = self.dirty.len() + self.queue.len();
        QUEUE.set_total(u64::try_from(waiting).unwrap_or(u64::MAX));
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
            let due: Vec<Key> = {
                let (due, later): (Vec<_>, Vec<_>) =
                    self.retry.drain(..).partition(|(at, _)| *at <= now);
                self.retry = later;
                due.into_iter().map(|(_, key)| key).collect()
            };
            for key in due {
                if let Some(memo) = self.memory.get_mut(&key) {
                    memo.handled = None;
                }
                self.mark(key);
            }
            self.gauge();
            if !self.dirty.is_empty() {
                // The first changed lease waits a moment for others to join its batch.
                let window = self.service.settings.window;
                let waited = self.since.map_or(window, |at| at.elapsed());
                if waited < window && self.dirty.len() < self.service.settings.batch {
                    let remaining = window.saturating_sub(waited);
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
            let next_retry = self.retry.iter().map(|(at, _)| *at).min();
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
        let take = self.service.settings.batch.max(1);
        let mut keys = Vec::with_capacity(take);
        while keys.len() < take {
            let Some(key) = self.dirty.pop_front() else {
                break;
            };
            self.pending.remove(&key);
            keys.push(key);
        }
        if self.dirty.is_empty() {
            self.since = None;
        }
        let Some(image) = self.image.as_ref() else {
            return;
        };
        for key in &keys {
            // WP9.1: the row of the key's family.
            let row = match key.1 {
                IpAddr::V4(addr) => view
                    .get_typed(&tables::LEASES, &(key.0, addr))
                    .map(|row| row.map(|(lease, _)| request_of(&lease, image, now))),
                IpAddr::V6(addr) => view
                    .get_typed(&tables::LEASES6, &(key.0, addr))
                    // WP9.2: a delegated prefix has no name.
                    .map(|row| {
                        row.filter(|(lease, _)| lease.kind == Lease6Kind::Na)
                            .map(|(lease, _)| request_of6(&lease, image, now))
                    }),
            };
            let request = match row {
                Ok(Some(request)) => request,
                Ok(None) => {
                    let Some(memo) = self.memory.get(key) else {
                        continue;
                    };
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
                    self.retry
                        .push((Instant::now() + self.service.settings.retry_after, *key));
                    continue;
                }
            };
            if self.memory.get(key).and_then(|memo| memo.handled.as_ref()) == Some(&request) {
                continue;
            }
            if self.queue.enqueue(request).is_err() {
                Outcome::Dropped.count();
                if self.pending.insert(*key) {
                    self.dirty.push_back(*key);
                }
            }
        }
        self.gauge();
        let requests = self.queue.drain();
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
    async fn apply(&mut self, view: &dyn ReadView, requests: Vec<DdnsRequest>, now: Timestamp) {
        let zones = match Zones::read(view) {
            Ok(zones) => zones,
            Err(error) => {
                tracing::warn!(%error, "the DDNS worker cannot read the zones");
                for request in &requests {
                    self.retry.push((
                        Instant::now() + self.service.settings.retry_after,
                        (request.vrf, request.addr),
                    ));
                }
                return;
            }
        };
        let profile = (self.service.profile)(view);
        let mut planner = Planner::new();
        let mut results: Vec<Result1> = Vec::with_capacity(requests.len());
        // The changes of the batch in order, each with its lease and part.
        let mut writes: Vec<(usize, Part, ZoneChanges)> = Vec::new();
        for (index, request) in requests.iter().enumerate() {
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
                plan::desired(&lease, &zones, profile, named)
            } else {
                Err(Skip::Quiet(None))
            };
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
                            writes.push((index, Part::Remove, zc));
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
                                writes.push((index, Part::Forward, zc));
                            }
                            if let Some(zc) = lease_plan.reverse {
                                writes.push((index, Part::Reverse, zc));
                            }
                        }
                        Err(error) => result.failure = Some(error.to_string()),
                    }
                }
                Err(Skip::Quiet(note)) => result.note = note,
                Err(Skip::Refused(reason)) => result.refusal = Some(reason),
            }
            results.push(result);
        }
        let failed = self.write(&writes).await;
        for (index, part, _) in &writes {
            let result = &mut results[*index];
            match failed.get(&(*index, *part)) {
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
                    result.failure.get_or_insert_with(|| error.clone());
                }
            }
        }
        // A forward write that failed takes its PTR with it only when the PTR was in the
        // same zone write; otherwise the PTR stands and is removed with the lease.
        let mut rows = Vec::new();
        for (request, mut result) in requests.into_iter().zip(results) {
            let key = (request.vrf, request.addr);
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
                self.retry
                    .push((Instant::now() + self.service.settings.retry_after, key));
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
        self.record(rows).await;
    }

    /// Writes the zone changes of a batch, one change set per zone; returns the parts that
    /// failed with the reason.
    async fn write(&self, writes: &[(usize, Part, ZoneChanges)]) -> HashMap<(usize, Part), String> {
        let mut zones: Vec<tenko_core::dns::ZoneId> = Vec::new();
        for (_, _, zc) in writes {
            if !zones.contains(&zc.zone) {
                zones.push(zc.zone);
            }
        }
        // The zones are written at the same time: the forward and the reverse zone are
        // separate change sets with their own serials.
        let per_zone = zones.into_iter().map(|zone| async move {
            let parts: Vec<&(usize, Part, ZoneChanges)> =
                writes.iter().filter(|(_, _, zc)| zc.zone == zone).collect();
            let changes: Vec<_> = parts
                .iter()
                .flat_map(|(_, _, zc)| zc.changes.iter().cloned())
                .collect();
            let mut failed = Vec::new();
            match self.write_zone(zone, &changes).await {
                Ok(()) => {}
                Err((_, false)) if parts.len() > 1 => {
                    // One lease's change spoiled the set: apply them one by one.
                    for (index, part, zc) in &parts {
                        if let Err((error, _)) = self.write_zone(zone, &zc.changes).await {
                            failed.push(((*index, *part), error));
                        }
                    }
                }
                Err((error, _)) => {
                    for (index, part, _) in &parts {
                        failed.push(((*index, *part), error.clone()));
                    }
                }
            }
            failed
        });
        futures::future::join_all(per_zone)
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// One zone write with the retries while the store refuses; the error says whether the
    /// store refused (true) or the change set was refused (false).
    async fn write_zone(
        &self,
        zone: tenko_core::dns::ZoneId,
        changes: &[tenko_dns::zone::records::Change],
    ) -> Result<(), (String, bool)> {
        let settings = self.service.settings;
        let mut pause = settings.backoff;
        let mut attempt = 0;
        loop {
            match self
                .service
                .zones
                .change_records(&self.cx, zone, changes, false)
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let coded = error.coded();
                    let again = retryable(coded.status, &coded.code);
                    if !again || attempt >= settings.retries {
                        tracing::info!(code = %coded.code, detail = %coded.detail, "a DDNS change set was not written");
                        return Err((format!("{}: {}", coded.code, coded.detail), again));
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
            let mut batch = WriteBatch::new(self.cx.principal.clone(), Timestamp::now());
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
