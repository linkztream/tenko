//! Conflict detection before an offer and the DECLINE rules (plan section 2.7, P3-Q7,
//! DHCP-06, TGL-16, WP8.5).
//!
//! # The probe before the offer
//!
//! A worker that built an OFFER asks [`rules::candidate`] whether its address needs a probe:
//! only an address with no lease history for this client, which no probe found clean within
//! the probe cache's time (`[dhcp.probe] cache_secs`, 10 minutes). A renewal is a REQUEST
//! and never reaches this point; the client's own lease, its previous address and a
//! reservation it already holds are never probed. When a probe is due the worker parks the
//! request and the OFFER it built in the [`pending`] table and goes on with the next
//! datagram: the DISCOVER waits there, not in a worker. The table is fixed at start
//! (`[dhcp.probe] pending` slots, 1,024) and parking copies into a free slot without
//! allocating; a full table, or a request too long for a slot, offers without a probe.
//!
//! The dispatcher ([`dispatch`]), one thread of the server with its own single-threaded
//! runtime, takes the parked requests and asks the [`ConflictProbe`] of the process. The
//! OFFER goes out when the probe answers [`ProbeOutcome::Clear`] (and the address enters
//! the cache), when it answers [`ProbeOutcome::Unavailable`], or at the cap
//! (`[dhcp.probe] timeout_ms`, 300 ms after the DISCOVER arrived), whichever comes first.
//! An answer from the client's own MAC address is no conflict. Any other answer marks the
//! address: the offer table holds it away from every client at once, an abandoned lease row
//! of kind `conflict` ends after the decline hold time (`[dhcp.decline] hold_secs`, 24
//! hours) and carries the answering MAC address when ARP gave one (the IPAM-23 fact of
//! [`observation`]), and the engine runs again on the same request, which offers the next
//! free address, probed in turn with the time left. A reservation that answers is counted
//! and offered all the same: no other address is the client's, and IPAM-23 reports the
//! squatter.
//!
//! The production probe is [`scan::ScanProbe`]: ARP through `tenko-scan`'s raw link where
//! the node sits on the address's link (Linux with `CAP_NET_RAW`), ICMP echo through
//! `tenko-scan`'s pinger otherwise (unprivileged datagram sockets on Linux, `ping.exe` on
//! Windows).
//!
//! # DECLINE
//!
//! The engine abandons a declined address for the hold time (WP7.3); [`Conflicts::decline`]
//! adds the per-client rate limit ([`limit`]: `[dhcp.decline] limit` DECLINEs per
//! `window_secs`, 3 per hour, so a broken client cannot drain a pool; one beyond is dropped
//! as `rate_limited` and the client keeps its lease), forgets the address in the probe
//! cache and queues the audit record `dhcp.decline` for the role's [`report`]er. The
//! abandoned row is the conflict observation, as for a probe's conflict.
//!
//! # When it runs (TGL-16)
//!
//! Conflict detection runs when a probe runs in the process ([`Conflicts::available`]) and
//! the effective setting says so: `dhcp.settings.conflict_detection` when set, else the
//! profile's default (on under Home, Standard and Hardened, off under Lab). Without a probe
//! the role offers without probing, logs it once per start and, under Hardened, raises the
//! health finding `dhcp.probe.missing`.

pub mod cache;
pub mod dispatch;
pub mod limit;
pub(crate) mod metrics;
pub mod observation;
pub mod pending;
pub mod report;
pub mod rules;
pub mod scan;

use std::{
    fmt,
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::Timestamp;

pub use self::{
    cache::ProbeCache,
    limit::DeclineLimit,
    pending::{Parked, PendingTable},
    report::{Report, ReportKind, ReportQueue},
    rules::Candidate,
};
use crate::probe::{ConflictProbe, ProbeOutcome};

/// What the dispatcher takes off the cap so that a timer that fires late by one tick of the
/// platform, and the send after it, still put the OFFER out within the cap: 16 ms on Windows
/// (the system timer ticks at 15.6 ms), 5 ms elsewhere (a millisecond timer rounded up).
pub const TIMER_TICK: Duration = if cfg!(windows) {
    Duration::from_millis(16)
} else {
    Duration::from_millis(5)
};

/// A probe behind a pointer, so that the server holds any [`ConflictProbe`].
pub trait DynProbe: Send + Sync {
    /// [`ConflictProbe::available`].
    fn available(&self) -> bool;

    /// [`ConflictProbe::probe`], boxed.
    fn probe_boxed(
        &self,
        addr: Ipv4Addr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + '_>>;
}

impl<P: ConflictProbe> DynProbe for P {
    fn available(&self) -> bool {
        ConflictProbe::available(self)
    }

    fn probe_boxed(
        &self,
        addr: Ipv4Addr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + '_>> {
        Box::pin(self.probe(addr, timeout))
    }
}

/// The probe of the process, shared by the server's dispatcher.
#[derive(Clone)]
pub struct ProbeHandle(Arc<dyn DynProbe>);

impl ProbeHandle {
    /// Wraps `probe`.
    pub fn new(probe: impl ConflictProbe + 'static) -> Self {
        Self(Arc::new(probe))
    }

    /// Wraps a probe that is shared already.
    pub fn shared(probe: Arc<dyn DynProbe>) -> Self {
        Self(probe)
    }

    /// Whether the probe runs.
    pub fn available(&self) -> bool {
        self.0.available()
    }

    /// Probes `addr` within `timeout`.
    pub async fn probe(&self, addr: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
        self.0.probe_boxed(addr, timeout).await
    }
}

impl fmt::Debug for ProbeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeHandle")
            .field("available", &self.available())
            .finish()
    }
}

/// The settings of conflict detection (`[dhcp.probe]` and `[dhcp.decline]` of `tenko.toml`
/// and the profile's default of TGL-16).
#[derive(Debug, Clone)]
pub struct ConflictSettings {
    /// The probe of the process; `None` without a `probe` role.
    pub probe: Option<ProbeHandle>,
    /// The profile's default when `dhcp.settings.conflict_detection` is unset (TGL-16: on,
    /// off under Lab).
    pub profile_default: bool,
    /// The cap from the DISCOVER to the OFFER (`timeout_ms`, 300 ms).
    pub cap: Duration,
    /// How long a clean probe result is kept (`cache_secs`, 600 s; zero keeps none).
    pub cache: Duration,
    /// Requests that may wait for a probe at once (`pending`, 1,024).
    pub pending: usize,
    /// Addresses the probe cache holds about (65,536).
    pub cache_entries: usize,
    /// DECLINEs one client may send per window before more are dropped (`limit`, 3).
    pub decline_limit: u32,
    /// The window of the DECLINE limit (`window_secs`, 3,600 s).
    pub decline_window: Duration,
    /// Clients the DECLINE limit tracks at once (4,096).
    pub decline_clients: usize,
    /// How many probes of further addresses one DISCOVER may cause after answers (3).
    pub max_attempts: u8,
}

impl Default for ConflictSettings {
    fn default() -> Self {
        Self {
            probe: None,
            profile_default: true,
            cap: Duration::from_millis(300),
            cache: Duration::from_secs(600),
            pending: 1_024,
            cache_entries: 65_536,
            decline_limit: 3,
            decline_window: Duration::from_secs(3_600),
            decline_clients: 4_096,
            max_attempts: 3,
        }
    }
}

/// What conflict detection counted since the start (`dhcp.stats` and the tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConflictStats {
    /// Offers parked for a probe.
    pub parked: u64,
    /// Offers sent without a probe because the pending table was full or the request too
    /// long for a slot.
    pub unparked: u64,
    /// Probes started.
    pub probes: u64,
    /// Probes that found nobody.
    pub clear: u64,
    /// Probes cut at the cap.
    pub capped: u64,
    /// Probes the probe could not run.
    pub unavailable: u64,
    /// Answers from the client's own MAC address.
    pub own: u64,
    /// Answers from another host: conflicts.
    pub conflicts: u64,
    /// Conflicts on a reservation of the client, offered all the same.
    pub reserved: u64,
    /// Offers skipped by the probe cache.
    pub cached: u64,
    /// DECLINEs accepted.
    pub declines: u64,
    /// DECLINEs dropped by the per-client limit.
    pub limited: u64,
}

#[derive(Debug, Default)]
struct Counters {
    parked: AtomicU64,
    unparked: AtomicU64,
    probes: AtomicU64,
    clear: AtomicU64,
    capped: AtomicU64,
    unavailable: AtomicU64,
    own: AtomicU64,
    conflicts: AtomicU64,
    reserved: AtomicU64,
    cached: AtomicU64,
    declines: AtomicU64,
    limited: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The setting of `dhcp.settings.conflict_detection`: unset, off, on.
const UNSET: u8 = 0;
const OFF: u8 = 1;
const ON: u8 = 2;

/// Conflict detection of one server: the switches, the pending table, the probe cache, the
/// DECLINE limit, the report queue and the counters. Made once at start; nothing the
/// workers call allocates.
pub struct Conflicts {
    probe: Option<ProbeHandle>,
    profile_default: AtomicBool,
    setting: AtomicU8,
    cap: Duration,
    cache_time: Duration,
    max_attempts: u8,
    pending: PendingTable,
    cache: ProbeCache,
    declines: DeclineLimit,
    reports: ReportQueue,
    wake: tokio::sync::Notify,
    counters: Counters,
}

impl fmt::Debug for Conflicts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conflicts")
            .field("available", &self.available())
            .field("enabled", &self.enabled())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl Conflicts {
    /// Conflict detection with `settings`.
    pub fn new(settings: &ConflictSettings) -> Self {
        Self {
            probe: settings.probe.clone(),
            profile_default: AtomicBool::new(settings.profile_default),
            setting: AtomicU8::new(UNSET),
            cap: settings.cap,
            cache_time: settings.cache,
            max_attempts: settings.max_attempts,
            pending: PendingTable::new(settings.pending),
            cache: ProbeCache::with_capacity(settings.cache_entries),
            declines: DeclineLimit::new(
                settings.decline_clients,
                settings.decline_limit,
                settings.decline_window,
            ),
            reports: ReportQueue::with_capacity(1_024),
            wake: tokio::sync::Notify::new(),
            counters: Counters::default(),
        }
    }

    /// Whether a probe runs in the process.
    pub fn available(&self) -> bool {
        self.probe.as_ref().is_some_and(ProbeHandle::available)
    }

    /// The probe, when one runs.
    pub fn probe(&self) -> Option<&ProbeHandle> {
        self.probe.as_ref().filter(|probe| probe.available())
    }

    /// Whether offers are probed now: a probe runs and the effective setting is on.
    pub fn enabled(&self) -> bool {
        self.available() && self.effective()
    }

    /// The effective setting of TGL-16: the stored one, else the profile's default.
    pub fn effective(&self) -> bool {
        match self.setting.load(Ordering::Relaxed) {
            ON => true,
            OFF => false,
            _ => self.profile_default.load(Ordering::Relaxed),
        }
    }

    /// Follows the profile's default (TGL-16: off under Lab).
    pub fn set_profile_default(&self, on: bool) {
        self.profile_default.store(on, Ordering::Relaxed);
    }

    /// Follows `dhcp.settings.conflict_detection`.
    pub fn set_setting(&self, setting: Option<bool>) {
        let value = match setting {
            None => UNSET,
            Some(false) => OFF,
            Some(true) => ON,
        };
        self.setting.store(value, Ordering::Relaxed);
    }

    /// The cap from the DISCOVER to the OFFER.
    pub fn cap(&self) -> Duration {
        self.cap
    }

    /// How many further addresses one DISCOVER may probe after answers.
    pub fn max_attempts(&self) -> u8 {
        self.max_attempts
    }

    /// The pending table.
    pub fn pending(&self) -> &PendingTable {
        &self.pending
    }

    /// The probe cache.
    pub fn cache(&self) -> &ProbeCache {
        &self.cache
    }

    // E32: the pending table and the cache grow with the image.
    /// Grows the pending table to `pending` slots and the cache to about `cache`
    /// addresses; smaller values change nothing. Allocates: never on the DORA path.
    pub fn grow(&self, pending: usize, cache: usize) {
        self.pending.grow(pending);
        self.cache.grow(cache);
    }

    /// The slots of the pending table and the addresses the cache holds about.
    pub fn room(&self) -> (usize, usize) {
        (self.pending.capacity(), self.cache.capacity())
    }

    /// The reports for the role.
    pub fn reports(&self) -> &ReportQueue {
        &self.reports
    }

    /// Wakes the dispatcher.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Waits until a worker parks a request or [`Conflicts::wake`] is called.
    pub async fn woken(&self) {
        self.wake.notified().await;
    }

    /// Parks an offer for its probe: the request, the reply, where it goes and the
    /// candidate address. False when no slot is free (the worker then sends the offer at
    /// once). Never allocates.
    pub fn park(&self, parking: &pending::Parking<'_>) -> bool {
        let deadline = parking.received + self.cap.saturating_sub(TIMER_TICK);
        if self.pending.park(parking, deadline, 0) {
            bump(&self.counters.parked);
            self.wake();
            true
        } else {
            bump(&self.counters.unparked);
            false
        }
    }

    /// Whether the client of the DECLINE in `request` may decline now (the per-client
    /// limit); counts it either way.
    pub fn decline_allowed(&self, identity: &[u8], now: Instant) -> bool {
        if self.declines.allow(identity, now) {
            bump(&self.counters.declines);
            true
        } else {
            bump(&self.counters.limited);
            false
        }
    }

    /// A DECLINE was accepted for `addr`: the probe cache forgets it and the audit record
    /// is queued.
    pub fn declined(&self, report: &Report) {
        self.cache.forget(report.vrf, report.addr);
        self.reports.push(report);
    }

    /// Records the outcome of one probe.
    pub(crate) fn count(&self, outcome: Option<ProbeOutcome>, own: bool) {
        bump(&self.counters.probes);
        match outcome {
            None => bump(&self.counters.capped),
            Some(ProbeOutcome::Clear) => bump(&self.counters.clear),
            Some(ProbeOutcome::Unavailable) => bump(&self.counters.unavailable),
            Some(ProbeOutcome::InUse { .. }) if own => bump(&self.counters.own),
            Some(ProbeOutcome::InUse { .. }) => {
                bump(&self.counters.conflicts);
                metrics::CONFLICTS.inc();
            }
        }
    }

    /// Records a conflict on the client's reservation (offered all the same).
    pub(crate) fn count_reserved(&self) {
        bump(&self.counters.reserved);
    }

    /// Records an offer the probe cache let through without a probe.
    pub fn count_cached(&self) {
        bump(&self.counters.cached);
    }

    /// Remembers `addr` as probed clean until the cache time has passed.
    pub(crate) fn clean(&self, candidate: &Candidate, now: Timestamp) {
        if !self.cache_time.is_zero()
            && let Some(until) = now.checked_add(self.cache_time)
        {
            self.cache.insert(candidate.vrf, candidate.addr, until);
        }
    }

    /// The counters.
    pub fn stats(&self) -> ConflictStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let c = &self.counters;
        ConflictStats {
            parked: load(&c.parked),
            unparked: load(&c.unparked),
            probes: load(&c.probes),
            clear: load(&c.clear),
            capped: load(&c.capped),
            unavailable: load(&c.unavailable),
            own: load(&c.own),
            conflicts: load(&c.conflicts),
            reserved: load(&c.reserved),
            cached: load(&c.cached),
            declines: load(&c.declines),
            limited: load(&c.limited),
        }
    }
}

/// A 64-bit hash of octets (FNV-1a, then a finaliser), for the fixed tables.
pub(crate) fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    mix(hash)
}

/// The finaliser of splitmix64.
pub(crate) fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
