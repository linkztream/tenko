//! Rate limits of a probe (TGL-19, SCAN-06, SCAN-07): probes per second for the whole
//! probe, a minimum spacing between two probes to the same address, and a ceiling on
//! probes in flight. Every method that sends anything takes a [`Permit`] per probe.
//!
//! The pacer works in three stages, in this order:
//!
//! 1. The target address reserves the next free slot of its own timeline and waits for it.
//!    Two probes to one address are therefore at least `per_host_interval` apart, and the
//!    wait holds no other resource.
//! 2. The probe takes one of `concurrency` places in flight.
//! 3. The probe passes a first-come-first-served gate that hands out tokens of the global
//!    bucket (`per_second` tokens a second, bursts of up to 100 ms worth) and, once more,
//!    checks the spacing of its address at the moment the permit is handed out.
//!
//! Dropping the future of [`Pacer::acquire`] at any point gives everything back: the
//! token is taken in the same step that completes the future, and the reserved slot of the
//! address is released when no later probe has reserved behind it (otherwise it costs the
//! address at most one interval).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    time::{Instant, sleep_until},
};

/// The longest spacing the pacer keeps per address; longer values are cut to this.
const MAX_SPACING: Duration = Duration::from_secs(24 * 60 * 60);

/// Acquisitions between two sweeps of the per-address table.
const PRUNE_EVERY: u32 = 4096;

/// Size of the per-address table that triggers a sweep on its own.
const PRUNE_ABOVE: usize = 65_536;

/// The limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaceLimits {
    /// Probes per second for the whole probe; `None` is unlimited (Lab profile).
    pub per_second: Option<u32>,
    /// Minimum time between two probes to the same address.
    pub per_host_interval: Duration,
    /// Most probes in flight at once.
    pub concurrency: usize,
}

impl Default for PaceLimits {
    fn default() -> Self {
        Self {
            per_second: Some(100),
            per_host_interval: Duration::from_millis(100),
            concurrency: 32,
        }
    }
}

/// Hands out permits within the limits; shared by every method of a probe.
#[derive(Debug)]
pub struct Pacer {
    limits: PaceLimits,
    slots: Arc<Semaphore>,
    /// Whether permits pass the gate: a rate limit or an address spacing is in force.
    gated: bool,
    /// The gate; a fair lock, so permits are handed out in the order the callers arrived.
    bucket: AsyncMutex<Bucket>,
    hosts: Mutex<Hosts>,
    spacing: Duration,
    sent: AtomicU64,
}

/// One probe in flight; dropping it frees the slot.
#[derive(Debug)]
pub struct Permit {
    _slot: OwnedSemaphorePermit,
}

impl Pacer {
    /// A pacer with `limits`.
    pub fn new(limits: PaceLimits) -> Self {
        let places = limits.concurrency.clamp(1, Semaphore::MAX_PERMITS);
        let bucket = Bucket::new(limits.per_second);
        let spacing = limits.per_host_interval.min(MAX_SPACING);
        Self {
            limits,
            slots: Arc::new(Semaphore::new(places)),
            gated: bucket.interval.is_some() || !spacing.is_zero(),
            bucket: AsyncMutex::new(bucket),
            hosts: Mutex::new(Hosts::default()),
            spacing,
            sent: AtomicU64::new(0),
        }
    }

    /// The limits.
    pub fn limits(&self) -> PaceLimits {
        self.limits
    }

    /// Waits until a probe to `target` fits the limits.
    ///
    /// Dropping the returned future before it completes gives back everything it holds.
    pub async fn acquire(&self, target: IpAddr) -> Permit {
        let mut reservation = self.reserve(target);
        if let Some(reservation) = &reservation
            && reservation.slot > Instant::now()
        {
            sleep_until(reservation.slot).await;
        }
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .unwrap_or_else(|_| unreachable!("the semaphore is never closed"));
        if self.gated {
            self.pass_gate(target).await;
        }
        if let Some(reservation) = &mut reservation {
            reservation.keep();
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Permit { _slot: slot }
    }

    /// Probes handed out since the pacer was made.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Reserves the next slot of `target`'s timeline; `None` without an address spacing.
    fn reserve(&self, target: IpAddr) -> Option<Reservation<'_>> {
        if self.spacing.is_zero() {
            return None;
        }
        let now = Instant::now();
        let (slot, end, previous) = self.lock_hosts().reserve(target, now, self.spacing);
        Some(Reservation {
            pacer: self,
            target,
            slot,
            end,
            previous,
            armed: true,
        })
    }

    /// Waits at the gate until the global bucket has a token and the address `target` has
    /// waited out its spacing, then takes the token and notes the time for the address.
    /// Everything that changes state happens in the poll that completes the future.
    async fn pass_gate(&self, target: IpAddr) {
        let mut bucket = self.bucket.lock().await;
        loop {
            let now = Instant::now();
            let ready = bucket.ready_at(now).max(self.host_ready_at(target, now));
            if ready <= now {
                bucket.take(now);
                if !self.spacing.is_zero() {
                    self.lock_hosts().stamp(target, now);
                }
                return;
            }
            sleep_until(ready).await;
        }
    }

    /// When `target` has waited out the spacing since its last permit.
    fn host_ready_at(&self, target: IpAddr, now: Instant) -> Instant {
        if self.spacing.is_zero() {
            return now;
        }
        self.lock_hosts().ready_at(target, now, self.spacing)
    }

    fn lock_hosts(&self) -> MutexGuard<'_, Hosts> {
        self.hosts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of addresses the pacer keeps a timeline for.
    #[cfg(test)]
    fn tracked_hosts(&self) -> usize {
        self.lock_hosts().entries.len()
    }
}

/// A reserved slot on the timeline of one address; released again when the acquisition
/// is cancelled and nobody reserved behind it.
struct Reservation<'a> {
    pacer: &'a Pacer,
    target: IpAddr,
    /// When the probe may go.
    slot: Instant,
    /// The first moment after the slot at which the next probe may go.
    end: Instant,
    /// The timeline before this reservation.
    previous: Instant,
    armed: bool,
}

impl Reservation<'_> {
    /// The permit was handed out; the slot stays used.
    fn keep(&mut self) {
        self.armed = false;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut hosts = self.pacer.lock_hosts();
        if let Some(host) = hosts.entries.get_mut(&self.target)
            && host.next_slot == self.end
        {
            host.next_slot = self.previous;
        }
    }
}

/// The global token bucket as a generic cell rate algorithm: one number, the time at which
/// the bucket would be empty again if no further probe came.
#[derive(Debug)]
struct Bucket {
    /// Time between two tokens; `None` is unlimited.
    interval: Option<Duration>,
    /// How far ahead of `empty_at` a token may be taken: the burst of `rate / 10` tokens.
    tolerance: Duration,
    /// `None` is a full bucket.
    empty_at: Option<Instant>,
}

impl Bucket {
    fn new(per_second: Option<u32>) -> Self {
        let Some(rate) = per_second.filter(|rate| *rate > 0) else {
            return Self {
                interval: None,
                tolerance: Duration::ZERO,
                empty_at: None,
            };
        };
        let interval = (Duration::from_secs(1) / rate).max(Duration::from_nanos(1));
        let capacity = (rate / 10).max(1);
        Self {
            interval: Some(interval),
            tolerance: interval * (capacity - 1),
            empty_at: None,
        }
    }

    /// The first moment, not before `now`, at which a token can be taken.
    fn ready_at(&self, now: Instant) -> Instant {
        if self.interval.is_none() {
            return now;
        }
        self.empty_at
            .and_then(|empty_at| empty_at.checked_sub(self.tolerance))
            .map_or(now, |at| at.max(now))
    }

    /// Takes a token at `now`; the caller has checked [`Bucket::ready_at`].
    fn take(&mut self, now: Instant) {
        let Some(interval) = self.interval else {
            return;
        };
        let base = self.empty_at.map_or(now, |empty_at| empty_at.max(now));
        self.empty_at = Some(base.checked_add(interval).unwrap_or(base));
    }
}

/// The timeline of every address a probe was sent to recently.
#[derive(Debug)]
struct Hosts {
    entries: HashMap<IpAddr, Host>,
    since_sweep: u32,
    sweep_above: usize,
}

impl Default for Hosts {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            since_sweep: 0,
            sweep_above: PRUNE_ABOVE,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Host {
    /// The first moment a new reservation may be placed at.
    next_slot: Instant,
    /// When the last permit for the address was handed out.
    last_grant: Option<Instant>,
}

impl Hosts {
    /// Places a reservation for `target` and returns the slot, the end of the reservation
    /// and the timeline before it.
    fn reserve(
        &mut self,
        target: IpAddr,
        now: Instant,
        spacing: Duration,
    ) -> (Instant, Instant, Instant) {
        self.sweep_if_due(now, spacing);
        let host = self.entries.entry(target).or_insert(Host {
            next_slot: now,
            last_grant: None,
        });
        let previous = host.next_slot;
        let slot = previous.max(now);
        let end = slot.checked_add(spacing).unwrap_or(slot);
        host.next_slot = end;
        (slot, end, previous)
    }

    /// When `target` has waited out `spacing` since its last permit.
    fn ready_at(&self, target: IpAddr, now: Instant, spacing: Duration) -> Instant {
        self.entries
            .get(&target)
            .and_then(|host| host.last_grant)
            .and_then(|granted| granted.checked_add(spacing))
            .map_or(now, |at| at.max(now))
    }

    /// Notes that a permit for `target` was handed out at `now`.
    fn stamp(&mut self, target: IpAddr, now: Instant) {
        self.entries
            .entry(target)
            .and_modify(|host| host.last_grant = Some(now))
            .or_insert(Host {
                next_slot: now,
                last_grant: Some(now),
            });
    }

    /// Forgets the addresses whose timeline lies in the past, now and then and when the
    /// table is large. The size that triggers the next sweep follows what stayed.
    fn sweep_if_due(&mut self, now: Instant, spacing: Duration) {
        self.since_sweep = self.since_sweep.saturating_add(1);
        if self.since_sweep < PRUNE_EVERY && self.entries.len() <= self.sweep_above {
            return;
        }
        self.since_sweep = 0;
        self.entries.retain(|_, host| {
            host.next_slot > now
                || host
                    .last_grant
                    .and_then(|granted| granted.checked_add(spacing))
                    .is_some_and(|until| until > now)
        });
        self.sweep_above = PRUNE_ABOVE.max(self.entries.len().saturating_mul(2));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::time::{advance, timeout};

    use super::*;

    const HOST_A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const HOST_B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

    fn limits(per_second: Option<u32>, interval_ms: u64, concurrency: usize) -> PaceLimits {
        PaceLimits {
            per_second,
            per_host_interval: Duration::from_millis(interval_ms),
            concurrency,
        }
    }

    /// A distinct documentation address (RFC 3849) for every `n`.
    fn doc_address(n: u32) -> IpAddr {
        let octets = n.to_be_bytes();
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0x0db8,
            0,
            0,
            0,
            0,
            u16::from_be_bytes([octets[0], octets[1]]),
            u16::from_be_bytes([octets[2], octets[3]]),
        ))
    }

    #[test]
    fn default_limits_are_the_documented_ones() {
        let defaults = PaceLimits::default();
        assert_eq!(defaults.per_second, Some(100));
        assert_eq!(defaults.per_host_interval, Duration::from_millis(100));
        assert_eq!(defaults.concurrency, 32);
        assert_eq!(Pacer::new(defaults).limits(), defaults);
    }

    #[tokio::test(start_paused = true)]
    async fn global_rate_spreads_probes_over_time() {
        let pacer = Pacer::new(limits(Some(50), 0, 8));
        let start = Instant::now();
        for n in 0..100 {
            let _permit = pacer.acquire(doc_address(n)).await;
        }
        let elapsed = start.elapsed();
        // 100 probes at 50 a second take two seconds, less the burst of 5 tokens.
        assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
        assert!(elapsed <= Duration::from_millis(2000), "{elapsed:?}");
        assert_eq!(pacer.sent(), 100);
    }

    #[tokio::test(start_paused = true)]
    async fn burst_is_a_tenth_of_a_second_of_probes() {
        let pacer = Pacer::new(limits(Some(100), 0, 64));
        let start = Instant::now();
        for n in 0..10 {
            let _permit = pacer.acquire(doc_address(n)).await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO, "10 probes fit the burst");
        let _permit = pacer.acquire(doc_address(10)).await;
        assert_eq!(start.elapsed(), Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_refills_the_bucket() {
        let pacer = Pacer::new(limits(Some(10), 0, 8));
        let _first = pacer.acquire(HOST_A).await;
        let second_started = Instant::now();
        let _second = pacer.acquire(HOST_A).await;
        assert_eq!(second_started.elapsed(), Duration::from_millis(100));
        advance(Duration::from_secs(5)).await;
        let idle_end = Instant::now();
        let _third = pacer.acquire(HOST_A).await;
        assert_eq!(idle_end.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn same_address_is_spaced_by_the_interval() {
        let pacer = Pacer::new(limits(None, 100, 8));
        let start = Instant::now();
        let mut times = Vec::new();
        for _ in 0..4 {
            let _permit = pacer.acquire(HOST_A).await;
            times.push(start.elapsed());
        }
        let expected: Vec<Duration> = (0..4).map(|n| Duration::from_millis(100 * n)).collect();
        assert_eq!(times, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn other_addresses_do_not_wait_for_a_busy_one() {
        let pacer = Pacer::new(limits(None, 100, 8));
        let start = Instant::now();
        let _first = pacer.acquire(HOST_A).await;
        let _other = pacer.acquire(HOST_B).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        let _second = pacer.acquire(HOST_A).await;
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_for_one_address_are_spaced() {
        let pacer = Arc::new(Pacer::new(limits(Some(1000), 100, 8)));
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let pacer = Arc::clone(&pacer);
            tasks.push(tokio::spawn(async move {
                let _permit = pacer.acquire(HOST_A).await;
                start.elapsed()
            }));
        }
        let mut times = Vec::new();
        for task in tasks {
            times.push(task.await.expect("the task finishes"));
        }
        times.sort();
        for pair in times.windows(2) {
            assert!(
                pair[1] >= pair[0] + Duration::from_millis(100),
                "permits too close together: {times:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spacing_holds_when_both_probes_wait_behind_the_global_limit() {
        // Both probes wait for a place in flight; when two places free up at the same
        // moment they must still keep the interval.
        let pacer = Arc::new(Pacer::new(limits(None, 100, 2)));
        let first = pacer.acquire(HOST_B).await;
        let second = pacer.acquire(doc_address(1)).await;
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pacer = Arc::clone(&pacer);
            tasks.push(tokio::spawn(async move {
                let permit = pacer.acquire(HOST_A).await;
                let at = start.elapsed();
                drop(permit);
                at
            }));
        }
        advance(Duration::from_millis(500)).await;
        drop(first);
        drop(second);
        let mut times = Vec::new();
        for task in tasks {
            times.push(task.await.expect("the task finishes"));
        }
        times.sort();
        assert!(
            times[1] >= times[0] + Duration::from_millis(100),
            "permits too close together: {times:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrency_limits_permits_alive() {
        let pacer = Pacer::new(limits(None, 0, 2));
        let first = pacer.acquire(HOST_A).await;
        let _second = pacer.acquire(HOST_B).await;
        let third = timeout(Duration::from_secs(1), pacer.acquire(doc_address(1))).await;
        assert!(third.is_err(), "a third permit must wait");
        drop(first);
        let third = timeout(Duration::from_millis(1), pacer.acquire(doc_address(1))).await;
        assert!(third.is_ok(), "a freed place is reused");
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_acquire_wakes_when_a_permit_drops() {
        let pacer = Arc::new(Pacer::new(limits(None, 0, 1)));
        let held = pacer.acquire(HOST_A).await;
        let start = Instant::now();
        let blocked = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move {
                let _permit = pacer.acquire(HOST_B).await;
                start.elapsed()
            })
        };
        advance(Duration::from_millis(250)).await;
        drop(held);
        let blocked_for = blocked.await.expect("the task finishes");
        assert_eq!(blocked_for, Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_concurrency_still_allows_one_probe() {
        let pacer = Pacer::new(limits(None, 0, 0));
        let permit = timeout(Duration::from_millis(1), pacer.acquire(HOST_A)).await;
        assert!(permit.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_never_waits() {
        for per_second in [None, Some(0)] {
            let pacer = Pacer::new(limits(per_second, 0, 4096));
            let start = Instant::now();
            let mut permits = Vec::new();
            for n in 0..2000 {
                permits.push(pacer.acquire(doc_address(n % 7)).await);
            }
            assert_eq!(start.elapsed(), Duration::ZERO);
            assert_eq!(pacer.sent(), 2000);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_pending_acquire_does_not_block_the_next_one() {
        // Address spacing: the cancelled probe gives its reserved slot back.
        let pacer = Pacer::new(limits(None, 100, 8));
        let start = Instant::now();
        let _first = pacer.acquire(HOST_A).await;
        let cancelled = timeout(Duration::from_millis(10), pacer.acquire(HOST_A)).await;
        assert!(cancelled.is_err());
        let _second = pacer.acquire(HOST_A).await;
        assert_eq!(start.elapsed(), Duration::from_millis(100));

        // Global rate: the cancelled probe does not take a token with it.
        let pacer = Pacer::new(limits(Some(10), 0, 8));
        let start = Instant::now();
        let _first = pacer.acquire(HOST_A).await;
        let cancelled = timeout(Duration::from_millis(10), pacer.acquire(HOST_B)).await;
        assert!(cancelled.is_err());
        let _second = pacer.acquire(HOST_B).await;
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_probe_in_the_middle_of_a_queue_costs_at_most_one_interval() {
        let pacer = Arc::new(Pacer::new(limits(None, 100, 8)));
        let start = Instant::now();
        let _first = pacer.acquire(HOST_A).await;
        // Two probes queue behind the first; the first of them is cancelled.
        let doomed = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move {
                let _permit = pacer.acquire(HOST_A).await;
            })
        };
        tokio::task::yield_now().await;
        let survivor = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move {
                let _permit = pacer.acquire(HOST_A).await;
                start.elapsed()
            })
        };
        tokio::task::yield_now().await;
        doomed.abort();
        let survived_at = survivor.await.expect("the task finishes");
        assert_eq!(survived_at, Duration::from_millis(200));
        // The next caller of the address is not held up by the cancelled probe.
        let _next = pacer.acquire(HOST_A).await;
        assert_eq!(start.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn sent_counts_permits_handed_out() {
        let pacer = Pacer::new(limits(Some(1000), 0, 4));
        assert_eq!(pacer.sent(), 0);
        let first = pacer.acquire(HOST_A).await;
        let second = pacer.acquire(HOST_B).await;
        assert_eq!(pacer.sent(), 2);
        drop((first, second));
        let _third = pacer.acquire(HOST_A).await;
        assert_eq!(pacer.sent(), 3);
        // A cancelled acquisition is not counted.
        let busy = Pacer::new(limits(None, 0, 1));
        let _held = busy.acquire(HOST_A).await;
        let cancelled = timeout(Duration::from_millis(5), busy.acquire(HOST_B)).await;
        assert!(cancelled.is_err());
        assert_eq!(busy.sent(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn address_table_stays_bounded() {
        let pacer = Pacer::new(limits(None, 100, 4));
        let mut peak = 0;
        for n in 0..30_000 {
            let _permit = pacer.acquire(doc_address(n)).await;
            if n % 500 == 499 {
                advance(Duration::from_millis(250)).await;
            }
            peak = peak.max(pacer.tracked_hosts());
        }
        let most = 2 * usize::try_from(PRUNE_EVERY).expect("fits");
        assert!(peak <= most, "{peak} addresses kept");
    }

    #[tokio::test(start_paused = true)]
    async fn address_table_sweeps_when_it_grows_large() {
        // Nothing expires while time stands still, so the table may exceed the nominal
        // size; the sweep threshold then follows the live entries instead of sweeping on
        // every call.
        let pacer = Pacer::new(limits(None, 100, 4));
        let fill = u32::try_from(PRUNE_ABOVE).expect("fits") + 100;
        for n in 0..fill {
            let _permit = pacer.acquire(doc_address(n)).await;
        }
        assert_eq!(pacer.tracked_hosts(), PRUNE_ABOVE + 100);
        advance(Duration::from_secs(1)).await;
        for n in 0..PRUNE_EVERY {
            let _permit = pacer.acquire(doc_address(1_000_000 + n)).await;
        }
        let most = 2 * usize::try_from(PRUNE_EVERY).expect("fits");
        assert!(pacer.tracked_hosts() <= most);
    }
}
