//! The history of the dashboard's figures (OPS-20, OPS-21): this controller's own tiers, folded
//! from its samples, and their combination with the tiers of the other controllers.
//!
//! - **Rings.** Every figure has the five tiers of [`MetricsFigure::tiers`], each a ring of
//!   fixed size ([`TierSpec::buckets`]) of [`MetricsBucket`]s, the newest bucket the open one.
//!   This controller allocates the rings of all 25 figures when the sampler starts
//!   ([`History::new`]: [`RING_BYTES`], 219,616 bytes) and never again, so the fold allocates
//!   nothing (M82). A figure is sent once a sample carries its role ([`produced`]); until then
//!   its rings fill with empty buckets.
//! - **The fold.** [`History::fold`] splits a sample's interval `[at − interval_ms, at)` over
//!   the buckets of each tier it overlaps (see [`Reading`]), then moves every tier to the bucket
//!   that holds `at`, closing the buckets it leaves; time without a sample, or a figure without a
//!   reading, leaves empty buckets, a gap and never a zero. Time before the open bucket (a clock
//!   that jumped back) goes into the open bucket, its covered time held at the step.
//! - **The combination.** The serving controller holds the other controllers' tiers as rings of
//!   the same shape ([`Rings::merge`]: their whole history from `Metrics.History`, then their
//!   closed buckets from each answer to `Metrics.Snapshot`) and combines bucket by bucket under
//!   each figure's [`MetricsMerge`] ([`history`], [`closed`]). Their buckets passed
//!   [`ControllerTiers::decode`], so no peer's numbers can overflow or decide a combination, and
//!   no peer's ring is larger than this controller's.

use std::collections::VecDeque;

use tenko_core::{NodeId, Timestamp};

use crate::dto::events::{
    BUCKET_BYTES, ControllerFigure, ControllerTier, ControllerTiers, MetricsBucket, MetricsClosed,
    MetricsFigure, MetricsFigureHistory, MetricsHistory, MetricsHistoryController, MetricsMerge,
    MetricsSample, MetricsTier, Reading, TierSpec,
};

const FIGURES: usize = MetricsFigure::ALL.len();
const TIERS: usize = 5;

/// The bytes of one controller's rings with every figure, the history's memory per controller
/// (dashboard history plan, section 2).
pub const RING_BYTES: usize = {
    let mut buckets = 0;
    let mut figure = 0;
    while figure < FIGURES {
        let tiers = MetricsFigure::ALL[figure].tiers();
        let mut tier = 0;
        while tier < TIERS {
            buckets += tiers[tier].buckets;
            tier += 1;
        }
        figure += 1;
    }
    buckets * BUCKET_BYTES
};

/// Milliseconds since the Unix epoch.
fn millis(time: Timestamp) -> i64 {
    i64::try_from(time.unix_nanos().div_euclid(1_000_000)).unwrap_or(0)
}

/// The time of `millis` since the Unix epoch.
fn time(millis: i64) -> Timestamp {
    Timestamp::from_unix_nanos(i128::from(millis) * 1_000_000).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// `count` buckets as milliseconds of `step`.
fn span(step: i64, count: usize) -> i64 {
    step.saturating_mul(i64::try_from(count).unwrap_or(i64::MAX))
}

/// Consecutive buckets of one tier, oldest first, at most `cap`; the newest starts at `newest`.
/// Its capacity is fixed at `cap`, so it never reallocates once allocated.
#[derive(Debug)]
struct Ring {
    /// The length of a bucket in milliseconds.
    step: i64,
    /// The most buckets kept.
    cap: usize,
    /// The start of the newest bucket in milliseconds since the Unix epoch; meaningless while
    /// there is no bucket.
    newest: i64,
    buckets: VecDeque<MetricsBucket>,
    /// Buckets that closed in the newest fold and in the fold before (this controller's rings).
    closed: [usize; 2],
}

impl Ring {
    fn new(spec: TierSpec, allocate: bool) -> Self {
        Self {
            step: i64::from(spec.step_ms),
            cap: spec.buckets,
            newest: 0,
            buckets: if allocate {
                VecDeque::with_capacity(spec.buckets)
            } else {
                VecDeque::new()
            },
            closed: [0; 2],
        }
    }

    fn floor(&self, millis: i64) -> i64 {
        millis.div_euclid(self.step) * self.step
    }

    fn oldest(&self) -> i64 {
        self.newest - span(self.step, self.buckets.len().saturating_sub(1))
    }

    fn index(&self, start: i64) -> Option<usize> {
        let back = usize::try_from((self.newest - start) / self.step).ok()?;
        self.buckets.len().checked_sub(back.checked_add(1)?)
    }

    fn get(&self, start: i64) -> Option<&MetricsBucket> {
        self.buckets.get(self.index(start)?)
    }

    /// Makes `start` (on the step) the newest bucket, with empty buckets in between, unless
    /// the ring is already there or past it. Returns how many buckets that closed.
    fn advance(&mut self, start: i64) -> usize {
        if self.buckets.is_empty() {
            // A no-op on this controller's rings, allocated at start.
            self.buckets.reserve_exact(self.cap);
            self.newest = start;
            self.buckets.push_back(MetricsBucket::EMPTY);
            return 0;
        }
        if start <= self.newest {
            return 0;
        }
        let moved = usize::try_from((start - self.newest) / self.step).unwrap_or(usize::MAX);
        self.newest = start;
        if moved >= self.cap {
            self.buckets.clear();
            self.buckets.push_back(MetricsBucket::EMPTY);
        } else {
            for _ in 0..moved {
                if self.buckets.len() == self.cap {
                    self.buckets.pop_front();
                }
                self.buckets.push_back(MetricsBucket::EMPTY);
            }
        }
        moved
    }

    /// Puts a peer's bucket at `start`: replaces the one there or follows the newest (with
    /// empty buckets in a hole); a start before the oldest is ignored.
    fn put(&mut self, start: i64, bucket: MetricsBucket) {
        self.advance(start);
        if let Some(slot) = self.index(start).and_then(|i| self.buckets.get_mut(i)) {
            *slot = bucket;
        }
    }

    /// Folds `reading` over `[from, to)` and moves the ring to the bucket that holds `to`.
    fn fold(&mut self, from: i64, to: i64, reading: Option<&Reading>) {
        self.closed = [0, self.closed[0]];
        if let Some(reading) = reading {
            if self.buckets.is_empty() {
                self.advance(self.floor(from));
            }
            let open = self.newest;
            if from < open
                && let Some(bucket) = self.buckets.back_mut()
            {
                add(bucket, reading, to.min(open) - from, self.step);
            }
            // Of a long interval, only the buckets the ring keeps: at most `cap` passes.
            let kept = self.floor(to - 1) - span(self.step, self.cap - 1);
            let mut at = from.max(open).max(kept);
            while at < to {
                let start = self.floor(at);
                self.closed[0] += self.advance(start);
                let end = to.min(start + self.step);
                if let Some(bucket) = self.buckets.back_mut() {
                    add(bucket, reading, end - at, self.step);
                }
                at = end;
            }
        }
        let start = self.floor(to);
        self.closed[0] += self.advance(start);
    }
}

/// Adds `millis` of `reading` to `bucket`, its covered time held at `step`.
fn add(bucket: &mut MetricsBucket, reading: &Reading, millis: i64, step: i64) {
    if millis <= 0 {
        return;
    }
    let room = step - i64::from(bucket.covered_ms);
    let weight = u32::try_from(millis.min(room)).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation, reason = "checked to fit an f32")]
    let value = reading.value as f32;
    bucket.lowest = bucket.lowest.min(value);
    bucket.highest = bucket.highest.max(value);
    bucket.sum += reading.sum * f64::from(weight);
    bucket.second += reading.second * f64::from(weight);
    bucket.covered_ms += weight;
}

/// The reading of `figure` in `sample` if every number of it is finite and the value fits the
/// bucket's `f32`; a figure without one adds nothing.
fn reading_of(figure: MetricsFigure, sample: &MetricsSample) -> Option<Reading> {
    figure.reading(sample).filter(|reading| {
        reading.value.abs() <= f64::from(f32::MAX)
            && reading.sum.is_finite()
            && reading.second.is_finite()
    })
}

/// Whether `sample` carries the role of `figure`, so that its tile exists even while it has no
/// reading (a quantile without traffic, a ratio without a lookup).
fn produced(figure: MetricsFigure, sample: &MetricsSample) -> bool {
    use MetricsFigure as F;
    let dns = sample.dns.as_ref();
    match figure {
        F::HostCpu | F::HostMemory | F::HostDisk => sample.host.is_some(),
        F::DnsSubqueries | F::DnsValidation => dns.is_some_and(|dns| dns.recursion.is_some()),
        F::DnsEncrypted => dns.is_some_and(|dns| dns.connections.is_some()),
        F::DnsQueries | F::DnsCache | F::DnsAnswers | F::DnsBlocked | F::DnsUpstreams => {
            dns.is_some()
        }
        F::DhcpLeases | F::DhcpAck | F::DhcpActive | F::DhcpPools | F::DhcpNaks | F::DhcpDdns => {
            sample.dhcp.is_some()
        }
        F::Requests | F::Commit | F::Store | F::Raft | F::Jobs | F::Ingest | F::Sse | F::Nodes => {
            true
        }
    }
}

/// The rings of every figure of one controller.
#[derive(Debug)]
pub(super) struct Rings {
    tiers: [[Ring; TIERS]; FIGURES],
    /// The figures the controller's roles produce.
    produced: [bool; FIGURES],
}

impl Rings {
    fn new(allocate: bool) -> Self {
        Self {
            tiers: std::array::from_fn(|figure| {
                let specs = MetricsFigure::ALL[figure].tiers();
                std::array::from_fn(|tier| Ring::new(specs[tier], allocate))
            }),
            produced: [false; FIGURES],
        }
    }

    /// The rings of a peer's whole history; only the tiers it has are allocated.
    pub(super) fn of(tiers: &ControllerTiers) -> Self {
        let mut rings = Self::new(false);
        rings.merge(tiers);
        rings
    }

    /// The bytes the buckets hold.
    pub(super) fn bytes(&self) -> usize {
        self.tiers
            .iter()
            .flatten()
            .map(|ring| ring.buckets.capacity() * BUCKET_BYTES)
            .sum()
    }

    /// Puts a peer's checked tiers into the rings: a bucket replaces the one with its start, a
    /// later one follows the newest. Returns whether a tier left a hole after the newest bucket
    /// it had (the peer's closed buckets of some seconds were missed): the caller fetches the
    /// whole history again.
    pub(super) fn merge(&mut self, tiers: &ControllerTiers) -> bool {
        let mut hole = false;
        for figure in &tiers.figures {
            let index = figure.figure.index();
            self.produced[index] = true;
            for tier in &figure.tiers {
                let Some(ring) = self.tiers[index]
                    .iter_mut()
                    .find(|ring| ring.step == i64::from(tier.step_ms))
                else {
                    continue;
                };
                let oldest =
                    millis(tier.start) - span(ring.step, tier.buckets.len().saturating_sub(1));
                hole |= !ring.buckets.is_empty() && oldest > ring.newest + ring.step;
                for (i, bucket) in tier.buckets.iter().enumerate() {
                    ring.put(oldest + span(ring.step, i), *bucket);
                }
            }
        }
        hole
    }
}

/// This controller's own history: its rings, its start and the end of the newest sample folded.
#[derive(Debug)]
pub struct History {
    started: Timestamp,
    at: Option<Timestamp>,
    rings: Rings,
}

impl History {
    /// An empty history of a controller that started at `started`, every ring allocated.
    pub fn new(started: Timestamp) -> Self {
        Self {
            started,
            at: None,
            rings: Rings::new(true),
        }
    }

    /// When the history starts: the controller's start.
    pub fn started(&self) -> Timestamp {
        self.started
    }

    /// The end of the newest sample folded.
    pub fn at(&self) -> Option<Timestamp> {
        self.at
    }

    /// The bytes the rings hold: [`RING_BYTES`].
    pub fn bytes(&self) -> usize {
        self.rings.bytes()
    }

    /// Folds `sample` into every tier of every figure. A sample without an interval (the first,
    /// which only sets the baseline of the rates) adds nothing. Allocates nothing.
    pub fn fold(&mut self, sample: &MetricsSample) {
        if sample.interval_ms == 0 {
            return;
        }
        let to = millis(sample.at);
        let from = to.saturating_sub(i64::try_from(sample.interval_ms).unwrap_or(i64::MAX));
        self.at = Some(sample.at);
        for figure in MetricsFigure::ALL {
            let index = figure.index();
            self.rings.produced[index] |= produced(figure, sample);
            let reading = reading_of(figure, sample);
            for ring in &mut self.rings.tiers[index] {
                ring.fold(from, to, reading.as_ref());
            }
        }
    }

    /// The whole history, for the answer to `Metrics.History`: every tier of every figure the
    /// roles produce, the open bucket last.
    pub fn tiers(&self) -> ControllerTiers {
        self.controller_tiers(true)
    }

    /// The buckets that closed in the newest fold and in the fold before, for the `closed` of
    /// the answer to `Metrics.Snapshot`: no figure when nothing closed, always the start.
    pub fn closed(&self) -> ControllerTiers {
        self.controller_tiers(false)
    }

    fn controller_tiers(&self, whole: bool) -> ControllerTiers {
        let figures = MetricsFigure::ALL
            .into_iter()
            .filter(|figure| self.rings.produced[figure.index()])
            .map(|figure| ControllerFigure {
                figure,
                tiers: self.rings.tiers[figure.index()]
                    .iter()
                    .filter_map(|ring| {
                        let len = ring.buckets.len();
                        let (end, count) = if whole {
                            (len, len)
                        } else {
                            let count =
                                (ring.closed[0] + ring.closed[1]).min(len.saturating_sub(1));
                            (len.saturating_sub(1), count)
                        };
                        (count > 0).then(|| ControllerTier {
                            step_ms: u32::try_from(ring.step).unwrap_or(u32::MAX),
                            start: time(ring.newest - span(ring.step, len - end)),
                            open: whole,
                            buckets: ring.buckets.range(end - count..end).copied().collect(),
                        })
                    })
                    .collect(),
            })
            .filter(|figure: &ControllerFigure| !figure.tiers.is_empty())
            .collect();
        ControllerTiers {
            started: self.started,
            figures,
        }
    }
}

/// Another controller as the serving controller holds it.
#[derive(Debug)]
pub(super) struct Peer {
    pub(super) node: NodeId,
    /// Its tiers, from its history and the closed buckets since.
    pub(super) rings: Option<Box<Rings>>,
    /// Its start, from its history.
    pub(super) started: Option<Timestamp>,
    /// It runs a release without the history.
    pub(super) unsupported: bool,
    /// It missed a call, or its closed buckets left a hole, since its history was fetched.
    pub(super) stale: bool,
    /// No fetch of its history before this moment (after a failed one).
    pub(super) retry: Option<std::time::Instant>,
}

impl Peer {
    pub(super) fn new(node: NodeId) -> Self {
        Self {
            node,
            rings: None,
            started: None,
            unsupported: false,
            stale: false,
            retry: None,
        }
    }

    /// A peer that runs a release without the history: combined as a missing controller.
    pub(super) fn without_history(node: NodeId) -> Self {
        Self {
            unsupported: true,
            ..Self::new(node)
        }
    }
}

/// A combined bucket.
#[derive(Debug, Default)]
struct Combined {
    lowest: Option<f64>,
    highest: Option<f64>,
    mean: Option<f64>,
    covered: u32,
    controllers: u16,
}

/// Combines the controllers' buckets of one start under `merge` (dashboard history plan,
/// section 4). The combination works in `f64`.
fn combine<'a>(merge: MetricsMerge, buckets: impl Iterator<Item = &'a MetricsBucket>) -> Combined {
    let mut combined = Combined::default();
    let (mut part, mut whole, mut least) = (0.0, 0.0, f64::INFINITY);
    let fold = |held: Option<f64>, value: f64, pick: fn(f64, f64) -> f64| {
        Some(held.map_or(value, |held| pick(held, value)))
    };
    for bucket in buckets {
        let Some(mean) = bucket.mean(merge) else {
            continue;
        };
        let (low, high) = (f64::from(bucket.lowest), f64::from(bucket.highest));
        combined.controllers = combined.controllers.saturating_add(1);
        combined.covered = combined.covered.max(bucket.covered_ms);
        match merge {
            MetricsMerge::Sum => {
                let add = |a: f64, b: f64| a + b;
                combined.lowest = fold(combined.lowest, low, add);
                combined.highest = fold(combined.highest, high, add);
                combined.mean = fold(combined.mean, mean, add);
            }
            MetricsMerge::Highest => {
                combined.lowest = fold(combined.lowest, low, f64::max);
                combined.highest = fold(combined.highest, high, f64::max);
                combined.mean = fold(combined.mean, mean, f64::max);
            }
            MetricsMerge::Ratio => {
                combined.lowest = fold(combined.lowest, low, f64::min);
                combined.highest = fold(combined.highest, high, f64::max);
                part += bucket.sum;
                whole += bucket.second;
            }
            MetricsMerge::LeastAvailable => {
                let share = bucket.second / f64::from(bucket.covered_ms);
                if share < least {
                    least = share;
                    (combined.lowest, combined.highest, combined.mean) =
                        (Some(low), Some(high), Some(mean));
                }
            }
        }
    }
    if merge == MetricsMerge::Ratio && whole > 0.0 {
        combined.mean = Some(part * 100.0 / whole);
    }
    combined
}

/// The combined buckets from `oldest` to `newest` of the same tier of every controller.
fn tier(merge: MetricsMerge, rings: &[&Ring], oldest: i64, newest: i64, open: bool) -> MetricsTier {
    let step = rings[0].step;
    let count = usize::try_from((newest - oldest) / step + 1).unwrap_or(0);
    let mut tier = MetricsTier {
        step_ms: u32::try_from(step).unwrap_or(u32::MAX),
        start: time(newest),
        open,
        ring: open.then(|| u16::try_from(rings[0].cap).unwrap_or(u16::MAX)),
        lowest: Vec::with_capacity(count),
        highest: Vec::with_capacity(count),
        mean: Vec::with_capacity(count),
        covered_ms: Vec::with_capacity(count),
        controllers: Vec::with_capacity(count),
    };
    for i in 0..count {
        let start = oldest + span(step, i);
        let bucket = combine(merge, rings.iter().filter_map(|ring| ring.get(start)));
        tier.lowest.push(bucket.lowest);
        tier.highest.push(bucket.highest);
        tier.mean.push(bucket.mean);
        tier.covered_ms.push(bucket.covered);
        tier.controllers.push(bucket.controllers);
    }
    tier
}

/// The figures with a tile: those a controller's roles produce.
fn figures<'a>(
    own: &'a History,
    peers: &'a [Peer],
) -> impl Iterator<Item = (MetricsFigure, Vec<[&'a Ring; TIERS]>)> + 'a {
    MetricsFigure::ALL.into_iter().filter_map(move |figure| {
        let index = figure.index();
        let rings: Vec<&Rings> = std::iter::once(&own.rings)
            .chain(peers.iter().filter_map(|peer| peer.rings.as_deref()))
            .collect();
        rings.iter().any(|rings| rings.produced[index]).then(|| {
            let tiers = rings
                .iter()
                .map(|rings| std::array::from_fn(|t| &rings.tiers[index][t]))
                .collect();
            (figure, tiers)
        })
    })
}

/// The rings of tier `t` of every controller that has a bucket in it, this controller first;
/// `None` while this controller has none.
fn tier_rings<'a>(controllers: &[[&'a Ring; TIERS]], t: usize) -> Option<Vec<&'a Ring>> {
    let own = controllers.first()?[t];
    (!own.buckets.is_empty()).then(|| {
        controllers
            .iter()
            .map(|tiers| tiers[t])
            .filter(|ring| !ring.buckets.is_empty())
            .collect()
    })
}

/// The cluster's history (the `metrics.history` event): this controller and `peers` combined,
/// each tier from the oldest bucket any controller holds, at most a ring, to this controller's
/// open bucket.
pub(super) fn history(own: &History, node: Option<NodeId>, peers: &[Peer]) -> MetricsHistory {
    let mut controllers = vec![MetricsHistoryController {
        node,
        started: Some(own.started),
        unsupported: false,
    }];
    controllers.extend(peers.iter().map(|peer| MetricsHistoryController {
        node: Some(peer.node),
        started: peer.rings.as_ref().and(peer.started),
        unsupported: peer.unsupported,
    }));
    let figures = figures(own, peers)
        .map(|(figure, controllers)| MetricsFigureHistory {
            figure,
            merge: figure.merge(),
            tiers: (0..TIERS)
                .filter_map(|t| {
                    let rings = tier_rings(&controllers, t)?;
                    let own = rings[0];
                    let floor = own.newest - span(own.step, own.cap - 1);
                    let oldest = rings.iter().map(|ring| ring.oldest()).min()?.max(floor);
                    Some(tier(figure.merge(), &rings, oldest, own.newest, true))
                })
                .collect(),
        })
        .collect();
    MetricsHistory {
        at: own.at.unwrap_or(own.started),
        controllers,
        figures,
    }
}

/// The combined buckets that closed (a snapshot's `closed`): per tier, from the oldest bucket
/// that closed here in the newest two folds or that a peer `delivered` in this tick, to the
/// newest bucket that closed here. A peer's bucket after that waits until it closes here too.
pub(super) fn closed(
    own: &History,
    peers: &[Peer],
    delivered: &[ControllerTiers],
) -> Vec<MetricsClosed> {
    figures(own, peers)
        .filter_map(|(figure, controllers)| {
            let tiers: Vec<MetricsTier> = (0..TIERS)
                .filter_map(|t| {
                    let rings = tier_rings(&controllers, t)?;
                    let own = rings[0];
                    let newest = own.newest - own.step;
                    let floor = own.newest - span(own.step, own.cap - 1);
                    let mine = (own.closed[0] + own.closed[1]).min(own.buckets.len() - 1);
                    let theirs = delivered
                        .iter()
                        .flat_map(|tiers| &tiers.figures)
                        .filter(|delivered| delivered.figure == figure)
                        .flat_map(|delivered| &delivered.tiers)
                        .filter(|tier| i64::from(tier.step_ms) == own.step)
                        .map(|tier| millis(tier.start) - span(own.step, tier.buckets.len() - 1));
                    let oldest = (mine > 0)
                        .then(|| own.newest - span(own.step, mine))
                        .into_iter()
                        .chain(theirs)
                        .min()?
                        .max(floor);
                    (oldest <= newest).then(|| tier(figure.merge(), &rings, oldest, newest, false))
                })
                .collect();
            (!tiers.is_empty()).then_some(MetricsClosed { figure, tiers })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::dto::events::{
        CONTROLLER_TIERS_ENCODING, MetricsDhcp, MetricsDns, MetricsDnsConnections,
        MetricsDnsRecursion, MetricsHost,
    };

    /// A whole hour since the Unix epoch.
    const T0: i64 = 1_792_998_000_000;

    /// A small deterministic generator (xorshift64).
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    fn ms(n: u64) -> i64 {
        i64::try_from(n).expect("small")
    }

    /// A sample of a controller without roles, `requests` its value of the summed figure.
    fn sample(at: i64, interval_ms: u64, requests: f64) -> MetricsSample {
        let mut sample = MetricsSample::empty(None, time(at));
        sample.interval_ms = interval_ms;
        sample.api.requests_per_second = requests;
        sample
    }

    /// A sample with every role: a figure of each merge rule moves with `value` (0 to 1).
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "made-up figures"
    )]
    fn full(at: i64, interval_ms: u64, value: f64) -> MetricsSample {
        let mut sample = sample(at, interval_ms, value * 900.0);
        sample.jobs.running = (value * 10.0) as u64;
        sample.store.commit_p99_ms = (value > 0.3).then_some(value * 40.0);
        let mut dns = MetricsDns {
            queries_per_second: value * 5_000.0,
            ..MetricsDns::default()
        };
        dns.cache.hits_per_second = value * 300.0;
        dns.cache.misses_per_second = 50.0;
        dns.recursion = Some(MetricsDnsRecursion::default());
        dns.connections = Some(MetricsDnsConnections::default());
        sample.dns = Some(dns);
        sample.dhcp = Some(MetricsDhcp::default());
        let (memory, disk): (u64, u64) = (1 << 33, 1 << 40);
        sample.host = Some(MetricsHost {
            cpu_percent: Some(value * 100.0),
            memory_total: Some(memory),
            memory_available: Some((memory as f64 * (1.0 - value * 0.9)) as u64),
            disk_total: Some(disk),
            disk_available: Some((disk as f64 * (0.5 + value * 0.4)) as u64),
        });
        sample
    }

    fn figure(tiers: &ControllerTiers, figure: MetricsFigure) -> &ControllerFigure {
        tiers
            .figures
            .iter()
            .find(|held| held.figure == figure)
            .expect("the figure")
    }

    fn wire_tier(history: &MetricsHistory, figure: MetricsFigure, step: u32) -> &MetricsTier {
        history
            .figures
            .iter()
            .find(|held| held.figure == figure)
            .and_then(|held| held.tiers.iter().find(|tier| tier.step_ms == step))
            .expect("the tier")
    }

    /// The memory of the history (OPS-21): every ring allocated at start, 219,616 bytes with
    /// all 25 figures, and not one byte more after three days of samples with every role,
    /// gaps, a clock that jumps back and one that jumps a day ahead.
    #[test]
    fn the_rings_are_allocated_once_and_never_grow() {
        assert_eq!(RING_BYTES, 219_616, "the plan's 214 KiB a controller");
        let mut history = History::new(time(T0));
        assert_eq!(history.bytes(), RING_BYTES);
        let mut rng = Rng(7);
        let mut at = T0;
        for i in 0..30_000u32 {
            let interval = 5_000 + rng.below(10_000);
            at += ms(interval);
            match i {
                10_000 => at -= 600_000,
                20_000 => at += 86_400_000,
                _ => {}
            }
            history.fold(&full(at, interval, f64::from(i % 100) / 100.0));
        }
        assert_eq!(history.bytes(), RING_BYTES);
        for ring in history.rings.tiers.iter().flatten() {
            assert_eq!(ring.buckets.len(), ring.cap, "every ring full");
            assert_eq!(ring.buckets.capacity(), ring.cap);
        }
        let encoded = tenko_core::codec::to_cbor(&history.tiers()).expect("cbor");
        assert!(encoded.len() < 300_000, "{} bytes", encoded.len());
    }

    /// E115: random series with gaps and uneven intervals through the tiers, every bucket
    /// compared with a direct computation from the samples: the covered time is the part of
    /// the intervals that falls into the bucket, the lowest and highest those of the samples
    /// that overlap it, the sum their values weighted by the overlap; a bucket no interval
    /// overlaps is exactly empty.
    #[test]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "made-up figures"
    )]
    fn every_bucket_is_what_a_direct_computation_gives() {
        for seed in 1..=24u64 {
            let mut rng = Rng(seed * 0x9E37_79B9);
            let mut history = History::new(time(T0));
            let mut at = T0 + ms(rng.below(1_000));
            history.fold(&sample(at, 0, 0.0));
            let mut intervals = Vec::new();
            for _ in 0..500 {
                let interval = 300 + rng.below(2_400);
                let gap = if rng.below(12) == 0 {
                    rng.below(40_000)
                } else {
                    0
                };
                at += ms(gap + interval);
                let value = rng.below(100_000) as f64 / 7.0;
                intervals.push((at - ms(interval), at, value));
                history.fold(&sample(at, interval, value));
            }
            let tiers = history.tiers();
            let requests = figure(&tiers, MetricsFigure::Requests);
            assert_eq!(requests.tiers.len(), 5);
            let mut empty = 0;
            for tier in &requests.tiers {
                let step = i64::from(tier.step_ms);
                let newest = millis(tier.start);
                assert_eq!(
                    newest,
                    at.div_euclid(step) * step,
                    "the open bucket holds `at`"
                );
                let n = tier.buckets.len();
                for (i, bucket) in tier.buckets.iter().enumerate() {
                    let start = newest - span(step, n - 1 - i);
                    let mut expected = MetricsBucket::EMPTY;
                    for &(from, to, value) in &intervals {
                        let overlap = to.min(start + step) - from.max(start);
                        if overlap > 0 {
                            expected.lowest = expected.lowest.min(value as f32);
                            expected.highest = expected.highest.max(value as f32);
                            expected.sum += value * overlap as f64;
                            expected.covered_ms += u32::try_from(overlap).expect("small");
                        }
                    }
                    if expected.covered_ms == 0 {
                        assert_eq!(*bucket, MetricsBucket::EMPTY, "seed {seed}, {step} ms");
                        empty += 1;
                        continue;
                    }
                    assert_eq!(
                        (bucket.lowest, bucket.highest, bucket.covered_ms),
                        (expected.lowest, expected.highest, expected.covered_ms),
                        "seed {seed}, {step} ms, bucket {i}"
                    );
                    assert!((bucket.sum - expected.sum).abs() <= 1e-9 * expected.sum.abs());
                    assert!(bucket.is_sound(MetricsMerge::Sum));
                }
            }
            assert!(empty > 0, "seed {seed}: the gaps are empty buckets");
        }
    }

    /// A gap is a gap: time without a sample (the controller did not run, a sample was late
    /// beyond its interval) and a figure without a reading (a quantile without traffic) are
    /// buckets without data, null on the wire with no covered time, never a zero.
    #[test]
    fn a_gap_is_null_on_the_wire_and_never_zero() {
        let mut history = History::new(time(T0));
        history.fold(&sample(T0 + 1_000, 1_000, 0.0));
        history.fold(&sample(T0 + 2_000, 1_000, 0.0));
        // Ten seconds without a sample, then one that covers only its own second.
        history.fold(&sample(T0 + 13_000, 1_000, 0.0));
        let wire = super::history(&history, None, &[]);
        let seconds = wire_tier(&wire, MetricsFigure::Requests, 1_000);
        assert_eq!(seconds.covered_ms[..3], [1_000, 1_000, 0]);
        assert_eq!(seconds.mean[..3], [Some(0.0), Some(0.0), None]);
        assert_eq!(seconds.lowest[2], None);
        assert_eq!(seconds.controllers[..3], [1, 1, 0]);
        assert!(seconds.is_consistent());
        let json = serde_json::to_value(seconds).expect("json");
        assert_eq!(json["mean"][2], serde_json::Value::Null);
        assert_eq!(json["mean"][1], 0);
        // Commit has no reading without writes: its tile exists, its buckets are empty.
        let commit = wire_tier(&wire, MetricsFigure::Commit, 1_000);
        assert!(commit.covered_ms.iter().all(|covered| *covered == 0));
        assert!(commit.mean.iter().all(Option::is_none));
        // A role that no sample carried has no tile.
        assert!(
            !wire
                .figures
                .iter()
                .any(|figure| figure.figure == MetricsFigure::DnsQueries)
        );
    }

    /// A clock that jumps back never rewrites a closed bucket: the time goes into the open
    /// bucket, its covered time held at its step; one that jumps forward leaves empty buckets.
    #[test]
    fn a_clock_jump_keeps_the_closed_buckets() {
        let mut history = History::new(time(T0));
        for second in 1..=120 {
            history.fold(&sample(T0 + second * 1_000, 1_000, 10.0));
        }
        let before = history.tiers();
        history.fold(&sample(T0 + 60_000, 1_000, 1_000.0));
        history.fold(&sample(T0 + 61_000, 1_000, 1_000.0));
        let after = history.tiers();
        let old = figure(&before, MetricsFigure::Requests);
        let new = figure(&after, MetricsFigure::Requests);
        for (old, new) in old.tiers.iter().zip(&new.tiers) {
            assert_eq!(old.start, new.start, "no bucket opened");
            let closed = old.buckets.len() - 1;
            assert_eq!(old.buckets[..closed], new.buckets[..closed]);
            let open = new.buckets[closed];
            assert!(
                (open.highest - 1_000.0).abs() < f32::EPSILON,
                "into the open one"
            );
            assert!(open.covered_ms <= old.step_ms);
            assert!(open.is_sound(MetricsMerge::Sum));
        }
        // Two hours ahead: the one-second ring holds empty buckets before the sample's second.
        history.fold(&sample(T0 + 7_320_000, 1_000, 10.0));
        let ahead = history.tiers();
        let seconds = &figure(&ahead, MetricsFigure::Requests).tiers[0];
        let empty = seconds.buckets.len() - 2;
        assert!(
            seconds.buckets[..empty]
                .iter()
                .all(|bucket| *bucket == MetricsBucket::EMPTY)
        );
        let encoded = tenko_core::codec::to_cbor(&ahead).expect("cbor");
        ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &encoded).expect("still sound");
    }

    /// What a controller hands its peers (the whole history and each tick's closed buckets)
    /// passes the strict check of the receiving side, for every merge rule, through uneven
    /// intervals, gaps and clock jumps.
    #[test]
    #[allow(clippy::cast_precision_loss, reason = "made-up figures")]
    fn the_tiers_a_peer_receives_pass_its_strict_check() {
        let check = |tiers: &ControllerTiers| {
            let encoded = tenko_core::codec::to_cbor(tiers).expect("cbor");
            let decoded = ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &encoded)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(&decoded, tiers);
        };
        let mut rng = Rng(42);
        let mut history = History::new(time(T0));
        let mut at = T0 + 345;
        for i in 0..3_000u32 {
            let interval = 200 + rng.below(3_000);
            at += ms(interval) + if i % 97 == 0 { 50_000 } else { 0 };
            if i % 499 == 0 {
                at -= 30_000;
            }
            history.fold(&full(at, interval, rng.below(1_000) as f64 / 1_000.0));
            check(&history.closed());
        }
        let whole = history.tiers();
        assert_eq!(whole.figures.len(), 25, "every role");
        check(&whole);
    }

    /// The client's rule: one bucket per figure, tier and start; a later copy replaces it.
    type Held = BTreeMap<(MetricsFigure, u32, i64), (Option<f64>, Option<f64>, u32, u16)>;

    fn keep(held: &mut Held, figure: MetricsFigure, tier: &MetricsTier) -> Vec<i64> {
        let step = i64::from(tier.step_ms);
        let newest = millis(tier.start);
        (0..tier.len())
            .map(|i| {
                let start = newest - span(step, tier.len() - 1 - i);
                let bucket = (
                    tier.mean[i],
                    tier.highest[i],
                    tier.covered_ms[i],
                    tier.controllers[i],
                );
                held.insert((figure, tier.step_ms, start), bucket);
                start
            })
            .collect()
    }

    /// A bucket that closes is in the `closed` of two consecutive ticks and of no other, the
    /// client keeps it once, and what the client holds after a minute of `closed` is what a
    /// new history says.
    #[test]
    fn a_closed_bucket_comes_twice_and_is_kept_once() {
        let mut history = History::new(time(T0));
        let mut held = Held::new();
        let mut seen: BTreeMap<(u32, i64), Vec<u32>> = BTreeMap::new();
        for tick in 0..=70u32 {
            let at = T0 + 500 + i64::from(tick) * 1_000;
            history.fold(&sample(at, 1_000, f64::from(tick)));
            for closed in super::closed(&history, &[], &[]) {
                for tier in &closed.tiers {
                    assert!(!tier.open && tier.ring.is_none());
                    for start in keep(&mut held, closed.figure, tier) {
                        if closed.figure == MetricsFigure::Requests {
                            seen.entry((tier.step_ms, start)).or_default().push(tick);
                        }
                    }
                }
            }
        }
        for ((step, start), ticks) in &seen {
            if *ticks.last().expect("one") < 70 {
                assert_eq!(ticks.len(), 2, "{step} ms bucket at {start}: {ticks:?}");
                assert_eq!(ticks[1], ticks[0] + 1);
            }
        }
        assert!(
            seen.keys().any(|(step, _)| *step == 10_000),
            "a ten-second bucket"
        );
        let wire = super::history(&history, None, &[]);
        for figure in &wire.figures {
            for tier in &figure.tiers {
                let mut fresh = Held::new();
                let starts = keep(&mut fresh, figure.figure, tier);
                for start in &starts[..starts.len() - 1] {
                    let key = (figure.figure, tier.step_ms, *start);
                    if let Some(kept) = held.get(&key) {
                        assert_eq!(Some(kept), fresh.get(&key), "{key:?}");
                    }
                }
            }
        }
    }

    fn peer(node: u64, history: &History) -> Peer {
        Peer {
            rings: Some(Box::new(Rings::of(&history.tiers()))),
            started: Some(history.started()),
            ..Peer::new(NodeId(node))
        }
    }

    /// E115 (the combination of section 4): three controllers, each with its own series. A
    /// summed figure's band contains the true range of the summed series and its mean is the
    /// sum of the means; a highest figure's highest is exact; a ratio's mean is recomputed
    /// from the counts; the least available follows the controller with the smallest share.
    #[test]
    #[allow(clippy::cast_precision_loss, reason = "made-up figures")]
    fn three_controllers_combine_by_the_merge_rules() {
        let series = |c: i64, second: i64| ((second * 7 + c * 13) % 17) as f64 / 17.0;
        let mut controllers: Vec<History> = (0..3).map(|_| History::new(time(T0))).collect();
        for second in 1..=20 {
            for (c, history) in (0i64..).zip(controllers.iter_mut()) {
                history.fold(&full(T0 + second * 1_000, 1_000, series(c, second)));
            }
        }
        let (own, others) = controllers.split_first().expect("three");
        let peers = [peer(2, &others[0]), peer(3, &others[1])];
        let wire = super::history(own, Some(NodeId(1)), &peers);
        assert_eq!(wire.controllers.len(), 3);
        // The ten seconds from T0 + 10 s: second 11 to 20 of each series, closed.
        let tens = wire_tier(&wire, MetricsFigure::Requests, 10_000);
        let i = tens.len() - 2;
        let summed: Vec<f64> = (11..=20)
            .map(|s| (0..3).map(|c| series(c, s) * 900.0).sum())
            .collect();
        let low = summed.iter().copied().fold(f64::INFINITY, f64::min);
        let high = summed.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mean = summed.iter().sum::<f64>() / 10.0;
        assert!(tens.lowest[i].expect("data") <= low + 1e-3);
        assert!(tens.highest[i].expect("data") >= high - 1e-3);
        assert!((tens.mean[i].expect("data") - mean).abs() < 1e-6);
        assert_eq!(tens.controllers[i], 3);
        // Highest: the CPU's highest is the highest of any controller.
        let cpu = wire_tier(&wire, MetricsFigure::HostCpu, 10_000);
        let top = (0..3)
            .flat_map(|c| (11..=20).map(move |s| series(c, s) * 100.0))
            .fold(f64::NEG_INFINITY, f64::max);
        assert!((cpu.highest[i].expect("data") - top).abs() < 1e-4);
        // Ratio: hits over hits and misses of all three, from the counts.
        let cache = wire_tier(&wire, MetricsFigure::DnsCache, 10_000);
        let hits: f64 = (0..3)
            .flat_map(|c| (11..=20).map(move |s| series(c, s) * 300.0))
            .sum();
        let share = hits * 100.0 / (hits + 50.0 * 30.0);
        assert!((cache.mean[i].expect("data") - share).abs() < 1e-6);
        // Least available: the disk of the controller with the smallest mean share available.
        let disk = wire_tier(&wire, MetricsFigure::HostDisk, 10_000);
        let least = (0..3)
            .min_by(|a, b| {
                let total = |c: i64| (11..=20).map(|s| series(c, s)).sum::<f64>();
                total(*a).total_cmp(&total(*b))
            })
            .and_then(|c| usize::try_from(c).ok())
            .expect("one");
        let alone = super::history(&controllers[least], None, &[]);
        let expected = wire_tier(&alone, MetricsFigure::HostDisk, 10_000);
        assert_eq!(disk.mean[i], expected.mean[expected.len() - 2]);
        // A controller without the history is listed and counted in no bucket.
        let lone = super::history(own, Some(NodeId(1)), &[Peer::without_history(NodeId(4))]);
        assert!(lone.controllers[1].unsupported);
        assert!(lone.figures[0].tiers[0].controllers.iter().all(|n| *n <= 1));
    }

    /// The serving controller sends a combined bucket again when a late controller's part
    /// arrives, and the client's copy is replaced: the past heals.
    #[test]
    fn a_late_peer_part_replaces_the_combined_bucket() {
        let mut own = History::new(time(T0));
        let mut other = History::new(time(T0));
        for second in 1..=3 {
            own.fold(&sample(T0 + second * 1_000, 1_000, 5.0));
            other.fold(&sample(T0 + second * 1_000, 1_000, 7.0));
        }
        let mut peers = [peer(2, &other)];
        own.fold(&sample(T0 + 4_000, 1_000, 5.0));
        let mut held = Held::new();
        for closed in super::closed(&own, &peers, &[]) {
            for tier in &closed.tiers {
                keep(&mut held, closed.figure, tier);
            }
        }
        let key = (MetricsFigure::Requests, 1_000, T0 + 3_000);
        assert_eq!(
            held[&key],
            (Some(5.0), Some(5.0), 1_000, 1),
            "the peer is late"
        );
        // The peer's closed bucket of that second arrives one tick later.
        other.fold(&sample(T0 + 4_000, 1_000, 7.0));
        let delivered = other.closed();
        let rings = peers[0].rings.as_mut().expect("rings");
        assert!(!rings.merge(&delivered), "no hole");
        own.fold(&sample(T0 + 5_000, 1_000, 5.0));
        for closed in super::closed(&own, &peers, &[delivered]) {
            for tier in &closed.tiers {
                keep(&mut held, closed.figure, tier);
            }
        }
        assert_eq!(held[&key], (Some(12.0), Some(12.0), 1_000, 2), "replaced");
    }

    /// A peer's rings never hold more than this controller's, whatever starts it sends.
    #[test]
    fn a_peers_rings_are_bounded() {
        let mut history = History::new(time(T0));
        for step in 1..=4_000 {
            history.fold(&full(T0 + step * 10_000, 10_000, 0.5));
        }
        let mut rings = Rings::of(&history.tiers());
        assert!(rings.bytes() <= RING_BYTES);
        let mut far = history.tiers();
        for figure in &mut far.figures {
            for tier in &mut figure.tiers {
                tier.start = time(millis(tier.start) + 3_600_000 * 1_000);
            }
        }
        assert!(rings.merge(&far), "a hole");
        assert!(rings.bytes() <= RING_BYTES);
        assert!(
            rings
                .tiers
                .iter()
                .flatten()
                .all(|ring| ring.buckets.len() <= ring.cap)
        );
    }
}
