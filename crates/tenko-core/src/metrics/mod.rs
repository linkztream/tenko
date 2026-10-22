//! The metrics core (OPS-21): counters, fixed-bucket histograms and gauges whose update is
//! one relaxed atomic add, a registry that aggregates them into a [`Snapshot`], and the
//! `OpenMetrics` text encoder.
//!
//! # Design
//!
//! - **Static descriptors.** Every family is a `static` item built with a `const fn` from a
//!   [`Desc`] (name, help, unit, kind and label names) and registered with a [`Registry`] at
//!   start (`registry.register(&FAMILY)`).
//! - **Sealed series.** A family with labels gets the label values of all its series once,
//!   when it is sealed ([`CounterVec::seal`], [`HistogramVec::seal`], [`GaugeVec::seal`]), or
//!   carries them in its constructor ([`CounterVec::fixed`]). Sealing allocates; nothing
//!   after it does. Series are addressed by a `u16` index in sealing order. Counter and
//!   histogram families never add series at run time. Gauges whose label values are only
//!   known at run time (node ids, instance ids) use a bounded slot table instead
//!   ([`GaugeVec::seal_slots`]); they are written by a timer, never on a hot path.
//! - **Striped storage.** Counters and histograms keep one stripe of cells per shard. The
//!   shard count is a parameter of the seal: [`default_shards`] (the available parallelism
//!   rounded up to a power of two, at most [`MAX_SHARDS`]) unless the family passes fewer
//!   ([`CounterVec::seal_with_shards`]), which a family on a path of bounded throughput with
//!   many series does to keep its memory small. A stripe starts on a 64-byte boundary and spans whole
//!   cache lines, so two shards never share a line; the series of one family lie
//!   contiguously inside a stripe. A worker thread on a hot path pins its shard with
//!   [`pin_worker_shard`] before its first update: workers count up from the first shard, so
//!   two of them never share one while there are no more workers than shards. Every other
//!   thread picks its shard once, at its first update, counting down from the last shard,
//!   and keeps it.
//! - **Checking.** [`check`] is a strict line checker of the text [`encode`] writes, for the
//!   tests of the crates that serve metrics.
//! - **The update path** ([`CounterVec::inc`], [`HistogramVec::observe`]) is a thread-local
//!   read, a mask and one or two `fetch_add(Relaxed)`: no lock, no allocation, no
//!   formatting, no I/O, no floating point. Reads ([`CounterVec::get`], [`Registry::snapshot`])
//!   sum the stripes with relaxed loads.
//!
//! The memory of a sealed counter family is about `series x shards x 8` bytes, rounded up
//! to whole cache lines per stripe (a histogram series holds its buckets, `+Inf` and the
//! sum); [`CounterVec::bytes`] and [`HistogramVec::bytes`] report it.
//!
//! # Example
//!
//! ```
//! use tenko_core::metrics::{CounterVec, Desc, Registry, encode};
//!
//! static REQUESTS: CounterVec = CounterVec::fixed(
//!     Desc::counter("demo_requests", "Requests by outcome.").labels(&["outcome"]),
//!     &[&["ok"], &["failed"]],
//! );
//!
//! let registry = Registry::new();
//! registry.register(&REQUESTS);
//! REQUESTS.inc(0);
//! let mut text = String::new();
//! encode(&registry.snapshot(), &mut text);
//! assert!(text.contains("demo_requests_total{outcome=\"ok\"} 1\n"));
//! assert!(text.ends_with("# EOF\n"));
//! ```

mod check;
mod counter;
mod encode;
mod gauge;
mod histogram;
mod registry;

use std::{
    cell::Cell,
    collections::HashMap,
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use serde::{Serialize, Serializer, ser::SerializeSeq};

pub use check::check;
pub use counter::{Counter, CounterVec};
pub use encode::encode;
pub use gauge::{Gauge, GaugeVec};
pub use histogram::{Histogram, HistogramValue, HistogramVec, MAX_BUCKETS};
pub use registry::{Collect, FamilySnapshot, Registry, Series, Snapshot, Value};

/// The largest number of shards of a counter or histogram family.
pub const MAX_SHARDS: usize = 32;

/// Cells (`u64`) per cache line.
const LINE_CELLS: usize = 8;
/// Bytes per cache line.
const LINE_BYTES: usize = 64;

/// What a family measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    /// A monotonic total; the samples carry the `_total` suffix.
    Counter,
    /// A value that goes up and down.
    Gauge,
    /// Observations counted into fixed buckets.
    Histogram {
        /// The upper bounds of the buckets, ascending, in an integer unit (for example
        /// microseconds); `+Inf` is implied.
        bounds: &'static [u64],
        /// Units per second (a power of ten): the encoder writes bounds and sums in seconds.
        per_second: u64,
    },
}

impl Kind {
    /// The `OpenMetrics` type name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram { .. } => "histogram",
        }
    }
}

/// The static description of a metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Desc {
    /// The family name, without the `_total` suffix of a counter. With a unit, it ends in
    /// `_<unit>`.
    pub name: &'static str,
    /// One line for people.
    pub help: &'static str,
    /// The unit (`seconds`, `bytes`), if the value has one.
    pub unit: Option<&'static str>,
    /// What it measures.
    pub kind: Kind,
    /// The label names; empty for a family of one series.
    pub labels: &'static [&'static str],
}

impl Desc {
    /// A counter.
    pub const fn counter(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            unit: None,
            kind: Kind::Counter,
            labels: &[],
        }
    }

    /// A gauge.
    pub const fn gauge(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            unit: None,
            kind: Kind::Gauge,
            labels: &[],
        }
    }

    /// A histogram with these bucket bounds (ascending, at most [`MAX_BUCKETS`]) in a unit
    /// with `per_second` units per second (a power of ten).
    ///
    /// # Panics
    ///
    /// At compile time for a static, when the bounds are empty, too many, not strictly
    /// ascending, or `per_second` is not a power of ten.
    pub const fn histogram(
        name: &'static str,
        help: &'static str,
        bounds: &'static [u64],
        per_second: u64,
    ) -> Self {
        assert!(
            !bounds.is_empty() && bounds.len() <= MAX_BUCKETS,
            "a histogram has 1 to 16 bucket bounds"
        );
        let mut i = 1;
        while i < bounds.len() {
            assert!(bounds[i - 1] < bounds[i], "bucket bounds must ascend");
            i += 1;
        }
        let mut power = per_second;
        while power >= 10 && power.is_multiple_of(10) {
            power /= 10;
        }
        assert!(power == 1, "per_second must be a power of ten");
        Self {
            name,
            help,
            unit: Some("seconds"),
            kind: Kind::Histogram { bounds, per_second },
            labels: &[],
        }
    }

    /// The same description with these label names.
    #[must_use]
    pub const fn labels(mut self, labels: &'static [&'static str]) -> Self {
        self.labels = labels;
        self
    }

    /// The same description with a unit; the name must end in `_<unit>`.
    #[must_use]
    pub const fn unit(mut self, unit: &'static str) -> Self {
        self.unit = Some(unit);
        self
    }

    /// The same description with the given kind of counter or gauge. A gauge family whose
    /// kind is [`Kind::Counter`] mirrors a total kept elsewhere (set by a timer).
    #[must_use]
    pub const fn as_counter(mut self) -> Self {
        self.kind = Kind::Counter;
        self
    }
}

/// The label values of one series, cheap to clone.
#[derive(Clone)]
pub struct Labels(Repr);

#[derive(Clone)]
enum Repr {
    /// A family without labels.
    Empty,
    /// Sealed at start: indices into the interned values of the family.
    Interned {
        values: &'static [&'static str],
        row: &'static [u16],
    },
    /// Assigned to a slot at run time.
    Owned(Arc<[Box<str>]>),
}

impl Labels {
    /// No labels.
    pub const EMPTY: Labels = Labels(Repr::Empty);

    /// Labels from owned values (a slot of a gauge family).
    pub fn owned(values: &[&str]) -> Self {
        if values.is_empty() {
            return Self::EMPTY;
        }
        Labels(Repr::Owned(
            values.iter().map(|value| Box::from(*value)).collect(),
        ))
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        match &self.0 {
            Repr::Empty => 0,
            Repr::Interned { row, .. } => row.len(),
            Repr::Owned(values) => values.len(),
        }
    }

    /// Whether there are no values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The value at `index`.
    pub fn get(&self, index: usize) -> Option<&str> {
        match &self.0 {
            Repr::Empty => None,
            Repr::Interned { values, row } => row
                .get(index)
                .and_then(|value| values.get(usize::from(*value)))
                .copied(),
            Repr::Owned(values) => values.get(index).map(AsRef::as_ref),
        }
    }

    /// The values in label order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        (0..self.len()).filter_map(|index| self.get(index))
    }

    /// Whether the values equal `other`.
    pub fn matches(&self, other: &[&str]) -> bool {
        self.len() == other.len() && self.iter().zip(other).all(|(a, b)| a == *b)
    }
}

impl fmt::Debug for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for Labels {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Serialize for Labels {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for value in self.iter() {
            seq.serialize_element(value)?;
        }
        seq.end()
    }
}

/// The label values of the series of a sealed family, interned once.
#[derive(Debug)]
pub(crate) struct SealedLabels {
    values: &'static [&'static str],
    rows: &'static [u16],
    width: usize,
}

impl SealedLabels {
    /// Interns `series` (one row of values per series, each as long as `names`).
    ///
    /// # Panics
    ///
    /// When a row has the wrong number of values, or there are more than 65,536 series or
    /// distinct values: a bug in the sealing code, found at start.
    pub(crate) fn new(name: &str, names: &[&str], series: &[&[&str]]) -> Self {
        assert!(
            u16::try_from(series.len().saturating_sub(1)).is_ok(),
            "{name}: more than 65,536 series"
        );
        let width = names.len();
        let mut index: HashMap<&str, u16> = HashMap::new();
        let mut order: Vec<&str> = Vec::new();
        let mut rows = Vec::with_capacity(series.len() * width);
        for row in series {
            assert_eq!(
                row.len(),
                width,
                "{name}: a series needs a value for each of {names:?}"
            );
            for value in *row {
                let next = order.len();
                let id = *index.entry(value).or_insert_with(|| {
                    order.push(value);
                    u16::try_from(next).expect("at most 65,536 distinct label values")
                });
                rows.push(id);
            }
        }
        let arena: &'static str = String::leak(order.concat());
        let mut values = Vec::with_capacity(order.len());
        let mut at = 0;
        for value in order {
            values.push(&arena[at..at + value.len()]);
            at += value.len();
        }
        Self {
            values: Vec::leak(values),
            rows: Vec::leak(rows),
            width,
        }
    }

    /// The labels of series `index`.
    pub(crate) fn labels(&self, index: usize) -> Labels {
        if self.width == 0 {
            return Labels::EMPTY;
        }
        let start = index * self.width;
        match self.rows.get(start..start + self.width) {
            Some(row) => Labels(Repr::Interned {
                values: self.values,
                row,
            }),
            None => Labels::EMPTY,
        }
    }

    /// The number of series.
    pub(crate) fn len(&self) -> usize {
        self.rows.len().checked_div(self.width).unwrap_or(1)
    }
}

/// The number of shards of a family on this machine: the available parallelism rounded
/// up to a power of two, at most [`MAX_SHARDS`]. Computed once.
pub fn default_shards() -> usize {
    static SHARDS: OnceLock<usize> = OnceLock::new();
    *SHARDS.get_or_init(|| {
        std::thread::available_parallelism()
            .map_or(1, NonZeroUsize::get)
            .next_power_of_two()
            .min(MAX_SHARDS)
    })
}

/// Shard numbers are counted modulo this, a multiple of every shard count, so that a shard
/// number masked by any family's `shards - 1` keeps its place in the cycle.
const SHARD_CYCLE: usize = MAX_SHARDS * 64;

/// How many threads without a pinned shard have taken one.
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// The shard number of this thread (unmasked); `usize::MAX` until its first update or
    /// its pin.
    static SHARD: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// The shard number of the `n`-th thread without a pinned shard: counting down from the
/// last shard of every family, away from the pinned workers, which count up from the first.
const fn unpinned_shard(n: usize) -> usize {
    SHARD_CYCLE - 1 - n % SHARD_CYCLE
}

/// Pins the calling thread to shard `worker` of every family (modulo the family's shard
/// count). A role whose workers update metrics on their hot path (the UDP workers of the
/// `dns` role) calls it on each worker thread before its first update, with the worker's
/// index among the role's workers: workers `0..n` take shards `0..n`, so two of them never
/// share a shard, and its cache lines never move between their cores, while `n` is at most
/// the family's shard count. Every other thread takes its shard at its first update,
/// counting down from the last shard, so it meets a pinned worker only when the threads
/// that update a family outnumber its shards. No allocation.
pub fn pin_worker_shard(worker: usize) {
    SHARD.with(|shard| shard.set(worker % SHARD_CYCLE));
}

/// The shard number of the calling thread: its pin, or else assigned at its first call.
#[inline]
fn thread_shard() -> usize {
    SHARD.with(|shard| {
        let current = shard.get();
        if current == usize::MAX {
            let assigned = unpinned_shard(NEXT_SHARD.fetch_add(1, Ordering::Relaxed));
            shard.set(assigned);
            assigned
        } else {
            current
        }
    })
}

/// One cache line of cells.
#[derive(Default)]
#[repr(align(64))]
struct Line([AtomicU64; LINE_CELLS]);

/// The cells of a counter or histogram family: one stripe per shard. A stripe is a run of
/// whole [`Line`]s (`#[repr(align(64))]`), so two shards never share a cache line, and the
/// cells of one family lie contiguously inside it.
pub(crate) struct Stripes {
    lines: Box<[Line]>,
    /// Lines per stripe.
    stride: usize,
    /// Used cells per stripe.
    width: usize,
    /// `shards - 1`.
    mask: usize,
}

/// The stripe of one shard.
pub(crate) struct Stripe<'a> {
    lines: &'a [Line],
    width: usize,
}

impl Stripe<'_> {
    /// Cell `index` of the stripe, if the family has it.
    #[inline]
    pub(crate) fn cell(&self, index: usize) -> Option<&AtomicU64> {
        if index >= self.width {
            return None;
        }
        self.lines
            .get(index / LINE_CELLS)
            .map(|line| &line.0[index % LINE_CELLS])
    }
}

impl Stripes {
    /// Stripes of `width` cells for `shards` shards (rounded up to a power of two, at most
    /// [`MAX_SHARDS`]). Allocates once.
    pub(crate) fn new(width: usize, shards: usize) -> Self {
        let shards = shards.clamp(1, MAX_SHARDS).next_power_of_two();
        let stride = width.max(1).div_ceil(LINE_CELLS);
        let lines = (0..stride * shards).map(|_| Line::default()).collect();
        Self {
            lines,
            stride,
            width,
            mask: shards - 1,
        }
    }

    /// The stripe of the calling thread.
    #[inline]
    pub(crate) fn local(&self) -> Stripe<'_> {
        let start = (thread_shard() & self.mask) * self.stride;
        Stripe {
            lines: &self.lines[start..start + self.stride],
            width: self.width,
        }
    }

    /// The number of shards.
    pub(crate) fn shards(&self) -> usize {
        self.mask + 1
    }

    fn load(&self, shard: usize, index: usize) -> u64 {
        self.lines[shard * self.stride + index / LINE_CELLS].0[index % LINE_CELLS]
            .load(Ordering::Relaxed)
    }

    /// Sums cell `index` over every stripe.
    pub(crate) fn sum(&self, index: usize) -> u64 {
        if index >= self.width {
            return 0;
        }
        (0..self.shards())
            .map(|shard| self.load(shard, index))
            .fold(0, u64::wrapping_add)
    }

    /// Sums every cell over every stripe, in cell order.
    pub(crate) fn sums(&self) -> Vec<u64> {
        let mut totals = vec![0_u64; self.width];
        for shard in 0..self.shards() {
            for (index, total) in totals.iter_mut().enumerate() {
                *total = total.wrapping_add(self.load(shard, index));
            }
        }
        totals
    }

    /// The bytes of the cells.
    pub(crate) fn bytes(&self) -> usize {
        self.lines.len() * LINE_BYTES
    }

    /// The address of the first cell of each stripe (tests).
    #[cfg(test)]
    pub(crate) fn stripe_addrs(&self) -> Vec<usize> {
        (0..self.shards())
            .map(|shard| std::ptr::from_ref(&self.lines[shard * self.stride]).addr())
            .collect()
    }
}

impl fmt::Debug for Stripes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stripes")
            .field("shards", &self.shards())
            .field("width", &self.width)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
