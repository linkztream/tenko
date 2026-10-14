//! Histograms with fixed buckets: [`HistogramVec`] and [`Histogram`].
//!
//! A series holds, in its stripe, one count per bucket (non-cumulative), the `+Inf` count
//! and the sum of the observed values, all in the integer unit of the family. An
//! observation finds its bucket by a linear scan of at most [`MAX_BUCKETS`] bounds and
//! does two `fetch_add(Relaxed)`. The cumulative counts are formed when read.

use std::sync::{OnceLock, atomic::Ordering};

use serde::Serialize;

use super::{
    Desc, Kind, SealedLabels, Stripes,
    registry::{Collect, Series, Value},
};

/// The largest number of bucket bounds of a histogram (`+Inf` comes on top).
pub const MAX_BUCKETS: usize = 16;

/// The value of one histogram series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistogramValue {
    /// Cumulative counts, one per bound of the family and the `+Inf` bucket last; the last
    /// equals the count.
    pub buckets: Vec<u64>,
    /// The sum of the observed values, in the integer unit of the family.
    pub sum: u64,
}

impl HistogramValue {
    /// The number of observations.
    pub fn count(&self) -> u64 {
        self.buckets.last().copied().unwrap_or(0)
    }
}

#[derive(Debug)]
struct Sealed {
    labels: SealedLabels,
    stripes: Stripes,
}

/// A histogram family with a fixed set of series, given when it is sealed.
#[derive(Debug)]
pub struct HistogramVec {
    desc: Desc,
    bounds: &'static [u64],
    preset: Option<&'static [&'static [&'static str]]>,
    sparse: bool,
    sealed: OnceLock<Sealed>,
}

impl HistogramVec {
    /// A family whose series are given later with [`HistogramVec::seal`].
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a histogram.
    pub const fn new(desc: Desc) -> Self {
        let Kind::Histogram { bounds, .. } = desc.kind else {
            panic!("not a histogram");
        };
        Self {
            desc,
            bounds,
            preset: None,
            sparse: false,
            sealed: OnceLock::new(),
        }
    }

    /// A family with these series, sealed at its first use or registration.
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a histogram.
    pub const fn fixed(desc: Desc, series: &'static [&'static [&'static str]]) -> Self {
        let mut family = Self::new(desc);
        family.preset = Some(series);
        family
    }

    /// The same family, leaving series without observations out of snapshots.
    #[must_use]
    pub const fn sparse(mut self) -> Self {
        self.sparse = true;
        self
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        &self.desc
    }

    /// Cells per series: the buckets, `+Inf` and the sum.
    const fn width(&self) -> usize {
        self.bounds.len() + 2
    }

    /// Seals the family with these series. Allocates once; a sealed family stays as it is
    /// (returns `false`).
    ///
    /// # Panics
    ///
    /// When a row has the wrong number of values or there are too many series.
    pub fn seal(&self, series: &[&[&str]]) -> bool {
        self.seal_with_shards(series, super::default_shards())
    }

    /// [`HistogramVec::seal`] with a given shard count (rounded up to a power of two, at most
    /// [`super::MAX_SHARDS`]), as [`super::CounterVec::seal_with_shards`].
    ///
    /// # Panics
    ///
    /// As [`HistogramVec::seal`].
    pub fn seal_with_shards(&self, series: &[&[&str]], shards: usize) -> bool {
        let mut fresh = false;
        self.sealed.get_or_init(|| {
            fresh = true;
            self.build(series, shards)
        });
        fresh
    }

    fn build(&self, series: &[&[&str]], shards: usize) -> Sealed {
        let labels = SealedLabels::new(self.desc.name, self.desc.labels, series);
        let stripes = Stripes::new(labels.len() * self.width(), shards);
        Sealed { labels, stripes }
    }

    #[inline]
    fn sealed(&self) -> Option<&Sealed> {
        match self.preset {
            None => self.sealed.get(),
            Some(series) => Some(
                self.sealed
                    .get_or_init(|| self.build(series, super::default_shards())),
            ),
        }
    }

    /// Records `value` (in the unit of the family) in series `series`.
    #[inline]
    pub fn observe(&self, series: u16, value: u64) {
        let Some(sealed) = self.sealed() else {
            return;
        };
        let width = self.width();
        let base = usize::from(series) * width;
        let stripe = sealed.stripes.local();
        let Some(sum) = stripe.cell(base + width - 1) else {
            return;
        };
        let mut bucket = self.bounds.len();
        for (index, bound) in self.bounds.iter().enumerate() {
            if value <= *bound {
                bucket = index;
                break;
            }
        }
        if let Some(count) = stripe.cell(base + bucket) {
            count.fetch_add(1, Ordering::Relaxed);
            sum.fetch_add(value, Ordering::Relaxed);
        }
    }

    /// The number of shards (0 before sealing).
    pub fn shards(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.stripes.shards())
    }

    /// The bytes of the histogram cells (0 before sealing).
    pub fn bytes(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.stripes.bytes())
    }

    /// The value of series `series`.
    pub fn get(&self, series: u16) -> HistogramValue {
        let width = self.width();
        let base = usize::from(series) * width;
        let raw: Vec<u64> = match self.sealed() {
            Some(sealed) => (base..base + width)
                .map(|cell| sealed.stripes.sum(cell))
                .collect(),
            None => vec![0; width],
        };
        cumulative(&raw)
    }

    /// The number of series (0 before sealing).
    pub fn len(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.labels.len())
    }

    /// Whether the family has no series (not sealed yet).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The value of one series from its raw cells (buckets, `+Inf`, sum).
fn cumulative(raw: &[u64]) -> HistogramValue {
    let (sum, counts) = raw.split_last().unwrap_or((&0, &[]));
    let mut running = 0_u64;
    let buckets = counts
        .iter()
        .map(|count| {
            running = running.wrapping_add(*count);
            running
        })
        .collect();
    HistogramValue { buckets, sum: *sum }
}

impl Collect for HistogramVec {
    fn desc(&self) -> &Desc {
        &self.desc
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let Some(sealed) = self.sealed() else {
            return;
        };
        let sums = sealed.stripes.sums();
        for (index, raw) in sums.chunks_exact(self.width()).enumerate() {
            let value = cumulative(raw);
            if self.sparse && value.count() == 0 {
                continue;
            }
            out.push(Series {
                labels: sealed.labels.labels(index),
                value: Value::Histogram(value),
            });
        }
    }
}

/// A histogram of one series, sealed at its first use or registration.
#[derive(Debug)]
pub struct Histogram(HistogramVec);

impl Histogram {
    /// A histogram.
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a histogram or has labels.
    pub const fn new(desc: Desc) -> Self {
        assert!(desc.labels.is_empty(), "a single histogram has no labels");
        Self(HistogramVec::fixed(desc, &[&[]]))
    }

    /// Records `value`.
    #[inline]
    pub fn observe(&self, value: u64) {
        self.0.observe(0, value);
    }

    /// The value.
    pub fn get(&self) -> HistogramValue {
        self.0.get(0)
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        self.0.desc()
    }
}

impl Collect for Histogram {
    fn desc(&self) -> &Desc {
        self.0.desc()
    }

    fn collect(&self, out: &mut Vec<Series>) {
        self.0.collect(out);
    }
}
