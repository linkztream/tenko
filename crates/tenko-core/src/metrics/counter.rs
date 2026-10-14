//! Counters: [`CounterVec`] (a fixed set of series) and [`Counter`] (one series).

use std::sync::{OnceLock, atomic::Ordering};

use super::{
    Desc, Kind, SealedLabels, Stripes,
    registry::{Collect, Series, Value},
};

/// A sealed counter family: its labels and its stripes.
#[derive(Debug)]
struct Sealed {
    labels: SealedLabels,
    stripes: Stripes,
}

/// A counter family with a fixed set of series, given when it is sealed.
///
/// `inc` and `add` are one `fetch_add(Relaxed)` on the calling thread's stripe. An update
/// of a family that is not sealed yet, or of a series index it does not have, is dropped.
#[derive(Debug)]
pub struct CounterVec {
    desc: Desc,
    /// The series of a family that seals itself at its first use.
    preset: Option<&'static [&'static [&'static str]]>,
    /// Series whose value is zero are left out of snapshots.
    sparse: bool,
    sealed: OnceLock<Sealed>,
}

impl CounterVec {
    /// A family whose series are given later with [`CounterVec::seal`].
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a counter.
    pub const fn new(desc: Desc) -> Self {
        assert!(matches!(desc.kind, Kind::Counter), "not a counter");
        Self {
            desc,
            preset: None,
            sparse: false,
            sealed: OnceLock::new(),
        }
    }

    /// A family with these series (one row of label values each), sealed at its first use
    /// or registration.
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a counter.
    pub const fn fixed(desc: Desc, series: &'static [&'static [&'static str]]) -> Self {
        assert!(matches!(desc.kind, Kind::Counter), "not a counter");
        Self {
            desc,
            preset: Some(series),
            sparse: false,
            sealed: OnceLock::new(),
        }
    }

    /// The same family, leaving series that are still zero out of snapshots (for families
    /// with many series of which few are ever used, such as requests by route and status).
    #[must_use]
    pub const fn sparse(mut self) -> Self {
        self.sparse = true;
        self
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        &self.desc
    }

    /// Seals the family with these series on [`super::default_shards`] shards. Allocates
    /// once; a family that is already sealed stays as it is (returns `false`).
    ///
    /// # Panics
    ///
    /// When a row has the wrong number of values or there are more than 65,536 series.
    pub fn seal(&self, series: &[&[&str]]) -> bool {
        self.seal_with_shards(series, super::default_shards())
    }

    /// [`CounterVec::seal`] with a given shard count (rounded up to a power of two, at most
    /// [`super::MAX_SHARDS`]). Hot families keep the default; a family with many series on a
    /// path of bounded throughput passes fewer shards, since its memory is series x shards x 8
    /// bytes.
    ///
    /// # Panics
    ///
    /// As [`CounterVec::seal`].
    pub fn seal_with_shards(&self, series: &[&[&str]], shards: usize) -> bool {
        let mut fresh = false;
        self.sealed.get_or_init(|| {
            fresh = true;
            let labels = SealedLabels::new(self.desc.name, self.desc.labels, series);
            let stripes = Stripes::new(labels.len(), shards);
            Sealed { labels, stripes }
        });
        fresh
    }

    #[inline]
    fn sealed(&self) -> Option<&Sealed> {
        match self.preset {
            None => self.sealed.get(),
            Some(series) => Some(self.sealed.get_or_init(|| {
                let labels = SealedLabels::new(self.desc.name, self.desc.labels, series);
                let stripes = Stripes::new(labels.len(), super::default_shards());
                Sealed { labels, stripes }
            })),
        }
    }

    /// Adds one to series `series`.
    #[inline]
    pub fn inc(&self, series: u16) {
        self.add(series, 1);
    }

    /// Adds `n` to series `series`.
    #[inline]
    pub fn add(&self, series: u16, n: u64) {
        if let Some(sealed) = self.sealed()
            && let Some(cell) = sealed.stripes.local().cell(usize::from(series))
        {
            cell.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// The value of series `series`: the sum of its stripes.
    pub fn get(&self, series: u16) -> u64 {
        self.sealed()
            .map_or(0, |sealed| sealed.stripes.sum(usize::from(series)))
    }

    /// The number of series (0 before sealing).
    pub fn len(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.labels.len())
    }

    /// Whether the family has no series (not sealed yet).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of shards (0 before sealing).
    pub fn shards(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.stripes.shards())
    }

    /// The bytes of the counter cells (0 before sealing).
    pub fn bytes(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.stripes.bytes())
    }

    /// The stripe addresses (tests).
    #[cfg(test)]
    pub(crate) fn stripe_addrs(&self) -> Vec<usize> {
        self.sealed()
            .map(|sealed| sealed.stripes.stripe_addrs())
            .unwrap_or_default()
    }
}

impl Collect for CounterVec {
    fn desc(&self) -> &Desc {
        &self.desc
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let Some(sealed) = self.sealed() else {
            return;
        };
        for (index, total) in sealed.stripes.sums().into_iter().enumerate() {
            if self.sparse && total == 0 {
                continue;
            }
            out.push(Series {
                labels: sealed.labels.labels(index),
                value: Value::Counter(total),
            });
        }
    }
}

/// A counter of one series, sealed at its first use or registration.
#[derive(Debug)]
pub struct Counter(CounterVec);

impl Counter {
    /// A counter.
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is not a counter or has labels.
    pub const fn new(desc: Desc) -> Self {
        assert!(desc.labels.is_empty(), "a single counter has no labels");
        Self(CounterVec::fixed(desc, &[&[]]))
    }

    /// Adds one.
    #[inline]
    pub fn inc(&self) {
        self.0.add(0, 1);
    }

    /// Adds `n`.
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.add(0, n);
    }

    /// The value.
    pub fn get(&self) -> u64 {
        self.0.get(0)
    }

    /// The number of shards.
    pub fn shards(&self) -> usize {
        self.0.shards()
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        self.0.desc()
    }
}

impl Collect for Counter {
    fn desc(&self) -> &Desc {
        self.0.desc()
    }

    fn collect(&self, out: &mut Vec<Series>) {
        self.0.collect(out);
    }
}
