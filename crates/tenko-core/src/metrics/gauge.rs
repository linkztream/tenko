//! Gauges: [`GaugeVec`] and [`Gauge`].
//!
//! A series is one `AtomicU64` holding the bits of an `f64`, not striped: gauges are
//! written by a timer task, never on a hot path. A series that was never set (or was
//! unset) is left out of snapshots. A family of kind [`Kind::Counter`] mirrors a total kept
//! elsewhere and holds integers ([`GaugeVec::set_total`]).
//!
//! Label values that are only known at run time (node ids, instance ids, sink names) use a
//! slot table of bounded capacity ([`GaugeVec::seal_slots`]): [`GaugeVec::set_labels`]
//! assigns a free slot to a label set the first time it is seen, and [`GaugeVec::sweep`]
//! frees the slots that were not set since the previous sweep.

use std::sync::{
    Mutex, MutexGuard, OnceLock, PoisonError,
    atomic::{AtomicU64, Ordering},
};

use super::{
    Desc, Kind, Labels, SealedLabels,
    registry::{Collect, Series, Value},
};

/// The bits of a series that holds no value. No arithmetic produces this NaN payload; a
/// caller that sets it gets the canonical NaN instead.
const UNSET: u64 = u64::MAX;

/// The slot table of a family whose label values are assigned at run time.
#[derive(Debug)]
struct Slots {
    /// The labels of each slot; `None` while free.
    labels: Vec<Option<Labels>>,
    /// Whether the slot was set since the last sweep.
    seen: Vec<bool>,
}

#[derive(Debug)]
struct Sealed {
    values: Box<[AtomicU64]>,
    fixed: Option<SealedLabels>,
    slots: Option<Mutex<Slots>>,
}

impl Sealed {
    fn values(len: usize) -> Box<[AtomicU64]> {
        (0..len).map(|_| AtomicU64::new(UNSET)).collect()
    }

    fn slots(&self) -> Option<MutexGuard<'_, Slots>> {
        self.slots
            .as_ref()
            .map(|slots| slots.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// A gauge family: a fixed set of series, or a bounded slot table.
#[derive(Debug)]
pub struct GaugeVec {
    desc: Desc,
    preset: Option<&'static [&'static [&'static str]]>,
    sealed: OnceLock<Sealed>,
}

impl GaugeVec {
    /// A family sealed later with [`GaugeVec::seal`] or [`GaugeVec::seal_slots`].
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is a histogram.
    pub const fn new(desc: Desc) -> Self {
        assert!(
            !matches!(desc.kind, Kind::Histogram { .. }),
            "a gauge family is a gauge or a mirrored counter"
        );
        Self {
            desc,
            preset: None,
            sealed: OnceLock::new(),
        }
    }

    /// A family with these series, sealed at its first use or registration.
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is a histogram.
    pub const fn fixed(desc: Desc, series: &'static [&'static [&'static str]]) -> Self {
        let mut family = Self::new(desc);
        family.preset = Some(series);
        family
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        &self.desc
    }

    /// Seals the family with a fixed set of series. A sealed family stays as it is
    /// (returns `false`).
    ///
    /// # Panics
    ///
    /// When a row has the wrong number of values or there are too many series.
    pub fn seal(&self, series: &[&[&str]]) -> bool {
        let mut fresh = false;
        self.sealed.get_or_init(|| {
            fresh = true;
            self.build(series)
        });
        fresh
    }

    /// Seals the family with a slot table of `capacity` series whose label values are
    /// assigned at run time. A sealed family stays as it is (returns `false`).
    pub fn seal_slots(&self, capacity: u16) -> bool {
        let mut fresh = false;
        self.sealed.get_or_init(|| {
            fresh = true;
            let len = usize::from(capacity);
            Sealed {
                values: Sealed::values(len),
                fixed: None,
                slots: Some(Mutex::new(Slots {
                    labels: vec![None; len],
                    seen: vec![false; len],
                })),
            }
        });
        fresh
    }

    fn build(&self, series: &[&[&str]]) -> Sealed {
        let labels = SealedLabels::new(self.desc.name, self.desc.labels, series);
        Sealed {
            values: Sealed::values(labels.len()),
            fixed: Some(labels),
            slots: None,
        }
    }

    fn sealed(&self) -> Option<&Sealed> {
        match self.preset {
            None => self.sealed.get(),
            Some(series) => Some(self.sealed.get_or_init(|| self.build(series))),
        }
    }

    fn cell(&self, series: u16) -> Option<&AtomicU64> {
        self.sealed()
            .and_then(|sealed| sealed.values.get(usize::from(series)))
    }

    /// Sets series `series` of a fixed family.
    pub fn set(&self, series: u16, value: f64) {
        if let Some(cell) = self.cell(series) {
            cell.store(bits(value), Ordering::Relaxed);
        }
    }

    /// Sets series `series` of a family of kind counter to the total `value`.
    pub fn set_total(&self, series: u16, value: u64) {
        if let Some(cell) = self.cell(series) {
            cell.store(value.min(UNSET - 1), Ordering::Relaxed);
        }
    }

    /// Sets series `series` to 1 and the other series of `series_set` to 0: a state gauge
    /// (`role="leader"` is 1, every other role 0).
    pub fn set_one_of(&self, series_set: std::ops::Range<u16>, series: u16) {
        for index in series_set {
            self.set(index, if index == series { 1.0 } else { 0.0 });
        }
    }

    /// Leaves series `series` out of snapshots until it is set again.
    pub fn unset(&self, series: u16) {
        if let Some(cell) = self.cell(series) {
            cell.store(UNSET, Ordering::Relaxed);
        }
    }

    /// The value of series `series`, if it is set.
    pub fn get(&self, series: u16) -> Option<f64> {
        let raw = self.cell(series)?.load(Ordering::Relaxed);
        (raw != UNSET).then(|| self.decode(raw))
    }

    fn decode(&self, raw: u64) -> f64 {
        match self.desc.kind {
            #[allow(clippy::cast_precision_loss)]
            Kind::Counter => raw as f64,
            _ => f64::from_bits(raw),
        }
    }

    /// Sets the series with these label values in a slot family, assigning a free slot the
    /// first time the values are seen. Returns `false` when the family has no slot table
    /// or every slot is taken (the value is dropped).
    pub fn set_labels(&self, labels: &[&str], value: f64) -> bool {
        self.store_labels(labels, bits(value))
    }

    /// [`GaugeVec::set_labels`] for a family of kind counter.
    pub fn set_labels_total(&self, labels: &[&str], value: u64) -> bool {
        self.store_labels(labels, value.min(UNSET - 1))
    }

    fn store_labels(&self, labels: &[&str], raw: u64) -> bool {
        let Some(sealed) = self.sealed() else {
            return false;
        };
        let Some(mut slots) = sealed.slots() else {
            return false;
        };
        let found = slots
            .labels
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.matches(labels)));
        let index = if let Some(index) = found {
            index
        } else {
            let Some(free) = slots.labels.iter().position(Option::is_none) else {
                return false;
            };
            slots.labels[free] = Some(Labels::owned(labels));
            free
        };
        slots.seen[index] = true;
        sealed.values[index].store(raw, Ordering::Relaxed);
        true
    }

    /// Frees the slots that were not set since the previous sweep; their series leave the
    /// snapshots. A fixed family is not affected.
    pub fn sweep(&self) {
        let Some(sealed) = self.sealed() else {
            return;
        };
        let Some(mut slots) = sealed.slots() else {
            return;
        };
        let Slots { labels, seen } = &mut *slots;
        for (index, (slot, seen)) in labels.iter_mut().zip(seen.iter_mut()).enumerate() {
            if !*seen && slot.is_some() {
                *slot = None;
                sealed.values[index].store(UNSET, Ordering::Relaxed);
            }
            *seen = false;
        }
    }

    /// The number of series (fixed) or slots (0 before sealing).
    pub fn len(&self) -> usize {
        self.sealed().map_or(0, |sealed| sealed.values.len())
    }

    /// Whether the family has no series (not sealed yet).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The bits stored for `value`.
fn bits(value: f64) -> u64 {
    let raw = value.to_bits();
    if raw == UNSET {
        f64::NAN.to_bits()
    } else {
        raw
    }
}

impl Collect for GaugeVec {
    fn desc(&self) -> &Desc {
        &self.desc
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let Some(sealed) = self.sealed() else {
            return;
        };
        let value = |raw: u64| match self.desc.kind {
            Kind::Counter => Value::Counter(raw),
            _ => Value::Gauge(f64::from_bits(raw)),
        };
        if let Some(fixed) = &sealed.fixed {
            for (index, cell) in sealed.values.iter().enumerate() {
                let raw = cell.load(Ordering::Relaxed);
                if raw != UNSET {
                    out.push(Series {
                        labels: fixed.labels(index),
                        value: value(raw),
                    });
                }
            }
        }
        if let Some(slots) = sealed.slots() {
            for (index, labels) in slots.labels.iter().enumerate() {
                let raw = sealed.values[index].load(Ordering::Relaxed);
                if let Some(labels) = labels
                    && raw != UNSET
                {
                    out.push(Series {
                        labels: labels.clone(),
                        value: value(raw),
                    });
                }
            }
        }
    }
}

/// A gauge of one series, sealed at its first use or registration.
#[derive(Debug)]
pub struct Gauge(GaugeVec);

impl Gauge {
    /// A gauge (or, with a [`Kind::Counter`] description, a mirrored counter).
    ///
    /// # Panics
    ///
    /// At compile time for a static, when `desc` is a histogram or has labels.
    pub const fn new(desc: Desc) -> Self {
        assert!(desc.labels.is_empty(), "a single gauge has no labels");
        Self(GaugeVec::fixed(desc, &[&[]]))
    }

    /// Sets the value.
    pub fn set(&self, value: f64) {
        self.0.set(0, value);
    }

    /// Sets the total of a mirrored counter.
    pub fn set_total(&self, value: u64) {
        self.0.set_total(0, value);
    }

    /// Leaves the gauge out of snapshots until it is set again.
    pub fn unset(&self) {
        self.0.unset(0);
    }

    /// The value, if set.
    pub fn get(&self) -> Option<f64> {
        self.0.get(0)
    }

    /// The description.
    pub const fn desc(&self) -> &Desc {
        self.0.desc()
    }
}

impl Collect for Gauge {
    fn desc(&self) -> &Desc {
        self.0.desc()
    }

    fn collect(&self, out: &mut Vec<Series>) {
        self.0.collect(out);
    }
}
