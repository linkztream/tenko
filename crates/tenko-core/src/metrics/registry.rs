//! The registry of metric families and its [`Snapshot`].

use std::sync::{PoisonError, RwLock};

use serde::Serialize;

use super::{Desc, HistogramValue, Labels};

/// A metric family the registry can read.
pub trait Collect: Send + Sync {
    /// The description of the family.
    fn desc(&self) -> &Desc;

    /// Appends the current value of every series that has one.
    fn collect(&self, out: &mut Vec<Series>);
}

/// The value of one series.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    /// A counter total.
    Counter(u64),
    /// A gauge.
    Gauge(f64),
    /// A histogram.
    Histogram(HistogramValue),
}

/// One series: its label values (in the order of the family's label names) and value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Series {
    /// The label values.
    pub labels: Labels,
    /// The value.
    pub value: Value,
}

/// One family in a snapshot.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FamilySnapshot {
    /// The description.
    pub desc: &'static Desc,
    /// The series that have a value, in sealing (or slot) order.
    pub series: Vec<Series>,
}

/// Every registered family, read once: what `GET /metrics` encodes and what the `metrics`
/// topic of the event stream publishes.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Snapshot {
    /// The families in registration order.
    pub families: Vec<FamilySnapshot>,
}

impl Snapshot {
    /// Appends a family of one series computed by the caller (a value read at scrape time,
    /// such as the uptime).
    pub fn push(&mut self, desc: &'static Desc, value: Value) {
        self.families.push(FamilySnapshot {
            desc,
            series: vec![Series {
                labels: Labels::EMPTY,
                value,
            }],
        });
    }

    /// The family with this name.
    pub fn family(&self, name: &str) -> Option<&FamilySnapshot> {
        self.families.iter().find(|family| family.desc.name == name)
    }
}

/// The families of a process, in registration order.
#[derive(Default)]
pub struct Registry {
    families: RwLock<Vec<&'static dyn Collect>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self
            .read()
            .iter()
            .map(|family| family.desc().name)
            .collect();
        f.debug_struct("Registry")
            .field("families", &names)
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<&'static dyn Collect>> {
        self.families.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a family. A family whose name is registered already is skipped (returns
    /// `false`), so registering the same static twice is harmless.
    pub fn register(&self, family: &'static dyn Collect) -> bool {
        let mut families = self
            .families
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let name = family.desc().name;
        if families.iter().any(|known| known.desc().name == name) {
            return false;
        }
        families.push(family);
        true
    }

    /// The names of the registered families, in order.
    pub fn names(&self) -> Vec<&'static str> {
        self.read()
            .iter()
            .map(|family| family.desc().name)
            .collect()
    }

    /// Reads every series of every family once.
    pub fn snapshot(&self) -> Snapshot {
        let families = self.read();
        let mut snapshot = Snapshot {
            families: Vec::with_capacity(families.len() + 2),
        };
        for &family in families.iter() {
            let mut series = Vec::new();
            family.collect(&mut series);
            snapshot.families.push(FamilySnapshot {
                desc: family.desc(),
                series,
            });
        }
        snapshot
    }
}
