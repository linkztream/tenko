//! The blocked counters: one per block list and RPZ zone, by name, since the process
//! started (`tenko_dns_blocked_total{list}` and the `blocked` field of the node status).
//!
//! A name gets a slot when the catalog first compiles a list or zone of that name (off the
//! query path, with a lock and an allocation); the query path adds to the slot with one
//! relaxed atomic add on its thread's stripe, so workers do not share a cache line.
//! Slot 0 is `other`, for names beyond [`SLOTS`].

use std::{
    cell::Cell,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use tenko_core::metrics::{Collect, Desc, Labels, Series, Value};

/// Names that get a counter of their own.
pub const SLOTS: usize = 1024;

const STRIPES: usize = 16;

#[allow(
    clippy::declare_interior_mutable_const,
    reason = "the initializer of the static arrays"
)]
const ZERO: AtomicU64 = AtomicU64::new(0);
#[allow(
    clippy::declare_interior_mutable_const,
    reason = "the initializer of the static arrays"
)]
const STRIPE: [AtomicU64; SLOTS] = [ZERO; SLOTS];

static COUNTS: [[AtomicU64; SLOTS]; STRIPES] = [STRIPE; STRIPES];
static NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static THREAD_STRIPE: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// The slot of a list or zone name, given on first use.
pub fn slot(name: &str) -> u16 {
    let mut names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
    if names.is_empty() {
        names.push("other".to_owned());
    }
    if let Some(at) = names.iter().position(|known| known == name) {
        return u16::try_from(at).unwrap_or(0);
    }
    if names.len() >= SLOTS {
        return 0;
    }
    names.push(name.to_owned());
    u16::try_from(names.len() - 1).unwrap_or(0)
}

fn stripe() -> usize {
    THREAD_STRIPE.with(|cell| {
        let mut stripe = cell.get();
        if stripe == usize::MAX {
            stripe = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) % STRIPES;
            cell.set(stripe);
        }
        stripe
    })
}

/// Counts one blocked query. Allocates nothing.
pub fn count(slot: u16) {
    if let Some(counter) = COUNTS[stripe()].get(usize::from(slot)) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The count of a slot.
pub fn total(slot: u16) -> u64 {
    COUNTS
        .iter()
        .filter_map(|stripe| stripe.get(usize::from(slot)))
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum()
}

/// The count of a name, 0 when it has no slot.
pub fn total_of(name: &str) -> u64 {
    let names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
    names
        .iter()
        .position(|known| known == name)
        .and_then(|at| u16::try_from(at).ok())
        .map_or(0, total)
}

/// `tenko_dns_blocked{list}`: every name that has a slot, `other` included once it counts.
#[derive(Debug)]
pub struct BlockedFamily;

/// The family registered with the process registry.
pub static BLOCKED_FAMILY: BlockedFamily = BlockedFamily;

impl Collect for BlockedFamily {
    fn desc(&self) -> &Desc {
        &crate::metrics::BLOCKED
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
        for (at, name) in names.iter().enumerate() {
            let value = u16::try_from(at).map_or(0, total);
            if at == 0 && value == 0 {
                continue;
            }
            out.push(Series {
                labels: Labels::owned(&[name]),
                value: Value::Counter(value),
            });
        }
    }
}
