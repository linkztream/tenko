//! The role's metric families in the process registry (OPS-21, `docs/dhcp-contracts.md`
//! section 8): the engine counts per worker with relaxed atomics, and these collectors sum
//! the workers when the registry is read; the lease gauges are computed from the table at
//! that time (lazy, as the contracts say).
//!
//! [`register`] adds every family of [`crate::metrics::ALL`] under its name and the three
//! families of the lease path (`tenko_dhcp_expired`, `tenko_dhcp_history_rows`,
//! `tenko_dhcp_history_purged`); [`install`] points the collectors at the running role and
//! [`clear`] detaches it when the role stops (the families then read nothing, or zero).
//! `tenko_dhcp_dropped` adds the engine's drops to those the lease path counts on its own
//! series; `tenko_dhcp_store_refused` and `tenko_dhcp_commit_duration_seconds` are the
//! lease path's (the committer measures from the hand-off to the durable commit). The
//! families of conflict detection and DDNS read zero until WP8.5 and WP8.3 count them.

use std::{
    collections::BTreeMap,
    sync::{Arc, PoisonError, RwLock},
};

use tenko_core::{
    dhcp::BindingState,
    metrics::{Collect, Counter, Desc, Histogram, HistogramValue, Labels, Registry, Series, Value},
};

use super::{LocalNode, state_name};
use crate::{
    lease::metrics as lease,
    metrics as families,
    metrics::EXCHANGE_BUCKETS_US,
    v4::engine::{
        MetricsSnapshot,
        metrics::{DROP_LABELS, OUTCOME_LABELS, STEP_LABELS, TYPE_LABELS},
    },
};

static SOURCE: RwLock<Option<Arc<LocalNode>>> = RwLock::new(None);

/// Points the collectors at `node`.
pub fn install(node: Arc<LocalNode>) {
    *SOURCE.write().unwrap_or_else(PoisonError::into_inner) = Some(node);
}

/// Detaches the role.
pub fn clear() {
    *SOURCE.write().unwrap_or_else(PoisonError::into_inner) = None;
}

fn source() -> Option<Arc<LocalNode>> {
    SOURCE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn engine() -> MetricsSnapshot {
    source().map(|node| node.stats().engine).unwrap_or_default()
}

/// Cumulative buckets of a per-bucket count.
fn cumulative(counts: &[u64; EXCHANGE_BUCKETS_US.len() + 1], sum: u64) -> HistogramValue {
    let mut total = 0;
    HistogramValue {
        buckets: counts
            .iter()
            .map(|count| {
                total += count;
                total
            })
            .collect(),
        sum,
    }
}

/// One family read from the engine's counters.
struct EngineFamily {
    desc: &'static Desc,
    read: fn(&MetricsSnapshot, &mut Vec<Series>),
}

impl Collect for EngineFamily {
    fn desc(&self) -> &Desc {
        self.desc
    }

    fn collect(&self, out: &mut Vec<Series>) {
        (self.read)(&engine(), out);
    }
}

fn packets(snapshot: &MetricsSnapshot, out: &mut Vec<Series>) {
    for (kind, row) in TYPE_LABELS.iter().zip(&snapshot.packets) {
        for (outcome, value) in OUTCOME_LABELS.iter().zip(row) {
            if *value > 0 {
                out.push(Series {
                    labels: Labels::owned(&["v4", kind, outcome]),
                    value: Value::Counter(*value),
                });
            }
        }
    }
}

fn exchange(snapshot: &MetricsSnapshot, out: &mut Vec<Series>) {
    for (step, (counts, sum)) in STEP_LABELS.iter().zip(&snapshot.exchange) {
        out.push(Series {
            labels: Labels::owned(&[step]),
            value: Value::Histogram(cumulative(counts, *sum)),
        });
    }
}

fn naks(snapshot: &MetricsSnapshot, out: &mut Vec<Series>) {
    out.push(Series {
        labels: Labels::EMPTY,
        value: Value::Counter(snapshot.naks),
    });
}

fn declines(snapshot: &MetricsSnapshot, out: &mut Vec<Series>) {
    out.push(Series {
        labels: Labels::EMPTY,
        value: Value::Counter(snapshot.declines),
    });
}

fn dropped(snapshot: &MetricsSnapshot, out: &mut Vec<Series>) {
    for (index, (reason, value)) in DROP_LABELS.iter().zip(&snapshot.dropped).enumerate() {
        let own = u16::try_from(index).map_or(0, |series| lease::DROPPED.get(series));
        out.push(Series {
            labels: Labels::owned(&[reason]),
            value: Value::Counter(value + own),
        });
    }
}

static PACKETS: EngineFamily = EngineFamily {
    desc: &families::PACKETS,
    read: packets,
};
static EXCHANGE: EngineFamily = EngineFamily {
    desc: &families::EXCHANGE_DURATION,
    read: exchange,
};
static NAKS: EngineFamily = EngineFamily {
    desc: &families::NAKS,
    read: naks,
};
static DECLINES: EngineFamily = EngineFamily {
    desc: &families::DECLINES,
    read: declines,
};
static DROPPED: EngineFamily = EngineFamily {
    desc: &families::DROPPED,
    read: dropped,
};

/// `tenko_dhcp_leases{state}`: the table's rows by binding state.
struct Leases;

impl Collect for Leases {
    fn desc(&self) -> &Desc {
        &families::LEASES
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let Some(node) = source() else {
            return;
        };
        for (state, count) in node.leases().read().counts_by_state() {
            #[allow(clippy::cast_precision_loss, reason = "a gauge of rows")]
            out.push(Series {
                labels: Labels::owned(&[state_name(state)]),
                value: Value::Gauge(count as f64),
            });
        }
    }
}

/// `tenko_dhcp_pool_utilization{scope}`: active bindings in a scope's pools over the pools'
/// addresses, per scope (by its network).
struct Utilization;

impl Collect for Utilization {
    fn desc(&self) -> &Desc {
        &families::POOL_UTILIZATION
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let Some(node) = source() else {
            return;
        };
        let Some(server) = node.server() else {
            return;
        };
        let image = server.image();
        let now = tenko_core::Timestamp::now();
        let mut bound: BTreeMap<tenko_core::PrefixId, u64> = BTreeMap::new();
        {
            let table = node.leases().read();
            for lease in table.iter() {
                if lease.state == BindingState::Active
                    && lease.ends > now
                    && image
                        .scope(lease.scope)
                        .is_some_and(|scope| scope.is_dynamic(lease.addr))
                {
                    *bound.entry(lease.scope).or_default() += 1;
                }
            }
            drop(table);
        }
        for scope in image.scopes() {
            let size: u64 = scope.pools.iter().map(crate::image::PoolImage::size).sum();
            if size == 0 {
                continue;
            }
            let used = bound.get(&scope.prefix).copied().unwrap_or(0);
            #[allow(clippy::cast_precision_loss, reason = "a share for people")]
            out.push(Series {
                labels: Labels::owned(&[&scope.network.to_string()]),
                value: Value::Gauge(used as f64 / size as f64),
            });
        }
    }
}

static LEASES: Leases = Leases;
static UTILIZATION: Utilization = Utilization;

// WP8.5: conflict detection counts these two (`crate::conflict::metrics`).
pub(crate) static CONFLICTS: Counter = Counter::new(families::CONFLICTS);
pub(crate) static PROBE_DURATION: Histogram = Histogram::new(families::PROBE_DURATION);
// WP8.3: the DDNS worker counts `tenko_dhcp_ddns{outcome}` and sets the queue gauge.
use crate::ddns::metrics::{OUTCOMES as DDNS, QUEUE as DDNS_QUEUE};

/// Registers every family of the role with `registry`.
pub fn register(registry: &Registry) {
    registry.register(&PACKETS);
    registry.register(&EXCHANGE);
    registry.register(&lease::COMMIT_DURATION);
    registry.register(&LEASES);
    registry.register(&UTILIZATION);
    registry.register(&NAKS);
    registry.register(&DECLINES);
    registry.register(&CONFLICTS);
    registry.register(&PROBE_DURATION);
    registry.register(&DDNS);
    registry.register(&DDNS_QUEUE);
    registry.register(&DROPPED);
    registry.register(&lease::STORE_REFUSED);
    registry.register(&lease::EXPIRED);
    registry.register(&lease::HISTORY_ROWS);
    registry.register(&lease::HISTORY_PURGED);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_of_the_contracts_registers_once() {
        let registry = Registry::new();
        register(&registry);
        register(&registry);
        let names = registry.names();
        for desc in families::ALL {
            assert_eq!(
                names.iter().filter(|name| **name == desc.name).count(),
                1,
                "{}",
                desc.name
            );
        }
        assert_eq!(names.len(), families::ALL.len() + 3);
        // Without a role the families read nothing but zeros.
        let snapshot = registry.snapshot();
        let leases = snapshot.family("tenko_dhcp_leases").expect("family");
        assert_eq!(leases.series.len(), 0);
    }

    #[test]
    fn buckets_accumulate() {
        let mut counts = [0u64; EXCHANGE_BUCKETS_US.len() + 1];
        counts[0] = 2;
        counts[3] = 1;
        counts[EXCHANGE_BUCKETS_US.len()] = 4;
        let value = cumulative(&counts, 99);
        assert_eq!(value.count(), 7);
        assert_eq!(value.buckets[2], 2);
        assert_eq!(value.buckets[3], 3);
        assert_eq!(value.sum, 99);
    }
}
