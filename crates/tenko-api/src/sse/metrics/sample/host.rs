//! The `host` part of a sample (OPS-20): the gauges `tenko_host_*` of the registry, which the
//! refresh before each sample sets from the host monitor's latest reading (at most five seconds
//! old). The part is there while at least one of them has a value, and a figure whose gauge is
//! unset is absent from it. Nothing here is a rate: consecutive samples repeat the reading until
//! the monitor takes a new one.
//!
//! The cluster's part holds the controller that is worst off for each figure: the highest CPU
//! share, and the memory and the disk of the controller with the smallest share available.

use tenko_core::metrics::{Snapshot, Value};

use super::{as_count, label};
use crate::dto::events::MetricsHost;

/// `tenko_host_cpu_busy_ratio`.
pub(crate) const HOST_CPU: &str = "tenko_host_cpu_busy_ratio";
/// `tenko_host_memory_bytes{kind}`.
pub(crate) const HOST_MEMORY: &str = "tenko_host_memory_bytes";
/// `tenko_host_disk_bytes{kind}`.
pub(crate) const HOST_DISK: &str = "tenko_host_disk_bytes";

/// The value of the series of a gauge family whose label `kind` is `kind`.
fn kind(snapshot: &Snapshot, name: &str, kind: &str) -> Option<u64> {
    let family = snapshot.family(name)?;
    family.series.iter().find_map(|series| match series.value {
        Value::Gauge(value) if label(family, series, "kind") == Some(kind) => Some(as_count(value)),
        _ => None,
    })
}

/// The host part of a sample, or `None` when no figure of the host is set.
pub(super) fn host_sample(snapshot: &Snapshot) -> Option<MetricsHost> {
    let cpu = snapshot
        .family(HOST_CPU)
        .and_then(|family| {
            family.series.iter().find_map(|series| match series.value {
                Value::Gauge(ratio) if ratio.is_finite() => Some(ratio),
                _ => None,
            })
        })
        .map(|ratio| (ratio * 100.0).clamp(0.0, 100.0));
    let host = MetricsHost {
        cpu_percent: cpu,
        memory_total: kind(snapshot, HOST_MEMORY, "total"),
        memory_available: kind(snapshot, HOST_MEMORY, "available"),
        disk_total: kind(snapshot, HOST_DISK, "total"),
        disk_available: kind(snapshot, HOST_DISK, "available"),
    };
    (host != MetricsHost::default()).then_some(host)
}

/// The share of `total` that is `available`; a pair that is incomplete or empty has none.
fn available_share(total: Option<u64>, available: Option<u64>) -> Option<f64> {
    let (total, available) = (total?, available?);
    (total > 0).then(|| super::as_f64(available) / super::as_f64(total))
}

/// Whether the pair `(total, available)` of `candidate` is worse off than that of `known`: a
/// smaller share available, and any pair with a share against none.
fn worse(candidate: (Option<u64>, Option<u64>), known: (Option<u64>, Option<u64>)) -> bool {
    match (
        available_share(candidate.0, candidate.1),
        available_share(known.0, known.1),
    ) {
        (Some(candidate), Some(known)) => candidate < known,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Adds a controller's `host` part to the cluster's.
pub(super) fn add_host(sum: &mut Option<MetricsHost>, host: &MetricsHost) {
    let Some(known) = sum else {
        *sum = Some(host.clone());
        return;
    };
    known.cpu_percent = match (known.cpu_percent, host.cpu_percent) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    if worse(
        (host.memory_total, host.memory_available),
        (known.memory_total, known.memory_available),
    ) || (known.memory_total.is_none() && known.memory_available.is_none())
    {
        known.memory_total = host.memory_total;
        known.memory_available = host.memory_available;
    }
    if worse(
        (host.disk_total, host.disk_available),
        (known.disk_total, known.disk_available),
    ) || (known.disk_total.is_none() && known.disk_available.is_none())
    {
        known.disk_total = host.disk_total;
        known.disk_available = host.disk_available;
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Instant};

    use tenko_core::{
        NodeId, Timestamp,
        metrics::{Collect, Desc, Gauge, GaugeVec, Registry},
    };

    use super::{super::SampleBuilder, *};
    use crate::dto::events::MetricsSample;

    static CPU: Gauge = Gauge::new(Desc::gauge(HOST_CPU, "CPU.").unit("ratio"));
    static MEMORY: GaugeVec = GaugeVec::fixed(
        Desc::gauge(HOST_MEMORY, "Memory.")
            .labels(&["kind"])
            .unit("bytes"),
        &[&["total"], &["available"]],
    );
    static DISK: GaugeVec = GaugeVec::fixed(
        Desc::gauge(HOST_DISK, "Disk.")
            .labels(&["kind"])
            .unit("bytes"),
        &[&["total"], &["available"]],
    );

    fn registry() -> Registry {
        let registry = Registry::new();
        for family in [&CPU as &'static dyn Collect, &MEMORY, &DISK] {
            registry.register(family);
        }
        registry
    }

    fn sample_of(registry: &Registry) -> MetricsSample {
        SampleBuilder::new().build(
            Some(NodeId(1)),
            Timestamp::now(),
            Instant::now(),
            &registry.snapshot(),
            &BTreeMap::new(),
        )
    }

    #[test]
    fn the_host_part_reads_the_gauges_and_leaves_out_the_unset_ones() {
        let registry = registry();
        assert_eq!(sample_of(&registry).host, None, "no gauge is set");

        CPU.set(0.375);
        MEMORY.set(0, 16_000.0);
        MEMORY.set(1, 4_000.0);
        DISK.set(0, 500_000.0);
        let host = sample_of(&registry).host.expect("the host part");
        assert_eq!(host.cpu_percent, Some(37.5));
        assert_eq!(host.memory_total, Some(16_000));
        assert_eq!(host.memory_available, Some(4_000));
        assert_eq!(host.disk_total, Some(500_000));
        assert_eq!(host.disk_available, None, "that gauge is unset");

        // A reading that could not be made is unset again.
        CPU.unset();
        DISK.unset(0);
        let host = sample_of(&registry).host.expect("memory is still set");
        assert_eq!((host.cpu_percent, host.disk_total), (None, None));

        let json = serde_json::to_value(sample_of(&registry)).expect("json");
        assert_eq!(json["host"]["memory_total"], 16_000);
        assert!(json["host"].get("cpu_percent").is_none());
        let back: MetricsSample = serde_json::from_value(json).expect("back");
        assert_eq!(back.host, sample_of(&registry).host);

        MEMORY.unset(0);
        MEMORY.unset(1);
        assert_eq!(sample_of(&registry).host, None);
        // An older peer's sample without the field reads as one without a host.
        let mut json = serde_json::to_value(sample_of(&registry)).expect("json");
        json.as_object_mut().expect("object").remove("host");
        let older: MetricsSample = serde_json::from_value(json).expect("older");
        assert_eq!(older.host, None);
    }

    fn part(cpu: Option<f64>, memory: (u64, u64), disk: Option<(u64, u64)>) -> MetricsHost {
        MetricsHost {
            cpu_percent: cpu,
            memory_total: Some(memory.0),
            memory_available: Some(memory.1),
            disk_total: disk.map(|(total, _)| total),
            disk_available: disk.map(|(_, available)| available),
        }
    }

    #[test]
    fn the_cluster_holds_the_worst_cpu_memory_and_disk_of_its_controllers() {
        let at = Timestamp::now();
        let mut one = MetricsSample::empty(Some(NodeId(1)), at);
        one.host = Some(part(Some(20.0), (16_000, 8_000), Some((1_000, 600))));
        let mut two = MetricsSample::empty(Some(NodeId(2)), at);
        // Less memory available as a share, more disk, a busier CPU.
        two.host = Some(part(Some(80.0), (8_000, 1_000), Some((2_000, 1_900))));
        let mut three = MetricsSample::empty(Some(NodeId(3)), at);
        // A controller on a platform that reads no CPU or memory.
        three.host = Some(MetricsHost {
            disk_total: Some(100),
            disk_available: Some(10),
            ..MetricsHost::default()
        });
        let four = MetricsSample::empty(Some(NodeId(4)), at);
        let mut stale = MetricsSample::empty(Some(NodeId(5)), at);
        stale.stale = true;
        stale.host = Some(part(Some(99.0), (1, 0), Some((1, 0))));

        let sum = super::super::cluster_sum(&[one, two, three, four, stale], at);
        let host = sum.host.expect("controllers report the host");
        assert_eq!(host.cpu_percent, Some(80.0));
        assert_eq!(
            (host.memory_total, host.memory_available),
            (Some(8_000), Some(1_000))
        );
        assert_eq!(
            (host.disk_total, host.disk_available),
            (Some(100), Some(10)),
            "10 percent is less than 60"
        );

        let none = super::super::cluster_sum(&[MetricsSample::empty(Some(NodeId(1)), at)], at);
        assert_eq!(none.host, None);
    }
}
