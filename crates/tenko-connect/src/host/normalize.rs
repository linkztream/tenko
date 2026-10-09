//! Observation normalization: what a plugin reports becomes observations in the IPAM shape
//! (`tenko_core::observe`), with the host's clock and limits applied. The host hands them to
//! an [`ObservationSink`]; the reconciler (WP2.4) ingests them into `ipam.obs.*` through a
//! [`sink_fn`] the server wires. Every batch names its source, so a complete batch that is
//! empty still tells which facts are gone.
//!
//! Rules: the source time of a batch is kept unless it lies more than five minutes in the
//! future (then the host's receive time is used, with a warning); every observation expires
//! after three poll intervals, at least 15 minutes, unless a newer poll refreshes it; a
//! host's MAC and IP addresses are sorted and deduplicated, its tags deduplicated in order.

use std::time::Duration;

use tenko_core::{
    ConnectorId, ObservationId, Timestamp,
    observe::{Observation, ObservationSource, Observed},
};

use crate::{InventoryBatch, TopologySnapshot};

/// How far in the future a source's timestamp may lie before the host replaces it.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// The shortest lifetime of an observation.
pub const MIN_TTL: Duration = Duration::from_secs(900);

/// Observations of one run of one connector instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationBatch {
    /// The connector instance.
    pub connector: ConnectorId,
    /// The source the batch covers (inventory or network controller of the instance); a
    /// complete batch expires the facts of this source that it no longer reports, even when
    /// it is empty.
    pub source: ObservationSource,
    /// The observations.
    pub observations: Vec<Observation>,
    /// Whether they are the whole inventory of the source: hosts of this source absent
    /// from the batch are gone.
    pub complete: bool,
    /// When the host received them.
    pub received_at: Timestamp,
}

/// Where normalized observations go.
#[async_trait::async_trait]
pub trait ObservationSink: Send + Sync + 'static {
    /// Takes one batch.
    ///
    /// # Errors
    ///
    /// A coded error; the run is recorded as failed.
    async fn ingest(&self, batch: ObservationBatch) -> Result<(), tenko_core::CodedError>;
}

/// The sink while no reconciler is wired: it keeps nothing, and the run records only the
/// counts.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardSink;

#[async_trait::async_trait]
impl ObservationSink for DiscardSink {
    async fn ingest(&self, _batch: ObservationBatch) -> Result<(), tenko_core::CodedError> {
        Ok(())
    }
}

/// A sink that hands every batch to an async function: the server wires the reconciler of
/// `tenko-ipam` this way, without either crate depending on the other.
pub struct FnSink<F> {
    f: F,
}

impl<F> std::fmt::Debug for FnSink<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnSink").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<F, Fut> ObservationSink for FnSink<F>
where
    F: Fn(ObservationBatch) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), tenko_core::CodedError>> + Send + 'static,
{
    async fn ingest(&self, batch: ObservationBatch) -> Result<(), tenko_core::CodedError> {
        (self.f)(batch).await
    }
}

/// The sink that calls `f` with every batch.
pub fn sink_fn<F, Fut>(f: F) -> std::sync::Arc<dyn ObservationSink>
where
    F: Fn(ObservationBatch) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), tenko_core::CodedError>> + Send + 'static,
{
    std::sync::Arc::new(FnSink { f })
}

/// The lifetime of observations polled every `interval`.
pub fn ttl(interval: Duration) -> Duration {
    interval.saturating_mul(3).max(MIN_TTL)
}

fn source_time(observed_at: Timestamp, now: Timestamp, warnings: &mut Vec<String>) -> Timestamp {
    match now.checked_add(MAX_CLOCK_SKEW) {
        Some(limit) if observed_at > limit => {
            warnings.push(format!(
                "the source reported the time {observed_at}, more than {} s ahead; the host time is used",
                MAX_CLOCK_SKEW.as_secs()
            ));
            now
        }
        _ => observed_at,
    }
}

/// The observations of an inventory batch.
pub fn inventory(
    connector: ConnectorId,
    batch: &InventoryBatch,
    now: Timestamp,
    interval: Duration,
) -> (ObservationBatch, Vec<String>) {
    let mut warnings = Vec::new();
    let observed_at = source_time(batch.observed_at, now, &mut warnings);
    let expires_at = now.checked_add(ttl(interval));
    let observations = batch
        .hosts
        .iter()
        .map(|host| {
            let mut host = host.clone();
            host.macs.sort();
            host.macs.dedup();
            host.ips.sort();
            host.ips.dedup();
            let mut tags: Vec<String> = Vec::with_capacity(host.tags.len());
            for tag in host.tags.drain(..) {
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
            host.tags = tags;
            Observation {
                id: ObservationId::generate(),
                source: ObservationSource::Inventory { connector },
                subject: Observed::Host(host),
                observed_at,
                received_at: now,
                expires_at,
            }
        })
        .collect();
    (
        ObservationBatch {
            connector,
            source: ObservationSource::Inventory { connector },
            observations,
            complete: batch.complete,
            received_at: now,
        },
        warnings,
    )
}

/// The observations of a network controller's topology: where each client is attached,
/// and the links between devices.
pub fn topology(
    connector: ConnectorId,
    topology: &TopologySnapshot,
    now: Timestamp,
    interval: Duration,
) -> (ObservationBatch, Vec<String>) {
    let mut warnings = Vec::new();
    let observed_at = source_time(topology.observed_at, now, &mut warnings);
    let expires_at = now.checked_add(ttl(interval));
    let observation = |subject| Observation {
        id: ObservationId::generate(),
        source: ObservationSource::NetworkController { connector },
        subject,
        observed_at,
        received_at: now,
        expires_at,
    };
    let mut observations: Vec<Observation> = topology
        .clients
        .iter()
        .map(|client| {
            observation(Observed::Attachment {
                mac: client.mac,
                device: client.device.0.clone(),
                port: client.port.map(|port| port.to_string()),
                ssid: client.ssid.clone(),
                vlan: client.vlan,
            })
        })
        .collect();
    observations.extend(topology.links.iter().map(|link| {
        observation(Observed::Link {
            a: link.a.clone(),
            b: link.b.clone(),
            kind: link.kind,
        })
    }));
    (
        ObservationBatch {
            connector,
            source: ObservationSource::NetworkController { connector },
            observations,
            complete: true,
            received_at: now,
        },
        warnings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::sample_host;

    #[test]
    fn inventory_hosts_become_host_observations() {
        let connector = ConnectorId::generate();
        let now: Timestamp = "2026-10-09T12:00:00Z".parse().expect("time");
        let mut host = sample_host(3, "lab", false);
        host.tags.push("lab".to_owned());
        host.macs.push(host.macs[0]);
        let batch =
            InventoryBatch::complete("2026-10-09T11:59:00Z".parse().expect("time"), vec![host]);
        let (normalized, warnings) = inventory(connector, &batch, now, Duration::from_secs(300));
        assert_eq!(warnings, Vec::<String>::new());
        assert!(normalized.complete);
        let observation = &normalized.observations[0];
        assert_eq!(
            observation.source,
            ObservationSource::Inventory { connector }
        );
        assert_eq!(observation.observed_at, batch.observed_at);
        assert_eq!(observation.received_at, now);
        assert_eq!(
            observation.expires_at,
            now.checked_add(Duration::from_secs(900))
        );
        let Observed::Host(host) = &observation.subject else {
            panic!("a host observation");
        };
        assert_eq!(host.tags, ["lab"]);
        assert_eq!(host.macs.len(), 1);
    }

    #[tokio::test]
    async fn batches_name_their_source_and_reach_a_function_sink() {
        let connector = ConnectorId::generate();
        let now: Timestamp = "2026-10-09T12:00:00Z".parse().expect("time");
        let (empty, _) = inventory(
            connector,
            &InventoryBatch::complete(now, Vec::new()),
            now,
            Duration::from_secs(300),
        );
        assert_eq!(empty.source, ObservationSource::Inventory { connector });
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = {
            let seen = std::sync::Arc::clone(&seen);
            sink_fn(move |batch: ObservationBatch| {
                let seen = std::sync::Arc::clone(&seen);
                async move {
                    seen.lock().expect("lock").push(batch.source.clone());
                    Ok(())
                }
            })
        };
        sink.ingest(empty).await.expect("ingest");
        assert_eq!(
            *seen.lock().expect("lock"),
            vec![ObservationSource::Inventory { connector }]
        );
    }
    #[test]
    fn a_source_clock_far_ahead_is_replaced() {
        let now: Timestamp = "2026-10-09T12:00:00Z".parse().expect("time");
        let batch = InventoryBatch::complete(
            "2026-10-09T13:00:00Z".parse().expect("time"),
            vec![sample_host(0, "lab", false)],
        );
        let (normalized, warnings) = inventory(
            ConnectorId::generate(),
            &batch,
            now,
            Duration::from_secs(3600),
        );
        assert_eq!(normalized.observations[0].observed_at, now);
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            normalized.observations[0].expires_at,
            now.checked_add(Duration::from_secs(3 * 3600))
        );
    }
}
