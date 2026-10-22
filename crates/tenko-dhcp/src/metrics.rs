//! The metric families of the `dhcp` role (plan section 3.3, OPS-21), declared once so that
//! every package registers the same names. The role counts per worker shard with relaxed
//! atomics and no allocation on the DORA path; `leases` and `pool_utilization` are lazy
//! gauges computed on a timer (docs/observability.md). Counter names carry no `_total`:
//! the encoder adds it.

use tenko_core::metrics::Desc;

/// Latency buckets of the DORA steps in microseconds: 50 µs to 1 s (an offer waits at most
/// the 300 ms probe cap; an ACK waits for its commit).
pub const EXCHANGE_BUCKETS_US: &[u64] = &[
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000,
];

/// Packets handled, by family (`v4`, `v6`), message type (`discover`, `request`, ...,
/// `solicit` in Slice 9) and outcome (`answered`, `nak`, `dropped`, `ignored`).
pub const PACKETS: Desc = Desc::counter("tenko_dhcp_packets", "DHCP packets handled")
    .labels(&["family", "type", "outcome"]);

/// Time of a DORA step: `offer` (DISCOVER to OFFER) and `ack` (REQUEST to ACK, the commit
/// included).
pub const EXCHANGE_DURATION: Desc = Desc::histogram(
    "tenko_dhcp_exchange_duration_seconds",
    "Time from a DHCP request's arrival to its answer",
    EXCHANGE_BUCKETS_US,
    1_000_000,
)
.labels(&["step"]);

/// Time from the hand-off of a lease change to its commit.
pub const COMMIT_DURATION: Desc = Desc::histogram(
    "tenko_dhcp_commit_duration_seconds",
    "Time from the hand-off of a DHCP lease change to its commit",
    EXCHANGE_BUCKETS_US,
    1_000_000,
);

/// Leases in the role's table, by binding state (a lazy gauge).
pub const LEASES: Desc =
    Desc::gauge("tenko_dhcp_leases", "DHCP leases by binding state").labels(&["state"]);

/// The share of a scope's pool addresses that are leased, 0 to 1 (a lazy gauge).
pub const POOL_UTILIZATION: Desc = Desc::gauge(
    "tenko_dhcp_pool_utilization",
    "Share of a DHCP scope's pool addresses that are leased",
)
.labels(&["scope"]);

/// NAKs sent.
pub const NAKS: Desc = Desc::counter("tenko_dhcp_naks", "DHCP NAKs sent");

/// DECLINEs received.
pub const DECLINES: Desc = Desc::counter("tenko_dhcp_declines", "DHCP DECLINEs received");

/// Conflicts found by a probe before an offer.
pub const CONFLICTS: Desc = Desc::counter(
    "tenko_dhcp_conflicts",
    "Addresses found in use by the conflict probe",
);

/// Duration of conflict probes.
pub const PROBE_DURATION: Desc = Desc::histogram(
    "tenko_dhcp_probe_duration_seconds",
    "Duration of DHCP conflict probes",
    EXCHANGE_BUCKETS_US,
    1_000_000,
);

/// DDNS change sets, by outcome (`written`, `removed`, `refused`, `failed`).
pub const DDNS: Desc =
    Desc::counter("tenko_dhcp_ddns", "DHCP DDNS change sets").labels(&["outcome"]);

/// DDNS requests waiting.
pub const DDNS_QUEUE: Desc = Desc::gauge("tenko_dhcp_ddns_queue", "DHCP DDNS requests waiting");

/// Requests dropped, by reason (`malformed`, `filtered`, `no_scope`, `pool_full`, `queue`,
/// `store_refused`, `rate_limited`).
pub const DROPPED: Desc =
    Desc::counter("tenko_dhcp_dropped", "DHCP requests dropped").labels(&["reason"]);

/// Lease writes the store refused (P3-Q14).
pub const STORE_REFUSED: Desc = Desc::counter(
    "tenko_dhcp_store_refused",
    "DHCP lease writes the store refused",
);

/// Every family of the role, for registration and the contracts document.
pub const ALL: [&Desc; 13] = [
    &PACKETS,
    &EXCHANGE_DURATION,
    &COMMIT_DURATION,
    &LEASES,
    &POOL_UTILIZATION,
    &NAKS,
    &DECLINES,
    &CONFLICTS,
    &PROBE_DURATION,
    &DDNS,
    &DDNS_QUEUE,
    &DROPPED,
    &STORE_REFUSED,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_prefixed() {
        let mut names: Vec<&str> = ALL.iter().map(|desc| desc.name).collect();
        assert!(names.iter().all(|name| name.starts_with("tenko_dhcp_")));
        assert!(names.iter().all(|name| !name.ends_with("_total")));
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL.len());
        for desc in ALL {
            if let Some(unit) = desc.unit {
                assert!(desc.name.ends_with(&format!("_{unit}")), "{}", desc.name);
            }
        }
    }
}
