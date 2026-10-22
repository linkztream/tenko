//! DHCP service: DHCPv4 and DHCPv6, relay agent handling, dynamic DNS updates, and the
//! failover pairing of Phase 5.
//!
//! The crate holds the DHCPv4 wire codec ([`v4`], WP7.1a) and the engine contracts of
//! WP7.0 (plan section 3.3, ADR 0019), each with an in-memory reference implementation that
//! the production one is tested against:
//!
//! | Module | Contract | Reference |
//! |---|---|---|
//! | [`feed`] | [`DhcpFeed`](feed::DhcpFeed): an image of the rows, then deltas | [`MemFeed`](feed::MemFeed) |
//! | [`image`] | [`ConfigImage`](image::ConfigImage): scopes, pools, exclusions, options, reservations, filters | [`ImageBuilder`](image::ImageBuilder) |
//! | [`lease`] | [`LeaseTable`](lease::LeaseTable), [`PendingChange`](lease::PendingChange) | [`MemLeaseTable`](lease::MemLeaseTable) |
//! | [`store`] | [`LeaseStore`](store::LeaseStore): the commit before the ACK | [`MemLeaseStore`](store::MemLeaseStore) |
//! | [`allocator`] | [`Allocator`](allocator::Allocator), [`PoolOwnership`](allocator::PoolOwnership), [`OfferHold`](allocator::OfferHold), [`grant_time`](allocator::grant_time) | [`ReferenceAllocator`](allocator::ReferenceAllocator), [`SingleNode`](allocator::SingleNode) |
//! | [`probe`] | [`ConflictProbe`](probe::ConflictProbe) | [`MemProbe`](probe::MemProbe), [`NoProbe`](probe::NoProbe) |
//! | [`ddns`] | [`DdnsQueue`](ddns::DdnsQueue) | [`MemDdnsQueue`](ddns::MemDdnsQueue) |
//! | [`fingerprint`] | [`Fingerprinter`](fingerprint::Fingerprinter) | [`RuleTable`](fingerprint::RuleTable) |
//! | [`metrics`] | the `tenko_dhcp_*` families | |
//! | [`v4::engine`], [`server`] | the DHCPv4 engine and its listeners (WP7.3) | |
//!
//! The DORA path (WP7.3) is a pure function of the configuration image, the lease table,
//! the request and the clock; it hands its lease change to the [`LeaseStore`](store::LeaseStore)
//! and sends the ACK when the commit returns. From the parse of the request to that
//! hand-off it allocates nothing (`tests/alloc.rs`). `docs/dhcp-contracts.md` describes
//! the contracts; `docs/dhcp.md` section 1 the wire format.

pub mod allocator;
// WP7.4: the configuration service, the image build and the effective options.
pub mod config;
pub mod ddns;
pub mod feed;
pub mod fingerprint;
pub mod image;
pub mod lease;
pub mod metrics;
pub mod probe;
// WP7.3: the listeners, the workers and the committer around the engine.
pub mod server;
pub mod store;
pub mod v4;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-dhcp";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
