//! The DNS engine contracts of Tenko DDI (Phase 2 plan, section 3.3; ADR 0009, ADR 0017).
//!
//! The engine serves from an in-memory index built from the replicated store's rows and
//! never writes them: a change is a change set the store commits (plan section 2.4). This
//! crate holds the contracts every Phase 2 package builds on, with reference
//! implementations that are simple and correct:
//!
//! | Module | Contract | Reference implementation |
//! |---|---|---|
//! | [`codec`] | [`Codec`]: parse a query, build an answer, allocation-free | [`DomainCodec`] on `domain` 0.12.3 |
//! | [`feed`] | [`ZoneFeed`]: an image at a revision, then deltas | [`MemFeed`] |
//! | [`index`] | [`Index`]: lookup with closest encloser, wildcards, cuts, CNAME chains | [`MemIndex`] |
//! | [`resolver`] | [`Resolver`]: the one lookup path of every transport | (WP4.1, WP4.3) |
//! | [`upstream`] | [`Upstream`]: one exchange with one resolver | plain, DoT and DoH (WP5.1) |
//! | [`policy`] | [`PolicyEngine`]: RPZ and block lists | [`policy::NoPolicy`] |
//! | [`rate`] | [`RateLimiter`]: RRL and per-client limits | [`rate::Unlimited`] |
//! | [`log`] | [`QueryLogSink`]: the non-blocking query log | [`log::NullLog`] |
//! | [`metrics`] | the metric families of the engine | |
//! | [`name`], [`wire`] | the fixed-size wire name, raw header and record helpers | |
//!
//! The model (zones, RRsets, record data, views, keys, lists), the tables, the error codes
//! and the audit actions are in `tenko_core::dns`. Phase 2 runs the `dns` role in the
//! controller's process and builds and measures one node (plan section 2.10); the traits
//! keep the engine unaware of where its rows come from, so the node-file feed of Phase 5
//! adds a feed, not a redesign.

pub mod authoritative;
pub mod catalog;
pub mod codec;
pub mod cookie;
pub mod feed;
pub mod forward;
pub mod index;
pub mod log;
pub mod metrics;
pub mod name;
pub mod policy;
pub mod querylog;
pub mod rate;
pub mod resolver;
pub mod respond;
pub mod server;
pub mod status;
pub mod store_feed;
pub mod tls;
pub mod transport;
pub mod tree;
pub mod upstream;
pub mod wire;
pub mod zone;

// The resolver side (WP5.1).
pub mod cache;
pub mod forwarders;
pub mod outbound;
pub mod pool;

// RPZ, block lists and rate limiting (WP5.2).
pub mod lists;

pub use codec::{AnswerBuf, Codec, CodecError, DomainCodec, Request};
pub use feed::{DnsData, MemFeed, ZoneFeed};
pub use index::{Index, Lookup, MemIndex};
pub use log::QueryLogSink;
pub use name::NameBuf;
pub use policy::PolicyEngine;
pub use rate::RateLimiter;
pub use resolver::Resolver;
pub use upstream::Upstream;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-dns";

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
