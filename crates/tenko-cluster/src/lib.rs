//! Node-to-node transport: gRPC over mutual TLS, node enrolment, and the internal
//! certificate authority (OPS-04, OPS-08, OPS-28).
//!
//! | Module | Contents |
//! |---|---|
//! | [`ca`] | the internal CA and the TLS model of the API listener (WP1.3); node certificates with roles |
//! | [`proto`] | the protocol `tenko.cluster.v1`, compiled from `proto/` |
//! | [`token`] | enrolment tokens: format, generation, digest |
//! | [`mod@version`] | protocol majors and their negotiation (OPS-08) |
//! | [`model`] | the records of the node registry and the views and requests of its API |
//! | [`registry`] | the node registry: tokens, enrolment, renewal, revocation, protocol state |
//! | [`mtls`] | the mutual TLS of the cluster port: verifiers, revocation, kill switches |
//! | [`session`] | the live heartbeat sessions and connections of the cluster port |
//! | [`server`] | the controller's cluster port: accept loop, mutual TLS, the router and the helpers the services share |
//! | `service` (private) | the gRPC services of the cluster port, one file per service |
//! | [`probe`] | probe batches, their wire form and the controller's sink |
//! | [`buffer`] | the resumable, size-bounded observation buffer of a probe (OPS-28) |
//! | [`identity`] | a node's credentials and status on its own disk |
//! | [`client`] | the node side: the supervised connection, heartbeats, buffer replay, renewal |
//! | [`error`] | the coded error of the registry and the transport |
//!
//! `docs/cluster.md` describes enrolment, certificates, revocation, the versioning rule,
//! the buffer and the ports.

pub mod buffer;
pub mod ca;
pub mod client;
pub mod error;
pub mod identity;
pub mod model;
pub mod mtls;
pub mod probe;
pub mod proto;
pub mod registry;
pub mod server;
mod service;
pub mod session;
pub mod token;
pub mod version;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-cluster";

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
