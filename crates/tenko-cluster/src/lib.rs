//! Node-to-node transport: gRPC over mutual TLS, node enrolment, and the internal
//! certificate authority (OPS-04, OPS-08, OPS-28).
//!
//! | Module | Contents |
//! |---|---|
//! | [`admin`] | the administration of the controller cluster behind `/cluster/*`: views and membership changes |
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
//! | [`kek`] | the key encryption keys on their way to a joining controller: the transfer traits and context |
//! | [`peers`] | the controller cluster: peer transport, joining, membership, write forwarding, the services `Raft` and `Cluster` |
//! | [`identity`] | a node's credentials and status on its own disk |
//! | [`client`] | the node side: the supervised connection, heartbeats, buffer replay, renewal |
//! | [`node_sync`] | configuration sync to nodes, node commands, ingest cursors and node secrets, both sides (OPS-28, SCAN-09) |
//! | [`wire`] | the payloads of the controller-to-controller services and their encodings |
//! | [`error`] | the coded error of the registry and the transport |
//!
//! `docs/cluster.md` describes enrolment, certificates, revocation, the versioning rule,
//! the buffer and the ports.

pub mod admin;
pub mod buffer;
pub mod ca;
pub mod client;
pub mod error;
pub mod identity;
pub mod kek;
pub mod metrics;
pub mod model;
pub mod mtls;
pub mod node_sync;
pub mod peers;
pub mod probe;
pub mod proto;
pub mod registry;
pub mod server;
mod service;
pub mod session;
pub mod token;
pub mod version;
pub mod wire;

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
