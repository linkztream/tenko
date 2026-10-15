//! The gRPC services of the cluster port, one file per service: the node services
//! implemented by [`ClusterService`](crate::server::ClusterService), the controller
//! services `Raft` and `Cluster` by [`PeerService`](crate::peers::PeerService). The
//! listener, the router and the shared helpers stay in [`server`](crate::server); a
//! service file holds the `impl` of one generated server trait and nothing else, so work
//! packages edit disjoint files.
//!
//! | File | Service | Callers | Owner |
//! |---|---|---|---|
//! | `handshake.rs` | `Handshake`: version negotiation | any enrolled node | WP3.1a (`endpoints`, `capabilities`) and WP3.10 (the node agent that reads them) |
//! | `node.rs` | `Node`: heartbeats, renewal | any enrolled node | WP3.1a (connection records across controllers) and WP3.10 (the node agent) |
//! | `observations.rs` | `Observations`: probe batches | a node with the role `probe` | WP3.10 (ingest cursors, large batches) |
//! | `config.rs` | `Config`: configuration sync, node secrets | a node record | WP3.10 |
//! | `commands.rs` | `Commands`: commands to nodes, reports back | a node record | WP3.10 |
//! | `raft.rs` | `Raft`: consensus between controllers | a controller with a member record | WP3.1a |
//! | `membership.rs` | `Cluster`: join, forwarding, digest, key transfer | a controller with a member record | WP3.1a |
//! | `metrics.rs` | `Metrics`: one controller's newest metrics sample | a controller | WP3.5 |
//!
//! A new service may start as a stub that answers `UNIMPLEMENTED` with a message that names
//! the package that implements it; the last one, `Metrics`, was filled in by WP3.5.
//! Replacing a stub body is not a protocol change.

mod commands;
mod config;
mod handshake;
mod membership;
mod metrics;
mod node;
mod observations;
mod raft;
