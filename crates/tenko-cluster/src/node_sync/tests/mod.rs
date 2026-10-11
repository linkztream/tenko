//! Loopback tests of the node sync over real mutual TLS: a controller (store, vault, CA,
//! node registry and cluster port) and agents in one process, all on 127.0.0.1.
//!
//! | Module | Tests |
//! |---|---|
//! | `harness` | the controller, the agent helpers and the rows the tests write |
//! | `watch` | `Config.Watch`: live changes, catch-up by delta, snapshot fallback, pacing |
//! | `secrets` | `Config.Secrets`: what a node's configuration names, audit, refusals |
//! | `ingest` | `Observations.Ingest`: cursors, resends across controllers, runs, failover |

mod harness;
mod ingest;
mod secrets;
mod watch;
