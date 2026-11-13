#![no_main]

//! The requests of the cluster port beyond the Raft and node-sync payloads: `Hello` and
//! the version negotiation, heartbeats, the CSR of a renewal, a controller's join, a
//! probe's ingest batch, command subscriptions and the small requests of the `Cluster`,
//! `Config` and `Metrics` services, the identity read from a caller's certificate, and the
//! generation record, claim and fence file of a `Raft` or `Cluster` call.
//! The first byte of the input picks the request.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tenko_cluster::server::fuzz_request(data);
});
