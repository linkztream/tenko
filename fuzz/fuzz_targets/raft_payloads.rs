#![no_main]

//! The payloads of the controller-to-controller services `Raft` and `Cluster` (WP3.1a):
//! the openraft requests and responses in CBOR, forwarded write batches and their
//! receipts, store errors in status details, forwarded membership changes, and the
//! protocol messages that carry them. The first byte of the input picks the payload.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tenko_cluster::wire::fuzz_payload(data);
});
