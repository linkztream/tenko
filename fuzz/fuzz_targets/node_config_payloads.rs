#![no_main]

//! The node-sync payloads a node and a controller decode from the network: configuration
//! deltas and snapshots of `Config.Watch`, command arguments, the frames of a watch stream
//! joined and applied to a node configuration, the `Config`, `Commands` and `Observations`
//! messages, a probe's offer of its own configuration and a stored probe configuration row.
//! The first byte of the input picks the decoder.

use libfuzzer_sys::fuzz_target;
use tenko_scan::control::{decode_offer, model::ProbeConfigRecord};

fuzz_target!(|data: &[u8]| match data.split_first() {
    // A probe's offer of its own configuration, as the controller decodes it.
    Some((&0xf0, rest)) => drop(decode_offer("cbor/1", rest)),
    // A probe configuration row, as the node decodes it from its synced configuration.
    Some((&0xf1, rest)) => {
        if let Ok(record) = tenko_core::codec::from_cbor::<ProbeConfigRecord>(rest) {
            let _ = record.config.validate_stored();
        }
    }
    _ => tenko_cluster::node_sync::payload::fuzz_payload(data),
});
