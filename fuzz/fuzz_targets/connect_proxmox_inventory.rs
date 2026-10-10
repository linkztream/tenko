//! Fuzzes the mapping of Proxmox VE API answers to observed hosts (`tenko_connect_proxmox::inventory`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_connect_proxmox::inventory::{Filter, Snapshot, build};

fuzz_target!(|data: &[u8]| {
    // The answers arrive as JSON; any shape that deserializes must map without panicking.
    let Ok(snapshot) = serde_json::from_slice::<Snapshot>(data) else {
        return;
    };
    for filter in [
        Filter::default(),
        Filter {
            include_stopped: false,
            include_templates: true,
            ..Filter::default()
        },
    ] {
        for host in build(&snapshot, &filter) {
            assert!(!host.external_id.is_empty());
        }
    }
});
