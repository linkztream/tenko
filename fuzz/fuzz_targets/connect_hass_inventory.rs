//! Fuzzes the mapping of Home Assistant answers to observed hosts and vendor facts (`tenko_connect_hass::inventory`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_connect_hass::inventory::{Options, Snapshot, build};

fuzz_target!(|data: &[u8]| {
    // The answers arrive as JSON; any shape that deserializes must map without panicking.
    let Ok(snapshot) = serde_json::from_slice::<Snapshot>(data) else {
        return;
    };
    for options in [
        Options::default(),
        Options {
            public_ipv4: true,
            include_disabled: true,
            device_trackers: false,
            ..Options::default()
        },
    ] {
        let built = build(&snapshot, &options);
        for host in &built.hosts {
            assert!(!host.external_id.is_empty());
            assert!(!host.macs.is_empty() || !host.ips.is_empty());
        }
    }
});
