#![no_main]

//! The passive neighbour frame parsers of the probe (WP3.14): LLDP (IEEE 802.1AB) and CDP
//! version 2 TLVs, reached both directly and through the Ethernet/SNAP framing. Their input
//! is attacker-controlled frames on the segment, so it is fuzzed like any network input.

use libfuzzer_sys::fuzz_target;
use tenko_scan::frame::{
    cdp,
    ethernet::{self, Protocol},
    lldp,
};

fuzz_target!(|data: &[u8]| {
    // Directly, as the method hands the Ethernet payload to each parser.
    let _ = lldp::parse(data);
    let _ = cdp::parse(data);
    // Through the Ethernet/SNAP framing, as the method routes a received frame.
    if let Some(frame) = ethernet::parse(data) {
        match frame.protocol {
            Protocol::EtherType(ethernet::ETHERTYPE_LLDP) => {
                let _ = lldp::parse(frame.payload);
            }
            Protocol::Snap { .. } => {
                let _ = cdp::parse(frame.payload);
            }
            Protocol::EtherType(_) => {}
        }
    }
});
