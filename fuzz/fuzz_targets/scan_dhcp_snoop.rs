#![no_main]

//! The DHCP-snoop frame parser of the probe (WP3.14): the small local DHCPv4 field parser
//! (RFC 2131), reached directly and through the Ethernet/IPv4/UDP framing the snoop reads.
//! This is the parser `tenko-dhcp`'s codec replaces once it merges. The input is broadcast
//! and relayed DHCP frames on the segment, so it is fuzzed like network input.

use libfuzzer_sys::fuzz_target;
use tenko_scan::frame::{
    dhcp,
    ethernet::{self, Protocol},
    ipv4,
};

fuzz_target!(|data: &[u8]| {
    let _ = dhcp::parse(data);
    if let Some(frame) = ethernet::parse(data) {
        if frame.protocol == Protocol::EtherType(ethernet::ETHERTYPE_IPV4) {
            if let Some(ip) = ipv4::parse(frame.payload) {
                if ip.protocol == ipv4::PROTO_UDP {
                    // Skip the 8-byte UDP header, as the snoop does.
                    if let Some(payload) = ip.payload.get(8..) {
                        let _ = dhcp::parse(payload);
                    }
                }
            }
        }
    }
});
