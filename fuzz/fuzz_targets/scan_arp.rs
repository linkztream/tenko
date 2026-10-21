#![no_main]

//! The active-scan frame parsers of the probe (WP3.14): Ethernet, ARP (RFC 826), and the
//! IPv4 and TCP parsers the SYN scan and the fingerprint read from replies. The input is
//! frames seen on the segment, so it is fuzzed like network input.

use libfuzzer_sys::fuzz_target;
use tenko_scan::frame::{
    arp,
    ethernet::{self, Protocol},
    ipv4, tcp,
};

fuzz_target!(|data: &[u8]| {
    let _ = arp::parse(data);
    let _ = ipv4::parse(data);
    let _ = tcp::parse(data);
    if let Some(frame) = ethernet::parse(data) {
        match frame.protocol {
            Protocol::EtherType(ethernet::ETHERTYPE_ARP) => {
                let _ = arp::parse(frame.payload);
            }
            Protocol::EtherType(ethernet::ETHERTYPE_IPV4) => {
                if let Some(ip) = ipv4::parse(frame.payload) {
                    if ip.protocol == ipv4::PROTO_TCP {
                        let _ = tcp::parse(ip.payload);
                    }
                }
            }
            _ => {}
        }
    }
});
