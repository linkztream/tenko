#![no_main]

//! The neighbour table parsers of the probe: `/proc/net/arp`, `ip neigh show` and the CSV of
//! `Get-NetNeighbor`. Their input comes from the operating system, but it lists what other
//! hosts on the segment claim, so it is parsed like network input.

use libfuzzer_sys::fuzz_target;
use tenko_scan::methods::neighbours::{
    findings, parse_get_net_neighbor_csv, parse_ip_neigh, parse_proc_net_arp,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for entries in [
        parse_proc_net_arp(&text),
        parse_ip_neigh(&text),
        parse_get_net_neighbor_csv(&text),
    ] {
        let _ = findings(&entries, |_| true);
    }
});
