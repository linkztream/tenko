#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use tenko_scan::dns::{llmnr, mdns, parse_response, ptr_names};

/// A documentation-range address (RFC 5737) for the sender of the datagram.
const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fuzz_target!(|data: &[u8]| {
    let Ok(response) = parse_response(data) else {
        return;
    };
    let _ = mdns::interpret(SOURCE, &response);
    let _ = llmnr::interpret(SOURCE, &response);
    let _ = mdns::service_types(&response);
    let _ = ptr_names(&response, SOURCE);
    let _ = ptr_names(&response, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
});
