#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use tenko_scan::dns::{MAX_WINDOW_ADDRESSES, NameFindings, llmnr, mdns, parse_response, ptr_names};

/// A documentation-range address (RFC 5737) for the sender of the datagram.
const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fuzz_target!(|data: &[u8]| {
    let Ok(response) = parse_response(data) else {
        return;
    };
    // Into a listen window, as the method merges each answer, with and without a scope.
    let mut window = NameFindings::default();
    let _ = window.merge(mdns::interpret(SOURCE, &response), |_| true);
    let _ = window.merge(llmnr::interpret(SOURCE, &response), |ip| ip.is_ipv4());
    assert!(window.addresses.len() <= MAX_WINDOW_ADDRESSES);
    let _ = mdns::service_types(&response);
    let _ = ptr_names(&response, SOURCE);
    let _ = ptr_names(&response, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
});
