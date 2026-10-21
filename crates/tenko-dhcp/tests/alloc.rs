//! The no-allocation rule of the DHCPv4 codec, as a test: a counting global allocator
//! (`stats_alloc`, as in the DNS engine's `tests/alloc.rs`) wraps the system allocator,
//! and parsing a message, walking its options, every typed accessor, the concatenation of
//! split options and building a reply must not allocate. The first section proves that
//! the counter sees an allocation, so a pass means something.
//!
//! The allocator counts every thread of the process, so the file has one test that runs
//! the measured sections one after another.

mod support;

use std::{alloc::System, hint::black_box, net::Ipv4Addr};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use support::{WELL_FORMED, fixture};
use tenko_dhcp::v4::{
    ClientFqdn, DomainSearch, Message, MessageBuilder, MessageType, Route, Routes, WireName, code,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Runs `f` `rounds` times after one warm-up round and returns the allocations, the
/// reallocations and the bytes allocated during the measured rounds.
fn measure(rounds: usize, mut f: impl FnMut()) -> (usize, usize, usize) {
    f();
    let region = Region::new(GLOBAL);
    for _ in 0..rounds {
        f();
    }
    let stats = region.change();
    (
        stats.allocations,
        stats.reallocations,
        stats.bytes_allocated,
    )
}

/// Every read a server makes of a request, folded into a number so nothing is optimised
/// away.
fn read_all(bytes: &[u8]) -> usize {
    let Ok(message) = Message::parse(bytes) else {
        return 0;
    };
    let mut sum = usize::from(message.op()) + message.xid() as usize;
    sum += message.chaddr().map_or(0, <[u8]>::len);
    sum += usize::from(message.mac().is_ok());
    sum += usize::from(message.overload().unwrap_or(0));
    sum += message.server_name().ok().flatten().map_or(0, <[u8]>::len);
    sum += message.boot_file_str().ok().flatten().map_or(0, str::len);
    let mut scratch = [0u8; 1024];
    for option in message.options() {
        let Ok(option) = option else { break };
        sum += option.data.len();
        sum += message
            .option_data(option.code, &mut scratch)
            .ok()
            .flatten()
            .map_or(0, <[u8]>::len);
    }
    sum += usize::from(
        message
            .message_type()
            .ok()
            .flatten()
            .map_or(0, MessageType::code),
    );
    sum += usize::from(message.server_identifier().ok().flatten().is_some());
    sum += usize::from(message.requested_address().ok().flatten().is_some());
    sum += message.lease_time().ok().flatten().unwrap_or(0) as usize;
    sum += message
        .parameter_request_list()
        .ok()
        .flatten()
        .map_or(0, <[u8]>::len);
    sum += message.max_reply_len();
    sum += message
        .vendor_class_identifier()
        .ok()
        .flatten()
        .map_or(0, <[u8]>::len);
    if let Ok(Some(id)) = message.client_identifier() {
        sum += usize::from(id.kind());
        if let Some((iaid, duid)) = id.iaid_duid() {
            sum +=
                iaid as usize + usize::from(duid.kind()) + duid.enterprise().unwrap_or(0) as usize;
        }
    }
    sum += message.host_name().ok().flatten().map_or(0, <[u8]>::len);
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        sum += fqdn.name().as_wire().len() + usize::from(fqdn.flags());
    }
    if let Ok(Some(relay)) = message.relay_agent_info() {
        sum += relay.circuit_id().map_or(0, <[u8]>::len) + relay.remote_id().map_or(0, <[u8]>::len);
    }
    if let Ok(Some(architectures)) = message.client_architectures() {
        sum += architectures.iter().map(usize::from).sum::<usize>();
    }
    if let Ok(Some(interface)) = message.network_interface() {
        sum += usize::from(interface.minor);
    }
    if let Ok(Some(machine)) = message.machine_id() {
        sum += machine.guid().map_or(0, |guid| usize::from(guid[0]));
    }
    if let Ok(Some(servers)) = message.domain_name_servers() {
        sum += servers.len();
    }
    if let Ok(Some(data)) = message.option_data(code::DOMAIN_SEARCH, &mut scratch)
        && let Ok(list) = DomainSearch::parse(data)
    {
        sum += list.iter().map(|name| name.as_wire().len()).sum::<usize>();
    }
    if let Ok(Some(data)) = message.option_data(code::CLASSLESS_STATIC_ROUTES, &mut scratch)
        && let Ok(routes) = Routes::parse(code::CLASSLESS_STATIC_ROUTES, data)
    {
        sum += routes
            .iter()
            .map(|route| usize::from(route.prefix_len))
            .sum::<usize>();
    }
    sum
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

/// The ACK of `fixtures/ack-fqdn-search.hex`, written into `out`.
fn build_ack(request: &[u8], search: &[WireName], out: &mut [u8]) -> usize {
    let request = Message::parse(request).expect("parse");
    let mut reply = MessageBuilder::reply(out, &request, MessageType::Ack).expect("reply");
    reply
        .yiaddr(ip("192.0.2.50"))
        .server_identifier(ip("198.51.100.10"))
        .and_then(|b| b.lease_time(86_400))
        .and_then(|b| b.renewal_time(43_200))
        .and_then(|b| b.rebinding_time(75_600))
        .and_then(|b| b.subnet_mask(ip("255.255.255.0")))
        .and_then(|b| b.routers(&[ip("192.0.2.1")]))
        .and_then(|b| b.domain_name_servers(&[ip("192.0.2.53"), ip("198.51.100.53")]))
        .and_then(|b| b.domain_name(b"example.test"))
        .and_then(|b| b.domain_search(search))
        .expect("options");
    let fqdn = request.client_fqdn().expect("ok").expect("81");
    reply
        .client_fqdn(ClientFqdn::FLAG_S | ClientFqdn::FLAG_E, &fqdn.name())
        .expect("81");
    let relay = request.relay_agent_info().expect("ok").expect("82");
    reply.relay_agent_info(relay.as_bytes()).expect("82");
    reply.finish().expect("finish")
}

/// An OFFER that overloads into `file` and `sname` and an ACK with split routes.
fn build_overload_and_split(request: &[u8], routes: &[Route], out: &mut [u8]) -> usize {
    let request = Message::parse(request).expect("parse");
    let mut offer =
        MessageBuilder::reply(&mut out[..300], &request, MessageType::Offer).expect("reply");
    offer
        .allow_overload()
        .expect("overload")
        .server_identifier(ip("198.51.100.10"))
        .and_then(|b| b.vendor_specific(&[7; 120]))
        .and_then(|b| b.tftp_server_name(b"tftp.example.test"))
        .and_then(|b| b.bootfile_name(b"boot/x64/bootfile.efi"))
        .and_then(|b| b.pad_to(300))
        .expect("options");
    let mut len = offer.finish().expect("finish");
    let mut ack = MessageBuilder::reply(out, &request, MessageType::Ack).expect("reply");
    ack.classless_routes(routes).expect("121");
    len += ack.finish().expect("finish");
    len
}

#[test]
fn the_codec_does_not_allocate() {
    // The counter sees an allocation.
    let (allocations, _, bytes) = measure(10, || {
        let v: Vec<u8> = black_box(Vec::with_capacity(64));
        black_box(&v);
    });
    assert_eq!(allocations, 10);
    assert!(bytes >= 640);

    // Everything the tests need is loaded before the measured sections.
    let fixtures: Vec<Vec<u8>> = WELL_FORMED.iter().map(|name| fixture(name)).collect();
    let malformed: Vec<Vec<u8>> = support::MALFORMED
        .iter()
        .map(|name| fixture(name))
        .collect();
    let request = fixture("relayed-request");
    let discover = fixture("windows-discover");
    let search = [
        WireName::from_str_text("eng.example.test.").expect("name"),
        WireName::from_str_text("marketing.example.test.").expect("name"),
    ];
    let routes: Vec<Route> = (0..40u8)
        .map(|host| Route {
            destination: Ipv4Addr::new(203, 0, 113, host),
            prefix_len: 32,
            router: ip("192.0.2.254"),
        })
        .collect();

    let mut total = 0;
    let (allocations, reallocations, bytes) = measure(100, || {
        for bytes in fixtures.iter().chain(&malformed) {
            total += read_all(black_box(bytes));
        }
    });
    assert!(total > 0);
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "parsing and reading"
    );

    let mut out = [0u8; 1500];
    let (allocations, reallocations, bytes) = measure(100, || {
        let len = build_ack(black_box(&request), &search, &mut out);
        black_box(&out[..len]);
        let len = build_overload_and_split(black_box(&discover), &routes, &mut out);
        black_box(len);
    });
    assert_eq!((allocations, reallocations, bytes), (0, 0, 0), "building");
}
