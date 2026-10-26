//! The no-allocation rule of the DHCPv4 codec, as a test: a counting global allocator
//! (`stats_alloc`, as in the DNS engine's `tests/alloc.rs`) wraps the system allocator,
//! and parsing a message, walking its options, every typed accessor, the concatenation of
//! split options and building a reply must not allocate. The first section proves that
//! the counter sees an allocation, so a pass means something.
//!
//! WP7.0 wires the same counter to the DORA path up to its commit hand-off: parse, scope
//! selection, the client identity, the filters, the reservation and lease lookups, the
//! allocator, the lease change and its hand-off to the `LeaseStore`, and the reply. The
//! engine of WP7.3 replaces the skeleton (`dora::dora`) and must keep the section at
//! zero. A deliberate allocation in a `LeaseStore::submit` makes the section fail, which
//! the test checks too, so the guard is known to bite.
//!
//! The allocator counts every thread of the process, so the file has one test that runs
//! the measured sections one after another.

// WP8.4: the world of the classes, policies and boot paths.
mod class_world;
mod dora;
// ADR 0027: the world of the engine tests with moving clients.
mod engine_world;
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
fn the_codec_and_the_dora_path_do_not_allocate() {
    the_codec_does_not_allocate();
    // WP7.3: the engine runs the fixtures and the request corpus (`fixtures/requests`).
    let mut requests: Vec<Vec<u8>> = WELL_FORMED.iter().map(|name| fixture(name)).collect();
    requests.extend(corpus());
    dora::section(&requests, GLOBAL);
    // WP8.5: the worker's step of conflict detection.
    conflict_section(&requests);
    // WP8.4: classes, policies, network boot and proxy DHCP.
    class_section();
    // ADR 0027: the short lease and the activity of a client a move job moves.
    moving_section();
}

// ADR 0027: with clients of move jobs in the image, the renewal that gets the short lease,
// the renewal of another client, the rebinding through the new network's relay that is
// NAKed and the DISCOVER there (both noted as the client's activity) do not allocate.
fn moving_section() {
    use engine_world::{Ask, World, at, ip, mac};
    use tenko_core::{
        JobId, MacAddr,
        dhcp::{MovingClient, MovingLease},
    };
    use tenko_dhcp::v4::engine::{Action, Scratch};

    let world = World::moving(|vrf, target| {
        (0x10..0x18u8)
            .map(|k| MovingClient {
                job: JobId::generate(),
                mac: MacAddr::new(mac(k)),
                lease: Some(MovingLease {
                    vrf,
                    addr: Ipv4Addr::new(192, 0, 2, 100 + k),
                }),
                short_secs: 120,
                target: Some(target),
                until: at(3_000),
                extended: false,
            })
            .collect()
    });
    let renew = |k: u8| {
        let mut ask = Ask::new(MessageType::Request, k);
        ask.giaddr = None;
        ask.ciaddr = Some(ip("192.0.2.110"));
        ask.bytes()
    };
    let rebind = {
        let mut ask = Ask::new(MessageType::Request, 0x10);
        ask.giaddr = Some(ip("198.51.100.1"));
        ask.ciaddr = Some(ip("192.0.2.110"));
        ask.bytes()
    };
    let discover = {
        let mut ask = Ask::new(MessageType::Discover, 0x10);
        ask.giaddr = Some(ip("198.51.100.1"));
        ask.bytes()
    };
    let requests = [renew(0x10), renew(0x32), rebind, discover];
    let mut scratch = Scratch::new();
    let mut acked = 0;
    let (allocations, reallocations, bytes) = measure(50, || {
        for bytes in &requests {
            let answer = world.run(black_box(bytes), at(60), &mut scratch);
            acked += usize::from(matches!(answer.action, Action::CommitThenReply { .. }));
        }
    });
    assert!(acked > 0, "the engine answers the renewals");
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the short lease and the activity of moving clients"
    );
}

// WP8.4: the engine over an image with classes and policies (the matcher's decision, the
// class allow lists of scopes and pools, a policy range, the boot options of PXE, iPXE and
// UEFI HTTP boot, reservations by MAC for clients with option 61) and the proxy DHCP path
// do not allocate.
fn class_section() {
    use std::net::SocketAddrV4;

    use class_world::{Ask, RELAY_L, World, type1_id};
    use tenko_dhcp::v4::engine::{Action, Scratch};

    let world = World::new();
    let requests: Vec<Vec<u8>> = vec![
        Ask::pxe(0x80, 0).bytes(),
        Ask::pxe(0x81, 7).bytes(),
        Ask {
            user_class: Some(b"iPXE".to_vec()),
            ..Ask::pxe(0x82, 0)
        }
        .bytes(),
        Ask {
            vendor_class: Some(b"HTTPClient:Arch:00016:UNDI:003001".to_vec()),
            architecture: Some(16),
            ..Ask::discover(0x83)
        }
        .bytes(),
        Ask {
            vendor_class: Some(b"Printer-Laser-2".to_vec()),
            ..Ask::discover(0x60)
        }
        .bytes(),
        Ask::discover(0x45).bytes(),
        Ask::discover(0x20).with_id(type1_id(0x20)).bytes(),
        Ask::discover(0x31).with_id(type1_id(0x31)).bytes(),
    ];
    let mut scratch = Scratch::new();
    let source = SocketAddrV4::new(RELAY_L, 67);
    let mut answered = 0;
    let (allocations, reallocations, bytes) = measure(50, || {
        for bytes in &requests {
            let answer = world.run_from(black_box(bytes), source, &mut scratch);
            answered += usize::from(matches!(answer.action, Action::Reply { .. }));
            let answer = world.proxy(black_box(bytes), source, &mut scratch);
            answered += usize::from(matches!(answer.action, Action::Reply { .. }));
        }
    });
    assert!(answered > 0, "the engine answers the class requests");
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "classes, policies and network boot"
    );
}

// WP8.5: the worker's step of conflict detection does not allocate: the rules of when, the
// park into the pending table, the DECLINE limit and its report (and the dispatcher's take
// of a parked slot).
#[allow(
    clippy::too_many_lines,
    reason = "the world, the step and the measure, read top to bottom"
)]
fn conflict_section(requests: &[Vec<u8>]) {
    use std::{
        net::SocketAddrV4,
        time::{Duration, Instant},
    };

    use tenko_core::{
        NodeId, Timestamp,
        dhcp::{BindingState, LeaseEventKind, lease::MAX_IDENTITY},
    };
    use tenko_dhcp::{
        allocator::SingleNode,
        conflict::{
            ConflictSettings, Conflicts, Parked, Report, ReportKind,
            pending::Parking,
            rules::{self, candidate},
        },
        lease::{LeaseTable as _, MemLeaseTable, PendingChange},
        v4::engine::{
            self, Action, Context, EngineSettings, HashedAllocator, ListenMode, OfferTable,
            Received, Scratch,
        },
    };

    let interface = Ipv4Addr::new(198, 51, 100, 10);
    let mut links = vec![interface];
    for bytes in requests {
        if let Ok(message) = Message::parse(bytes)
            && !message.giaddr().is_unspecified()
        {
            links.push(message.giaddr());
        }
    }
    let image = dora::image(&links);
    let now = Timestamp::now();
    let mut leases = MemLeaseTable::default();
    let scope = &image.scopes()[0];
    let change = PendingChange::new(
        LeaseEventKind::Granted,
        scope.vrf,
        scope.prefix,
        Ipv4Addr::from(u32::from(scope.pools[0].first) + 5),
        1,
        &[0x00, 0x00, 0x5e, 0x00, 0x53, 0xee],
        None,
        BindingState::Active,
        now,
        now.checked_add(Duration::from_secs(3_600)).expect("time"),
    );
    leases.apply(change.to_lease(NodeId(1), None));
    let conflicts = Conflicts::new(&ConflictSettings {
        pending: 64,
        ..ConflictSettings::default()
    });
    let offers = OfferTable::with_capacity(1_024);
    let settings = EngineSettings::default();
    let mut scratch = Scratch::new();
    let mut taken = Parked::boxed();
    let mut parked = 0usize;
    let mut declines = 0usize;
    let mut identity = [0u8; MAX_IDENTITY];
    let mut step = || {
        for bytes in requests {
            let ctx = Context {
                image: &image,
                leases: &leases,
                offers: &offers,
                ownership: &SingleNode,
                allocator: &HashedAllocator,
                settings: &settings,
                accepting: true,
                now,
            };
            let received = Received {
                bytes: black_box(bytes),
                source: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 67),
                local: interface,
                mode: ListenMode::Relay,
            };
            let answer = engine::handle(&ctx, &received, &mut scratch);
            if let Action::Reply { len, dest, .. } = answer.action
                && let Some(found) = candidate(
                    &conflicts,
                    &image,
                    &leases,
                    &received,
                    &scratch.reply[..len],
                    now,
                )
                && conflicts.park(&Parking {
                    request: bytes,
                    source: received.source,
                    local: interface,
                    mode: ListenMode::Relay,
                    listener: 0,
                    worker: 0,
                    reply: &scratch.reply[..len],
                    dest,
                    candidate: found,
                    received: Instant::now(),
                })
            {
                parked += 1;
                let ready = conflicts.pending().next_ready().expect("a parked slot");
                assert!(
                    conflicts
                        .pending()
                        .take(ready.index, ready.generation, &mut taken)
                );
            }
            if let Some(len) = rules::identity_of(bytes, &mut identity)
                && conflicts.decline_allowed(&identity[..len], Instant::now())
            {
                declines += 1;
                conflicts.declined(&Report {
                    kind: ReportKind::Decline,
                    vrf: scope.vrf,
                    prefix: scope.prefix,
                    addr: Ipv4Addr::new(192, 0, 2, 150),
                    mac: None,
                    at: now,
                });
            }
        }
    };
    step();
    let region = Region::new(GLOBAL);
    for _ in 0..20 {
        step();
    }
    let stats = region.change();
    assert_eq!(
        (
            stats.allocations,
            stats.reallocations,
            stats.bytes_allocated
        ),
        (0, 0, 0),
        "the worker's step of conflict detection"
    );
    assert!(parked > 0, "offers were parked");
    assert!(declines > 0, "declines were counted");
}

/// The requests of `fixtures/requests/*.hex` (WP7.3), in name order.
fn corpus() -> Vec<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/requests");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the corpus")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".hex").map(str::to_owned)
        })
        .collect();
    names.sort();
    names
        .iter()
        .map(|name| fixture(&format!("requests/{name}")))
        .collect()
}

/// The codec's sections (WP7.1a).
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
