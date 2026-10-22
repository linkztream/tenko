//! Classes, policies, network boot and the reservation identity through the engine
//! (WP8.4, plan section 2.4, DHCP-03 and DHCP-05), in the world of `class_world`: a
//! vendor-class policy and a MAC-wildcard policy select their range, options and lease
//! time; a scope and a pool admit their classes only; PXE, iPXE and UEFI HTTP boot get the
//! boot file of their architecture with `siaddr`, `file` and option 60; PXELINUX's options
//! go out unasked; proxy DHCP answers without an address; a reservation keyed by MAC holds
//! for a client that sends option 61, one keyed by client identifier only for that
//! identifier, and the latter wins where both exist.

mod class_world;

use std::net::{Ipv4Addr, SocketAddrV4};

use class_world::{Ask, BOOT_SERVER, RELAY_K, SERVER, World, duid_id, ip, mac, type1_id};
use tenko_dhcp::v4::{
    Message, MessageType, code,
    engine::{Action, Destination, DropReason, IgnoreReason, Scratch, boot},
};

/// The reply of an answer, parsed.
fn reply<'a>(action: &Action, scratch: &'a Scratch) -> Message<'a> {
    let (Action::Reply { len, .. } | Action::CommitThenReply { len, .. }) = *action else {
        panic!("a reply, not {action:?}");
    };
    Message::parse(&scratch.reply[..len]).expect("the reply parses")
}

fn offer(world: &World, ask: &Ask, scratch: &mut Scratch) -> Ipv4Addr {
    let answer = world.run(&ask.bytes(), scratch);
    let message = reply(&answer.action, scratch);
    assert_eq!(
        message.message_type().expect("53"),
        Some(MessageType::Offer)
    );
    message.yiaddr()
}

fn in_range(addr: Ipv4Addr, first: &str, last: &str) -> bool {
    ip(first) <= addr && addr <= ip(last)
}

#[test]
fn a_vendor_class_policy_selects_its_range_and_options() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // Eight clients: the offers held keep their addresses, and the range has ten.
    for client in 0x60..0x68 {
        let printer = Ask {
            vendor_class: Some(b"Printer-Laser-2".to_vec()),
            ..Ask::discover(client)
        };
        let answer = world.run(&printer.bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        assert!(
            in_range(message.yiaddr(), "192.0.2.150", "192.0.2.159"),
            "{}",
            message.yiaddr()
        );
        assert_eq!(
            message.domain_name().expect("15"),
            Some(&b"printers.example.test"[..])
        );
        // A client outside the class never gets an address of the policy's range.
        let laptop = Ask {
            vendor_class: Some(b"MSFT 5.0".to_vec()),
            ..Ask::discover(client)
        };
        let answer = world.run(&laptop.bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        let addr = message.yiaddr();
        assert!(in_range(addr, "192.0.2.100", "192.0.2.199"), "{addr}");
        assert!(!in_range(addr, "192.0.2.150", "192.0.2.159"), "{addr}");
        assert_eq!(
            message.domain_name().expect("15"),
            Some(&b"example.test"[..])
        );
    }
}

/// The DDNS settings the matcher decides go to the lease row's change (the Slice 8
/// follow-ups): a policy's, else none for the scope's.
#[test]
fn the_policys_ddns_settings_go_to_the_lease_row() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let mut acked = |ask: Ask| {
        let addr = offer(&world, &ask, &mut scratch);
        let request = Ask {
            kind: MessageType::Request,
            requested: Some(addr),
            server_id: Some(SERVER),
            ..ask
        };
        let answer = world.run(&request.bytes(), &mut scratch);
        assert!(
            matches!(answer.action, Action::CommitThenReply { .. }),
            "{:?}",
            answer.action
        );
        scratch.change.ddns_policy.clone()
    };
    // The printers' policy turns DDNS off while scope L has it on.
    let printer = acked(Ask {
        vendor_class: Some(b"Printer-Laser-2".to_vec()),
        ..Ask::discover(0x70)
    });
    assert_eq!(printer.map(|ddns| ddns.enabled), Some(false));
    // The iot policy's own settings.
    let sensor = acked(Ask::discover(0x45)).expect("the policy's settings");
    assert!(sensor.enabled);
    assert_eq!(sensor.ttl, Some(60));
    // No policy with DDNS settings: the scope's apply (none recorded).
    assert_eq!(acked(Ask::discover(0x46)), None);
}

#[test]
fn a_mac_wildcard_policy_sets_the_lease_time() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // 00:00:5e:00:53:45 matches 00:00:5e:*:*:45.
    let answer = world.run(&Ask::discover(0x45).bytes(), &mut scratch);
    assert_eq!(
        reply(&answer.action, &scratch).lease_time().expect("51"),
        Some(600)
    );
    let answer = world.run(&Ask::discover(0x46).bytes(), &mut scratch);
    assert_eq!(
        reply(&answer.action, &scratch).lease_time().expect("51"),
        Some(86_400)
    );
}

#[test]
fn a_scope_and_a_pool_admit_their_classes_only() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // Scope K admits printers only.
    let other = Ask {
        giaddr: Some(RELAY_K),
        ..Ask::discover(0x70)
    };
    let answer = world.run_from(&other.bytes(), SocketAddrV4::new(RELAY_K, 67), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::Filtered));
    let printer = Ask {
        vendor_class: Some(b"Printer".to_vec()),
        ..other
    };
    let answer = world.run_from(
        &printer.bytes(),
        SocketAddrV4::new(RELAY_K, 67),
        &mut scratch,
    );
    let addr = reply(&answer.action, &scratch).yiaddr();
    assert!(in_range(addr, "198.51.100.100", "198.51.100.199"), "{addr}");
    // Pool .200 to .209 of scope L is for PXE clients: others never get an address of it.
    for client in 0..64 {
        let addr = offer(&world, &Ask::discover(client), &mut scratch);
        assert!(!in_range(addr, "192.0.2.200", "192.0.2.209"), "{addr}");
    }
}

#[test]
fn a_pxe_bios_client_gets_its_boot_file_by_architecture() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let answer = world.run(&Ask::pxe(0x80, 0).bytes(), &mut scratch);
    let message = reply(&answer.action, &scratch);
    assert_eq!(message.siaddr(), BOOT_SERVER);
    assert_eq!(
        message.boot_file_str().expect("file"),
        Some("undionly.kpxe")
    );
    assert_eq!(
        message.bootfile_name().expect("67"),
        Some(&b"undionly.kpxe"[..])
    );
    assert_eq!(
        message.vendor_class_identifier().expect("60"),
        Some(boot::PXE_CLIENT)
    );
    assert_eq!(
        message.vendor_specific().expect("43"),
        Some(&boot::PXE_VENDOR_DEFAULT[..])
    );
    // PXELINUX's options (RFC 5071) go out unasked.
    assert_eq!(
        message.option(209).expect("209"),
        Some(&b"pxelinux.cfg/default"[..])
    );
    assert_eq!(message.option(210).expect("210"), Some(&b"/tftpboot/"[..]));
}

#[test]
fn a_pxe_uefi_client_gets_the_efi_boot_file() {
    let world = World::new();
    let mut scratch = Scratch::new();
    for arch in [7, 9] {
        let answer = world.run(&Ask::pxe(0x81, arch).bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        assert_eq!(message.boot_file_str().expect("file"), Some("ipxe.efi"));
        assert_eq!(message.siaddr(), BOOT_SERVER);
        assert_eq!(message.option(209).expect("209"), None);
    }
}

#[test]
fn ipxe_is_detected_by_its_user_class_and_chained_to_its_script() {
    let world = World::new();
    let mut scratch = Scratch::new();
    for arch in [0, 7] {
        let ipxe = Ask {
            user_class: Some(b"iPXE".to_vec()),
            ..Ask::pxe(0x82, arch)
        };
        let answer = world.run(&ipxe.bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        assert_eq!(
            message.boot_file_str().expect("file"),
            Some("http://192.0.2.5/boot.ipxe")
        );
    }
}

#[test]
fn a_uefi_http_boot_client_gets_its_url_and_option_60() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let http = Ask {
        vendor_class: Some(b"HTTPClient:Arch:00016:UNDI:003001".to_vec()),
        architecture: Some(16),
        ..Ask::discover(0x83)
    };
    let answer = world.run(&http.bytes(), &mut scratch);
    let message = reply(&answer.action, &scratch);
    assert_eq!(
        message.boot_file_str().expect("file"),
        Some("http://192.0.2.5/ipxe.efi")
    );
    assert_eq!(
        message.vendor_class_identifier().expect("60"),
        Some(boot::HTTP_CLIENT)
    );
    // Option 43 is PXE's; an HTTP boot client gets none.
    assert_eq!(message.vendor_specific().expect("43"), None);
}

#[test]
fn a_client_that_is_no_boot_client_gets_no_boot_fields() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let answer = world.run(&Ask::discover(0x84).bytes(), &mut scratch);
    let message = reply(&answer.action, &scratch);
    assert_eq!(message.siaddr(), Ipv4Addr::UNSPECIFIED);
    assert!(
        message
            .boot_file_str()
            .expect("file")
            .is_none_or(str::is_empty)
    );
    assert_eq!(message.vendor_class_identifier().expect("60"), None);
}

#[test]
fn proxy_dhcp_answers_boot_clients_without_an_address() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // A DISCOVER through the relay: an OFFER with yiaddr 0 and the boot information.
    let answer = world.proxy(
        &Ask::pxe(0x85, 7).bytes(),
        SocketAddrV4::new(class_world::RELAY_L, 67),
        &mut scratch,
    );
    let Action::Reply { kind, dest, .. } = answer.action else {
        panic!("a reply: {answer:?}");
    };
    assert_eq!(kind, MessageType::Offer);
    assert_eq!(
        dest,
        Destination::Relay(SocketAddrV4::new(class_world::RELAY_L, 67))
    );
    let message = reply(&answer.action, &scratch);
    assert_eq!(message.yiaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(message.lease_time().expect("51"), None);
    assert_eq!(message.boot_file_str().expect("file"), Some("ipxe.efi"));
    assert_eq!(message.siaddr(), BOOT_SERVER);
    assert_eq!(
        message.vendor_class_identifier().expect("60"),
        Some(boot::PXE_CLIENT)
    );
    assert_eq!(message.server_identifier().expect("54"), Some(SERVER));
    assert!(
        message
            .option(code::CLIENT_MACHINE_IDENTIFIER)
            .expect("97")
            .is_some()
    );
    // The boot server discovery on port 4011: a REQUEST from a client with an address,
    // answered with an ACK to the port it came from.
    let request = Ask {
        kind: MessageType::Request,
        giaddr: None,
        ciaddr: Some(ip("192.0.2.140")),
        ..Ask::pxe(0x85, 7)
    };
    let source = SocketAddrV4::new(ip("192.0.2.140"), 4011);
    let answer = world.proxy(&request.bytes(), source, &mut scratch);
    let Action::Reply { kind, dest, .. } = answer.action else {
        panic!("a reply: {answer:?}");
    };
    assert_eq!(
        (kind, dest),
        (MessageType::Ack, Destination::Client(source))
    );
    let message = reply(&answer.action, &scratch);
    assert_eq!(message.ciaddr(), ip("192.0.2.140"));
    assert_eq!(message.yiaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(message.boot_file_str().expect("file"), Some("ipxe.efi"));
    // Not a boot client: nothing.
    let answer = world.proxy(
        &Ask::discover(0x86).bytes(),
        SocketAddrV4::new(class_world::RELAY_L, 67),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Ignore(IgnoreReason::NotBootClient));
}

#[test]
fn a_mac_reservation_holds_for_a_client_that_sends_option_61() {
    let mut scratch = Scratch::new();
    // Without option 61, with option 61 of type 1 (Windows), with a DUID-style one; a world
    // each, since an offer holds the address for the identity it was made to.
    let mut duid = duid_id();
    *duid.last_mut().expect("a DUID") = 0x20;
    for id in [None, Some(type1_id(0x20)), Some(duid)] {
        let world = World::new();
        let ask = Ask {
            client_id: id.clone(),
            ..Ask::discover(0x20)
        };
        let answer = world.run(&ask.bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        assert_eq!(message.yiaddr(), ip("192.0.2.20"), "{id:?}");
        assert_eq!(
            message.domain_name().expect("15"),
            Some(&b"reserved.example.test"[..])
        );
        // The REQUEST in SELECTING for the reserved address is acknowledged.
        let request = Ask {
            kind: MessageType::Request,
            requested: Some(ip("192.0.2.20")),
            server_id: Some(SERVER),
            ..ask
        };
        let answer = world.run(&request.bytes(), &mut scratch);
        let message = reply(&answer.action, &scratch);
        assert_eq!(message.message_type().expect("53"), Some(MessageType::Ack));
        assert_eq!(message.yiaddr(), ip("192.0.2.20"));
    }
    // Another client asking for the reserved address does not get it.
    let world = World::new();
    let squatter = Ask {
        kind: MessageType::Request,
        requested: Some(ip("192.0.2.20")),
        server_id: Some(SERVER),
        ..Ask::discover(0x21).with_id(type1_id(0x21))
    };
    let answer = world.run(&squatter.bytes(), &mut scratch);
    let message = reply(&answer.action, &scratch);
    assert_eq!(message.message_type().expect("53"), Some(MessageType::Nak));
}

#[test]
fn a_client_identifier_reservation_holds_for_that_identifier_only() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let ask = Ask::discover(0x30).with_id(duid_id());
    assert_eq!(offer(&world, &ask, &mut scratch), ip("192.0.2.30"));
    // The same MAC without the identifier, or with another one, is a pool client.
    for id in [None, Some(type1_id(0x30))] {
        let ask = Ask {
            client_id: id,
            ..Ask::discover(0x30)
        };
        let addr = offer(&world, &ask, &mut scratch);
        assert!(in_range(addr, "192.0.2.100", "192.0.2.199"), "{addr}");
    }
}

#[test]
fn the_client_identifier_reservation_wins_over_the_mac_one() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let ask = Ask::discover(0x31).with_id(type1_id(0x31));
    assert_eq!(offer(&world, &ask, &mut scratch), ip("192.0.2.32"));
    // Without option 61 the MAC's reservation holds.
    assert_eq!(
        offer(&world, &Ask::discover(0x31), &mut scratch),
        ip("192.0.2.31")
    );
    assert_eq!(mac(0x31)[5], 0x31);
}

#[test]
fn a_proxy_listener_answers_the_boot_server_discovery_on_its_port() {
    use std::{net::UdpSocket, sync::Arc, time::Duration};

    use tenko_core::NodeId;
    use tenko_dhcp::{
        server::{DhcpServer, ServerConfig, SocketLayout},
        store::{LeaseStore, MemLeaseStore},
    };

    let world = World::new();
    let config = ServerConfig {
        workers: 1,
        layout: SocketLayout::Shared,
        proxy: vec![SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)],
        ..ServerConfig::default()
    };
    let store: Arc<dyn LeaseStore> = Arc::new(MemLeaseStore::with_capacity(NodeId(1), 16));
    let server = DhcpServer::start(
        &config,
        world.image.clone(),
        world.leases.clone(),
        store,
        None,
    )
    .expect("start");
    let address = server.proxies()[0];
    assert_ne!(address.port(), 0);
    let client = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let request = Ask {
        kind: MessageType::Request,
        giaddr: None,
        ciaddr: Some(ip("192.0.2.140")),
        ..Ask::pxe(0x87, 0)
    };
    client.send_to(&request.bytes(), address).expect("send");
    let mut buf = [0u8; 1500];
    let (len, from) = client.recv_from(&mut buf).expect("an answer");
    assert_eq!(from, std::net::SocketAddr::V4(address));
    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(message.message_type().expect("53"), Some(MessageType::Ack));
    assert_eq!(message.yiaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(
        message.boot_file_str().expect("file"),
        Some("undionly.kpxe")
    );
    server.stop();
}
