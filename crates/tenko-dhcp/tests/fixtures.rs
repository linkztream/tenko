//! The captured messages of `fixtures/`: what the view reads from each, the byte-exact
//! round trip through the builder, and the replies the builder writes compared octet for
//! octet with the fixtures written independently of it.

mod support;

use std::net::Ipv4Addr;

use support::{WELL_FORMED, fixture, rebuild};
use tenko_dhcp::v4::{
    Area, BOOTREPLY, BOOTREQUEST, ClientFqdn, DecodeError, DomainSearch, Duid, Message,
    MessageBuilder, MessageType, Route, WireName, code,
};

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

fn name(text: &str) -> WireName {
    WireName::from_str_text(text).expect("a name")
}

#[test]
fn every_well_formed_fixture_round_trips() {
    for fixture_name in WELL_FORMED {
        let bytes = fixture(fixture_name);
        let message = Message::parse(&bytes).expect(fixture_name);
        message.validate().expect(fixture_name);
        let mut out = vec![0xa5; bytes.len() + 64];
        let len = rebuild(&message, &mut out);
        assert_eq!(&out[..len], &bytes[..], "{fixture_name}");
    }
}

#[test]
fn windows_discover() {
    let bytes = fixture("windows-discover");
    assert_eq!(bytes.len(), 300);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.op(), BOOTREQUEST);
    assert_eq!(message.xid(), 0x3903_f326);
    assert!(!message.broadcast());
    assert_eq!(message.mac(), Ok([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]));
    assert_eq!(
        message.chaddr(),
        Ok(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01][..])
    );
    assert_eq!(message.message_type(), Ok(Some(MessageType::Discover)));
    let client_id = message.client_identifier().expect("ok").expect("61");
    assert_eq!(
        client_id.hardware(),
        Some((1, &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01][..]))
    );
    assert_eq!(client_id.iaid_duid(), None);
    assert_eq!(message.max_message_size(), Ok(Some(1500)));
    assert_eq!(message.max_reply_len(), 1472);
    assert_eq!(message.host_name(), Ok(Some(&b"WS-01"[..])));
    assert_eq!(
        message.vendor_class_identifier(),
        Ok(Some(&b"MSFT 5.0"[..]))
    );
    assert_eq!(
        message.parameter_request_list(),
        Ok(Some(
            &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252][..]
        ))
    );
    assert_eq!(message.server_identifier(), Ok(None));
    assert_eq!(message.server_name(), Ok(Some(&b""[..])));
    assert_eq!(message.boot_file_str(), Ok(Some("")));
    let codes: Vec<u8> = message
        .options()
        .map(|option| option.expect("ok").code)
        .collect();
    assert_eq!(codes, [53, 61, 57, 12, 60, 55]);
}

#[test]
fn linux_discover_with_a_duid() {
    let bytes = fixture("linux-discover-duid");
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.len(), bytes.len());
    assert_eq!(message.secs(), 3);
    let client_id = message.client_identifier().expect("ok").expect("61");
    assert_eq!(client_id.kind(), 255);
    assert_eq!(client_id.hardware(), None);
    let (iaid, duid) = client_id.iaid_duid().expect("RFC 4361 form");
    assert_eq!(iaid, 0x8a2b_5c01);
    assert_eq!(duid.kind(), Duid::EN);
    assert_eq!(duid.enterprise(), Some(43793));
    assert_eq!(duid.link_layer(), None);
    assert_eq!(duid.as_bytes().len(), 14);
    assert_eq!(message.max_reply_len(), 1444);
    assert_eq!(message.host_name(), Ok(Some(&b"host-02"[..])));
}

#[test]
fn relayed_request() {
    let bytes = fixture("relayed-request");
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.hops(), 1);
    assert_eq!(message.giaddr(), ip("192.0.2.1"));
    assert_eq!(message.message_type(), Ok(Some(MessageType::Request)));
    assert_eq!(message.requested_address(), Ok(Some(ip("192.0.2.50"))));
    assert_eq!(message.server_identifier(), Ok(Some(ip("198.51.100.10"))));
    let fqdn = message.client_fqdn().expect("ok").expect("81");
    assert!(fqdn.server_updates() && fqdn.encoded());
    assert!(!fqdn.overridden() && !fqdn.no_update());
    assert_eq!((fqdn.rcode1(), fqdn.rcode2()), (0, 0));
    assert!(fqdn.name().is_absolute());
    assert_eq!(fqdn.name().to_string(), "host-01.example.test");
    let relay = message.relay_agent_info().expect("ok").expect("82");
    assert_eq!(
        relay.circuit_id(),
        Some(&[0x00, 0x04, 0x00, 0x0a, 0x00, 0x03][..])
    );
    assert_eq!(
        relay.remote_id(),
        Some(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0xfe][..])
    );
    assert_eq!(relay.link_selection(), None);
    assert_eq!(relay.server_id_override(), None);
    assert_eq!(relay.sub_options().into_iter().count(), 2);
    assert_eq!(message.max_reply_len(), 548);
}

#[test]
fn inform() {
    let bytes = fixture("inform");
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.message_type(), Ok(Some(MessageType::Inform)));
    assert_eq!(message.ciaddr(), ip("203.0.113.20"));
    assert_eq!(message.yiaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(message.giaddr(), Ipv4Addr::UNSPECIFIED);
}

#[test]
fn pxe_discover() {
    let bytes = fixture("pxe-discover");
    let message = Message::parse(&bytes).expect("parse");
    assert!(message.broadcast());
    assert_eq!(message.max_reply_len(), 1232);
    let architectures = message.client_architectures().expect("ok").expect("93");
    assert_eq!(architectures.first(), 7);
    assert_eq!(architectures.iter().collect::<Vec<_>>(), [7]);
    let interface = message.network_interface().expect("ok").expect("94");
    assert_eq!(
        (interface.kind, interface.major, interface.minor),
        (1, 3, 16)
    );
    let machine = message.machine_id().expect("ok").expect("97");
    assert_eq!(machine.kind(), 0);
    assert_eq!(
        machine.guid().map(|guid| guid[0..4].to_vec()),
        Some(vec![0x4c, 0x4c, 0x45, 0x44])
    );
    assert!(
        message
            .vendor_class_identifier()
            .expect("ok")
            .expect("60")
            .starts_with(b"PXEClient")
    );
}

#[test]
fn rfc3397_split_search_list() {
    let bytes = fixture("rfc3397-search-split");
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(
        message.domain_search(),
        Err(DecodeError::Split {
            code: code::DOMAIN_SEARCH
        })
    );
    let mut buf = [0; 64];
    let data = message
        .option_data(code::DOMAIN_SEARCH, &mut buf)
        .expect("ok")
        .expect("119");
    assert_eq!(data.len(), 30);
    let list = DomainSearch::parse(data).expect("a list");
    assert!(
        list.iter()
            .eq([name("eng.example.test."), name("marketing.example.test.")])
    );
    let mut small = [0; 29];
    assert_eq!(
        message.option_data(code::DOMAIN_SEARCH, &mut small),
        Err(DecodeError::BufferTooSmall { needed: 30 })
    );
    // One instance comes from the message itself.
    assert_eq!(
        message.option_data(code::MESSAGE_TYPE, &mut small),
        Ok(Some(&[5][..]))
    );
    assert_eq!(message.option_data(code::ROUTERS, &mut small), Ok(None));
}

#[test]
fn the_ack_to_the_relayed_request() {
    let request_bytes = fixture("relayed-request");
    let request = Message::parse(&request_bytes).expect("parse");
    let mut buf = [0xa5; 1500];
    let mut reply = MessageBuilder::reply(&mut buf, &request, MessageType::Ack).expect("reply");
    assert_eq!(reply.limit(), 548);
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
        .and_then(|b| {
            b.domain_search(&[name("eng.example.test."), name("marketing.example.test.")])
        })
        .expect("options");
    let fqdn = request.client_fqdn().expect("ok").expect("81");
    reply
        .client_fqdn(ClientFqdn::FLAG_S | ClientFqdn::FLAG_E, &fqdn.name())
        .expect("81");
    let relay = request.relay_agent_info().expect("ok").expect("82");
    reply.relay_agent_info(relay.as_bytes()).expect("82");
    let len = reply.finish().expect("finish");
    assert_eq!(&buf[..len], &fixture("ack-fqdn-search")[..]);

    let ack = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(ack.op(), BOOTREPLY);
    assert_eq!(ack.xid(), request.xid());
    assert_eq!(ack.giaddr(), request.giaddr());
    assert_eq!(ack.chaddr(), request.chaddr());
    let fqdn = ack.client_fqdn().expect("ok").expect("81");
    assert_eq!((fqdn.rcode1(), fqdn.rcode2()), (255, 255));
    let last = ack.options().last().expect("an option").expect("ok");
    assert_eq!(last.code, code::RELAY_AGENT_INFORMATION);
}

#[test]
fn the_offer_with_overload() {
    let discover_bytes = fixture("windows-discover");
    let discover = Message::parse(&discover_bytes).expect("parse");
    let mut buf = [0xa5; 1500];
    let mut offer =
        MessageBuilder::reply(&mut buf[..300], &discover, MessageType::Offer).expect("reply");
    offer
        .allow_overload()
        .expect("overload")
        .yiaddr(ip("192.0.2.60"))
        .server_identifier(ip("198.51.100.10"))
        .and_then(|b| b.lease_time(3600))
        .and_then(|b| b.subnet_mask(ip("255.255.255.0")))
        .and_then(|b| b.routers(&[ip("192.0.2.1")]))
        .and_then(|b| b.domain_name_servers(&[ip("192.0.2.53"), ip("198.51.100.53")]))
        .and_then(|b| b.domain_name(b"example.test"))
        .and_then(|b| b.ntp_servers(&[ip("192.0.2.123")]))
        .and_then(|b| {
            b.domain_search(&[name("eng.example.test."), name("marketing.example.test.")])
        })
        .and_then(|b| b.vendor_specific(&(1..=50).collect::<Vec<u8>>()))
        .and_then(|b| b.tftp_server_name(b"tftp.example.test"))
        .and_then(|b| b.renewal_time(1800))
        .and_then(|b| b.bootfile_name(b"boot/x64/bootfile.efi"))
        .and_then(|b| b.option(46, &[8]))
        .and_then(|b| b.pad_to(300))
        .expect("options");
    let len = offer.finish().expect("finish");
    assert_eq!(&buf[..len], &fixture("offer-overload")[..]);

    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(message.overload(), Ok(3));
    assert_eq!(message.server_name(), Ok(None));
    assert_eq!(message.boot_file(), Ok(None));
    let areas: Vec<(u8, Area)> = message
        .options()
        .map(|option| option.map(|option| (option.code, option.area)).expect("ok"))
        .collect();
    assert_eq!(
        areas,
        [
            (53, Area::Options),
            (54, Area::Options),
            (51, Area::Options),
            (1, Area::Options),
            (3, Area::Options),
            (6, Area::Options),
            (15, Area::Options),
            (46, Area::Options),
            (52, Area::Options),
            (42, Area::File),
            (119, Area::File),
            (43, Area::File),
            (66, Area::File),
            (58, Area::File),
            (67, Area::Sname),
        ]
    );
    assert_eq!(
        message.bootfile_name(),
        Ok(Some(&b"boot/x64/bootfile.efi"[..]))
    );
    assert_eq!(message.renewal_time(), Ok(Some(1800)));
}

#[test]
fn the_ack_with_split_routes() {
    let inform_bytes = fixture("inform");
    let inform = Message::parse(&inform_bytes).expect("parse");
    let mut routes = vec![
        Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            router: ip("192.0.2.1"),
        },
        Route {
            destination: ip("198.51.100.0"),
            prefix_len: 24,
            router: ip("192.0.2.254"),
        },
        Route {
            destination: ip("198.51.100.128"),
            prefix_len: 25,
            router: ip("192.0.2.254"),
        },
        Route {
            destination: ip("203.0.113.0"),
            prefix_len: 27,
            router: ip("192.0.2.254"),
        },
        Route {
            destination: ip("203.0.113.32"),
            prefix_len: 28,
            router: ip("192.0.2.254"),
        },
        Route {
            destination: ip("203.0.113.64"),
            prefix_len: 30,
            router: ip("192.0.2.254"),
        },
    ];
    for host in 100..125 {
        routes.push(Route {
            destination: Ipv4Addr::new(203, 0, 113, host),
            prefix_len: 32,
            router: ip("192.0.2.254"),
        });
    }
    let mut buf = [0; 1500];
    let mut ack = MessageBuilder::reply(&mut buf, &inform, MessageType::Ack).expect("reply");
    ack.ciaddr(inform.ciaddr())
        .server_identifier(ip("198.51.100.10"))
        .and_then(|b| b.subnet_mask(ip("255.255.255.0")))
        .and_then(|b| b.classless_routes(&routes))
        .expect("options");
    let len = ack.finish().expect("finish");
    assert_eq!(&buf[..len], &fixture("ack-split-routes")[..]);

    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(
        message.classless_routes().map(|routes| routes.is_some()),
        Err(DecodeError::Split {
            code: code::CLASSLESS_STATIC_ROUTES
        })
    );
    let mut concatenated = [0; 512];
    let data = message
        .option_data(code::CLASSLESS_STATIC_ROUTES, &mut concatenated)
        .expect("ok")
        .expect("121");
    let parsed =
        tenko_dhcp::v4::Routes::parse(code::CLASSLESS_STATIC_ROUTES, data).expect("routes");
    assert!(parsed.iter().eq(routes.iter().copied()));
}
