//! The typed options the fixtures do not carry, and the builder's size, split and
//! overload rules.

mod support;

use std::net::Ipv4Addr;

use support::fixture;
use tenko_dhcp::v4::{
    BOOTP_MIN_LEN, ClientFqdn, ClientId, DecodeError, EncodeError, Message, MessageBuilder,
    MessageType, OPTIONS_START, RelayAgentInfo, Route, Routes, UserClass, VendorClasses,
    VendorInfos, WireName, code, encode_classless_routes,
};

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

/// A DHCPREQUEST with the given options after option 53, in a buffer of its own.
fn request_with(options: &[(u8, &[u8])]) -> Vec<u8> {
    let mut buf = vec![0; 1500];
    let mut builder = MessageBuilder::new(&mut buf, 1500).expect("builder");
    builder.op(1).htype(1).hlen(6).xid(7);
    builder.message_type(MessageType::Request).expect("53");
    for (code, data) in options {
        builder.option(*code, data).expect("room");
    }
    let len = builder.finish().expect("finish");
    buf.truncate(len);
    buf
}

#[test]
fn message_types() {
    for value in 0..=255u8 {
        assert_eq!(MessageType::from(value).code(), value);
    }
    assert_eq!(MessageType::from(8), MessageType::Inform);
    assert_eq!(MessageType::from(10), MessageType::Other(10));
}

#[test]
fn relay_agent_sub_options() {
    let value = [
        1, 2, 0x01, 0x02, // circuit ID
        5, 4, 192, 0, 2, 0, // link selection (RFC 3527)
        6, 3, b's', b'u', b'b', // subscriber ID (RFC 3993)
        11, 4, 192, 0, 2, 1, // server identifier override (RFC 5107)
        12, 5, 0, 0, 0x5e, 0x00, 0x53, // relay ID (RFC 6925)
    ];
    let bytes = request_with(&[(code::RELAY_AGENT_INFORMATION, &value)]);
    let message = Message::parse(&bytes).expect("parse");
    let relay = message.relay_agent_info().expect("ok").expect("82");
    assert_eq!(relay.circuit_id(), Some(&[1, 2][..]));
    assert_eq!(relay.remote_id(), None);
    assert_eq!(relay.link_selection(), Some(ip("192.0.2.0")));
    assert_eq!(relay.subscriber_id(), Some(&b"sub"[..]));
    assert_eq!(relay.server_id_override(), Some(ip("192.0.2.1")));
    assert_eq!(relay.relay_id(), Some(&[0, 0, 0x5e, 0x00, 0x53][..]));
    assert_eq!(relay.as_bytes(), &value[..]);
    let codes: Vec<u8> = relay.sub_options().into_iter().map(|(c, _)| c).collect();
    assert_eq!(codes, [1, 5, 6, 11, 12]);

    let bad = DecodeError::BadValue {
        code: code::RELAY_AGENT_INFORMATION,
    };
    assert_eq!(RelayAgentInfo::parse(&[1, 3, 0]), Err(bad));
    assert_eq!(RelayAgentInfo::parse(&[1]), Err(bad));
    assert_eq!(RelayAgentInfo::parse(&[5, 3, 192, 0, 2]), Err(bad));
    assert_eq!(
        RelayAgentInfo::parse(&[]),
        Err(DecodeError::BadLength {
            code: code::RELAY_AGENT_INFORMATION,
            len: 0
        })
    );
}

#[test]
fn user_class_in_both_forms() {
    let rfc = UserClass::parse(b"\x04iPXE\x03lab").expect("77");
    let classes: Vec<&[u8]> = rfc.classes().expect("RFC 3004 form").into_iter().collect();
    assert_eq!(classes, [&b"iPXE"[..], &b"lab"[..]]);
    let plain = UserClass::parse(b"iPXE").expect("77");
    assert_eq!(plain.classes(), None);
    assert_eq!(plain.as_bytes(), b"iPXE");
    assert!(UserClass::parse(b"").is_err());
}

#[test]
fn vendor_identifying_options() {
    let classes = [0, 0, 0x0d, 0xe9, 6, 5, b'c', b'l', b'a', b's', b's'];
    let parsed = VendorClasses::parse(&classes).expect("124");
    let vendor = parsed.iter().next().expect("a vendor");
    assert_eq!(vendor.enterprise, 3561);
    let inner: Vec<&[u8]> = vendor.classes().expect("classes").into_iter().collect();
    assert_eq!(inner, [&b"class"[..]]);
    assert!(VendorClasses::parse(&classes[..10]).is_err());
    assert!(VendorClasses::parse(&[]).is_err());

    let infos = [
        0, 0, 0x0d, 0xe9, 7, 1, 2, 0xab, 0xcd, 2, 1, 0xef, 0, 0, 0, 9, 0,
    ];
    let parsed = VendorInfos::parse(&infos).expect("125");
    let vendors: Vec<_> = parsed.iter().collect();
    assert_eq!(vendors.len(), 2);
    assert_eq!(vendors[0].enterprise, 3561);
    assert_eq!(vendors[0].sub_options.get(2), Some(&[0xef][..]));
    assert_eq!(vendors[1].enterprise, 9);
    assert_eq!(vendors[1].sub_options.into_iter().count(), 0);
    let mut bad = infos;
    bad[6] = 9;
    assert!(VendorInfos::parse(&bad).is_err());
}

#[test]
fn client_identifiers_and_duids() {
    let llt = [
        255, 0, 0, 0, 1, 0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 0, 0x5e, 0, 0x53, 9,
    ];
    let id = ClientId::parse(&llt).expect("61");
    let (iaid, duid) = id.iaid_duid().expect("RFC 4361");
    assert_eq!(iaid, 1);
    assert_eq!(duid.link_layer(), Some((1, &[0, 0, 0x5e, 0, 0x53, 9][..])));
    let ll = [255, 0, 0, 0, 2, 0, 3, 0, 1, 0, 0, 0x5e, 0, 0x53, 9];
    let (_, duid) = ClientId::parse(&ll).expect("61").iaid_duid().expect("DUID");
    assert_eq!(duid.link_layer(), Some((1, &[0, 0, 0x5e, 0, 0x53, 9][..])));
    assert_eq!(duid.enterprise(), None);
    let text = ClientId::parse(b"\x00host-01").expect("61");
    assert_eq!(text.hardware(), None);
    assert!(ClientId::parse(&[1]).is_err());
    assert!(ClientId::parse(&[255, 0, 0, 0, 1, 0]).is_err());
}

#[test]
fn client_fqdn_in_ascii_and_partial_wire_form() {
    let ascii = ClientFqdn::parse(b"\x00\x00\x00ws-01.example.test.\x00").expect("81");
    assert!(!ascii.encoded());
    assert!(ascii.name().is_absolute());
    assert_eq!(ascii.name().to_string(), "ws-01.example.test");
    let partial = ClientFqdn::parse(b"\x04\x00\x00\x05ws-01").expect("81");
    assert!(!partial.name().is_absolute());
    assert_eq!(partial.name().to_string(), "ws-01");
    let empty = ClientFqdn::parse(&[ClientFqdn::FLAG_E, 0, 0]).expect("81");
    assert!(empty.name().is_empty());
    assert!(ClientFqdn::parse(b"\x04\x00\x00\x09ws").is_err());
    assert!(ClientFqdn::parse(b"\x00\x00").is_err());

    // The server answers in the client's encoding.
    let name = WireName::from_str_text("ws-01.example.test.").expect("name");
    let mut buf = [0; 600];
    let mut builder = MessageBuilder::new(&mut buf, 600).expect("builder");
    builder.client_fqdn(ClientFqdn::FLAG_S, &name).expect("81");
    let len = builder.finish().expect("finish");
    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(
        message.option(code::CLIENT_FQDN),
        Ok(Some(&b"\x01\xff\xffws-01.example.test."[..]))
    );
}

#[test]
fn remaining_typed_reads() {
    let bytes = request_with(&[
        (code::AUTO_CONFIGURE, &[1]),
        (code::SUBNET_SELECTION, &[192, 0, 2, 0]),
        (code::INTERFACE_MTU, &1500u16.to_be_bytes()),
        (code::BROADCAST_ADDRESS, &[192, 0, 2, 255]),
        (code::NTP_SERVERS, &[192, 0, 2, 123, 198, 51, 100, 123]),
        (code::TFTP_SERVER_NAME, b"tftp.example.test"),
        (
            code::MS_CLASSLESS_STATIC_ROUTES,
            &[24, 192, 0, 2, 192, 0, 2, 1],
        ),
        (code::USER_CLASS, b"\x04iPXE"),
    ]);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.auto_configure(), Ok(Some(1)));
    assert_eq!(message.subnet_selection(), Ok(Some(ip("192.0.2.0"))));
    assert_eq!(message.interface_mtu(), Ok(Some(1500)));
    assert_eq!(message.broadcast_address(), Ok(Some(ip("192.0.2.255"))));
    let ntp = message.ntp_servers().expect("ok").expect("42");
    assert_eq!(ntp.len(), 2);
    assert_eq!(
        ntp.iter().collect::<Vec<_>>(),
        [ip("192.0.2.123"), ip("198.51.100.123")]
    );
    assert_eq!(
        message.tftp_server_name(),
        Ok(Some(&b"tftp.example.test"[..]))
    );
    let routes: Vec<Route> = message
        .ms_classless_routes()
        .expect("ok")
        .expect("249")
        .iter()
        .collect();
    assert_eq!(
        routes,
        [Route {
            destination: ip("192.0.2.0"),
            prefix_len: 24,
            router: ip("192.0.2.1")
        }]
    );
    assert!(
        message
            .user_class()
            .expect("ok")
            .expect("77")
            .classes()
            .is_some()
    );
    assert_eq!(message.subnet_mask(), Ok(None));
    assert_eq!(message.domain_name(), Ok(None));
}

#[test]
fn rfc3442_route_encoding() {
    // RFC 3442, section 3: the widths of its examples on documentation addresses; the
    // destination bits after the prefix length are cleared on both sides.
    let routes = [
        (0, "0.0.0.0", &[0][..]),
        (8, "198.0.0.0", &[8, 198]),
        (16, "198.51.0.0", &[16, 198, 51]),
        (24, "198.51.100.0", &[24, 198, 51, 100]),
        (25, "198.51.100.128", &[25, 198, 51, 100, 128]),
        (32, "198.51.100.47", &[32, 198, 51, 100, 47]),
    ];
    for (prefix_len, destination, expected) in routes {
        let route = Route {
            destination: ip(destination),
            prefix_len,
            router: ip("192.0.2.1"),
        };
        let mut out = [0; 16];
        let len = encode_classless_routes(121, &[route], &mut out).expect("encode");
        assert_eq!(&out[..len - 4], expected);
        assert_eq!(&out[len - 4..len], &[192, 0, 2, 1]);
        let parsed: Vec<Route> = Routes::parse(121, &out[..len])
            .expect("parse")
            .iter()
            .collect();
        assert_eq!(parsed, [route]);
    }
    let sloppy = [24, 198, 51, 100, 192, 0, 2, 1];
    let mut sloppy_host = sloppy;
    sloppy_host[0] = 20;
    // A /20 keeps three octets; the bits after 20 are cleared.
    let parsed: Vec<Route> = Routes::parse(121, &sloppy_host)
        .expect("parse")
        .iter()
        .collect();
    assert_eq!(parsed[0].destination, ip("198.51.96.0"));
    assert!(Routes::parse(121, &[33, 1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    assert!(Routes::parse(121, &sloppy[..7]).is_err());
    assert!(Routes::parse(121, &[0, 1, 2, 3]).is_err());
}

#[test]
fn an_option_that_does_not_fit_leaves_the_message_unchanged() {
    let mut buf = [0; 548];
    let mut builder = MessageBuilder::new(&mut buf, 300).expect("builder");
    builder.message_type(MessageType::Ack).expect("53");
    let before = builder.len();
    // 300 - 240 = 60 octets, one for the end option: 3 are used, 56 remain.
    assert_eq!(
        builder.option(43, &[0; 55]).map(drop),
        Err(EncodeError::NoRoom { code: 43 })
    );
    assert_eq!(builder.len(), before);
    builder.option(43, &[7; 54]).expect("exactly fits");
    assert_eq!(builder.len(), 300);
    assert_eq!(
        builder.allow_overload().map(drop),
        Err(EncodeError::NoRoom { code: 52 })
    );
    let len = builder.finish().expect("finish");
    assert_eq!(len, 300);
    assert_eq!(buf[299], code::END);
}

#[test]
fn a_split_option_is_all_or_nothing() {
    let mut buf = [0xa5; 1000];
    let mut builder = MessageBuilder::new(&mut buf, 548).expect("builder");
    builder.allow_overload().expect("overload");
    // 548 - 240 - 4 = 304 octets in the options field, 127 in file, 63 in sname: the
    // first instance (257 octets) fits into the options field, the second (57) into file.
    builder.option(43, &[1; 310]).expect("257 + 57 octets");
    let len = builder.len();
    // An instance of 255 octets fits nowhere any more.
    assert_eq!(
        builder.option(125, &[2; 600]).map(drop),
        Err(EncodeError::NoRoom { code: 125 })
    );
    assert_eq!(builder.len(), len);
    let len = builder.finish().expect("finish");
    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(message.overload(), Ok(1), "the tail of 43 went to file");
    let mut concatenated = [0; 400];
    assert_eq!(
        message.option_data(43, &mut concatenated),
        Ok(Some(&[1; 310][..]))
    );
    assert!(
        message
            .options()
            .all(|option| option.expect("ok").code != 125)
    );
    assert!(message.sname_field().iter().all(|&b| b == 0));

    // A split option whose second instance does not fit is taken back whole.
    let mut buf = [0xa5; 1000];
    let mut builder = MessageBuilder::new(&mut buf, 548).expect("builder");
    builder.message_type(MessageType::Ack).expect("53");
    assert_eq!(
        builder.option(43, &[1; 400]).map(drop),
        Err(EncodeError::NoRoom { code: 43 })
    );
    let len = builder.finish().expect("finish");
    assert_eq!(len, OPTIONS_START + 4);
    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(message.options().count(), 1);
}

#[test]
fn fields_and_overload_exclude_each_other() {
    let mut buf = [0; 600];
    let mut builder = MessageBuilder::new(&mut buf, 300).expect("builder");
    builder.file(b"boot/bios/pxelinux.0").expect("file");
    builder.sname(b"next.example.test").expect("sname");
    builder.allow_overload().expect("overload");
    // Both fields hold names: overload has nowhere to go and keeps no octets.
    builder
        .option(43, &[0; 57])
        .expect("the whole options field");
    assert_eq!(
        builder.option(66, b"x").map(drop),
        Err(EncodeError::NoRoom { code: 66 })
    );
    let len = builder.finish().expect("finish");
    let message = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(message.overload(), Ok(0));
    assert_eq!(message.boot_file_str(), Ok(Some("boot/bios/pxelinux.0")));
    assert_eq!(message.server_name_str(), Ok(Some("next.example.test")));

    let mut buf = [0; 600];
    let mut builder = MessageBuilder::new(&mut buf, 260).expect("builder");
    builder.allow_overload().expect("overload");
    builder.option(43, &[0; 40]).expect("into file");
    assert_eq!(builder.file(b"x").map(drop), Err(EncodeError::FieldInUse));
    assert_eq!(
        builder.sname(&[b'a'; 64]).map(drop),
        Err(EncodeError::FieldTooLong)
    );
    assert_eq!(
        builder.chaddr(&[0; 17]).map(drop),
        Err(EncodeError::FieldTooLong)
    );
}

#[test]
fn builder_limits_and_padding() {
    let mut small = [0; 240];
    assert_eq!(
        MessageBuilder::new(&mut small, 548).map(drop),
        Err(EncodeError::BufferTooSmall)
    );
    let mut buf = [0xa5; 600];
    assert_eq!(
        MessageBuilder::new(&mut buf, 240).map(drop),
        Err(EncodeError::BufferTooSmall)
    );
    let mut builder = MessageBuilder::new(&mut buf, 548).expect("builder");
    assert_eq!(
        builder.pad_to(549).map(drop),
        Err(EncodeError::PaddingTooLong { len: 549 })
    );
    builder.pad_to(BOOTP_MIN_LEN).expect("pad");
    builder.message_type(MessageType::Nak).expect("53");
    builder.broadcast(true);
    for code in [code::PAD, code::END, code::OVERLOAD] {
        assert_eq!(
            builder.option(code, &[1]).map(drop),
            Err(EncodeError::BadValue { code })
        );
    }
    assert_eq!(
        builder.routers(&[]).map(drop),
        Err(EncodeError::BadValue {
            code: code::ROUTERS
        })
    );
    assert_eq!(
        builder
            .domain_search(&[WireName::from_str_text("relative").expect("name")])
            .map(drop),
        Err(EncodeError::BadValue {
            code: code::DOMAIN_SEARCH
        })
    );
    builder.option(80, &[]).expect("rapid commit has no value");
    let len = builder.finish().expect("finish");
    assert_eq!(len, BOOTP_MIN_LEN);
    let message = Message::parse(&buf[..len]).expect("parse");
    assert!(message.broadcast());
    assert_eq!(message.option(80), Ok(Some(&[][..])));
    assert!(buf[246..300].iter().all(|&b| b == 0));
}

#[test]
fn reply_limit_from_option_57() {
    for (size, expected) in [
        (None, 548),
        (Some(575), 548),
        (Some(576), 548),
        (Some(1500), 1472),
    ] {
        let bytes = match size {
            Some(size) => request_with(&[(code::MAX_MESSAGE_SIZE, &u16::to_be_bytes(size))]),
            None => request_with(&[]),
        };
        let message = Message::parse(&bytes).expect("parse");
        assert_eq!(message.max_reply_len(), expected);
        let mut buf = [0; 2000];
        let reply = MessageBuilder::reply(&mut buf, &message, MessageType::Offer).expect("reply");
        assert_eq!(reply.limit(), expected);
    }
    let pxe = fixture("pxe-discover");
    let message = Message::parse(&pxe).expect("parse");
    let mut buf = [0; 600];
    let reply = MessageBuilder::reply(&mut buf, &message, MessageType::Offer).expect("reply");
    assert_eq!(reply.limit(), 600, "the buffer is the tighter bound");
}
