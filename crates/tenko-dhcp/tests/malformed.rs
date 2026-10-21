//! Malformed messages: the fixtures with their exact errors, the rule that the options
//! before a malformed one stay readable, and loops over generated inputs (truncations,
//! octet flips and random option areas) that must never panic.

mod support;

use support::{MALFORMED, Rng, WELL_FORMED, fixture, rebuild};
use tenko_dhcp::v4::{
    Area, DecodeError, Message, MessageBuilder, MessageType, OPTIONS_START, code,
};

#[test]
fn short_and_cookieless_messages_do_not_parse() {
    let short = fixture("malformed-short");
    assert_eq!(short.len(), 239);
    assert_eq!(
        Message::parse(&short).map(|_| ()),
        Err(DecodeError::TooShort { len: 239 })
    );
    assert_eq!(
        Message::parse(&[]).map(|_| ()),
        Err(DecodeError::TooShort { len: 0 })
    );
    let cookie = fixture("malformed-cookie");
    assert_eq!(
        Message::parse(&cookie).map(|_| ()),
        Err(DecodeError::NoCookie)
    );
    // The smallest message: the header and the cookie, no options at all.
    let mut minimal = fixture("windows-discover");
    minimal.truncate(OPTIONS_START);
    let message = Message::parse(&minimal).expect("parse");
    assert_eq!(message.options().count(), 0);
    assert_eq!(message.message_type(), Ok(None));
}

#[test]
fn a_truncated_option_leaves_the_options_before_it_readable() {
    let bytes = fixture("malformed-truncated");
    let message = Message::parse(&bytes).expect("the header parses");
    let error = DecodeError::Truncated {
        code: code::PARAMETER_REQUEST_LIST,
        area: Area::Options,
    };
    assert_eq!(message.validate(), Err(error));
    let items: Vec<_> = message.options().collect();
    assert_eq!(items.len(), 4);
    assert_eq!(items[3], Err(error));
    assert_eq!(message.message_type(), Ok(Some(MessageType::Discover)));
    assert_eq!(message.host_name(), Ok(Some(&b"host-01"[..])));
    assert!(message.client_identifier().expect("ok").is_some());
    // An option after the malformed one cannot be seen: the error says why.
    assert_eq!(message.parameter_request_list(), Err(error));
    assert_eq!(message.server_identifier(), Err(error));
    // A reply can still be built from what was read.
    let mut buf = [0; 600];
    let builder = MessageBuilder::reply(&mut buf, &message, MessageType::Offer).expect("reply");
    let len = builder.finish().expect("finish");
    let offer = Message::parse(&buf[..len]).expect("parse");
    assert_eq!(offer.validate(), Ok(()));
}

#[test]
fn a_bad_overload_ends_the_walk() {
    let bytes = fixture("malformed-overload");
    let message = Message::parse(&bytes).expect("the header parses");
    let error = DecodeError::BadValue {
        code: code::OVERLOAD,
    };
    assert_eq!(message.overload(), Err(error));
    assert_eq!(message.server_name(), Err(error));
    assert_eq!(message.boot_file(), Err(error));
    assert_eq!(message.message_type(), Ok(Some(MessageType::Offer)));
    assert!(message.server_identifier().expect("ok").is_some());
    assert_eq!(message.lease_time(), Err(error));
}

#[test]
fn a_truncated_option_in_file() {
    let bytes = fixture("malformed-file-truncated");
    let message = Message::parse(&bytes).expect("the header parses");
    assert_eq!(message.overload(), Ok(1));
    let error = DecodeError::Truncated {
        code: code::VENDOR_SPECIFIC,
        area: Area::File,
    };
    assert_eq!(message.validate(), Err(error));
    assert_eq!(message.message_type(), Ok(Some(MessageType::Ack)));
    assert_eq!(
        message.routers().map(|routers| routers.map(|r| r.first())),
        Ok(Some("192.0.2.1".parse().expect("address")))
    );
    assert_eq!(message.vendor_specific(), Err(error));
    assert_eq!(message.server_name(), Ok(Some(&b""[..])));
    assert_eq!(message.boot_file(), Ok(None));
}

#[test]
fn bad_lengths_of_typed_options() {
    let mut bytes = fixture("windows-discover");
    // Option 53 with two octets, option 57 with one: the walk is fine, the types are not.
    let at = OPTIONS_START;
    bytes.splice(at..at + 3, [53, 2, 1, 0]);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(
        message.message_type(),
        Err(DecodeError::BadLength {
            code: code::MESSAGE_TYPE,
            len: 2
        })
    );
    assert_eq!(message.validate(), Ok(()));
    // The client identifier is still read; the hardware accessors check htype and hlen.
    assert!(message.client_identifier().expect("ok").is_some());
    let mut other = fixture("windows-discover");
    other[2] = 17;
    let message = Message::parse(&other).expect("parse");
    assert_eq!(
        message.chaddr(),
        Err(DecodeError::Hardware { htype: 1, hlen: 17 })
    );
    assert_eq!(
        message.mac(),
        Err(DecodeError::Hardware { htype: 1, hlen: 17 })
    );
    other[1] = 6;
    other[2] = 6;
    let message = Message::parse(&other).expect("parse");
    assert_eq!(
        message.mac(),
        Err(DecodeError::Hardware { htype: 6, hlen: 6 })
    );
    assert_eq!(message.chaddr().map(<[u8]>::len), Ok(6));
}

/// Reads everything a server could read; must not panic on any input.
fn read_everything(message: &Message<'_>) {
    let _ = message.chaddr();
    let _ = message.mac();
    let _ = message.server_name_str();
    let _ = message.boot_file_str();
    let _ = message.overload();
    let _ = message.validate();
    for item in message.options() {
        let Ok(option) = item else { break };
        let mut buf = [0; 1024];
        let _ = message.option_data(option.code, &mut buf);
    }
    let _ = message.message_type();
    let _ = message.server_identifier();
    let _ = message.requested_address();
    let _ = message.lease_time();
    let _ = message.renewal_time();
    let _ = message.rebinding_time();
    let _ = message.parameter_request_list();
    let _ = message.max_reply_len();
    let _ = message.vendor_class_identifier();
    if let Ok(Some(id)) = message.client_identifier() {
        let _ = (
            id.hardware(),
            id.iaid_duid().map(|(_, duid)| duid.link_layer()),
        );
    }
    let _ = message.host_name();
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        let _ = fqdn.name().to_string();
    }
    if let Ok(Some(relay)) = message.relay_agent_info() {
        let _ = (relay.circuit_id(), relay.link_selection(), relay.relay_id());
    }
    if let Ok(Some(class)) = message.user_class() {
        let _ = class.classes().map(|classes| classes.into_iter().count());
    }
    if let Ok(Some(list)) = message.domain_search() {
        let _ = list.iter().count();
    }
    if let Ok(Some(routes)) = message.classless_routes() {
        let _ = routes.iter().count();
    }
    if let Ok(Some(vendors)) = message.vendor_infos() {
        let _ = vendors
            .iter()
            .map(|vendor| vendor.sub_options.into_iter().count())
            .sum::<usize>();
    }
    if let Ok(Some(vendors)) = message.vendor_classes() {
        let _ = vendors.iter().filter_map(|vendor| vendor.classes()).count();
    }
    let _ = message.client_architectures();
    let _ = message.network_interface();
    let _ = message.machine_id();
    let _ = message.domain_name_servers();
}

#[test]
fn malformed_fixtures_never_panic() {
    for name in MALFORMED {
        if let Ok(message) = Message::parse(&fixture(name)) {
            read_everything(&message);
        }
    }
}

#[test]
fn truncations_and_octet_flips_never_panic() {
    let mut rng = Rng::new(0x5eed_d4c9);
    for name in WELL_FORMED {
        let bytes = fixture(name);
        for len in OPTIONS_START..bytes.len() {
            if let Ok(message) = Message::parse(&bytes[..len]) {
                read_everything(&message);
            }
        }
        for _ in 0..2_000 {
            let mut mutated = bytes.clone();
            for _ in 0..=rng.below(4) {
                let at = OPTIONS_START + rng.below(mutated.len() - OPTIONS_START);
                mutated[at] = rng.byte();
            }
            if rng.below(4) == 0 {
                // Lend file and sname to options at random.
                mutated[OPTIONS_START..OPTIONS_START + 3].copy_from_slice(&[52, 1, rng.byte() % 5]);
            }
            let message = Message::parse(&mutated).expect("the header is intact");
            read_everything(&message);
        }
    }
}

#[test]
fn random_option_areas_round_trip_when_they_walk() {
    let mut rng = Rng::new(0x0dd_ba11);
    let template = fixture("relayed-request");
    let mut walked = 0;
    for _ in 0..5_000 {
        let mut bytes = template[..OPTIONS_START].to_vec();
        // Random but mostly well-formed options: code, length, value.
        for _ in 0..rng.below(12) {
            let code = match rng.byte() {
                0 | 52 | 255 => 53,
                other => other,
            };
            let len = rng.below(24);
            bytes.push(code);
            bytes.push(u8::try_from(len).expect("small"));
            bytes.extend((0..len).map(|_| rng.byte()));
        }
        bytes.push(255);
        let message = Message::parse(&bytes).expect("parse");
        read_everything(&message);
        if message.validate().is_ok() {
            walked += 1;
            let mut out = vec![0; bytes.len() + 16];
            let len = rebuild(&message, &mut out);
            assert_eq!(&out[..len], &bytes[..]);
        }
    }
    assert!(walked > 4_000, "{walked}");
}
