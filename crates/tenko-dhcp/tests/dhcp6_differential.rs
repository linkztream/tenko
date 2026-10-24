//! The differential test of the DHCPv6 codec against `dhcproto` 0.15 (the counterpart of
//! `differential.rs` for DHCPv4): every well-formed fixture of `fixtures/v6/` is decoded by
//! both codecs and the message type, the transaction id, the option codes, the DUIDs, the
//! identity associations with their addresses and lifetimes, the option request and, for
//! relays, the hop count and the two addresses are compared.
//!
//! Where the two disagree on purpose, the comment says which RFC rule decides:
//!
//! * `dhcproto` keeps its options sorted by option code, so the order on the wire is lost.
//!   RFC 8415 section 16 puts no order on options, but a relay that wants the bytes it
//!   received back (and the fixtures of this crate, byte for byte) needs the order; the
//!   comparison sorts our codes before comparing.
//! * `dhcproto` types the Relay Message option (9) as a `RelayMessage` whatever it holds. RFC
//!   8415 section 21.10 says it holds any DHCP message, a SOLICIT as well as a RELAY-FORW, so
//!   it misreads a relayed client message. The relay layers are therefore compared one at a
//!   time, with the Relay Message option cut out of the layer and the relayed message
//!   decoded on its own, with the decoder of its type.
//! * `dhcproto` has no type for the Client FQDN (RFC 4704), Remote-Id (RFC 4649) and Client
//!   Link-Layer Address (RFC 6939) options: it keeps their octets as unknown options, and the
//!   comparison is of those octets.
//! * `dhcproto` calls the elapsed time a count of milliseconds; RFC 8415 section 21.9 counts
//!   hundredths of a second. Both read the same 16-bit value.
//! * `dhcproto` silently drops what it cannot decode (`DhcpOptions::decode` stops at the
//!   first option that fails), where this crate reports the error; only well-formed messages
//!   are compared here.

mod support;

use dhcproto::{
    Decodable, Encodable, Encoder,
    v6::{
        self, DhcpOption, DhcpOptions, IAAddr, IANA, NtpSuboption as TheirNtpSuboption, ORO,
        OptionCode, RelayMessage,
    },
};
use support::fixture;
use tenko_dhcp::v6::{
    AddrList, DecodeError, Message, MessageType, NtpServer, NtpSuboption, code, option::DomainList,
};

/// The fixtures that are client or server messages.
const PLAIN: [&str; 10] = [
    "solicit-dhclient",
    "solicit-networkd",
    "request",
    "renew",
    "rebind",
    "release",
    "decline",
    "confirm",
    "information-request",
    "reply",
];

fn fx(name: &str) -> Vec<u8> {
    fixture(&format!("v6/{name}"))
}

fn their_code(option: &DhcpOption) -> u16 {
    u16::from(OptionCode::from(option))
}

/// The codes of `dhcproto`'s options (sorted by code).
fn their_codes(opts: &DhcpOptions) -> Vec<u16> {
    opts.iter().map(their_code).collect()
}

/// The codes of ours, sorted, without `skip`: `dhcproto` sorts.
fn our_codes_sorted(message: &Message<'_>, skip: Option<u16>) -> Vec<u16> {
    let mut codes: Vec<u16> = message
        .options()
        .map(|option| option.expect("a well-formed option").code)
        .filter(|code| Some(*code) != skip)
        .collect();
    codes.sort_unstable();
    codes
}

/// The value of the one unknown option `code` of `opts`.
fn their_raw(opts: &DhcpOptions, code: u16) -> Option<&[u8]> {
    opts.iter().find_map(|option| match option {
        DhcpOption::Unknown(unknown) if their_code(option) == code => Some(unknown.data()),
        _ => None,
    })
}

/// Compares the options both codecs read from a client or server message.
#[allow(
    clippy::too_many_lines,
    reason = "one block per option, each compared the same way"
)]
fn compare_message(label: &str, bytes: &[u8]) {
    let ours = Message::parse(bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
    ours.validate().expect(label);
    let theirs =
        v6::Message::from_bytes(bytes).unwrap_or_else(|error| panic!("{label}: dhcproto: {error}"));

    assert_eq!(
        u8::from(theirs.msg_type()),
        ours.kind().to_u8(),
        "{label}: type"
    );
    assert_eq!(theirs.xid_num(), ours.transaction_id(), "{label}: xid");
    assert_eq!(
        theirs.xid(),
        ours.transaction_id().to_be_bytes()[1..],
        "{label}: xid octets"
    );
    assert_eq!(
        their_codes(theirs.opts()),
        our_codes_sorted(&ours, None),
        "{label}: option codes"
    );

    // The DUIDs.
    for (option_code, theirs_duid) in [(OptionCode::ClientId, true), (OptionCode::ServerId, false)]
    {
        let their_duid = theirs.opts().get(option_code).map(|option| match option {
            DhcpOption::ClientId(duid) | DhcpOption::ServerId(duid) => duid.as_slice(),
            other => panic!("{label}: {other:?}"),
        });
        let our_duid = if theirs_duid {
            ours.client_id()
        } else {
            ours.server_id()
        }
        .expect(label)
        .map(|duid| duid.as_bytes());
        assert_eq!(their_duid, our_duid, "{label}: DUID {option_code:?}");
    }

    // The identity associations, in order, with their addresses.
    let our_ias: Vec<_> = ours.ia_nas().map(|ia| ia.expect(label)).collect();
    let their_ias: &[DhcpOption] = theirs.opts().get_all(OptionCode::IANA).unwrap_or(&[]);
    assert_eq!(their_ias.len(), our_ias.len(), "{label}: IA_NA count");
    for (their_ia, our_ia) in their_ias.iter().zip(&our_ias) {
        let DhcpOption::IANA(their_ia) = their_ia else {
            panic!("{label}: not an IA_NA");
        };
        assert_eq!(their_ia.id, our_ia.iaid, "{label}: IAID");
        assert_eq!(their_ia.t1, our_ia.t1, "{label}: T1");
        assert_eq!(their_ia.t2, our_ia.t2, "{label}: T2");
        let their_addresses: &[DhcpOption] =
            their_ia.opts.get_all(OptionCode::IAAddr).unwrap_or(&[]);
        let our_addresses: Vec<_> = our_ia
            .addresses()
            .map(|address| address.expect(label))
            .collect();
        assert_eq!(
            their_addresses.len(),
            our_addresses.len(),
            "{label}: address count"
        );
        for (their_address, our_address) in their_addresses.iter().zip(&our_addresses) {
            let DhcpOption::IAAddr(their_address) = their_address else {
                panic!("{label}: not an IA Address");
            };
            assert_eq!(their_address.addr, our_address.addr, "{label}: address");
            assert_eq!(
                their_address.preferred_life, our_address.preferred,
                "{label}: preferred"
            );
            assert_eq!(
                their_address.valid_life, our_address.valid,
                "{label}: valid"
            );
        }
    }

    // The option request.
    let their_oro: Option<Vec<u16>> = theirs.opts().get(OptionCode::ORO).map(|option| {
        let DhcpOption::ORO(oro) = option else {
            panic!("{label}: not an ORO");
        };
        oro.opts.iter().map(|code| u16::from(*code)).collect()
    });
    let our_oro: Option<Vec<u16>> = ours
        .option_request()
        .expect(label)
        .map(|request| request.codes().collect());
    assert_eq!(their_oro, our_oro, "{label}: option request");

    // Elapsed time (both read the raw 16-bit value), rapid commit and preference.
    let their_elapsed = theirs
        .opts()
        .get(OptionCode::ElapsedTime)
        .map(|option| match option {
            DhcpOption::ElapsedTime(value) => *value,
            other => panic!("{label}: {other:?}"),
        });
    assert_eq!(their_elapsed, ours.elapsed_time().expect(label), "{label}");
    assert_eq!(
        theirs.opts().get(OptionCode::RapidCommit).is_some(),
        ours.rapid_commit(),
        "{label}: rapid commit"
    );
    let their_preference = theirs
        .opts()
        .get(OptionCode::Preference)
        .map(|option| match option {
            DhcpOption::Preference(value) => *value,
            other => panic!("{label}: {other:?}"),
        });
    let our_preference = ours
        .option(code::PREFERENCE)
        .expect(label)
        .map(|data| data[0]);
    assert_eq!(their_preference, our_preference, "{label}: preference");

    // Options only dhcproto keeps as unknown (RFC 4704): the octets are the same.
    assert_eq!(
        their_raw(theirs.opts(), code::CLIENT_FQDN),
        ours.option(code::CLIENT_FQDN).expect(label),
        "{label}: client FQDN octets"
    );

    // The typed options of a server's message.
    if let Some(DhcpOption::DomainNameServers(their_dns)) =
        theirs.opts().get(OptionCode::DomainNameServers)
    {
        let data = ours
            .option(code::DNS_SERVERS)
            .expect(label)
            .expect("option 23");
        let our_dns: Vec<_> = AddrList::parse(code::DNS_SERVERS, data)
            .expect(label)
            .iter()
            .collect();
        assert_eq!(their_dns, &our_dns, "{label}: DNS servers");
    } else {
        assert!(!ours.has(code::DNS_SERVERS), "{label}: DNS servers");
    }
    if let Some(DhcpOption::DomainSearchList(their_names)) =
        theirs.opts().get(OptionCode::DomainSearchList)
    {
        let data = ours
            .option(code::DOMAIN_LIST)
            .expect(label)
            .expect("option 24");
        let our_names: Vec<String> = DomainList::parse(code::DOMAIN_LIST, data)
            .expect(label)
            .iter()
            .map(|name| format!("{name}."))
            .collect();
        let their_names: Vec<String> = their_names.iter().map(ToString::to_string).collect();
        assert_eq!(their_names, our_names, "{label}: domain list");
    } else {
        assert!(!ours.has(code::DOMAIN_LIST), "{label}: domain list");
    }
    if let Some(DhcpOption::NtpServer(their_ntp)) = theirs.opts().get(OptionCode::NtpServer) {
        let data = ours
            .option(code::NTP_SERVER)
            .expect(label)
            .expect("option 56");
        let our_ntp: Vec<_> = NtpServer::parse(data).expect(label).suboptions().collect();
        assert_eq!(their_ntp.len(), our_ntp.len(), "{label}: NTP sub-options");
        for (their_sub, our_sub) in their_ntp.iter().zip(&our_ntp) {
            match (their_sub, our_sub) {
                (TheirNtpSuboption::ServerAddress(a), NtpSuboption::ServerAddress(b))
                | (TheirNtpSuboption::MulticastAddress(a), NtpSuboption::MulticastAddress(b)) => {
                    assert_eq!(a, b, "{label}: NTP address");
                }
                (TheirNtpSuboption::FQDN(name), NtpSuboption::ServerName(wire)) => {
                    let ours = tenko_dhcp::v4::WireName::from_wire(wire).expect(label);
                    assert_eq!(name.to_string(), format!("{ours}."), "{label}: NTP name");
                }
                other => panic!("{label}: {other:?}"),
            }
        }
    } else {
        assert!(!ours.has(code::NTP_SERVER), "{label}: NTP server");
    }
}

#[test]
fn both_codecs_read_the_same_client_and_server_messages() {
    for name in PLAIN {
        compare_message(name, &fx(name));
    }
}

#[test]
fn both_codecs_read_the_innermost_advertise_of_a_relay_reply() {
    let bytes = fx("relay-repl-2");
    let outer = Message::parse(&bytes).expect("parse");
    let inner = outer.relay_message().expect("ok").expect("9");
    let advertise = inner.relay_message().expect("ok").expect("9");
    assert_eq!(advertise.kind(), MessageType::Advertise);
    compare_message("relay-repl-2: ADVERTISE", advertise.as_bytes());
}

#[test]
fn the_options_of_the_wire_order_differ_from_the_sorted_order_of_dhcproto() {
    // The reason `our_codes_sorted` sorts: our walk keeps the order of the wire.
    let bytes = fx("solicit-networkd");
    let ours = Message::parse(&bytes).expect("parse");
    let theirs = v6::Message::from_bytes(&bytes).expect("dhcproto parses it");
    let wire: Vec<u16> = ours
        .options()
        .map(|option| option.expect("ok").code)
        .collect();
    assert_eq!(wire, [1, 3, 14, 6, 8, 39]);
    assert_eq!(their_codes(theirs.opts()), [1, 3, 6, 8, 14, 39]);
}

/// A copy of a relay message without its Relay Message option (9).
fn without_relay_message(message: &Message<'_>) -> Vec<u8> {
    let mut out = message.as_bytes()[..34].to_vec();
    for option in message.options() {
        let option = option.expect("a well-formed option");
        if option.code != code::RELAY_MSG {
            out.extend_from_slice(&option.code.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(option.data.len())
                    .expect("a length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(option.data);
        }
    }
    out
}

/// Compares one relay layer and goes inwards; returns the number of relay layers.
fn compare_relay(label: &str, bytes: &[u8]) -> usize {
    let ours = Message::parse(bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(ours.is_relay(), "{label}");
    ours.validate().expect(label);
    let stripped = without_relay_message(&ours);
    let theirs = RelayMessage::from_bytes(&stripped)
        .unwrap_or_else(|error| panic!("{label}: dhcproto: {error}"));

    assert_eq!(
        u8::from(theirs.msg_type()),
        ours.kind().to_u8(),
        "{label}: type"
    );
    assert_eq!(theirs.hop_count(), ours.hop_count(), "{label}: hop count");
    assert_eq!(theirs.link_addr(), ours.link_address(), "{label}: link");
    assert_eq!(theirs.peer_addr(), ours.peer_address(), "{label}: peer");
    assert_eq!(
        their_codes(theirs.opts()),
        our_codes_sorted(&ours, Some(code::RELAY_MSG)),
        "{label}: option codes"
    );
    let their_interface = theirs
        .opts()
        .get(OptionCode::InterfaceId)
        .map(|option| match option {
            DhcpOption::InterfaceId(id) => id.as_slice(),
            other => panic!("{label}: {other:?}"),
        });
    assert_eq!(
        their_interface,
        ours.interface_id().expect(label),
        "{label}: interface id"
    );
    // Remote-Id (RFC 4649) and Client Link-Layer Address (RFC 6939): unknown to dhcproto.
    assert_eq!(
        their_raw(theirs.opts(), code::REMOTE_ID),
        ours.option(code::REMOTE_ID).expect(label),
        "{label}: remote id octets"
    );
    assert_eq!(
        their_raw(theirs.opts(), code::CLIENT_LINKLAYER_ADDR),
        ours.option(code::CLIENT_LINKLAYER_ADDR).expect(label),
        "{label}: link-layer octets"
    );

    let relayed = ours
        .relay_message()
        .expect(label)
        .unwrap_or_else(|| panic!("{label}: no relayed message"));
    if relayed.is_relay() {
        1 + compare_relay(&format!("{label} > relay"), relayed.as_bytes())
    } else {
        compare_message(&format!("{label} > client"), relayed.as_bytes());
        1
    }
}

#[test]
fn both_codecs_read_the_same_relay_forw_of_one_relay() {
    let depth = compare_relay("relay-forw-1", &fx("relay-forw-1"));
    assert_eq!(depth, 1);
}

#[test]
fn both_codecs_read_the_same_relay_forw_of_two_relays() {
    let depth = compare_relay("relay-forw-2", &fx("relay-forw-2"));
    assert_eq!(depth, 2);
}

#[test]
fn both_codecs_read_the_same_relay_repl_of_two_relays() {
    let depth = compare_relay("relay-repl-2", &fx("relay-repl-2"));
    assert_eq!(depth, 2);
}

#[test]
fn dhcproto_reads_a_relay_inside_a_relay_directly() {
    // Where the relayed message is itself a relay message, dhcproto's typing of option 9
    // is right, and the two outer layers decode without the cut.
    let bytes = fx("relay-forw-2");
    let ours = Message::parse(&bytes).expect("parse");
    let inner_ours = ours.relay_message().expect("ok").expect("9");
    let inner_bytes = without_relay_message(&inner_ours);
    let theirs_inner = RelayMessage::from_bytes(&inner_bytes).expect("dhcproto parses it");
    assert_eq!(theirs_inner.link_addr(), inner_ours.link_address());
    assert!(theirs_inner.link_addr().is_unspecified());
    assert_eq!(theirs_inner.peer_addr(), inner_ours.peer_address());
}

#[test]
fn our_codec_reads_what_dhcproto_encodes() {
    let client_duid = vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x03];
    let mut ia_opts = DhcpOptions::new();
    ia_opts.insert(DhcpOption::IAAddr(IAAddr {
        addr: "2001:db8:1::200".parse().expect("an address"),
        preferred_life: 3000,
        valid_life: 4000,
        opts: DhcpOptions::new(),
    }));
    let mut message = v6::Message::new_with_id(v6::MessageType::Request, [0x0a, 0x0b, 0x0c]);
    message
        .opts_mut()
        .insert(DhcpOption::ClientId(client_duid.clone()));
    message.opts_mut().insert(DhcpOption::ServerId(vec![
        0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]));
    message.opts_mut().insert(DhcpOption::ElapsedTime(250));
    message.opts_mut().insert(DhcpOption::ORO(ORO {
        opts: vec![OptionCode::DomainNameServers, OptionCode::DomainSearchList],
    }));
    message.opts_mut().insert(DhcpOption::IANA(IANA {
        id: 0x5e00_5303,
        t1: 1500,
        t2: 2400,
        opts: ia_opts,
    }));
    message.opts_mut().insert(DhcpOption::RapidCommit);
    let mut bytes = Vec::new();
    message
        .encode(&mut Encoder::new(&mut bytes))
        .expect("dhcproto encodes it");

    let ours = Message::parse(&bytes).expect("our codec parses it");
    ours.validate().expect("well formed");
    assert_eq!(ours.kind(), MessageType::Request);
    assert_eq!(ours.transaction_id(), 0x0a_0b0c);
    assert_eq!(
        ours.client_id().expect("ok").expect("1").as_bytes(),
        &client_duid[..]
    );
    assert_eq!(ours.elapsed_time(), Ok(Some(250)));
    assert!(ours.rapid_commit());
    let request = ours.option_request().expect("ok").expect("6");
    assert_eq!(
        request.codes().collect::<Vec<_>>(),
        [code::DNS_SERVERS, code::DOMAIN_LIST]
    );
    let ias: Vec<_> = ours
        .ia_nas()
        .collect::<Result<_, DecodeError>>()
        .expect("well formed");
    assert_eq!(ias.len(), 1);
    assert_eq!(
        (ias[0].iaid, ias[0].t1, ias[0].t2),
        (0x5e00_5303, 1500, 2400)
    );
    let addresses: Vec<_> = ias[0]
        .addresses()
        .collect::<Result<_, DecodeError>>()
        .expect("well formed");
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0].addr,
        "2001:db8:1::200"
            .parse::<std::net::Ipv6Addr>()
            .expect("an address")
    );
    assert_eq!((addresses[0].preferred, addresses[0].valid), (3000, 4000));
}

#[test]
fn what_dhcproto_reencodes_has_the_same_options_as_the_fixture() {
    // Decode, encode, and read the result with our codec: the options are the fixture's,
    // in dhcproto's order (sorted by code).
    for name in [
        "solicit-dhclient",
        "solicit-networkd",
        "request",
        "renew",
        "decline",
    ] {
        let bytes = fx(name);
        let theirs = v6::Message::from_bytes(&bytes).expect(name);
        let mut again = Vec::new();
        theirs
            .encode(&mut Encoder::new(&mut again))
            .expect("dhcproto encodes it");
        assert_eq!(again.len(), bytes.len(), "{name}: no octet lost");
        let original = Message::parse(&bytes).expect(name);
        let reencoded = Message::parse(&again).expect(name);
        assert_eq!(reencoded.kind(), original.kind(), "{name}");
        assert_eq!(
            reencoded.transaction_id(),
            original.transaction_id(),
            "{name}"
        );
        let mut expected: Vec<(u16, Vec<u8>)> = original
            .options()
            .map(|option| {
                let option = option.expect("ok");
                (option.code, option.data.to_vec())
            })
            .collect();
        expected.sort_by_key(|(option_code, _)| *option_code);
        let found: Vec<(u16, Vec<u8>)> = reencoded
            .options()
            .map(|option| {
                let option = option.expect("ok");
                (option.code, option.data.to_vec())
            })
            .collect();
        assert_eq!(found, expected, "{name}");
    }
}
