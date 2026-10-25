//! The DHCPv6 codec (RFC 8415): what the view reads from each hand-written fixture of
//! `fixtures/v6/`, the byte-exact write of every fixture through `MessageBuilder`, the walk of
//! relay chains, the malformed fixtures with their exact errors, the builder's rules, the
//! typed options on the vectors of their RFCs, and loops over generated inputs that must
//! never panic.

mod support;

use std::net::Ipv6Addr;

use support::{Rng, fixture};
use tenko_dhcp::v4::WireName;
use tenko_dhcp::v6::{
    AddrList, ClientFqdn, DecodeError, Duid, EncodeError, HOP_COUNT_LIMIT, IaAddress, IaNa, IaPd,
    IaPrefix, LinkLayerAddress, MAX_RELAY_DEPTH, Message, MessageBuilder, MessageType, NtpServer,
    NtpSuboption, OptionRequest, Options, RELAY_HEADER_LEN, RelayChain, RemoteId, StatusCode,
    VendorClass,
    builder::MAX_NESTING,
    code, encode_domain_list, encode_ntp_servers,
    option::{DomainList, LengthPrefixed, flags_from_v4, flags_to_v4},
    status,
};

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

/// The octets of `fixtures/v6/<name>.hex`.
fn fx(name: &str) -> Vec<u8> {
    fixture(&format!("v6/{name}"))
}

fn ip(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

fn name(text: &str) -> WireName {
    WireName::from_str_text(text).expect("a name")
}

/// Documentation MAC 00:00:5e:00:53:01 (RFC 7042).
const MAC_1: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
/// Documentation MAC 00:00:5e:00:53:02.
const MAC_2: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02];

/// DUID-LL, hardware type 1, `MAC_1`.
const DUID_LL_1: [u8; 10] = [0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
/// DUID-LL, hardware type 1, `MAC_2`.
const DUID_LL_2: [u8; 10] = [0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02];
/// DUID-LLT, hardware type 1, time 0x2c3d4e5f, `MAC_2`.
const DUID_LLT_2: [u8; 14] = [
    0, 1, 0, 1, 0x2c, 0x3d, 0x4e, 0x5f, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02,
];
/// DUID-EN, enterprise 43793, eight octets.
const DUID_EN: [u8; 14] = [
    0, 2, 0, 0, 0xab, 0x11, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
];
/// DUID-UUID with the UUID 00112233-4455-4677-8899-aabbccddeeff.
const DUID_UUID: [u8; 18] = [
    0, 4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    0xff,
];
const UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// The well-formed fixtures that a client or server message holds.
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

/// The well-formed fixtures that are relay messages.
const RELAYED: [&str; 3] = ["relay-forw-1", "relay-forw-2", "relay-repl-2"];

/// The malformed fixtures.
const MALFORMED: [&str; 6] = [
    "malformed-short",
    "malformed-relay-short",
    "malformed-truncated-option",
    "malformed-ia-na-short",
    "malformed-relay-no-msg",
    "malformed-relay-too-deep",
];

/// The option codes of a message in wire order.
fn option_codes(message: &Message<'_>) -> Vec<u16> {
    message
        .options()
        .map(|option| option.expect("a well-formed option").code)
        .collect()
}

fn ia_nas<'a>(message: &Message<'a>) -> Vec<IaNa<'a>> {
    message
        .ia_nas()
        .collect::<Result<Vec<_>, _>>()
        .expect("well-formed IA_NA options")
}

fn addresses<'a>(ia: &IaNa<'a>) -> Vec<IaAddress<'a>> {
    ia.addresses()
        .collect::<Result<Vec<_>, _>>()
        .expect("well-formed IA Address options")
}

fn codes_of(request: &OptionRequest<'_>) -> Vec<u16> {
    request.codes().collect()
}

/// Writes a message with `f` into a buffer of its own and returns its octets.
fn build(f: impl FnOnce(&mut MessageBuilder<'_>)) -> Vec<u8> {
    let mut buf = vec![0xa5; 2048];
    let mut builder = MessageBuilder::new(&mut buf, 1500).expect("builder");
    f(&mut builder);
    let len = builder.finish().expect("balanced options");
    buf.truncate(len);
    buf
}

// ---------------------------------------------------------------------------------------
// The messages of the fixtures, written through the builder
// ---------------------------------------------------------------------------------------

fn put_solicit_dhclient(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::Solicit, 0x4a_6b1c).expect("header");
    b.option(code::CLIENTID, &DUID_LL_1).expect("1");
    b.option(code::ELAPSED_TIME, &[0, 0]).expect("8");
    b.option(code::ORO, &[0, 23, 0, 24]).expect("6");
    let ia = b.begin_ia_na(0x5e00_5301, 0, 0).expect("3");
    b.end(ia).expect("end of 3");
}

fn put_solicit_networkd(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::Solicit, 0x0b_17c9).expect("header");
    b.option(code::CLIENTID, &DUID_EN).expect("1");
    let ia = b.begin_ia_na(2, 0, 0).expect("3");
    b.end(ia).expect("end of 3");
    b.option(code::RAPID_COMMIT, &[]).expect("14");
    b.option(code::ORO, &[0, 23, 0, 24, 0, 56, 0, 31, 0, 82])
        .expect("6");
    b.option(code::ELAPSED_TIME, &[0, 0]).expect("8");
    b.client_fqdn(ClientFqdn::FLAG_S, &name("laptop"))
        .expect("39");
}

fn put_request(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::Request, 0x1d_2e3f).expect("header");
    b.option(code::CLIENTID, &DUID_LLT_2).expect("1");
    b.option(code::SERVERID, &DUID_UUID).expect("2");
    let ia = b.begin_ia_na(0x5e00_5302, 0, 0).expect("3");
    b.ia_address(ip("2001:db8:1::100"), 3000, 4000).expect("5");
    b.end(ia).expect("end of 3");
    b.option(code::ORO, &[0, 23, 0, 24]).expect("6");
    b.option(code::ELAPSED_TIME, &[0, 100]).expect("8");
}

/// RENEW, REBIND, RELEASE, DECLINE and CONFIRM: the client identifier, the server
/// identifier when `server`, elapsed time, and an `IA_NA` with the one address.
fn put_ia_message(
    b: &mut MessageBuilder<'_>,
    kind: MessageType,
    xid: u32,
    server: bool,
    lifetimes: (u32, u32),
) {
    b.message(kind, xid).expect("header");
    b.option(code::CLIENTID, &DUID_LL_2).expect("1");
    if server {
        b.option(code::SERVERID, &DUID_UUID).expect("2");
    }
    b.option(code::ELAPSED_TIME, &[0, 0]).expect("8");
    let ia = b.begin_ia_na(0x5e00_5302, 0, 0).expect("3");
    b.ia_address(ip("2001:db8:1::100"), lifetimes.0, lifetimes.1)
        .expect("5");
    b.end(ia).expect("end of 3");
}

fn put_information_request(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::InformationRequest, 0x2a_0006)
        .expect("header");
    b.option(code::CLIENTID, &DUID_LL_2).expect("1");
    b.option(code::ELAPSED_TIME, &[0, 0]).expect("8");
    b.option(code::ORO, &[0, 23, 0, 24, 0, 32]).expect("6");
}

fn put_reply(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::Reply, 0x1d_2e3f).expect("header");
    b.option(code::SERVERID, &DUID_UUID).expect("2");
    b.option(code::CLIENTID, &DUID_LLT_2).expect("1");
    let ia = b.begin_ia_na(0x5e00_5302, 1500, 2400).expect("3");
    b.ia_address(ip("2001:db8:1::100"), 3000, 4000).expect("5");
    b.end(ia).expect("end of 3");
    b.addresses(code::DNS_SERVERS, &[ip("2001:db8::53")])
        .expect("23");
    let names = [name("example.test."), name("lab.example.test.")];
    let mut list = [0u8; 64];
    let len = encode_domain_list(&names, &mut list).expect("domain list");
    b.option(code::DOMAIN_LIST, &list[..len]).expect("24");
    let mut ntp = [0u8; 64];
    let len = encode_ntp_servers(&[ip("2001:db8::123")], &mut ntp).expect("ntp");
    b.option(code::NTP_SERVER, &ntp[..len]).expect("56");
    b.client_fqdn(ClientFqdn::FLAG_S, &name("laptop.example.test."))
        .expect("39");
}

fn put_advertise(b: &mut MessageBuilder<'_>) {
    b.message(MessageType::Advertise, 0x0b_17c9)
        .expect("header");
    b.option(code::SERVERID, &DUID_UUID).expect("2");
    b.option(code::CLIENTID, &DUID_EN).expect("1");
    let ia = b.begin_ia_na(2, 1500, 2400).expect("3");
    b.ia_address(ip("2001:db8:1::101"), 3000, 4000).expect("5");
    b.end(ia).expect("end of 3");
    b.option(code::PREFERENCE, &[255]).expect("7");
}

fn put_relay_forw_1(b: &mut MessageBuilder<'_>) {
    b.relay(
        MessageType::RelayForw,
        0,
        ip("2001:db8:1::1"),
        ip("fe80::200:5eff:fe00:5301"),
    )
    .expect("relay header");
    b.option(code::INTERFACE_ID, b"eth1").expect("18");
    b.option_parts(code::REMOTE_ID, &[&32473u32.to_be_bytes(), &[1, 2, 3, 4]])
        .expect("37");
    b.option(
        code::CLIENT_LINKLAYER_ADDR,
        &[0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
    )
    .expect("79");
    let relayed = b.begin(code::RELAY_MSG).expect("9");
    put_solicit_dhclient(b);
    b.end(relayed).expect("end of 9");
}

fn put_relay_forw_2(b: &mut MessageBuilder<'_>) {
    b.relay(
        MessageType::RelayForw,
        1,
        ip("2001:db8:ffff::1"),
        ip("2001:db8:1::2"),
    )
    .expect("outer header");
    let outer = b.begin(code::RELAY_MSG).expect("outer 9");
    b.relay(
        MessageType::RelayForw,
        0,
        Ipv6Addr::UNSPECIFIED,
        ip("fe80::200:5eff:fe00:5301"),
    )
    .expect("inner header");
    b.option(code::INTERFACE_ID, b"port-7").expect("18");
    let inner = b.begin(code::RELAY_MSG).expect("inner 9");
    put_solicit_networkd(b);
    b.end(inner).expect("end of inner 9");
    b.end(outer).expect("end of outer 9");
}

fn put_relay_repl_2(b: &mut MessageBuilder<'_>) {
    b.relay(
        MessageType::RelayRepl,
        1,
        ip("2001:db8:ffff::1"),
        ip("2001:db8:1::2"),
    )
    .expect("outer header");
    let outer = b.begin(code::RELAY_MSG).expect("outer 9");
    b.relay(
        MessageType::RelayRepl,
        0,
        Ipv6Addr::UNSPECIFIED,
        ip("fe80::200:5eff:fe00:5301"),
    )
    .expect("inner header");
    b.option(code::INTERFACE_ID, b"port-7").expect("18");
    let inner = b.begin(code::RELAY_MSG).expect("inner 9");
    put_advertise(b);
    b.end(inner).expect("end of inner 9");
    b.end(outer).expect("end of outer 9");
}

// ---------------------------------------------------------------------------------------
// Reading the fixtures
// ---------------------------------------------------------------------------------------

#[test]
fn every_well_formed_fixture_parses_and_walks_without_an_error() {
    for fixture_name in PLAIN.iter().chain(&RELAYED) {
        let bytes = fx(fixture_name);
        let message = Message::parse(&bytes).expect(fixture_name);
        message.validate().expect(fixture_name);
        assert_eq!(message.as_bytes(), &bytes[..], "{fixture_name}");
        assert_eq!(message.len(), bytes.len(), "{fixture_name}");
        assert!(!message.is_empty(), "{fixture_name}");
    }
}

#[test]
fn a_dhclient_solicit_reads_field_by_field() {
    let bytes = fx("solicit-dhclient");
    assert_eq!(bytes.len(), 48);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::Solicit);
    assert!(!message.is_relay());
    assert_eq!(message.transaction_id(), 0x4a_6b1c);
    assert_eq!(message.hop_count(), 0);
    assert_eq!(message.link_address(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(message.peer_address(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(message.options_area(), &bytes[4..]);
    assert_eq!(option_codes(&message), [1, 8, 6, 3]);

    let client = message.client_id().expect("ok").expect("option 1");
    assert_eq!(client.kind(), Duid::LL);
    assert_eq!(client.as_bytes(), DUID_LL_1);
    assert_eq!(client.body(), &DUID_LL_1[2..]);
    assert_eq!(client.link_layer(), Some((1, &MAC_1[..])));
    assert_eq!(client.time(), None);
    assert_eq!(client.enterprise(), None);
    assert_eq!(client.uuid(), None);
    assert_eq!(message.server_id(), Ok(None));
    assert_eq!(message.elapsed_time(), Ok(Some(0)));

    let request = message.option_request().expect("ok").expect("option 6");
    assert_eq!(codes_of(&request), [23, 24]);
    assert_eq!(request.len(), 2);
    assert!(!request.is_empty());
    assert!(request.contains(code::DNS_SERVERS));
    assert!(request.contains(code::DOMAIN_LIST));
    assert!(!request.contains(code::NTP_SERVER));

    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!(ias[0].iaid, 0x5e00_5301);
    assert_eq!(ias[0].t1, 0);
    assert_eq!(ias[0].t2, 0);
    assert_eq!(ias[0].options().count(), 0);
    assert_eq!(addresses(&ias[0]).len(), 0);
    assert_eq!(ias[0].status(), None);

    assert!(!message.rapid_commit());
    assert!(!message.reconfigure_accept());
    assert!(!message.has_ia_ta());
    assert!(message.has(code::IA_NA));
    assert!(!message.has(code::IA_PD));
    assert_eq!(message.ia_pds().count(), 0);
    assert_eq!(message.client_fqdn(), Ok(None));
    assert_eq!(message.relay_message(), Ok(None));
    assert_eq!(message.interface_id(), Ok(None));
    assert_eq!(message.remote_id(), Ok(None));
    assert_eq!(message.client_link_layer(), Ok(None));
    assert_eq!(message.user_class(), Ok(None));
    assert_eq!(message.vendor_class(), Ok(None));
    assert_eq!(message.option(code::SERVERID), Ok(None));
}

#[test]
fn a_networkd_solicit_reads_field_by_field() {
    let bytes = fx("solicit-networkd");
    assert_eq!(bytes.len(), 74);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::Solicit);
    assert_eq!(message.transaction_id(), 0x0b_17c9);
    assert_eq!(option_codes(&message), [1, 3, 14, 6, 8, 39]);

    let client = message.client_id().expect("ok").expect("option 1");
    assert_eq!(client.kind(), Duid::EN);
    assert_eq!(client.enterprise(), Some(43793));
    assert_eq!(client.body(), &DUID_EN[2..]);
    assert_eq!(
        &client.body()[4..],
        &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]
    );
    assert_eq!(client.link_layer(), None);
    assert_eq!(client.time(), None);
    assert_eq!(client.uuid(), None);

    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (2, 0, 0));
    assert!(message.rapid_commit());
    assert_eq!(message.option(code::RAPID_COMMIT), Ok(Some(&[][..])));

    let request = message.option_request().expect("ok").expect("option 6");
    assert_eq!(codes_of(&request), [23, 24, 56, 31, 82]);
    assert!(request.contains(code::NTP_SERVER));
    assert!(request.contains(code::SNTP_SERVERS));
    assert!(request.contains(code::SOL_MAX_RT));
    assert_eq!(message.elapsed_time(), Ok(Some(0)));

    let fqdn = message.client_fqdn().expect("ok").expect("option 39");
    assert_eq!(fqdn.flags(), 0x01);
    assert!(fqdn.server_updates());
    assert!(!fqdn.no_update());
    assert_eq!(fqdn.name_bytes(), b"\x06laptop");
    assert_eq!(fqdn.name(), name("laptop"));
    assert!(!fqdn.name().is_absolute());
    // S stays, N is clear, and E (the DHCPv4 encoding flag) is set.
    assert_eq!(fqdn.flags_v4(), 0x05);
}

#[test]
fn a_request_reads_the_address_in_its_ia_na() {
    let bytes = fx("request");
    assert_eq!(bytes.len(), 4 + 18 + 22 + 44 + 8 + 6);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::Request);
    assert_eq!(message.transaction_id(), 0x1d_2e3f);
    assert_eq!(option_codes(&message), [1, 2, 3, 6, 8]);

    let client = message.client_id().expect("ok").expect("option 1");
    assert_eq!(client.kind(), Duid::LLT);
    assert_eq!(client.time(), Some(0x2c3d_4e5f));
    assert_eq!(client.link_layer(), Some((1, &MAC_2[..])));
    assert_eq!(client.enterprise(), None);
    assert_eq!(client.uuid(), None);

    let server = message.server_id().expect("ok").expect("option 2");
    assert_eq!(server.kind(), Duid::UUID);
    assert_eq!(server.uuid(), Some(UUID));
    assert_eq!(server.link_layer(), None);
    assert_eq!(server.time(), None);

    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (0x5e00_5302, 0, 0));
    let found = addresses(&ias[0]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, ip("2001:db8:1::100"));
    assert_eq!(found[0].preferred, 3000);
    assert_eq!(found[0].valid, 4000);
    assert_eq!(found[0].options().count(), 0);
    assert_eq!(found[0].status(), None);
    assert_eq!(ias[0].options().count(), 1);

    let request = message.option_request().expect("ok").expect("option 6");
    assert_eq!(codes_of(&request), [23, 24]);
    assert_eq!(message.elapsed_time(), Ok(Some(100)));
}

/// What the five IA messages share: the client identifier of `DUID_LL_2`, elapsed time 0,
/// and one `IA_NA` with one address; returns the address.
fn check_ia_message(bytes: &[u8], kind: MessageType, xid: u32, server: bool) -> IaAddress<'_> {
    let message = Message::parse(bytes).expect("parse");
    message.validate().expect("well formed");
    assert_eq!(message.kind(), kind);
    assert_eq!(message.transaction_id(), xid);
    assert_eq!(
        message
            .client_id()
            .expect("ok")
            .expect("option 1")
            .as_bytes(),
        DUID_LL_2
    );
    let expected = if server {
        vec![1, 2, 8, 3]
    } else {
        vec![1, 8, 3]
    };
    assert_eq!(option_codes(&message), expected);
    match message.server_id().expect("ok") {
        Some(id) => {
            assert!(server);
            assert_eq!(id.as_bytes(), DUID_UUID);
        }
        None => assert!(!server),
    }
    assert_eq!(message.elapsed_time(), Ok(Some(0)));
    assert_eq!(message.option_request(), Ok(None));
    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (0x5e00_5302, 0, 0));
    let mut found = addresses(&ias[0]);
    assert_eq!(found.len(), 1);
    let address = found.remove(0);
    assert_eq!(address.addr, ip("2001:db8:1::100"));
    address
}

#[test]
fn a_renew_names_the_server_and_the_address() {
    let bytes = fx("renew");
    assert_eq!(bytes.len(), 90);
    let address = check_ia_message(&bytes, MessageType::Renew, 0x2a_0001, true);
    assert_eq!((address.preferred, address.valid), (3000, 4000));
}

#[test]
fn a_rebind_has_no_server_identifier() {
    let bytes = fx("rebind");
    assert_eq!(bytes.len(), 68);
    let address = check_ia_message(&bytes, MessageType::Rebind, 0x2a_0002, false);
    assert_eq!((address.preferred, address.valid), (3000, 4000));
}

#[test]
fn a_release_names_the_server_and_the_address() {
    let bytes = fx("release");
    assert_eq!(bytes.len(), 90);
    let address = check_ia_message(&bytes, MessageType::Release, 0x2a_0003, true);
    assert_eq!((address.preferred, address.valid), (0, 0));
}

#[test]
fn a_decline_names_the_server_and_the_address() {
    let bytes = fx("decline");
    assert_eq!(bytes.len(), 90);
    let address = check_ia_message(&bytes, MessageType::Decline, 0x2a_0004, true);
    assert_eq!((address.preferred, address.valid), (0, 0));
}

#[test]
fn a_confirm_has_no_server_identifier() {
    let bytes = fx("confirm");
    assert_eq!(bytes.len(), 68);
    let address = check_ia_message(&bytes, MessageType::Confirm, 0x2a_0005, false);
    assert_eq!((address.preferred, address.valid), (0, 0));
}

#[test]
fn an_information_request_has_no_ia_and_asks_for_options() {
    let bytes = fx("information-request");
    assert_eq!(bytes.len(), 34);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::InformationRequest);
    assert_eq!(message.transaction_id(), 0x2a_0006);
    assert_eq!(option_codes(&message), [1, 8, 6]);
    assert_eq!(
        message.client_id().expect("ok").expect("1").as_bytes(),
        DUID_LL_2
    );
    assert_eq!(message.server_id(), Ok(None));
    assert_eq!(message.ia_nas().count(), 0);
    assert_eq!(message.ia_pds().count(), 0);
    assert!(!message.has_ia_ta());
    let request = message.option_request().expect("ok").expect("6");
    assert_eq!(
        codes_of(&request),
        [
            code::DNS_SERVERS,
            code::DOMAIN_LIST,
            code::INFORMATION_REFRESH_TIME
        ]
    );
}

#[test]
fn a_reply_reads_every_typed_option() {
    let bytes = fx("reply");
    assert_eq!(bytes.len(), 194);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::Reply);
    assert_eq!(message.transaction_id(), 0x1d_2e3f);
    assert_eq!(option_codes(&message), [2, 1, 3, 23, 24, 56, 39]);
    assert_eq!(
        message.server_id().expect("ok").expect("2").uuid(),
        Some(UUID)
    );
    assert_eq!(
        message.client_id().expect("ok").expect("1").as_bytes(),
        DUID_LLT_2
    );

    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!(
        (ias[0].iaid, ias[0].t1, ias[0].t2),
        (0x5e00_5302, 1500, 2400)
    );
    let found = addresses(&ias[0]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, ip("2001:db8:1::100"));
    assert_eq!((found[0].preferred, found[0].valid), (3000, 4000));

    let dns = message
        .option(code::DNS_SERVERS)
        .expect("ok")
        .expect("option 23");
    let dns = AddrList::parse(code::DNS_SERVERS, dns).expect("addresses");
    assert_eq!(dns.len(), 1);
    assert!(!dns.is_empty());
    assert_eq!(dns.iter().collect::<Vec<_>>(), [ip("2001:db8::53")]);

    let list = message
        .option(code::DOMAIN_LIST)
        .expect("ok")
        .expect("option 24");
    let list = DomainList::parse(code::DOMAIN_LIST, list).expect("names");
    assert_eq!(
        list.iter().collect::<Vec<_>>(),
        [name("example.test."), name("lab.example.test.")]
    );
    assert_eq!(list.as_bytes().len(), 32);

    let ntp = message
        .option(code::NTP_SERVER)
        .expect("ok")
        .expect("option 56");
    let ntp = NtpServer::parse(ntp).expect("sub-options");
    assert_eq!(
        ntp.suboptions().collect::<Vec<_>>(),
        [NtpSuboption::ServerAddress(ip("2001:db8::123"))]
    );

    let fqdn = message.client_fqdn().expect("ok").expect("option 39");
    assert_eq!(fqdn.flags(), 0x01);
    assert!(fqdn.server_updates());
    assert_eq!(fqdn.name(), name("laptop.example.test."));
    assert!(fqdn.name().is_absolute());
    assert_eq!(fqdn.flags_v4(), 0x05);
}

#[test]
fn a_relay_forw_reads_the_header_and_the_relay_options() {
    let bytes = fx("relay-forw-1");
    assert_eq!(bytes.len(), 118);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::RelayForw);
    assert!(message.is_relay());
    assert_eq!(message.transaction_id(), 0);
    assert_eq!(message.hop_count(), 0);
    assert_eq!(message.link_address(), ip("2001:db8:1::1"));
    assert_eq!(message.peer_address(), ip("fe80::200:5eff:fe00:5301"));
    assert_eq!(message.options_area(), &bytes[RELAY_HEADER_LEN..]);
    assert_eq!(option_codes(&message), [18, 37, 79, 9]);
    assert_eq!(message.interface_id(), Ok(Some(&b"eth1"[..])));
    let remote = message.remote_id().expect("ok").expect("option 37");
    assert_eq!(remote.enterprise, 32473);
    assert_eq!(remote.id, [1, 2, 3, 4]);
    assert_eq!(remote.as_bytes(), [0, 0, 0x7e, 0xd9, 1, 2, 3, 4]);
    let link_layer = message.client_link_layer().expect("ok").expect("option 79");
    assert_eq!(link_layer.kind, 1);
    assert_eq!(link_layer.address, MAC_1);
    assert_eq!(link_layer.mac(), Some(MAC_1));

    let relayed = message.relay_message().expect("ok").expect("option 9");
    assert_eq!(relayed.as_bytes(), &fx("solicit-dhclient")[..]);
    assert_eq!(relayed.kind(), MessageType::Solicit);
    assert_eq!(relayed.transaction_id(), 0x4a_6b1c);
}

#[test]
fn a_relay_forw_two_deep_nests_the_header_fields_of_each_relay() {
    let bytes = fx("relay-forw-2");
    assert_eq!(bytes.len(), 160);
    let outer = Message::parse(&bytes).expect("parse");
    assert_eq!(outer.kind(), MessageType::RelayForw);
    assert_eq!(outer.hop_count(), 1);
    assert_eq!(outer.link_address(), ip("2001:db8:ffff::1"));
    assert_eq!(outer.peer_address(), ip("2001:db8:1::2"));
    assert_eq!(option_codes(&outer), [9]);
    assert_eq!(outer.interface_id(), Ok(None));

    let inner = outer.relay_message().expect("ok").expect("outer 9");
    assert_eq!(inner.len(), 122);
    assert_eq!(inner.kind(), MessageType::RelayForw);
    assert_eq!(inner.hop_count(), 0);
    assert_eq!(inner.link_address(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(inner.peer_address(), ip("fe80::200:5eff:fe00:5301"));
    assert_eq!(option_codes(&inner), [18, 9]);
    assert_eq!(inner.interface_id(), Ok(Some(&b"port-7"[..])));

    let client = inner.relay_message().expect("ok").expect("inner 9");
    assert_eq!(client.as_bytes(), &fx("solicit-networkd")[..]);
    assert_eq!(client.kind(), MessageType::Solicit);
}

#[test]
fn a_relay_repl_chain_echoes_the_header_fields_and_the_interface_id() {
    let bytes = fx("relay-repl-2");
    assert_eq!(bytes.len(), 179);
    let outer = Message::parse(&bytes).expect("parse");
    assert_eq!(outer.kind(), MessageType::RelayRepl);
    assert!(outer.is_relay());
    // The reply copies the hop count, the link and the peer address of the request.
    let request = fx("relay-forw-2");
    let request = Message::parse(&request).expect("parse");
    assert_eq!(outer.hop_count(), request.hop_count());
    assert_eq!(outer.link_address(), request.link_address());
    assert_eq!(outer.peer_address(), request.peer_address());
    // The outer relay sent no Interface-Id, so none is echoed.
    assert_eq!(option_codes(&outer), [9]);
    assert_eq!(outer.interface_id(), Ok(None));

    let inner = outer.relay_message().expect("ok").expect("outer 9");
    let request_inner = request.relay_message().expect("ok").expect("9");
    assert_eq!(inner.kind(), MessageType::RelayRepl);
    assert_eq!(inner.hop_count(), request_inner.hop_count());
    assert_eq!(inner.link_address(), request_inner.link_address());
    assert_eq!(inner.peer_address(), request_inner.peer_address());
    assert_eq!(inner.interface_id(), request_inner.interface_id());
    assert_eq!(inner.interface_id(), Ok(Some(&b"port-7"[..])));

    let advertise = inner.relay_message().expect("ok").expect("inner 9");
    assert_eq!(advertise.len(), 93);
    assert_eq!(advertise.kind(), MessageType::Advertise);
    assert_eq!(advertise.transaction_id(), 0x0b_17c9);
    assert_eq!(option_codes(&advertise), [2, 1, 3, 7]);
    assert_eq!(advertise.option(code::PREFERENCE), Ok(Some(&[255][..])));
    assert_eq!(
        advertise.client_id().expect("ok").expect("1").enterprise(),
        Some(43793)
    );
    let ias = ia_nas(&advertise);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (2, 1500, 2400));
    assert_eq!(addresses(&ias[0])[0].addr, ip("2001:db8:1::101"));
}

// ---------------------------------------------------------------------------------------
// Writing the fixtures through the builder
// ---------------------------------------------------------------------------------------

#[test]
fn the_builder_writes_the_solicit_of_dhclient_octet_for_octet() {
    assert_eq!(build(put_solicit_dhclient), fx("solicit-dhclient"));
}

#[test]
fn the_builder_writes_the_solicit_of_networkd_octet_for_octet() {
    assert_eq!(build(put_solicit_networkd), fx("solicit-networkd"));
}

#[test]
fn the_builder_writes_the_request_octet_for_octet() {
    assert_eq!(build(put_request), fx("request"));
}

#[test]
fn the_builder_writes_the_renew_octet_for_octet() {
    let written = build(|b| put_ia_message(b, MessageType::Renew, 0x2a_0001, true, (3000, 4000)));
    assert_eq!(written, fx("renew"));
}

#[test]
fn the_builder_writes_the_rebind_octet_for_octet() {
    let written = build(|b| put_ia_message(b, MessageType::Rebind, 0x2a_0002, false, (3000, 4000)));
    assert_eq!(written, fx("rebind"));
}

#[test]
fn the_builder_writes_the_release_octet_for_octet() {
    let written = build(|b| put_ia_message(b, MessageType::Release, 0x2a_0003, true, (0, 0)));
    assert_eq!(written, fx("release"));
}

#[test]
fn the_builder_writes_the_decline_octet_for_octet() {
    let written = build(|b| put_ia_message(b, MessageType::Decline, 0x2a_0004, true, (0, 0)));
    assert_eq!(written, fx("decline"));
}

#[test]
fn the_builder_writes_the_confirm_octet_for_octet() {
    let written = build(|b| put_ia_message(b, MessageType::Confirm, 0x2a_0005, false, (0, 0)));
    assert_eq!(written, fx("confirm"));
}

#[test]
fn the_builder_writes_the_information_request_octet_for_octet() {
    assert_eq!(build(put_information_request), fx("information-request"));
}

#[test]
fn the_builder_writes_the_reply_octet_for_octet() {
    assert_eq!(build(put_reply), fx("reply"));
}

#[test]
fn the_builder_writes_the_relay_forw_octet_for_octet() {
    assert_eq!(build(put_relay_forw_1), fx("relay-forw-1"));
}

#[test]
fn the_builder_writes_the_relay_forw_two_deep_octet_for_octet() {
    assert_eq!(build(put_relay_forw_2), fx("relay-forw-2"));
}

#[test]
fn the_builder_writes_the_relay_repl_chain_octet_for_octet() {
    assert_eq!(build(put_relay_repl_2), fx("relay-repl-2"));
}

#[test]
fn the_low_24_bits_of_the_transaction_id_are_written() {
    let written = build(|b| {
        b.message(MessageType::Solicit, 0xff12_3456)
            .expect("header");
    });
    assert_eq!(written, [1, 0x12, 0x34, 0x56]);
    assert_eq!(
        Message::parse(&written).expect("parse").transaction_id(),
        0x12_3456
    );
}

#[test]
fn a_status_code_written_by_the_builder_reads_back_in_the_ia_and_its_address() {
    let written = build(|b| {
        b.message(MessageType::Reply, 1).expect("header");
        b.status(status::SUCCESS, b"all good").expect("13");
        let ia = b.begin_ia_na(7, 0, 0).expect("3");
        b.status(status::NO_ADDRS_AVAIL, b"none left").expect("13");
        let address = b.begin_ia_address(ip("2001:db8:1::7"), 0, 0).expect("5");
        b.status(status::NOT_ON_LINK, b"").expect("13");
        b.end(address).expect("end of 5");
        b.end(ia).expect("end of 3");
    });
    let message = Message::parse(&written).expect("parse");
    message.validate().expect("well formed");
    let first = message
        .option(code::STATUS_CODE)
        .expect("ok")
        .expect("option 13");
    let first = StatusCode::parse(first).expect("status");
    assert_eq!(first.code, status::SUCCESS);
    assert_eq!(first.message, b"all good");
    let ias = ia_nas(&message);
    let ia_status = ias[0].status().expect("a status in the IA_NA");
    assert_eq!(ia_status.code, status::NO_ADDRS_AVAIL);
    assert_eq!(ia_status.message, b"none left");
    let found = addresses(&ias[0]);
    let nested = found[0].status().expect("a status in the IA Address");
    assert_eq!(nested.code, status::NOT_ON_LINK);
    assert_eq!(nested.message, b"");
}

#[test]
fn an_ia_pd_written_by_the_builder_reads_back_field_for_field() {
    let written = build(|b| {
        b.message(MessageType::Reply, 2).expect("header");
        let ia = b.begin_ia_pd(0x5e00_5303, 1500, 2400).expect("25");
        b.ia_prefix(ip("2001:db8:180:110::"), 60, 3000, 4000)
            .expect("26");
        b.ia_prefix(ip("2001:db8:999::"), 56, 0, 0).expect("26");
        b.status(status::NO_PREFIX_AVAIL, b"none left").expect("13");
        b.end(ia).expect("end of 25");
    });
    let message = Message::parse(&written).expect("parse");
    message.validate().expect("well formed");
    // The wire form of the IA_PD: its head, two IA Prefix options, the status.
    let data = message.option(code::IA_PD).expect("ok").expect("option 25");
    assert_eq!(data.len(), 12 + 2 * (4 + 25) + (4 + 2 + 9));
    assert_eq!(
        &data[..12],
        [0x5e, 0x00, 0x53, 0x03, 0, 0, 5, 220, 0, 0, 9, 96]
    );
    let mut first = vec![0, 26, 0, 25, 0, 0, 0x0b, 0xb8, 0, 0, 0x0f, 0xa0, 60];
    first.extend_from_slice(&ip("2001:db8:180:110::").octets());
    assert_eq!(&data[12..12 + 29], first.as_slice());
    // The codec reads it back, field for field.
    let ia = IaPd::parse(data).expect("an IA_PD");
    assert_eq!((ia.iaid, ia.t1, ia.t2), (0x5e00_5303, 1500, 2400));
    let prefixes: Vec<IaPrefix<'_>> = ia
        .prefixes()
        .collect::<Result<_, _>>()
        .expect("well-formed IA Prefix options");
    assert_eq!(prefixes.len(), 2);
    assert_eq!(prefixes[0].prefix, ip("2001:db8:180:110::"));
    assert_eq!(prefixes[0].prefix_len, 60);
    assert_eq!((prefixes[0].preferred, prefixes[0].valid), (3000, 4000));
    assert_eq!(prefixes[0].options().count(), 0);
    assert_eq!(prefixes[1].prefix, ip("2001:db8:999::"));
    assert_eq!(prefixes[1].prefix_len, 56);
    assert_eq!((prefixes[1].preferred, prefixes[1].valid), (0, 0));
    let ia_status = ia.status().expect("a status in the IA_PD");
    assert_eq!(ia_status.code, status::NO_PREFIX_AVAIL);
    assert_eq!(ia_status.message, b"none left");
    // The message's own walk gives the same IA_PD.
    let walked: Vec<IaPd<'_>> = message
        .ia_pds()
        .collect::<Result<_, _>>()
        .expect("well-formed IA_PD options");
    assert_eq!(walked, [ia]);
}

#[test]
fn an_ia_prefix_that_does_not_fit_leaves_the_message_as_it_was() {
    // 4 (header) + 16 (IA_PD head) + 29 (one IA Prefix) = 49 octets: the limit.
    let mut buf = [0u8; 120];
    let mut b = MessageBuilder::new(&mut buf, 49).expect("builder");
    b.message(MessageType::Reply, 9).expect("header");
    let ia = b.begin_ia_pd(1, 2, 3).expect("16 octets");
    b.ia_prefix(ip("2001:db8:180:110::"), 60, 3000, 4000)
        .expect("29 octets");
    assert_eq!(b.len(), 49);
    assert_eq!(b.room(), 0);
    assert_eq!(
        b.ia_prefix(ip("2001:db8:180:120::"), 60, 3000, 4000)
            .map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::IAPREFIX
        })
    );
    assert_eq!(b.len(), 49, "the refused prefix left no trace");
    assert_eq!(
        b.status(status::NO_PREFIX_AVAIL, b"").map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::STATUS_CODE
        })
    );
    assert_eq!(b.len(), 49);
    // The builder is still balanced and usable: the IA_PD closes with its one prefix.
    b.end(ia).expect("end of 25");
    let len = b.finish().expect("balanced");
    assert_eq!(len, 49);
    let expected = build(|b| {
        b.message(MessageType::Reply, 9).expect("header");
        let ia = b.begin_ia_pd(1, 2, 3).expect("16 octets");
        b.ia_prefix(ip("2001:db8:180:110::"), 60, 3000, 4000)
            .expect("29 octets");
        b.end(ia).expect("end of 25");
    });
    assert_eq!(&buf[..len], expected.as_slice());
    let message = Message::parse(&buf[..len]).expect("parse");
    message.validate().expect("well formed");
    let pds: Vec<IaPd<'_>> = message
        .ia_pds()
        .collect::<Result<_, _>>()
        .expect("well-formed IA_PD options");
    assert_eq!(pds.len(), 1);
    assert_eq!(pds[0].prefixes().count(), 1);

    // An IA_PD head that does not fit is taken back whole.
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, 40).expect("builder");
    b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
        .expect("34 octets");
    assert_eq!(
        b.begin_ia_pd(1, 2, 3).map(|_| ()),
        Err(EncodeError::NoRoom { code: code::IA_PD })
    );
    assert_eq!(b.len(), 34);
    assert_eq!(b.finish(), Ok(34));
}

// ---------------------------------------------------------------------------------------
// Relay chains
// ---------------------------------------------------------------------------------------

#[test]
fn a_message_that_came_without_a_relay_has_a_chain_of_depth_zero() {
    let bytes = fx("solicit-dhclient");
    let message = Message::parse(&bytes).expect("parse");
    let chain = RelayChain::parse(message).expect("chain");
    assert_eq!(chain.depth(), 0);
    assert!(!chain.is_relayed());
    assert_eq!(chain.client(), message);
    assert_eq!(chain.relays().count(), 0);
    assert!(chain.innermost().is_none());
    assert!(chain.outermost().is_none());
    assert_eq!(chain.link_address(), None);
    assert_eq!(chain.interface_id(), None);
    assert_eq!(chain.remote_id(), None);
    assert_eq!(chain.client_link_layer(), None);
}

#[test]
fn a_relay_chain_one_deep_reads_the_options_of_its_relay() {
    let bytes = fx("relay-forw-1");
    let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
    assert_eq!(chain.depth(), 1);
    assert!(chain.is_relayed());
    assert_eq!(chain.outermost(), chain.innermost());
    assert_eq!(chain.outermost().expect("a relay").as_bytes(), &bytes[..]);
    assert_eq!(chain.link_address(), Some(ip("2001:db8:1::1")));
    assert_eq!(chain.interface_id(), Some(&b"eth1"[..]));
    let remote: RemoteId<'_> = chain.remote_id().expect("a remote id");
    assert_eq!(remote.enterprise, 32473);
    assert_eq!(remote.id, [1, 2, 3, 4]);
    let link_layer: LinkLayerAddress<'_> = chain.client_link_layer().expect("a link-layer");
    assert_eq!(link_layer.mac(), Some(MAC_1));
    let client = chain.client();
    assert_eq!(client.as_bytes(), &fx("solicit-dhclient")[..]);
    assert_eq!(client.kind(), MessageType::Solicit);
    assert_eq!(
        client.client_id().expect("ok").expect("1").link_layer(),
        Some((1, &MAC_1[..]))
    );
}

#[test]
fn a_relay_chain_two_deep_yields_the_innermost_link_address() {
    let bytes = fx("relay-forw-2");
    let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
    assert_eq!(chain.depth(), 2);
    assert!(chain.is_relayed());
    let outermost = chain.outermost().expect("outermost");
    let innermost = chain.innermost().expect("innermost");
    assert_eq!(outermost.as_bytes(), &bytes[..]);
    assert_eq!(outermost.hop_count(), 1);
    assert_eq!(innermost.hop_count(), 0);
    assert_eq!(innermost.len(), 122);
    // Outermost first.
    let order: Vec<u8> = chain.relays().map(|relay| relay.hop_count()).collect();
    assert_eq!(order, [1, 0]);
    let reversed: Vec<u8> = chain
        .relays()
        .rev()
        .map(|relay| relay.hop_count())
        .collect();
    assert_eq!(reversed, [0, 1]);
    // RFC 6221 section 5.3: the lightweight relay's :: is skipped, the relay above names the
    // link.
    assert_eq!(innermost.link_address(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(chain.link_address(), Some(ip("2001:db8:ffff::1")));
    // Only the inner relay sent an Interface-Id; nobody sent a Remote-Id or a link-layer.
    assert_eq!(chain.interface_id(), Some(&b"port-7"[..]));
    assert_eq!(chain.remote_id(), None);
    assert_eq!(chain.client_link_layer(), None);
    let client = chain.client();
    assert_eq!(client.as_bytes(), &fx("solicit-networkd")[..]);
    assert_eq!(client.kind(), MessageType::Solicit);
    assert_eq!(client.transaction_id(), 0x0b_17c9);
}

#[test]
fn the_link_address_comes_from_the_innermost_relay_that_names_one() {
    // Two relays that both name a link: the innermost's wins.
    let bytes = build(|b| {
        b.relay(
            MessageType::RelayForw,
            1,
            ip("2001:db8:aaaa::1"),
            ip("2001:db8:1::2"),
        )
        .expect("outer");
        let outer = b.begin(code::RELAY_MSG).expect("9");
        b.relay(
            MessageType::RelayForw,
            0,
            ip("2001:db8:bbbb::1"),
            ip("fe80::1"),
        )
        .expect("inner");
        let inner = b.begin(code::RELAY_MSG).expect("9");
        put_solicit_dhclient(b);
        b.end(inner).expect("end");
        b.end(outer).expect("end");
    });
    let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
    assert_eq!(chain.depth(), 2);
    assert_eq!(chain.link_address(), Some(ip("2001:db8:bbbb::1")));

    // A chain whose relays all send :: names no link.
    let bytes = build(|b| {
        b.relay(
            MessageType::RelayForw,
            0,
            Ipv6Addr::UNSPECIFIED,
            ip("fe80::1"),
        )
        .expect("relay");
        let relayed = b.begin(code::RELAY_MSG).expect("9");
        put_solicit_dhclient(b);
        b.end(relayed).expect("end");
    });
    let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
    assert_eq!(chain.depth(), 1);
    assert_eq!(chain.link_address(), None);
}

#[test]
fn the_relay_options_come_from_the_innermost_relay_that_sends_them() {
    // The outer relay sends an Interface-Id and a Remote-Id, the inner one only an
    // Interface-Id: the inner one wins where both exist, the outer one fills the gap.
    let bytes = build(|b| {
        b.relay(
            MessageType::RelayForw,
            1,
            ip("2001:db8:aaaa::1"),
            ip("2001:db8:1::2"),
        )
        .expect("outer");
        b.option(code::INTERFACE_ID, b"outer-if").expect("18");
        b.option_parts(code::REMOTE_ID, &[&9u32.to_be_bytes(), b"outer-remote"])
            .expect("37");
        let outer = b.begin(code::RELAY_MSG).expect("9");
        b.relay(
            MessageType::RelayForw,
            0,
            ip("2001:db8:bbbb::1"),
            ip("fe80::1"),
        )
        .expect("inner");
        b.option(code::INTERFACE_ID, b"inner-if").expect("18");
        b.option(code::CLIENT_LINKLAYER_ADDR, &[0, 1, 0, 0, 0x5e, 0, 0x53, 9])
            .expect("79");
        let inner = b.begin(code::RELAY_MSG).expect("9");
        put_solicit_dhclient(b);
        b.end(inner).expect("end");
        b.end(outer).expect("end");
    });
    let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
    assert_eq!(chain.interface_id(), Some(&b"inner-if"[..]));
    let remote = chain.remote_id().expect("the outer relay's remote id");
    assert_eq!(remote.enterprise, 9);
    assert_eq!(remote.id, b"outer-remote");
    assert_eq!(
        chain.client_link_layer().expect("link-layer").mac(),
        Some([0, 0, 0x5e, 0, 0x53, 9])
    );
}

#[test]
fn a_relay_chain_eight_deep_is_walked_and_nine_deep_is_refused() {
    fn nested(depth: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let mut b = MessageBuilder::new(&mut buf, 4096).expect("builder");
        let mut marks = Vec::new();
        for level in 0..depth {
            let hop = u8::try_from(depth - 1 - level).expect("a hop count");
            b.relay(
                MessageType::RelayForw,
                hop,
                ip("2001:db8:1::1"),
                ip("fe80::1"),
            )
            .expect("relay header");
            marks.push(b.begin(code::RELAY_MSG).expect("9"));
        }
        put_solicit_dhclient(&mut b);
        while let Some(mark) = marks.pop() {
            b.end(mark).expect("end of 9");
        }
        let len = b.finish().expect("balanced");
        buf.truncate(len);
        buf
    }

    assert_eq!(HOP_COUNT_LIMIT, 8);
    assert_eq!(MAX_RELAY_DEPTH, 8);
    for depth in 1..=MAX_RELAY_DEPTH {
        let bytes = nested(depth);
        let chain = RelayChain::parse(Message::parse(&bytes).expect("parse")).expect("chain");
        assert_eq!(chain.depth(), depth);
        assert_eq!(chain.client().kind(), MessageType::Solicit);
        assert_eq!(chain.relays().count(), depth);
        assert_eq!(
            chain.outermost().expect("outermost").hop_count(),
            u8::try_from(depth - 1).expect("hop")
        );
        assert_eq!(chain.innermost().expect("innermost").hop_count(), 0);
    }
    let too_deep = nested(MAX_RELAY_DEPTH + 1);
    let message = Message::parse(&too_deep).expect("the outer header parses");
    assert_eq!(
        RelayChain::parse(message).map(|_| ()),
        Err(DecodeError::RelayChain)
    );
}

#[test]
fn a_relay_chain_that_ends_in_a_short_message_names_its_length() {
    let bytes = build(|b| {
        b.relay(
            MessageType::RelayForw,
            0,
            ip("2001:db8:1::1"),
            ip("fe80::1"),
        )
        .expect("relay");
        b.option(code::RELAY_MSG, &[1, 2, 3]).expect("9");
    });
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(
        RelayChain::parse(message).map(|_| ()),
        Err(DecodeError::TooShort { len: 3 })
    );
    assert_eq!(
        message.relay_message().map(|_| ()),
        Err(DecodeError::TooShort { len: 3 })
    );
}

#[test]
fn a_relay_chain_whose_options_are_cut_before_the_relayed_message_is_refused() {
    let mut bytes = build(|b| {
        b.relay(
            MessageType::RelayForw,
            0,
            ip("2001:db8:1::1"),
            ip("fe80::1"),
        )
        .expect("relay");
        b.option(code::INTERFACE_ID, b"eth1").expect("18");
        let relayed = b.begin(code::RELAY_MSG).expect("9");
        put_solicit_dhclient(b);
        b.end(relayed).expect("end");
    });
    // Cut inside the Relay Message option.
    bytes.truncate(bytes.len() - 10);
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(
        RelayChain::parse(message).map(|_| ()),
        Err(DecodeError::Truncated {
            code: code::RELAY_MSG
        })
    );
    // The Interface-Id before it stays readable.
    assert_eq!(message.interface_id(), Ok(Some(&b"eth1"[..])));
}

// ---------------------------------------------------------------------------------------
// Malformed messages
// ---------------------------------------------------------------------------------------

#[test]
fn a_datagram_shorter_than_its_header_does_not_parse() {
    let short = fx("malformed-short");
    assert_eq!(short.len(), 3);
    assert_eq!(
        Message::parse(&short).map(|_| ()),
        Err(DecodeError::TooShort { len: 3 })
    );
    assert_eq!(
        Message::parse(&[]).map(|_| ()),
        Err(DecodeError::TooShort { len: 0 })
    );
    // A relay header is 34 octets, not four.
    let relay = fx("malformed-relay-short");
    assert_eq!(relay.len(), 20);
    assert_eq!(
        Message::parse(&relay).map(|_| ()),
        Err(DecodeError::TooShort { len: 20 })
    );
    let mut relay = fx("relay-forw-1");
    relay.truncate(RELAY_HEADER_LEN - 1);
    assert_eq!(
        Message::parse(&relay).map(|_| ()),
        Err(DecodeError::TooShort { len: 33 })
    );
    relay.push(0);
    let header_only = Message::parse(&relay).expect("a bare relay header parses");
    assert_eq!(header_only.options().count(), 0);
    assert!(header_only.relay_message().expect("ok").is_none());
}

#[test]
fn the_smallest_messages_have_no_options() {
    let message = Message::parse(&[1, 0, 0, 7]).expect("a bare header");
    assert_eq!(message.kind(), MessageType::Solicit);
    assert_eq!(message.transaction_id(), 7);
    assert_eq!(message.options().count(), 0);
    assert_eq!(message.validate(), Ok(()));
    assert_eq!(message.client_id(), Ok(None));
    assert_eq!(message.ia_nas().count(), 0);
    // A type the codec does not know is a client message of that type.
    for kind in [0u8, 14, 21, 255] {
        let bytes = [kind, 1, 2, 3];
        let message = Message::parse(&bytes).expect("parse");
        assert_eq!(message.kind(), MessageType::Other(kind));
        assert!(!message.is_relay());
        assert_eq!(message.transaction_id(), 0x01_0203);
    }
}

#[test]
fn a_truncated_option_leaves_the_options_before_it_readable() {
    let bytes = fx("malformed-truncated-option");
    let message = Message::parse(&bytes).expect("the header parses");
    let error = DecodeError::Truncated { code: code::ORO };
    assert_eq!(message.validate(), Err(error));
    let items: Vec<_> = message.options().collect();
    assert_eq!(items.len(), 3, "two options and the error, once");
    assert!(items[0].is_ok());
    assert!(items[1].is_ok());
    assert_eq!(items[2], Err(error));
    // The options before the malformed one.
    assert_eq!(
        message.client_id().expect("ok").expect("1").as_bytes(),
        DUID_LL_1
    );
    assert_eq!(message.elapsed_time(), Ok(Some(0)));
    assert!(message.has(code::CLIENTID));
    // The malformed option and anything after it.
    assert_eq!(message.option_request().map(|_| ()), Err(error));
    assert_eq!(message.option(code::ORO), Err(error));
    assert_eq!(message.server_id(), Err(error));
    assert!(!message.has(code::ORO));
    assert!(!message.rapid_commit());
    let mut ias = message.ia_nas();
    assert_eq!(ias.next(), Some(Err(error)));
    assert_eq!(ias.next(), None);
}

#[test]
fn an_ia_na_below_twelve_octets_is_a_bad_length_and_ends_the_ia_walk() {
    let bytes = fx("malformed-ia-na-short");
    let message = Message::parse(&bytes).expect("parse");
    // The walk of the options is well formed.
    assert_eq!(message.validate(), Ok(()));
    assert_eq!(option_codes(&message), [1, 3]);
    assert_eq!(
        message.client_id().expect("ok").expect("1").as_bytes(),
        DUID_LL_1
    );
    assert!(message.has(code::IA_NA));
    let error = DecodeError::BadLength {
        code: code::IA_NA,
        len: 8,
    };
    let mut ias = message.ia_nas();
    assert_eq!(ias.next(), Some(Err(error)));
    assert_eq!(ias.next(), None);
    assert_eq!(IaNa::parse(&[0; 8]).map(|_| ()), Err(error));
}

#[test]
fn a_relay_forw_without_a_relay_message_option_is_refused() {
    let bytes = fx("malformed-relay-no-msg");
    let message = Message::parse(&bytes).expect("parse");
    assert_eq!(message.kind(), MessageType::RelayForw);
    assert_eq!(message.validate(), Ok(()));
    assert_eq!(message.relay_message(), Ok(None));
    assert_eq!(message.interface_id(), Ok(Some(&b"eth1"[..])));
    assert_eq!(
        RelayChain::parse(message).map(|_| ()),
        Err(DecodeError::RelayChain)
    );
}

#[test]
fn nine_nested_relay_forws_are_refused() {
    let bytes = fx("malformed-relay-too-deep");
    let message = Message::parse(&bytes).expect("the outer header parses");
    assert_eq!(message.kind(), MessageType::RelayForw);
    assert_eq!(message.hop_count(), 8);
    assert_eq!(message.validate(), Ok(()));
    assert_eq!(
        RelayChain::parse(message).map(|_| ()),
        Err(DecodeError::RelayChain)
    );
    // Eight layers are fine: take the Relay Message of the outermost one.
    let eight = message.relay_message().expect("ok").expect("9");
    let chain = RelayChain::parse(eight).expect("eight relays deep");
    assert_eq!(chain.depth(), MAX_RELAY_DEPTH);
    assert_eq!(chain.client().as_bytes(), &fx("solicit-dhclient")[..]);
}

#[test]
fn the_option_walk_reports_a_truncated_header_once_and_stops() {
    // An option, then 1, 2 and 3 stray octets.
    let option = [0, 8, 0, 2, 0, 0];
    let cases: [(&[u8], Option<u16>); 4] = [
        (&[], None),
        (&[0x00], Some(0)),
        (&[0x00, 0x07], Some(7)),
        (&[0x00, 0x07, 0x00], Some(7)),
    ];
    for (tail, expected) in cases {
        let mut area = option.to_vec();
        area.extend_from_slice(tail);
        let items: Vec<_> = Options::new(&area).collect();
        match expected {
            None => assert_eq!(items.len(), 1, "{tail:?}"),
            Some(code) => {
                assert_eq!(items.len(), 2, "{tail:?}");
                assert_eq!(items[1], Err(DecodeError::Truncated { code }), "{tail:?}");
            }
        }
        assert_eq!(items[0].expect("the first option").code, 8);
        assert_eq!(
            Options::new(&area).first(8),
            Ok(Some(&[0u8, 0][..])),
            "{tail:?}"
        );
        assert!(Options::new(&area).has(8));
        assert_eq!(
            Options::new(&area).validate().is_ok(),
            expected.is_none(),
            "{tail:?}"
        );
    }
    // A value that runs past the end, with the code reported.
    let area = [0, 6, 0, 4, 0, 23];
    assert_eq!(
        Options::new(&area).first(6),
        Err(DecodeError::Truncated { code: 6 })
    );
    assert_eq!(
        Options::new(&area).first(99),
        Err(DecodeError::Truncated { code: 6 })
    );
    assert!(!Options::new(&area).has(6));
}

#[test]
fn a_zero_length_option_and_repeated_options_are_walked_in_order() {
    let area = [
        0, 14, 0, 0, // rapid commit
        0, 23, 0, 0, // an empty address list
        0, 14, 0, 0, // rapid commit again
    ];
    let codes: Vec<u16> = Options::new(&area)
        .map(|option| option.expect("ok").code)
        .collect();
    assert_eq!(codes, [14, 23, 14]);
    assert_eq!(Options::new(&area).first(23), Ok(Some(&[][..])));
}

#[test]
fn a_malformed_option_value_is_the_error_of_its_typed_accessor_only() {
    // An elapsed time of one octet, a client FQDN with a compression pointer, a
    // Remote-Id of four octets and a Client Link-Layer of two.
    let bytes = build(|b| {
        b.message(MessageType::Solicit, 1).expect("header");
        b.option(code::ELAPSED_TIME, &[7]).expect("8");
        b.option(code::CLIENT_FQDN, &[1, 0xc0, 0x0c]).expect("39");
        b.option(code::REMOTE_ID, &[0, 0, 0, 9]).expect("37");
        b.option(code::CLIENT_LINKLAYER_ADDR, &[0, 1]).expect("79");
        b.option(code::CLIENTID, &[0, 3]).expect("1");
        b.option(code::RAPID_COMMIT, &[]).expect("14");
    });
    let message = Message::parse(&bytes).expect("parse");
    // The walk is fine, and the later options are still found.
    assert_eq!(message.validate(), Ok(()));
    assert!(message.rapid_commit());
    assert_eq!(
        message.elapsed_time(),
        Err(DecodeError::BadLength {
            code: code::ELAPSED_TIME,
            len: 1
        })
    );
    assert_eq!(
        message.client_fqdn().map(|_| ()),
        Err(DecodeError::BadValue {
            code: code::CLIENT_FQDN
        })
    );
    assert_eq!(
        message.remote_id().map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::REMOTE_ID,
            len: 4
        })
    );
    assert_eq!(
        message.client_link_layer().map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::CLIENT_LINKLAYER_ADDR,
            len: 2
        })
    );
    assert_eq!(
        message.client_id().map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::CLIENTID,
            len: 2
        })
    );
}

// ---------------------------------------------------------------------------------------
// The builder's rules
// ---------------------------------------------------------------------------------------

#[test]
fn a_builder_needs_room_for_a_relay_header() {
    let mut small = [0u8; 33];
    assert_eq!(
        MessageBuilder::new(&mut small, 33).map(|_| ()),
        Err(EncodeError::BufferTooSmall)
    );
    let mut buf = [0u8; 64];
    assert_eq!(
        MessageBuilder::new(&mut buf, 33).map(|_| ()),
        Err(EncodeError::BufferTooSmall)
    );
    // The limit is clamped to the buffer.
    let mut buf = [0u8; 40];
    let mut builder = MessageBuilder::new(&mut buf, 4096).expect("34 octets fit");
    assert_eq!(builder.room(), 40);
    assert!(builder.is_empty());
    builder.message(MessageType::Solicit, 1).expect("header");
    assert_eq!(builder.len(), 4);
    assert_eq!(builder.room(), 36);
    assert!(!builder.is_empty());
}

#[test]
fn an_option_that_does_not_fit_leaves_the_message_unchanged() {
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, 40).expect("builder");
    b.message(MessageType::Solicit, 1).expect("header");
    b.option(code::CLIENTID, &[0xee; 20])
        .expect("fits: 24 octets");
    assert_eq!(b.len(), 28);
    assert_eq!(b.room(), 12);

    let before = b.len();
    assert_eq!(
        b.option(code::SERVERID, &[0xdd; 20]).map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::SERVERID
        })
    );
    assert_eq!(b.len(), before);
    assert_eq!(
        b.option_parts(code::STATUS_CODE, &[&[0, 0], &[b'x'; 20]])
            .map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::STATUS_CODE
        })
    );
    assert_eq!(b.len(), before);
    assert_eq!(
        b.addresses(code::DNS_SERVERS, &[ip("2001:db8::53")])
            .map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::DNS_SERVERS
        })
    );
    assert_eq!(b.len(), before);
    assert_eq!(
        b.ia_address(ip("2001:db8:1::100"), 1, 2).map(|_| ()),
        Err(EncodeError::NoRoom { code: code::IAADDR })
    );
    assert_eq!(b.len(), before);
    assert_eq!(
        b.client_fqdn(
            ClientFqdn::FLAG_S,
            &name("a-long-enough-name.example.test.")
        )
        .map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::CLIENT_FQDN
        })
    );
    assert_eq!(b.len(), before);
    // The 12 octets that remain take an option of exactly that size.
    b.option(code::RAPID_COMMIT, &[]).expect("4 octets");
    b.option(code::ORO, &[0, 23, 0, 24]).expect("8 octets");
    assert_eq!(b.len(), 40);
    assert_eq!(b.room(), 0);
    assert_eq!(
        b.option(code::RAPID_COMMIT, &[]).map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::RAPID_COMMIT
        })
    );
    assert_eq!(b.len(), 40);
    assert_eq!(b.finish(), Ok(40));
    // Nothing of the refused options reached the buffer.
    assert_eq!(&buf[28..40], [0, 14, 0, 0, 0, 6, 0, 4, 0, 23, 0, 24]);
    let message = Message::parse(&buf[..40]).expect("parse");
    message.validate().expect("well formed");
    assert_eq!(option_codes(&message), [1, 14, 6]);
}

#[test]
fn a_header_that_does_not_fit_is_refused_with_code_zero() {
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, 40).expect("builder");
    b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
        .expect("34 octets");
    assert_eq!(b.len(), 34);
    assert_eq!(
        b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
            .map(|_| ()),
        Err(EncodeError::NoRoom { code: 0 })
    );
    assert_eq!(b.len(), 34);
    b.message(MessageType::Solicit, 1)
        .expect("4 octets, up to 38");
    assert_eq!(
        b.message(MessageType::Solicit, 1).map(|_| ()),
        Err(EncodeError::NoRoom { code: 0 })
    );
    assert_eq!(b.len(), 38);
}

#[test]
fn an_opened_option_that_does_not_fit_leaves_the_message_unchanged() {
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, 40).expect("builder");
    b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
        .expect("34 octets");
    // `begin` needs four octets: they fit (38), but an IA_NA also needs its 12-octet head.
    let before = b.len();
    assert_eq!(
        b.begin_ia_na(1, 2, 3).map(|_| ()),
        Err(EncodeError::NoRoom { code: code::IA_NA })
    );
    assert_eq!(b.len(), before, "the opened IA_NA is taken back");
    assert_eq!(
        b.begin_ia_address(ip("2001:db8::1"), 1, 2).map(|_| ()),
        Err(EncodeError::NoRoom { code: code::IAADDR })
    );
    assert_eq!(b.len(), before);
    // The builder is still balanced and usable.
    b.option(code::RAPID_COMMIT, &[]).expect("4 octets");
    assert_eq!(b.finish(), Ok(38));

    // `begin` itself fails when not even code and length fit.
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, 36).expect("builder");
    b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
        .expect("34 octets");
    assert_eq!(
        b.begin(code::RELAY_MSG).map(|_| ()),
        Err(EncodeError::NoRoom {
            code: code::RELAY_MSG
        })
    );
    assert_eq!(b.len(), 34);
    assert_eq!(b.finish(), Ok(34));
}

#[test]
fn a_nested_option_that_does_not_fit_can_be_taken_back_and_the_message_stays_valid() {
    let mut buf = [0u8; 80];
    let mut b = MessageBuilder::new(&mut buf, 60).expect("builder");
    b.message(MessageType::Reply, 9).expect("header");
    b.option(code::SERVERID, &DUID_UUID).expect("22 octets");
    let before = b.len();
    assert_eq!(before, 4 + 22);
    let ia = b.begin_ia_na(1, 2, 3).expect("16 octets: 42 in all");
    assert_eq!(b.len(), 42);
    assert_eq!(
        b.ia_address(ip("2001:db8::1"), 4, 5).map(|_| ()),
        Err(EncodeError::NoRoom { code: code::IAADDR })
    );
    assert_eq!(b.len(), 42, "the refused address left no trace");
    // The caller leaves the IA_NA out.
    b.rewind(ia).expect("rewind");
    assert_eq!(b.len(), before);
    b.status(status::NO_ADDRS_AVAIL, b"none")
        .expect("10 octets");
    let len = b.finish().expect("balanced");
    let message = Message::parse(&buf[..len]).expect("parse");
    message.validate().expect("well formed");
    assert_eq!(option_codes(&message), [2, 13]);
    assert_eq!(message.ia_nas().count(), 0);
}

#[test]
fn rewind_takes_back_an_opened_option_and_what_was_written_in_it() {
    let mut buf = [0xa5u8; 256];
    let mut b = MessageBuilder::new(&mut buf, 256).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");
    b.option(code::CLIENTID, &DUID_LL_1).expect("1");
    let before = b.len();
    assert_eq!(before, 18);

    let ia = b.begin_ia_na(1, 2, 3).expect("3");
    b.ia_address(ip("2001:db8::1"), 4, 5).expect("5");
    let address = b.begin_ia_address(ip("2001:db8::2"), 6, 7).expect("5");
    b.status(status::NOT_ON_LINK, b"nope").expect("13");
    assert!(b.len() > before + 12);
    // The innermost option first, then the one around it.
    assert!(b.rewind(ia).is_err(), "the IA_NA is not the innermost");
    b.rewind(address).expect("rewind the address");
    b.end(ia)
        .expect("close the IA_NA, which now holds one address");
    let closed = b.len();
    assert_eq!(closed, before + 4 + 12 + 28);

    let second = b.begin_ia_na(2, 0, 0).expect("3");
    b.ia_address(ip("2001:db8::3"), 1, 1).expect("5");
    b.rewind(second).expect("rewind the whole second IA_NA");
    assert_eq!(b.len(), closed);
    b.option(code::ELAPSED_TIME, &[0, 0]).expect("8");
    let len = b.finish().expect("balanced");
    let message = Message::parse(&buf[..len]).expect("parse");
    message.validate().expect("well formed");
    assert_eq!(option_codes(&message), [1, 3, 8]);
    let ias = ia_nas(&message);
    assert_eq!(ias.len(), 1);
    assert_eq!(ias[0].iaid, 1);
    let found = addresses(&ias[0]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, ip("2001:db8::1"));
}

#[test]
fn finishing_with_an_option_open_is_unbalanced() {
    let mut buf = [0u8; 128];
    let mut b = MessageBuilder::new(&mut buf, 128).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");
    let _ia = b.begin_ia_na(1, 2, 3).expect("3");
    assert_eq!(b.finish(), Err(EncodeError::Unbalanced));

    let mut buf = [0u8; 128];
    let mut b = MessageBuilder::new(&mut buf, 128).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");
    let ia = b.begin_ia_na(1, 2, 3).expect("3");
    let _address = b.begin_ia_address(ip("2001:db8::1"), 1, 2).expect("5");
    // Closing only the outer one is not enough, and not allowed.
    assert_eq!(b.end(ia).map(|_| ()), Err(EncodeError::Unbalanced));
    assert_eq!(b.finish(), Err(EncodeError::Unbalanced));
}

#[test]
fn ending_with_a_stale_or_foreign_mark_is_unbalanced() {
    let mut buf = [0u8; 256];
    let mut b = MessageBuilder::new(&mut buf, 256).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");

    // A mark that was already ended.
    let first = b.begin(code::RELAY_MSG).expect("9");
    b.end(first).expect("end");
    assert_eq!(b.end(first).map(|_| ()), Err(EncodeError::Unbalanced));
    // A mark that was rewound.
    let second = b.begin(code::RELAY_MSG).expect("9");
    b.rewind(second).expect("rewind");
    assert_eq!(b.end(second).map(|_| ()), Err(EncodeError::Unbalanced));
    assert_eq!(b.rewind(second).map(|_| ()), Err(EncodeError::Unbalanced));
    // A rewound mark while another option is open at the same depth, elsewhere.
    let third = b.begin(code::IA_NA).expect("3");
    b.rewind(third).expect("rewind");
    b.option(code::RAPID_COMMIT, &[]).expect("14");
    let fourth = b.begin(code::IA_NA).expect("3");
    assert_eq!(b.end(third).map(|_| ()), Err(EncodeError::Unbalanced));
    // The open option is unharmed.
    b.end(fourth).expect("end");
    // Out of order.
    let outer = b.begin(code::IA_NA).expect("3");
    let inner = b.begin(code::IAADDR).expect("5");
    assert_eq!(b.end(outer).map(|_| ()), Err(EncodeError::Unbalanced));
    assert_eq!(b.rewind(outer).map(|_| ()), Err(EncodeError::Unbalanced));
    b.end(inner).expect("end the inner one");
    b.end(outer).expect("end the outer one");
    assert_eq!(b.end(inner).map(|_| ()), Err(EncodeError::Unbalanced));
    let len = b.finish().expect("balanced in the end");
    let message = Message::parse(&buf[..len]).expect("parse");
    message.validate().expect("well formed");
    assert_eq!(option_codes(&message), [9, 14, 3, 3]);
}

#[test]
fn options_nest_to_the_limit_and_no_deeper() {
    let mut buf = vec![0u8; 4096];
    let mut b = MessageBuilder::new(&mut buf, 4096).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");
    let mut marks = Vec::new();
    for _ in 0..MAX_NESTING {
        marks.push(b.begin(code::RELAY_MSG).expect("within the nesting limit"));
    }
    let len = b.len();
    assert_eq!(
        b.begin(code::RELAY_MSG).map(|_| ()),
        Err(EncodeError::Unbalanced)
    );
    assert_eq!(b.len(), len);
    while let Some(mark) = marks.pop() {
        b.end(mark).expect("end");
    }
    assert!(b.finish().is_ok());
}

#[test]
fn a_value_above_65535_octets_is_too_long() {
    let mut buf = vec![0u8; 140_000];
    let mut b = MessageBuilder::new(&mut buf, 140_000).expect("builder");
    b.message(MessageType::Reply, 1).expect("header");
    let before = b.len();
    assert_eq!(
        b.option(code::VENDOR_OPTS, &vec![0u8; 65_536]).map(|_| ()),
        Err(EncodeError::TooLong {
            code: code::VENDOR_OPTS
        })
    );
    assert_eq!(b.len(), before);
    b.option(code::VENDOR_OPTS, &vec![0u8; 65_535])
        .expect("the longest value");
    assert_eq!(b.len(), before + 4 + 65_535);

    // An opened option that outgrows its length field cannot be ended.
    let mark = b.begin(code::RELAY_MSG).expect("9");
    b.option(code::VENDOR_OPTS, &vec![0u8; 65_535])
        .expect("a long value");
    assert_eq!(
        b.end(mark).map(|_| ()),
        Err(EncodeError::TooLong {
            code: code::RELAY_MSG
        })
    );
}

#[test]
fn domain_lists_and_ntp_servers_are_encoded_and_bounded() {
    let mut out = [0u8; 64];
    let names = [name("example.test."), name("lab.example.test.")];
    let len = encode_domain_list(&names, &mut out).expect("room");
    assert_eq!(len, 32);
    assert_eq!(&out[..14], b"\x07example\x04test\x00");
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, &out[..len])
            .expect("names")
            .iter()
            .collect::<Vec<_>>(),
        names
    );
    assert_eq!(encode_domain_list(&[], &mut out), Ok(0));
    // A relative name cannot be in the list (RFC 3646: absolute names).
    assert_eq!(
        encode_domain_list(&[name("lab")], &mut out),
        Err(EncodeError::BadValue {
            code: code::DOMAIN_LIST
        })
    );
    let mut small = [0u8; 31];
    assert_eq!(
        encode_domain_list(&names, &mut small),
        Err(EncodeError::NoRoom {
            code: code::DOMAIN_LIST
        })
    );

    let mut out = [0u8; 40];
    let servers = [ip("2001:db8::123"), ip("2001:db8::124")];
    let len = encode_ntp_servers(&servers, &mut out).expect("room");
    assert_eq!(len, 40);
    assert_eq!(&out[..4], [0, 1, 0, 16]);
    assert_eq!(&out[4..20], servers[0].octets());
    assert_eq!(&out[20..24], [0, 1, 0, 16]);
    assert_eq!(&out[24..40], servers[1].octets());
    assert_eq!(encode_ntp_servers(&[], &mut out), Ok(0));
    let mut small = [0u8; 39];
    assert_eq!(
        encode_ntp_servers(&servers, &mut small),
        Err(EncodeError::NoRoom {
            code: code::NTP_SERVER
        })
    );
}

// ---------------------------------------------------------------------------------------
// The typed options on the vectors of their RFCs
// ---------------------------------------------------------------------------------------

#[test]
fn message_types_round_trip_and_know_the_relay_types() {
    for value in 0..=255u8 {
        let kind = MessageType::from_u8(value);
        assert_eq!(kind.to_u8(), value);
        assert_eq!(kind.is_relay(), value == 12 || value == 13, "{value}");
    }
    assert_eq!(MessageType::from_u8(1), MessageType::Solicit);
    assert_eq!(MessageType::from_u8(11), MessageType::InformationRequest);
    assert_eq!(MessageType::from_u8(12), MessageType::RelayForw);
    assert_eq!(MessageType::from_u8(13), MessageType::RelayRepl);
    assert_eq!(MessageType::from_u8(14), MessageType::Other(14));
    assert_eq!(MessageType::from_u8(0), MessageType::Other(0));
}

#[test]
fn a_duid_llt_carries_a_hardware_type_a_time_and_an_address() {
    // RFC 8415 section 11.2: type 1, hardware type, time, link-layer address.
    let llt = [
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95,
    ];
    let duid = Duid::parse(code::CLIENTID, &llt).expect("a DUID-LLT");
    assert_eq!(duid.kind(), Duid::LLT);
    assert_eq!(duid.time(), Some(0x1c39_cf88));
    assert_eq!(
        duid.link_layer(),
        Some((1, &[0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95][..]))
    );
    assert_eq!(duid.enterprise(), None);
    assert_eq!(duid.uuid(), None);
    assert_eq!(duid.as_bytes(), llt);
    assert_eq!(duid.body(), &llt[2..]);
    // Without an address there is no link layer; the time is still there.
    let bare = Duid::parse(code::CLIENTID, &llt[..8]).expect("eight octets");
    assert_eq!(bare.time(), Some(0x1c39_cf88));
    assert_eq!(bare.link_layer(), None);
    // Without a full time there is nothing.
    let cut = Duid::parse(code::CLIENTID, &llt[..7]).expect("seven octets");
    assert_eq!(cut.time(), None);
    assert_eq!(cut.link_layer(), None);
}

#[test]
fn a_duid_en_carries_an_enterprise_number_and_an_identifier() {
    // RFC 8415 section 11.3, the example: enterprise 9 (ciscoSystems), the identifier
    // 0c:c0:84:d3:03:00:09:12.
    let en = [
        0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x0c, 0xc0, 0x84, 0xd3, 0x03, 0x00, 0x09, 0x12,
    ];
    let duid = Duid::parse(code::SERVERID, &en).expect("a DUID-EN");
    assert_eq!(duid.kind(), Duid::EN);
    assert_eq!(duid.enterprise(), Some(9));
    assert_eq!(
        duid.body()[4..],
        [0x0c, 0xc0, 0x84, 0xd3, 0x03, 0x00, 0x09, 0x12]
    );
    assert_eq!(duid.link_layer(), None);
    assert_eq!(duid.time(), None);
    assert_eq!(duid.uuid(), None);
    // Four octets of enterprise number need six octets in all.
    let cut = Duid::parse(code::SERVERID, &en[..5]).expect("five octets");
    assert_eq!(cut.enterprise(), None);
    let minimal = Duid::parse(code::SERVERID, &en[..6]).expect("six octets");
    assert_eq!(minimal.enterprise(), Some(9));
}

#[test]
fn a_duid_ll_carries_a_hardware_type_and_an_address() {
    // RFC 8415 section 11.4.
    let ll = [0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
    let duid = Duid::parse(code::CLIENTID, &ll).expect("a DUID-LL");
    assert_eq!(duid.kind(), Duid::LL);
    assert_eq!(duid.link_layer(), Some((1, &MAC_1[..])));
    assert_eq!(duid.time(), None);
    assert_eq!(duid.enterprise(), None);
    assert_eq!(duid.uuid(), None);
    // A hardware type alone has no address.
    assert_eq!(
        Duid::parse(code::CLIENTID, &ll[..4])
            .expect("four octets")
            .link_layer(),
        None
    );
    // Another hardware type (32, InfiniBand) with a longer address.
    let infiniband = [0x00, 0x03, 0x00, 0x20, 1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        Duid::parse(code::CLIENTID, &infiniband)
            .expect("a DUID-LL")
            .link_layer(),
        Some((32, &[1, 2, 3, 4, 5, 6, 7, 8][..]))
    );
}

#[test]
fn a_duid_uuid_carries_sixteen_octets() {
    // RFC 6355 section 4: type 4 and a UUID (here the DNS namespace of RFC 4122).
    let uuid = [
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ];
    let mut data = vec![0x00, 0x04];
    data.extend_from_slice(&uuid);
    let duid = Duid::parse(code::CLIENTID, &data).expect("a DUID-UUID");
    assert_eq!(duid.kind(), Duid::UUID);
    assert_eq!(duid.uuid(), Some(uuid));
    assert_eq!(duid.link_layer(), None);
    assert_eq!(duid.time(), None);
    assert_eq!(duid.enterprise(), None);
    // 15 and 17 octets are not a UUID, though they are DUIDs.
    assert_eq!(
        Duid::parse(code::CLIENTID, &data[..17]).expect("15").uuid(),
        None
    );
    data.push(0);
    assert_eq!(Duid::parse(code::CLIENTID, &data).expect("17").uuid(), None);
}

#[test]
fn a_duid_has_between_three_and_130_octets() {
    assert_eq!(Duid::MIN_LEN, 3);
    assert_eq!(Duid::MAX_LEN, 130);
    for len in [0usize, 1, 2, 131, 200] {
        let data = vec![9u8; len];
        assert_eq!(
            Duid::parse(code::CLIENTID, &data).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::CLIENTID,
                len
            }),
            "{len}"
        );
    }
    for len in [3usize, 4, 100, 130] {
        let data = vec![9u8; len];
        assert!(Duid::parse(code::SERVERID, &data).is_ok(), "{len}");
    }
    // The code of the option is in the error.
    assert_eq!(
        Duid::parse(code::SERVERID, &[1, 2]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::SERVERID,
            len: 2
        })
    );
    // An unknown DUID type is still a DUID.
    let unknown = Duid::parse(code::CLIENTID, &[0x12, 0x34, 0x56]).expect("a DUID");
    assert_eq!(unknown.kind(), 0x1234);
    assert_eq!(unknown.link_layer(), None);
    assert_eq!(unknown.time(), None);
    assert_eq!(unknown.enterprise(), None);
    assert_eq!(unknown.uuid(), None);
    assert_eq!(format!("{unknown:?}"), "Duid(12:34:56)");
}

#[test]
fn an_option_request_has_an_even_length() {
    let request = OptionRequest::parse(&[0, 23, 0, 24, 0, 56]).expect("three codes");
    assert_eq!(codes_of(&request), [23, 24, 56]);
    assert_eq!(request.len(), 3);
    assert!(request.contains(56));
    assert!(!request.contains(57));
    let empty = OptionRequest::parse(&[]).expect("an empty list");
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.codes().count(), 0);
    for len in [1usize, 3, 5, 7] {
        assert_eq!(
            OptionRequest::parse(&vec![0u8; len]).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::ORO,
                len
            }),
            "{len}"
        );
    }
}

#[test]
fn an_address_list_is_a_multiple_of_sixteen_octets() {
    let mut data = Vec::new();
    data.extend_from_slice(&ip("2001:db8::53").octets());
    data.extend_from_slice(&ip("2001:db8::54").octets());
    let list = AddrList::parse(code::DNS_SERVERS, &data).expect("two addresses");
    assert_eq!(list.len(), 2);
    assert!(!list.is_empty());
    assert_eq!(
        list.iter().collect::<Vec<_>>(),
        [ip("2001:db8::53"), ip("2001:db8::54")]
    );
    let empty = AddrList::parse(code::SNTP_SERVERS, &[]).expect("empty");
    assert!(empty.is_empty());
    assert_eq!(empty.iter().count(), 0);
    for len in [1usize, 15, 17, 31, 33] {
        assert_eq!(
            AddrList::parse(code::DNS_SERVERS, &vec![0u8; len]).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::DNS_SERVERS,
                len
            }),
            "{len}"
        );
    }
    // The error names the option it was asked about.
    assert_eq!(
        AddrList::parse(code::SIP_SERVER_A, &[0u8; 17]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::SIP_SERVER_A,
            len: 17
        })
    );
}

#[test]
fn a_domain_list_is_uncompressed_absolute_names() {
    let wire = b"\x07example\x04test\x00\x03lab\x07example\x04test\x00";
    let list = DomainList::parse(code::DOMAIN_LIST, wire).expect("two names");
    assert_eq!(
        list.iter().collect::<Vec<_>>(),
        [name("example.test."), name("lab.example.test.")]
    );
    assert_eq!(list.as_bytes(), &wire[..]);
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, &[])
            .expect("empty")
            .iter()
            .count(),
        0
    );
    let bad = DecodeError::BadValue {
        code: code::DOMAIN_LIST,
    };
    // RFC 3646 section 4 forbids compression: a pointer is refused, wherever it is.
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, b"\x07example\x04test\x00\xc0\x00").map(|_| ()),
        Err(bad)
    );
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, b"\x03lab\xc0\x00").map(|_| ()),
        Err(bad)
    );
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, &[0xc0, 0x0c]).map(|_| ()),
        Err(bad)
    );
    // A name that does not end, a label that runs past the end, and a label above 63 octets.
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, b"\x07example\x04test").map(|_| ()),
        Err(bad)
    );
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, b"\x09short").map(|_| ()),
        Err(bad)
    );
    let mut long = vec![64u8];
    long.extend_from_slice(&[b'a'; 64]);
    long.push(0);
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, &long).map(|_| ()),
        Err(bad)
    );
    // The error carries the code it was asked for (option 21 is a domain list too).
    assert_eq!(
        DomainList::parse(code::SIP_SERVER_D, &[0xc0, 0x00]).map(|_| ()),
        Err(DecodeError::BadValue {
            code: code::SIP_SERVER_D
        })
    );
    // A name of 255 octets is the longest; 256 is too long.
    let label = [&[63u8][..], &[b'a'; 63]].concat();
    let mut longest = Vec::new();
    for _ in 0..3 {
        longest.extend_from_slice(&label);
    }
    longest.push(61);
    longest.extend_from_slice(&[b'b'; 61]);
    longest.push(0);
    assert_eq!(longest.len(), 3 * 64 + 62 + 1);
    assert!(longest.len() <= 255);
    assert!(DomainList::parse(code::DOMAIN_LIST, &longest).is_ok());
    let mut too_long = longest.clone();
    too_long.splice(0..0, [1u8, b'z']);
    assert!(too_long.len() > 255);
    assert_eq!(
        DomainList::parse(code::DOMAIN_LIST, &too_long).map(|_| ()),
        Err(bad)
    );
}

#[test]
fn an_ntp_server_option_holds_sixteen_octet_addresses_and_names() {
    let bad = DecodeError::BadValue {
        code: code::NTP_SERVER,
    };
    // The three sub-options of RFC 5908 section 4, and an unknown one.
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 1, 0, 16]);
    data.extend_from_slice(&ip("2001:db8::123").octets());
    data.extend_from_slice(&[0, 2, 0, 16]);
    data.extend_from_slice(&ip("ff0e::101").octets());
    data.extend_from_slice(&[0, 3, 0, 14]);
    data.extend_from_slice(b"\x07example\x04test\x00");
    data.extend_from_slice(&[0, 9, 0, 2, 0xaa, 0xbb]);
    let ntp = NtpServer::parse(&data).expect("four sub-options");
    assert_eq!(
        ntp.suboptions().collect::<Vec<_>>(),
        [
            NtpSuboption::ServerAddress(ip("2001:db8::123")),
            NtpSuboption::MulticastAddress(ip("ff0e::101")),
            NtpSuboption::ServerName(b"\x07example\x04test\x00"),
            NtpSuboption::Other(9),
        ]
    );
    assert_eq!(
        NtpServer::parse(&[]).expect("empty").suboptions().count(),
        0
    );
    assert_eq!(NtpServer::SRV_ADDR, 1);
    assert_eq!(NtpServer::MC_ADDR, 2);
    assert_eq!(NtpServer::SRV_FQDN, 3);

    // A SRV_ADDR of 15 octets, and of 17.
    for len in [0usize, 15, 17] {
        let mut data = vec![0, 1, 0, u8::try_from(len).expect("len")];
        data.extend_from_slice(&vec![0u8; len]);
        assert_eq!(
            NtpServer::parse(&data).map(|_| ()),
            Err(bad),
            "SRV_ADDR {len}"
        );
        data[1] = 2;
        assert_eq!(
            NtpServer::parse(&data).map(|_| ()),
            Err(bad),
            "MC_ADDR {len}"
        );
    }
    // A sub-option that runs past the end, and a header cut short.
    assert_eq!(NtpServer::parse(&[0, 1, 0, 16, 0, 0]).map(|_| ()), Err(bad));
    assert_eq!(NtpServer::parse(&[0, 1, 0]).map(|_| ()), Err(bad));
    // A server name with a compression pointer.
    assert_eq!(
        NtpServer::parse(&[0, 3, 0, 2, 0xc0, 0x0c]).map(|_| ()),
        Err(bad)
    );
}

#[test]
fn a_client_fqdn_has_flags_and_a_name() {
    let fqdn = ClientFqdn::parse(&[0x01, 3, b'a', b'b', b'c', 0]).expect("an absolute name");
    assert_eq!(fqdn.flags(), 0x01);
    assert!(fqdn.server_updates());
    assert!(!fqdn.no_update());
    assert_eq!(fqdn.name(), name("abc."));
    assert_eq!(fqdn.name_bytes(), [3, b'a', b'b', b'c', 0]);

    let no_update = ClientFqdn::parse(&[0x04]).expect("flags only");
    assert!(no_update.no_update());
    assert!(!no_update.server_updates());
    assert!(no_update.name().is_empty());
    assert_eq!(no_update.name_bytes(), b"");

    assert_eq!(ClientFqdn::FLAG_S, 0x01);
    assert_eq!(ClientFqdn::FLAG_O, 0x02);
    assert_eq!(ClientFqdn::FLAG_N, 0x04);
    assert_eq!(
        ClientFqdn::parse(&[]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::CLIENT_FQDN,
            len: 0
        })
    );
    // RFC 4704 section 4.2: no compression in the name; a label past the end is refused.
    let bad = DecodeError::BadValue {
        code: code::CLIENT_FQDN,
    };
    assert_eq!(ClientFqdn::parse(&[0, 0xc0, 0x0c]).map(|_| ()), Err(bad));
    assert_eq!(ClientFqdn::parse(&[0, 5, b'a']).map(|_| ()), Err(bad));
    assert_eq!(ClientFqdn::parse(&[0, 1, b'a', 0, 0]).map(|_| ()), Err(bad));
}

#[test]
fn the_fqdn_flags_map_between_the_v6_and_the_v4_layout() {
    // Option 39 (RFC 4704): S 0x01, O 0x02, N 0x04.
    // Option 81 (RFC 4702): S 0x01, O 0x02, E 0x04, N 0x08.
    let cases = [
        (0x00, 0x04),
        (0x01, 0x05),
        (0x02, 0x06),
        (0x03, 0x07),
        (0x04, 0x0c),
        (0x05, 0x0d),
        (0x06, 0x0e),
        (0x07, 0x0f),
    ];
    for (v6, v4) in cases {
        assert_eq!(flags_to_v4(v6), v4, "to v4 {v6:#04x}");
        assert_eq!(flags_from_v4(v4), v6, "from v4 {v4:#04x}");
        assert_eq!(flags_from_v4(flags_to_v4(v6)), v6, "round trip {v6:#04x}");
        let octets = [v6];
        let parsed = ClientFqdn::parse(&octets).expect("flags only");
        assert_eq!(parsed.flags_v4(), v4, "flags_v4 {v6:#04x}");
    }
    // E is set going to v4 and dropped coming back; N moves from 0x04 to 0x08 and back.
    assert_eq!(flags_to_v4(0x00) & 0x04, 0x04);
    assert_eq!(flags_from_v4(0x04), 0x00);
    assert_eq!(flags_to_v4(0x04) & 0x08, 0x08);
    assert_eq!(flags_to_v4(0x04) & 0x04, 0x04, "E, not the old N bit");
    assert_eq!(flags_from_v4(0x08), 0x04);
    // Bits that neither layout defines do not cross.
    assert_eq!(flags_to_v4(0xf8), 0x04);
    assert_eq!(flags_from_v4(0xf0), 0x00);
    assert_eq!(flags_from_v4(0xf3), 0x03);
    // The v4 constants agree with the layout this test assumes.
    assert_eq!(tenko_dhcp::v4::ClientFqdn::FLAG_S, 0x01);
    assert_eq!(tenko_dhcp::v4::ClientFqdn::FLAG_O, 0x02);
    assert_eq!(tenko_dhcp::v4::ClientFqdn::FLAG_E, 0x04);
    assert_eq!(tenko_dhcp::v4::ClientFqdn::FLAG_N, 0x08);
}

#[test]
fn a_client_link_layer_address_is_an_ethernet_mac_only_for_type_one_and_six_octets() {
    let ether = LinkLayerAddress::parse(&[0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]).expect("mac");
    assert_eq!(ether.kind, 1);
    assert_eq!(ether.address, MAC_1);
    assert_eq!(ether.mac(), Some(MAC_1));
    // Ethernet with eight octets, another hardware type with six, and one octet.
    let long = LinkLayerAddress::parse(&[0, 1, 1, 2, 3, 4, 5, 6, 7, 8]).expect("parse");
    assert_eq!(long.mac(), None);
    let other = LinkLayerAddress::parse(&[0, 32, 1, 2, 3, 4, 5, 6]).expect("parse");
    assert_eq!(other.kind, 32);
    assert_eq!(other.mac(), None);
    let one = LinkLayerAddress::parse(&[0, 1, 9]).expect("a type and one octet");
    assert_eq!(one.address, [9]);
    assert_eq!(one.mac(), None);
    for len in [0usize, 1, 2] {
        assert_eq!(
            LinkLayerAddress::parse(&vec![0u8; len]).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::CLIENT_LINKLAYER_ADDR,
                len
            }),
            "{len}"
        );
    }
}

#[test]
fn a_status_code_has_a_code_and_a_message() {
    let ok = StatusCode::parse(&[0, 0, b'o', b'k']).expect("status");
    assert_eq!(ok.code, status::SUCCESS);
    assert_eq!(ok.message, b"ok");
    let bare = StatusCode::parse(&[0, 2]).expect("two octets");
    assert_eq!(bare.code, status::NO_ADDRS_AVAIL);
    assert_eq!(bare.message, b"");
    let unknown = StatusCode::parse(&[0xff, 0xfe, 0xc3, 0x28]).expect("any code, any bytes");
    assert_eq!(unknown.code, 0xfffe);
    assert_eq!(unknown.message, [0xc3, 0x28], "the message is kept as sent");
    for len in [0usize, 1] {
        assert_eq!(
            StatusCode::parse(&vec![0u8; len]).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::STATUS_CODE,
                len
            }),
            "{len}"
        );
    }
    assert_eq!(status::SUCCESS, 0);
    assert_eq!(status::UNSPEC_FAIL, 1);
    assert_eq!(status::NO_ADDRS_AVAIL, 2);
    assert_eq!(status::NO_BINDING, 3);
    assert_eq!(status::NOT_ON_LINK, 4);
    assert_eq!(status::USE_MULTICAST, 5);
    assert_eq!(status::NO_PREFIX_AVAIL, 6);
}

#[test]
fn an_ia_na_and_an_ia_address_check_their_fixed_parts() {
    let mut ia = vec![0, 0, 0, 1, 0, 0, 0x05, 0xdc, 0, 0, 0x09, 0x60];
    let parsed = IaNa::parse(&ia).expect("12 octets");
    assert_eq!((parsed.iaid, parsed.t1, parsed.t2), (1, 1500, 2400));
    assert_eq!(parsed.options().count(), 0);
    ia.pop();
    assert_eq!(
        IaNa::parse(&ia).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::IA_NA,
            len: 11
        })
    );
    assert_eq!(
        IaNa::parse(&[]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::IA_NA,
            len: 0
        })
    );

    let mut address = Vec::new();
    address.extend_from_slice(&ip("2001:db8::1").octets());
    address.extend_from_slice(&[0, 0, 0x0b, 0xb8, 0, 0, 0x0f, 0xa0]);
    let parsed = IaAddress::parse(&address).expect("24 octets");
    assert_eq!(parsed.addr, ip("2001:db8::1"));
    assert_eq!((parsed.preferred, parsed.valid), (3000, 4000));
    address.pop();
    assert_eq!(
        IaAddress::parse(&address).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::IAADDR,
            len: 23
        })
    );

    // An IA_NA whose nested option runs past its end: the IA parses, its walk fails.
    let mut broken = vec![0u8; 12];
    broken.extend_from_slice(&[0, 5, 0, 24, 1, 2, 3]);
    let parsed = IaNa::parse(&broken).expect("the head is fine");
    assert_eq!(
        parsed.addresses().next(),
        Some(Err(DecodeError::Truncated { code: 5 }))
    );
    assert_eq!(parsed.status(), None);
    // An IA Address with a malformed nested status has no status.
    let mut with_bad_status = address.clone();
    with_bad_status.push(0);
    with_bad_status.extend_from_slice(&[0, 13, 0, 1, 0]);
    let parsed = IaAddress::parse(&with_bad_status).expect("24 octets and a status");
    assert_eq!(parsed.status(), None, "a status of one octet is malformed");
}

#[test]
fn an_ia_pd_and_its_prefixes_are_read() {
    let mut pd = vec![0, 0, 0, 9, 0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0];
    // One IA Prefix: preferred 3000, valid 4000, /56, 2001:db8:0:100::.
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&[0, 0, 0x0b, 0xb8, 0, 0, 0x0f, 0xa0, 56]);
    prefix.extend_from_slice(&ip("2001:db8:0:100::").octets());
    pd.extend_from_slice(&[0, 26, 0, 25]);
    pd.extend_from_slice(&prefix);
    let bytes = build(|b| {
        b.message(MessageType::Solicit, 3).expect("header");
        b.option(code::IA_PD, &pd).expect("25");
    });
    let message = Message::parse(&bytes).expect("parse");
    let pds: Vec<IaPd<'_>> = message
        .ia_pds()
        .collect::<Result<_, _>>()
        .expect("well-formed IA_PD options");
    assert_eq!(pds.len(), 1);
    assert_eq!((pds[0].iaid, pds[0].t1, pds[0].t2), (9, 1000, 2000));
    let prefixes: Vec<IaPrefix<'_>> = pds[0]
        .prefixes()
        .collect::<Result<_, _>>()
        .expect("well-formed IA Prefix options");
    assert_eq!(prefixes.len(), 1);
    assert_eq!((prefixes[0].preferred, prefixes[0].valid), (3000, 4000));
    assert_eq!(prefixes[0].prefix_len, 56);
    assert_eq!(prefixes[0].prefix, ip("2001:db8:0:100::"));
    assert_eq!(prefixes[0].options().count(), 0);
    assert_eq!(pds[0].status(), None);

    assert_eq!(
        IaPd::parse(&[0; 11]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::IA_PD,
            len: 11
        })
    );
    assert_eq!(
        IaPrefix::parse(&prefix[..24]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::IAPREFIX,
            len: 24
        })
    );
    // A prefix length above 128.
    let mut long_prefix = prefix.clone();
    long_prefix[8] = 129;
    assert_eq!(
        IaPrefix::parse(&long_prefix).map(|_| ()),
        Err(DecodeError::BadValue {
            code: code::IAPREFIX
        })
    );
    long_prefix[8] = 128;
    assert!(IaPrefix::parse(&long_prefix).is_ok());
}

#[test]
fn a_remote_id_has_an_enterprise_number_and_at_least_one_octet() {
    let remote = RemoteId::parse(&[0, 0, 0x7e, 0xd9, 0xaa]).expect("five octets");
    assert_eq!(remote.enterprise, 32473);
    assert_eq!(remote.id, [0xaa]);
    assert_eq!(remote.as_bytes(), [0, 0, 0x7e, 0xd9, 0xaa]);
    for len in [0usize, 1, 4] {
        assert_eq!(
            RemoteId::parse(&vec![0u8; len]).map(|_| ()),
            Err(DecodeError::BadLength {
                code: code::REMOTE_ID,
                len
            }),
            "{len}"
        );
    }
}

#[test]
fn user_and_vendor_classes_are_length_prefixed_lists() {
    let list = LengthPrefixed::parse(code::USER_CLASS, &[0, 3, b'a', b'b', b'c', 0, 1, b'x'])
        .expect("two items");
    assert_eq!(list.iter().collect::<Vec<_>>(), [&b"abc"[..], &b"x"[..]]);
    assert_eq!(list.as_bytes().len(), 8);
    assert_eq!(
        LengthPrefixed::parse(code::USER_CLASS, &[])
            .expect("empty")
            .iter()
            .count(),
        0
    );
    let bad = DecodeError::BadValue {
        code: code::USER_CLASS,
    };
    // An item that runs past the end, and a lone octet where a length should be.
    assert_eq!(
        LengthPrefixed::parse(code::USER_CLASS, &[0, 5, 1, 2]).map(|_| ()),
        Err(bad)
    );
    assert_eq!(
        LengthPrefixed::parse(code::USER_CLASS, &[0, 1, 1, 7]).map(|_| ()),
        Err(bad)
    );

    let vendor = VendorClass::parse(&[0, 0, 0x7e, 0xd9, 0, 2, b'h', b'i']).expect("one class");
    assert_eq!(vendor.enterprise, 32473);
    assert_eq!(vendor.classes.iter().collect::<Vec<_>>(), [&b"hi"[..]]);
    assert_eq!(
        VendorClass::parse(&[0, 0, 1]).map(|_| ()),
        Err(DecodeError::BadLength {
            code: code::VENDOR_CLASS,
            len: 3
        })
    );
    assert_eq!(
        VendorClass::parse(&[0, 0, 0, 1, 0, 9, 1]).map(|_| ()),
        Err(DecodeError::BadValue {
            code: code::VENDOR_CLASS
        })
    );

    // Through a message.
    let bytes = build(|b| {
        b.message(MessageType::Solicit, 3).expect("header");
        b.option(code::USER_CLASS, &[0, 3, b'a', b'b', b'c'])
            .expect("15");
        b.option(code::VENDOR_CLASS, &[0, 0, 0x7e, 0xd9, 0, 2, b'h', b'i'])
            .expect("16");
    });
    let message = Message::parse(&bytes).expect("parse");
    let classes = message.user_class().expect("ok").expect("option 15");
    assert_eq!(classes.iter().collect::<Vec<_>>(), [&b"abc"[..]]);
    let vendor = message.vendor_class().expect("ok").expect("option 16");
    assert_eq!(vendor.enterprise, 32473);
}

// ---------------------------------------------------------------------------------------
// Generated inputs: nothing may panic, and every octet yielded lies inside the message
// ---------------------------------------------------------------------------------------

/// Whether `inner` is a sub-slice of `outer` (the same allocation, within its bounds).
fn within(outer: &[u8], inner: &[u8]) -> bool {
    let outer = outer.as_ptr_range();
    let inner = inner.as_ptr_range();
    outer.start <= inner.start && inner.end <= outer.end
}

/// Reads one option with its typed view and checks that what the view yields lies in
/// `outer`; walks the options nested in it.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per typed option, each short"
)]
fn touch_option(outer: &[u8], option_code: u16, data: &[u8], depth: usize) {
    assert!(
        within(outer, data),
        "option {option_code} lies in the datagram"
    );
    match option_code {
        code::CLIENTID | code::SERVERID => {
            if let Ok(duid) = Duid::parse(option_code, data) {
                assert!(within(outer, duid.as_bytes()));
                assert!(within(outer, duid.body()));
                let _ = (duid.kind(), duid.time(), duid.enterprise(), duid.uuid());
                if let Some((_, address)) = duid.link_layer() {
                    assert!(within(outer, address));
                    assert_ne!(address.len(), 0);
                }
            }
        }
        code::IA_NA => {
            if let Ok(ia) = IaNa::parse(data) {
                touch_area(outer, ia.options(), depth + 1);
                for address in ia.addresses().flatten() {
                    touch_area(outer, address.options(), depth + 1);
                    let _ = (address.addr, address.preferred, address.valid);
                    if let Some(status) = address.status() {
                        assert!(within(outer, status.message));
                    }
                }
                if let Some(status) = ia.status() {
                    assert!(within(outer, status.message));
                }
            }
        }
        code::IA_PD => {
            if let Ok(ia) = IaPd::parse(data) {
                touch_area(outer, ia.options(), depth + 1);
                for prefix in ia.prefixes().flatten() {
                    assert!(prefix.prefix_len <= 128);
                    touch_area(outer, prefix.options(), depth + 1);
                }
                if let Some(status) = ia.status() {
                    assert!(within(outer, status.message));
                }
            }
        }
        code::IAADDR => {
            if let Ok(address) = IaAddress::parse(data) {
                touch_area(outer, address.options(), depth + 1);
            }
        }
        code::IAPREFIX => {
            if let Ok(prefix) = IaPrefix::parse(data) {
                touch_area(outer, prefix.options(), depth + 1);
            }
        }
        code::ORO => {
            if let Ok(request) = OptionRequest::parse(data) {
                assert_eq!(request.codes().count(), request.len());
                let _ = request.contains(code::DNS_SERVERS);
            }
        }
        code::STATUS_CODE => {
            if let Ok(status) = StatusCode::parse(data) {
                assert!(within(outer, status.message));
            }
        }
        code::CLIENT_FQDN => {
            if let Ok(fqdn) = ClientFqdn::parse(data) {
                assert!(within(outer, fqdn.name_bytes()));
                let _ = (fqdn.name(), fqdn.flags_v4(), fqdn.server_updates());
            }
        }
        code::CLIENT_LINKLAYER_ADDR => {
            if let Ok(link_layer) = LinkLayerAddress::parse(data) {
                assert!(within(outer, link_layer.address));
                let _ = link_layer.mac();
            }
        }
        code::REMOTE_ID => {
            if let Ok(remote) = RemoteId::parse(data) {
                assert!(within(outer, remote.id));
                assert!(within(outer, remote.as_bytes()));
            }
        }
        code::DNS_SERVERS | code::SNTP_SERVERS | code::SIP_SERVER_A => {
            if let Ok(list) = AddrList::parse(option_code, data) {
                assert_eq!(list.iter().count(), list.len());
            }
        }
        code::DOMAIN_LIST | code::SIP_SERVER_D => {
            if let Ok(list) = DomainList::parse(option_code, data) {
                assert!(within(outer, list.as_bytes()));
                let _ = list.iter().count();
            }
        }
        code::NTP_SERVER => {
            if let Ok(ntp) = NtpServer::parse(data) {
                for sub in ntp.suboptions() {
                    if let NtpSuboption::ServerName(bytes) = sub {
                        assert!(within(outer, bytes));
                    }
                }
            }
        }
        code::USER_CLASS => {
            if let Ok(list) = LengthPrefixed::parse(option_code, data) {
                for item in list.iter() {
                    assert!(within(outer, item));
                }
            }
        }
        code::VENDOR_CLASS => {
            if let Ok(vendor) = VendorClass::parse(data) {
                for item in vendor.classes.iter() {
                    assert!(within(outer, item));
                }
            }
        }
        code::RELAY_MSG if depth < 64 => {
            if let Ok(relayed) = Message::parse(data) {
                touch_message(outer, &relayed, depth + 1);
            }
        }
        _ => {}
    }
}

fn touch_area(outer: &[u8], area: Options<'_>, depth: usize) {
    for option in area {
        let Ok(option) = option else { break };
        touch_option(outer, option.code, option.data, depth);
    }
}

/// Every accessor of a message, and the walk of every option.
fn touch_message(outer: &[u8], message: &Message<'_>, depth: usize) {
    assert!(within(outer, message.as_bytes()));
    assert!(within(outer, message.options_area()));
    let _ = (
        message.kind(),
        message.transaction_id(),
        message.hop_count(),
        message.link_address(),
        message.peer_address(),
    );
    touch_area(outer, message.options(), depth);
    let _ = message.validate();
    let _ = message.client_id();
    let _ = message.server_id();
    let _ = message.option_request();
    let _ = message.elapsed_time();
    let _ = message.rapid_commit();
    let _ = message.reconfigure_accept();
    let _ = message.has_ia_ta();
    if let Ok(Some(relayed)) = message.relay_message() {
        assert!(within(outer, relayed.as_bytes()));
    }
    if let Ok(Some(id)) = message.interface_id() {
        assert!(within(outer, id));
    }
    let _ = message.remote_id();
    let _ = message.client_link_layer();
    let _ = message.client_fqdn();
    let _ = message.user_class();
    let _ = message.vendor_class();
    let mut failed = false;
    for ia in message.ia_nas() {
        assert!(!failed, "an IA_NA walk ends at its first error");
        match ia {
            Ok(ia) => {
                for address in ia.addresses() {
                    if address.is_err() {
                        break;
                    }
                }
            }
            Err(_) => failed = true,
        }
    }
    for ia in message.ia_pds().flatten() {
        for prefix in ia.prefixes() {
            if prefix.is_err() {
                break;
            }
        }
    }
}

/// Parses `bytes` and reads everything in it; must not panic.
fn exercise(bytes: &[u8]) {
    let Ok(message) = Message::parse(bytes) else {
        return;
    };
    touch_message(bytes, &message, 0);
    if let Ok(chain) = RelayChain::parse(message) {
        assert!(chain.depth() <= MAX_RELAY_DEPTH);
        assert_eq!(chain.relays().count(), chain.depth());
        assert_eq!(chain.is_relayed(), chain.depth() > 0);
        for relay in chain.relays() {
            assert!(within(bytes, relay.as_bytes()));
            assert_eq!(relay.kind(), MessageType::RelayForw);
            touch_message(bytes, &relay, 0);
        }
        touch_message(bytes, &chain.client(), 0);
        assert_eq!(chain.outermost().is_some(), chain.depth() > 0);
        assert_eq!(chain.innermost().is_some(), chain.depth() > 0);
        let _ = chain.link_address();
        if let Some(id) = chain.interface_id() {
            assert!(within(bytes, id));
        }
        if let Some(remote) = chain.remote_id() {
            assert!(within(bytes, remote.id));
        }
        if let Some(link_layer) = chain.client_link_layer() {
            assert!(within(bytes, link_layer.address));
        }
        let _ = format!("{chain:?}");
    }
    let _ = format!("{message:?}");
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    PLAIN
        .iter()
        .chain(&RELAYED)
        .chain(&MALFORMED)
        .map(|fixture_name| ((*fixture_name).to_owned(), fx(fixture_name)))
        .collect()
}

#[test]
fn every_truncation_of_every_fixture_is_handled() {
    for (fixture_name, bytes) in corpus() {
        for len in 0..=bytes.len() {
            exercise(&bytes[..len]);
        }
        // Every truncation of a client or server message that keeps its header parses, and
        // the walk reports an error at most once.
        if !bytes.is_empty() && !MessageType::from_u8(bytes[0]).is_relay() {
            for len in 4..=bytes.len() {
                let message = Message::parse(&bytes[..len]).expect(&fixture_name);
                let errors = message.options().filter(Result::is_err).count();
                assert!(errors <= 1, "{fixture_name} cut at {len}");
            }
        }
    }
}

#[test]
fn every_single_octet_flip_of_every_fixture_is_handled() {
    for (_, bytes) in corpus() {
        for at in 0..bytes.len() {
            for mask in [0x01u8, 0x10, 0x80, 0xff] {
                let mut flipped = bytes.clone();
                flipped[at] ^= mask;
                exercise(&flipped);
            }
            for value in [0x00u8, 0xff] {
                let mut set = bytes.clone();
                set[at] = value;
                exercise(&set);
            }
        }
    }
}

#[test]
fn every_pair_of_adjacent_octets_set_to_extreme_values_is_handled() {
    // The length fields: two octets at a time to 0x0000, 0xffff, 0x0001 and 0x8000.
    for (_, bytes) in corpus() {
        for at in 0..bytes.len().saturating_sub(1) {
            for pair in [[0x00u8, 0x00], [0xff, 0xff], [0x00, 0x01], [0x80, 0x00]] {
                let mut set = bytes.clone();
                set[at] = pair[0];
                set[at + 1] = pair[1];
                exercise(&set);
            }
        }
    }
}

#[test]
fn random_byte_strings_are_handled() {
    let mut rng = Rng::new(0x6d5a_56da_2f1c_8e07);
    for _ in 0..60_000usize {
        let len = rng.below(260);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Bias the type octet towards the real message types, half of them relays.
        if let Some(first) = bytes.first_mut() {
            *first = match rng.below(4) {
                0 => 12,
                1 => u8::try_from(1 + rng.below(13)).expect("a type"),
                _ => *first,
            };
        }
        exercise(&bytes);
    }
}

#[test]
fn random_option_lists_are_handled() {
    const CODES: [u16; 28] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 20, 21, 22, 23, 24, 25, 26, 31, 37,
        39, 56, 79,
    ];
    let mut rng = Rng::new(0x1f2e_3d4c_5b6a_7988);
    for _ in 0..40_000usize {
        let mut bytes = Vec::new();
        let relay = rng.below(3) == 0;
        if relay {
            bytes.push(12);
            for _ in 0..33 {
                bytes.push(rng.byte());
            }
        } else {
            bytes.push(u8::try_from(1 + rng.below(11)).expect("a type"));
            for _ in 0..3 {
                bytes.push(rng.byte());
            }
        }
        for _ in 0..rng.below(8) {
            let option_code = if rng.below(5) == 0 {
                u16::try_from(rng.below(300)).expect("a code")
            } else {
                CODES[rng.below(CODES.len())]
            };
            let len = rng.below(48);
            // Sometimes lie about the length.
            let claimed = if rng.below(6) == 0 {
                rng.below(80)
            } else {
                len
            };
            bytes.extend_from_slice(&option_code.to_be_bytes());
            bytes.extend_from_slice(&u16::try_from(claimed).expect("a length").to_be_bytes());
            for _ in 0..len {
                bytes.push(rng.byte());
            }
        }
        exercise(&bytes);
    }
}

#[test]
fn randomly_mutated_fixtures_are_handled() {
    let corpus = corpus();
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
    for _ in 0..40_000usize {
        let (_, original) = &corpus[rng.below(corpus.len())];
        let mut bytes = original.clone();
        if bytes.is_empty() {
            continue;
        }
        for _ in 0..=rng.below(4) {
            let at = rng.below(bytes.len());
            match rng.below(4) {
                0 => bytes[at] = rng.byte(),
                1 => bytes[at] ^= 1 << rng.below(8),
                2 => {
                    bytes.insert(at, rng.byte());
                }
                _ => {
                    bytes.remove(at);
                    if bytes.is_empty() {
                        break;
                    }
                }
            }
        }
        exercise(&bytes);
    }
}

#[test]
fn what_the_builder_writes_is_always_walked_without_an_error() {
    // Random nesting of options written through the builder walks cleanly, however the
    // marks are used.
    let mut rng = Rng::new(0x0123_4567_89ab_cdef);
    for _ in 0..2_000usize {
        let mut buf = vec![0u8; 600];
        let limit = 34 + rng.below(560);
        let mut b = MessageBuilder::new(&mut buf, limit).expect("builder");
        if rng.below(2) == 0 {
            b.message(MessageType::Solicit, 5).expect("header");
        } else {
            b.relay(MessageType::RelayForw, 0, ip("::1"), ip("::2"))
                .expect("header");
        }
        let mut marks = Vec::new();
        for _ in 0..rng.below(30) {
            match rng.below(5) {
                0 => {
                    if let Ok(mark) = b.begin(code::RELAY_MSG) {
                        marks.push(mark);
                    }
                }
                1 => {
                    if let Some(mark) = marks.pop() {
                        b.end(mark).expect("the innermost mark");
                    }
                }
                2 => {
                    if let Some(mark) = marks.pop() {
                        b.rewind(mark).expect("the innermost mark");
                    }
                }
                3 => {
                    let size = rng.below(40);
                    let data: Vec<u8> = (0..size).map(|_| rng.byte()).collect();
                    let before = b.len();
                    if b.option(code::VENDOR_OPTS, &data).is_err() {
                        assert_eq!(b.len(), before);
                    }
                }
                _ => {
                    let before = b.len();
                    if let Ok(mark) = b.begin_ia_na(1, 2, 3) {
                        marks.push(mark);
                    } else {
                        assert_eq!(b.len(), before);
                    }
                }
            }
        }
        while let Some(mark) = marks.pop() {
            b.end(mark).expect("the innermost mark");
        }
        let len = b.finish().expect("balanced");
        assert!(len <= limit);
        // The nested containers hold options, but the Relay Message ones hold bare option
        // bytes rather than messages, so only the outer walk is checked.
        let message = Message::parse(&buf[..len]).expect("a header was written");
        message.validate().expect("every option is well formed");
    }
}

// ---------------------------------------------------------------------------------------
// The fuzz seeds with IA_PD (WP9.2)
// ---------------------------------------------------------------------------------------

/// The directory of the `dhcp6_wire` fuzz seeds.
fn seed_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz")
        .join("seeds")
        .join("dhcp6_wire")
}

/// The octets of the fuzz seed `name`.
fn seed(name: &str) -> Vec<u8> {
    let path = seed_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn every_ia_pd_fuzz_seed_parses_and_validates() {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(seed_dir()).expect("the seed directory") {
        let name = entry
            .expect("an entry")
            .file_name()
            .into_string()
            .expect("a UTF-8 name");
        if name.contains("ia-pd") || name.contains("pd") {
            names.push(name);
        }
    }
    names.sort();
    assert_eq!(
        names,
        [
            "release-ia-pd",
            "renew-ia-na-ia-pd-same-iaid",
            "reply-ia-pd-no-prefix-avail",
            "request-ia-pd-hint",
            "solicit-ia-pd",
        ]
    );
    for name in &names {
        let bytes = seed(name);
        let message = Message::parse(&bytes).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        message
            .validate()
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert!(message.ia_pds().count() >= 1, "{name}: an IA_PD");
        for ia in message.ia_pds() {
            let ia = ia.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            ia.options()
                .validate()
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            for prefix in ia.prefixes() {
                let prefix = prefix.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert!(prefix.prefix_len <= 128, "{name}");
                prefix
                    .options()
                    .validate()
                    .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            }
        }
    }
}

#[test]
fn the_request_seed_asks_for_a_prefix_of_a_length() {
    let bytes = seed("request-ia-pd-hint");
    let message = Message::parse(&bytes).expect("parses");
    assert_eq!(message.kind(), MessageType::Request);
    assert_eq!(message.transaction_id(), 0x0000_bb01);
    assert!(message.client_id().expect("ok").is_some());
    assert!(message.server_id().expect("ok").is_some());
    assert_eq!(message.ia_nas().count(), 0);
    let ias: Vec<_> = message.ia_pds().map(|ia| ia.expect("an IA_PD")).collect();
    assert_eq!(ias.len(), 1);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (1, 0, 0));
    let prefixes: Vec<_> = ias[0]
        .prefixes()
        .map(|prefix| prefix.expect("an IA Prefix"))
        .collect();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(prefixes[0].prefix, ip("2001:db8:180:100::"));
    assert_eq!(prefixes[0].prefix_len, 60);
    assert_eq!((prefixes[0].preferred, prefixes[0].valid), (0, 0));
}

#[test]
fn the_reply_seed_has_a_prefix_and_a_no_prefix_avail_status() {
    let bytes = seed("reply-ia-pd-no-prefix-avail");
    let message = Message::parse(&bytes).expect("parses");
    assert_eq!(message.kind(), MessageType::Reply);
    assert_eq!(message.transaction_id(), 0x0000_bb02);
    let ias: Vec<_> = message.ia_pds().map(|ia| ia.expect("an IA_PD")).collect();
    assert_eq!(ias.len(), 2);
    assert_eq!((ias[0].iaid, ias[0].t1, ias[0].t2), (1, 3000, 4800));
    let prefix = ias[0]
        .prefixes()
        .next()
        .expect("a prefix")
        .expect("an IA Prefix");
    assert_eq!(prefix.prefix, ip("2001:db8:180:100::"));
    assert_eq!(prefix.prefix_len, 60);
    assert_eq!((prefix.preferred, prefix.valid), (6000, 7200));
    assert_eq!(ias[0].status(), None);
    assert_eq!(ias[1].iaid, 2);
    assert_eq!(ias[1].prefixes().count(), 0);
    let status = ias[1].status().expect("a status");
    assert_eq!(status.code, status::NO_PREFIX_AVAIL);
    assert_eq!(status.message, b"no prefixes available");
}

#[test]
fn the_renew_seed_shares_an_iaid_between_an_ia_na_and_an_ia_pd() {
    let bytes = seed("renew-ia-na-ia-pd-same-iaid");
    let message = Message::parse(&bytes).expect("parses");
    assert_eq!(message.kind(), MessageType::Renew);
    assert_eq!(message.transaction_id(), 0x0000_bb03);
    let nas: Vec<_> = message.ia_nas().map(|ia| ia.expect("an IA_NA")).collect();
    let pds: Vec<_> = message.ia_pds().map(|ia| ia.expect("an IA_PD")).collect();
    assert_eq!((nas.len(), pds.len()), (1, 1));
    assert_eq!(nas[0].iaid, 1);
    assert_eq!(pds[0].iaid, 1);
    let address = nas[0]
        .addresses()
        .next()
        .expect("an address")
        .expect("an IA Address");
    assert_eq!(address.addr, ip("2001:db8:1::100"));
    assert_eq!((address.preferred, address.valid), (3000, 4000));
    let prefix = pds[0]
        .prefixes()
        .next()
        .expect("a prefix")
        .expect("an IA Prefix");
    assert_eq!(prefix.prefix, ip("2001:db8:180:100::"));
    assert_eq!(prefix.prefix_len, 60);
    assert_eq!((prefix.preferred, prefix.valid), (3000, 4000));
}

#[test]
fn the_release_seed_gives_back_a_prefix() {
    let bytes = seed("release-ia-pd");
    let message = Message::parse(&bytes).expect("parses");
    assert_eq!(message.kind(), MessageType::Release);
    assert_eq!(message.transaction_id(), 0x0000_bb04);
    assert_eq!(message.ia_nas().count(), 0);
    let ia = message
        .ia_pds()
        .next()
        .expect("an IA_PD")
        .expect("well formed");
    assert_eq!(ia.iaid, 1);
    let prefix = ia
        .prefixes()
        .next()
        .expect("a prefix")
        .expect("an IA Prefix");
    assert_eq!(
        (prefix.prefix, prefix.prefix_len),
        (ip("2001:db8:180:100::"), 60)
    );
}
