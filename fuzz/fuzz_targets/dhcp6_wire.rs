#![no_main]
//! The DHCPv6 codec on arbitrary octets (RFC 8415): `Message::parse`, the option walk, every
//! typed accessor, the identity associations with their addresses and prefixes, the relay
//! chain, the domain list and the NTP server option, and a REPLY built for every client or
//! server message that parses, which must read back.
//!
//! Nothing may panic. The invariants kept: the options a walk yields lie inside the message
//! and, when the walk ends without an error, add up to the options area; the relay chain is
//! at most `MAX_RELAY_DEPTH` deep and ends in a message that is no RELAY-FORW; a domain list
//! encodes back to the octets it came from; and a built REPLY parses with the transaction id
//! it was given and the IA_NA options in the order they were written, also when an option
//! did not fit and was rewound.

use std::net::Ipv6Addr;

use libfuzzer_sys::fuzz_target;
use tenko_dhcp::v4::WireName;
use tenko_dhcp::v6::{
    EncodeError, MAX_RELAY_DEPTH, Message, MessageBuilder, MessageType, NtpServer, NtpSuboption,
    Options, RELAY_HEADER_LEN, RelayChain, code, encode_domain_list, encode_ntp_servers,
    option::{AddrList, DomainList},
};

/// The address every built `IA_NA` carries.
const ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// The octets of `inner` lie inside `outer`.
fn is_inside(outer: &[u8], inner: &[u8]) -> bool {
    let start = outer.as_ptr() as usize;
    let at = inner.as_ptr() as usize;
    at >= start && at + inner.len() <= start + outer.len()
}

/// Walks an option area: every value lies inside the message, and a walk that ends without
/// an error has used every octet of the area.
fn walk(message: &[u8], area: &[u8], options: Options<'_>) {
    let mut walked = 0;
    let mut failed = false;
    for option in options {
        match option {
            Ok(option) => {
                assert!(!failed, "an option after an error");
                assert!(is_inside(message, option.data));
                assert!(is_inside(area, option.data));
                walked += 4 + option.data.len();
            }
            Err(_) => failed = true,
        }
    }
    if failed {
        assert!(walked <= area.len());
        assert!(options.validate().is_err());
    } else {
        assert_eq!(walked, area.len());
        assert_eq!(options.validate(), Ok(()));
    }
}

/// Reads the typed options of a client, server or relay message.
fn read_typed(message: &Message<'_>) {
    let _ = message.validate();
    let _ = (message.rapid_commit(), message.reconfigure_accept());
    let _ = message.has_ia_ta();
    let _ = (message.elapsed_time(), message.interface_id());
    for duid in [message.client_id(), message.server_id()] {
        if let Ok(Some(duid)) = duid {
            assert!((3..=130).contains(&duid.as_bytes().len()));
            assert_eq!(duid.body().len() + 2, duid.as_bytes().len());
            let _ = (duid.kind(), duid.time(), duid.enterprise(), duid.uuid());
            if let Some((_, address)) = duid.link_layer() {
                assert!(!address.is_empty());
            }
            let _ = format!("{duid:?}");
        }
    }
    if let Ok(Some(request)) = message.option_request() {
        assert_eq!(request.len(), request.codes().count());
        assert_eq!(request.is_empty(), request.len() == 0);
        if let Some(first) = request.codes().next() {
            assert!(request.contains(first));
        }
    }
    if let Ok(Some(id)) = message.remote_id() {
        assert_eq!(&id.as_bytes()[4..], id.id);
    }
    if let Ok(Some(link)) = message.client_link_layer() {
        let _ = link.mac();
        assert!(!link.address.is_empty());
    }
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        let name = fqdn.name();
        assert!(name.as_wire().len() <= 255);
        let _ = name.to_string();
        let _ = (
            fqdn.flags(),
            fqdn.server_updates(),
            fqdn.no_update(),
            fqdn.flags_v4(),
        );
        let _ = fqdn.name_bytes();
    }
    if let Ok(Some(classes)) = message.user_class() {
        let used: usize = classes.iter().map(|class| 2 + class.len()).sum();
        assert_eq!(used, classes.as_bytes().len());
    }
    if let Ok(Some(vendor)) = message.vendor_class() {
        let _ = vendor.enterprise;
        let _ = vendor.classes.iter().count();
    }
    for code in [code::DNS_SERVERS, code::SNTP_SERVERS, code::SIP_SERVER_A] {
        if let Ok(Some(data)) = message.option(code)
            && let Ok(list) = AddrList::parse(code, data)
        {
            assert_eq!(list.len(), list.iter().count());
            assert_eq!(list.is_empty(), data.is_empty());
        }
    }
    let _ = message.relay_message();
    // The identity associations with the addresses and prefixes in them.
    for ia in message.ia_nas() {
        let Ok(ia) = ia else { break };
        let _ = (ia.iaid, ia.t1, ia.t2, ia.status());
        let _ = ia.options().validate();
        for address in ia.addresses() {
            let Ok(address) = address else { break };
            let _ = (address.addr, address.preferred, address.valid);
            let _ = address.status();
            let _ = address.options().validate();
        }
    }
    for ia in message.ia_pds() {
        let Ok(ia) = ia else { break };
        let _ = (ia.iaid, ia.t1, ia.t2, ia.status());
        let _ = ia.options().validate();
        for prefix in ia.prefixes() {
            let Ok(prefix) = prefix else { break };
            assert!(prefix.prefix_len <= 128);
            let _ = (prefix.preferred, prefix.valid, prefix.prefix);
            let _ = prefix.options().validate();
        }
    }
}

/// Re-encodes the names of a domain list: the octets must be the ones it was read from.
fn check_domain_list(code: u16, data: &[u8]) {
    let Ok(list) = DomainList::parse(code, data) else {
        return;
    };
    assert_eq!(list.as_bytes(), data);
    let names: Vec<WireName> = list.iter().collect();
    assert!(names.iter().all(WireName::is_absolute));
    let mut out = vec![0u8; data.len()];
    let len = encode_domain_list(&names, &mut out).expect("the names fit where they came from");
    assert_eq!(&out[..len], data);
}

/// The NTP Server option: its sub-options read as a walk of the value, and the addresses in
/// it encode again.
fn check_ntp(data: &[u8]) {
    let Ok(ntp) = NtpServer::parse(data) else {
        return;
    };
    let mut addresses = Vec::new();
    let mut count = 0;
    for sub in ntp.suboptions() {
        count += 1;
        match sub {
            NtpSuboption::ServerAddress(addr) => addresses.push(addr),
            NtpSuboption::MulticastAddress(_) | NtpSuboption::Other(_) => {}
            NtpSuboption::ServerName(name) => assert!(WireName::from_wire(name).is_some()),
        }
    }
    assert_eq!(count, Options::new(data).count());
    let mut out = vec![0u8; addresses.len() * 20];
    let len = encode_ntp_servers(&addresses, &mut out).expect("twenty octets each");
    let again = NtpServer::parse(&out[..len]).expect("encoded servers decode");
    assert!(
        again.suboptions().eq(addresses
            .iter()
            .map(|addr| NtpSuboption::ServerAddress(*addr)))
    );
}

/// Walks the relay chain of a message.
fn check_chain(message: Message<'_>) {
    let Ok(chain) = RelayChain::parse(message) else {
        return;
    };
    assert!(chain.depth() <= MAX_RELAY_DEPTH);
    assert_ne!(chain.client().kind(), MessageType::RelayForw);
    assert_eq!(chain.is_relayed(), chain.depth() > 0);
    assert_eq!(chain.relays().count(), chain.depth());
    assert!(
        chain
            .relays()
            .all(|relay| relay.kind() == MessageType::RelayForw)
    );
    assert_eq!(chain.relays().next(), chain.outermost());
    assert_eq!(chain.relays().next_back(), chain.innermost());
    if chain.depth() == 0 {
        assert_eq!(chain.client(), message);
        assert!(chain.innermost().is_none() && chain.outermost().is_none());
    } else {
        assert_eq!(chain.outermost(), Some(message));
        let innermost = chain.innermost().expect("a relay");
        assert_eq!(innermost.relay_message(), Ok(Some(chain.client())));
        // Each relay holds the next one in its Relay Message option.
        let relays: Vec<_> = chain.relays().collect();
        for pair in relays.windows(2) {
            assert_eq!(pair[0].relay_message(), Ok(Some(pair[1])));
        }
    }
    if let Some(link) = chain.link_address() {
        assert!(!link.is_unspecified());
        assert!(chain.relays().any(|relay| relay.link_address() == link));
    } else {
        assert!(
            chain
                .relays()
                .all(|relay| relay.link_address().is_unspecified())
        );
    }
    let _ = (chain.interface_id(), chain.remote_id());
    let _ = chain.client_link_layer();
    let _ = format!("{chain:?}");
}

/// One `IA_NA` of the reply: an address with a status in it, and a status of the `IA_NA`.
/// On an error the options opened here are taken back.
fn add_ia(reply: &mut MessageBuilder<'_>, iaid: u32) -> Result<(), EncodeError> {
    let ia = reply.begin_ia_na(iaid, 3600, 5400)?;
    match fill_ia(reply) {
        Ok(()) => {
            reply.end(ia)?;
            Ok(())
        }
        Err(error) => {
            reply
                .rewind(ia)
                .expect("the IA_NA is the innermost open option");
            Err(error)
        }
    }
}

fn fill_ia(reply: &mut MessageBuilder<'_>) -> Result<(), EncodeError> {
    let address = reply.begin_ia_address(ADDRESS, 1800, 3600)?;
    if let Err(error) = reply.status(0, b"ok") {
        reply
            .rewind(address)
            .expect("the address is the innermost open option");
        return Err(error);
    }
    reply.end(address)?;
    reply.status(0, b"granted")?;
    Ok(())
}

/// Builds a REPLY for a message that parsed and reads it back.
fn build_reply(message: &Message<'_>) {
    let id = message.transaction_id();
    // A fourth of the messages get a small limit, so that options do not fit.
    let limit = if id & 3 == 0 {
        RELAY_HEADER_LEN + (id >> 2) as usize % 300
    } else {
        1452
    };
    let mut buf = [0u8; 1452];
    let mut reply = MessageBuilder::new(&mut buf, limit).expect("room for a header");
    reply
        .message(MessageType::Reply, id)
        .expect("a header fits");
    let mut echoed = None;
    if let Ok(Some(duid)) = message.client_id() {
        match reply.option(code::CLIENTID, duid.as_bytes()) {
            Ok(_) => echoed = Some(duid),
            Err(error) => assert_eq!(
                error,
                EncodeError::NoRoom {
                    code: code::CLIENTID
                }
            ),
        }
    }
    let mut iaids = Vec::new();
    for ia in message.ia_nas().take(8) {
        let Ok(ia) = ia else { break };
        match add_ia(&mut reply, ia.iaid) {
            Ok(()) => iaids.push(ia.iaid),
            Err(error) => {
                // The option that did not fit is the innermost one that was open.
                assert!(matches!(error, EncodeError::NoRoom { .. }));
                break;
            }
        }
    }
    let len = reply.finish().expect("every option was closed or rewound");
    assert!(len <= limit);

    let built = Message::parse(&buf[..len]).expect("a built reply parses");
    assert_eq!(built.kind(), MessageType::Reply);
    assert_eq!(built.transaction_id(), id);
    built.validate().expect("a built reply walks");
    assert_eq!(built.client_id().expect("ok"), echoed);
    let read: Vec<_> = built
        .ia_nas()
        .map(|ia| ia.expect("a built IA_NA parses"))
        .collect();
    assert_eq!(read.len(), iaids.len());
    for (ia, iaid) in read.iter().zip(&iaids) {
        assert_eq!(ia.iaid, *iaid);
        assert_eq!((ia.t1, ia.t2), (3600, 5400));
        assert_eq!(ia.status().map(|status| status.code), Some(0));
        let addresses: Vec<_> = ia.addresses().collect();
        assert_eq!(addresses.len(), 1);
        let address = addresses[0].expect("a built address parses");
        assert_eq!(address.addr, ADDRESS);
        assert_eq!(
            address.status().map(|status| status.message),
            Some(&b"ok"[..])
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(message) = Message::parse(data) else {
        return;
    };
    assert_eq!(message.as_bytes(), data);
    assert_eq!(message.len(), data.len());
    assert!(!message.is_empty());
    assert_eq!(message.kind().to_u8(), data[0]);
    walk(data, message.options_area(), message.options());
    read_typed(&message);
    let _ = format!("{message:?}");
    for area in [code::DOMAIN_LIST, code::SIP_SERVER_D] {
        if let Ok(Some(value)) = message.option(area) {
            check_domain_list(area, value);
        }
    }
    if let Ok(Some(value)) = message.option(code::NTP_SERVER) {
        check_ntp(value);
    }
    check_chain(message);
    if !message.is_relay() {
        build_reply(&message);
    }
});
