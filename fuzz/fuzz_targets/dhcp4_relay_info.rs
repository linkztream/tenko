#![no_main]
//! Option 82, the relay agent information (RFC 3046), from the sub-option parser through
//! scope selection to the echo in the reply.
//!
//! The input is one control octet and the value of option 82. The control octet picks the
//! request around the value: bits 0 and 1 the message type (DISCOVER, REQUEST, INFORM,
//! RELEASE), bit 2 a `giaddr`, bit 3 option 118, bit 4 a `ciaddr`; the value goes in as the
//! last option, split into instances of at most 255 octets when longer (RFC 3396).
//!
//! It checks that the parser walks every octet of a value it accepts and that its
//! accessors return the first instance of their sub-option; that scope selection follows
//! the order of plan section 2.5 (link selection, option 118, `giaddr`, `ciaddr`, the
//! listener); and that a reply built for the request carries the value back unchanged.

use std::net::{Ipv4Addr, SocketAddrV4};

use libfuzzer_sys::fuzz_target;
use tenko_dhcp::v4::{
    BOOTREQUEST, Message, MessageBuilder, MessageType, RelayAgentInfo, SubOptions, code,
    engine::{
        ListenMode, Received,
        select::{Selector, selector},
    },
};

const GIADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SUBNET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
const CIADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const LISTENER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

/// The parser's view of a value it accepts.
fn check_parser(value: &[u8], info: &RelayAgentInfo<'_>) {
    assert_eq!(info.as_bytes(), value);
    let subs = info.sub_options();
    let mut walked = 0;
    for (sub, data) in subs {
        walked += 2 + data.len();
        if matches!(
            sub,
            RelayAgentInfo::LINK_SELECTION | RelayAgentInfo::SERVER_ID_OVERRIDE
        ) {
            assert_eq!(data.len(), 4);
        }
    }
    assert_eq!(walked, value.len());
    let first = |code: u8| {
        subs.into_iter()
            .find(|(sub, _)| *sub == code)
            .map(|(_, v)| v)
    };
    assert_eq!(info.circuit_id(), first(RelayAgentInfo::CIRCUIT_ID));
    assert_eq!(info.remote_id(), first(RelayAgentInfo::REMOTE_ID));
    assert_eq!(info.subscriber_id(), first(RelayAgentInfo::SUBSCRIBER_ID));
    assert_eq!(info.relay_id(), first(RelayAgentInfo::RELAY_ID));
    let address = |code: u8| {
        first(code).map(|v| Ipv4Addr::from(<[u8; 4]>::try_from(v).expect("four octets")))
    };
    assert_eq!(
        info.link_selection(),
        address(RelayAgentInfo::LINK_SELECTION)
    );
    assert_eq!(
        info.server_id_override(),
        address(RelayAgentInfo::SERVER_ID_OVERRIDE)
    );
    assert_eq!(
        SubOptions::parse(code::RELAY_AGENT_INFORMATION, value),
        Ok(subs)
    );
}

/// The request around the value, or `None` when the value does not fit a message.
fn request(control: u8, value: &[u8], out: &mut [u8]) -> Option<usize> {
    let kind = match control & 3 {
        0 => MessageType::Discover,
        1 => MessageType::Request,
        2 => MessageType::Inform,
        _ => MessageType::Release,
    };
    let mut builder = MessageBuilder::new(out, out.len()).ok()?;
    builder.op(BOOTREQUEST).htype(1).hlen(6).xid(0x5e00_5301);
    if control & 4 != 0 {
        builder.hops(1).giaddr(GIADDR);
    }
    if control & 16 != 0 {
        builder.ciaddr(CIADDR);
    }
    builder.chaddr(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]).ok()?;
    builder.message_type(kind).ok()?;
    if control & 8 != 0 {
        builder
            .option(code::SUBNET_SELECTION, &SUBNET.octets())
            .ok()?;
    }
    if !value.is_empty() {
        builder.relay_agent_info(value).ok()?;
    }
    builder.finish().ok()
}

fuzz_target!(|data: &[u8]| {
    let (control, value) = data.split_first().map_or((0, data), |(c, v)| (*c, v));

    let parsed = RelayAgentInfo::parse(value);
    if let Ok(info) = &parsed {
        check_parser(value, info);
    }

    let mut buf = vec![0u8; 576 + 2 * value.len() + 16];
    let Some(len) = request(control, value, &mut buf) else {
        return;
    };
    let message = Message::parse(&buf[..len]).expect("a built request parses");
    message.validate().expect("a built request walks");

    // The value read back from the message: one instance as is, several joined.
    let mut joined = vec![0u8; value.len()];
    let read = message
        .option_data(code::RELAY_AGENT_INFORMATION, &mut joined)
        .expect("the request walks");
    assert_eq!(read, (!value.is_empty()).then_some(value));
    if value.len() <= 255 {
        assert_eq!(message.relay_agent_info().ok().flatten(), parsed.ok());
    }

    // Scope selection: the first of link selection, option 118, giaddr, ciaddr, listener.
    let kind = message.message_type().expect("53").expect("a type");
    let relay = parsed.ok();
    let received = Received {
        bytes: &buf[..len],
        source: SocketAddrV4::new(GIADDR, 67),
        local: LISTENER,
        mode: ListenMode::Relay,
    };
    let expected = if let Some(link) = relay.and_then(|info| info.link_selection()) {
        (link, Selector::LinkSelection)
    } else if control & 8 != 0 {
        (SUBNET, Selector::SubnetSelection)
    } else if control & 4 != 0 {
        (GIADDR, Selector::Giaddr)
    } else if control & 16 != 0 && kind != MessageType::Discover {
        (CIADDR, Selector::ClientAddress)
    } else {
        (LISTENER, Selector::Interface)
    };
    assert_eq!(selector(&message, kind, relay, &received), expected);

    // The reply carries the value back unchanged (RFC 3046 section 2.2).
    let Some(info) = relay else {
        return;
    };
    let mut out = vec![0u8; 1500];
    let Ok(mut reply) = MessageBuilder::reply(&mut out, &message, MessageType::Offer) else {
        return;
    };
    reply.yiaddr(Ipv4Addr::new(198, 51, 100, 20));
    if reply.server_identifier(LISTENER).is_err() {
        return;
    }
    if reply.relay_agent_info(info.as_bytes()).is_err() {
        // A value longer than the reply's limit does not fit; the engine then drops it.
        return;
    }
    let len = reply.finish().expect("finish");
    let built = Message::parse(&out[..len]).expect("a built reply parses");
    let mut echoed = vec![0u8; value.len()];
    let back = built
        .option_data(code::RELAY_AGENT_INFORMATION, &mut echoed)
        .expect("the reply walks")
        .expect("option 82 in the reply");
    assert_eq!(back, value);
    assert_eq!(built.giaddr(), message.giaddr());
    assert_eq!(built.xid(), message.xid());
});
