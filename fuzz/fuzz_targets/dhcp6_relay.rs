#![no_main]
//! A DHCPv6 relay chain (RFC 8415 section 19) built from the input, parsed, and answered with
//! a RELAY-REPL chain built back from what was parsed.
//!
//! The input is a control octet and the rest. Bits 0 to 2 of the control octet are the depth,
//! 0 to 7 RELAY-FORW layers. For each layer, from the outermost, the input gives:
//!
//! - a control octet: bit 0 a link address of `::` (a lightweight relay of RFC 6221), bit 1 an
//!   Interface-Id, bit 2 a Client Link-Layer Address (RFC 6939), bit 3 the two options after
//!   the Relay Message option instead of before it, bits 4 to 7 the hop count;
//! - one octet for the link address, one for the peer address;
//! - with bit 1, a length octet (taken modulo 20) and that many octets of Interface-Id;
//! - with bit 2, a hardware type octet, a length octet (1 to 8 after the modulo) and that
//!   many octets of address.
//!
//! Then three octets of transaction id, and the rest of the input is the options area of the
//! client's SOLICIT in the innermost layer, whatever it holds.
//!
//! It checks that `RelayChain::parse` finds the depth, that the link address, the
//! Interface-Id and the Client Link-Layer Address are the innermost ones built, that the
//! relays carry the hop counts and addresses they were built with, and that a RELAY-REPL
//! chain built from the parsed one has the same depth with the Interface-Ids echoed at the
//! layers they came from.

use std::net::Ipv6Addr;

use libfuzzer_sys::fuzz_target;
use tenko_dhcp::v6::{MAX_RELAY_DEPTH, Message, MessageBuilder, MessageType, RelayChain, code};

/// The octets of the input, read in order; zeros after the end.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((&byte, rest)) => {
                self.rest = rest;
                byte
            }
            None => 0,
        }
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let (head, rest) = self.rest.split_at(len.min(self.rest.len()));
        self.rest = rest;
        head
    }
}

/// One RELAY-FORW layer as it is built.
struct Layer<'a> {
    hop_count: u8,
    link: Ipv6Addr,
    peer: Ipv6Addr,
    interface_id: Option<&'a [u8]>,
    /// The value of option 79: the hardware type and the address.
    link_layer: Option<Vec<u8>>,
    after: bool,
}

impl<'a> Layer<'a> {
    fn read(cursor: &mut Cursor<'a>, depth: u16) -> Self {
        let control = cursor.byte();
        let link_byte = cursor.byte();
        let peer_byte = cursor.byte();
        let link = if control & 1 != 0 {
            Ipv6Addr::UNSPECIFIED
        } else {
            Ipv6Addr::new(0x2001, 0xdb8, depth, u16::from(link_byte), 0, 0, 0, 1)
        };
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(peer_byte));
        let interface_id = (control & 2 != 0).then(|| {
            let len = usize::from(cursor.byte() % 20);
            cursor.take(len)
        });
        let link_layer = (control & 4 != 0)
            .then(|| {
                let kind = cursor.byte();
                let len = 1 + usize::from(cursor.byte() % 8);
                let address = cursor.take(len);
                (!address.is_empty()).then(|| {
                    let mut value = vec![0, kind];
                    value.extend_from_slice(address);
                    value
                })
            })
            .flatten();
        Self {
            hop_count: control >> 4,
            link,
            peer,
            interface_id,
            link_layer,
            after: control & 8 != 0,
        }
    }

    /// The options a relay adds around the relayed message.
    fn write_options(&self, out: &mut MessageBuilder<'_>) {
        if let Some(id) = self.interface_id {
            out.option(code::INTERFACE_ID, id).expect("room");
        }
        if let Some(value) = &self.link_layer {
            out.option(code::CLIENT_LINKLAYER_ADDR, value)
                .expect("room");
        }
    }
}

/// The RELAY-FORW message for `layers` around `inner`.
fn build_forward(layers: &[Layer<'_>], inner: &[u8]) -> Vec<u8> {
    if layers.is_empty() {
        return inner.to_vec();
    }
    // Each layer adds a header and at most 80 octets of options.
    let size = layers.len() * 128 + inner.len() + 64;
    let mut buf = vec![0u8; size];
    let mut out = MessageBuilder::new(&mut buf, size).expect("room for a header");
    let mut marks = Vec::new();
    for (at, layer) in layers.iter().enumerate() {
        out.relay(
            MessageType::RelayForw,
            layer.hop_count,
            layer.link,
            layer.peer,
        )
        .expect("room");
        if !layer.after {
            layer.write_options(&mut out);
        }
        if at + 1 == layers.len() {
            out.option(code::RELAY_MSG, inner).expect("room");
            if layer.after {
                layer.write_options(&mut out);
            }
        } else {
            marks.push(out.begin(code::RELAY_MSG).expect("room"));
        }
    }
    for (at, mark) in marks.into_iter().enumerate().rev() {
        out.end(mark).expect("closed from the inside out");
        if layers[at].after {
            layers[at].write_options(&mut out);
        }
    }
    let len = out.finish().expect("every option was closed");
    buf.truncate(len);
    buf
}

/// The RELAY-REPL chain for the relays of `chain` around a REPLY: each layer copies the hop
/// count and the addresses, and echoes the Interface-Id.
fn build_reply(chain: &RelayChain<'_>, transaction_id: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let size = buf.len();
    let mut out = MessageBuilder::new(&mut buf, size).expect("room for a header");
    let mut marks = Vec::new();
    for relay in chain.relays() {
        out.relay(
            MessageType::RelayRepl,
            relay.hop_count(),
            relay.link_address(),
            relay.peer_address(),
        )
        .expect("room");
        if let Ok(Some(id)) = relay.interface_id() {
            out.option(code::INTERFACE_ID, id).expect("room");
        }
        marks.push(out.begin(code::RELAY_MSG).expect("room"));
    }
    out.message(MessageType::Reply, transaction_id)
        .expect("room");
    out.status(0, b"ok").expect("room");
    for mark in marks.into_iter().rev() {
        out.end(mark).expect("closed from the inside out");
    }
    let len = out.finish().expect("every option was closed");
    buf.truncate(len);
    buf
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let depth = usize::from(control & 7);
    let mut cursor = Cursor { rest };
    let layers: Vec<Layer<'_>> = (0..depth)
        .map(|at| Layer::read(&mut cursor, at as u16))
        .collect();
    let transaction_id = u32::from_be_bytes([0, cursor.byte(), cursor.byte(), cursor.byte()]);
    // A Relay Message option holds at most 65,535 octets.
    let options = &cursor.rest[..cursor.rest.len().min(32 * 1024)];
    let mut inner = vec![MessageType::Solicit.to_u8()];
    inner.extend_from_slice(&transaction_id.to_be_bytes()[1..]);
    inner.extend_from_slice(options);

    let forward = build_forward(&layers, &inner);
    let message = Message::parse(&forward).expect("a built relay message parses");
    let chain = RelayChain::parse(message).expect("a built relay chain parses");

    assert_eq!(chain.depth(), depth);
    assert!(chain.depth() <= MAX_RELAY_DEPTH);
    assert_eq!(chain.client().as_bytes(), &inner[..]);
    assert_eq!(chain.client().kind(), MessageType::Solicit);
    assert_eq!(chain.client().transaction_id(), transaction_id);
    for (relay, layer) in chain.relays().zip(&layers) {
        assert_eq!(relay.kind(), MessageType::RelayForw);
        assert_eq!(relay.hop_count(), layer.hop_count);
        assert_eq!(relay.link_address(), layer.link);
        assert_eq!(relay.peer_address(), layer.peer);
        assert_eq!(relay.validate(), Ok(()));
        assert_eq!(relay.interface_id(), Ok(layer.interface_id));
    }

    let link = layers
        .iter()
        .rev()
        .map(|layer| layer.link)
        .find(|link| !link.is_unspecified());
    assert_eq!(chain.link_address(), link);
    let interface_id = layers.iter().rev().find_map(|layer| layer.interface_id);
    assert_eq!(chain.interface_id(), interface_id);
    let link_layer = layers
        .iter()
        .rev()
        .find_map(|layer| layer.link_layer.as_deref());
    match (chain.client_link_layer(), link_layer) {
        (None, None) => {}
        (Some(read), Some(built)) => {
            assert_eq!(read.kind, u16::from_be_bytes([built[0], built[1]]));
            assert_eq!(read.address, &built[2..]);
        }
        (read, built) => panic!("client link-layer address {read:?} for {built:?}"),
    }

    // The reply goes back out through the same relays.
    let reply = build_reply(&chain, transaction_id);
    let mut current = Message::parse(&reply).expect("a built relay reply parses");
    // `RelayChain::parse` follows RELAY-FORW only: a RELAY-REPL is where its walk ends.
    if depth > 0 {
        let reply_chain = RelayChain::parse(current).expect("no relay to follow");
        assert_eq!(reply_chain.depth(), 0);
        assert_eq!(reply_chain.client(), current);
    }
    for relay in chain.relays() {
        assert_eq!(current.kind(), MessageType::RelayRepl);
        assert_eq!(current.hop_count(), relay.hop_count());
        assert_eq!(current.link_address(), relay.link_address());
        assert_eq!(current.peer_address(), relay.peer_address());
        assert_eq!(current.interface_id(), relay.interface_id());
        assert_eq!(current.validate(), Ok(()));
        current = current
            .relay_message()
            .expect("the relayed message parses")
            .expect("a Relay Message option");
    }
    assert_eq!(current.kind(), MessageType::Reply);
    assert_eq!(current.transaction_id(), transaction_id);
    assert_eq!(current.validate(), Ok(()));
});
