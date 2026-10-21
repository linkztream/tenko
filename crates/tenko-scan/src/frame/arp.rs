//! ARP for IPv4 over Ethernet (RFC 826): the request the sweep sends and the reply it
//! reads. Only the Ethernet/IPv4 hardware and protocol pair is handled, which is the only
//! one the sweep uses.

use std::net::Ipv4Addr;

use tenko_core::MacAddr;

use super::ethernet::{ETHERTYPE_ARP, ETHERTYPE_IPV4};

/// ARP hardware type 1: Ethernet.
const HW_ETHERNET: u16 = 1;
/// ARP opcode for a request.
pub const OP_REQUEST: u16 = 1;
/// ARP opcode for a reply.
pub const OP_REPLY: u16 = 2;

/// A parsed ARP message (the fields the sweep needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    /// The operation: [`OP_REQUEST`] or [`OP_REPLY`].
    pub operation: u16,
    /// The sender's hardware address.
    pub sender_mac: MacAddr,
    /// The sender's IPv4 address.
    pub sender_ip: Ipv4Addr,
    /// The target's hardware address.
    pub target_mac: MacAddr,
    /// The target's IPv4 address.
    pub target_ip: Ipv4Addr,
}

fn mac_at(bytes: &[u8], at: usize) -> Option<MacAddr> {
    let slice: [u8; 6] = bytes.get(at..at + 6)?.try_into().ok()?;
    Some(MacAddr::new(slice))
}

fn ipv4_at(bytes: &[u8], at: usize) -> Option<Ipv4Addr> {
    let slice: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(slice))
}

/// Parses an ARP message (the payload of an ARP Ethernet frame). Only Ethernet hardware
/// with IPv4 protocol addresses is accepted.
pub fn parse(bytes: &[u8]) -> Option<Arp> {
    let hw_type = u16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?);
    let proto_type = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    let hw_len = *bytes.get(4)?;
    let proto_len = *bytes.get(5)?;
    if hw_type != HW_ETHERNET || proto_type != ETHERTYPE_IPV4 || hw_len != 6 || proto_len != 4 {
        return None;
    }
    let operation = u16::from_be_bytes(bytes.get(6..8)?.try_into().ok()?);
    Some(Arp {
        operation,
        sender_mac: mac_at(bytes, 8)?,
        sender_ip: ipv4_at(bytes, 14)?,
        target_mac: mac_at(bytes, 18)?,
        target_ip: ipv4_at(bytes, 24)?,
    })
}

/// Builds an Ethernet frame holding an ARP request that asks who has `target_ip`, from the
/// probe's `source_mac` and `source_ip`. The destination is the broadcast address.
pub fn request_frame(source_mac: MacAddr, source_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]); // broadcast destination
    frame.extend_from_slice(&source_mac.octets());
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame.extend_from_slice(&HW_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&OP_REQUEST.to_be_bytes());
    frame.extend_from_slice(&source_mac.octets());
    frame.extend_from_slice(&source_ip.octets());
    frame.extend_from_slice(&[0x00; 6]); // unknown target hardware address
    frame.extend_from_slice(&target_ip.octets());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(bytes: [u8; 6]) -> MacAddr {
        MacAddr::new(bytes)
    }

    #[test]
    fn a_built_request_parses_back() {
        let src = mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        let frame = request_frame(
            src,
            Ipv4Addr::new(192, 0, 2, 5),
            Ipv4Addr::new(192, 0, 2, 9),
        );
        assert_eq!(frame.len(), 42);
        // Skip the 14-byte Ethernet header.
        let arp = parse(&frame[14..]).expect("arp");
        assert_eq!(arp.operation, OP_REQUEST);
        assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 0, 2, 5));
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(arp.sender_mac, src);
    }

    #[test]
    fn a_reply_is_read() {
        let reply = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, // Ethernet/IPv4, reply
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a, // sender MAC
            0xc0, 0x00, 0x02, 0x09, // sender IP 192.0.2.9
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, // target MAC
            0xc0, 0x00, 0x02, 0x05, // target IP 192.0.2.5
        ];
        let arp = parse(&reply).expect("arp");
        assert_eq!(arp.operation, OP_REPLY);
        assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(arp.sender_mac, mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a]));
    }

    #[test]
    fn other_hardware_or_protocol_is_rejected() {
        // Hardware type 2 is not Ethernet.
        let other = [0x00, 0x02, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
        assert!(parse(&other).is_none());
        assert!(parse(&[0x00, 0x01]).is_none());
    }
}
