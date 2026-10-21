//! Ethernet II and IEEE 802.2/SNAP framing: the destination and source MAC, the VLAN tag
//! when present, and the ethertype or the SNAP (OUI, protocol) pair that says what the
//! payload is. LLDP rides directly on Ethernet II (ethertype `0x88cc`); CDP rides on
//! 802.2 LLC with a SNAP header (Cisco OUI `00:00:0c`, protocol `0x2000`).

use tenko_core::MacAddr;

/// The ethertype of LLDP frames (IEEE 802.1AB).
pub const ETHERTYPE_LLDP: u16 = 0x88cc;
/// The ethertype of ARP frames (RFC 826).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// The ethertype of IPv4 frames.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// The ethertype of an 802.1Q VLAN tag; the real ethertype follows the tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// The Cisco OUI used in the SNAP header of CDP.
pub const CISCO_OUI: [u8; 3] = [0x00, 0x00, 0x0c];
/// The SNAP protocol id of CDP.
pub const SNAP_PROTOCOL_CDP: u16 = 0x2000;

/// What the payload of an Ethernet frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// An Ethernet II ethertype, such as [`ETHERTYPE_LLDP`].
    EtherType(u16),
    /// A SNAP (OUI, protocol) pair from an 802.2 LLC/SNAP header.
    Snap {
        /// The organizationally unique identifier.
        oui: [u8; 3],
        /// The protocol id within the OUI.
        protocol: u16,
    },
}

/// A parsed Ethernet frame header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The destination MAC address.
    pub destination: MacAddr,
    /// The source MAC address.
    pub source: MacAddr,
    /// The 802.1Q VLAN id, when the frame carried a tag.
    pub vlan: Option<u16>,
    /// What the payload is.
    pub protocol: Protocol,
    /// The payload after the header (and after the LLC/SNAP header for a SNAP frame).
    pub payload: &'a [u8],
}

fn mac_at(bytes: &[u8], at: usize) -> Option<MacAddr> {
    let slice: [u8; 6] = bytes.get(at..at + 6)?.try_into().ok()?;
    Some(MacAddr::new(slice))
}

/// Parses an Ethernet frame: the two MAC addresses, an optional VLAN tag, then either an
/// Ethernet II ethertype or an 802.2 LLC frame whose SNAP header gives the (OUI,
/// protocol). A length field below `0x0600` marks an 802.2 frame; only LLC/SNAP (DSAP and
/// SSAP `0xaa`, control `0x03`) is read, which is what CDP uses.
pub fn parse(bytes: &[u8]) -> Option<Frame<'_>> {
    let destination = mac_at(bytes, 0)?;
    let source = mac_at(bytes, 6)?;
    let mut at = 12;
    let mut vlan = None;
    let mut type_or_len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
    if type_or_len == ETHERTYPE_VLAN {
        let tag = u16::from_be_bytes(bytes.get(at + 2..at + 4)?.try_into().ok()?);
        vlan = Some(tag & 0x0fff);
        at += 4;
        type_or_len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
    }
    at += 2;
    if type_or_len >= 0x0600 {
        return Some(Frame {
            destination,
            source,
            vlan,
            protocol: Protocol::EtherType(type_or_len),
            payload: bytes.get(at..)?,
        });
    }
    // An 802.2 frame: the type field was a length. Read an LLC/SNAP header.
    let llc = bytes.get(at..at + 3)?;
    if llc != [0xaa, 0xaa, 0x03] {
        return None;
    }
    let oui: [u8; 3] = bytes.get(at + 3..at + 6)?.try_into().ok()?;
    let protocol = u16::from_be_bytes(bytes.get(at + 6..at + 8)?.try_into().ok()?);
    Some(Frame {
        destination,
        source,
        vlan,
        protocol: Protocol::Snap { oui, protocol },
        payload: bytes.get(at + 8..)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_ii_with_an_ethertype() {
        let mut frame = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // destination
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, // source
            0x88, 0xcc, // LLDP
        ];
        frame.extend_from_slice(&[0xde, 0xad]);
        let parsed = parse(&frame).expect("frame");
        assert_eq!(parsed.protocol, Protocol::EtherType(ETHERTYPE_LLDP));
        assert_eq!(parsed.vlan, None);
        assert_eq!(parsed.payload, &[0xde, 0xad]);
        assert_eq!(
            parsed.source,
            MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01])
        );
    }

    #[test]
    fn a_vlan_tag_is_read_and_skipped() {
        let frame = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x81, 0x00,
            0x00, 0x64, // VLAN 100
            0x08, 0x00, // IPv4
            0x45,
        ];
        let parsed = parse(&frame).expect("frame");
        assert_eq!(parsed.vlan, Some(100));
        assert_eq!(parsed.protocol, Protocol::EtherType(ETHERTYPE_IPV4));
        assert_eq!(parsed.payload, &[0x45]);
    }

    #[test]
    fn an_llc_snap_frame_gives_the_oui_and_protocol() {
        let frame = vec![
            0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x20,
            // length 0x20 < 0x0600 marks 802.2
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00, // SNAP: Cisco OUI, CDP
            0x02, 0xb4, // payload
        ];
        let parsed = parse(&frame).expect("frame");
        assert_eq!(
            parsed.protocol,
            Protocol::Snap {
                oui: CISCO_OUI,
                protocol: SNAP_PROTOCOL_CDP
            }
        );
        assert_eq!(parsed.payload, &[0x02, 0xb4]);
    }

    #[test]
    fn short_and_non_snap_frames_are_rejected() {
        assert!(parse(&[0x00; 10]).is_none());
        let not_snap = vec![
            0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x10,
            0xff, 0xff, 0x03,
        ];
        assert!(parse(&not_snap).is_none());
    }
}
