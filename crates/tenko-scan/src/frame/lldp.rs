//! LLDP TLV parsing (IEEE 802.1AB): chassis id, port id, TTL, port description, system
//! name, system description, capabilities, management address, and the 802.1
//! organizationally specific TLVs for the port VLAN id and VLAN names. The frame is the
//! Ethernet payload after ethertype `0x88cc`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tenko_core::MacAddr;

use super::{Neighbour, NeighbourCapabilities, NeighbourSource};

/// The 802.1 organizationally specific OUI (VLAN TLVs).
const OUI_8021: [u8; 3] = [0x00, 0x80, 0xc2];

/// Formats a chassis or port id by its subtype byte: a MAC address (subtype 4 chassis / 3
/// port), a network address (subtype 5 chassis / 4 port), otherwise the bytes as text when
/// they are printable, else lowercase hex.
fn format_id(subtype: u8, value: &[u8], mac_subtype: u8, addr_subtype: u8) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if subtype == mac_subtype && value.len() == 6 {
        let mac: [u8; 6] = value.try_into().ok()?;
        return Some(MacAddr::new(mac).to_string());
    }
    if subtype == addr_subtype
        && let Some(ip) = network_address(value)
    {
        return Some(ip.to_string());
    }
    Some(as_text(value))
}

/// Reads a network address: a 1-byte family (1 IPv4, 2 IPv6) then the address.
fn network_address(value: &[u8]) -> Option<IpAddr> {
    match value {
        [1, rest @ ..] if rest.len() == 4 => {
            Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?)))
        }
        [2, rest @ ..] if rest.len() == 16 => {
            Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?)))
        }
        _ => None,
    }
}

/// Printable bytes as a trimmed string, else lowercase hex.
fn as_text(value: &[u8]) -> String {
    if value
        .iter()
        .all(|&b| b == 0 || b.is_ascii_graphic() || b == b' ')
    {
        let text = String::from_utf8_lossy(value)
            .trim_end_matches('\0')
            .trim()
            .to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    super::hex(value)
}

fn capabilities(enabled: u16) -> NeighbourCapabilities {
    NeighbourCapabilities {
        bridge: enabled & 0x04 != 0,
        router: enabled & 0x10 != 0,
        wlan: enabled & 0x08 != 0,
        telephone: enabled & 0x20 != 0,
        station: enabled & 0x80 != 0,
    }
}

/// Parses an LLDP frame into a [`Neighbour`]. Unknown TLVs are skipped by their length.
/// Returns `None` only when the TLV stream is malformed before anything useful is read.
pub fn parse(payload: &[u8]) -> Option<Neighbour> {
    let mut neighbour = Neighbour {
        source: Some(NeighbourSource::Lldp),
        ..Neighbour::default()
    };
    let mut at = 0;
    let mut saw_tlv = false;
    while at + 2 <= payload.len() {
        let header = u16::from_be_bytes([payload[at], payload[at + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = usize::from(header & 0x01ff);
        at += 2;
        if tlv_type == 0 {
            break; // end of LLDPDU
        }
        let Some(value) = payload.get(at..at + tlv_len) else {
            break;
        };
        at += tlv_len;
        saw_tlv = true;
        match tlv_type {
            1 if !value.is_empty() => {
                neighbour.chassis_id = format_id(value[0], &value[1..], 4, 5);
            }
            2 if !value.is_empty() => {
                neighbour.port_id = format_id(value[0], &value[1..], 3, 4);
            }
            3 if value.len() >= 2 => {
                neighbour.ttl = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            4 => neighbour.port_desc = Some(as_text(value)).filter(|t| !t.is_empty()),
            5 => neighbour.system_name = Some(as_text(value)).filter(|t| !t.is_empty()),
            6 => neighbour.system_desc = Some(as_text(value)).filter(|t| !t.is_empty()),
            7 if value.len() >= 4 => {
                let enabled = u16::from_be_bytes([value[2], value[3]]);
                neighbour.capabilities = capabilities(enabled);
            }
            8 => read_management_address(value, &mut neighbour),
            127 => read_org_specific(value, &mut neighbour),
            _ => {}
        }
    }
    if saw_tlv && !neighbour.is_empty() {
        Some(neighbour)
    } else {
        None
    }
}

/// Management address TLV: 1-byte address string length (subtype + address), 1-byte
/// address subtype, the address, then interface numbering and the OID, which are ignored.
fn read_management_address(value: &[u8], neighbour: &mut Neighbour) {
    let Some(&addr_len) = value.first() else {
        return;
    };
    let addr_len = usize::from(addr_len);
    if addr_len < 1 {
        return;
    }
    let Some(field) = value.get(1..1 + addr_len) else {
        return;
    };
    if let Some(ip) = network_address(field)
        && !neighbour.mgmt_addrs.contains(&ip)
    {
        neighbour.mgmt_addrs.push(ip);
    }
}

/// Organizationally specific TLV: 3-byte OUI, 1-byte subtype, then the value. The 802.1
/// OUI carries the port VLAN id (subtype 1) and VLAN names (subtype 3).
fn read_org_specific(value: &[u8], neighbour: &mut Neighbour) {
    let (Some(oui), Some(&subtype)) = (value.get(0..3), value.get(3)) else {
        return;
    };
    let body = &value[4.min(value.len())..];
    if oui == OUI_8021 {
        match subtype {
            1 if body.len() >= 2 => {
                neighbour.vlan = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            3 if body.len() >= 3 => {
                let name_len = usize::from(body[2]);
                if let Some(name) = body.get(3..3 + name_len) {
                    let name = as_text(name);
                    if !name.is_empty() {
                        neighbour.vlan_name = Some(name);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one TLV: 7-bit type, 9-bit length, then the value.
    fn tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let header = (u16::from(tlv_type) << 9)
            | (u16::try_from(value.len()).expect("test value fits a u16") & 0x01ff);
        let mut out = header.to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }

    fn sample() -> Vec<u8> {
        let mut frame = Vec::new();
        // Chassis id, subtype 4 (MAC).
        frame.extend(tlv(1, &[4, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]));
        // Port id, subtype 5 (interface name) "Gi0/1".
        frame.extend(tlv(2, &[5, b'G', b'i', b'0', b'/', b'1']));
        // TTL 120.
        frame.extend(tlv(3, &[0x00, 0x78]));
        // Port description.
        frame.extend(tlv(4, b"uplink to probe"));
        // System name.
        frame.extend(tlv(5, b"switch-a.example.test"));
        // System description.
        frame.extend(tlv(6, b"Example Switch OS 1.0"));
        // Capabilities: bridge+router enabled (0x14).
        frame.extend(tlv(7, &[0x00, 0x14, 0x00, 0x14]));
        // Management address: IPv4 192.0.2.2, interface numbering + OID.
        frame.extend(tlv(8, &[5, 1, 192, 0, 2, 2, 2, 0, 0, 0, 1, 0]));
        // 802.1 PVID 100.
        frame.extend(tlv(127, &[0x00, 0x80, 0xc2, 1, 0x00, 0x64]));
        // 802.1 VLAN name: VLAN 100 "clients".
        frame.extend(tlv(
            127,
            &[
                0x00, 0x80, 0xc2, 3, 0x00, 0x64, 7, b'c', b'l', b'i', b'e', b'n', b't', b's',
            ],
        ));
        frame.extend(tlv(0, &[])); // end
        frame
    }

    #[test]
    fn every_named_tlv_is_read() {
        let neighbour = parse(&sample()).expect("neighbour");
        assert_eq!(neighbour.chassis_id.as_deref(), Some("00:00:5e:00:53:02"));
        assert_eq!(neighbour.port_id.as_deref(), Some("Gi0/1"));
        assert_eq!(neighbour.ttl, Some(120));
        assert_eq!(neighbour.port_desc.as_deref(), Some("uplink to probe"));
        assert_eq!(
            neighbour.system_name.as_deref(),
            Some("switch-a.example.test")
        );
        assert_eq!(
            neighbour.system_desc.as_deref(),
            Some("Example Switch OS 1.0")
        );
        assert!(neighbour.capabilities.bridge && neighbour.capabilities.router);
        assert_eq!(
            neighbour.mgmt_addrs,
            vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(neighbour.vlan, Some(100));
        assert_eq!(neighbour.vlan_name.as_deref(), Some("clients"));
        assert_eq!(neighbour.source, Some(NeighbourSource::Lldp));
    }

    #[test]
    fn a_truncated_tlv_stops_the_parse_but_keeps_what_was_read() {
        let mut frame = tlv(1, &[4, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);
        // A TLV claiming 20 bytes but with 2 present.
        frame.extend_from_slice(&[5 << 1, 20, 0x01, 0x02]);
        let neighbour = parse(&frame).expect("neighbour");
        assert_eq!(neighbour.chassis_id.as_deref(), Some("00:00:5e:00:53:02"));
        assert!(neighbour.system_name.is_none());
    }

    #[test]
    fn an_empty_or_end_only_frame_is_none() {
        assert!(parse(&[]).is_none());
        assert!(parse(&tlv(0, &[])).is_none());
    }
}
