//! Cisco Discovery Protocol version 2 TLV parsing: device id, addresses, port id,
//! capabilities, software version, platform and the native VLAN. The frame is the payload
//! after the LLC/SNAP header (Cisco OUI `00:00:0c`, protocol `0x2000`): a 1-byte version,
//! a 1-byte TTL, a 2-byte checksum, then the TLVs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{Neighbour, NeighbourCapabilities, NeighbourSource};

const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_ADDRESSES: u16 = 0x0002;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_SOFTWARE: u16 = 0x0005;
const TLV_PLATFORM: u16 = 0x0006;
const TLV_NATIVE_VLAN: u16 = 0x000a;

fn text(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value)
        .trim_end_matches('\0')
        .trim()
        .to_owned();
    (!text.is_empty()).then_some(text)
}

fn capabilities(bits: u32) -> NeighbourCapabilities {
    NeighbourCapabilities {
        router: bits & 0x01 != 0,
        bridge: bits & 0x02 != 0 || bits & 0x08 != 0,
        wlan: false,
        telephone: bits & 0x80 != 0,
        station: bits & 0x10 != 0,
    }
}

/// Reads the addresses TLV: a 4-byte count, then entries of protocol type, protocol,
/// address length and address. IPv4 (4 bytes) and IPv6 (16 bytes) addresses are kept.
fn read_addresses(value: &[u8], neighbour: &mut Neighbour) {
    if value.len() < 4 {
        return;
    }
    let count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let mut at = 4;
    for _ in 0..count.min(64) {
        let (Some(&_ptype), Some(&plen)) = (value.get(at), value.get(at + 1)) else {
            break;
        };
        let plen = usize::from(plen);
        at += 2 + plen;
        let Some(addr_len) = value
            .get(at..at + 2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        else {
            break;
        };
        at += 2;
        let Some(addr) = value.get(at..at + addr_len) else {
            break;
        };
        at += addr_len;
        let ip = match addr.len() {
            4 => Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(addr).unwrap(),
            ))),
            16 => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(addr).unwrap(),
            ))),
            _ => None,
        };
        if let Some(ip) = ip
            && !neighbour.mgmt_addrs.contains(&ip)
        {
            neighbour.mgmt_addrs.push(ip);
        }
    }
}

/// Parses a CDP frame into a [`Neighbour`]. The device id serves as both the chassis id
/// and the system name; the platform and software version form the system description.
pub fn parse(payload: &[u8]) -> Option<Neighbour> {
    if payload.len() < 4 {
        return None;
    }
    let mut neighbour = Neighbour {
        source: Some(NeighbourSource::Cdp),
        ..Neighbour::default()
    };
    let mut platform = None;
    let mut software = None;
    let mut at = 4; // version, ttl, checksum
    let mut saw_tlv = false;
    while at + 4 <= payload.len() {
        let tlv_type = u16::from_be_bytes([payload[at], payload[at + 1]]);
        let tlv_len = usize::from(u16::from_be_bytes([payload[at + 2], payload[at + 3]]));
        if tlv_len < 4 || at + tlv_len > payload.len() {
            break;
        }
        let value = &payload[at + 4..at + tlv_len];
        at += tlv_len;
        saw_tlv = true;
        match tlv_type {
            TLV_DEVICE_ID => {
                let id = text(value);
                neighbour.chassis_id.clone_from(&id);
                neighbour.system_name = id;
            }
            TLV_ADDRESSES => read_addresses(value, &mut neighbour),
            TLV_PORT_ID => neighbour.port_id = text(value),
            TLV_CAPABILITIES if value.len() >= 4 => {
                let bits = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                neighbour.capabilities = capabilities(bits);
            }
            TLV_SOFTWARE => software = text(value),
            TLV_PLATFORM => platform = text(value),
            TLV_NATIVE_VLAN if value.len() >= 2 => {
                neighbour.vlan = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            _ => {}
        }
    }
    neighbour.system_desc = match (platform, software) {
        (Some(p), Some(s)) => Some(format!("{p}; {}", s.lines().next().unwrap_or(&s))),
        (Some(p), None) => Some(p),
        (None, Some(s)) => Some(s.lines().next().unwrap_or(&s).to_owned()),
        (None, None) => None,
    };
    if saw_tlv && !neighbour.is_empty() {
        Some(neighbour)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let len = u16::try_from(value.len() + 4).expect("test TLV length fits a u16");
        let mut out = Vec::new();
        out.extend_from_slice(&tlv_type.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn sample() -> Vec<u8> {
        let mut frame = vec![0x02, 0xb4, 0x00, 0x00]; // version 2, TTL 180, checksum
        frame.extend(tlv(TLV_DEVICE_ID, b"switch-b.example.test"));
        // Addresses: one IPv4 192.0.2.3.
        frame.extend(tlv(
            TLV_ADDRESSES,
            &[0, 0, 0, 1, 1, 1, 0xcc, 0, 4, 192, 0, 2, 3],
        ));
        frame.extend(tlv(TLV_PORT_ID, b"GigabitEthernet0/2"));
        // Capabilities: switch (0x08).
        frame.extend(tlv(TLV_CAPABILITIES, &[0x00, 0x00, 0x00, 0x08]));
        frame.extend(tlv(TLV_SOFTWARE, b"Example IOS\nbuild 9"));
        frame.extend(tlv(TLV_PLATFORM, b"ExampleSwitch 2960"));
        frame.extend(tlv(TLV_NATIVE_VLAN, &[0x00, 0x0a]));
        frame
    }

    #[test]
    fn every_cdp_tlv_is_read() {
        let neighbour = parse(&sample()).expect("neighbour");
        assert_eq!(
            neighbour.system_name.as_deref(),
            Some("switch-b.example.test")
        );
        assert_eq!(
            neighbour.chassis_id.as_deref(),
            Some("switch-b.example.test")
        );
        assert_eq!(neighbour.port_id.as_deref(), Some("GigabitEthernet0/2"));
        assert!(neighbour.capabilities.bridge);
        assert_eq!(
            neighbour.mgmt_addrs,
            vec!["192.0.2.3".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(neighbour.vlan, Some(10));
        assert_eq!(
            neighbour.system_desc.as_deref(),
            Some("ExampleSwitch 2960; Example IOS")
        );
        assert_eq!(neighbour.source, Some(NeighbourSource::Cdp));
    }

    #[test]
    fn a_short_or_empty_frame_is_none() {
        assert!(parse(&[0x02, 0xb4]).is_none());
        assert!(parse(&[0x02, 0xb4, 0x00, 0x00]).is_none());
    }
}
