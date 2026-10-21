//! A small, local parser for the DHCPv4 fields the snoop needs (RFC 2131): the op, the
//! transaction id, the client hardware address, the address offered or acknowledged
//! (`yiaddr`), and options 53 (message type), 12 (host name), 60 (vendor class), 61
//! (client id), 50 (requested address) and 54 (server identifier).
//!
//! This is deliberately minimal. `tenko-dhcp`'s DHCPv4 codec, written in parallel, becomes
//! the full parser once it merges; the snoop then calls it and this module is removed. The
//! snoop needs only these fields, so a bounded local parse keeps WP3.14 free of that
//! dependency.

use std::net::Ipv4Addr;

use tenko_core::MacAddr;

/// The DHCP magic cookie that precedes the options (RFC 2131).
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// BOOTREQUEST, a message from a client.
pub const OP_REQUEST: u8 = 1;
/// BOOTREPLY, a message from a server.
pub const OP_REPLY: u8 = 2;

/// The DHCP message type (option 53) the snoop reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// DISCOVER (1).
    Discover,
    /// OFFER (2).
    Offer,
    /// REQUEST (3).
    Request,
    /// ACK (5).
    Ack,
    /// NAK (6).
    Nak,
    /// Any other type, by its number.
    Other(u8),
}

impl MessageType {
    fn from_byte(value: u8) -> Self {
        match value {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            other => MessageType::Other(other),
        }
    }

    /// The type name for a note and the status.
    pub const fn name(self) -> &'static str {
        match self {
            MessageType::Discover => "DISCOVER",
            MessageType::Offer => "OFFER",
            MessageType::Request => "REQUEST",
            MessageType::Ack => "ACK",
            MessageType::Nak => "NAK",
            MessageType::Other(_) => "other",
        }
    }
}

/// The fields the snoop reads from one DHCPv4 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp {
    /// The op field: [`OP_REQUEST`] from a client, [`OP_REPLY`] from a server.
    pub op: u8,
    /// The transaction id, which ties a DISCOVER/OFFER or REQUEST/ACK pair together.
    pub xid: u32,
    /// The client hardware address (the first six bytes of `chaddr` when `hlen` is 6).
    pub client_mac: Option<MacAddr>,
    /// `yiaddr`: the address the server offered or acknowledged (zero on a client
    /// message).
    pub your_ip: Ipv4Addr,
    /// The message type (option 53).
    pub message_type: Option<MessageType>,
    /// The host name the client sent (option 12).
    pub host_name: Option<String>,
    /// The vendor class identifier (option 60).
    pub vendor_class: Option<String>,
    /// The client identifier (option 61), formatted as a MAC when its type is 1 and it is
    /// seven bytes, else as lowercase hex.
    pub client_id: Option<String>,
    /// The requested address (option 50).
    pub requested_ip: Option<Ipv4Addr>,
    /// The server identifier (option 54): the server that offered or acknowledged.
    pub server_id: Option<Ipv4Addr>,
}

fn text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let trimmed: Vec<u8> = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let text = String::from_utf8_lossy(&trimmed).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

fn client_id(bytes: &[u8]) -> Option<String> {
    if bytes.len() == 7 && bytes[0] == 1 {
        let mac: [u8; 6] = bytes[1..7].try_into().ok()?;
        return Some(MacAddr::new(mac).to_string());
    }
    if bytes.is_empty() {
        return None;
    }
    Some(super::hex(bytes))
}

/// Parses a DHCPv4 message: the fixed BOOTP header, then the options after the magic
/// cookie. Returns `None` when the header is too short or the cookie is missing. Only the
/// fields above are read; other options are skipped by their length.
pub fn parse(bytes: &[u8]) -> Option<Dhcp> {
    if bytes.len() < 240 {
        return None;
    }
    let op = bytes[0];
    let hlen = usize::from(bytes[2]);
    let xid = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
    let your_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?);
    let client_mac = (hlen == 6)
        .then(|| <[u8; 6]>::try_from(&bytes[28..34]).ok().map(MacAddr::new))
        .flatten();
    if bytes[236..240] != MAGIC_COOKIE {
        return None;
    }
    let mut message = Dhcp {
        op,
        xid,
        client_mac,
        your_ip,
        message_type: None,
        host_name: None,
        vendor_class: None,
        client_id: None,
        requested_ip: None,
        server_id: None,
    };
    let mut at = 240;
    while at < bytes.len() {
        let code = bytes[at];
        if code == 255 {
            break; // end option
        }
        if code == 0 {
            at += 1; // pad
            continue;
        }
        let Some(&len) = bytes.get(at + 1) else { break };
        let len = usize::from(len);
        let Some(value) = bytes.get(at + 2..at + 2 + len) else {
            break;
        };
        match code {
            53 if !value.is_empty() => {
                message.message_type = Some(MessageType::from_byte(value[0]));
            }
            12 => message.host_name = text(value),
            60 => message.vendor_class = text(value),
            61 => message.client_id = client_id(value),
            50 if value.len() == 4 => {
                message.requested_ip = Some(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?));
            }
            54 if value.len() == 4 => {
                message.server_id = Some(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?));
            }
            _ => {}
        }
        at += 2 + len;
    }
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal DHCP message: a 236-byte header with `op`, `hlen` 6, `xid`,
    /// `yiaddr` and `chaddr`, the cookie, then the given options, ended by 255.
    fn message(op: u8, xid: u32, yiaddr: Ipv4Addr, chaddr: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; 240];
        m[0] = op;
        m[1] = 1; // htype Ethernet
        m[2] = 6; // hlen
        m[4..8].copy_from_slice(&xid.to_be_bytes());
        m[16..20].copy_from_slice(&yiaddr.octets());
        m[28..34].copy_from_slice(&chaddr);
        m[236..240].copy_from_slice(&MAGIC_COOKIE);
        m.extend_from_slice(options);
        m.push(255);
        m
    }

    #[test]
    fn a_discover_from_a_client_is_read() {
        let chaddr = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a];
        let options = [
            53, 1, 1, // DISCOVER
            12, 7, b'l', b'a', b'p', b't', b'o', b'p', b'1', // host name
            60, 8, b'd', b'h', b'c', b'p', b'c', b'd', b'-', b'9', // vendor class
            61, 7, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a, // client id as MAC
        ];
        let dhcp = parse(&message(
            OP_REQUEST,
            0xdead_beef,
            Ipv4Addr::UNSPECIFIED,
            chaddr,
            &options,
        ))
        .expect("dhcp");
        assert_eq!(dhcp.message_type, Some(MessageType::Discover));
        assert_eq!(dhcp.client_mac, Some(MacAddr::new(chaddr)));
        assert_eq!(dhcp.host_name.as_deref(), Some("laptop1"));
        assert_eq!(dhcp.vendor_class.as_deref(), Some("dhcpcd-9"));
        assert_eq!(dhcp.client_id.as_deref(), Some("00:00:5e:00:53:0a"));
        assert_eq!(dhcp.your_ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn an_ack_from_a_server_carries_yiaddr_and_the_server_id() {
        let chaddr = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a];
        let options = [
            53, 1, 5, // ACK
            54, 4, 192, 0, 2, 1, // server identifier
        ];
        let dhcp = parse(&message(
            OP_REPLY,
            0xdead_beef,
            Ipv4Addr::new(192, 0, 2, 50),
            chaddr,
            &options,
        ))
        .expect("dhcp");
        assert_eq!(dhcp.message_type, Some(MessageType::Ack));
        assert_eq!(dhcp.your_ip, Ipv4Addr::new(192, 0, 2, 50));
        assert_eq!(dhcp.server_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn a_message_without_the_cookie_or_too_short_is_rejected() {
        assert!(parse(&[0u8; 100]).is_none());
        let mut no_cookie = vec![0u8; 240];
        no_cookie[0] = OP_REQUEST;
        assert!(parse(&no_cookie).is_none());
    }
}
