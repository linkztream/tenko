//! TCP segments for the SYN scan and the fingerprint (RFC 9293): parsing the flags, the
//! window and the options in the order they appear, and building the SYN the scan sends
//! and the RST it sends to close an open port. Checksums are computed over the IPv4
//! pseudo-header so the segments are accepted on the wire.

use std::net::Ipv4Addr;

/// TCP flag bits.
pub const FLAG_FIN: u8 = 0x01;
/// The SYN flag.
pub const FLAG_SYN: u8 = 0x02;
/// The RST flag.
pub const FLAG_RST: u8 = 0x04;
/// The ACK flag.
pub const FLAG_ACK: u8 = 0x10;

/// A TCP option as it appears in the header, by kind, for the fingerprint's option order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption {
    /// End of option list (kind 0).
    End,
    /// No operation, a padding byte (kind 1).
    Nop,
    /// Maximum segment size (kind 2), with its value.
    Mss(u16),
    /// Window scale (kind 3), with its shift.
    WindowScale(u8),
    /// SACK permitted (kind 4).
    SackPermitted,
    /// Timestamps (kind 8).
    Timestamps,
    /// Any other option, by its kind.
    Other(u8),
}

impl TcpOption {
    /// The single letter the fingerprint uses for the option order (`M`, `S`, `T`, `W`,
    /// `N`), or `.` for anything else. This is the p0f-style option-layout string.
    pub const fn code(self) -> char {
        match self {
            TcpOption::Mss(_) => 'M',
            TcpOption::SackPermitted => 'S',
            TcpOption::Timestamps => 'T',
            TcpOption::WindowScale(_) => 'W',
            TcpOption::Nop => 'N',
            TcpOption::End | TcpOption::Other(_) => '.',
        }
    }
}

/// A parsed TCP segment (the fields the raw methods read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    /// The source port.
    pub source_port: u16,
    /// The destination port.
    pub destination_port: u16,
    /// The sequence number.
    pub sequence: u32,
    /// The acknowledgement number.
    pub acknowledgement: u32,
    /// The flag byte.
    pub flags: u8,
    /// The advertised window size.
    pub window: u16,
    /// The options in the order they appear.
    pub options: Vec<TcpOption>,
}

impl Tcp {
    /// Whether exactly the SYN and ACK flags are set (an open-port answer).
    pub fn is_syn_ack(&self) -> bool {
        self.flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK)
    }

    /// Whether the RST flag is set (a closed-port answer).
    pub fn is_rst(&self) -> bool {
        self.flags & FLAG_RST != 0
    }

    /// The maximum segment size the segment advertised, when any.
    pub fn mss(&self) -> Option<u16> {
        self.options.iter().find_map(|option| match option {
            TcpOption::Mss(value) => Some(*value),
            _ => None,
        })
    }

    /// The option-layout string (`MSTNW...`) in order, for the fingerprint.
    pub fn option_layout(&self) -> String {
        self.options
            .iter()
            .take_while(|option| !matches!(option, TcpOption::End))
            .map(|option| option.code())
            .collect()
    }
}

fn parse_options(bytes: &[u8]) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let kind = bytes[at];
        match kind {
            0 => {
                options.push(TcpOption::End);
                break;
            }
            1 => {
                options.push(TcpOption::Nop);
                at += 1;
            }
            _ => {
                let Some(&len) = bytes.get(at + 1) else { break };
                let len = usize::from(len);
                if len < 2 || at + len > bytes.len() {
                    break;
                }
                let body = &bytes[at + 2..at + len];
                options.push(match kind {
                    2 if body.len() == 2 => TcpOption::Mss(u16::from_be_bytes([body[0], body[1]])),
                    3 if body.len() == 1 => TcpOption::WindowScale(body[0]),
                    4 => TcpOption::SackPermitted,
                    8 => TcpOption::Timestamps,
                    other => TcpOption::Other(other),
                });
                at += len;
            }
        }
    }
    options
}

/// Parses a TCP segment (the payload of an IPv4 packet with protocol 6).
pub fn parse(bytes: &[u8]) -> Option<Tcp> {
    let source_port = u16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?);
    let destination_port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    let sequence = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
    let acknowledgement = u32::from_be_bytes(bytes.get(8..12)?.try_into().ok()?);
    let data_offset = usize::from(bytes.get(12)? >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    let flags = *bytes.get(13)?;
    let window = u16::from_be_bytes(bytes.get(14..16)?.try_into().ok()?);
    let options = bytes
        .get(20..data_offset)
        .map(parse_options)
        .unwrap_or_default();
    Some(Tcp {
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        window,
        options,
    })
}

/// One's-complement sum used by the IP and TCP checksums.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;
    for part in parts {
        let mut bytes = part.iter();
        if let Some(high) = carry_byte.take() {
            if let Some(&low) = bytes.next() {
                sum += u32::from(u16::from_be_bytes([high, low]));
            } else {
                sum += u32::from(u16::from_be_bytes([high, 0]));
            }
        }
        let remaining: Vec<u8> = bytes.copied().collect();
        let (pairs, rest) = remaining.as_chunks::<2>();
        for pair in pairs {
            sum += u32::from(u16::from_be_bytes(*pair));
        }
        if let [last] = rest {
            carry_byte = Some(*last);
        }
    }
    if let Some(high) = carry_byte {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("the folded sum fits sixteen bits")
}

fn ipv4_header(source: Ipv4Addr, destination: Ipv4Addr, payload_len: usize) -> Vec<u8> {
    let total = u16::try_from(20 + payload_len).expect("an IPv4 packet is under 65,536 bytes");
    let [total_high, total_low] = total.to_be_bytes();
    let mut header = vec![
        0x45,
        0x00,
        total_high,
        total_low,
        0x00,
        0x00,
        0x40,
        0x00, // DF
        0x40, // TTL 64
        super::ipv4::PROTO_TCP,
        0x00,
        0x00, // checksum, filled below
    ];
    header.extend_from_slice(&source.octets());
    header.extend_from_slice(&destination.octets());
    let sum = checksum(&[&header]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header
}

/// The fields of a TCP segment the builders set.
struct Segment<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    window: u16,
    options: &'a [u8],
}

fn tcp_segment(segment: &Segment<'_>) -> Vec<u8> {
    let Segment {
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        window,
        options,
    } = *segment;
    let header_len = 20 + options.len();
    debug_assert!(
        header_len.is_multiple_of(4),
        "options must pad the header to 4 bytes"
    );
    let mut tcp = Vec::with_capacity(header_len);
    tcp.extend_from_slice(&source_port.to_be_bytes());
    tcp.extend_from_slice(&destination_port.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&acknowledgement.to_be_bytes());
    tcp.push(u8::try_from(header_len / 4).expect("a TCP header is at most 60 bytes") << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&[0x00, 0x00]); // checksum, filled below
    tcp.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    tcp.extend_from_slice(options);
    let pseudo = {
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&source.octets());
        p.extend_from_slice(&destination.octets());
        p.push(0);
        p.push(super::ipv4::PROTO_TCP);
        let tcp_len = u16::try_from(tcp.len()).expect("a TCP segment is under 65,536 bytes");
        p.extend_from_slice(&tcp_len.to_be_bytes());
        p
    };
    let sum = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    tcp
}

/// The MSS and SACK-permitted options a SYN carries, padded to a 4-byte boundary with a
/// NOP. The layout (`MSNS` once padded) is a common one, so the SYN does not stand out.
fn syn_options() -> Vec<u8> {
    vec![
        0x02, 0x04, 0x05, 0xb4, // MSS 1460
        0x04, 0x02, // SACK permitted
        0x01, 0x01, // two NOPs to pad to 8 bytes
    ]
}

/// Builds an IPv4 TCP SYN to `destination:destination_port` from `source:source_port`,
/// with sequence `sequence`. The returned bytes are the IPv4 packet (header and segment);
/// the method prepends the Ethernet header.
pub fn syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let options = syn_options();
    let segment = tcp_segment(&Segment {
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        acknowledgement: 0,
        flags: FLAG_SYN,
        window: 64240,
        options: &options,
    });
    let mut packet = ipv4_header(source, destination, segment.len());
    packet.extend_from_slice(&segment);
    packet
}

/// Builds an IPv4 TCP RST that closes the connection a SYN-ACK opened: it acknowledges the
/// SYN-ACK's sequence so the peer drops the half-open state.
pub fn rst_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
) -> Vec<u8> {
    let segment = tcp_segment(&Segment {
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags: FLAG_RST | FLAG_ACK,
        window: 0,
        options: &[],
    });
    let mut packet = ipv4_header(source, destination, segment.len());
    packet.extend_from_slice(&segment);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
    const B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);

    #[test]
    fn checksum_of_a_segment_verifies_as_zero() {
        // A correct checksum makes the whole sum (including the checksum field) zero.
        let packet = syn_packet(A, B, 40000, 22, 0x1234_5678);
        let ip = super::super::ipv4::parse(&packet).expect("ipv4");
        let pseudo = {
            let mut p = Vec::new();
            p.extend_from_slice(&A.octets());
            p.extend_from_slice(&B.octets());
            p.push(0);
            p.push(PROTO_TCP_FOR_TEST);
            let len = u16::try_from(ip.payload.len()).expect("test payload fits a u16");
            p.extend_from_slice(&len.to_be_bytes());
            p
        };
        assert_eq!(checksum(&[&pseudo, ip.payload]), 0);
    }

    const PROTO_TCP_FOR_TEST: u8 = 6;

    #[test]
    fn a_built_syn_parses_back_with_its_options() {
        let packet = syn_packet(A, B, 40000, 443, 0x0102_0304);
        let ip = super::super::ipv4::parse(&packet).expect("ipv4");
        let tcp = parse(ip.payload).expect("tcp");
        assert_eq!(tcp.flags, FLAG_SYN);
        assert_eq!(tcp.destination_port, 443);
        assert_eq!(tcp.source_port, 40000);
        assert_eq!(tcp.mss(), Some(1460));
        assert_eq!(tcp.option_layout(), "MSNN");
    }

    #[test]
    fn syn_ack_and_rst_are_recognised() {
        let syn_ack = Tcp {
            source_port: 22,
            destination_port: 40000,
            sequence: 1,
            acknowledgement: 2,
            flags: FLAG_SYN | FLAG_ACK,
            window: 64240,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
        };
        assert!(syn_ack.is_syn_ack());
        assert!(!syn_ack.is_rst());
        assert_eq!(syn_ack.option_layout(), "MNW");
        let rst = Tcp {
            flags: FLAG_RST | FLAG_ACK,
            ..syn_ack.clone()
        };
        assert!(rst.is_rst());
        assert!(!rst.is_syn_ack());
    }

    #[test]
    fn options_parse_in_order_and_stop_at_end() {
        // MSS, SACK permitted, timestamps, NOP, window scale, then EOL and padding.
        let header = [
            0x00, 0x16, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xa0, 0x12,
            0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, // 20-byte fixed header, data offset 10
            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];
        let tcp = parse(&header).expect("tcp");
        assert_eq!(tcp.option_layout(), "MSTNW");
        assert!(tcp.is_syn_ack());
    }
}
