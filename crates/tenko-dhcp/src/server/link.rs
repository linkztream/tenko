//! The link-layer reply of direct mode (plan section 2.5, WP7.5): an answer to a client
//! that has no address yet and did not ask for a broadcast goes to its hardware address
//! with `yiaddr` as the IP destination (RFC 2131 section 4.1).
//!
//! The datagram is framed here ([`frame`]: Ethernet, IPv4 and UDP headers around the
//! DHCP message; the UDP checksum is zero, which IPv4 allows) and sent through an
//! `AF_PACKET` socket of the listener's interface. The socket comes from `pnet_datalink`,
//! the safe link-layer API the scanner's raw methods use (WP3.14): Linux only, and only
//! with `CAP_NET_RAW` (the drop-in `deploy/systemd/dhcp-direct.conf`). Where the socket
//! cannot be opened (no capability, no interface name, another platform) the listener has
//! no [`LinkSender`] and the reply goes out as a broadcast, which every client accepts.
//! The socket is opened without promiscuous mode; the role never reads from it.

use std::net::Ipv4Addr;

/// Octets of the Ethernet, IPv4 and UDP headers.
pub const HEADERS: usize = 14 + 20 + 8;

/// The IPv4 header checksum (RFC 791) of `header`.
fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The fold leaves at most 16 bits.
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// The addresses of one link-layer reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framing {
    /// The interface's hardware address.
    pub source_mac: [u8; 6],
    /// The listener's address.
    pub source: Ipv4Addr,
    /// The server port.
    pub source_port: u16,
    /// The client's hardware address (`chaddr`).
    pub dest_mac: [u8; 6],
    /// `yiaddr`.
    pub dest: Ipv4Addr,
    /// The client port.
    pub dest_port: u16,
}

/// Writes the frame of `payload` into `out` and returns its length, or `None` when `out`
/// is too short or the payload too long for one IPv4 datagram.
pub fn frame(framing: &Framing, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = HEADERS.checked_add(payload.len())?;
    let ip_len = u16::try_from(20 + 8 + payload.len()).ok()?;
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let out = out.get_mut(..total)?;
    out[0..6].copy_from_slice(&framing.dest_mac);
    out[6..12].copy_from_slice(&framing.source_mac);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut out[14..34];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&[0, 0]);
    // Don't fragment.
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&framing.source.octets());
    ip[16..20].copy_from_slice(&framing.dest.octets());
    let sum = checksum(ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let udp = &mut out[34..42];
    udp[0..2].copy_from_slice(&framing.source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&framing.dest_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&[0, 0]);
    out[42..].copy_from_slice(payload);
    Some(total)
}

#[cfg(target_os = "linux")]
mod sender {
    use std::{
        io,
        net::Ipv4Addr,
        sync::{Mutex, PoisonError},
    };

    use pnet_datalink::{Channel, Config, DataLinkSender};

    use super::{Framing, HEADERS, frame};

    /// An `AF_PACKET` socket of one interface, for the replies of a direct listener.
    pub struct LinkSender {
        interface: String,
        mac: [u8; 6],
        tx: Mutex<Box<dyn DataLinkSender>>,
    }

    impl std::fmt::Debug for LinkSender {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinkSender")
                .field("interface", &self.interface)
                .finish_non_exhaustive()
        }
    }

    impl LinkSender {
        /// Opens the socket of `interface`.
        ///
        /// # Errors
        ///
        /// No such interface, an interface without a hardware address, or a socket the
        /// process may not open (`CAP_NET_RAW`).
        pub fn open(interface: &str) -> io::Result<Self> {
            let native = pnet_datalink::interfaces()
                .into_iter()
                .find(|candidate| candidate.name == interface)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("no interface {interface}"))
                })?;
            let mac = native.mac.map(|mac| mac.octets()).ok_or_else(|| {
                io::Error::other(format!("interface {interface} has no hardware address"))
            })?;
            let config = Config {
                promiscuous: false,
                read_buffer_size: 64,
                write_buffer_size: 2048,
                ..Config::default()
            };
            match pnet_datalink::channel(&native, config)? {
                Channel::Ethernet(tx, _rx) => Ok(Self {
                    interface: interface.to_owned(),
                    mac,
                    tx: Mutex::new(tx),
                }),
                _ => Err(io::Error::other("the link-layer channel is not Ethernet")),
            }
        }

        /// The interface's name.
        pub fn interface(&self) -> &str {
            &self.interface
        }

        /// Sends `payload` from `source` to the client.
        ///
        /// # Errors
        ///
        /// The socket's error, or a payload too long for one frame.
        pub fn send(
            &self,
            source: (Ipv4Addr, u16),
            dest: ([u8; 6], Ipv4Addr, u16),
            payload: &[u8],
        ) -> io::Result<()> {
            let framing = Framing {
                source_mac: self.mac,
                source: source.0,
                source_port: source.1,
                dest_mac: dest.0,
                dest: dest.1,
                dest_port: dest.2,
            };
            let len = HEADERS + payload.len();
            let mut tx = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
            let mut written = None;
            let sent = tx.build_and_send(1, len, &mut |buf| {
                written = frame(&framing, payload, buf);
            });
            match (sent, written) {
                (Some(result), Some(_)) => result,
                _ => Err(io::Error::other("the reply does not fit one frame")),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sender {
    use std::{io, net::Ipv4Addr};

    /// No link-layer socket off Linux: direct replies go out as broadcasts.
    #[derive(Debug)]
    pub struct LinkSender(());

    impl LinkSender {
        /// Always unsupported.
        ///
        /// # Errors
        ///
        /// Always: link-layer replies are a Linux feature.
        pub fn open(_interface: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "link-layer replies need AF_PACKET (Linux)",
            ))
        }

        /// The interface's name (none: no sender exists).
        pub fn interface(&self) -> &'static str {
            ""
        }

        /// Never called: no sender exists.
        ///
        /// # Errors
        ///
        /// Always.
        pub fn send(
            &self,
            _source: (Ipv4Addr, u16),
            _dest: ([u8; 6], Ipv4Addr, u16),
            _payload: &[u8],
        ) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

pub use sender::LinkSender;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_carry_valid_ipv4_and_udp_headers() {
        let framing = Framing {
            source_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x10],
            source: Ipv4Addr::new(192, 0, 2, 1),
            source_port: 67,
            dest_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
            dest: Ipv4Addr::new(192, 0, 2, 100),
            dest_port: 68,
        };
        let payload = [7u8; 300];
        let mut out = [0u8; 1514];
        let len = frame(&framing, &payload, &mut out).expect("fits");
        assert_eq!(len, HEADERS + 300);
        assert_eq!(&out[0..6], &framing.dest_mac);
        assert_eq!(&out[6..12], &framing.source_mac);
        assert_eq!(&out[12..14], &[0x08, 0x00]);
        // A header with its checksum sums to 0xffff, so the checksum over it is zero.
        assert_eq!(checksum(&out[14..34]), 0);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 328);
        assert_eq!(&out[26..30], &[192, 0, 2, 1]);
        assert_eq!(&out[30..34], &[192, 0, 2, 100]);
        assert_eq!(u16::from_be_bytes([out[34], out[35]]), 67);
        assert_eq!(u16::from_be_bytes([out[36], out[37]]), 68);
        assert_eq!(u16::from_be_bytes([out[38], out[39]]), 308);
        assert_eq!(&out[42..len], &payload[..]);
        assert_eq!(frame(&framing, &payload, &mut [0u8; 100]), None);
    }

    #[test]
    fn the_checksum_matches_a_known_header() {
        // 192.0.2.1 to 192.0.2.199, checksum field zeroed; the sum worked out by hand
        // (RFC 1071): 0x24a4c folds to 0x4a4e, whose complement is 0xb5b1.
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0x00,
            0x02, 0x01, 0xc0, 0x00, 0x02, 0xc7,
        ];
        assert_eq!(checksum(&header), 0xb5b1);
    }
}
