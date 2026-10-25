//! Router advertisements (RFC 4861 section 4.2) as the probe hears them, for the check of
//! DHCP-10: the M (managed address configuration) and O (other configuration) flags a
//! router sends on a link, against the DHCPv6 service of that link (WP9.2).
//!
//! - **The view.** [`RouterAdvert::parse`] reads an `ICMPv6` message of type 134 without
//!   allocating: the hop limit, the flags, the router lifetime, the reachable and retransmit
//!   timers, and the options as [`NdOption`]s (the source link-layer address, the MTU, the
//!   prefix information of RFC 4861 section 4.6.2, the recursive DNS servers of RFC 8106 and
//!   any other option by its type). A message that is not an advertisement, is shorter than
//!   its fixed part, has a code other than 0 or an option of length zero or past the end is
//!   refused, as section 6.1.2 says a host silently discards it.
//! - **The solicitation.** [`router_solicitation`] writes a Router Solicitation (RFC 4861
//!   section 4.1) with the sender's link-layer address, so that a router answers at once
//!   instead of at its next periodic advertisement.
//! - **The socket.** [`RaSocket`] (Linux) is a raw `ICMPv6` socket: the kernel hands it every
//!   `ICMPv6` message the host receives, with the source's interface as the scope of its
//!   link-local address, and computes the checksum of what it sends. Opening it needs
//!   `CAP_NET_RAW`, which the drop-in `deploy/systemd/probe.conf` grants; without it
//!   [`RaSocket::open`] fails with `scan.unavailable` and nothing else is tried. An
//!   unprivileged `ICMPv6` datagram socket receives echo replies only, so it cannot replace
//!   it. On other systems the socket is not available.
//!
//! DHCPv6 never sets a default route: the route comes from the advertisements' router
//! lifetime, and the M and O flags only tell hosts whether to ask DHCPv6 for addresses (M)
//! or for other configuration (O).

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

/// The `ICMPv6` type of a Router Solicitation.
pub const ROUTER_SOLICITATION: u8 = 133;
/// The `ICMPv6` type of a Router Advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// The All-Routers multicast address (RFC 4291 section 2.7.1).
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// The hop limit of every Neighbor Discovery message (RFC 4861 section 4.1).
pub const ND_HOP_LIMIT: u32 = 255;

/// The length of an advertisement's fixed part: type, code, checksum, hop limit, flags,
/// router lifetime, reachable time and retransmit timer.
const FIXED: usize = 16;

/// The flag bits of the octet after the hop limit.
const FLAG_MANAGED: u8 = 0x80;
const FLAG_OTHER: u8 = 0x40;

/// The option types read by name (RFC 4861 section 4.6, RFC 8106 section 5.1).
const OPT_SOURCE_LINK_LAYER: u8 = 1;
const OPT_PREFIX_INFORMATION: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;

/// Why an `ICMPv6` message is not a valid router advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaError {
    /// Shorter than the fixed part.
    Short,
    /// Not of type 134.
    NotAdvert(u8),
    /// A code other than 0.
    Code(u8),
    /// An option of length zero, or one that runs past the end.
    BadOption,
}

impl std::fmt::Display for RaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => f.write_str("shorter than a router advertisement"),
            Self::NotAdvert(kind) => write!(f, "ICMPv6 type {kind}, not a router advertisement"),
            Self::Code(code) => write!(f, "code {code}, not 0"),
            Self::BadOption => f.write_str("an option of length zero or past the end"),
        }
    }
}

impl std::error::Error for RaError {}

/// A Router Advertisement, read from the `ICMPv6` message (without the IPv6 header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterAdvert<'a> {
    /// The hop limit hosts should use, 0 for unspecified.
    pub cur_hop_limit: u8,
    /// The flags octet: M (0x80), O (0x40), and the others of later RFCs.
    pub flags: u8,
    /// How long the router is a default router, in seconds; 0: not a default router.
    pub router_lifetime: u16,
    /// The reachable time in milliseconds, 0 for unspecified.
    pub reachable_ms: u32,
    /// The retransmit timer in milliseconds, 0 for unspecified.
    pub retrans_ms: u32,
    options: &'a [u8],
}

/// One prefix information option (RFC 4861 section 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInfo {
    /// The prefix, without host bits.
    pub prefix: Ipv6Net,
    /// The L flag: the prefix is on the link.
    pub on_link: bool,
    /// The A flag: hosts may form addresses in it (SLAAC, RFC 4862).
    pub autonomous: bool,
    /// The valid lifetime in seconds.
    pub valid: u32,
    /// The preferred lifetime in seconds.
    pub preferred: u32,
}

/// One Neighbor Discovery option of an advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdOption<'a> {
    /// The router's link-layer address.
    SourceLinkLayer(&'a [u8]),
    /// The link's MTU.
    Mtu(u32),
    /// A prefix of the link.
    Prefix(PrefixInfo),
    /// Recursive DNS servers (RFC 8106): their lifetime and the addresses, 16 octets each.
    Rdnss {
        /// The lifetime in seconds.
        lifetime: u32,
        /// The addresses.
        addrs: &'a [u8],
    },
    /// Any other option, or one of the types above too short for its fields.
    Other {
        /// The option type.
        kind: u8,
        /// The option's octets after the type and length.
        data: &'a [u8],
    },
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

impl<'a> RouterAdvert<'a> {
    /// The advertisement in the `ICMPv6` message `icmp`.
    ///
    /// # Errors
    ///
    /// [`RaError`] for a message that is not a valid advertisement.
    pub fn parse(icmp: &'a [u8]) -> Result<Self, RaError> {
        if icmp.len() < FIXED {
            return Err(RaError::Short);
        }
        if icmp[0] != ROUTER_ADVERTISEMENT {
            return Err(RaError::NotAdvert(icmp[0]));
        }
        if icmp[1] != 0 {
            return Err(RaError::Code(icmp[1]));
        }
        let options = &icmp[FIXED..];
        let mut rest = options;
        while !rest.is_empty() {
            if rest.len() < 2 || rest[1] == 0 {
                return Err(RaError::BadOption);
            }
            let len = usize::from(rest[1]) * 8;
            if len > rest.len() {
                return Err(RaError::BadOption);
            }
            rest = &rest[len..];
        }
        Ok(Self {
            cur_hop_limit: icmp[4],
            flags: icmp[5],
            router_lifetime: u16_at(icmp, 6),
            reachable_ms: u32_at(icmp, 8),
            retrans_ms: u32_at(icmp, 12),
            options,
        })
    }

    /// The M flag: addresses are available from DHCPv6.
    pub fn managed(&self) -> bool {
        self.flags & FLAG_MANAGED != 0
    }

    /// The O flag: other configuration is available from DHCPv6.
    pub fn other(&self) -> bool {
        self.flags & FLAG_OTHER != 0
    }

    /// The options in order.
    pub fn options(&self) -> impl Iterator<Item = NdOption<'a>> + 'a {
        let mut rest = self.options;
        std::iter::from_fn(move || {
            // `parse` checked every length, so the walk cannot fail here.
            if rest.len() < 2 || rest[1] == 0 {
                return None;
            }
            let len = (usize::from(rest[1]) * 8).min(rest.len());
            let (option, tail) = rest.split_at(len);
            rest = tail;
            Some(NdOption::read(option[0], &option[2..]))
        })
    }

    /// The prefix information options.
    pub fn prefixes(&self) -> impl Iterator<Item = PrefixInfo> + 'a {
        self.options().filter_map(|option| match option {
            NdOption::Prefix(info) => Some(info),
            _ => None,
        })
    }

    /// The router's link-layer address, when it sent one.
    pub fn source_link_layer(&self) -> Option<&'a [u8]> {
        self.options().find_map(|option| match option {
            NdOption::SourceLinkLayer(address) => Some(address),
            _ => None,
        })
    }
}

impl<'a> NdOption<'a> {
    fn read(kind: u8, data: &'a [u8]) -> Self {
        match kind {
            OPT_SOURCE_LINK_LAYER => Self::SourceLinkLayer(data),
            OPT_MTU if data.len() >= 6 => Self::Mtu(u32_at(data, 2)),
            OPT_PREFIX_INFORMATION if data.len() >= 30 => {
                let len = data[0].min(128);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[14..30]);
                let prefix = Ipv6Net::new(Ipv6Addr::from(octets), len)
                    .map(|net| net.trunc())
                    .unwrap_or_default();
                Self::Prefix(PrefixInfo {
                    prefix,
                    on_link: data[1] & 0x80 != 0,
                    autonomous: data[1] & 0x40 != 0,
                    valid: u32_at(data, 2),
                    preferred: u32_at(data, 6),
                })
            }
            OPT_RDNSS if data.len() >= 6 => {
                let addrs = &data[6..];
                Self::Rdnss {
                    lifetime: u32_at(data, 2),
                    addrs: &addrs[..addrs.len() - addrs.len() % 16],
                }
            }
            _ => Self::Other { kind, data },
        }
    }
}

/// Writes a Router Solicitation into `out` and returns its length: the fixed part with a
/// checksum of zero (the kernel fills it on a raw `ICMPv6` socket) and, when the sender's
/// Ethernet address is known, the source link-layer address option (RFC 4861 section 4.1).
pub fn router_solicitation(mac: Option<[u8; 6]>, out: &mut [u8; 16]) -> usize {
    *out = [0; 16];
    out[0] = ROUTER_SOLICITATION;
    match mac {
        Some(mac) => {
            out[8] = OPT_SOURCE_LINK_LAYER;
            out[9] = 1;
            out[10..16].copy_from_slice(&mac);
            16
        }
        None => 8,
    }
}

/// A link the probe can hear advertisements on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaLink {
    /// The interface index, the scope of its link-local addresses.
    pub index: u32,
    /// The interface name.
    pub name: String,
    /// Its Ethernet address, when it has one.
    pub mac: Option<[u8; 6]>,
    /// Its IPv6 networks (addresses with their prefix lengths), link-local ones left out.
    pub networks: Vec<Ipv6Net>,
}

/// One advertisement as the socket received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    /// The interface it came in on.
    pub interface: u32,
    /// The router's link-local address.
    pub router: Ipv6Addr,
    /// The `ICMPv6` message.
    pub message: Vec<u8>,
}

#[cfg(target_os = "linux")]
mod host {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use ipnet::Ipv6Net;
    use socket2::{Domain, Protocol, Socket, Type};

    use super::{ALL_ROUTERS, Heard, ND_HOP_LIMIT, RaLink, router_solicitation};
    use crate::error::ScanError;

    /// The links that can carry advertisements: up, not loopback, with an IPv6 address.
    pub fn links() -> Vec<RaLink> {
        pnet_datalink::interfaces()
            .iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .filter(|iface| iface.ips.iter().any(|ip| ip.ip().is_ipv6()))
            .map(|iface| RaLink {
                index: iface.index,
                name: iface.name.clone(),
                mac: iface.mac.map(|mac| mac.octets()),
                networks: iface
                    .ips
                    .iter()
                    .filter_map(|ip| match ip.ip() {
                        IpAddr::V6(addr) if (addr.segments()[0] & 0xffc0) != 0xfe80 => {
                            Ipv6Net::new(addr, ip.prefix()).ok()
                        }
                        _ => None,
                    })
                    .collect(),
            })
            .collect()
    }

    /// A raw `ICMPv6` socket that hears router advertisements and sends solicitations.
    #[derive(Debug)]
    pub struct RaSocket {
        socket: tokio::net::UdpSocket,
    }

    impl RaSocket {
        /// Opens the socket.
        ///
        /// # Errors
        ///
        /// `scan.unavailable` when the process may not open a raw socket (no
        /// `CAP_NET_RAW`), `scan.io` for another failure.
        pub fn open() -> Result<Self, ScanError> {
            let socket =
                Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|error| {
                    match error.kind() {
                        std::io::ErrorKind::PermissionDenied => ScanError::unavailable(
                            "a raw ICMPv6 socket needs CAP_NET_RAW (deploy/systemd/probe.conf)",
                        ),
                        _ => ScanError::io(format!("raw ICMPv6 socket: {error}")),
                    }
                })?;
            socket.set_multicast_hops_v6(ND_HOP_LIMIT)?;
            socket.set_unicast_hops_v6(ND_HOP_LIMIT)?;
            socket.set_multicast_loop_v6(false)?;
            socket.set_nonblocking(true)?;
            let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
            Ok(Self { socket })
        }

        /// The next router advertisement from a link-local source; other `ICMPv6` messages
        /// are skipped.
        ///
        /// # Errors
        ///
        /// `scan.io` when the socket fails.
        pub async fn next(&self) -> Result<Heard, ScanError> {
            let mut buffer = [0u8; 1500];
            loop {
                let (len, from) = self.socket.recv_from(&mut buffer).await?;
                let SocketAddr::V6(from) = from else {
                    continue;
                };
                let router = *from.ip();
                // RFC 4861 section 6.1.2: the source of an advertisement is link-local.
                if len == 0
                    || buffer[0] != super::ROUTER_ADVERTISEMENT
                    || (router.segments()[0] & 0xffc0) != 0xfe80
                {
                    continue;
                }
                return Ok(Heard {
                    interface: from.scope_id(),
                    router,
                    message: buffer[..len].to_vec(),
                });
            }
        }

        /// Sends a Router Solicitation to the routers of a link.
        ///
        /// # Errors
        ///
        /// `scan.io` when it cannot be sent.
        pub async fn solicit(&self, link: &RaLink) -> Result<(), ScanError> {
            let mut packet = [0u8; 16];
            let len = router_solicitation(link.mac, &mut packet);
            let to = SocketAddrV6::new(ALL_ROUTERS, 0, 0, link.index);
            self.socket
                .send_to(&packet[..len], SocketAddr::V6(to))
                .await?;
            Ok(())
        }
    }

    /// Whether `addr` is link-local (`fe80::/10`).
    pub fn is_link_local(addr: Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xffc0) == 0xfe80
    }
}

#[cfg(not(target_os = "linux"))]
mod host {
    use super::{Heard, RaLink};
    use crate::error::ScanError;

    /// No links: the socket is Linux only.
    pub fn links() -> Vec<RaLink> {
        Vec::new()
    }

    /// The raw `ICMPv6` socket, not available on this system.
    #[derive(Debug)]
    pub struct RaSocket;

    impl RaSocket {
        /// Always `scan.unavailable`: the check runs on Linux only.
        ///
        /// # Errors
        ///
        /// Always.
        pub fn open() -> Result<Self, ScanError> {
            Err(ScanError::unavailable(
                "the router advertisement check runs on Linux only",
            ))
        }

        /// Never returns a message.
        ///
        /// # Errors
        ///
        /// Never.
        pub async fn next(&self) -> Result<Heard, ScanError> {
            std::future::pending().await
        }

        /// Sends nothing.
        ///
        /// # Errors
        ///
        /// Never.
        #[allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "the signature of the Linux socket"
        )]
        pub async fn solicit(&self, _link: &RaLink) -> Result<(), ScanError> {
            Ok(())
        }
    }

    /// Whether `addr` is link-local (`fe80::/10`).
    pub fn is_link_local(addr: std::net::Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xffc0) == 0xfe80
    }
}

pub use host::{RaSocket, is_link_local, links};

#[cfg(test)]
mod tests {
    use super::*;

    /// An advertisement with M and O set, a router lifetime of 1800 s, the source
    /// link-layer address, an MTU of 1500 and the prefix `2001:db8:100::/64` (L and A).
    fn sample(flags: u8) -> Vec<u8> {
        let mut out = vec![134, 0, 0, 0, 64, flags, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&[1, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        out.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x05, 0xdc]);
        out.extend_from_slice(&[3, 4, 64, 0xc0]);
        out.extend_from_slice(&86_400u32.to_be_bytes());
        out.extend_from_slice(&14_400u32.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&"2001:db8:100::".parse::<Ipv6Addr>().expect("addr").octets());
        out
    }

    #[test]
    fn an_advertisement_reads_its_flags_and_options() {
        let bytes = sample(0xc0);
        let ra = RouterAdvert::parse(&bytes).expect("an advertisement");
        assert!(ra.managed() && ra.other());
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.source_link_layer(), Some(&[0, 0, 0x5e, 0, 0x53, 1][..]));
        let prefixes: Vec<_> = ra.prefixes().collect();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix.to_string(), "2001:db8:100::/64");
        assert!(prefixes[0].on_link && prefixes[0].autonomous);
        assert!(ra.options().any(|option| option == NdOption::Mtu(1500)));
        let off = sample(0);
        let ra = RouterAdvert::parse(&off).expect("an advertisement");
        assert!(!ra.managed() && !ra.other());
    }

    #[test]
    fn a_malformed_advertisement_is_refused() {
        let bytes = sample(0x80);
        assert_eq!(RouterAdvert::parse(&bytes[..15]), Err(RaError::Short));
        let mut zero = bytes.clone();
        zero[17] = 0;
        assert_eq!(RouterAdvert::parse(&zero), Err(RaError::BadOption));
        assert_eq!(
            RouterAdvert::parse(&bytes[..bytes.len() - 1]),
            Err(RaError::BadOption)
        );
        let mut code = bytes.clone();
        code[1] = 1;
        assert_eq!(RouterAdvert::parse(&code), Err(RaError::Code(1)));
        let mut solicitation = bytes;
        solicitation[0] = 133;
        assert_eq!(
            RouterAdvert::parse(&solicitation),
            Err(RaError::NotAdvert(133))
        );
    }

    #[test]
    fn a_solicitation_carries_the_link_layer_address_when_known() {
        let mut out = [0u8; 16];
        assert_eq!(router_solicitation(None, &mut out), 8);
        assert_eq!(out[..8], [133, 0, 0, 0, 0, 0, 0, 0]);
        let mac = [0, 0, 0x5e, 0, 0x53, 9];
        assert_eq!(router_solicitation(Some(mac), &mut out), 16);
        assert_eq!(out[8..], [1, 1, 0, 0, 0x5e, 0, 0x53, 9]);
    }
}
