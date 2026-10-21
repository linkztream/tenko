//! Safe parsers and builders for the link- and network-layer frames the raw-socket
//! methods read and send: Ethernet, ARP, IPv4, TCP, LLDP, CDP and the four DHCPv4 fields
//! the snoop needs. Every function works on byte slices and never uses `unsafe`, so the
//! parsers are tested with crafted and captured frames and fuzzed without a socket. The
//! raw sockets themselves are in [`crate::methods::raw::link`] (Linux only).
//!
//! | Module | Frame |
//! |---|---|
//! | [`ethernet`] | Ethernet II and 802.2/SNAP headers, the ethertype or SNAP protocol |
//! | [`arp`] | ARP requests and replies (RFC 826) |
//! | [`ipv4`] | the IPv4 header fields the fingerprint and the snoop read |
//! | [`tcp`] | TCP segments: SYN, SYN-ACK, RST and the options the fingerprint reads |
//! | [`lldp`] | LLDP TLVs (IEEE 802.1AB) |
//! | [`cdp`] | Cisco Discovery Protocol version 2 TLVs |
//! | [`dhcp`] | the op, xid, chaddr, yiaddr and options 53, 12, 60, 61, 50, 54 of a DHCPv4 message (RFC 2131). A small local parser, replaced by `tenko-dhcp`'s codec after it merges |

use std::net::IpAddr;

use tenko_core::MacAddr;

pub mod arp;
pub mod cdp;
pub mod dhcp;
pub mod ethernet;
pub mod ipv4;
pub mod lldp;
pub mod tcp;

/// Lowercase hex of `bytes`, two digits per byte.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Which passive neighbour protocol a [`Neighbour`] was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighbourSource {
    /// Link Layer Discovery Protocol (IEEE 802.1AB).
    Lldp,
    /// Cisco Discovery Protocol version 2.
    Cdp,
}

impl NeighbourSource {
    /// The protocol name for a note.
    pub const fn name(self) -> &'static str {
        match self {
            NeighbourSource::Lldp => "LLDP",
            NeighbourSource::Cdp => "CDP",
        }
    }
}

/// What the switch or access point on the other end of the probe's link announced, read
/// from one LLDP or CDP frame. The fields are those shared by both protocols; a field the
/// frame did not carry is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Neighbour {
    /// The chassis identifier: a MAC address, a network address or a name, formatted by
    /// its subtype (LLDP) or the device id (CDP).
    pub chassis_id: Option<String>,
    /// The port the probe is attached to, as the neighbour names it (LLDP port id, CDP
    /// port id).
    pub port_id: Option<String>,
    /// The port description, when the frame carried one.
    pub port_desc: Option<String>,
    /// The announced time to live, in seconds (LLDP TTL TLV).
    pub ttl: Option<u16>,
    /// The system name (LLDP system name, CDP device id).
    pub system_name: Option<String>,
    /// The system description (LLDP system description, CDP software version and
    /// platform).
    pub system_desc: Option<String>,
    /// The capabilities the neighbour claims (the enabled set).
    pub capabilities: NeighbourCapabilities,
    /// Management addresses (LLDP management address TLV, CDP addresses TLV).
    pub mgmt_addrs: Vec<IpAddr>,
    /// The VLAN of the link: the 802.1 port VLAN id (LLDP) or the native VLAN (CDP).
    pub vlan: Option<u16>,
    /// The name of a VLAN the neighbour named (LLDP 802.1 VLAN name TLV).
    pub vlan_name: Option<String>,
    /// Which protocol carried the frame.
    pub source: Option<NeighbourSource>,
}

impl Neighbour {
    /// The chassis id as a MAC address, when it is one (for the OUI vendor lookup).
    pub fn chassis_mac(&self) -> Option<MacAddr> {
        self.chassis_id.as_deref()?.parse().ok()
    }

    /// Whether the frame named anything worth a fact.
    pub fn is_empty(&self) -> bool {
        self.chassis_id.is_none()
            && self.port_id.is_none()
            && self.system_name.is_none()
            && self.mgmt_addrs.is_empty()
    }
}

/// The device capabilities LLDP and CDP report; the set a neighbour says is enabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
// The fields mirror the protocol's capability bits.
#[allow(clippy::struct_excessive_bools)]
pub struct NeighbourCapabilities {
    /// Acts as a bridge (switch).
    pub bridge: bool,
    /// Acts as a router.
    pub router: bool,
    /// Acts as a WLAN access point.
    pub wlan: bool,
    /// Acts as a telephone.
    pub telephone: bool,
    /// Acts as a station (end host) only.
    pub station: bool,
}

impl NeighbourCapabilities {
    /// Whether any capability is set.
    pub fn any(self) -> bool {
        self.bridge || self.router || self.wlan || self.telephone || self.station
    }
}
