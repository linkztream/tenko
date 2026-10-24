//! DHCPv6 (RFC 8415, WP9.1): the wire codec, the engine over the configuration image and
//! the lease store, the lease path of `dhcp.leases6`, and the listeners on UDP 547.
//!
//! The codec is allocation-free in the manner of [`crate::v4`]. [`Message::parse`] checks
//! the fixed header of a received datagram (the message type and the transaction id of a
//! client or server message, or the hop count and the two addresses of a relay message,
//! RFC 8415 sections 8 and 9) and returns a view over the buffer; the options, the options
//! nested in them (an `IA_NA` holds its addresses, an address its status) and the typed
//! values are read from the buffer when asked for. [`RelayChain::parse`] walks a
//! RELAY-FORW inwards through its Relay Message options to the client's message, at most
//! [`MAX_RELAY_DEPTH`] relays deep, without allocating. [`MessageBuilder`] writes a message
//! into a caller's buffer: the header, options, and nested options opened with
//! [`MessageBuilder::begin`] and closed with [`MessageBuilder::end`], so that an `IA_NA`
//! with its addresses and a RELAY-REPL around a REPLY around nothing else are written in
//! one pass; an option that does not fit is an error, never a truncated message.
//!
//! # Malformed messages
//!
//! Only a datagram shorter than its header fails to parse. A malformed option (a length
//! that runs past the end of its area) ends the walk of its area at that option, as in
//! DHCPv4: the options before it stay readable, [`Options`] yields the error once and stops,
//! and an accessor returns the error only when the option it looks for was not found before
//! it. [`Message::validate`] walks every option for a server that wants to refuse such a
//! message.
//!
//! | Module | What |
//! |---|---|
//! | [`message`] | [`Message`], [`Options`], [`RelayChain`] |
//! | [`option`] | the typed options: DUIDs, `IA_NA`, `IA_PD`, status codes, the option request, the client FQDN of RFC 4704, the client link-layer address of RFC 6939, the DNS and NTP options of RFC 3646 and RFC 5908 |
//! | [`builder`] | [`MessageBuilder`], [`encode_domain_list`], [`encode_ntp_servers`] |

pub mod builder;
// WP9.1: the engine, the lease path and the listeners.
pub mod engine;
pub mod image;
pub mod lease;
pub mod message;
pub mod option;
pub mod server;

use std::net::Ipv6Addr;

pub use builder::{Mark, MessageBuilder, encode_domain_list, encode_ntp_servers};
pub use message::{Message, Options, RawOption, RelayChain};
pub use option::{
    AddrList, ClientFqdn, Duid, IaAddress, IaNa, IaPd, IaPrefix, LinkLayerAddress, NtpServer,
    NtpSuboption, OptionRequest, RemoteId, StatusCode, VendorClass,
};

/// The port servers and relay agents listen on (RFC 8415 section 7.2).
pub const SERVER_PORT: u16 = 547;

/// The port clients listen on.
pub const CLIENT_PORT: u16 = 546;

/// `All_DHCP_Relay_Agents_and_Servers`, the link-scoped multicast address clients send to
/// (RFC 8415 section 7.1).
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// The largest hop count a relay forwards (RFC 8415 section 7.6, `HOP_COUNT_LIMIT`).
pub const HOP_COUNT_LIMIT: u8 = 8;

/// The deepest relay chain the codec walks: one relay per hop the hop count allows.
pub const MAX_RELAY_DEPTH: usize = HOP_COUNT_LIMIT as usize;

/// The fixed part of a client or server message: the type and the transaction id.
pub const CLIENT_HEADER_LEN: usize = 4;

/// The fixed part of a relay message: the type, the hop count and the two addresses.
pub const RELAY_HEADER_LEN: usize = 34;

/// The message types (RFC 8415 section 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// 1.
    Solicit,
    /// 2.
    Advertise,
    /// 3.
    Request,
    /// 4.
    Confirm,
    /// 5.
    Renew,
    /// 6.
    Rebind,
    /// 7.
    Reply,
    /// 8.
    Release,
    /// 9.
    Decline,
    /// 10.
    Reconfigure,
    /// 11.
    InformationRequest,
    /// 12.
    RelayForw,
    /// 13.
    RelayRepl,
    /// Any other value (the leasequery and DHCPv4-over-DHCPv6 types among them).
    Other(u8),
}

impl MessageType {
    /// The type of a value.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Solicit,
            2 => Self::Advertise,
            3 => Self::Request,
            4 => Self::Confirm,
            5 => Self::Renew,
            6 => Self::Rebind,
            7 => Self::Reply,
            8 => Self::Release,
            9 => Self::Decline,
            10 => Self::Reconfigure,
            11 => Self::InformationRequest,
            12 => Self::RelayForw,
            13 => Self::RelayRepl,
            other => Self::Other(other),
        }
    }

    /// The value on the wire.
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Solicit => 1,
            Self::Advertise => 2,
            Self::Request => 3,
            Self::Confirm => 4,
            Self::Renew => 5,
            Self::Rebind => 6,
            Self::Reply => 7,
            Self::Release => 8,
            Self::Decline => 9,
            Self::Reconfigure => 10,
            Self::InformationRequest => 11,
            Self::RelayForw => 12,
            Self::RelayRepl => 13,
            Self::Other(value) => value,
        }
    }

    /// Whether messages of this type have the relay header.
    pub const fn is_relay(self) -> bool {
        matches!(self, Self::RelayForw | Self::RelayRepl)
    }
}

/// Option codes (RFC 8415 section 21 and the option RFCs; the IANA registry).
pub mod code {
    /// Client Identifier (RFC 8415 section 21.2).
    pub const CLIENTID: u16 = 1;
    /// Server Identifier (21.3).
    pub const SERVERID: u16 = 2;
    /// Identity Association for Non-temporary Addresses (21.4).
    pub const IA_NA: u16 = 3;
    /// Identity Association for Temporary Addresses (21.5; not served).
    pub const IA_TA: u16 = 4;
    /// IA Address (21.6).
    pub const IAADDR: u16 = 5;
    /// Option Request (21.7).
    pub const ORO: u16 = 6;
    /// Preference (21.8).
    pub const PREFERENCE: u16 = 7;
    /// Elapsed Time (21.9).
    pub const ELAPSED_TIME: u16 = 8;
    /// Relay Message (21.10).
    pub const RELAY_MSG: u16 = 9;
    /// Authentication (21.11).
    pub const AUTH: u16 = 11;
    /// Server Unicast (21.12).
    pub const UNICAST: u16 = 12;
    /// Status Code (21.13).
    pub const STATUS_CODE: u16 = 13;
    /// Rapid Commit (21.14).
    pub const RAPID_COMMIT: u16 = 14;
    /// User Class (21.15).
    pub const USER_CLASS: u16 = 15;
    /// Vendor Class (21.16).
    pub const VENDOR_CLASS: u16 = 16;
    /// Vendor-specific Information (21.17).
    pub const VENDOR_OPTS: u16 = 17;
    /// Interface-Id (21.18).
    pub const INTERFACE_ID: u16 = 18;
    /// Reconfigure Message (21.19).
    pub const RECONF_MSG: u16 = 19;
    /// Reconfigure Accept (21.20).
    pub const RECONF_ACCEPT: u16 = 20;
    /// SIP servers, domain names (RFC 3319).
    pub const SIP_SERVER_D: u16 = 21;
    /// SIP servers, addresses (RFC 3319).
    pub const SIP_SERVER_A: u16 = 22;
    /// DNS Recursive Name Server (RFC 3646 section 3).
    pub const DNS_SERVERS: u16 = 23;
    /// Domain Search List (RFC 3646 section 4).
    pub const DOMAIN_LIST: u16 = 24;
    /// Identity Association for Prefix Delegation (21.21).
    pub const IA_PD: u16 = 25;
    /// IA Prefix (21.22).
    pub const IAPREFIX: u16 = 26;
    /// SNTP servers (RFC 4075).
    pub const SNTP_SERVERS: u16 = 31;
    /// Information Refresh Time (21.23).
    pub const INFORMATION_REFRESH_TIME: u16 = 32;
    /// Relay Agent Remote-ID (RFC 4649).
    pub const REMOTE_ID: u16 = 37;
    /// Client FQDN (RFC 4704).
    pub const CLIENT_FQDN: u16 = 39;
    /// NTP Server (RFC 5908).
    pub const NTP_SERVER: u16 = 56;
    /// Client Link-Layer Address (RFC 6939).
    pub const CLIENT_LINKLAYER_ADDR: u16 = 79;
    /// `SOL_MAX_RT` (21.24).
    pub const SOL_MAX_RT: u16 = 82;
    /// `INF_MAX_RT` (21.25).
    pub const INF_MAX_RT: u16 = 83;
}

/// Status codes (RFC 8415 section 21.13).
pub mod status {
    /// Success.
    pub const SUCCESS: u16 = 0;
    /// Failure, reason unspecified.
    pub const UNSPEC_FAIL: u16 = 1;
    /// The server has no addresses available to assign to the IA.
    pub const NO_ADDRS_AVAIL: u16 = 2;
    /// The client record (binding) is unavailable.
    pub const NO_BINDING: u16 = 3;
    /// The prefix of an address is not appropriate for the link.
    pub const NOT_ON_LINK: u16 = 4;
    /// The client must send its message to the multicast address.
    pub const USE_MULTICAST: u16 = 5;
    /// The server has no prefixes available to assign to the `IA_PD`.
    pub const NO_PREFIX_AVAIL: u16 = 6;
}

/// Why a message, an option or a value could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Shorter than the header of its type.
    #[error("{len} octets: shorter than a DHCPv6 message header")]
    TooShort {
        /// The length of the datagram (or of the relayed message).
        len: usize,
    },
    /// The option's code and length, or its value, run past the end of its area.
    #[error("option {code} runs past the end of its area")]
    Truncated {
        /// The option code (0 when the area ended inside the code itself).
        code: u16,
    },
    /// The option's length is not one its type allows.
    #[error("option {code} has the length {len}")]
    BadLength {
        /// The option code.
        code: u16,
        /// The length of the value.
        len: usize,
    },
    /// The option's value does not follow its format (a bad name, a nested option that
    /// runs past the end).
    #[error("option {code} has a malformed value")]
    BadValue {
        /// The option code.
        code: u16,
    },
    /// A relay message of another relay message, deeper than [`MAX_RELAY_DEPTH`], or a
    /// RELAY-FORW without its Relay Message option.
    #[error("the relay chain is deeper than {MAX_RELAY_DEPTH} or has no relayed message")]
    RelayChain,
}

/// Why a message could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The buffer or the limit is smaller than the header.
    #[error("the buffer or the limit is too small for a message")]
    BufferTooSmall,
    /// The option does not fit within the limit; nothing of it was written.
    #[error("option {code} does not fit")]
    NoRoom {
        /// The option code.
        code: u16,
    },
    /// A value longer than an option holds (65,535 octets).
    #[error("option {code} is too long")]
    TooLong {
        /// The option code.
        code: u16,
    },
    /// Options opened with `begin` and not closed, closed out of order, or nested deeper
    /// than the builder keeps.
    #[error("the nested options are not balanced")]
    Unbalanced,
    /// The value cannot be encoded (a bad name).
    #[error("option {code} cannot be encoded")]
    BadValue {
        /// The option code.
        code: u16,
    },
}

/// A big-endian `u16` at `at` (the caller checked the length).
pub(crate) fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

/// A big-endian `u32` at `at` (the caller checked the length).
pub(crate) fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// An IPv6 address at `at` (the caller checked the length).
pub(crate) fn addr_at(data: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&data[at..at + 16]);
    Ipv6Addr::from(octets)
}
