//! The DHCPv4 wire codec (RFC 2131, RFC 2132).
//!
//! [`Message::parse`] checks the fixed header and the magic cookie of a received datagram
//! and returns a view over the buffer; the fields, the options and the typed option values
//! are read from the buffer when asked for, so parsing and reading allocate nothing.
//! [`Message::options`] walks the three option areas in the order RFC 2131 gives (the
//! `options` field, then `file`, then `sname`, the last two only when option 52 says they
//! carry options) and yields every instance with the area it came from. The typed accessors
//! read the first instance of an option; when an option comes as several instances (RFC
//! 3396) they return [`DecodeError::Split`] and the caller concatenates the instances with
//! [`Message::option_data`] into a buffer of its own and reads them with the type's
//! `parse`.
//!
//! [`MessageBuilder`] writes a message into a caller's buffer: the fixed header (for a reply
//! copied from the request by [`MessageBuilder::reply`]), option 53 first, the options with
//! RFC 3396 splitting of values longer than 255 octets, overload into `file` and `sname`
//! when the caller allows it, the end option and the BOOTP padding when asked for. The size
//! limit comes from the client's option 57 ([`Message::max_reply_len`]); an option that
//! does not fit is an error, never a truncated reply.
//!
//! # Malformed messages
//!
//! Only a message shorter than 240 octets or without the magic cookie fails to parse. A
//! malformed option (a length that runs past the end of its area, a bad option 52) ends the
//! walk at that option: the options before it stay readable, [`Message::options`] yields
//! the error once and stops, and an accessor returns the error only when the option it
//! looks for was not found before it. The server decides whether such a message is served
//! ([`Message::validate`] walks every option for a server that wants to refuse it).

mod builder;
// WP7.3: the engine over the codec, the image, the leases and the allocator.
pub mod engine;
mod message;
mod name;
mod option;

pub use builder::{MessageBuilder, encode_classless_routes};
pub use message::{Area, Message, Options, RawOption};
pub use name::{DomainSearch, WireName, encode_domain_search};
pub use option::{
    AddrList, Architectures, ClientFqdn, ClientId, Duid, LengthPrefixed, LengthPrefixedIter,
    MachineId, MessageType, NetworkInterfaceId, RelayAgentInfo, Route, Routes, SubOptionIter,
    SubOptions, UserClass, VendorClass, VendorClasses, VendorInfo, VendorInfos,
};

/// The magic cookie that starts the options field (RFC 2131, section 3).
pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// The length of the fixed header before the magic cookie.
pub const HEADER_LEN: usize = 236;

/// Where the options field starts: the fixed header and the magic cookie.
pub const OPTIONS_START: usize = HEADER_LEN + MAGIC_COOKIE.len();

/// The smallest message a BOOTP relay or client accepts (RFC 1542, section 2.1): replies are
/// padded to it when the caller asks.
pub const BOOTP_MIN_LEN: usize = 300;

/// The smallest IP datagram every host accepts and the smallest legal option 57 (RFC 2131,
/// section 4.1; RFC 2132, section 9.10).
pub const MIN_DATAGRAM_LEN: usize = 576;

/// The IPv4 and UDP headers without options, which option 57 counts and the DHCP message
/// does not.
pub const IP_UDP_HEADERS_LEN: usize = 28;

/// The largest DHCP message a client accepts when it sends no option 57: 576 octets less
/// the IP and UDP headers.
pub const DEFAULT_MAX_LEN: usize = MIN_DATAGRAM_LEN - IP_UDP_HEADERS_LEN;

/// `op` of a message from a client.
pub const BOOTREQUEST: u8 = 1;

/// `op` of a message from a server.
pub const BOOTREPLY: u8 = 2;

/// `htype` of Ethernet (RFC 1700, the ARP hardware types).
pub const HTYPE_ETHERNET: u8 = 1;

/// The broadcast bit of `flags` (RFC 2131, section 2).
pub const FLAG_BROADCAST: u16 = 0x8000;

/// Positions of the fixed fields (RFC 2131, section 2, figure 1).
pub mod offset {
    /// `op`, one octet.
    pub const OP: usize = 0;
    /// `htype`, one octet.
    pub const HTYPE: usize = 1;
    /// `hlen`, one octet.
    pub const HLEN: usize = 2;
    /// `hops`, one octet.
    pub const HOPS: usize = 3;
    /// `xid`, four octets.
    pub const XID: usize = 4;
    /// `secs`, two octets.
    pub const SECS: usize = 8;
    /// `flags`, two octets.
    pub const FLAGS: usize = 10;
    /// `ciaddr`, four octets.
    pub const CIADDR: usize = 12;
    /// `yiaddr`, four octets.
    pub const YIADDR: usize = 16;
    /// `siaddr`, four octets.
    pub const SIADDR: usize = 20;
    /// `giaddr`, four octets.
    pub const GIADDR: usize = 24;
    /// `chaddr`, sixteen octets.
    pub const CHADDR: usize = 28;
    /// `sname`, sixty-four octets.
    pub const SNAME: usize = 44;
    /// `file`, one hundred and twenty-eight octets.
    pub const FILE: usize = 108;
    /// The magic cookie, four octets.
    pub const COOKIE: usize = 236;
}

/// The length of `chaddr`.
pub const CHADDR_LEN: usize = 16;

/// The length of `sname`.
pub const SNAME_LEN: usize = 64;

/// The length of `file`.
pub const FILE_LEN: usize = 128;

/// Option codes (RFC 2132 and the later option RFCs; the registry of RFC 3942).
pub mod code {
    /// Pad (RFC 2132, section 3.1): one octet, no length.
    pub const PAD: u8 = 0;
    /// Subnet mask (RFC 2132, section 3.3).
    pub const SUBNET_MASK: u8 = 1;
    /// Routers (RFC 2132, section 3.5).
    pub const ROUTERS: u8 = 3;
    /// Domain name servers (RFC 2132, section 3.8).
    pub const DOMAIN_NAME_SERVERS: u8 = 6;
    /// Host name (RFC 2132, section 3.14).
    pub const HOST_NAME: u8 = 12;
    /// Domain name (RFC 2132, section 3.17).
    pub const DOMAIN_NAME: u8 = 15;
    /// Interface MTU (RFC 2132, section 5.1).
    pub const INTERFACE_MTU: u8 = 26;
    /// Broadcast address (RFC 2132, section 5.3).
    pub const BROADCAST_ADDRESS: u8 = 28;
    /// NTP servers (RFC 2132, section 8.3).
    pub const NTP_SERVERS: u8 = 42;
    /// Vendor-specific information (RFC 2132, section 8.4).
    pub const VENDOR_SPECIFIC: u8 = 43;
    /// Requested IP address (RFC 2132, section 9.1).
    pub const REQUESTED_ADDRESS: u8 = 50;
    /// IP address lease time (RFC 2132, section 9.2).
    pub const LEASE_TIME: u8 = 51;
    /// Option overload (RFC 2132, section 9.3).
    pub const OVERLOAD: u8 = 52;
    /// DHCP message type (RFC 2132, section 9.6).
    pub const MESSAGE_TYPE: u8 = 53;
    /// Server identifier (RFC 2132, section 9.7).
    pub const SERVER_IDENTIFIER: u8 = 54;
    /// Parameter request list (RFC 2132, section 9.8).
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    /// Message (RFC 2132, section 9.9).
    pub const MESSAGE: u8 = 56;
    /// Maximum DHCP message size (RFC 2132, section 9.10).
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    /// Renewal (T1) time (RFC 2132, section 9.11).
    pub const RENEWAL_TIME: u8 = 58;
    /// Rebinding (T2) time (RFC 2132, section 9.12).
    pub const REBINDING_TIME: u8 = 59;
    /// Vendor class identifier (RFC 2132, section 9.13).
    pub const VENDOR_CLASS_IDENTIFIER: u8 = 60;
    /// Client identifier (RFC 2132, section 9.14; RFC 4361).
    pub const CLIENT_IDENTIFIER: u8 = 61;
    /// TFTP server name (RFC 2132, section 9.4).
    pub const TFTP_SERVER_NAME: u8 = 66;
    /// Bootfile name (RFC 2132, section 9.5).
    pub const BOOTFILE_NAME: u8 = 67;
    /// User class (RFC 3004).
    pub const USER_CLASS: u8 = 77;
    /// Client FQDN (RFC 4702).
    pub const CLIENT_FQDN: u8 = 81;
    /// Relay agent information (RFC 3046).
    pub const RELAY_AGENT_INFORMATION: u8 = 82;
    /// Client system architecture (RFC 4578, section 2.1).
    pub const CLIENT_ARCHITECTURE: u8 = 93;
    /// Client network interface identifier (RFC 4578, section 2.2).
    pub const CLIENT_NETWORK_INTERFACE: u8 = 94;
    /// Client machine identifier (RFC 4578, section 2.3).
    pub const CLIENT_MACHINE_IDENTIFIER: u8 = 97;
    /// Auto-configure (RFC 2563).
    pub const AUTO_CONFIGURE: u8 = 116;
    /// Subnet selection (RFC 3011).
    pub const SUBNET_SELECTION: u8 = 118;
    /// Domain search (RFC 3397).
    pub const DOMAIN_SEARCH: u8 = 119;
    /// Classless static routes (RFC 3442).
    pub const CLASSLESS_STATIC_ROUTES: u8 = 121;
    /// Vendor-identifying vendor class (RFC 3925, section 3).
    pub const VENDOR_CLASS: u8 = 124;
    /// Vendor-identifying vendor-specific information (RFC 3925, section 4).
    pub const VENDOR_IDENTIFYING_INFO: u8 = 125;
    /// The classless static routes code that Microsoft clients ask for besides 121.
    pub const MS_CLASSLESS_STATIC_ROUTES: u8 = 249;
    /// End (RFC 2132, section 3.2): one octet, no length.
    pub const END: u8 = 255;
}

/// Why a message, an option or a field could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Shorter than the fixed header and the magic cookie (240 octets).
    #[error("{len} octets: shorter than a DHCP message")]
    TooShort {
        /// The length of the datagram.
        len: usize,
    },
    /// The four octets after the fixed header are not the magic cookie.
    #[error("no magic cookie")]
    NoCookie,
    /// The option's length octet, or its value, runs past the end of its area.
    #[error("option {code} runs past the end of the {area} area")]
    Truncated {
        /// The option code.
        code: u8,
        /// The area the option is in.
        area: Area,
    },
    /// The option's length is not one its type allows.
    #[error("option {code} has the length {len}")]
    BadLength {
        /// The option code.
        code: u8,
        /// The length of the value (all instances together for a concatenated option).
        len: usize,
    },
    /// The option's value does not follow its format (a bad name, a bad route, an unknown
    /// overload value, a sub-option that runs past the end).
    #[error("option {code} has a malformed value")]
    BadValue {
        /// The option code.
        code: u8,
    },
    /// The option comes as several instances (RFC 3396): concatenate them with
    /// [`Message::option_data`] and read the result with the type's `parse`.
    #[error("option {code} is split into several instances")]
    Split {
        /// The option code.
        code: u8,
    },
    /// The caller's buffer is too small for the concatenated option.
    #[error("the concatenated option needs {needed} octets")]
    BufferTooSmall {
        /// The octets the concatenation needs.
        needed: usize,
    },
    /// `chaddr` does not hold what was asked for: `hlen` above 16, or not an Ethernet
    /// address (`htype` 1, `hlen` 6) for [`Message::mac`].
    #[error("hardware type {htype} with length {hlen}")]
    Hardware {
        /// `htype`.
        htype: u8,
        /// `hlen`.
        hlen: u8,
    },
}

/// Why a message could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The buffer or the size limit is below 241 octets, the smallest message with an end
    /// option.
    #[error("the buffer or the limit is too small for a message")]
    BufferTooSmall,
    /// The option does not fit within the size limit; nothing of it was written.
    #[error("option {code} does not fit")]
    NoRoom {
        /// The option code.
        code: u8,
    },
    /// The padding asked for is above the size limit.
    #[error("padding to {len} octets exceeds the limit")]
    PaddingTooLong {
        /// The length asked for.
        len: usize,
    },
    /// A fixed field value is too long: `chaddr` above 16 octets, `sname` above 63, `file`
    /// above 127 (one octet is kept for the terminating zero).
    #[error("the value is too long for its field")]
    FieldTooLong,
    /// `sname` or `file` carries options already, or a value set by the caller keeps
    /// options out of it.
    #[error("the field carries options")]
    FieldInUse,
    /// The value cannot be encoded: an empty value where the option needs one, pad or end
    /// as an option code, a bad name or route.
    #[error("option {code} cannot be encoded")]
    BadValue {
        /// The option code.
        code: u8,
    },
}
