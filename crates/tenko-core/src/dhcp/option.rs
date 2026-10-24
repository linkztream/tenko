//! DHCP options (plan section 2.4, DHCP-02): option spaces, definitions, values in wire
//! form with a typed view, the option sets of the five levels and the built-in catalog.
//!
//! An [`OptionValue`] holds the option data as it goes on the wire (without code and length;
//! longer than 255 octets is split by the reply builder, RFC 3396), as [`crate::dns::Rdata`]
//! holds record data. [`OptionData`] is the typed view the API and the UI show; a value is
//! checked against the definition of its code, built in ([`CATALOG_V4`]) or custom
//! ([`OptionDef`], `dhcp.option_defs`).
//!
//! The catalog here holds the options of RFC 2132 and its successors that the server sets or
//! that a Phase 3 package names; WP7.4 completes it. Codes the server writes itself (the
//! message type, the server identifier, the lease times, the parameter list, the client's
//! own options) are [`SERVER_MANAGED_V4`] and never set through an option set.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, schema::Schema},
};

use super::{DhcpError, OptionDefId, PolicyId, SharedNetworkId, codes};
use crate::{
    codec::key::{KeyCodec, KeyError, encode_str},
    dns::DnsName,
    error::InvalidValue,
    id::{InterfaceId, PrefixId, RangeId},
    ipam::Stamp,
    serde_util::{HexBytes, string_schema},
};

/// The largest option data the model holds, in octets. A DHCPv4 reply splits values above
/// 255 octets (RFC 3396); DHCPv6 options may be longer but no Phase 3 option is.
pub const MAX_OPTION_DATA: usize = 4096;

/// The most values one option set holds.
pub const MAX_OPTIONS_PER_SET: usize = 256;

// ---------------------------------------------------------------------------------------
// Spaces

/// An option space: `dhcp4` (RFC 2132), `dhcp6` (RFC 8415, Slice 9) or a vendor space whose
/// options travel as sub-options of option 43 for a vendor class (as Windows and Kea name
/// them). A vendor space name is 1 to 63 characters of `a-z`, `0-9` and `-`, starting with a
/// letter, and neither `dhcp4` nor `dhcp6`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OptionSpace(String);

impl OptionSpace {
    /// The DHCPv4 space.
    pub const DHCP4: &'static str = "dhcp4";
    /// The DHCPv6 space.
    pub const DHCP6: &'static str = "dhcp6";

    /// The DHCPv4 space.
    pub fn dhcp4() -> Self {
        Self(Self::DHCP4.to_owned())
    }

    /// The DHCPv6 space.
    pub fn dhcp6() -> Self {
        Self(Self::DHCP6.to_owned())
    }

    /// Validates a space name.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the name breaks the rules above.
    pub fn new(name: &str) -> Result<Self, InvalidValue> {
        let valid = (1..=63).contains(&name.len())
            && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidValue::new(
                "option space",
                name,
                "1 to 63 characters of a-z, 0-9 and -, starting with a letter",
            ))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the DHCPv4 space.
    pub fn is_dhcp4(&self) -> bool {
        self.0 == Self::DHCP4
    }

    /// Whether this is the DHCPv6 space.
    pub fn is_dhcp6(&self) -> bool {
        self.0 == Self::DHCP6
    }

    /// Whether this is a vendor space.
    pub fn is_vendor(&self) -> bool {
        !self.is_dhcp4() && !self.is_dhcp6()
    }

    /// The largest code of the space: 254 for DHCPv4 and vendor spaces (0 and 255 are pad
    /// and end), 65,535 for DHCPv6.
    pub fn max_code(&self) -> u16 {
        if self.is_dhcp6() { u16::MAX } else { 254 }
    }
}

impl fmt::Debug for OptionSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OptionSpace({:?})", self.0)
    }
}

impl fmt::Display for OptionSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for OptionSpace {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for OptionSpace {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<OptionSpace> for String {
    fn from(space: OptionSpace) -> Self {
        space.0
    }
}

impl PartialSchema for OptionSpace {
    fn schema() -> RefOr<Schema> {
        string_schema("Option space: `dhcp4`, `dhcp6` or a vendor space name")
    }
}

impl ToSchema for OptionSpace {}

impl KeyCodec for OptionSpace {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_str(&self.0, out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Self::new(&String::decode_key(input)?).map_err(|_| KeyError::Invalid("option space"))
    }
}

// ---------------------------------------------------------------------------------------
// Kinds and definitions

/// The data type of an option (plan section 2.4). With [`OptionDef::array`] a scalar kind
/// repeats: an address list is `ipv4_address` with `array`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    /// Four octets.
    Ipv4Address,
    /// Sixteen octets.
    Ipv6Address,
    /// A prefix length (0 to 128) and sixteen octets.
    Ipv6Prefix,
    /// One octet.
    U8,
    /// Two octets, network order.
    U16,
    /// Four octets, network order.
    U32,
    /// Four octets, network order, two's complement (option 2).
    I32,
    /// One octet, 0 or 1.
    Bool,
    /// Text: UTF-8 without NUL (NVT ASCII in RFC 2132).
    String,
    /// A domain name in RFC 1035 wire form, uncompressed, ending with the root label.
    Fqdn,
    /// Classless static routes (RFC 3442): destination width, significant octets, router.
    ClasslessRoutes,
    /// Any octets.
    Binary,
    /// No data (a flag option such as rapid commit, RFC 4039).
    Empty,
}

impl OptionKind {
    /// The width of one element of a fixed-width kind; `None` for variable kinds.
    pub const fn width(self) -> Option<usize> {
        match self {
            Self::Ipv4Address | Self::U32 | Self::I32 => Some(4),
            Self::Ipv6Address => Some(16),
            Self::Ipv6Prefix => Some(17),
            Self::U8 | Self::Bool => Some(1),
            Self::U16 => Some(2),
            Self::Empty => Some(0),
            Self::String | Self::Fqdn | Self::ClasslessRoutes | Self::Binary => None,
        }
    }

    /// Whether `array` is meaningful for the kind: the fixed-width kinds except `empty`,
    /// and `fqdn` (a list of names, as option 119 without compression).
    pub const fn may_repeat(self) -> bool {
        !matches!(
            self,
            Self::Empty | Self::String | Self::ClasslessRoutes | Self::Binary | Self::I32
        )
    }

    /// Checks option data against the kind.
    ///
    /// # Errors
    ///
    /// An English reason when the data does not fit.
    pub fn check(self, array: bool, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_OPTION_DATA {
            return Err("option data longer than 4096 octets");
        }
        if array && !self.may_repeat() {
            return Err("this type does not repeat");
        }
        match self {
            Self::Empty => {
                if data.is_empty() {
                    Ok(())
                } else {
                    Err("this option carries no data")
                }
            }
            Self::String => {
                if data.is_empty() {
                    return Err("text options are not empty");
                }
                match std::str::from_utf8(data) {
                    Ok(text) if !text.contains('\0') => Ok(()),
                    _ => Err("text must be UTF-8 without NUL"),
                }
            }
            Self::Binary => Ok(()),
            Self::Fqdn => check_wire_names(data, array),
            Self::ClasslessRoutes => check_routes(data),
            fixed => {
                let width = fixed.width().unwrap_or(1);
                if data.is_empty() || !data.len().is_multiple_of(width) {
                    return Err("the data length does not fit the option type");
                }
                if !array && data.len() != width {
                    return Err("this option holds one value");
                }
                if fixed == Self::Bool && data.iter().any(|b| *b > 1) {
                    return Err("a boolean is 0 or 1");
                }
                if fixed == Self::Ipv6Prefix && data.chunks(17).any(|chunk| chunk[0] > 128) {
                    return Err("an IPv6 prefix length is at most 128");
                }
                // Slice 8 follow-ups: a prefix is its network address and its length.
                if fixed == Self::Ipv6Prefix
                    && data.chunks(17).any(|chunk| {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&chunk[1..]);
                        !is_network(Ipv6Addr::from(octets), chunk[0])
                    })
                {
                    return Err(HOST_BITS);
                }
                Ok(())
            }
        }
    }
}

// Slice 8 follow-ups: the rule for IPv6 prefixes (`docs/dhcp.md` section 4).
/// The refusal of an IPv6 prefix with bits set beyond its length.
const HOST_BITS: &str = "an IPv6 prefix has no bits set beyond its length";

/// Whether `address` is the network address of a prefix of `len` bits (`len` at most
/// 128): every bit after the first `len` is clear. The check, the decoding and the encoding
/// refuse anything else, so a prefix reads back as it was written.
fn is_network(address: Ipv6Addr, len: u8) -> bool {
    let bits = u128::from(address);
    match u32::from(len) {
        0 => bits == 0,
        len if len >= 128 => true,
        len => bits & (u128::MAX >> len) == 0,
    }
}

fn check_wire_names(data: &[u8], array: bool) -> Result<(), &'static str> {
    let mut names = 0;
    let mut rest = data;
    while !rest.is_empty() {
        let (text, used) = read_wire_name(rest)?;
        if DnsName::new(&text).is_err() || text.is_empty() {
            return Err("a name is not a DNS host name");
        }
        rest = &rest[used..];
        names += 1;
    }
    match names {
        0 => Err("a name list is not empty"),
        1 => Ok(()),
        _ if array => Ok(()),
        _ => Err("this option holds one name"),
    }
}

/// Reads one uncompressed wire name; returns it as text and the octets used.
fn read_wire_name(data: &[u8]) -> Result<(String, usize), &'static str> {
    let mut text = String::new();
    let mut at = 0;
    loop {
        let Some(&len) = data.get(at) else {
            return Err("a name ends before its root label");
        };
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err("a label is longer than 63 octets or compressed");
        }
        let label = data
            .get(at..at + usize::from(len))
            .ok_or("a label runs past the data")?;
        at += usize::from(len);
        if !text.is_empty() {
            text.push('.');
        }
        text.push_str(std::str::from_utf8(label).map_err(|_| "a label is not text")?);
    }
    if at > 255 {
        return Err("a name is longer than 255 octets");
    }
    Ok((text, at))
}

fn check_routes(data: &[u8]) -> Result<(), &'static str> {
    if data.is_empty() {
        return Err("a route list is not empty");
    }
    let mut rest = data;
    while let Some((&width, tail)) = rest.split_first() {
        if width > 32 {
            return Err("a route's width is at most 32");
        }
        let significant = usize::from(width).div_ceil(8);
        if tail.len() < significant + 4 {
            return Err("a route runs past the data");
        }
        rest = &tail[significant + 4..];
    }
    Ok(())
}

/// A custom option definition (`dhcp.option_defs`, DHCP-02): a code in a space with a name
/// and a type. A definition for a code the built-in catalog knows is refused
/// (`dhcp.option.code_reserved`); codes 224 to 254 of `dhcp4` are the site-specific range
/// (RFC 3942).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OptionDef {
    /// Identifier.
    pub id: OptionDefId,
    /// The space.
    pub space: OptionSpace,
    /// The code: 1 to 254, or 1 to 65,535 in `dhcp6`.
    pub code: u16,
    /// The name: 1 to 64 characters of `a-z`, `0-9` and `-` (the Kea convention, so the
    /// Kea export of WP9.3 keeps it).
    pub name: String,
    /// The type.
    pub kind: OptionKind,
    /// Whether the option holds a list of values of the kind.
    #[serde(default)]
    pub array: bool,
    /// For a vendor space: the vendor class (option 60) whose clients receive its options
    /// in option 43.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

/// Whether a name follows the option and class name rule: 1 to 64 characters of `a-z`,
/// `0-9` and `-`, starting with a letter or digit.
pub(super) fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl OptionDef {
    /// Checks a definition: the code is in the space's range and not a catalog code of
    /// `dhcp4`; the name follows the rule; `array` only for kinds that repeat; a vendor
    /// class only in a vendor space.
    ///
    /// # Errors
    ///
    /// `dhcp.option.invalid` naming the field, or `dhcp.option.code_reserved`.
    pub fn validate(&self) -> Result<(), DhcpError> {
        let invalid = |field: &str, reason: &str| {
            Err(DhcpError::invalid(codes::OPTION_INVALID, field, reason))
        };
        if self.code == 0 || self.code > self.space.max_code() {
            return invalid("code", "the code is outside the space's range");
        }
        if self.space.is_dhcp4()
            && let Ok(code) = u8::try_from(self.code)
            && (catalog_v4(code).is_some() || SERVER_MANAGED_V4.contains(&code))
        {
            return Err(DhcpError::code_reserved(
                &self.space,
                self.code,
                "the built-in catalog defines this code",
            ));
        }
        // WP9.1: the same for the DHCPv6 catalog.
        if self.space.is_dhcp6()
            && (catalog_v6(self.code).is_some() || SERVER_MANAGED_V6.contains(&self.code))
        {
            return Err(DhcpError::code_reserved(
                &self.space,
                self.code,
                "the built-in DHCPv6 catalog defines this code",
            ));
        }
        if !valid_name(&self.name) {
            return invalid("name", "1 to 64 characters of a-z, 0-9 and -");
        }
        if self.array && !self.kind.may_repeat() {
            return invalid("array", "this type does not repeat");
        }
        if self.vendor_class.is_some() && !self.space.is_vendor() {
            return invalid("vendor_class", "only a vendor space names a vendor class");
        }
        if self
            .vendor_class
            .as_ref()
            .is_some_and(|class| class.is_empty() || class.len() > 255)
        {
            return invalid("vendor_class", "1 to 255 characters");
        }
        Ok(())
    }
}

/// One entry of the built-in catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The code in `dhcp4`.
    pub code: u8,
    /// The name, as Kea names it.
    pub name: &'static str,
    /// The type.
    pub kind: OptionKind,
    /// Whether it holds a list.
    pub array: bool,
}

const fn entry(code: u8, name: &'static str, kind: OptionKind, array: bool) -> CatalogEntry {
    CatalogEntry {
        code,
        name,
        kind,
        array,
    }
}

/// Codes the server writes itself and an option set never holds: pad, end, the requested
/// address, the lease time, overload, the message type, the server identifier, the
/// parameter list, the message, the maximum size, T1 and T2, the client identifier, the
/// client FQDN (the server's answer of RFC 4702), the relay agent information (echoed),
/// the subnet selection (RFC 3011) and the client's architecture and machine identifier.
pub const SERVER_MANAGED_V4: [u8; 18] = [
    0, 255, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 81, 82, 118, 93, 97,
];

/// The built-in DHCPv4 catalog (RFC 2132 and later), by code. WP7.4 completes it; until
/// then a code outside it needs a custom definition.
pub const CATALOG_V4: &[CatalogEntry] = &[
    entry(1, "subnet-mask", OptionKind::Ipv4Address, false),
    entry(2, "time-offset", OptionKind::I32, false),
    entry(3, "routers", OptionKind::Ipv4Address, true),
    entry(4, "time-servers", OptionKind::Ipv4Address, true),
    entry(5, "name-servers", OptionKind::Ipv4Address, true),
    entry(6, "domain-name-servers", OptionKind::Ipv4Address, true),
    entry(7, "log-servers", OptionKind::Ipv4Address, true),
    entry(12, "host-name", OptionKind::String, false),
    entry(13, "boot-size", OptionKind::U16, false),
    entry(15, "domain-name", OptionKind::String, false),
    entry(17, "root-path", OptionKind::String, false),
    entry(19, "ip-forwarding", OptionKind::Bool, false),
    entry(23, "default-ip-ttl", OptionKind::U8, false),
    entry(26, "interface-mtu", OptionKind::U16, false),
    entry(28, "broadcast-address", OptionKind::Ipv4Address, false),
    entry(33, "static-routes", OptionKind::Ipv4Address, true),
    entry(40, "nis-domain", OptionKind::String, false),
    entry(41, "nis-servers", OptionKind::Ipv4Address, true),
    entry(42, "ntp-servers", OptionKind::Ipv4Address, true),
    entry(43, "vendor-encapsulated-options", OptionKind::Binary, false),
    entry(44, "netbios-name-servers", OptionKind::Ipv4Address, true),
    entry(46, "netbios-node-type", OptionKind::U8, false),
    entry(47, "netbios-scope", OptionKind::String, false),
    entry(60, "vendor-class-identifier", OptionKind::String, false),
    entry(64, "nisplus-domain-name", OptionKind::String, false),
    entry(66, "tftp-server-name", OptionKind::String, false),
    entry(67, "boot-file-name", OptionKind::String, false),
    entry(69, "smtp-server", OptionKind::Ipv4Address, true),
    entry(72, "www-server", OptionKind::Ipv4Address, true),
    entry(100, "pcode", OptionKind::String, false),
    entry(101, "tcode", OptionKind::String, false),
    entry(108, "v6-only-preferred", OptionKind::U32, false),
    entry(114, "v4-captive-portal", OptionKind::String, false),
    entry(119, "domain-search", OptionKind::Fqdn, true),
    entry(
        121,
        "classless-static-route",
        OptionKind::ClasslessRoutes,
        false,
    ),
    entry(125, "vivso-suboptions", OptionKind::Binary, false),
    entry(150, "tftp-server-address", OptionKind::Ipv4Address, true),
    entry(209, "pxelinux-configfile", OptionKind::String, false),
    entry(210, "pxelinux-pathprefix", OptionKind::String, false),
    entry(211, "pxelinux-reboottime", OptionKind::U32, false),
    entry(
        249,
        "ms-classless-static-route",
        OptionKind::ClasslessRoutes,
        false,
    ),
    entry(252, "wpad", OptionKind::String, false),
];

/// The catalog entry of a DHCPv4 code.
pub fn catalog_v4(code: u8) -> Option<&'static CatalogEntry> {
    CATALOG_V4.iter().find(|entry| entry.code == code)
}

// WP9.1: the DHCPv6 catalog (RFC 8415 and the option RFCs).
/// One entry of the built-in DHCPv6 catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Catalog6Entry {
    /// The code in `dhcp6`.
    pub code: u16,
    /// The name, as Kea names it.
    pub name: &'static str,
    /// The type.
    pub kind: OptionKind,
    /// Whether it holds a list.
    pub array: bool,
}

const fn entry6(code: u16, name: &'static str, kind: OptionKind, array: bool) -> Catalog6Entry {
    Catalog6Entry {
        code,
        name,
        kind,
        array,
    }
}

/// DHCPv6 codes the server writes itself and an option set never holds: the identifiers,
/// the identity associations and their addresses and prefixes, the option request, the
/// preference, the elapsed time, the relay message, authentication, server unicast, the
/// status code, rapid commit, the Interface-Id, the reconfigure options, the Remote-Id,
/// the client FQDN (the server's answer of RFC 4704) and the client link-layer address.
pub const SERVER_MANAGED_V6: [u16; 21] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 18, 19, 20, 25, 26, 37, 39, 79,
];

/// The built-in DHCPv6 catalog. Option 56 (NTP server, RFC 5908) holds the servers'
/// addresses; the server writes each as an `NTP_SUBOPTION_SRV_ADDR` sub-option.
pub const CATALOG_V6: &[Catalog6Entry] = &[
    entry6(21, "sip-server-dns", OptionKind::Fqdn, true),
    entry6(22, "sip-server-addr", OptionKind::Ipv6Address, true),
    entry6(23, "dns-servers", OptionKind::Ipv6Address, true),
    entry6(24, "domain-search", OptionKind::Fqdn, true),
    entry6(27, "nis-servers", OptionKind::Ipv6Address, true),
    entry6(28, "nisp-servers", OptionKind::Ipv6Address, true),
    entry6(29, "nis-domain-name", OptionKind::Fqdn, false),
    entry6(30, "nisp-domain-name", OptionKind::Fqdn, false),
    entry6(31, "sntp-servers", OptionKind::Ipv6Address, true),
    entry6(32, "information-refresh-time", OptionKind::U32, false),
    entry6(41, "new-posix-timezone", OptionKind::String, false),
    entry6(42, "new-tzdb-timezone", OptionKind::String, false),
    entry6(56, "ntp-server", OptionKind::Ipv6Address, true),
    entry6(59, "bootfile-url", OptionKind::String, false),
    entry6(60, "bootfile-param", OptionKind::Binary, false),
    entry6(64, "aftr-name", OptionKind::Fqdn, false),
    entry6(82, "sol-max-rt", OptionKind::U32, false),
    entry6(83, "inf-max-rt", OptionKind::U32, false),
];

/// The catalog entry of a DHCPv6 code.
pub fn catalog_v6(code: u16) -> Option<&'static Catalog6Entry> {
    CATALOG_V6.iter().find(|entry| entry.code == code)
}

/// The type of an option: the catalog for `dhcp4`, else the custom definition of the same
/// space and code among `defs`.
pub fn kind_of<'a>(
    space: &OptionSpace,
    code: u16,
    defs: impl IntoIterator<Item = &'a OptionDef>,
) -> Option<(OptionKind, bool)> {
    if space.is_dhcp4()
        && let Ok(code) = u8::try_from(code)
        && let Some(entry) = catalog_v4(code)
    {
        return Some((entry.kind, entry.array));
    }
    // WP9.1: the DHCPv6 catalog.
    if space.is_dhcp6()
        && let Some(entry) = catalog_v6(code)
    {
        return Some((entry.kind, entry.array));
    }
    defs.into_iter()
        .find(|def| &def.space == space && def.code == code)
        .map(|def| (def.kind, def.array))
}

// ---------------------------------------------------------------------------------------
// Values and sets

/// One option with its data in wire form (plan section 3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct OptionValue {
    /// The space.
    pub space: OptionSpace,
    /// The code.
    pub code: u16,
    /// The data in wire form, without code and length.
    pub data: HexBytes,
}

impl OptionValue {
    /// A `dhcp4` option.
    pub fn v4(code: u8, data: Vec<u8>) -> Self {
        Self {
            space: OptionSpace::dhcp4(),
            code: u16::from(code),
            data: HexBytes(data),
        }
    }

    /// Checks the value against the type of its code.
    ///
    /// # Errors
    ///
    /// `dhcp.option.code_reserved` for a code the server manages, `dhcp.option.unknown`
    /// for a code without definition, `dhcp.option.invalid` when the data does not fit.
    pub fn validate<'a>(
        &self,
        defs: impl IntoIterator<Item = &'a OptionDef>,
    ) -> Result<(), DhcpError> {
        // WP9.1: and the codes a DHCPv6 server writes itself.
        if (self.space.is_dhcp4()
            && u8::try_from(self.code).is_ok_and(|code| SERVER_MANAGED_V4.contains(&code)))
            || (self.space.is_dhcp6() && SERVER_MANAGED_V6.contains(&self.code))
        {
            return Err(DhcpError::code_reserved(
                &self.space,
                self.code,
                "the server sets this option itself",
            ));
        }
        let Some((kind, array)) = kind_of(&self.space, self.code, defs) else {
            return Err(DhcpError::new(
                codes::OPTION_UNKNOWN,
                400,
                format!("option {} {} has no definition", self.space, self.code),
            )
            .with_param("space", self.space.as_str())
            .with_param("code", self.code.to_string()));
        };
        kind.check(array, &self.data.0).map_err(|reason| {
            DhcpError::new(
                codes::OPTION_INVALID,
                400,
                format!("option {} {}: {reason}", self.space, self.code),
            )
            .with_param("space", self.space.as_str())
            .with_param("code", self.code.to_string())
            .with_param("reason", reason)
        })
    }

    /// The typed view of the data.
    ///
    /// # Errors
    ///
    /// An English reason when the data does not fit `kind`.
    pub fn typed(&self, kind: OptionKind, array: bool) -> Result<OptionData, &'static str> {
        OptionData::decode(kind, array, &self.data.0)
    }
}

/// The typed view of option data (as [`crate::dns::RecordData`] is of record data), for the
/// API and the UI. Every variant holds a list; a single-valued option holds one element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OptionData {
    /// IPv4 addresses.
    Ipv4 {
        /// The addresses.
        #[schema(value_type = Vec<String>)]
        values: Vec<Ipv4Addr>,
    },
    /// IPv6 addresses.
    Ipv6 {
        /// The addresses.
        #[schema(value_type = Vec<String>)]
        values: Vec<Ipv6Addr>,
    },
    /// IPv6 prefixes.
    Ipv6Prefix {
        /// The prefixes.
        #[schema(value_type = Vec<String>)]
        values: Vec<Ipv6Net>,
    },
    /// Unsigned integers (`u8`, `u16`, `u32`).
    Unsigned(Vec<u32>),
    /// A signed integer.
    Signed(i32),
    /// Booleans.
    Bool(Vec<bool>),
    /// Text.
    Text(String),
    /// Domain names.
    Names(Vec<DnsName>),
    /// Classless static routes.
    Routes(Vec<StaticRoute>),
    /// Octets.
    Binary(HexBytes),
    /// No data.
    Empty,
}

/// One classless static route (RFC 3442).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct StaticRoute {
    /// The destination.
    #[schema(value_type = String, example = "203.0.113.0/24")]
    pub destination: Ipv4Net,
    /// The router.
    #[schema(value_type = String, example = "192.0.2.1")]
    pub router: Ipv4Addr,
}

impl OptionData {
    /// Decodes wire data of `kind`.
    ///
    /// # Errors
    ///
    /// An English reason when the data does not fit `kind`.
    pub fn decode(kind: OptionKind, array: bool, data: &[u8]) -> Result<Self, &'static str> {
        kind.check(array, data)?;
        Ok(match kind {
            OptionKind::Ipv4Address => Self::Ipv4 {
                values: data
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::from(*c))
                    .collect(),
            },
            OptionKind::Ipv6Address => Self::Ipv6 {
                values: data
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|c| Ipv6Addr::from(*c))
                    .collect(),
            },
            OptionKind::Ipv6Prefix => Self::Ipv6Prefix {
                values: data
                    .as_chunks::<17>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&c[1..]);
                        let address = Ipv6Addr::from(octets);
                        let net = Ipv6Net::new(address, c[0])
                            .map_err(|_| "an IPv6 prefix length is at most 128")?;
                        // Slice 8 follow-ups: no host bits, as the check says.
                        if is_network(address, c[0]) {
                            Ok(net)
                        } else {
                            Err(HOST_BITS)
                        }
                    })
                    .collect::<Result<_, _>>()?,
            },
            OptionKind::U8 => Self::Unsigned(data.iter().map(|b| u32::from(*b)).collect()),
            OptionKind::U16 => Self::Unsigned(
                data.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u32::from(u16::from_be_bytes(*c)))
                    .collect(),
            ),
            OptionKind::U32 => Self::Unsigned(
                data.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_be_bytes(*c))
                    .collect(),
            ),
            OptionKind::I32 => {
                Self::Signed(i32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            OptionKind::Bool => Self::Bool(data.iter().map(|b| *b == 1).collect()),
            OptionKind::String => {
                Self::Text(String::from_utf8(data.to_vec()).map_err(|_| "text must be UTF-8")?)
            }
            OptionKind::Fqdn => {
                let mut names = Vec::new();
                let mut rest = data;
                while !rest.is_empty() {
                    let (text, used) = read_wire_name(rest)?;
                    names.push(DnsName::new(&text).map_err(|_| "a name is not a DNS name")?);
                    rest = &rest[used..];
                }
                Self::Names(names)
            }
            OptionKind::ClasslessRoutes => {
                let mut routes = Vec::new();
                let mut rest = data;
                while let Some((&width, tail)) = rest.split_first() {
                    let significant = usize::from(width).div_ceil(8);
                    let mut octets = [0u8; 4];
                    octets[..significant].copy_from_slice(&tail[..significant]);
                    let r = &tail[significant..significant + 4];
                    routes.push(StaticRoute {
                        // Slice 8 follow-ups: the bits after the width cleared, as the
                        // encoding and the message reader clear them (RFC 3442), so that the
                        // view encodes to data that decodes to the same view.
                        destination: Ipv4Net::new(Ipv4Addr::from(octets), width)
                            .map_err(|_| "a route's width is at most 32")?
                            .trunc(),
                        router: Ipv4Addr::new(r[0], r[1], r[2], r[3]),
                    });
                    rest = &tail[significant + 4..];
                }
                Self::Routes(routes)
            }
            OptionKind::Binary => Self::Binary(HexBytes(data.to_vec())),
            OptionKind::Empty => Self::Empty,
        })
    }

    /// Encodes the data in the wire form of `kind`.
    ///
    /// # Errors
    ///
    /// An English reason when the view does not fit `kind` (a text for an address option,
    /// a number out of range).
    pub fn encode(&self, kind: OptionKind, array: bool) -> Result<Vec<u8>, &'static str> {
        let mismatch = "the value does not fit the option type";
        let mut out = Vec::new();
        match (self, kind) {
            (Self::Ipv4 { values: list }, OptionKind::Ipv4Address) => {
                for address in list {
                    out.extend_from_slice(&address.octets());
                }
            }
            (Self::Ipv6 { values: list }, OptionKind::Ipv6Address) => {
                for address in list {
                    out.extend_from_slice(&address.octets());
                }
            }
            (Self::Ipv6Prefix { values: list }, OptionKind::Ipv6Prefix) => {
                for net in list {
                    // Slice 8 follow-ups: refused, not cut, so that it decodes as given.
                    if !is_network(net.addr(), net.prefix_len()) {
                        return Err(HOST_BITS);
                    }
                    out.push(net.prefix_len());
                    out.extend_from_slice(&net.addr().octets());
                }
            }
            (Self::Unsigned(list), OptionKind::U8 | OptionKind::U16 | OptionKind::U32) => {
                for value in list {
                    match kind {
                        OptionKind::U8 => out.push(u8::try_from(*value).map_err(|_| mismatch)?),
                        OptionKind::U16 => out.extend_from_slice(
                            &u16::try_from(*value).map_err(|_| mismatch)?.to_be_bytes(),
                        ),
                        _ => out.extend_from_slice(&value.to_be_bytes()),
                    }
                }
            }
            (Self::Signed(value), OptionKind::I32) => out.extend_from_slice(&value.to_be_bytes()),
            (Self::Bool(list), OptionKind::Bool) => out.extend(list.iter().map(|b| u8::from(*b))),
            (Self::Text(text), OptionKind::String) => out.extend_from_slice(text.as_bytes()),
            (Self::Names(names), OptionKind::Fqdn) => {
                for name in names {
                    out.extend_from_slice(&name.to_wire());
                }
            }
            (Self::Routes(routes), OptionKind::ClasslessRoutes) => {
                for route in routes {
                    let width = route.destination.prefix_len();
                    out.push(width);
                    let significant = usize::from(width).div_ceil(8);
                    out.extend_from_slice(&route.destination.network().octets()[..significant]);
                    out.extend_from_slice(&route.router.octets());
                }
            }
            (Self::Binary(bytes), OptionKind::Binary) => out.extend_from_slice(&bytes.0),
            (Self::Empty, OptionKind::Empty) => {}
            _ => return Err(mismatch),
        }
        kind.check(array, &out)?;
        Ok(out)
    }
}

/// The level an option set belongs to (plan section 2.4): the effective set for a client is
/// merged in this order, the more specific level winning per code.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OptionLevel {
    /// Every scope of the server.
    Server,
    /// The scopes of a shared network.
    SharedNetwork,
    /// One scope.
    Scope,
    /// One pool of a scope.
    Pool,
    /// The clients a policy matches.
    Policy,
    /// One reservation: the IPAM interface.
    Host,
}

/// The owner of an option set: the key of `dhcp.option_sets`. One set per owner; the set
/// of a scope is the scope's options (`Scope` has no options field of its own), the set of
/// an IPAM interface is the reservation's options (the plan's `HostOptions`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OptionOwner {
    /// The server level (`dhcp.settings`).
    Server,
    /// A shared network.
    SharedNetwork(SharedNetworkId),
    /// A scope, by its prefix.
    Scope(PrefixId),
    /// A pool, by its range.
    Pool(RangeId),
    /// A policy.
    Policy(PolicyId),
    /// A reservation, by the IPAM interface.
    Host(InterfaceId),
}

/// The reference from an object to its option set: the owner itself.
pub type OptionSetRef = OptionOwner;

impl OptionOwner {
    /// The level.
    pub const fn level(self) -> OptionLevel {
        match self {
            Self::Server => OptionLevel::Server,
            Self::SharedNetwork(_) => OptionLevel::SharedNetwork,
            Self::Scope(_) => OptionLevel::Scope,
            Self::Pool(_) => OptionLevel::Pool,
            Self::Policy(_) => OptionLevel::Policy,
            Self::Host(_) => OptionLevel::Host,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Server => 0,
            Self::SharedNetwork(_) => 1,
            Self::Scope(_) => 2,
            Self::Pool(_) => 3,
            Self::Policy(_) => 4,
            Self::Host(_) => 5,
        }
    }

    /// The owner's identifier; nil for the server level.
    pub const fn uuid(self) -> uuid::Uuid {
        match self {
            Self::Server => uuid::Uuid::nil(),
            Self::SharedNetwork(id) => id.0,
            Self::Scope(id) => id.0,
            Self::Pool(id) => id.0,
            Self::Policy(id) => id.0,
            Self::Host(id) => id.0,
        }
    }

    /// The text form of the API path: `server`, `shared_network:<id>`, `scope:<prefix>`,
    /// `pool:<range>`, `policy:<id>`, `host:<interface>`.
    pub fn to_path(self) -> String {
        match self {
            Self::Server => "server".to_owned(),
            other => format!("{}:{}", level_name(other.level()), other.uuid()),
        }
    }

    /// Parses the text form of [`OptionOwner::to_path`].
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the text is not an owner.
    pub fn from_path(text: &str) -> Result<Self, InvalidValue> {
        let invalid = || InvalidValue::new("option owner", text, "not an option set owner");
        if text == "server" {
            return Ok(Self::Server);
        }
        let (level, id) = text.split_once(':').ok_or_else(invalid)?;
        let id: uuid::Uuid = id.parse().map_err(|_| invalid())?;
        Ok(match level {
            "shared_network" => Self::SharedNetwork(SharedNetworkId(id)),
            "scope" => Self::Scope(PrefixId(id)),
            "pool" => Self::Pool(RangeId(id)),
            "policy" => Self::Policy(PolicyId(id)),
            "host" => Self::Host(InterfaceId(id)),
            _ => return Err(invalid()),
        })
    }
}

const fn level_name(level: OptionLevel) -> &'static str {
    match level {
        OptionLevel::Server => "server",
        OptionLevel::SharedNetwork => "shared_network",
        OptionLevel::Scope => "scope",
        OptionLevel::Pool => "pool",
        OptionLevel::Policy => "policy",
        OptionLevel::Host => "host",
    }
}

impl KeyCodec for OptionOwner {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.tag().encode_key(out);
        self.uuid().encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let tag = u8::decode_key(input)?;
        let id = uuid::Uuid::decode_key(input)?;
        Ok(match tag {
            0 => Self::Server,
            1 => Self::SharedNetwork(SharedNetworkId(id)),
            2 => Self::Scope(PrefixId(id)),
            3 => Self::Pool(RangeId(id)),
            4 => Self::Policy(PolicyId(id)),
            5 => Self::Host(InterfaceId(id)),
            _ => return Err(KeyError::Invalid("option owner")),
        })
    }
}

/// The options of one owner (`dhcp.option_sets`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OptionSet {
    /// The owner, which is also the key.
    pub owner: OptionOwner,
    /// The values, at most one per space and code, in the order the operator gave them.
    #[serde(default)]
    pub values: Vec<OptionValue>,
    /// Last change.
    pub updated: Stamp,
}

impl OptionSet {
    /// The level.
    pub fn level(&self) -> OptionLevel {
        self.owner.level()
    }

    /// Checks the set: at most [`MAX_OPTIONS_PER_SET`] values, no space and code twice,
    /// every value valid against the catalog and `defs`.
    ///
    /// # Errors
    ///
    /// The first value's error, or `dhcp.option.invalid` for a duplicate.
    pub fn validate(&self, defs: &[OptionDef]) -> Result<(), DhcpError> {
        if self.values.len() > MAX_OPTIONS_PER_SET {
            return Err(DhcpError::invalid(
                codes::OPTION_INVALID,
                "values",
                "at most 256 options per set",
            ));
        }
        for (index, value) in self.values.iter().enumerate() {
            if self.values[..index]
                .iter()
                .any(|other| other.space == value.space && other.code == value.code)
            {
                return Err(DhcpError::invalid(
                    codes::OPTION_INVALID,
                    "values",
                    "an option appears twice",
                ));
            }
            value.validate(defs)?;
        }
        Ok(())
    }
}

/// Merges option sets from the least to the most specific level: a later set replaces an
/// option of the same space and code, and new codes keep their order. The effective set of
/// a client is `merge([server, shared network, scope, pool, policies..., host])`; the
/// configuration image precompiles the first four per scope (plan section 2.4).
pub fn merge<'a>(sets: impl IntoIterator<Item = &'a [OptionValue]>) -> Vec<OptionValue> {
    let mut merged: Vec<OptionValue> = Vec::new();
    for set in sets {
        for value in set {
            match merged
                .iter_mut()
                .find(|held| held.space == value.space && held.code == value.code)
            {
                Some(held) => held.clone_from(value),
                None => merged.push(value.clone()),
            }
        }
    }
    merged
}
