//! The typed DHCPv6 options: each is a view that checks its format once in `parse` and then
//! reads without failing; an option with the wrong length or format is
//! [`DecodeError::BadLength`] or [`DecodeError::BadValue`] with its code, and the walk and
//! the other options are not affected.

use std::{fmt, net::Ipv6Addr};

use super::{DecodeError, addr_at, code, message::Options, u16_at, u32_at};
use crate::v4::WireName;

/// The value of an option of exactly `N` octets.
pub(crate) fn fixed<const N: usize>(code: u16, data: &[u8]) -> Result<[u8; N], DecodeError> {
    <[u8; N]>::try_from(data).map_err(|_| DecodeError::BadLength {
        code,
        len: data.len(),
    })
}

/// A DUID (RFC 8415 section 11): a two-octet type and 1 to 128 octets of identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Duid<'a> {
    data: &'a [u8],
}

impl<'a> Duid<'a> {
    /// DUID-LLT: a hardware type, a time and a link-layer address (section 11.2).
    pub const LLT: u16 = 1;
    /// DUID-EN: an enterprise number and an identifier (section 11.3).
    pub const EN: u16 = 2;
    /// DUID-LL: a hardware type and a link-layer address (section 11.4).
    pub const LL: u16 = 3;
    /// DUID-UUID (RFC 6355): a UUID.
    pub const UUID: u16 = 4;

    /// The shortest DUID: its type and one octet.
    pub const MIN_LEN: usize = 3;
    /// The longest DUID: its type and 128 octets.
    pub const MAX_LEN: usize = 130;

    /// The DUID in the value of option `code` (1 or 2).
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] outside 3 to 130 octets.
    pub fn parse(code: u16, data: &'a [u8]) -> Result<Self, DecodeError> {
        if (Self::MIN_LEN..=Self::MAX_LEN).contains(&data.len()) {
            Ok(Self { data })
        } else {
            Err(DecodeError::BadLength {
                code,
                len: data.len(),
            })
        }
    }

    /// The DUID with its type, as on the wire.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The DUID type.
    pub fn kind(&self) -> u16 {
        u16_at(self.data, 0)
    }

    /// The octets after the type.
    pub fn body(&self) -> &'a [u8] {
        &self.data[2..]
    }

    /// The hardware type and link-layer address of a DUID-LLT (at least eight octets) or
    /// a DUID-LL (at least four).
    pub fn link_layer(&self) -> Option<(u16, &'a [u8])> {
        let start = match self.kind() {
            Self::LLT => 8,
            Self::LL => 4,
            _ => return None,
        };
        let address = self.data.get(start..)?;
        (!address.is_empty()).then(|| (u16_at(self.data, 2), address))
    }

    /// The time of a DUID-LLT: seconds since midnight UTC, 1 January 2000.
    pub fn time(&self) -> Option<u32> {
        (self.kind() == Self::LLT && self.data.len() >= 8).then(|| u32_at(self.data, 4))
    }

    /// The enterprise number of a DUID-EN.
    pub fn enterprise(&self) -> Option<u32> {
        (self.kind() == Self::EN && self.data.len() >= 6).then(|| u32_at(self.data, 2))
    }

    /// The UUID of a DUID-UUID (exactly 16 octets after the type).
    pub fn uuid(&self) -> Option<[u8; 16]> {
        if self.kind() == Self::UUID {
            <[u8; 16]>::try_from(self.body()).ok()
        } else {
            None
        }
    }
}

impl fmt::Debug for Duid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Duid(")?;
        for (index, octet) in self.data.iter().enumerate() {
            if index > 0 {
                f.write_str(":")?;
            }
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// A Status Code option (RFC 8415 section 21.13): a code and a message in UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode<'a> {
    /// The code (`status::*`).
    pub code: u16,
    /// The message, as sent.
    pub message: &'a [u8],
}

impl<'a> StatusCode<'a> {
    /// The status in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below two octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 2 {
            return Err(DecodeError::BadLength {
                code: code::STATUS_CODE,
                len: data.len(),
            });
        }
        Ok(Self {
            code: u16_at(data, 0),
            message: &data[2..],
        })
    }
}

/// The status of an option area: its first Status Code option, when it has a well-formed
/// one.
fn status_of(options: Options<'_>) -> Option<StatusCode<'_>> {
    options
        .first(code::STATUS_CODE)
        .ok()
        .flatten()
        .and_then(|data| StatusCode::parse(data).ok())
}

/// An `IA_NA` option (RFC 8415 section 21.4): the IAID, T1, T2 and its options (the
/// addresses and a status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaNa<'a> {
    /// The identity association's identifier.
    pub iaid: u32,
    /// T1 in seconds.
    pub t1: u32,
    /// T2 in seconds.
    pub t2: u32,
    options: &'a [u8],
}

impl<'a> IaNa<'a> {
    /// The `IA_NA` in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 12 octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 12 {
            return Err(DecodeError::BadLength {
                code: code::IA_NA,
                len: data.len(),
            });
        }
        Ok(Self {
            iaid: u32_at(data, 0),
            t1: u32_at(data, 4),
            t2: u32_at(data, 8),
            options: &data[12..],
        })
    }

    /// Its options.
    pub fn options(&self) -> Options<'a> {
        Options::new(self.options)
    }

    /// Its IA Address options in order; a malformed one is yielded as an error and ends
    /// the walk.
    pub fn addresses(&self) -> impl Iterator<Item = Result<IaAddress<'a>, DecodeError>> + 'a {
        super::message::of_code(self.options(), code::IAADDR, IaAddress::parse)
    }

    /// Its status.
    pub fn status(&self) -> Option<StatusCode<'a>> {
        status_of(self.options())
    }
}

/// An IA Address option (RFC 8415 section 21.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaAddress<'a> {
    /// The address.
    pub addr: Ipv6Addr,
    /// The preferred lifetime in seconds.
    pub preferred: u32,
    /// The valid lifetime in seconds.
    pub valid: u32,
    options: &'a [u8],
}

impl<'a> IaAddress<'a> {
    /// The address in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 24 octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 24 {
            return Err(DecodeError::BadLength {
                code: code::IAADDR,
                len: data.len(),
            });
        }
        Ok(Self {
            addr: addr_at(data, 0),
            preferred: u32_at(data, 16),
            valid: u32_at(data, 20),
            options: &data[24..],
        })
    }

    /// Its options.
    pub fn options(&self) -> Options<'a> {
        Options::new(self.options)
    }

    /// Its status.
    pub fn status(&self) -> Option<StatusCode<'a>> {
        status_of(self.options())
    }
}

/// An `IA_PD` option (RFC 8415 section 21.21): read by the codec, served by WP9.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaPd<'a> {
    /// The identity association's identifier.
    pub iaid: u32,
    /// T1 in seconds.
    pub t1: u32,
    /// T2 in seconds.
    pub t2: u32,
    options: &'a [u8],
}

impl<'a> IaPd<'a> {
    /// The `IA_PD` in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 12 octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 12 {
            return Err(DecodeError::BadLength {
                code: code::IA_PD,
                len: data.len(),
            });
        }
        Ok(Self {
            iaid: u32_at(data, 0),
            t1: u32_at(data, 4),
            t2: u32_at(data, 8),
            options: &data[12..],
        })
    }

    /// Its options.
    pub fn options(&self) -> Options<'a> {
        Options::new(self.options)
    }

    /// Its IA Prefix options in order.
    pub fn prefixes(&self) -> impl Iterator<Item = Result<IaPrefix<'a>, DecodeError>> + 'a {
        super::message::of_code(self.options(), code::IAPREFIX, IaPrefix::parse)
    }

    /// Its status.
    pub fn status(&self) -> Option<StatusCode<'a>> {
        status_of(self.options())
    }
}

/// An IA Prefix option (RFC 8415 section 21.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaPrefix<'a> {
    /// The preferred lifetime in seconds.
    pub preferred: u32,
    /// The valid lifetime in seconds.
    pub valid: u32,
    /// The prefix length, 0 to 128.
    pub prefix_len: u8,
    /// The prefix.
    pub prefix: Ipv6Addr,
    options: &'a [u8],
}

impl<'a> IaPrefix<'a> {
    /// The prefix in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 25 octets, [`DecodeError::BadValue`] for a prefix
    /// length above 128.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 25 {
            return Err(DecodeError::BadLength {
                code: code::IAPREFIX,
                len: data.len(),
            });
        }
        let prefix_len = data[8];
        if prefix_len > 128 {
            return Err(DecodeError::BadValue {
                code: code::IAPREFIX,
            });
        }
        Ok(Self {
            preferred: u32_at(data, 0),
            valid: u32_at(data, 4),
            prefix_len,
            prefix: addr_at(data, 9),
            options: &data[25..],
        })
    }

    /// Its options.
    pub fn options(&self) -> Options<'a> {
        Options::new(self.options)
    }
}

/// The Option Request option (RFC 8415 section 21.7): the codes the client asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionRequest<'a> {
    data: &'a [u8],
}

impl<'a> OptionRequest<'a> {
    /// The list in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an odd length.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len().is_multiple_of(2) {
            Ok(Self { data })
        } else {
            Err(DecodeError::BadLength {
                code: code::ORO,
                len: data.len(),
            })
        }
    }

    /// The codes in the client's order.
    pub fn codes(self) -> impl Iterator<Item = u16> + 'a {
        self.data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
    }

    /// Whether the client asks for `code`.
    pub fn contains(&self, code: u16) -> bool {
        self.codes().any(|asked| asked == code)
    }

    /// The number of codes.
    pub fn len(&self) -> usize {
        self.data.len() / 2
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The Client FQDN option of RFC 4704: the flags (S, O, N) and a domain name in the
/// uncompressed wire encoding, fully qualified or partial (without the root label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFqdn<'a> {
    flags: u8,
    name: &'a [u8],
}

impl<'a> ClientFqdn<'a> {
    /// S: the server performs the AAAA update (RFC 4704 section 4.1).
    pub const FLAG_S: u8 = 0x01;
    /// O: the server overrode the client's S flag.
    pub const FLAG_O: u8 = 0x02;
    /// N: the server performs no update.
    pub const FLAG_N: u8 = 0x04;

    /// The option in `data`; the name is checked.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an empty value, [`DecodeError::BadValue`] for a name
    /// that does not decode.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        let [flags, name @ ..] = data else {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_FQDN,
                len: 0,
            });
        };
        if !name.is_empty() && WireName::from_wire(name).is_none() {
            return Err(DecodeError::BadValue {
                code: code::CLIENT_FQDN,
            });
        }
        Ok(Self {
            flags: *flags,
            name,
        })
    }

    /// The flags octet.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Flag S: the client asks the server to update the AAAA record.
    pub fn server_updates(&self) -> bool {
        self.flags & Self::FLAG_S != 0
    }

    /// Flag N: the client asks the server not to update any record.
    pub fn no_update(&self) -> bool {
        self.flags & Self::FLAG_N != 0
    }

    /// The name; empty when the client leaves the name to the server.
    pub fn name(&self) -> WireName {
        WireName::from_wire(self.name).unwrap_or_default()
    }

    /// The name as it was sent.
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// The flags in the layout of RFC 4702's option 81 (S 0x01, O 0x02, E 0x04, N 0x08),
    /// so that the DDNS rules of DHCPv4 read them: S and O stay, N moves to 0x08, and E
    /// (a DHCPv4 encoding flag) is set, since the name is always in the wire encoding.
    pub fn flags_v4(&self) -> u8 {
        flags_to_v4(self.flags)
    }
}

/// Option 39's flags in the layout of option 81 (see [`ClientFqdn::flags_v4`]).
pub fn flags_to_v4(flags: u8) -> u8 {
    let mut out = flags & (ClientFqdn::FLAG_S | ClientFqdn::FLAG_O);
    if flags & ClientFqdn::FLAG_N != 0 {
        out |= crate::v4::ClientFqdn::FLAG_N;
    }
    out | crate::v4::ClientFqdn::FLAG_E
}

/// Option 81's flags in the layout of option 39: S and O stay, N moves to 0x04, E goes.
pub fn flags_from_v4(flags: u8) -> u8 {
    let mut out = flags & (ClientFqdn::FLAG_S | ClientFqdn::FLAG_O);
    if flags & crate::v4::ClientFqdn::FLAG_N != 0 {
        out |= ClientFqdn::FLAG_N;
    }
    out
}

/// The Client Link-Layer Address option of RFC 6939: a hardware type (the ARP hardware
/// types, 1 for Ethernet) and the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkLayerAddress<'a> {
    /// The hardware type.
    pub kind: u16,
    /// The address.
    pub address: &'a [u8],
}

impl<'a> LinkLayerAddress<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below three octets (a type and one octet).
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 3 {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_LINKLAYER_ADDR,
                len: data.len(),
            });
        }
        Ok(Self {
            kind: u16_at(data, 0),
            address: &data[2..],
        })
    }

    /// The Ethernet address, when the type is 1 and the address six octets.
    pub fn mac(&self) -> Option<[u8; 6]> {
        if self.kind == 1 {
            <[u8; 6]>::try_from(self.address).ok()
        } else {
            None
        }
    }
}

/// A list of IPv6 addresses (options 23, 31, 22): a multiple of 16 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrList<'a> {
    data: &'a [u8],
}

impl<'a> AddrList<'a> {
    /// The list in the value of option `code`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for a length that is not a multiple of 16.
    pub fn parse(code: u16, data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len().is_multiple_of(16) {
            Ok(Self { data })
        } else {
            Err(DecodeError::BadLength {
                code,
                len: data.len(),
            })
        }
    }

    /// The addresses in order.
    pub fn iter(&self) -> impl Iterator<Item = Ipv6Addr> + 'a {
        self.data
            .as_chunks::<16>()
            .0
            .iter()
            .map(|chunk| Ipv6Addr::from(*chunk))
    }

    /// The number of addresses.
    pub fn len(&self) -> usize {
        self.data.len() / 16
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The names of a domain list (option 24, RFC 3646 section 4; also option 21): names in
/// the uncompressed wire encoding, one after the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainList<'a> {
    data: &'a [u8],
}

/// The length of the wire name at the start of `data`, root label included.
fn name_len(data: &[u8]) -> Option<usize> {
    let mut at = 0;
    loop {
        let len = usize::from(*data.get(at)?);
        if len == 0 {
            return Some(at + 1);
        }
        if len > 63 {
            return None;
        }
        at += 1 + len;
        if at > 255 {
            return None;
        }
    }
}

impl<'a> DomainList<'a> {
    /// The list in the value of option `code`: every name ends with the root label.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] for a name that does not decode or does not end.
    pub fn parse(code: u16, data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut rest = data;
        while !rest.is_empty() {
            let len = name_len(rest).ok_or(DecodeError::BadValue { code })?;
            WireName::from_wire(&rest[..len]).ok_or(DecodeError::BadValue { code })?;
            rest = &rest[len..];
        }
        Ok(Self { data })
    }

    /// The names in order.
    pub fn iter(&self) -> impl Iterator<Item = WireName> + 'a {
        let mut rest = self.data;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let len = name_len(rest)?;
            let name = WireName::from_wire(&rest[..len]);
            rest = &rest[len..];
            name
        })
    }

    /// The value as sent.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// One sub-option of the NTP Server option (RFC 5908 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpSuboption<'a> {
    /// `NTP_SUBOPTION_SRV_ADDR` (1): a server's unicast address.
    ServerAddress(Ipv6Addr),
    /// `NTP_SUBOPTION_MC_ADDR` (2): a multicast address.
    MulticastAddress(Ipv6Addr),
    /// `NTP_SUBOPTION_SRV_FQDN` (3): a server's name in the wire encoding, as sent
    /// (`WireName::from_wire` reads it).
    ServerName(&'a [u8]),
    /// Any other sub-option.
    Other(u16),
}

/// The NTP Server option (RFC 5908): sub-options naming time servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpServer<'a> {
    data: &'a [u8],
}

impl<'a> NtpServer<'a> {
    /// `NTP_SUBOPTION_SRV_ADDR`.
    pub const SRV_ADDR: u16 = 1;
    /// `NTP_SUBOPTION_MC_ADDR`.
    pub const MC_ADDR: u16 = 2;
    /// `NTP_SUBOPTION_SRV_FQDN`.
    pub const SRV_FQDN: u16 = 3;

    /// The option in `data`: every sub-option ends inside the value, the address
    /// sub-options are 16 octets and the name one decodes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] for a sub-option that does not.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        let bad = DecodeError::BadValue {
            code: code::NTP_SERVER,
        };
        for sub in Options::new(data) {
            let sub = sub.map_err(|_| bad)?;
            let ok = match sub.code {
                Self::SRV_ADDR | Self::MC_ADDR => sub.data.len() == 16,
                // RFC 5908 section 4.3: a fully qualified name.
                Self::SRV_FQDN => WireName::from_wire(sub.data)
                    .is_some_and(|name| name.is_absolute() && !name.is_empty()),
                _ => true,
            };
            if !ok {
                return Err(bad);
            }
        }
        Ok(Self { data })
    }

    /// The sub-options in order.
    pub fn suboptions(&self) -> impl Iterator<Item = NtpSuboption<'a>> + 'a {
        Options::new(self.data).flatten().map(|sub| match sub.code {
            Self::SRV_ADDR => NtpSuboption::ServerAddress(addr_at(sub.data, 0)),
            Self::MC_ADDR => NtpSuboption::MulticastAddress(addr_at(sub.data, 0)),
            Self::SRV_FQDN => NtpSuboption::ServerName(sub.data),
            other => NtpSuboption::Other(other),
        })
    }
}

/// The Relay Agent Remote-ID option (RFC 4649): an enterprise number and an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteId<'a> {
    /// The enterprise number.
    pub enterprise: u32,
    /// The identifier.
    pub id: &'a [u8],
    data: &'a [u8],
}

impl<'a> RemoteId<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below five octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 5 {
            return Err(DecodeError::BadLength {
                code: code::REMOTE_ID,
                len: data.len(),
            });
        }
        Ok(Self {
            enterprise: u32_at(data, 0),
            id: &data[4..],
            data,
        })
    }

    /// The whole value, as the lease keeps it.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// A list of opaque values each with a two-octet length (the User Class option, RFC 8415
/// section 21.15, and the data of a Vendor Class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthPrefixed<'a> {
    data: &'a [u8],
}

impl<'a> LengthPrefixed<'a> {
    /// The list in the value of option `code`: every item ends inside the value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] for an item that runs past the end.
    pub fn parse(code: u16, data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut rest = data;
        while !rest.is_empty() {
            if rest.len() < 2 {
                return Err(DecodeError::BadValue { code });
            }
            let len = usize::from(u16_at(rest, 0));
            rest = rest.get(2 + len..).ok_or(DecodeError::BadValue { code })?;
        }
        Ok(Self { data })
    }

    /// The items in order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut rest = self.data;
        std::iter::from_fn(move || {
            if rest.len() < 2 {
                return None;
            }
            let len = usize::from(u16_at(rest, 0));
            let item = rest.get(2..2 + len)?;
            rest = &rest[2 + len..];
            Some(item)
        })
    }

    /// The value as sent.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// The Vendor Class option (RFC 8415 section 21.16): an enterprise number and the classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorClass<'a> {
    /// The enterprise number.
    pub enterprise: u32,
    /// The classes.
    pub classes: LengthPrefixed<'a>,
}

impl<'a> VendorClass<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below four octets, [`DecodeError::BadValue`] for a class
    /// that runs past the end.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 4 {
            return Err(DecodeError::BadLength {
                code: code::VENDOR_CLASS,
                len: data.len(),
            });
        }
        Ok(Self {
            enterprise: u32_at(data, 0),
            classes: LengthPrefixed::parse(code::VENDOR_CLASS, &data[4..])?,
        })
    }
}
