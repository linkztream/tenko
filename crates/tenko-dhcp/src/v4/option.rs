//! Typed option values: views over an option's value that check its format once in
//! `parse` and then read it without failing.

use std::net::Ipv4Addr;

use super::{DecodeError, WireName, code};

/// Option 53, the DHCP message type (RFC 2131, section 3.1; RFC 2132, section 9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// 1, a client looks for servers.
    Discover,
    /// 2, a server offers an address.
    Offer,
    /// 3, a client requests the offered address, or renews or rebinds.
    Request,
    /// 4, a client found the address in use.
    Decline,
    /// 5, a server commits the lease.
    Ack,
    /// 6, a server refuses the request.
    Nak,
    /// 7, a client gives the address back.
    Release,
    /// 8, a client with an address asks for its configuration only.
    Inform,
    /// Any other type: FORCERENEW (9, RFC 3203), the leasequery types (10 to 13, RFC 4388),
    /// the bulk leasequery types (14 to 18, RFC 6926) and unassigned values.
    Other(u8),
}

impl MessageType {
    /// The value on the wire.
    pub fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
            Self::Other(value) => value,
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// A list of IPv4 addresses (options 3, 6, 42 and the others of RFC 2132 that carry one or
/// more addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrList<'a> {
    data: &'a [u8],
}

impl<'a> AddrList<'a> {
    /// The list in the value of option `code`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] unless the length is a non-zero multiple of 4.
    pub fn parse(code: u8, data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.is_empty() || !data.len().is_multiple_of(4) {
            return Err(DecodeError::BadLength {
                code,
                len: data.len(),
            });
        }
        Ok(Self { data })
    }

    /// The addresses in order.
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + 'a {
        self.data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&octets| Ipv4Addr::from(octets))
    }

    /// The first address.
    pub fn first(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[0], self.data[1], self.data[2], self.data[3])
    }

    /// The number of addresses (at least one).
    pub fn len(&self) -> usize {
        self.data.len() / 4
    }

    /// Always `false`: the list has at least one address.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The value as it is on the wire.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// Option 61, the client identifier (RFC 2132, section 9.14): a type octet and the
/// identifier. Type 255 is the RFC 4361 form, an IAID and a DHCPv6 DUID; types 1 to 254 are
/// a hardware type and address; type 0 is anything else (a name, for example).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId<'a> {
    data: &'a [u8],
}

impl<'a> ClientId<'a> {
    /// The type octet that marks the RFC 4361 form.
    pub const TYPE_DUID: u8 = 255;

    /// The client identifier in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 2 octets, or below 7 octets for type 255 (the
    /// type, a four-octet IAID and at least the DUID type).
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        let short = match data.first() {
            Some(&Self::TYPE_DUID) => data.len() < 7,
            _ => data.len() < 2,
        };
        if short {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_IDENTIFIER,
                len: data.len(),
            });
        }
        Ok(Self { data })
    }

    /// The whole value, the key a reservation by client identifier compares.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The type octet.
    pub fn kind(&self) -> u8 {
        self.data[0]
    }

    /// The hardware type and address, for types 1 to 254.
    pub fn hardware(&self) -> Option<(u8, &'a [u8])> {
        match self.kind() {
            0 | Self::TYPE_DUID => None,
            htype => Some((htype, &self.data[1..])),
        }
    }

    /// The IAID and the DUID of the RFC 4361 form (type 255).
    pub fn iaid_duid(&self) -> Option<(u32, Duid<'a>)> {
        (self.kind() == Self::TYPE_DUID).then(|| {
            (
                u32_at(self.data, 1),
                Duid {
                    data: &self.data[5..],
                },
            )
        })
    }
}

/// A DHCPv6 DUID (RFC 8415, section 11) as carried by option 61 of RFC 4361.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Duid<'a> {
    data: &'a [u8],
}

impl<'a> Duid<'a> {
    /// DUID-LLT: link-layer address plus time.
    pub const LLT: u16 = 1;
    /// DUID-EN: an enterprise number and an identifier.
    pub const EN: u16 = 2;
    /// DUID-LL: link-layer address.
    pub const LL: u16 = 3;
    /// DUID-UUID (RFC 6355).
    pub const UUID: u16 = 4;

    /// The DUID as it is on the wire, with its type.
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

    /// The enterprise number of a DUID-EN.
    pub fn enterprise(&self) -> Option<u32> {
        (self.kind() == Self::EN && self.data.len() >= 6).then(|| u32_at(self.data, 2))
    }

    /// The hardware type and link-layer address of a DUID-LLT or DUID-LL.
    pub fn link_layer(&self) -> Option<(u16, &'a [u8])> {
        let start = match self.kind() {
            Self::LLT => 8,
            Self::LL => 4,
            _ => return None,
        };
        (self.data.len() > start).then(|| (u16_at(self.data, 2), &self.data[start..]))
    }
}

/// Option 81, the client FQDN (RFC 4702): the flags, the two deprecated RCODE octets and
/// the name in the canonical wire encoding (flag E) or the deprecated ASCII encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFqdn<'a> {
    flags: u8,
    rcode1: u8,
    rcode2: u8,
    name: &'a [u8],
}

impl<'a> ClientFqdn<'a> {
    /// S: the server performs the A record update (RFC 4702, section 2.1).
    pub const FLAG_S: u8 = 0x01;
    /// O: the server overrode the client's S flag.
    pub const FLAG_O: u8 = 0x02;
    /// E: the name is in the canonical wire encoding.
    pub const FLAG_E: u8 = 0x04;
    /// N: the server performs no update at all.
    pub const FLAG_N: u8 = 0x08;

    /// The option in `data`; the name is checked in its encoding.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 3 octets, [`DecodeError::BadValue`] for a name that
    /// does not decode.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        let [flags, rcode1, rcode2, name @ ..] = data else {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_FQDN,
                len: data.len(),
            });
        };
        let fqdn = Self {
            flags: *flags,
            rcode1: *rcode1,
            rcode2: *rcode2,
            name,
        };
        fqdn.decode().ok_or(DecodeError::BadValue {
            code: code::CLIENT_FQDN,
        })?;
        Ok(fqdn)
    }

    fn decode(&self) -> Option<WireName> {
        if self.encoded() {
            WireName::from_wire(self.name)
        } else {
            // Some clients end the ASCII name with a zero octet.
            let end = self
                .name
                .iter()
                .rposition(|&b| b != 0)
                .map_or(0, |last| last + 1);
            WireName::from_text(&self.name[..end])
        }
    }

    /// The flags octet.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Flag S: the client asks the server to update the A record.
    pub fn server_updates(&self) -> bool {
        self.flags & Self::FLAG_S != 0
    }

    /// Flag O: the server overrode the client's S flag (set by servers only).
    pub fn overridden(&self) -> bool {
        self.flags & Self::FLAG_O != 0
    }

    /// Flag E: the name is in the canonical wire encoding.
    pub fn encoded(&self) -> bool {
        self.flags & Self::FLAG_E != 0
    }

    /// Flag N: the client asks the server not to update any record.
    pub fn no_update(&self) -> bool {
        self.flags & Self::FLAG_N != 0
    }

    /// The first RCODE octet (deprecated; 0 from clients, 255 from servers).
    pub fn rcode1(&self) -> u8 {
        self.rcode1
    }

    /// The second RCODE octet (deprecated; 0 from clients, 255 from servers).
    pub fn rcode2(&self) -> u8 {
        self.rcode2
    }

    /// The name octets as sent.
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// The name: absolute when the client sent a fully qualified name, relative (a partial
    /// name the server completes) otherwise, empty when the client leaves the name to the
    /// server.
    pub fn name(&self) -> WireName {
        self.decode().unwrap_or_default()
    }
}

/// Code, length and value triples without pad or end: the sub-options of option 82 (RFC
/// 3046) and of the vendor data in option 125 (RFC 3925) and option 43.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubOptions<'a> {
    data: &'a [u8],
}

impl<'a> SubOptions<'a> {
    /// The sub-options in `data`, the value of option `code`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] when a sub-option runs past the end.
    pub fn parse(code: u8, data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        while pos < data.len() {
            let len = data.get(pos + 1).ok_or(DecodeError::BadValue { code })?;
            pos += 2 + usize::from(*len);
        }
        if pos != data.len() {
            return Err(DecodeError::BadValue { code });
        }
        Ok(Self { data })
    }

    /// The value of the first sub-option `code`.
    pub fn get(&self, code: u8) -> Option<&'a [u8]> {
        self.into_iter()
            .find_map(|(sub, value)| (sub == code).then_some(value))
    }

    /// The value as it is on the wire.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> IntoIterator for SubOptions<'a> {
    type Item = (u8, &'a [u8]);
    type IntoIter = SubOptionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SubOptionIter { rest: self.data }
    }
}

/// The iterator of [`SubOptions`]: code and value.
#[derive(Debug, Clone)]
pub struct SubOptionIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SubOptionIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let [code, len, rest @ ..] = self.rest else {
            return None;
        };
        let value = rest.get(..usize::from(*len))?;
        self.rest = &rest[value.len()..];
        Some((*code, value))
    }
}

/// Option 82, the relay agent information (RFC 3046): the sub-options a relay agent adds,
/// which the server echoes in its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAgentInfo<'a> {
    sub_options: SubOptions<'a>,
}

impl<'a> RelayAgentInfo<'a> {
    /// Agent circuit ID (RFC 3046, section 3.1).
    pub const CIRCUIT_ID: u8 = 1;
    /// Agent remote ID (RFC 3046, section 3.2).
    pub const REMOTE_ID: u8 = 2;
    /// Link selection (RFC 3527).
    pub const LINK_SELECTION: u8 = 5;
    /// Subscriber ID (RFC 3993).
    pub const SUBSCRIBER_ID: u8 = 6;
    /// Server identifier override (RFC 5107).
    pub const SERVER_ID_OVERRIDE: u8 = 11;
    /// Relay agent identifier (RFC 6925).
    pub const RELAY_ID: u8 = 12;

    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an empty value, [`DecodeError::BadValue`] for a
    /// sub-option that runs past the end or a link selection or server identifier override
    /// that is not four octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        const CODE: u8 = code::RELAY_AGENT_INFORMATION;
        if data.is_empty() {
            return Err(DecodeError::BadLength { code: CODE, len: 0 });
        }
        let sub_options = SubOptions::parse(CODE, data)?;
        let addresses_ok = sub_options.into_iter().all(|(sub, value)| {
            !matches!(sub, Self::LINK_SELECTION | Self::SERVER_ID_OVERRIDE) || value.len() == 4
        });
        if !addresses_ok {
            return Err(DecodeError::BadValue { code: CODE });
        }
        Ok(Self { sub_options })
    }

    /// The sub-options in order.
    pub fn sub_options(&self) -> SubOptions<'a> {
        self.sub_options
    }

    /// The whole value, which the server copies into its reply.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.sub_options.as_bytes()
    }

    /// Sub-option 1, the agent circuit ID.
    pub fn circuit_id(&self) -> Option<&'a [u8]> {
        self.sub_options.get(Self::CIRCUIT_ID)
    }

    /// Sub-option 2, the agent remote ID.
    pub fn remote_id(&self) -> Option<&'a [u8]> {
        self.sub_options.get(Self::REMOTE_ID)
    }

    /// Sub-option 5, the link selection: the subnet the client is on (RFC 3527).
    pub fn link_selection(&self) -> Option<Ipv4Addr> {
        self.address(Self::LINK_SELECTION)
    }

    /// Sub-option 6, the subscriber ID (RFC 3993).
    pub fn subscriber_id(&self) -> Option<&'a [u8]> {
        self.sub_options.get(Self::SUBSCRIBER_ID)
    }

    /// Sub-option 11, the server identifier override (RFC 5107).
    pub fn server_id_override(&self) -> Option<Ipv4Addr> {
        self.address(Self::SERVER_ID_OVERRIDE)
    }

    /// Sub-option 12, the relay agent identifier (RFC 6925).
    pub fn relay_id(&self) -> Option<&'a [u8]> {
        self.sub_options.get(Self::RELAY_ID)
    }

    fn address(&self, code: u8) -> Option<Ipv4Addr> {
        let value = self.sub_options.get(code)?;
        let octets: [u8; 4] = value.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }
}

/// Instances of one length octet and that many octets: the classes of option 77 (RFC 3004)
/// and of the vendor class data in option 124 (RFC 3925).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthPrefixed<'a> {
    data: &'a [u8],
}

impl<'a> LengthPrefixed<'a> {
    /// The instances in `data`, or `None` when `data` is empty, an instance is empty or
    /// one runs past the end.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut pos = 0;
        while pos < data.len() {
            let len = usize::from(data[pos]);
            if len == 0 {
                return None;
            }
            pos += 1 + len;
        }
        (!data.is_empty() && pos == data.len()).then_some(Self { data })
    }
}

impl<'a> IntoIterator for LengthPrefixed<'a> {
    type Item = &'a [u8];
    type IntoIter = LengthPrefixedIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        LengthPrefixedIter { rest: self.data }
    }
}

/// The iterator of [`LengthPrefixed`].
#[derive(Debug, Clone)]
pub struct LengthPrefixedIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for LengthPrefixedIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (len, rest) = self.rest.split_first()?;
        let value = rest.get(..usize::from(*len))?;
        self.rest = &rest[value.len()..];
        Some(value)
    }
}

/// Option 77, the user class (RFC 3004). The RFC form is a list of length-prefixed
/// classes; many clients (Windows among them) send one plain string instead, so both are
/// kept: [`UserClass::as_bytes`] is the value as sent and [`UserClass::classes`] the RFC
/// form when the value follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserClass<'a> {
    data: &'a [u8],
}

impl<'a> UserClass<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an empty value.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::BadLength {
                code: code::USER_CLASS,
                len: 0,
            });
        }
        Ok(Self { data })
    }

    /// The value as sent.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The classes of the RFC 3004 form, or `None` when the value does not follow it.
    pub fn classes(&self) -> Option<LengthPrefixed<'a>> {
        LengthPrefixed::parse(self.data)
    }
}

/// Option 93, the client system architectures (RFC 4578, section 2.1; the IANA registry):
/// 0 BIOS x86, 6 EFI IA32, 7 EFI x86-64, 9 EFI x86-64, 11 EFI ARM 64-bit, 16 EFI x86-64
/// HTTP boot, among others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Architectures<'a> {
    data: &'a [u8],
}

impl<'a> Architectures<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] unless the length is a non-zero multiple of 2.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.is_empty() || !data.len().is_multiple_of(2) {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_ARCHITECTURE,
                len: data.len(),
            });
        }
        Ok(Self { data })
    }

    /// The architecture types in order.
    pub fn iter(&self) -> impl Iterator<Item = u16> + 'a {
        self.data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&octets| u16::from_be_bytes(octets))
    }

    /// The first architecture type.
    pub fn first(&self) -> u16 {
        u16_at(self.data, 0)
    }
}

/// Option 94, the client network interface identifier (RFC 4578, section 2.2): type 1 is
/// UNDI with its major and minor version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkInterfaceId {
    /// The interface type (1 for UNDI).
    pub kind: u8,
    /// The major version.
    pub major: u8,
    /// The minor version.
    pub minor: u8,
}

impl NetworkInterfaceId {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] unless the length is 3.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let &[kind, major, minor] = data else {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_NETWORK_INTERFACE,
                len: data.len(),
            });
        };
        Ok(Self { kind, major, minor })
    }
}

/// Option 97, the client machine identifier (RFC 4578, section 2.3): type 0 and a
/// sixteen-octet GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineId<'a> {
    kind: u8,
    id: &'a [u8],
}

impl<'a> MachineId<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an empty value.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        let [kind, id @ ..] = data else {
            return Err(DecodeError::BadLength {
                code: code::CLIENT_MACHINE_IDENTIFIER,
                len: 0,
            });
        };
        Ok(Self { kind: *kind, id })
    }

    /// The identifier type (0 for a GUID).
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// The identifier after the type octet.
    pub fn id(&self) -> &'a [u8] {
        self.id
    }

    /// The GUID of type 0 with sixteen octets.
    pub fn guid(&self) -> Option<[u8; 16]> {
        if self.kind != 0 {
            return None;
        }
        self.id.try_into().ok()
    }
}

/// Enterprise number, length octet and data triples, the outer form of options 124 and
/// 125 (RFC 3925).
fn check_enterprise_items(code: u8, data: &[u8]) -> Result<(), DecodeError> {
    let mut pos = 0;
    while pos < data.len() {
        let len = data.get(pos + 4).ok_or(DecodeError::BadValue { code })?;
        pos += 5 + usize::from(*len);
    }
    if data.is_empty() || pos != data.len() {
        return Err(DecodeError::BadValue { code });
    }
    Ok(())
}

fn next_enterprise_item<'a>(rest: &mut &'a [u8]) -> Option<(u32, &'a [u8])> {
    let [a, b, c, d, len, tail @ ..] = *rest else {
        return None;
    };
    let data = tail.get(..usize::from(*len))?;
    *rest = &tail[data.len()..];
    Some((u32::from_be_bytes([*a, *b, *c, *d]), data))
}

/// One vendor of option 124: the IANA enterprise number and its class data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorClass<'a> {
    /// The vendor's IANA enterprise number.
    pub enterprise: u32,
    /// The vendor class data as sent.
    pub data: &'a [u8],
}

impl<'a> VendorClass<'a> {
    /// The classes of the data, or `None` when it is not a list of length-prefixed
    /// classes.
    pub fn classes(&self) -> Option<LengthPrefixed<'a>> {
        LengthPrefixed::parse(self.data)
    }
}

/// Option 124, the vendor-identifying vendor classes (RFC 3925, section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorClasses<'a> {
    data: &'a [u8],
}

impl<'a> VendorClasses<'a> {
    /// The option in `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] for an empty value or an entry that runs past the end.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        check_enterprise_items(code::VENDOR_CLASS, data)?;
        Ok(Self { data })
    }

    /// The vendors in order.
    pub fn iter(&self) -> impl Iterator<Item = VendorClass<'a>> + 'a {
        let mut rest = self.data;
        std::iter::from_fn(move || {
            next_enterprise_item(&mut rest)
                .map(|(enterprise, data)| VendorClass { enterprise, data })
        })
    }
}

/// One vendor of option 125: the IANA enterprise number and its sub-options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorInfo<'a> {
    /// The vendor's IANA enterprise number.
    pub enterprise: u32,
    /// The vendor's sub-options.
    pub sub_options: SubOptions<'a>,
}

/// Option 125, the vendor-identifying vendor-specific information (RFC 3925, section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorInfos<'a> {
    data: &'a [u8],
}

impl<'a> VendorInfos<'a> {
    /// The option in `data`; the sub-options of every vendor are checked.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadValue`] for an empty value, an entry or a sub-option that runs
    /// past the end.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        const CODE: u8 = code::VENDOR_IDENTIFYING_INFO;
        check_enterprise_items(CODE, data)?;
        let mut rest = data;
        while let Some((_, vendor)) = next_enterprise_item(&mut rest) {
            SubOptions::parse(CODE, vendor)?;
        }
        Ok(Self { data })
    }

    /// The vendors in order.
    pub fn iter(&self) -> impl Iterator<Item = VendorInfo<'a>> + 'a {
        let mut rest = self.data;
        std::iter::from_fn(move || {
            next_enterprise_item(&mut rest).map(|(enterprise, data)| VendorInfo {
                enterprise,
                sub_options: SubOptions { data },
            })
        })
    }
}

/// One classless static route (RFC 3442).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    /// The destination network, with the bits after the prefix length cleared.
    pub destination: Ipv4Addr,
    /// The prefix length, 0 to 32.
    pub prefix_len: u8,
    /// The router.
    pub router: Ipv4Addr,
}

impl Route {
    /// The octets of the destination descriptor that the prefix length keeps.
    pub(crate) fn significant_octets(prefix_len: u8) -> usize {
        usize::from(prefix_len).div_ceil(8)
    }

    pub(crate) fn mask(prefix_len: u8) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(prefix_len))
            .unwrap_or(0)
    }
}

/// Options 121 and 249, the classless static routes (RFC 3442): a destination descriptor
/// (the prefix length and the significant octets of the network) and a router per route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Routes<'a> {
    data: &'a [u8],
}

impl<'a> Routes<'a> {
    /// The routes in `data`, the value of option `code`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] below 5 octets, [`DecodeError::BadValue`] for a prefix
    /// length above 32 or a route that runs past the end.
    pub fn parse(code: u8, data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.len() < 5 {
            return Err(DecodeError::BadLength {
                code,
                len: data.len(),
            });
        }
        let mut rest = data;
        while !rest.is_empty() {
            next_route(&mut rest).ok_or(DecodeError::BadValue { code })?;
        }
        Ok(Self { data })
    }

    /// The routes in order.
    pub fn iter(&self) -> impl Iterator<Item = Route> + 'a {
        let mut rest = self.data;
        std::iter::from_fn(move || next_route(&mut rest))
    }
}

fn next_route(rest: &mut &[u8]) -> Option<Route> {
    let (&prefix_len, tail) = rest.split_first()?;
    if prefix_len > 32 {
        return None;
    }
    let significant = Route::significant_octets(prefix_len);
    let network = tail.get(..significant)?;
    let router = tail.get(significant..significant + 4)?;
    let mut octets = [0; 4];
    octets[..significant].copy_from_slice(network);
    *rest = &tail[significant + 4..];
    Some(Route {
        destination: Ipv4Addr::from(u32::from_be_bytes(octets) & Route::mask(prefix_len)),
        prefix_len,
        router: Ipv4Addr::new(router[0], router[1], router[2], router[3]),
    })
}
