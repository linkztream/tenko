//! The view over a received message: the fixed fields, the walk over the option areas and
//! the typed accessors.

use std::{fmt, net::Ipv4Addr};

use super::{
    CHADDR_LEN, DEFAULT_MAX_LEN, DecodeError, FILE_LEN, FLAG_BROADCAST, HTYPE_ETHERNET,
    IP_UDP_HEADERS_LEN, MAGIC_COOKIE, MIN_DATAGRAM_LEN, OPTIONS_START, SNAME_LEN, code,
    name::DomainSearch,
    offset,
    option::{
        AddrList, Architectures, ClientFqdn, ClientId, MachineId, MessageType, NetworkInterfaceId,
        RelayAgentInfo, Routes, UserClass, VendorClasses, VendorInfos,
    },
};

/// Where an option was found: the `options` field, or `file` and `sname` when option 52
/// lends them to options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Area {
    /// The options field after the magic cookie.
    Options,
    /// The `file` field (overload value 1 or 3).
    File,
    /// The `sname` field (overload value 2 or 3).
    Sname,
}

impl fmt::Display for Area {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Options => "options",
            Self::File => "file",
            Self::Sname => "sname",
        })
    }
}

/// One instance of an option as it is in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOption<'a> {
    /// The option code.
    pub code: u8,
    /// The value, without the code and length octets.
    pub data: &'a [u8],
    /// The area the instance is in.
    pub area: Area,
}

/// A received DHCPv4 message: a view over the datagram that reads fields and options on
/// demand and never allocates.
#[derive(Clone, Copy)]
pub struct Message<'a> {
    header: &'a [u8; OPTIONS_START],
    options: &'a [u8],
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn addr_at(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32_at(bytes, at))
}

/// The octets of a field up to its first zero octet.
fn until_nul(field: &[u8]) -> &[u8] {
    field
        .iter()
        .position(|&b| b == 0)
        .map_or(field, |end| &field[..end])
}

impl<'a> Message<'a> {
    /// A view over `buf`: at least the 236 octets of the fixed header and the magic cookie.
    /// The options are not read until asked for; see the module documentation for what a
    /// malformed option does.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TooShort`] below 240 octets, [`DecodeError::NoCookie`] when the
    /// magic cookie is missing.
    pub fn parse(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let Some((header, options)) = buf.split_first_chunk::<OPTIONS_START>() else {
            return Err(DecodeError::TooShort { len: buf.len() });
        };
        if header[offset::COOKIE..] != MAGIC_COOKIE {
            return Err(DecodeError::NoCookie);
        }
        Ok(Self { header, options })
    }

    /// The fixed header with the magic cookie (240 octets).
    pub fn header_bytes(&self) -> &'a [u8; OPTIONS_START] {
        self.header
    }

    /// The octets after the magic cookie, up to the end of the datagram.
    pub fn options_field(&self) -> &'a [u8] {
        self.options
    }

    /// The length of the datagram.
    pub fn len(&self) -> usize {
        OPTIONS_START + self.options.len()
    }

    /// Always `false`: a message has at least 240 octets.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// `op`: 1 (BOOTREQUEST) from a client, 2 (BOOTREPLY) from a server.
    pub fn op(&self) -> u8 {
        self.header[offset::OP]
    }

    /// `htype`: the hardware address type (1 for Ethernet).
    pub fn htype(&self) -> u8 {
        self.header[offset::HTYPE]
    }

    /// `hlen`: the hardware address length (6 for Ethernet).
    pub fn hlen(&self) -> u8 {
        self.header[offset::HLEN]
    }

    /// `hops`: the relay agents the message passed.
    pub fn hops(&self) -> u8 {
        self.header[offset::HOPS]
    }

    /// `xid`: the transaction id the client chose.
    pub fn xid(&self) -> u32 {
        u32_at(self.header, offset::XID)
    }

    /// `secs`: seconds since the client began the exchange.
    pub fn secs(&self) -> u16 {
        u16_at(self.header, offset::SECS)
    }

    /// `flags`, with the broadcast bit at 0x8000.
    pub fn flags(&self) -> u16 {
        u16_at(self.header, offset::FLAGS)
    }

    /// Whether the client asks for broadcast replies (RFC 2131, section 4.1).
    pub fn broadcast(&self) -> bool {
        self.flags() & FLAG_BROADCAST != 0
    }

    /// `ciaddr`: the client's address when it is bound, renewing or rebinding.
    pub fn ciaddr(&self) -> Ipv4Addr {
        addr_at(self.header, offset::CIADDR)
    }

    /// `yiaddr`: the address the server gives.
    pub fn yiaddr(&self) -> Ipv4Addr {
        addr_at(self.header, offset::YIADDR)
    }

    /// `siaddr`: the next server of the boot process.
    pub fn siaddr(&self) -> Ipv4Addr {
        addr_at(self.header, offset::SIADDR)
    }

    /// `giaddr`: the relay agent's address, unspecified when the message was not relayed.
    pub fn giaddr(&self) -> Ipv4Addr {
        addr_at(self.header, offset::GIADDR)
    }

    /// All sixteen octets of `chaddr`.
    pub fn chaddr_field(&self) -> &'a [u8] {
        &self.header[offset::CHADDR..offset::CHADDR + CHADDR_LEN]
    }

    /// The client hardware address: the first `hlen` octets of `chaddr`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Hardware`] when `hlen` is above 16.
    pub fn chaddr(&self) -> Result<&'a [u8], DecodeError> {
        let hlen = usize::from(self.hlen());
        if hlen > CHADDR_LEN {
            return Err(self.hardware_error());
        }
        Ok(&self.chaddr_field()[..hlen])
    }

    /// The client's Ethernet address.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Hardware`] unless `htype` is 1 and `hlen` is 6.
    pub fn mac(&self) -> Result<[u8; 6], DecodeError> {
        if self.htype() != HTYPE_ETHERNET || self.hlen() != 6 {
            return Err(self.hardware_error());
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&self.chaddr_field()[..6]);
        Ok(mac)
    }

    fn hardware_error(&self) -> DecodeError {
        DecodeError::Hardware {
            htype: self.htype(),
            hlen: self.hlen(),
        }
    }

    /// All sixty-four octets of `sname`, whatever they carry.
    pub fn sname_field(&self) -> &'a [u8] {
        &self.header[offset::SNAME..offset::SNAME + SNAME_LEN]
    }

    /// All one hundred and twenty-eight octets of `file`, whatever they carry.
    pub fn file_field(&self) -> &'a [u8] {
        &self.header[offset::FILE..offset::FILE + FILE_LEN]
    }

    /// The server host name in `sname` up to its terminating zero, or `None` when `sname`
    /// carries options.
    ///
    /// # Errors
    ///
    /// The errors of [`Message::overload`], which leave the meaning of the field open.
    pub fn server_name(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        Ok((self.overload()? & 2 == 0).then(|| until_nul(self.sname_field())))
    }

    /// The boot file name in `file` up to its terminating zero, or `None` when `file`
    /// carries options.
    ///
    /// # Errors
    ///
    /// The errors of [`Message::overload`], which leave the meaning of the field open.
    pub fn boot_file(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        Ok((self.overload()? & 1 == 0).then(|| until_nul(self.file_field())))
    }

    /// The server host name as text, when `sname` holds no options and is UTF-8.
    ///
    /// # Errors
    ///
    /// As [`Message::server_name`].
    pub fn server_name_str(&self) -> Result<Option<&'a str>, DecodeError> {
        Ok(self
            .server_name()?
            .and_then(|name| std::str::from_utf8(name).ok()))
    }

    /// The boot file name as text, when `file` holds no options and is UTF-8.
    ///
    /// # Errors
    ///
    /// As [`Message::boot_file`].
    pub fn boot_file_str(&self) -> Result<Option<&'a str>, DecodeError> {
        Ok(self
            .boot_file()?
            .and_then(|name| std::str::from_utf8(name).ok()))
    }

    /// Option 52: 0 without it, 1 when `file` carries options, 2 for `sname`, 3 for both.
    /// Only the options field is read (RFC 2131, section 4.1: the option is only valid
    /// there).
    ///
    /// # Errors
    ///
    /// A malformed option in the options field before option 52 (anywhere in the field
    /// when it has no option 52: one might have followed), or option 52 with a length other
    /// than 1 or a value other than 1 to 3.
    pub fn overload(&self) -> Result<u8, DecodeError> {
        let mut options = self.options();
        for item in &mut options {
            let option = item?;
            if option.area != Area::Options {
                break;
            }
            if option.code == code::OVERLOAD {
                return Ok(option.data[0]);
            }
        }
        Ok(0)
    }

    /// Every option instance in RFC 2131 order: the options field, then `file`, then
    /// `sname` as option 52 allows. Pad and end are not yielded. A malformed option is
    /// yielded as an error once and ends the walk.
    pub fn options(&self) -> Options<'a> {
        Options {
            header: self.header,
            field: self.options,
            area: Area::Options,
            pos: 0,
            overload: None,
            done: false,
        }
    }

    /// Walks every option and returns the first error.
    ///
    /// # Errors
    ///
    /// The malformed option that ends the walk.
    pub fn validate(&self) -> Result<(), DecodeError> {
        self.options().try_for_each(|item| item.map(drop))
    }

    /// The value of the one instance of option `code`, or `None` when the message does not
    /// carry it. Instances after a malformed option are not seen.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Split`] when the option comes as several instances (concatenate them
    /// with [`Message::option_data`]); the malformed option that ends the walk when it
    /// comes before any instance.
    pub fn option(&self, code: u8) -> Result<Option<&'a [u8]>, DecodeError> {
        let mut found = None;
        for item in self.options() {
            match item {
                Ok(option) if option.code == code => {
                    if found.is_some() {
                        return Err(DecodeError::Split { code });
                    }
                    found = Some(option.data);
                }
                Ok(_) => {}
                Err(error) => return found.map_or(Err(error), |data| Ok(Some(data))),
            }
        }
        Ok(found)
    }

    /// The value of option `code` with every instance concatenated in RFC 3396 order. One
    /// instance is returned from the message; several are copied into `buf`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BufferTooSmall`] when the instances do not fit into `buf`; the
    /// malformed option that ends the walk when it comes before any instance.
    pub fn option_data<'b>(
        &self,
        code: u8,
        buf: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, DecodeError>
    where
        'a: 'b,
    {
        let mut first: Option<&'a [u8]> = None;
        let mut count = 0usize;
        let mut total = 0usize;
        for item in self.options() {
            let option = match item {
                Ok(option) => option,
                Err(error) if count == 0 => return Err(error),
                Err(_) => break,
            };
            if option.code != code {
                continue;
            }
            if let Some(target) = buf.get_mut(total..total + option.data.len()) {
                target.copy_from_slice(option.data);
            }
            first.get_or_insert(option.data);
            count += 1;
            total += option.data.len();
        }
        match count {
            0 => Ok(None),
            1 => Ok(first),
            _ if total > buf.len() => Err(DecodeError::BufferTooSmall { needed: total }),
            _ => Ok(Some(&buf[..total])),
        }
    }

    fn fixed<const N: usize>(&self, code: u8) -> Result<Option<[u8; N]>, DecodeError> {
        let Some(data) = self.option(code)? else {
            return Ok(None);
        };
        <[u8; N]>::try_from(data)
            .map(Some)
            .map_err(|_| DecodeError::BadLength {
                code,
                len: data.len(),
            })
    }

    fn addr(&self, code: u8) -> Result<Option<Ipv4Addr>, DecodeError> {
        Ok(self.fixed::<4>(code)?.map(Ipv4Addr::from))
    }

    fn u32_value(&self, code: u8) -> Result<Option<u32>, DecodeError> {
        Ok(self.fixed::<4>(code)?.map(u32::from_be_bytes))
    }

    fn u16_value(&self, code: u8) -> Result<Option<u16>, DecodeError> {
        Ok(self.fixed::<2>(code)?.map(u16::from_be_bytes))
    }

    /// A value of at least one octet.
    fn bytes(&self, code: u8) -> Result<Option<&'a [u8]>, DecodeError> {
        match self.option(code)? {
            Some([]) => Err(DecodeError::BadLength { code, len: 0 }),
            other => Ok(other),
        }
    }

    fn typed<T>(
        &self,
        code: u8,
        parse: impl FnOnce(&'a [u8]) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        self.option(code)?.map(parse).transpose()
    }

    /// Option 53, the DHCP message type (RFC 2132, section 9.6).
    ///
    /// # Errors
    ///
    /// A length other than 1, and the errors of [`Message::option`].
    pub fn message_type(&self) -> Result<Option<MessageType>, DecodeError> {
        Ok(self
            .fixed::<1>(code::MESSAGE_TYPE)?
            .map(|[kind]| MessageType::from(kind)))
    }

    /// Option 54, the server identifier (RFC 2132, section 9.7).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn server_identifier(&self) -> Result<Option<Ipv4Addr>, DecodeError> {
        self.addr(code::SERVER_IDENTIFIER)
    }

    /// Option 50, the requested IP address (RFC 2132, section 9.1).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn requested_address(&self) -> Result<Option<Ipv4Addr>, DecodeError> {
        self.addr(code::REQUESTED_ADDRESS)
    }

    /// Option 51, the lease time in seconds (RFC 2132, section 9.2).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn lease_time(&self) -> Result<Option<u32>, DecodeError> {
        self.u32_value(code::LEASE_TIME)
    }

    /// Option 58, the renewal time T1 in seconds (RFC 2132, section 9.11).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn renewal_time(&self) -> Result<Option<u32>, DecodeError> {
        self.u32_value(code::RENEWAL_TIME)
    }

    /// Option 59, the rebinding time T2 in seconds (RFC 2132, section 9.12).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn rebinding_time(&self) -> Result<Option<u32>, DecodeError> {
        self.u32_value(code::REBINDING_TIME)
    }

    /// Option 55, the parameter request list (RFC 2132, section 9.8): the option codes in
    /// the client's order of preference.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn parameter_request_list(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::PARAMETER_REQUEST_LIST)
    }

    /// Option 57, the maximum DHCP message size as sent (RFC 2132, section 9.10); see
    /// [`Message::max_reply_len`] for the limit a reply keeps.
    ///
    /// # Errors
    ///
    /// A length other than 2, and the errors of [`Message::option`].
    pub fn max_message_size(&self) -> Result<Option<u16>, DecodeError> {
        self.u16_value(code::MAX_MESSAGE_SIZE)
    }

    /// The largest reply this client accepts, in octets of DHCP message: option 57 less the
    /// IP and UDP headers when it is at least 576, else 548 (RFC 2131, section 4.1). A
    /// malformed option 57 counts as absent.
    pub fn max_reply_len(&self) -> usize {
        match self.max_message_size() {
            Ok(Some(size)) if usize::from(size) >= MIN_DATAGRAM_LEN => {
                usize::from(size) - IP_UDP_HEADERS_LEN
            }
            _ => DEFAULT_MAX_LEN,
        }
    }

    /// Option 60, the vendor class identifier (RFC 2132, section 9.13), for example
    /// `MSFT 5.0` or `PXEClient:Arch:00007:UNDI:003016`.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn vendor_class_identifier(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::VENDOR_CLASS_IDENTIFIER)
    }

    /// Option 61, the client identifier (RFC 2132, section 9.14; RFC 4361).
    ///
    /// # Errors
    ///
    /// The errors of [`ClientId::parse`] and [`Message::option`].
    pub fn client_identifier(&self) -> Result<Option<ClientId<'a>>, DecodeError> {
        self.typed(code::CLIENT_IDENTIFIER, ClientId::parse)
    }

    /// Option 12, the host name (RFC 2132, section 3.14), as sent.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn host_name(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::HOST_NAME)
    }

    /// Option 81, the client FQDN (RFC 4702).
    ///
    /// # Errors
    ///
    /// The errors of [`ClientFqdn::parse`] and [`Message::option`].
    pub fn client_fqdn(&self) -> Result<Option<ClientFqdn<'a>>, DecodeError> {
        self.typed(code::CLIENT_FQDN, ClientFqdn::parse)
    }

    /// Option 82, the relay agent information (RFC 3046).
    ///
    /// # Errors
    ///
    /// The errors of [`RelayAgentInfo::parse`] and [`Message::option`].
    pub fn relay_agent_info(&self) -> Result<Option<RelayAgentInfo<'a>>, DecodeError> {
        self.typed(code::RELAY_AGENT_INFORMATION, RelayAgentInfo::parse)
    }

    /// Option 77, the user class (RFC 3004).
    ///
    /// # Errors
    ///
    /// The errors of [`UserClass::parse`] and [`Message::option`].
    pub fn user_class(&self) -> Result<Option<UserClass<'a>>, DecodeError> {
        self.typed(code::USER_CLASS, UserClass::parse)
    }

    /// Option 93, the client system architectures (RFC 4578, section 2.1).
    ///
    /// # Errors
    ///
    /// The errors of [`Architectures::parse`] and [`Message::option`].
    pub fn client_architectures(&self) -> Result<Option<Architectures<'a>>, DecodeError> {
        self.typed(code::CLIENT_ARCHITECTURE, Architectures::parse)
    }

    /// Option 94, the client network interface identifier (RFC 4578, section 2.2).
    ///
    /// # Errors
    ///
    /// The errors of [`NetworkInterfaceId::parse`] and [`Message::option`].
    pub fn network_interface(&self) -> Result<Option<NetworkInterfaceId>, DecodeError> {
        self.typed(code::CLIENT_NETWORK_INTERFACE, NetworkInterfaceId::parse)
    }

    /// Option 97, the client machine identifier (RFC 4578, section 2.3).
    ///
    /// # Errors
    ///
    /// The errors of [`MachineId::parse`] and [`Message::option`].
    pub fn machine_id(&self) -> Result<Option<MachineId<'a>>, DecodeError> {
        self.typed(code::CLIENT_MACHINE_IDENTIFIER, MachineId::parse)
    }

    /// Option 124, the vendor-identifying vendor classes (RFC 3925, section 3).
    ///
    /// # Errors
    ///
    /// The errors of [`VendorClasses::parse`] and [`Message::option`].
    pub fn vendor_classes(&self) -> Result<Option<VendorClasses<'a>>, DecodeError> {
        self.typed(code::VENDOR_CLASS, VendorClasses::parse)
    }

    /// Option 125, the vendor-identifying vendor-specific information (RFC 3925, section 4).
    ///
    /// # Errors
    ///
    /// The errors of [`VendorInfos::parse`] and [`Message::option`].
    pub fn vendor_infos(&self) -> Result<Option<VendorInfos<'a>>, DecodeError> {
        self.typed(code::VENDOR_IDENTIFYING_INFO, VendorInfos::parse)
    }

    /// Option 116, auto-configure (RFC 2563): 0 do not auto-configure, 1 auto-configure.
    ///
    /// # Errors
    ///
    /// A length other than 1, and the errors of [`Message::option`].
    pub fn auto_configure(&self) -> Result<Option<u8>, DecodeError> {
        Ok(self.fixed::<1>(code::AUTO_CONFIGURE)?.map(|[value]| value))
    }

    /// Option 118, the subnet selection (RFC 3011).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn subnet_selection(&self) -> Result<Option<Ipv4Addr>, DecodeError> {
        self.addr(code::SUBNET_SELECTION)
    }

    /// Option 119, the domain search list (RFC 3397). A long list is often split; then this
    /// returns [`DecodeError::Split`] and the caller reads
    /// `DomainSearch::parse(message.option_data(119, &mut buf)?)`.
    ///
    /// # Errors
    ///
    /// The errors of [`DomainSearch::parse`] and [`Message::option`].
    pub fn domain_search(&self) -> Result<Option<DomainSearch<'a>>, DecodeError> {
        self.typed(code::DOMAIN_SEARCH, DomainSearch::parse)
    }

    /// Option 121, the classless static routes (RFC 3442).
    ///
    /// # Errors
    ///
    /// The errors of [`Routes::parse`] and [`Message::option`].
    pub fn classless_routes(&self) -> Result<Option<Routes<'a>>, DecodeError> {
        self.typed(code::CLASSLESS_STATIC_ROUTES, |data| {
            Routes::parse(code::CLASSLESS_STATIC_ROUTES, data)
        })
    }

    /// Option 249, the classless static routes in Microsoft's code (the RFC 3442 format).
    ///
    /// # Errors
    ///
    /// The errors of [`Routes::parse`] and [`Message::option`].
    pub fn ms_classless_routes(&self) -> Result<Option<Routes<'a>>, DecodeError> {
        self.typed(code::MS_CLASSLESS_STATIC_ROUTES, |data| {
            Routes::parse(code::MS_CLASSLESS_STATIC_ROUTES, data)
        })
    }

    /// Option 1, the subnet mask (RFC 2132, section 3.3).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn subnet_mask(&self) -> Result<Option<Ipv4Addr>, DecodeError> {
        self.addr(code::SUBNET_MASK)
    }

    /// Option 3, the routers (RFC 2132, section 3.5).
    ///
    /// # Errors
    ///
    /// The errors of [`AddrList::parse`] and [`Message::option`].
    pub fn routers(&self) -> Result<Option<AddrList<'a>>, DecodeError> {
        self.typed(code::ROUTERS, |data| AddrList::parse(code::ROUTERS, data))
    }

    /// Option 6, the domain name servers (RFC 2132, section 3.8).
    ///
    /// # Errors
    ///
    /// The errors of [`AddrList::parse`] and [`Message::option`].
    pub fn domain_name_servers(&self) -> Result<Option<AddrList<'a>>, DecodeError> {
        self.typed(code::DOMAIN_NAME_SERVERS, |data| {
            AddrList::parse(code::DOMAIN_NAME_SERVERS, data)
        })
    }

    /// Option 15, the domain name (RFC 2132, section 3.17), as sent.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn domain_name(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::DOMAIN_NAME)
    }

    /// Option 26, the interface MTU (RFC 2132, section 5.1).
    ///
    /// # Errors
    ///
    /// A length other than 2, and the errors of [`Message::option`].
    pub fn interface_mtu(&self) -> Result<Option<u16>, DecodeError> {
        self.u16_value(code::INTERFACE_MTU)
    }

    /// Option 28, the broadcast address (RFC 2132, section 5.3).
    ///
    /// # Errors
    ///
    /// A length other than 4, and the errors of [`Message::option`].
    pub fn broadcast_address(&self) -> Result<Option<Ipv4Addr>, DecodeError> {
        self.addr(code::BROADCAST_ADDRESS)
    }

    /// Option 42, the NTP servers (RFC 2132, section 8.3).
    ///
    /// # Errors
    ///
    /// The errors of [`AddrList::parse`] and [`Message::option`].
    pub fn ntp_servers(&self) -> Result<Option<AddrList<'a>>, DecodeError> {
        self.typed(code::NTP_SERVERS, |data| {
            AddrList::parse(code::NTP_SERVERS, data)
        })
    }

    /// Option 43, the vendor-specific information (RFC 2132, section 8.4), raw.
    ///
    /// # Errors
    ///
    /// The errors of [`Message::option`].
    pub fn vendor_specific(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.option(code::VENDOR_SPECIFIC)
    }

    /// Option 66, the TFTP server name (RFC 2132, section 9.4), as sent.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn tftp_server_name(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::TFTP_SERVER_NAME)
    }

    /// Option 67, the boot file name (RFC 2132, section 9.5), as sent.
    ///
    /// # Errors
    ///
    /// An empty value, and the errors of [`Message::option`].
    pub fn bootfile_name(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.bytes(code::BOOTFILE_NAME)
    }
}

impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("op", &self.op())
            .field("xid", &format_args!("{:#010x}", self.xid()))
            .field("chaddr", &self.chaddr())
            .field("ciaddr", &self.ciaddr())
            .field("yiaddr", &self.yiaddr())
            .field("giaddr", &self.giaddr())
            .field("message_type", &self.message_type())
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// The walk over the option areas of a [`Message`]; see [`Message::options`].
#[derive(Debug, Clone)]
pub struct Options<'a> {
    header: &'a [u8; OPTIONS_START],
    field: &'a [u8],
    area: Area,
    pos: usize,
    /// Option 52 once the walk passed it in the options field.
    overload: Option<u8>,
    done: bool,
}

impl<'a> Options<'a> {
    fn area_bytes(&self) -> &'a [u8] {
        match self.area {
            Area::Options => self.field,
            Area::File => &self.header[offset::FILE..offset::FILE + FILE_LEN],
            Area::Sname => &self.header[offset::SNAME..offset::SNAME + SNAME_LEN],
        }
    }

    /// Moves to the next area option 52 allows; `false` when the walk is over.
    fn advance(&mut self) -> bool {
        let overload = self.overload.unwrap_or(0);
        let next = match self.area {
            Area::Options if overload & 1 != 0 => Area::File,
            Area::Options | Area::File if overload & 2 != 0 => Area::Sname,
            _ => {
                self.done = true;
                return false;
            }
        };
        self.area = next;
        self.pos = 0;
        true
    }

    fn fail(&mut self, error: DecodeError) -> Result<RawOption<'a>, DecodeError> {
        self.done = true;
        Err(error)
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = Result<RawOption<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let bytes = self.area_bytes();
            let Some(&option_code) = bytes.get(self.pos) else {
                self.advance();
                continue;
            };
            match option_code {
                code::PAD => {
                    self.pos += 1;
                    continue;
                }
                code::END => {
                    self.advance();
                    continue;
                }
                _ => {}
            }
            let truncated = DecodeError::Truncated {
                code: option_code,
                area: self.area,
            };
            let Some(&len) = bytes.get(self.pos + 1) else {
                return Some(self.fail(truncated));
            };
            let start = self.pos + 2;
            let Some(data) = bytes.get(start..start + usize::from(len)) else {
                return Some(self.fail(truncated));
            };
            self.pos = start + usize::from(len);
            if option_code == code::OVERLOAD
                && self.area == Area::Options
                && self.overload.is_none()
            {
                match data {
                    [value @ 1..=3] => self.overload = Some(*value),
                    [_] => return Some(self.fail(DecodeError::BadValue { code: option_code })),
                    _ => {
                        return Some(self.fail(DecodeError::BadLength {
                            code: option_code,
                            len: data.len(),
                        }));
                    }
                }
            }
            return Some(Ok(RawOption {
                code: option_code,
                data,
                area: self.area,
            }));
        }
        None
    }
}
