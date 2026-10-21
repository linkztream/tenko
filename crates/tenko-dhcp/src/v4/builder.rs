//! The message builder: a message written into a caller's buffer, within a size limit,
//! with RFC 3396 splitting and option overload.

use std::net::Ipv4Addr;

use super::{
    BOOTREPLY, CHADDR_LEN, EncodeError, FILE_LEN, FLAG_BROADCAST, MAGIC_COOKIE, Message,
    OPTIONS_START, SNAME_LEN, WireName, code,
    name::{MAX_WIRE_LEN, encode_domain_search},
    offset,
    option::{ClientFqdn, MessageType, Route},
};

/// The largest value the typed setters assemble on the stack before splitting it into
/// instances: a domain search list, a route list or an address list. A longer value is
/// encoded by the caller ([`encode_domain_search`], [`encode_classless_routes`]) and
/// written with [`MessageBuilder::option`].
const SCRATCH_LEN: usize = 2048;

/// The longest value of one option instance.
const MAX_INSTANCE_LEN: usize = 255;

/// What a `sname` or `file` field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Nothing yet: zeros, available for options when overload is allowed.
    Free,
    /// A name the caller set.
    Value,
    /// Options, up to the position in `Cursors`.
    Options,
}

/// The positions the builder writes at; copied to undo an option that does not fit.
#[derive(Debug, Clone, Copy)]
struct Cursors {
    /// The next octet of the options field (absolute).
    options: usize,
    /// The next octet of `file` (relative to the field).
    file: usize,
    /// The next octet of `sname` (relative to the field).
    sname: usize,
    file_state: Field,
    sname_state: Field,
}

/// Writes a DHCPv4 message into a caller's buffer, allocating nothing.
///
/// The fixed header is zero and the magic cookie written when the builder is made; the
/// setters fill the fields, [`MessageBuilder::option`] and the typed setters append options,
/// [`MessageBuilder::finish`] writes the end option and the padding and returns the length.
///
/// # Size rules
///
/// The message stays within the limit given to [`MessageBuilder::new`] (for a reply,
/// [`Message::max_reply_len`] of the request, at most the buffer's length). An option that
/// does not fit returns [`EncodeError::NoRoom`] and leaves the message as it was, so the
/// caller can leave it out or answer without it; nothing is truncated silently. One
/// octet is kept for the end option. When the caller allows overload
/// ([`MessageBuilder::allow_overload`]), three more octets are kept for option 52, and an
/// option that does not fit into the options field goes into `file` and then `sname`
/// (RFC 2131, section 4.1), each ended by its own end option; a field the caller gave a
/// value is not used.
///
/// # Splitting
///
/// A value longer than 255 octets is written as consecutive instances of 255 octets and a
/// last shorter one (RFC 3396), never into an area before the one of the previous part.
/// A value of 255 octets or less is one instance: clients without RFC 3396 support see the
/// option they expect.
#[derive(Debug)]
pub struct MessageBuilder<'b> {
    buf: &'b mut [u8],
    limit: usize,
    overload: bool,
    pad_to: usize,
    at: Cursors,
}

impl<'b> MessageBuilder<'b> {
    /// A builder over `buf` for a message of at most `limit` octets (and at most
    /// `buf.len()`): the fixed header zero, the magic cookie written.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`] when the buffer or the limit is below 241 octets.
    pub fn new(buf: &'b mut [u8], limit: usize) -> Result<Self, EncodeError> {
        let limit = limit.min(buf.len());
        if limit <= OPTIONS_START {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[..offset::COOKIE].fill(0);
        buf[offset::COOKIE..OPTIONS_START].copy_from_slice(&MAGIC_COOKIE);
        Ok(Self {
            buf,
            limit,
            overload: false,
            pad_to: 0,
            at: Cursors {
                options: OPTIONS_START,
                file: 0,
                sname: 0,
                file_state: Field::Free,
                sname_state: Field::Free,
            },
        })
    }

    /// A reply to `request`: `op` BOOTREPLY; `htype`, `hlen`, `xid`, `flags`, `giaddr` and
    /// `chaddr` copied; option 53 set to `kind`; the limit from the request's option 57.
    /// The caller sets `ciaddr`, `yiaddr` and `siaddr` as RFC 2131, table 3, asks for the
    /// message type. Pass a shorter `buf` to keep the reply below an MTU of the server.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::new`].
    pub fn reply(
        buf: &'b mut [u8],
        request: &Message<'_>,
        kind: MessageType,
    ) -> Result<Self, EncodeError> {
        let mut builder = Self::new(buf, request.max_reply_len())?;
        let header = request.header_bytes();
        builder.buf[offset::OP] = BOOTREPLY;
        builder.buf[offset::HTYPE] = request.htype();
        builder.buf[offset::HLEN] = request.hlen();
        builder.buf[offset::XID..offset::SECS].copy_from_slice(&header[offset::XID..offset::SECS]);
        builder.buf[offset::FLAGS..offset::CIADDR]
            .copy_from_slice(&header[offset::FLAGS..offset::CIADDR]);
        builder.buf[offset::GIADDR..offset::SNAME]
            .copy_from_slice(&header[offset::GIADDR..offset::SNAME]);
        builder.message_type(kind)?;
        Ok(builder)
    }

    /// The size limit of the message.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The length the message would have if it were finished now (without the padding).
    pub fn len(&self) -> usize {
        self.at.options + usize::from(self.overload_value() != 0) * 3 + 1
    }

    /// Always `false`: a message has at least the fixed header.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Sets `op`.
    pub fn op(&mut self, op: u8) -> &mut Self {
        self.buf[offset::OP] = op;
        self
    }

    /// Sets `htype`.
    pub fn htype(&mut self, htype: u8) -> &mut Self {
        self.buf[offset::HTYPE] = htype;
        self
    }

    /// Sets `hlen`.
    pub fn hlen(&mut self, hlen: u8) -> &mut Self {
        self.buf[offset::HLEN] = hlen;
        self
    }

    /// Sets `hops`.
    pub fn hops(&mut self, hops: u8) -> &mut Self {
        self.buf[offset::HOPS] = hops;
        self
    }

    /// Sets `xid`.
    pub fn xid(&mut self, xid: u32) -> &mut Self {
        self.buf[offset::XID..offset::SECS].copy_from_slice(&xid.to_be_bytes());
        self
    }

    /// Sets `secs`.
    pub fn secs(&mut self, secs: u16) -> &mut Self {
        self.buf[offset::SECS..offset::FLAGS].copy_from_slice(&secs.to_be_bytes());
        self
    }

    /// Sets `flags`.
    pub fn flags(&mut self, flags: u16) -> &mut Self {
        self.buf[offset::FLAGS..offset::CIADDR].copy_from_slice(&flags.to_be_bytes());
        self
    }

    /// Sets or clears the broadcast bit of `flags`.
    pub fn broadcast(&mut self, broadcast: bool) -> &mut Self {
        let flags = u16::from_be_bytes([self.buf[offset::FLAGS], self.buf[offset::FLAGS + 1]]);
        let flags = if broadcast {
            flags | FLAG_BROADCAST
        } else {
            flags & !FLAG_BROADCAST
        };
        self.flags(flags)
    }

    fn address(&mut self, at: usize, address: Ipv4Addr) -> &mut Self {
        self.buf[at..at + 4].copy_from_slice(&address.octets());
        self
    }

    /// Sets `ciaddr`.
    pub fn ciaddr(&mut self, address: Ipv4Addr) -> &mut Self {
        self.address(offset::CIADDR, address)
    }

    /// Sets `yiaddr`.
    pub fn yiaddr(&mut self, address: Ipv4Addr) -> &mut Self {
        self.address(offset::YIADDR, address)
    }

    /// Sets `siaddr`, the next server of the boot process.
    pub fn siaddr(&mut self, address: Ipv4Addr) -> &mut Self {
        self.address(offset::SIADDR, address)
    }

    /// Sets `giaddr`.
    pub fn giaddr(&mut self, address: Ipv4Addr) -> &mut Self {
        self.address(offset::GIADDR, address)
    }

    /// Sets `chaddr`, zero-padded to 16 octets; `hlen` is not changed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::FieldTooLong`] above 16 octets.
    pub fn chaddr(&mut self, chaddr: &[u8]) -> Result<&mut Self, EncodeError> {
        if chaddr.len() > CHADDR_LEN {
            return Err(EncodeError::FieldTooLong);
        }
        let field = &mut self.buf[offset::CHADDR..offset::CHADDR + CHADDR_LEN];
        field.fill(0);
        field[..chaddr.len()].copy_from_slice(chaddr);
        Ok(self)
    }

    /// Sets `sname`, the server host name, zero-terminated.
    ///
    /// # Errors
    ///
    /// [`EncodeError::FieldTooLong`] above 63 octets, [`EncodeError::FieldInUse`] when
    /// `sname` carries options already.
    pub fn sname(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        if name.len() >= SNAME_LEN {
            return Err(EncodeError::FieldTooLong);
        }
        if self.at.sname_state == Field::Options {
            return Err(EncodeError::FieldInUse);
        }
        let field = &mut self.buf[offset::SNAME..offset::SNAME + SNAME_LEN];
        field.fill(0);
        field[..name.len()].copy_from_slice(name);
        self.at.sname_state = Field::Value;
        Ok(self)
    }

    /// Sets `file`, the boot file name, zero-terminated.
    ///
    /// # Errors
    ///
    /// [`EncodeError::FieldTooLong`] above 127 octets, [`EncodeError::FieldInUse`] when
    /// `file` carries options already.
    pub fn file(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        if name.len() >= FILE_LEN {
            return Err(EncodeError::FieldTooLong);
        }
        if self.at.file_state == Field::Options {
            return Err(EncodeError::FieldInUse);
        }
        let field = &mut self.buf[offset::FILE..offset::FILE + FILE_LEN];
        field.fill(0);
        field[..name.len()].copy_from_slice(name);
        self.at.file_state = Field::Value;
        Ok(self)
    }

    /// Lets options that do not fit into the options field go into `file` and `sname`
    /// (option 52). Three octets of the options field are kept for option 52 from now on.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`] when the options field has no three octets left.
    pub fn allow_overload(&mut self) -> Result<&mut Self, EncodeError> {
        if self.at.options + 3 + 1 > self.limit {
            return Err(EncodeError::NoRoom {
                code: code::OVERLOAD,
            });
        }
        self.overload = true;
        Ok(self)
    }

    /// Pads the finished message with zeros to `len` octets (300 for BOOTP relays and
    /// clients, [`super::BOOTP_MIN_LEN`]); a longer message is not changed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::PaddingTooLong`] when `len` is above the limit.
    pub fn pad_to(&mut self, len: usize) -> Result<&mut Self, EncodeError> {
        if len > self.limit {
            return Err(EncodeError::PaddingTooLong { len });
        }
        self.pad_to = len;
        Ok(self)
    }

    /// The last octet the options field may use for options.
    fn options_end(&self) -> usize {
        let usable = |state| self.overload && state != Field::Value;
        let reserve = if usable(self.at.file_state) || usable(self.at.sname_state) {
            4
        } else {
            1
        };
        self.limit - reserve
    }

    fn overload_value(&self) -> u8 {
        u8::from(self.at.file_state == Field::Options)
            | (u8::from(self.at.sname_state == Field::Options) << 1)
    }

    /// Writes one instance into the first area from `first` on where it fits and returns
    /// that area (0 options, 1 file, 2 sname).
    fn place(&mut self, option: u8, data: &[u8], first: u8) -> Result<u8, EncodeError> {
        let need = 2 + data.len();
        let len = u8::try_from(data.len()).map_err(|_| EncodeError::NoRoom { code: option })?;
        let write = |target: &mut [u8]| {
            target[0] = option;
            target[1] = len;
            target[2..].copy_from_slice(data);
        };
        if first == 0 && self.at.options + need <= self.options_end() {
            write(&mut self.buf[self.at.options..self.at.options + need]);
            self.at.options += need;
            return Ok(0);
        }
        if !self.overload {
            return Err(EncodeError::NoRoom { code: option });
        }
        // One octet of each field is kept for its end option.
        if first <= 1 && self.at.file_state != Field::Value && self.at.file + need < FILE_LEN {
            let at = offset::FILE + self.at.file;
            write(&mut self.buf[at..at + need]);
            self.at.file += need;
            self.at.file_state = Field::Options;
            return Ok(1);
        }
        if self.at.sname_state != Field::Value && self.at.sname + need < SNAME_LEN {
            let at = offset::SNAME + self.at.sname;
            write(&mut self.buf[at..at + need]);
            self.at.sname += need;
            self.at.sname_state = Field::Options;
            return Ok(2);
        }
        Err(EncodeError::NoRoom { code: option })
    }

    /// Appends option `option` with `data`: one instance up to 255 octets, consecutive
    /// instances above (RFC 3396). Either the whole value is written or nothing.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for pad, end and option 52 (the builder writes it),
    /// [`EncodeError::NoRoom`] when the value does not fit.
    pub fn option(&mut self, option: u8, data: &[u8]) -> Result<&mut Self, EncodeError> {
        if matches!(option, code::PAD | code::END | code::OVERLOAD) {
            return Err(EncodeError::BadValue { code: option });
        }
        let saved = self.at;
        let mut area = 0;
        let mut chunks = data.chunks(MAX_INSTANCE_LEN);
        let result = if data.is_empty() {
            self.place(option, data, 0).map(drop)
        } else {
            chunks.try_for_each(|chunk| {
                area = self.place(option, chunk, area)?;
                Ok(())
            })
        };
        if let Err(error) = result {
            self.at = saved;
            return Err(error);
        }
        Ok(self)
    }

    /// Assembles a value on the stack with `encode` and appends it as option `option`.
    fn assembled(
        &mut self,
        option: u8,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, EncodeError>,
    ) -> Result<&mut Self, EncodeError> {
        let mut scratch = [0u8; SCRATCH_LEN];
        let len = encode(&mut scratch)?;
        self.option(option, &scratch[..len])
    }

    fn addresses(&mut self, option: u8, addresses: &[Ipv4Addr]) -> Result<&mut Self, EncodeError> {
        if addresses.is_empty() {
            return Err(EncodeError::BadValue { code: option });
        }
        self.assembled(option, |out| {
            let len = addresses.len() * 4;
            let target = out
                .get_mut(..len)
                .ok_or(EncodeError::NoRoom { code: option })?;
            for (chunk, address) in target.as_chunks_mut::<4>().0.iter_mut().zip(addresses) {
                *chunk = address.octets();
            }
            Ok(len)
        })
    }

    /// Option 53, the message type. [`MessageBuilder::reply`] writes it first, as clients
    /// expect.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn message_type(&mut self, kind: MessageType) -> Result<&mut Self, EncodeError> {
        self.option(code::MESSAGE_TYPE, &[kind.code()])
    }

    /// Option 54, the server identifier.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn server_identifier(&mut self, address: Ipv4Addr) -> Result<&mut Self, EncodeError> {
        self.option(code::SERVER_IDENTIFIER, &address.octets())
    }

    /// Option 51, the lease time in seconds (`u32::MAX` is infinite).
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn lease_time(&mut self, seconds: u32) -> Result<&mut Self, EncodeError> {
        self.option(code::LEASE_TIME, &seconds.to_be_bytes())
    }

    /// Option 58, the renewal time T1 in seconds.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn renewal_time(&mut self, seconds: u32) -> Result<&mut Self, EncodeError> {
        self.option(code::RENEWAL_TIME, &seconds.to_be_bytes())
    }

    /// Option 59, the rebinding time T2 in seconds.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn rebinding_time(&mut self, seconds: u32) -> Result<&mut Self, EncodeError> {
        self.option(code::REBINDING_TIME, &seconds.to_be_bytes())
    }

    /// Option 1, the subnet mask.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn subnet_mask(&mut self, mask: Ipv4Addr) -> Result<&mut Self, EncodeError> {
        self.option(code::SUBNET_MASK, &mask.octets())
    }

    /// Option 3, the routers in order of preference.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty list, [`EncodeError::NoRoom`].
    pub fn routers(&mut self, routers: &[Ipv4Addr]) -> Result<&mut Self, EncodeError> {
        self.addresses(code::ROUTERS, routers)
    }

    /// Option 6, the domain name servers in order of preference.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty list, [`EncodeError::NoRoom`].
    pub fn domain_name_servers(&mut self, servers: &[Ipv4Addr]) -> Result<&mut Self, EncodeError> {
        self.addresses(code::DOMAIN_NAME_SERVERS, servers)
    }

    /// Option 15, the domain name.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty name, [`EncodeError::NoRoom`].
    pub fn domain_name(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::DOMAIN_NAME, name)
    }

    /// Option 12, the host name.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty name, [`EncodeError::NoRoom`].
    pub fn host_name(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::HOST_NAME, name)
    }

    fn non_empty(&mut self, option: u8, data: &[u8]) -> Result<&mut Self, EncodeError> {
        if data.is_empty() {
            return Err(EncodeError::BadValue { code: option });
        }
        self.option(option, data)
    }

    /// Option 26, the interface MTU.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn interface_mtu(&mut self, mtu: u16) -> Result<&mut Self, EncodeError> {
        self.option(code::INTERFACE_MTU, &mtu.to_be_bytes())
    }

    /// Option 28, the broadcast address.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`].
    pub fn broadcast_address(&mut self, address: Ipv4Addr) -> Result<&mut Self, EncodeError> {
        self.option(code::BROADCAST_ADDRESS, &address.octets())
    }

    /// Option 42, the NTP servers in order of preference.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty list, [`EncodeError::NoRoom`].
    pub fn ntp_servers(&mut self, servers: &[Ipv4Addr]) -> Result<&mut Self, EncodeError> {
        self.addresses(code::NTP_SERVERS, servers)
    }

    /// Option 43, the vendor-specific information, as given.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty value, [`EncodeError::NoRoom`].
    pub fn vendor_specific(&mut self, data: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::VENDOR_SPECIFIC, data)
    }

    /// Option 60, the vendor class identifier (`PXEClient` for a PXE boot server, RFC
    /// 4578).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty value, [`EncodeError::NoRoom`].
    pub fn vendor_class_identifier(&mut self, data: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::VENDOR_CLASS_IDENTIFIER, data)
    }

    /// Option 66, the TFTP server name.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty name, [`EncodeError::NoRoom`].
    pub fn tftp_server_name(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::TFTP_SERVER_NAME, name)
    }

    /// Option 67, the boot file name.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty name, [`EncodeError::NoRoom`].
    pub fn bootfile_name(&mut self, name: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::BOOTFILE_NAME, name)
    }

    /// Option 81, the client FQDN of a server (RFC 4702, section 4): `flags` (S, O, E, N
    /// of [`ClientFqdn`]), both RCODE octets 255, and `name` in the canonical wire encoding
    /// when E is set (answer in the encoding the client used) or as ASCII text otherwise.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an ASCII name with a dot inside a label,
    /// [`EncodeError::NoRoom`].
    pub fn client_fqdn(&mut self, flags: u8, name: &WireName) -> Result<&mut Self, EncodeError> {
        const CODE: u8 = code::CLIENT_FQDN;
        let mut value = [0u8; 3 + MAX_WIRE_LEN];
        value[..3].copy_from_slice(&[flags, 255, 255]);
        let mut len = 3;
        if flags & ClientFqdn::FLAG_E != 0 {
            let wire = name.as_wire();
            value[3..3 + wire.len()].copy_from_slice(wire);
            len += wire.len();
        } else {
            for (index, label) in name.labels().enumerate() {
                if label.contains(&b'.') {
                    return Err(EncodeError::BadValue { code: CODE });
                }
                if index > 0 {
                    value[len] = b'.';
                    len += 1;
                }
                value[len..len + label.len()].copy_from_slice(label);
                len += label.len();
            }
            if name.is_absolute() && !name.is_empty() {
                value[len] = b'.';
                len += 1;
            }
        }
        self.option(CODE, &value[..len])
    }

    /// Option 82, the relay agent information of the request, copied unchanged (RFC 3046,
    /// section 2.2). Write it last: relay agents expect it as the last option.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadValue`] for an empty value, [`EncodeError::NoRoom`].
    pub fn relay_agent_info(&mut self, data: &[u8]) -> Result<&mut Self, EncodeError> {
        self.non_empty(code::RELAY_AGENT_INFORMATION, data)
    }

    /// Option 119, the domain search list, compressed ([`encode_domain_search`]) and split
    /// when it is longer than 255 octets.
    ///
    /// # Errors
    ///
    /// The errors of [`encode_domain_search`] (a list above 2,048 octets is encoded by the
    /// caller), [`EncodeError::NoRoom`].
    pub fn domain_search(&mut self, names: &[WireName]) -> Result<&mut Self, EncodeError> {
        self.assembled(code::DOMAIN_SEARCH, |out| encode_domain_search(names, out))
    }

    /// Option 121, the classless static routes ([`encode_classless_routes`]).
    ///
    /// # Errors
    ///
    /// The errors of [`encode_classless_routes`], [`EncodeError::NoRoom`].
    pub fn classless_routes(&mut self, routes: &[Route]) -> Result<&mut Self, EncodeError> {
        self.assembled(code::CLASSLESS_STATIC_ROUTES, |out| {
            encode_classless_routes(code::CLASSLESS_STATIC_ROUTES, routes, out)
        })
    }

    /// Writes option 52 when `file` or `sname` carry options, the end options and the
    /// padding, and returns the length of the message, which starts at `buf[0]`.
    ///
    /// # Errors
    ///
    /// None today; the result keeps the signature open for checks at the end.
    pub fn finish(self) -> Result<usize, EncodeError> {
        let overload = self.overload_value();
        let mut end = self.at.options;
        if overload != 0 {
            // `options_end` kept these three octets and the end option's.
            self.buf[end..end + 3].copy_from_slice(&[code::OVERLOAD, 1, overload]);
            end += 3;
        }
        self.buf[end] = code::END;
        end += 1;
        for (start, len, pos, state) in [
            (offset::FILE, FILE_LEN, self.at.file, self.at.file_state),
            (offset::SNAME, SNAME_LEN, self.at.sname, self.at.sname_state),
        ] {
            let field = &mut self.buf[start..start + len];
            match state {
                Field::Free => field.fill(0),
                Field::Value => {}
                Field::Options => {
                    field[pos] = code::END;
                    field[pos + 1..].fill(0);
                }
            }
        }
        if self.pad_to > end {
            self.buf[end..self.pad_to].fill(0);
            end = self.pad_to;
        }
        Ok(end)
    }
}

/// Writes `routes` as the value of option `option` (121, or 249 for Microsoft clients) in
/// the RFC 3442 encoding into `out` and returns its length: per route the prefix length,
/// the significant octets of the destination and the router.
///
/// # Errors
///
/// [`EncodeError::BadValue`] for an empty list or a prefix length above 32,
/// [`EncodeError::NoRoom`] when `out` is too small.
pub fn encode_classless_routes(
    option: u8,
    routes: &[Route],
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    if routes.is_empty() {
        return Err(EncodeError::BadValue { code: option });
    }
    let mut len = 0;
    for route in routes {
        if route.prefix_len > 32 {
            return Err(EncodeError::BadValue { code: option });
        }
        let significant = Route::significant_octets(route.prefix_len);
        let need = 1 + significant + 4;
        let target = out
            .get_mut(len..len + need)
            .ok_or(EncodeError::NoRoom { code: option })?;
        let destination =
            (u32::from(route.destination) & Route::mask(route.prefix_len)).to_be_bytes();
        target[0] = route.prefix_len;
        target[1..=significant].copy_from_slice(&destination[..significant]);
        target[1 + significant..].copy_from_slice(&route.router.octets());
        len += need;
    }
    Ok(len)
}
