//! The DHCPv6 message builder: a message written into a caller's buffer without
//! allocating.
//!
//! [`MessageBuilder::message`] starts a client or server message (type and transaction id)
//! and [`MessageBuilder::relay`] a relay message (type, hop count, link and peer address).
//! Options are appended with [`MessageBuilder::option`]; an option that holds options (an
//! `IA_NA` with its addresses, an IA Address with its status, a Relay Message with the
//! message it relays) is opened with [`MessageBuilder::begin`], filled, and closed with
//! [`MessageBuilder::end`], which writes its length. So a RELAY-REPL around a RELAY-REPL
//! around a REPLY is written outside in, in one pass. Nothing is truncated: an option that
//! does not fit within the limit returns [`EncodeError::NoRoom`] and leaves the message as
//! it was, and [`MessageBuilder::rewind`] takes back an opened option and everything in
//! it when the caller decides to leave it out.

use std::net::Ipv6Addr;

use super::{CLIENT_HEADER_LEN, EncodeError, MessageType, NtpServer, RELAY_HEADER_LEN, code};
use crate::v4::WireName;

/// How deep options may nest in the builder: relay messages (one per relay) and an
/// `IA_NA`, an IA Address and its status inside the innermost.
pub const MAX_NESTING: usize = super::MAX_RELAY_DEPTH + 4;

/// An option opened with [`MessageBuilder::begin`]: where its code starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    at: usize,
    depth: usize,
}

/// Writes one DHCPv6 message into a buffer.
#[derive(Debug)]
pub struct MessageBuilder<'b> {
    buf: &'b mut [u8],
    len: usize,
    limit: usize,
    open: [usize; MAX_NESTING],
    depth: usize,
}

impl<'b> MessageBuilder<'b> {
    /// A builder over `buf` that writes at most `limit` octets (the smaller of the two).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`] when the room is below a relay header.
    pub fn new(buf: &'b mut [u8], limit: usize) -> Result<Self, EncodeError> {
        let limit = limit.min(buf.len());
        if limit < RELAY_HEADER_LEN {
            return Err(EncodeError::BufferTooSmall);
        }
        Ok(Self {
            buf,
            len: 0,
            limit,
            open: [0; MAX_NESTING],
            depth: 0,
        })
    }

    /// Writes the header of a client or server message at the current position: the type
    /// and the low 24 bits of `transaction_id`. A header inside an opened Relay Message
    /// option starts the relayed message.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`] when the header does not fit.
    pub fn message(
        &mut self,
        kind: MessageType,
        transaction_id: u32,
    ) -> Result<&mut Self, EncodeError> {
        let id = transaction_id.to_be_bytes();
        self.put(0, &[kind.to_u8(), id[1], id[2], id[3]])?;
        debug_assert_eq!(CLIENT_HEADER_LEN, 4);
        Ok(self)
    }

    /// Writes the header of a relay message at the current position.
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`] when the header does not fit.
    pub fn relay(
        &mut self,
        kind: MessageType,
        hop_count: u8,
        link_address: Ipv6Addr,
        peer_address: Ipv6Addr,
    ) -> Result<&mut Self, EncodeError> {
        let mut header = [0u8; RELAY_HEADER_LEN];
        header[0] = kind.to_u8();
        header[1] = hop_count;
        header[2..18].copy_from_slice(&link_address.octets());
        header[18..34].copy_from_slice(&peer_address.octets());
        self.put(0, &header)?;
        Ok(self)
    }

    fn put(&mut self, code: u16, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self.len + bytes.len();
        if end > self.limit {
            return Err(EncodeError::NoRoom { code });
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// Appends one option.
    ///
    /// # Errors
    ///
    /// [`EncodeError::TooLong`] above 65,535 octets, [`EncodeError::NoRoom`] when it does
    /// not fit (nothing is written then).
    pub fn option(&mut self, code: u16, data: &[u8]) -> Result<&mut Self, EncodeError> {
        let len = u16::try_from(data.len()).map_err(|_| EncodeError::TooLong { code })?;
        if self.len + 4 + data.len() > self.limit {
            return Err(EncodeError::NoRoom { code });
        }
        let [c0, c1] = code.to_be_bytes();
        let [l0, l1] = len.to_be_bytes();
        self.put(code, &[c0, c1, l0, l1])?;
        self.put(code, data)?;
        Ok(self)
    }

    /// Appends an option made of parts, written one after the other (a header and a
    /// value) without assembling them first.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::option`].
    pub fn option_parts(&mut self, code: u16, parts: &[&[u8]]) -> Result<&mut Self, EncodeError> {
        let total: usize = parts.iter().map(|part| part.len()).sum();
        let len = u16::try_from(total).map_err(|_| EncodeError::TooLong { code })?;
        if self.len + 4 + total > self.limit {
            return Err(EncodeError::NoRoom { code });
        }
        let [c0, c1] = code.to_be_bytes();
        let [l0, l1] = len.to_be_bytes();
        self.put(code, &[c0, c1, l0, l1])?;
        for part in parts {
            self.put(code, part)?;
        }
        Ok(self)
    }

    /// Opens an option whose value is written next (options, or a relayed message), and
    /// returns its mark for [`MessageBuilder::end`].
    ///
    /// # Errors
    ///
    /// [`EncodeError::NoRoom`] when not even its code and length fit,
    /// [`EncodeError::Unbalanced`] beyond [`MAX_NESTING`] open options.
    pub fn begin(&mut self, code: u16) -> Result<Mark, EncodeError> {
        if self.depth == MAX_NESTING {
            return Err(EncodeError::Unbalanced);
        }
        let at = self.len;
        let [c0, c1] = code.to_be_bytes();
        self.put(code, &[c0, c1, 0, 0])?;
        self.open[self.depth] = at;
        self.depth += 1;
        Ok(Mark {
            at,
            depth: self.depth,
        })
    }

    /// Closes the option of `mark`: writes its length.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Unbalanced`] when `mark` is not the innermost open option,
    /// [`EncodeError::TooLong`] for a value above 65,535 octets.
    pub fn end(&mut self, mark: Mark) -> Result<&mut Self, EncodeError> {
        if mark.depth != self.depth || self.open[self.depth - 1] != mark.at {
            return Err(EncodeError::Unbalanced);
        }
        let value = self.len - mark.at - 4;
        let code = u16::from_be_bytes([self.buf[mark.at], self.buf[mark.at + 1]]);
        let len = u16::try_from(value).map_err(|_| EncodeError::TooLong { code })?;
        self.buf[mark.at + 2..mark.at + 4].copy_from_slice(&len.to_be_bytes());
        self.depth -= 1;
        Ok(self)
    }

    /// Takes back the option of `mark` and everything written in it, and closes it.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Unbalanced`] when `mark` is not the innermost open option.
    pub fn rewind(&mut self, mark: Mark) -> Result<&mut Self, EncodeError> {
        if mark.depth != self.depth || self.open[self.depth - 1] != mark.at {
            return Err(EncodeError::Unbalanced);
        }
        self.len = mark.at;
        self.depth -= 1;
        Ok(self)
    }

    /// The octets written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The room left within the limit.
    pub fn room(&self) -> usize {
        self.limit - self.len
    }

    /// Appends the Status Code option.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::option`].
    pub fn status(&mut self, status: u16, message: &[u8]) -> Result<&mut Self, EncodeError> {
        self.option_parts(code::STATUS_CODE, &[&status.to_be_bytes(), message])
    }

    /// Opens an `IA_NA` with its IAID, T1 and T2; its options follow.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::begin`].
    pub fn begin_ia_na(&mut self, iaid: u32, t1: u32, t2: u32) -> Result<Mark, EncodeError> {
        let mark = self.begin(code::IA_NA)?;
        let mut head = [0u8; 12];
        head[..4].copy_from_slice(&iaid.to_be_bytes());
        head[4..8].copy_from_slice(&t1.to_be_bytes());
        head[8..].copy_from_slice(&t2.to_be_bytes());
        if let Err(error) = self.put(code::IA_NA, &head) {
            self.rewind(mark)?;
            return Err(error);
        }
        Ok(mark)
    }

    /// Opens an IA Address with its lifetimes; its options (a status) follow.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::begin`].
    pub fn begin_ia_address(
        &mut self,
        addr: Ipv6Addr,
        preferred: u32,
        valid: u32,
    ) -> Result<Mark, EncodeError> {
        let mark = self.begin(code::IAADDR)?;
        let mut head = [0u8; 24];
        head[..16].copy_from_slice(&addr.octets());
        head[16..20].copy_from_slice(&preferred.to_be_bytes());
        head[20..].copy_from_slice(&valid.to_be_bytes());
        if let Err(error) = self.put(code::IAADDR, &head) {
            self.rewind(mark)?;
            return Err(error);
        }
        Ok(mark)
    }

    /// Appends an IA Address without options.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::option`].
    pub fn ia_address(
        &mut self,
        addr: Ipv6Addr,
        preferred: u32,
        valid: u32,
    ) -> Result<&mut Self, EncodeError> {
        self.option_parts(
            code::IAADDR,
            &[
                &addr.octets(),
                &preferred.to_be_bytes(),
                &valid.to_be_bytes(),
            ],
        )
    }

    /// Appends a list of addresses (options 23, 31, 22).
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::option`].
    pub fn addresses(&mut self, code: u16, addrs: &[Ipv6Addr]) -> Result<&mut Self, EncodeError> {
        let total = addrs.len() * 16;
        let len = u16::try_from(total).map_err(|_| EncodeError::TooLong { code })?;
        if self.len + 4 + total > self.limit {
            return Err(EncodeError::NoRoom { code });
        }
        let [c0, c1] = code.to_be_bytes();
        let [l0, l1] = len.to_be_bytes();
        self.put(code, &[c0, c1, l0, l1])?;
        for addr in addrs {
            self.put(code, &addr.octets())?;
        }
        Ok(self)
    }

    /// Appends the Client FQDN option of RFC 4704 with `flags` and `name`.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::option`].
    pub fn client_fqdn(&mut self, flags: u8, name: &WireName) -> Result<&mut Self, EncodeError> {
        self.option_parts(code::CLIENT_FQDN, &[&[flags], name.as_wire()])
    }

    /// Checks that every opened option was closed and returns the length.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Unbalanced`] while an option is open.
    pub fn finish(self) -> Result<usize, EncodeError> {
        if self.depth == 0 {
            Ok(self.len)
        } else {
            Err(EncodeError::Unbalanced)
        }
    }
}

/// Writes `names` as the value of a domain list (option 24, RFC 3646 section 4: each name
/// uncompressed, absolute) into `out` and returns its length.
///
/// # Errors
///
/// [`EncodeError::BadValue`] for a relative name, [`EncodeError::NoRoom`] when `out` is
/// too small.
pub fn encode_domain_list<'n>(
    names: impl IntoIterator<Item = &'n WireName>,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut len = 0;
    for name in names {
        if !name.is_absolute() {
            return Err(EncodeError::BadValue {
                code: code::DOMAIN_LIST,
            });
        }
        let wire = name.as_wire();
        out.get_mut(len..len + wire.len())
            .ok_or(EncodeError::NoRoom {
                code: code::DOMAIN_LIST,
            })?
            .copy_from_slice(wire);
        len += wire.len();
    }
    Ok(len)
}

/// Writes `servers` as the value of the NTP Server option (RFC 5908), one
/// `NTP_SUBOPTION_SRV_ADDR` sub-option per address, into `out`; returns its length.
///
/// # Errors
///
/// [`EncodeError::NoRoom`] when `out` is too small.
pub fn encode_ntp_servers(servers: &[Ipv6Addr], out: &mut [u8]) -> Result<usize, EncodeError> {
    let mut len = 0;
    for server in servers {
        let slot = out.get_mut(len..len + 20).ok_or(EncodeError::NoRoom {
            code: code::NTP_SERVER,
        })?;
        slot[..2].copy_from_slice(&NtpServer::SRV_ADDR.to_be_bytes());
        slot[2..4].copy_from_slice(&16u16.to_be_bytes());
        slot[4..].copy_from_slice(&server.octets());
        len += 20;
    }
    Ok(len)
}
