//! The view over a received DHCPv6 message (RFC 8415 sections 8, 9 and 21.1) and the walk
//! of a relay chain.

use std::{fmt, net::Ipv6Addr};

use super::{
    CLIENT_HEADER_LEN, DecodeError, MAX_RELAY_DEPTH, MessageType, RELAY_HEADER_LEN, addr_at, code,
    option::{
        ClientFqdn, Duid, IaNa, IaPd, LengthPrefixed, LinkLayerAddress, OptionRequest, RemoteId,
        VendorClass, fixed,
    },
    u16_at,
};

/// One option as it is on the wire: its code and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOption<'a> {
    /// The code.
    pub code: u16,
    /// The value, without code and length.
    pub data: &'a [u8],
}

/// The options of one area (a message's, or those nested in an option), in order. A
/// malformed option is yielded once as an error and ends the walk.
#[derive(Clone, Copy)]
pub struct Options<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> Options<'a> {
    /// The options encoded in `area`.
    pub const fn new(area: &'a [u8]) -> Self {
        Self {
            rest: area,
            failed: false,
        }
    }

    /// The first instance of `code`, or the error of a malformed option before it.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when the walk fails before an instance of `code`.
    pub fn first(self, code: u16) -> Result<Option<&'a [u8]>, DecodeError> {
        for option in self {
            let option = option?;
            if option.code == code {
                return Ok(Some(option.data));
            }
        }
        Ok(None)
    }

    /// Whether the area holds an instance of `code` before any malformed option.
    pub fn has(self, code: u16) -> bool {
        matches!(self.first(code), Ok(Some(_)))
    }

    /// Walks every option; the first error.
    ///
    /// # Errors
    ///
    /// The first malformed option.
    pub fn validate(self) -> Result<(), DecodeError> {
        for option in self {
            option?;
        }
        Ok(())
    }
}

impl fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(*self).finish()
    }
}

#[allow(
    clippy::copy_iterator,
    reason = "a walk is a cursor over borrowed octets; copying it starts another walk"
)]
impl<'a> Iterator for Options<'a> {
    type Item = Result<RawOption<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 4 {
            self.failed = true;
            let code = if self.rest.len() >= 2 {
                u16_at(self.rest, 0)
            } else {
                0
            };
            return Some(Err(DecodeError::Truncated { code }));
        }
        let code = u16_at(self.rest, 0);
        let len = usize::from(u16_at(self.rest, 2));
        let Some(data) = self.rest.get(4..4 + len) else {
            self.failed = true;
            return Some(Err(DecodeError::Truncated { code }));
        };
        self.rest = &self.rest[4 + len..];
        Some(Ok(RawOption { code, data }))
    }
}

/// A received DHCPv6 message: a view over the datagram (or over the value of a Relay
/// Message option).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    buf: &'a [u8],
}

impl<'a> Message<'a> {
    /// The message in `buf`: at least the header of its type (four octets for a client or
    /// server message, 34 for a relay message).
    ///
    /// # Errors
    ///
    /// [`DecodeError::TooShort`] for a datagram shorter than its header.
    pub fn parse(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let Some(&kind) = buf.first() else {
            return Err(DecodeError::TooShort { len: 0 });
        };
        let header = if MessageType::from_u8(kind).is_relay() {
            RELAY_HEADER_LEN
        } else {
            CLIENT_HEADER_LEN
        };
        if buf.len() < header {
            return Err(DecodeError::TooShort { len: buf.len() });
        }
        Ok(Self { buf })
    }

    /// The octets of the message.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The length of the message.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the message is empty (never: a parsed message has its header).
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The message type.
    pub fn kind(&self) -> MessageType {
        MessageType::from_u8(self.buf[0])
    }

    /// Whether the message is a RELAY-FORW or RELAY-REPL.
    pub fn is_relay(&self) -> bool {
        self.kind().is_relay()
    }

    /// The transaction id of a client or server message (three octets); 0 for a relay
    /// message.
    pub fn transaction_id(&self) -> u32 {
        if self.is_relay() {
            0
        } else {
            u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]])
        }
    }

    /// The hop count of a relay message; 0 otherwise.
    pub fn hop_count(&self) -> u8 {
        if self.is_relay() { self.buf[1] } else { 0 }
    }

    /// The link address of a relay message (RFC 8415 section 9); unspecified otherwise.
    pub fn link_address(&self) -> Ipv6Addr {
        if self.is_relay() {
            addr_at(self.buf, 2)
        } else {
            Ipv6Addr::UNSPECIFIED
        }
    }

    /// The peer address of a relay message; unspecified otherwise.
    pub fn peer_address(&self) -> Ipv6Addr {
        if self.is_relay() {
            addr_at(self.buf, 18)
        } else {
            Ipv6Addr::UNSPECIFIED
        }
    }

    /// The octets of the options area.
    pub fn options_area(&self) -> &'a [u8] {
        let header = if self.is_relay() {
            RELAY_HEADER_LEN
        } else {
            CLIENT_HEADER_LEN
        };
        &self.buf[header..]
    }

    /// The options in order.
    pub fn options(&self) -> Options<'a> {
        Options::new(self.options_area())
    }

    /// Walks every option; the first error.
    ///
    /// # Errors
    ///
    /// The first malformed option.
    pub fn validate(&self) -> Result<(), DecodeError> {
        self.options().validate()
    }

    /// The first instance of an option.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when a malformed option comes before any instance.
    pub fn option(&self, code: u16) -> Result<Option<&'a [u8]>, DecodeError> {
        self.options().first(code)
    }

    /// Whether the message carries the option (before any malformed one).
    pub fn has(&self, code: u16) -> bool {
        self.options().has(code)
    }

    fn typed<T>(
        &self,
        code: u16,
        parse: impl FnOnce(&'a [u8]) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        self.option(code)?.map(parse).transpose()
    }

    /// Option 1, the client's DUID.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a DUID of a bad length.
    pub fn client_id(&self) -> Result<Option<Duid<'a>>, DecodeError> {
        self.typed(code::CLIENTID, |data| Duid::parse(code::CLIENTID, data))
    }

    /// Option 2, the server's DUID.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a DUID of a bad length.
    pub fn server_id(&self) -> Result<Option<Duid<'a>>, DecodeError> {
        self.typed(code::SERVERID, |data| Duid::parse(code::SERVERID, data))
    }

    /// Option 6, the options the client asks for.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or an odd length.
    pub fn option_request(&self) -> Result<Option<OptionRequest<'a>>, DecodeError> {
        self.typed(code::ORO, OptionRequest::parse)
    }

    /// Option 8, the elapsed time in hundredths of a second.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a length other than two.
    pub fn elapsed_time(&self) -> Result<Option<u16>, DecodeError> {
        self.typed(code::ELAPSED_TIME, |data| {
            fixed::<2>(code::ELAPSED_TIME, data).map(u16::from_be_bytes)
        })
    }

    /// Option 14: whether the client asks for rapid commit (RFC 8415 section 18.2.1).
    pub fn rapid_commit(&self) -> bool {
        self.has(code::RAPID_COMMIT)
    }

    /// Option 20: whether the client accepts Reconfigure messages.
    pub fn reconfigure_accept(&self) -> bool {
        self.has(code::RECONF_ACCEPT)
    }

    /// Option 9 of a relay message, the relayed message.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a relayed message shorter than its header.
    pub fn relay_message(&self) -> Result<Option<Message<'a>>, DecodeError> {
        self.typed(code::RELAY_MSG, Message::parse)
    }

    /// Option 18, the relay's Interface-Id.
    ///
    /// # Errors
    ///
    /// A malformed option before it.
    pub fn interface_id(&self) -> Result<Option<&'a [u8]>, DecodeError> {
        self.option(code::INTERFACE_ID)
    }

    /// Option 37, the relay's Remote-Id (RFC 4649).
    ///
    /// # Errors
    ///
    /// A malformed option before it, or one shorter than its enterprise number.
    pub fn remote_id(&self) -> Result<Option<RemoteId<'a>>, DecodeError> {
        self.typed(code::REMOTE_ID, RemoteId::parse)
    }

    /// Option 79, the client's link-layer address a relay added (RFC 6939).
    ///
    /// # Errors
    ///
    /// A malformed option before it, or one shorter than its type.
    pub fn client_link_layer(&self) -> Result<Option<LinkLayerAddress<'a>>, DecodeError> {
        self.typed(code::CLIENT_LINKLAYER_ADDR, LinkLayerAddress::parse)
    }

    /// Option 39, the client's FQDN (RFC 4704).
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a malformed name.
    pub fn client_fqdn(&self) -> Result<Option<ClientFqdn<'a>>, DecodeError> {
        self.typed(code::CLIENT_FQDN, ClientFqdn::parse)
    }

    /// Option 15, the user classes.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a class that runs past the end.
    pub fn user_class(&self) -> Result<Option<LengthPrefixed<'a>>, DecodeError> {
        self.typed(code::USER_CLASS, |data| {
            LengthPrefixed::parse(code::USER_CLASS, data)
        })
    }

    /// Option 16, the vendor class.
    ///
    /// # Errors
    ///
    /// A malformed option before it, or a malformed class.
    pub fn vendor_class(&self) -> Result<Option<VendorClass<'a>>, DecodeError> {
        self.typed(code::VENDOR_CLASS, VendorClass::parse)
    }

    /// The `IA_NA` options in order; a malformed one is yielded as an error and ends the
    /// walk.
    pub fn ia_nas(&self) -> impl Iterator<Item = Result<IaNa<'a>, DecodeError>> + 'a {
        of_code(self.options(), code::IA_NA, IaNa::parse)
    }

    /// The `IA_PD` options in order (WP9.2 serves them).
    pub fn ia_pds(&self) -> impl Iterator<Item = Result<IaPd<'a>, DecodeError>> + 'a {
        of_code(self.options(), code::IA_PD, IaPd::parse)
    }

    /// Whether the message carries an `IA_TA` option (not served).
    pub fn has_ia_ta(&self) -> bool {
        self.has(code::IA_TA)
    }
}

/// The instances of `code` in `options`, each parsed; the walk's error once.
pub(crate) fn of_code<'a, T: 'a>(
    options: Options<'a>,
    code: u16,
    parse: fn(&'a [u8]) -> Result<T, DecodeError>,
) -> impl Iterator<Item = Result<T, DecodeError>> + 'a {
    let mut failed = false;
    options.filter_map(move |option| {
        if failed {
            return None;
        }
        match option {
            Ok(option) if option.code == code => {
                let parsed = parse(option.data);
                failed = parsed.is_err();
                Some(parsed)
            }
            Ok(_) => None,
            Err(error) => {
                failed = true;
                Some(Err(error))
            }
        }
    })
}

impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("Message");
        out.field("kind", &self.kind());
        if self.is_relay() {
            out.field("hop_count", &self.hop_count())
                .field("link_address", &self.link_address())
                .field("peer_address", &self.peer_address());
        } else {
            out.field("transaction_id", &self.transaction_id());
        }
        out.field("options", &self.options()).finish()
    }
}

/// A received message with the relays it passed: the RELAY-FORW messages from the
/// outermost (the relay that sent the datagram to the server) to the innermost (the relay
/// on the client's link), and the client's message inside them. A message that a client
/// sent straight to the server has no relays.
#[derive(Clone, Copy)]
pub struct RelayChain<'a> {
    relays: [Option<Message<'a>>; MAX_RELAY_DEPTH],
    depth: usize,
    client: Message<'a>,
}

impl<'a> RelayChain<'a> {
    /// Walks `message` inwards: each RELAY-FORW must carry a Relay Message option whose
    /// value is a message, and at most [`MAX_RELAY_DEPTH`] relay messages may enclose the
    /// client's.
    ///
    /// # Errors
    ///
    /// [`DecodeError::RelayChain`] for a chain that is too deep or a RELAY-FORW without a
    /// relayed message, or the error of a malformed relay option before the relayed
    /// message.
    pub fn parse(message: Message<'a>) -> Result<Self, DecodeError> {
        let mut relays = [None; MAX_RELAY_DEPTH];
        let mut depth = 0;
        let mut current = message;
        while current.kind() == MessageType::RelayForw {
            if depth == MAX_RELAY_DEPTH {
                return Err(DecodeError::RelayChain);
            }
            relays[depth] = Some(current);
            depth += 1;
            current = current.relay_message()?.ok_or(DecodeError::RelayChain)?;
        }
        Ok(Self {
            relays,
            depth,
            client: current,
        })
    }

    /// The client's message.
    pub fn client(&self) -> Message<'a> {
        self.client
    }

    /// The number of relays.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Whether the client's message came through a relay.
    pub fn is_relayed(&self) -> bool {
        self.depth > 0
    }

    /// The relay messages, outermost first.
    pub fn relays(&self) -> impl DoubleEndedIterator<Item = Message<'a>> + '_ {
        self.relays[..self.depth].iter().flatten().copied()
    }

    /// The relay closest to the client (the innermost RELAY-FORW).
    pub fn innermost(&self) -> Option<Message<'a>> {
        self.depth.checked_sub(1).and_then(|at| self.relays[at])
    }

    /// The relay that sent the datagram (the outermost RELAY-FORW).
    pub fn outermost(&self) -> Option<Message<'a>> {
        self.relays[0].filter(|_| self.depth > 0)
    }

    /// The link address that tells the client's link: the innermost relay's that is not
    /// unspecified (a lightweight relay of RFC 6221 sends zero and the relay above it
    /// names the link, RFC 6221 section 5.3).
    pub fn link_address(&self) -> Option<Ipv6Addr> {
        self.relays()
            .rev()
            .map(|relay| relay.link_address())
            .find(|addr| !addr.is_unspecified())
    }

    /// The Interface-Id of the innermost relay that sends one.
    pub fn interface_id(&self) -> Option<&'a [u8]> {
        self.relays()
            .rev()
            .find_map(|relay| relay.interface_id().ok().flatten())
    }

    /// The Remote-Id of the innermost relay that sends one (RFC 4649).
    pub fn remote_id(&self) -> Option<RemoteId<'a>> {
        self.relays()
            .rev()
            .find_map(|relay| relay.remote_id().ok().flatten())
    }

    /// The client's link-layer address of the innermost relay that adds one (RFC 6939:
    /// the relay on the client's link).
    pub fn client_link_layer(&self) -> Option<LinkLayerAddress<'a>> {
        self.relays()
            .rev()
            .find_map(|relay| relay.client_link_layer().ok().flatten())
    }
}

impl fmt::Debug for RelayChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayChain")
            .field("relays", &self.relays().collect::<arrayish::Relays<'_>>())
            .field("client", &self.client)
            .finish()
    }
}

/// Debug output of the relays without collecting into a heap vector.
mod arrayish {
    use std::fmt;

    use super::{MAX_RELAY_DEPTH, Message};

    pub(super) struct Relays<'a>([Option<Message<'a>>; MAX_RELAY_DEPTH]);

    impl<'a> FromIterator<Message<'a>> for Relays<'a> {
        fn from_iter<I: IntoIterator<Item = Message<'a>>>(iter: I) -> Self {
            let mut out = [None; MAX_RELAY_DEPTH];
            for (slot, message) in out.iter_mut().zip(iter) {
                *slot = Some(message);
            }
            Self(out)
        }
    }

    impl fmt::Debug for Relays<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list().entries(self.0.iter().flatten()).finish()
        }
    }
}
