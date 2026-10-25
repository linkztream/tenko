//! The DHCPv6 reply (RFC 8415 sections 18.3 and 19.3): an ADVERTISE or REPLY, wrapped in a
//! RELAY-REPL per relay the request passed, written into the worker's buffer in one pass.
//!
//! - **The relays.** For each RELAY-FORW from the outermost in: a RELAY-REPL with its hop
//!   count, link address and peer address, its Interface-Id echoed when it sent one (RFC
//!   8415 section 19.3), and a Relay Message option around the next layer.
//! - **The message.** The type and the client's transaction id; the Server Identifier (the
//!   server's DUID) and the Client Identifier echoed; the `IA_NA`s in the client's order,
//!   each with its address and lifetimes, the addresses the client may no longer use with
//!   lifetimes of zero, or its status, then the `IA_PD`s (WP9.2) the same way with IA
//!   Prefix options; a top-level Status Code when the message has one;
//!   Rapid Commit in a REPLY to a SOLICIT that asked for it; the Client FQDN option of RFC
//!   4704 with the server's flags; then the options the client asks for in its Option
//!   Request, in its order, and the DNS servers (23) and domain list (24) when they are set
//!   and not asked for (as the DHCPv4 engine sends options 6 and 15), from the most
//!   specific level that holds the code: the reservation, the pool, then the scope (which
//!   holds the shared network's and the server's already merged).
//! - **The size.** An option that does not fit is left out whole; the identifiers, the
//!   `IA_NA`s and the statuses come first, so what is left out is a configuration option.
//!
//! Option 56 holds addresses in the option set; it is written as one
//! `NTP_SUBOPTION_SRV_ADDR` per address (RFC 5908 section 4.1).

use std::net::Ipv6Addr;

use tenko_core::dhcp::{Lease6Kind, OptionValue, SERVER_MANAGED_V6};

use crate::{
    v4::WireName,
    v6::{
        EncodeError, MessageBuilder, MessageType, OptionRequest, RelayChain, code,
        encode_ntp_servers, image::Scope6Image,
    },
};

/// Addresses returned with lifetimes of zero per IA, at most.
pub const MAX_ZEROED: usize = 4;

/// The answer for one `IA_NA` or (WP9.2) `IA_PD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaReply {
    /// An `IA_NA` or an `IA_PD`.
    pub kind: Lease6Kind,
    /// The IAID.
    pub iaid: u32,
    /// T1.
    pub t1: u32,
    /// T2.
    pub t2: u32,
    /// The address, or the delegated prefix, with its preferred and valid lifetimes.
    pub addr: Option<(Ipv6Addr, u32, u32)>,
    /// The length of the delegated prefix in `addr` (128 for an address).
    pub prefix_len: u8,
    /// Addresses or prefixes (with their lengths) the client may no longer use (lifetimes
    /// of zero).
    pub zeroed: [Option<(Ipv6Addr, u8)>; MAX_ZEROED],
    /// The IA's status, when it has one.
    pub status: Option<u16>,
}

impl IaReply {
    /// An `IA_NA` without an address yet.
    pub const fn new(iaid: u32) -> Self {
        Self {
            kind: Lease6Kind::Na,
            iaid,
            t1: 0,
            t2: 0,
            addr: None,
            prefix_len: 128,
            zeroed: [None; MAX_ZEROED],
            status: None,
        }
    }

    /// An `IA_PD` without a prefix yet.
    pub const fn new_pd(iaid: u32) -> Self {
        let mut reply = Self::new(iaid);
        reply.kind = Lease6Kind::Pd;
        reply
    }

    /// Adds an address to return with lifetimes of zero; false when full.
    pub fn zero(&mut self, addr: Ipv6Addr) -> bool {
        self.zero_prefix(addr, 128)
    }

    /// Adds a prefix to return with lifetimes of zero; false when full.
    pub fn zero_prefix(&mut self, addr: Ipv6Addr, len: u8) -> bool {
        if self.zeroed.contains(&Some((addr, len))) {
            return true;
        }
        match self.zeroed.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some((addr, len));
                true
            }
            None => false,
        }
    }
}

/// The option levels of a reply, most specific last.
#[derive(Debug, Clone, Copy, Default)]
pub struct Levels6<'a> {
    /// The scope (its options merged with the shared network's and the server's).
    pub scope: Option<&'a Scope6Image>,
    /// The pool's options.
    pub pool: Option<&'a [OptionValue]>,
    /// The reservation's options.
    pub host: Option<&'a [OptionValue]>,
}

impl<'a> Levels6<'a> {
    /// The value of a `dhcp6` code, from the most specific level that holds it.
    pub fn value(&self, code: u16) -> Option<&'a OptionValue> {
        let find = |values: &'a [OptionValue]| {
            values
                .iter()
                .find(|value| value.space.is_dhcp6() && value.code == code)
        };
        self.host
            .and_then(find)
            .or_else(|| self.pool.and_then(find))
            .or_else(|| self.scope.and_then(|scope| scope.option(code)))
    }
}

/// What a reply says.
#[derive(Debug, Clone, Copy)]
pub struct Reply6<'r> {
    /// The request with its relays.
    pub chain: &'r RelayChain<'r>,
    /// ADVERTISE or REPLY.
    pub kind: MessageType,
    /// The server's DUID.
    pub server_duid: &'r [u8],
    /// The client's DUID, echoed.
    pub client_id: Option<&'r [u8]>,
    /// The answers per `IA_NA`, in the client's order.
    pub ias: &'r [IaReply],
    /// The top-level status and its message.
    pub status: Option<(u16, &'r str)>,
    /// Rapid Commit in the reply.
    pub rapid_commit: bool,
    /// The client FQDN reply: the flags of option 39 and the name.
    pub fqdn: Option<(u8, &'r WireName)>,
    /// The options the client asks for.
    pub oro: Option<OptionRequest<'r>>,
    /// The configuration levels.
    pub levels: Levels6<'r>,
}

/// Codes sent although the client did not ask for them, when set.
const UNASKED: [u16; 2] = [code::DNS_SERVERS, code::DOMAIN_LIST];

/// Writes `reply` into `buf` within `limit` octets; its length.
///
/// # Errors
///
/// [`EncodeError`] when not even the relays, the identifiers and the IAs fit.
pub fn write(buf: &mut [u8], limit: usize, reply: &Reply6<'_>) -> Result<usize, EncodeError> {
    let mut builder = MessageBuilder::new(buf, limit)?;
    let mut marks = [None; crate::v6::MAX_RELAY_DEPTH];
    for (depth, relay) in reply.chain.relays().enumerate() {
        builder.relay(
            MessageType::RelayRepl,
            relay.hop_count(),
            relay.link_address(),
            relay.peer_address(),
        )?;
        if let Ok(Some(id)) = relay.interface_id() {
            builder.option(code::INTERFACE_ID, id)?;
        }
        marks[depth] = Some(builder.begin(code::RELAY_MSG)?);
    }
    builder.message(reply.kind, reply.chain.client().transaction_id())?;
    builder.option(code::SERVERID, reply.server_duid)?;
    if let Some(client) = reply.client_id {
        builder.option(code::CLIENTID, client)?;
    }
    for ia in reply.ias {
        let pd = ia.kind == Lease6Kind::Pd;
        let mark = if pd {
            builder.begin_ia_pd(ia.iaid, ia.t1, ia.t2)?
        } else {
            builder.begin_ia_na(ia.iaid, ia.t1, ia.t2)?
        };
        if let Some((addr, preferred, valid)) = ia.addr {
            if pd {
                builder.ia_prefix(addr, ia.prefix_len, preferred, valid)?;
            } else {
                builder.ia_address(addr, preferred, valid)?;
            }
        }
        for (addr, len) in ia.zeroed.iter().flatten() {
            if Some((*addr, *len)) == ia.addr.map(|(held, _, _)| (held, ia.prefix_len)) {
                continue;
            }
            if pd {
                builder.ia_prefix(*addr, *len, 0, 0)?;
            } else {
                builder.ia_address(*addr, 0, 0)?;
            }
        }
        if let Some(status) = ia.status {
            builder.status(status, status_text(status).as_bytes())?;
        }
        builder.end(mark)?;
    }
    if let Some((status, text)) = reply.status {
        builder.status(status, text.as_bytes())?;
    }
    if reply.rapid_commit {
        builder.option(code::RAPID_COMMIT, &[])?;
    }
    if let Some((flags, name)) = reply.fqdn {
        // A name too long for the room left is no reason to fail the reply.
        let _ = builder.client_fqdn(flags, name);
    }
    write_options(&mut builder, reply);
    for mark in marks.iter().rev().flatten() {
        builder.end(*mark)?;
    }
    builder.finish()
}

/// The configuration options: the asked-for ones in the client's order, then the unasked
/// DNS options; each code once, none the server manages.
fn write_options(builder: &mut MessageBuilder<'_>, reply: &Reply6<'_>) {
    let mut written = [0u16; 64];
    let mut count = 0;
    let asked = reply.oro.into_iter().flat_map(OptionRequest::codes);
    for code in asked.chain(UNASKED) {
        if SERVER_MANAGED_V6.contains(&code) || written[..count].contains(&code) {
            continue;
        }
        let Some(value) = reply.levels.value(code) else {
            continue;
        };
        if count < written.len() {
            written[count] = code;
            count += 1;
        }
        let data = value.data.0.as_slice();
        if code == code::NTP_SERVER {
            let mut servers = [Ipv6Addr::UNSPECIFIED; 16];
            let mut n = 0;
            for chunk in data.as_chunks::<16>().0.iter().take(servers.len()) {
                servers[n] = Ipv6Addr::from(*chunk);
                n += 1;
            }
            let mut encoded = [0u8; 16 * 20];
            if let Ok(len) = encode_ntp_servers(&servers[..n], &mut encoded) {
                let _ = builder.option(code, &encoded[..len]);
            }
        } else {
            let _ = builder.option(code, data);
        }
    }
}

/// The English text of a status code.
pub fn status_text(status: u16) -> &'static str {
    use crate::v6::status;
    match status {
        status::SUCCESS => "success",
        status::NO_ADDRS_AVAIL => "no address is available for this IA",
        status::NO_BINDING => "no binding for this IA",
        status::NOT_ON_LINK => "an address is not appropriate for the link",
        status::USE_MULTICAST => "send to the multicast address",
        status::NO_PREFIX_AVAIL => "no prefix is available for this IA",
        _ => "the request failed",
    }
}
