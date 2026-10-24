//! The DHCPv6 engine (RFC 8415, WP9.1): a pure function of the configuration image, the
//! DHCPv6 lease table, the offers held, the request and the clock, which returns what to
//! send, where, and the lease change to commit first, as the DHCPv4 engine of
//! [`crate::v4::engine`] does.
//!
//! [`handle`] reads one received datagram:
//!
//! - **The relays** ([`RelayChain`]). A RELAY-FORW is walked to the client's message, at
//!   most eight relays deep; the reply goes back through a RELAY-REPL per relay with its
//!   Interface-Id echoed, to the address the outermost RELAY-FORW came from.
//! - **The client.** Its DUID (option 1); its link-layer address from the Client
//!   Link-Layer Address option the relay on its link added (RFC 6939), else from a
//!   DUID-LLT or DUID-LL, for the MAC filters (DHCP-08), the reservations by MAC and the
//!   correlation with its DHCPv4 lease (DHCP-11).
//! - **The scope** ([`select`]): the relay's Interface-Id when a scope names it, else the
//!   link address of the innermost relay that sends one (RFC 6221: a lightweight relay
//!   sends zero and the relay above names the link), else, for a client on the listener's
//!   link, the listener's address. A scope of a shared network brings its siblings into the
//!   choice of address.
//! - **The message** (RFC 8415 section 18.3): SOLICIT gets an ADVERTISE and writes nothing
//!   (the address is held in [`Offers6`]), or with Rapid Commit, where the scope allows it,
//!   a REPLY after the commit; REQUEST, RENEW and REBIND get a REPLY after the commit, with
//!   lifetimes of zero for the addresses the client may no longer use; CONFIRM gets
//!   `Success` or `NotOnLink`; RELEASE and DECLINE commit and get a REPLY with `Success`;
//!   INFORMATION-REQUEST gets the options. One message is one change of up to
//!   [`MAX_BINDINGS`] bindings.
//! - **The reply** ([`assemble`]): the server's DUID, the client's, the `IA_NA`s in the
//!   client's order, the status, Rapid Commit, the client FQDN of RFC 4704 with the
//!   server's flags, and the options the client asks for (23, 24 and 56 among them) from
//!   the reservation, the pool and the scope.
//!
//! Classes and policies are DHCPv4 only. From the parse to the change in
//! [`Scratch6::change`] nothing allocates (`tests/alloc.rs`).

pub mod alloc;
pub mod assemble;
pub mod metrics;
pub mod offers;

use std::{
    net::{Ipv6Addr, SocketAddrV6},
    time::Duration,
};

use tenko_core::{
    Timestamp,
    dhcp::{BindingState, FilterVerdict, Lease6Kind, LeaseEventKind, lease::MAX_IDENTITY6},
};

use self::{
    alloc::{Client, Source},
    assemble::{IaReply, Levels6, Reply6},
};
pub use self::{
    metrics::{Metrics6Snapshot, WorkerMetrics6},
    offers::Offers6,
};
use super::{
    IaNa, Message, MessageType, RelayChain, code,
    image::Scope6Image,
    lease::{Binding6, Lease6Table, MAX_BINDINGS, PendingChange6, PendingRelay6},
    option::flags_from_v4,
    status,
};
use crate::{
    image::ConfigImage,
    lease::InlineBytes,
    v4::{
        WireName,
        engine::{DropReason, ListenMode},
    },
};

/// The largest datagram the engine writes: an Ethernet MTU less the IPv6 and UDP headers.
pub const REPLY_CAPACITY6: usize = 1500 - 40 - 8;

/// The engine's settings (`[dhcp]` and `[dhcp.v6]` of `tenko.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine6Settings {
    /// How long an ADVERTISE holds its addresses (`[dhcp] offer_secs`, 10).
    pub offer_secs: u32,
    /// How long a declined address stays abandoned (`[dhcp.decline] hold_secs`).
    pub decline_hold_secs: u32,
    /// The port replies to a relay agent go to (547).
    pub relay_port: u16,
    /// The port replies to a client go to (546).
    pub client_port: u16,
}

impl Default for Engine6Settings {
    fn default() -> Self {
        Self {
            offer_secs: 10,
            decline_hold_secs: 86_400,
            relay_port: super::SERVER_PORT,
            client_port: super::CLIENT_PORT,
        }
    }
}

/// One received datagram.
#[derive(Debug, Clone, Copy)]
pub struct Received6<'a> {
    /// The octets.
    pub bytes: &'a [u8],
    /// Where it came from.
    pub source: SocketAddrV6,
    /// The listener's address: the address that tells the link of a client on it.
    pub local: Ipv6Addr,
    /// The listener's mode.
    pub mode: ListenMode,
}

/// What the engine reads.
pub struct Context6<'a> {
    /// The configuration image.
    pub image: &'a ConfigImage,
    /// The DHCPv6 lease table.
    pub leases: &'a dyn Lease6Table,
    /// The offers held.
    pub offers: &'a Offers6,
    /// The settings.
    pub settings: &'a Engine6Settings,
    /// The server's DUID (option 2).
    pub server_duid: &'a [u8],
    /// Whether the store takes lease writes now (P3-Q14).
    pub accepting: bool,
    /// Now.
    pub now: Timestamp,
}

/// Where a reply goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination6 {
    /// The relay that sent the RELAY-FORW, on the relay port.
    Relay(SocketAddrV6),
    /// The client, on the client port.
    Client(SocketAddrV6),
}

impl Destination6 {
    /// The socket address.
    pub fn address(self) -> SocketAddrV6 {
        match self {
            Self::Relay(address) | Self::Client(address) => address,
        }
    }
}

/// Why a well-formed request got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignore6 {
    /// A server's message (ADVERTISE, REPLY, RECONFIGURE, RELAY-REPL).
    NotRequest,
    /// A message type a server does not answer.
    OtherType,
    /// A message for another server (its Server Identifier).
    OtherServer,
    /// A message without the options its type needs, or with ones it must not have (RFC
    /// 8415 section 16).
    Incomplete,
}

/// What to do with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action6 {
    /// Send the reply in [`Scratch6::reply`] now.
    Reply {
        /// The reply's type.
        kind: MessageType,
        /// Its length.
        len: usize,
        /// Where it goes.
        dest: Destination6,
    },
    /// Commit [`Scratch6::change`], then send the reply.
    CommitThenReply {
        /// The reply's type.
        kind: MessageType,
        /// Its length.
        len: usize,
        /// Where it goes.
        dest: Destination6,
    },
    /// Drop and count.
    Drop(DropReason),
    /// No answer.
    Ignore(Ignore6),
}

/// How the scope was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector6 {
    /// The relay's Interface-Id.
    InterfaceId,
    /// The relay's link address.
    LinkAddress,
    /// The listener's address (a client on the listener's link).
    Listener,
}

/// The engine's answer to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer6 {
    /// The client's message type, when the message parsed.
    pub request: Option<MessageType>,
    /// What to do.
    pub action: Action6,
    /// How the scope was selected.
    pub selector: Option<Selector6>,
}

/// A worker's buffers, made once.
#[derive(Debug, Clone)]
pub struct Scratch6 {
    /// The reply.
    pub reply: [u8; REPLY_CAPACITY6],
    /// The lease change of [`Action6::CommitThenReply`].
    pub change: PendingChange6,
}

impl Scratch6 {
    /// The buffers of one worker, on the heap.
    pub fn new() -> Box<Self> {
        Box::new(Self {
            reply: [0; REPLY_CAPACITY6],
            change: PendingChange6::new(&[0, 0, 0], Timestamp::now()),
        })
    }
}

/// The request as the paths below read it.
struct Inbound<'m> {
    chain: &'m RelayChain<'m>,
    message: Message<'m>,
    duid: &'m [u8],
    link_layer: Option<(u16, &'m [u8])>,
    mac: Option<[u8; 6]>,
}

impl Inbound<'_> {
    fn client(&self) -> Client<'_> {
        Client {
            duid: self.duid,
            mac: self.mac,
        }
    }
}

fn answer(request: Option<MessageType>, action: Action6) -> Answer6 {
    Answer6 {
        request,
        action,
        selector: None,
    }
}

fn later(now: Timestamp, secs: u32) -> Timestamp {
    now.checked_add(Duration::from_secs(u64::from(secs)))
        .unwrap_or(now)
}

/// The scope of a request: the relay's Interface-Id, the relay's link address, else the
/// listener's address for a client on its link.
pub fn select<'a>(
    image: &'a ConfigImage,
    chain: &RelayChain<'_>,
    local: Ipv6Addr,
) -> Option<(&'a Scope6Image, Selector6)> {
    let v6 = image.v6();
    if chain.is_relayed() {
        if let Some(scope) = chain
            .relays()
            .rev()
            .filter_map(|relay| relay.interface_id().ok().flatten())
            .find_map(|id| v6.by_interface_id(id))
        {
            return Some((scope, Selector6::InterfaceId));
        }
        return chain
            .link_address()
            .and_then(|link| v6.select(link))
            .map(|scope| (scope, Selector6::LinkAddress));
    }
    v6.select(local).map(|scope| (scope, Selector6::Listener))
}

/// The client's link-layer address: the RFC 6939 option of the relay on its link, else the
/// one of its DUID.
fn link_layer_of<'a>(
    chain: &RelayChain<'a>,
    duid: Option<super::Duid<'a>>,
) -> Option<(u16, &'a [u8])> {
    chain
        .client_link_layer()
        .map(|link| (link.kind, link.address))
        .or_else(|| duid.and_then(|duid| duid.link_layer()))
}

/// Handles one received datagram: the reply in `scratch.reply`, the lease change in
/// `scratch.change`, and what to do with them.
#[allow(
    clippy::too_many_lines,
    reason = "the checks of RFC 8415 section 16 and the scope, in order, before the dispatch"
)]
pub fn handle(ctx: &Context6<'_>, received: &Received6<'_>, scratch: &mut Scratch6) -> Answer6 {
    let Ok(message) = Message::parse(received.bytes) else {
        return answer(None, Action6::Drop(DropReason::Malformed));
    };
    let Ok(chain) = RelayChain::parse(message) else {
        return answer(None, Action6::Drop(DropReason::Malformed));
    };
    let client = chain.client();
    let kind = client.kind();
    let request = Some(kind);
    match kind {
        MessageType::Solicit
        | MessageType::Request
        | MessageType::Confirm
        | MessageType::Renew
        | MessageType::Rebind
        | MessageType::Release
        | MessageType::Decline
        | MessageType::InformationRequest => {}
        MessageType::Advertise
        | MessageType::Reply
        | MessageType::Reconfigure
        | MessageType::RelayForw
        | MessageType::RelayRepl => {
            return answer(request, Action6::Ignore(Ignore6::NotRequest));
        }
        MessageType::Other(_) => return answer(request, Action6::Ignore(Ignore6::OtherType)),
    }
    let (Ok(client_id), Ok(server_id)) = (client.client_id(), client.server_id()) else {
        return answer(request, Action6::Drop(DropReason::Malformed));
    };
    // RFC 8415 section 16: which messages carry a Server Identifier, and whose.
    let ours = server_id.map(|id| id.as_bytes() == ctx.server_duid);
    let server_rule = match kind {
        MessageType::Solicit | MessageType::Confirm | MessageType::Rebind => match ours {
            None => Ok(()),
            Some(_) => Err(Ignore6::Incomplete),
        },
        MessageType::Request | MessageType::Renew | MessageType::Release | MessageType::Decline => {
            match ours {
                Some(true) => Ok(()),
                Some(false) => Err(Ignore6::OtherServer),
                None => Err(Ignore6::Incomplete),
            }
        }
        _ => match ours {
            Some(false) => Err(Ignore6::OtherServer),
            _ => Ok(()),
        },
    };
    if let Err(reason) = server_rule {
        return answer(request, Action6::Ignore(reason));
    }
    if client_id.is_none() && kind != MessageType::InformationRequest {
        return answer(request, Action6::Ignore(Ignore6::Incomplete));
    }
    let link_layer = link_layer_of(&chain, client_id);
    let mac = link_layer
        .filter(|(kind, _)| *kind == 1)
        .and_then(|(_, address)| <[u8; 6]>::try_from(address).ok());
    let verdict = mac.map_or(FilterVerdict::Unlisted, |mac| ctx.image.verdict(&mac));
    if verdict == FilterVerdict::Denied {
        return answer(request, Action6::Drop(DropReason::Filtered));
    }
    let Some((scope, selector)) = select(ctx.image, &chain, received.local) else {
        return answer(request, Action6::Drop(DropReason::NoScope));
    };
    let inbound = Inbound {
        chain: &chain,
        message: client,
        duid: client_id.map_or(&[][..], |id| id.as_bytes()),
        link_layer,
        mac,
    };
    let reserved = !inbound.duid.is_empty()
        && ctx
            .image
            .v6()
            .client_reservation(scope, inbound.duid, mac)
            .is_some();
    if scope.restricted && verdict != FilterVerdict::Allowed && !reserved {
        return Answer6 {
            request,
            action: Action6::Drop(DropReason::Filtered),
            selector: Some(selector),
        };
    }
    let action = match kind {
        MessageType::Solicit => solicit(ctx, &inbound, scope, received, scratch),
        MessageType::Request | MessageType::Renew | MessageType::Rebind => {
            stateful(ctx, &inbound, scope, received, scratch, kind)
        }
        MessageType::Confirm => confirm(ctx, &inbound, scope, received, scratch),
        MessageType::Release | MessageType::Decline => {
            give_back(ctx, &inbound, scope, received, scratch, kind)
        }
        _ => information(ctx, &inbound, scope, received, scratch),
    };
    Answer6 {
        request,
        action,
        selector: Some(selector),
    }
}

/// The `IA_NA`s of the message, at most [`MAX_BINDINGS`]; none when one is malformed.
fn ias<'m>(message: &Message<'m>) -> Option<([Option<IaNa<'m>>; MAX_BINDINGS], usize)> {
    let mut out = [None; MAX_BINDINGS];
    let mut count = 0;
    for ia in message.ia_nas() {
        let ia = ia.ok()?;
        if count < MAX_BINDINGS {
            out[count] = Some(ia);
            count += 1;
        }
    }
    Some((out, count))
}

/// The addresses a client put in an IA, at most four.
fn hints(ia: &IaNa<'_>) -> ([Ipv6Addr; 4], usize) {
    let mut out = [Ipv6Addr::UNSPECIFIED; 4];
    let mut count = 0;
    for addr in ia.addresses().flatten() {
        if count < out.len() {
            out[count] = addr.addr;
            count += 1;
        }
    }
    (out, count)
}

/// Where the reply goes.
fn destination(
    inbound: &Inbound<'_>,
    received: &Received6<'_>,
    settings: &Engine6Settings,
) -> Destination6 {
    let source = received.source;
    if inbound.chain.is_relayed() {
        Destination6::Relay(SocketAddrV6::new(
            *source.ip(),
            settings.relay_port,
            0,
            source.scope_id(),
        ))
    } else {
        Destination6::Client(SocketAddrV6::new(
            *source.ip(),
            settings.client_port,
            0,
            source.scope_id(),
        ))
    }
}

/// The client FQDN of the request (RFC 4704): the flags in the layout of option 81, the
/// name, and the flags of the reply under the scope's DDNS settings.
fn fqdn_of(inbound: &Inbound<'_>, scope: &Scope6Image) -> Option<(u8, WireName, u8)> {
    let fqdn = inbound.message.client_fqdn().ok().flatten()?;
    let client = fqdn.flags_v4();
    let reply = flags_from_v4(crate::ddns::flags::reply_flags(&scope.ddns, client));
    Some((client, fqdn.name(), reply))
}

/// Starts the change of the message: the client, its link-layer address, its name and the
/// relay closest to it.
fn begin_change(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    change: &mut PendingChange6,
    fqdn: Option<&(u8, WireName, u8)>,
) {
    change.reset(inbound.duid, ctx.now);
    change.link_layer = inbound
        .link_layer
        .map(|(kind, address)| (kind, InlineBytes::new(address).0));
    if let Some((flags, name, _)) = fqdn {
        let mut text = [0u8; 255];
        let mut len = 0;
        for label in name.labels() {
            let need = label.len() + usize::from(len > 0);
            if len + need > text.len() {
                break;
            }
            if len > 0 {
                text[len] = b'.';
                len += 1;
            }
            text[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        change.fqdn.set(&text[..len]);
        change.fqdn_flags = Some(*flags);
    }
    if let Some(innermost) = inbound.chain.innermost() {
        let mut relay = PendingRelay6 {
            link_address: inbound
                .chain
                .link_address()
                .unwrap_or(Ipv6Addr::UNSPECIFIED),
            peer_address: innermost.peer_address(),
            hops: u8::try_from(inbound.chain.depth()).unwrap_or(u8::MAX),
            interface_id: InlineBytes::default(),
            remote_id: InlineBytes::default(),
        };
        if let Some(id) = inbound.chain.interface_id() {
            relay.interface_id.set(id);
        }
        if let Some(id) = inbound.chain.remote_id() {
            relay.remote_id.set(id.as_bytes());
        }
        change.relay = Some(relay);
    }
}

/// The configuration levels of a reply: the scope, the pool of the first address, the
/// reservation's options.
fn levels<'a>(
    scope: &'a Scope6Image,
    first: Option<(&'a Scope6Image, Ipv6Addr)>,
    host: Option<&'a [tenko_core::dhcp::OptionValue]>,
) -> Levels6<'a> {
    let (home, pool) = match first {
        Some((home, addr)) => (home, home.pool_of(addr).map(|pool| pool.options.as_slice())),
        None => (scope, None),
    };
    Levels6 {
        scope: Some(home),
        pool,
        host,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the parts of one reply, each a field of `Reply6`"
)]
fn reply(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
    kind: MessageType,
    ias: &[IaReply],
    status: Option<(u16, &str)>,
    rapid_commit: bool,
    fqdn: Option<&(u8, WireName, u8)>,
    levels: Levels6<'_>,
) -> Action6 {
    let written = assemble::write(
        &mut scratch.reply,
        REPLY_CAPACITY6,
        &Reply6 {
            chain: inbound.chain,
            kind,
            server_duid: ctx.server_duid,
            client_id: (!inbound.duid.is_empty()).then_some(inbound.duid),
            ias,
            status,
            rapid_commit,
            fqdn: fqdn.map(|(_, name, flags)| (*flags, name)),
            oro: inbound.message.option_request().ok().flatten(),
            levels,
        },
    );
    match written {
        Ok(len) => Action6::Reply {
            kind,
            len,
            dest: destination(inbound, received, ctx.settings),
        },
        Err(_) => Action6::Drop(DropReason::Malformed),
    }
}

fn commit_then(action: Action6) -> Action6 {
    match action {
        Action6::Reply { kind, len, dest } => Action6::CommitThenReply { kind, len, dest },
        other => other,
    }
}

/// One IA's address for a SOLICIT, REQUEST, RENEW or REBIND, held in the offers for the
/// client (a claim fails when another worker holds it for another client; the next pick
/// skips it).
fn claim<'a>(
    ctx: &Context6<'a>,
    inbound: &Inbound<'_>,
    scope: &'a Scope6Image,
    ia: &IaNa<'_>,
    taken: &[Ipv6Addr],
    hold: bool,
) -> Option<alloc::Pick<'a>> {
    let (hinted, count) = hints(ia);
    let mut identity = [0u8; MAX_IDENTITY6];
    let len = alloc::identity(ia.iaid, inbound.duid, &mut identity);
    let mut skip = [Ipv6Addr::UNSPECIFIED; MAX_BINDINGS + 4];
    let mut skipped = taken.len().min(MAX_BINDINGS);
    skip[..skipped].copy_from_slice(&taken[..skipped]);
    for _ in 0..4 {
        let pick = alloc::pick(
            ctx,
            inbound.client(),
            scope,
            ia.iaid,
            &hinted[..count],
            &skip[..skipped],
        )?;
        if !hold {
            return Some(pick);
        }
        let until = later(ctx.now, ctx.settings.offer_secs);
        if ctx.offers.hold(
            pick.home.prefix,
            pick.addr,
            &identity[..len],
            until,
            ctx.now,
        ) {
            return Some(pick);
        }
        if skipped < skip.len() {
            skip[skipped] = pick.addr;
            skipped += 1;
        }
    }
    None
}

fn solicit(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    scope: &Scope6Image,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
) -> Action6 {
    let Some((list, count)) = ias(&inbound.message) else {
        return Action6::Drop(DropReason::Malformed);
    };
    let fqdn = fqdn_of(inbound, scope);
    let rapid = inbound.message.rapid_commit() && scope.v6.rapid_commit() && ctx.accepting;
    let mut replies = [IaReply::new(0); MAX_BINDINGS];
    let mut taken = [Ipv6Addr::UNSPECIFIED; MAX_BINDINGS];
    let mut granted = 0;
    let mut bound = 0;
    let mut first = None;
    let mut host = None;
    begin_change(ctx, inbound, &mut scratch.change, fqdn.as_ref());
    for (index, ia) in list[..count].iter().flatten().enumerate() {
        let mut out = IaReply::new(ia.iaid);
        match claim(ctx, inbound, scope, ia, &taken[..granted], true) {
            Some(pick) if ctx.accepting || pick.source == Source::Lease => {
                let times = alloc::lifetimes(pick.home, pick.home.pool_of(pick.addr));
                out.t1 = times.t1;
                out.t2 = times.t2;
                out.addr = Some((pick.addr, times.preferred, times.valid));
                taken[granted] = pick.addr;
                granted += 1;
                if pick.source == Source::Lease {
                    bound += 1;
                }
                first = first.or(Some((pick.home, pick.addr)));
                host = host.or(pick.host_options);
                if rapid {
                    let renewed = pick.source == Source::Lease;
                    scratch.change.push(Binding6 {
                        event: if renewed {
                            LeaseEventKind::Renewed
                        } else {
                            LeaseEventKind::Granted
                        },
                        kind: Lease6Kind::Na,
                        vrf: pick.home.vrf,
                        scope: pick.home.prefix,
                        iaid: ia.iaid,
                        addr: pick.addr,
                        prefix_len: 128,
                        state: BindingState::Active,
                        preferred_ends: later(ctx.now, times.preferred),
                        ends: later(ctx.now, times.valid),
                    });
                }
            }
            _ => out.status = Some(status::NO_ADDRS_AVAIL),
        }
        replies[index] = out;
    }
    let levels = levels(scope, first, host);
    if !ctx.accepting && bound == 0 {
        return Action6::Drop(DropReason::StoreRefused);
    }
    if granted == 0 {
        // RFC 8415 section 18.3.9: nothing to assign: an ADVERTISE with the identifiers and
        // a Status Code of NoAddrsAvail only.
        return reply(
            ctx,
            inbound,
            received,
            scratch,
            MessageType::Advertise,
            &[],
            Some((
                status::NO_ADDRS_AVAIL,
                assemble::status_text(status::NO_ADDRS_AVAIL),
            )),
            false,
            None,
            levels,
        );
    }
    if rapid {
        let action = reply(
            ctx,
            inbound,
            received,
            scratch,
            MessageType::Reply,
            &replies[..count],
            None,
            true,
            fqdn.as_ref(),
            levels,
        );
        return commit_then(action);
    }
    reply(
        ctx,
        inbound,
        received,
        scratch,
        MessageType::Advertise,
        &replies[..count],
        None,
        false,
        fqdn.as_ref(),
        levels,
    )
}

/// REQUEST, RENEW and REBIND (RFC 8415 sections 18.3.2, 18.3.4 and 18.3.5).
#[allow(
    clippy::too_many_lines,
    clippy::single_match_else,
    reason = "the three states of a binding, per IA, read top to bottom"
)]
fn stateful(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    scope: &Scope6Image,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
    kind: MessageType,
) -> Action6 {
    let Some((list, count)) = ias(&inbound.message) else {
        return Action6::Drop(DropReason::Malformed);
    };
    if count == 0 {
        return Action6::Ignore(Ignore6::Incomplete);
    }
    let fqdn = fqdn_of(inbound, scope);
    let image = ctx.image.v6();
    let mut replies = [IaReply::new(0); MAX_BINDINGS];
    let mut taken = [Ipv6Addr::UNSPECIFIED; MAX_BINDINGS];
    let mut granted = 0;
    let mut first = None;
    let mut host = None;
    begin_change(ctx, inbound, &mut scratch.change, fqdn.as_ref());
    for (index, ia) in list[..count].iter().flatten().enumerate() {
        let mut out = IaReply::new(ia.iaid);
        let (hinted, hint_count) = hints(ia);
        let hinted = &hinted[..hint_count];
        let pick = if ctx.accepting {
            claim(ctx, inbound, scope, ia, &taken[..granted], true)
        } else {
            // P3-Q14: only a binding the client holds is answered, for the time it has
            // left, and nothing is written.
            let mut identity = [0u8; MAX_IDENTITY6];
            let len = alloc::identity(ia.iaid, inbound.duid, &mut identity);
            image.siblings(scope).find_map(|sibling| {
                ctx.leases
                    .by_client(sibling.prefix, &identity[..len])
                    .filter(|lease| lease.is_bound(ctx.now))
                    .map(|lease| alloc::Pick {
                        home: sibling,
                        addr: lease.addr6(),
                        source: Source::Lease,
                        host_options: None,
                    })
            })
        };
        match pick {
            Some(pick) => {
                let times = alloc::lifetimes(pick.home, pick.home.pool_of(pick.addr));
                let (preferred, valid) = if ctx.accepting {
                    (times.preferred, times.valid)
                } else {
                    let left = ctx
                        .leases
                        .get(pick.home.vrf, pick.addr)
                        .map_or(0, |lease| lease.ends.saturating_since(ctx.now).as_secs());
                    let valid = u32::try_from(left).unwrap_or(u32::MAX).max(1);
                    (times.preferred.min(valid), valid)
                };
                out.t1 = times.t1.min(preferred);
                out.t2 = times.t2.min(preferred);
                out.addr = Some((pick.addr, preferred, valid));
                taken[granted] = pick.addr;
                granted += 1;
                first = first.or(Some((pick.home, pick.addr)));
                host = host.or(pick.host_options);
                if ctx.accepting {
                    let renewed = pick.source == Source::Lease
                        || ctx
                            .leases
                            .get(pick.home.vrf, pick.addr)
                            .is_some_and(|lease| {
                                lease.is_bound(ctx.now)
                                    && lease.iaid == ia.iaid
                                    && lease.duid.as_bytes() == inbound.duid
                            });
                    let event = match (renewed, kind) {
                        (true, MessageType::Rebind) => LeaseEventKind::Rebound,
                        (true, _) => LeaseEventKind::Renewed,
                        (false, _) => LeaseEventKind::Granted,
                    };
                    scratch.change.push(Binding6 {
                        event,
                        kind: Lease6Kind::Na,
                        vrf: pick.home.vrf,
                        scope: pick.home.prefix,
                        iaid: ia.iaid,
                        addr: pick.addr,
                        prefix_len: 128,
                        state: BindingState::Active,
                        preferred_ends: later(ctx.now, times.preferred),
                        ends: later(ctx.now, times.valid),
                    });
                }
                // The addresses of the IA the client may no longer use (RFC 8415 section
                // 18.3.4: not appropriate for the link, or not its binding).
                for hint in hinted {
                    if *hint != pick.addr {
                        out.zero(*hint);
                    }
                }
            }
            None => {
                for hint in hinted {
                    out.zero(*hint);
                }
                out.status = Some(match kind {
                    MessageType::Request => status::NO_ADDRS_AVAIL,
                    _ if hinted.is_empty() => status::NO_BINDING,
                    _ => status::NO_ADDRS_AVAIL,
                });
                if kind != MessageType::Request && !hinted.is_empty() {
                    // Lifetimes of zero tell the client to stop using the addresses; the
                    // status adds why.
                    out.status = None;
                }
            }
        }
        replies[index] = out;
    }
    if !ctx.accepting && granted == 0 {
        return Action6::Drop(DropReason::StoreRefused);
    }
    let levels = levels(scope, first, host);
    let action = reply(
        ctx,
        inbound,
        received,
        scratch,
        MessageType::Reply,
        &replies[..count],
        None,
        false,
        fqdn.as_ref(),
        levels,
    );
    if ctx.accepting && !scratch.change.is_empty() {
        commit_then(action)
    } else {
        action
    }
}

/// CONFIRM (RFC 8415 section 18.3.3): whether every address of the IAs is on the link.
fn confirm(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    scope: &Scope6Image,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
) -> Action6 {
    let Some((list, count)) = ias(&inbound.message) else {
        return Action6::Drop(DropReason::Malformed);
    };
    let image = ctx.image.v6();
    let mut any = false;
    let mut on_link = true;
    for ia in list[..count].iter().flatten() {
        for addr in ia.addresses().flatten() {
            any = true;
            on_link &= image
                .siblings(scope)
                .any(|sibling| sibling.network.contains(&addr.addr));
        }
    }
    if !any {
        // No address to check: the server sends no reply.
        return Action6::Ignore(Ignore6::Incomplete);
    }
    let status = if on_link {
        status::SUCCESS
    } else {
        status::NOT_ON_LINK
    };
    reply(
        ctx,
        inbound,
        received,
        scratch,
        MessageType::Reply,
        &[],
        Some((status, assemble::status_text(status))),
        false,
        None,
        levels(scope, None, None),
    )
}

/// RELEASE and DECLINE (RFC 8415 sections 18.3.7 and 18.3.8): the client's bindings among
/// the addresses of its IAs are released, or abandoned for the hold time; the others are
/// answered `NoBinding`.
fn give_back(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    scope: &Scope6Image,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
    kind: MessageType,
) -> Action6 {
    let Some((list, count)) = ias(&inbound.message) else {
        return Action6::Drop(DropReason::Malformed);
    };
    let image = ctx.image.v6();
    let mut replies = [IaReply::new(0); MAX_BINDINGS];
    let mut shown = 0;
    begin_change(ctx, inbound, &mut scratch.change, None);
    for ia in list[..count].iter().flatten() {
        let mut held_any = false;
        for addr in ia.addresses().flatten() {
            let Some((home, lease)) = image.siblings(scope).find_map(|sibling| {
                ctx.leases
                    .get(sibling.vrf, addr.addr)
                    .filter(|_| sibling.network.contains(&addr.addr))
                    .map(|lease| (sibling, lease))
            }) else {
                continue;
            };
            let holds = lease.state == BindingState::Active
                && lease.iaid == ia.iaid
                && lease.duid.as_bytes() == inbound.duid;
            if !holds {
                continue;
            }
            held_any = true;
            let (event, state, ends) = if kind == MessageType::Decline {
                (
                    LeaseEventKind::Declined,
                    BindingState::Abandoned,
                    later(ctx.now, ctx.settings.decline_hold_secs),
                )
            } else {
                (LeaseEventKind::Released, BindingState::Released, ctx.now)
            };
            scratch.change.push(Binding6 {
                event,
                kind: Lease6Kind::Na,
                vrf: home.vrf,
                scope: home.prefix,
                iaid: ia.iaid,
                addr: addr.addr,
                prefix_len: 128,
                state,
                preferred_ends: ctx.now,
                ends,
            });
        }
        if !held_any && shown < MAX_BINDINGS {
            let mut out = IaReply::new(ia.iaid);
            out.status = Some(status::NO_BINDING);
            replies[shown] = out;
            shown += 1;
        }
    }
    if !scratch.change.is_empty() && !ctx.accepting {
        return Action6::Drop(DropReason::StoreRefused);
    }
    let action = reply(
        ctx,
        inbound,
        received,
        scratch,
        MessageType::Reply,
        &replies[..shown],
        Some((status::SUCCESS, assemble::status_text(status::SUCCESS))),
        false,
        None,
        levels(scope, None, None),
    );
    if scratch.change.is_empty() {
        action
    } else {
        commit_then(action)
    }
}

/// INFORMATION-REQUEST (RFC 8415 section 18.3.6): the options, no address.
fn information(
    ctx: &Context6<'_>,
    inbound: &Inbound<'_>,
    scope: &Scope6Image,
    received: &Received6<'_>,
    scratch: &mut Scratch6,
) -> Action6 {
    if inbound.message.has(code::IA_NA)
        || inbound.message.has(code::IA_PD)
        || inbound.message.has(code::IA_TA)
    {
        return Action6::Ignore(Ignore6::Incomplete);
    }
    let host = (!inbound.duid.is_empty())
        .then(|| {
            ctx.image
                .v6()
                .client_reservation(scope, inbound.duid, inbound.mac)
        })
        .flatten()
        .map(|reservation| reservation.options.as_slice());
    reply(
        ctx,
        inbound,
        received,
        scratch,
        MessageType::Reply,
        &[],
        None,
        false,
        None,
        levels(scope, None, host),
    )
}
