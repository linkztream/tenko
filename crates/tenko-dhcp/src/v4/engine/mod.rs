//! The DHCPv4 engine (plan sections 2.3 to 2.6, WP7.3): a pure function of the
//! configuration image, the lease table, the offers held, the request and the clock, which
//! returns what to send, where, and the lease change to commit first.
//!
//! [`handle`] reads one received datagram and decides:
//!
//! - **The client.** Its identity is option 61 when sent, else `htype` and `chaddr` (RFC
//!   4361, RFC 6842); option 61 is echoed in every reply.
//! - **The filters.** A MAC address the deny list matches is dropped (DHCP-08); a scope
//!   marked restricted serves only clients the allow list matches and clients with a
//!   reservation (TGL-17).
//! - **The scope** ([`select`]): the link selection sub-option of option 82 (RFC 3527), then
//!   option 118 (RFC 3011), then `giaddr`, then `ciaddr` of a client that has an address, then
//!   the address of the listener the request arrived on. A scope of a shared network extends
//!   the choice to its siblings. The server identifier is the relay's override (RFC 5107,
//!   sub-option 11), else the scope's, else the listener's address.
//! - **The message** (RFC 2131 section 4.3): DISCOVER gets an OFFER and writes nothing (the
//!   address is held in the [`OfferBook`]); REQUEST in SELECTING, INIT-REBOOT, RENEWING and
//!   REBINDING gets an ACK after the commit or a NAK; DECLINE and RELEASE commit and get no
//!   reply; INFORM gets an ACK without lease times. The NAK rules are in [`handle`]'s
//!   request path.
//! - **The reply** ([`assemble`]): option 53, 54, the lease times, the subnet mask, the
//!   options the client asked for in the order of its option 55, the options the server
//!   always sends, option 61, option 81 and last option 82 unchanged (RFC 3046), within the
//!   size the client accepts; long values are split by the builder (RFC 3396).
//! - **The destination** ([`Destination`], RFC 2131 section 4.1): the relay at `giaddr`
//!   port 67; else `ciaddr` port 68; else a broadcast when the client asks for one or for a
//!   NAK; else the client's hardware address.
//!
//! From the parse to the lease change in [`Scratch::change`] nothing allocates; the
//! worker hands the change to the [`LeaseStore`](crate::store::LeaseStore) and sends the
//! reply when the commit returns (`tests/alloc.rs`).

pub mod assemble;
mod hash;
pub mod hashed;
pub mod metrics;
pub mod offers;
pub mod select;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use tenko_core::{
    NodeId, PrefixId, Timestamp, VrfId,
    dhcp::{
        BindingState, FilterVerdict, Lease, LeaseEventKind, LeaseTimes, lease::MAX_IDENTITY,
        write_identity,
    },
};

pub use self::{
    hashed::HashedAllocator,
    metrics::{MetricsSnapshot, WorkerMetrics},
    offers::{OfferBook, OfferTable},
    select::Selector,
};
use super::{BOOTREQUEST, ClientFqdn, Message, MessageBuilder, MessageType, RelayAgentInfo};
use crate::{
    allocator::{Allocator, Choice, PoolOwnership, Request, grant_time},
    image::{ConfigImage, PoolImage, ScopeImage},
    lease::{InlineBytes, LeaseTable, PendingChange, PendingFingerprint, PendingRelay},
};

/// The largest reply the engine writes: an Ethernet MTU less the IP and UDP headers.
pub const REPLY_CAPACITY: usize = 1500 - super::IP_UDP_HEADERS_LEN;

/// The engine's settings (`[dhcp]` of `tenko.toml`, plan section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineSettings {
    /// How long an offer holds its address (`offer_secs`, 10).
    pub offer_secs: u32,
    /// How long a declined address stays abandoned (`[dhcp.decline] hold_secs`, 86,400).
    pub decline_hold_secs: u32,
    /// The port replies to a relay agent go to (67; tests and benches use another).
    pub relay_port: u16,
    /// The port replies to a client go to (68).
    pub client_port: u16,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            offer_secs: 10,
            decline_hold_secs: 86_400,
            relay_port: 67,
            client_port: 68,
        }
    }
}

/// How a listener receives (plan section 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListenMode {
    /// Bound to a unicast address: only relayed and unicast traffic arrives.
    Relay,
    /// Bound to an interface: broadcasts of clients on the link arrive as well.
    Direct,
}

/// One received datagram.
#[derive(Debug, Clone, Copy)]
pub struct Received<'a> {
    /// The octets.
    pub bytes: &'a [u8],
    /// Where it came from.
    pub source: SocketAddrV4,
    /// The address of the listener it arrived on (the interface's address).
    pub local: Ipv4Addr,
    /// The listener's mode.
    pub mode: ListenMode,
}

/// What the engine reads.
pub struct Context<'a> {
    /// The configuration image.
    pub image: &'a ConfigImage,
    /// The lease table.
    pub leases: &'a dyn LeaseTable,
    /// The offers held.
    pub offers: &'a dyn OfferBook,
    /// The ownership rule (one node: [`SingleNode`](crate::allocator::SingleNode)).
    pub ownership: &'a dyn PoolOwnership,
    /// The allocator ([`HashedAllocator`]).
    pub allocator: &'a dyn Allocator,
    /// The settings.
    pub settings: &'a EngineSettings,
    /// Whether the store takes lease writes now (P3-Q14).
    pub accepting: bool,
    /// Now.
    pub now: Timestamp,
}

/// Where a reply goes (RFC 2131 section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// The relay agent at `giaddr`, on the relay port.
    Relay(SocketAddrV4),
    /// The client at `ciaddr`, on the client port.
    Client(SocketAddrV4),
    /// `255.255.255.255` on the client port, out of the listener's interface.
    Broadcast(u16),
    /// The client's hardware address with `yiaddr` as the IP destination: a link-layer
    /// reply where the listener can send one, else a broadcast.
    Link {
        /// `yiaddr`.
        addr: Ipv4Addr,
        /// `chaddr`.
        mac: [u8; 6],
        /// The client port.
        port: u16,
    },
}

/// Why a request was dropped (`tenko_dhcp_dropped_total{reason}`), in the order of
/// [`metrics::DROP_LABELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not a DHCP message, or a malformed option the engine needs.
    Malformed = 0,
    /// The MAC filters or a restricted scope.
    Filtered = 1,
    /// No scope serves the request's link.
    NoScope = 2,
    /// No free address in the scope and its siblings.
    PoolFull = 3,
    /// The commit queue had no slot (decided by the server).
    Queue = 4,
    /// The store refuses lease writes (P3-Q14).
    StoreRefused = 5,
    /// Rate limited (DECLINE floods, WP8.5).
    RateLimited = 6,
}

/// Why a request got no answer although it was well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    /// A BOOTREPLY, or a BOOTP request without option 53 (BOOTP is not served).
    NotRequest,
    /// A message type a server does not answer.
    OtherType,
    /// A REQUEST, DECLINE or RELEASE for another server (option 54).
    OtherServer,
    /// An INIT-REBOOT of a client the server has no record of (RFC 2131 section 4.3.2).
    NoRecord,
    /// A NAK case on a scope that is not authoritative.
    NotAuthoritative,
    /// A DECLINE or RELEASE of an address the client does not hold.
    NotHolder,
    /// A REQUEST or INFORM without the fields its state needs.
    Incomplete,
}

/// What to do with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send the reply in [`Scratch::reply`] now.
    Reply {
        /// The reply's type.
        kind: MessageType,
        /// Its length.
        len: usize,
        /// Where it goes.
        dest: Destination,
    },
    /// Commit [`Scratch::change`], then send the reply.
    CommitThenReply {
        /// The reply's type.
        kind: MessageType,
        /// Its length.
        len: usize,
        /// Where it goes.
        dest: Destination,
    },
    /// Commit [`Scratch::change`]; no reply (DECLINE, RELEASE).
    Commit,
    /// Drop and count.
    Drop(DropReason),
    /// No answer (counted as ignored).
    Ignore(IgnoreReason),
}

/// The engine's answer to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The request's message type, when it had one.
    pub request: Option<MessageType>,
    /// What to do.
    pub action: Action,
    /// How the scope was selected, when one was.
    pub selector: Option<Selector>,
}

/// A worker's buffers, made once: the reply and the lease change are written here.
#[derive(Debug, Clone)]
pub struct Scratch {
    /// The reply.
    pub reply: [u8; REPLY_CAPACITY],
    /// The lease change of [`Action::CommitThenReply`] and [`Action::Commit`].
    pub change: PendingChange,
    /// Option 55 concatenated when it was split (RFC 3396).
    prl: [u8; 512],
}

impl Scratch {
    /// The buffers of one worker, on the heap.
    pub fn new() -> Box<Self> {
        Box::new(Self {
            reply: [0; REPLY_CAPACITY],
            change: empty_change(),
            prl: [0; 512],
        })
    }
}

/// A placeholder change.
pub fn empty_change() -> PendingChange {
    PendingChange::new(
        LeaseEventKind::Granted,
        VrfId::generate(),
        PrefixId::generate(),
        Ipv4Addr::UNSPECIFIED,
        0,
        &[],
        None,
        BindingState::Free,
        Timestamp::now(),
        Timestamp::now(),
    )
}

/// The request as the paths below read it.
struct Inbound<'m, 'i> {
    message: &'m Message<'m>,
    identity: &'i [u8],
    chaddr: &'m [u8],
    client_id: Option<&'m [u8]>,
    relay: Option<RelayAgentInfo<'m>>,
    server_id: Ipv4Addr,
}

fn answer(request: Option<MessageType>, action: Action) -> Answer {
    Answer {
        request,
        action,
        selector: None,
    }
}

/// Handles one received datagram: the reply in `scratch.reply`, the lease change in
/// `scratch.change`, and what to do with them.
pub fn handle(ctx: &Context<'_>, received: &Received<'_>, scratch: &mut Scratch) -> Answer {
    let Ok(message) = Message::parse(received.bytes) else {
        return answer(None, Action::Drop(DropReason::Malformed));
    };
    if message.op() != BOOTREQUEST {
        return answer(None, Action::Ignore(IgnoreReason::NotRequest));
    }
    let kind = match message.message_type() {
        Ok(Some(kind)) => kind,
        Ok(None) => return answer(None, Action::Ignore(IgnoreReason::NotRequest)),
        Err(_) => return answer(None, Action::Drop(DropReason::Malformed)),
    };
    let request = Some(kind);
    if !matches!(
        kind,
        MessageType::Discover
            | MessageType::Request
            | MessageType::Decline
            | MessageType::Release
            | MessageType::Inform
    ) {
        return answer(request, Action::Ignore(IgnoreReason::OtherType));
    }
    let (Ok(chaddr), Ok(client_id), Ok(relay)) = (
        message.chaddr(),
        message.client_identifier(),
        message.relay_agent_info(),
    ) else {
        return answer(request, Action::Drop(DropReason::Malformed));
    };
    let client_id = client_id.map(|id| id.as_bytes());
    let mut identity = [0u8; MAX_IDENTITY];
    let len = write_identity(message.htype(), chaddr, client_id, &mut identity);
    let identity = &identity[..len];
    let verdict = message
        .mac()
        .map_or(FilterVerdict::Unlisted, |mac| ctx.image.verdict(&mac));
    if verdict == FilterVerdict::Denied {
        return answer(request, Action::Drop(DropReason::Filtered));
    }
    let Some((scope, selector)) = select::select(ctx.image, &message, kind, relay, received) else {
        return answer(request, Action::Drop(DropReason::NoScope));
    };
    let reserved = ctx
        .image
        .siblings(scope)
        .any(|sibling| ctx.image.reservation(sibling.prefix, identity).is_some());
    if scope.restricted && verdict != FilterVerdict::Allowed && !reserved {
        return Answer {
            request,
            action: Action::Drop(DropReason::Filtered),
            selector: Some(selector),
        };
    }
    let server_id = relay
        .and_then(|info| info.server_id_override())
        .or(scope.server_id)
        .unwrap_or(received.local);
    let client = Inbound {
        message: &message,
        identity,
        chaddr,
        client_id,
        relay,
        server_id,
    };
    let action = match kind {
        MessageType::Discover => discover(ctx, &client, scope, scratch),
        MessageType::Request => self::request(ctx, &client, scope, received, scratch),
        MessageType::Decline => decline(ctx, &client, scope, received, scratch),
        MessageType::Release => release(ctx, &client, scope, received, scratch),
        _ => inform(ctx, &client, scope, scratch),
    };
    Answer {
        request,
        action,
        selector: Some(selector),
    }
}

/// The scope of the shared network that holds `addr`.
fn home<'a>(
    image: &'a ConfigImage,
    scope: &'a ScopeImage,
    addr: Ipv4Addr,
) -> Option<&'a ScopeImage> {
    image
        .siblings(scope)
        .find(|sibling| sibling.network.contains(&addr))
}

/// The lease times of an address: its pool's, else its scope's.
fn times_of(scope: &ScopeImage, addr: Ipv4Addr) -> (LeaseTimes, Option<&PoolImage>) {
    match scope.pool_of(addr) {
        Some(pool) => (pool.lease, Some(pool)),
        None => (scope.lease, None),
    }
}

fn later(now: Timestamp, secs: u32) -> Timestamp {
    now.checked_add(Duration::from_secs(u64::from(secs)))
        .unwrap_or(now)
}

/// Whether `lease` belongs to the client of `identity`.
pub fn is_holder(lease: &Lease, identity: &[u8]) -> bool {
    let mut held = [0u8; MAX_IDENTITY];
    let len = write_identity(
        lease.client.htype,
        &lease.client.chaddr.0,
        lease.client.client_id.as_ref().map(|id| id.0.as_slice()),
        &mut held,
    );
    &held[..len] == identity
}

fn allocate(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    requested: Option<Ipv4Addr>,
) -> Option<Choice> {
    ctx.allocator.pick(&Request {
        image: ctx.image,
        scope,
        identity: client.identity,
        requested,
        leases: ctx.leases,
        offers: ctx.offers,
        ownership: ctx.ownership,
        now: ctx.now,
    })
}

/// The reservation's options when the choice is the client's reservation.
fn host_options<'a>(
    ctx: &'a Context<'_>,
    client: &Inbound<'_, '_>,
    home: &ScopeImage,
    choice: Choice,
) -> Option<&'a [tenko_core::dhcp::OptionValue]> {
    match choice {
        Choice::Reservation(_) => ctx
            .image
            .reservation(home.prefix, client.identity)
            .map(|reservation| reservation.options.as_slice()),
        _ => None,
    }
}

fn discover(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    scratch: &mut Scratch,
) -> Action {
    let requested = client.message.requested_address().ok().flatten();
    let until = later(ctx.now, ctx.settings.offer_secs);
    // A claim fails only when another worker held the address for another client after
    // the pick; the next pick skips it.
    for _ in 0..4 {
        let Some(choice) = allocate(ctx, client, scope, requested) else {
            return Action::Drop(DropReason::PoolFull);
        };
        let addr = choice.addr();
        let Some(home) = choice_home(ctx, client, scope, choice) else {
            return Action::Drop(DropReason::PoolFull);
        };
        if !ctx.accepting && !matches!(choice, Choice::Lease(_)) {
            return Action::Drop(DropReason::StoreRefused);
        }
        if !ctx
            .offers
            .hold(home.prefix, addr, client.identity, until, ctx.now)
        {
            continue;
        }
        let (times, pool) = times_of(home, addr);
        let granted = grant_time(&times, client.message.lease_time().ok().flatten(), None);
        let host = host_options(ctx, client, home, choice);
        let lease = Some(assemble::LeaseGrant {
            granted,
            times: times.renewal_times(granted),
        });
        return reply(
            ctx,
            client,
            MessageType::Offer,
            addr,
            assemble::Levels {
                scope: home,
                pool,
                host,
            },
            lease,
            scratch,
        );
    }
    Action::Drop(DropReason::PoolFull)
}

fn choice_home<'a>(
    ctx: &'a Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &'a ScopeImage,
    choice: Choice,
) -> Option<&'a ScopeImage> {
    match choice {
        Choice::Reservation(_) => ctx.image.siblings(scope).find(|sibling| {
            ctx.image
                .reservation(sibling.prefix, client.identity)
                .is_some()
        }),
        other => home(ctx.image, scope, other.addr()),
    }
}

/// The REQUEST's state (RFC 2131 section 4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Selecting,
    InitReboot,
    Renewing,
    Rebinding,
}

#[allow(
    clippy::too_many_lines,
    reason = "the four states of RFC 2131 section 4.3.2, read top to bottom"
)]
fn request(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    received: &Received<'_>,
    scratch: &mut Scratch,
) -> Action {
    let message = client.message;
    let (Ok(server_id), Ok(requested)) = (message.server_identifier(), message.requested_address())
    else {
        return Action::Drop(DropReason::Malformed);
    };
    let ciaddr = message.ciaddr();
    let (state, target) = match (server_id, requested) {
        (Some(id), Some(asked)) => {
            if !is_ours(id, client, scope, received) {
                return Action::Ignore(IgnoreReason::OtherServer);
            }
            (State::Selecting, asked)
        }
        (None, Some(asked)) if ciaddr.is_unspecified() => (State::InitReboot, asked),
        (None, _) if !ciaddr.is_unspecified() => {
            if message.giaddr().is_unspecified() {
                (State::Renewing, ciaddr)
            } else {
                (State::Rebinding, ciaddr)
            }
        }
        _ => return Action::Ignore(IgnoreReason::Incomplete),
    };
    let authoritative = scope.authoritative;
    let refuse = |scratch: &mut Scratch, text: &[u8]| {
        if state == State::Selecting || authoritative {
            nak(ctx, client, text, scratch)
        } else {
            Action::Ignore(IgnoreReason::NotAuthoritative)
        }
    };
    let Some(home) = home(ctx.image, scope, target) else {
        return refuse(scratch, b"the address is not on this network");
    };
    if state == State::InitReboot {
        let known = ctx.image.siblings(scope).any(|sibling| {
            ctx.image
                .reservation(sibling.prefix, client.identity)
                .is_some()
                || ctx
                    .leases
                    .by_client(sibling.prefix, client.identity)
                    .is_some()
        });
        if !known {
            return Action::Ignore(IgnoreReason::NoRecord);
        }
    }
    let Some(choice) = allocate(ctx, client, scope, Some(target)) else {
        return refuse(scratch, b"the address is not available");
    };
    if choice.addr() != target {
        return refuse(scratch, b"the address is not available");
    }
    let bound = ctx
        .leases
        .get(home.vrf, target)
        .filter(|lease| lease.is_bound(ctx.now) && is_holder(lease, client.identity));
    let (times, pool) = times_of(home, target);
    let host = host_options(ctx, client, home, choice);
    let levels = assemble::Levels {
        scope: home,
        pool,
        host,
    };
    if !ctx.accepting {
        // P3-Q14: a bound lease is answered for the time it still has, and nothing is
        // written; everything else waits for the store.
        let Some(lease) = bound else {
            return Action::Drop(DropReason::StoreRefused);
        };
        let left = lease.ends.saturating_since(ctx.now).as_secs();
        let left = u32::try_from(left).unwrap_or(u32::MAX).max(1);
        let grant = assemble::LeaseGrant {
            granted: left,
            times: times.renewal_times(left),
        };
        return reply(
            ctx,
            client,
            MessageType::Ack,
            target,
            levels,
            Some(grant),
            scratch,
        );
    }
    let until = later(ctx.now, ctx.settings.offer_secs);
    if !ctx
        .offers
        .hold(home.prefix, target, client.identity, until, ctx.now)
    {
        return refuse(scratch, b"the address is not available");
    }
    let granted = grant_time(&times, message.lease_time().ok().flatten(), None);
    let kind = match (bound.is_some(), state) {
        (true, State::Rebinding) => LeaseEventKind::Rebound,
        (true, _) => LeaseEventKind::Renewed,
        (false, _) => LeaseEventKind::Granted,
    };
    scratch.change = PendingChange::new(
        kind,
        home.vrf,
        home.prefix,
        target,
        message.htype(),
        client.chaddr,
        client.client_id,
        BindingState::Active,
        ctx.now,
        later(ctx.now, granted),
    );
    describe(client, &mut scratch.change);
    let grant = assemble::LeaseGrant {
        granted,
        times: times.renewal_times(granted),
    };
    match reply(
        ctx,
        client,
        MessageType::Ack,
        target,
        levels,
        Some(grant),
        scratch,
    ) {
        Action::Reply { kind, len, dest } => Action::CommitThenReply { kind, len, dest },
        other => other,
    }
}

/// Whether option 54 names this server: the effective server identifier, the scope's or
/// the listener's address.
fn is_ours(
    id: Ipv4Addr,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    received: &Received<'_>,
) -> bool {
    id == client.server_id || Some(id) == scope.server_id || id == received.local
}

/// The parts of the request the lease row keeps: host name, FQDN, relay, fingerprint.
fn describe(client: &Inbound<'_, '_>, change: &mut PendingChange) {
    let message = client.message;
    if let Ok(Some(name)) = message.host_name() {
        change.hostname.set(name);
    }
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        let name = fqdn.name();
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
    }
    if let Some(info) = client.relay {
        let mut relay = PendingRelay {
            giaddr: message.giaddr(),
            raw: InlineBytes::default(),
        };
        relay.raw.set(info.as_bytes());
        change.relay = Some(relay);
    }
    let mut fingerprint = PendingFingerprint::default();
    let mut prl = [0u8; 255];
    if let Ok(Some(list)) = message.option_data(super::code::PARAMETER_REQUEST_LIST, &mut prl) {
        fingerprint.parameters.set(list);
    }
    if let Ok(Some(class)) = message.vendor_class_identifier() {
        fingerprint.vendor_class.set(class);
    }
    fingerprint.user_class = matches!(message.option(super::code::USER_CLASS), Ok(Some(_)));
    fingerprint.client_fqdn = matches!(message.option(super::code::CLIENT_FQDN), Ok(Some(_)));
    fingerprint.architecture = message
        .client_architectures()
        .ok()
        .flatten()
        .map(|list| list.first());
    change.fingerprint = Some(fingerprint);
}

fn decline(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    received: &Received<'_>,
    scratch: &mut Scratch,
) -> Action {
    let message = client.message;
    let (Ok(server_id), Ok(Some(addr))) =
        (message.server_identifier(), message.requested_address())
    else {
        return Action::Ignore(IgnoreReason::Incomplete);
    };
    if server_id.is_some_and(|id| !is_ours(id, client, scope, received)) {
        return Action::Ignore(IgnoreReason::OtherServer);
    }
    let Some(home) = home(ctx.image, scope, addr) else {
        return Action::Ignore(IgnoreReason::NotHolder);
    };
    let holds = ctx
        .leases
        .get(home.vrf, addr)
        .is_some_and(|lease| lease.state.holds_address() && is_holder(lease, client.identity));
    if !holds {
        return Action::Ignore(IgnoreReason::NotHolder);
    }
    if !ctx.accepting {
        return Action::Drop(DropReason::StoreRefused);
    }
    // The declined address is abandoned for the hold time and belongs to no client, so
    // that the allocator offers it to nobody, the decliner included (as Kea does).
    scratch.change = PendingChange::new(
        LeaseEventKind::Declined,
        home.vrf,
        home.prefix,
        addr,
        0,
        &[],
        None,
        BindingState::Abandoned,
        ctx.now,
        later(ctx.now, ctx.settings.decline_hold_secs),
    );
    Action::Commit
}

fn release(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    received: &Received<'_>,
    scratch: &mut Scratch,
) -> Action {
    let message = client.message;
    let addr = message.ciaddr();
    if let Ok(Some(id)) = message.server_identifier()
        && !is_ours(id, client, scope, received)
    {
        return Action::Ignore(IgnoreReason::OtherServer);
    }
    let Some(home) = home(ctx.image, scope, addr) else {
        return Action::Ignore(IgnoreReason::NotHolder);
    };
    let holds = ctx.leases.get(home.vrf, addr).is_some_and(|lease| {
        lease.state == BindingState::Active && is_holder(lease, client.identity)
    });
    if !holds {
        return Action::Ignore(IgnoreReason::NotHolder);
    }
    if !ctx.accepting {
        return Action::Drop(DropReason::StoreRefused);
    }
    scratch.change = PendingChange::new(
        LeaseEventKind::Released,
        home.vrf,
        home.prefix,
        addr,
        message.htype(),
        client.chaddr,
        client.client_id,
        BindingState::Released,
        ctx.now,
        ctx.now,
    );
    Action::Commit
}

fn inform(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    scope: &ScopeImage,
    scratch: &mut Scratch,
) -> Action {
    let ciaddr = client.message.ciaddr();
    if ciaddr.is_unspecified() {
        return Action::Ignore(IgnoreReason::Incomplete);
    }
    let home = home(ctx.image, scope, ciaddr).unwrap_or(scope);
    let levels = assemble::Levels {
        scope: home,
        pool: home.pool_of(ciaddr),
        host: None,
    };
    reply(
        ctx,
        client,
        MessageType::Ack,
        Ipv4Addr::UNSPECIFIED,
        levels,
        None,
        scratch,
    )
}

/// Writes an OFFER or ACK (with `lease`) or an INFORM's ACK (without) and decides where it
/// goes.
fn reply(
    ctx: &Context<'_>,
    client: &Inbound<'_, '_>,
    kind: MessageType,
    yiaddr: Ipv4Addr,
    levels: assemble::Levels<'_>,
    lease: Option<assemble::LeaseGrant>,
    scratch: &mut Scratch,
) -> Action {
    let message = client.message;
    let Ok(mut builder) = MessageBuilder::reply(&mut scratch.reply, message, kind) else {
        return Action::Drop(DropReason::Malformed);
    };
    builder.yiaddr(yiaddr);
    if kind == MessageType::Ack {
        builder.ciaddr(message.ciaddr());
    }
    let written = assemble::options(
        &mut builder,
        &assemble::Reply {
            message,
            server_id: client.server_id,
            client_id: client.client_id,
            relay: client.relay,
            lease,
            levels,
        },
        &mut scratch.prl,
    );
    if written.is_err() {
        return Action::Drop(DropReason::Malformed);
    }
    let Ok(len) = builder.finish() else {
        return Action::Drop(DropReason::Malformed);
    };
    Action::Reply {
        kind,
        len,
        dest: destination(message, kind, yiaddr, ctx.settings),
    }
}

/// A NAK: option 53, 54, a message (option 56), the client identifier and option 82; the
/// broadcast bit set when it goes through a relay (RFC 2131 section 4.3.2).
fn nak(ctx: &Context<'_>, client: &Inbound<'_, '_>, text: &[u8], scratch: &mut Scratch) -> Action {
    let message = client.message;
    let Ok(mut builder) = MessageBuilder::reply(&mut scratch.reply, message, MessageType::Nak)
    else {
        return Action::Drop(DropReason::Malformed);
    };
    if !message.giaddr().is_unspecified() {
        builder.broadcast(true);
    }
    let mut written = builder
        .server_identifier(client.server_id)
        .and_then(|b| b.option(super::code::MESSAGE, text))
        .map(|_| ());
    if written.is_ok()
        && let Some(id) = client.client_id
    {
        written = builder
            .option(super::code::CLIENT_IDENTIFIER, id)
            .map(|_| ());
    }
    if written.is_ok()
        && let Some(info) = client.relay
    {
        written = builder.relay_agent_info(info.as_bytes()).map(|_| ());
    }
    let (Ok(()), Ok(len)) = (written, builder.finish()) else {
        return Action::Drop(DropReason::Malformed);
    };
    Action::Reply {
        kind: MessageType::Nak,
        len,
        dest: destination(
            message,
            MessageType::Nak,
            Ipv4Addr::UNSPECIFIED,
            ctx.settings,
        ),
    }
}

/// The destination of a reply (RFC 2131 section 4.1).
pub fn destination(
    message: &Message<'_>,
    kind: MessageType,
    yiaddr: Ipv4Addr,
    settings: &EngineSettings,
) -> Destination {
    let giaddr = message.giaddr();
    if !giaddr.is_unspecified() {
        return Destination::Relay(SocketAddrV4::new(giaddr, settings.relay_port));
    }
    if kind == MessageType::Nak {
        return Destination::Broadcast(settings.client_port);
    }
    let ciaddr = message.ciaddr();
    if !ciaddr.is_unspecified() {
        return Destination::Client(SocketAddrV4::new(ciaddr, settings.client_port));
    }
    match message.mac() {
        Ok(mac) if !message.broadcast() && !yiaddr.is_unspecified() => Destination::Link {
            addr: yiaddr,
            mac,
            port: settings.client_port,
        },
        _ => Destination::Broadcast(settings.client_port),
    }
}

/// The lease row of a committed change, for the table: the row the store writes.
pub fn committed_row(change: &PendingChange, node: NodeId, previous: Option<&Lease>) -> Lease {
    change.to_lease(node, previous)
}

/// The FQDN flags of a server that performs no DNS update (RFC 4702 section 4): N set, S
/// clear, O set when the client asked for S, E as the client sent it.
pub fn fqdn_flags_without_update(client: &ClientFqdn<'_>) -> u8 {
    let mut flags = ClientFqdn::FLAG_N | (client.flags() & ClientFqdn::FLAG_E);
    if client.server_updates() {
        flags |= ClientFqdn::FLAG_O;
    }
    flags
}
