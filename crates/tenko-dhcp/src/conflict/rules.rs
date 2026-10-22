//! When an offer waits for a probe (plan section 2.7): only for an address with no lease
//! history for this client that no probe found clean within the cache's time.
//!
//! [`candidate`] reads the request and the OFFER the engine built for it, as the worker
//! holds them, and answers `None` (send the OFFER now) when:
//!
//! - the reply is no OFFER, or the request no DISCOVER;
//! - the table holds a row for the address whose client is this one, in any state: the
//!   client's own binding, its expired or released address, a reservation it already uses;
//! - the client's latest row in the scope or a sibling of its shared network is the
//!   address (its previous address);
//! - the probe cache holds the address as clean.
//!
//! Renewals never get here: they are REQUESTs, answered by an ACK after the commit.
//! Nothing here allocates: the request is parsed again in place (the parse is a view).

use std::net::Ipv4Addr;

use tenko_core::{
    PrefixId, Timestamp, VrfId,
    dhcp::{lease::MAX_IDENTITY, write_identity},
};

use super::Conflicts;
use crate::{
    image::ConfigImage,
    lease::LeaseTable,
    v4::{
        BOOTREPLY, Message, MessageType,
        engine::{self, Received, select},
    },
};

/// An address an offer would hand out before a probe looked at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The address (`yiaddr` of the OFFER).
    pub addr: Ipv4Addr,
    /// Its scope's VRF.
    pub vrf: VrfId,
    /// Its scope.
    pub prefix: PrefixId,
    /// The client's MAC address, when it has an Ethernet one: an answer from it is no
    /// conflict.
    pub mac: Option<[u8; 6]>,
    /// Whether the address is the client's reservation (offered even when it answers).
    pub reserved: bool,
    identity: [u8; MAX_IDENTITY],
    identity_len: usize,
}

impl Candidate {
    /// An empty candidate, for an unused slot.
    pub(crate) fn placeholder() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            vrf: VrfId::from_uuid(uuid::Uuid::nil()),
            prefix: PrefixId::from_uuid(uuid::Uuid::nil()),
            mac: None,
            reserved: false,
            identity: [0; MAX_IDENTITY],
            identity_len: 0,
        }
    }

    /// The client identity (`ClientKey::identity`).
    pub fn identity(&self) -> &[u8] {
        &self.identity[..self.identity_len]
    }
}

/// The address `yiaddr` of a reply.
pub fn yiaddr(reply: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = reply.get(16..20)?.try_into().ok()?;
    (reply.first() == Some(&BOOTREPLY)).then(|| Ipv4Addr::from(octets))
}

/// The client identity of a request into `out`; its length, or `None` for a request that
/// does not parse.
pub fn identity_of(request: &[u8], out: &mut [u8; MAX_IDENTITY]) -> Option<usize> {
    let message = Message::parse(request).ok()?;
    let chaddr = message.chaddr().ok()?;
    let client_id = message.client_identifier().ok()?.map(|id| id.as_bytes());
    Some(write_identity(message.htype(), chaddr, client_id, out))
}

/// The address the OFFER in `reply` hands out, when it needs a probe first; see the module
/// documentation. Counts an offer the cache lets through.
pub fn candidate(
    conflicts: &Conflicts,
    image: &ConfigImage,
    leases: &dyn LeaseTable,
    received: &Received<'_>,
    reply: &[u8],
    now: Timestamp,
) -> Option<Candidate> {
    let addr = yiaddr(reply)?;
    let message = Message::parse(received.bytes).ok()?;
    if message.message_type().ok()?? != MessageType::Discover || addr.is_unspecified() {
        return None;
    }
    let chaddr = message.chaddr().ok()?;
    let client_id = message.client_identifier().ok()?.map(|id| id.as_bytes());
    let relay = message.relay_agent_info().ok()?;
    let mut identity = [0u8; MAX_IDENTITY];
    let identity_len = write_identity(message.htype(), chaddr, client_id, &mut identity);
    let who = &identity[..identity_len];
    let (scope, _) = select::select(image, &message, MessageType::Discover, relay, received)?;
    let home = image
        .siblings(scope)
        .find(|sibling| sibling.network.contains(&addr))?;
    if leases
        .get(home.vrf, addr)
        .is_some_and(|lease| engine::is_holder(lease, who))
    {
        return None;
    }
    if image.siblings(scope).any(|sibling| {
        leases
            .by_client(sibling.prefix, who)
            .is_some_and(|lease| lease.addr == addr)
    }) {
        return None;
    }
    if conflicts.cache().is_clean(home.vrf, addr, now) {
        conflicts.count_cached();
        return None;
    }
    // WP8.4: the client's reservation, by client identity or by hardware address.
    let mut hardware = [0u8; MAX_IDENTITY];
    let hardware_len = write_identity(message.htype(), chaddr, None, &mut hardware);
    let reserved = image
        .reservation_of(home.prefix, who, &hardware[..hardware_len])
        .is_some_and(|reservation| reservation.addr == addr);
    Some(Candidate {
        addr,
        vrf: home.vrf,
        prefix: home.prefix,
        mac: message.mac().ok(),
        reserved,
        identity,
        identity_len,
    })
}
