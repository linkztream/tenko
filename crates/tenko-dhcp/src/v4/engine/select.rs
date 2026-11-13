//! Scope selection (plan section 2.5, the topology-based selection of RFC 7969): the scope
//! of the network a request came from, by how it arrived (`docs/dhcp.md` section 9.1). No
//! field a client fills in by itself selects a network the request did not come from.
//!
//! | Client state | How it arrives | What selects the scope | What is checked |
//! |---|---|---|---|
//! | Any | Relayed (`giaddr` set) | The link selection sub-option of option 82 (RFC 3527), else option 118 (RFC 3011), else `giaddr` | The sender is a trusted relay bound to that link ([`super::relay_link_gate`]) |
//! | INIT, SELECTING, INIT-REBOOT; DECLINE | Not relayed, no `ciaddr` | The listener's address | The source address is none or on that network ([`super::client_address_gate`]); option 50 lies on it |
//! | REBINDING; RELEASE, INFORM | Not relayed, from no address (a broadcast on the listener's link) | The listener's address | `ciaddr` lies on that network |
//! | RENEWING, REBINDING; RELEASE, INFORM | Not relayed, from an address | `ciaddr` | The source address lies on `ciaddr`'s network ([`super::client_address_gate`]); on another network than the listener's (a renewal routed to the server) only a lease the client holds is renewed or released |
//!
//! [`ConfigImage::select`] takes the most specific network that holds the selecting address;
//! a scope of a shared network brings its siblings, and "lies on the network" means on one
//! of them. Relay data counts only from a trusted relay (RFC 3527 section 4, RFC 3011
//! section 5: `dhcp.settings.trusted_relays`, [`crate::relay`]); the engine refuses a request
//! with a `giaddr` from any other sender before it selects. A client sends from its address
//! once it has one and from no address before (RFC 2131 section 4.1), so the source address
//! tells which network a request with `ciaddr` came from.
//!
//! The selection never reads the store and never allocates.

use std::net::Ipv4Addr;

use super::Received;
use crate::{
    image::{ConfigImage, ScopeImage},
    v4::{Message, MessageType, RelayAgentInfo},
};

/// Which field selected the scope (logged at debug level, risk R60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// The link selection sub-option of option 82 (RFC 3527).
    LinkSelection,
    /// Option 118 (RFC 3011).
    SubnetSelection,
    /// `giaddr`.
    Giaddr,
    /// `ciaddr` of a client that sends from an address.
    ClientAddress,
    /// The listener's address.
    Interface,
}

/// The address the scope is selected by, and why. `relay` is option 82 of a trusted relay
/// and `trusted` whether the sender is one; option 118 counts only then.
pub fn selector(
    message: &Message<'_>,
    kind: MessageType,
    relay: Option<RelayAgentInfo<'_>>,
    trusted: bool,
    received: &Received<'_>,
) -> (Ipv4Addr, Selector) {
    if let Some(link) = relay.and_then(|info| info.link_selection()) {
        return (link, Selector::LinkSelection);
    }
    if trusted && let Ok(Some(subnet)) = message.subnet_selection() {
        return (subnet, Selector::SubnetSelection);
    }
    let giaddr = message.giaddr();
    if !giaddr.is_unspecified() {
        return (giaddr, Selector::Giaddr);
    }
    let ciaddr = message.ciaddr();
    if !ciaddr.is_unspecified()
        && !received.source.ip().is_unspecified()
        && matches!(
            kind,
            MessageType::Request | MessageType::Inform | MessageType::Release
        )
    {
        return (ciaddr, Selector::ClientAddress);
    }
    (received.local, Selector::Interface)
}

/// The scope that serves the request, and why.
pub fn select<'a>(
    image: &'a ConfigImage,
    message: &Message<'_>,
    kind: MessageType,
    relay: Option<RelayAgentInfo<'_>>,
    trusted: bool,
    received: &Received<'_>,
) -> Option<(&'a ScopeImage, Selector)> {
    let (addr, how) = selector(message, kind, relay, trusted, received);
    image.select(addr).map(|scope| (scope, how))
}
