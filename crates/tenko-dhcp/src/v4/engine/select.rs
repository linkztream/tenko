//! Scope selection (plan section 2.5, the topology-based selection of RFC 7969).
//!
//! The first of these that a request carries picks the address the scope's network must
//! hold, and [`ConfigImage::select`] takes the most specific network that holds it:
//!
//! 1. the link selection sub-option of option 82 (RFC 3527), which a relay sets when
//!    `giaddr` is an address of another link than the client's;
//! 2. option 118, the subnet selection (RFC 3011);
//! 3. `giaddr`, the relay's address on the client's link (RFC 2131 section 4.3.1);
//! 4. `ciaddr` of a REQUEST, INFORM or RELEASE that is not relayed: a client that has an
//!    address and unicasts to the server, which in relay mode is the only way a renewal
//!    arrives (the client is on another link than the listener);
//! 5. the address of the listener the request arrived on (a client on the listener's link).
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
    /// `ciaddr` of a client with an address.
    ClientAddress,
    /// The listener's address.
    Interface,
}

/// The address the scope is selected by, and why.
pub fn selector(
    message: &Message<'_>,
    kind: MessageType,
    relay: Option<RelayAgentInfo<'_>>,
    received: &Received<'_>,
) -> (Ipv4Addr, Selector) {
    if let Some(link) = relay.and_then(|info| info.link_selection()) {
        return (link, Selector::LinkSelection);
    }
    if let Ok(Some(subnet)) = message.subnet_selection() {
        return (subnet, Selector::SubnetSelection);
    }
    let giaddr = message.giaddr();
    if !giaddr.is_unspecified() {
        return (giaddr, Selector::Giaddr);
    }
    let ciaddr = message.ciaddr();
    if !ciaddr.is_unspecified()
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
    received: &Received<'_>,
) -> Option<(&'a ScopeImage, Selector)> {
    let (addr, how) = selector(message, kind, relay, received);
    image.select(addr).map(|scope| (scope, how))
}
