//! The options of a reply (plan section 2.4).
//!
//! The effective value of a code is the most specific level's: the reservation's (host
//! level), then the first matching policy's that holds the code (WP8.4), then the pool's,
//! then the scope's, which the image holds already merged with the shared network's and
//! the server's. The merge is a lookup per code over these short lists; nothing is copied.
//!
//! The order in the reply: option 53 (the builder writes it first), 54, the lease times
//! (51, 58, 59) when a lease is granted, the subnet mask (RFC 2132 section 3.3 wants it
//! before the routers), then every option the client lists in option 55 in the client's
//! order, then the options the server sends unasked when they are set (routers, DNS
//! servers, domain name, as Kea does), then option 61 echoed (RFC 6842), option 81 when
//! the client sent one, and option 82 unchanged and last (RFC 3046). A boot client with a
//! boot file also gets the boot options after the unasked ones ([`super::boot`], WP8.4). Codes the server
//! manages itself ([`SERVER_MANAGED_V4`]) never come from an option set. Room for the
//! closing options is kept before the others are written; an option that does not fit
//! within the client's size is left out whole, never cut. A value above 255 octets is
//! split into consecutive instances by the builder (RFC 3396). Option overload into `file`
//! and `sname` stays off: the scope image has no switch for it yet.

use std::net::Ipv4Addr;

use tenko_core::dhcp::{OptionValue, SERVER_MANAGED_V4};

// WP8.3: the reply's option 81 says what DDNS does for the scope.
use crate::ddns::flags::reply_flags;
// WP8.4: the policies and the boot options.
use super::boot;
use crate::class::Decision;
use crate::{
    image::{PoolImage, ScopeImage},
    v4::{EncodeError, Message, MessageBuilder, RelayAgentInfo, code},
};

/// The options the server sends without being asked when a level sets them.
pub const UNASKED: [u8; 3] = [code::ROUTERS, code::DOMAIN_NAME_SERVERS, code::DOMAIN_NAME];

/// The option levels of the reply's address.
#[derive(Debug, Clone, Copy)]
pub struct Levels<'a> {
    /// The address's scope (options merged from server, shared network and scope).
    pub scope: &'a ScopeImage,
    /// The address's pool.
    pub pool: Option<&'a PoolImage>,
    /// The reservation's options.
    pub host: Option<&'a [OptionValue]>,
    // WP8.4: the policies that match the client, between the pool and the reservation.
    /// The client's classes and policies; none outside the engine's request paths.
    pub decision: Option<&'a Decision<'a>>,
}

impl<'a> Levels<'a> {
    /// The effective value of `code` in the `dhcp4` space.
    pub fn lookup(&self, code: u8) -> Option<&'a [u8]> {
        let find = |values: &'a [OptionValue]| {
            values
                .iter()
                .find(|value| value.code == u16::from(code) && value.space.is_dhcp4())
                .map(|value| value.data.0.as_slice())
        };
        self.host
            .and_then(find)
            // WP8.4: the first matching policy whose set holds the code.
            .or_else(|| self.decision.and_then(|decision| decision.option(code)))
            .or_else(|| self.pool.and_then(|pool| find(&pool.options)))
            .or_else(|| find(&self.scope.options))
    }

    // WP8.4: the DDNS settings a policy gives the client.
    /// The DDNS settings for the client: the first matching policy's that sets them, else
    /// the scope's.
    pub fn ddns(&self) -> &'a tenko_core::dhcp::DdnsPolicy {
        self.decision
            .and_then(Decision::ddns)
            .unwrap_or(&self.scope.ddns)
    }
}

/// The lease times of an OFFER or ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseGrant {
    /// Option 51.
    pub granted: u32,
    /// Options 58 and 59.
    pub times: (u32, u32),
}

/// What the reply is built from.
pub struct Reply<'a, 'm> {
    /// The request.
    pub message: &'a Message<'m>,
    /// Option 54.
    pub server_id: Ipv4Addr,
    /// Option 61 of the request.
    pub client_id: Option<&'a [u8]>,
    /// Option 82 of the request.
    pub relay: Option<RelayAgentInfo<'a>>,
    /// The lease times; none for the ACK of an INFORM.
    pub lease: Option<LeaseGrant>,
    /// The option levels.
    pub levels: Levels<'a>,
}

/// The octets an option of `len` octets takes, split per RFC 3396.
fn cost(len: usize) -> usize {
    len + 2 * len.div_ceil(255).max(1)
}

/// Writes the options of an OFFER or ACK after option 53. `prl` is scratch space for a
/// split option 55.
///
/// # Errors
///
/// [`EncodeError::NoRoom`] when not even the server identifier and the lease times fit.
pub fn options(
    builder: &mut MessageBuilder<'_>,
    reply: &Reply<'_, '_>,
    prl: &mut [u8],
) -> Result<(), EncodeError> {
    builder.server_identifier(reply.server_id)?;
    if let Some(lease) = reply.lease {
        builder
            .lease_time(lease.granted)?
            .renewal_time(lease.times.0)?
            .rebinding_time(lease.times.1)?;
    }
    let fqdn = reply.message.client_fqdn().ok().flatten();
    let mut tail = 0;
    if let Some(id) = reply.client_id {
        tail += cost(id.len());
    }
    if let Some(fqdn) = &fqdn {
        tail += cost(3 + fqdn.name().as_wire().len());
    }
    if let Some(info) = reply.relay {
        tail += cost(info.as_bytes().len());
    }
    let mut done = [false; 256];
    for managed in SERVER_MANAGED_V4 {
        done[usize::from(managed)] = true;
    }
    let mut put = |builder: &mut MessageBuilder<'_>, code: u8, data: &[u8]| {
        if done[usize::from(code)] {
            return;
        }
        done[usize::from(code)] = true;
        if builder.len() + cost(data.len()) + tail <= builder.limit() {
            // Only `NoRoom` can come back here, and the option is left out whole.
            let _ = builder.option(code, data);
        }
    };
    let mask = reply.levels.scope.network.netmask().octets();
    let mask = reply.levels.lookup(code::SUBNET_MASK).unwrap_or(&mask);
    put(builder, code::SUBNET_MASK, mask);
    let asked = reply
        .message
        .option_data(code::PARAMETER_REQUEST_LIST, prl)
        .ok()
        .flatten()
        .unwrap_or_default();
    for &code in asked {
        if let Some(data) = reply.levels.lookup(code) {
            put(builder, code, data);
        }
    }
    for code in UNASKED {
        if let Some(data) = reply.levels.lookup(code) {
            put(builder, code, data);
        }
    }
    // WP8.4: a boot client with a boot file gets the boot options.
    if let Some((client, _)) = boot::boot_reply(&reply.levels) {
        boot::options(builder, &reply.levels, client, &mut put);
    }
    if let Some(id) = reply.client_id {
        builder.option(code::CLIENT_IDENTIFIER, id)?;
    }
    if let Some(fqdn) = &fqdn {
        // A name the ASCII form cannot carry is left out with the option.
        // WP8.3: the flags of the scope's DDNS policy (RFC 4702 section 4).
        // WP8.4: the first matching policy's DDNS settings over the scope's.
        let flags = reply_flags(reply.levels.ddns(), fqdn.flags());
        let _ = builder.client_fqdn(flags, &fqdn.name());
    }
    if let Some(info) = reply.relay {
        builder.relay_agent_info(info.as_bytes())?;
    }
    Ok(())
}
