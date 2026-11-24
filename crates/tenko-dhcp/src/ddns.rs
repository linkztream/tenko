//! DDNS from DHCP (plan section 2.9, ADR 0020): names are written after the lease commit,
//! never inside it.
//!
//! When a committed lease gains, keeps or loses a name, the DDNS worker sees its row change
//! after the commit (the client has its answer already), builds a [`DdnsRequest`] from it
//! and applies it as a change set through the zone service with the RRset origin `dhcp`,
//! retrying with a backoff while the store refuses (`[dhcp.ddns] retries`, `backoff_ms`),
//! and records the names it wrote in `dhcp.ddns_names` in the same batch ([`names_of`]). On
//! release and expiry the records go while they are still the lease's.
//!
//! | Module | What |
//! |---|---|
//! | [`dhcid`] | the DHCID record of RFC 4701 (identifier types 0, 1 and 2, SHA-256) |
//! | [`names`] | the name of a lease: option 81, else option 12, under the scope's zone |
//! | [`flags`] | who writes the A record, and the flags of the reply's option 81 |
//! | [`plan`] | the RFC 4703 rules: what a request changes in the zones |
//! | [`worker`] | [`worker::DdnsService`], the leader service `dhcp.ddns` that follows the lease rows |
//! | [`metrics`] | `tenko_dhcp_ddns_total{outcome}`, `tenko_dhcp_ddns_queue` and `tenko_dhcp_ddns_oldest_seconds` |

pub mod dhcid;
pub mod flags;
pub mod metrics;
pub mod names;
pub mod plan;
pub mod worker;

pub use self::{
    plan::DdnsProfile,
    worker::{DdnsService, DdnsSettings, ProfileSource},
};

use std::net::IpAddr;

use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{ClientKey, DdnsNames, DdnsPolicy, DdnsState, tables::DDNS_NAMES},
};
use tenko_store::{ReadView, ReadViewExt as _, StoreError};

/// The names the DDNS worker wrote for the lease at `addr`, whose row holds `legacy`, as every
/// reader sees them: its record read through to the names an earlier version left on the
/// lease row ([`DdnsNames::through`]).
///
/// # Errors
///
/// The store's error.
pub fn names_of(
    view: &dyn ReadView,
    vrf: VrfId,
    addr: IpAddr,
    legacy: &DdnsState,
) -> Result<DdnsNames, StoreError> {
    Ok(record_of(view, vrf, addr, legacy)?.0)
}

/// [`names_of`] with the record row's version (none: no row).
fn record_of(
    view: &dyn ReadView,
    vrf: VrfId,
    addr: IpAddr,
    legacy: &DdnsState,
) -> Result<(DdnsNames, Option<Revision>), StoreError> {
    let row = view.get_typed(&DDNS_NAMES, &(vrf, addr))?;
    let version = row.as_ref().map(|(_, version)| *version);
    Ok((DdnsNames::through(row.map(|(row, _)| row), legacy), version))
}

/// Whether names are written or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdnsAction {
    /// Write the forward record, the PTR and the DHCID for the lease (on commit).
    Add,
    /// Remove them if the DHCID still matches (on release and expiry).
    Remove,
}

/// One DDNS job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdnsRequest {
    /// Write or remove.
    pub action: DdnsAction,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The address: of a DHCPv4 lease (A record) or, since WP9.1, a DHCPv6 lease (AAAA).
    pub addr: IpAddr,
    /// The client (the DHCID is computed from it, RFC 4701; a DHCPv6 client in the RFC
    /// 4361 form of its DUID).
    pub client: ClientKey,
    /// The name of option 81, as the client sent it.
    pub fqdn: Option<String>,
    /// The name of option 12.
    pub hostname: Option<String>,
    /// The flags of option 81 the client sent (S, O, E, N).
    pub fqdn_flags: Option<u8>,
    /// The scope's (or the policy's) DDNS settings.
    pub policy: DdnsPolicy,
    /// The lease time granted, for the TTL default.
    pub lease_secs: u32,
    /// When the lease ends.
    pub ends: Timestamp,
}
