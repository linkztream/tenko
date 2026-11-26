//! The plan of a scripted Windows takeover (ADR 0038, `docs/plans/windows-takeover-plan.md`
//! section 2.16.2): what the takeover script found on Windows and asks a person to approve.
//! It arrives with the approval request, is fixed by it, and bounds everything the run's
//! delegated session may create or change.
//!
//! The types hold the shape and the bounds a parse guarantees; the rules that relate the
//! parts (which zones a plan may name, one PDC emulator) are Tenko's own limits on the plan,
//! checked by `tenko_auth::approval` when the request arrives. Every list is bounded below,
//! and every name is a validated DNS name (at most 255 octets), so a plan that parses holds
//! at most [`MAX_ZONES`] + [`MAX_FORWARDERS`] + [`MAX_CONTROLLERS`] + [`MAX_DHCP_SERVERS`] +
//! [`MAX_SCOPES`] items whatever its body's size.

use std::net::IpAddr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    dns::DnsName,
    net::{Fqdn, HostName},
};

/// The most zones a plan names (the domain, `_msdcs` and the reverse zones).
pub const MAX_ZONES: usize = 64;
/// The most domain controllers a plan names.
pub const MAX_CONTROLLERS: usize = 16;
/// The most DHCP servers a plan names.
pub const MAX_DHCP_SERVERS: usize = 32;
/// The most DHCPv4 scopes a plan names.
pub const MAX_SCOPES: usize = 256;
/// The most conditional and server forwarders a plan names: a stated resource limit, far
/// above what a domain holds.
pub const MAX_FORWARDERS: usize = 64;
/// The most addresses of one controller or one forwarder: a stated resource limit.
pub const MAX_ADDRESSES: usize = 8;
/// The longest name of a failover relationship, in characters (ASCII only).
pub const MAX_RELATIONSHIP_LEN: usize = 64;
/// The most service principal names of Tenko's computer account.
pub const MAX_SPNS: usize = 4;

/// The plan of a run, as the script sends it with the approval request.
///
/// It is stored until its run is closed (`migrate.run_plans`), and these types refuse unknown
/// fields. A field added later therefore carries `#[serde(default)]` and raises the data
/// format with an empty migration (`crates/tenko/src/upgrade/migrations/mod.rs`,
/// `docs/upgrades.md` section 4.2), so that an older binary refuses the data directory instead
/// of failing on a stored plan that holds the field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TakeoverPlan {
    /// The domain (`corp.example.test`).
    #[schema(value_type = String)]
    pub domain: DnsName,
    /// The forest root, whose `_msdcs` zone the plan may name.
    #[schema(value_type = String)]
    pub forest_root: DnsName,
    /// The domain controllers, exactly one of them the PDC emulator.
    pub controllers: Vec<PlanController>,
    /// The zones the run takes over.
    #[schema(value_type = Vec<String>)]
    pub zones: Vec<DnsName>,
    /// Windows' conditional forwarders and server forwarders (`.`).
    #[serde(default)]
    pub forwarders: Vec<PlanForwarder>,
    /// The DHCP servers.
    pub dhcp_servers: Vec<PlanServer>,
    /// The failover relationship of the DHCP servers, when they have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    /// The DHCPv4 scopes the run takes over.
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Ipv4Net>,
    /// The member server the exporter runs on.
    pub mirror_host: PlanServer,
    /// The node's own host name, one label under the domain: its SOA `mname` and NS.
    #[schema(value_type = String)]
    pub node_name: HostName,
    /// What the run does on Tenko, phase by phase.
    pub operations: Vec<PlanOperation>,
    /// Tenko's computer account, for zones that take secure updates: the account the run
    /// adopts, absent when no zone needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kerberos: Option<PlanKerberos>,
}

/// Tenko's computer account in the domain, as the run creates and adopts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanKerberos {
    /// The realm: the domain in upper case (`CORP.EXAMPLE.TEST`).
    pub realm: String,
    /// The account's `sAMAccountName`: 1 to 15 letters, digits or hyphens and a `$`.
    pub account: String,
    /// Its service principal names, `DNS/<the node's name>` (1 to [`MAX_SPNS`]).
    pub spns: Vec<String>,
}

/// A domain controller of the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanController {
    /// Its name as Active Directory reports it.
    #[schema(value_type = String)]
    pub name: Fqdn,
    /// Its addresses as Active Directory reports them.
    #[schema(value_type = Vec<String>)]
    pub addresses: Vec<IpAddr>,
    /// Whether it is the PDC emulator: the one primary of Tenko's secondary zones.
    #[serde(default)]
    pub pdc: bool,
}

/// A server of the plan: a DHCP server or the mirror host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanServer {
    /// Its name.
    #[schema(value_type = String)]
    pub name: Fqdn,
    /// Its address.
    #[schema(value_type = String)]
    pub address: IpAddr,
}

/// A forwarder Windows holds: a conditional forwarder for a zone, or the server's forwarders
/// for `.`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanForwarder {
    /// The zone it forwards; `.` for the server's forwarders.
    #[schema(value_type = String)]
    pub zone: DnsName,
    /// The addresses it forwards to.
    #[schema(value_type = Vec<String>)]
    pub servers: Vec<IpAddr>,
}

/// What a run does on Tenko (the Tenko column of plan section 2.16.1's phases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanOperation {
    /// The mirrors of the DHCP servers, bound to the mirror host.
    Mirrors,
    /// The secondary zones from the PDC emulator, created not served.
    SecondaryZones,
    /// The forwarding rules of Windows' forwarders, created inactive.
    ForwardingRules,
    /// The zones' update policy and Kerberos settings.
    UpdatePolicy,
    /// The adoption of Tenko's computer account.
    KerberosAdopt,
    /// The prepare of the scopes.
    Prepare,
    /// The flip of the zones to primary, with their transfer and notify lists.
    Flip,
    /// The takeover of the scopes.
    Takeover,
    /// The release of the zones' frozen names.
    Release,
}
