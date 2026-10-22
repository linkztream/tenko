//! The DHCP part of the migration IR (plan section 3.1, P3-Q10; MIG-08 and MIG-12 in
//! Phase 4).
//!
//! A DHCP source adapter (the Windows DHCP export of `Export-DhcpServer` first, Kea and ISC
//! dhcpd in Phase 4) produces a [`DhcpIr`] beside the IPAM [`Ir`](super::Ir) and one
//! [`LossReport`](super::LossReport) for both. The items name each other by natural key:
//! a scope by its network, a class by its name, a reservation's host by its name; the
//! import maps them onto the Phase 3 model (a scope becomes a prefix with a `dhcp.scopes`
//! row, a pool an IPAM range of role `dhcp_pool`, a reservation an IPAM host of mode
//! `reserved` with its interface and address, options become option sets by owner).
//! `docs/dhcp-contracts.md` section 9 maps every element of the Windows export onto these
//! types.
//!
//! Values that have a Tenko type are parsed into it (addresses, networks, MAC addresses,
//! host names, lease times); option data stays in the source's text form ([`IrOption`]),
//! because only the import knows the definitions that give it a type, and data that does
//! not parse then becomes a loss entry. A failover relationship's shared secret is never
//! carried: the import records it as a loss and the operator enters it in the vault.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::SourceLocation;
use crate::{
    dhcp::{DdnsPolicy, FilterKind, Join, MacPattern, OptionKind},
    net::{HostName, MacAddr},
    serde_util::HexBytes,
    timestamp::Timestamp,
};

/// The DHCP content of a migration source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DhcpIr {
    /// Server-level option values.
    #[serde(default)]
    pub server_options: Vec<IrOption>,
    /// Custom option definitions.
    #[serde(default)]
    pub option_defs: Vec<IrOptionDef>,
    /// Vendor and user classes.
    #[serde(default)]
    pub classes: Vec<IrClass>,
    /// Scopes with their pools, exclusions, reservations and options.
    #[serde(default)]
    pub scopes: Vec<IrScope>,
    /// Superscopes (shared networks).
    #[serde(default)]
    pub superscopes: Vec<IrSuperscope>,
    /// Server-level and scope policies.
    #[serde(default)]
    pub policies: Vec<IrPolicy>,
    /// MAC filters.
    #[serde(default)]
    pub filters: Vec<IrFilter>,
    /// Failover relationships (kept for the Phase 5 pairing; the secret is never carried).
    #[serde(default)]
    pub failover: Vec<IrFailover>,
    /// Leases.
    #[serde(default)]
    pub leases: Vec<IrLease>,
}

impl DhcpIr {
    /// Whether the IR holds nothing.
    pub fn is_empty(&self) -> bool {
        self.server_options.is_empty()
            && self.option_defs.is_empty()
            && self.classes.is_empty()
            && self.scopes.is_empty()
            && self.superscopes.is_empty()
            && self.policies.is_empty()
            && self.filters.is_empty()
            && self.failover.is_empty()
            && self.leases.is_empty()
    }
}

/// An inclusive address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct IrRange {
    /// The first address.
    #[schema(value_type = String, example = "192.0.2.100")]
    pub first: IpAddr,
    /// The last address.
    #[schema(value_type = String, example = "192.0.2.199")]
    pub last: IpAddr,
}

/// How a client is identified in the source: a MAC address, or other client identifier
/// octets (Windows writes either in `ClientId`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct IrClientId {
    /// The MAC address, when the identifier is six octets of an Ethernet address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The identifier octets otherwise (option 61 data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<HexBytes>,
}

/// One option value, in the source's text form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrOption {
    /// The option code.
    pub code: u16,
    /// The vendor class it is set for (vendor options travel in option 43).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// The user class it is set for (Windows sets options per user class; Tenko maps this
    /// to a policy on the class).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_class: Option<String>,
    /// The values as the source writes them, one per element.
    #[serde(default)]
    pub values: Vec<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A custom option definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrOptionDef {
    /// The code.
    pub code: u16,
    /// The name in the source.
    pub name: String,
    /// The type, mapped from the source's type name.
    pub kind: OptionKind,
    /// Whether it holds a list.
    #[serde(default)]
    pub array: bool,
    /// The vendor class of a vendor option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// Whether a source class matches option 60 or option 77.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IrClassKind {
    /// Vendor class (option 60).
    Vendor,
    /// User class (option 77).
    User,
}

/// A vendor or user class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrClass {
    /// The name (the natural key options and policies refer to).
    pub name: String,
    /// Vendor or user.
    pub kind: IrClassKind,
    /// The class data the client sends.
    pub data: HexBytes,
    /// Whether the source marks it as a built-in default class (Windows' Microsoft
    /// classes), which the import skips.
    #[serde(default)]
    pub builtin: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrReservation {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub ip: IpAddr,
    /// The client.
    pub client: IrClientId,
    /// The name, as a host name when it parses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<HostName>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the reservation also answers BOOTP (Windows `Type` `Both` or `Bootp`).
    #[serde(default)]
    pub bootp: bool,
    /// Reservation-level options.
    #[serde(default)]
    pub options: Vec<IrOption>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrScope {
    /// The network (the natural key; becomes the IPAM prefix).
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// The name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the scope serves clients in the source.
    #[serde(default)]
    pub active: bool,
    /// The lease time in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u32>,
    /// The pools (Windows has one start and end range per scope).
    #[serde(default)]
    pub ranges: Vec<IrRange>,
    /// The exclusion ranges.
    #[serde(default)]
    pub exclusions: Vec<IrRange>,
    /// The reservations.
    #[serde(default)]
    pub reservations: Vec<IrReservation>,
    /// The scope's options.
    #[serde(default)]
    pub options: Vec<IrOption>,
    /// The DDNS settings, mapped (`DnsSettings` of Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddns: Option<DdnsPolicy>,
    /// The superscope it belongs to, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superscope: Option<String>,
    /// Whether only clients of the allow filter are served (the scope is restricted).
    #[serde(default)]
    pub restricted: bool,
    /// The offer delay in milliseconds (Windows `Delay`, for split scopes); Tenko has no
    /// delay and reports it as a loss when not zero.
    #[serde(default)]
    pub delay_ms: u32,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A superscope: several scopes on one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrSuperscope {
    /// The name.
    pub name: String,
    /// The member scopes, by network.
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<IpNet>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// What a policy condition looks at (the Windows criteria).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IrCriterion {
    /// Vendor class, by class name.
    VendorClass,
    /// User class, by class name.
    UserClass,
    /// MAC address, with wildcards.
    Mac,
    /// Client identifier.
    ClientId,
    /// Relay agent information as a whole.
    RelayAgent,
    /// Circuit-id.
    CircuitId,
    /// Remote-id.
    RemoteId,
    /// Subscriber-id (RFC 3993); Tenko has no match for it and reports a loss.
    SubscriberId,
    /// The client's FQDN, with a leading wildcard.
    Fqdn,
}

/// One condition of a policy: a criterion, equal or not equal, to any of the values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrCondition {
    /// The criterion.
    pub criterion: IrCriterion,
    /// Whether the condition is negated (`NotEquals`).
    #[serde(default)]
    pub negate: bool,
    /// The values in the source's text form (class names, MAC patterns, hexadecimal).
    pub values: Vec<String>,
}

/// A policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrPolicy {
    /// The name.
    pub name: String,
    /// The scope, by network; none for a server-level policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub scope: Option<IpNet>,
    /// The processing order.
    pub order: u32,
    /// Whether the policy is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// How the conditions are joined.
    pub join: Join,
    /// The conditions.
    #[serde(default)]
    pub conditions: Vec<IrCondition>,
    /// The address ranges the policy restricts its clients to.
    #[serde(default)]
    pub ranges: Vec<IrRange>,
    /// The options the policy sets.
    #[serde(default)]
    pub options: Vec<IrOption>,
    /// The lease time in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u32>,
    /// The DDNS settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddns: Option<DdnsPolicy>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A MAC filter entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrFilter {
    /// The addresses.
    pub mac: MacPattern,
    /// Allow or deny.
    pub kind: FilterKind,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// The mode of a failover relationship.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IrFailoverMode {
    /// Both servers serve, split by the RFC 3074 hash.
    LoadBalance,
    /// One server serves, the other holds a reserve.
    HotStandby,
}

/// A failover relationship (Phase 5 builds the pairing; Phase 4 keeps it for the report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrFailover {
    /// The relationship's name.
    pub name: String,
    /// The partner server, as the source names it (a placeholder in tests).
    pub partner: String,
    /// The mode.
    pub mode: IrFailoverMode,
    /// The maximum client lead time in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mclt_secs: Option<u32>,
    /// The local server's share in load balance, in percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balance_percent: Option<u8>,
    /// The reserve of the standby in hot standby, in percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_percent: Option<u8>,
    /// The scopes of the relationship, by network.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<IpNet>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// The state of a source lease.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IrLeaseState {
    /// Leased.
    Active,
    /// Leased to the client of a reservation.
    ActiveReservation,
    /// Declined by the client.
    Declined,
    /// Expired, not yet reclaimed.
    Expired,
    /// Any other state the source knows; reported as a loss.
    Other,
}

/// A lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrLease {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.50")]
    pub ip: IpAddr,
    /// The scope, by network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
    /// The client.
    pub client: IrClientId,
    /// The host name the client registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// When the lease ends; none for a reservation's lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    /// The state.
    pub state: IrLeaseState,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_cbor, to_cbor};

    #[test]
    fn the_dhcp_ir_round_trips() {
        let scope: IpNet = "192.0.2.0/24".parse().expect("net");
        let ir = DhcpIr {
            scopes: vec![IrScope {
                cidr: scope,
                name: Some("office".to_owned()),
                description: None,
                active: true,
                lease_secs: Some(691_200),
                ranges: vec![IrRange {
                    first: "192.0.2.100".parse().expect("ip"),
                    last: "192.0.2.199".parse().expect("ip"),
                }],
                exclusions: Vec::new(),
                reservations: vec![IrReservation {
                    ip: "192.0.2.10".parse().expect("ip"),
                    client: IrClientId {
                        mac: Some("00:00:5e:00:53:10".parse().expect("mac")),
                        client_id: None,
                    },
                    name: Some(HostName::new("printer01").expect("name")),
                    description: None,
                    bootp: false,
                    options: Vec::new(),
                    origin: SourceLocation::default(),
                }],
                options: vec![IrOption {
                    code: 6,
                    vendor_class: None,
                    user_class: None,
                    values: vec!["192.0.2.53".to_owned(), "198.51.100.53".to_owned()],
                    origin: SourceLocation::default(),
                }],
                ddns: Some(DdnsPolicy::default()),
                superscope: None,
                restricted: false,
                delay_ms: 0,
                origin: SourceLocation::default(),
            }],
            filters: vec![IrFilter {
                mac: "00:00:5e:00:53:*".parse().expect("pattern"),
                kind: FilterKind::Deny,
                description: None,
                origin: SourceLocation::default(),
            }],
            leases: vec![IrLease {
                ip: "192.0.2.150".parse().expect("ip"),
                scope,
                client: IrClientId {
                    mac: None,
                    client_id: Some(HexBytes(vec![1, 0, 0, 0x5e, 0, 0x53, 0x50])),
                },
                hostname: Some("laptop".to_owned()),
                expires: Some("2026-10-30T12:00:00Z".parse().expect("time")),
                state: IrLeaseState::Active,
                origin: SourceLocation::default(),
            }],
            ..DhcpIr::default()
        };
        assert!(!ir.is_empty() && DhcpIr::default().is_empty());
        assert_eq!(
            from_cbor::<DhcpIr>(&to_cbor(&ir).expect("cbor")).expect("cbor"),
            ir
        );
        let json = serde_json::to_string(&ir).expect("json");
        assert_eq!(serde_json::from_str::<DhcpIr>(&json).expect("json"), ir);
    }
}
