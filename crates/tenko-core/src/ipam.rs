//! The IPAM model (plan section 2.2): tenants, VRFs, sites, VLANs, prefixes, ranges,
//! addresses, hosts and interfaces, with their shared metadata.
//!
//! These are plain data. The rules (overlap only across VRFs per IPAM-23, the nibble-boundary
//! acknowledgement for IPv6 per IPAM-06, the warning for a `reserved` host without MAC or
//! DUID per IPAM-18) live in `tenko-ipam`, which owns the `ipam.*` tables.
//!
//! The IPAM-12 intent sentence "host X has IP Y in network Z, with an assignment mode, a DNS
//! name and a VLAN" maps to [`Host`] (mode), [`Interface`] (MAC), [`Address`] (IP, DNS name)
//! and [`Prefix`] (network, VLAN).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    str::FromStr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    error::InvalidValue,
    id::{
        AddressId, CustomFieldId, HostId, InterfaceId, PrefixId, RangeId, Revision, SiteId,
        TenantId, VlanId, VrfId,
    },
    net::{Duid, Fqdn, HostName, MacAddr},
    object::ObjectKind,
    principal::Principal,
    serde_util::HexBytes,
    timestamp::Timestamp,
};

/// When and by whom something happened.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Stamp {
    /// The time (the proposer's request time).
    pub at: Timestamp,
    /// The principal.
    pub by: Principal,
}

impl Stamp {
    /// Creates a stamp.
    pub fn new(at: Timestamp, by: Principal) -> Self {
        Self { at, by }
    }
}

/// Metadata shared by every IPAM object (IPAM-08, IPAM-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Meta {
    /// Store revision of the last write. Readers overwrite it with the revision the store
    /// reports for the value (`Versioned::revision`); the stored copy is not authoritative,
    /// because the revision is only known after the write commits.
    #[serde(default)]
    pub revision: Revision,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
    /// Soft deletion (IPAM-09); a deleted object can be restored.
    #[serde(default)]
    pub deleted: Option<Stamp>,
    /// Tags (IPAM-08).
    #[serde(default)]
    pub tags: BTreeSet<Tag>,
    /// Custom field values (IPAM-08), validated against their [`CustomFieldDef`].
    #[serde(default)]
    pub custom: BTreeMap<FieldKey, CustomValue>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

impl Meta {
    /// Metadata of a new object.
    pub fn new(stamp: Stamp) -> Self {
        Self {
            revision: Revision::ZERO,
            created: stamp.clone(),
            updated: stamp,
            deleted: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    /// Whether the object is soft-deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

/// A tenant (IPAM-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Tenant {
    /// Identifier.
    pub id: TenantId,
    /// Unique name.
    pub name: String,
    // Backlog: the tenant's default zone.
    /// DNS settings: the default zone (`dns.default_zone`).
    #[serde(default, skip_serializing_if = "crate::dns::TenantDns::is_empty")]
    pub dns: crate::dns::TenantDns,
    /// Metadata.
    pub meta: Meta,
}

/// A VRF: an independent address space inside a tenant (IPAM-01). Prefixes overlap only
/// across VRFs (IPAM-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Vrf {
    /// Identifier.
    pub id: VrfId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Name, unique within the tenant.
    pub name: String,
    /// Route distinguisher, informational.
    #[serde(default)]
    pub rd: Option<String>,
    /// Metadata.
    pub meta: Meta,
}

/// A site, optionally nested (IPAM-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Site {
    /// Identifier.
    pub id: SiteId,
    /// Name.
    pub name: String,
    /// Parent site.
    #[serde(default)]
    pub parent: Option<SiteId>,
    /// Matching Active Directory site name, for migration and DNS later.
    #[serde(default)]
    pub ad_site: Option<String>,
    /// Metadata.
    pub meta: Meta,
}

/// A VLAN (IPAM-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Vlan {
    /// Identifier.
    pub id: VlanId,
    /// VLAN id, 1 to 4094.
    pub vid: u16,
    /// VXLAN network identifier, if any.
    #[serde(default)]
    pub vni: Option<u32>,
    /// Name.
    pub name: String,
    /// Site the VLAN belongs to; `None` means global.
    #[serde(default)]
    pub site: Option<SiteId>,
    /// Lifecycle status.
    pub status: Status,
    /// Metadata.
    pub meta: Meta,
}

/// A prefix: a supernet (container) or a network (IPAM-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Prefix {
    /// Identifier.
    pub id: PrefixId,
    /// The VRF the prefix lives in.
    pub vrf: VrfId,
    /// The network in CIDR notation, without host bits.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// Supernet or network.
    pub role: PrefixRole,
    /// Lifecycle status.
    pub status: Status,
    /// VLAN of the network.
    #[serde(default)]
    pub vlan: Option<VlanId>,
    /// Site of the network.
    #[serde(default)]
    pub site: Option<SiteId>,
    /// Utilization alarm thresholds (IPAM-10).
    #[serde(default)]
    pub alarm: Option<UtilizationAlarm>,
    /// Allocation policy for next-free (IPAM-07).
    #[serde(default)]
    pub alloc: AllocPolicy,
    /// Whether Tenko keeps the reverse zone of the network (plan section 2.6, DNS-22);
    /// absent: managed when the VRF's tenant has a forward zone in Tenko, else off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_reverse: Option<DnsReverse>,
    /// Metadata.
    pub meta: Meta,
}

/// Whether Tenko creates and keeps the reverse zone of a prefix (plan section 2.6,
/// P2-Q11).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DnsReverse {
    /// The `in-addr.arpa` or `ip6.arpa` zone is created and its PTR records kept.
    Managed,
    /// No reverse zone is kept; a zone kept before stays in place.
    Off,
}

/// A range of addresses inside a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Range {
    /// Identifier.
    pub id: RangeId,
    /// The containing prefix.
    pub prefix: PrefixId,
    /// First address, inclusive.
    #[schema(value_type = String, example = "192.0.2.100")]
    pub first: IpAddr,
    /// Last address, inclusive.
    #[schema(value_type = String, example = "192.0.2.199")]
    pub last: IpAddr,
    /// What the range is for.
    pub role: RangeRole,
    /// DHCP lease time in seconds of a `dhcp_pool` range. Informational until Tenko DHCP
    /// exists, and the source of the default move timeout (IPAM-19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u32>,
    /// Lifecycle status.
    pub status: Status,
    /// Metadata.
    pub meta: Meta,
}

/// An IP address object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Address {
    /// Identifier.
    pub id: AddressId,
    /// The VRF.
    pub vrf: VrfId,
    /// The address.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub ip: IpAddr,
    /// The most specific prefix containing the address.
    pub prefix: PrefixId,
    /// Lifecycle status.
    pub status: Status,
    /// The interface the address is assigned to.
    #[serde(default)]
    pub interface: Option<InterfaceId>,
    /// Intended DNS name (A, AAAA and PTR from Phase 2).
    #[serde(default)]
    pub dns_name: Option<Fqdn>,
    /// Metadata.
    pub meta: Meta,
}

/// A host: the unit of intent (IPAM-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Host {
    /// Identifier.
    pub id: HostId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Name.
    pub name: HostName,
    /// What IPAM may do with the host (IPAM-14).
    pub mode: AssignmentMode,
    /// Stops all automation for the host (IPAM-16).
    #[serde(default)]
    pub lock: bool,
    /// Site.
    #[serde(default)]
    pub site: Option<SiteId>,
    /// Metadata.
    pub meta: Meta,
}

/// A network interface of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Interface {
    /// Identifier.
    pub id: InterfaceId,
    /// Owning host.
    pub host: HostId,
    /// Name, such as `eth0`.
    pub name: String,
    /// MAC address (DHCPv4 reservations).
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// DUID (DHCPv6 reservations).
    #[serde(default)]
    pub duid: Option<Duid>,
    /// DHCPv4 client identifier (option 61).
    #[serde(default)]
    pub client_id: Option<HexBytes>,
    /// Metadata.
    pub meta: Meta,
}

/// What IPAM may do when a host's intent changes (IPAM-14, ADR 0005).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentMode {
    /// DNS only, plus a manual task to reconfigure the device.
    Static,
    /// DHCP reservation and DNS.
    Reserved,
    /// IPAM only observes.
    Dynamic,
    /// Nothing touches the host.
    Unmanaged,
}

/// Lifecycle status (IPAM-05).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Planned, not in use yet.
    Planned,
    /// In use.
    #[default]
    Active,
    /// Held back, not to be allocated.
    Reserved,
    /// Being retired.
    Deprecated,
}

/// Role of a prefix (IPAM-02).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrefixRole {
    /// A container of other prefixes.
    Supernet,
    /// A network that holds addresses.
    Network,
}

/// Role of a range.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RangeRole {
    /// A DHCP pool.
    DhcpPool,
    /// Held back from allocation.
    Reserved,
    /// Gateways, switches and other infrastructure.
    Infrastructure,
}

/// Which end of a prefix next-free allocation starts from (IPAM-07).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AllocPolicy {
    /// Lowest free address or prefix first.
    #[default]
    Lowest,
    /// Highest free address or prefix first.
    Highest,
}

/// Utilization alarm thresholds of a prefix in percent (IPAM-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct UtilizationAlarm {
    /// Warning threshold.
    pub warn_pct: u8,
    /// Critical threshold.
    pub crit_pct: u8,
}

impl UtilizationAlarm {
    /// Validates the thresholds: `warn_pct < crit_pct <= 100`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the thresholds are out of order or above 100.
    pub fn new(warn_pct: u8, crit_pct: u8) -> Result<Self, InvalidValue> {
        if warn_pct < crit_pct && crit_pct <= 100 {
            Ok(Self { warn_pct, crit_pct })
        } else {
            Err(InvalidValue::new(
                "utilization alarm",
                &format!("{warn_pct}/{crit_pct}"),
                "warning must be below critical, and critical at most 100",
            ))
        }
    }
}

/// A tag (IPAM-08): 1 to 64 characters, no control characters, surrounding whitespace
/// removed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type = String)]
pub struct Tag(String);

impl Tag {
    /// Validates a tag.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the tag is empty, too long or has control characters.
    pub fn new(tag: &str) -> Result<Self, InvalidValue> {
        let trimmed = tag.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 64 {
            return Err(InvalidValue::new("tag", tag, "must be 1 to 64 characters"));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(InvalidValue::new(
                "tag",
                tag,
                "control characters are not allowed",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The tag text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({:?})", self.0)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Tag {
    type Error = InvalidValue;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<Tag> for String {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

impl FromStr for Tag {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Key of a custom field (IPAM-08): `[a-z][a-z0-9_]{0,63}`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type = String)]
pub struct FieldKey(String);

impl FieldKey {
    /// Validates a key.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the key breaks the pattern.
    pub fn new(key: &str) -> Result<Self, InvalidValue> {
        let valid = (1..=64).contains(&key.len())
            && key.starts_with(|c: char| c.is_ascii_lowercase())
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if valid {
            Ok(Self(key.to_owned()))
        } else {
            Err(InvalidValue::new(
                "custom field key",
                key,
                "must match [a-z][a-z0-9_]{0,63}",
            ))
        }
    }

    /// The key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FieldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldKey({:?})", self.0)
    }
}

impl fmt::Display for FieldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for FieldKey {
    type Error = InvalidValue;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<FieldKey> for String {
    fn from(key: FieldKey) -> Self {
        key.0
    }
}

impl FromStr for FieldKey {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Definition of a custom field (IPAM-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CustomFieldDef {
    /// Identifier, so the definition can be audited and referenced.
    pub id: CustomFieldId,
    /// The key used in [`Meta::custom`].
    pub key: FieldKey,
    /// Value type.
    pub kind: CustomKind,
    /// Object kinds the field applies to.
    pub applies_to: Vec<ObjectKind>,
    /// Whether every object of those kinds must have a value.
    #[serde(default)]
    pub required: bool,
}

/// Value type of a custom field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CustomKind {
    /// Free text.
    Text,
    /// A signed integer.
    Integer,
    /// True or false.
    Boolean,
    /// A calendar date (`YYYY-MM-DD`).
    Date,
    /// A URL.
    Url,
    /// One of a fixed list of options.
    Select {
        /// The allowed options.
        options: Vec<String>,
    },
}

/// A custom field value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum CustomValue {
    /// Free text.
    Text(String),
    /// A signed integer.
    Integer(i64),
    /// True or false.
    Boolean(bool),
    /// A calendar date in ISO 8601 form (`YYYY-MM-DD`), validated by the IPAM domain.
    Date(String),
    /// A URL.
    Url(String),
    /// The chosen option.
    Select(String),
}

impl CustomValue {
    /// Whether the value matches the field type (dates and select options are checked;
    /// URL syntax is left to the IPAM domain).
    pub fn matches(&self, kind: &CustomKind) -> bool {
        match (self, kind) {
            (CustomValue::Text(_), CustomKind::Text)
            | (CustomValue::Integer(_), CustomKind::Integer)
            | (CustomValue::Boolean(_), CustomKind::Boolean)
            | (CustomValue::Url(_), CustomKind::Url) => true,
            (CustomValue::Date(date), CustomKind::Date) => is_iso_date(date),
            (CustomValue::Select(choice), CustomKind::Select { options }) => {
                options.contains(choice)
            }
            _ => false,
        }
    }
}

fn is_iso_date(text: &str) -> bool {
    // Only digits and separators: `parse` would accept signed components such as `+026`.
    if !text.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return false;
    }
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return false;
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) =
        (year.parse::<i32>(), month.parse::<u8>(), day.parse::<u8>())
    else {
        return false;
    };
    time::Month::try_from(month)
        .ok()
        .and_then(|month| time::Date::from_calendar_date(year, month, day).ok())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{from_cbor, to_cbor},
        principal::SystemComponent,
    };

    fn stamp() -> Stamp {
        Stamp::new(
            "2026-10-09T12:00:00Z".parse().expect("time"),
            Principal::system(SystemComponent::Ipam),
        )
    }

    fn prefix() -> Prefix {
        Prefix {
            id: PrefixId::generate(),
            vrf: VrfId::generate(),
            cidr: "192.0.2.0/24".parse().expect("cidr"),
            role: PrefixRole::Network,
            status: Status::Active,
            vlan: None,
            site: None,
            alarm: Some(UtilizationAlarm::new(80, 95).expect("alarm")),
            alloc: AllocPolicy::Lowest,
            dns_reverse: None,
            meta: Meta::new(stamp()),
        }
    }

    #[test]
    fn prefix_round_trips_in_json_and_cbor() {
        let mut prefix = prefix();
        prefix.meta.tags.insert(Tag::new("lab").expect("tag"));
        prefix.meta.custom.insert(
            FieldKey::new("owner").expect("key"),
            CustomValue::Text("network team".to_owned()),
        );
        let json = serde_json::to_value(&prefix).expect("json");
        assert_eq!(json["cidr"], "192.0.2.0/24");
        assert_eq!(json["meta"]["custom"]["owner"]["type"], "text");
        let back: Prefix = serde_json::from_value(json).expect("json");
        assert_eq!(back, prefix);
        let back: Prefix = from_cbor(&to_cbor(&prefix).expect("cbor")).expect("cbor");
        assert_eq!(back, prefix);
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let mut json = serde_json::to_value(prefix()).expect("json");
        let object = json.as_object_mut().expect("object");
        for field in ["vlan", "site", "alarm", "alloc", "dns_reverse"] {
            object.remove(field);
        }
        let back: Prefix = serde_json::from_value(json).expect("json");
        assert_eq!(back.alloc, AllocPolicy::Lowest);
        assert_eq!(back.alarm, None);
        assert_eq!(back.dns_reverse, None);
    }

    #[test]
    fn the_reverse_setting_round_trips_and_older_rows_read_without_it() {
        let mut prefix = prefix();
        prefix.dns_reverse = Some(DnsReverse::Managed);
        let json = serde_json::to_value(&prefix).expect("json");
        assert_eq!(json["dns_reverse"], "managed");
        let back: Prefix = from_cbor(&to_cbor(&prefix).expect("cbor")).expect("cbor");
        assert_eq!(back, prefix);
        // A row written before the field existed (format 3) reads as automatic.
        prefix.dns_reverse = None;
        let old = to_cbor(&prefix).expect("cbor");
        let back: Prefix = from_cbor(&old).expect("cbor");
        assert_eq!(back.dns_reverse, None);
        assert!(
            !serde_json::to_value(&back)
                .expect("json")
                .as_object()
                .expect("object")
                .contains_key("dns_reverse")
        );
    }

    #[test]
    fn alarm_thresholds_are_ordered() {
        assert!(UtilizationAlarm::new(80, 95).is_ok());
        assert!(UtilizationAlarm::new(95, 80).is_err());
        assert!(UtilizationAlarm::new(80, 101).is_err());
    }

    #[test]
    fn tags_and_field_keys_validate() {
        assert_eq!(Tag::new("  iot ").expect("tag").as_str(), "iot");
        assert!(Tag::new("").is_err());
        assert!(Tag::new("a\nb").is_err());
        assert!(FieldKey::new("rack_unit").is_ok());
        assert!(FieldKey::new("Rack").is_err());
        assert!(FieldKey::new("1rack").is_err());
    }

    #[test]
    fn custom_values_match_their_kind() {
        assert!(CustomValue::Date("2026-02-28".to_owned()).matches(&CustomKind::Date));
        assert!(!CustomValue::Date("2026-02-30".to_owned()).matches(&CustomKind::Date));
        let select = CustomKind::Select {
            options: vec!["a".to_owned()],
        };
        assert!(CustomValue::Select("a".to_owned()).matches(&select));
        assert!(!CustomValue::Select("b".to_owned()).matches(&select));
        assert!(!CustomValue::Integer(1).matches(&CustomKind::Text));
    }
}
