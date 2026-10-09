//! The import vocabulary: the targets a column can map to, the header synonyms that
//! suggest them (English and Swedish), and the column names of the CSV export.
//!
//! The export writes exactly the canonical names of [`Target`] as its headers
//! (MIG-14), so an export maps onto itself when it is imported again (IPAM-11).
//!
//! A target applies to the entity a row describes: in an address list `description` is
//! the address's description, in a network list the prefix's, in a host list or a
//! device-centric sheet the host's.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tenko_core::ipam::FieldKey;
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, Type},
};

/// Prefix of a custom field target (`custom.rack_unit`).
pub const CUSTOM_PREFIX: &str = "custom.";

/// What a column is imported as.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// Not imported (values in it are listed in the loss report).
    Ignore,
    /// An address (several address columns make a device-centric sheet: one interface per
    /// column). Range cells are split into their addresses.
    Address,
    /// A network in CIDR notation.
    Prefix,
    /// A subnet mask or prefix length for the address or network of the row.
    Mask,
    /// The host name.
    Name,
    /// The intended DNS name of the address.
    DnsName,
    /// Free text of the row's entity.
    Description,
    /// Lifecycle status of the row's entity (`planned`, `active`, `reserved`,
    /// `deprecated`).
    Status,
    /// Assignment mode of the host (`static`, `reserved`, `dynamic`, `unmanaged`).
    Mode,
    /// Lock of the host against automation (`true`, `false`, `yes`, `no`, `ja`, `nej`).
    Lock,
    /// MAC address of the interface.
    Mac,
    /// DUID of the interface.
    Duid,
    /// DHCPv4 client identifier of the interface (hexadecimal).
    ClientId,
    /// Interface name of the address.
    Interface,
    /// Every interface of a host: `name`, `name=mac` or `name=mac=duid`, separated by `;`.
    Interfaces,
    /// VLAN id of the network.
    Vlan,
    /// VLAN name.
    VlanName,
    /// Site name.
    Site,
    /// VRF name.
    Vrf,
    /// Tenant name.
    Tenant,
    /// Prefix role (`network`, `supernet`).
    Role,
    /// Next-free policy of a prefix (`lowest`, `highest`).
    Alloc,
    /// Utilization warning threshold of a prefix, in percent.
    AlarmWarn,
    /// Utilization critical threshold of a prefix, in percent.
    AlarmCrit,
    /// Tags, separated by `;`.
    Tags,
    /// A login: a credential, stored as an operator secret of the host, never as an IPAM
    /// field.
    Login,
    /// A password: a credential, stored as an operator secret of the host, never as an
    /// IPAM field.
    Password,
    /// A custom field (IPAM-08).
    Custom(FieldKey),
}

impl Target {
    /// Every target except custom fields, in the order the mapping UI lists them.
    pub const FIXED: [Target; 27] = [
        Target::Ignore,
        Target::Address,
        Target::Prefix,
        Target::Mask,
        Target::Name,
        Target::DnsName,
        Target::Description,
        Target::Status,
        Target::Mode,
        Target::Lock,
        Target::Mac,
        Target::Duid,
        Target::ClientId,
        Target::Interface,
        Target::Interfaces,
        Target::Vlan,
        Target::VlanName,
        Target::Site,
        Target::Vrf,
        Target::Tenant,
        Target::Role,
        Target::Alloc,
        Target::AlarmWarn,
        Target::AlarmCrit,
        Target::Tags,
        Target::Login,
        Target::Password,
    ];

    /// The canonical name, which is also the export column name.
    pub fn name(&self) -> String {
        match self {
            Target::Custom(key) => format!("{CUSTOM_PREFIX}{key}"),
            other => other.fixed_name().to_owned(),
        }
    }

    fn fixed_name(&self) -> &'static str {
        match self {
            Target::Ignore => "ignore",
            Target::Address => "address",
            Target::Prefix => "prefix",
            Target::Mask => "mask",
            Target::Name => "host",
            Target::DnsName => "dns_name",
            Target::Description => "description",
            Target::Status => "status",
            Target::Mode => "mode",
            Target::Lock => "lock",
            Target::Mac => "mac",
            Target::Duid => "duid",
            Target::ClientId => "client_id",
            Target::Interface => "interface",
            Target::Interfaces => "interfaces",
            Target::Vlan => "vlan",
            Target::VlanName => "vlan_name",
            Target::Site => "site",
            Target::Vrf => "vrf",
            Target::Tenant => "tenant",
            Target::Role => "role",
            Target::Alloc => "alloc",
            Target::AlarmWarn => "alarm_warn",
            Target::AlarmCrit => "alarm_crit",
            Target::Tags => "tags",
            Target::Login => "login",
            Target::Password => "password",
            Target::Custom(_) => "custom",
        }
    }

    /// Whether the target is a credential (never an IPAM field).
    pub fn is_credential(&self) -> bool {
        matches!(self, Target::Login | Target::Password)
    }

    /// An English label for the mapping UI (the UI translates by [`Target::name`]).
    pub fn label(&self) -> String {
        let text = match self {
            Target::Ignore => "Do not import",
            Target::Address => "Address",
            Target::Prefix => "Network (CIDR)",
            Target::Mask => "Subnet mask or prefix length",
            Target::Name => "Host name",
            Target::DnsName => "DNS name",
            Target::Description => "Description",
            Target::Status => "Status",
            Target::Mode => "Assignment mode",
            Target::Lock => "Lock",
            Target::Mac => "MAC address",
            Target::Duid => "DUID",
            Target::ClientId => "DHCP client identifier",
            Target::Interface => "Interface name",
            Target::Interfaces => "Interfaces of the host",
            Target::Vlan => "VLAN id",
            Target::VlanName => "VLAN name",
            Target::Site => "Site",
            Target::Vrf => "VRF",
            Target::Tenant => "Tenant",
            Target::Role => "Prefix role",
            Target::Alloc => "Next-free policy",
            Target::AlarmWarn => "Utilization warning (%)",
            Target::AlarmCrit => "Utilization critical (%)",
            Target::Tags => "Tags",
            Target::Login => "Login (stored in the vault)",
            Target::Password => "Password (stored in the vault)",
            Target::Custom(key) => return format!("Custom field {key}"),
        };
        text.to_owned()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Custom(key) => write!(f, "{CUSTOM_PREFIX}{key}"),
            other => f.write_str(other.fixed_name()),
        }
    }
}

/// An unknown target name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not an import target")]
pub struct UnknownTarget(pub String);

impl FromStr for Target {
    type Err = UnknownTarget;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(key) = s.strip_prefix(CUSTOM_PREFIX) {
            return FieldKey::new(key)
                .map(Target::Custom)
                .map_err(|_| UnknownTarget(s.to_owned()));
        }
        Target::FIXED
            .iter()
            .find(|target| target.fixed_name() == s)
            .cloned()
            .ok_or_else(|| UnknownTarget(s.to_owned()))
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for Target {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .description(Some(
                "Import target: `ignore`, `address`, `prefix`, `mask`, `host`, `dns_name`, \
                 `description`, `status`, `mode`, `lock`, `mac`, `duid`, `client_id`, \
                 `interface`, `interfaces`, `vlan`, `vlan_name`, `site`, `vrf`, `tenant`, \
                 `role`, `alloc`, `alarm_warn`, `alarm_crit`, `tags`, `login`, `password` or \
                 `custom.<key>`",
            ))
            .examples([serde_json::json!("address")])
            .into()
    }
}

impl ToSchema for Target {}

/// Normalizes a header for synonym lookup: lowercase, letters (including `å`, `ä`, `ö`)
/// and digits kept, everything else removed.
pub fn normalize_header(header: &str) -> String {
    header
        .trim()
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Header synonyms (normalized, see [`normalize_header`]) and the target they suggest.
const SYNONYMS: &[(&str, Target)] = &[
    // Addresses.
    ("ip", Target::Address),
    ("ipadress", Target::Address),
    ("ipaddress", Target::Address),
    ("ipaddr", Target::Address),
    ("address", Target::Address),
    ("adress", Target::Address),
    ("ipv4", Target::Address),
    ("ipv6", Target::Address),
    ("ipv4adress", Target::Address),
    ("ipv4address", Target::Address),
    ("ipv6adress", Target::Address),
    ("ipv6address", Target::Address),
    // Networks.
    ("prefix", Target::Prefix),
    ("cidr", Target::Prefix),
    ("network", Target::Prefix),
    ("net", Target::Prefix),
    ("nät", Target::Prefix),
    ("nätverk", Target::Prefix),
    ("subnet", Target::Prefix),
    ("subnät", Target::Prefix),
    ("prefixcidr", Target::Prefix),
    // Masks.
    ("mask", Target::Mask),
    ("netmask", Target::Mask),
    ("nätmask", Target::Mask),
    ("subnetmask", Target::Mask),
    ("subnätmask", Target::Mask),
    ("prefixlength", Target::Mask),
    ("prefixlen", Target::Mask),
    ("prefixlängd", Target::Mask),
    // Names.
    ("host", Target::Name),
    ("hostname", Target::Name),
    ("name", Target::Name),
    ("namn", Target::Name),
    ("värdnamn", Target::Name),
    ("värd", Target::Name),
    ("device", Target::Name),
    ("enhet", Target::Name),
    ("beteckning", Target::Name),
    ("dator", Target::Name),
    ("server", Target::Name),
    // DNS names.
    ("dnsname", Target::DnsName),
    ("dns", Target::DnsName),
    ("dnsnamn", Target::DnsName),
    ("fqdn", Target::DnsName),
    // Descriptions.
    ("description", Target::Description),
    ("beskrivning", Target::Description),
    ("comment", Target::Description),
    ("comments", Target::Description),
    ("kommentar", Target::Description),
    ("kommentarer", Target::Description),
    ("notes", Target::Description),
    ("note", Target::Description),
    ("anteckning", Target::Description),
    ("anteckningar", Target::Description),
    ("info", Target::Description),
    ("remark", Target::Description),
    ("övrigt", Target::Description),
    // Lifecycle and assignment.
    ("status", Target::Status),
    ("state", Target::Status),
    ("mode", Target::Mode),
    ("assignment", Target::Mode),
    ("assignmentmode", Target::Mode),
    ("tilldelning", Target::Mode),
    ("lock", Target::Lock),
    ("locked", Target::Lock),
    ("låst", Target::Lock),
    // Interfaces.
    ("mac", Target::Mac),
    ("macaddress", Target::Mac),
    ("macadress", Target::Mac),
    ("macaddr", Target::Mac),
    ("hwaddr", Target::Mac),
    ("hardwareaddress", Target::Mac),
    ("duid", Target::Duid),
    ("clientid", Target::ClientId),
    ("klientid", Target::ClientId),
    ("interface", Target::Interface),
    ("iface", Target::Interface),
    ("nätverkskort", Target::Interface),
    ("interfaces", Target::Interfaces),
    // VLANs, sites and tenancy.
    ("vlan", Target::Vlan),
    ("vlanid", Target::Vlan),
    ("vid", Target::Vlan),
    ("vlanname", Target::VlanName),
    ("vlannamn", Target::VlanName),
    ("site", Target::Site),
    ("plats", Target::Site),
    ("location", Target::Site),
    ("placering", Target::Site),
    ("vrf", Target::Vrf),
    ("tenant", Target::Tenant),
    ("kund", Target::Tenant),
    // Prefix settings.
    ("role", Target::Role),
    ("roll", Target::Role),
    ("alloc", Target::Alloc),
    ("alarmwarn", Target::AlarmWarn),
    ("alarmcrit", Target::AlarmCrit),
    // Tags.
    ("tags", Target::Tags),
    ("tag", Target::Tags),
    ("taggar", Target::Tags),
    // Credentials: never IPAM fields.
    ("login", Target::Login),
    ("user", Target::Login),
    ("username", Target::Login),
    ("användare", Target::Login),
    ("användarnamn", Target::Login),
    ("anv", Target::Login),
    ("pass", Target::Password),
    ("password", Target::Password),
    ("passwd", Target::Password),
    ("pwd", Target::Password),
    ("lösen", Target::Password),
    ("lösenord", Target::Password),
];

/// Header stems that, followed by a number, name one of several address columns of a
/// device-centric sheet (`Nic1` to `Nic4`, `IP 2`, `eth0`).
const NUMBERED_ADDRESS_STEMS: &[&str] = &["nic", "ip", "eth", "if", "port", "nätverkskort"];

/// The target a header suggests, if any. `custom.<key>` headers suggest the custom field.
pub fn target_for_header(header: &str) -> Option<Target> {
    let trimmed = header.trim();
    if let Some(key) = trimmed.strip_prefix(CUSTOM_PREFIX) {
        return FieldKey::new(key).ok().map(Target::Custom);
    }
    let normalized = normalize_header(trimmed);
    if normalized.is_empty() {
        return None;
    }
    if let Some((_, target)) = SYNONYMS.iter().find(|(name, _)| *name == normalized) {
        return Some(target.clone());
    }
    numbered_interface(&normalized).map(|_| Target::Address)
}

/// The interface name a numbered address header implies (`Nic1` → `nic1`, `IP 2` →
/// `ip2`), if the header is one.
pub fn numbered_interface(header: &str) -> Option<String> {
    let normalized = normalize_header(header);
    let digits = normalized
        .char_indices()
        .find(|(_, c)| c.is_ascii_digit())
        .map(|(index, _)| index)?;
    let (stem, number) = normalized.split_at(digits);
    (NUMBERED_ADDRESS_STEMS.contains(&stem) && number.chars().all(|c| c.is_ascii_digit()))
        .then_some(normalized)
}

/// The name of an interface created for the `n`-th address (1-based) of a host whose
/// source names no interface.
pub fn default_interface(n: usize) -> String {
    format!("nic{n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_round_trip_through_their_names() {
        for target in Target::FIXED {
            assert_eq!(target.name().parse::<Target>().expect("parse"), target);
        }
        let custom: Target = "custom.rack_unit".parse().expect("custom");
        assert_eq!(custom.to_string(), "custom.rack_unit");
        assert!("custom.Rack".parse::<Target>().is_err());
        assert!("nonsense".parse::<Target>().is_err());
        let json = serde_json::to_string(&Target::DnsName).expect("json");
        assert_eq!(json, "\"dns_name\"");
    }

    #[test]
    fn english_and_swedish_headers_suggest_targets() {
        let cases = [
            ("IP", Target::Address),
            ("Nic1", Target::Address),
            ("NIC 4", Target::Address),
            ("Beteckning", Target::Name),
            ("Enhet", Target::Name),
            ("Namn", Target::Name),
            ("Hostname", Target::Name),
            ("Login", Target::Login),
            ("login", Target::Login),
            ("Användare", Target::Login),
            ("User", Target::Login),
            ("Pass", Target::Password),
            ("pass", Target::Password),
            ("Lösen", Target::Password),
            ("Password", Target::Password),
            ("VLAN", Target::Vlan),
            ("MAC", Target::Mac),
            ("Beskrivning", Target::Description),
            ("Description", Target::Description),
            ("Kommentar", Target::Description),
            ("Notes", Target::Description),
            ("dns_name", Target::DnsName),
            ("alarm_warn", Target::AlarmWarn),
        ];
        for (header, target) in cases {
            assert_eq!(target_for_header(header), Some(target), "{header}");
        }
        assert_eq!(target_for_header(""), None);
        assert_eq!(target_for_header("Färg"), None);
    }

    #[test]
    fn export_headers_map_onto_themselves() {
        for target in Target::FIXED {
            if target == Target::Ignore {
                continue;
            }
            assert_eq!(
                target_for_header(&target.name()),
                Some(target.clone()),
                "{target}"
            );
        }
    }

    #[test]
    fn numbered_headers_name_interfaces() {
        assert_eq!(numbered_interface("Nic1").as_deref(), Some("nic1"));
        assert_eq!(numbered_interface("IP 2").as_deref(), Some("ip2"));
        assert_eq!(numbered_interface("eth0").as_deref(), Some("eth0"));
        assert_eq!(numbered_interface("Nic"), None);
        assert_eq!(numbered_interface("ipv4"), None);
        assert_eq!(default_interface(1), "nic1");
    }
}
