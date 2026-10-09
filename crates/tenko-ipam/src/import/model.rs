//! The import model: what a source says, after mapping and transforms, before it is
//! compared with the store.
//!
//! It is the IPAM intermediate representation of `tenko_core::ir` (MIG-01) extended with
//! what that representation does not carry yet: interfaces by name, the VRF and tenant of
//! each item, prefix roles, proposed prefixes, and credentials by reference.
//! [`ImportModel::to_ir`] gives the plain [`Ir`]. References between items are by natural
//! key (CIDR, host name, interface name), because the source has no identifiers.
//!
//! Credential values never appear here: [`ModelCredential`] says which host has which
//! credential fields and where they came from; the values travel separately in
//! [`CredentialValues`] and reach the vault only (IAM-15).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    MacAddr,
    ipam::{AllocPolicy, AssignmentMode, PrefixRole, Status},
    ir::{Ir, IrAddress, IrHost, IrNetwork, IrVlan, SourceLocation},
    net::{Duid, Fqdn, HostName},
};
use utoipa::ToSchema;
use zeroize::Zeroizing;

/// Where a prefix of the model comes from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrefixSource {
    /// A sheet named after its network.
    Sheet,
    /// A row of the `Index` sheet without a sheet of its own.
    Index,
    /// A row of a network list (a prefix column, or an address with a mask).
    Row,
    /// Proposed by the import for addresses outside every known network (rule 4 of the
    /// import specification); created only while the proposal is accepted.
    Proposal,
}

/// A prefix to import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelPrefix {
    /// The network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// VRF name; the import's target VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// Role: a supernet when the prefix contains other prefixes of the import or the store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<PrefixRole>,
    /// Status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// VLAN id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Site name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// Utilization warning threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm_warn: Option<u8>,
    /// Utilization critical threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm_crit: Option<u8>,
    /// Next-free policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alloc: Option<AllocPolicy>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Custom field values as text, by key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
    /// Where the prefix comes from.
    pub source: PrefixSource,
    /// Origin in the source.
    pub origin: SourceLocation,
}

impl ModelPrefix {
    /// A prefix with only its network, source and origin.
    pub fn new(cidr: IpNet, source: PrefixSource, origin: SourceLocation) -> Self {
        Self {
            cidr,
            vrf: None,
            role: None,
            status: None,
            vlan: None,
            site: None,
            alarm_warn: None,
            alarm_crit: None,
            alloc: None,
            description: None,
            tags: Vec::new(),
            custom: BTreeMap::new(),
            source,
            origin,
        }
    }
}

/// A VLAN to import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelVlan {
    /// VLAN id.
    pub vid: u16,
    /// Name; `VLAN <vid>` when the source gives none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Site name; global when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// Origin in the source.
    pub origin: SourceLocation,
}

/// An interface of a host to import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelInterface {
    /// Name, unique per host (`nic1`).
    pub name: String,
    /// MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// DUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duid: Option<Duid>,
    /// DHCPv4 client identifier, hexadecimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Origin in the source.
    pub origin: SourceLocation,
}

/// A host to import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelHost {
    /// Host name (the natural key).
    #[schema(value_type = String)]
    pub name: HostName,
    /// Tenant name; the import's tenant when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Assignment mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AssignmentMode>,
    /// Lock against automation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<bool>,
    /// Site name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Custom field values as text, by key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
    /// Interfaces, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<ModelInterface>,
    /// Origin in the source (the first row that names the host).
    pub origin: SourceLocation,
}

impl ModelHost {
    /// A host with only its name and origin.
    pub fn new(name: HostName, origin: SourceLocation) -> Self {
        Self {
            name,
            tenant: None,
            mode: None,
            lock: None,
            site: None,
            description: None,
            tags: Vec::new(),
            custom: BTreeMap::new(),
            interfaces: Vec::new(),
            origin,
        }
    }

    /// The interface with this name.
    pub fn interface(&self, name: &str) -> Option<&ModelInterface> {
        self.interfaces.iter().find(|i| i.name == name)
    }
}

/// An address to import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelAddress {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub ip: IpAddr,
    /// VRF name; the import's target VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// Status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Intended DNS name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub dns_name: Option<Fqdn>,
    /// The host, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub host: Option<HostName>,
    /// The interface of the host, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Custom field values as text, by key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
    /// Origin in the source.
    pub origin: SourceLocation,
}

impl ModelAddress {
    /// An address with only its value and origin.
    pub fn new(ip: IpAddr, origin: SourceLocation) -> Self {
        Self {
            ip,
            vrf: None,
            status: None,
            dns_name: None,
            host: None,
            interface: None,
            description: None,
            tags: Vec::new(),
            custom: BTreeMap::new(),
            origin,
        }
    }
}

/// A credential of a host, by reference: which fields the source holds. The values are
/// in [`CredentialValues`] and become one operator secret per host in the vault
/// (IAM-15, IAM-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModelCredential {
    /// The host the secret is attached to.
    #[schema(value_type = String)]
    pub host: HostName,
    /// Whether a login is present.
    pub login: bool,
    /// Whether a password is present.
    pub password: bool,
    /// Origin in the source.
    pub origin: SourceLocation,
}

/// The content of an import after mapping and transforms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportModel {
    /// Prefixes, ordered by family, network and length (supernets before their children).
    #[serde(default)]
    pub prefixes: Vec<ModelPrefix>,
    /// VLANs, ordered by site and id.
    #[serde(default)]
    pub vlans: Vec<ModelVlan>,
    /// Hosts, ordered by name.
    #[serde(default)]
    pub hosts: Vec<ModelHost>,
    /// Addresses, ordered by VRF and address.
    #[serde(default)]
    pub addresses: Vec<ModelAddress>,
    /// Credentials by reference, ordered by host.
    #[serde(default)]
    pub credentials: Vec<ModelCredential>,
}

impl ImportModel {
    /// Whether the model holds nothing.
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
            && self.vlans.is_empty()
            && self.hosts.is_empty()
            && self.addresses.is_empty()
            && self.credentials.is_empty()
    }

    /// The host with this name.
    pub fn host(&self, name: &HostName) -> Option<&ModelHost> {
        self.hosts.iter().find(|h| &h.name == name)
    }

    /// The plain migration IR (MIG-01). Interfaces become the MAC list of the host and
    /// the MAC of each address; VRFs, tenants, roles and credentials have no place in it.
    pub fn to_ir(&self) -> Ir {
        let networks = self
            .prefixes
            .iter()
            .map(|p| IrNetwork {
                cidr: p.cidr,
                name: None,
                vlan: p.vlan,
                site: p.site.clone(),
                status: p.status,
                description: p.description.clone(),
                tags: p.tags.clone(),
                custom: p.custom.clone(),
                origin: p.origin.clone(),
            })
            .collect();
        let vlans = self
            .vlans
            .iter()
            .map(|v| IrVlan {
                vid: v.vid,
                name: v.name.clone(),
                site: v.site.clone(),
                description: None,
                origin: v.origin.clone(),
            })
            .collect();
        let hosts = self
            .hosts
            .iter()
            .map(|h| IrHost {
                name: h.name.clone(),
                mode: h.mode,
                macs: h.interfaces.iter().filter_map(|i| i.mac).collect(),
                site: h.site.clone(),
                description: h.description.clone(),
                tags: h.tags.clone(),
                custom: h.custom.clone(),
                origin: h.origin.clone(),
            })
            .collect();
        let addresses = self
            .addresses
            .iter()
            .map(|a| {
                let mac = a
                    .host
                    .as_ref()
                    .zip(a.interface.as_ref())
                    .and_then(|(host, name)| {
                        self.host(host)
                            .and_then(|h| h.interface(name))
                            .and_then(|i| i.mac)
                    });
                IrAddress {
                    ip: a.ip,
                    dns_name: a.dns_name.clone(),
                    host: a.host.clone(),
                    mac,
                    status: a.status,
                    description: a.description.clone(),
                    tags: a.tags.clone(),
                    custom: a.custom.clone(),
                    origin: a.origin.clone(),
                }
            })
            .collect();
        Ir {
            networks,
            vlans,
            hosts,
            addresses,
        }
    }

    /// Puts every list in its canonical order.
    pub fn sort(&mut self) {
        self.prefixes.sort_by(|a, b| {
            (
                a.vrf.as_deref().unwrap_or(""),
                family(&a.cidr),
                a.cidr.network(),
                a.cidr.prefix_len(),
            )
                .cmp(&(
                    b.vrf.as_deref().unwrap_or(""),
                    family(&b.cidr),
                    b.cidr.network(),
                    b.cidr.prefix_len(),
                ))
        });
        self.vlans
            .sort_by(|a, b| (a.site.as_deref(), a.vid).cmp(&(b.site.as_deref(), b.vid)));
        self.hosts.sort_by(|a, b| a.name.cmp(&b.name));
        for host in &mut self.hosts {
            host.interfaces
                .sort_by(|a, b| natural_cmp(&a.name, &b.name));
        }
        self.addresses.sort_by(|a, b| {
            (a.vrf.as_deref().unwrap_or(""), a.ip).cmp(&(b.vrf.as_deref().unwrap_or(""), b.ip))
        });
        self.credentials.sort_by(|a, b| a.host.cmp(&b.host));
    }
}

fn family(net: &IpNet) -> u8 {
    match net {
        IpNet::V4(_) => 4,
        IpNet::V6(_) => 6,
    }
}

/// Compares names so that `nic2` sorts before `nic10`.
pub fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(s: &str) -> (&str, Option<u64>) {
        let digits = s.len() - s.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        let (stem, number) = s.split_at(s.len() - digits);
        (stem, number.parse().ok())
    }
    let (sa, na) = split(a);
    let (sb, nb) = split(b);
    sa.cmp(sb).then(na.cmp(&nb)).then(a.cmp(b))
}

/// One credential's values. Zeroized on drop; `Debug` never prints them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CredentialValue {
    /// The login.
    pub login: Option<Zeroizing<String>>,
    /// The password.
    pub password: Option<Zeroizing<String>>,
}

impl fmt::Debug for CredentialValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialValue")
            .field("login", &self.login.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CredentialValue {
    /// The secret value stored in the vault: a JSON object with the fields present, keys
    /// in a fixed order, so equal credentials give equal bytes.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut map = serde_json::Map::new();
        if let Some(login) = &self.login {
            map.insert(
                "login".to_owned(),
                serde_json::Value::String(login.to_string()),
            );
        }
        if let Some(password) = &self.password {
            map.insert(
                "password".to_owned(),
                serde_json::Value::String(password.to_string()),
            );
        }
        Zeroizing::new(serde_json::to_vec(&map).unwrap_or_default())
    }
}

/// The credential values of an import, by host. Never serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialValues(pub BTreeMap<HostName, CredentialValue>);

/// Names of hosts, used to collect the hosts a chunk touches.
pub type HostNames = BTreeSet<HostName>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_order_of_interface_names() {
        let mut names = vec!["nic10", "nic2", "eth0", "nic1"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, ["eth0", "nic1", "nic2", "nic10"]);
    }

    #[test]
    fn credential_values_never_print() {
        let value = CredentialValue {
            login: Some(Zeroizing::new("admin".to_owned())),
            password: Some(Zeroizing::new("example-only".to_owned())),
        };
        let printed = format!("{value:?}");
        assert!(!printed.contains("admin"));
        assert!(!printed.contains("example-only"));
        let bytes = value.to_secret_bytes();
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf8"),
            r#"{"login":"admin","password":"example-only"}"#
        );
    }

    #[test]
    fn the_plain_ir_carries_macs_through_interfaces() {
        let origin = SourceLocation::default();
        let name = HostName::new("nas01").expect("name");
        let mut host = ModelHost::new(name.clone(), origin.clone());
        host.interfaces.push(ModelInterface {
            name: "nic1".to_owned(),
            mac: Some("00:00:5e:00:53:01".parse().expect("mac")),
            duid: None,
            client_id: None,
            origin: origin.clone(),
        });
        let mut address = ModelAddress::new("192.0.2.10".parse().expect("ip"), origin);
        address.host = Some(name);
        address.interface = Some("nic1".to_owned());
        let model = ImportModel {
            hosts: vec![host],
            addresses: vec![address],
            ..ImportModel::default()
        };
        let ir = model.to_ir();
        assert_eq!(ir.hosts[0].macs.len(), 1);
        assert_eq!(ir.addresses[0].mac, ir.hosts[0].macs.first().copied());
    }
}
