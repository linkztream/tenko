//! The Integration API of the Network application with a local API key (`X-API-Key`): the
//! reduced, read-only topology for instances without a local account.
//!
//! The Integration API of the 9.x releases reports sites, devices with their upstream
//! device, and clients with the device they hang on; it reports no port profiles, no
//! port of a wired client, no SSID or VLAN of a client and no LLDP. The releases from
//! 10.0 on also report the networks with their VLAN ids (`/sites/{id}/networks`, the
//! subnet and the DHCP mode in the detail of each network); on a release without them the
//! list answers 404 and the topology has no networks. The topology it yields therefore has
//! devices without port tables (an uplink the plugin cannot mark must not appear as an
//! ordinary port), uplink links without ports, clients attached to a device without a port
//! or an SSID, in the network whose subnet holds their address, and the networks. Writes
//! need the classic API.

use std::collections::HashMap;

use ipnet::IpNet;
use serde_json::Value;
use tenko_connect::sdk::http::reqwest::{Method, StatusCode};
use tenko_connect::{
    ClientAttachment, ControllerDhcp, ControllerNetwork, DeviceKind, DeviceRef, NetworkDevice,
    NetworkRef, TopologyLink, TopologySnapshot,
};
use tenko_core::{
    MacAddr, Timestamp,
    observe::{Endpoint, LinkKind, ObservedHost},
};

use crate::{
    detect::Paths,
    http::{Effect, Http},
    json,
    model::Local,
};

/// The most pages one list reads.
const MAX_PAGES: usize = 50;

/// The page size of list reads.
const PAGE: usize = 200;

/// A device as the Integration API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The API's id.
    pub id: String,
    /// The MAC address.
    pub mac: MacAddr,
    /// The name.
    pub name: Option<String>,
    /// The model.
    pub model: Option<String>,
    /// The management address.
    pub ip: Option<std::net::IpAddr>,
    /// What it is.
    pub kind: DeviceKind,
    /// The upstream device's API id.
    pub uplink: Option<String>,
}

/// A client as the Integration API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The MAC address.
    pub mac: MacAddr,
    /// The address.
    pub ip: Option<std::net::IpAddr>,
    /// The name.
    pub name: Option<String>,
    /// Wired or wireless.
    pub wired: bool,
    /// The API id of the device it hangs on.
    pub device: Option<String>,
}

/// A network as the Integration API reports it (Network 10.0 and later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    /// The API's id.
    pub id: String,
    /// The name.
    pub name: String,
    /// The VLAN id; `None` for the default network, which the API reports as VLAN 1 and
    /// which is untagged.
    pub vlan: Option<u16>,
    /// Whether it is the default network.
    pub default: bool,
    /// The subnet, without host bits (`hostIpAddress` and `prefixLength` of the detail).
    pub subnet: Option<IpNet>,
    /// The DHCP mode of the detail.
    pub dhcp: ControllerDhcp,
}

/// Everything one Integration API read returned.
#[derive(Debug, Clone, Default)]
pub struct Read {
    /// Devices.
    pub devices: Vec<Device>,
    /// Clients.
    pub clients: Vec<Client>,
    /// Networks; empty on releases before 10.0.
    pub networks: Vec<Network>,
}

/// A client of the Integration API.
pub struct Api<'a> {
    http: &'a Http,
    base: &'static str,
    key: &'a str,
}

impl std::fmt::Debug for Api<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl<'a> Api<'a> {
    /// The Integration API of a deployment.
    pub fn new(http: &'a Http, paths: Paths, key: &'a str) -> Self {
        Self {
            http,
            base: paths.integration,
            key,
        }
    }

    async fn get(&self, path: &str) -> Result<Value, tenko_connect::ConnectorError> {
        use tenko_connect::ConnectorError;
        let response = self
            .http
            .send(
                Method::GET,
                &format!("{}{path}", self.base),
                &[("X-API-Key", self.key)],
                None,
                Effect::Read,
            )
            .await?;
        match response.status {
            status if status.is_success() => response
                .json()
                .ok_or_else(|| ConnectorError::protocol("the Integration API answer is not JSON")),
            // The Integration API answers 403 for a key it does not know.
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ConnectorError::Unauthorized),
            StatusCode::NOT_FOUND => Err(ConnectorError::Unsupported),
            status if status.is_server_error() => Err(ConnectorError::Unreachable),
            status => Err(ConnectorError::protocol(format!(
                "the Integration API answered HTTP {}",
                status.as_u16()
            ))),
        }
    }

    async fn list(&self, path: &str) -> Result<Vec<Value>, tenko_connect::ConnectorError> {
        let mut items = Vec::new();
        for page in 0..MAX_PAGES {
            let separator = if path.contains('?') { '&' } else { '?' };
            let answer = self
                .get(&format!(
                    "{path}{separator}offset={}&limit={PAGE}",
                    page * PAGE
                ))
                .await?;
            let data = json::array(&answer, "data");
            items.extend(data.iter().cloned());
            let total = json::uint(&answer, "totalCount")
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(items.len());
            if data.len() < PAGE || items.len() >= total {
                break;
            }
        }
        Ok(items)
    }

    /// The version of the application.
    ///
    /// # Errors
    ///
    /// The API's error.
    pub async fn version(&self) -> Result<Option<String>, tenko_connect::ConnectorError> {
        let info = self.get("/info").await?;
        Ok(json::text(&info, "applicationVersion"))
    }

    /// The API id of the site with the short name `site`.
    ///
    /// # Errors
    ///
    /// [`tenko_connect::ConnectorError::InvalidSettings`] when there is no such site.
    pub async fn site(&self, site: &str) -> Result<String, tenko_connect::ConnectorError> {
        self.list("/sites")
            .await?
            .iter()
            .find(|entry| {
                json::text(entry, "internalReference").as_deref() == Some(site)
                    || json::text(entry, "name").as_deref() == Some(site)
            })
            .and_then(|entry| json::id(entry, "id"))
            .ok_or_else(|| {
                tenko_connect::ConnectorError::invalid_settings(format!(
                    "the controller has no site `{site}`"
                ))
            })
    }

    /// The networks of a site, each with the detail that carries its subnet and DHCP mode;
    /// none on a release whose API has no networks (the list answers 404).
    ///
    /// # Errors
    ///
    /// The API's error.
    pub async fn networks(
        &self,
        site_id: &str,
    ) -> Result<Vec<Network>, tenko_connect::ConnectorError> {
        let entries = match self.list(&format!("/sites/{site_id}/networks")).await {
            Ok(entries) => entries,
            Err(tenko_connect::ConnectorError::Unsupported) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut networks = Vec::new();
        for entry in entries {
            if json::flag(&entry, "enabled") == Some(false) {
                continue;
            }
            let Some(id) = json::id(&entry, "id") else {
                continue;
            };
            // The list leaves out the IPv4 configuration; a network the gateway or a switch
            // manages has it in its detail.
            let unmanaged = json::text(&entry, "management")
                .is_some_and(|management| management.eq_ignore_ascii_case("unmanaged"));
            let detail = if unmanaged || entry.get("ipv4Configuration").is_some() {
                entry
            } else {
                match self.get(&format!("/sites/{site_id}/networks/{id}")).await {
                    Ok(detail) => detail,
                    Err(tenko_connect::ConnectorError::Unsupported) => entry,
                    Err(error) => return Err(error),
                }
            };
            if let Some(network) = network_of(&detail) {
                networks.push(network);
            }
        }
        Ok(networks)
    }

    /// Devices, clients and networks of a site.
    ///
    /// # Errors
    ///
    /// The API's error.
    pub async fn read(&self, site_id: &str) -> Result<Read, tenko_connect::ConnectorError> {
        let mut devices = Vec::new();
        for entry in self.list(&format!("/sites/{site_id}/devices")).await? {
            let Some(id) = json::id(&entry, "id") else {
                continue;
            };
            // The list may leave out the upstream device; the detail carries it.
            let detail = if entry.get("uplink").is_some() {
                entry
            } else {
                self.get(&format!("/sites/{site_id}/devices/{id}")).await?
            };
            if let Some(device) = device_of(&id, &detail) {
                devices.push(device);
            }
        }
        let clients = self
            .list(&format!("/sites/{site_id}/clients"))
            .await?
            .iter()
            .filter_map(client_of)
            .collect();
        let networks = self.networks(site_id).await?;
        Ok(Read {
            devices,
            clients,
            networks,
        })
    }
}

fn has_feature(value: &Value, feature: &str) -> bool {
    match value.get("features") {
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(feature)),
        Some(Value::Object(map)) => map.contains_key(feature),
        _ => false,
    }
}

pub(crate) fn device_of(id: &str, value: &Value) -> Option<Device> {
    let mac = json::mac(value, "macAddress")?;
    let kind = if has_feature(value, "accessPoint") {
        DeviceKind::AccessPoint
    } else if has_feature(value, "gateway") {
        DeviceKind::Gateway
    } else if has_feature(value, "switching") {
        DeviceKind::Switch
    } else {
        DeviceKind::Other
    };
    Some(Device {
        id: id.to_owned(),
        mac,
        name: json::text(value, "name"),
        model: json::text(value, "model"),
        ip: json::ip(value, "ipAddress"),
        kind,
        uplink: value
            .get("uplink")
            .and_then(|uplink| json::id(uplink, "deviceId")),
    })
}

pub(crate) fn client_of(value: &Value) -> Option<Client> {
    Some(Client {
        mac: json::mac(value, "macAddress")?,
        ip: json::ip(value, "ipAddress"),
        name: json::text(value, "name"),
        wired: json::text(value, "type").is_some_and(|kind| kind.eq_ignore_ascii_case("wired")),
        device: json::id(value, "uplinkDeviceId"),
    })
}

pub(crate) fn network_of(value: &Value) -> Option<Network> {
    let id = json::id(value, "id")?;
    let default = json::flag(value, "default").unwrap_or(false);
    let ipv4 = value.get("ipv4Configuration");
    let subnet = ipv4.and_then(|ipv4| {
        let host = json::ip(ipv4, "hostIpAddress")?;
        let length = u8::try_from(json::uint(ipv4, "prefixLength")?).ok()?;
        IpNet::new(host, length).ok().map(|net| net.trunc())
    });
    let dhcp = ipv4
        .and_then(|ipv4| ipv4.get("dhcpConfiguration"))
        .filter(|dhcp| !dhcp.is_null())
        .map_or(ControllerDhcp::Disabled, |dhcp| {
            match json::text(dhcp, "mode").as_deref() {
                Some(mode) if mode.eq_ignore_ascii_case("server") => ControllerDhcp::Server,
                Some(mode) if mode.eq_ignore_ascii_case("relay") => ControllerDhcp::RelayTo(
                    json::array(dhcp, "dhcpServerIpAddresses")
                        .iter()
                        .filter_map(|ip| ip.as_str()?.trim().parse().ok())
                        .collect(),
                ),
                _ => ControllerDhcp::Disabled,
            }
        });
    Some(Network {
        name: json::text(value, "name").unwrap_or_else(|| id.clone()),
        id,
        // VLAN 1 is the untagged default network; additional networks have 2 and up.
        vlan: json::vlan(value, "vlanId").filter(|vid| *vid >= 2 && !default),
        default,
        subnet,
        dhcp,
    })
}

/// The topology of an Integration API read. `local` holds the addresses of the controller
/// and of Tenko: a network that holds one of them, or the address of a device, is a
/// management network, like the default network (see [`crate::model`]).
pub fn topology(read: &Read, local: &Local, observed_at: Timestamp) -> TopologySnapshot {
    let networks: Vec<ControllerNetwork> = read
        .networks
        .iter()
        .map(|network| {
            let holds = |ip: &std::net::IpAddr| network.subnet.is_some_and(|net| net.contains(ip));
            ControllerNetwork {
                id: NetworkRef(network.id.clone()),
                name: network.name.clone(),
                vlan: network.vlan,
                subnet: network.subnet,
                dhcp: network.dhcp.clone(),
                management: network.default
                    || local.controller.iter().chain(&local.tenko).any(holds)
                    || read.devices.iter().filter_map(|d| d.ip.as_ref()).any(holds),
            }
        })
        .collect();
    // The API names no network of a client: the most specific subnet that holds its address.
    let network_of_ip = |ip: std::net::IpAddr| {
        networks
            .iter()
            .filter(|network| network.subnet.is_some_and(|net| net.contains(&ip)))
            .max_by_key(|network| network.subnet.map(|net| net.prefix_len()))
    };
    let macs: HashMap<&str, MacAddr> = read
        .devices
        .iter()
        .map(|device| (device.id.as_str(), device.mac))
        .collect();
    TopologySnapshot {
        observed_at,
        devices: read
            .devices
            .iter()
            .map(|device| NetworkDevice {
                id: DeviceRef(device.mac.to_string()),
                name: device
                    .name
                    .clone()
                    .unwrap_or_else(|| device.mac.to_string()),
                model: device.model.clone(),
                mac: Some(device.mac),
                ip: device.ip,
                kind: device.kind,
                ports: Vec::new(),
            })
            .collect(),
        links: read
            .devices
            .iter()
            .filter_map(|device| {
                let parent = macs.get(device.uplink.as_deref()?)?;
                Some(TopologyLink {
                    a: Endpoint {
                        device: device.mac.to_string(),
                        port: None,
                    },
                    b: Endpoint {
                        device: parent.to_string(),
                        port: None,
                    },
                    kind: LinkKind::Uplink,
                })
            })
            .collect(),
        clients: read
            .clients
            .iter()
            .filter_map(|client| {
                let device = macs.get(client.device.as_deref()?)?;
                let network = client.ip.and_then(network_of_ip);
                Some(ClientAttachment {
                    mac: client.mac,
                    ip: client.ip,
                    device: DeviceRef(device.to_string()),
                    port: None,
                    ssid: None,
                    network: network.map(|network| network.id.clone()),
                    vlan: network.and_then(|network| network.vlan),
                    name: client.name.clone(),
                    name_placeholder: client_placeholder(client),
                    vendor: None,
                    management: false,
                    // The integration API reports no radio.
                    band: None,
                })
            })
            .collect(),
        networks,
        profiles: Vec::new(),
        wlans: Vec::new(),
    }
}

/// Whether the name of an Integration API client is a placeholder
/// ([`crate::model::placeholder_name`]).
fn client_placeholder(client: &Client) -> bool {
    let ips: Vec<std::net::IpAddr> = client.ip.into_iter().collect();
    client
        .name
        .as_deref()
        .is_some_and(|name| crate::model::placeholder_name(name, client.mac, &ips))
}

/// The inventory of an Integration API read.
pub fn inventory(read: &Read) -> Vec<ObservedHost> {
    let device_macs: std::collections::HashSet<MacAddr> =
        read.devices.iter().map(|d| d.mac).collect();
    let devices = read.devices.iter().map(|device| ObservedHost {
        external_id: format!("device:{}", device.mac),
        name: device.name.clone(),
        macs: vec![device.mac],
        ips: device.ip.into_iter().collect(),
        tags: vec!["unifi:device".to_owned()],
        ..ObservedHost::default()
    });
    let clients = read
        .clients
        .iter()
        .filter(|client| !device_macs.contains(&client.mac))
        .map(|client| ObservedHost {
            external_id: format!("client:{}", client.mac),
            name: client.name.clone(),
            name_placeholder: client_placeholder(client),
            macs: vec![client.mac],
            ips: client.ip.into_iter().collect(),
            tags: vec![if client.wired {
                "unifi:wired".to_owned()
            } else {
                "unifi:wireless".to_owned()
            }],
            ..ObservedHost::default()
        });
    let mut hosts: Vec<ObservedHost> = devices.chain(clients).collect();
    hosts.sort_by(|a, b| a.external_id.cmp(&b.external_id));
    hosts.dedup_by(|a, b| a.external_id == b.external_id);
    hosts
}
