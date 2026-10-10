//! The Integration API of the Network application with a local API key (`X-API-Key`): the
//! reduced, read-only topology for instances without a local account.
//!
//! The Integration API of the 9.x releases reports sites, devices with their upstream
//! device, and clients with the device they hang on; it reports no port profiles, no
//! port of a wired client, no SSID or VLAN of a client, no LLDP and no networks. The
//! topology it yields therefore has devices without port tables (an uplink the plugin
//! cannot mark must not appear as an ordinary port), uplink links without ports, and
//! clients attached to a device without a port. Writes need the classic API.

use std::collections::HashMap;

use serde_json::Value;
use tenko_connect::sdk::http::reqwest::{Method, StatusCode};
use tenko_connect::{
    ClientAttachment, DeviceKind, DeviceRef, NetworkDevice, TopologyLink, TopologySnapshot,
};
use tenko_core::{
    MacAddr, Timestamp,
    observe::{Endpoint, LinkKind, ObservedHost},
};

use crate::{
    detect::Paths,
    http::{Effect, Http},
    json,
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

/// Everything one Integration API read returned.
#[derive(Debug, Clone, Default)]
pub struct Read {
    /// Devices.
    pub devices: Vec<Device>,
    /// Clients.
    pub clients: Vec<Client>,
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

    /// Devices and clients of a site.
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
        Ok(Read { devices, clients })
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

/// The topology of an Integration API read.
pub fn topology(read: &Read, observed_at: Timestamp) -> TopologySnapshot {
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
                Some(ClientAttachment {
                    mac: client.mac,
                    ip: client.ip,
                    device: DeviceRef(device.to_string()),
                    port: None,
                    ssid: None,
                    network: None,
                    vlan: None,
                    name: client.name.clone(),
                    vendor: None,
                    management: false,
                })
            })
            .collect(),
        networks: Vec::new(),
        profiles: Vec::new(),
        wlans: Vec::new(),
    }
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
