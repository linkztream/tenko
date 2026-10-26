//! The classic API of the Network application: a session of a local account (cookie and
//! CSRF token), the records the plugin reads, and the writes it performs.
//!
//! Every answer has the envelope `{"meta": {"rc": "ok" | "error", "msg": ...}, "data": [...]}`.
//! The session logs in once per call and logs out at its end; it keeps nothing between
//! calls. The password travels only in the login body and is never logged.

use std::net::IpAddr;

use serde_json::Value;
use tenko_connect::ConnectorError;
use tenko_connect::sdk::http::reqwest::{Method, StatusCode};
use tenko_core::MacAddr;
use zeroize::Zeroizing;

use crate::{
    detect::Paths,
    http::{Effect, Http, Response},
    json,
};

/// A logged-in session of a local account.
pub struct Session {
    http: Http,
    paths: Paths,
    site: String,
    cookie: Zeroizing<String>,
    csrf: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("deployment", &self.paths.deployment)
            .field("site", &self.site)
            .finish_non_exhaustive()
    }
}

/// The cookie names a login sets that later requests carry.
const SESSION_COOKIES: [&str; 3] = ["unifises", "csrf_token", "TOKEN"];

impl Session {
    /// Logs in with a local account.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Unauthorized`] for rejected credentials,
    /// [`ConnectorError::RateLimited`] when the controller limits logins, or the errors of
    /// [`Http::send`].
    pub async fn login(
        http: &Http,
        paths: Paths,
        site: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, ConnectorError> {
        let body = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({
                "username": username,
                "password": password,
                "remember": false,
                "rememberMe": false,
            }))
            .map_err(|error| ConnectorError::PluginFailed(format!("login body: {error}")))?,
        );
        let response = http
            .send(Method::POST, paths.login, &[], Some(&body), Effect::Write)
            .await?;
        drop(body);
        if !response.status.is_success() {
            return Err(match response.status {
                StatusCode::FORBIDDEN => ConnectorError::Forbidden,
                StatusCode::NOT_FOUND => ConnectorError::invalid_settings(format!(
                    "the controller has no login at `{}`; check `url` and `deployment`",
                    paths.login
                )),
                status if status.is_server_error() => ConnectorError::Unreachable,
                _ => match message(&response).as_deref() {
                    Some(msg) if msg.contains("RateLimit") || msg.contains("TooMany") => {
                        ConnectorError::RateLimited {
                            retry_after: std::time::Duration::from_secs(60),
                        }
                    }
                    _ => ConnectorError::Unauthorized,
                },
            });
        }
        let mut cookie = String::new();
        let mut csrf = response
            .header("x-csrf-token")
            .filter(|token| !token.is_empty());
        for set in response.header_values("set-cookie") {
            let Some(pair) = set.split(';').next() else {
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            if !SESSION_COOKIES.contains(&name) || value.is_empty() {
                continue;
            }
            if name == "csrf_token" && csrf.is_none() {
                csrf = Some(value.to_owned());
            }
            if !cookie.is_empty() {
                cookie.push_str("; ");
            }
            cookie.push_str(name);
            cookie.push('=');
            cookie.push_str(value);
        }
        if cookie.is_empty() {
            return Err(ConnectorError::protocol(
                "the controller accepted the login but set no session cookie",
            ));
        }
        Ok(Self {
            http: http.clone(),
            paths,
            site: site.to_owned(),
            cookie: Zeroizing::new(cookie),
            csrf: csrf.map(Zeroizing::new),
        })
    }

    /// Ends the session (best effort; a failure is ignored).
    pub async fn logout(self) {
        let headers = self.headers();
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let _ = self
            .http
            .send(
                Method::POST,
                self.paths.logout,
                &pairs,
                Some(b"{}"),
                Effect::Write,
            )
            .await;
    }

    /// The paths of the deployment.
    pub fn paths(&self) -> Paths {
        self.paths
    }

    fn headers(&self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut headers = vec![("Cookie", self.cookie.clone())];
        if let Some(token) = &self.csrf {
            headers.push(("X-Csrf-Token", token.clone()));
        }
        headers
    }

    /// Sends a request to a path of the site (`stat/device`, `rest/networkconf/<id>`) and
    /// returns the `data` of the envelope.
    async fn site_call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Vec<Value>, ConnectorError> {
        let full = format!("{}/api/s/{}/{path}", self.paths.network, self.site);
        self.call(method, &full, body).await
    }

    async fn call(
        &mut self,
        method: Method,
        full: &str,
        body: Option<&Value>,
    ) -> Result<Vec<Value>, ConnectorError> {
        let effect = if method == Method::GET {
            Effect::Read
        } else {
            Effect::Write
        };
        let encoded = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| ConnectorError::PluginFailed(format!("request body: {error}")))?;
        let headers = self.headers();
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let response = self
            .http
            .send(method, full, &pairs, encoded.as_deref(), effect)
            .await?;
        if let Some(token) = response
            .header("x-updated-csrf-token")
            .filter(|token| !token.is_empty())
        {
            self.csrf = Some(Zeroizing::new(token));
        }
        envelope(&response, &self.site)
    }

    /// The sites the account may see (short names).
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn sites(&mut self) -> Result<Vec<String>, ConnectorError> {
        let full = format!("{}/api/self/sites", self.paths.network);
        let data = self.call(Method::GET, &full, None).await?;
        Ok(data
            .iter()
            .filter_map(|site| json::id(site, "name"))
            .collect())
    }

    /// The version of the Network application.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn version(&mut self) -> Result<Option<String>, ConnectorError> {
        let data = self.site_call(Method::GET, "stat/sysinfo", None).await?;
        Ok(data.first().and_then(|info| json::text(info, "version")))
    }

    /// The records a read endpoint of the site answers (`stat/device`, `rest/networkconf`),
    /// as the controller sent them. The recorder of the crate's fixtures uses it; the plugin's
    /// own reads go through the typed methods below.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn records(&mut self, path: &str) -> Result<Vec<Value>, ConnectorError> {
        self.site_call(Method::GET, path, None).await
    }

    /// The managed devices.
    ///
    /// # Errors
    ///
    /// The controller's error, or [`ConnectorError::Protocol`] for a device without a MAC
    /// address (a device the plugin cannot name could hide an uplink).
    pub async fn devices(&mut self) -> Result<Vec<Device>, ConnectorError> {
        let data = self.site_call(Method::GET, "stat/device", None).await?;
        // A device the controller does not manage yet may lack members; a managed one that
        // cannot be read fails the read, because it could hide an uplink.
        data.iter()
            .filter_map(|value| match Device::from_value(value) {
                Ok(device) => Some(Ok(device)),
                Err(_) if json::flag(value, "adopted") == Some(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    /// The connected clients.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn clients(&mut self) -> Result<Vec<Client>, ConnectorError> {
        let data = self.site_call(Method::GET, "stat/sta", None).await?;
        Ok(data.iter().filter_map(Client::from_value).collect())
    }

    /// The networks.
    ///
    /// # Errors
    ///
    /// The controller's error, or [`ConnectorError::Protocol`] for a network without an id.
    pub async fn networks(&mut self) -> Result<Vec<Network>, ConnectorError> {
        let data = self
            .site_call(Method::GET, "rest/networkconf", None)
            .await?;
        data.iter().map(Network::from_value).collect()
    }

    /// The wireless networks.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn wlans(&mut self) -> Result<Vec<Wlan>, ConnectorError> {
        let data = self.site_call(Method::GET, "rest/wlanconf", None).await?;
        Ok(data.iter().filter_map(Wlan::from_value).collect())
    }

    /// The port profiles.
    ///
    /// # Errors
    ///
    /// The controller's error, or [`ConnectorError::Protocol`] for a profile without an id.
    pub async fn profiles(&mut self) -> Result<Vec<Profile>, ConnectorError> {
        let data = self.site_call(Method::GET, "rest/portconf", None).await?;
        data.iter().map(Profile::from_value).collect()
    }

    /// The client record (`user`) of a MAC address, with its per-client VLAN override.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::NotFound`] when the controller has no record of the client.
    pub async fn user(&mut self, mac: MacAddr) -> Result<User, ConnectorError> {
        let data = self
            .site_call(Method::GET, &format!("stat/user/{mac}"), None)
            .await?;
        data.iter()
            .find_map(User::from_value)
            .filter(|user| user.mac == mac)
            .ok_or(ConnectorError::NotFound)
    }

    /// Creates a network; returns its id.
    ///
    /// # Errors
    ///
    /// The controller's error, or [`ConnectorError::Protocol`] when the answer names no id.
    pub async fn create_network(&mut self, body: &Value) -> Result<String, ConnectorError> {
        let data = self
            .site_call(Method::POST, "rest/networkconf", Some(body))
            .await?;
        data.first()
            .and_then(|network| json::id(network, "_id"))
            .ok_or_else(|| ConnectorError::protocol("the created network has no `_id`"))
    }

    /// Changes members of a network.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn update_network(&mut self, id: &str, body: &Value) -> Result<(), ConnectorError> {
        self.site_call(Method::PUT, &format!("rest/networkconf/{id}"), Some(body))
            .await
            .map(drop)
    }

    /// Deletes a network.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn delete_network(&mut self, id: &str) -> Result<(), ConnectorError> {
        self.site_call(Method::DELETE, &format!("rest/networkconf/{id}"), None)
            .await
            .map(drop)
    }

    /// Replaces the port overrides of a device.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn set_port_overrides(
        &mut self,
        device_id: &str,
        overrides: &[Value],
    ) -> Result<(), ConnectorError> {
        let body = serde_json::json!({ "port_overrides": overrides });
        self.site_call(
            Method::PUT,
            &format!("rest/device/{device_id}"),
            Some(&body),
        )
        .await
        .map(drop)
    }

    /// Changes members of a client record.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn update_user(&mut self, id: &str, body: &Value) -> Result<(), ConnectorError> {
        self.site_call(Method::PUT, &format!("rest/user/{id}"), Some(body))
            .await
            .map(drop)
    }

    /// Disconnects a wireless client through the station manager (`cmd/stamgr`,
    /// `kick-sta`): it associates again by itself. Never `block-sta`.
    ///
    /// # Errors
    ///
    /// The controller's error.
    pub async fn kick(&mut self, mac: MacAddr) -> Result<(), ConnectorError> {
        let body = serde_json::json!({ "cmd": "kick-sta", "mac": mac.to_string() });
        self.site_call(Method::POST, "cmd/stamgr", Some(&body))
            .await
            .map(drop)
    }
}

/// The `msg` of a classic error answer, restricted to the characters of an error code.
fn message(response: &Response) -> Option<String> {
    let json = response.json()?;
    let msg = json.pointer("/meta/msg")?.as_str()?;
    let code: String = msg
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(100)
        .collect();
    (!code.is_empty()).then_some(code)
}

/// The `data` of a classic answer, or the error it reports.
fn envelope(response: &Response, site: &str) -> Result<Vec<Value>, ConnectorError> {
    let status = response.status;
    let msg = message(response);
    let ok = response.json().and_then(|json| {
        json.pointer("/meta/rc")
            .and_then(Value::as_str)
            .map(|rc| rc == "ok")
    });
    if status.is_success() && ok != Some(false) {
        let json = response
            .json()
            .ok_or_else(|| ConnectorError::protocol("the controller's answer is not JSON"))?;
        return match json.get("data") {
            Some(Value::Array(items)) => Ok(items.clone()),
            Some(Value::Null) | None => Ok(Vec::new()),
            Some(other) => Ok(vec![other.clone()]),
        };
    }
    if status.is_server_error() {
        return Err(ConnectorError::Unreachable);
    }
    Err(match (status, msg.as_deref()) {
        (_, Some("api.err.LoginRequired" | "api.err.Invalid")) | (StatusCode::UNAUTHORIZED, _) => {
            ConnectorError::Unauthorized
        }
        (_, Some("api.err.NoPermission")) | (StatusCode::FORBIDDEN, _) => ConnectorError::Forbidden,
        (_, Some("api.err.NoSiteContext" | "api.err.UnknownSite")) => {
            ConnectorError::invalid_settings(format!("the controller has no site `{site}`"))
        }
        (_, Some(msg))
            if msg.contains("NotFound")
                || msg.contains("IdInvalid")
                || msg.contains("UnknownUser") =>
        {
            ConnectorError::NotFound
        }
        (StatusCode::NOT_FOUND, _) => ConnectorError::NotFound,
        (_, Some(msg)) => {
            ConnectorError::invalid_settings(format!("the controller refused the request: {msg}"))
        }
        (status, None) => ConnectorError::protocol(format!(
            "the controller answered HTTP {} without an error code",
            status.as_u16()
        )),
    })
}

/// A managed device (`stat/device`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The record id (`_id`), used for writes.
    pub id: String,
    /// The MAC address: the device's reference in topologies.
    pub mac: MacAddr,
    /// The management address.
    pub ip: Option<IpAddr>,
    /// The name an operator gave it.
    pub name: Option<String>,
    /// The model code.
    pub model: Option<String>,
    /// The device type code (`usw`, `uap`, `ugw`, `udm`, `uxg`, ...).
    pub kind: String,
    /// Whether the controller manages it.
    pub adopted: bool,
    /// The firmware version.
    pub version: Option<String>,
    /// The switch ports.
    pub ports: Vec<Port>,
    /// The configured port overrides, as the controller keeps them (written back whole).
    pub overrides: Vec<Value>,
    /// The upstream connection.
    pub uplink: Option<Uplink>,
    /// LLDP neighbours.
    pub lldp: Vec<Lldp>,
    /// The wireless networks it broadcasts (access points).
    pub vaps: Vec<Vap>,
}

/// A switch port of a device (`port_table`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// The port index.
    pub idx: u16,
    /// The port name.
    pub name: Option<String>,
    /// Link state.
    pub up: bool,
    /// Whether the controller marks it as the device's uplink.
    pub is_uplink: bool,
    /// The effective port profile.
    pub portconf_id: Option<String>,
    /// The untagged network, when the controller reports it per port.
    pub native_networkconf_id: Option<String>,
    /// The aggregate (LAG) this port belongs to, by the index of its first port.
    pub aggregated_by: Option<u16>,
    /// The administrative state (`enable`), when the controller reports it.
    pub enable: Option<bool>,
    /// What the port forwards (`all`, `native`, `customize` or `disabled`), when reported.
    pub forward: Option<String>,
    /// How many MAC addresses the switch learned on the port (`mac_table_count`, else the
    /// length of `mac_table`), when reported.
    pub learned_macs: Option<u32>,
}

impl Port {
    /// Whether the port table shows the port switched off.
    pub fn switched_off(&self) -> bool {
        self.enable == Some(false) || self.forward.as_deref() == Some("disabled")
    }
}

/// The upstream connection of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    /// Whether it is wireless (a mesh access point).
    pub wireless: bool,
    /// The upstream device.
    pub mac: Option<MacAddr>,
    /// The port on the upstream device.
    pub remote_port: Option<u16>,
    /// The local port.
    pub local_port: Option<u16>,
}

/// One LLDP neighbour of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldp {
    /// The neighbour's chassis id (usually a MAC address).
    pub chassis: String,
    /// The neighbour's port id.
    pub port: Option<String>,
    /// The local port.
    pub local_port: Option<u16>,
}

/// One wireless network an access point broadcasts (`vap_table`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vap {
    /// The SSID.
    pub essid: Option<String>,
    /// The wireless network's record id.
    pub wlan: Option<String>,
}

impl Device {
    pub(crate) fn from_value(value: &Value) -> Result<Self, ConnectorError> {
        let mac = json::mac(value, "mac")
            .ok_or_else(|| ConnectorError::protocol("a device has no valid `mac`"))?;
        let id = json::id(value, "_id")
            .ok_or_else(|| ConnectorError::protocol("a device has no `_id`"))?;
        let ports = json::array(value, "port_table")
            .iter()
            .filter_map(|port| {
                Some(Port {
                    idx: json::u16(port, "port_idx").filter(|idx| *idx > 0)?,
                    name: json::text(port, "name"),
                    up: json::flag(port, "up").unwrap_or(false),
                    is_uplink: json::flag(port, "is_uplink").unwrap_or(false),
                    portconf_id: json::id(port, "portconf_id"),
                    native_networkconf_id: json::id(port, "native_networkconf_id"),
                    aggregated_by: json::u16(port, "aggregated_by").filter(|idx| *idx > 0),
                    enable: json::flag(port, "enable"),
                    forward: json::text(port, "forward"),
                    learned_macs: port
                        .get("mac_table_count")
                        .and_then(Value::as_u64)
                        .or_else(|| {
                            port.get("mac_table")
                                .and_then(Value::as_array)
                                .map(|table| table.len() as u64)
                        })
                        .map(|count| u32::try_from(count).unwrap_or(u32::MAX)),
                })
            })
            .collect();
        let uplink = value
            .get("uplink")
            .filter(|u| u.is_object())
            .map(|uplink| Uplink {
                wireless: json::text(uplink, "type").is_some_and(|kind| kind == "wireless"),
                mac: json::mac(uplink, "uplink_mac"),
                remote_port: json::u16(uplink, "uplink_remote_port").filter(|p| *p > 0),
                local_port: json::u16(uplink, "port_idx").filter(|p| *p > 0),
            });
        let lldp = json::array(value, "lldp_table")
            .iter()
            .filter_map(|entry| {
                Some(Lldp {
                    chassis: json::text(entry, "chassis_id")?,
                    port: json::text(entry, "port_id"),
                    local_port: json::u16(entry, "local_port_idx").filter(|p| *p > 0),
                })
            })
            .collect();
        let vaps = json::array(value, "vap_table")
            .iter()
            .map(|vap| Vap {
                essid: json::text(vap, "essid"),
                wlan: json::id(vap, "id").or_else(|| json::id(vap, "wlanconf_id")),
            })
            .collect();
        Ok(Self {
            id,
            mac,
            ip: json::ip(value, "ip"),
            name: json::text(value, "name"),
            model: json::text(value, "model"),
            kind: json::text(value, "type").unwrap_or_default(),
            adopted: json::flag(value, "adopted").unwrap_or(true),
            version: json::text(value, "version"),
            ports,
            overrides: json::array(value, "port_overrides").to_vec(),
            uplink,
            lldp,
            vaps,
        })
    }

    /// The override entry of a port, when the device has one.
    pub fn override_of(&self, port: u16) -> Option<&Value> {
        self.overrides
            .iter()
            .find(|entry| json::u16(entry, "port_idx") == Some(port))
    }

    /// Whether the port's override switches it off (`forward` is `disabled`).
    pub fn disabled_by_override(&self, port: u16) -> bool {
        self.override_of(port)
            .and_then(|entry| json::text(entry, "forward"))
            .is_some_and(|forward| forward == "disabled")
    }

    /// The configured profile of a port: its override, else the effective one.
    pub fn profile_of(&self, port: u16) -> Option<String> {
        self.overrides
            .iter()
            .find(|entry| json::u16(entry, "port_idx") == Some(port))
            .and_then(|entry| json::id(entry, "portconf_id"))
            .or_else(|| {
                self.ports
                    .iter()
                    .find(|p| p.idx == port)
                    .and_then(|p| p.portconf_id.clone())
            })
    }
}

/// A connected client (`stat/sta`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The MAC address.
    pub mac: MacAddr,
    /// The IPv4 address.
    pub ip: Option<IpAddr>,
    /// IPv6 addresses.
    pub ipv6: Vec<IpAddr>,
    /// The alias an operator gave it.
    pub name: Option<String>,
    /// The name it announced (DHCP host name).
    pub hostname: Option<String>,
    /// The vendor of its MAC address as the controller knows it.
    pub vendor: Option<String>,
    /// Wired or wireless.
    pub wired: bool,
    /// A guest.
    pub guest: bool,
    /// The switch of a wired client.
    pub switch: Option<MacAddr>,
    /// The switch port of a wired client.
    pub switch_port: Option<u16>,
    /// The access point of a wireless client.
    pub ap: Option<MacAddr>,
    /// The SSID of a wireless client.
    pub essid: Option<String>,
    /// The network the client is in.
    pub network_id: Option<String>,
    /// The VLAN the controller reports for it.
    pub vlan: Option<u16>,
}

impl Client {
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        let mac = json::mac(value, "mac")?;
        let mut ipv6: Vec<IpAddr> = json::array(value, "ipv6_addresses")
            .iter()
            .chain(json::array(value, "ip6s"))
            .filter_map(|ip| ip.as_str()?.trim().parse::<IpAddr>().ok())
            .filter(IpAddr::is_ipv6)
            .collect();
        ipv6.sort();
        ipv6.dedup();
        let wired = json::flag(value, "is_wired").unwrap_or(false);
        Some(Self {
            mac,
            ip: json::ip(value, "ip").filter(IpAddr::is_ipv4),
            ipv6,
            name: json::text(value, "name"),
            hostname: json::text(value, "hostname"),
            vendor: json::text(value, "oui"),
            wired,
            guest: json::flag(value, "is_guest").unwrap_or(false),
            switch: json::mac(value, "sw_mac"),
            switch_port: json::u16(value, "sw_port").filter(|p| *p > 0),
            ap: if wired {
                None
            } else {
                json::mac(value, "ap_mac")
            },
            essid: if wired {
                None
            } else {
                json::text(value, "essid")
            },
            network_id: json::id(value, "network_id"),
            vlan: json::vlan(value, "vlan"),
        })
    }

    /// The name to show: the alias, else the announced name.
    pub fn display_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.hostname.as_deref())
    }
}

/// A network (`rest/networkconf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    /// The record id.
    pub id: String,
    /// The name.
    pub name: String,
    /// The purpose (`corporate`, `guest`, `vlan-only`, `wan`, VPN kinds).
    pub purpose: String,
    /// The VLAN id when the network is tagged.
    pub vlan: Option<u16>,
    /// The gateway address and prefix (`192.0.2.1/24`).
    pub subnet: Option<String>,
    /// Whether the controller serves DHCP on it.
    pub dhcp_server: bool,
    /// Whether the controller relays DHCP on it.
    pub dhcp_relay: bool,
    /// Whether it is the default network that cannot be deleted.
    pub default: bool,
}

impl Network {
    pub(crate) fn from_value(value: &Value) -> Result<Self, ConnectorError> {
        let id = json::id(value, "_id")
            .ok_or_else(|| ConnectorError::protocol("a network has no `_id`"))?;
        let tagged = json::flag(value, "vlan_enabled").unwrap_or(false);
        Ok(Self {
            name: json::text(value, "name").unwrap_or_else(|| id.clone()),
            id,
            purpose: json::text(value, "purpose").unwrap_or_default(),
            vlan: if tagged {
                json::vlan(value, "vlan")
            } else {
                None
            },
            subnet: json::text(value, "ip_subnet"),
            dhcp_server: json::flag(value, "dhcpd_enabled").unwrap_or(false),
            dhcp_relay: json::flag(value, "dhcp_relay_enabled").unwrap_or(false),
            default: json::flag(value, "attr_no_delete").unwrap_or(false)
                || json::text(value, "attr_hidden_id").is_some_and(|hidden| hidden == "LAN"),
        })
    }

    /// Whether it is a LAN (not a WAN or VPN).
    pub fn is_lan(&self) -> bool {
        matches!(self.purpose.as_str(), "corporate" | "guest" | "vlan-only")
    }

    /// The DHCP mode as diff text.
    pub fn dhcp_text(&self) -> &'static str {
        if self.purpose == "vlan-only" {
            "disabled"
        } else if self.dhcp_relay {
            "relay"
        } else if self.dhcp_server {
            "server"
        } else {
            "disabled"
        }
    }
}

/// A wireless network (`rest/wlanconf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wlan {
    /// The record id.
    pub id: String,
    /// The SSID.
    pub ssid: String,
    /// Whether it is enabled.
    pub enabled: bool,
    /// The network it carries.
    pub network_id: Option<String>,
    /// The VLAN of older controllers, which tag the SSID directly.
    pub vlan: Option<u16>,
}

impl Wlan {
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        let tagged = json::flag(value, "vlan_enabled").unwrap_or(false);
        Some(Self {
            id: json::id(value, "_id")?,
            ssid: json::text(value, "name")?,
            enabled: json::flag(value, "enabled").unwrap_or(true),
            network_id: json::id(value, "networkconf_id"),
            vlan: if tagged {
                json::vlan(value, "vlan")
            } else {
                None
            },
        })
    }
}

/// A port profile (`rest/portconf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The record id.
    pub id: String,
    /// The name.
    pub name: String,
    /// The untagged network.
    pub native: Option<String>,
    /// What the port forwards: `all`, `native`, `customize` or `disabled`.
    pub forward: String,
    /// The tagged networks of a `customize` profile.
    pub tagged: Vec<String>,
    /// The networks a `customize` profile of older controllers excludes.
    pub excluded: Vec<String>,
    /// Whether the controller reports the tagged list explicitly.
    pub has_tagged_list: bool,
}

impl Profile {
    pub(crate) fn from_value(value: &Value) -> Result<Self, ConnectorError> {
        let id = json::id(value, "_id")
            .ok_or_else(|| ConnectorError::protocol("a port profile has no `_id`"))?;
        Ok(Self {
            name: json::text(value, "name").unwrap_or_else(|| id.clone()),
            id,
            native: json::id(value, "native_networkconf_id"),
            forward: json::text(value, "forward").unwrap_or_else(|| "all".to_owned()),
            tagged: json::ids(value, "tagged_networkconf_ids"),
            excluded: json::ids(value, "excluded_networkconf_ids"),
            has_tagged_list: value
                .get("tagged_networkconf_ids")
                .is_some_and(Value::is_array),
        })
    }
}

/// A client record (`stat/user/<mac>`) with its per-client VLAN override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The record id.
    pub id: String,
    /// The MAC address.
    pub mac: MacAddr,
    /// Whether the client is wired, when the controller says so.
    pub wired: Option<bool>,
    /// Whether the controller version knows per-client VLAN overrides.
    pub supports_override: bool,
    /// The override network, when the override is on.
    pub override_network: Option<String>,
}

impl User {
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        let enabled = json::flag(value, "virtual_network_override_enabled");
        Some(Self {
            id: json::id(value, "_id")?,
            mac: json::mac(value, "mac")?,
            wired: json::flag(value, "is_wired"),
            supports_override: enabled.is_some(),
            override_network: if enabled == Some(true) {
                json::id(value, "virtual_network_override_id")
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &Value) -> Response {
        Response {
            status: StatusCode::from_u16(status).expect("status"),
            headers: tenko_connect::sdk::http::reqwest::header::HeaderMap::new(),
            body: serde_json::to_vec(body).expect("json"),
        }
    }

    #[test]
    fn envelopes_map_to_data_or_coded_errors() {
        let ok = response(
            200,
            &serde_json::json!({ "meta": { "rc": "ok" }, "data": [{ "a": 1 }] }),
        );
        assert_eq!(envelope(&ok, "default").expect("data").len(), 1);
        let cases = [
            (401, "api.err.LoginRequired", "connect.unauthorized"),
            (400, "api.err.NoPermission", "connect.forbidden"),
            (400, "api.err.NoSiteContext", "connect.invalid_settings"),
            (400, "api.err.IdInvalid", "connect.not_found"),
            (400, "api.err.VlanUsed", "connect.invalid_settings"),
            (500, "api.err.Internal", "connect.unreachable"),
        ];
        for (status, msg, code) in cases {
            let error = envelope(
                &response(
                    status,
                    &serde_json::json!({ "meta": { "rc": "error", "msg": msg }, "data": [] }),
                ),
                "default",
            )
            .expect_err(msg);
            assert_eq!(tenko_core::Coded::code(&error), code, "{msg}");
        }
        let refused = envelope(
            &response(200, &serde_json::json!({ "meta": { "rc": "error", "msg": "api.err.VlanUsed" }, "data": [] }),
            ),
            "default",
        )
        .expect_err("rc error");
        assert!(refused.to_string().contains("api.err.VlanUsed"));
    }

    #[test]
    fn records_read_the_members_the_plugin_needs() {
        let device = Device::from_value(&serde_json::json!({
            "_id": "d1", "mac": "00:00:5e:00:53:10", "type": "usw", "model": "US8P60",
            "port_table": [
                { "port_idx": 1, "up": true, "is_uplink": true, "portconf_id": "p-all" },
                { "port_idx": 2, "up": false, "portconf_id": "p-all" },
                { "port_idx": 0 }
            ],
            "port_overrides": [{ "port_idx": 2, "portconf_id": "p-iot", "name": "printer" }],
            "uplink": { "type": "wire", "uplink_mac": "00:00:5e:00:53:01", "uplink_remote_port": 4, "port_idx": 1 }
        }))
        .expect("device");
        assert_eq!(device.ports.len(), 2);
        assert_eq!(device.profile_of(2).as_deref(), Some("p-iot"));
        assert_eq!(device.profile_of(1).as_deref(), Some("p-all"));
        assert_eq!(device.uplink.as_ref().and_then(|u| u.remote_port), Some(4));
        assert!(Device::from_value(&serde_json::json!({ "_id": "x" })).is_err());
        let network = Network::from_value(&serde_json::json!({
            "_id": "n1", "name": "IoT", "purpose": "corporate", "vlan_enabled": true, "vlan": "30",
            "dhcpd_enabled": true
        }))
        .expect("network");
        assert_eq!((network.vlan, network.dhcp_text()), (Some(30), "server"));
        let user = User::from_value(&serde_json::json!({
            "_id": "u1", "mac": "00:00:5e:00:53:20",
            "virtual_network_override_enabled": true, "virtual_network_override_id": "n1"
        }))
        .expect("user");
        assert!(user.supports_override);
        assert_eq!(user.override_network.as_deref(), Some("n1"));
    }
}
