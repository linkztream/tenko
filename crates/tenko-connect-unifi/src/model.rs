//! What the plugin reports, computed from the classic records: the topology of the network
//! controller contract and the inventory hosts.
//!
//! Rules the host's guardrails rely on:
//!
//! - **Uplinks.** A port is reported as an uplink when it carries a link to another network
//!   device: the device's own uplink port, the port of a parent device that a managed
//!   device hangs on, a port whose LLDP neighbour is a managed device, a port the controller
//!   marks as uplink, and every member of an aggregate one of those belongs to.
//! - **Management.** A network is a management network when it is the untagged default
//!   network, or its subnet holds the controller's address, the address Tenko reaches the
//!   controller from, or the address of a managed device. The client whose address is the
//!   controller's or Tenko's is a management client, and its switch port a management port.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
};

use ipnet::IpNet;
use tenko_connect::{
    ClientAttachment, ControllerDhcp, ControllerNetwork, DeviceKind, DevicePort, DeviceRef,
    NetworkDevice, NetworkRef, PortProfile, ProfileRef, TopologyLink, TopologySnapshot,
    WirelessNetwork,
};
use tenko_core::{
    MacAddr, Timestamp,
    observe::{Endpoint, LinkKind, ObservedHost},
};

use crate::classic::{Client, Device, Network, Profile, Wlan};

/// Everything one classic read returned.
#[derive(Debug, Clone, Default)]
pub struct Read {
    /// Devices.
    pub devices: Vec<Device>,
    /// Connected clients.
    pub clients: Vec<Client>,
    /// Networks.
    pub networks: Vec<Network>,
    /// Wireless networks.
    pub wlans: Vec<Wlan>,
    /// Port profiles.
    pub profiles: Vec<Profile>,
}

/// The addresses that mark the management path.
#[derive(Debug, Clone, Default)]
pub struct Local {
    /// The controller's addresses (the host of the instance's URL).
    pub controller: Vec<IpAddr>,
    /// The addresses Tenko reaches the controller from.
    pub tenko: Vec<IpAddr>,
}

impl Local {
    fn contains(&self, ip: IpAddr) -> bool {
        self.controller.contains(&ip) || self.tenko.contains(&ip)
    }

    fn all(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.controller.iter().chain(&self.tenko).copied()
    }
}

/// The kind of a device type code.
pub fn kind_of(code: &str) -> DeviceKind {
    match code {
        "usw" => DeviceKind::Switch,
        "uap" => DeviceKind::AccessPoint,
        "ugw" | "udm" | "uxg" => DeviceKind::Gateway,
        _ => DeviceKind::Other,
    }
}

/// The name a device is reported with: its own, else its model and MAC address.
pub fn device_name(device: &Device) -> String {
    device.name.clone().unwrap_or_else(|| match &device.model {
        Some(model) => format!("{model} {}", device.mac),
        None => device.mac.to_string(),
    })
}

/// A subnet text (`192.0.2.1/24`) as its network (`192.0.2.0/24`).
pub fn subnet(text: &str) -> Option<IpNet> {
    text.trim().parse::<IpNet>().ok().map(|net| net.trunc())
}

/// The port index in an LLDP port id of a managed device (`Port 7`, `local Port 7`, `7`).
/// A UniFi switch names its port with the locally assigned subtype, which the controller
/// renders as `local Port 7`.
fn lldp_port_index(text: &str) -> Option<u16> {
    let text = text.trim();
    let text = text
        .strip_prefix("local ")
        .or_else(|| text.strip_prefix("Local "))
        .unwrap_or(text);
    let digits = text
        .strip_prefix("Port ")
        .or_else(|| text.strip_prefix("port "))
        .unwrap_or(text);
    digits.parse().ok().filter(|idx| *idx > 0)
}

/// The ports that carry links to other network devices, by device MAC and index.
fn link_ports(devices: &[&Device]) -> HashSet<(MacAddr, u16)> {
    let managed: HashSet<MacAddr> = devices.iter().map(|d| d.mac).collect();
    let mut ports = HashSet::new();
    for device in devices {
        for port in &device.ports {
            if port.is_uplink {
                ports.insert((device.mac, port.idx));
            }
        }
        if let Some(uplink) = &device.uplink
            && !uplink.wireless
        {
            if let Some(local) = uplink.local_port {
                ports.insert((device.mac, local));
            }
            if let (Some(parent), Some(remote)) = (uplink.mac, uplink.remote_port) {
                ports.insert((parent, remote));
            }
        }
        for neighbour in &device.lldp {
            let is_managed = crate::json::parse_mac(&neighbour.chassis)
                .is_some_and(|mac| managed.contains(&mac));
            if let (true, Some(local)) = (is_managed, neighbour.local_port) {
                ports.insert((device.mac, local));
            }
        }
    }
    // Every member of an aggregate that carries a link carries it too.
    for device in devices {
        let lag = |idx: u16| {
            device
                .ports
                .iter()
                .find(|p| p.idx == idx)
                .and_then(|p| p.aggregated_by)
                .unwrap_or(idx)
        };
        let heads: BTreeSet<u16> = device
            .ports
            .iter()
            .filter(|p| ports.contains(&(device.mac, p.idx)))
            .map(|p| lag(p.idx))
            .collect();
        for port in &device.ports {
            if heads.contains(&lag(port.idx)) {
                ports.insert((device.mac, port.idx));
            }
        }
    }
    ports
}

/// The tagged networks of a profile.
fn tagged_of(profile: &Profile, lans: &[&Network]) -> Vec<NetworkRef> {
    let all_but_native = || {
        lans.iter()
            .filter(|n| Some(&n.id) != profile.native.as_ref())
            .map(|n| n.id.clone())
            .collect::<Vec<_>>()
    };
    let ids = match profile.forward.as_str() {
        "native" | "disabled" => Vec::new(),
        "customize" if !profile.has_tagged_list => all_but_native()
            .into_iter()
            .filter(|id| !profile.excluded.contains(id))
            .collect(),
        "customize" => profile.tagged.clone(),
        _ if profile.has_tagged_list && !profile.tagged.is_empty() => profile.tagged.clone(),
        _ => all_but_native(),
    };
    ids.into_iter().map(NetworkRef).collect()
}

/// The lookups one topology is computed with.
struct View<'a> {
    devices: Vec<&'a Device>,
    by_mac: HashMap<MacAddr, &'a Device>,
    lans: Vec<&'a Network>,
    networks: HashMap<&'a str, &'a Network>,
    profiles: HashMap<&'a str, &'a Profile>,
    link_ports: HashSet<(MacAddr, u16)>,
    management_clients: HashSet<MacAddr>,
    management_ports: HashSet<(MacAddr, u16)>,
}

impl<'a> View<'a> {
    fn new(read: &'a Read, local: &Local) -> Self {
        let devices: Vec<&Device> = read.devices.iter().filter(|d| d.adopted).collect();
        let lans: Vec<&Network> = read.networks.iter().filter(|n| n.is_lan()).collect();
        let management_clients: HashSet<MacAddr> = read
            .clients
            .iter()
            .filter(|c| {
                c.ip.into_iter()
                    .chain(c.ipv6.iter().copied())
                    .any(|ip| local.contains(ip))
            })
            .map(|c| c.mac)
            .collect();
        let management_ports = read
            .clients
            .iter()
            .filter(|c| management_clients.contains(&c.mac) && c.wired)
            .filter_map(|c| Some((c.switch?, c.switch_port?)))
            .collect();
        Self {
            by_mac: devices.iter().map(|d| (d.mac, *d)).collect(),
            networks: lans.iter().map(|n| (n.id.as_str(), *n)).collect(),
            profiles: read.profiles.iter().map(|p| (p.id.as_str(), p)).collect(),
            link_ports: link_ports(&devices),
            devices,
            lans,
            management_clients,
            management_ports,
        }
    }

    fn vlan_of(&self, network: &str) -> Option<u16> {
        self.networks.get(network).and_then(|n| n.vlan)
    }

    fn device(&self, device: &Device) -> NetworkDevice {
        NetworkDevice {
            id: DeviceRef(device.mac.to_string()),
            name: device_name(device),
            model: device.model.clone(),
            mac: Some(device.mac),
            ip: device.ip,
            kind: kind_of(&device.kind),
            ports: device
                .ports
                .iter()
                .map(|port| {
                    let profile = device.profile_of(port.idx);
                    let native = port.native_networkconf_id.clone().or_else(|| {
                        profile
                            .as_deref()
                            .and_then(|id| self.profiles.get(id))
                            .and_then(|p| p.native.clone())
                    });
                    DevicePort {
                        index: port.idx,
                        name: port.name.clone(),
                        profile: profile.map(ProfileRef),
                        native_vlan: native.as_deref().and_then(|id| self.vlan_of(id)),
                        uplink: self.link_ports.contains(&(device.mac, port.idx)),
                        up: port.up,
                        management: self.management_ports.contains(&(device.mac, port.idx)),
                    }
                })
                .collect(),
        }
    }

    /// Uplinks of managed devices, then LLDP neighbours that no uplink already covers.
    fn links(&self) -> Vec<TopologyLink> {
        let mut links = Vec::new();
        let mut pairs: HashSet<(MacAddr, MacAddr)> = HashSet::new();
        for device in &self.devices {
            let Some(uplink) = &device.uplink else {
                continue;
            };
            let Some(parent) = uplink.mac else {
                continue;
            };
            pairs.insert((device.mac, parent));
            pairs.insert((parent, device.mac));
            let (kind, near, far) = if uplink.wireless {
                (LinkKind::Wireless, None, None)
            } else {
                (
                    LinkKind::Uplink,
                    uplink.local_port.map(|p| p.to_string()),
                    uplink.remote_port.map(|p| p.to_string()),
                )
            };
            links.push(TopologyLink {
                a: Endpoint {
                    device: device.mac.to_string(),
                    port: near,
                },
                b: Endpoint {
                    device: parent.to_string(),
                    port: far,
                },
                kind,
            });
        }
        let mut seen: HashSet<(String, Option<String>, String, Option<String>)> = HashSet::new();
        for device in &self.devices {
            for neighbour in &device.lldp {
                let neighbour_mac = crate::json::parse_mac(&neighbour.chassis);
                if neighbour_mac.is_some_and(|mac| pairs.contains(&(device.mac, mac))) {
                    continue;
                }
                let managed = neighbour_mac.is_some_and(|mac| self.by_mac.contains_key(&mac));
                let near = (
                    device.mac.to_string(),
                    neighbour.local_port.map(|p| p.to_string()),
                );
                let far = (
                    neighbour_mac.map_or_else(|| neighbour.chassis.clone(), |m| m.to_string()),
                    neighbour
                        .port
                        .as_deref()
                        .map(|text| match (managed, lldp_port_index(text)) {
                            (true, Some(idx)) => idx.to_string(),
                            _ => text.to_owned(),
                        }),
                );
                let key = if near <= far {
                    (near.0.clone(), near.1.clone(), far.0.clone(), far.1.clone())
                } else {
                    (far.0.clone(), far.1.clone(), near.0.clone(), near.1.clone())
                };
                if seen.insert(key) {
                    links.push(TopologyLink {
                        a: Endpoint {
                            device: near.0,
                            port: near.1,
                        },
                        b: Endpoint {
                            device: far.0,
                            port: far.1,
                        },
                        kind: LinkKind::Lldp,
                    });
                }
            }
        }
        links
    }

    fn client(&self, client: &Client) -> Option<ClientAttachment> {
        let (device, port, ssid) = if client.wired {
            (client.switch?, client.switch_port, None)
        } else {
            (client.ap?, None, client.essid.clone())
        };
        let network = client
            .network_id
            .as_deref()
            .filter(|id| self.networks.contains_key(id))
            .map(str::to_owned);
        Some(ClientAttachment {
            mac: client.mac,
            ip: client.ip.or_else(|| client.ipv6.first().copied()),
            device: DeviceRef(device.to_string()),
            port,
            ssid,
            vlan: network
                .as_deref()
                .and_then(|id| self.vlan_of(id))
                .or(client.vlan),
            network: network.map(NetworkRef),
            name: client.display_name().map(str::to_owned),
            vendor: client.vendor.clone(),
            management: self.management_clients.contains(&client.mac),
        })
    }

    fn network(&self, network: &Network, local: &Local) -> ControllerNetwork {
        let net = network.subnet.as_deref().and_then(subnet);
        let holds = |ip: IpAddr| net.is_some_and(|net| net.contains(&ip));
        ControllerNetwork {
            id: NetworkRef(network.id.clone()),
            name: network.name.clone(),
            vlan: network.vlan,
            subnet: net,
            dhcp: dhcp_of(network),
            management: network.default
                || local.all().any(holds)
                || self.devices.iter().filter_map(|d| d.ip).any(holds),
        }
    }

    fn wlan(&self, wlan: &Wlan) -> WirelessNetwork {
        let access_points: BTreeSet<String> = self
            .devices
            .iter()
            .filter(|d| {
                d.vaps.iter().any(|vap| {
                    vap.wlan.as_deref() == Some(wlan.id.as_str())
                        || vap.essid.as_deref() == Some(wlan.ssid.as_str())
                })
            })
            .map(|d| d.mac.to_string())
            .collect();
        let network = wlan
            .network_id
            .as_deref()
            .filter(|id| self.networks.contains_key(id));
        WirelessNetwork {
            id: wlan.id.clone(),
            ssid: wlan.ssid.clone(),
            network: network.map(|id| NetworkRef(id.to_owned())),
            vlan: network.and_then(|id| self.vlan_of(id)).or(wlan.vlan),
            enabled: wlan.enabled,
            access_points: access_points.into_iter().map(DeviceRef).collect(),
        }
    }
}

/// The topology of one read.
pub fn topology(read: &Read, local: &Local, observed_at: Timestamp) -> TopologySnapshot {
    let view = View::new(read, local);
    TopologySnapshot {
        observed_at,
        devices: view.devices.iter().map(|d| view.device(d)).collect(),
        links: view.links(),
        clients: read.clients.iter().filter_map(|c| view.client(c)).collect(),
        networks: view.lans.iter().map(|n| view.network(n, local)).collect(),
        profiles: read
            .profiles
            .iter()
            .map(|profile| PortProfile {
                id: ProfileRef(profile.id.clone()),
                name: profile.name.clone(),
                native_network: profile.native.clone().map(NetworkRef),
                tagged: tagged_of(profile, &view.lans),
            })
            .collect(),
        wlans: read.wlans.iter().map(|w| view.wlan(w)).collect(),
    }
}

/// The controller's DHCP of a network.
pub fn dhcp_of(network: &Network) -> ControllerDhcp {
    match network.dhcp_text() {
        "server" => ControllerDhcp::Server,
        // The classic API does not report the relay targets per network.
        "relay" => ControllerDhcp::RelayTo(Vec::new()),
        _ => ControllerDhcp::Disabled,
    }
}

/// The inventory of one read: every connected client and every managed device as a host.
/// Addresses from a controller carry no VRF; the reconciler places them (see
/// `docs/connectors-unifi.md`).
pub fn inventory(read: &Read) -> Vec<ObservedHost> {
    let mut hosts: BTreeMap<String, ObservedHost> = BTreeMap::new();
    for device in read.devices.iter().filter(|d| d.adopted) {
        let kind = match kind_of(&device.kind) {
            DeviceKind::Switch => "unifi:switch",
            DeviceKind::AccessPoint => "unifi:access_point",
            DeviceKind::Gateway => "unifi:gateway",
            DeviceKind::Other => "unifi:device",
        };
        let id = format!("device:{}", device.mac);
        hosts.insert(
            id.clone(),
            ObservedHost {
                external_id: id,
                name: Some(device_name(device)),
                macs: vec![device.mac],
                ips: device.ip.into_iter().collect(),
                tags: vec![kind.to_owned()],
                ..ObservedHost::default()
            },
        );
    }
    let device_macs: HashSet<MacAddr> = read.devices.iter().map(|d| d.mac).collect();
    for client in &read.clients {
        if device_macs.contains(&client.mac) {
            continue;
        }
        let id = format!("client:{}", client.mac);
        let mut tags = vec![if client.wired {
            "unifi:wired".to_owned()
        } else {
            "unifi:wireless".to_owned()
        }];
        if client.guest {
            tags.push("unifi:guest".to_owned());
        }
        hosts.insert(
            id.clone(),
            ObservedHost {
                external_id: id,
                name: client.display_name().map(str::to_owned),
                macs: vec![client.mac],
                ips: client
                    .ip
                    .into_iter()
                    .chain(client.ipv6.iter().copied())
                    .collect(),
                tags,
                ..ObservedHost::default()
            },
        );
    }
    hosts.into_values().collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn read() -> Read {
        let devices = [
            json!({ "_id": "g", "mac": "00:00:5e:00:53:01", "type": "ugw", "ip": "192.0.2.1",
                    "port_table": [{ "port_idx": 1 }, { "port_idx": 2, "up": true }] }),
            json!({ "_id": "s", "mac": "00:00:5e:00:53:10", "type": "usw", "ip": "192.0.2.2",
                    "uplink": { "type": "wire", "uplink_mac": "00:00:5e:00:53:01", "uplink_remote_port": 2, "port_idx": 1 },
                    "port_table": [
                        { "port_idx": 1, "up": true }, { "port_idx": 7, "up": true },
                        { "port_idx": 8, "up": true }, { "port_idx": 15, "up": true },
                        { "port_idx": 16, "up": true, "aggregated_by": 15 }
                    ],
                    "lldp_table": [{ "chassis_id": "00:00:5e:00:53:20", "port_id": "Port 1", "local_port_idx": 15 }] }),
            json!({ "_id": "a", "mac": "00:00:5e:00:53:20", "type": "uap", "ip": "192.0.2.4",
                    "vap_table": [{ "essid": "home.example", "id": "w1" }] }),
        ];
        let clients = [
            json!({ "mac": "00:00:5e:00:53:30", "ip": "192.0.2.10", "is_wired": true,
                    "sw_mac": "00:00:5e:00:53:10", "sw_port": 7, "network_id": "n-default" }),
            json!({ "mac": "00:00:5e:00:53:31", "ip": "198.51.100.5", "is_wired": true,
                    "sw_mac": "00:00:5e:00:53:10", "sw_port": 8, "network_id": "n-iot", "oui": "Example Co" }),
            json!({ "mac": "00:00:5e:00:53:32", "ip": "192.0.2.11", "is_wired": false,
                    "ap_mac": "00:00:5e:00:53:20", "essid": "home.example", "hostname": "tenko" }),
        ];
        let networks = [
            json!({ "_id": "n-default", "name": "Default", "purpose": "corporate", "ip_subnet": "192.0.2.1/24",
                    "dhcpd_enabled": true, "attr_no_delete": true }),
            json!({ "_id": "n-iot", "name": "IoT", "purpose": "corporate", "vlan_enabled": true, "vlan": 30,
                    "ip_subnet": "198.51.100.1/24" }),
            json!({ "_id": "n-mgmt", "name": "Mgmt", "purpose": "vlan-only", "vlan_enabled": true, "vlan": 10 }),
            json!({ "_id": "n-wan", "name": "Internet", "purpose": "wan" }),
        ];
        Read {
            devices: devices
                .iter()
                .map(|v| Device::from_value(v).expect("device"))
                .collect(),
            clients: clients.iter().filter_map(Client::from_value).collect(),
            networks: networks
                .iter()
                .map(|v| Network::from_value(v).expect("network"))
                .collect(),
            wlans: [json!({ "_id": "w1", "name": "home.example", "networkconf_id": "n-default" })]
                .iter()
                .filter_map(Wlan::from_value)
                .collect(),
            profiles: Vec::new(),
        }
    }

    fn port(snapshot: &TopologySnapshot, device: &str, index: u16) -> DevicePort {
        snapshot
            .devices
            .iter()
            .find(|d| d.id.0 == device)
            .and_then(|d| d.ports.iter().find(|p| p.index == index))
            .cloned()
            .expect("port")
    }

    #[test]
    fn uplinks_and_the_management_path_are_marked() {
        let local = Local {
            controller: vec!["192.0.2.10".parse().expect("ip")],
            tenko: vec!["192.0.2.11".parse().expect("ip")],
        };
        let snapshot = topology(&read(), &local, Timestamp::now());
        let switch = "00:00:5e:00:53:10";
        assert!(port(&snapshot, switch, 1).uplink, "own uplink");
        assert!(
            port(&snapshot, "00:00:5e:00:53:01", 2).uplink,
            "parent port"
        );
        assert!(port(&snapshot, switch, 15).uplink, "LLDP to a managed AP");
        assert!(
            port(&snapshot, switch, 16).uplink,
            "member of that aggregate"
        );
        assert!(!port(&snapshot, switch, 8).uplink);
        assert!(
            port(&snapshot, switch, 7).management,
            "the controller's port"
        );
        assert!(!port(&snapshot, switch, 8).management);
        let management: Vec<String> = snapshot
            .clients
            .iter()
            .filter(|c| c.management)
            .map(|c| c.mac.to_string())
            .collect();
        assert_eq!(management, ["00:00:5e:00:53:30", "00:00:5e:00:53:32"]);
        let networks: Vec<(&str, bool)> = snapshot
            .networks
            .iter()
            .map(|n| (n.name.as_str(), n.management))
            .collect();
        assert_eq!(
            networks,
            [("Default", true), ("IoT", false), ("Mgmt", false)]
        );
        let iot = snapshot
            .clients
            .iter()
            .find(|c| c.vlan == Some(30))
            .expect("iot client");
        assert_eq!(iot.vendor.as_deref(), Some("Example Co"));
        assert_eq!(snapshot.wlans[0].access_points.len(), 1);
        assert_eq!(
            snapshot
                .links
                .iter()
                .filter(|l| l.kind == LinkKind::Lldp)
                .count(),
            1
        );
    }

    #[test]
    fn the_inventory_has_one_host_per_device_and_client() {
        let hosts = inventory(&read());
        assert_eq!(hosts.len(), 6);
        assert!(hosts.iter().all(|h| h.macs.len() == 1));
        let tenko = hosts
            .iter()
            .find(|h| h.external_id == "client:00:00:5e:00:53:32")
            .expect("client");
        assert_eq!(tenko.name.as_deref(), Some("tenko"));
        assert_eq!(tenko.tags, ["unifi:wireless"]);
        assert_eq!(
            subnet("192.0.2.1/24").map(|n| n.to_string()).as_deref(),
            Some("192.0.2.0/24")
        );
        assert_eq!(lldp_port_index("Port 9"), Some(9));
        assert_eq!(lldp_port_index("local Port 23"), Some(23));
        assert_eq!(lldp_port_index("eth0"), None);
    }
}
