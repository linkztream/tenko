//! Network controllers: topology reads and guarded L2 writes (CONN-05 to CONN-09).
//!
//! The plugin performs the concrete calls; the host keeps the policy. Before a write the
//! host reads the [`TopologySnapshot`], checks its [`Guardrails`] (uplinks and management
//! networks always, plus the configured protected paths), asks the plugin to
//! [`plan`](NetworkController::plan) and shows the plan as a preview; only then does it
//! call [`apply`](NetworkController::apply) with that plan, and after a real write it plans
//! the same change again and expects an empty diff.

use std::{fmt, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{MacAddr, Timestamp, observe::Endpoint, observe::LinkKind};

use crate::{
    CallContext, ConnectorError,
    actuator::{DiffLine, WriteMode},
};

/// Reads topology from, and writes VLANs, port profiles and per-client VLANs to, a network
/// controller (capability `network_controller`).
#[async_trait::async_trait]
pub trait NetworkController: Send + Sync + 'static {
    /// Devices, ports, links, clients, networks, profiles and wireless networks.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn topology(&self, ctx: &CallContext) -> Result<TopologySnapshot, ConnectorError>;

    /// Reads back the current state, diffs it against the change and fingerprints the
    /// state. Writes nothing; the guardrails are checked by the host.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn plan(&self, ctx: &CallContext, change: &L2Change) -> Result<L2Plan, ConnectorError>;

    /// Re-reads, rejects a stale plan with [`ConnectorError::VerifyMismatch`], writes (only
    /// in [`WriteMode::Apply`]) and verifies the result by reading it back.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::VerifyMismatch`] when the plan is stale or the read-back differs.
    async fn apply(
        &self,
        ctx: &CallContext,
        plan: &L2Plan,
        mode: WriteMode,
    ) -> Result<L2Receipt, ConnectorError>;

    /// Undoes an applied change with the undo steps of its receipt.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`]; the job then asks for a manual undo.
    async fn revert(&self, ctx: &CallContext, receipt: &L2Receipt) -> Result<(), ConnectorError>;
}

macro_rules! controller_ref {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

controller_ref! {
    /// A device as the controller identifies it (for UniFi the device MAC or `_id`).
    DeviceRef
}

controller_ref! {
    /// A network as the controller identifies it (for UniFi the network `_id`, not the
    /// VLAN number).
    NetworkRef
}

controller_ref! {
    /// A port profile as the controller identifies it.
    ProfileRef
}

/// A change Tenko asks a network controller to make.
///
/// Adjacently tagged because variants carry IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum L2Change {
    /// Create or update the network for a VLAN.
    EnsureNetwork {
        /// The VLAN id.
        vlan: u16,
        /// The network name.
        name: String,
        /// The controller's DHCP for the network.
        dhcp: ControllerDhcp,
    },
    /// Assign a port profile to a switch port.
    SetPortProfile {
        /// The switch.
        device: DeviceRef,
        /// The port index.
        port: u16,
        /// The profile.
        profile: ProfileRef,
    },
    /// Put a client into a network (per-client VLAN).
    SetClientVlan {
        /// The client.
        mac: MacAddr,
        /// The network.
        network: NetworkRef,
    },
    /// Remove a per-client VLAN override.
    ClearClientVlan {
        /// The client.
        mac: MacAddr,
    },
    /// Remove a network: the undo of a network that `EnsureNetwork` created.
    RemoveNetwork {
        /// The network.
        network: NetworkRef,
        /// The VLAN it carries.
        vlan: u16,
    },
}

/// The controller's own DHCP for a network: Tenko serves DHCP, so it is off or relays.
///
/// Adjacently tagged because a variant carries IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ControllerDhcp {
    /// No DHCP on the controller.
    Disabled,
    /// Relay to these servers.
    RelayTo(Vec<IpAddr>),
    /// The controller serves DHCP itself (reported, and restored by undo steps; Tenko never
    /// asks for it).
    Server,
}

/// The plan of one change: what was read, what would change, and the fingerprint
/// `apply` uses to reject a stale plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2Plan {
    /// The change.
    pub change: L2Change,
    /// When the state was read.
    pub read_at: Timestamp,
    /// Fingerprint of the state the plan was made against.
    pub fingerprint: String,
    /// What would change.
    pub diff: Vec<DiffLine>,
    /// English warnings for the preview.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// What `apply` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2Receipt {
    /// The plan that was applied.
    pub plan: L2Plan,
    /// Dry run or real write.
    pub mode: WriteMode,
    /// When the write happened.
    pub applied_at: Timestamp,
    /// Whether the read-back matched.
    pub verified: bool,
    /// Changes that restore the previous state, in order.
    #[serde(default)]
    pub undo: Vec<L2Change>,
}

/// A snapshot of a controller's view of the network (IPAM-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySnapshot {
    /// When it was read.
    pub observed_at: Timestamp,
    /// Switches, access points and gateways.
    pub devices: Vec<NetworkDevice>,
    /// Links between devices.
    pub links: Vec<TopologyLink>,
    /// Clients and where they are attached.
    pub clients: Vec<ClientAttachment>,
    /// Networks.
    pub networks: Vec<ControllerNetwork>,
    /// Port profiles.
    pub profiles: Vec<PortProfile>,
    /// Wireless networks (CONN-18).
    #[serde(default)]
    pub wlans: Vec<WirelessNetwork>,
}

impl TopologySnapshot {
    /// The device with the given reference.
    pub fn device(&self, id: &DeviceRef) -> Option<&NetworkDevice> {
        self.devices.iter().find(|device| &device.id == id)
    }
}

/// A managed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDevice {
    /// Controller reference.
    pub id: DeviceRef,
    /// Name.
    pub name: String,
    /// Model.
    #[serde(default)]
    pub model: Option<String>,
    /// MAC address.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// Management address.
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// What it is.
    pub kind: DeviceKind,
    /// Switch ports.
    #[serde(default)]
    pub ports: Vec<DevicePort>,
}

/// Kinds of devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// A switch.
    Switch,
    /// A wireless access point.
    AccessPoint,
    /// A gateway or router.
    Gateway,
    /// Anything else.
    Other,
}

/// A switch port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePort {
    /// Port index as the controller numbers it.
    pub index: u16,
    /// Port name.
    #[serde(default)]
    pub name: Option<String>,
    /// Assigned profile.
    #[serde(default)]
    pub profile: Option<ProfileRef>,
    /// Untagged VLAN.
    #[serde(default)]
    pub native_vlan: Option<u16>,
    /// Whether the port is an uplink (always protected).
    #[serde(default)]
    pub uplink: bool,
    /// Link state.
    #[serde(default)]
    pub up: bool,
    /// Whether Tenko or the controller is reached through this port (always protected).
    #[serde(default)]
    pub management: bool,
}

/// A link between two devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyLink {
    /// One end.
    pub a: Endpoint,
    /// The other end.
    pub b: Endpoint,
    /// How the link is known.
    pub kind: LinkKind,
}

/// A client and where it is attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAttachment {
    /// The client.
    pub mac: MacAddr,
    /// Its address.
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// The switch or access point.
    pub device: DeviceRef,
    /// The switch port (wired clients).
    #[serde(default)]
    pub port: Option<u16>,
    /// The wireless network (wireless clients).
    #[serde(default)]
    pub ssid: Option<String>,
    /// The network.
    #[serde(default)]
    pub network: Option<NetworkRef>,
    /// The VLAN.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// The name on the controller.
    #[serde(default)]
    pub name: Option<String>,
    /// The vendor of the MAC address.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Whether the client is the controller or Tenko's host (always protected).
    #[serde(default)]
    pub management: bool,
}

/// A network on the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerNetwork {
    /// Controller reference.
    pub id: NetworkRef,
    /// Name.
    pub name: String,
    /// VLAN id (`None` for the untagged default network).
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Gateway subnet.
    #[serde(default)]
    pub subnet: Option<IpNet>,
    /// The controller's DHCP.
    pub dhcp: ControllerDhcp,
    /// Whether Tenko or the controller is managed through this network.
    #[serde(default)]
    pub management: bool,
}

/// A port profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortProfile {
    /// Controller reference.
    pub id: ProfileRef,
    /// Name.
    pub name: String,
    /// Untagged network.
    #[serde(default)]
    pub native_network: Option<NetworkRef>,
    /// Tagged networks.
    #[serde(default)]
    pub tagged: Vec<NetworkRef>,
}

/// A wireless network (SSID) and the network it carries (CONN-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessNetwork {
    /// Controller reference.
    pub id: String,
    /// The SSID.
    pub ssid: String,
    /// The network the SSID maps to.
    #[serde(default)]
    pub network: Option<NetworkRef>,
    /// The VLAN it carries.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Whether it is broadcast.
    #[serde(default)]
    pub enabled: bool,
    /// The access points that broadcast it.
    #[serde(default)]
    pub access_points: Vec<DeviceRef>,
}

/// Paths a connector never touches (CONN-09).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtectedPath {
    /// A switch port, such as the port Tenko or the controller is reached through.
    Port {
        /// The switch.
        device: DeviceRef,
        /// The port index.
        port: u16,
    },
    /// A network, such as the management network.
    Network {
        /// The network.
        network: NetworkRef,
    },
    /// A VLAN.
    Vlan {
        /// The VLAN id.
        vid: u16,
    },
    /// A client, such as the Tenko host itself.
    Client {
        /// The client.
        mac: MacAddr,
    },
}

/// Guardrails for network-controller writes (CONN-09), enforced by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guardrails {
    /// Configured and derived protected paths. Uplinks and management networks from the
    /// topology are protected on top of these.
    pub protected: Vec<ProtectedPath>,
    /// Concurrent writes allowed through one controller.
    pub max_parallel: usize,
}

impl Default for Guardrails {
    fn default() -> Self {
        Self {
            protected: Vec::new(),
            max_parallel: 10,
        }
    }
}

impl Guardrails {
    /// Checks a change against the protected paths and the topology: uplink ports and
    /// management networks are always protected.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::GuardrailRefused`] with the rule that refused.
    pub fn check(
        &self,
        change: &L2Change,
        topology: &TopologySnapshot,
    ) -> Result<(), ConnectorError> {
        let refuse = |rule| Err(ConnectorError::GuardrailRefused { rule });
        match change {
            L2Change::SetPortProfile { device, port, .. } => {
                let uplink = topology
                    .device(device)
                    .and_then(|d| d.ports.iter().find(|p| p.index == *port))
                    .is_some_and(|p| p.uplink);
                if uplink {
                    return refuse("connect.guardrail.uplink");
                }
                let management_port = topology
                    .device(device)
                    .and_then(|d| d.ports.iter().find(|p| p.index == *port))
                    .is_some_and(|p| p.management);
                if management_port {
                    return refuse("connect.guardrail.management_port");
                }
                if self.protected.iter().any(|path| {
                    matches!(path, ProtectedPath::Port { device: d, port: p } if d == device && p == port)
                }) {
                    return refuse("connect.guardrail.protected_port");
                }
            }
            L2Change::SetClientVlan { mac, network } => {
                if topology
                    .clients
                    .iter()
                    .any(|c| c.mac == *mac && c.management)
                {
                    return refuse("connect.guardrail.management_client");
                }
                if self.is_protected_client(*mac) {
                    return refuse("connect.guardrail.protected_client");
                }
                if self.is_protected_network(network, topology) {
                    return refuse("connect.guardrail.protected_network");
                }
            }
            L2Change::ClearClientVlan { mac } => {
                if topology
                    .clients
                    .iter()
                    .any(|c| c.mac == *mac && c.management)
                {
                    return refuse("connect.guardrail.management_client");
                }
                if self.is_protected_client(*mac) {
                    return refuse("connect.guardrail.protected_client");
                }
            }
            L2Change::EnsureNetwork { vlan, .. } => {
                let management_vlan = topology
                    .networks
                    .iter()
                    .any(|n| n.management && n.vlan == Some(*vlan));
                let protected_vlan = self
                    .protected
                    .iter()
                    .any(|path| matches!(path, ProtectedPath::Vlan { vid } if vid == vlan));
                if management_vlan || protected_vlan {
                    return refuse("connect.guardrail.protected_vlan");
                }
            }
            L2Change::RemoveNetwork { network, vlan } => {
                if self.is_protected_network(network, topology) {
                    return refuse("connect.guardrail.protected_network");
                }
                let management_vlan = topology
                    .networks
                    .iter()
                    .any(|n| n.management && n.vlan == Some(*vlan));
                let protected_vlan = self
                    .protected
                    .iter()
                    .any(|path| matches!(path, ProtectedPath::Vlan { vid } if vid == vlan));
                if management_vlan || protected_vlan {
                    return refuse("connect.guardrail.protected_vlan");
                }
            }
        }
        Ok(())
    }

    fn is_protected_client(&self, mac: MacAddr) -> bool {
        self.protected
            .iter()
            .any(|path| matches!(path, ProtectedPath::Client { mac: m } if *m == mac))
    }

    fn is_protected_network(&self, network: &NetworkRef, topology: &TopologySnapshot) -> bool {
        topology
            .networks
            .iter()
            .any(|n| n.management && &n.id == network)
            || self
                .protected
                .iter()
                .any(|path| matches!(path, ProtectedPath::Network { network: n } if n == network))
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::codec::{from_cbor, to_cbor};

    use super::*;

    fn topology() -> TopologySnapshot {
        TopologySnapshot {
            observed_at: "2026-10-09T12:00:00Z".parse().expect("time"),
            devices: vec![NetworkDevice {
                id: DeviceRef("switch-a".to_owned()),
                name: "switch-a".to_owned(),
                model: None,
                mac: Some("00:00:5e:00:53:a0".parse().expect("mac")),
                ip: Some("192.0.2.2".parse().expect("ip")),
                kind: DeviceKind::Switch,
                ports: vec![
                    DevicePort {
                        index: 1,
                        name: None,
                        profile: None,
                        native_vlan: Some(1),
                        uplink: true,
                        up: true,
                        management: false,
                    },
                    DevicePort {
                        index: 5,
                        name: None,
                        profile: None,
                        native_vlan: Some(20),
                        uplink: false,
                        up: true,
                        management: false,
                    },
                    DevicePort {
                        index: 8,
                        name: None,
                        profile: None,
                        native_vlan: Some(10),
                        uplink: false,
                        up: true,
                        management: true,
                    },
                ],
            }],
            links: vec![],
            clients: vec![ClientAttachment {
                mac: "00:00:5e:00:53:0a".parse().expect("mac"),
                ip: Some("192.0.2.3".parse().expect("ip")),
                device: DeviceRef("switch-a".to_owned()),
                port: Some(8),
                ssid: None,
                network: Some(NetworkRef("mgmt".to_owned())),
                vlan: Some(10),
                name: Some("controller.example.test".to_owned()),
                vendor: None,
                management: true,
            }],
            networks: vec![ControllerNetwork {
                id: NetworkRef("mgmt".to_owned()),
                name: "Management".to_owned(),
                vlan: Some(10),
                subnet: Some("192.0.2.0/24".parse().expect("net")),
                dhcp: ControllerDhcp::RelayTo(vec!["192.0.2.53".parse().expect("ip")]),
                management: true,
            }],
            profiles: vec![],
            wlans: vec![WirelessNetwork {
                id: "wlan-iot".to_owned(),
                ssid: "iot.example.net".to_owned(),
                network: Some(NetworkRef("iot".to_owned())),
                vlan: Some(30),
                enabled: true,
                access_points: vec![DeviceRef("ap-a".to_owned())],
            }],
        }
    }

    fn refused(result: Result<(), ConnectorError>) -> &'static str {
        match result {
            Err(ConnectorError::GuardrailRefused { rule }) => rule,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn uplinks_and_management_paths_are_refused() {
        let guardrails = Guardrails {
            protected: vec![
                ProtectedPath::Client {
                    mac: "00:00:5e:00:53:01".parse().expect("mac"),
                },
                ProtectedPath::Port {
                    device: DeviceRef("switch-a".to_owned()),
                    port: 5,
                },
            ],
            max_parallel: 10,
        };
        let topology = topology();
        let profile = ProfileRef("iot".to_owned());
        let port = |port| L2Change::SetPortProfile {
            device: DeviceRef("switch-a".to_owned()),
            port,
            profile: profile.clone(),
        };
        assert_eq!(
            refused(guardrails.check(&port(1), &topology)),
            "connect.guardrail.uplink"
        );
        assert_eq!(
            refused(guardrails.check(&port(5), &topology)),
            "connect.guardrail.protected_port"
        );
        assert!(guardrails.check(&port(6), &topology).is_ok());
        let tenko_host = L2Change::ClearClientVlan {
            mac: "00:00:5e:00:53:01".parse().expect("mac"),
        };
        assert_eq!(
            refused(guardrails.check(&tenko_host, &topology)),
            "connect.guardrail.protected_client"
        );
        let into_management = L2Change::SetClientVlan {
            mac: "00:00:5e:00:53:02".parse().expect("mac"),
            network: NetworkRef("mgmt".to_owned()),
        };
        assert_eq!(
            refused(guardrails.check(&into_management, &topology)),
            "connect.guardrail.protected_network"
        );
        let management_vlan = L2Change::EnsureNetwork {
            vlan: 10,
            name: "x".to_owned(),
            dhcp: ControllerDhcp::Disabled,
        };
        assert_eq!(
            refused(guardrails.check(&management_vlan, &topology)),
            "connect.guardrail.protected_vlan"
        );
    }

    #[test]
    fn the_management_port_and_the_management_client_are_refused() {
        let guardrails = Guardrails {
            protected: vec![],
            max_parallel: 10,
        };
        let topology = topology();
        let port = L2Change::SetPortProfile {
            device: DeviceRef("switch-a".to_owned()),
            port: 8,
            profile: ProfileRef("iot".to_owned()),
        };
        assert_eq!(
            refused(guardrails.check(&port, &topology)),
            "connect.guardrail.management_port"
        );
        let controller: MacAddr = "00:00:5e:00:53:0a".parse().expect("mac");
        let set = L2Change::SetClientVlan {
            mac: controller,
            network: NetworkRef("iot".to_owned()),
        };
        assert_eq!(
            refused(guardrails.check(&set, &topology)),
            "connect.guardrail.management_client"
        );
        let clear = L2Change::ClearClientVlan { mac: controller };
        assert_eq!(
            refused(guardrails.check(&clear, &topology)),
            "connect.guardrail.management_client"
        );
        let other = L2Change::SetClientVlan {
            mac: "00:00:5e:00:53:0b".parse().expect("mac"),
            network: NetworkRef("iot".to_owned()),
        };
        assert!(guardrails.check(&other, &topology).is_ok());
    }

    #[test]
    fn removing_a_management_network_or_a_protected_vlan_is_refused() {
        let guardrails = Guardrails {
            protected: vec![
                ProtectedPath::Vlan { vid: 40 },
                ProtectedPath::Network {
                    network: NetworkRef("lab".to_owned()),
                },
            ],
            max_parallel: 10,
        };
        let topology = topology();
        let remove = |network: &str, vlan| L2Change::RemoveNetwork {
            network: NetworkRef(network.to_owned()),
            vlan,
        };
        assert_eq!(
            refused(guardrails.check(&remove("mgmt", 10), &topology)),
            "connect.guardrail.protected_network"
        );
        assert_eq!(
            refused(guardrails.check(&remove("lab", 50), &topology)),
            "connect.guardrail.protected_network"
        );
        assert_eq!(
            refused(guardrails.check(&remove("other", 10), &topology)),
            "connect.guardrail.protected_vlan"
        );
        assert_eq!(
            refused(guardrails.check(&remove("guests", 40), &topology)),
            "connect.guardrail.protected_vlan"
        );
        assert!(guardrails.check(&remove("iot", 30), &topology).is_ok());
    }

    #[test]
    fn changes_and_topology_round_trip_through_cbor() {
        let change = L2Change::EnsureNetwork {
            vlan: 30,
            name: "IoT".to_owned(),
            dhcp: ControllerDhcp::RelayTo(vec!["2001:db8::53".parse().expect("ip")]),
        };
        assert_eq!(
            from_cbor::<L2Change>(&to_cbor(&change).expect("cbor")).expect("cbor"),
            change
        );
        let topology = topology();
        assert_eq!(
            from_cbor::<TopologySnapshot>(&to_cbor(&topology).expect("cbor")).expect("cbor"),
            topology
        );
        let json = serde_json::to_value(&change).expect("json");
        assert_eq!(json["type"], "ensure_network");
    }
}
