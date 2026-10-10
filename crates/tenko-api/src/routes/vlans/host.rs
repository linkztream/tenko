//! The network controllers of `tenko-ipam` over the connector host: [`HostControllers`]
//! implements [`NetworkControllers`] with the host's typed calls, so the host keeps its
//! policy for every write (guardrails, TGL-20, plan age, verification by planning again).
//!
//! The server wires it once the connector service runs:
//!
//! ```ignore
//! controllers.set(HostControllers::new(Arc::clone(connector_host)));
//! ```

// The port reports `CodedError`s, so the conversions that produce them return it as well.
#![allow(clippy::result_large_err)]

use std::{net::IpAddr, sync::Arc};

use tenko_connect::{
    Capability, ControllerDhcp, DeviceKind, Guardrails, L2Change, L2Plan, L2Receipt,
    TopologySnapshot, WriteMode,
    host::{ConnectorHost, HostError},
};
use tenko_core::{
    CodedError, ConnectorId, UserId,
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_ipam::vlan::controllers::{
    ControllerDevice, ControllerDeviceKind, ControllerInfo, ControllerNetwork, ControllerPort,
    ControllerTopology, ControllerWlan, DiffEntry, NetworkControllers, NetworkPlan, NetworkReceipt,
    NetworkSpec, PortFuture,
};

/// [`NetworkControllers`] over the connector host.
#[derive(Debug, Clone)]
pub struct HostControllers {
    host: Arc<ConnectorHost>,
    guardrails: Guardrails,
}

impl HostControllers {
    /// The controllers of `host` with the default guardrails: uplinks and management
    /// networks of the topology are always protected by the host.
    pub fn new(host: Arc<ConnectorHost>) -> Self {
        Self {
            host,
            guardrails: Guardrails::default(),
        }
    }

    /// The controllers of `host` with configured protected paths on top.
    pub fn with_guardrails(host: Arc<ConnectorHost>, guardrails: Guardrails) -> Self {
        Self { host, guardrails }
    }
}

fn coded(error: HostError) -> CodedError {
    error.into_coded()
}

fn codec(error: &tenko_core::codec::CodecError) -> CodedError {
    CodedError::internal(format!("a controller plan does not encode: {error}"))
}

/// The change that makes the controller have the network of `spec`.
pub fn change_of(spec: &NetworkSpec) -> L2Change {
    L2Change::EnsureNetwork {
        vlan: spec.vid,
        name: spec.name.clone(),
        dhcp: if spec.dhcp_relay.is_empty() {
            ControllerDhcp::Disabled
        } else {
            ControllerDhcp::RelayTo(spec.dhcp_relay.clone())
        },
    }
}

/// The plan IPAM sees, with the host's plan as its token.
///
/// # Errors
///
/// `sys.internal` when the plan does not encode.
pub fn plan_of(
    connector: ConnectorId,
    spec: &NetworkSpec,
    plan: &L2Plan,
) -> Result<NetworkPlan, CodedError> {
    Ok(NetworkPlan {
        connector,
        spec: spec.clone(),
        read_at: plan.read_at,
        fingerprint: plan.fingerprint.clone(),
        diff: plan
            .diff
            .iter()
            .map(|line| DiffEntry {
                path: line.path.clone(),
                before: line.before.clone(),
                after: line.after.clone(),
            })
            .collect(),
        warnings: plan.warnings.clone(),
        token: HexBytes(to_cbor(plan).map_err(|e| codec(&e))?.to_vec()),
    })
}

/// The receipt IPAM sees, with the host's receipt as its token.
///
/// # Errors
///
/// `sys.internal` when the receipt does not encode.
pub fn receipt_of(
    connector: ConnectorId,
    receipt: &L2Receipt,
) -> Result<NetworkReceipt, CodedError> {
    Ok(NetworkReceipt {
        connector,
        dry_run: receipt.mode == WriteMode::DryRun,
        applied_at: receipt.applied_at,
        verified: receipt.verified,
        undo_steps: receipt.undo.len(),
        token: HexBytes(to_cbor(receipt).map_err(|e| codec(&e))?.to_vec()),
    })
}

/// The devices, networks and wireless networks of a controller's topology.
pub fn topology_of(connector: ConnectorId, snapshot: &TopologySnapshot) -> ControllerTopology {
    ControllerTopology {
        connector,
        observed_at: snapshot.observed_at,
        devices: snapshot
            .devices
            .iter()
            .map(|device| ControllerDevice {
                id: device.id.0.clone(),
                name: device.name.clone(),
                model: device.model.clone(),
                mac: device.mac,
                ip: device.ip,
                kind: match device.kind {
                    DeviceKind::Switch => ControllerDeviceKind::Switch,
                    DeviceKind::AccessPoint => ControllerDeviceKind::AccessPoint,
                    DeviceKind::Gateway => ControllerDeviceKind::Gateway,
                    DeviceKind::Other => ControllerDeviceKind::Other,
                },
                ports: device
                    .ports
                    .iter()
                    .map(|port| ControllerPort {
                        index: port.index,
                        name: port.name.clone(),
                        native_vlan: port.native_vlan,
                        uplink: port.uplink,
                        up: port.up,
                    })
                    .collect(),
            })
            .collect(),
        networks: snapshot
            .networks
            .iter()
            .map(|network| ControllerNetwork {
                id: network.id.0.clone(),
                name: network.name.clone(),
                vlan: network.vlan,
                subnet: network.subnet,
                management: network.management,
            })
            .collect(),
        wlans: snapshot
            .wlans
            .iter()
            .map(|wlan| ControllerWlan {
                ssid: wlan.ssid.clone(),
                vlan: wlan.vlan,
                enabled: wlan.enabled,
                access_points: wlan.access_points.iter().map(|ap| ap.0.clone()).collect(),
            })
            .collect(),
    }
}

/// The relay targets of a controller's DHCP setting (empty when it is off or the controller
/// serves DHCP itself).
pub fn relays_of(dhcp: &ControllerDhcp) -> Vec<IpAddr> {
    match dhcp {
        ControllerDhcp::Disabled | ControllerDhcp::Server => Vec::new(),
        ControllerDhcp::RelayTo(targets) => targets.clone(),
    }
}

impl NetworkControllers for HostControllers {
    fn controllers(&self) -> PortFuture<'_, Vec<ControllerInfo>> {
        Box::pin(async move {
            let views = self.host.list(None).await.map_err(coded)?;
            Ok(views
                .into_iter()
                .filter(|view| view.capabilities.contains(&Capability::NetworkController))
                .map(|view| ControllerInfo {
                    id: view.instance.id,
                    name: view.instance.name,
                    plugin: view.instance.plugin,
                    enabled: view.instance.enabled,
                    writes_enabled: view.instance.writes_enabled,
                })
                .collect())
        })
    }

    fn plan_network<'a>(
        &'a self,
        connector: ConnectorId,
        spec: &'a NetworkSpec,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkPlan> {
        Box::pin(async move {
            let plan = self
                .host
                .plan_l2(connector, &change_of(spec), &self.guardrails, on_behalf_of)
                .await
                .map_err(coded)?;
            plan_of(connector, spec, &plan)
        })
    }

    fn apply_network<'a>(
        &'a self,
        plan: &'a NetworkPlan,
        dry_run: bool,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkReceipt> {
        Box::pin(async move {
            let l2: L2Plan = from_cbor(&plan.token.0).map_err(|e| codec(&e))?;
            let mode = if dry_run {
                WriteMode::DryRun
            } else {
                WriteMode::Apply
            };
            let receipt = self
                .host
                .apply_l2(plan.connector, &l2, mode, &self.guardrails, on_behalf_of)
                .await
                .map_err(coded)?;
            receipt_of(plan.connector, &receipt)
        })
    }

    fn revert_network<'a>(
        &'a self,
        receipt: &'a NetworkReceipt,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            let l2: L2Receipt = from_cbor(&receipt.token.0).map_err(|e| codec(&e))?;
            self.host
                .revert_l2(receipt.connector, &l2, on_behalf_of)
                .await
                .map_err(coded)
        })
    }

    fn topology(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerTopology> {
        Box::pin(async move {
            let snapshot = self
                .host
                .topology(connector, on_behalf_of)
                .await
                .map_err(coded)?;
            Ok(topology_of(connector, &snapshot))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, time::Duration};

    use tenko_connect::{
        DevicePort, DeviceRef, DiffLine, NetworkDevice, NetworkRef, WirelessNetwork,
        host::{
            HostConfig,
            launch::LaunchSpec,
            normalize::{DiscardSink, ObservationSink},
            registry::{Bundled, PluginRegistry},
            supervisor::SupervisorConfig,
        },
        sample,
    };
    use tenko_core::Timestamp;
    use tenko_store::{MemStore, Store};

    use super::*;

    fn spec(relay: bool) -> NetworkSpec {
        NetworkSpec {
            vid: 30,
            name: "IoT".to_owned(),
            dhcp_relay: if relay {
                vec!["192.0.2.53".parse().expect("ip")]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn a_network_spec_becomes_an_ensure_network_change() {
        let L2Change::EnsureNetwork { vlan, name, dhcp } = change_of(&spec(true)) else {
            panic!("an ensure-network change");
        };
        assert_eq!((vlan, name.as_str()), (30, "IoT"));
        assert_eq!(relays_of(&dhcp), spec(true).dhcp_relay);
        let L2Change::EnsureNetwork { dhcp, .. } = change_of(&spec(false)) else {
            panic!("an ensure-network change");
        };
        assert_eq!(dhcp, ControllerDhcp::Disabled);
    }

    #[test]
    fn plans_and_receipts_carry_the_host_shapes_as_tokens() {
        let connector = ConnectorId::generate();
        let at: Timestamp = "2026-10-10T12:00:00Z".parse().expect("time");
        let l2 = L2Plan {
            change: change_of(&spec(false)),
            read_at: at,
            fingerprint: "abc".to_owned(),
            diff: vec![DiffLine {
                path: "networks/iot/vlan".to_owned(),
                before: None,
                after: Some("30".to_owned()),
            }],
            warnings: vec!["DHCP relay is off".to_owned()],
        };
        let plan = plan_of(connector, &spec(false), &l2).expect("plan");
        assert_eq!(plan.diff[0].after.as_deref(), Some("30"));
        assert_eq!(plan.read_at, at);
        assert_eq!(from_cbor::<L2Plan>(&plan.token.0).expect("token"), l2);
        let l2_receipt = L2Receipt {
            plan: l2,
            mode: WriteMode::Apply,
            applied_at: at,
            verified: true,
            undo: vec![change_of(&spec(true))],
        };
        let receipt = receipt_of(connector, &l2_receipt).expect("receipt");
        assert!(!receipt.dry_run);
        assert_eq!(receipt.undo_steps, 1);
        assert_eq!(
            from_cbor::<L2Receipt>(&receipt.token.0).expect("token"),
            l2_receipt
        );
    }

    #[test]
    fn a_topology_snapshot_keeps_devices_ports_networks_and_ssids() {
        let connector = ConnectorId::generate();
        let snapshot = TopologySnapshot {
            observed_at: "2026-10-10T12:00:00Z".parse().expect("time"),
            devices: vec![NetworkDevice {
                id: DeviceRef("sw-1".to_owned()),
                name: "USW-24".to_owned(),
                model: Some("US24".to_owned()),
                mac: Some("00:00:5e:00:53:a2".parse().expect("mac")),
                ip: Some("192.0.2.2".parse().expect("ip")),
                kind: DeviceKind::Switch,
                ports: vec![DevicePort {
                    index: 1,
                    name: Some("Port 1".to_owned()),
                    profile: None,
                    native_vlan: Some(10),
                    uplink: true,
                    management: false,
                    up: true,
                }],
            }],
            links: Vec::new(),
            clients: Vec::new(),
            networks: vec![tenko_connect::ControllerNetwork {
                id: NetworkRef("net-iot".to_owned()),
                name: "IoT".to_owned(),
                vlan: Some(30),
                subnet: Some("198.51.100.0/24".parse().expect("net")),
                dhcp: ControllerDhcp::Disabled,
                management: false,
            }],
            profiles: Vec::new(),
            wlans: vec![WirelessNetwork {
                id: "wlan-1".to_owned(),
                ssid: "iot.example.test".to_owned(),
                network: Some(NetworkRef("net-iot".to_owned())),
                vlan: Some(30),
                enabled: true,
                access_points: vec![DeviceRef("ap-1".to_owned())],
            }],
        };
        let topology = topology_of(connector, &snapshot);
        assert_eq!(topology.devices[0].id, "sw-1");
        assert_eq!(topology.devices[0].kind, ControllerDeviceKind::Switch);
        assert!(topology.devices[0].ports[0].uplink);
        assert_eq!(topology.networks[0].id, "net-iot");
        assert_eq!(topology.wlans[0].access_points, ["ap-1"]);
    }

    /// A connector host whose only plugin is the sample inventory, which cannot start.
    fn host() -> Arc<ConnectorHost> {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let manifest = sample::manifest();
        let registry = PluginRegistry::new(
            vec![Bundled {
                manifest: manifest.clone(),
                launch: LaunchSpec {
                    expected: Some(manifest),
                    program: std::env::temp_dir().join("tenko-no-such-plugin-program"),
                    args: vec![OsString::from("--mode"), OsString::from("normal")],
                    cwd: None,
                    env: Vec::new(),
                },
            }],
            None,
        );
        ConnectorHost::new(
            store,
            None,
            registry,
            HostConfig {
                supervisor: SupervisorConfig::default(),
                start_wait: Duration::from_millis(100),
                schedule: false,
                ..HostConfig::default()
            },
            Arc::new(DiscardSink) as Arc<dyn ObservationSink>,
        )
    }

    #[tokio::test]
    async fn the_host_lists_only_network_controllers_and_passes_its_errors_on() {
        let controllers = HostControllers::new(host());
        assert_eq!(controllers.controllers().await.expect("list"), Vec::new());
        let error = controllers
            .plan_network(ConnectorId::generate(), &spec(false), None)
            .await
            .expect_err("no such instance on this node");
        assert_eq!(error.code, "connect.instance.disabled");
        let error = controllers
            .topology(ConnectorId::generate(), None)
            .await
            .expect_err("no such instance on this node");
        assert_eq!(error.code, "connect.instance.disabled");
    }
}
