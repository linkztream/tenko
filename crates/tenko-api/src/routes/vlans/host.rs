//! The network controllers of `tenko-ipam` over the connector host: [`HostControllers`]
//! implements [`NetworkControllers`] with the host's typed calls, so the host keeps its
//! policy for every write (guardrails, TGL-20, plan age, verification by planning again).
//! The VLAN provision job writes networks through it, and the move job port profiles and
//! per-client VLANs ([`attachment_change_of`]); the guardrails of an attachment change are
//! also checked against the read the move job planned from ([`guardrail_view_of`]), and the
//! undo steps of every receipt are checked against a fresh topology before a revert.
//!
//! The server wires it once the connector service runs:
//!
//! ```ignore
//! controllers.set(HostControllers::following(Arc::clone(connector_host), guardrails));
//! ```

// The port reports `CodedError`s, so the conversions that produce them return it as well.
#![allow(clippy::result_large_err)]

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
};

use tenko_connect::{
    Capability, ClientAttachment, ControllerDhcp, DeviceKind, DevicePort, DeviceRef, Guardrails,
    L2Change, L2Plan, L2Receipt, NetworkDevice, NetworkRef, ProfileRef, TopologySnapshot,
    WriteMode,
    host::{ConnectorHost, HostError},
};
use tenko_core::{
    CodedError, ConnectorId, UserId,
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_ipam::vlan::controllers::{
    AttachmentChange, AttachmentPlan, ControllerAttachments, ControllerClient, ControllerDevice,
    ControllerDeviceKind, ControllerInfo, ControllerLink, ControllerNetwork, ControllerPort,
    ControllerPortState, ControllerProfile, ControllerTopology, ControllerWlan, DiffEntry,
    NetworkControllers, NetworkPlan, NetworkReceipt, NetworkSpec, PortFuture,
};
use tokio::sync::{Notify, watch};

/// [`NetworkControllers`] over the connector host.
///
/// The guardrails are the ones in force (`connect.guardrails`, followed through a watch
/// channel when the server builds it with [`HostControllers::following`]), read at every
/// call. `max_parallel` bounds the concurrent real writes (applies and reverts, not dry
/// runs) through one controller instance; further writes wait for a free slot.
#[derive(Debug, Clone)]
pub struct HostControllers {
    host: Arc<ConnectorHost>,
    guardrails: watch::Receiver<Guardrails>,
    writes: Arc<WriteLimit>,
}

impl HostControllers {
    /// The controllers of `host` with the default guardrails: uplinks and management
    /// networks of the topology are always protected by the host.
    pub fn new(host: Arc<ConnectorHost>) -> Self {
        Self::with_guardrails(host, Guardrails::default())
    }

    /// The controllers of `host` with configured protected paths on top.
    pub fn with_guardrails(host: Arc<ConnectorHost>, guardrails: Guardrails) -> Self {
        Self::following(host, watch::channel(guardrails).1)
    }

    /// The controllers of `host` with the guardrails `guardrails` holds now, at every call
    /// (the server follows the settings in the store with it).
    pub fn following(host: Arc<ConnectorHost>, guardrails: watch::Receiver<Guardrails>) -> Self {
        Self {
            host,
            guardrails,
            writes: Arc::new(WriteLimit::default()),
        }
    }

    /// The guardrails in force.
    fn guardrails(&self) -> Guardrails {
        self.guardrails.borrow().clone()
    }

    /// The concurrent writes allowed through one controller.
    fn max_parallel(&self) -> usize {
        self.guardrails.borrow().max_parallel.max(1)
    }

    /// A slot for a real write through `connector`; none for a dry run.
    async fn write_slot(&self, connector: ConnectorId, dry_run: bool) -> Option<WriteSlot> {
        if dry_run {
            return None;
        }
        Some(self.writes.acquire(connector, self.max_parallel()).await)
    }
}

/// The writes in flight per controller instance.
#[derive(Debug, Default)]
struct WriteLimit {
    in_flight: Mutex<HashMap<ConnectorId, usize>>,
    released: Notify,
}

impl WriteLimit {
    /// Waits until fewer than `limit` writes run through `connector` and takes a slot.
    async fn acquire(self: &Arc<Self>, connector: ConnectorId, limit: usize) -> WriteSlot {
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            {
                let mut in_flight = self
                    .in_flight
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let count = in_flight.entry(connector).or_default();
                if *count < limit {
                    *count += 1;
                    return WriteSlot {
                        limit: Arc::clone(self),
                        connector,
                    };
                }
            }
            released.await;
        }
    }

    /// The writes running through `connector` now.
    #[cfg(test)]
    fn running(&self, connector: ConnectorId) -> usize {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&connector)
            .copied()
            .unwrap_or_default()
    }
}

/// A slot of [`WriteLimit`], given back when dropped.
struct WriteSlot {
    limit: Arc<WriteLimit>,
    connector: ConnectorId,
}

impl Drop for WriteSlot {
    fn drop(&mut self) {
        {
            let mut in_flight = self
                .limit
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = in_flight.get_mut(&self.connector) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    in_flight.remove(&self.connector);
                }
            }
        }
        self.limit.released.notify_waiters();
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

/// The change of the host for an attachment change of the move job.
pub fn attachment_change_of(change: &AttachmentChange) -> L2Change {
    match change {
        AttachmentChange::SetPortProfile {
            device,
            port,
            profile,
        } => L2Change::SetPortProfile {
            device: DeviceRef(device.clone()),
            port: *port,
            profile: ProfileRef(profile.clone()),
        },
        AttachmentChange::SetClientVlan { mac, network } => L2Change::SetClientVlan {
            mac: *mac,
            network: NetworkRef(network.clone()),
        },
        AttachmentChange::ClearClientVlan { mac } => L2Change::ClearClientVlan { mac: *mac },
    }
}

/// The attachment plan IPAM sees, with the host's plan as its token.
///
/// # Errors
///
/// `sys.internal` when the plan does not encode.
pub fn attachment_plan_of(
    connector: ConnectorId,
    change: &AttachmentChange,
    plan: &L2Plan,
) -> Result<AttachmentPlan, CodedError> {
    Ok(AttachmentPlan {
        connector,
        change: change.clone(),
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

/// Where the clients of a controller's topology are attached, for the move job.
pub fn attachments_of(
    connector: ConnectorId,
    snapshot: &TopologySnapshot,
) -> ControllerAttachments {
    let topology = topology_of(connector, snapshot);
    ControllerAttachments {
        connector,
        observed_at: snapshot.observed_at,
        ports: snapshot
            .devices
            .iter()
            .flat_map(|device| {
                device.ports.iter().map(|port| ControllerPortState {
                    device: device.id.0.clone(),
                    index: port.index,
                    name: port.name.clone(),
                    profile: port.profile.as_ref().map(|p| p.0.clone()),
                    native_vlan: port.native_vlan,
                    uplink: port.uplink,
                    management: port.management,
                    up: port.up,
                })
            })
            .collect(),
        clients: snapshot
            .clients
            .iter()
            .map(|client| ControllerClient {
                mac: client.mac,
                ip: client.ip,
                device: client.device.0.clone(),
                port: client.port,
                ssid: client.ssid.clone(),
                network: client.network.as_ref().map(|n| n.0.clone()),
                vlan: client.vlan,
                name: client.name.clone(),
                management: client.management,
            })
            .collect(),
        profiles: snapshot
            .profiles
            .iter()
            .map(|profile| ControllerProfile {
                id: profile.id.0.clone(),
                name: profile.name.clone(),
                native_network: profile.native_network.as_ref().map(|n| n.0.clone()),
                tagged: profile.tagged.iter().map(|n| n.0.clone()).collect(),
            })
            .collect(),
        links: snapshot
            .links
            .iter()
            .map(|link| ControllerLink {
                a: link.a.clone(),
                b: link.b.clone(),
            })
            .collect(),
        devices: topology.devices,
        networks: topology.networks,
        wlans: topology.wlans,
    }
}

/// The part of a topology the host's guardrails look at, rebuilt from what
/// [`attachments_of`] reported: ports with their flags, clients, networks.
pub fn guardrail_view_of(state: &ControllerAttachments) -> TopologySnapshot {
    let mut devices: Vec<NetworkDevice> = Vec::new();
    for port in &state.ports {
        let index = if let Some(index) = devices.iter().position(|d| d.id.0 == port.device) {
            index
        } else {
            let known = state.device(&port.device);
            devices.push(NetworkDevice {
                id: DeviceRef(port.device.clone()),
                name: known.map_or_else(|| port.device.clone(), |d| d.name.clone()),
                model: None,
                mac: known.and_then(|d| d.mac),
                ip: known.and_then(|d| d.ip),
                kind: DeviceKind::Switch,
                ports: Vec::new(),
            });
            devices.len() - 1
        };
        devices[index].ports.push(DevicePort {
            index: port.index,
            name: port.name.clone(),
            profile: port.profile.clone().map(ProfileRef),
            native_vlan: port.native_vlan,
            uplink: port.uplink,
            up: port.up,
            management: port.management,
        });
    }
    TopologySnapshot {
        observed_at: state.observed_at,
        devices,
        links: Vec::new(),
        clients: state
            .clients
            .iter()
            .map(|client| ClientAttachment {
                mac: client.mac,
                ip: client.ip,
                device: DeviceRef(client.device.clone()),
                port: client.port,
                ssid: client.ssid.clone(),
                network: client.network.clone().map(NetworkRef),
                vlan: client.vlan,
                name: client.name.clone(),
                vendor: None,
                management: client.management,
            })
            .collect(),
        networks: state
            .networks
            .iter()
            .map(|network| tenko_connect::ControllerNetwork {
                id: NetworkRef(network.id.clone()),
                name: network.name.clone(),
                vlan: network.vlan,
                subnet: network.subnet,
                // The guardrails do not look at DHCP.
                dhcp: ControllerDhcp::Disabled,
                management: network.management,
            })
            .collect(),
        profiles: Vec::new(),
        wlans: Vec::new(),
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
                .plan_l2(
                    connector,
                    &change_of(spec),
                    &self.guardrails(),
                    on_behalf_of,
                )
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
            let _slot = self.write_slot(plan.connector, dry_run).await;
            let receipt = self
                .host
                .apply_l2(plan.connector, &l2, mode, &self.guardrails(), on_behalf_of)
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
            // The host checks the undo steps against the guardrails in force and a fresh
            // topology before it writes (CONN-09).
            let _slot = self.write_slot(receipt.connector, false).await;
            self.host
                .revert_l2(receipt.connector, &l2, &self.guardrails(), on_behalf_of)
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

    fn attachments(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerAttachments> {
        Box::pin(async move {
            let snapshot = self
                .host
                .topology(connector, on_behalf_of)
                .await
                .map_err(coded)?;
            Ok(attachments_of(connector, &snapshot))
        })
    }

    fn check_attachment(
        &self,
        state: &ControllerAttachments,
        change: &AttachmentChange,
    ) -> Result<(), CodedError> {
        self.guardrails()
            .check(&attachment_change_of(change), &guardrail_view_of(state))
            .map_err(|error| coded(error.into()))
    }

    fn plan_attachment<'a>(
        &'a self,
        connector: ConnectorId,
        change: &'a AttachmentChange,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, AttachmentPlan> {
        Box::pin(async move {
            let plan = self
                .host
                .plan_l2(
                    connector,
                    &attachment_change_of(change),
                    &self.guardrails(),
                    on_behalf_of,
                )
                .await
                .map_err(coded)?;
            attachment_plan_of(connector, change, &plan)
        })
    }

    fn apply_attachment<'a>(
        &'a self,
        plan: &'a AttachmentPlan,
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
            let _slot = self.write_slot(plan.connector, dry_run).await;
            let receipt = self
                .host
                .apply_l2(plan.connector, &l2, mode, &self.guardrails(), on_behalf_of)
                .await
                .map_err(coded)?;
            receipt_of(plan.connector, &receipt)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, time::Duration};

    use tenko_connect::{
        ConnectorError, DevicePort, DeviceRef, DiffLine, NetworkDevice, NetworkRef, PortProfile,
        ProtectedPath, TopologyLink, WirelessNetwork,
        host::{
            HostConfig,
            launch::LaunchSpec,
            normalize::{DiscardSink, ObservationSink},
            registry::{Bundled, PluginRegistry},
            supervisor::SupervisorConfig,
        },
        sample,
    };
    use tenko_core::{
        MacAddr, Timestamp,
        observe::{Endpoint, LinkKind},
    };
    use tenko_ipam::vlan::controllers::derived_guardrails;
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

    // The attachments of the move job.

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, n])
    }

    fn at() -> Timestamp {
        "2026-10-10T12:00:00Z".parse().expect("time")
    }

    fn set_profile(port: u16) -> AttachmentChange {
        AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port,
            profile: "prof-iot".to_owned(),
        }
    }

    fn set_vlan(n: u8, network: &str) -> AttachmentChange {
        AttachmentChange::SetClientVlan {
            mac: mac(n),
            network: network.to_owned(),
        }
    }

    fn clear_vlan(n: u8) -> AttachmentChange {
        AttachmentChange::ClearClientVlan { mac: mac(n) }
    }

    fn device_ports() -> Vec<DevicePort> {
        vec![
            DevicePort {
                index: 1,
                name: Some("Port 1".to_owned()),
                profile: Some(ProfileRef("prof-home".to_owned())),
                native_vlan: Some(20),
                uplink: false,
                management: false,
                up: true,
            },
            DevicePort {
                index: 2,
                name: Some("Port 2".to_owned()),
                profile: None,
                native_vlan: None,
                uplink: false,
                management: false,
                up: false,
            },
            DevicePort {
                index: 3,
                name: Some("Uplink".to_owned()),
                profile: None,
                native_vlan: Some(1),
                uplink: true,
                management: false,
                up: true,
            },
            DevicePort {
                index: 4,
                name: Some("Controller".to_owned()),
                profile: None,
                native_vlan: Some(10),
                uplink: false,
                management: true,
                up: true,
            },
        ]
    }

    fn attachment(
        n: u8,
        device: &str,
        port: Option<u16>,
        ssid: Option<&str>,
        network: &str,
        vlan: u16,
    ) -> ClientAttachment {
        ClientAttachment {
            mac: mac(n),
            ip: None,
            device: DeviceRef(device.to_owned()),
            port,
            ssid: ssid.map(str::to_owned),
            network: Some(NetworkRef(network.to_owned())),
            vlan: Some(vlan),
            name: None,
            vendor: Some("Example Corp".to_owned()),
            management: false,
        }
    }

    fn host_network(
        id: &str,
        name: &str,
        vlan: u16,
        management: bool,
    ) -> tenko_connect::ControllerNetwork {
        tenko_connect::ControllerNetwork {
            id: NetworkRef(id.to_owned()),
            name: name.to_owned(),
            vlan: Some(vlan),
            subnet: None,
            dhcp: ControllerDhcp::Disabled,
            management,
        }
    }

    /// A switch with four ports (1 on the home profile, 2 down without a profile, 3 the
    /// uplink, 4 the management port), an access point linked to port 3, three clients (a
    /// wired one on port 1, a wireless one and the controller on port 4), three networks
    /// (the last one is the management network) and two profiles.
    fn attachment_snapshot() -> TopologySnapshot {
        TopologySnapshot {
            observed_at: at(),
            devices: vec![
                NetworkDevice {
                    id: DeviceRef("sw-1".to_owned()),
                    name: "USW-24".to_owned(),
                    model: Some("US24".to_owned()),
                    mac: Some(mac(0xa2)),
                    ip: Some("192.0.2.2".parse().expect("ip")),
                    kind: DeviceKind::Switch,
                    ports: device_ports(),
                },
                NetworkDevice {
                    id: DeviceRef("ap-1".to_owned()),
                    name: "AP-1".to_owned(),
                    model: None,
                    mac: None,
                    ip: None,
                    kind: DeviceKind::AccessPoint,
                    ports: Vec::new(),
                },
            ],
            links: vec![TopologyLink {
                a: Endpoint {
                    device: "ap-1".to_owned(),
                    port: None,
                },
                b: Endpoint {
                    device: "sw-1".to_owned(),
                    port: Some("3".to_owned()),
                },
                kind: LinkKind::Uplink,
            }],
            clients: vec![
                ClientAttachment {
                    ip: Some("198.51.100.20".parse().expect("ip")),
                    name: Some("nas.example.test".to_owned()),
                    ..attachment(1, "sw-1", Some(1), None, "net-home", 20)
                },
                attachment(2, "ap-1", None, Some("home.example.test"), "net-home", 20),
                ClientAttachment {
                    ip: Some("192.0.2.3".parse().expect("ip")),
                    name: Some("controller.example.test".to_owned()),
                    management: true,
                    ..attachment(3, "sw-1", Some(4), None, "net-mgmt", 10)
                },
            ],
            networks: vec![
                host_network("net-home", "Home", 20, false),
                host_network("net-iot", "IoT", 30, false),
                host_network("net-mgmt", "Management", 10, true),
            ],
            profiles: vec![
                PortProfile {
                    id: ProfileRef("prof-home".to_owned()),
                    name: "Home".to_owned(),
                    native_network: Some(NetworkRef("net-home".to_owned())),
                    tagged: Vec::new(),
                },
                PortProfile {
                    id: ProfileRef("prof-trunk".to_owned()),
                    name: "Trunk".to_owned(),
                    native_network: Some(NetworkRef("net-iot".to_owned())),
                    tagged: vec![
                        NetworkRef("net-home".to_owned()),
                        NetworkRef("net-mgmt".to_owned()),
                    ],
                },
            ],
            wlans: vec![WirelessNetwork {
                id: "wlan-1".to_owned(),
                ssid: "iot.example.test".to_owned(),
                network: Some(NetworkRef("net-iot".to_owned())),
                vlan: Some(30),
                enabled: true,
                access_points: vec![DeviceRef("ap-1".to_owned())],
            }],
        }
    }

    fn state_of_snapshot() -> ControllerAttachments {
        attachments_of(ConnectorId::generate(), &attachment_snapshot())
    }

    #[test]
    fn an_attachment_change_becomes_the_hosts_change() {
        assert_eq!(
            attachment_change_of(&set_profile(7)),
            L2Change::SetPortProfile {
                device: DeviceRef("sw-1".to_owned()),
                port: 7,
                profile: ProfileRef("prof-iot".to_owned()),
            }
        );
        assert_eq!(
            attachment_change_of(&set_vlan(3, "net-iot")),
            L2Change::SetClientVlan {
                mac: mac(3),
                network: NetworkRef("net-iot".to_owned()),
            }
        );
        assert_eq!(
            attachment_change_of(&clear_vlan(3)),
            L2Change::ClearClientVlan { mac: mac(3) }
        );
    }

    #[test]
    fn the_attachments_keep_the_ports_with_profile_uplink_and_management_flags() {
        let connector = ConnectorId::generate();
        let state = attachments_of(connector, &attachment_snapshot());
        assert_eq!(state.connector, connector);
        assert_eq!(state.observed_at, at());
        let port =
            |index, name: &str, profile: Option<&str>, native_vlan, flags: (bool, bool, bool)| {
                ControllerPortState {
                    device: "sw-1".to_owned(),
                    index,
                    name: Some(name.to_owned()),
                    profile: profile.map(str::to_owned),
                    native_vlan,
                    uplink: flags.0,
                    management: flags.1,
                    up: flags.2,
                }
            };
        assert_eq!(
            state.ports,
            vec![
                port(
                    1,
                    "Port 1",
                    Some("prof-home"),
                    Some(20),
                    (false, false, true)
                ),
                port(2, "Port 2", None, None, (false, false, false)),
                port(3, "Uplink", None, Some(1), (true, false, true)),
                port(4, "Controller", None, Some(10), (false, true, true)),
            ]
        );
    }

    #[test]
    fn the_attachments_keep_the_clients_with_port_ssid_network_vlan_and_management() {
        let state = state_of_snapshot();
        let client =
            |n, ip: Option<&str>, device: &str, port, ssid: Option<&str>| ControllerClient {
                mac: mac(n),
                ip: ip.map(|ip| ip.parse().expect("ip")),
                device: device.to_owned(),
                port,
                ssid: ssid.map(str::to_owned),
                network: None,
                vlan: None,
                name: None,
                management: false,
            };
        assert_eq!(
            state.clients,
            vec![
                ControllerClient {
                    network: Some("net-home".to_owned()),
                    vlan: Some(20),
                    name: Some("nas.example.test".to_owned()),
                    ..client(1, Some("198.51.100.20"), "sw-1", Some(1), None)
                },
                ControllerClient {
                    network: Some("net-home".to_owned()),
                    vlan: Some(20),
                    ..client(2, None, "ap-1", None, Some("home.example.test"))
                },
                ControllerClient {
                    network: Some("net-mgmt".to_owned()),
                    vlan: Some(10),
                    name: Some("controller.example.test".to_owned()),
                    management: true,
                    ..client(3, Some("192.0.2.3"), "sw-1", Some(4), None)
                },
            ]
        );
    }

    #[test]
    fn the_attachments_keep_the_profiles_the_links_and_the_topology() {
        let connector = ConnectorId::generate();
        let snapshot = attachment_snapshot();
        let state = attachments_of(connector, &snapshot);
        assert_eq!(
            state.profiles,
            vec![
                ControllerProfile {
                    id: "prof-home".to_owned(),
                    name: "Home".to_owned(),
                    native_network: Some("net-home".to_owned()),
                    tagged: Vec::new(),
                },
                ControllerProfile {
                    id: "prof-trunk".to_owned(),
                    name: "Trunk".to_owned(),
                    native_network: Some("net-iot".to_owned()),
                    tagged: vec!["net-home".to_owned(), "net-mgmt".to_owned()],
                },
            ]
        );
        assert_eq!(
            state.links,
            vec![ControllerLink {
                a: Endpoint {
                    device: "ap-1".to_owned(),
                    port: None,
                },
                b: Endpoint {
                    device: "sw-1".to_owned(),
                    port: Some("3".to_owned()),
                },
            }]
        );
        // Devices, networks and wireless networks are those of the topology.
        let topology = topology_of(connector, &snapshot);
        assert_eq!(state.devices, topology.devices);
        assert_eq!(state.networks, topology.networks);
        assert_eq!(state.wlans, topology.wlans);
        assert_eq!(state.device("ap-1").map(|d| d.name.as_str()), Some("AP-1"));
        assert_eq!(
            state.device("ap-1").map(|d| d.kind),
            Some(ControllerDeviceKind::AccessPoint)
        );
        let networks: Vec<(&str, Option<u16>, bool)> = state
            .networks
            .iter()
            .map(|n| (n.id.as_str(), n.vlan, n.management))
            .collect();
        assert_eq!(
            networks,
            [
                ("net-home", Some(20), false),
                ("net-iot", Some(30), false),
                ("net-mgmt", Some(10), true)
            ]
        );
        assert_eq!(state.wlans[0].access_points, ["ap-1"]);
    }

    #[test]
    fn the_guardrail_view_keeps_the_ports_clients_and_networks_the_rules_look_at() {
        let snapshot = attachment_snapshot();
        let view = guardrail_view_of(&attachments_of(ConnectorId::generate(), &snapshot));
        assert_eq!(view.observed_at, at());
        // Only the switch has ports to protect.
        assert_eq!(view.devices.len(), 1);
        let switch = &view.devices[0];
        assert_eq!(switch.id, DeviceRef("sw-1".to_owned()));
        assert_eq!(switch.name, "USW-24");
        assert_eq!(switch.mac, Some(mac(0xa2)));
        assert_eq!(switch.ip, Some("192.0.2.2".parse().expect("ip")));
        assert_eq!(switch.ports, device_ports());
        let clients: Vec<_> = view
            .clients
            .iter()
            .map(|c| (c.mac, c.device.0.as_str(), c.port, c.management))
            .collect();
        assert_eq!(
            clients,
            [
                (mac(1), "sw-1", Some(1), false),
                (mac(2), "ap-1", None, false),
                (mac(3), "sw-1", Some(4), true)
            ]
        );
        let networks: Vec<_> = view
            .networks
            .iter()
            .map(|n| (n.id.0.as_str(), n.management))
            .collect();
        assert_eq!(
            networks,
            [("net-home", false), ("net-iot", false), ("net-mgmt", true)]
        );
        assert_eq!(view.links, Vec::new());
        assert_eq!(view.profiles, Vec::new());
        assert_eq!(view.wlans, Vec::new());
    }

    /// The rule through which the host's guardrails refuse `change`, if one does.
    fn host_rule(
        guardrails: &Guardrails,
        state: &ControllerAttachments,
        change: &AttachmentChange,
    ) -> Option<&'static str> {
        match guardrails.check(&attachment_change_of(change), &guardrail_view_of(state)) {
            Ok(()) => None,
            Err(ConnectorError::GuardrailRefused { rule }) => Some(rule),
            Err(other) => panic!("a guardrail refusal was expected, not {other:?}"),
        }
    }

    #[test]
    fn the_hosts_guardrails_refuse_the_same_cases_as_the_derived_rules() {
        let state = state_of_snapshot();
        let guardrails = Guardrails::default();
        for (change, rule) in [
            (set_profile(3), "connect.guardrail.uplink"),
            (set_profile(4), "connect.guardrail.management_port"),
            (
                set_vlan(3, "net-iot"),
                "connect.guardrail.management_client",
            ),
            (clear_vlan(3), "connect.guardrail.management_client"),
            (
                set_vlan(1, "net-mgmt"),
                "connect.guardrail.protected_network",
            ),
        ] {
            assert_eq!(
                host_rule(&guardrails, &state, &change),
                Some(rule),
                "{change:?}"
            );
            let derived = derived_guardrails(&state, &change).expect_err("refused as well");
            assert_eq!(derived.code, rule, "{change:?}");
        }
        for change in [
            set_profile(1),
            set_profile(2),
            set_vlan(2, "net-iot"),
            clear_vlan(2),
        ] {
            assert_eq!(host_rule(&guardrails, &state, &change), None, "{change:?}");
            assert_eq!(derived_guardrails(&state, &change), Ok(()), "{change:?}");
        }
    }

    #[test]
    fn configured_protected_paths_refuse_what_the_derived_rules_allow() {
        let state = state_of_snapshot();
        let guardrails = Guardrails {
            protected: vec![
                ProtectedPath::Port {
                    device: DeviceRef("sw-1".to_owned()),
                    port: 1,
                },
                ProtectedPath::Client { mac: mac(2) },
                ProtectedPath::Network {
                    network: NetworkRef("net-iot".to_owned()),
                },
            ],
            max_parallel: 10,
        };
        for (change, rule) in [
            (set_profile(1), "connect.guardrail.protected_port"),
            (
                set_vlan(2, "net-home"),
                "connect.guardrail.protected_client",
            ),
            (clear_vlan(2), "connect.guardrail.protected_client"),
            (
                set_vlan(1, "net-iot"),
                "connect.guardrail.protected_network",
            ),
        ] {
            assert_eq!(
                host_rule(&guardrails, &state, &change),
                Some(rule),
                "{change:?}"
            );
            assert_eq!(derived_guardrails(&state, &change), Ok(()), "{change:?}");
        }
        // The derived rules still hold, and what is not protected passes.
        assert_eq!(
            host_rule(&guardrails, &state, &set_profile(3)),
            Some("connect.guardrail.uplink")
        );
        assert_eq!(host_rule(&guardrails, &state, &set_profile(2)), None);
        assert_eq!(
            host_rule(&guardrails, &state, &set_vlan(1, "net-home")),
            None
        );
    }

    #[test]
    fn check_attachment_answers_with_the_coded_error_of_the_rule() {
        let state = state_of_snapshot();
        let protected = HostControllers::with_guardrails(
            host(),
            Guardrails {
                protected: vec![
                    ProtectedPath::Port {
                        device: DeviceRef("sw-1".to_owned()),
                        port: 1,
                    },
                    ProtectedPath::Client { mac: mac(2) },
                ],
                max_parallel: 10,
            },
        );
        let error = protected
            .check_attachment(&state, &set_profile(1))
            .expect_err("protected port");
        assert_eq!(error.code, "connect.guardrail.protected_port");
        assert_eq!(error.status, 409);
        let error = protected
            .check_attachment(&state, &set_vlan(2, "net-iot"))
            .expect_err("protected client");
        assert_eq!(error.code, "connect.guardrail.protected_client");
        assert_eq!(protected.check_attachment(&state, &set_profile(2)), Ok(()));

        // Without configured paths only the derived rules hold.
        let plain = HostControllers::new(host());
        assert_eq!(plain.check_attachment(&state, &set_profile(1)), Ok(()));
        let error = plain
            .check_attachment(&state, &set_profile(3))
            .expect_err("uplink");
        assert_eq!(error.code, "connect.guardrail.uplink");
        assert_eq!(error.status, 409);
    }

    #[tokio::test]
    async fn a_port_protected_in_the_settings_is_refused_to_the_next_move() {
        let state = state_of_snapshot();
        let (settings, guardrails) = tokio::sync::watch::channel(Guardrails::default());
        let controllers = HostControllers::following(host(), guardrails);
        // The move job checks its port change with `check_attachment` before it plans.
        assert_eq!(
            controllers.check_attachment(&state, &set_profile(1)),
            Ok(())
        );
        settings
            .send(Guardrails {
                protected: vec![ProtectedPath::Port {
                    device: DeviceRef("sw-1".to_owned()),
                    port: 1,
                }],
                max_parallel: 10,
            })
            .expect("settings");
        let error = controllers
            .check_attachment(&state, &set_profile(1))
            .expect_err("protected port");
        assert_eq!(error.code, "connect.guardrail.protected_port");
        assert_eq!(error.status, 409);
        assert_eq!(
            controllers.check_attachment(&state, &set_profile(2)),
            Ok(())
        );
    }

    #[tokio::test]
    async fn max_parallel_bounds_the_writes_through_one_controller() {
        let (settings, guardrails) = tokio::sync::watch::channel(Guardrails {
            protected: Vec::new(),
            max_parallel: 2,
        });
        let controllers = HostControllers::following(host(), guardrails);
        let (one, other) = (ConnectorId::generate(), ConnectorId::generate());
        let first = controllers.write_slot(one, false).await;
        let second = controllers.write_slot(one, false).await;
        assert!(
            controllers.write_slot(one, true).await.is_none(),
            "a dry run takes no slot"
        );
        assert_eq!(controllers.writes.running(one), 2);
        // Another controller has slots of its own.
        let elsewhere = controllers.write_slot(other, false).await;
        assert_eq!(controllers.writes.running(other), 1);
        // A third write through the same controller waits for a free slot.
        let waiting = {
            let controllers = controllers.clone();
            tokio::spawn(async move { controllers.write_slot(one, false).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("a slot was freed")
            .expect("task");
        assert_eq!(controllers.writes.running(one), 2);
        // A higher limit in the settings applies to the next write at once.
        settings
            .send(Guardrails {
                protected: Vec::new(),
                max_parallel: 3,
            })
            .expect("settings");
        let fourth =
            tokio::time::timeout(Duration::from_secs(5), controllers.write_slot(one, false))
                .await
                .expect("the third slot");
        assert_eq!(controllers.writes.running(one), 3);
        drop((second, third, fourth, elsewhere));
        assert_eq!(controllers.writes.running(one), 0);
        assert_eq!(controllers.writes.running(other), 0);
    }

    #[test]
    fn an_attachment_plan_keeps_the_diff_and_the_hosts_plan_as_its_token() {
        let connector = ConnectorId::generate();
        let change = set_profile(1);
        let l2 = L2Plan {
            change: attachment_change_of(&change),
            read_at: at(),
            fingerprint: "abc".to_owned(),
            diff: vec![DiffLine {
                path: "devices/sw-1/ports/1/profile".to_owned(),
                before: Some("Home".to_owned()),
                after: Some("IoT".to_owned()),
            }],
            warnings: vec!["the link drops for a moment".to_owned()],
        };
        let plan = attachment_plan_of(connector, &change, &l2).expect("plan");
        assert_eq!(plan.connector, connector);
        assert_eq!(plan.change, change);
        assert_eq!(plan.read_at, at());
        assert_eq!(plan.fingerprint, "abc");
        assert_eq!(
            plan.diff,
            vec![DiffEntry {
                path: "devices/sw-1/ports/1/profile".to_owned(),
                before: Some("Home".to_owned()),
                after: Some("IoT".to_owned()),
            }]
        );
        assert_eq!(plan.warnings, ["the link drops for a moment"]);
        assert_eq!(from_cbor::<L2Plan>(&plan.token.0).expect("token"), l2);
    }

    #[test]
    fn a_client_plan_without_a_diff_round_trips_through_its_token() {
        let connector = ConnectorId::generate();
        let change = set_vlan(2, "net-iot");
        let l2 = L2Plan {
            change: attachment_change_of(&change),
            read_at: at(),
            fingerprint: "def".to_owned(),
            diff: Vec::new(),
            warnings: Vec::new(),
        };
        let plan = attachment_plan_of(connector, &change, &l2).expect("plan");
        assert_eq!(plan.diff, Vec::new());
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_eq!(plan.change, change);
        let back: L2Plan = from_cbor(&plan.token.0).expect("token");
        assert_eq!(back, l2);
        assert_eq!(
            back.change,
            L2Change::SetClientVlan {
                mac: mac(2),
                network: NetworkRef("net-iot".to_owned()),
            }
        );
    }
}
