//! The port through which IPAM reaches network controllers (CONN-05 to CONN-09).
//!
//! `tenko-ipam` does not depend on the connector crate: the server implements
//! [`NetworkControllers`] over the connector host (`tenko_api::routes::vlans::host`) and
//! hands it to [`Controllers`], a slot that the VLAN job steps and the topology read from.
//! The host keeps the policy of every write: the guardrails (uplinks and management
//! networks always, CONN-09), writes only when the instance allows them (TGL-20), plans
//! younger than its limit, and the verification after a write by planning the same change
//! again (CONN-08). This port carries the plans and receipts as opaque tokens next to the
//! parts IPAM shows (the diff, warnings, times), so nothing of the host's types leaks here.
//!
//! The move job (IPAM-19 step 4) uses the same port for the L2 change of a device:
//! [`attachments`](NetworkControllers::attachments) reads where the clients are attached,
//! [`check_attachment`](NetworkControllers::check_attachment) runs the guardrails against
//! that read, and [`plan_attachment`](NetworkControllers::plan_attachment) and
//! [`apply_attachment`](NetworkControllers::apply_attachment) change a port profile or a
//! per-client VLAN with the discipline of a network write; the receipt is undone with
//! [`revert_network`](NetworkControllers::revert_network) like any other.
//!
//! [`MemoryControllers`](super::memory::MemoryControllers) is an in-memory implementation
//! with the same discipline, for tests and demonstrations.

// The port reports `CodedError`s, so the guardrail checks return it as well.
#![allow(clippy::result_large_err)]

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};

use arc_swap::ArcSwapOption;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, ConnectorId, MacAddr, Timestamp, UserId, observe::Endpoint, serde_util::HexBytes,
};
use utoipa::ToSchema;

/// A connector instance that can act as a network controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ControllerInfo {
    /// The connector instance.
    pub id: ConnectorId,
    /// Its display name.
    pub name: String,
    /// The plugin, such as `unifi`.
    pub plugin: String,
    /// Whether the instance is enabled.
    pub enabled: bool,
    /// Whether writes through the instance are allowed (TGL-20).
    pub writes_enabled: bool,
}

/// The network Tenko asks a controller to have for a VLAN: the controller's DHCP off, or
/// relaying to the given servers (Tenko serves DHCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NetworkSpec {
    /// The VLAN id.
    pub vid: u16,
    /// The network name on the controller.
    pub name: String,
    /// DHCP relay targets; empty means the controller's DHCP is off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub dhcp_relay: Vec<IpAddr>,
}

/// One line of a read-back diff: what the controller has and what the change would set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiffEntry {
    /// What changes, for example `networks/iot/vlan`.
    pub path: String,
    /// The current value; absent when the item does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// The planned value; absent when the item goes away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// The plan of a network change: read back and diffed, nothing written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPlan {
    /// The controller.
    pub connector: ConnectorId,
    /// The change.
    pub spec: NetworkSpec,
    /// When the controller state was read.
    pub read_at: Timestamp,
    /// Fingerprint of the state the plan was made against.
    pub fingerprint: String,
    /// What would change; empty when the controller already has the network as asked.
    pub diff: Vec<DiffEntry>,
    /// English warnings of the plugin.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The plan as the implementation needs it back for the write (opaque).
    pub token: HexBytes,
}

/// What a write (or its dry run) did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkReceipt {
    /// The controller.
    pub connector: ConnectorId,
    /// Whether nothing was written.
    pub dry_run: bool,
    /// When the write happened.
    pub applied_at: Timestamp,
    /// Whether the read-back matched the plan.
    pub verified: bool,
    /// How many changes undo the write.
    pub undo_steps: usize,
    /// The receipt as the implementation needs it back to undo the write (opaque).
    pub token: HexBytes,
}

/// What a controller reports about its devices, networks and wireless networks, for the
/// topology (IPAM-20). Links and client attachments arrive as observations; this adds what
/// observations do not carry: names, kinds and port tables of the managed devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerTopology {
    /// The controller.
    pub connector: ConnectorId,
    /// When it was read.
    pub observed_at: Timestamp,
    /// Switches, access points and gateways.
    pub devices: Vec<ControllerDevice>,
    /// Networks.
    pub networks: Vec<ControllerNetwork>,
    /// Wireless networks.
    pub wlans: Vec<ControllerWlan>,
}

/// Kinds of managed devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerDeviceKind {
    /// A switch.
    Switch,
    /// A wireless access point.
    AccessPoint,
    /// A gateway or router.
    Gateway,
    /// Anything else.
    Other,
}

/// A managed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerDevice {
    /// The controller's reference, the device name in its attachments and links.
    pub id: String,
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
    pub kind: ControllerDeviceKind,
    /// Switch ports.
    #[serde(default)]
    pub ports: Vec<ControllerPort>,
}

/// A switch port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPort {
    /// The index as the controller numbers it, the port in its attachments.
    pub index: u16,
    /// The port name.
    #[serde(default)]
    pub name: Option<String>,
    /// The untagged VLAN.
    #[serde(default)]
    pub native_vlan: Option<u16>,
    /// Whether the port is an uplink.
    #[serde(default)]
    pub uplink: bool,
    /// Link state.
    #[serde(default)]
    pub up: bool,
}

/// A network on the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ControllerNetwork {
    /// The controller's reference (for UniFi the network `_id`, not the VLAN).
    pub id: String,
    /// Name.
    pub name: String,
    /// The VLAN id; absent for the untagged default network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// The gateway subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub subnet: Option<IpNet>,
    /// Whether Tenko or the controller is managed through this network (never written).
    #[serde(default)]
    pub management: bool,
}

/// A wireless network (SSID).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerWlan {
    /// The SSID.
    pub ssid: String,
    /// The VLAN it carries.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Whether it is broadcast.
    #[serde(default)]
    pub enabled: bool,
    /// The access points that broadcast it, by controller reference.
    #[serde(default)]
    pub access_points: Vec<String>,
}

/// A client as a network controller sees it: the switch port or access point it is
/// attached to and the network it is in (CONN-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerClient {
    /// The client.
    pub mac: MacAddr,
    /// Its address.
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// The switch or access point, by controller reference.
    pub device: String,
    /// The switch port of a wired client.
    #[serde(default)]
    pub port: Option<u16>,
    /// The wireless network of a wireless client.
    #[serde(default)]
    pub ssid: Option<String>,
    /// The network it is in, by controller reference.
    #[serde(default)]
    pub network: Option<String>,
    /// The VLAN it is in.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// The name on the controller.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether the client is the controller or Tenko's host (never written, CONN-09).
    #[serde(default)]
    pub management: bool,
}

/// A switch port with its profile and the flags of the guardrails (CONN-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPortState {
    /// The switch, by controller reference.
    pub device: String,
    /// The port index as the controller numbers it.
    pub index: u16,
    /// The port name.
    #[serde(default)]
    pub name: Option<String>,
    /// The assigned port profile, by controller reference.
    #[serde(default)]
    pub profile: Option<String>,
    /// The untagged VLAN.
    #[serde(default)]
    pub native_vlan: Option<u16>,
    /// Whether the port is an uplink (never written).
    #[serde(default)]
    pub uplink: bool,
    /// Whether Tenko or the controller is reached through the port (never written).
    #[serde(default)]
    pub management: bool,
    /// Link state.
    #[serde(default)]
    pub up: bool,
}

/// A port profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerProfile {
    /// The controller's reference.
    pub id: String,
    /// Name.
    pub name: String,
    /// The untagged network, by controller reference.
    #[serde(default)]
    pub native_network: Option<String>,
    /// The tagged networks, by controller reference.
    #[serde(default)]
    pub tagged: Vec<String>,
}

/// A link between two managed devices: an uplink or an LLDP neighbour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerLink {
    /// One end (device by controller reference, port index as text).
    pub a: Endpoint,
    /// The other end.
    pub b: Endpoint,
}

/// Where a controller's clients are attached, read fresh (never cached) for the move job
/// (IPAM-19 step 4): devices, switch ports with profiles and guardrail flags, clients,
/// networks, port profiles, wireless networks and the links between devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerAttachments {
    /// The controller.
    pub connector: ConnectorId,
    /// When it was read.
    pub observed_at: Timestamp,
    /// Switches, access points and gateways (names and kinds).
    #[serde(default)]
    pub devices: Vec<ControllerDevice>,
    /// Switch ports with their profiles and guardrail flags.
    #[serde(default)]
    pub ports: Vec<ControllerPortState>,
    /// Connected clients.
    #[serde(default)]
    pub clients: Vec<ControllerClient>,
    /// Networks.
    #[serde(default)]
    pub networks: Vec<ControllerNetwork>,
    /// Port profiles.
    #[serde(default)]
    pub profiles: Vec<ControllerProfile>,
    /// Wireless networks.
    #[serde(default)]
    pub wlans: Vec<ControllerWlan>,
    /// Links between devices.
    #[serde(default)]
    pub links: Vec<ControllerLink>,
}

impl ControllerAttachments {
    /// The connected client with this MAC address.
    pub fn client(&self, mac: MacAddr) -> Option<&ControllerClient> {
        self.clients.iter().find(|client| client.mac == mac)
    }

    /// A switch port.
    pub fn port(&self, device: &str, index: u16) -> Option<&ControllerPortState> {
        self.ports
            .iter()
            .find(|port| port.device == device && port.index == index)
    }

    /// A managed device.
    pub fn device(&self, id: &str) -> Option<&ControllerDevice> {
        self.devices.iter().find(|device| device.id == id)
    }

    /// A network by its reference.
    pub fn network(&self, id: &str) -> Option<&ControllerNetwork> {
        self.networks.iter().find(|network| network.id == id)
    }

    /// A port profile by its reference.
    pub fn profile(&self, id: &str) -> Option<&ControllerProfile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }

    /// The other clients on a switch port.
    pub fn others_on_port(&self, device: &str, index: u16, mac: MacAddr) -> usize {
        self.clients
            .iter()
            .filter(|c| c.mac != mac && c.device == device && c.port == Some(index))
            .count()
    }
}

/// A change of how a client is attached, the L2 step of a move (CONN-06): the port profile
/// of a switch port, or the per-client VLAN override of a client.
///
/// Adjacently tagged because variants carry MAC addresses (see `tenko_core::codec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum AttachmentChange {
    /// Give a switch port a port profile.
    SetPortProfile {
        /// The switch, by controller reference.
        device: String,
        /// The port index.
        port: u16,
        /// The profile, by controller reference.
        profile: String,
    },
    /// Put a client into a network with the per-client VLAN override.
    SetClientVlan {
        /// The client.
        mac: MacAddr,
        /// The network, by controller reference (for UniFi the network `_id`).
        network: String,
    },
    /// Remove a client's per-client VLAN override.
    ClearClientVlan {
        /// The client.
        mac: MacAddr,
    },
}

/// The plan of an attachment change: read back and diffed, nothing written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentPlan {
    /// The controller.
    pub connector: ConnectorId,
    /// The change.
    pub change: AttachmentChange,
    /// When the controller state was read.
    pub read_at: Timestamp,
    /// Fingerprint of the state the plan was made against.
    pub fingerprint: String,
    /// What would change; empty when the controller already has it.
    pub diff: Vec<DiffEntry>,
    /// English warnings of the plugin.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The plan as the implementation needs it back for the write (opaque).
    pub token: HexBytes,
}

/// Codes of the guardrails (CONN-09), as the connector host answers them.
pub mod guardrail {
    /// The port is an uplink.
    pub const UPLINK: &str = "connect.guardrail.uplink";
    /// Tenko or the controller is reached through the port.
    pub const MANAGEMENT_PORT: &str = "connect.guardrail.management_port";
    /// The client is the controller or Tenko's host.
    pub const MANAGEMENT_CLIENT: &str = "connect.guardrail.management_client";
    /// The network is a management network (or a configured protected one).
    pub const PROTECTED_NETWORK: &str = "connect.guardrail.protected_network";
}

fn refused(rule: &'static str, detail: String) -> CodedError {
    CodedError::new(rule, 409, detail).with_title("Refused by a guardrail")
}

/// The guardrails that hold for every controller, checked against what it reported:
/// uplinks, management ports, management clients and management networks are never
/// written (CONN-09). The connector host checks the same rules, plus configured protected
/// paths, before every plan and write.
///
/// # Errors
///
/// A 409 refusal with the code of the rule (`connect.guardrail.*`).
pub fn derived_guardrails(
    state: &ControllerAttachments,
    change: &AttachmentChange,
) -> Result<(), CodedError> {
    match change {
        AttachmentChange::SetPortProfile { device, port, .. } => {
            if let Some(state) = state.port(device, *port) {
                if state.uplink {
                    return Err(refused(
                        guardrail::UPLINK,
                        format!("port {port} of {device} is an uplink"),
                    ));
                }
                if state.management {
                    return Err(refused(
                        guardrail::MANAGEMENT_PORT,
                        format!(
                            "Tenko or the controller is reached through port {port} of {device}"
                        ),
                    ));
                }
            }
        }
        AttachmentChange::SetClientVlan { mac, network } => {
            if state.client(*mac).is_some_and(|c| c.management) {
                return Err(refused(
                    guardrail::MANAGEMENT_CLIENT,
                    format!("{mac} is the controller or Tenko's host"),
                ));
            }
            if state.network(network).is_some_and(|n| n.management) {
                return Err(refused(
                    guardrail::PROTECTED_NETWORK,
                    format!("network {network} is a management network"),
                ));
            }
        }
        AttachmentChange::ClearClientVlan { mac } => {
            if state.client(*mac).is_some_and(|c| c.management) {
                return Err(refused(
                    guardrail::MANAGEMENT_CLIENT,
                    format!("{mac} is the controller or Tenko's host"),
                ));
            }
        }
    }
    Ok(())
}

fn unsupported(what: &str) -> CodedError {
    CodedError::new(
        "connect.unsupported",
        501,
        format!("these network controllers cannot {what}"),
    )
}

/// The future a method of [`NetworkControllers`] returns.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CodedError>> + Send + 'a>>;

/// Network controllers as IPAM uses them. Errors are coded errors of the implementation
/// (`connect.*` codes of the host, such as `connect.guardrail.protected_vlan`,
/// `connect.writes_disabled`, `connect.verify_mismatch` or `connect.unreachable`).
///
/// The methods return boxed futures, so implementors need no macro crate:
/// `fn controllers(&self) -> PortFuture<'_, Vec<ControllerInfo>> { Box::pin(async move { ... }) }`.
pub trait NetworkControllers: Send + Sync + 'static {
    /// The connector instances whose plugin is a network controller; fails with the
    /// implementation's error.
    fn controllers(&self) -> PortFuture<'_, Vec<ControllerInfo>>;

    /// Reads the controller, checks the guardrails and diffs the network against `spec`.
    /// Writes nothing. Fails with a guardrail refusal, the controller's error or a call
    /// error.
    fn plan_network<'a>(
        &'a self,
        connector: ConnectorId,
        spec: &'a NetworkSpec,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkPlan>;

    /// Applies a plan: with `dry_run` the controller re-reads and validates without
    /// writing; otherwise it writes, and the result is verified by reading back. Fails with
    /// `connect.writes_disabled` for a write through a read-only instance,
    /// `connect.verify_mismatch` for a stale plan or a read-back that differs, a guardrail
    /// refusal, or a call error.
    fn apply_network<'a>(
        &'a self,
        plan: &'a NetworkPlan,
        dry_run: bool,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkReceipt>;

    /// Undoes a write with the undo steps of its receipt, a network write or an attachment
    /// change alike; on an error the job asks a person to undo it.
    fn revert_network<'a>(
        &'a self,
        receipt: &'a NetworkReceipt,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, ()>;

    /// The devices, networks and wireless networks of one controller.
    fn topology(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerTopology>;

    /// Where the clients of one controller are attached, read fresh. Without an
    /// implementation: `connect.unsupported`.
    fn attachments(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerAttachments> {
        let _ = (connector, on_behalf_of);
        Box::pin(std::future::ready(Err(unsupported("report attachments"))))
    }

    /// Checks an attachment change against the guardrails, with what
    /// [`attachments`](Self::attachments) read; nothing is called. The default checks the
    /// rules that hold for every controller ([`derived_guardrails`]); the connector host
    /// adds its configured protected paths.
    ///
    /// # Errors
    ///
    /// A 409 refusal with the code of the rule (`connect.guardrail.*`).
    fn check_attachment(
        &self,
        state: &ControllerAttachments,
        change: &AttachmentChange,
    ) -> Result<(), CodedError> {
        derived_guardrails(state, change)
    }

    /// Reads the controller, checks the guardrails and diffs the attachment against
    /// `change`. Writes nothing. Without an implementation: `connect.unsupported`.
    fn plan_attachment<'a>(
        &'a self,
        connector: ConnectorId,
        change: &'a AttachmentChange,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, AttachmentPlan> {
        let _ = (connector, change, on_behalf_of);
        Box::pin(std::future::ready(Err(unsupported("change attachments"))))
    }

    /// Applies an attachment plan like [`apply_network`](Self::apply_network): a dry run,
    /// or a write verified by reading back. The receipt is undone with
    /// [`revert_network`](Self::revert_network). Without an implementation:
    /// `connect.unsupported`.
    fn apply_attachment<'a>(
        &'a self,
        plan: &'a AttachmentPlan,
        dry_run: bool,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkReceipt> {
        let _ = (plan, dry_run, on_behalf_of);
        Box::pin(std::future::ready(Err(unsupported("change attachments"))))
    }
}

/// The slot that holds the network controllers once the server has started its connector
/// service. The VLAN steps are registered before the job runner starts and the connector
/// service starts after it, so the steps read the controllers from here when they run.
#[derive(Default)]
pub struct Controllers {
    inner: ArcSwapOption<Box<dyn NetworkControllers>>,
}

impl std::fmt::Debug for Controllers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controllers")
            .field("set", &self.inner.load().is_some())
            .finish()
    }
}

impl Controllers {
    /// An empty slot.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A slot holding `controllers`.
    pub fn with(controllers: impl NetworkControllers) -> Arc<Self> {
        let slot = Self::new();
        slot.set(controllers);
        slot
    }

    /// Fills (or replaces) the slot.
    pub fn set(&self, controllers: impl NetworkControllers) {
        self.inner.store(Some(Arc::new(Box::new(controllers))));
    }

    /// The controllers, once set.
    pub fn get(&self) -> Option<Arc<Box<dyn NetworkControllers>>> {
        self.inner.load_full()
    }
}
