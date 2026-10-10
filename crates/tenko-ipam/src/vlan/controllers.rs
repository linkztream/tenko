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
//! [`MemoryControllers`](super::memory::MemoryControllers) is an in-memory implementation
//! with the same discipline, for tests and demonstrations.

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};

use arc_swap::ArcSwapOption;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{CodedError, ConnectorId, MacAddr, Timestamp, UserId, serde_util::HexBytes};
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

    /// Undoes a write with the undo steps of its receipt; on an error the job asks a person
    /// to undo it.
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
