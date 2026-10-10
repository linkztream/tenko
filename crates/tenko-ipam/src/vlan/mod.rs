//! VLANs and their networks on network controllers (IPAM-03, CONN-06, CONN-08, CONN-09,
//! TGL-20).
//!
//! VLANs are objects of the IPAM model (`tenko_core::ipam::Vlan`, table `ipam.vlans`, the
//! commands `CreateVlan` and `UpdateVlan`, unique per site), and a prefix names its VLAN
//! (`Prefix::vlan`). This module adds the synchronisation with the network:
//!
//! - [`controllers`]: the port to the network-controller connectors and the slot that
//!   holds it; [`memory`]: an in-memory controller for tests and demonstrations.
//! - [`provision`]: the VLAN provision job. A request names a new VLAN (or an existing
//!   one), optionally a network prefix for it, and how the network gets onto the switches
//!   and access points: through a network controller, or by hand.
//! - [`steps`]: the step handlers of that job.
//! - [`links`]: the prefixes of a VLAN.
//!
//! # The provision job
//!
//! | Step kind | Preview kind | Automatic | When |
//! |---|---|---|---|
//! | `ipam.vlan.intent` | `ipam.intent` | yes: the new VLAN and prefix, as `planned` | a new VLAN or a prefix |
//! | `ipam.vlan.controller` | `l2.network` | yes: plan (read back and diff), dry run, write, read back and diff again | a controller with writes allowed, or a network that exists as asked |
//! | `ipam.vlan.manual` | `l2.manual` | no: a person creates the network | no controller, writes off (TGL-20), several controllers and none named, or `manual` |
//! | `ipam.vlan.activate` | `activate` | yes: the new VLAN and prefix become `active` | with `ipam.vlan.intent` |
//!
//! The controller resolves like this: the connector the request names; else the only
//! enabled network-controller connector; with none the network step is manual
//! (`ipam.vlan.no_controller`), with several it is manual unless the request names one
//! (`ipam.vlan.controller_ambiguous`, a warning to acknowledge). A connector with writes
//! off gets a manual step with the planned diff shown (`ipam.vlan.controller_read_only`,
//! a warning to acknowledge). A plan that changes a network the controller already has
//! (another name on the VLAN) needs an acknowledgement (`ipam.vlan.network_changes`). The
//! guardrails of the connector host refuse the management VLAN (CONN-09): the preview and
//! the submit answer the refusal (409 `connect.guardrail.protected_vlan`), and
//! `manual: true` creates the VLAN in IPAM without touching the controller.
//!
//! The submit computes the preview again, refuses unacknowledged warnings and starts one
//! background job. The network step plans again when it runs and fails with
//! `ipam.vlan.controller_changed` when the diff is not the one the submit planned; after a
//! failure, a timeout or a cancel the engine compensates in reverse: the write is undone
//! with the receipt's undo steps (a person is asked when that fails), and the VLAN and
//! prefix the job created are soft-deleted. A job with a manual step waits for the person
//! at most 30 days.

pub mod controllers;
pub mod links;
pub mod memory;
pub mod provision;
pub mod steps;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    ConnectorId, JobId, PrefixId, SiteId, Timestamp, VlanId, VrfId,
    ipam::{Status, Tag},
};
use utoipa::ToSchema;

pub use controllers::{
    ControllerInfo, Controllers, DiffEntry, NetworkControllers, NetworkPlan, NetworkReceipt,
    NetworkSpec,
};
pub use steps::{register_steps, step_handlers};

use crate::plan::{PlanView, PlanWarning};

/// Job kind of a VLAN provision.
pub const PROVISION_JOB: &str = "ipam.vlan.provision";
/// Title of the job (a UI message key).
pub const PROVISION_TITLE: &str = "ipam.vlan.job.title";
/// Longest job with an automatic network step.
pub const AUTOMATIC_TIMEOUT_SECS: u64 = 3_600;
/// Longest job with a manual network step, waiting for the person included.
pub const MANUAL_TIMEOUT_SECS: u64 = 30 * 24 * 3_600;
/// Timeout of the network step (each controller call has its own as well).
pub const CONTROLLER_STEP_TIMEOUT_SECS: u64 = 600;
/// Provision jobs through one controller that run at once (CONN-09).
pub const CONTROLLER_PARALLELISM: u32 = 4;
/// Most DHCP relay targets.
pub const MAX_RELAYS: usize = 8;
/// Longest network name in characters.
pub const MAX_NETWORK_NAME: usize = 64;

/// Stable codes of VLAN provisioning.
pub mod codes {
    /// The request is malformed: neither or both of `vlan` and `create`, a bad network
    /// name, too many relays (400).
    pub const INVALID_REQUEST: &str = "ipam.vlan.invalid_request";
    /// The named connector is not a network controller this server knows (404).
    pub const CONTROLLER_UNKNOWN: &str = "ipam.vlan.controller_unknown";
    /// The named connector is disabled (409).
    pub const CONTROLLER_DISABLED: &str = "ipam.vlan.controller_disabled";
    /// The network controllers are not reachable from this server yet (503).
    pub const CONTROLLERS_UNAVAILABLE: &str = "ipam.vlan.controllers_unavailable";
    /// The controller changed between the submit and the network step (409).
    pub const CONTROLLER_CHANGED: &str = "ipam.vlan.controller_changed";
    /// Reason of a manual step: no network-controller connector is configured.
    pub const NO_CONTROLLER: &str = "ipam.vlan.no_controller";
    /// Reason of a manual step: the request asked for it.
    pub const MANUAL_REQUESTED: &str = "ipam.vlan.manual_requested";
    /// Warning and reason (needs acknowledgement): several controllers, none named.
    pub const CONTROLLER_AMBIGUOUS: &str = "ipam.vlan.controller_ambiguous";
    /// Warning and reason (needs acknowledgement): the controller does not allow writes.
    pub const CONTROLLER_READ_ONLY: &str = "ipam.vlan.controller_read_only";
    /// Warning (needs acknowledgement): the write changes a network the controller has.
    pub const NETWORK_CHANGES: &str = "ipam.vlan.network_changes";
}

/// A VLAN the job creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewVlan {
    /// VLAN id, 1 to 4094, unique per site.
    pub vid: u16,
    /// Name.
    pub name: String,
    /// Site; global when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
    /// VXLAN network identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<Tag>,
}

/// A network prefix the job creates for the VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewVlanPrefix {
    /// The network.
    #[schema(value_type = String, example = "198.51.100.0/24")]
    pub cidr: IpNet,
    /// VRF; the default VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfId>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A request to create a VLAN with its network (IPAM-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VlanProvisionRequest {
    /// An existing VLAN to put onto the network; absent when `create` describes a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// The VLAN to create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create: Option<NewVlan>,
    /// A network prefix to create for the VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<NewVlanPrefix>,
    /// The network-controller connector; the only one when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ConnectorId>,
    /// Leave the controller alone: a person creates the network.
    #[serde(default)]
    pub manual: bool,
    /// The network name on the controller; the VLAN name when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    /// DHCP relay targets of the network (Tenko serves DHCP); the controller's DHCP is off
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub dhcp_relay: Vec<IpAddr>,
    /// Warning codes the caller acknowledges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledge: Vec<String>,
}

/// The VLAN of a provision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanTarget {
    /// The VLAN (the identifier it will have when the job creates it).
    pub id: VlanId,
    /// The VLAN id.
    pub vid: u16,
    /// Its name.
    pub name: String,
    /// Its site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
    /// Whether it exists already.
    pub existing: bool,
    /// Its status now, or `planned` for a new one.
    pub status: Status,
}

/// The prefix of a provision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PrefixTarget {
    /// The identifier the prefix will have.
    pub id: PrefixId,
    /// The network.
    #[schema(value_type = String, example = "198.51.100.0/24")]
    pub cidr: IpNet,
    /// The VRF; the default VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfId>,
}

/// How the network gets onto the switches and access points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerMode {
    /// The controller writes it: dry run, write, read back.
    Automatic,
    /// The controller has it as asked; the job only checks.
    Unchanged,
    /// A person creates it.
    Manual,
}

/// The network step of a provision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ControllerPreview {
    /// How the network gets there.
    pub mode: ControllerMode,
    /// Why the step is manual (`ipam.vlan.no_controller`, `ipam.vlan.manual_requested`,
    /// `ipam.vlan.controller_ambiguous`, `ipam.vlan.controller_read_only`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ControllerInfo>,
    /// The network asked for.
    pub network: NetworkSpec,
    /// The read-back diff: what the write changes on the controller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<DiffEntry>,
    /// The controller's warnings, in English.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// When the controller was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<Timestamp>,
    /// The network controllers to choose from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ControllerInfo>,
}

/// One step of the job, as previewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanStepPreview {
    /// `ipam.intent`, `l2.network`, `l2.manual` or `activate`.
    pub kind: String,
    /// The engine's step kind (`ipam.vlan.intent`, ...).
    pub step_kind: String,
    /// Whether Tenko does it; otherwise a person ticks it off.
    pub automatic: bool,
    /// English description.
    pub text: String,
    /// Values for the text (VLAN id, name, network, connector).
    pub params: BTreeMap<String, String>,
}

/// The preview of a provision (the dry run, API-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanProvisionPreview {
    /// The VLAN.
    pub vlan: VlanTarget,
    /// The prefix the job creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<PrefixTarget>,
    /// The IPAM changes of the first step; absent when IPAM does not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanView>,
    /// The network step.
    pub controller: ControllerPreview,
    /// The steps of the job, in order.
    pub steps: Vec<VlanStepPreview>,
    /// Every warning: of the IPAM plan and of the network step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
    /// Warning codes that need an acknowledgement before a submit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unacknowledged: Vec<String>,
    /// The store revision the preview was computed at.
    pub base_revision: u64,
}

/// The answer of a submitted provision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanProvisionSubmitted {
    /// The job.
    pub job_id: JobId,
    /// The VLAN.
    pub vlan: VlanId,
    /// The prefix the job creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<PrefixId>,
    /// The preview as computed at submit, to compare with the dry run.
    pub preview: VlanProvisionPreview,
    /// Whether an earlier answer was returned for a repeated idempotency key.
    #[serde(default)]
    pub replayed: bool,
}
