//! Moving hosts and addresses to another network (IPAM-19, design decisions 5 to 8).
//!
//! A move request names hosts or addresses and a target network prefix. The service
//! computes a [`MovePreview`] from a read view (the dry run), and a submit computes it
//! again and starts one background job per moved address, all in one job group, so the
//! runner's group limit bounds how many devices are between "moved" and "confirmed".
//!
//! # What moves
//!
//! - An **address** moves itself. It must be in the target's address family and not
//!   already inside the target prefix (`ipam.move.already_in_target`).
//! - A **host** moves every live address on its live interfaces that is in the target's
//!   address family and not already inside the target prefix, each as its own item and
//!   job. Addresses of the other family stay. A host without such an address is refused
//!   (`ipam.move.nothing_to_move`).
//! - `unmanaged` hosts are refused (422 `ipam.move.unmanaged`) and locked hosts too (423
//!   `ipam.host.locked`): a move drives other systems, which a lock forbids.
//!
//! # The new address
//!
//! The same host part relative to the target's prefix length (the low bits of the old
//! address under the target's host mask) when it is inside the target's assignable space,
//! outside every range of the target and not used; otherwise the next free address by the
//! target's allocation policy, and `same_host_part` is `false` with a reason
//! (`ipam.move.host_part_outside`, `ipam.move.host_part_reserved`,
//! `ipam.move.host_part_taken`). Items of one move never get the same address.
//!
//! # The job of one address
//!
//! | Step kind | Preview kind | Automatic | When |
//! |---|---|---|---|
//! | `ipam.move.intent` | `ipam.intent` | yes: the new address as planned intent on the interface; the old one stays | always |
//! | `ipam.move.dhcp` | `dhcp.manual` | no (Tenko DHCP from Phase 3): the reservation | `reserved` hosts |
//! | `ipam.move.dns` | `dns.manual` | no (Tenko DNS from Phase 2): A or AAAA and PTR | a DNS name |
//! | `ipam.move.device` | `device.manual` | no: reconfigure the device | `static` hosts |
//! | `ipam.move.l2` | `l2.move` | no in Slice 1 (the network controller from Slice 2) | always |
//! | `ipam.move.observe` | `observe` | no in Slice 1 (observations later); the timeout runs from its start | always |
//! | `ipam.move.cleanup` | `cleanup` | yes: remove the old address, activate the new one | always |
//!
//! The manual tasks come before the L2 change: a device waits for its ticked tasks before
//! it moves (IPAM-19, design decision 7). `dynamic` hosts get neither DHCP nor device tasks.
//!
//! # Timeout and rollback
//!
//! The observation timeout defaults to half the longest DHCP lease of the target's pools
//! (the renewal point), else 3,600 s, never below 300 s; a request may set it from 300 s
//! to 604,800 s. When the observe step passes its deadline, or any step fails, the engine
//! compensates in reverse: the intent step's compensation removes the new address,
//! restores the old one if needed and tags the requested object `move-failed`; the job
//! ends `rolled_back` with the reason in its error. The tag goes away with the next
//! successful move of the object. Manual steps carry no undo task, so a rollback never
//! waits for a person; the failure tells what may need putting back.

mod preview;
mod steps;
mod submit;

use std::{collections::BTreeMap, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, HostId, InterfaceId, JobId, MacAddr, ObjectRef, PrefixId, VlanId, VrfId,
    ipam::AssignmentMode,
    net::{Fqdn, HostName},
};
use utoipa::ToSchema;

pub use preview::preview;
pub use steps::{
    MoveCleanupStep, MoveIntentStep, MoveManualStep, MoveStepParams, move_step_handlers,
};
pub use submit::MoveReceipt;

use crate::plan::PlanWarning;

/// Job kind of a move.
pub const MOVE_JOB: &str = "ipam.move";
/// Tag that marks an object whose last move rolled back.
pub const MOVE_FAILED_TAG: &str = "move-failed";
/// Longest job of a move, waiting for people included; past it the job rolls back.
pub const JOB_TIMEOUT_SECS: u64 = 7 * 24 * 3600;
/// Shortest observation timeout.
pub const MIN_TIMEOUT_SECS: u32 = 300;
/// Longest observation timeout a request may ask for.
pub const MAX_TIMEOUT_SECS: u32 = 604_800;
/// Observation timeout without a lease time on the target.
pub const DEFAULT_TIMEOUT_SECS: u32 = 3_600;
/// Most objects in one request.
pub const MAX_OBJECTS: usize = 1_000;

/// Stable codes of moves.
pub mod codes {
    /// A host with `unmanaged` assignment mode (422).
    pub const UNMANAGED: &str = "ipam.move.unmanaged";
    /// Nothing of the requested host needs to move (422).
    pub const NOTHING_TO_MOVE: &str = "ipam.move.nothing_to_move";
    /// The address is inside the target already (422).
    pub const ALREADY_IN_TARGET: &str = "ipam.move.already_in_target";
    /// The address is of another family than the target (422).
    pub const FAMILY_MISMATCH: &str = "ipam.move.family_mismatch";
    /// The object is neither a host nor an address (422).
    pub const UNSUPPORTED_OBJECT: &str = "ipam.move.unsupported_object";
    /// The target is a supernet (422).
    pub const TARGET_NOT_NETWORK: &str = "ipam.move.target_not_network";
    /// The request is empty, too large or has a duplicate (400).
    pub const INVALID_REQUEST: &str = "ipam.move.invalid_request";
    /// Background jobs need the job engine (503).
    pub const NO_ENGINE: &str = "ipam.move.no_engine";
    /// Reason: the same host part lies outside the target's assignable space.
    pub const HOST_PART_OUTSIDE: &str = "ipam.move.host_part_outside";
    /// Reason: the same host part lies in a range of the target.
    pub const HOST_PART_RESERVED: &str = "ipam.move.host_part_reserved";
    /// Reason: the same host part is used already.
    pub const HOST_PART_TAKEN: &str = "ipam.move.host_part_taken";
    /// Warning (needs acknowledgement): another object in the target VRF has the DNS name.
    pub const DNS_COLLISION: &str = "ipam.move.dns_collision";
}

/// A move request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveRequest {
    /// Hosts or addresses to move.
    pub objects: Vec<ObjectRef>,
    /// The target network prefix.
    pub target: PrefixId,
    /// Observation timeout in seconds, 300 to 604,800; half the target's DHCP lease (else
    /// 3,600) when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    /// Warning codes the caller acknowledges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledge: Vec<String>,
    /// How many of the move's jobs run at once; the configured parallelism when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
}

/// The target of a move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveTarget {
    /// The prefix.
    pub prefix: PrefixId,
    /// Its network.
    #[schema(value_type = String, example = "198.51.100.0/24")]
    pub cidr: IpNet,
    /// Its VRF.
    pub vrf: VrfId,
    /// Its VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// The VLAN id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vid: Option<u16>,
    /// The longest DHCP lease of its pools, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u32>,
}

/// The DNS change of an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveDns {
    /// The name.
    #[schema(value_type = String)]
    pub name: Fqdn,
    /// What the name points to now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub old: Option<IpAddr>,
    /// What it will point to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub new: Option<IpAddr>,
}

/// One step of an item, as previewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveStepPreview {
    /// `ipam.intent`, `dhcp.manual`, `dns.manual`, `device.manual`, `l2.move`, `observe`
    /// or `cleanup`.
    pub kind: String,
    /// The engine's step kind (`ipam.move.intent`, ...).
    pub step_kind: String,
    /// Whether Tenko does it; otherwise a person ticks it off.
    pub automatic: bool,
    /// English description.
    pub text: String,
    /// References and values for the text and for automation (prefix, VLAN, address,
    /// MAC).
    pub params: BTreeMap<String, String>,
}

/// One address that moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveItem {
    /// The address that moves.
    pub object: ObjectRef,
    /// What the request named (the address itself or its host).
    pub requested: ObjectRef,
    /// The host of the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// The host's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub host_name: Option<HostName>,
    /// The host's assignment mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AssignmentMode>,
    /// The interface of the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceId>,
    /// The interface's MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The address now.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub old_ip: IpAddr,
    /// The address after the move.
    #[schema(value_type = String, example = "198.51.100.10")]
    pub new_ip: IpAddr,
    /// The identifier the new address will have.
    pub new_address: AddressId,
    /// Whether the host part stays.
    pub same_host_part: bool,
    /// Why not (`ipam.move.host_part_*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The DNS change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<MoveDns>,
    /// The steps of the item's job, in order.
    pub steps: Vec<MoveStepPreview>,
    /// Warnings of this item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
}

/// How the observation timeout of a move was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MoveTimeoutSource {
    /// The request named it (`timeout_secs`).
    Request,
    /// Half the longest DHCP lease of the target's pools, at least 300 s.
    Lease,
    /// The target has no lease time: 3,600 s.
    Default,
}

/// The preview of a move (the dry run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MovePreview {
    /// The target.
    pub target: MoveTarget,
    /// The observation timeout in seconds.
    pub timeout_secs: u32,
    /// How the timeout was chosen.
    pub timeout_source: MoveTimeoutSource,
    /// How many jobs run at once.
    pub parallelism: u32,
    /// The store revision the preview was computed at.
    pub base_revision: u64,
    /// One item per moved address.
    pub items: Vec<MoveItem>,
    /// Every warning of the move (also listed per item where it belongs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
    /// Warning codes that need an acknowledgement before a submit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unacknowledged: Vec<String>,
}

/// The job of one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveJob {
    /// The address that moves.
    pub object: ObjectRef,
    /// Its job.
    pub job_id: JobId,
}

/// The answer of a submitted move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveSubmitted {
    /// The job group of the move.
    pub group: String,
    /// One job per item, in item order.
    pub jobs: Vec<MoveJob>,
    /// The items as computed at submit, to compare with the preview.
    pub items: Vec<MoveItem>,
    /// The observation timeout in seconds.
    pub timeout_secs: u32,
    /// How many jobs run at once.
    pub parallelism: u32,
    /// Warnings of the move.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
    /// Whether an earlier answer was returned for a repeated idempotency key.
    #[serde(default)]
    pub replayed: bool,
}
