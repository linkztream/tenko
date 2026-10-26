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
//! | `ipam.move.dhcp` | `dhcp.reservation` | yes when the target has a Tenko scope ([`dhcp`]): the reservation from intent, served once the role's image holds the new address | `reserved` hosts |
//! | `ipam.move.dhcp` | `dhcp.manual` | no: a person creates the reservation | `reserved` hosts, the target without a Tenko scope |
//! | `ipam.move.dns` | `dns.records` or `dns.manual` | yes when the name's zone is in Tenko ([`dns`]): the old A or AAAA and PTR removed, the new ones written; otherwise a task for a person | a DNS name |
//! | `ipam.move.device` | `device.manual` | no: reconfigure the device | `static` hosts |
//! | `ipam.move.controller` | `l2.controller` | yes: the port profile or the per-client VLAN through the network controller | the controller can make the change |
//! | `ipam.move.l2` | `l2.move` | no: a person moves the device, with the exact action | the controller cannot (see below) |
//! | `ipam.move.nudge` | `l2.nudge` | yes: waits `reappear_secs` for the client to come back, then bounces its port or kicks it, once | the controller step runs, the controller offers it, its guardrails let it and the move did not switch it off (ADR 0028) |
//! | `ipam.move.observe` | `observe` | completed by the reconciler on a sighting of the device at its new address (WP2.4) or on a lease of its MAC address in the target network (WP8.1), or by a person; the timeout runs from its start | always |
//! | `ipam.move.cleanup` | `cleanup` | yes: remove the old address, activate the new one, release the old lease | always |
//!
//! The manual tasks come before the L2 change: a device waits for its ticked tasks before
//! it moves (IPAM-19, design decision 7). `dynamic` hosts get neither DHCP nor device tasks.
//! A device that is in the target VLAN already, or whose interface another address of the
//! same move moves, has no L2 step.
//!
//! # The L2 step
//!
//! The preview reads every enabled network controller once ([`MoveL2`],
//! `NetworkControllers::attachments`) and finds the device by the MAC address of its
//! interface:
//!
//! - **Wired**, on a switch port: the port gets a port profile whose untagged network is
//!   the target VLAN's network (one without tagged networks first, then by name). Uplinks,
//!   the port through which Tenko or the controller is reached and the controller's own
//!   client are refused (CONN-09), and a port that serves other devices too is left to a
//!   person, because a profile change would move them all.
//! - **Wireless**: the device's per-client VLAN override is set to the target network while
//!   it stays on its SSID. When its access point does not carry the VLAN (its uplink port's
//!   profile lacks the network and no SSID of the AP carries it), a person joins it to an
//!   SSID that carries the VLAN (CONN-18).
//! - **Not controllable**: no VLAN on the target, no MAC address, no controller, not seen
//!   by any controller (or by several), no network for the VLAN on the controller, no
//!   profile that carries it, writes off for the controller (TGL-20), or a guardrail
//!   refusal: a manual step says exactly what a person has to do. A refusal is a warning to
//!   acknowledge (`ipam.move.l2_refused`), and so is a controller that cannot be read
//!   (`ipam.move.controller_unavailable`).
//!
//! # Making the client start over (ADR 0028)
//!
//! A client that does not notice the VLAN change waits for its short lease. When the
//! controller offers it, the job forces it to start over: after the L2 change and a wait of
//! `[dhcp.moves] reappear_secs` for the client to come back by itself (its DHCP exchange on
//! the target network or its lease there), it bounces the client's switch port (wired) or
//! disconnects it from its access point (wireless), once ([`nudge`]). On a rollback, the same
//! bounce or kick follows the L2 undo, so the client gets its old address back at once. The
//! preview says which of the two will run, or why neither (`ipam.move.nudge.*`), and a move
//! can switch it off (`MoveRequest::nudge`).
//!
//! The job's `ipam.move.controller` step reads the controller again when it runs and
//! refuses with 409 `ipam.move.l2_changed` when the device or its port is no longer as the
//! submit found it; then it plans the change (read back and diff), runs a dry run, writes,
//! and the connector host verifies the write by planning again. The step's output, JSON
//! of [`MoveL2Output`], keeps the diff and the receipt.
//!
//! # Preview and submit
//!
//! A preview and a submit compute the same plan; the preview's `fingerprint` covers what
//! would run (addresses, steps and L2 changes, not the identifiers of the new addresses).
//! A submit that names `expect_fingerprint` refuses with 409 `ipam.move.plan_changed`
//! when its plan differs from the confirmed preview.
//!
//! # Timeout and rollback
//!
//! The observation timeout defaults to half the longest DHCP lease of the target's pools
//! (the renewal point; with a Tenko scope the lease time a pool's client gets: the pool's
//! setting, else the range's `lease_secs`, else the scope's, else the server's), else
//! 3,600 s, never below 300 s; a request may set it from 300 s
//! to 604,800 s. When the observe step passes its deadline, or any step fails, the engine
//! compensates in reverse: the L2 step is undone with the undo steps of its receipt (a
//! person is asked when that fails or the receipt has none), the intent step's
//! compensation removes the new address, restores the old one if needed and tags the
//! requested object `move-failed`; the job ends `rolled_back` with the reason in its
//! error. The tag goes away with the next successful move of the object. Manual steps
//! carry no undo task, so a rollback never waits for a person for them; the failure tells
//! what may need putting back. Every address has its own job, so a failure rolls back
//! that address only; a bulk move runs as one job group of at most `parallelism` jobs
//! between "moved" and "confirmed" (CONN-09).

// The clock of a move: the deadlines of its waiting steps (moves.md section 5).
pub mod clock;
// WP8.1: the automatic DHCP step with Tenko DHCP.
pub mod dhcp;
pub mod dns;
mod l2;
// The short lease before the network change and the moving client (ADR 0027).
pub mod lease;
// ADR 0028: the port bounce or client kick after the network change.
pub mod nudge;
mod preview;
pub mod settings;
pub mod steps;
mod submit;
pub mod timing;

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, ConnectorId, HostId, InterfaceId, JobId, MacAddr, ObjectRef, PrefixId, Timestamp,
    VlanId, VrfId,
    ipam::AssignmentMode,
    net::{Fqdn, HostName},
};
use tenko_jobs::JobEngine;
use utoipa::ToSchema;

pub use preview::preview;
pub use steps::{
    L2StepPlan, MoveCleanupStep, MoveControllerStep, MoveIntentStep, MoveL2Output, MoveManualStep,
    MoveStepParams, move_step_handlers,
};
pub use submit::{MoveReceipt, preview_move, submit_move};

use crate::{
    plan::PlanWarning,
    vlan::controllers::{AttachmentChange, ControllerInfo, Controllers, DiffEntry},
};

/// Registers the steps that need the network controllers, `ipam.move.controller` and
/// `ipam.move.nudge`, with the engine; the other steps of a move come with
/// [`crate::jobs::register_steps`]. [`nudge::register_steps`] registers the nudge again with
/// the dhcp role's slot, so that it sees the client's exchange on the target network.
pub fn register_steps(engine: &mut JobEngine, controllers: &Arc<Controllers>) {
    engine.register(Arc::new(MoveControllerStep::new(Arc::clone(controllers))));
    engine.register(Arc::new(nudge::MoveNudgeStep::new(
        Arc::clone(controllers),
        None,
    )));
}

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
    /// Warning (needs acknowledgement): another object in the target VRF has the DNS name;
    /// and the error of the automatic DNS step when another origin holds the name's RRset
    /// or a PTR the move needs (409).
    pub const DNS_COLLISION: &str = "ipam.move.dns_collision";
    /// The automatic DNS step could not write the records (409; `cause` names the zone
    /// service's code).
    pub const DNS_FAILED: &str = "ipam.move.dns_failed";
    /// The plan differs from the confirmed preview (`expect_fingerprint`) (409).
    pub const PLAN_CHANGED: &str = "ipam.move.plan_changed";
    /// The L2 step found the device or its port changed since the submit (409).
    pub const L2_CHANGED: &str = "ipam.move.l2_changed";
    /// Warning (needs acknowledgement): a guardrail refuses the L2 change of a device, so a
    /// person moves it.
    pub const L2_REFUSED: &str = "ipam.move.l2_refused";
    /// Warning: a network controller could not be read; it needs an acknowledgement when
    /// a device's L2 step is left to a person because of it.
    pub const CONTROLLER_UNAVAILABLE: &str = "ipam.move.controller_unavailable";

    /// Reason of a manual L2 step: the target network has no VLAN.
    pub const L2_NO_VLAN: &str = "ipam.move.l2.no_vlan";
    /// Reason: no network controller is configured.
    pub const L2_NO_CONTROLLER: &str = "ipam.move.l2.no_controller";
    /// Reason: a network controller could not be read (see `problem`).
    pub const L2_UNAVAILABLE: &str = "ipam.move.l2.controller_unavailable";
    /// Reason: several network controllers see the device.
    pub const L2_AMBIGUOUS: &str = "ipam.move.l2.controller_ambiguous";
    /// Reason: the interface has no MAC address to find the device by.
    pub const L2_NO_MAC: &str = "ipam.move.l2.no_mac";
    /// Reason: no network controller sees the device.
    pub const L2_NOT_SEEN: &str = "ipam.move.l2.not_seen";
    /// Reason: the controller has no network for the target VLAN.
    pub const L2_NO_NETWORK: &str = "ipam.move.l2.no_network";
    /// Reason: no port profile carries the target VLAN untagged.
    pub const L2_NO_PROFILE: &str = "ipam.move.l2.no_profile";
    /// Reason: other devices are on the switch port.
    pub const L2_SHARED_PORT: &str = "ipam.move.l2.shared_port";
    /// Reason: the controller reports the wired device without its switch port.
    pub const L2_NO_PORT: &str = "ipam.move.l2.no_port";
    /// Reason: the access point does not carry the VLAN; the device joins an SSID that does.
    pub const L2_JOIN_SSID: &str = "ipam.move.l2.join_ssid";
    /// Reason: the access point does not carry the VLAN and no SSID carries it.
    pub const L2_NO_SSID: &str = "ipam.move.l2.no_ssid";
    /// Reason: writes through the controller are off (TGL-20).
    pub const L2_READ_ONLY: &str = "ipam.move.l2.read_only";
    /// Reason: a guardrail refuses the change (see `problem`).
    pub const L2_REFUSED_REASON: &str = "ipam.move.l2.refused";
    /// Reason of no L2 step: the device is in the target VLAN already.
    pub const L2_ALREADY_THERE: &str = "ipam.move.l2.already_there";
    /// Reason of no L2 step: another address of the same interface moves the device.
    pub const L2_SAME_INTERFACE: &str = "ipam.move.l2.same_interface";

    /// Note: the device loses its link for a moment while the switch applies the profile.
    pub const NOTE_LINK_FLAP: &str = "ipam.move.l2.note.link_flap";
    /// Note: the port has no profile on record, so a rollback asks a person to put it back.
    pub const NOTE_NO_UNDO: &str = "ipam.move.l2.note.no_undo";
    /// Note: the profile also carries tagged networks.
    pub const NOTE_TAGGED: &str = "ipam.move.l2.note.tagged";
    /// Note: the client moves when it reconnects.
    pub const NOTE_RECONNECT: &str = "ipam.move.l2.note.reconnect";
    /// Note: Tenko cannot tell whether the access point carries the VLAN.
    pub const NOTE_CARRY_UNKNOWN: &str = "ipam.move.l2.note.carry_unknown";

    /// Reason of no nudge: the move switched it off (`nudge: false`).
    pub const NUDGE_OFF: &str = "ipam.move.nudge.off";
    /// Reason of no nudge: the controller offers neither a port bounce (wired) nor a client
    /// kick (wireless).
    pub const NUDGE_NO_CAPABILITY: &str = "ipam.move.nudge.no_capability";
    /// Reason of no nudge: a guardrail refuses it (see `problem`).
    pub const NUDGE_REFUSED: &str = "ipam.move.nudge.refused";
}

/// A move request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveRequest {
    /// Hosts or addresses to move.
    pub objects: Vec<ObjectRef>,
    /// The target network prefix.
    pub target: PrefixId,
    /// The migration deadline in seconds from the start of the observation, 300 to
    /// 604,800; computed from each client's lease when absent (`docs/moves.md` section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    /// Change the network at once instead of waiting for the client's next renewal, which
    /// would get the short lease first: for a client known to ask for a new lease when its
    /// link changes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub move_now: bool,
    /// After the network change, bounce the client's switch port or disconnect it from its
    /// access point when it does not come back by itself (ADR 0028); on when absent. It
    /// runs only where the controller offers it and its guardrails let it.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub nudge: bool,
    /// Warning codes the caller acknowledges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledge: Vec<String>,
    /// How many of the move's jobs run at once; the configured parallelism when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// The `fingerprint` of the preview the caller confirms: a submit whose plan differs
    /// answers 409 `ipam.move.plan_changed` and starts nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_fingerprint: Option<String>,
}

const fn yes() -> bool {
    true
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde asks for"
)]
const fn is_yes(value: &bool) -> bool {
    *value
}

/// How the job makes the client start over after the network change (ADR 0028).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MoveNudgeAction {
    /// The connector host takes the client's switch port down for a few seconds and brings
    /// it up again.
    Bounce,
    /// The controller disconnects the wireless client, which associates again.
    Kick,
    /// Neither; `reason` says why.
    #[default]
    None,
}

/// The nudge of a device after its network change, as previewed (ADR 0028).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct MoveNudge {
    /// What the job does when the client does not come back by itself.
    pub action: MoveNudgeAction,
    /// Why there is none (`ipam.move.nudge.*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The guardrail refusal behind `ipam.move.nudge.refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<MoveL2Problem>,
    /// The bounce or kick, also when it is switched off or refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<crate::vlan::controllers::NudgeChange>,
    /// How long the job waits for the client to come back by itself first.
    #[serde(default)]
    pub reappear_secs: u32,
}

/// How a device gets into the target VLAN (IPAM-19 step 4).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MoveL2Action {
    /// The network controller gives the device's switch port a port profile whose
    /// untagged network is the target VLAN.
    PortProfile,
    /// The network controller sets the device's per-client VLAN override to the target
    /// network.
    ClientVlan,
    /// A person moves the device; `reason` says why and the manual step what to do.
    #[default]
    Manual,
    /// The device is in the target VLAN already: no L2 step.
    Unchanged,
    /// Another address of the same interface moves the device (`with`): no L2 step.
    Shared,
}

/// How a device is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MoveMedium {
    /// On a switch port.
    Wired,
    /// On an access point.
    Wireless,
}

/// Where the network controller sees a device now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveAttachment {
    /// Wired or wireless.
    pub medium: MoveMedium,
    /// The switch or access point, by controller reference.
    pub device: String,
    /// Its name.
    pub device_name: String,
    /// The switch port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The port's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_name: Option<String>,
    /// The port's profile now, by controller reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// The wireless network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// The network the device is in now, by controller reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    /// The VLAN the device is in now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
}

/// The refusal or controller error behind a manual L2 step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveL2Problem {
    /// The code, such as `connect.guardrail.uplink` or `connect.unreachable`.
    pub code: String,
    /// English detail.
    pub detail: String,
}

/// The L2 step of a device, as previewed (IPAM-19 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct MoveL2 {
    /// What happens.
    pub action: MoveL2Action,
    /// Why a person moves the device, or why there is no step (`ipam.move.l2.*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The guardrail refusal or controller error behind a manual step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<MoveL2Problem>,
    /// The network controller that sees the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ControllerInfo>,
    /// Where the controller sees the device now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<MoveAttachment>,
    /// The change on the controller; also shown when a person makes it (writes off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<AttachmentChange>,
    /// The name of the port profile the port gets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// The name of the controller's network for the target VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    /// What changes on the controller, from its state as read for the preview; the job
    /// records the controller's own read-back diff when it writes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<DiffEntry>,
    /// Notes about the change (`ipam.move.l2.note.*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// How many other devices are on the switch port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub others_on_port: Option<u32>,
    /// The SSIDs that carry the target VLAN: joining one is a change on the device itself
    /// (CONN-18).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssids: Vec<String>,
    /// The address whose L2 step moves this device too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with: Option<AddressId>,
    /// When the controller was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<Timestamp>,
    /// What the job does after the change when the client does not come back by itself:
    /// a port bounce, a client kick, or neither and why (ADR 0028). Present with an
    /// automatic change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudge: Option<MoveNudge>,
}

impl MoveL2 {
    /// Whether the job has an L2 step for the device.
    pub fn has_step(&self) -> bool {
        !matches!(self.action, MoveL2Action::Unchanged | MoveL2Action::Shared)
    }

    /// Whether the network controller makes the change.
    pub fn automatic(&self) -> bool {
        matches!(
            self.action,
            MoveL2Action::PortProfile | MoveL2Action::ClientVlan
        )
    }

    /// The controller of an automatic change.
    pub fn connector_id(&self) -> Option<ConnectorId> {
        self.connector.as_ref().map(|c| c.id)
    }
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
    /// The zone Tenko serves for the name: the DNS step is automatic. Absent, a person
    /// points the name to the new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// The records the step removes (the dry run of the actuator), in presentation form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
    /// The records the step writes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<String>,
}

/// One step of an item, as previewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveStepPreview {
    /// `ipam.intent`, `dhcp.reservation`, `dhcp.manual`, `dns.records`, `dns.manual`,
    /// `device.manual`, `l2.controller`, `l2.move`, `observe` or `cleanup`.
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
    /// The L2 step: how the device gets into the target VLAN.
    #[serde(default)]
    pub l2: MoveL2,
    /// The two times: the client's next expected DHCP activity and the migration deadline.
    #[serde(default)]
    pub timing: timing::MoveTiming,
    /// The steps of the item's job, in order.
    pub steps: Vec<MoveStepPreview>,
    /// Warnings of this item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
}

/// How the migration deadline of a move was chosen (the observation's timeout,
/// [`timing::migration_deadline`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MoveTimeoutSource {
    /// The request named it (`timeout_secs`).
    Request,
    /// The end of the short lease the job asked for before the network change, plus the
    /// margin, at least 300 s.
    ShortLease,
    /// The end of the client's lease on its old network (Tenko's lease table) plus the
    /// margin, at least 300 s and at most the configured limit.
    Lease,
    /// The longest default lease of the target's pools plus the margin (Tenko does not
    /// serve the old network), at least 300 s and at most the limit.
    Pool,
    /// The target has no lease time: 3,600 s.
    #[default]
    Default,
}

/// The preview of a move (the dry run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MovePreview {
    /// The target.
    pub target: MoveTarget,
    /// The longest migration deadline of the items, in seconds from the start of their
    /// observation (each item's own is in its `timing`).
    pub timeout_secs: u32,
    /// How that deadline was chosen.
    pub timeout_source: MoveTimeoutSource,
    /// Whether the jobs change the network at once (`move_now`).
    #[serde(default)]
    pub move_now: bool,
    /// Whether the jobs bounce or kick a client that does not come back by itself
    /// (`nudge`, ADR 0028).
    #[serde(default)]
    pub nudge: bool,
    /// Whether a controller that sees a device of the move offers the port bounce or the
    /// client kick: the preview shows the switch then.
    #[serde(default)]
    pub nudge_offered: bool,
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
    /// The network controllers that were read for the L2 steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controllers: Vec<ControllerInfo>,
    /// Fingerprint of what would run: the addresses, the steps and the L2 changes. A
    /// submit with it as `expect_fingerprint` runs this plan or nothing.
    #[serde(default)]
    pub fingerprint: String,
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
