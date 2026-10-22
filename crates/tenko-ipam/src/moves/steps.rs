//! The step handlers of a move job: the automatic intent, L2 (through the network
//! controller) and cleanup steps, and the manual steps (DHCP, DNS, device, L2 by a person
//! and observation), each with its own step kind so later phases replace one handler
//! without touching the job layout.

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, CodedError, ConnectorId, HostId, InterfaceId, MacAddr, MessageKey, ObjectKind,
    ObjectRef, PrefixId, Timestamp, VlanId, VrfId,
    codec::from_cbor,
    ipam::{Address, Host, Status},
    net::Fqdn,
};
use tenko_jobs::{
    ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt};

use super::{MOVE_FAILED_TAG, MoveAttachment, MoveL2Action, codes, preview::move_failed_tag};
use crate::{
    command::{AddressInput, AddressPatch, HostPatch, IpamCommand, UpdateAddress, UpdateHost},
    plan::{PlanOptions, plan},
    tables::{ADDRESSES, HOSTS},
    vlan::controllers::{
        AttachmentChange, ControllerAttachments, Controllers, DiffEntry, NetworkReceipt,
    },
};

/// Step kind: the new address as planned intent.
pub const INTENT: &str = "ipam.move.intent";
/// Step kind: the DHCP reservation (automatic when the target has a Tenko scope, see
/// [`super::dhcp`]; a task for a person otherwise).
pub const DHCP: &str = "ipam.move.dhcp";
/// Step kind: the DNS records (automatic when the name's zone is in Tenko, see
/// [`super::dns`]).
pub const DNS: &str = "ipam.move.dns";
/// Step kind: reconfiguring a static device.
pub const DEVICE: &str = "ipam.move.device";
/// Step kind: the L2 change made by a person.
pub const L2: &str = "ipam.move.l2";
/// Step kind: the L2 change through the network controller.
pub const CONTROLLER: &str = "ipam.move.controller";
/// Timeout of the controller step (each controller call has its own as well).
pub const CONTROLLER_TIMEOUT_SECS: u64 = 600;
/// Step kind: the device seen in the target network (manual until observations).
pub const OBSERVE: &str = "ipam.move.observe";
/// Step kind: removing the old address and activating the new one.
pub const CLEANUP: &str = "ipam.move.cleanup";

/// Parameters of every step of a move job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveStepParams {
    /// The job group of the move.
    pub group: String,
    /// What the request named (the address or its host); it gets the failure tag.
    pub requested: ObjectRef,
    /// The address that moves.
    pub address: AddressId,
    /// The identifier of the new address.
    pub new_address: AddressId,
    /// The address now.
    pub old_ip: IpAddr,
    /// The address after the move.
    pub new_ip: IpAddr,
    /// The target VRF.
    pub vrf: VrfId,
    /// The target prefix.
    pub prefix: PrefixId,
    /// The target network.
    pub cidr: IpNet,
    /// The target VLAN.
    #[serde(default)]
    pub vlan: Option<VlanId>,
    /// The target VLAN id.
    #[serde(default)]
    pub vid: Option<u16>,
    /// The host.
    #[serde(default)]
    pub host: Option<HostId>,
    /// The interface of the address.
    #[serde(default)]
    pub interface: Option<InterfaceId>,
    /// The DNS name.
    #[serde(default)]
    pub dns_name: Option<Fqdn>,
    /// The task of a manual step.
    #[serde(default)]
    pub task: Option<ManualTask>,
    /// The change of the controller step.
    #[serde(default)]
    pub l2: Option<L2StepPlan>,
    /// The zone of an automatic DNS step; absent, the step is a task for a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<super::dns::DnsStepPlan>,
    /// The Tenko scope of an automatic DHCP step; absent, the step is a task for a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<super::dhcp::DhcpStepPlan>,
}

/// What the controller step changes, as the submit planned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2StepPlan {
    /// The network controller.
    pub connector: ConnectorId,
    /// Its name.
    pub connector_name: String,
    /// The device.
    pub mac: MacAddr,
    /// The change.
    pub change: AttachmentChange,
    /// Where the controller saw the device at the submit; the step refuses to write when
    /// the device or its port changed since.
    pub attachment: MoveAttachment,
    /// Port profile or per-client VLAN.
    pub action: MoveL2Action,
    /// What the preview showed would change.
    pub diff: Vec<DiffEntry>,
}

/// What the controller step did, kept as JSON in the step's output so the jobs view can
/// show it and the rollback can undo it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveL2Output {
    /// The network controller.
    pub connector: ConnectorId,
    /// The change.
    pub change: AttachmentChange,
    /// The controller's read-back diff right before the write.
    #[serde(default)]
    pub diff: Vec<DiffEntry>,
    /// The controller's warnings, in English.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// When the controller was read for the write.
    pub read_at: Timestamp,
    /// Whether the controller had the change already, so nothing was written.
    #[serde(default)]
    pub unchanged: bool,
    /// Whether an interrupted earlier attempt may have written without keeping the
    /// receipt: the rollback then asks a person.
    #[serde(default)]
    pub unknown_write: bool,
    /// The receipt of the write: its undo steps put the device back.
    #[serde(default)]
    pub receipt: Option<NetworkReceipt>,
}

impl MoveStepParams {
    pub(super) fn decode(params: &[u8]) -> Result<Self, StepError> {
        from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))
    }

    pub(super) fn changes(&self) -> Vec<ObjectRef> {
        let mut out = vec![
            ObjectRef::from(self.address),
            ObjectRef::from(self.new_address),
        ];
        if let Some(host) = self.host {
            out.push(host.into());
        }
        out
    }

    pub(super) fn args(&self) -> BTreeMap<String, String> {
        let mut args = BTreeMap::from([
            ("old_ip".to_owned(), self.old_ip.to_string()),
            ("new_ip".to_owned(), self.new_ip.to_string()),
            ("cidr".to_owned(), self.cidr.to_string()),
        ]);
        if let Some(vid) = self.vid {
            args.insert("vid".to_owned(), vid.to_string());
        }
        args
    }
}

fn step_error(error: &crate::IpamError) -> StepError {
    StepError::coded(error)
}

/// Plans `commands` against the step's view and stages the batch with the step's state
/// (or proposes it outside the engine).
async fn write(
    cx: &StepContext,
    view: &dyn ReadView,
    commands: &[IpamCommand],
) -> Result<(), StepError> {
    if commands.is_empty() {
        return Ok(());
    }
    let planned = plan(view, &cx.request, &PlanOptions::default(), commands)
        .map_err(|error| step_error(&error))?;
    if planned.is_empty() {
        return Ok(());
    }
    let batch = planned.to_batch();
    match tenko_jobs::stage(cx, batch.clone()) {
        Ok(()) => Ok(()),
        Err(StepError::Coded(error)) if error.code == "jobs.stage.outside_step" => {
            cx.store.propose(batch).await?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn live_address(view: &dyn ReadView, id: AddressId) -> Result<Option<Address>, StepError> {
    Ok(view
        .get_typed(&ADDRESSES, &id)?
        .map(|(address, _)| address)
        .filter(|address| !address.meta.is_deleted()))
}

/// Sets or clears the failure tag of the requested object, if it is live.
fn tag_command(
    view: &dyn ReadView,
    object: ObjectRef,
    failed: bool,
) -> Result<Option<IpamCommand>, StepError> {
    let tag = move_failed_tag().map_err(|error| step_error(&error))?;
    let current = match object.kind {
        ObjectKind::Host => view
            .get_typed(&HOSTS, &object.id.into())?
            .map(|(host, _): (Host, _)| host.meta)
            .filter(|meta| !meta.is_deleted()),
        ObjectKind::Address => view
            .get_typed(&ADDRESSES, &object.id.into())?
            .map(|(address, _): (Address, _)| address.meta)
            .filter(|meta| !meta.is_deleted()),
        _ => None,
    };
    let Some(meta) = current else {
        return Ok(None);
    };
    if meta.tags.contains(&tag) == failed {
        return Ok(None);
    }
    let mut tags = meta.tags.clone();
    if failed {
        tags.insert(tag);
    } else {
        tags.retain(|t| t.as_str() != MOVE_FAILED_TAG);
    }
    Ok(Some(match object.kind {
        ObjectKind::Host => IpamCommand::UpdateHost(UpdateHost {
            id: object.id.into(),
            expected: None,
            patch: HostPatch {
                tags: Some(tags),
                ..HostPatch::default()
            },
        }),
        _ => IpamCommand::UpdateAddress(UpdateAddress {
            id: object.id.into(),
            expected: None,
            patch: AddressPatch {
                tags: Some(tags),
                ..AddressPatch::default()
            },
        }),
    }))
}

async fn view_of(cx: &StepContext) -> Result<std::sync::Arc<dyn ReadView>, StepError> {
    Ok(cx.store.read(ReadConsistency::Local).await?)
}

fn automatic_preview(summary: &'static str, params: &MoveStepParams) -> StepPreview {
    StepPreview {
        summary: MessageKey::from_static(summary),
        args: params.args(),
        changes: params.changes(),
        manual: None,
        warnings: Vec::new(),
    }
}

/// `ipam.move.intent`: creates the new address as planned intent on the interface and
/// keeps the old one. Its compensation removes the new address, keeps the old one and
/// tags the requested object `move-failed`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MoveIntentStep;

#[async_trait::async_trait]
impl StepHandler for MoveIntentStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(INTENT)
    }

    /// Running it again finds the new address and does nothing.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        Ok(automatic_preview("ipam.move.step.intent", &params))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let view = view_of(cx).await?;
        if live_address(view.as_ref(), params.new_address)?.is_some() {
            return Ok(StepOutcome::Done { output: None });
        }
        let Some(old) = live_address(view.as_ref(), params.address)? else {
            return Err(StepError::Coded(Box::new(
                CodedError::new(
                    crate::codes::REFERENCE_MISSING,
                    409,
                    format!("the address {} to move is gone", params.old_ip),
                )
                .with_param("ip", params.old_ip.to_string()),
            )));
        };
        let mut tags = old.meta.tags.clone();
        tags.retain(|tag| tag.as_str() != MOVE_FAILED_TAG);
        let command = IpamCommand::CreateAddress(AddressInput {
            id: Some(params.new_address),
            vrf: Some(params.vrf),
            ip: params.new_ip,
            status: Some(Status::Planned),
            interface: old.interface,
            dns_name: old.dns_name.clone(),
            tags,
            custom: old.meta.custom.clone(),
            description: old.meta.description.clone(),
        });
        write(cx, view.as_ref(), &[command]).await?;
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let params = MoveStepParams::decode(params)?;
        let view = view_of(cx).await?;
        let mut commands = Vec::new();
        if live_address(view.as_ref(), params.new_address)?.is_some() {
            commands.push(IpamCommand::Delete {
                object: params.new_address.into(),
                expected: None,
                cascade: false,
            });
        }
        if live_address(view.as_ref(), params.address)?.is_none()
            && view.get_typed(&ADDRESSES, &params.address)?.is_some()
        {
            commands.push(IpamCommand::Restore {
                object: params.address.into(),
                expected: None,
            });
        }
        if let Some(tag) = tag_command(view.as_ref(), params.requested, true)? {
            commands.push(tag);
        }
        write(cx, view.as_ref(), &commands).await
    }
}

/// `ipam.move.cleanup`: removes the old address, makes the new one active and clears a
/// `move-failed` tag of the requested object. With the `dhcp` role in the process it also
/// releases the old lease, when the moved interface's MAC address still holds it, through
/// the node command `dhcp.lease.release` ([`super::dhcp::release_held`]); the old
/// reservation goes with the old address. A release that fails is logged and left to the
/// lease's expiry: the cleanup never rolls a confirmed move back.
#[derive(Debug, Clone, Default)]
pub struct MoveCleanupStep {
    dhcp: Option<super::dhcp::DhcpMoves>,
}

/// What the cleanup did beyond IPAM, kept as JSON in the step's output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveCleanupOutput {
    /// Whether the old lease was released.
    #[serde(default)]
    pub released_old_lease: bool,
}

impl MoveCleanupStep {
    /// The cleanup that also releases the old lease through the role of `slot`.
    pub fn with_dhcp(slot: super::dhcp::DhcpMoves) -> Self {
        Self { dhcp: Some(slot) }
    }

    /// Releases the old lease when the role runs and the interface's MAC holds it.
    async fn release_old(
        &self,
        view: &dyn ReadView,
        params: &MoveStepParams,
        cx: &StepContext,
    ) -> bool {
        let Some(role) = self.dhcp.as_ref().and_then(super::dhcp::DhcpMoves::get) else {
            return false;
        };
        // The old address's VRF, from its row even once deleted (a step run again).
        let old = view
            .get_typed(&ADDRESSES, &params.address)
            .map_err(StepError::from)
            .and_then(|old| Ok((old, super::dhcp::interface_mac(view, params)?)));
        let (vrf, mac) = match old {
            Ok((Some((old, _)), mac)) => (old.vrf, mac),
            Ok((None, _)) => return false,
            Err(error) => {
                tracing::warn!(job = %cx.job, %error, "the old lease of a move was not looked up");
                return false;
            }
        };
        match super::dhcp::release_held(
            role.as_ref(),
            view,
            vrf,
            params.old_ip,
            mac,
            Timestamp::now(),
            "the move to another network is confirmed",
        )
        .await
        {
            Ok(released) => released == super::dhcp::Released::Released,
            Err(error) => {
                tracing::warn!(
                    job = %cx.job,
                    old_ip = %params.old_ip,
                    %error,
                    "the old lease of a move was not released; it expires on its own"
                );
                false
            }
        }
    }
}

#[async_trait::async_trait]
impl StepHandler for MoveCleanupStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(CLEANUP)
    }

    /// Running it again finds the work done.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        Ok(automatic_preview("ipam.move.step.cleanup", &params))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let view = view_of(cx).await?;
        let mut commands = Vec::new();
        if live_address(view.as_ref(), params.address)?.is_some() {
            commands.push(IpamCommand::Delete {
                object: params.address.into(),
                expected: None,
                cascade: false,
            });
        }
        if let Some(new) = live_address(view.as_ref(), params.new_address)?
            && new.status == Status::Planned
        {
            commands.push(IpamCommand::UpdateAddress(UpdateAddress {
                id: params.new_address,
                expected: None,
                patch: AddressPatch {
                    status: Some(Status::Active),
                    ..AddressPatch::default()
                },
            }));
        }
        if let Some(tag) = tag_command(view.as_ref(), params.requested, false)? {
            commands.push(tag);
        }
        let released_old_lease = self.release_old(view.as_ref(), &params, cx).await;
        write(cx, view.as_ref(), &commands).await?;
        if self.dhcp.is_none() {
            return Ok(StepOutcome::Done { output: None });
        }
        let output = MoveCleanupOutput { released_old_lease };
        let bytes = serde_json::to_vec(&output)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepOutcome::Done {
            output: Some(bytes.into()),
        })
    }

    /// The last step: nothing runs after it, so nothing undoes it.
    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Ok(())
    }
}

/// A manual step of Slice 1: holds the job until a person completes the task (or the
/// step's deadline passes, for the observation). No undo task: a rollback never waits for
/// a person.
#[derive(Debug, Clone)]
pub struct MoveManualStep {
    kind: &'static str,
}

impl MoveManualStep {
    /// The handler of one manual step kind.
    pub const fn new(kind: &'static str) -> Self {
        Self { kind }
    }

    fn task(params: &MoveStepParams) -> ManualTask {
        params.task.clone().unwrap_or_else(|| ManualTask {
            instruction: MessageKey::from_static("ipam.move.task.generic"),
            args: params.args(),
            undo: None,
        })
    }
}

#[async_trait::async_trait]
impl StepHandler for MoveManualStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(self.kind)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        let task = Self::task(&params);
        Ok(StepPreview {
            summary: task.instruction.clone(),
            args: task.args.clone(),
            changes: params.changes(),
            manual: Some(task),
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], _cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        Ok(StepOutcome::Manual(Self::task(&params)))
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Ok(())
    }
}

/// `ipam.move.controller`: the L2 change through the network controller. It reads the
/// controller again and refuses (409 `ipam.move.l2_changed`) when the device or its port
/// is no longer as the submit found it, plans the change (read back and diff), runs a dry
/// run and writes; the connector host verifies the write by planning again (CONN-08). The
/// output keeps the diff and the receipt; the compensation undoes the write with the
/// receipt's undo steps, and asks a person when that fails or there are none.
#[derive(Debug, Clone)]
pub struct MoveControllerStep {
    controllers: Arc<Controllers>,
}

impl MoveControllerStep {
    /// The handler over the controller slot.
    pub fn new(controllers: Arc<Controllers>) -> Self {
        Self { controllers }
    }
}

fn changed(plan: &L2StepPlan, what: &str) -> StepError {
    StepError::Coded(Box::new(
        CodedError::new(
            codes::L2_CHANGED,
            409,
            format!(
                "the network changed since the move was submitted: {what}; nothing was written, preview the move again"
            ),
        )
        .with_title("The network changed")
        .with_param("mac", plan.mac.to_string())
        .with_param("what", what.to_owned()),
    ))
}

/// Refuses to write when the device or its port is no longer as the submit found it. A
/// port that has the target profile already, or a device that went offline, is fine.
fn still_as_submitted(plan: &L2StepPlan, state: &ControllerAttachments) -> Result<(), StepError> {
    let client = state.client(plan.mac);
    let device = &plan.attachment.device_name;
    match &plan.change {
        AttachmentChange::SetPortProfile {
            device: switch,
            port,
            profile,
        } => {
            let Some(now) = state.port(switch, *port) else {
                return Err(changed(plan, &format!("port {port} of {device} is gone")));
            };
            if now.profile != plan.attachment.profile && now.profile.as_deref() != Some(profile) {
                return Err(changed(
                    plan,
                    &format!("port {port} of {device} has another port profile"),
                ));
            }
            if let Some(client) = client
                && (client.device != *switch || client.port != Some(*port))
            {
                return Err(changed(plan, "the device is on another port"));
            }
            let others = state.others_on_port(switch, *port, plan.mac);
            if others > 0 {
                return Err(changed(
                    plan,
                    &format!("{others} other devices are on port {port} of {device}"),
                ));
            }
        }
        AttachmentChange::SetClientVlan { network, .. } => {
            if state.network(network).is_none() {
                return Err(changed(plan, "the target network is gone"));
            }
            if client.is_some_and(|c| c.port.is_some()) {
                return Err(changed(plan, "the device is wired now"));
            }
        }
        AttachmentChange::ClearClientVlan { .. } => {}
    }
    Ok(())
}

fn port_error(error: CodedError) -> StepError {
    StepError::Coded(Box::new(error))
}

#[async_trait::async_trait]
impl StepHandler for MoveControllerStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(CONTROLLER)
    }

    /// Running it again plans first: a change written before the interruption shows an
    /// empty diff and is not written twice (the rollback then asks a person, because the
    /// receipt of that write is lost).
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        let mut args = params.args();
        let summary = match &params.l2 {
            Some(plan) => {
                args.insert("connector".to_owned(), plan.connector_name.clone());
                args.insert("device".to_owned(), plan.attachment.device_name.clone());
                args.insert("mac".to_owned(), plan.mac.to_string());
                if let Some(port) = plan.attachment.port {
                    args.insert("port".to_owned(), port.to_string());
                }
                if let Some(ssid) = &plan.attachment.ssid {
                    args.insert("ssid".to_owned(), ssid.clone());
                }
                if let Some(line) = plan.diff.first() {
                    args.insert("path".to_owned(), line.path.clone());
                    if let Some(before) = &line.before {
                        args.insert("before".to_owned(), before.clone());
                    }
                    if let Some(after) = &line.after {
                        args.insert("after".to_owned(), after.clone());
                    }
                }
                match plan.action {
                    MoveL2Action::PortProfile => "ipam.move.step.controller_port",
                    _ => "ipam.move.step.controller_client",
                }
            }
            None => "ipam.move.step.controller_client",
        };
        let mut changes = params.changes();
        if let Some(plan) = &params.l2 {
            changes.push(plan.connector.into());
        }
        Ok(StepPreview {
            summary: MessageKey::from_static(summary),
            args,
            changes,
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let Some(plan) = params.l2 else {
            return Err(StepError::InvalidParams(
                "the controller step carries no change".to_owned(),
            ));
        };
        let Some(port) = self.controllers.get() else {
            return Err(port_error(CodedError::new(
                crate::vlan::codes::CONTROLLERS_UNAVAILABLE,
                503,
                "the network controllers are not available on this server",
            )));
        };
        let user = cx.request.principal.user();
        let state = port
            .attachments(plan.connector, user)
            .await
            .map_err(port_error)?;
        still_as_submitted(&plan, &state)?;
        let planned = port
            .plan_attachment(plan.connector, &plan.change, user)
            .await
            .map_err(port_error)?;
        let mut output = MoveL2Output {
            connector: plan.connector,
            change: plan.change.clone(),
            diff: planned.diff.clone(),
            warnings: planned.warnings.clone(),
            read_at: planned.read_at,
            unchanged: false,
            unknown_write: false,
            receipt: None,
        };
        if planned.diff.is_empty() {
            // The controller has the change: a person made it, or an earlier attempt of
            // this step wrote it before it was interrupted (its receipt is lost).
            output.unchanged = cx.attempt <= 1;
            output.unknown_write = cx.attempt > 1;
        } else {
            port.apply_attachment(&planned, true, user)
                .await
                .map_err(port_error)?;
            let receipt =
                port.apply_attachment(&planned, false, user)
                    .await
                    .map_err(|mut error| {
                        if error.code == "connect.verify_mismatch" {
                            error.params.insert(
                            "note".to_owned(),
                            "the controller may hold part of the change; compare it with the plan"
                                .to_owned(),
                        );
                        }
                        port_error(error)
                    })?;
            output.receipt = Some(receipt);
        }
        let bytes = serde_json::to_vec(&output)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepOutcome::Done {
            output: Some(bytes.into()),
        })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let Some(output) = output else {
            return Ok(());
        };
        let output: MoveL2Output = serde_json::from_slice(output)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        if output.unknown_write {
            return Err(StepError::NotCompensable);
        }
        let Some(receipt) = output.receipt.filter(|r| !r.dry_run) else {
            return Ok(());
        };
        if receipt.undo_steps == 0 {
            // The port had no profile on record: nothing tells what to put back.
            return Err(StepError::NotCompensable);
        }
        let Some(port) = self.controllers.get() else {
            return Err(StepError::NotCompensable);
        };
        port.revert_network(&receipt, cx.request.principal.user())
            .await
            .map_err(|error| {
                tracing::warn!(
                    job = %cx.job,
                    code = %error.code,
                    detail = %error.detail,
                    "the L2 change of a move could not be undone; a person is asked"
                );
                StepError::NotCompensable
            })
    }
}

/// Every step handler of a move job.
pub fn move_step_handlers() -> Vec<Arc<dyn StepHandler>> {
    vec![
        Arc::new(MoveIntentStep),
        Arc::new(MoveCleanupStep::default()),
        Arc::new(super::dhcp::MoveDhcpStep::default()),
        Arc::new(super::dns::MoveDnsStep::manual()),
        Arc::new(MoveManualStep::new(DEVICE)),
        Arc::new(MoveManualStep::new(L2)),
        Arc::new(MoveManualStep::new(OBSERVE)),
    ]
}
