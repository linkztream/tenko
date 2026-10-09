//! The step handlers of a move job: the automatic intent and cleanup steps, and the
//! manual steps of Slice 1 (DHCP, DNS, device, L2 and observation), each with its own
//! step kind so later phases replace one handler without touching the job layout.

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, CodedError, HostId, InterfaceId, MessageKey, ObjectKind, ObjectRef, PrefixId,
    VlanId, VrfId,
    codec::from_cbor,
    ipam::{Address, Host, Status},
    net::Fqdn,
};
use tenko_jobs::{
    ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt};

use super::{MOVE_FAILED_TAG, preview::move_failed_tag};
use crate::{
    command::{AddressInput, AddressPatch, HostPatch, IpamCommand, UpdateAddress, UpdateHost},
    plan::{PlanOptions, plan},
    tables::{ADDRESSES, HOSTS},
};

/// Step kind: the new address as planned intent.
pub const INTENT: &str = "ipam.move.intent";
/// Step kind: the DHCP reservation (manual until Tenko DHCP).
pub const DHCP: &str = "ipam.move.dhcp";
/// Step kind: the DNS records (manual until Tenko DNS).
pub const DNS: &str = "ipam.move.dns";
/// Step kind: reconfiguring a static device.
pub const DEVICE: &str = "ipam.move.device";
/// Step kind: the L2 change (manual until the network controller connector).
pub const L2: &str = "ipam.move.l2";
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
}

impl MoveStepParams {
    fn decode(params: &[u8]) -> Result<Self, StepError> {
        from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))
    }

    fn changes(&self) -> Vec<ObjectRef> {
        let mut out = vec![
            ObjectRef::from(self.address),
            ObjectRef::from(self.new_address),
        ];
        if let Some(host) = self.host {
            out.push(host.into());
        }
        out
    }

    fn args(&self) -> BTreeMap<String, String> {
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
/// `move-failed` tag of the requested object.
#[derive(Debug, Clone, Copy, Default)]
pub struct MoveCleanupStep;

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
        write(cx, view.as_ref(), &commands).await?;
        Ok(StepOutcome::Done { output: None })
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

/// Every step handler of a move job.
pub fn move_step_handlers() -> Vec<Arc<dyn StepHandler>> {
    vec![
        Arc::new(MoveIntentStep),
        Arc::new(MoveCleanupStep),
        Arc::new(MoveManualStep::new(DHCP)),
        Arc::new(MoveManualStep::new(DNS)),
        Arc::new(MoveManualStep::new(DEVICE)),
        Arc::new(MoveManualStep::new(L2)),
        Arc::new(MoveManualStep::new(OBSERVE)),
    ]
}
