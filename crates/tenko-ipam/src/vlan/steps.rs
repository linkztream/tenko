//! The step handlers of the VLAN provision job.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, ConnectorId, MessageKey, ObjectRef, PrefixId, VlanId,
    codec::{from_cbor, to_cbor},
    ipam::{Prefix, Status, Vlan},
};
use tenko_jobs::{
    JobEngine, ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt};

use super::{
    codes,
    controllers::{Controllers, DiffEntry, NetworkReceipt, NetworkSpec},
};
use crate::{
    command::{
        IpamCommand, PrefixInput, PrefixPatch, UpdatePrefix, UpdateVlan, VlanInput, VlanPatch,
    },
    plan::{PlanOptions, plan},
    tables::{PREFIXES, VLANS},
};

/// Step kind: the new VLAN and prefix as planned intent.
pub const INTENT: &str = "ipam.vlan.intent";
/// Step kind: the network through the network controller.
pub const CONTROLLER: &str = "ipam.vlan.controller";
/// Step kind: the network created by a person.
pub const MANUAL: &str = "ipam.vlan.manual";
/// Step kind: the new VLAN and prefix become active.
pub const ACTIVATE: &str = "ipam.vlan.activate";

/// Parameters of every step of a provision job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanStepParams {
    /// The VLAN.
    pub vlan: VlanId,
    /// Its VLAN id.
    pub vid: u16,
    /// Its name.
    pub name: String,
    /// The VLAN to create, when the job creates it.
    #[serde(default)]
    pub create: Option<VlanInput>,
    /// The prefix to create.
    #[serde(default)]
    pub prefix: Option<PrefixInput>,
    /// The controller of an automatic network step.
    #[serde(default)]
    pub connector: Option<ConnectorId>,
    /// The network asked for.
    pub network: NetworkSpec,
    /// The diff the submit planned; the network step refuses another one.
    #[serde(default)]
    pub expected_diff: Vec<DiffEntry>,
    /// The task of the manual step.
    #[serde(default)]
    pub task: Option<ManualTask>,
}

impl VlanStepParams {
    fn decode(params: &[u8]) -> Result<Self, StepError> {
        from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))
    }

    fn prefix_id(&self) -> Option<PrefixId> {
        self.prefix.as_ref().and_then(|p| p.id)
    }

    fn changes(&self) -> Vec<ObjectRef> {
        let mut out = vec![ObjectRef::from(self.vlan)];
        if let Some(prefix) = self.prefix_id() {
            out.push(prefix.into());
        }
        out
    }

    fn args(&self) -> BTreeMap<String, String> {
        let mut args = BTreeMap::from([
            ("vid".to_owned(), self.vid.to_string()),
            ("name".to_owned(), self.network.name.clone()),
        ]);
        if let Some(prefix) = &self.prefix {
            args.insert("cidr".to_owned(), prefix.cidr.to_string());
        }
        args
    }
}

/// What the network step did, for its compensation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerOutput {
    /// Whether the controller had the network as asked, so nothing was written.
    pub unchanged: bool,
    /// The receipt of the write.
    #[serde(default)]
    pub receipt: Option<NetworkReceipt>,
}

fn coded(code: &'static str, status: u16, detail: impl Into<String>) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, detail)))
}

fn ipam_error(error: &crate::IpamError) -> StepError {
    StepError::coded(error)
}

async fn view_of(cx: &StepContext) -> Result<Arc<dyn ReadView>, StepError> {
    Ok(cx.store.read(ReadConsistency::Local).await?)
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
        .map_err(|error| ipam_error(&error))?;
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

fn live_vlan(view: &dyn ReadView, id: VlanId) -> Result<Option<Vlan>, StepError> {
    Ok(view
        .get_typed(&VLANS, &id)?
        .map(|(vlan, _)| vlan)
        .filter(|vlan| !vlan.meta.is_deleted()))
}

fn live_prefix(view: &dyn ReadView, id: PrefixId) -> Result<Option<Prefix>, StepError> {
    Ok(view
        .get_typed(&PREFIXES, &id)?
        .map(|(prefix, _)| prefix)
        .filter(|prefix| !prefix.meta.is_deleted()))
}

fn automatic_preview(summary: &'static str, params: &VlanStepParams) -> StepPreview {
    StepPreview {
        summary: MessageKey::from_static(summary),
        args: params.args(),
        changes: params.changes(),
        manual: None,
        warnings: Vec::new(),
    }
}

/// `ipam.vlan.intent`: creates the new VLAN and prefix as `planned`. Its compensation
/// soft-deletes what the job created; when that is refused (something was added to the
/// prefix meanwhile) a person is asked.
#[derive(Debug, Clone, Copy, Default)]
pub struct IntentStep;

#[async_trait::async_trait]
impl StepHandler for IntentStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(INTENT)
    }

    /// Running it again finds the objects and creates nothing.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = VlanStepParams::decode(params)?;
        Ok(automatic_preview("ipam.vlan.step.intent", &params))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = VlanStepParams::decode(params)?;
        let view = view_of(cx).await?;
        let mut commands = Vec::new();
        if let Some(input) = &params.create
            && view.get_typed(&VLANS, &params.vlan)?.is_none()
        {
            commands.push(IpamCommand::CreateVlan(input.clone()));
        }
        if let (Some(input), Some(id)) = (&params.prefix, params.prefix_id())
            && view.get_typed(&PREFIXES, &id)?.is_none()
        {
            commands.push(IpamCommand::CreatePrefix(input.clone()));
        }
        write(cx, view.as_ref(), &commands).await?;
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let params = VlanStepParams::decode(params)?;
        let view = view_of(cx).await?;
        let mut commands = Vec::new();
        if let Some(id) = params.prefix_id()
            && live_prefix(view.as_ref(), id)?.is_some()
        {
            commands.push(IpamCommand::Delete {
                object: id.into(),
                expected: None,
                cascade: false,
            });
        }
        if params.create.is_some() && live_vlan(view.as_ref(), params.vlan)?.is_some() {
            commands.push(IpamCommand::Delete {
                object: params.vlan.into(),
                expected: None,
                cascade: false,
            });
        }
        match write(cx, view.as_ref(), &commands).await {
            Ok(()) => Ok(()),
            // Something now uses the VLAN or the prefix: a person decides.
            Err(StepError::Coded(error)) if error.code.starts_with("ipam.") => {
                Err(StepError::NotCompensable)
            }
            Err(error) => Err(error),
        }
    }
}

/// `ipam.vlan.controller`: plans the network again (read back and diff), refuses a diff
/// other than the submitted one, asks the controller for a dry run, writes and keeps the
/// receipt; the connector host verifies the write by reading back. Its compensation
/// undoes the write with the receipt, or asks a person when that fails.
#[derive(Debug, Clone)]
pub struct ControllerStep {
    controllers: Arc<Controllers>,
}

impl ControllerStep {
    /// The handler over the controller slot.
    pub fn new(controllers: Arc<Controllers>) -> Self {
        Self { controllers }
    }
}

#[async_trait::async_trait]
impl StepHandler for ControllerStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(CONTROLLER)
    }

    /// Running it again plans first: a network written before the interruption shows an
    /// empty diff and nothing is written twice.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = VlanStepParams::decode(params)?;
        Ok(automatic_preview("ipam.vlan.step.controller", &params))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = VlanStepParams::decode(params)?;
        let Some(connector) = params.connector else {
            return Err(StepError::InvalidParams(
                "the network step names no connector".to_owned(),
            ));
        };
        let Some(port) = self.controllers.get() else {
            return Err(coded(
                codes::CONTROLLERS_UNAVAILABLE,
                503,
                "the network controllers are not available on this server",
            ));
        };
        let user = cx.request.principal.user();
        let plan = port
            .plan_network(connector, &params.network, user)
            .await
            .map_err(|error| StepError::Coded(Box::new(error)))?;
        let output = |unchanged, receipt| -> Result<StepOutcome, StepError> {
            let bytes = to_cbor(&ControllerOutput { unchanged, receipt })
                .map_err(|error| StepError::coded(&error))?;
            Ok(StepOutcome::Done {
                output: Some(bytes),
            })
        };
        if plan.diff.is_empty() {
            return output(true, None);
        }
        if plan.diff != params.expected_diff {
            let lines: Vec<String> = plan
                .diff
                .iter()
                .map(|line| {
                    format!(
                        "{}: {} -> {}",
                        line.path,
                        line.before.as_deref().unwrap_or("absent"),
                        line.after.as_deref().unwrap_or("absent")
                    )
                })
                .collect();
            return Err(StepError::Coded(Box::new(
                CodedError::new(
                    codes::CONTROLLER_CHANGED,
                    409,
                    format!(
                        "the controller changed since the provision was submitted; it would now change {}; preview again",
                        lines.join(", ")
                    ),
                )
                .with_title("The controller changed")
                .with_param("vid", params.vid.to_string()),
            )));
        }
        port.apply_network(&plan, true, user)
            .await
            .map_err(|error| StepError::Coded(Box::new(error)))?;
        let receipt = port
            .apply_network(&plan, false, user)
            .await
            .map_err(|error| {
                let mut error = error;
                if error.code == "connect.verify_mismatch" {
                    error.params.insert(
                        "note".to_owned(),
                        "the controller may hold part of the change; compare it with the plan"
                            .to_owned(),
                    );
                }
                StepError::Coded(Box::new(error))
            })?;
        output(false, Some(receipt))
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
        let output: ControllerOutput =
            from_cbor(output).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let Some(receipt) = output.receipt.filter(|r| !r.dry_run && r.undo_steps > 0) else {
            return Ok(());
        };
        let Some(port) = self.controllers.get() else {
            return Err(StepError::NotCompensable);
        };
        port.revert_network(&receipt, cx.request.principal.user())
            .await
            .map_err(|_| StepError::NotCompensable)
    }
}

/// `ipam.vlan.manual`: holds the job until a person has created the network. No undo
/// task: a rollback never waits for a person.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManualNetworkStep;

impl ManualNetworkStep {
    fn task(params: &VlanStepParams) -> ManualTask {
        params.task.clone().unwrap_or_else(|| ManualTask {
            instruction: MessageKey::from_static("ipam.vlan.task.network"),
            args: params.args(),
            undo: None,
        })
    }
}

#[async_trait::async_trait]
impl StepHandler for ManualNetworkStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(MANUAL)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = VlanStepParams::decode(params)?;
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
        let params = VlanStepParams::decode(params)?;
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

/// `ipam.vlan.activate`: the VLAN and prefix the job created become `active`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ActivateStep;

#[async_trait::async_trait]
impl StepHandler for ActivateStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(ACTIVATE)
    }

    /// Running it again finds them active.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = VlanStepParams::decode(params)?;
        Ok(automatic_preview("ipam.vlan.step.activate", &params))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = VlanStepParams::decode(params)?;
        let view = view_of(cx).await?;
        let mut commands = Vec::new();
        if params.create.is_some()
            && let Some(vlan) = live_vlan(view.as_ref(), params.vlan)?
            && vlan.status == Status::Planned
        {
            commands.push(IpamCommand::UpdateVlan(UpdateVlan {
                id: params.vlan,
                expected: None,
                patch: VlanPatch {
                    status: Some(Status::Active),
                    ..VlanPatch::default()
                },
            }));
        }
        if let Some(id) = params.prefix_id()
            && let Some(prefix) = live_prefix(view.as_ref(), id)?
            && prefix.status == Status::Planned
        {
            commands.push(IpamCommand::UpdatePrefix(UpdatePrefix {
                id,
                expected: None,
                patch: PrefixPatch {
                    status: Some(Status::Active),
                    ..PrefixPatch::default()
                },
            }));
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

/// Every step handler of a provision job, over the controller slot.
pub fn step_handlers(controllers: &Arc<Controllers>) -> Vec<Arc<dyn StepHandler>> {
    vec![
        Arc::new(IntentStep),
        Arc::new(ControllerStep::new(Arc::clone(controllers))),
        Arc::new(ManualNetworkStep),
        Arc::new(ActivateStep),
    ]
}

/// Registers the step handlers of the provision job with the engine.
pub fn register_steps(engine: &mut JobEngine, controllers: &Arc<Controllers>) {
    for handler in step_handlers(controllers) {
        engine.register(handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_round_trip_through_cbor() {
        let params = VlanStepParams {
            vlan: VlanId::generate(),
            vid: 30,
            name: "IoT".to_owned(),
            create: None,
            prefix: None,
            connector: Some(ConnectorId::generate()),
            network: NetworkSpec {
                vid: 30,
                name: "IoT".to_owned(),
                dhcp_relay: vec!["192.0.2.53".parse().expect("ip")],
            },
            expected_diff: vec![DiffEntry {
                path: "networks/vlan-30/name".to_owned(),
                before: None,
                after: Some("IoT".to_owned()),
            }],
            task: None,
        };
        let bytes = to_cbor(&params).expect("cbor");
        assert_eq!(VlanStepParams::decode(&bytes).expect("decode"), params);
        assert_eq!(params.args()["vid"], "30");
    }
}
