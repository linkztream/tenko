//! The nudge of a move (ADR 0028, `docs/moves.md` section 4): after the network change, a
//! client that does not come back by itself is made to start over, once.
//!
//! `ipam.move.nudge` runs right after `ipam.move.controller`. It waits up to
//! `[dhcp.moves] reappear_secs` (30 s) for the client to come back by itself: the L2 change
//! drops the link on many switches, and a client that notices asks for an address at once.
//! The job sees that when it follows the client's DHCP (it has a moving client): the dhcp
//! role saw the client's exchange on the target network, or the lease table holds its
//! lease there. Only when it did not come back does the step bounce its switch port
//! (wired, after a port profile change) or disconnect it from its access point (wireless,
//! after a per-client VLAN), through the network controller, which keeps the policy of a
//! write and, for a bounce, the way back up of the port.
//!
//! A refusal or a controller error at that point is no failure of the move: the client
//! still comes back with its short lease, and the step's output (JSON of
//! [`MoveNudgeOutput`]) says what happened. A port that does not come up again after the
//! bounce fails the step with `connect.port_stuck` (the job rolls back, and the health view
//! shows the port until the connector host brought it up). A step that ran again after an
//! interruption does not nudge a second time.
//!
//! On a rollback, the compensation of `ipam.move.controller` does the same bounce or kick
//! right after the L2 undo, without waiting, so the client gets its old address back at
//! once.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{CodedError, MessageKey, Timestamp};
use tenko_jobs::{
    JobEngine, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::ReadConsistency;

use super::{
    MoveL2Problem,
    dhcp::DhcpMoves,
    steps::{L2StepPlan, MoveStepParams},
};
use crate::vlan::controllers::{Controllers, NudgeChange, NudgeOutcome, NudgeReport};

/// Step kind: the bounce or kick after the network change.
pub const NUDGE: &str = "ipam.move.nudge";
/// The preview kind of [`NUDGE`].
pub const NUDGE_KIND: &str = "l2.nudge";
/// The code of a port that did not come up again after a bounce.
pub const PORT_STUCK: &str = "connect.port_stuck";
/// How much longer than its wait the step may run: the bounce, its way back up and the
/// controller calls.
pub const STEP_MARGIN_SECS: u64 = 300;

/// The nudge the submit planned, carried by the controller step and the nudge step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NudgePlan {
    /// The bounce or kick.
    pub change: NudgeChange,
    /// How long the job waits for the client to come back by itself first.
    pub reappear_secs: u32,
}

/// What `ipam.move.nudge` did, kept as JSON in its output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveNudgeOutput {
    /// The bounce or kick that was planned.
    pub change: NudgeChange,
    /// When the client was seen back by itself, so nothing was done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reappeared_at: Option<Timestamp>,
    /// How it was seen: `dhcp` (its exchange on the target network) or `lease`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reappeared_by: Option<String>,
    /// What the controller reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<NudgeReport>,
    /// Why nothing was done: a refusal or a controller error at the time of the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<MoveL2Problem>,
    /// Whether the step ran again after an interruption and did not nudge a second time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interrupted: bool,
}

/// `ipam.move.nudge` (see the module documentation).
#[derive(Debug, Clone)]
pub struct MoveNudgeStep {
    controllers: Arc<Controllers>,
    dhcp: Option<DhcpMoves>,
}

impl MoveNudgeStep {
    /// The handler over the controller slot and, when the dhcp role runs in the process,
    /// its slot.
    pub fn new(controllers: Arc<Controllers>, dhcp: Option<DhcpMoves>) -> Self {
        Self { controllers, dhcp }
    }

    /// Whether the client came back by itself since `since`, and how it was seen.
    async fn reappeared(
        &self,
        cx: &StepContext,
        params: &MoveStepParams,
        since: Timestamp,
    ) -> Result<Option<(Timestamp, &'static str)>, StepError> {
        let Some(plan) = &params.lease else {
            return Ok(None);
        };
        if let Some(seen) = self
            .dhcp
            .as_ref()
            .and_then(DhcpMoves::get)
            .and_then(|role| role.activity(cx.job, plan.mac))
            .and_then(|activity| activity.on_target)
            .filter(|seen| *seen >= since)
        {
            return Ok(Some((seen, "dhcp")));
        }
        if plan.target.is_none() {
            return Ok(None);
        }
        let view = cx.store.read(ReadConsistency::Local).await?;
        Ok(
            super::clock::target_lease(view.as_ref(), params, plan, since, Timestamp::now())?
                .map(|lease| (lease.cltt, "lease")),
        )
    }
}

fn json(output: &MoveNudgeOutput) -> Result<StepOutcome, StepError> {
    let bytes =
        serde_json::to_vec(output).map_err(|error| StepError::InvalidParams(error.to_string()))?;
    Ok(StepOutcome::Done {
        output: Some(bytes.into()),
    })
}

/// The step error of a port that a bounce left down.
fn stuck(plan: &L2StepPlan, change: &NudgeChange, code: &str, detail: &str) -> StepError {
    let mut error = CodedError::new(
        PORT_STUCK,
        503,
        format!(
            "the client's switch port did not come up again after the bounce ({code}: {detail}); \
             the connector host keeps trying and the health view shows the port"
        ),
    )
    .with_title("A switch port stayed down")
    .with_param("connector", plan.connector_name.clone())
    .with_param("cause", code.to_owned());
    if let NudgeChange::BouncePort { device, port, .. } = change {
        error = error
            .with_param("device", plan.attachment.device_name.clone())
            .with_param("device_id", device.clone())
            .with_param("port", port.to_string());
    }
    StepError::Coded(Box::new(error))
}

/// Bounces or kicks for the job of `cx`, for the rollback after the L2 undo: no wait, and
/// whatever happens is logged, never an error of the rollback.
pub(super) async fn on_rollback(controllers: &Controllers, plan: &L2StepPlan, cx: &StepContext) {
    let Some(nudge) = &plan.nudge else {
        return;
    };
    let Some(port) = controllers.get() else {
        return;
    };
    match port
        .nudge(
            plan.connector,
            &nudge.change,
            Some(cx.job),
            cx.request.principal.user(),
        )
        .await
    {
        Ok(report) => match report.outcome {
            NudgeOutcome::Done => tracing::info!(
                job = %cx.job,
                "the client was nudged after the L2 undo, so it takes its old address at once"
            ),
            NudgeOutcome::Failed { code, .. } | NudgeOutcome::Stuck { code, .. } => {
                tracing::warn!(job = %cx.job, %code, "the nudge after the L2 undo did not work");
            }
        },
        Err(error) => tracing::warn!(
            job = %cx.job,
            code = %error.code,
            "the nudge after the L2 undo was not done; the client comes back with its lease"
        ),
    }
}

#[async_trait::async_trait]
impl StepHandler for MoveNudgeStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(NUDGE)
    }

    /// Running it again after an interruption does not nudge a second time.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(
        &self,
        params: &[u8],
        _view: &dyn tenko_store::ReadView,
    ) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        let mut args = params.args();
        let summary = match params.l2.as_ref().and_then(|plan| plan.nudge.as_ref()) {
            Some(NudgePlan {
                change:
                    NudgeChange::BouncePort {
                        port, down_secs, ..
                    },
                reappear_secs,
            }) => {
                args.insert("port".to_owned(), port.to_string());
                args.insert("down_secs".to_owned(), down_secs.to_string());
                args.insert("reappear_secs".to_owned(), reappear_secs.to_string());
                "ipam.move.step.nudge_bounce"
            }
            Some(NudgePlan { reappear_secs, .. }) => {
                args.insert("reappear_secs".to_owned(), reappear_secs.to_string());
                "ipam.move.step.nudge_kick"
            }
            None => "ipam.move.step.nudge_kick",
        };
        if let Some(plan) = &params.l2 {
            args.insert("connector".to_owned(), plan.connector_name.clone());
            args.insert("device".to_owned(), plan.attachment.device_name.clone());
            args.insert("mac".to_owned(), plan.mac.to_string());
        }
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
        let Some(plan) = params.l2.clone() else {
            return Ok(StepOutcome::Skip);
        };
        let Some(nudge) = plan.nudge.clone() else {
            return Ok(StepOutcome::Skip);
        };
        let mut output = MoveNudgeOutput {
            change: nudge.change.clone(),
            reappeared_at: None,
            reappeared_by: None,
            report: None,
            problem: None,
            interrupted: false,
        };
        if cx.attempt > 1 {
            output.interrupted = true;
            return json(&output);
        }
        let since = Timestamp::now();
        let until =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(nudge.reappear_secs));
        loop {
            if let Some((at, by)) = self.reappeared(cx, &params, since).await? {
                output.reappeared_at = Some(at);
                output.reappeared_by = Some(by.to_owned());
                return json(&output);
            }
            if tokio::time::Instant::now() >= until {
                break;
            }
            tokio::time::sleep_until(
                until.min(tokio::time::Instant::now() + Duration::from_secs(1)),
            )
            .await;
        }
        let Some(port) = self.controllers.get() else {
            output.problem = Some(MoveL2Problem {
                code: crate::vlan::codes::CONTROLLERS_UNAVAILABLE.to_owned(),
                detail: "the network controllers are not available on this server".to_owned(),
            });
            return json(&output);
        };
        match port
            .nudge(
                plan.connector,
                &nudge.change,
                Some(cx.job),
                cx.request.principal.user(),
            )
            .await
        {
            Ok(report) => {
                if let NudgeOutcome::Stuck { code, detail } = &report.outcome {
                    return Err(stuck(&plan, &nudge.change, code, detail));
                }
                if let NudgeOutcome::Failed { code, .. } = &report.outcome {
                    tracing::warn!(job = %cx.job, %code, "the nudge of a moved client did not work; it comes back with its short lease");
                }
                output.report = Some(report);
            }
            Err(error) => {
                tracing::warn!(
                    job = %cx.job,
                    code = %error.code,
                    "the nudge of a moved client was not done; it comes back with its short lease"
                );
                output.problem = Some(MoveL2Problem {
                    code: error.code.to_string(),
                    detail: error.detail,
                });
            }
        }
        json(&output)
    }

    /// Nothing to undo but the moving client (ADR 0027); the nudge after the L2 undo is the
    /// controller step's.
    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        super::lease::clear(cx, None).await
    }
}

/// Registers `ipam.move.nudge` over the controller slot and the dhcp role's slot, in place
/// of the handler without the role.
pub fn register_steps(engine: &mut JobEngine, controllers: &Arc<Controllers>, dhcp: &DhcpMoves) {
    engine.register(Arc::new(MoveNudgeStep::new(
        Arc::clone(controllers),
        Some(dhcp.clone()),
    )));
}
