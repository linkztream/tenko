//! `ipam.move.dns` (IPAM-19 step 3): the DNS records of a moved address.
//!
//! The step is automatic when the submit found the name under a zone Tenko serves
//! ([`DnsStepPlan`] in its parameters) and the server runs the DNS actuator: it removes the
//! A or AAAA record and the PTR of the old address and writes those of the new one,
//! through the actuator with the move treated as in flight, and keeps the changed records
//! as its output (JSON of [`MoveDnsOutput`]). A name whose RRset another origin holds stops
//! it with 409 `ipam.move.dns_collision`, and the job rolls back. Its compensation plans
//! again without the move and writes the old records back.
//!
//! Otherwise it is the manual task of Slice 1: point the name to the new address.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenko_core::{CodedError, JobId, MessageKey, dns::DnsName};
use tenko_jobs::{
    ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::{ReadConsistency, ReadView};

use super::{codes, steps::MoveStepParams};
use crate::dns::{
    DnsActuation, DnsActuator, OrphanRule, PlanOptions,
    moves::{batches_for, held_for, texts},
    plan::{self, MoveOverride},
};

/// What the submit found for the DNS step: the zone Tenko serves for the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsStepPlan {
    /// The zone apex.
    pub zone: String,
}

/// What the automatic DNS step changed, kept as JSON in the step's output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveDnsOutput {
    /// The records removed, in presentation form.
    #[serde(default)]
    pub removed: Vec<String>,
    /// The records added.
    #[serde(default)]
    pub added: Vec<String>,
}

/// The handler of `ipam.move.dns`; without an actuator every step is the manual task.
#[derive(Debug, Clone, Default)]
pub struct MoveDnsStep {
    actuator: Option<Arc<DnsActuator>>,
}

impl MoveDnsStep {
    /// The handler without DNS: the manual task.
    pub fn manual() -> Self {
        Self { actuator: None }
    }

    /// The handler over the actuator.
    pub fn new(actuator: Arc<DnsActuator>) -> Self {
        Self {
            actuator: Some(actuator),
        }
    }

    fn task(params: &MoveStepParams) -> ManualTask {
        params.task.clone().unwrap_or_else(|| ManualTask {
            instruction: MessageKey::from_static("ipam.move.task.dns"),
            args: params.args(),
            undo: None,
        })
    }

    fn automatic<'a>(&'a self, params: &MoveStepParams) -> Option<(&'a DnsActuator, DnsName)> {
        let actuator = self.actuator.as_deref()?;
        params.dns.as_ref()?;
        let name = params.dns_name.as_ref().map(DnsName::from)?;
        Some((actuator, name))
    }
}

fn collision(name: &DnsName, held: &[String]) -> StepError {
    StepError::Coded(Box::new(
        CodedError::new(
            codes::DNS_COLLISION,
            409,
            format!(
                "the DNS records of {name} cannot move: {}; nothing was written",
                held.join("; ")
            ),
        )
        .with_title("The DNS name is held by another origin")
        .with_param("name", name.to_string())
        .with_param("held", held.join("; ")),
    ))
}

fn failed(name: &DnsName, report: &DnsActuation) -> Option<StepError> {
    let first = report.failures.first()?;
    let code = if first.code == tenko_core::dns::codes::RECORD_ORIGIN {
        codes::DNS_COLLISION
    } else {
        codes::DNS_FAILED
    };
    Some(StepError::Coded(Box::new(
        CodedError::new(
            code,
            409,
            format!(
                "the DNS records of {name} could not be written in {}: {}",
                first.zone, first.detail
            ),
        )
        .with_param("name", name.to_string())
        .with_param("zone", first.zone.clone())
        .with_param("cause", first.code.clone()),
    )))
}

/// Plans the records of `name` with the options and writes them; the changed records.
async fn apply(
    actuator: &DnsActuator,
    cx: &StepContext,
    name: &DnsName,
    options: &PlanOptions,
) -> Result<MoveDnsOutput, StepError> {
    let view = cx.store.read(ReadConsistency::Local).await?;
    let planned = plan::plan(view.as_ref(), options).map_err(|error| StepError::coded(&error))?;
    drop(view);
    let held = held_for(&planned, name);
    if !held.is_empty() {
        return Err(collision(name, &held));
    }
    let batches = batches_for(&planned, name);
    let (removed, added) = texts(&batches);
    let mut report = DnsActuation::default();
    actuator.write(&cx.request, &batches, &mut report).await;
    if let Some(error) = failed(name, &report) {
        return Err(error);
    }
    Ok(MoveDnsOutput { removed, added })
}

fn options(params: &MoveStepParams, job: JobId, moved: bool) -> PlanOptions {
    PlanOptions {
        orphans: OrphanRule::Remove,
        moves: if moved {
            vec![MoveOverride {
                old: params.address,
                new: params.new_address,
            }]
        } else {
            Vec::new()
        },
        ignore_jobs: if moved { Vec::new() } else { vec![job] },
    }
}

#[async_trait::async_trait]
impl StepHandler for MoveDnsStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(super::steps::DNS)
    }

    /// Running it again plans again and finds the records written.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        if let Some((_, name)) = self.automatic(&params) {
            let mut args = params.args();
            args.insert("name".to_owned(), name.to_string());
            if let Some(plan) = &params.dns {
                args.insert("zone".to_owned(), plan.zone.clone());
            }
            return Ok(StepPreview {
                summary: MessageKey::from_static("ipam.move.step.dns"),
                args,
                changes: params.changes(),
                manual: None,
                warnings: Vec::new(),
            });
        }
        let task = Self::task(&params);
        Ok(StepPreview {
            summary: task.instruction.clone(),
            args: task.args.clone(),
            changes: params.changes(),
            manual: Some(task),
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let Some((actuator, name)) = self.automatic(&params) else {
            return Ok(StepOutcome::Manual(Self::task(&params)));
        };
        let output = apply(actuator, cx, &name, &options(&params, cx.job, true)).await?;
        let bytes = serde_json::to_vec(&output)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepOutcome::Done {
            output: Some(bytes.into()),
        })
    }

    async fn compensate(
        &self,
        params: &[u8],
        output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let params = MoveStepParams::decode(params)?;
        // ADR 0027: the moving client goes first, before anything is undone.
        super::lease::clear(cx, None).await?;
        let Some((actuator, name)) = self.automatic(&params) else {
            return Ok(());
        };
        if output.is_none() {
            return Ok(());
        }
        apply(actuator, cx, &name, &options(&params, cx.job, false))
            .await
            .map(drop)
            .inspect_err(|_| {
                tracing::warn!(job = %cx.job, %name, "the DNS records of a move could not be put back; the reconciler restores them");
            })
    }
}
