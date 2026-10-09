//! The job steps of the connector service: `connect.write` (the inline job of every edit,
//! decision Q4) and `connect.poll` (the job of a run a person asked for).

use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, ConnectorId, MessageKey, ObjectRef,
    codec::{from_cbor, to_cbor},
};
use tenko_jobs::{StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview};
use tenko_store::{ReadView, WriteBatch};

use super::{
    ConnectorHost,
    model::{RunOutcome, RunTrigger, kinds},
};

/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

/// Stages the write batch of an edit, so the change, the job record and the audit draft
/// commit as one write; outside the engine it proposes the batch itself.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WriteStep;

/// Parameters of `connect.write`: the batch and the instance it changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WriteParams {
    pub(crate) connector: ConnectorId,
    pub(crate) summary: String,
    pub(crate) batch: WriteBatch,
}

#[async_trait::async_trait]
impl StepHandler for WriteStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(kinds::WRITE_STEP)
    }

    /// Not idempotent: its preconditions fail once the batch committed.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(kinds::WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), params.summary)]),
            changes: vec![ObjectRef::from(params.connector)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        match tenko_jobs::stage(cx, params.batch.clone()) {
            Ok(()) => Ok(StepOutcome::Done { output: None }),
            Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
                let committed = cx.store.propose(params.batch).await?;
                let output = to_cbor(&committed).map_err(|error| StepError::coded(&error))?;
                Ok(StepOutcome::Done {
                    output: Some(output),
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Err(StepError::NotCompensable)
    }
}

/// Runs a connector instance once: reads the plugin and hands the observations on.
pub(crate) struct PollStep {
    pub(crate) host: Weak<ConnectorHost>,
}

/// Parameters of `connect.poll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PollParams {
    pub(crate) connector: ConnectorId,
}

#[async_trait::async_trait]
impl StepHandler for PollStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(kinds::POLL_STEP)
    }

    /// A read: running it again after a restart is harmless.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: PollParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(kinds::POLL_PREVIEW),
            args: BTreeMap::from([("connector".to_owned(), params.connector.to_string())]),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: PollParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let Some(host) = self.host.upgrade() else {
            return Err(StepError::Coded(Box::new(CodedError::new(
                "connect.unavailable",
                503,
                "the connector service has stopped",
            ))));
        };
        run_step(&host, params.connector, cx).await
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        // A read changes nothing to undo.
        Ok(())
    }
}

async fn run_step(
    host: &Arc<ConnectorHost>,
    connector: ConnectorId,
    cx: &StepContext,
) -> Result<StepOutcome, StepError> {
    let run = host
        .run(
            connector,
            RunTrigger::Manual,
            Some(cx.job),
            cx.request.principal.user(),
        )
        .await
        .map_err(|error| StepError::Coded(error.0))?;
    match run.outcome {
        RunOutcome::Succeeded => {
            let output = to_cbor(&run).map_err(|error| StepError::coded(&error))?;
            Ok(StepOutcome::Done {
                output: Some(output),
            })
        }
        RunOutcome::Failed => {
            Err(StepError::Coded(Box::new(run.error.unwrap_or_else(|| {
                CodedError::new("connect.run.failed", 502, "the run failed")
            }))))
        }
    }
}
