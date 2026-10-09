//! The built-in `jobs.manual` step: a task for a person, such as the DHCP and DNS steps of
//! the Phase 1 move job (IPAM-19).
//!
//! Its parameters are a CBOR [`ManualTask`]. Executing it holds the job in `waiting` until
//! someone completes the task (`POST /jobs/{id}/steps/{index}/complete`) or the step
//! timeout passes. When the job rolls back after the task was done, the task's `undo`
//! message becomes a manual undo task; without one there is nothing to undo.

use std::time::Duration;

use tenko_core::{
    codec::{CodecError, from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_store::ReadView;

use crate::model::{
    ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview, StepSpec,
};

/// The step kind of [`ManualStep`].
pub const MANUAL: StepKind = StepKind::from_static("jobs.manual");

/// The handler of `jobs.manual`, registered in every engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManualStep;

impl ManualStep {
    /// A step that asks a person to do `task`, waiting at most `timeout` (the job timeout
    /// when `None`).
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the task cannot be encoded.
    pub fn spec(task: &ManualTask, timeout: Option<Duration>) -> Result<StepSpec, CodecError> {
        Ok(StepSpec {
            kind: MANUAL,
            params: HexBytes(to_cbor(task)?.to_vec()),
            timeout,
        })
    }

    fn task(params: &[u8]) -> Result<ManualTask, StepError> {
        from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))
    }
}

#[async_trait::async_trait]
impl StepHandler for ManualStep {
    fn kind(&self) -> StepKind {
        MANUAL
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let task = Self::task(params)?;
        Ok(StepPreview {
            summary: task.instruction.clone(),
            args: task.args.clone(),
            changes: Vec::new(),
            manual: Some(task),
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], _cx: &StepContext) -> Result<StepOutcome, StepError> {
        Ok(StepOutcome::Manual(Self::task(params)?))
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        // A task with an `undo` message never gets here: the engine turns it into a manual
        // undo task. Without one, the task declared that it leaves nothing to undo.
        Ok(())
    }
}
