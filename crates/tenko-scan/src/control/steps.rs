//! The job steps of the scan control: the inline edit (`scan.write`) and the three steps of
//! a scan on demand (`scan.dispatch`, `scan.await`, `scan.diff`). Every step of a scan is
//! idempotent: it reads the run and the commands from the store and does only what is not
//! done yet, so a runner that takes over a job after a failover runs it again safely.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use tenko_cluster::{
    model::tables::NODES,
    node_sync::{
        commands::{self, CommandRecord, CommandState, SCAN_CANCEL, SCAN_RUN},
        payload::{CancelArgs, ScanRunArgs, encode_args},
        tables::NODE_COMMANDS,
    },
};
use tenko_core::{
    Coded, CodedError, JobId, MessageKey, NodeId, ObjectRef, RequestCtx, Revision, Timestamp,
    codec::{from_cbor, to_cbor},
    observe::ObservationSource,
    serde_util::HexBytes,
};
use tenko_ipam::observe::{
    source_key,
    view::{FactQuery, list_facts},
};
use tenko_jobs::{
    JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, StoreError, WatchFilter, WriteBatch};
use uuid::Uuid;

use super::{
    Shared, codes, diff, kinds, messages, methods_of,
    model::{
        Baseline, BaselineFact, MAX_BASELINE, RunPart, ScanRun, ScanState,
        tables::{BASELINES, RUNS},
    },
    nodes_of, target,
};
use crate::method::MethodKind;

/// Parameters of the steps of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RunParams {
    /// The run.
    pub run: Uuid,
}

/// Registers the steps with `engine`.
pub(crate) fn register(engine: &mut JobEngine, shared: &Shared) {
    engine.register(Arc::new(WriteStep));
    engine.register(Arc::new(DispatchStep(shared.clone())));
    engine.register(Arc::new(AwaitStep));
    engine.register(Arc::new(DiffStep));
}

/// Parameters of `scan.write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WriteParams {
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
}

/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

fn job_error(error: &tenko_jobs::JobError) -> CodedError {
    match error {
        tenko_jobs::JobError::Store(store) => store.to_coded_error(),
        other => other.to_coded_error(),
    }
}

/// Commits an edit as an inline job `scan.edit` with the step `scan.write`.
pub(crate) async fn commit(
    engine: &JobEngine,
    cx: &RequestCtx,
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
) -> Result<Revision, CodedError> {
    let params = WriteParams {
        summary,
        targets: targets.clone(),
        batch,
    };
    let params = HexBytes(
        to_cbor(&params)
            .map_err(|error| error.to_coded_error())?
            .to_vec(),
    );
    let spec = JobSpec {
        kind: JobKind::from_static(kinds::EDIT_JOB),
        title: MessageKey::from_static(messages::EDIT_TITLE),
        targets,
        steps: vec![StepSpec {
            kind: StepKind::from_static(kinds::WRITE_STEP),
            params,
            timeout: None,
        }],
        timeout: Duration::from_secs(30),
        group: None,
        group_limit: None,
        idempotency: None,
        node: None,
    };
    let job = engine
        .run_inline(spec, cx)
        .await
        .map_err(|error| job_error(&error))?;
    Ok(job.revision)
}

/// Stages the batch of an edit, so the change, the job record and the audit record commit
/// as one write.
#[derive(Debug, Clone, Copy, Default)]
struct WriteStep;

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
            summary: MessageKey::from_static(messages::WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), params.summary)]),
            changes: params.targets,
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
                cx.store.propose(params.batch).await?;
                Ok(StepOutcome::Done { output: None })
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

/// Writes the job id into a run, unless the run has one already.
pub(crate) async fn set_job(store: &dyn tenko_store::Store, run: Uuid, job: JobId) {
    for _ in 0..4 {
        let Ok(view) = store.read(ReadConsistency::Local).await else {
            return;
        };
        let Ok(Some((mut record, revision))) = view.get_typed(&RUNS, &run) else {
            return;
        };
        drop(view);
        if record.job.is_some() {
            return;
        }
        record.job = Some(job);
        let mut batch =
            WriteBatch::for_request(&RequestCtx::system(tenko_core::SystemComponent::Scan));
        batch.expect_typed(&RUNS, &run, Some(revision));
        if batch.put_typed(&RUNS, &run, &record).is_err() {
            return;
        }
        match store.propose(batch).await {
            Ok(_) => return,
            Err(StoreError::PreconditionFailed(_)) => {}
            Err(error) => {
                tracing::debug!(%error, "the job of a scan run could not be recorded");
                return;
            }
        }
    }
}

fn step_error(error: CodedError) -> StepError {
    StepError::Coded(Box::new(error))
}

fn params_of(params: &[u8]) -> Result<RunParams, StepError> {
    from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))
}

async fn read_run(
    cx: &StepContext,
    run: Uuid,
) -> Result<(Arc<dyn ReadView>, ScanRun, Revision), StepError> {
    let view = cx.store.read(ReadConsistency::Local).await?;
    let (record, revision) = view.get_typed(&RUNS, &run)?.ok_or_else(|| {
        step_error(CodedError::new(
            codes::JOB_NOT_FOUND,
            404,
            format!("there is no scan run {run}"),
        ))
    })?;
    Ok((view, record, revision))
}

/// Stages `batch` with the step, or proposes it when the step runs outside the engine.
async fn stage_or_propose(cx: &StepContext, batch: WriteBatch) -> Result<(), StepError> {
    match tenko_jobs::stage(cx, batch.clone()) {
        Ok(()) => Ok(()),
        Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
            cx.store.propose(batch).await?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn preview(summary: &'static str, run: Uuid) -> StepPreview {
    StepPreview {
        summary: MessageKey::from_static(summary),
        args: BTreeMap::from([("run".to_owned(), run.to_string())]),
        changes: Vec::new(),
        manual: None,
        warnings: Vec::new(),
    }
}

/// The source keys the methods of a run give on its probes.
fn sources(nodes: &BTreeSet<NodeId>, methods: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for node in nodes {
        for method in methods {
            if let Some(kind) = MethodKind::parse(method) {
                out.insert(source_key(&ObservationSource::Probe {
                    node: *node,
                    method: kind.probe_method(),
                }));
            }
        }
    }
    out
}

/// The facts of the run's networks from its probes and methods.
fn baseline(
    view: &dyn ReadView,
    run: &ScanRun,
    sources: &BTreeSet<String>,
    now: Timestamp,
) -> Result<Baseline, StepError> {
    let mut out = Baseline::default();
    for network in &run.networks {
        let mut cursor = None;
        loop {
            let page = list_facts(
                view,
                &FactQuery {
                    within: Some(*network),
                    limit: Some(tenko_ipam::observe::view::MAX_LIMIT),
                    cursor: cursor.take(),
                    ..FactQuery::default()
                },
                now,
            )
            .map_err(|error| step_error(error.into_coded()))?;
            for fact in page.items {
                if !sources.contains(&fact.source_key) {
                    continue;
                }
                if out.facts.len() >= MAX_BASELINE {
                    out.truncated = true;
                    return Ok(out);
                }
                out.facts.push(BaselineFact {
                    current: fact.is_current(now),
                    source: fact.source_key,
                    fact_type: fact.subject.type_name().to_owned(),
                    subject: fact.subject_key,
                    observed: fact.observed,
                });
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    Ok(out)
}

/// `scan.dispatch`: takes the baseline and issues one command per probe and part.
struct DispatchStep(Shared);

#[async_trait::async_trait]
impl StepHandler for DispatchStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(kinds::DISPATCH_STEP)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        Ok(preview(messages::DISPATCH_PREVIEW, params_of(params)?.run))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = params_of(params)?;
        let (view, mut run, revision) = read_run(cx, params.run).await?;
        if !run.parts.is_empty() || matches!(run.state, ScanState::Cancelled) {
            return Ok(StepOutcome::Done { output: None });
        }
        let now = Timestamp::now();
        let default_vrf = target::default_vrf(view.as_ref()).map_err(step_error)?;
        let candidates = target::candidates(view.as_ref(), self.0.local).map_err(step_error)?;
        let shares = target::shares(&candidates, &run.networks, run.vrf, default_vrf);
        let methods = methods_of(&run.kinds);
        let mut batch = WriteBatch::for_request(&cx.request);
        if shares.is_empty() {
            run.state = ScanState::Failed;
            run.error = Some("no probe's scope covers the target any more".to_owned());
            run.finished_at = Some(now);
            run.job = Some(cx.job);
            batch.expect_typed(&RUNS, &run.id, Some(revision));
            batch.put_typed(&RUNS, &run.id, &run)?;
            stage_or_propose(cx, batch).await?;
            return Err(step_error(CodedError::new(
                codes::JOB_NO_PROBE,
                422,
                "no probe's scope covers the target any more",
            )));
        }
        let nodes: BTreeSet<NodeId> = shares.iter().map(|share| share.node).collect();
        let base = baseline(view.as_ref(), &run, &sources(&nodes, &methods), now)?;
        drop(view);
        let deadline_secs =
            u32::try_from(run.deadline.saturating_since(now).as_secs()).unwrap_or(u32::MAX);
        for share in &shares {
            let args = ScanRunArgs {
                methods: methods.clone(),
                target: Some(share.target_text()),
                ignore_blackout: false,
                deadline_secs: Some(deadline_secs),
            };
            let payload = encode_args(&args).map_err(|error| step_error(error.into_coded()))?;
            let mut record = CommandRecord::new(share.node, SCAN_RUN, payload, now);
            record.issued_by = run.requested_by;
            record.run = Some(run.id);
            record.expires_at = Some(run.deadline);
            commands::stage_issue(&mut batch, &record)?;
            run.parts.push(RunPart {
                node: share.node,
                command: record.id,
                target: share.target_text(),
            });
        }
        run.state = ScanState::Running;
        run.job = Some(cx.job);
        batch.expect_typed(&RUNS, &run.id, Some(revision));
        batch.put_typed(&RUNS, &run.id, &run)?;
        batch.put_typed(&BASELINES, &run.id, &base)?;
        stage_or_propose(cx, batch).await?;
        tracing::info!(run = %run.id, parts = run.parts.len(), baseline = base.facts.len(), "scan dispatched to the probes");
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        cancel_run(cx, params_of(params)?.run).await
    }
}

/// Withdraws the commands of a run that are not over, asks the probes that work on one to
/// cancel it, and marks the run cancelled.
async fn cancel_run(cx: &StepContext, run: Uuid) -> Result<(), StepError> {
    let (view, mut record, revision) = read_run(cx, run).await?;
    let now = Timestamp::now();
    let mut batch = WriteBatch::for_request(&cx.request);
    for part in &record.parts {
        let Some((command, command_revision)) =
            commands::get(view.as_ref(), part.node, part.command)?
        else {
            continue;
        };
        if command.state.is_final() {
            continue;
        }
        if matches!(
            command.state,
            CommandState::Accepted | CommandState::Running
        ) {
            let payload = encode_args(&CancelArgs {
                command: command.id,
            })
            .map_err(|error| step_error(error.into_coded()))?;
            let mut cancel = CommandRecord::new(part.node, SCAN_CANCEL, payload, now);
            cancel.run = Some(run);
            cancel.expires_at = now.checked_add(Duration::from_secs(600));
            commands::stage_issue(&mut batch, &cancel)?;
        }
        commands::stage_expire(
            &mut batch,
            &command,
            command_revision,
            CommandState::Cancelled,
            now,
        )?;
    }
    drop(view);
    if record.finished_at.is_none() {
        record.state = ScanState::Cancelled;
        record.finished_at = Some(now);
        batch.expect_typed(&RUNS, &run, Some(revision));
        batch.put_typed(&RUNS, &run, &record)?;
    }
    if !batch.is_empty() {
        stage_or_propose(cx, batch).await?;
    }
    Ok(())
}

/// `scan.await`: waits until every command is over and its results are in, or the
/// deadline; marks what is left as expired.
struct AwaitStep;

/// How often the waiting step looks again without a change.
const AWAIT_POLL: Duration = Duration::from_secs(5);

#[async_trait::async_trait]
impl StepHandler for AwaitStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(kinds::AWAIT_STEP)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        Ok(preview(messages::AWAIT_PREVIEW, params_of(params)?.run))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = params_of(params)?;
        let filter = WatchFilter::tables([NODE_COMMANDS.name().clone()]);
        let mut changes = None;
        loop {
            let (view, run, _) = read_run(cx, params.run).await?;
            let now = Timestamp::now();
            let mut open = Vec::new();
            for part in &run.parts {
                if let Some((command, revision)) =
                    commands::get(view.as_ref(), part.node, part.command)?
                    && !command.settled()
                {
                    open.push((command, revision));
                }
            }
            if open.is_empty() || run.finished_at.is_some() {
                return Ok(StepOutcome::Done { output: None });
            }
            if now >= run.deadline {
                let mut batch = WriteBatch::for_request(&cx.request);
                for (command, revision) in &open {
                    // A command that finished but whose results did not all arrive stays
                    // done; the diff uses what arrived.
                    commands::stage_expire(
                        &mut batch,
                        command,
                        *revision,
                        CommandState::Expired,
                        now,
                    )?;
                }
                if !batch.is_empty() {
                    stage_or_propose(cx, batch).await?;
                }
                tracing::info!(run = %run.id, open = open.len(), "the scan deadline passed");
                return Ok(StepOutcome::Done { output: None });
            }
            let revision = view.revision();
            drop(view);
            if changes.is_none() {
                changes = cx.store.watch(Some(revision), filter.clone()).ok();
            }
            let wait = run
                .deadline
                .saturating_since(now)
                .min(AWAIT_POLL)
                .max(Duration::from_millis(50));
            let next = async {
                if let Some(stream) = changes.as_mut() {
                    stream.next().await.is_some_and(|item| item.is_ok())
                } else {
                    tokio::time::sleep(wait).await;
                    true
                }
            };
            let woke = tokio::select! {
                woke = next => woke,
                () = tokio::time::sleep(wait) => true,
            };
            if !woke {
                changes = None;
            }
        }
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

/// `scan.diff`: compares what arrived with the baseline and ends the run.
struct DiffStep;

#[async_trait::async_trait]
impl StepHandler for DiffStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(kinds::DIFF_STEP)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        Ok(preview(messages::DIFF_PREVIEW, params_of(params)?.run))
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = params_of(params)?;
        let (view, mut run, revision) = read_run(cx, params.run).await?;
        if run.diff.is_some() || matches!(run.state, ScanState::Cancelled | ScanState::Failed) {
            return Ok(StepOutcome::Done { output: None });
        }
        let now = Timestamp::now();
        let baseline = view
            .get_typed(&BASELINES, &run.id)?
            .map(|(baseline, _)| baseline)
            .unwrap_or_default();
        let default_vrf = target::default_vrf(view.as_ref()).map_err(step_error)?;
        let mut node_vrfs: BTreeMap<NodeId, Option<tenko_core::VrfId>> = BTreeMap::new();
        for node in nodes_of(&run) {
            let vrf = view
                .get_typed(&NODES, &node.0)?
                .and_then(|(record, _)| record.vrf)
                .or(default_vrf);
            node_vrfs.insert(node, vrf);
        }
        let mut results = Vec::new();
        let mut finished_nodes = BTreeSet::new();
        let mut all_done = true;
        for part in &run.parts {
            let command =
                commands::get(view.as_ref(), part.node, part.command)?.map(|(record, _)| record);
            match &command {
                Some(command) if command.state == CommandState::Done => {
                    finished_nodes.insert(part.node);
                    if !command.results_in() {
                        all_done = false;
                    }
                }
                _ => all_done = false,
            }
            results.extend(commands::results_of(view.as_ref(), part.command)?);
        }
        drop(view);
        let methods = methods_of(&run.kinds);
        let seen = diff::seen(
            &results,
            |node| node_vrfs.get(&node).copied().flatten(),
            now,
        );
        let finished = sources(&finished_nodes, &methods);
        let result = diff::compare(&baseline, &seen, &finished);
        run.state = if all_done {
            ScanState::Done
        } else {
            ScanState::Partial
        };
        run.diff = Some(result);
        run.finished_at = Some(now);
        run.job = Some(cx.job);
        let mut batch = WriteBatch::for_request(&cx.request);
        batch.expect_typed(&RUNS, &run.id, Some(revision));
        batch.put_typed(&RUNS, &run.id, &run)?;
        stage_or_propose(cx, batch).await?;
        tracing::info!(run = %run.id, state = ?run.state, "scan finished");
        Ok(StepOutcome::Done { output: None })
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
