//! Reading jobs for the API: summaries, details and filtered pages (plan section 4).
//!
//! Lists run newest first (job ids are UUIDv7) and page by an opaque cursor, the id of
//! the last job of the previous page. A target filter scans `jobs.by_target`, a single
//! state scans `jobs.by_state`, anything else scans `jobs.jobs`; remaining filters are
//! applied while scanning, so pages stay full: the group filter and the scope of a scoped
//! principal (IAM-01) of [`JobFilter`] too ([`list_filtered`]).

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, NodeId, ObjectRef, Revision, Timestamp, codec::encode_key, ipam::Stamp,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError};
use utoipa::ToSchema;

use crate::{
    event::StepStateKind,
    model::{GroupKey, Job, JobError, JobKind, JobPreview, JobState, StepKind, StepState},
    persist::{self, PAGE},
    tables::{BY_STATE, BY_TARGET, JOBS, PREVIEWS, Transition},
};
use tenko_core::MessageKey;

/// Most jobs in one page.
pub const MAX_LIMIT: usize = 1_000;
/// Jobs in a page when the request names no limit.
pub const DEFAULT_LIMIT: usize = 100;

/// Filters and paging of a job list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobQuery {
    /// Jobs in any of these states; empty means every state.
    pub states: Vec<JobState>,
    /// Jobs of any of these kinds; empty means every kind.
    pub kinds: Vec<JobKind>,
    /// Jobs that change this object.
    pub target: Option<ObjectRef>,
    /// Page size, 1 to [`MAX_LIMIT`]; 0 means [`DEFAULT_LIMIT`].
    pub limit: usize,
    /// The last job of the previous page.
    pub cursor: Option<JobId>,
    /// Read at least at this revision (read-your-writes).
    pub at_least: Option<Revision>,
}

/// A job in a list: everything a job panel shows per row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobSummary {
    /// Identifier.
    pub id: JobId,
    /// The kind of job.
    pub kind: JobKind,
    /// Translatable title.
    pub title: MessageKey,
    /// Current state.
    pub state: JobState,
    /// The objects the job changes.
    pub targets: Vec<ObjectRef>,
    /// Parallelism group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupKey>,
    /// Submission.
    pub created: Stamp,
    /// When the job reached a final state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<Timestamp>,
    /// The runner that owns the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<NodeId>,
    /// Number of steps.
    pub step_count: u16,
    /// Steps done or skipped.
    pub steps_done: u16,
    /// The first step that is neither done nor skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_step: Option<u16>,
    /// The state of that step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_step_state: Option<StepStateKind>,
    /// The handler kind of that step (`ipam.move.controller`, `dns.manual`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_step_kind: Option<StepKind>,
    /// Steps waiting for a person: manual tasks and manual undo tasks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manual_steps: Vec<u16>,
    /// Whether someone asked to cancel.
    pub cancel_requested: bool,
    /// Why the job is rolling back, failed or was cancelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CodedError>,
    /// Store revision of the job's last write.
    pub revision: Revision,
}

impl From<&Job> for JobSummary {
    fn from(job: &Job) -> Self {
        let count = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
        let current = job
            .steps
            .iter()
            .find(|record| !matches!(record.state, StepState::Done | StepState::Skipped));
        Self {
            id: job.id,
            kind: job.spec.kind.clone(),
            title: job.spec.title.clone(),
            state: job.state,
            targets: job.spec.targets.clone(),
            group: job.spec.group.clone(),
            created: job.created.clone(),
            finished: job.finished,
            runner: job.runner,
            step_count: count(job.steps.len()),
            steps_done: count(
                job.steps
                    .iter()
                    .filter(|record| matches!(record.state, StepState::Done | StepState::Skipped))
                    .count(),
            ),
            current_step: current.map(|record| record.index),
            current_step_state: current.map(|record| StepStateKind::from(&record.state)),
            current_step_kind: current.map(|record| record.kind.clone()),
            manual_steps: job
                .steps
                .iter()
                .filter(|record| matches!(record.state, StepState::WaitingForManual { .. }))
                .map(|record| record.index)
                .collect(),
            cancel_requested: job.cancel_requested.is_some(),
            error: job.error.clone(),
            revision: job.revision,
        }
    }
}

/// One page of jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobPage {
    /// The jobs, newest first.
    pub items: Vec<JobSummary>,
    /// The cursor of the next page, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<JobId>,
    /// The revision the page was read at; SSE continues from here.
    pub revision: Revision,
}

/// A job with its history and preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobDetail {
    /// The job with every step.
    pub job: Job,
    /// The transition log, oldest first.
    pub transitions: Vec<Transition>,
    /// What the job meant to do, computed at submission (inline jobs have none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<JobPreview>,
    /// The revision the detail was read at.
    pub revision: Revision,
}

/// Reads a job with its history and preview.
pub(crate) fn detail(view: &dyn ReadView, id: JobId) -> Result<JobDetail, JobError> {
    let loaded = persist::load(view, id)?.ok_or(JobError::NotFound(id))?;
    Ok(JobDetail {
        job: loaded.job,
        transitions: persist::transitions(view, id)?,
        preview: view.get_typed(&PREVIEWS, &id)?.map(|(preview, _)| preview),
        revision: view.revision(),
    })
}

/// Where a list scan reads ids from.
enum Source {
    Target(ObjectRef),
    State(JobState),
    All,
}

/// Filters of a job list beyond [`JobQuery`]: applied while scanning, before the page is
/// cut.
#[derive(Default)]
pub struct JobFilter<'a> {
    /// Jobs of this parallelism group (a group of move jobs).
    pub group: Option<GroupKey>,
    /// Jobs the caller may see (the scope of a scoped principal).
    pub keep: Option<&'a (dyn Fn(&Job) -> bool + Sync)>,
}

impl std::fmt::Debug for JobFilter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobFilter")
            .field("group", &self.group)
            .field("keep", &self.keep.is_some())
            .finish()
    }
}

/// Lists jobs.
pub(crate) fn list(view: &dyn ReadView, query: &JobQuery) -> Result<JobPage, StoreError> {
    list_filtered(view, query, &JobFilter::default())
}

/// Lists jobs with the filters of `filter` too (`GET /jobs` with `group`, and the jobs a
/// scoped principal may see).
///
/// # Errors
///
/// A store or decoding error.
pub fn list_filtered(
    view: &dyn ReadView,
    query: &JobQuery,
    filter: &JobFilter<'_>,
) -> Result<JobPage, StoreError> {
    let limit = match query.limit {
        0 => DEFAULT_LIMIT,
        limit => limit.min(MAX_LIMIT),
    };
    let source = match (&query.target, query.states.as_slice()) {
        (Some(target), _) => Source::Target(*target),
        (None, [state]) => Source::State(*state),
        (None, _) => Source::All,
    };
    let keep = |job: &Job| {
        (query.states.is_empty() || query.states.contains(&job.state))
            && (query.kinds.is_empty() || query.kinds.contains(&job.spec.kind))
            && query
                .target
                .is_none_or(|target| job.spec.targets.contains(&target))
            && filter
                .group
                .as_ref()
                .is_none_or(|group| job.spec.group.as_ref() == Some(group))
            && filter.keep.is_none_or(|keep| keep(job))
    };
    let prefix = match &source {
        Source::Target(target) => KeyRange::prefix(encode_key(target)),
        Source::State(state) => KeyRange::prefix(encode_key(state)),
        Source::All => KeyRange::all(),
    };
    let mut range = prefix.clone();
    if let Some(cursor) = query.cursor {
        let mut key = match &source {
            Source::Target(target) => encode_key(target).to_vec(),
            Source::State(state) => encode_key(state).to_vec(),
            Source::All => Vec::new(),
        };
        key.extend_from_slice(&encode_key(&cursor));
        range = range.before(key);
    }

    let mut items: Vec<JobSummary> = Vec::new();
    let mut more = false;
    'scan: loop {
        let ids: Vec<(JobId, Option<Job>, Vec<u8>)> = match &source {
            Source::Target(_) => view
                .scan_typed(&BY_TARGET, range.clone(), PAGE, true)?
                .into_iter()
                .map(|(key, (), _)| (key.1, None, BY_TARGET.key(&key).to_vec()))
                .collect(),
            Source::State(_) => view
                .scan_typed(&BY_STATE, range.clone(), PAGE, true)?
                .into_iter()
                .map(|(key, (), _)| (key.1, None, BY_STATE.key(&key).to_vec()))
                .collect(),
            Source::All => view
                .scan_typed(&JOBS, range.clone(), PAGE, true)?
                .into_iter()
                .map(|(id, mut job, revision)| {
                    job.revision = revision;
                    (id, Some(job), JOBS.key(&id).to_vec())
                })
                .collect(),
        };
        let full = ids.len() == PAGE;
        let last_key = ids.last().map(|(_, _, key)| key.clone());
        for (id, job, _) in ids {
            let job = match job {
                Some(job) => job,
                None => match view.get_typed(&JOBS, &id)? {
                    Some((mut job, revision)) => {
                        job.revision = revision;
                        job
                    }
                    None => continue,
                },
            };
            if !keep(&job) {
                continue;
            }
            if items.len() == limit {
                more = true;
                break 'scan;
            }
            items.push(JobSummary::from(&job));
        }
        match last_key {
            Some(key) if full => range = prefix.clone().before(key),
            _ => break,
        }
    }
    let next_cursor = if more {
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(JobPage {
        items,
        next_cursor,
        revision: view.revision(),
    })
}
