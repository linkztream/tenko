//! The IPAM service: plan, apply with retries, allocation, alarms.
//!
//! # Apply
//!
//! [`IpamService::apply`] proposes exactly one plan as one write batch inside an inline
//! one-step job (Q4). If the store refuses a precondition, the plan is stale
//! (`ipam.plan.stale`): something it read changed. [`IpamService::execute`] plans and
//! applies in a loop instead, re-planning from a fresh view after a stale result, up to
//! [`IpamConfig::max_attempts`] plans; re-planning also surfaces user-level conflicts such as
//! a changed `If-Match` revision as their own errors.
//!
//! # Allocation protocol (IPAM-07)
//!
//! A next-free command expects and bumps the allocation counter of its prefix, and its
//! address or prefix key must be absent, so two allocators can never commit the same
//! address: one of two concurrent batches fails its preconditions. To keep that from
//! turning into retry storms, allocators on one controller queue on a per-prefix lock that
//! remembers the revision of the last allocation (creates of addresses and ranges join the
//! queue of their prefix too); the next writer reads at least that revision, so local
//! writers never conflict and a retry is only needed when another controller commits in
//! between. After a stale plan the service pauses for a jittered, growing interval before
//! planning again, so controllers stop colliding in lockstep. The prefix tree proposes the
//! candidates (hints); the plan verifies each against its view and searches the view when a
//! hint is stale.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, PoisonError},
};

use tenko_core::Coded;
use tenko_core::{PrefixId, RequestCtx, Revision};
use tenko_jobs::JobState;
use tenko_store::{ReadConsistency, ReadView, Store};

use crate::{
    alarm::{self, AlarmEvent},
    command::IpamCommand,
    error::{IpamError, IpamResult, codes},
    jobs::{DirectJobs, JobSink, WriteStepParams, committed_revision, edit_job, with_batch},
    plan::{self, Applied, IpamPlan, PlanOptions},
    tree::PrefixTree,
};

/// Limits of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpamConfig {
    /// Plans made by [`IpamService::execute`] before it gives up with `ipam.contended`.
    pub max_attempts: u32,
    /// Commands in one request (API-04 bulk).
    pub max_commands: usize,
    /// How many jobs of one move run at once when the request does not say (IPAM-19,
    /// design decision 8).
    pub move_parallelism: u32,
}

impl Default for IpamConfig {
    fn default() -> Self {
        Self {
            max_attempts: 16,
            max_commands: 10_000,
            move_parallelism: 2,
        }
    }
}

/// The IPAM domain service. Cheap to share as `Arc<IpamService>`.
pub struct IpamService {
    store: Arc<dyn Store>,
    jobs: Arc<dyn JobSink>,
    tree: Arc<PrefixTree>,
    config: IpamConfig,
    /// Per-prefix allocation queues with the revision of the last local allocation.
    alloc_locks: Mutex<HashMap<PrefixId, Arc<tokio::sync::Mutex<Revision>>>>,
}

impl std::fmt::Debug for IpamService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpamService")
            .field("tree", &self.tree)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl IpamService {
    /// Creates the service and registers the prefix tree with the store.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the tree cannot be built.
    pub fn new(
        store: Arc<dyn Store>,
        jobs: Arc<dyn JobSink>,
        config: IpamConfig,
    ) -> IpamResult<Arc<Self>> {
        let tree = Arc::new(PrefixTree::new());
        store.register_index(Arc::clone(&tree) as Arc<dyn tenko_store::DerivedIndex>)?;
        Ok(Arc::new(Self {
            store,
            jobs,
            tree,
            config,
            alloc_locks: Mutex::new(HashMap::new()),
        }))
    }

    /// A service that runs its inline jobs in place ([`DirectJobs`]).
    ///
    /// # Errors
    ///
    /// Returns the store's error if the tree cannot be built.
    pub fn with_direct_jobs(store: Arc<dyn Store>) -> IpamResult<Arc<Self>> {
        let jobs = Arc::new(DirectJobs::new(Arc::clone(&store)));
        Self::new(store, jobs, IpamConfig::default())
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The job sink: inline jobs of changes, background jobs of moves.
    pub fn jobs(&self) -> &Arc<dyn JobSink> {
        &self.jobs
    }

    /// The prefix tree.
    pub fn tree(&self) -> &Arc<PrefixTree> {
        &self.tree
    }

    /// The limits.
    pub fn config(&self) -> IpamConfig {
        self.config
    }

    /// A read view, at least at `at_least` when given (read-your-writes).
    ///
    /// # Errors
    ///
    /// Returns `sys.store.timeout` when the revision is not reached in time.
    pub async fn view(&self, at_least: Option<Revision>) -> IpamResult<Arc<dyn ReadView>> {
        let consistency = match at_least {
            Some(revision) => ReadConsistency::AtLeast(revision),
            None => ReadConsistency::Local,
        };
        Ok(self.store.read(consistency).await?)
    }

    /// Plans commands against a view ([`plan::plan`]), after filling missing allocation
    /// hints from the prefix tree. Pure apart from reading the tree; the plan verifies
    /// every hint against the view.
    ///
    /// # Errors
    ///
    /// Returns the planning error.
    pub fn plan(
        &self,
        view: &dyn ReadView,
        cx: &RequestCtx,
        options: &PlanOptions,
        commands: &[IpamCommand],
    ) -> IpamResult<IpamPlan> {
        if commands.len() > self.config.max_commands {
            return Err(IpamError::new(
                codes::BULK_TOO_LARGE,
                413,
                format!(
                    "{} commands exceed the limit of {}",
                    commands.len(),
                    self.config.max_commands
                ),
            )
            .titled("Too many changes in one request")
            .param("count", commands.len())
            .param("limit", self.config.max_commands));
        }
        let hinted = self.with_hints(commands);
        plan::plan(view, cx, options, &hinted)
    }

    /// Fills allocation hints: per prefix (and range) as many candidates as the commands
    /// allocate there, so a bulk allocation gets distinct hints.
    fn with_hints(&self, commands: &[IpamCommand]) -> Vec<IpamCommand> {
        type Key = (
            PrefixId,
            Option<tenko_core::RangeId>,
            Option<tenko_core::ipam::AllocPolicy>,
        );
        let mut wanted: BTreeMap<Key, usize> = BTreeMap::new();
        for command in commands {
            if let IpamCommand::AllocateAddress(alloc) = command
                && alloc.hint.is_none()
            {
                *wanted
                    .entry((alloc.prefix, alloc.range, alloc.policy))
                    .or_default() += 1;
            }
        }
        let mut hints: BTreeMap<Key, std::vec::IntoIter<std::net::IpAddr>> = wanted
            .into_iter()
            .map(|((prefix, range, policy), count)| {
                let free = self.tree.next_free_addresses(prefix, policy, range, count);
                ((prefix, range, policy), free.into_iter())
            })
            .collect();
        commands
            .iter()
            .cloned()
            .map(|mut command| {
                match &mut command {
                    IpamCommand::AllocateAddress(alloc) if alloc.hint.is_none() => {
                        alloc.hint = hints
                            .get_mut(&(alloc.prefix, alloc.range, alloc.policy))
                            .and_then(Iterator::next);
                    }
                    IpamCommand::AllocatePrefix(alloc) if alloc.hint.is_none() => {
                        alloc.hint =
                            self.tree
                                .next_free_prefix(alloc.parent, alloc.length, alloc.policy);
                    }
                    _ => {}
                }
                command
            })
            .collect()
    }

    /// Plans without applying: the dry run (API-09) and the import preview.
    ///
    /// # Errors
    ///
    /// Returns the planning error.
    pub async fn preview(
        &self,
        commands: &[IpamCommand],
        cx: &RequestCtx,
        options: &PlanOptions,
        at_least: Option<Revision>,
    ) -> IpamResult<IpamPlan> {
        let view = self.view(at_least).await?;
        self.plan(view.as_ref(), cx, options, commands)
    }

    /// Applies one plan as one batch inside an inline one-step job (Q4).
    ///
    /// # Errors
    ///
    /// `ipam.plan.unacknowledged` when a warning needs an acknowledgement,
    /// `ipam.plan.stale` when the store changed since the plan was made, or the error of
    /// the job.
    pub async fn apply(&self, plan: &IpamPlan, cx: &RequestCtx) -> IpamResult<Applied> {
        if let Some(receipt) = &plan.replay {
            return Ok(Applied {
                revision: receipt.revision,
                job_id: None,
                results: receipt.results.clone(),
                replayed: true,
                retries: 0,
                warnings: Vec::new(),
            });
        }
        let unacknowledged = plan.unacknowledged();
        if !unacknowledged.is_empty() {
            return Err(IpamError::new(
                codes::PLAN_UNACKNOWLEDGED,
                409,
                format!(
                    "the change needs an acknowledgement of: {}",
                    unacknowledged.join(", ")
                ),
            )
            .titled("Warnings need an acknowledgement")
            .param("codes", unacknowledged.join(",")));
        }
        if plan.is_empty() {
            return Ok(Applied {
                revision: plan.base,
                job_id: None,
                results: plan.results.clone(),
                replayed: false,
                retries: 0,
                warnings: plan.warnings.clone(),
            });
        }
        let batch = plan.to_batch();
        let params = WriteStepParams {
            nonce: uuid::Uuid::now_v7(),
            summary: plan.summary().lines,
            targets: plan.targets(),
            mutations: u64::try_from(batch.mutations.len()).unwrap_or(u64::MAX),
            audit: u64::try_from(batch.audit.len()).unwrap_or(u64::MAX),
        };
        let spec = edit_job(&params)?;
        let outcome = with_batch(&params, batch, self.jobs.run_inline(spec, cx)).await;
        let job = match outcome {
            Ok(job) if job.state == JobState::Succeeded => job,
            Ok(job) => {
                return Err(stale_or(job.error.unwrap_or_else(|| {
                    tenko_core::CodedError::new(codes::JOB_FAILED, 500, "the job failed")
                })));
            }
            Err(error) => return Err(stale_or(error.to_coded_error())),
        };
        let revision = committed_revision(&job).ok_or_else(|| {
            IpamError::new(codes::JOB_FAILED, 500, "the write step reported no result")
        })?;
        if let Err(error) = alarm::flush(&self.store, &self.tree, plan.at).await {
            tracing::warn!(%error, "utilization alarms not written");
        }
        Ok(Applied {
            revision,
            job_id: Some(job.id),
            results: plan.results.clone(),
            replayed: false,
            retries: 0,
            warnings: plan.warnings.clone(),
        })
    }

    /// Plans and applies commands, re-planning after stale plans (see the module
    /// documentation). With `dry_run`, only plans.
    ///
    /// # Errors
    ///
    /// The planning error, `ipam.contended` after too many stale plans, or the job's
    /// error.
    pub async fn execute(
        &self,
        commands: &[IpamCommand],
        cx: &RequestCtx,
        options: &PlanOptions,
    ) -> IpamResult<Applied> {
        let prefixes: BTreeSet<PrefixId> = commands
            .iter()
            .filter_map(|command| self.queue_prefix(command))
            .collect();
        let locks: Vec<Arc<tokio::sync::Mutex<Revision>>> = {
            let mut map = self
                .alloc_locks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            prefixes
                .iter()
                .map(|prefix| Arc::clone(map.entry(*prefix).or_default()))
                .collect()
        };
        let mut guards = Vec::with_capacity(locks.len());
        for lock in &locks {
            guards.push(lock.lock().await);
        }
        let mut at_least = guards.iter().map(|g| **g).max().unwrap_or_default();
        for attempt in 0..self.config.max_attempts {
            let consistency = if attempt == 0 {
                if at_least > Revision::ZERO {
                    ReadConsistency::AtLeast(at_least)
                } else {
                    ReadConsistency::Local
                }
            } else {
                ReadConsistency::Linearizable
            };
            let view = self.store.read(consistency).await?;
            let plan = self.plan(view.as_ref(), cx, options, commands)?;
            drop(view);
            match self.apply(&plan, cx).await {
                Ok(mut applied) => {
                    for guard in &mut guards {
                        **guard = (**guard).max(applied.revision);
                    }
                    applied.retries = attempt;
                    return Ok(applied);
                }
                Err(error) if error.is(codes::PLAN_STALE) => {
                    at_least = at_least.max(self.store.status().revision);
                    tracing::debug!(attempt, "IPAM plan stale; planning again");
                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(IpamError::contended(self.config.max_attempts))
    }

    /// Creates the tenant and the VRF named `default` when they do not exist, exactly as
    /// the first write that needs them would, so that a new installation lists both before
    /// anything else is written. Idempotent: when both exist nothing is written and the
    /// answer carries the current revision. The results are the tenant and the VRF.
    ///
    /// The change is planned, audited and recorded in the history under `cx`; callers pass
    /// a system context (setup, server start).
    ///
    /// # Errors
    ///
    /// Store errors, `ipam.contended` after too many stale plans, or the job's error.
    pub async fn ensure_defaults(&self, cx: &RequestCtx) -> IpamResult<Applied> {
        for attempt in 0..self.config.max_attempts {
            let consistency = if attempt == 0 {
                ReadConsistency::Local
            } else {
                ReadConsistency::Linearizable
            };
            let view = self.store.read(consistency).await?;
            let plan = plan::plan_defaults(view.as_ref(), cx)?;
            drop(view);
            match self.apply(&plan, cx).await {
                Ok(mut applied) => {
                    applied.retries = attempt;
                    return Ok(applied);
                }
                Err(error) if error.is(codes::PLAN_STALE) => {
                    tracing::debug!(attempt, "IPAM defaults plan stale; planning again");
                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(IpamError::contended(self.config.max_attempts))
    }

    /// The prefix whose local queue a command joins: next-free commands, and creates of
    /// addresses and ranges whose prefix the tree can tell. These all change the
    /// allocation counter of the prefix, so queueing them locally avoids conflicts between
    /// writers of this controller.
    fn queue_prefix(&self, command: &IpamCommand) -> Option<PrefixId> {
        match command {
            IpamCommand::CreateAddress(input) => input
                .vrf
                .and_then(|vrf| self.tree.containing(vrf, input.ip)),
            IpamCommand::CreateRange(input) => Some(input.prefix),
            other => other.allocation_prefix(),
        }
    }

    /// Writes pending utilization alarm transitions now ([`alarm::flush`]).
    ///
    /// # Errors
    ///
    /// Returns store errors.
    pub async fn flush_alarms(&self) -> IpamResult<Vec<AlarmEvent>> {
        alarm::flush(&self.store, &self.tree, tenko_core::Timestamp::now()).await
    }

    /// Writes alarm transitions whenever the tree marks prefixes, until `shutdown`
    /// completes. The server spawns it, so changes applied by other controllers raise
    /// alarms here too.
    pub async fn run_alarms(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                () = self.tree.changed() => {
                    if let Err(error) = self.flush_alarms().await {
                        tracing::warn!(%error, "utilization alarms not written");
                    }
                }
            }
        }
    }
}

/// A failed precondition means the plan is stale; anything else keeps its own code.
fn stale_or(error: tenko_core::CodedError) -> IpamError {
    if error.code == "sys.store.precondition_failed" {
        IpamError::stale()
    } else {
        IpamError::from_coded_error(error)
    }
}

/// A jittered, growing pause before planning again after a stale plan, so that writers on
/// several controllers stop colliding in lockstep: up to 0.2 ms, doubling per attempt to at
/// most about 26 ms.
fn backoff(attempt: u32) -> std::time::Duration {
    let ceiling = 200u64 << attempt.min(7);
    let entropy = u64::try_from(
        tenko_core::Timestamp::now()
            .unix_nanos()
            .rem_euclid(1 << 40),
    )
    .unwrap_or_default();
    std::time::Duration::from_micros(50 + entropy % ceiling)
}
