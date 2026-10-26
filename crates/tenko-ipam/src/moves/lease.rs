//! The moving client and the short lease before the network change (`docs/moves.md`
//! sections 4 and 5, ADR 0027).
//!
//! # The marker
//!
//! A move of an address whose interface has a MAC address, when Tenko serves the client's
//! old network (its lease is in `dhcp.leases`) or the target network (an enabled scope),
//! starts with `ipam.move.prepare`: it writes the client's row of `dhcp.moving`
//! ([`MovingClient`], keyed by the job), staged with the step. The `dhcp` role serves the
//! row in its configuration image: while the job is active (before the row's `until`, the
//! job's deadline) the next REQUEST of the client for its old address gets the short lease
//! (`[dhcp.moves] short_lease_secs`), and every DHCP message of the client's MAC address is
//! noted, so the job's clock ([`super::clock`]) sees the client's exchange. The row names
//! the old lease only when the client holds one and the operator did not choose to move at
//! once (`move_now`).
//!
//! The marker is the job's: the cleanup removes it when the move is confirmed, and every
//! compensation of a move step removes it first ([`clear`]), so the rollback drops it
//! before it undoes anything: the client that comes back to its old network renews with
//! its normal lease. The compensations of the observation and of the preparation wait
//! until the role's image no longer holds it before the steps before them are undone. A
//! row whose job ended without that (a job that failed) is ignored by the role from its
//! `until` on and removed by the leader's lease expiry ([`is_stale`]).
//!
//! # The wait for the short lease
//!
//! `ipam.move.lease` comes right before the L2 change when the client holds a lease on its
//! old network and the move is not `move_now`. It is done at once when the client's lease
//! is short already, when the client holds no lease any more, or when its next renewal is
//! expected later than `[dhcp.moves] prepare_limit_secs`; otherwise it is a task for a
//! person that the clock completes when the lease table shows the short lease, or when the
//! renewal did not come by its expected time plus the margin. A person completing it moves
//! the client at once.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    JobId, MacAddr, MessageKey, PrefixId, Revision, Timestamp,
    dhcp::{Lease, MovingClient, MovingLease, tables as dhcp_tables},
};
use tenko_jobs::{
    JobEngine, ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
    tables::JOBS,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, StoreError, WriteBatch};

use super::{
    JOB_TIMEOUT_SECS,
    dhcp::{DHCP_WAIT_SECS, DhcpMoves, image_at},
    settings::MoveSettings,
    steps::MoveStepParams,
    timing::{LeaseClock, plus, secs_between},
};

/// Step kind: the moving client's row, the first step of the job.
pub const PREPARE: &str = "ipam.move.prepare";
/// Step kind: the wait for the client's renewal with the short lease.
pub const LEASE: &str = "ipam.move.lease";
/// The preview kind of [`PREPARE`].
pub const PREPARE_KIND: &str = "dhcp.prepare";
/// The preview kind of [`LEASE`].
pub const LEASE_KIND: &str = "dhcp.short_lease";

/// What the submit found for the DHCP timing of an item; every step of the job carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePlan {
    /// The client's MAC address.
    pub mac: MacAddr,
    /// The client's lease on its old network, when Tenko holds one: the deadline's input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<MovingLease>,
    /// Whether its next renewal gets the short lease and the job waits for it; not when
    /// the operator moves at once (`move_now`).
    #[serde(default)]
    pub shorten: bool,
    /// The Tenko scope of the target network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PrefixId>,
    /// Whether the client must hold the prepared address on the target (a reserved host).
    #[serde(default)]
    pub reserved: bool,
    /// The request's own migration deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_secs: Option<u32>,
    /// The longest default lease of the target's pools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_secs: Option<u32>,
    /// `[dhcp.moves]` as the submit read it.
    #[serde(default)]
    pub settings: MoveSettings,
}

/// What `ipam.move.lease` found when it ran, kept as JSON in its output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseOutcome {
    /// The client's lease is the short lease.
    ShortLease,
    /// The client holds no lease on its old network any more.
    NoLease,
    /// Its next renewal is expected later than the preparation limit.
    Limit,
}

/// The output of `ipam.move.lease` when it did not wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveLeaseOutput {
    /// What it found.
    pub outcome: LeaseOutcome,
}

/// The output of `ipam.move.prepare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovePrepareOutput {
    /// Whether the row names the old lease, so that its renewal gets the short lease.
    pub short_lease: bool,
}

/// The client's row of `dhcp.moving` for `job`, with its revision.
///
/// # Errors
///
/// A store error.
pub fn marker(
    view: &dyn ReadView,
    job: JobId,
) -> Result<Option<(MovingClient, Revision)>, StoreError> {
    view.get_typed(&dhcp_tables::MOVING, &job)
}

/// The client's lease on its old network: the row of the plan's lease when it is the
/// client's (its MAC address), whatever its state.
///
/// # Errors
///
/// A store error.
pub fn old_lease(view: &dyn ReadView, plan: &LeasePlan) -> Result<Option<Lease>, StoreError> {
    let Some(old) = plan.lease else {
        return Ok(None);
    };
    Ok(view
        .get_typed(&dhcp_tables::LEASES, &(old.vrf, old.addr))?
        .map(|(lease, _): (Lease, _)| lease)
        .filter(|lease| lease.client.mac() == Some(plan.mac.octets())))
}

/// Whether `lease` is the short lease of `settings` (or shorter).
pub fn is_short(lease: &Lease, settings: &MoveSettings) -> bool {
    LeaseClock::of(lease).secs <= u64::from(settings.short_lease_secs)
}

/// Whether a row of `dhcp.moving` is stale at `now`: past its `until`, or its job is gone
/// or ended. The leader's lease expiry removes stale rows.
///
/// # Errors
///
/// A store error.
pub fn is_stale(
    view: &dyn ReadView,
    row: &MovingClient,
    now: Timestamp,
) -> Result<bool, StoreError> {
    if !row.is_active(now) {
        return Ok(true);
    }
    Ok(view
        .get_typed(&JOBS, &row.job)?
        .is_none_or(|(job, _)| job.state.is_terminal()))
}

/// Removes the job's row of `dhcp.moving`, at once and not staged, so that the role drops
/// it before the rollback undoes anything; with the role's slot, waits until the role's
/// image no longer holds it (at most [`DHCP_WAIT_SECS`]). Nothing when there is none.
///
/// # Errors
///
/// A store error other than a row that changed meanwhile.
pub async fn clear(cx: &StepContext, slot: Option<&DhcpMoves>) -> Result<(), StepError> {
    let view = cx.store.read(ReadConsistency::Local).await?;
    let Some((_, revision)) = marker(view.as_ref(), cx.job)? else {
        return Ok(());
    };
    drop(view);
    let mut batch = WriteBatch::for_request(&cx.request);
    batch.idempotency = None;
    batch.expect_typed(&dhcp_tables::MOVING, &cx.job, Some(revision));
    batch.delete_typed(&dhcp_tables::MOVING, &cx.job);
    let committed = match cx.store.propose(batch).await {
        Ok(committed) => committed.revision,
        // Removed meanwhile by another compensation or the expiry.
        Err(StoreError::PreconditionFailed(_)) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if let Some(role) = slot.and_then(DhcpMoves::get)
        && !image_at(
            role.as_ref(),
            committed,
            Duration::from_secs(DHCP_WAIT_SECS),
        )
        .await
    {
        tracing::warn!(job = %cx.job, "the dhcp role did not drop the moving client in time; the rollback goes on");
    }
    Ok(())
}

/// Stages `batch` with the running step, or proposes it outside the engine.
async fn stage_or_propose(cx: &StepContext, batch: WriteBatch) -> Result<(), StepError> {
    match tenko_jobs::stage(cx, batch.clone()) {
        Ok(()) => Ok(()),
        Err(StepError::Coded(error)) if error.code == "jobs.stage.outside_step" => {
            cx.store.propose(batch).await?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Stages the removal of the job's row with the running step (the cleanup).
///
/// # Errors
///
/// A store error.
pub(super) async fn stage_clear(cx: &StepContext, view: &dyn ReadView) -> Result<(), StepError> {
    let Some((_, revision)) = marker(view, cx.job)? else {
        return Ok(());
    };
    let mut batch = WriteBatch::for_request(&cx.request);
    batch.idempotency = None;
    batch.expect_typed(&dhcp_tables::MOVING, &cx.job, Some(revision));
    batch.delete_typed(&dhcp_tables::MOVING, &cx.job);
    stage_or_propose(cx, batch).await
}

fn plan_of(params: &MoveStepParams) -> Result<&LeasePlan, StepError> {
    params
        .lease
        .as_ref()
        .ok_or_else(|| StepError::InvalidParams("the step carries no lease plan".to_owned()))
}

fn json<T: Serialize>(value: &T) -> Result<StepOutcome, StepError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| StepError::InvalidParams(error.to_string()))?;
    Ok(StepOutcome::Done {
        output: Some(bytes.into()),
    })
}

/// `ipam.move.prepare`: writes the moving client's row of `dhcp.moving` (see the module
/// documentation). Its compensation removes the row.
#[derive(Debug, Clone, Default)]
pub struct MovePrepareStep {
    slot: Option<DhcpMoves>,
}

impl MovePrepareStep {
    /// The handler over the role's slot.
    pub fn new(slot: DhcpMoves) -> Self {
        Self { slot: Some(slot) }
    }
}

#[async_trait::async_trait]
impl StepHandler for MovePrepareStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(PREPARE)
    }

    /// Running it again finds the row written.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        Ok(StepPreview {
            summary: MessageKey::from_static("ipam.move.step.prepare"),
            args: params.args(),
            changes: params.changes(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let plan = plan_of(&params)?;
        let view = cx.store.read(ReadConsistency::Local).await?;
        if let Some((row, _)) = marker(view.as_ref(), cx.job)? {
            return json(&MovePrepareOutput {
                short_lease: row.lease.is_some(),
            });
        }
        let now = Timestamp::now();
        let lease = match old_lease(view.as_ref(), plan)? {
            Some(held) if plan.shorten && held.is_bound(now) => plan.lease,
            _ => None,
        };
        let row = MovingClient {
            job: cx.job,
            mac: plan.mac,
            lease,
            short_secs: plan.settings.short_lease_secs,
            target: plan.target,
            until: plus(now, JOB_TIMEOUT_SECS),
            extended: false,
        };
        let mut batch = WriteBatch::for_request(&cx.request);
        batch.idempotency = None;
        batch.expect_typed(&dhcp_tables::MOVING, &cx.job, None);
        batch.put_typed(&dhcp_tables::MOVING, &cx.job, &row)?;
        stage_or_propose(cx, batch).await?;
        json(&MovePrepareOutput {
            short_lease: lease.is_some(),
        })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        clear(cx, self.slot.as_ref()).await
    }
}

/// The task of `ipam.move.lease`.
fn lease_task(params: &MoveStepParams, plan: &LeasePlan, next: Timestamp) -> ManualTask {
    let mut args = params.args();
    args.insert(
        "short_secs".to_owned(),
        plan.settings.short_lease_secs.to_string(),
    );
    args.insert("next_activity".to_owned(), next.to_rfc3339());
    args.insert("mac".to_owned(), plan.mac.to_string());
    ManualTask {
        instruction: MessageKey::from_static("ipam.move.task.short_lease"),
        args,
        undo: None,
    }
}

/// When the wait of `ipam.move.lease` for the renewal of `lease` ends, for a step that
/// started at `started`: the expected renewal plus the margin, at most the preparation
/// limit; none when no renewal is expected within the limit.
pub fn wait_until(lease: &Lease, started: Timestamp, settings: &MoveSettings) -> Option<Timestamp> {
    let next = LeaseClock::of(lease).next_activity(started)?;
    if secs_between(started, next) > u64::from(settings.prepare_limit_secs) {
        return None;
    }
    Some(
        plus(next, u64::from(settings.margin_secs))
            .min(plus(started, u64::from(settings.prepare_limit_secs))),
    )
}

/// `ipam.move.lease`: waits for the client's renewal with the short lease before the L2
/// change (see the module documentation).
#[derive(Debug, Clone, Copy, Default)]
pub struct MoveLeaseStep;

#[async_trait::async_trait]
impl StepHandler for MoveLeaseStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(LEASE)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        Ok(StepPreview {
            summary: MessageKey::from_static("ipam.move.step.short_lease"),
            args: params.args(),
            changes: params.changes(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        let plan = plan_of(&params)?;
        let view = cx.store.read(ReadConsistency::Local).await?;
        let now = Timestamp::now();
        let Some(lease) = old_lease(view.as_ref(), plan)?.filter(|lease| lease.is_bound(now))
        else {
            return json(&MoveLeaseOutput {
                outcome: LeaseOutcome::NoLease,
            });
        };
        if is_short(&lease, &plan.settings) {
            return json(&MoveLeaseOutput {
                outcome: LeaseOutcome::ShortLease,
            });
        }
        if wait_until(&lease, now, &plan.settings).is_none() {
            return json(&MoveLeaseOutput {
                outcome: LeaseOutcome::Limit,
            });
        }
        let next = LeaseClock::of(&lease).next_activity(now).unwrap_or(now);
        Ok(StepOutcome::Manual(lease_task(&params, plan, next)))
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        clear(cx, None).await
    }
}

/// `ipam.move.observe`: the device seen at its new address; a task the reconciler, the
/// move's clock or a person completes. Its compensation removes the moving client first
/// and waits until the role's image dropped it, before the L2 change is undone.
#[derive(Debug, Clone, Default)]
pub struct MoveObserveStep {
    slot: Option<DhcpMoves>,
}

impl MoveObserveStep {
    /// The handler over the role's slot.
    pub fn new(slot: DhcpMoves) -> Self {
        Self { slot: Some(slot) }
    }

    fn task(params: &MoveStepParams) -> ManualTask {
        params.task.clone().unwrap_or_else(|| ManualTask {
            instruction: MessageKey::from_static("ipam.move.task.observe"),
            args: params.args(),
            undo: None,
        })
    }
}

#[async_trait::async_trait]
impl StepHandler for MoveObserveStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(super::steps::OBSERVE)
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
        cx: &StepContext,
    ) -> Result<(), StepError> {
        clear(cx, self.slot.as_ref()).await
    }
}

/// Registers the steps of the moving client over the role's slot, in place of the
/// handlers without it.
pub fn register_steps(engine: &mut JobEngine, slot: &DhcpMoves) {
    engine.register(Arc::new(MovePrepareStep::new(slot.clone())));
    engine.register(Arc::new(MoveObserveStep::new(slot.clone())));
}
