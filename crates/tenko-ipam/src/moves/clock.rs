//! The clock of moves (`docs/moves.md` section 5): the leader service `ipam.moves` that
//! moves the waiting steps of move jobs along their DHCP timing.
//!
//! Every second it looks at the move jobs that wait at a step for a person and carry a
//! lease plan (the job follows the client's DHCP, [`super::lease`]):
//!
//! - **`ipam.move.lease`**: done when the lease table shows the client's renewal with the
//!   short lease, when the client no longer holds its old lease, or when the renewal did
//!   not come by its expected time plus the margin (at most the preparation limit). The
//!   job then changes the network.
//! - **`ipam.move.observe`**, in this order:
//!   1. *Verified*: the client holds a lease of the target scope (the prepared address for
//!      a reserved host, any address of the network otherwise) given after the job
//!      started; the step is done. The reconciler confirms on the lease's fact as well.
//!   2. *The migration deadline*: once, when the step starts waiting, from the client's
//!      old lease as the lease table holds it then ([`super::timing::migration_deadline`]):
//!      the short lease's end plus the margin when the preparation succeeded, else the
//!      lease's end plus the margin within the limit, else the target pools' lease; the
//!      request's own timeout replaces it. The step's timeout from the submit holds until
//!      then.
//!   3. *The verification window*: when the role saw the client's DHCP message on the
//!      target scope (its refused rebinding, or its DISCOVER), the deadline becomes that
//!      time plus `verify_secs` when that is earlier: the client should hold its new lease
//!      within seconds.
//!   4. *The extension*: when the role saw a DHCP message of the client in the last
//!      `extend_window_secs` before the deadline, the deadline moves by `extend_secs`,
//!      once per job (the moving client's row records it), so that the job does not roll
//!      back in the middle of the client's exchange.
//!
//! Past the deadline the engine rolls the job back. Every change of a deadline is a
//! transition of the job with a note that says why.

use std::{net::IpAddr, sync::Arc, time::Duration};

use tenko_core::{
    Coded, JobId, Principal, RequestCtx, SystemComponent, Timestamp,
    cluster::LeaderService,
    codec::from_cbor,
    dhcp::{BindingState, Lease, tables as dhcp_tables},
};
use tenko_jobs::{
    Job, JobState, StepRecord, StepState,
    tables::{BY_STATE, JOBS},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use super::{
    MOVE_JOB,
    dhcp::DhcpMoves,
    lease::{LEASE, LeasePlan, is_short, marker, old_lease, wait_until},
    steps::{MoveStepParams, OBSERVE},
    timing::{DeadlineInputs, LeaseClock, migration_deadline, minus, plus},
};
use crate::{error::IpamResult, jobs::JobSink};

/// How often the clock looks at the waiting jobs.
pub const PERIOD: Duration = Duration::from_secs(1);

/// What one round of the clock did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockRound {
    /// Waits for the short lease that ended.
    pub prepared: usize,
    /// Observations whose migration deadline was set.
    pub deadlines: usize,
    /// Deadlines moved to the verification window.
    pub windows: usize,
    /// Deadlines extended.
    pub extended: usize,
    /// Observations completed by the client's new lease.
    pub verified: usize,
}

/// The clock of moves.
pub struct MoveClock {
    store: Arc<dyn Store>,
    jobs: Arc<dyn JobSink>,
    dhcp: DhcpMoves,
}

impl std::fmt::Debug for MoveClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoveClock")
            .field("dhcp", &self.dhcp)
            .finish_non_exhaustive()
    }
}

/// A move job waiting at a step for a person, with its lease plan.
struct Waiting {
    job: Job,
    step: u16,
    params: MoveStepParams,
    plan: LeasePlan,
}

fn waiting(job: Job) -> Option<Waiting> {
    if job.spec.kind.as_str() != MOVE_JOB || job.state != JobState::Waiting {
        return None;
    }
    let record: &StepRecord = job
        .steps
        .iter()
        .find(|record| matches!(record.state, StepState::WaitingForManual { .. }))?;
    if !matches!(record.kind.as_str(), LEASE | OBSERVE) {
        return None;
    }
    let step = record.index;
    let spec = job.spec.steps.get(usize::from(step))?;
    let params: MoveStepParams = from_cbor(&spec.params.0).ok()?;
    let plan = params.lease.clone()?;
    Some(Waiting {
        job,
        step,
        params,
        plan,
    })
}

fn cx(now: Timestamp) -> RequestCtx {
    let mut cx = RequestCtx::system(SystemComponent::Ipam);
    cx.now = now;
    cx
}

impl MoveClock {
    /// The clock over the store, the job engine and the role's slot.
    pub fn new(store: Arc<dyn Store>, jobs: Arc<dyn JobSink>, dhcp: DhcpMoves) -> Arc<Self> {
        Arc::new(Self { store, jobs, dhcp })
    }

    /// The leader service `ipam.moves`.
    pub fn leader_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(ClockService(Arc::clone(self)))
    }

    /// One round at `now`; with `epoch`, the clock's own writes carry the leader fence.
    ///
    /// # Errors
    ///
    /// A store error of the reads; a step another actor moved on meanwhile is skipped.
    pub async fn tick(&self, now: Timestamp, epoch: Option<u64>) -> IpamResult<ClockRound> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut round = ClockRound::default();
        if !crate::reconcile::moves::any_waiting(view.as_ref())? {
            return Ok(round);
        }
        let rows = view.scan_typed(
            &BY_STATE,
            KeyRange::prefix(tenko_core::codec::encode_key(&(JobState::Waiting,))),
            usize::MAX,
            false,
        )?;
        for ((_, id), (), _) in rows {
            let Some((job, _)) = view.get_typed(&JOBS, &id)? else {
                continue;
            };
            let Some(waiting) = waiting(job) else {
                continue;
            };
            let kind = waiting.job.steps[usize::from(waiting.step)].kind.clone();
            if kind.as_str() == LEASE {
                if self.lease(view.as_ref(), &waiting, now).await? {
                    round.prepared += 1;
                }
            } else {
                self.observe(view.as_ref(), &waiting, now, epoch, &mut round)
                    .await?;
            }
        }
        Ok(round)
    }

    async fn complete(&self, job: JobId, step: u16, note: String, now: Timestamp) -> bool {
        match self
            .jobs
            .complete_manual(job, step, Some(note), &cx(now))
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(%job, step, error = %error.to_coded_error().code, "a move step moved on meanwhile");
                false
            }
        }
    }

    async fn deadline(
        &self,
        job: JobId,
        step: u16,
        deadline: Timestamp,
        note: String,
        now: Timestamp,
    ) -> bool {
        match self
            .jobs
            .set_manual_deadline(job, step, deadline, Some(note), &cx(now))
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(%job, step, error = %error.to_coded_error().code, "a move step moved on meanwhile");
                false
            }
        }
    }

    /// `ipam.move.lease`: whether it was completed.
    async fn lease(&self, view: &dyn ReadView, w: &Waiting, now: Timestamp) -> IpamResult<bool> {
        let settings = &w.plan.settings;
        let started = w.job.steps[usize::from(w.step)].started.unwrap_or(now);
        let note = match old_lease(view, &w.plan)?.filter(|lease| lease.is_bound(now)) {
            None => Some(
                "the client holds no lease on its old network any more; the network changes now"
                    .to_owned(),
            ),
            Some(lease) if is_short(&lease, settings) => Some(format!(
                "the client renewed with the {} s lease at {}; the network changes now",
                LeaseClock::of(&lease).secs,
                lease.cltt.to_rfc3339()
            )),
            Some(lease) => match wait_until(&lease, started, settings) {
                None => Some(format!(
                    "the client's next renewal is expected later than {} s; the network \
                     changes now",
                    settings.prepare_limit_secs
                )),
                Some(until) if now >= until => Some(format!(
                    "the client did not renew by {}; the network changes without the short lease",
                    until.to_rfc3339()
                )),
                Some(_) => None,
            },
        };
        Ok(match note {
            Some(note) => self.complete(w.job.id, w.step, note, now).await,
            None => false,
        })
    }

    /// The client's lease on the target scope, given after `since`.
    fn target_lease(
        view: &dyn ReadView,
        w: &Waiting,
        since: Timestamp,
        now: Timestamp,
    ) -> Result<Option<Lease>, StoreError> {
        let mac = w.plan.mac.octets();
        let fits = |lease: &Lease| {
            lease.is_bound(now) && lease.client.mac() == Some(mac) && lease.cltt >= since
        };
        if w.plan.reserved {
            let IpAddr::V4(addr) = w.params.new_ip else {
                return Ok(None);
            };
            return Ok(view
                .get_typed(&dhcp_tables::LEASES, &(w.params.vrf, addr))?
                .map(|(lease, _)| lease)
                .filter(fits));
        }
        let ipnet::IpNet::V4(net) = w.params.cidr else {
            return Ok(None);
        };
        let range = KeyRange {
            start: std::ops::Bound::Included(
                dhcp_tables::LEASES.key(&(w.params.vrf, net.network())),
            ),
            end: std::ops::Bound::Included(
                dhcp_tables::LEASES.key(&(w.params.vrf, net.broadcast())),
            ),
        };
        Ok(view
            .scan_typed(&dhcp_tables::LEASES, range, usize::MAX, false)?
            .into_iter()
            .map(|(_, lease, _)| lease)
            .find(fits))
    }

    /// The migration deadline of an observation that started at `started`, from the
    /// client's old lease as the lease table holds it now, with the note that says how.
    fn first_deadline(
        view: &dyn ReadView,
        w: &Waiting,
        started: Timestamp,
    ) -> Result<(Timestamp, String), StoreError> {
        let settings = &w.plan.settings;
        let old = old_lease(view, &w.plan)?
            .filter(|lease| matches!(lease.state, BindingState::Active | BindingState::Expired));
        let inputs = DeadlineInputs {
            request_secs: w.plan.request_secs,
            lease: old.as_ref().map(LeaseClock::of),
            prepared: old.as_ref().is_some_and(|lease| is_short(lease, settings)),
            pool_secs: w.plan.pool_secs,
        };
        let (at, source) = migration_deadline(started, &inputs, settings);
        let source = serde_json::to_value(source)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok((
            at,
            format!("the migration deadline is {} ({source})", at.to_rfc3339()),
        ))
    }

    async fn observe(
        &self,
        view: &dyn ReadView,
        w: &Waiting,
        now: Timestamp,
        epoch: Option<u64>,
        round: &mut ClockRound,
    ) -> IpamResult<()> {
        let settings = &w.plan.settings;
        let record = &w.job.steps[usize::from(w.step)];
        let started = record.started.unwrap_or(now);
        let since = w.job.started.unwrap_or(w.job.created.at);
        let StepState::WaitingForManual { deadline, .. } = &record.state else {
            return Ok(());
        };
        let job = w.job.id;
        // 1. The client holds its new lease.
        if w.plan.target.is_some()
            && let Some(lease) = Self::target_lease(view, w, since, now)?
        {
            let note = format!(
                "verified: the client holds {} on the target network since {}",
                lease.addr,
                lease.cltt.to_rfc3339()
            );
            if self.complete(job, w.step, note, now).await {
                round.verified += 1;
            }
            return Ok(());
        }
        // 2. The migration deadline, once.
        let mut deadline = if let Some(deadline) = deadline {
            *deadline
        } else {
            let (at, note) = Self::first_deadline(view, w, started)?;
            if !self.deadline(job, w.step, at, note, now).await {
                return Ok(());
            }
            round.deadlines += 1;
            at
        };
        let activity = self
            .dhcp
            .get()
            .and_then(|role| role.activity(job, w.plan.mac))
            .unwrap_or_default();
        // 3. The client's exchange on the target network: the short window.
        if let Some(seen) = activity.on_target.filter(|seen| *seen >= since) {
            let window = plus(seen, u64::from(settings.verify_secs));
            if window < deadline {
                let note = format!(
                    "the client's DHCP exchange on the target network was seen at {}; its \
                     new lease is verified by {}",
                    seen.to_rfc3339(),
                    window.to_rfc3339()
                );
                if self.deadline(job, w.step, window, note, now).await {
                    round.windows += 1;
                    deadline = window;
                }
            }
        }
        // 4. The extension, once.
        let from = minus(deadline, u64::from(settings.extend_window_secs));
        if now >= from
            && now < deadline
            && activity.last.is_some_and(|last| last >= from)
            && let Some((mut row, revision)) = marker(view, job)?
            && !row.extended
        {
            row.extended = true;
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), now);
            if let Some(epoch) = epoch {
                batch.preconditions.push(fence(epoch));
            }
            batch.expect_typed(&dhcp_tables::MOVING, &job, Some(revision));
            batch.put_typed(&dhcp_tables::MOVING, &job, &row)?;
            match self.store.propose(batch).await {
                Ok(_) => {}
                Err(StoreError::PreconditionFailed(_)) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            let later = plus(deadline, u64::from(settings.extend_secs));
            let note = format!(
                "a DHCP message of the client at {} came within {} s of the deadline; it \
                 moves once by {} s to {}",
                activity.last.map(Timestamp::to_rfc3339).unwrap_or_default(),
                settings.extend_window_secs,
                settings.extend_secs,
                later.to_rfc3339()
            );
            if self.deadline(job, w.step, later, note, now).await {
                round.extended += 1;
            }
        }
        Ok(())
    }
}

struct ClockService(Arc<MoveClock>);

#[async_trait::async_trait]
impl LeaderService for ClockService {
    fn name(&self) -> &'static str {
        "ipam.moves"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        loop {
            if let Err(error) = self.0.tick(Timestamp::now(), Some(epoch)).await {
                tracing::warn!(error = %error.code_str(), "a round of the move clock failed");
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(PERIOD) => {}
            }
        }
    }
}
