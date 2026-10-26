//! Port bounces and client kicks (ADR 0028): the two optional writes that make a moved
//! client start over at once.
//!
//! # The bounce, and who brings the port back up
//!
//! [`ConnectorHost::bounce_port`] takes a switch port administratively down for
//! `down_secs` (1 to 30) and brings it up again. The way back up belongs to the host, never
//! to the caller (a move job) and never to the plugin:
//!
//! 1. The host checks the write switch and the guardrails against a fresh topology and asks
//!    the plugin for the plan of the [`L2Change::BouncePort`]. The plan carries the
//!    [`L2Change::EnablePort`] that restores the port as read (`undo`).
//! 2. Before the down is sent, the host writes a pending record ([`PendingBounce`],
//!    `connect.bounces`): the connector, the device and the port, the port's state as read
//!    back (the plan's diff and its way back up) and when the port is due up, together with
//!    the audit record `connect.port.bounce`.
//! 3. A task of the host, not of the caller, sends the down, waits `down_secs` and sends
//!    the up, whatever happens to the caller (a job that times out, is cancelled or fails
//!    drops only its wait for the report).
//! 4. The up is planned, written and read back like any write; the record is removed only
//!    when the read-back shows the port up, with the audit record `connect.port.enable`.
//!    The up ignores the write switch, the plan age and the guardrails: it restores what
//!    Tenko changed seconds before, and a port left down is worse than anything it touches.
//! 5. An up that fails keeps the record, marks it stuck and raises the condition
//!    `connect.port_stuck` with the device and the port ([`ConnectorHost::stuck_ports`]);
//!    the host tries again with a growing pause until it succeeds.
//! 6. At every start the host brings up every port with a pending record, and every second
//!    it brings up the records that are past due and that no task of its own handles (a
//!    record of another controller that stopped, or a stuck one), and logs what it did.
//!
//! # The kick
//!
//! [`ConnectorHost::kick_client`] disconnects a wireless client through the controller, so
//! that it associates again and asks for an address. It is a write like any other (write
//! switch, guardrails against a fresh topology, plan age), with nothing to undo; the
//! receipt's `verified` says that the controller accepted it. Every kick is audited
//! (`connect.client.kick`).

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, ConnectorId, JobId, MacAddr, ObjectRef, Principal, Timestamp, UserId,
    audit::{AuditAction, AuditDraft, AuditOutcome},
    principal::SystemComponent,
    table::TableDef,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, StoreError, WriteBatch};
use tokio::sync::oneshot;

use super::{ConnectorHost, HostError, calls::capability};
use crate::{
    Capability, ConnectorError, DeviceRef, DiffLine, Guardrails, L2Change, L2Plan, MAX_DOWN_SECS,
    MIN_DOWN_SECS, WriteMode,
};

/// The pending bounces: the key is the connector, the device and the port.
pub const BOUNCES: TableDef<BounceKey, PendingBounce> = TableDef::new("connect.bounces");

/// The key of a pending bounce.
pub type BounceKey = (ConnectorId, String, u16);

/// The condition of a port whose way back up failed (the health view).
pub const PORT_STUCK: &str = "connect.port_stuck";
/// A bounce of a port that has one pending already (409).
pub const BOUNCE_PENDING: &str = "connect.bounce.pending";
/// A bounce with a down time outside 1 to 30 seconds (422).
pub const BOUNCE_INVALID: &str = "connect.bounce.invalid";
/// A plugin whose bounce plan lacks its way back up (502).
pub const BOUNCE_NO_UNDO: &str = "connect.bounce.no_undo";
/// A bounce or kick sent through the generic L2 calls instead of their own (422).
pub const NUDGE_DIRECT: &str = "connect.nudge.direct";

/// Audit action: a port goes down for a bounce.
pub const PORT_BOUNCE: AuditAction = AuditAction::from_static("connect.port.bounce");
/// Audit action: the port of a bounce comes up again (or failed to).
pub const PORT_ENABLE: AuditAction = AuditAction::from_static("connect.port.enable");
/// Audit action: a wireless client was disconnected.
pub const CLIENT_KICK: AuditAction = AuditAction::from_static("connect.client.kick");

/// How often the bounce task tries the up before it leaves the port to the sweep.
const TASK_ATTEMPTS: u32 = 3;

/// A bounce whose port may still be down: written before the down is sent, removed once
/// the read-back shows the port up again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingBounce {
    /// The connector instance.
    pub connector: ConnectorId,
    /// The switch.
    pub device: DeviceRef,
    /// The port index.
    pub port: u16,
    /// How long the port stays down.
    pub down_secs: u16,
    /// The job the bounce belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobId>,
    /// The user the job acts for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<UserId>,
    /// The port's state as read back before the down: the plan's diff.
    #[serde(default)]
    pub diff: Vec<DiffLine>,
    /// The way back up: the plan's `undo`, one `EnablePort`.
    pub restore: Vec<L2Change>,
    /// When the record was written.
    pub created_at: Timestamp,
    /// When the port was taken down, once the plugin confirmed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_at: Option<Timestamp>,
    /// When the next attempt to bring the port up is due: a host that does not run the
    /// bounce itself (after a restart, another controller) brings it up from then on.
    pub due: Timestamp,
    /// The failed attempts to bring the port up.
    #[serde(default)]
    pub attempts: u32,
    /// Why the last attempt failed: the port is stuck down (`connect.port_stuck`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stuck: Option<CodedError>,
}

impl PendingBounce {
    /// The key of the record.
    pub fn key(&self) -> BounceKey {
        (self.connector, self.device.0.clone(), self.port)
    }

    /// The condition of a stuck port, for the health view.
    pub fn condition(&self, connector: &str) -> CodedError {
        let cause = self
            .stuck
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |error| error.code.to_string());
        CodedError::new(
            PORT_STUCK,
            503,
            format!(
                "port {} of {} on {connector} stayed down after a bounce: bringing it up \
                 failed {} time(s) ({cause}); Tenko keeps trying, and a person can switch it \
                 on at the controller",
                self.port, self.device, self.attempts
            ),
        )
        .with_param("connector", connector.to_owned())
        .with_param("connector_id", self.connector.to_string())
        .with_param("device", self.device.0.clone())
        .with_param("port", self.port.to_string())
        .with_param("attempts", self.attempts.to_string())
        .with_param("cause", cause)
        .with_param("since", self.created_at.to_rfc3339())
    }
}

/// What became of a bounce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BounceOutcome {
    /// The port went down and came up again, read back.
    Bounced,
    /// The down was not written or not confirmed; the port was brought up (or found up)
    /// again at once.
    DownFailed {
        /// Why.
        error: CodedError,
    },
    /// The port did not come up again: the record stays, the condition
    /// `connect.port_stuck` shows it and the host keeps trying.
    Stuck {
        /// Why the last attempt failed.
        error: CodedError,
    },
}

/// The report of a bounce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BounceReport {
    /// The connector instance.
    pub connector: ConnectorId,
    /// The switch.
    pub device: DeviceRef,
    /// The port index.
    pub port: u16,
    /// How long the port was meant to stay down.
    pub down_secs: u16,
    /// The port's state as read back before the down.
    #[serde(default)]
    pub diff: Vec<DiffLine>,
    /// When the port went down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_at: Option<Timestamp>,
    /// When the read-back showed it up again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_at: Option<Timestamp>,
    /// What became of it.
    #[serde(flatten)]
    pub outcome: BounceOutcome,
}

/// The report of a kick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KickReport {
    /// The connector instance.
    pub connector: ConnectorId,
    /// The client.
    pub mac: MacAddr,
    /// When the controller accepted the command.
    pub kicked_at: Timestamp,
    /// What the plan said would change.
    #[serde(default)]
    pub diff: Vec<DiffLine>,
}

/// Why the host brings a port up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// The bounce's own task, after the down time.
    Scheduled,
    /// The start of the host: a record of an earlier process.
    Startup,
    /// The sweep: a record past due that no task of this host handles.
    Overdue,
}

impl Reason {
    const fn as_str(self) -> &'static str {
        match self {
            Reason::Scheduled => "scheduled",
            Reason::Startup => "startup",
            Reason::Overdue => "overdue",
        }
    }
}

/// The pause before the next attempt after `attempts` failed ones, from the configured
/// first pause (5 s by default): 5 s, 15 s, 60 s, then every 5 minutes.
fn retry_after(base: Duration, attempts: u32) -> Duration {
    base.saturating_mul(match attempts {
        0 | 1 => 1,
        2 => 3,
        3 => 12,
        _ => 60,
    })
}

fn plus(at: Timestamp, after: Duration) -> Timestamp {
    at.checked_add(after).unwrap_or(at)
}

fn principal(on_behalf_of: Option<UserId>) -> Principal {
    Principal::System {
        component: SystemComponent::Connector,
        on_behalf_of,
    }
}

fn objects(connector: ConnectorId, job: Option<JobId>) -> Vec<ObjectRef> {
    let mut objects = vec![ObjectRef::from(connector)];
    if let Some(job) = job {
        objects.push(ObjectRef::from(job));
    }
    objects
}

fn port_context(
    draft: AuditDraft,
    device: &DeviceRef,
    port: u16,
    job: Option<JobId>,
) -> AuditDraft {
    let draft = draft
        .with_context("device", device.0.clone())
        .with_context("port", port.to_string());
    match job {
        Some(job) => draft.with_context("job", job.to_string()),
        None => draft,
    }
}

/// The audit draft of an action that failed with `error`.
fn failed(action: AuditAction, objects: Vec<ObjectRef>, error: &HostError) -> AuditDraft {
    AuditDraft {
        outcome: AuditOutcome::Failed {
            code: std::borrow::Cow::Owned(error.code().to_owned()),
        },
        ..AuditDraft::success(action, objects)
    }
}

/// Checks the plan of a bounce: it names the change and carries exactly one `EnablePort` of
/// the same port in its `undo`.
fn check_bounce_plan(plan: &L2Plan, change: &L2Change) -> Result<(), HostError> {
    if plan.change != *change {
        return Err(ConnectorError::protocol("the plugin planned another change").into());
    }
    let L2Change::BouncePort { device, port, .. } = change else {
        return Err(ConnectorError::protocol("not a bounce").into());
    };
    match plan.undo.as_slice() {
        [
            L2Change::EnablePort {
                device: up_device,
                port: up_port,
                ..
            },
        ] if up_device == device && up_port == port => Ok(()),
        _ => Err(HostError::new(
            BOUNCE_NO_UNDO,
            502,
            "the plugin's plan of the bounce does not carry its way back up (one EnablePort of the same port); nothing was written",
        )),
    }
}

impl ConnectorHost {
    /// Bounces a switch port: down for `down_secs`, then up again, with the way back up
    /// owned by the host (see the module documentation). Returns when the port is up again
    /// or the host gave up for now; dropping the future does not stop the bounce.
    ///
    /// # Errors
    ///
    /// Before anything is written: `connect.bounce.invalid` (the down time), the
    /// capability (`connect.unsupported`), `connect.writes_disabled`, `connect.guardrail.*`,
    /// `connect.bounce.pending`, `connect.bounce.no_undo`, or the errors of a call. Once the
    /// record is written the outcome is in the report, never an error.
    pub async fn bounce_port(
        self: &Arc<Self>,
        id: ConnectorId,
        device: &DeviceRef,
        port: u16,
        down_secs: u16,
        guardrails: &Guardrails,
        job: Option<JobId>,
        on_behalf_of: Option<UserId>,
    ) -> Result<BounceReport, HostError> {
        if !(MIN_DOWN_SECS..=MAX_DOWN_SECS).contains(&down_secs) {
            return Err(HostError::new(
                BOUNCE_INVALID,
                422,
                format!("a port stays down {MIN_DOWN_SECS} to {MAX_DOWN_SECS} seconds"),
            )
            .with_param("down_secs", down_secs.to_string()));
        }
        capability(self, id, Capability::NetworkController)?;
        capability(self, id, Capability::PortBounce)?;
        let change = L2Change::BouncePort {
            device: device.clone(),
            port,
            down_secs,
        };
        let (runtime, client) = self.client(id).await?;
        if !runtime.instance().writes_enabled {
            return Err(ConnectorError::WritesDisabled.into());
        }
        let plan = {
            let _slot = runtime.calls.acquire().await;
            let timeout = runtime.call_timeout();
            let ctx = self.context(&runtime, "bounce_plan", on_behalf_of).await?;
            let topology = client.topology(&ctx, timeout).await?;
            guardrails.check(&change, &topology)?;
            client.plan(&ctx, &change, timeout).await?
        };
        check_bounce_plan(&plan, &change)?;
        if plan.diff.is_empty() {
            // The controller shows the port switched off already.
            return Err(ConnectorError::GuardrailRefused {
                rule: crate::guardrail::PORT_DOWN,
            }
            .into());
        }
        let now = Timestamp::now();
        let call = runtime.call_timeout();
        let record = PendingBounce {
            connector: id,
            device: device.clone(),
            port,
            down_secs,
            job,
            on_behalf_of,
            diff: plan.diff.clone(),
            restore: plan.undo.clone(),
            created_at: now,
            down_at: None,
            due: plus(now, Duration::from_secs(u64::from(down_secs)) + call),
            attempts: 0,
            stuck: None,
        };
        let key = record.key();
        let mut batch = WriteBatch::new(principal(on_behalf_of), now);
        batch.expect_typed(&BOUNCES, &key, None);
        batch.put_typed(&BOUNCES, &key, &record)?;
        batch.audit(
            port_context(
                AuditDraft::success(PORT_BOUNCE, objects(id, job)),
                device,
                port,
                job,
            )
            .with_context("plugin", runtime.instance().plugin)
            .with_context("down_secs", down_secs.to_string()),
        );
        match self.store.propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => {
                return Err(HostError::new(
                    BOUNCE_PENDING,
                    409,
                    format!("port {port} of {device} has a bounce pending; nothing was written"),
                )
                .with_param("device", device.0.clone())
                .with_param("port", port.to_string()));
            }
            Err(error) => return Err(error.into()),
        }
        self.claim(&key);
        let (done, report) = oneshot::channel();
        let host = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = host.run_bounce(record, plan).await;
            host.release(&key);
            let _ = done.send(outcome);
        });
        report.await.map_err(|_| {
            HostError::new(
                "connect.bounce.lost",
                500,
                "the bounce task ended without a report; the pending record brings the port up",
            )
        })
    }

    /// The task of one bounce: the down, the wait, the up.
    async fn run_bounce(self: &Arc<Self>, mut record: PendingBounce, plan: L2Plan) -> BounceReport {
        let key = record.key();
        let down = self.send_down(&record, &plan).await;
        let mut report = BounceReport {
            connector: record.connector,
            device: record.device.clone(),
            port: record.port,
            down_secs: record.down_secs,
            diff: record.diff.clone(),
            down_at: None,
            up_at: None,
            outcome: BounceOutcome::Bounced,
        };
        match &down {
            Ok(at) => {
                report.down_at = Some(*at);
                record.down_at = Some(*at);
                self.note_down(&key, *at).await;
                tokio::time::sleep(Duration::from_secs(u64::from(record.down_secs))).await;
            }
            Err(error) => {
                tracing::warn!(
                    connector = %record.connector,
                    device = %record.device,
                    port = record.port,
                    code = %error.code(),
                    "the down of a port bounce failed; the port is brought up again at once"
                );
                self.audit_failed(&record, PORT_BOUNCE, error).await;
            }
        }
        let mut last = None;
        for attempt in 0..TASK_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(retry_after(self.config.bounce_retry, attempt)).await;
            }
            match self.bring_up(&key, Reason::Scheduled).await {
                Ok(at) => {
                    report.up_at = at;
                    last = None;
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        report.outcome = match (last, down) {
            (Some(error), _) => BounceOutcome::Stuck {
                error: error.into_coded(),
            },
            (None, Err(error)) => BounceOutcome::DownFailed {
                error: error.into_coded(),
            },
            (None, Ok(_)) => BounceOutcome::Bounced,
        };
        report
    }

    /// Sends the down of a bounce and checks that the plugin confirmed it.
    async fn send_down(
        &self,
        record: &PendingBounce,
        plan: &L2Plan,
    ) -> Result<Timestamp, HostError> {
        let (runtime, client) = self.client(record.connector).await?;
        let _slot = runtime.calls.acquire().await;
        let ctx = self
            .context(&runtime, "bounce_apply", record.on_behalf_of)
            .await?;
        let receipt = client
            .apply(&ctx, plan, WriteMode::Apply, runtime.call_timeout())
            .await?;
        if receipt.plan.change != plan.change || receipt.plan.fingerprint != plan.fingerprint {
            return Err(ConnectorError::protocol("the receipt names another plan").into());
        }
        if !receipt.verified {
            return Err(ConnectorError::VerifyMismatch {
                diff: "the plugin reports that the port did not read back as down".to_owned(),
            }
            .into());
        }
        Ok(receipt.applied_at)
    }

    /// Notes in the record when the port went down (best effort: the record serves its
    /// purpose without it).
    async fn note_down(&self, key: &BounceKey, at: Timestamp) {
        for _ in 0..3 {
            let Ok(view) = self.store.read(ReadConsistency::Local).await else {
                return;
            };
            let Ok(Some((mut record, revision))) = view.get_typed(&BOUNCES, key) else {
                return;
            };
            drop(view);
            record.down_at = Some(at);
            let mut batch = WriteBatch::new(principal(record.on_behalf_of), Timestamp::now());
            batch.expect_typed(&BOUNCES, key, Some(revision));
            if batch.put_typed(&BOUNCES, key, &record).is_err() {
                return;
            }
            match self.store.propose(batch).await {
                Err(StoreError::PreconditionFailed(_)) => {}
                _ => return,
            }
        }
    }

    /// Brings the port of a pending record up: plans its way back up, writes it when the
    /// port is not up, reads back, and removes the record with the audit record. On a
    /// failure the record stays, marked stuck, due again after a pause. `Ok(None)` when
    /// there is no record (another task brought the port up).
    async fn bring_up(
        &self,
        key: &BounceKey,
        reason: Reason,
    ) -> Result<Option<Timestamp>, HostError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let Some((record, revision)) = view.get_typed(&BOUNCES, key)? else {
            return Ok(None);
        };
        drop(view);
        match self.send_up(&record).await {
            Ok(()) => {
                let now = Timestamp::now();
                let mut batch = WriteBatch::new(principal(record.on_behalf_of), now);
                batch.expect_typed(&BOUNCES, key, Some(revision));
                batch.delete_typed(&BOUNCES, key);
                batch.audit(
                    port_context(
                        AuditDraft::success(PORT_ENABLE, objects(record.connector, record.job)),
                        &record.device,
                        record.port,
                        record.job,
                    )
                    .with_context("reason", reason.as_str())
                    .with_context("attempts", record.attempts.to_string()),
                );
                match self.store.propose(batch).await {
                    Ok(_) | Err(StoreError::PreconditionFailed(_)) => {}
                    Err(error) => return Err(error.into()),
                }
                if reason != Reason::Scheduled || record.stuck.is_some() {
                    tracing::warn!(
                        connector = %record.connector,
                        device = %record.device,
                        port = record.port,
                        reason = reason.as_str(),
                        attempts = record.attempts,
                        "a port left down by a bounce is up again"
                    );
                }
                if record.stuck.is_some() {
                    self.health_changed(record.connector);
                }
                Ok(Some(now))
            }
            Err(error) => {
                let first = record.stuck.is_none();
                let mut next = record.clone();
                next.attempts = next.attempts.saturating_add(1);
                next.stuck = Some((*error.0).clone());
                next.due = plus(
                    Timestamp::now(),
                    retry_after(self.config.bounce_retry, next.attempts),
                );
                let mut batch = WriteBatch::new(principal(record.on_behalf_of), Timestamp::now());
                batch.expect_typed(&BOUNCES, key, Some(revision));
                batch.put_typed(&BOUNCES, key, &next)?;
                if first {
                    batch.audit(
                        port_context(
                            failed(PORT_ENABLE, objects(record.connector, record.job), &error),
                            &record.device,
                            record.port,
                            record.job,
                        )
                        .with_context("reason", reason.as_str()),
                    );
                }
                match self.store.propose(batch).await {
                    Ok(_) | Err(StoreError::PreconditionFailed(_)) => {}
                    Err(store) => {
                        tracing::warn!(%store, "the stuck port could not be recorded");
                    }
                }
                tracing::error!(
                    connector = %record.connector,
                    device = %record.device,
                    port = record.port,
                    code = %error.code(),
                    attempts = next.attempts,
                    "a port did not come up again after a bounce ({PORT_STUCK}); Tenko keeps trying"
                );
                if first {
                    self.health_changed(record.connector);
                }
                Err(error)
            }
        }
    }

    /// Writes the way back up of a record and reads it back.
    async fn send_up(&self, record: &PendingBounce) -> Result<(), HostError> {
        let (runtime, client) = self.client(record.connector).await?;
        let _slot = runtime.calls.acquire().await;
        let timeout = runtime.call_timeout();
        let ctx = self
            .context(&runtime, "bounce_enable", record.on_behalf_of)
            .await?;
        for change in &record.restore {
            if !matches!(change, L2Change::EnablePort { .. }) {
                return Err(
                    ConnectorError::protocol("the way back up is not an EnablePort").into(),
                );
            }
            let plan = client.plan(&ctx, change, timeout).await?;
            if plan.diff.is_empty() {
                continue;
            }
            let receipt = client.apply(&ctx, &plan, WriteMode::Apply, timeout).await?;
            if !receipt.verified {
                return Err(ConnectorError::VerifyMismatch {
                    diff: "the plugin reports that the port did not read back as up".to_owned(),
                }
                .into());
            }
            let again = client.plan(&ctx, change, timeout).await?;
            if let Some(line) = again.diff.first() {
                return Err(ConnectorError::VerifyMismatch {
                    diff: format!(
                        "after the way back up `{}` is {} instead of {}",
                        line.path,
                        line.before.as_deref().unwrap_or("absent"),
                        line.after.as_deref().unwrap_or("absent")
                    ),
                }
                .into());
            }
        }
        Ok(())
    }

    /// Writes an audit record of a failure (best effort).
    async fn audit_failed(&self, record: &PendingBounce, action: AuditAction, error: &HostError) {
        let mut batch = WriteBatch::new(principal(record.on_behalf_of), Timestamp::now());
        batch.audit(port_context(
            failed(action, objects(record.connector, record.job), error),
            &record.device,
            record.port,
            record.job,
        ));
        if let Err(store) = self.store.propose(batch).await {
            tracing::warn!(%store, "a failed bounce could not be audited");
        }
    }

    /// Marks a record as handled by a task of this host.
    fn claim(&self, key: &BounceKey) -> bool {
        self.bouncing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.clone())
    }

    fn release(&self, key: &BounceKey) {
        self.bouncing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

    /// Brings up the ports of pending records: every one at the start of the host
    /// (`startup`), else those past due that no task of this host handles. Each runs in
    /// a task of its own.
    pub(super) async fn sweep_bounces(self: &Arc<Self>, startup: bool) {
        let records = match self.pending_bounces().await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error, "the pending bounces could not be read");
                return;
            }
        };
        let now = Timestamp::now();
        let reason = if startup {
            Reason::Startup
        } else {
            Reason::Overdue
        };
        for record in records {
            if !startup && record.due > now {
                continue;
            }
            let key = record.key();
            if !self.claim(&key) {
                continue;
            }
            if startup {
                tracing::warn!(
                    connector = %record.connector,
                    device = %record.device,
                    port = record.port,
                    "a bounce of an earlier process left a port pending; it is brought up now"
                );
            }
            let host = Arc::clone(self);
            tokio::spawn(async move {
                let _ = host.bring_up(&key, reason).await;
                host.release(&key);
            });
        }
    }

    /// Every pending bounce.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn pending_bounces(&self) -> Result<Vec<PendingBounce>, HostError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(view
            .scan_typed(&BOUNCES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, _)| record)
            .collect())
    }

    /// The ports a bounce left down, with the condition `connect.port_stuck` of each, for
    /// the health view.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn stuck_ports(&self) -> Result<Vec<CodedError>, HostError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut conditions = Vec::new();
        for (_, record, _) in view.scan_typed(&BOUNCES, KeyRange::all(), usize::MAX, false)? {
            if record.stuck.is_none() {
                continue;
            }
            let name = view
                .get_typed(&super::tables::INSTANCES, &record.connector)?
                .map_or_else(
                    || record.connector.to_string(),
                    |(instance, _)| instance.name,
                );
            conditions.push(record.condition(&name));
        }
        Ok(conditions)
    }

    /// Disconnects a wireless client so that it associates again (see the module
    /// documentation).
    ///
    /// # Errors
    ///
    /// The capability (`connect.unsupported`), `connect.writes_disabled`,
    /// `connect.guardrail.*`, `connect.verify_mismatch` (a stale plan, or a controller that
    /// did not accept the command), or the errors of a call.
    pub async fn kick_client(
        &self,
        id: ConnectorId,
        mac: MacAddr,
        guardrails: &Guardrails,
        job: Option<JobId>,
        on_behalf_of: Option<UserId>,
    ) -> Result<KickReport, HostError> {
        capability(self, id, Capability::NetworkController)?;
        capability(self, id, Capability::ClientKick)?;
        let change = L2Change::KickClient { mac };
        let (runtime, client) = self.client(id).await?;
        if !runtime.instance().writes_enabled {
            return Err(ConnectorError::WritesDisabled.into());
        }
        let outcome = async {
            let _slot = runtime.calls.acquire().await;
            let timeout = runtime.call_timeout();
            let ctx = self.context(&runtime, "kick", on_behalf_of).await?;
            let topology = client.topology(&ctx, timeout).await?;
            guardrails.check(&change, &topology)?;
            let plan = client.plan(&ctx, &change, timeout).await?;
            if plan.change != change {
                return Err(ConnectorError::protocol("the plugin planned another change").into());
            }
            if Timestamp::now().saturating_since(plan.read_at) > self.config.plan_max_age {
                return Err(HostError::from(ConnectorError::VerifyMismatch {
                    diff: "the plan is too old; plan the kick again".to_owned(),
                }));
            }
            let receipt = client.apply(&ctx, &plan, WriteMode::Apply, timeout).await?;
            if !receipt.verified {
                return Err(ConnectorError::VerifyMismatch {
                    diff: "the controller did not accept the kick".to_owned(),
                }
                .into());
            }
            Ok(KickReport {
                connector: id,
                mac,
                kicked_at: receipt.applied_at,
                diff: plan.diff,
            })
        }
        .await;
        let draft = match &outcome {
            Ok(_) => AuditDraft::success(CLIENT_KICK, objects(id, job)),
            Err(error) => failed(CLIENT_KICK, objects(id, job), error),
        };
        let mut draft = draft
            .with_context("mac", mac.to_string())
            .with_context("plugin", runtime.instance().plugin);
        if let Some(job) = job {
            draft = draft.with_context("job", job.to_string());
        }
        let mut batch = WriteBatch::new(principal(on_behalf_of), Timestamp::now());
        batch.audit(draft);
        if let Err(store) = self.store.propose(batch).await {
            tracing::warn!(%store, "a client kick could not be audited");
        }
        outcome
    }
}

/// Refuses a bounce or a kick through the generic L2 calls: those have their own calls,
/// which own the way back up of a bounce.
pub(super) fn refuse_direct(change: &L2Change) -> Result<(), HostError> {
    if change.is_nudge() {
        return Err(HostError::new(
            NUDGE_DIRECT,
            422,
            "a port bounce or a client kick goes through its own call, which owns the way back up",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pause_grows_and_stays_bounded() {
        let base = Duration::from_secs(5);
        assert_eq!(retry_after(base, 1), Duration::from_secs(5));
        assert_eq!(retry_after(base, 2), Duration::from_secs(15));
        assert_eq!(retry_after(base, 3), Duration::from_secs(60));
        assert_eq!(retry_after(base, 40), Duration::from_secs(300));
    }

    #[test]
    fn a_bounce_plan_must_carry_its_way_back_up() {
        let device = DeviceRef("00:00:5e:00:53:a0".to_owned());
        let change = L2Change::BouncePort {
            device: device.clone(),
            port: 3,
            down_secs: 5,
        };
        let mut plan = L2Plan {
            change: change.clone(),
            read_at: Timestamp::now(),
            fingerprint: "f".to_owned(),
            diff: Vec::new(),
            warnings: Vec::new(),
            undo: Vec::new(),
        };
        assert_eq!(
            check_bounce_plan(&plan, &change)
                .expect_err("no undo")
                .code(),
            BOUNCE_NO_UNDO
        );
        plan.undo = vec![L2Change::EnablePort {
            device: device.clone(),
            port: 4,
            restore: String::new(),
        }];
        assert!(check_bounce_plan(&plan, &change).is_err(), "another port");
        plan.undo = vec![L2Change::EnablePort {
            device,
            port: 3,
            restore: String::new(),
        }];
        assert!(check_bounce_plan(&plan, &change).is_ok());
        assert_eq!(
            refuse_direct(&change).expect_err("direct").code(),
            NUDGE_DIRECT
        );
    }
}
