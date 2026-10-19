//! Key rollovers as a job (RFC 6781, RFC 7583): `dns.dnssec.rollover`, started by
//! `POST /dns/zones/{id}/dnssec/rollover` or by the schedule of `zsk_rollover_days`.
//!
//! | Step | ZSK (pre-publish, RFC 6781 4.1.1.1) | KSK or CSK (double KSK with CDS and CDNSKEY) |
//! |---|---|---|
//! | `dns.dnssec.publish` | a new ZSK is published; nothing is signed with it | a new key is published and signs the DNSKEY set beside the old one; CDS and CDNSKEY list both |
//! | `dns.dnssec.wait` | the DNSKEY TTL and the propagation delay | the same |
//! | `dns.dnssec.parent` | | a person puts the new DS at the parent (the job waits for the confirmation) |
//! | `dns.dnssec.activate` | the new ZSK signs, the old one retires: every signature is made again | the new key is the one, the old one retires; CDS and CDNSKEY list the new one only |
//! | `dns.dnssec.wait` | the largest TTL of the zone and the propagation delay | the same |
//! | `dns.dnssec.retire` | the old key leaves the DNSKEY set and the vault | the same |
//!
//! The propagation delay is the SOA refresh (at most an hour) when the zone has
//! secondaries (a transfer access list or NOTIFY targets), else nothing. Every step is
//! idempotent and reads where the rollover stands from the keys' states and timestamps,
//! so a step that runs again after a restart or a change of leader picks up where it was;
//! a wait sleeps what is left of it. Each step re-signs the zone ([`Signer::sync`]) and is
//! audited as `dns.dnssec.rollover`, each key change as `dns.dnssec.key_state`. Undoing a
//! rollover removes a key that was published and never active; later steps are not undone.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    MessageKey, ObjectRef, RequestCtx, Timestamp,
    audit::AuditDraft,
    codec::{from_cbor, to_cbor},
    dns::{KeyRole, KeyState, SignState, Zone, ZoneId, audit, tables::SIGN_STATE},
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobKind, JobSpec, ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{ReadView, StoreError};

use super::{
    keys::{self, role_name},
    signer::{self, Signer},
};
use crate::zone::{ZoneError, ZoneService, signing::signer_batch};

/// The kind of the job.
pub const ROLLOVER_JOB: &str = "dns.dnssec.rollover";

/// The title of the job.
pub const ROLLOVER_TITLE: &str = "dns.job.dnssec_rollover";

/// The step that publishes the new key.
pub const PUBLISH_STEP: &str = "dns.dnssec.publish";

/// The step that waits.
pub const WAIT_STEP: &str = "dns.dnssec.wait";

/// The step that asks for the DS at the parent.
pub const PARENT_STEP: &str = "dns.dnssec.parent";

/// The step that makes the new key the signing one.
pub const ACTIVATE_STEP: &str = "dns.dnssec.activate";

/// The step that removes the old key.
pub const RETIRE_STEP: &str = "dns.dnssec.retire";

/// The manual task of the parent step.
pub const PARENT_TASK: &str = "dns.dnssec.parent_ds";

/// The manual task's undo text.
pub const PARENT_UNDO: &str = "dns.dnssec.parent_ds_undo";

/// The longest a rollover job may take.
pub const JOB_TIMEOUT: Duration = Duration::from_secs(90 * 86_400);

/// Where a rollover step is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Publish the new key.
    Publish,
    /// Wait for caches to hold the new DNSKEY set.
    AfterPublish,
    /// The DS at the parent.
    Parent,
    /// The new key signs.
    Activate,
    /// Wait for caches to forget the old signatures or DS.
    AfterActivate,
    /// Remove the old key.
    Retire,
}

/// The parameters of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// The zone.
    pub zone: ZoneId,
    /// The role rolled.
    pub role: KeyRole,
    /// The step.
    pub phase: Phase,
}

fn step(kind: &'static str, params: Params) -> StepSpec {
    StepSpec {
        kind: StepKind::from_static(kind),
        params: HexBytes(
            to_cbor(&params)
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default(),
        ),
        timeout: None,
    }
}

/// The job of a rollover of `role` in `zone`.
pub fn job_spec(zone: &Zone, role: KeyRole) -> JobSpec {
    let params = |phase| Params {
        zone: zone.id,
        role,
        phase,
    };
    let mut steps = vec![
        step(PUBLISH_STEP, params(Phase::Publish)),
        step(WAIT_STEP, params(Phase::AfterPublish)),
    ];
    if keys::signs_keys(role) {
        steps.push(step(PARENT_STEP, params(Phase::Parent)));
    }
    steps.push(step(ACTIVATE_STEP, params(Phase::Activate)));
    steps.push(step(WAIT_STEP, params(Phase::AfterActivate)));
    steps.push(step(RETIRE_STEP, params(Phase::Retire)));
    JobSpec {
        kind: JobKind::from_static(ROLLOVER_JOB),
        title: MessageKey::from_static(ROLLOVER_TITLE),
        targets: vec![ObjectRef::from(zone.id)],
        steps,
        timeout: JOB_TIMEOUT,
        group: None,
        group_limit: None,
        idempotency: None,
        node: None,
    }
}

/// The propagation delay of a zone: the SOA refresh, at most an hour, when it has
/// secondaries; nothing otherwise.
pub fn propagation(zone: &Zone) -> Duration {
    if zone.transfer.allow.is_empty() && zone.transfer.notify.is_empty() {
        Duration::ZERO
    } else {
        Duration::from_secs(u64::from(zone.soa.refresh.min(3_600)))
    }
}

/// The step handlers of the rollover job.
pub fn step_handlers(signer: &Arc<Signer>) -> Vec<Arc<dyn StepHandler>> {
    [
        PUBLISH_STEP,
        WAIT_STEP,
        PARENT_STEP,
        ACTIVATE_STEP,
        RETIRE_STEP,
    ]
    .into_iter()
    .map(|kind| {
        Arc::new(RolloverStep {
            kind,
            signer: Arc::clone(signer),
        }) as Arc<dyn StepHandler>
    })
    .collect()
}

/// Starts the scheduled ZSK rollover of a zone whose ZSK has signed for
/// `zsk_rollover_days`. A zone with a CSK rolls only when asked, since its rollover needs
/// the parent.
pub async fn schedule(signer: &Signer, zone: &Zone, state: &SignState, now: Timestamp) {
    let Some(days) = zone.dnssec.zsk_rollover_days else {
        return;
    };
    if zone.dnssec.csk || state.rollover_job.is_some() {
        return;
    }
    let period = Duration::from_secs(u64::from(days) * 86_400);
    let due = state
        .keys
        .iter()
        .filter(|key| key.role == KeyRole::Zsk && key.state == KeyState::Active)
        .filter_map(|key| key.activated)
        .any(|activated| now.saturating_since(activated) >= period);
    if !due {
        return;
    }
    let cx = crate::zone::signing::signer_ctx();
    match signer
        .zones()
        .start_rollover(&cx, zone.id, KeyRole::Zsk, |zone, _| {
            job_spec(zone, KeyRole::Zsk)
        })
        .await
    {
        Ok(job) => tracing::info!(zone = %zone.name, %job, "scheduled ZSK rollover started"),
        Err(error) => {
            tracing::warn!(zone = %zone.name, %error, "the scheduled ZSK rollover could not start");
        }
    }
}

struct RolloverStep {
    kind: &'static str,
    signer: Arc<Signer>,
}

fn coded(error: &ZoneError) -> StepError {
    StepError::coded(error)
}

/// The zone and its signing state, read now.
async fn read(
    signer: &Signer,
    zone: ZoneId,
) -> Result<(Arc<dyn ReadView>, Zone, SignState, tenko_core::Revision), StepError> {
    let view = signer
        .zones()
        .view(None)
        .await
        .map_err(|error| coded(&error))?;
    let zone_row = ZoneService::zone(view.as_ref(), zone).map_err(|error| coded(&error))?;
    let (state, revision) = ZoneService::sign_state(view.as_ref(), zone)
        .map_err(|error| coded(&error))?
        .ok_or_else(|| StepError::InvalidParams("the zone has no signing state".to_owned()))?;
    Ok((view, zone_row.zone, state, revision))
}

impl RolloverStep {
    /// Writes a changed signing state with its audit records, then signs the zone.
    async fn write(
        &self,
        zone: &Zone,
        state: &SignState,
        revision: tenko_core::Revision,
        audits: Vec<AuditDraft>,
        deletes: &[tenko_core::secret::SecretRef],
        cx: &StepContext,
    ) -> Result<bool, StepError> {
        let mut batch = signer_batch(self.signer.epoch());
        for draft in audits {
            batch.audit(draft);
        }
        let vault = self
            .signer
            .zones()
            .vault_handle()
            .ok_or_else(|| StepError::InvalidParams("the vault does not run".to_owned()))?;
        for secret in deletes {
            vault.stage_delete(&mut batch, &cx.request, *secret);
        }
        batch.expect_typed(&SIGN_STATE, &zone.id, Some(revision));
        batch
            .put_typed(&SIGN_STATE, &zone.id, state)
            .map_err(StepError::Store)?;
        match cx.store.propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => return Ok(false),
            Err(error) => return Err(StepError::Store(error)),
        }
        self.signer
            .sync(zone.id, signer::key_trigger())
            .await
            .map_err(|error| coded(&error))?;
        Ok(true)
    }

    fn audit(zone: &Zone, role: KeyRole, phase: &str) -> AuditDraft {
        AuditDraft::success(audit::DNSSEC_ROLLOVER, vec![ObjectRef::from(zone.id)])
            .with_context("zone", zone.name.as_str())
            .with_context("role", role_name(role))
            .with_context("step", phase)
    }

    fn key_audit(zone: &Zone, role: KeyRole, tag: u16, state: KeyState) -> AuditDraft {
        AuditDraft::success(audit::DNSSEC_KEY_STATE, vec![ObjectRef::from(zone.id)])
            .with_context("zone", zone.name.as_str())
            .with_context("role", role_name(role))
            .with_context("key_tag", tag.to_string())
            .with_context("state", keys::state_name(state))
    }

    async fn publish(&self, params: Params, cx: &StepContext) -> Result<StepOutcome, StepError> {
        for _ in 0..8 {
            let (_, zone, mut state, revision) = read(&self.signer, params.zone).await?;
            if state.rollover_job.is_some_and(|job| job != cx.job) {
                return Err(StepError::coded(&ZoneError::new(
                    tenko_core::dns::codes::DNSSEC_ROLLOVER_RUNNING,
                    409,
                    format!("another key rollover of zone {} runs", zone.name),
                )));
            }
            if state
                .keys
                .iter()
                .any(|key| key.role == params.role && key.state == KeyState::Published)
            {
                return Ok(StepOutcome::Done { output: None });
            }
            let Some(algorithm) = state
                .keys
                .iter()
                .find(|key| key.role == params.role && key.state == KeyState::Active)
                .map(|key| key.algorithm)
            else {
                return Err(StepError::InvalidParams(format!(
                    "zone {} has no active {} to roll",
                    zone.name,
                    role_name(params.role)
                )));
            };
            let vault = self
                .signer
                .zones()
                .vault_handle()
                .ok_or_else(|| StepError::InvalidParams("the vault does not run".to_owned()))?;
            let mut batch = signer_batch(self.signer.epoch());
            let taken: Vec<u16> = state.keys.iter().map(|key| key.key_tag).collect();
            let request = RequestCtx {
                now: Timestamp::now(),
                ..cx.request.clone()
            };
            let key = keys::stage_new_key(
                vault.as_ref(),
                &mut batch,
                &request,
                zone.id,
                &zone.name,
                params.role,
                algorithm,
                KeyState::Published,
                &taken,
            )
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
            batch.audit(
                AuditDraft::success(audit::DNSSEC_KEY_CREATE, vec![ObjectRef::from(zone.id)])
                    .with_context("zone", zone.name.as_str())
                    .with_context("role", role_name(params.role))
                    .with_context("key_tag", key.key_tag.to_string()),
            );
            batch.audit(Self::key_audit(
                &zone,
                params.role,
                key.key_tag,
                KeyState::Published,
            ));
            batch.audit(Self::audit(&zone, params.role, "publish"));
            state.keys.push(key);
            state.rollover_job = Some(cx.job);
            batch.expect_typed(&SIGN_STATE, &zone.id, Some(revision));
            batch
                .put_typed(&SIGN_STATE, &zone.id, &state)
                .map_err(StepError::Store)?;
            match cx.store.propose(batch).await {
                Ok(_) => {
                    self.signer
                        .sync(zone.id, signer::key_trigger())
                        .await
                        .map_err(|error| coded(&error))?;
                    return Ok(StepOutcome::Done { output: None });
                }
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(StepError::Store(error)),
            }
        }
        Err(StepError::Store(StoreError::Timeout))
    }

    async fn wait(&self, params: Params) -> Result<StepOutcome, StepError> {
        let (view, zone, state, _) = read(&self.signer, params.zone).await?;
        let (since, hold) = if params.phase == Phase::AfterPublish {
            {
                let Some(published) = state
                    .keys
                    .iter()
                    .filter(|key| key.role == params.role && key.state == KeyState::Published)
                    .filter_map(|key| key.published)
                    .max()
                else {
                    return Ok(StepOutcome::Skip);
                };
                (published, Duration::from_secs(u64::from(zone.soa.ttl)))
            }
        } else {
            {
                let Some(retired) = state
                    .keys
                    .iter()
                    .filter(|key| key.role == params.role && key.state == KeyState::Retired)
                    .filter_map(|key| key.retired)
                    .max()
                else {
                    return Ok(StepOutcome::Skip);
                };
                let largest =
                    signer::max_ttl(view.as_ref(), &zone).map_err(|error| coded(&error))?;
                (
                    retired,
                    Duration::from_secs(u64::from(largest.max(zone.soa.ttl))),
                )
            }
        };
        drop(view);
        let wait = hold + propagation(&zone);
        let passed = Timestamp::now().saturating_since(since);
        if let Some(left) = wait.checked_sub(passed) {
            tokio::time::sleep(left).await;
        }
        Ok(StepOutcome::Done { output: None })
    }

    async fn parent(&self, params: Params) -> Result<StepOutcome, StepError> {
        let (_, zone, state, _) = read(&self.signer, params.zone).await?;
        if !state
            .keys
            .iter()
            .any(|key| key.role == params.role && key.state == KeyState::Published)
        {
            return Ok(StepOutcome::Skip);
        }
        let ds = keys::ds_records(&zone.name, &state)
            .iter()
            .filter_map(|record| match record {
                tenko_core::dns::RecordData::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                } => Some(format!(
                    "{} DS {key_tag} {algorithm} {digest_type} {}",
                    zone.name,
                    tenko_core::serde_util::to_hex(&digest.0).to_ascii_uppercase()
                )),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(StepOutcome::Manual(ManualTask {
            instruction: MessageKey::from_static(PARENT_TASK),
            args: BTreeMap::from([
                ("zone".to_owned(), zone.name.to_string()),
                ("ds".to_owned(), ds),
            ]),
            undo: Some(MessageKey::from_static(PARENT_UNDO)),
        }))
    }

    async fn activate(&self, params: Params, cx: &StepContext) -> Result<StepOutcome, StepError> {
        for _ in 0..8 {
            let (_, zone, mut state, revision) = read(&self.signer, params.zone).await?;
            let now = Timestamp::now();
            let Some(index) = state
                .keys
                .iter()
                .position(|key| key.role == params.role && key.state == KeyState::Published)
            else {
                return Ok(StepOutcome::Skip);
            };
            let mut audits = vec![Self::audit(&zone, params.role, "activate")];
            for (position, key) in state.keys.iter_mut().enumerate() {
                if key.role != params.role {
                    continue;
                }
                if position == index {
                    keys::set_state(key, KeyState::Active, now);
                    audits.push(Self::key_audit(
                        &zone,
                        params.role,
                        key.key_tag,
                        KeyState::Active,
                    ));
                } else if key.state == KeyState::Active {
                    keys::set_state(key, KeyState::Retired, now);
                    audits.push(Self::key_audit(
                        &zone,
                        params.role,
                        key.key_tag,
                        KeyState::Retired,
                    ));
                }
            }
            if self.write(&zone, &state, revision, audits, &[], cx).await? {
                return Ok(StepOutcome::Done { output: None });
            }
        }
        Err(StepError::Store(StoreError::Timeout))
    }

    async fn retire(&self, params: Params, cx: &StepContext) -> Result<StepOutcome, StepError> {
        for _ in 0..8 {
            let (_, zone, mut state, revision) = read(&self.signer, params.zone).await?;
            let mut audits = vec![Self::audit(&zone, params.role, "finish")];
            let mut deletes = Vec::new();
            for key in &mut state.keys {
                if key.role == params.role && key.state == KeyState::Retired {
                    key.state = KeyState::Removed;
                    deletes.push(key.secret);
                    audits.push(Self::key_audit(
                        &zone,
                        params.role,
                        key.key_tag,
                        KeyState::Removed,
                    ));
                }
            }
            if state.rollover_job == Some(cx.job) {
                state.rollover_job = None;
            }
            if self
                .write(&zone, &state, revision, audits, &deletes, cx)
                .await?
            {
                return Ok(StepOutcome::Done { output: None });
            }
        }
        Err(StepError::Store(StoreError::Timeout))
    }

    /// Undoes the publish step: a key published and never active goes, and the job is no
    /// longer the zone's rollover.
    async fn undo_publish(&self, params: Params, cx: &StepContext) -> Result<(), StepError> {
        for _ in 0..8 {
            let (_, zone, mut state, revision) = read(&self.signer, params.zone).await?;
            if state.rollover_job != Some(cx.job) {
                // Another rollover's key is not this job's to undo.
                return Ok(());
            }
            let mut deletes = Vec::new();
            let mut audits = vec![Self::audit(&zone, params.role, "undo")];
            for key in &mut state.keys {
                if key.role == params.role && key.state == KeyState::Published {
                    key.state = KeyState::Removed;
                    deletes.push(key.secret);
                    audits.push(Self::key_audit(
                        &zone,
                        params.role,
                        key.key_tag,
                        KeyState::Removed,
                    ));
                }
            }
            if state.rollover_job == Some(cx.job) {
                state.rollover_job = None;
            }
            if self
                .write(&zone, &state, revision, audits, &deletes, cx)
                .await?
            {
                return Ok(());
            }
        }
        Err(StepError::Store(StoreError::Timeout))
    }
}

#[async_trait::async_trait]
impl StepHandler for RolloverStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(self.kind)
    }

    /// Each step reads where the rollover stands and does only what is left.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: Params =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(ROLLOVER_TITLE),
            args: BTreeMap::from([
                ("zone".to_owned(), params.zone.to_string()),
                ("role".to_owned(), role_name(params.role).to_owned()),
            ]),
            changes: vec![ObjectRef::from(params.zone)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: Params =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        match params.phase {
            Phase::Publish => self.publish(params, cx).await,
            Phase::AfterPublish | Phase::AfterActivate => self.wait(params).await,
            Phase::Parent => self.parent(params).await,
            Phase::Activate => self.activate(params, cx).await,
            Phase::Retire => self.retire(params, cx).await,
        }
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let params: Params =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        if params.phase == Phase::Publish {
            self.undo_publish(params, cx).await
        } else {
            Ok(())
        }
    }
}
