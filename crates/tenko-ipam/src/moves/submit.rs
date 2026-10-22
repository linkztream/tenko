//! Previewing and submitting moves: the plan from the store and the network controllers,
//! one background job per item in one job group, and an idempotency receipt per request
//! key.

// The controllers' port reports `CodedError`s, so the connector authorization returns it too.
#![allow(clippy::result_large_err)]

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    CodedError, IdempotencyKey, MessageKey, ObjectRef, RequestCtx, Revision,
    audit::Digest,
    codec::{canonical_sha256, to_cbor},
    serde_util::{HexBytes, to_hex},
};
use tenko_jobs::{GroupKey, JobKind, JobSpec, StepKind, StepSpec};
use tenko_store::{ReadConsistency, ReadViewExt, StoreError, WriteBatch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    JOB_TIMEOUT_SECS, MOVE_JOB, MoveItem, MoveJob, MovePreview, MoveRequest, MoveStepParams,
    MoveSubmitted, codes as move_codes, l2,
    preview::{Computed, StepPlan, compute, finish},
};
use crate::{
    error::{IpamError, IpamResult, codes},
    service::IpamService,
    tables::MOVE_RECEIPTS,
    vlan::controllers::{ControllerInfo, Controllers},
};

/// Authorizes a submit to write through a network controller (the route checks
/// `Execute` on the connector).
pub type AuthorizeController<'a> = &'a (dyn Fn(&ControllerInfo) -> Result<(), CodedError> + Sync);

/// The preview of a move (the dry run, API-09) with the L2 step of every device from the
/// network controllers, at least at `at_least` when given. Writes nothing; the controllers
/// are read once each.
///
/// # Errors
///
/// See [`super::preview()`]. A controller that cannot be read is a warning, not an error.
pub async fn preview_move(
    ipam: &IpamService,
    controllers: &Controllers,
    request: &MoveRequest,
    cx: &RequestCtx,
    at_least: Option<Revision>,
) -> IpamResult<MovePreview> {
    let view = ipam.view(at_least).await?;
    let base = compute(view.as_ref(), cx, &ipam.config(), request)?;
    drop(view);
    let plans = l2::plan(controllers, &base.items, &base.target, cx).await;
    Ok(finish(base, plans, request)?.preview)
}

/// Submits a move: computes the plan again from a fresh view and fresh controller reads,
/// refuses a plan other than the confirmed preview (`expect_fingerprint`, 409
/// `ipam.move.plan_changed`) and unacknowledged warnings, asks `authorize` for every
/// controller an automatic L2 step writes through, and starts one job per item in one job
/// group. A repeated idempotency key returns the first answer with `replayed: true`;
/// another request under the same key is 422 `ipam.idempotency_mismatch`.
///
/// # Errors
///
/// The errors of the preview, 409 `ipam.move.plan_changed`, 409
/// `ipam.plan.unacknowledged`, the refusal of `authorize`, 503 `ipam.move.no_engine`
/// without the job engine, and the engine's errors.
pub async fn submit_move(
    ipam: &IpamService,
    controllers: &Controllers,
    request: &MoveRequest,
    cx: &RequestCtx,
    authorize: AuthorizeController<'_>,
) -> IpamResult<MoveSubmitted> {
    let fingerprint = Digest(canonical_sha256(request)?);
    let key = cx
        .idempotency
        .as_ref()
        .map(|key| (cx.principal.subject(), key.as_str().to_owned()));
    if let Some(key) = &key
        && let Some(receipt) = ipam.move_receipt(key).await?
    {
        return replay(receipt, fingerprint);
    }
    let view = ipam.store().read(ReadConsistency::Linearizable).await?;
    let base = compute(view.as_ref(), cx, &ipam.config(), request)?;
    drop(view);
    let plans = l2::plan(controllers, &base.items, &base.target, cx).await;
    let Computed { preview, steps } = finish(base, plans, request)?;
    if let Some(expected) = &request.expect_fingerprint
        && *expected != preview.fingerprint
    {
        return Err(IpamError::new(
            move_codes::PLAN_CHANGED,
            409,
            "the move would now do something else than the confirmed preview; preview it again",
        )
        .titled("The move changed")
        .param("fingerprint", &preview.fingerprint));
    }
    if !preview.unacknowledged.is_empty() {
        return Err(IpamError::new(
            codes::PLAN_UNACKNOWLEDGED,
            409,
            format!(
                "the move needs an acknowledgement of: {}",
                preview.unacknowledged.join(", ")
            ),
        )
        .titled("Warnings need an acknowledgement")
        .param("codes", preview.unacknowledged.join(",")));
    }
    let mut checked = std::collections::BTreeSet::new();
    for item in &preview.items {
        if item.l2.automatic()
            && let Some(connector) = &item.l2.connector
            && checked.insert(connector.id)
        {
            authorize(connector).map_err(IpamError::from_coded_error)?;
        }
    }
    let group = group_name(cx);
    let group_key = GroupKey::new(group.clone())?;
    let mut jobs = Vec::with_capacity(preview.items.len());
    for (index, (item, plans)) in preview.items.iter().zip(&steps).enumerate() {
        let spec = job_spec(&preview, item, plans, &group, &group_key, cx, index)?;
        let job_id = ipam.jobs().submit(spec, cx).await?;
        jobs.push(MoveJob {
            object: item.object,
            job_id,
        });
    }
    let submitted = MoveSubmitted {
        group,
        jobs,
        items: preview.items,
        timeout_secs: preview.timeout_secs,
        parallelism: preview.parallelism,
        warnings: preview.warnings,
        replayed: false,
    };
    if let Some(key) = key {
        let receipt = MoveReceipt {
            fingerprint,
            submitted: submitted.clone(),
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        batch.expect_typed(&MOVE_RECEIPTS, &key, None);
        batch.put_typed(&MOVE_RECEIPTS, &key, &receipt)?;
        match ipam.store().propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => {
                // A concurrent request with the same key finished first; its jobs are
                // the same ones (the engine deduplicates by the derived keys).
                if let Some(receipt) = ipam.move_receipt(&key).await? {
                    return replay(receipt, fingerprint);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(submitted)
}

/// The stored answer of a move submitted with an idempotency key (API-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MoveReceipt {
    /// SHA-256 over the canonical CBOR of the request.
    pub fingerprint: Digest,
    /// The first answer.
    pub submitted: MoveSubmitted,
}

impl IpamService {
    /// The preview of a move (the dry run, API-09), at least at `at_least` when given,
    /// without network controllers: every L2 step is left to a person. The routes use
    /// [`preview_move`].
    ///
    /// # Errors
    ///
    /// See [`super::preview()`].
    pub async fn move_preview(
        &self,
        request: &MoveRequest,
        cx: &RequestCtx,
        at_least: Option<Revision>,
    ) -> IpamResult<MovePreview> {
        preview_move(self, &Controllers::default(), request, cx, at_least).await
    }

    /// Submits a move without network controllers, like [`submit_move`]: every L2 step
    /// is left to a person.
    ///
    /// # Errors
    ///
    /// See [`submit_move`].
    pub async fn move_submit(
        &self,
        request: &MoveRequest,
        cx: &RequestCtx,
    ) -> IpamResult<MoveSubmitted> {
        submit_move(self, &Controllers::default(), request, cx, &|_| Ok(())).await
    }

    async fn move_receipt(&self, key: &(String, String)) -> IpamResult<Option<MoveReceipt>> {
        let view = self.store().read(ReadConsistency::Local).await?;
        Ok(view
            .get_typed(&MOVE_RECEIPTS, key)?
            .map(|(receipt, _)| receipt))
    }
}

fn replay(receipt: MoveReceipt, fingerprint: Digest) -> IpamResult<MoveSubmitted> {
    if receipt.fingerprint != fingerprint {
        return Err(IpamError::new(
            codes::IDEMPOTENCY_MISMATCH,
            422,
            "the idempotency key was used before for a different move",
        )
        .titled("Idempotency key reused"));
    }
    let mut submitted = receipt.submitted;
    submitted.replayed = true;
    Ok(submitted)
}

/// The group of a move: derived from the idempotency key when there is one, so a retried
/// request lands in the same group.
fn group_name(cx: &RequestCtx) -> String {
    let id = match &cx.idempotency {
        Some(key) => {
            let mut hasher = Sha256::new();
            hasher.update(cx.principal.subject().as_bytes());
            hasher.update([0]);
            hasher.update(key.as_str().as_bytes());
            let digest = hasher.finalize();
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            Uuid::from_bytes(bytes)
        }
        None => Uuid::now_v7(),
    };
    format!("{MOVE_JOB}.{}", id.simple())
}

/// The job of one item.
fn job_spec(
    preview: &MovePreview,
    item: &MoveItem,
    plans: &[StepPlan],
    group: &str,
    group_key: &GroupKey,
    cx: &RequestCtx,
    index: usize,
) -> IpamResult<JobSpec> {
    let base = MoveStepParams {
        group: group.to_owned(),
        requested: item.requested,
        address: item.object.id.into(),
        new_address: item.new_address,
        old_ip: item.old_ip,
        new_ip: item.new_ip,
        vrf: preview.target.vrf,
        prefix: preview.target.prefix,
        cidr: preview.target.cidr,
        vlan: preview.target.vlan,
        vid: preview.target.vid,
        host: item.host,
        interface: item.interface,
        dns_name: item.dns.as_ref().map(|dns| dns.name.clone()),
        task: None,
        l2: None,
        dns: None,
        dhcp: None,
    };
    let mut steps = Vec::with_capacity(plans.len());
    for plan in plans {
        let params = MoveStepParams {
            task: plan.task.clone(),
            l2: plan.l2.clone(),
            dns: plan.dns.clone(),
            dhcp: plan.dhcp.clone(),
            ..base.clone()
        };
        steps.push(StepSpec {
            kind: StepKind::new(plan.step_kind)?,
            params: HexBytes(to_cbor(&params)?.to_vec()),
            timeout: plan.timeout,
        });
    }
    let mut targets = vec![item.object, ObjectRef::from(item.new_address)];
    if let Some(host) = item.host {
        targets.push(host.into());
    }
    targets.push(preview.target.prefix.into());
    if item.l2.automatic()
        && let Some(connector) = item.l2.connector_id()
    {
        targets.push(connector.into());
    }
    let idempotency = match &cx.idempotency {
        Some(key) => {
            let mut hasher = Sha256::new();
            hasher.update(key.as_str().as_bytes());
            let digest = hasher.finalize();
            Some(IdempotencyKey::new(format!(
                "{MOVE_JOB}.{}.{index}",
                to_hex(&digest[..16])
            ))?)
        }
        None => None,
    };
    Ok(JobSpec {
        kind: JobKind::from_static(MOVE_JOB),
        title: MessageKey::from_static("ipam.move.title"),
        targets,
        steps,
        timeout: Duration::from_secs(JOB_TIMEOUT_SECS),
        group: Some(group_key.clone()),
        group_limit: Some(preview.parallelism),
        idempotency,
        node: None,
    })
}
