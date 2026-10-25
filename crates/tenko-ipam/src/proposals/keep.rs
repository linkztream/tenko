//! "Keep both": a person says an address conflict is intended.
//!
//! An address conflict (`ipam.reconcile.conflict_shared_address`, two devices on one
//! address, or `ipam.reconcile.conflict_address_taken`, an address used by a device other
//! than the intended one) can be intended: a fallback guest kept beside the guest that
//! replaced it, started now and then. Keeping it closes the proposal like a rejection and
//! records a per-address exception on the rejection row ([`KeptConflict`]): the subject
//! stays quiet while the same devices share the address, even when other sources start to
//! report them (a plain rejection reopens when the evidence changes at all). A conflict
//! with another device on the address opens again, and the exception is forgotten.

use tenko_core::{
    ObjectRef, ProposalId, RequestCtx, Revision,
    audit::{AuditAction, AuditDraft},
    ipam::Stamp,
};
use tenko_store::{ReadConsistency, ReadViewExt, WriteBatch};

use super::{
    decide::{Decision, check, clean_reason, close_key, load, pause, run_write},
    model::{
        IntentProposal, IntentProposalKind, IntentProposalState, KeptConflict, PROPOSALS,
        REJECTIONS, Rejection, actions, codes,
    },
};
use crate::{
    error::{IpamError, IpamResult},
    reconcile::rule,
    service::IpamService,
};

/// Whether a proposal is an address conflict that can be kept.
pub fn keepable(proposal: &IntentProposal) -> bool {
    proposal.kind == IntentProposalKind::Conflict
        && matches!(
            proposal.rule.as_str(),
            rule::CONFLICT_SHARED_ADDRESS | rule::CONFLICT_ADDRESS_TAKEN
        )
}

/// Keeps an open address conflict as intended, as `cx`, with an optional reason.
///
/// # Errors
///
/// `ipam.validation` (400) for a bad reason, `ipam.proposal.not_found` (404),
/// `ipam.proposal.revision_mismatch` (412), `ipam.proposal.not_open` (409),
/// `ipam.proposal.not_keepable` (409) for anything but an address conflict,
/// `ipam.contended`.
pub async fn keep(
    ipam: &IpamService,
    id: ProposalId,
    reason: Option<String>,
    cx: &RequestCtx,
    expected: Option<Revision>,
) -> IpamResult<Decision> {
    let reason = clean_reason(reason)?;
    let attempts = ipam.config().max_attempts.max(1);
    for attempt in 0..attempts {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = ipam.store().read(consistency).await?;
        let proposal = load(view.as_ref(), id)?;
        check(&proposal, expected)?;
        if !keepable(&proposal) {
            return Err(IpamError::new(
                codes::NOT_KEEPABLE,
                409,
                format!(
                    "proposal {id} is not an address conflict ({}); reject it instead",
                    proposal.rule
                ),
            )
            .titled("Only an address conflict can be kept")
            .param("id", id)
            .param("rule", proposal.rule.clone()));
        }
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let kept = KeptConflict::of(&proposal.evidence);
        let mut closed = proposal.clone();
        closed.state = IntentProposalState::Rejected;
        closed.decided = Some(stamp.clone());
        closed.reason.clone_from(&reason);
        closed.updated = cx.now;
        closed.revision = Revision::ZERO;
        let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
        batch.request = Some(cx.request);
        batch.put_typed(&PROPOSALS, &id, &closed)?;
        batch.expect_typed(&PROPOSALS, &id, Some(proposal.revision));
        close_key(view.as_ref(), &proposal, &mut batch)?;
        let remembered = view
            .get_typed(&REJECTIONS, &proposal.key)?
            .map(|(_, revision)| revision);
        batch.put_typed(
            &REJECTIONS,
            &proposal.key,
            &Rejection {
                fingerprint: proposal.fingerprint,
                proposal: id,
                stamp,
                reason: reason.clone(),
                kept: Some(kept.clone()),
            },
        )?;
        batch.expect_typed(&REJECTIONS, &proposal.key, remembered);
        let macs: Vec<String> = kept.macs.iter().map(ToString::to_string).collect();
        let mut draft = AuditDraft::success(
            AuditAction::from_static(actions::KEEP),
            vec![ObjectRef::from(id)],
        )
        .with_source_ip(cx.source_ip)
        .with_context("kind", proposal.kind.as_str())
        .with_context("key", proposal.key.clone())
        .with_context("macs", macs.join(", "));
        if let Some(reason) = &reason {
            draft = draft.with_context("reason", reason.clone());
        }
        batch.audit(draft);
        drop(view);
        match run_write(
            ipam,
            batch,
            vec!["1 address conflict kept".to_owned()],
            vec![ObjectRef::from(id)],
            cx,
        )
        .await
        {
            Ok((revision, job_id)) => {
                closed.revision = revision;
                return Ok(Decision {
                    proposal: closed,
                    dry_run: false,
                    revision: Some(revision),
                    job_id,
                    results: Vec::new(),
                    warnings: Vec::new(),
                    plan: None,
                });
            }
            Err(error) if error.is(crate::codes::PLAN_STALE) => pause(attempt).await,
            Err(error) => return Err(error),
        }
    }
    Err(IpamError::contended(attempts))
}
