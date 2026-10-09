//! Writing the reconciler's candidates into `ipam.proposals`: open what is new, refresh
//! what is unchanged, supersede what changed, expire what no longer holds, and leave
//! closed what a person rejected with the same evidence.

use std::collections::BTreeSet;

use serde::Serialize;
use tenko_core::{
    ObjectRef, Principal, ProposalId, Revision, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft, Digest},
    codec::canonical_sha256,
    ipam::Stamp,
};
use tenko_store::WriteBatch;

use super::model::{
    IntentProposal, IntentProposalKind, IntentProposalState, OPEN_KEYS, PROPOSALS, REJECTIONS,
    actions,
};
use crate::{error::IpamResult, reconcile::rules::Candidate, reconcile::snapshot::Snapshot};

/// The reason recorded on a proposal whose observation no longer holds.
pub const EXPIRED_REASON: &str = "the observation behind it no longer holds";

/// What the fingerprint covers.
#[derive(Serialize)]
struct FingerprintInput<'a> {
    kind: IntentProposalKind,
    key: &'a str,
    evidence: Vec<(&'a str, &'a str, Option<String>, Option<String>)>,
    shape: &'a [String],
}

/// The fingerprint of a candidate: kind, key, evidence identities and the shape of its
/// suggestion; times and generated identifiers do not count.
pub(crate) fn fingerprint(candidate: &Candidate) -> IpamResult<Digest> {
    let mut evidence: Vec<(&str, &str, Option<String>, Option<String>)> = candidate
        .evidence
        .iter()
        .map(|evidence| {
            (
                evidence.source_key.as_str(),
                evidence.subject_key.as_str(),
                evidence.mac.map(|mac| mac.to_string()),
                evidence.ip.map(|ip| ip.to_string()),
            )
        })
        .collect();
    evidence.sort();
    evidence.dedup();
    let input = FingerprintInput {
        kind: candidate.kind,
        key: &candidate.key,
        evidence,
        shape: &candidate.shape,
    };
    Ok(Digest(canonical_sha256(&input)?))
}

/// Counts of one sync.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SyncCounts {
    pub opened: u32,
    pub refreshed: u32,
    pub superseded: u32,
    pub expired: u32,
    pub suppressed: u32,
    pub unchanged: u32,
}

/// How much later evidence must be before an unchanged open proposal is rewritten.
pub(crate) struct SyncConfig {
    pub refresh: std::time::Duration,
}

fn reconciler_stamp(now: Timestamp) -> Stamp {
    Stamp::new(now, Principal::system(SystemComponent::Reconciler))
}

fn audit(action: &'static str, proposal: &IntentProposal) -> AuditDraft {
    let mut objects = vec![ObjectRef::from(proposal.id)];
    objects.extend(proposal.subject.objects.iter().copied());
    AuditDraft::success(AuditAction::from_static(action), objects)
        .with_context("kind", proposal.kind.as_str())
        .with_context("rule", proposal.rule.clone())
        .with_context("key", proposal.key.clone())
}

fn new_proposal(candidate: &Candidate, fingerprint: Digest, now: Timestamp) -> IntentProposal {
    IntentProposal {
        id: ProposalId::generate(),
        kind: candidate.kind,
        rule: candidate.rule.to_owned(),
        key: candidate.key.clone(),
        subject: candidate.subject.clone(),
        severity: candidate.severity,
        state: IntentProposalState::Open,
        summary: candidate.summary.clone(),
        params: candidate.params.clone(),
        evidence: candidate.evidence.clone(),
        commands: candidate.commands.clone(),
        fingerprint,
        created: now,
        updated: now,
        decided: None,
        reason: None,
        adopted_by: None,
        results: Vec::new(),
        superseded_by: None,
        adoption_error: None,
        revision: Revision::ZERO,
    }
}

/// Adds the proposal writes of `candidates` to `batch` and counts them.
pub(crate) fn sync(
    snapshot: &Snapshot,
    candidates: &[Candidate],
    config: &SyncConfig,
    batch: &mut WriteBatch,
) -> IpamResult<SyncCounts> {
    let now = snapshot.now;
    let mut counts = SyncCounts::default();
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    for candidate in candidates {
        if !keys.insert(candidate.key.as_str()) {
            continue;
        }
        let fingerprint = fingerprint(candidate)?;
        let open = snapshot.open.get(&candidate.key);
        if open.is_none()
            && let Some((rejection, _)) = snapshot.rejections.get(&candidate.key)
            && rejection.fingerprint == fingerprint
        {
            counts.suppressed += 1;
            continue;
        }
        match open {
            Some((current, _)) if current.fingerprint == fingerprint => {
                let newer = candidate
                    .evidence
                    .iter()
                    .map(|evidence| evidence.last_seen)
                    .max()
                    .zip(current.last_seen())
                    .is_some_and(|(fresh, stored)| {
                        fresh.saturating_since(stored) >= config.refresh
                    });
                let more_sightings = candidate
                    .evidence
                    .iter()
                    .map(|evidence| evidence.sightings)
                    .max()
                    .unwrap_or_default()
                    > current.sightings();
                if !(newer || more_sightings) {
                    counts.unchanged += 1;
                    continue;
                }
                let mut refreshed = current.clone();
                refreshed.evidence.clone_from(&candidate.evidence);
                refreshed.summary.clone_from(&candidate.summary);
                refreshed.params.clone_from(&candidate.params);
                refreshed.severity = candidate.severity;
                refreshed.updated = now;
                refreshed.revision = Revision::ZERO;
                batch.put_typed(&PROPOSALS, &current.id, &refreshed)?;
                batch.expect_typed(&PROPOSALS, &current.id, Some(current.revision));
                counts.refreshed += 1;
            }
            Some((current, key_revision)) => {
                let fresh = new_proposal(candidate, fingerprint, now);
                let mut old = current.clone();
                old.state = IntentProposalState::Superseded;
                old.superseded_by = Some(fresh.id);
                old.decided = Some(reconciler_stamp(now));
                old.updated = now;
                old.revision = Revision::ZERO;
                batch.put_typed(&PROPOSALS, &old.id, &old)?;
                batch.expect_typed(&PROPOSALS, &old.id, Some(current.revision));
                batch.audit(
                    audit(actions::SUPERSEDE, &old).with_context("by", fresh.id.to_string()),
                );
                batch.put_typed(&PROPOSALS, &fresh.id, &fresh)?;
                batch.expect_typed(&PROPOSALS, &fresh.id, None);
                batch.put_typed(&OPEN_KEYS, &fresh.key, &fresh.id)?;
                batch.expect_typed(&OPEN_KEYS, &fresh.key, Some(*key_revision));
                batch.audit(audit(actions::OPEN, &fresh));
                counts.superseded += 1;
                counts.opened += 1;
            }
            None => {
                let fresh = new_proposal(candidate, fingerprint, now);
                batch.put_typed(&PROPOSALS, &fresh.id, &fresh)?;
                batch.expect_typed(&PROPOSALS, &fresh.id, None);
                batch.put_typed(&OPEN_KEYS, &fresh.key, &fresh.id)?;
                batch.expect_typed(&OPEN_KEYS, &fresh.key, None);
                if let Some((_, revision)) = snapshot.rejections.get(&fresh.key) {
                    // The evidence changed since the rejection: forget it.
                    batch.delete_typed(&REJECTIONS, &fresh.key);
                    batch.expect_typed(&REJECTIONS, &fresh.key, Some(*revision));
                }
                batch.audit(audit(actions::OPEN, &fresh));
                counts.opened += 1;
            }
        }
    }
    counts.expired = expire(snapshot, &keys, batch)?;
    Ok(counts)
}

/// Expires the open proposals whose key no candidate has; returns how many.
fn expire(snapshot: &Snapshot, keys: &BTreeSet<&str>, batch: &mut WriteBatch) -> IpamResult<u32> {
    let now = snapshot.now;
    let mut expired = 0;
    for (key, (current, key_revision)) in &snapshot.open {
        if keys.contains(key.as_str()) {
            continue;
        }
        let mut old = current.clone();
        old.state = IntentProposalState::Expired;
        old.decided = Some(reconciler_stamp(now));
        old.reason = Some(EXPIRED_REASON.to_owned());
        old.updated = now;
        old.revision = Revision::ZERO;
        batch.put_typed(&PROPOSALS, &old.id, &old)?;
        batch.expect_typed(&PROPOSALS, &old.id, Some(current.revision));
        batch.delete_typed(&OPEN_KEYS, key);
        batch.expect_typed(&OPEN_KEYS, key, Some(*key_revision));
        batch.audit(audit(actions::EXPIRE, &old));
        expired += 1;
    }
    Ok(expired)
}
