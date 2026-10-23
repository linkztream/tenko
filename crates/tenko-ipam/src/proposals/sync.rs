//! Writing the reconciler's candidates into `ipam.proposals`: open what is new, refresh
//! what is unchanged, supersede what changed, expire what no longer holds, and leave
//! closed what a person rejected with the same evidence.
//!
//! The writes come out as [`Item`]s, one per subject key, each complete in itself (the
//! proposal row, the open-key row, a forgotten rejection and the audit records), in key
//! order. The reconciler writes them in batches under the store's limit; because no item
//! depends on another, any prefix of them leaves the tables consistent and the next run
//! completes the rest.

use std::collections::BTreeSet;

use serde::Serialize;
use tenko_core::{
    ObjectRef, Principal, ProposalId, Revision, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft, Digest},
    codec::canonical_sha256,
    ipam::Stamp,
};
use tenko_store::{Mutation, Precondition, WriteBatch};

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

/// Counts of one sync, or of one item of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SyncCounts {
    pub opened: u32,
    pub refreshed: u32,
    pub superseded: u32,
    pub expired: u32,
    pub suppressed: u32,
    pub unchanged: u32,
    /// Last sightings of intent objects (the reconciler's own items).
    pub sightings: u32,
}

impl SyncCounts {
    /// Adds `other` to these counts.
    pub(crate) fn add(&mut self, other: SyncCounts) {
        self.opened += other.opened;
        self.refreshed += other.refreshed;
        self.superseded += other.superseded;
        self.expired += other.expired;
        self.suppressed += other.suppressed;
        self.unchanged += other.unchanged;
        self.sightings += other.sightings;
    }

    /// The proposal rows written: opened, refreshed, superseded and expired.
    pub(crate) fn proposals(&self) -> u32 {
        self.opened + self.refreshed + self.superseded + self.expired
    }
}

/// One independent write of a run: the rows of one subject key (a proposal opened,
/// refreshed, superseded or expired, with its open-key row, a forgotten rejection and the
/// audit records) or one last sighting, with what it counts as and its payload size
/// ([`WriteBatch::payload_size`] of the item alone, which counts the audit records a little
/// over what they take in a larger batch, so a sum of items never underestimates a batch).
pub(crate) struct Item {
    /// The subject key of a proposal item; `None` for a sighting.
    pub key: Option<String>,
    /// What the item counts as.
    pub counts: SyncCounts,
    /// The item's payload size.
    pub size: usize,
    mutations: Vec<Mutation>,
    preconditions: Vec<Precondition>,
    audit: Vec<AuditDraft>,
}

impl Item {
    /// An item from the writes collected in `batch`.
    pub(crate) fn new(key: Option<String>, counts: SyncCounts, batch: WriteBatch) -> Self {
        let size = batch.payload_size();
        Self {
            key,
            counts,
            size,
            mutations: batch.mutations,
            preconditions: batch.preconditions,
            audit: batch.audit,
        }
    }

    /// Copies the item's writes into `batch`.
    pub(crate) fn add_to(&self, batch: &mut WriteBatch) {
        batch.mutations.extend(self.mutations.iter().cloned());
        batch
            .preconditions
            .extend(self.preconditions.iter().cloned());
        batch.audit.extend(self.audit.iter().cloned());
    }
}

/// What a sync found: the writes as items in subject-key order, and what it leaves as it
/// is.
#[derive(Default)]
pub(crate) struct SyncPlan {
    /// The writes.
    pub items: Vec<Item>,
    /// Open proposals left as they were.
    pub unchanged: u32,
    /// Subjects not opened again because a person rejected the same evidence.
    pub suppressed: u32,
}

/// An empty batch for the writes of one item.
pub(crate) fn scratch(now: Timestamp) -> WriteBatch {
    WriteBatch::new(Principal::system(SystemComponent::Reconciler), now)
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

/// The proposal writes of `candidates` as items, in subject-key order, with the counts of
/// what stays as it is. `written` holds the subject keys an earlier pass of the same run
/// committed; a proposal of such a key that is now unchanged is not counted again.
pub(crate) fn sync(
    snapshot: &Snapshot,
    candidates: &[Candidate],
    config: &SyncConfig,
    written: &BTreeSet<String>,
) -> IpamResult<SyncPlan> {
    let now = snapshot.now;
    let mut plan = SyncPlan::default();
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
            plan.suppressed += 1;
            continue;
        }
        let mut batch = scratch(now);
        let mut counts = SyncCounts::default();
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
                    if !written.contains(&candidate.key) {
                        plan.unchanged += 1;
                    }
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
        plan.items
            .push(Item::new(Some(candidate.key.clone()), counts, batch));
    }
    expire(snapshot, &keys, &mut plan)?;
    plan.items.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(plan)
}

/// Adds an item expiring each open proposal whose key no candidate has.
fn expire(snapshot: &Snapshot, keys: &BTreeSet<&str>, plan: &mut SyncPlan) -> IpamResult<()> {
    let now = snapshot.now;
    for (key, (current, key_revision)) in &snapshot.open {
        if keys.contains(key.as_str()) {
            continue;
        }
        let mut batch = scratch(now);
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
        let counts = SyncCounts {
            expired: 1,
            ..SyncCounts::default()
        };
        plan.items.push(Item::new(Some(key.clone()), counts, batch));
    }
    Ok(())
}
