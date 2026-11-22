//! Writing the reconciler's candidates into `ipam.proposals`: open what is new, refresh
//! what is unchanged, replace what changed, delete what no longer holds, and leave closed
//! what a person rejected with the same evidence.
//!
//! The writes come out as [`Item`]s, one per subject key, each complete in itself (the
//! proposal row, the open-key row and a forgotten rejection), in key order. The reconciler
//! writes them in batches under the store's limit, each batch with one audit record that
//! counts what it wrote; because no item depends on another, any prefix of them leaves the
//! tables consistent and the next run completes the rest.
//!
//! A proposal the reconciler closes itself (it expired, or a newer one supersedes it) is
//! deleted rather than kept closed: it carries no person's decision, the facts keep what it
//! was about visible, and sources that report what a client chooses would otherwise fill
//! the disk with closed rows. While the clock guard holds expiry, `bound` keeps the open
//! discovered hosts within what bounds them. Each removal of an open proposal that
//! nothing replaces is an item that only deletes.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use tenko_core::{
    PrefixId, Principal, ProposalId, Revision, SystemComponent, Timestamp, audit::Digest,
    codec::canonical_sha256,
};
use tenko_store::{Mutation, Precondition, WriteBatch};

use super::model::{
    IntentProposal, IntentProposalKind, IntentProposalState, KeptConflict, OPEN_KEYS, PROPOSALS,
    REJECTIONS,
};
use crate::{
    error::IpamResult, net::host_capacity, observe::model::observed_macs,
    reconcile::rules::Candidate, reconcile::snapshot::Snapshot,
};

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
    /// Proposals deleted as they expired or were superseded (counted there too).
    pub deleted: u32,
    /// Open discovered hosts deleted to keep their network within its addresses.
    pub bounded: u32,
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
        self.deleted += other.deleted;
        self.bounded += other.bounded;
        self.sightings += other.sightings;
    }

    /// The proposal rows written: opened, refreshed, superseded, expired and removed at the
    /// bound.
    pub(crate) fn proposals(&self) -> u32 {
        self.opened + self.refreshed + self.superseded + self.expired + self.bounded
    }
}

/// One independent write of a run: the rows of one subject key (a proposal opened,
/// refreshed, superseded, expired or removed, with its open-key row and a forgotten
/// rejection) or one last sighting, with what it counts as and its payload size
/// ([`WriteBatch::payload_size`] of the item alone).
pub(crate) struct Item {
    /// The subject key of a proposal item; `None` for a sighting.
    pub key: Option<String>,
    /// What the item counts as.
    pub counts: SyncCounts,
    /// The item's payload size.
    pub size: usize,
    mutations: Vec<Mutation>,
    preconditions: Vec<Precondition>,
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
        }
    }

    /// Whether the item only deletes rows: a store that refuses growth still takes it.
    pub(crate) fn deletes_only(&self) -> bool {
        self.mutations
            .iter()
            .all(|mutation| matches!(mutation, Mutation::Delete { .. }))
    }

    /// Copies the item's writes into `batch`.
    pub(crate) fn add_to(&self, batch: &mut WriteBatch) {
        batch.mutations.extend(self.mutations.iter().cloned());
        batch
            .preconditions
            .extend(self.preconditions.iter().cloned());
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

/// The item that deletes the open proposal of `key` and its open-key row: deletes only.
fn removal(
    now: Timestamp,
    key: &str,
    (current, key_revision): &(IntentProposal, Revision),
    counts: SyncCounts,
) -> Item {
    let key = key.to_owned();
    let mut batch = scratch(now);
    batch.delete_typed(&PROPOSALS, &current.id);
    batch.expect_typed(&PROPOSALS, &current.id, Some(current.revision));
    batch.delete_typed(&OPEN_KEYS, &key);
    batch.expect_typed(&OPEN_KEYS, &key, Some(*key_revision));
    Item::new(Some(key), counts, batch)
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
        choices: candidate.choices.clone(),
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
            && (rejection.fingerprint == fingerprint
                || rejection
                    .kept
                    .as_ref()
                    .is_some_and(|kept| *kept == KeptConflict::of(&candidate.evidence)))
        {
            // Neither open nor opened: it takes no room under the bound.
            keys.remove(candidate.key.as_str());
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
                refreshed.choices.clone_from(&candidate.choices);
                refreshed.severity = candidate.severity;
                refreshed.updated = now;
                refreshed.revision = Revision::ZERO;
                batch.put_typed(&PROPOSALS, &current.id, &refreshed)?;
                batch.expect_typed(&PROPOSALS, &current.id, Some(current.revision));
                counts.refreshed += 1;
            }
            Some((current, key_revision)) => {
                let fresh = new_proposal(candidate, fingerprint, now);
                batch.delete_typed(&PROPOSALS, &current.id);
                batch.expect_typed(&PROPOSALS, &current.id, Some(current.revision));
                batch.put_typed(&PROPOSALS, &fresh.id, &fresh)?;
                batch.expect_typed(&PROPOSALS, &fresh.id, None);
                batch.put_typed(&OPEN_KEYS, &fresh.key, &fresh.id)?;
                batch.expect_typed(&OPEN_KEYS, &fresh.key, Some(*key_revision));
                counts.superseded += 1;
                counts.deleted += 1;
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
                counts.opened += 1;
            }
        }
        plan.items
            .push(Item::new(Some(candidate.key.clone()), counts, batch));
    }
    // The candidates follow the age of the facts, so nothing expires while the clock guard
    // holds destruction; the bound is a count and holds all the same.
    if let Err(held) = tenko_core::clock::trusted_now() {
        tracing::debug!(?held, "no proposal expires until the clock is trusted");
        bound(snapshot, candidates, &keys, &mut plan);
    } else {
        expire(snapshot, &keys, &mut plan);
    }
    plan.items.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(plan)
}

/// Adds an item deleting each open proposal whose key no candidate has: it expired.
fn expire(snapshot: &Snapshot, keys: &BTreeSet<&str>, plan: &mut SyncPlan) {
    for (key, open) in &snapshot.open {
        if !keys.contains(key.as_str()) {
            let counts = SyncCounts {
                expired: 1,
                deleted: 1,
                ..SyncCounts::default()
            };
            plan.items.push(removal(snapshot.now, key, open, counts));
        }
    }
}

/// Adds an item deleting each open discovered host that its network's addresses leave no
/// room for: those no candidate stands for, oldest sighting first, until the network's
/// candidate and open discovered hosts fit its assignable addresses. The rules raise at most
/// one discovered host per uncontested address, so the candidates alone always fit, and a
/// device that is present never makes room for one that is gone. Those outside every IPv4
/// network (an IPv6 network, a device seen with no address) that no candidate stands for
/// are held to the number of distinct MAC addresses the facts within the retention name,
/// so those whose facts were overwritten leave.
fn bound(
    snapshot: &Snapshot,
    candidates: &[Candidate],
    keys: &BTreeSet<&str>,
    plan: &mut SyncPlan,
) {
    type Stale<'a> = Vec<(Option<Timestamp>, &'a str, &'a (IntentProposal, Revision))>;
    let discovered = |kind: IntentProposalKind| kind == IntentProposalKind::DiscoveredHost;
    let ipv4 = |prefix: Option<PrefixId>| {
        let network = |id: &PrefixId| snapshot.intent.prefixes.get(id);
        prefix.filter(|id| network(id).is_some_and(|p| p.cidr.addr().is_ipv4()))
    };
    let mut networks: BTreeMap<Option<PrefixId>, (u128, Stale<'_>)> = BTreeMap::new();
    for candidate in candidates {
        if discovered(candidate.kind)
            && keys.contains(candidate.key.as_str())
            && let Some(prefix) = ipv4(candidate.subject.prefix)
        {
            networks.entry(Some(prefix)).or_default().0 += 1;
        }
    }
    for (key, open) in &snapshot.open {
        if discovered(open.0.kind) && !keys.contains(key.as_str()) {
            let entry = (open.0.last_seen(), key.as_str(), open);
            networks
                .entry(ipv4(open.0.subject.prefix))
                .or_default()
                .1
                .push(entry);
        }
    }
    let named_macs = || {
        let facts = snapshot.facts.iter();
        let macs: BTreeSet<_> = facts
            .flat_map(|fact| observed_macs(&fact.observed))
            .collect();
        u128::try_from(macs.len()).unwrap_or(u128::MAX)
    };
    for (prefix, (current, mut stale)) in networks {
        let capacity = prefix
            .and_then(|id| snapshot.intent.prefixes.get(&id))
            .map_or_else(named_macs, |network| host_capacity(&network.cidr));
        let total = current + u128::try_from(stale.len()).unwrap_or(u128::MAX);
        let excess = total.saturating_sub(capacity);
        stale.sort_by_key(|&(seen, key, _)| (seen, key));
        for (_, key, open) in stale
            .into_iter()
            .take(usize::try_from(excess).unwrap_or(usize::MAX))
        {
            let counts = SyncCounts {
                bounded: 1,
                ..SyncCounts::default()
            };
            plan.items.push(removal(snapshot.now, key, open, counts));
        }
    }
}
