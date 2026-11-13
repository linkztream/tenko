//! The generation of this controller's history at run time (the cluster recovery plan,
//! sections 3.6 and 3.7).
//!
//! - **Every `Raft` and `Cluster` call and answer** carries this controller's claim
//!   ([`GENERATION_METADATA`]); a call without one claims generation 0, which is what a
//!   binary without generations sends. [`Peers::admit`] runs before a call reaches openraft
//!   or the service: a lineage the caller offers is checked first ([`Peers::offer`]), then a
//!   caller marked superseded in this store is refused whatever it claims (the store
//!   decides, not the message), then a claim that differs from this history's is refused
//!   with `cluster.superseded` and this history's lineage ([`RECORD_METADATA`]), so the
//!   caller learns why and can pass the proof on. A store that holds nothing yet (a learner
//!   that is joining) accepts any claim: it has no history to protect, and its snapshot
//!   brings the generation. A `Join` from a controller of an older claim is let through: a
//!   joining controller starts empty.
//! - **A lineage offered by any path** is decided by [`Lineage::admit`] against this
//!   controller's own lineage and the standing its store gives the signers
//!   ([`Standing::read`]): a descendant fences this controller ([`FenceReason::Superseded`]);
//!   a sibling, or a newer history it cannot place, stops its writes until an operator
//!   chooses ([`FenceReason::Conflict`], CR-Q3); a refused offer changes nothing.
//! - **The fence** is written to `<data_dir>/node/` first, then the store stops
//!   ([`tenko_store::raft::RaftStore::fence`]), so a crash between the two leaves the fence
//!   to the next start ([`Peers::load_generation`]).
//! - **The authority pushes its lineage** to every controller its store marks superseded
//!   and has not revoked, every [`PUSH_INTERVAL`], from its leader; the status names the
//!   ones not reached yet (`cluster.recover.superseded_unreached`).

use std::{
    collections::{BTreeSet, HashSet},
    sync::{
        Mutex, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustls::pki_types::CertificateDer;
use tenko_core::{NodeId, Timestamp};
use tenko_store::{FenceReason, KeyRange, ReadConsistency, ReadViewExt as _, Store as _};
use tokio::sync::watch;
use tonic::{
    Status,
    metadata::{MetadataMap, MetadataValue},
};

use super::{Inner, Peers, network::GenerationHook};
use crate::{
    admin::{GenerationView, MemberRole, MemberView, OtherHistory},
    error::ClusterError,
    generation::{
        Claim, FenceFile, GENERATION_METADATA, GenerationRecord, Lineage, MAX_LINEAGE,
        RECORD_METADATA, Relation, SUPERSEDED, Signed, Standing, codes, decode_lineage,
        encode_lineage, suggested_winner,
    },
    model::tables,
    mtls::PeerInfo,
    proto::v1,
    server::status_of,
};

/// How often the authority's leader offers its lineage to the superseded controllers.
pub const PUSH_INTERVAL: Duration = Duration::from_secs(10);

/// How long one offer may take.
const PUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// The generation state of this controller.
#[derive(Default)]
pub(super) struct Generations {
    state: Mutex<GenerationState>,
    /// The installation's CA root, against which offered records are checked.
    ca_root: OnceLock<CertificateDer<'static>>,
    /// Peers that answered with an older or competing history: the next call to each of
    /// them carries this history's lineage.
    behind: Mutex<HashSet<NodeId>>,
    /// Superseded controllers the last push did not reach.
    unreached: Mutex<BTreeSet<NodeId>>,
    /// Superseded controllers that answered with this history's newest record: they hold
    /// it, and the push leaves them alone until the next start.
    informed: Mutex<HashSet<NodeId>>,
    /// One offer at a time: two offers that raced could leave the fence file and the
    /// in-memory state with a weaker reason than the store keeps.
    offering: tokio::sync::Mutex<()>,
    /// The lineage is kept unsent: the first start after a forced step has not taken
    /// office (section 3.5), so an old majority that is alive is not fenced by a step the
    /// operator may still undo.
    holding: AtomicBool,
}

/// This controller's history and its fence.
#[derive(Debug, Clone, Default)]
pub struct GenerationState {
    /// The records of the history this store holds; empty at generation 0.
    pub lineage: Lineage,
    /// Why this controller stopped writing, and the records that stopped it.
    pub fence: Option<(FenceReason, Lineage)>,
}

impl GenerationState {
    /// The claim of this controller's history.
    pub fn claim(&self) -> Claim {
        self.lineage.claim()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The hook of the peer transport: stamps calls, reads refusals.
pub(super) struct Hook(pub(super) Weak<Inner>);

impl GenerationHook for Hook {
    fn stamp(&self, metadata: &mut MetadataMap, target: NodeId) {
        if let Some(inner) = self.0.upgrade() {
            Peers { inner }.stamp_metadata(metadata, target);
        }
    }

    fn observe(&self, status: &Status, from: NodeId) {
        if let Some(inner) = self.0.upgrade() {
            Peers { inner }.observe(status, from);
        }
    }

    fn answered(&self, from: NodeId) {
        if let Some(inner) = self.0.upgrade() {
            lock(&inner.generations.behind).remove(&from);
        }
    }
}

/// The lineage a status or a request carries in [`RECORD_METADATA`].
fn offered_lineage(metadata: &MetadataMap) -> Option<Result<Vec<GenerationRecord>, ClusterError>> {
    let value = metadata.get_bin(RECORD_METADATA)?;
    Some(
        value
            .to_bytes()
            .map_err(|_| {
                ClusterError::new(
                    codes::RECORD_INVALID,
                    400,
                    "the generation record entry is not base64",
                )
            })
            .and_then(|bytes| decode_lineage(&bytes)),
    )
}

/// The claim a request or an answer carries; generation 0 without the entry.
///
/// # Errors
///
/// `cluster.recover.record_invalid` (400) for an entry that does not read.
pub(crate) fn claim_of(metadata: &MetadataMap) -> Result<Claim, Status> {
    match metadata.get(GENERATION_METADATA) {
        None => Ok(Claim::ZERO),
        Some(value) => value.to_str().ok().and_then(Claim::parse).ok_or_else(|| {
            status_of(&ClusterError::new(
                codes::RECORD_INVALID,
                400,
                "the generation entry of the call does not read",
            ))
        }),
    }
}

impl Peers {
    fn generations(&self) -> &Generations {
        &self.inner.generations
    }

    /// This controller's history and fence.
    pub fn generation(&self) -> GenerationState {
        lock(&self.generations().state).clone()
    }

    /// The superseded controllers the last push did not reach.
    pub fn unreached(&self) -> BTreeSet<NodeId> {
        lock(&self.generations().unreached).clone()
    }

    /// Keeps this history's lineage unsent (`true`) while the first start after a forced
    /// step looks for a live old majority, and for good when it found one; a refusal then
    /// carries no record and the push does not run.
    pub fn hold_record(&self, hold: bool) {
        self.generations().holding.store(hold, Ordering::SeqCst);
    }

    fn holding(&self) -> bool {
        self.generations().holding.load(Ordering::SeqCst)
    }

    /// Hands over the installation's CA root, against which offered records are checked.
    pub fn attach_ca_root(&self, root: CertificateDer<'static>) {
        let _ = self.generations().ca_root.set(root);
    }

    fn ca_root(&self) -> Option<CertificateDer<'static>> {
        self.generations().ca_root.get().cloned().or_else(|| {
            self.inner
                .registry
                .get()
                .map(|registry| registry.ca().root_der().clone())
        })
    }

    /// Reads this history's lineage from the store and the fence this controller keeps
    /// under `<data_dir>/node/`, and fences the store when one is kept. The start step calls
    /// it before the peer transport runs, so a fenced controller never elects again.
    ///
    /// # Errors
    ///
    /// A store error, or `cluster.node.files` for a fence file that cannot be read.
    pub async fn load_generation(&self) -> Result<GenerationState, ClusterError> {
        let lineage = self.stored_lineage().await?;
        lock(&self.generations().state).lineage = lineage;
        let kept = match &self.inner.config.data_dir {
            Some(dir) => FenceFile::load(dir)?,
            None => None,
        };
        if let Some(kept) = kept {
            let records = Lineage::kept(&kept.records)?;
            self.apply_fence(kept.kind, records, false).await;
        }
        Ok(self.generation())
    }

    async fn stored_lineage(&self) -> Result<Lineage, ClusterError> {
        let view = self.store().read(ReadConsistency::Local).await?;
        Lineage::read(view.as_ref())
    }

    /// Reads the store's lineage again (a learner that installed the authority's snapshot).
    async fn refresh_lineage(&self) {
        match self.stored_lineage().await {
            Ok(lineage) => lock(&self.generations().state).lineage = lineage,
            Err(error) => tracing::warn!(code = %error.code(), "{}", error.detail()),
        }
    }

    // -----------------------------------------------------------------------------------
    // The calls this controller makes.

    fn stamp_metadata(&self, metadata: &mut MetadataMap, target: NodeId) {
        let state = self.generation();
        if let Some(value) = state
            .claim()
            .render()
            .and_then(|text| MetadataValue::try_from(text).ok())
        {
            metadata.insert(GENERATION_METADATA, value);
        }
        if !self.holding() && lock(&self.generations().behind).contains(&target) {
            attach(metadata, &offerable(&state));
        }
    }

    /// Reads a refusal of `from`: the lineage it carries is offered to this controller, and
    /// a peer that answered with an older or competing history gets this history's lineage
    /// on the next call.
    pub(crate) fn observe(&self, status: &Status, from: NodeId) {
        let Some(Ok(records)) = offered_lineage(status.metadata()) else {
            return;
        };
        let theirs = records
            .last()
            .and_then(|record| record.header().ok())
            .map(|header| header.number);
        let state = self.generation();
        let newest = records.last().map(GenerationRecord::hash);
        let ours = state.lineage.tip().map(Signed::hash);
        if newest == ours && ours.is_some() {
            // It holds this history's newest record: nothing to offer either way.
            lock(&self.generations().behind).remove(&from);
            lock(&self.generations().informed).insert(from);
            return;
        }
        let known = state
            .fence
            .as_ref()
            .is_some_and(|(_, fence)| fence.tip().map(Signed::hash) == newest)
            || state
                .lineage
                .records()
                .iter()
                .any(|own| Some(own.hash()) == newest);
        if theirs.is_some_and(|theirs| theirs <= state.lineage.number()) {
            lock(&self.generations().behind).insert(from);
        }
        if known {
            return;
        }
        let peers = self.clone();
        tokio::spawn(async move {
            if let Err(error) = peers.offer(&records, Some(from)).await {
                tracing::warn!(peer = %from, code = %error.code(), "{}", error.detail());
            }
        });
    }

    // -----------------------------------------------------------------------------------
    // The calls this controller answers.

    /// The generation check of a `Raft` or `Cluster` call, before the service runs.
    ///
    /// # Errors
    ///
    /// The refusal of the call, with a lineage attached when it helps the caller.
    pub(crate) async fn admit(
        &self,
        peer: &PeerInfo,
        join: bool,
        metadata: &MetadataMap,
    ) -> Result<(), Status> {
        let claim = claim_of(metadata)?;
        if let Some(offered) = offered_lineage(metadata) {
            let records = offered.map_err(|error| status_of(&error))?;
            if let Err(error) = self.offer(&records, Some(peer.identity.node)).await {
                tracing::warn!(peer = %peer.identity.node, code = %error.code(), "{}", error.detail());
            }
        }
        let mut state = self.generation();
        let held = self.holding();
        let own = |state: &GenerationState| {
            (!held && state.lineage.tip().is_some()).then(|| state.lineage.offer())
        };
        if let Some((reason, fence)) = &state.fence {
            // A member of this history learns the competing records; any other caller the
            // records that stopped this controller, or this history's own.
            let records = match reason {
                FenceReason::Conflict if claim == state.claim() => Some(records_of(fence)),
                FenceReason::Conflict | FenceReason::MajorityAlive => own(&state),
                FenceReason::Superseded | FenceReason::Unknown => Some(offerable(&state)),
            };
            return Err(refusal(
                reason.code(),
                format!(
                    "this controller stopped writing ({}); it takes no calls of its peers",
                    reason.code()
                ),
                records.as_deref(),
            ));
        }
        if state.lineage.tip().is_some() && self.superseded_here(peer.identity.node).await {
            return Err(refusal(
                codes::SUPERSEDED,
                format!(
                    "controller {} was superseded by generation {} of this cluster; it may only \
                     receive the record",
                    peer.identity.node,
                    state.claim().number
                ),
                own(&state).as_deref(),
            ));
        }
        if claim == state.claim() {
            return Ok(());
        }
        self.refresh_lineage().await;
        state = self.generation();
        if claim == state.claim()
            || (state.lineage.tip().is_none() && self.store().applied_index().is_none())
        {
            return Ok(());
        }
        if join && claim.number < state.claim().number {
            return Ok(());
        }
        Err(refusal(
            codes::SUPERSEDED,
            format!(
                "the caller speaks for generation {} of the cluster, this controller for \
                 generation {}",
                claim.number,
                state.claim().number
            ),
            own(&state).as_deref(),
        ))
    }

    async fn superseded_here(&self, node: NodeId) -> bool {
        let Ok(view) = self.store().read(ReadConsistency::Local).await else {
            return false;
        };
        view.get_typed(&SUPERSEDED, &node.0)
            .is_ok_and(|mark| mark.is_some())
    }

    /// A lineage offered by any path: admitted against this controller's own and the
    /// standing its store gives the signers, then acted on (section 3.6).
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` for an offer [`Lineage::admit`] refuses; a store
    /// error.
    pub async fn offer(
        &self,
        records: &[GenerationRecord],
        from: Option<NodeId>,
    ) -> Result<Relation, ClusterError> {
        let root = self.ca_root().ok_or_else(|| {
            ClusterError::new(
                codes::RECORD_INVALID,
                503,
                "this controller cannot check a generation record yet: it has no CA root",
            )
        })?;
        let _one_at_a_time = self.generations().offering.lock().await;
        self.refresh_lineage().await;
        let state = self.generation();
        let standing = {
            let view = self.store().read(ReadConsistency::Local).await?;
            Standing::read(
                view.as_ref(),
                self.store().membership().voters,
                Timestamp::now(),
            )?
        };
        let admission = state.lineage.admit(records, &root, &standing)?;
        let (Some(reason), Some(newest)) = (admission.relation.fence(), admission.new.last())
        else {
            return Ok(admission.relation);
        };
        // Already stopped: the same records again, or a reason no stricter than the one
        // that holds, change nothing.
        if let Some((current, fenced)) = &state.fence
            && (fenced.tip().map(Signed::hash) == Some(newest.hash())
                || (reason == FenceReason::Conflict && *current != FenceReason::MajorityAlive))
        {
            return Ok(admission.relation);
        }
        let suggested = state.lineage.tip().map_or(newest.forced(), |own| {
            if suggested_winner(own, newest).is_lt() {
                own.forced()
            } else {
                newest.forced()
            }
        });
        tracing::error!(
            relation = ?admission.relation,
            generation = newest.number(),
            forced = %newest.forced(),
            from = ?from,
            suggested = %suggested,
            "generation {} of the cluster, forced on controller {}, {}; this controller stops \
             writing",
            newest.number(),
            newest.forced(),
            match admission.relation {
                Relation::Descendant => "supersedes this controller's history",
                Relation::Sibling => {
                    "competes with this controller's history; an operator chooses, and the \
                     suggested winner is the history forced on the controller named as \
                     suggested"
                }
                _ => "cannot be placed beside this controller's history; an operator decides",
            }
        );
        let kept: Vec<GenerationRecord> = admission
            .new
            .iter()
            .map(|signed| signed.record().clone())
            .collect();
        self.apply_fence(reason, Lineage::kept(&kept)?, true).await;
        Ok(admission.relation)
    }

    /// The first start after a forced step found the old cluster alive: this controller
    /// does not take office, keeps its lineage unsent and refuses writes
    /// (`cluster.recover.majority_alive`) until an operator undoes or confirms the step. The
    /// fence is not kept on disk: the next start probes again.
    pub async fn refuse_office(&self) {
        self.hold_record(true);
        let lineage = self.generation().lineage;
        self.apply_fence(FenceReason::MajorityAlive, lineage, false)
            .await;
    }

    /// Fences this controller: the fence file first, then the store.
    async fn apply_fence(&self, reason: FenceReason, records: Lineage, persist: bool) {
        // A fence never weakens: a weaker reason after a stricter one changes nothing.
        if lock(&self.generations().state)
            .fence
            .as_ref()
            .is_some_and(|(current, _)| current.strictness() > reason.strictness())
        {
            return;
        }
        if persist && let Some(dir) = &self.inner.config.data_dir {
            let kept = FenceFile {
                kind: reason,
                records: records_of(&records),
                at: Timestamp::now(),
            };
            if let Err(error) = kept.save(dir) {
                tracing::error!(code = %error.code(), "the fence could not be kept on disk; this run stays fenced: {}", error.detail());
            }
        }
        lock(&self.generations().state).fence = Some((reason, records));
        self.store().fence(reason).await;
        // Enrolled nodes learn the record from their controller in a later package; until
        // then their sessions end when this controller stops answering them.
    }

    // -----------------------------------------------------------------------------------
    // The views.

    /// The members a forced step superseded, for the cluster view: no longer in the Raft
    /// group, refused by this history.
    pub(super) async fn superseded_views(
        &self,
        records: &std::collections::BTreeMap<NodeId, crate::model::MemberRecord>,
        names: &std::collections::HashMap<NodeId, String>,
    ) -> Result<Vec<MemberView>, ClusterError> {
        let membership = self.store().membership();
        let view = self.store().read(ReadConsistency::Local).await?;
        Ok(view
            .scan_typed(&SUPERSEDED, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(node, _, _)| NodeId(node))
            .filter(|node| !membership.voters.contains(node) && !membership.learners.contains(node))
            .map(|node| {
                let record = records.get(&node);
                MemberView {
                    node,
                    name: names.get(&node).cloned(),
                    address: record.map(|record| record.address.clone()),
                    role: MemberRole::Superseded,
                    leader: false,
                    matched: None,
                    lag_entries: None,
                    last_contact_ms: None,
                    version: record.map(|record| record.version.clone()),
                    data_format: record.map(|record| record.data_format),
                    joined_at: record.map(|record| record.joined_at),
                    protocol_majors: record
                        .map(|record| record.protocol_majors.clone())
                        .unwrap_or_default(),
                    raft_wire: record.and_then(|record| record.raft_wire.clone()),
                    formats: record
                        .map(|record| record.formats.clone())
                        .unwrap_or_default(),
                    revoked: self.is_revoked(node),
                }
            })
            .collect())
    }

    /// The generation part of the cluster view; `None` at generation 0 without a fence.
    pub(super) fn generation_view(&self) -> Option<Box<GenerationView>> {
        let state = self.generation();
        let own = state.lineage.tip();
        if own.is_none() && state.fence.is_none() {
            return None;
        }
        let stopped_by = state.fence.as_ref().and_then(|(reason, other)| {
            let other = other.tip()?;
            Some(OtherHistory {
                number: other.number(),
                record: other.hash().to_string(),
                forced: other.forced(),
                suggested: *reason == FenceReason::Conflict
                    && own.is_some_and(|own| suggested_winner(other, own).is_lt()),
            })
        });
        Some(Box::new(GenerationView {
            number: state.lineage.number(),
            record: own.map(|own| own.hash().to_string()),
            forced: own.map(Signed::forced),
            stopped_by,
            unreached: self.unreached().into_iter().collect(),
        }))
    }

    // -----------------------------------------------------------------------------------
    // The authority's push.

    /// Offers this history's record to every controller the store marks superseded and
    /// has not revoked, once every [`PUSH_INTERVAL`] on the leader, until `stop` turns true.
    pub(super) async fn push_loop(self, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(PUSH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                _ = tick.tick() => {}
            }
            let state = self.generation();
            if state.lineage.tip().is_none() || state.fence.is_some() || self.holding() {
                continue;
            }
            let offer = state.lineage.offer();
            if self.store().current_leader() != Some(self.local()) {
                continue;
            }
            let targets = match self.push_targets().await {
                Ok(targets) => targets,
                Err(error) => {
                    tracing::debug!(code = %error.code(), "{}", error.detail());
                    continue;
                }
            };
            let mut unreached = BTreeSet::new();
            for node in targets {
                if !self.push_one(node, &offer).await {
                    unreached.insert(node);
                }
            }
            let mut kept = lock(&self.generations().unreached);
            for node in unreached.difference(&kept) {
                tracing::warn!(
                    node = %node,
                    code = codes::SUPERSEDED_UNREACHED,
                    "superseded controller {node} has not received the generation record yet"
                );
            }
            *kept = unreached;
        }
    }

    async fn push_targets(&self) -> Result<Vec<NodeId>, ClusterError> {
        let view = self.store().read(ReadConsistency::Local).await?;
        let revoked: HashSet<NodeId> = view
            .scan_typed(&tables::REVOCATIONS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, revocation, _)| revocation.node)
            .collect();
        let informed = lock(&self.generations().informed).clone();
        Ok(view
            .scan_typed(&SUPERSEDED, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(node, _, _)| NodeId(node))
            .filter(|node| !revoked.contains(node) && !informed.contains(node))
            .collect())
    }

    /// Offers the lineage to `node`; whether it answered at all.
    async fn push_one(&self, node: NodeId, offer: &[GenerationRecord]) -> bool {
        let call = async {
            let mut client = self.network().cluster_client(node).await.ok()?;
            let mut request = tonic::Request::new(v1::MembersRequest {});
            request.set_timeout(PUSH_TIMEOUT);
            self.network().stamp(&mut request, node);
            attach(request.metadata_mut(), offer);
            Some(client.members(request).await)
        };
        match tokio::time::timeout(PUSH_TIMEOUT, call).await {
            Ok(Some(Ok(_))) => true,
            Ok(Some(Err(status))) => {
                let answered = crate::server::code_of(&status).is_some();
                if answered {
                    self.observe(&status, node);
                }
                answered
            }
            _ => false,
        }
    }
}

/// The records of a lineage, oldest first.
fn records_of(lineage: &Lineage) -> Vec<GenerationRecord> {
    lineage
        .records()
        .iter()
        .map(|signed| signed.record().clone())
        .collect()
}

/// What a caller that is behind should receive: this history's lineage, followed by the
/// records that superseded it when they did, the newest [`MAX_LINEAGE`].
fn offerable(state: &GenerationState) -> Vec<GenerationRecord> {
    let mut records = state.lineage.offer();
    if let Some((FenceReason::Superseded | FenceReason::Unknown, fence)) = &state.fence {
        records.extend(records_of(fence));
    }
    let skip = records.len().saturating_sub(MAX_LINEAGE);
    records.split_off(skip)
}

fn attach(metadata: &mut MetadataMap, records: &[GenerationRecord]) {
    if records.is_empty() {
        return;
    }
    if let Ok(bytes) = encode_lineage(records) {
        metadata.insert_bin(RECORD_METADATA, MetadataValue::from_bytes(&bytes));
    }
}

/// A refusal with `records` attached.
fn refusal(code: &'static str, detail: String, records: Option<&[GenerationRecord]>) -> Status {
    let mut status = status_of(&ClusterError::new(code, 409, detail));
    if let Some(records) = records {
        attach(status.metadata_mut(), records);
    }
    status
}
