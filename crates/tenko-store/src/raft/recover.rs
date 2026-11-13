//! The store side of a forced step on a stopped controller (the cluster recovery plan,
//! sections 3.2 and 3.4): what a closed store holds, and its whole log applied into a
//! snapshot that a new one-voter store installs.
//!
//! [`inspect`] reads a closed store: its last, committed and applied log ids, its vote, its
//! revision and audit head and its membership, plus a read view for the caller's own tables.
//! It writes no data (opening the databases may let redb finish a transaction a crash
//! interrupted, as any open does).
//!
//! [`replay`] copies a closed store into a work directory and applies every entry of the
//! copy's log after its applied position, the entries not yet known as committed (the
//! uncommitted tail) included, as an election of that controller would apply them (Raft's
//! new leader commits its whole log, so these entries may have been acknowledged). It then builds a snapshot at the last log id.
//! The original directory is only read; every write goes to the copy.

use std::{collections::BTreeSet, path::Path, sync::Arc};

use openraft::{RaftLogReader as _, storage::RaftLogStorage as _};
use tenko_core::{NodeId, Revision, audit::ChainHead};

use super::{
    NODE_ID_FILE,
    log::LogStore,
    sm::{SmOptions, StateMachine},
    types::{Entry, LogId, SnapshotMeta},
};
use crate::{
    api::{ReadView, StoreError},
    format,
};

/// redb cache of the offline databases: enough for a sequential replay.
const CACHE_BYTES: usize = 64 * 1024 * 1024;

/// What a closed store holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFacts {
    /// The node id the directory belongs to, when it recorded one.
    pub node: Option<NodeId>,
    /// The last entry of its log, applied or not.
    pub last_log: Option<LogId>,
    /// The last entry it knows as committed.
    pub committed: Option<LogId>,
    /// The last entry its state machine applied.
    pub applied: Option<LogId>,
    /// The highest term it has voted in or seen.
    pub vote_term: u64,
    /// The store revision of its state.
    pub revision: Revision,
    /// The head of its audit chain.
    pub audit_head: ChainHead,
    /// The voters of the membership it applied.
    pub voters: BTreeSet<NodeId>,
    /// The learners of that membership.
    pub learners: BTreeSet<NodeId>,
    /// Bytes of the closed store (log, state, snapshots): what a forced step needs again
    /// beside it.
    pub bytes: u64,
}

impl CopyFacts {
    /// Entries this copy holds without knowing that they were committed.
    pub fn unknown_commit(&self) -> u64 {
        index(self.last_log).saturating_sub(index(self.committed))
    }

    /// Entries this copy holds but has not applied.
    pub fn unapplied(&self) -> u64 {
        index(self.last_log).saturating_sub(index(self.applied))
    }

    /// The highest term this copy has seen: its vote, or the term of its last entry.
    pub fn highest_term(&self) -> u64 {
        self.vote_term
            .max(self.last_log.map_or(0, |log_id| log_id.leader_id.term))
    }
}

fn index(log_id: Option<LogId>) -> u64 {
    log_id.map_or(0, |log_id| log_id.index)
}

fn storage(what: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Storage(format!("{what}: {error}"))
}

/// An opened closed store: its facts and a read view of its state. Dropping it closes the
/// databases.
pub struct OfflineCopy {
    /// What it holds.
    pub facts: CopyFacts,
    view: Arc<dyn ReadView>,
    log: LogStore,
    sm: StateMachine,
}

impl std::fmt::Debug for OfflineCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineCopy")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl OfflineCopy {
    /// A read view of the state.
    pub fn view(&self) -> Arc<dyn ReadView> {
        Arc::clone(&self.view)
    }

    async fn open(dir: &Path) -> Result<Self, StoreError> {
        format::ensure_closed(dir).map_err(|error| storage("the store", error))?;
        let log = LogStore::open(&dir.join("log.redb"), CACHE_BYTES)?;
        let options = SmOptions {
            cache_bytes: CACHE_BYTES,
            durable_apply: false,
            verify_full_chain: false,
        };
        let sm_dir = dir.to_path_buf();
        let sm = tokio::task::spawn_blocking(move || StateMachine::open(&sm_dir, options))
            .await
            .map_err(|error| storage("the state machine", error))??;
        let mut reader = log.clone();
        let state = reader
            .get_log_state()
            .await
            .map_err(|error| storage("the log", error))?;
        let committed = reader
            .read_committed()
            .await
            .map_err(|error| storage("the log", error))?;
        let vote_term = reader
            .read_vote()
            .await
            .map_err(|error| storage("the log", error))?
            .map_or(0, |vote| vote.leader_id().term);
        let meta = sm.meta();
        let membership = meta.membership.membership();
        let node = std::fs::read_to_string(dir.join(NODE_ID_FILE))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .map(NodeId);
        let facts = CopyFacts {
            node,
            last_log: state.last_log_id.or(meta.last_applied),
            committed,
            applied: meta.last_applied,
            vote_term,
            revision: meta.revision,
            audit_head: meta.audit_head,
            voters: membership.voter_ids().map(NodeId).collect(),
            learners: membership.learner_ids().map(NodeId).collect(),
            bytes: format::closed_store_bytes(dir).unwrap_or(0),
        };
        let view: Arc<dyn ReadView> = Arc::new(sm.view()?);
        Ok(Self {
            facts,
            view,
            log,
            sm,
        })
    }
}

impl Drop for OfflineCopy {
    /// Closes both databases and waits until their worker threads released the files, so
    /// the directory can be opened, moved or removed at once.
    fn drop(&mut self) {
        self.log.shutdown();
        self.sm.wake_all();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while (self.log.handles() > 1 || self.sm.handles() > 1)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Reads the closed store in `dir`.
///
/// # Errors
///
/// [`StoreError::Storage`] when the store is open in a process, missing or unreadable.
pub async fn inspect(dir: &Path) -> Result<OfflineCopy, StoreError> {
    OfflineCopy::open(dir).await
}

/// A copy with its whole log applied.
#[derive(Debug)]
pub struct Replayed {
    /// The copy after the replay: `applied` and `last_log` are equal, `revision` and
    /// `audit_head` are the fork point's.
    pub copy: OfflineCopy,
    /// The facts of the original before the replay.
    pub before: CopyFacts,
    /// The snapshot of the replayed state: a file in the work directory.
    pub snapshot: std::path::PathBuf,
    /// Its metadata (the last log id, the membership of the copy).
    pub meta: SnapshotMeta,
    /// The entries after the copy's committed position (the uncommitted tail), applied.
    pub tail: Vec<Entry>,
}

/// Copies the closed store `kept` into the empty directory `work`, applies the copy's whole
/// log there and builds a snapshot of the result. `kept` is only read.
///
/// # Errors
///
/// [`StoreError::Storage`] when either directory cannot be used, or the error of an entry
/// that does not apply.
pub async fn replay(kept: &Path, work: &Path) -> Result<Replayed, StoreError> {
    let (from, to) = (kept.to_path_buf(), work.to_path_buf());
    tokio::task::spawn_blocking(move || format::copy_closed_store(&from, &to))
        .await
        .map_err(|error| storage("copying the store", error))?
        .map_err(|error| storage("copying the store", error))?;
    let mut copy = OfflineCopy::open(work).await?;
    let before = copy.facts.clone();
    let mut reader = copy.log.clone();
    let start = index(before.applied) + u64::from(before.applied.is_some());
    let entries = match before.last_log {
        Some(last) if last.index >= start => reader
            .try_get_log_entries(start..=last.index)
            .await
            .map_err(|error| storage("reading the log", error))?,
        _ => Vec::new(),
    };
    let committed = index(before.committed);
    let tail: Vec<Entry> = entries
        .iter()
        .filter(|entry| before.committed.is_none() || entry.log_id.index > committed)
        .cloned()
        .collect();
    let sm = copy.sm.clone();
    let built = tokio::task::spawn_blocking(move || {
        if !entries.is_empty() {
            sm.apply_entries(entries)?;
        }
        sm.build_snapshot()
    })
    .await
    .map_err(|error| storage("applying the log", error))??;
    let meta = copy.sm.meta();
    copy.facts.applied = meta.last_applied;
    copy.facts.revision = meta.revision;
    copy.facts.audit_head = meta.audit_head;
    copy.view = Arc::new(copy.sm.view()?);
    Ok(Replayed {
        copy,
        before,
        snapshot: built.snapshot.path.clone(),
        meta: built.meta,
        tail,
    })
}
