//! The openraft type configuration and the payload of Raft entries.
//!
//! A Raft entry carries a [`Proposal`]: the encoded write batches the coalescer packed into
//! it, in queue order. The state machine answers with an [`ApplyResponse`] holding one
//! [`BatchOutcome`] per batch, because batches that share an entry apply in order, each
//! against its own preconditions (ADR 0002 decision 4, ADR 0011 decision 3).

use std::{fmt, path::PathBuf};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenko_core::{TableName, audit::Digest};

use crate::api::{Committed, FailedPrecondition, StoreError};

/// The Raft node id (the value of [`tenko_core::NodeId`]).
pub type RaftNodeId = u64;

openraft::declare_raft_types!(
    /// The openraft type configuration of the store.
    pub TypeConfig:
        D = Proposal,
        R = ApplyResponse,
        NodeId = RaftNodeId,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = SnapshotFile,
        AsyncRuntime = openraft::TokioRuntime,
);

/// The Raft handle.
pub type Raft = openraft::Raft<TypeConfig>;
/// A Raft log entry.
pub type Entry = openraft::Entry<TypeConfig>;
/// A Raft log id.
pub type LogId = openraft::LogId<RaftNodeId>;
/// A Raft vote.
pub type Vote = openraft::Vote<RaftNodeId>;
/// The membership as of a log id.
pub type StoredMembership = openraft::StoredMembership<RaftNodeId, openraft::BasicNode>;
/// Snapshot metadata.
pub type SnapshotMeta = openraft::SnapshotMeta<RaftNodeId, openraft::BasicNode>;
/// A snapshot with its data.
pub type Snapshot = openraft::Snapshot<TypeConfig>;
/// openraft's storage error.
pub type StorageError = openraft::StorageError<RaftNodeId>;
/// openraft's storage I/O error.
pub type StorageIOError = openraft::StorageIOError<RaftNodeId>;

/// Snapshot data: a complete snapshot file on this node's disk (see `snapshot`).
#[derive(Debug)]
pub struct SnapshotFile {
    /// The file.
    pub path: PathBuf,
}

/// The application payload of one Raft entry: write batches in queue order.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Change sets the journal keeps (from the leader's configuration, so every replica
    /// trims its journal identically).
    pub journal_retention: u64,
    /// Bytes of change sets the journal keeps at most (`0`: no byte limit; entries written
    /// before the limit existed), also from the leader's configuration.
    #[serde(default)]
    pub journal_max_bytes: u64,
    /// The batches, applied in this order.
    pub batches: Vec<ProposedBatch>,
}

/// One write batch inside a [`Proposal`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedBatch {
    /// The batch as CBOR (`tenko_core::codec::to_cbor` of a `WriteBatch`).
    pub batch: Bytes,
    /// The idempotency fingerprint ([`crate::api::WriteBatch::fingerprint`]), computed once
    /// by the proposer when the batch carries an idempotency key, so every replica compares
    /// the same bytes.
    #[serde(default)]
    pub fingerprint: Option<Digest>,
}

impl Proposal {
    /// Encoded bytes of the batches.
    pub fn payload_bytes(&self) -> usize {
        self.batches.iter().map(|batch| batch.batch.len()).sum()
    }
}

impl fmt::Debug for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proposal({} batches, {} bytes)",
            self.batches.len(),
            self.payload_bytes()
        )
    }
}

impl fmt::Display for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::Debug for ProposedBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProposedBatch({} bytes)", self.batch.len())
    }
}

/// The state machine's answer to one entry: one outcome per batch, in order. Blank and
/// membership entries answer with no outcomes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyResponse {
    /// The outcomes.
    pub outcomes: Vec<BatchOutcome>,
}

/// The deterministic result of applying one batch. Storage failures are not outcomes: they
/// stop the state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchOutcome {
    /// The batch committed (or replayed an earlier commit).
    Committed(Committed),
    /// Preconditions failed; nothing applied.
    PreconditionFailed(Vec<FailedPrecondition>),
    /// The idempotency key was used for a different batch; nothing applied.
    IdempotencyMismatch,
    /// The batch writes a table the store maintains; nothing applied.
    ReservedTable(TableName),
    /// The batch or one of its audit records did not encode or decode; nothing applied.
    Codec(String),
}

impl BatchOutcome {
    /// The outcome as the result `Store::propose` returns.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] for every outcome except `Committed`.
    pub fn into_result(self) -> Result<Committed, StoreError> {
        match self {
            BatchOutcome::Committed(committed) => Ok(committed),
            BatchOutcome::PreconditionFailed(failures) => {
                Err(StoreError::PreconditionFailed(failures))
            }
            BatchOutcome::IdempotencyMismatch => Err(StoreError::IdempotencyMismatch),
            BatchOutcome::ReservedTable(table) => Err(StoreError::ReservedTable { table }),
            BatchOutcome::Codec(message) => Err(StoreError::Codec(message)),
        }
    }
}
