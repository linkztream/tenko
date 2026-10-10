//! The payloads of the controller-to-controller services `Raft` and `Cluster` (WP3.1a).
//!
//! The protocol messages carry their payloads as CBOR in `bytes` fields, each with a
//! `wire` tag that names the encoding. A receiver checks the tag before it decodes and
//! refuses another one with `cluster.forward.wire` (409, `FAILED_PRECONDITION`), so a
//! rolling upgrade never mixes two encodings (R19). A new encoding is a new tag.
//!
//! | Tag | Payloads |
//! |---|---|
//! | [`RAFT_WIRE`] `openraft-0.9/cbor-1` | the request and response types of openraft 0.9 (append entries, vote, snapshot metadata and response) |
//! | [`BATCH_WIRE`] `tenko-batch/cbor-1` | a store [`WriteBatch`], its [`Committed`] receipt, a [`WireStoreError`] in the status details of a refusal |
//! | [`CLUSTER_WIRE`] `tenko-cluster/cbor-1` | a membership change forwarded to the leader ([`ChangeEnvelope`]) and its [`ChangeResult`] |
//!
//! Every decoder here reads input from the network: the fuzz target `raft_payloads`
//! (`fuzz/fuzz_targets/raft_payloads.rs`) runs them on arbitrary bytes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    NodeId, Principal, RequestCtx, RequestId, TableName, Timestamp,
    codec::{from_cbor, to_cbor},
};
use tenko_store::{
    Committed, FailedPrecondition, StoreError, WriteBatch,
    raft::{
        openraft::raft::{
            AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest,
            VoteResponse,
        },
        types::{RaftNodeId, SnapshotMeta, TypeConfig, Vote},
    },
};
use tonic::{Status, metadata::MetadataValue};

use crate::{
    admin::{ClusterView, PromoteRequest, StepDown},
    error::ClusterError,
    server::{ERROR_CODE_METADATA, status_of},
};

/// The encoding of openraft payloads.
pub const RAFT_WIRE: &str = "openraft-0.9/cbor-1";
/// The encoding of forwarded store batches, receipts and store errors.
pub const BATCH_WIRE: &str = "tenko-batch/cbor-1";
/// The encoding of forwarded membership changes.
pub const CLUSTER_WIRE: &str = "tenko-cluster/cbor-1";
/// Metadata entry with the node id of the leader, on a `cluster.forward.not_leader`
/// refusal.
pub const LEADER_METADATA: &str = "tenko-leader";
/// The code of a refusal by a member that does not lead (nothing was queued).
pub const NOT_LEADER: &str = "cluster.forward.not_leader";
/// The code of a payload in another encoding.
pub const WIRE_MISMATCH: &str = "cluster.forward.wire";

/// openraft's append-entries request of the store.
pub type AppendRequest = AppendEntriesRequest<TypeConfig>;
/// openraft's append-entries response.
pub type AppendResponse = AppendEntriesResponse<RaftNodeId>;
/// openraft's vote request.
pub type VoteRequestOf = VoteRequest<RaftNodeId>;
/// openraft's vote response.
pub type VoteResponseOf = VoteResponse<RaftNodeId>;
/// openraft's answer to an installed snapshot.
pub type SnapshotResponseOf = SnapshotResponse<RaftNodeId>;
/// openraft's vote.
pub type VoteOf = Vote;
/// openraft's snapshot metadata.
pub type SnapshotMetaOf = SnapshotMeta;

/// Encodes a payload as CBOR.
///
/// # Errors
///
/// `cluster.wire.encode` (500).
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ClusterError> {
    to_cbor(value).map(|bytes| bytes.to_vec()).map_err(|error| {
        ClusterError::new(
            "cluster.wire.encode",
            500,
            format!("a payload does not encode: {error}"),
        )
    })
}

/// Decodes a CBOR payload; `what` names it in the error.
///
/// # Errors
///
/// `cluster.wire.payload` (400).
pub fn decode<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> Result<T, ClusterError> {
    from_cbor(bytes).map_err(|error| {
        ClusterError::new(
            "cluster.wire.payload",
            400,
            format!("the {what} payload does not decode: {error}"),
        )
        .with_param("payload", what.to_owned())
    })
}

/// Checks the `wire` tag of a payload.
///
/// # Errors
///
/// `cluster.forward.wire` (409) naming both encodings.
pub fn check(found: &str, expected: &str) -> Result<(), ClusterError> {
    if found == expected {
        Ok(())
    } else {
        Err(ClusterError::new(
            WIRE_MISMATCH,
            409,
            format!(
                "the peer sent a payload in the encoding `{found}`; this controller speaks \
                 `{expected}`: upgrade the older controller"
            ),
        )
        .with_param("found", found.to_owned())
        .with_param("expected", expected.to_owned()))
    }
}

/// A store error in transit: the follower that forwarded a batch returns exactly what the
/// leader's store returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireStoreError {
    /// [`StoreError::PreconditionFailed`].
    PreconditionFailed(Vec<FailedPrecondition>),
    /// [`StoreError::IdempotencyMismatch`].
    IdempotencyMismatch,
    /// [`StoreError::BatchTooLarge`].
    BatchTooLarge {
        /// The payload size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// [`StoreError::NoQuorum`].
    NoQuorum,
    /// [`StoreError::Timeout`].
    Timeout,
    /// [`StoreError::ShuttingDown`].
    ShuttingDown,
    /// [`StoreError::Compacted`].
    Compacted {
        /// The oldest revision kept.
        oldest: tenko_core::Revision,
    },
    /// [`StoreError::ReservedTable`].
    ReservedTable {
        /// The table.
        table: TableName,
    },
    /// [`StoreError::PlaintextSecret`].
    PlaintextSecret {
        /// The table.
        table: TableName,
    },
    /// [`StoreError::Storage`].
    Storage(String),
    /// [`StoreError::Codec`].
    Codec(String),
}

impl From<&StoreError> for WireStoreError {
    fn from(error: &StoreError) -> Self {
        match error {
            StoreError::PreconditionFailed(failures) => Self::PreconditionFailed(failures.clone()),
            StoreError::IdempotencyMismatch => Self::IdempotencyMismatch,
            StoreError::BatchTooLarge { size, limit } => Self::BatchTooLarge {
                size: *size,
                limit: *limit,
            },
            StoreError::NoQuorum => Self::NoQuorum,
            StoreError::Timeout => Self::Timeout,
            StoreError::ShuttingDown => Self::ShuttingDown,
            StoreError::Compacted { oldest } => Self::Compacted { oldest: *oldest },
            StoreError::ReservedTable { table } => Self::ReservedTable {
                table: table.clone(),
            },
            StoreError::PlaintextSecret { table } => Self::PlaintextSecret {
                table: table.clone(),
            },
            StoreError::Storage(detail) => Self::Storage(detail.clone()),
            StoreError::Codec(detail) => Self::Codec(detail.clone()),
        }
    }
}

impl From<WireStoreError> for StoreError {
    fn from(error: WireStoreError) -> Self {
        match error {
            WireStoreError::PreconditionFailed(failures) => Self::PreconditionFailed(failures),
            WireStoreError::IdempotencyMismatch => Self::IdempotencyMismatch,
            WireStoreError::BatchTooLarge { size, limit } => Self::BatchTooLarge { size, limit },
            WireStoreError::NoQuorum => Self::NoQuorum,
            WireStoreError::Timeout => Self::Timeout,
            WireStoreError::ShuttingDown => Self::ShuttingDown,
            WireStoreError::Compacted { oldest } => Self::Compacted { oldest },
            WireStoreError::ReservedTable { table } => Self::ReservedTable { table },
            WireStoreError::PlaintextSecret { table } => Self::PlaintextSecret { table },
            WireStoreError::Storage(detail) => Self::Storage(detail),
            WireStoreError::Codec(detail) => Self::Codec(detail),
        }
    }
}

/// The status of a refusal by the store: the store's code and status, and the error in
/// the details.
pub fn store_status(error: &StoreError) -> Status {
    let status = status_of(&ClusterError::coded(error));
    let details = encode(&WireStoreError::from(error)).unwrap_or_default();
    let mut with_details =
        Status::with_details(status.code(), status.message().to_owned(), details.into());
    *with_details.metadata_mut() = status.metadata().clone();
    with_details
}

/// The store error a refusal carries, if it is one.
pub fn store_error_of(status: &Status) -> Option<StoreError> {
    let code = status
        .metadata()
        .get(ERROR_CODE_METADATA)
        .and_then(|value| value.to_str().ok())?;
    if !code.starts_with("sys.store.") || status.details().is_empty() {
        return None;
    }
    decode::<WireStoreError>("store error", status.details())
        .ok()
        .map(StoreError::from)
}

/// The refusal of a member that does not lead; names the leader when it knows one.
pub fn not_leader_status(leader: Option<NodeId>) -> Status {
    let mut status = status_of(&ClusterError::new(
        NOT_LEADER,
        503,
        "this controller does not lead; nothing was queued",
    ));
    if let Some(leader) = leader
        && let Ok(value) = MetadataValue::try_from(leader.0.to_string())
    {
        status.metadata_mut().insert(LEADER_METADATA, value);
    }
    status
}

/// The leader a `cluster.forward.not_leader` refusal names.
pub fn leader_of(status: &Status) -> Option<NodeId> {
    status
        .metadata()
        .get(LEADER_METADATA)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse().ok())
        .map(NodeId)
}

/// The context of a request forwarded to the leader, for its audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCtx {
    /// Who asked.
    pub principal: Principal,
    /// The request id.
    pub request: RequestId,
    /// When.
    pub now: Timestamp,
    /// The client address.
    pub source_ip: Option<IpAddr>,
}

impl From<&RequestCtx> for WireCtx {
    fn from(cx: &RequestCtx) -> Self {
        Self {
            principal: cx.principal.clone(),
            request: cx.request,
            now: cx.now,
            source_ip: cx.source_ip,
        }
    }
}

impl From<WireCtx> for RequestCtx {
    fn from(wire: WireCtx) -> Self {
        let mut cx = RequestCtx::new(wire.principal);
        cx.request = wire.request;
        cx.now = wire.now;
        cx.source_ip = wire.source_ip;
        cx
    }
}

/// A membership change an administrator asked a follower for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberChange {
    /// Promote a learner (`POST /cluster/members/{id}/promote`).
    Promote {
        /// The learner.
        node: NodeId,
        /// The options.
        request: PromoteRequest,
    },
    /// Remove a member (`DELETE /cluster/members/{id}`).
    Remove {
        /// The member.
        node: NodeId,
    },
    /// Hand leadership over (`POST /cluster/step-down`).
    StepDown,
}

/// What `Cluster.Change` carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEnvelope {
    /// The request context.
    pub ctx: WireCtx,
    /// The change.
    pub change: MemberChange,
}

/// What `Cluster.Change` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeResult {
    /// The members after a promotion or removal.
    View(ClusterView),
    /// The outcome of a step-down.
    StepDown(StepDown),
}

/// Decodes a forwarded batch.
///
/// # Errors
///
/// `cluster.wire.payload`.
pub fn decode_batch(bytes: &[u8]) -> Result<WriteBatch, ClusterError> {
    decode("write batch", bytes)
}

/// Decodes a commit receipt.
///
/// # Errors
///
/// `cluster.wire.payload`.
pub fn decode_committed(bytes: &[u8]) -> Result<Committed, ClusterError> {
    decode("commit receipt", bytes)
}

/// Runs every decoder of this module, and the protocol decoding of every controller
/// message, on `data`: the first byte picks the payload, the rest is the input. The entry
/// point of the fuzz target `raft_payloads`; it never panics on any input.
pub fn fuzz_payload(data: &[u8]) {
    use prost::Message as _;

    use crate::proto::v1;

    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    match kind % 20 {
        0 => drop(decode::<AppendRequest>("append", input)),
        1 => drop(decode::<AppendResponse>("append response", input)),
        2 => drop(decode::<VoteRequestOf>("vote", input)),
        3 => drop(decode::<VoteResponseOf>("vote response", input)),
        4 => drop(decode::<VoteOf>("snapshot vote", input)),
        5 => drop(decode::<SnapshotMetaOf>("snapshot metadata", input)),
        6 => drop(decode::<SnapshotResponseOf>("snapshot response", input)),
        7 => {
            if let Ok(batch) = decode_batch(input) {
                // A forwarded batch is validated and fingerprinted by the leader.
                let _ = batch.validate(16 * 1024 * 1024);
                let _ = batch.fingerprint();
            }
        }
        8 => drop(decode_committed(input)),
        9 => drop(decode::<WireStoreError>("store error", input).map(StoreError::from)),
        10 => drop(
            decode::<ChangeEnvelope>("change", input)
                .map(|envelope| RequestCtx::from(envelope.ctx)),
        ),
        11 => drop(decode::<ChangeResult>("change result", input)),
        12 => drop(v1::RaftRequest::decode(input)),
        13 => drop(v1::SnapshotChunk::decode(input)),
        14 => drop(v1::JoinRequest::decode(input)),
        15 => drop(v1::ProposeRequest::decode(input)),
        16 => drop(v1::TransferKekRequest::decode(input)),
        17 => drop(v1::ChangeRequest::decode(input)),
        18 => drop(v1::ReadIndexResponse::decode(input)),
        _ => {
            let status = Status::with_details(
                tonic::Code::FailedPrecondition,
                "refused",
                prost::bytes::Bytes::copy_from_slice(input),
            );
            let mut status = status;
            status.metadata_mut().insert(
                ERROR_CODE_METADATA,
                MetadataValue::from_static("sys.store.precondition_failed"),
            );
            let _ = store_error_of(&status);
            let _ = leader_of(&status);
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;
    use tenko_core::{CounterKey, Revision, SystemComponent};
    use tenko_store::raft::openraft::{CommittedLeaderId, LogId};

    use super::*;

    #[test]
    fn openraft_payloads_round_trip() {
        let vote = Vote::new(3, 1);
        let request = VoteRequestOf::new(vote, Some(LogId::new(CommittedLeaderId::new(2, 1), 7)));
        let decoded: VoteRequestOf =
            decode("vote", &encode(&request).expect("encode")).expect("decode");
        assert_eq!(decoded, request);
        let append = AppendRequest {
            vote,
            prev_log_id: None,
            entries: Vec::new(),
            leader_commit: None,
        };
        let decoded: AppendRequest =
            decode("append", &encode(&append).expect("encode")).expect("decode");
        assert_eq!(decoded.vote, vote);
        assert!(decode::<AppendRequest>("append", b"\xff\x00garbage").is_err());
    }

    #[test]
    fn the_fuzz_entry_point_survives_garbage() {
        for kind in 0_u8..40 {
            for input in [
                Vec::new(),
                vec![0],
                vec![0xff; 4],
                vec![0xa1, 0x61, 0x61, 0x9f, 0x9f, 0x9f],
            ] {
                let mut data = vec![kind];
                data.extend_from_slice(&input);
                fuzz_payload(&data);
            }
        }
        fuzz_payload(&[]);
    }

    #[test]
    fn wire_tags_are_checked() {
        assert!(check(RAFT_WIRE, RAFT_WIRE).is_ok());
        let error = check("openraft-0.10/cbor-1", RAFT_WIRE).expect_err("another encoding");
        assert_eq!(error.code(), WIRE_MISMATCH);
        assert_eq!(error.status(), 409);
    }

    #[test]
    fn store_errors_survive_the_trip() {
        let errors = [
            StoreError::PreconditionFailed(vec![FailedPrecondition::Counter {
                counter: CounterKey::new("sys.leader_epoch"),
                expected: 3,
                actual: 4,
            }]),
            StoreError::IdempotencyMismatch,
            StoreError::Compacted {
                oldest: Revision(9),
            },
            StoreError::Storage("disk".to_owned()),
        ];
        for error in errors {
            let status = store_status(&error);
            assert_eq!(store_error_of(&status), Some(error.clone()), "{error}");
        }
        // A status without details or with another code carries no store error.
        assert_eq!(store_error_of(&not_leader_status(Some(NodeId(1001)))), None);
        assert_eq!(
            leader_of(&not_leader_status(Some(NodeId(1001)))),
            Some(NodeId(1001))
        );
        assert_eq!(leader_of(&not_leader_status(None)), None);
    }

    #[test]
    fn batches_and_changes_round_trip() {
        let mut batch = WriteBatch::new(
            Principal::system(SystemComponent::Cluster),
            Timestamp::now(),
        );
        batch.put(
            TableName::from_static("cluster.members"),
            Bytes::from_static(b"k"),
            Bytes::from_static(b"v"),
        );
        let decoded = decode_batch(&encode(&batch).expect("encode")).expect("decode");
        assert_eq!(decoded, batch);
        let envelope = ChangeEnvelope {
            ctx: WireCtx::from(&RequestCtx::system(SystemComponent::Cluster)),
            change: MemberChange::Promote {
                node: NodeId(1001),
                request: PromoteRequest {
                    force: true,
                    replace: Some(NodeId(1002)),
                },
            },
        };
        let decoded: ChangeEnvelope =
            decode("change", &encode(&envelope).expect("encode")).expect("decode");
        assert_eq!(decoded, envelope);
    }

    /// One valid payload of every kind `fuzz_payload` reads, each behind its selector
    /// byte: the openraft messages.
    fn raft_seeds() -> Vec<(&'static str, u8, Vec<u8>)> {
        use std::collections::{BTreeMap, BTreeSet};

        use tenko_store::raft::{
            openraft::{BasicNode, EntryPayload, Membership},
            types::{Entry, Proposal, ProposedBatch, StoredMembership},
        };

        let log_id = |index| LogId::new(CommittedLeaderId::new(2, 1), index);
        let vote = Vote::new_committed(2, 1);
        let membership = Membership::new(
            vec![BTreeSet::from([1, 1001, 1002])],
            BTreeMap::from([
                (1, BasicNode::new("192.0.2.1:8444")),
                (1001, BasicNode::new("192.0.2.2:8444")),
                (1002, BasicNode::new("192.0.2.3:8444")),
            ]),
        );
        let proposal = Proposal {
            journal_retention: 10_000,
            journal_max_bytes: 0,
            batches: vec![ProposedBatch {
                batch: Bytes::from(cbor(&seed_batch())),
                fingerprint: None,
            }],
        };
        let heartbeat = AppendRequest {
            vote,
            prev_log_id: Some(log_id(9)),
            entries: Vec::new(),
            leader_commit: Some(log_id(9)),
        };
        let append = AppendRequest {
            vote,
            prev_log_id: Some(log_id(3)),
            entries: vec![
                Entry {
                    log_id: log_id(4),
                    payload: EntryPayload::Blank,
                },
                Entry {
                    log_id: log_id(5),
                    payload: EntryPayload::Membership(membership.clone()),
                },
                Entry {
                    log_id: log_id(6),
                    payload: EntryPayload::Normal(proposal),
                },
            ],
            leader_commit: Some(log_id(5)),
        };
        let meta = SnapshotMetaOf {
            last_log_id: Some(log_id(9)),
            last_membership: StoredMembership::new(Some(log_id(5)), membership),
            snapshot_id: "2-1-9-1".to_owned(),
        };
        vec![
            ("append-heartbeat", 0, cbor(&heartbeat)),
            ("append-entries", 0, cbor(&append)),
            ("append-success", 1, cbor(&AppendResponse::Success)),
            (
                "append-partial",
                1,
                cbor(&AppendResponse::PartialSuccess(Some(log_id(5)))),
            ),
            ("append-conflict", 1, cbor(&AppendResponse::Conflict)),
            (
                "append-higher-vote",
                1,
                cbor(&AppendResponse::HigherVote(vote)),
            ),
            ("vote", 2, cbor(&VoteRequestOf::new(vote, Some(log_id(9))))),
            (
                "vote-response",
                3,
                cbor(&VoteResponseOf {
                    vote,
                    vote_granted: true,
                    last_log_id: Some(log_id(9)),
                }),
            ),
            ("snapshot-vote", 4, cbor(&vote)),
            ("snapshot-meta", 5, cbor(&meta)),
            ("snapshot-response", 6, cbor(&SnapshotResponseOf { vote })),
        ]
    }

    /// The CBOR payloads of `Cluster` and of a refusal, behind their selector bytes.
    fn cluster_seeds() -> Vec<(&'static str, u8, Vec<u8>)> {
        let batch = cbor(&seed_batch());
        let refusal = WireStoreError::from(&StoreError::PreconditionFailed(vec![
            FailedPrecondition::Counter {
                counter: CounterKey::new("sys.leader_epoch"),
                expected: 3,
                actual: 4,
            },
        ]));
        let envelope = |change| ChangeEnvelope {
            ctx: WireCtx::from(&RequestCtx::system(SystemComponent::Cluster)),
            change,
        };
        let promote = envelope(MemberChange::Promote {
            node: NodeId(1002),
            request: PromoteRequest {
                force: false,
                replace: Some(NodeId(1001)),
            },
        });
        let committed = Committed {
            revision: Revision(42),
            audit: Vec::new(),
            replayed: false,
        };
        vec![
            ("batch", 7, batch),
            ("committed", 8, cbor(&committed)),
            ("store-error", 9, cbor(&refusal)),
            ("change-promote", 10, cbor(&promote)),
            (
                "change-remove",
                10,
                cbor(&envelope(MemberChange::Remove { node: NodeId(1002) })),
            ),
            (
                "change-step-down",
                10,
                cbor(&envelope(MemberChange::StepDown)),
            ),
            (
                "change-result",
                11,
                cbor(&ChangeResult::StepDown(StepDown {
                    previous: NodeId(1),
                    leader: NodeId(1001),
                    term: 3,
                })),
            ),
            ("status-details", 19, cbor(&refusal)),
        ]
    }

    /// The protocol messages of `Raft` and `Cluster`, behind their selector bytes.
    fn protocol_seeds() -> Vec<(&'static str, u8, Vec<u8>)> {
        use prost::Message as _;

        use crate::proto::v1;

        let change = ChangeEnvelope {
            ctx: WireCtx::from(&RequestCtx::system(SystemComponent::Cluster)),
            change: MemberChange::Promote {
                node: NodeId(1002),
                request: PromoteRequest {
                    force: true,
                    replace: None,
                },
            },
        };
        vec![
            (
                "raft-request",
                12,
                v1::RaftRequest {
                    wire: RAFT_WIRE.to_owned(),
                    payload: cbor(&VoteRequestOf::new(Vote::new(3, 1002), None)),
                }
                .encode_to_vec(),
            ),
            (
                "snapshot-chunk",
                13,
                v1::SnapshotChunk {
                    wire: RAFT_WIRE.to_owned(),
                    vote: cbor(&Vote::new_committed(2, 1)),
                    sha256: vec![0x5a; 32],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                "join",
                14,
                v1::JoinRequest {
                    node_id: 1002,
                    address: "controller-3.example.test:8444".to_owned(),
                    version: "0.0.1".to_owned(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                "propose",
                15,
                v1::ProposeRequest {
                    wire: BATCH_WIRE.to_owned(),
                    batch: cbor(&seed_batch()),
                }
                .encode_to_vec(),
            ),
            (
                "transfer-kek",
                16,
                v1::TransferKekRequest {
                    ephemeral_public_key: vec![9; 32],
                    join_token_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                }
                .encode_to_vec(),
            ),
            (
                "change-request",
                17,
                v1::ChangeRequest {
                    wire: CLUSTER_WIRE.to_owned(),
                    change: cbor(&change),
                }
                .encode_to_vec(),
            ),
            (
                "read-index",
                18,
                v1::ReadIndexResponse {
                    log_index: Some(9),
                    term: 2,
                    leader_id: 1,
                }
                .encode_to_vec(),
            ),
        ]
    }

    /// A payload as CBOR.
    fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
        encode(value).expect("encode")
    }

    /// A small batch of the shape a forwarded write has.
    fn seed_batch() -> WriteBatch {
        let mut batch = WriteBatch::new(
            Principal::system(SystemComponent::Cluster),
            "2026-01-01T00:00:00Z".parse().expect("time"),
        );
        batch.put(
            TableName::from_static("cluster.members"),
            Bytes::from_static(b"1002"),
            Bytes::from_static(b"member"),
        );
        batch
    }

    /// Whether `input` decodes as the payload `kind` selects, nested payloads included.
    fn decodes(kind: u8, input: &[u8]) -> bool {
        use prost::Message as _;

        use crate::proto::v1;

        match kind {
            0 => decode::<AppendRequest>("append", input).is_ok(),
            1 => decode::<AppendResponse>("append response", input).is_ok(),
            2 => decode::<VoteRequestOf>("vote", input).is_ok(),
            3 => decode::<VoteResponseOf>("vote response", input).is_ok(),
            4 => decode::<VoteOf>("snapshot vote", input).is_ok(),
            5 => decode::<SnapshotMetaOf>("snapshot metadata", input).is_ok(),
            6 => decode::<SnapshotResponseOf>("snapshot response", input).is_ok(),
            7 => decode_batch(input).is_ok_and(|batch| batch.validate(1 << 24).is_ok()),
            8 => decode_committed(input).is_ok(),
            9 | 19 => decode::<WireStoreError>("store error", input).is_ok(),
            10 => decode::<ChangeEnvelope>("change", input).is_ok(),
            11 => decode::<ChangeResult>("change result", input).is_ok(),
            12 => v1::RaftRequest::decode(input)
                .is_ok_and(|request| decode::<VoteRequestOf>("vote", &request.payload).is_ok()),
            13 => v1::SnapshotChunk::decode(input)
                .is_ok_and(|chunk| decode::<VoteOf>("vote", &chunk.vote).is_ok()),
            14 => v1::JoinRequest::decode(input).is_ok(),
            15 => v1::ProposeRequest::decode(input)
                .is_ok_and(|request| decode_batch(&request.batch).is_ok()),
            16 => v1::TransferKekRequest::decode(input).is_ok(),
            17 => v1::ChangeRequest::decode(input)
                .is_ok_and(|request| decode::<ChangeEnvelope>("change", &request.change).is_ok()),
            18 => v1::ReadIndexResponse::decode(input).is_ok(),
            _ => false,
        }
    }

    /// The seeds of the fuzz target `raft_payloads` decode; with `TENKO_FUZZ_SEEDS` set to
    /// a directory they are written there (`fuzz/seeds/raft_payloads/`), one file each.
    #[test]
    fn fuzz_seeds_decode() {
        let seeds: Vec<_> = raft_seeds()
            .into_iter()
            .chain(cluster_seeds())
            .chain(protocol_seeds())
            .collect();
        let kinds: std::collections::BTreeSet<u8> = seeds.iter().map(|seed| seed.1).collect();
        assert_eq!(kinds.len(), 20, "every selector has a seed");
        let out = std::env::var_os("TENKO_FUZZ_SEEDS").map(std::path::PathBuf::from);
        for (name, kind, payload) in seeds {
            assert!(decodes(kind, &payload), "the seed {name} does not decode");
            let mut data = vec![kind];
            data.extend_from_slice(&payload);
            fuzz_payload(&data);
            if let Some(dir) = &out {
                std::fs::create_dir_all(dir).expect("seed directory");
                std::fs::write(dir.join(name), &data).expect("seed");
            }
        }
    }
}
