//! Saved bytes of the store's stored formats (`tests/fixtures/golden/`): the write batch,
//! the Raft log entry with its log id and the vote (the CBOR that `raft::log` frames into
//! its records), the state machine's metadata, the snapshot header and whole snapshot files
//! of both formats, whose records hold every table the state machine writes (a data table,
//! the counters, the idempotency records, the journal, the audit chain and the format
//! record).
//!
//! Each format has a test that decodes the saved bytes and compares the value, and one that
//! encodes the value and compares the bytes, so a change of a stored type fails here
//! instead of in an installation. A deliberate change of a format adds files for the new
//! form and keeps the old ones: whatever a released binary wrote must still decode.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::PathBuf,
};

use bytes::Bytes;
use openraft::{BasicNode, CommittedLeaderId, Membership};
use tenko_core::{
    CounterKey, IdempotencyKey, NodeId, ObjectKind, ObjectRef, Principal, SystemComponent,
    Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::{from_cbor, to_cbor},
};

use super::*;
use crate::{
    WriteBatch,
    format::{StoredFormat, stage_stored},
    raft::{
        snapshot::FORMAT_PLAIN,
        types::{BatchOutcome, Proposal, ProposedBatch, Vote},
    },
};

const ROWS: TableName = TableName::from_static("ipam.golden_rows");
const COUNTER: CounterKey = CounterKey::new("ipam.golden_counter");

fn saved(name: &str) -> Vec<u8> {
    let path = golden_dir().join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden")
}

/// A batch with every part a batch has: preconditions of both kinds, an idempotency key,
/// a put, a delete, a counter bump, an audit draft naming objects, and the format record.
fn batch() -> WriteBatch {
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), at);
    batch.idempotency = Some(IdempotencyKey::new("golden-1").expect("key"));
    batch
        .expect_version(ROWS, Bytes::from_static(b"host-1"), None)
        .expect_counter(COUNTER, 0)
        .put(
            ROWS,
            Bytes::from_static(b"host-1"),
            Bytes::from_static(b"\xa1\x64name\x66host-1"),
        )
        .delete(ROWS, Bytes::from_static(b"host-0"))
        .bump(COUNTER)
        .audit(AuditDraft::success(
            AuditAction::from_static("ipam.golden.write"),
            vec![
                ObjectRef::node(NodeId(7)),
                ObjectRef::singleton(ObjectKind::Vlan),
            ],
        ));
    stage_stored(
        &mut batch,
        None,
        &StoredFormat {
            version: 6,
            written_by: "0.0.0-golden".to_owned(),
        },
    )
    .expect("format record");
    batch
}

fn log_id(index: u64) -> LogId {
    LogId::new(CommittedLeaderId::new(3, 1), index)
}

/// A membership entry: three voters and a learner, with their addresses.
fn membership_entry() -> Entry {
    let nodes: BTreeMap<u64, BasicNode> = (1..=4)
        .map(|node| (node, BasicNode::new(format!("192.0.2.{node}:7443"))))
        .collect();
    Entry {
        log_id: log_id(1),
        payload: EntryPayload::Membership(Membership::new(vec![BTreeSet::from([1, 2, 3])], nodes)),
    }
}

/// A normal entry carrying the batch with its fingerprint.
fn normal_entry() -> Entry {
    let batch = batch();
    Entry {
        log_id: log_id(2),
        payload: EntryPayload::Normal(Proposal {
            journal_retention: 1_000,
            journal_max_bytes: 1 << 20,
            batches: vec![ProposedBatch {
                fingerprint: Some(batch.fingerprint().expect("fingerprint")),
                batch: to_cbor(&batch).expect("batch"),
            }],
        }),
    }
}

/// The state machine after both entries, in a fresh directory (removed by the caller).
fn applied(name: &str) -> (PathBuf, StateMachine) {
    let dir = std::env::temp_dir().join(format!(
        "tenko-golden-{name}-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    let options = SmOptions {
        cache_bytes: 1 << 20,
        durable_apply: false,
        verify_full_chain: true,
    };
    let sm = StateMachine::open(&dir, options).expect("open");
    let responses = sm
        .apply_entries(vec![membership_entry(), normal_entry()])
        .expect("apply");
    assert!(
        matches!(responses[1].outcomes[..], [BatchOutcome::Committed(_)]),
        "{responses:?}"
    );
    (dir, sm)
}

fn header(state: &SmMeta, format: u32) -> SnapshotHeader {
    SnapshotHeader {
        format,
        meta: SnapshotMeta {
            last_log_id: state.last_applied,
            last_membership: state.membership.clone(),
            snapshot_id: "2-golden".to_owned(),
        },
        state: state.clone(),
    }
}

/// The saved CBOR forms with the values they hold.
fn cbor_forms(state: &SmMeta) -> Vec<(&'static str, Bytes)> {
    let vote = Vote::new_committed(4, 2);
    vec![
        ("write_batch.cbor", to_cbor(&batch()).expect("batch")),
        (
            "log_entry_membership.cbor",
            to_cbor(&membership_entry()).expect("entry"),
        ),
        (
            "log_entry_normal.cbor",
            to_cbor(&normal_entry()).expect("entry"),
        ),
        ("log_id.cbor", to_cbor(&log_id(2)).expect("log id")),
        ("vote.cbor", to_cbor(&vote).expect("vote")),
        ("sm_meta.cbor", state.encode().expect("meta")),
        (
            "snapshot_header.cbor",
            to_cbor(&header(state, FORMAT)).expect("header"),
        ),
    ]
}

#[test]
fn saved_cbor_forms_decode_to_their_values() {
    let (dir, sm) = applied("decode");
    let state = sm.meta();
    assert_eq!(
        from_cbor::<WriteBatch>(&saved("write_batch.cbor")).expect("batch"),
        batch()
    );
    assert_eq!(
        from_cbor::<Entry>(&saved("log_entry_membership.cbor")).expect("entry"),
        membership_entry()
    );
    assert_eq!(
        from_cbor::<Entry>(&saved("log_entry_normal.cbor")).expect("entry"),
        normal_entry()
    );
    assert_eq!(
        from_cbor::<LogId>(&saved("log_id.cbor")).expect("log id"),
        log_id(2)
    );
    assert_eq!(
        from_cbor::<Vote>(&saved("vote.cbor")).expect("vote"),
        Vote::new_committed(4, 2)
    );
    assert_eq!(SmMeta::decode(&saved("sm_meta.cbor")).expect("meta"), state);
    assert_eq!(
        from_cbor::<SnapshotHeader>(&saved("snapshot_header.cbor")).expect("header"),
        header(&state, FORMAT)
    );
    drop(sm);
    fs::remove_dir_all(&dir).expect("clean up");
}

#[test]
fn values_encode_to_the_saved_cbor_forms() {
    let (dir, sm) = applied("encode");
    for (name, encoded) in cbor_forms(&sm.meta()) {
        assert!(
            saved(name) == encoded[..],
            "{name} no longer encodes as saved"
        );
    }
    drop(sm);
    fs::remove_dir_all(&dir).expect("clean up");
}

/// The bytes after the header: the records, the end tag and the hash, inflated for a
/// compressed file, so the comparison does not depend on the DEFLATE encoder's choices.
fn records_of(file: &[u8], format: u32) -> Vec<u8> {
    let header_len = usize::try_from(u32::from_be_bytes(
        file[8..12].try_into().expect("length field"),
    ))
    .expect("length");
    let body = &file[12 + header_len..];
    if format == FORMAT_PLAIN {
        return body.to_vec();
    }
    let mut plain = Vec::new();
    flate2::read::DeflateDecoder::new(body)
        .read_to_end(&mut plain)
        .expect("inflate");
    plain
}

const SNAPSHOT_FILES: [(&str, u32); 2] = [
    ("snapshot_format1.tnks", FORMAT_PLAIN),
    ("snapshot_format2.tnks", FORMAT),
];

#[test]
fn saved_snapshots_install_to_the_state_they_were_taken_of() {
    let (dir, sm) = applied("install-source");
    let expected = sm.digest().expect("digest");
    for (name, format) in SNAPSHOT_FILES {
        let copy = dir.join(name);
        fs::write(&copy, saved(name)).expect("copy");
        let reader = SnapshotReader::open(&copy).expect("open");
        assert_eq!(reader.header(), &header(&sm.meta(), format), "{name}");
        drop(reader);

        let target_dir = dir.join(format!("target-{format}"));
        let target = StateMachine::open(
            &target_dir,
            SmOptions {
                cache_bytes: 1 << 20,
                durable_apply: false,
                verify_full_chain: true,
            },
        )
        .expect("open");
        target
            .install(&header(&sm.meta(), format).meta, &copy)
            .expect("install");
        assert_eq!(target.meta(), sm.meta(), "{name}");
        assert_eq!(target.digest().expect("digest"), expected, "{name}");
    }
    drop(sm);
    fs::remove_dir_all(&dir).expect("clean up");
}

#[test]
fn snapshots_encode_to_the_saved_files() {
    let (dir, sm) = applied("snapshot-encode");
    let view = sm.view().expect("view");
    for (name, format) in SNAPSHOT_FILES {
        let path = dir.join(name);
        write_snapshot(view.txn(), &header(view.meta(), format), &path).expect("write");
        let (written, saved) = (fs::read(&path).expect("read"), saved(name));
        let header_end = 12
            + usize::try_from(u32::from_be_bytes(
                saved[8..12].try_into().expect("length field"),
            ))
            .expect("length");
        assert!(
            written[..header_end] == saved[..header_end],
            "{name}: the header no longer encodes as saved"
        );
        assert!(
            records_of(&written, format) == records_of(&saved, format),
            "{name}: the records no longer encode as saved"
        );
    }
    drop(view);
    drop(sm);
    fs::remove_dir_all(&dir).expect("clean up");
}
