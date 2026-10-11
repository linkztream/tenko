//! `Config.Watch` over mutual TLS: live changes, catch-up from a stored revision, the
//! snapshot fallback and the bandwidth cap.

use std::time::{Duration, Instant};

use tenko_core::{NodeId, codec::key::encode_key};
use tenko_store::mem::MemStoreConfig;

use super::harness::{
    Controller, FIRST_NODE, Options, Row, Running, WAIT, config_files, state_file, wait_for,
};
use crate::{
    identity::{AgentState, Credentials},
    node_sync::{
        local::{Assembler, Received},
        payload::{CBOR, CBOR_DEFLATE},
        tables::PROBE_CONFIG,
    },
    proto::v1,
};

/// One message of a raw configuration stream, with what it cost on the wire.
struct Seen {
    received: Received,
    encoding: String,
    frames: usize,
    /// The sum of the frame payloads, which is what the bandwidth cap counts.
    bytes: usize,
    /// From the request to the last frame of the message.
    elapsed: Duration,
}

/// Opens `Config.Watch` from `from` on a new channel and reads its first message.
async fn first_message(controller: &Controller, credentials: &Credentials, from: u64) -> Seen {
    let channel = controller.channel(credentials).await;
    let mut client = v1::config_client::ConfigClient::new(channel);
    let started = Instant::now();
    let mut stream = client
        .watch(v1::WatchRequest {
            from_revision: from,
        })
        .await
        .expect("watch")
        .into_inner();
    let mut assembler = Assembler::default();
    let (mut frames, mut bytes, mut encoding) = (0, 0, String::new());
    loop {
        let frame = tokio::time::timeout(WAIT, stream.message())
            .await
            .expect("the stream answers")
            .expect("frame")
            .expect("the stream stays open");
        frames += 1;
        bytes += frame.payload.len();
        encoding.clone_from(&frame.encoding);
        if let Some(received) = assembler.push(frame).expect("assemble") {
            return Seen {
                received,
                encoding,
                frames,
                bytes,
                elapsed: started.elapsed(),
            };
        }
    }
}

fn key_of(node: NodeId) -> Vec<u8> {
    encode_key(&node.0).to_vec()
}

/// Whether the node holds exactly `row` for `node`, in memory and on disk.
fn holds(agent: &crate::client::Agent, dir: &std::path::Path, node: NodeId, row: &Row) -> bool {
    let key = key_of(node);
    let want = row.encode();
    let memory = agent.config().borrow().clone();
    memory.get(PROBE_CONFIG.as_str(), &key) == Some(want.as_slice())
        && config_files(dir)
            .load()
            .ok()
            .flatten()
            .is_some_and(|disk| disk == *memory)
}

#[tokio::test]
async fn a_connected_probe_applies_a_configuration_change_as_it_happens() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    controller.enrol(dir.path(), "probe-live").await;
    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the first sync", || {
        agent.status().state == AgentState::Connected && agent.config().borrow().synced()
    })
    .await;
    let before = agent.config().borrow().clone();
    assert!(before.rows.is_empty(), "nothing is configured yet");

    let first = Row::plain(1);
    let written = controller.put_config(FIRST_NODE, &first).await;
    wait_for("the change to arrive", || {
        holds(agent, dir.path(), FIRST_NODE, &first)
    })
    .await;
    let after = agent.config().borrow().clone();
    assert!(
        after.revision >= written.0,
        "{} < {written}",
        after.revision
    );
    assert!(after.revision > before.revision);
    assert_eq!(after.rows.len(), 1);
    assert_eq!(after.rows[0].table, PROBE_CONFIG.as_str());
    assert!(after.applied_at.is_some());
    assert!(state_file(dir.path()).is_file(), "the state file exists");
    assert_eq!(agent.status().config_revision, Some(after.revision));

    // A second change replaces the row, and a row of another node is not for this one.
    controller.put_config(NodeId(1002), &Row::plain(50)).await;
    let second = Row::plain(2);
    controller.put_config(FIRST_NODE, &second).await;
    wait_for("the second change", || {
        holds(agent, dir.path(), FIRST_NODE, &second)
    })
    .await;
    assert_eq!(agent.config().borrow().rows.len(), 1);
    running.stop().await;
}

#[tokio::test]
async fn a_node_that_was_away_catches_up_from_its_revision_with_a_delta() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-away").await;
    controller.put_config(FIRST_NODE, &Row::plain(1)).await;

    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the first row", || {
        holds(agent, dir.path(), FIRST_NODE, &Row::plain(1))
    })
    .await;
    let held = agent.config().borrow().revision;
    running.stop().await;

    // Two changes while the node is away, and traffic that is not its own.
    controller.put_config(FIRST_NODE, &Row::plain(2)).await;
    controller.put_config(NodeId(1002), &Row::plain(70)).await;
    let last = controller.put_config(FIRST_NODE, &Row::plain(3)).await;

    // What the controller would send the node: a delta from the stored revision.
    let stored = config_files(dir.path())
        .load()
        .expect("state")
        .expect("a state");
    assert_eq!(stored.revision, held);
    let seen = first_message(&controller, &credentials, held).await;
    assert!(!seen.received.snapshot, "a delta, not a snapshot");
    assert_eq!(seen.encoding, CBOR);
    assert_eq!(seen.received.payload.entries.len(), 1);
    assert!(seen.received.revision >= last.0);

    // The node, started again, ends with the last of the changes.
    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the node to catch up", || {
        holds(agent, dir.path(), FIRST_NODE, &Row::plain(3))
    })
    .await;
    assert!(agent.config().borrow().revision >= last.0);
    assert_eq!(agent.config().borrow().rows.len(), 1);
    running.stop().await;
}

#[tokio::test]
async fn a_node_behind_a_compacted_journal_gets_a_snapshot_of_exactly_the_current_rows() {
    let controller = Controller::start_with(Options {
        store: MemStoreConfig {
            journal_retention: 5,
            ..MemStoreConfig::default()
        },
        ..Options::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-compacted").await;
    controller.put_config(FIRST_NODE, &Row::plain(1)).await;

    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the first row", || {
        holds(agent, dir.path(), FIRST_NODE, &Row::plain(1))
    })
    .await;
    let held = agent.config().borrow().revision;
    running.stop().await;

    // The row is deleted while the node is away, and the journal moves on past `held`.
    controller.delete_config(FIRST_NODE).await;
    controller.churn(8).await;
    let seen = first_message(&controller, &credentials, held).await;
    assert!(
        seen.received.snapshot,
        "the journal no longer covers {held}"
    );
    assert_eq!(seen.encoding, CBOR_DEFLATE, "a snapshot is compressed");
    assert!(seen.received.payload.entries.is_empty(), "the row is gone");
    assert!(seen.received.revision > held);

    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the deleted row to disappear", || {
        let config = agent.config().borrow().clone();
        config.rows.is_empty()
            && config.revision >= seen.received.revision
            && config_files(dir.path())
                .load()
                .ok()
                .flatten()
                .is_some_and(|disk| disk == *config)
    })
    .await;
    let held = agent.config().borrow().revision;
    running.stop().await;

    // Again, with a row that exists: the snapshot carries exactly it.
    controller.put_config(FIRST_NODE, &Row::plain(9)).await;
    controller.put_config(NodeId(1002), &Row::plain(70)).await;
    controller.churn(8).await;
    let seen = first_message(&controller, &credentials, held).await;
    assert!(seen.received.snapshot);
    assert_eq!(seen.received.payload.entries.len(), 1);
    let running = Running::start(dir.path());
    wait_for("the snapshot to apply", || {
        holds(&running.agent, dir.path(), FIRST_NODE, &Row::plain(9))
    })
    .await;
    assert_eq!(running.agent.config().borrow().rows.len(), 1);
    running.stop().await;
}

#[tokio::test]
async fn a_node_that_has_never_synced_gets_a_snapshot() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-new").await;
    controller.put_config(FIRST_NODE, &Row::plain(4)).await;
    let seen = first_message(&controller, &credentials, 0).await;
    assert!(seen.received.snapshot);
    assert_eq!(seen.encoding, CBOR_DEFLATE);
    assert_eq!(seen.received.payload.entries.len(), 1);
    assert_eq!(seen.frames, 1, "no cap, one frame");
}

#[tokio::test]
async fn the_bandwidth_cap_paces_a_snapshot_to_its_rate() {
    const KBPS: u64 = 128;
    const KBPS_F64: f64 = 128.0;
    // A bucket of 128 kbps is 16,000 bytes per second; it starts with the smallest burst.
    const BYTES_PER_SECOND: f64 = 16_000.0;
    const BURST: f64 = 4096.0;
    let row = Row::heavy(1, 48 * 1024);

    // Without a cap the same snapshot arrives at once.
    let open = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = open.enrol(dir.path(), "probe-fast").await;
    open.put_config(FIRST_NODE, &row).await;
    let fast = first_message(&open, &credentials, 0).await;
    assert!(fast.received.snapshot);
    assert_eq!(fast.frames, 1);
    assert!(
        fast.elapsed < Duration::from_secs(1),
        "uncapped took {:?}",
        fast.elapsed
    );

    // With a cap, the bytes of the message take (bytes - burst) / rate: the burst is free,
    // and the last chunk goes out when the debt of all of them is paid.
    let capped = Controller::start_with(Options {
        rate_kbps: KBPS,
        ..Options::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = capped.enrol(dir.path(), "probe-slow").await;
    capped.put_config(FIRST_NODE, &row).await;
    let slow = first_message(&capped, &credentials, 0).await;
    assert!(slow.received.snapshot);
    assert!(slow.frames > 1, "a capped stream is chunked");
    assert_eq!(slow.received.payload.entries.len(), 1);
    #[allow(clippy::cast_precision_loss, reason = "a few tens of kilobytes")]
    let bytes = slow.bytes as f64;
    let expected = (bytes - BURST) / BYTES_PER_SECOND;
    let seconds = slow.elapsed.as_secs_f64();
    let naive = bytes * 8.0 / (KBPS_F64 * 1000.0);
    eprintln!(
        "pacing: {} bytes in {} frames, {seconds:.3} s measured, {expected:.3} s expected \
         ({naive:.3} s without the burst), uncapped {:.3} s",
        slow.bytes,
        slow.frames,
        fast.elapsed.as_secs_f64()
    );
    assert!(
        (2.0..=4.0).contains(&expected),
        "the test is sized for 2 to 4 seconds, not {expected:.2}"
    );
    // The cap holds when the stream is never faster than the bucket allows; a slower one
    // only says the machine is busy, so the upper bound is loose.
    assert!(
        seconds >= expected * 0.90,
        "measured {seconds:.3} s, faster than the cap allows ({expected:.3} s)"
    );
    assert!(
        seconds <= expected * 1.5 + 1.0,
        "measured {seconds:.3} s, expected {expected:.3} s"
    );
    assert!(slow.elapsed > fast.elapsed * 5);
}
