//! `Observations.Ingest` over mutual TLS: the ingest cursors that all controllers share, a
//! resend after a lost answer, runs, and a node that moves on from a controller that cannot
//! write.

use tenko_core::{NodeId, Timestamp};
use tenko_store::{ReadConsistency, ReadViewExt, Store, WriteBatch};
use uuid::Uuid;

use super::harness::{Controller, FIRST_NODE, Running, WAIT, batch, system, wait_for};
use crate::{
    identity::{AgentState, Credentials},
    node_sync::{
        commands::{CommandRecord, SCAN_RUN},
        cursors::{self, IngestCursor},
        tables::{INGEST_CURSORS, NODE_COMMANDS, RUN_RESULTS},
    },
    proto::v1,
};

async fn cursor(controller: &Controller, node: NodeId) -> Option<IngestCursor> {
    let view = controller
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.get_typed(&INGEST_CURSORS, &node.0)
        .expect("cursor")
        .map(|(cursor, _)| cursor)
}

async fn command(controller: &Controller, node: NodeId, id: Uuid) -> CommandRecord {
    let view = controller
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.get_typed(&NODE_COMMANDS, &(node.0, id))
        .expect("command")
        .expect("the command exists")
        .0
}

/// Sends a batch the way the agent does, to the controller `to`.
async fn ingest(
    to: &Controller,
    credentials: &Credentials,
    epoch: &str,
    sequence: u64,
    run: Option<Uuid>,
    n: u8,
) -> v1::IngestResponse {
    let channel = to.channel(credentials).await;
    let mut client = v1::observations_client::ObservationsClient::new(channel);
    let mut request = batch(n).to_request();
    request.epoch = epoch.to_owned();
    request.sequence = sequence;
    request.run = run.map(|run| run.to_string());
    tokio::time::timeout(WAIT, client.ingest(request))
        .await
        .expect("an answer")
        .expect("ingest")
        .into_inner()
}

#[tokio::test]
async fn a_batch_sent_again_to_another_controller_is_a_duplicate_that_its_sink_never_sees() {
    let first = Controller::start().await;
    let second = first.join(2).await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = first.enrol(dir.path(), "probe-resend").await;

    // The node delivers a batch to the first controller.
    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the node to connect", || {
        agent.status().state == AgentState::Connected
    })
    .await;
    agent.push(&batch(10)).expect("push");
    wait_for("the batch to arrive", || first.sink.batches().len() == 1).await;
    wait_for("the answer to empty the buffer", || {
        agent.outbox().stats().batches == 0
    })
    .await;
    running.stop().await;
    let recorded = cursor(&first, FIRST_NODE).await.expect("a cursor");
    assert_eq!(recorded.sequence, 1);
    assert_ne!(recorded.epoch, "");

    // The answer is lost: the node sends the same batch, same epoch and sequence, to the
    // second controller, which shares the store but not the sink.
    let answer = ingest(&second, &credentials, &recorded.epoch, 1, None, 10).await;
    assert!(answer.duplicate, "{answer:?}");
    assert_eq!(answer.sequence, 1);
    assert!(second.sink.batches().is_empty(), "the sink never saw it");
    // And again to the first one, which also remembers it in memory.
    let answer = ingest(&first, &credentials, &recorded.epoch, 1, None, 10).await;
    assert!(answer.duplicate);
    assert_eq!(first.sink.batches().len(), 1);

    // The next batch is new for the second controller, and moves the shared cursor.
    let answer = ingest(&second, &credentials, &recorded.epoch, 2, None, 11).await;
    assert!(!answer.duplicate, "{answer:?}");
    assert_eq!(answer.new, 1);
    assert_eq!(second.sink.batches().len(), 1);
    assert_eq!(
        cursor(&first, FIRST_NODE).await.expect("cursor").sequence,
        2
    );
    // Now batch 2 is a duplicate for the first controller as well.
    let answer = ingest(&first, &credentials, &recorded.epoch, 2, None, 11).await;
    assert!(answer.duplicate);
    assert_eq!(first.sink.batches().len(), 1);

    // A new epoch (the node's buffer was recreated) starts over.
    let answer = ingest(&second, &credentials, "epoch-two", 1, None, 12).await;
    assert!(!answer.duplicate);
    assert_eq!(second.sink.batches().len(), 2);
}

#[tokio::test]
async fn a_batch_tagged_with_a_run_is_counted_on_its_command_and_kept_once() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-run").await;
    let record = CommandRecord::new(FIRST_NODE, SCAN_RUN, Vec::new(), Timestamp::now());
    let id = record.id;
    let mut write = WriteBatch::for_request(&system());
    write
        .put_typed(&NODE_COMMANDS, &(FIRST_NODE.0, id), &record)
        .expect("command");
    controller.store.propose(write).await.expect("propose");

    let answer = ingest(&controller, &credentials, "epoch-run", 1, Some(id), 20).await;
    assert!(!answer.duplicate);
    let answer = ingest(&controller, &credentials, "epoch-run", 2, Some(id), 21).await;
    assert!(!answer.duplicate);
    assert_eq!(controller.sink.batches().len(), 2);

    let held = cursor(&controller, FIRST_NODE).await.expect("a cursor");
    assert_eq!((held.epoch.as_str(), held.sequence), ("epoch-run", 2));
    assert_eq!(command(&controller, FIRST_NODE, id).await.ingested, 2);
    let view = controller
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    for sequence in [1, 2] {
        let (result, _) = view
            .get_typed(&RUN_RESULTS, &(id, sequence))
            .expect("result")
            .expect("a result row for each batch");
        assert_eq!(result.node, FIRST_NODE);
    }

    // The resend of a tagged batch counts nowhere a second time.
    let answer = ingest(&controller, &credentials, "epoch-run", 2, Some(id), 21).await;
    assert!(answer.duplicate);
    assert_eq!(command(&controller, FIRST_NODE, id).await.ingested, 2);
    assert_eq!(controller.sink.batches().len(), 2);

    // A batch of a run nobody issued moves the cursor and counts for nothing.
    let stray = Uuid::now_v7();
    let answer = ingest(&controller, &credentials, "epoch-run", 3, Some(stray), 22).await;
    assert!(!answer.duplicate);
    assert_eq!(
        cursor(&controller, FIRST_NODE)
            .await
            .expect("cursor")
            .sequence,
        3
    );
}

#[tokio::test]
async fn recording_a_run_twice_for_the_same_sequence_changes_nothing() {
    let controller = Controller::start().await;
    let record = CommandRecord::new(FIRST_NODE, SCAN_RUN, Vec::new(), Timestamp::now());
    let id = record.id;
    let mut write = WriteBatch::for_request(&system());
    write
        .put_typed(&NODE_COMMANDS, &(FIRST_NODE.0, id), &record)
        .expect("command");
    controller.store.propose(write).await.expect("propose");

    let tagged = batch(30);
    for _ in 0..2 {
        cursors::record(
            controller.store.as_ref(),
            FIRST_NODE,
            "epoch-direct",
            5,
            Some((id, &tagged)),
        )
        .await
        .expect("record");
    }
    let held = cursor(&controller, FIRST_NODE).await.expect("cursor");
    assert_eq!((held.epoch.as_str(), held.sequence), ("epoch-direct", 5));
    assert_eq!(command(&controller, FIRST_NODE, id).await.ingested, 1);
    // An older sequence of the same epoch is covered and records nothing.
    cursors::record(
        controller.store.as_ref(),
        FIRST_NODE,
        "epoch-direct",
        4,
        Some((id, &tagged)),
    )
    .await
    .expect("record");
    assert_eq!(command(&controller, FIRST_NODE, id).await.ingested, 1);
}

#[tokio::test]
async fn an_agent_moves_to_the_next_controller_when_one_has_no_quorum_and_keeps_its_batch() {
    let first = Controller::start().await;
    let second = first.join(2).await;
    let dir = tempfile::tempdir().expect("dir");
    first
        .enrol_at(dir.path(), "probe-failover", &[first.addr, second.addr])
        .await;
    first.gate.cut_off(true);

    let running = Running::start(dir.path());
    let agent = &running.agent;
    agent.push(&batch(40)).expect("push");
    wait_for("the batch to reach the controller that can write", || {
        second.sink.batches().len() == 1
    })
    .await;
    wait_for("the buffer to empty", || {
        agent.outbox().stats().batches == 0
    })
    .await;
    assert!(
        first.sink.batches().is_empty(),
        "the controller without quorum took nothing"
    );
    assert_eq!(second.sink.batches().len(), 1, "delivered once");
    assert_eq!(
        cursor(&second, FIRST_NODE).await.expect("cursor").sequence,
        1
    );

    // The first controller can write again: nothing is sent twice.
    first.gate.cut_off(false);
    agent.push(&batch(41)).expect("push");
    wait_for("the second batch", || {
        first.sink.batches().len() + second.sink.batches().len() == 2
    })
    .await;
    assert_eq!(
        cursor(&first, FIRST_NODE).await.expect("cursor").sequence,
        2
    );
    running.stop().await;
}
