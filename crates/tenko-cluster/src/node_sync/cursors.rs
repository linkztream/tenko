//! Ingest cursors: the last batch of each node's observation buffer that a controller
//! ingested, as (epoch, sequence), in `cluster.ingest_cursors`.
//!
//! The cursor replaces the in-memory resend recognition of a single controller: every
//! controller reads it before it ingests and writes it after, before it answers, so a node
//! that sends a batch again after a lost answer (to the same controller or, after a
//! failover, to another one) gets `duplicate` instead of a second ingest. A batch tagged
//! with a command id also counts toward that command's `ingested` in the same write.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tenko_core::{NodeId, Principal, RequestCtx, Timestamp};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch};
use uuid::Uuid;

use super::{
    commands::RunResult,
    store_error,
    tables::{INGEST_CURSORS, NODE_COMMANDS, RUN_RESULTS},
};
use crate::{error::ClusterError, probe::ProbeBatch};

/// How many times the cursor write is planned before it gives up (the batch was ingested;
/// a lost cursor only weakens the recognition of a resend).
const ATTEMPTS: usize = 4;

/// The last ingested batch of a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestCursor {
    /// The epoch of the node's buffer.
    pub epoch: String,
    /// The sequence of the batch within the epoch.
    pub sequence: u64,
    /// When the controller ingested it.
    pub at: Timestamp,
}

impl IngestCursor {
    /// Whether the batch (`epoch`, `sequence`) is covered: the same epoch, and not after
    /// this cursor.
    pub fn covers(&self, epoch: &str, sequence: u64) -> bool {
        self.epoch == epoch && sequence <= self.sequence
    }
}

/// Whether the batch was ingested before, per the cursor in `view`.
///
/// # Errors
///
/// A store error.
pub fn seen(
    view: &dyn ReadView,
    node: NodeId,
    epoch: &str,
    sequence: u64,
) -> Result<bool, StoreError> {
    Ok(view
        .get_typed(&INGEST_CURSORS, &node.0)?
        .is_some_and(|(cursor, _)| cursor.covers(epoch, sequence)))
}

/// Whether the batch was ingested before; reads the local copy first and, when that says
/// no, asks for a linearizable view, so a batch another controller ingested a moment ago
/// is recognised too.
///
/// # Errors
///
/// `cluster.no_quorum` or a store error.
pub async fn seen_anywhere(
    store: &dyn Store,
    node: NodeId,
    epoch: &str,
    sequence: u64,
) -> Result<bool, ClusterError> {
    let view = store
        .read(ReadConsistency::Local)
        .await
        .map_err(store_error)?;
    if seen(view.as_ref(), node, epoch, sequence)? {
        return Ok(true);
    }
    drop(view);
    match store.read(ReadConsistency::Linearizable).await {
        Ok(view) => Ok(seen(view.as_ref(), node, epoch, sequence)?),
        // A single node or an isolated one: the local copy is all there is, and the ingest
        // that follows refuses to write anyway.
        Err(StoreError::NoQuorum | StoreError::Timeout) => Ok(false),
        Err(error) => Err(store_error(error)),
    }
}

/// Records (`epoch`, `sequence`) as the cursor of `node` and, for a batch tagged with a
/// command id (`run`: the command and the batch), counts it toward that command and keeps
/// what it reported (`scan.run_results`), in one write.
///
/// # Errors
///
/// `cluster.no_quorum` or a store error. Losing every race is not an error: another
/// controller recorded a later batch meanwhile.
pub async fn record(
    store: &dyn Store,
    node: NodeId,
    epoch: &str,
    sequence: u64,
    run: Option<(Uuid, &ProbeBatch)>,
) -> Result<(), ClusterError> {
    for attempt in 0..ATTEMPTS {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = store.read(consistency).await.map_err(store_error)?;
        let current = view.get_typed(&INGEST_CURSORS, &node.0)?;
        if current
            .as_ref()
            .is_some_and(|(cursor, _)| cursor.covers(epoch, sequence))
        {
            return Ok(());
        }
        let command = match run {
            Some((command, _)) => view.get_typed(&NODE_COMMANDS, &(node.0, command))?,
            None => None,
        };
        drop(view);
        let now = Timestamp::now();
        let ctx = RequestCtx::new(Principal::Node { id: node });
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(
            &INGEST_CURSORS,
            &node.0,
            current.as_ref().map(|(_, revision)| *revision),
        );
        batch.put_typed(
            &INGEST_CURSORS,
            &node.0,
            &IngestCursor {
                epoch: epoch.to_owned(),
                sequence,
                at: now,
            },
        )?;
        if let Some((mut command, revision)) = command {
            command.ingested = command.ingested.saturating_add(1);
            command.updated_at = now;
            let key = (node.0, command.id);
            batch.expect_typed(&NODE_COMMANDS, &key, Some(revision));
            batch.put_typed(&NODE_COMMANDS, &key, &command)?;
            if let Some((_, probe_batch)) = run {
                batch.put_typed(
                    &RUN_RESULTS,
                    &(command.id, sequence),
                    &RunResult::of(node, probe_batch, now),
                )?;
            }
        }
        match store.propose(batch).await {
            Ok(_) => return Ok(()),
            Err(StoreError::PreconditionFailed(_)) => {
                tokio::time::sleep(Duration::from_millis(10 << attempt)).await;
            }
            Err(error) => return Err(store_error(error)),
        }
    }
    tracing::warn!(node = %node, sequence, "the ingest cursor lost every race; a resend may be ingested again");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_covers_its_epoch_up_to_its_sequence() {
        let cursor = IngestCursor {
            epoch: "e1".to_owned(),
            sequence: 7,
            at: Timestamp::now(),
        };
        assert!(cursor.covers("e1", 7));
        assert!(cursor.covers("e1", 1));
        assert!(!cursor.covers("e1", 8));
        assert!(!cursor.covers("e2", 1), "a new epoch starts over");
    }
}
