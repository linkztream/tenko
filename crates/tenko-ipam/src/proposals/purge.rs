//! Closed proposals (accepted, rejected, expired, superseded) whose last change is older than
//! the fact retention are deleted in the same purge pass as the old facts, in batches that
//! only delete: at most `PURGE_CHUNK` rows, each with its version, and one audit record
//! `ipam.observation.purge` (context `proposals` and `cutoff`). A remembered rejection stays.
//! Nothing is purged while the clock guard holds destruction (`tenko_core::clock`).

use std::{sync::Arc, time::Duration};

use tenko_core::Timestamp;
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store};

use super::model::PROPOSALS;
use crate::{error::IpamResult, observe::retention::delete_chunks};

/// Deletes the closed proposals last changed before `now - retention`, every batch fenced
/// with the leader `epoch` when given; returns how many it deleted. A batch that loses a
/// race with another writer is skipped, and the next purge takes what is still old.
///
/// # Errors
///
/// Store errors.
pub(crate) async fn closed(
    store: &Arc<dyn Store>,
    retention: Duration,
    now: Timestamp,
    epoch: Option<u64>,
) -> IpamResult<usize> {
    if let Err(held) = tenko_core::clock::trusted_now() {
        tracing::debug!(?held, "the proposal purge waits for a trusted clock");
        return Ok(0);
    }
    let Some(cutoff) = now.checked_sub(retention) else {
        return Ok(0);
    };
    let view = store.read(ReadConsistency::Local).await?;
    let old: Vec<_> = view
        .scan_typed(&PROPOSALS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, proposal, _)| !proposal.is_open() && proposal.updated < cutoff)
        .map(|(id, _, revision)| (id, revision))
        .collect();
    drop(view);
    delete_chunks(
        store,
        &old,
        (now, epoch),
        ("proposals", Some(cutoff)),
        |(id, revision), batch| {
            batch.delete_typed(&PROPOSALS, id);
            batch.expect_typed(&PROPOSALS, id, Some(*revision));
        },
    )
    .await
}
