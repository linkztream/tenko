//! Retention: facts whose last sighting is older than the retention are purged with their
//! index rows, in batches of at most [`PURGE_CHUNK`] facts and [`PURGE_BATCH_BYTES`]
//! (`system:reconciler`, audit action `ipam.observation.purge`). Sightings of intent objects
//! that no longer exist (`ipam.obs.last_seen`) go with them. Nothing is purged while the
//! clock guard holds destruction (`tenko_core::clock`).

use std::sync::Arc;

use tenko_core::{
    ObjectKind, Principal, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft},
    ipam::{Address, Interface},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch};

use super::{
    ObserveConfig,
    ingest::delete_fact,
    tables::{FACTS, LAST_SEEN},
};
use crate::{
    error::IpamResult,
    tables::{ADDRESSES, INTERFACES},
};

/// Audit action of a purge.
pub const PURGE_ACTION: &str = "ipam.observation.purge";

/// Facts deleted per batch.
pub const PURGE_CHUNK: usize = 2_000;

/// The most a batch that only deletes carries in keys, values and preconditions: half the
/// 256 KiB a store close to its disk reserve still takes, since the encoding of a batch of
/// deletes with their versions adds up to three quarters to them, and the batch's record.
pub const PURGE_BATCH_BYTES: usize = 128 * 1024;

/// Deletes facts last seen before `now - retention` and stale intent sightings; returns
/// the number of facts deleted.
///
/// # Errors
///
/// Store errors. A batch that loses a race with an ingest is skipped; the next run purges
/// what is still old.
pub async fn purge(
    store: &Arc<dyn Store>,
    config: &ObserveConfig,
    now: Timestamp,
) -> IpamResult<usize> {
    purge_fenced(store, config, now, None).await
}

/// [`purge`], with every batch fenced with the leader `epoch` when given (the purge of the
/// leader service `ipam.reconcile`): once another controller took office, a batch of the
/// deposed one fails and the purge stops.
///
/// # Errors
///
/// As [`purge`].
pub async fn purge_fenced(
    store: &Arc<dyn Store>,
    config: &ObserveConfig,
    now: Timestamp,
    epoch: Option<u64>,
) -> IpamResult<usize> {
    if let Err(held) = tenko_core::clock::trusted_now() {
        tracing::debug!(?held, "the observation purge waits for a trusted clock");
        return Ok(0);
    }
    let Some(cutoff) = now
        .unix_nanos()
        .checked_sub(i128::try_from(config.retention.as_nanos()).unwrap_or(i128::MAX))
        .and_then(|nanos| Timestamp::from_unix_nanos(nanos).ok())
    else {
        return Ok(0);
    };
    let view = store.read(ReadConsistency::Local).await?;
    let old: Vec<_> = view
        .scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter_map(|(_, mut fact, revision)| {
            fact.revision = revision;
            (fact.last_seen < cutoff).then_some(fact)
        })
        .collect();
    let mut stale_sightings = Vec::new();
    for (object, _, revision) in view.scan_typed(&LAST_SEEN, KeyRange::all(), usize::MAX, false)? {
        let live = match object.kind {
            ObjectKind::Address => view
                .get_typed(&ADDRESSES, &object.id.into())?
                .is_some_and(|(address, _): (Address, _)| !address.meta.is_deleted()),
            ObjectKind::Interface => view
                .get_typed(&INTERFACES, &object.id.into())?
                .is_some_and(|(interface, _): (Interface, _)| !interface.meta.is_deleted()),
            _ => false,
        };
        if !live {
            stale_sightings.push((object, revision));
        }
    }
    drop(view);
    let at = (now, epoch);
    let purged = delete_chunks(store, &old, at, ("facts", Some(cutoff)), delete_fact).await?;
    delete_chunks(
        store,
        &stale_sightings,
        at,
        ("sightings", None),
        |(object, revision), batch| {
            batch.delete_typed(&LAST_SEEN, object);
            batch.expect_typed(&LAST_SEEN, object, Some(*revision));
        },
    )
    .await?;
    Ok(purged)
}

/// Deletes `rows` in the batches of [`purge_batches`]; returns how many it deleted. A batch
/// that loses a race with another writer is skipped, and the next purge takes what is still
/// old.
pub(crate) async fn delete_chunks<T>(
    store: &Arc<dyn Store>,
    rows: &[T],
    at: (Timestamp, Option<u64>),
    counted: (&'static str, Option<Timestamp>),
    delete: impl Fn(&T, &mut WriteBatch),
) -> IpamResult<usize> {
    let mut deleted = 0;
    for (count, batch) in purge_batches(rows, at, counted, delete) {
        match store.propose(batch).await {
            Ok(_) => deleted += count,
            Err(StoreError::PreconditionFailed(_)) => {
                tracing::debug!("a purge raced with another writer; skipped a batch");
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(deleted)
}

/// The batches that delete `rows`, with how many rows each holds: at most [`PURGE_CHUNK`]
/// rows and [`PURGE_BATCH_BYTES`] each, only deletes, fenced with the leader epoch of `at`
/// when given, and one [`PURGE_ACTION`] record that counts the rows under the name of
/// `counted` (with its cutoff, when given).
fn purge_batches<T>(
    rows: &[T],
    (now, epoch): (Timestamp, Option<u64>),
    (counted, cutoff): (&'static str, Option<Timestamp>),
    delete: impl Fn(&T, &mut WriteBatch),
) -> Vec<(usize, WriteBatch)> {
    let empty = || WriteBatch::new(Principal::system(SystemComponent::Reconciler), now);
    let seal = |mut batch: WriteBatch, count: usize| {
        batch.preconditions.extend(epoch.map(tenko_store::fence));
        let mut record = AuditDraft::success(AuditAction::from_static(PURGE_ACTION), Vec::new())
            .with_context(counted, count.to_string());
        if let Some(cutoff) = cutoff {
            record = record.with_context("cutoff", cutoff.to_rfc3339());
        }
        batch.audit(record);
        (count, batch)
    };
    let (mut out, mut batch, mut count, mut size) = (Vec::new(), empty(), 0, 0);
    for row in rows {
        let mut one = empty();
        delete(row, &mut one);
        let bytes = one.payload_size();
        if count > 0 && (count == PURGE_CHUNK || size + bytes > PURGE_BATCH_BYTES) {
            out.push(seal(std::mem::replace(&mut batch, empty()), count));
            (count, size) = (0, 0);
        }
        batch.mutations.append(&mut one.mutations);
        batch.preconditions.append(&mut one.preconditions);
        (count, size) = (count + 1, size + bytes);
    }
    if count > 0 {
        out.push(seal(batch, count));
    }
    out
}

#[cfg(test)]
mod tests {
    use tenko_core::{ProposalId, Revision, codec::to_cbor};
    use tenko_store::Mutation;

    use super::*;
    use crate::proposals::model::PROPOSALS;

    #[test]
    fn a_purge_batch_stays_under_the_bytes_a_full_disk_takes() {
        let at = (Timestamp::UNIX_EPOCH, Some(7));
        // Rows far longer than any key the tables hold, and many short ones.
        let long: Vec<Vec<u8>> = (0..300u32)
            .map(|n| [n.to_be_bytes().to_vec(), vec![b'k'; 4_096]].concat())
            .collect();
        let short: Vec<u32> = (0..5_000).collect();
        let deleting = |key: Vec<u8>, batch: &mut WriteBatch| {
            batch.mutations.push(Mutation::Delete {
                table: FACTS.name().clone(),
                key: key.into(),
            });
        };
        let batches = purge_batches(&long, at, ("facts", None), |key, batch| {
            deleting(key.clone(), batch);
        });
        let shorts = purge_batches(&short, at, ("facts", None), |n, batch| {
            deleting(n.to_be_bytes().to_vec(), batch);
        });
        // A full chunk of the proposal purge: the shortest rows, each with its version.
        let ids: Vec<_> = (0..=PURGE_CHUNK)
            .map(|_| (ProposalId::generate(), Revision(u64::MAX)))
            .collect();
        let purge = purge_batches(
            &ids,
            at,
            ("proposals", Some(Timestamp::UNIX_EPOCH)),
            |(id, revision), batch| {
                batch.delete_typed(&PROPOSALS, id);
                batch.expect_typed(&PROPOSALS, id, Some(*revision));
            },
        );
        for (count, batch) in batches.iter().chain(&shorts).chain(&purge) {
            let encoded = to_cbor(batch).expect("cbor").len();
            assert!(
                encoded <= 256 * 1024,
                "{count} rows, {encoded} bytes encoded"
            );
            assert!(
                batch.payload_size() <= 256 * 1024,
                "{count} rows, {} bytes",
                batch.payload_size()
            );
            assert!(
                batch
                    .mutations
                    .iter()
                    .all(|m| matches!(m, Mutation::Delete { .. }))
            );
            assert_eq!(batch.audit.len(), 1);
            assert_eq!(batch.mutations.len(), *count);
        }
        assert!(batches.len() > 1, "the bytes split them");
        assert_eq!(
            batches.iter().map(|(count, _)| count).sum::<usize>(),
            long.len()
        );
        assert_eq!(
            shorts.iter().map(|(count, _)| *count).max(),
            Some(PURGE_CHUNK)
        );
        assert_eq!(
            shorts.iter().map(|(count, _)| count).sum::<usize>(),
            short.len()
        );
    }
}
