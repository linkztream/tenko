//! Retention: facts whose last sighting is older than the retention are purged with their
//! index rows, in batches of at most [`PURGE_CHUNK`] facts (`system:reconciler`, audit
//! action `ipam.observation.purge`). Sightings of intent objects that no longer exist
//! (`ipam.obs.last_seen`) go with them.

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
    let mut purged = 0;
    for chunk in old.chunks(PURGE_CHUNK) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), now);
        for fact in chunk {
            delete_fact(fact, &mut batch);
        }
        batch.audit(
            AuditDraft::success(AuditAction::from_static(PURGE_ACTION), Vec::new())
                .with_context("facts", chunk.len().to_string())
                .with_context("cutoff", cutoff.to_rfc3339()),
        );
        match store.propose(batch).await {
            Ok(_) => purged += chunk.len(),
            Err(StoreError::PreconditionFailed(_)) => {
                tracing::debug!("observation purge raced with an ingest; skipped a chunk");
            }
            Err(error) => return Err(error.into()),
        }
    }
    for chunk in stale_sightings.chunks(PURGE_CHUNK) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), now);
        for (object, revision) in chunk {
            batch.delete_typed(&LAST_SEEN, object);
            batch.expect_typed(&LAST_SEEN, object, Some(*revision));
        }
        batch.audit(
            AuditDraft::success(AuditAction::from_static(PURGE_ACTION), Vec::new())
                .with_context("sightings", chunk.len().to_string()),
        );
        match store.propose(batch).await {
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(purged)
}
