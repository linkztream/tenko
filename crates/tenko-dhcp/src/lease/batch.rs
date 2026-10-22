//! The lease change as one store batch (plan section 2.1, ADR 0019 point 3): the lease row,
//! the client index rows it moves, the history row and the IPAM observation fact, committed
//! as one transaction with one revision.
//!
//! [`build`] runs on the committer's side, after the hand-off: it completes a
//! [`PendingChange`] into the row with the fields of the row held before
//! ([`PendingChange::to_lease`]), refuses a change that would take an address another
//! client still holds (the last guard of "no address on two clients"), and writes:
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `dhcp.leases` | VRF, address | the row after the change |
//! | `dhcp.leases.by_client` | scope, client identity | the client's latest row; the previous holder's entry moved or removed |
//! | `dhcp.history` | time, VRF, address | the [`LeaseEvent`](tenko_core::dhcp::LeaseEvent) |
//! | IPAM observations | the hook's | the fact of `dhcp:<node>` ([`ObservationHook`], WP8.1) |
//!
//! The principal is `system:dhcp`; the role's lease commits are not audited one by one (the
//! history is their record, `docs/dhcp-contracts.md` section 7).

use tenko_core::{
    NodeId, Principal, SystemComponent, Timestamp,
    dhcp::{Lease, LeaseEventKind, tables},
};
use tenko_store::{StoreError, WriteBatch};

use super::{PendingChange, table::IndexUpdate};

/// Adds the IPAM observation fact of a lease change to its batch (plan section 2.8). WP8.1
/// fills it with the helper of `tenko-ipam`; until then the batch carries no fact
/// ([`NoObservations`]).
pub trait ObservationHook: Send + Sync {
    /// Adds the fact for `lease` (the row after the change; `previous` the row before) to
    /// `batch` when the rules of `observe::ingest` say one is due, and returns the time to
    /// record as the row's `observed_at` (`None` keeps the row's value).
    ///
    /// # Errors
    ///
    /// A store error when the fact cannot be encoded; the change then fails.
    fn observe(
        &self,
        lease: &Lease,
        previous: Option<&Lease>,
        batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError>;
}

/// No observation facts (until WP8.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObservations;

impl ObservationHook for NoObservations {
    fn observe(
        &self,
        _lease: &Lease,
        _previous: Option<&Lease>,
        _batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError> {
        Ok(None)
    }
}

/// Why a change was not turned into a batch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// Another client holds the address until its end (`dhcp.lease.state`): the request is
    /// not answered, and no address goes to two clients.
    #[error("the address is held by another client")]
    HeldByOther,
    /// A row did not encode.
    #[error("the lease change did not encode: {0}")]
    Encode(String),
}

/// A built batch and the row it writes.
#[derive(Debug, Clone)]
pub struct LeaseBatch {
    /// The batch.
    pub batch: WriteBatch,
    /// The lease row after the change, for the table once the batch commits.
    pub lease: Lease,
}

/// Whether `previous` stops `change`: another client's binding (or abandoned address) that
/// has not ended at `now`. An operator's reclaim may take it.
pub fn held_by_other(change: &PendingChange, previous: Option<&Lease>, now: Timestamp) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    if change.kind == LeaseEventKind::Reclaimed || !previous.blocks(now) {
        return false;
    }
    let mut identity = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
    let len = change.identity(&mut identity);
    previous.client.identity() != identity[..len]
}

/// Builds the batch of one lease change. `previous` is the row the table holds for the
/// address, `index` the client index entries the change moves
/// ([`LeaseIndex::index_after`](super::LeaseIndex::index_after)), `now` the proposer's
/// clock.
///
/// # Errors
///
/// [`BuildError::HeldByOther`] for an address another client holds, [`BuildError::Encode`]
/// when a row does not encode.
pub fn build(
    change: &PendingChange,
    node: NodeId,
    previous: Option<&Lease>,
    index: impl FnOnce(&Lease) -> Vec<IndexUpdate>,
    hook: &dyn ObservationHook,
    now: Timestamp,
) -> Result<LeaseBatch, BuildError> {
    if held_by_other(change, previous, now) {
        return Err(BuildError::HeldByOther);
    }
    let mut lease = change.to_lease(node, previous);
    // A row never moves back in client time, so that the table's rule (the later `cltt`
    // wins) and the store agree even if the clock stepped back.
    if let Some(previous) = previous
        && previous.cltt > lease.cltt
    {
        lease.cltt = previous.cltt;
    }
    let encode = |error: StoreError| BuildError::Encode(error.to_string());
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
    if let Some(observed) = hook.observe(&lease, previous, &mut batch).map_err(encode)? {
        lease.observed_at = Some(observed);
    }
    batch
        .put_typed(&tables::LEASES, &(lease.vrf, lease.addr), &lease)
        .map_err(encode)?;
    for update in index(&lease) {
        let key = (update.scope, update.identity);
        match update.target {
            Some(target) => {
                batch
                    .put_typed(&tables::LEASES_BY_CLIENT, &key, &target)
                    .map_err(encode)?;
            }
            None => {
                batch.delete_typed(&tables::LEASES_BY_CLIENT, &key);
            }
        }
    }
    let mut event = change.to_event(node);
    event.at = lease.cltt;
    batch
        .put_typed(&tables::HISTORY, &(event.at, event.vrf, event.addr), &event)
        .map_err(encode)?;
    Ok(LeaseBatch { batch, lease })
}
