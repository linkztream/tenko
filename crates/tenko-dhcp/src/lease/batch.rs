//! The lease change as store batches (plan section 2.1, ADR 0019 point 3, ADR 0030, ADR
//! 0031): the lease row and the client index rows it moves, committed before the ACK as one
//! transaction with one revision; and the history row derived from it, built at the same
//! time against the same row but written by the asynchronous writer ([`super::derived`])
//! once the lease committed, with the revision of that commit.
//!
//! [`build`] runs on the committer's side, after the hand-off: it completes a
//! [`PendingChange`] into the row with the fields of the row held before
//! ([`PendingChange::to_lease`]), refuses a change that would take an address another
//! client still holds (the last guard of "no address on two clients"), and writes:
//!
//! | Batch | Table | Key | Value |
//! |---|---|---|---|
//! | synchronous | `dhcp.leases` | VRF, address | the row after the change |
//! | synchronous | `dhcp.leases.by_client` | scope, client identity | the client's latest row; the previous holder's entry moved or removed |
//! | derived | `dhcp.history` | time, VRF, address | the lean event ([`HistoryRow`]): the event, the state and its end, the scope, the client identity, the node and the lease row's revision |
//!
//! No IPAM observation fact is written (ADR 0031): the lease table is the observation
//! source `dhcp:<node>`, which IPAM reads through its lease view
//! (`tenko_ipam::observe::dhcp::LeaseFacts`).
//!
//! The principal is `system:dhcp`; the role's lease commits are not audited one by one (the
//! history is their record, `docs/dhcp-contracts.md` section 7).

use tenko_core::{
    NodeId, Principal, Revision, SystemComponent, Timestamp,
    dhcp::{HistoryRow, Lease, LeaseEvent, LeaseEventKind, tables},
};
use tenko_store::{StoreError, WriteBatch};

use super::{PendingChange, table::IndexUpdate};

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

/// A built change: the synchronous batch, the history event and the row it writes.
#[derive(Debug, Clone)]
pub struct LeaseBatch {
    /// The synchronous batch: the lease row and the client index rows (DHCP-17).
    pub batch: WriteBatch,
    /// The history event of the change, for the asynchronous writer once `batch` committed
    /// ([`LeaseBatch::derived`], ADR 0030 and ADR 0031).
    pub history: LeaseEvent,
    /// The lease row after the change, for the table once the batch commits.
    pub lease: Lease,
}

impl LeaseBatch {
    /// The derived batch of the change once its lease row committed at `revision`: the
    /// lean history row, which names that revision.
    ///
    /// # Errors
    ///
    /// The row does not encode.
    pub fn derived(&self, revision: Revision) -> Result<WriteBatch, StoreError> {
        history_batch(&self.history, Some(revision), self.batch.proposed_at)
    }
}

/// A batch of the lean history row of `event`, naming the lease row's `revision` (`None`:
/// the row is written in the lease row's own batch), proposed at `now`.
///
/// # Errors
///
/// The row does not encode.
pub fn history_batch(
    event: &LeaseEvent,
    revision: Option<Revision>,
    now: Timestamp,
) -> Result<WriteBatch, StoreError> {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
    put_history(&mut batch, event, revision)?;
    Ok(batch)
}

/// Adds the lean history row of `event` to `batch`, naming the lease row's `revision`
/// (`None`: the lease row is written in `batch` itself).
///
/// # Errors
///
/// The row does not encode.
pub fn put_history(
    batch: &mut WriteBatch,
    event: &LeaseEvent,
    revision: Option<Revision>,
) -> Result<(), StoreError> {
    let mut row = HistoryRow::of(event);
    if let HistoryRow::Lean(lean) = &mut row {
        lean.revision = revision;
    }
    batch.put_typed(&tables::HISTORY, &(event.at, event.vrf, event.addr), &row)?;
    Ok(())
}

/// The time by which a binding of client time `cltt` is judged at `now`. A binding written
/// before the forward jump the clock guard holds (`tenko_core::clock::forward_hold`) ends
/// by the clock before the jump, so it is judged that much earlier and the jump ends it no
/// sooner; a binding written since is judged at `now`. A time out of range reads as the
/// Unix epoch.
pub(crate) fn reuse_now(now: Timestamp, cltt: Timestamp) -> Timestamp {
    let Some(jump) = tenko_core::clock::forward_hold() else {
        return now;
    };
    let before = now.checked_sub(jump).unwrap_or(Timestamp::UNIX_EPOCH);
    if cltt <= before { before } else { now }
}

/// Whether `previous` stops `change`: another client's binding (or abandoned address) that
/// has not ended at `now`, judged by `reuse_now`. An operator's reclaim may take it.
pub fn held_by_other(change: &PendingChange, previous: Option<&Lease>, now: Timestamp) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    let now = reuse_now(now, previous.cltt);
    if change.kind == LeaseEventKind::Reclaimed || !previous.blocks(now) {
        return false;
    }
    // WP8.5: a DECLINE's change belongs to no client (the engine checked that the decliner
    // holds the binding), so it may end an active binding; it never replaces an abandoned
    // row.
    if change.kind == LeaseEventKind::Declined
        && previous.state == tenko_core::dhcp::BindingState::Active
    {
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
    now: Timestamp,
) -> Result<LeaseBatch, BuildError> {
    if held_by_other(change, previous, now) {
        return Err(BuildError::HeldByOther);
    }
    let mut lease = change.to_lease(node, previous);
    // A row never moves back in client time, so that the table's rule (the later `cltt`
    // wins) and the store agree even if the clock stepped back; its end stays the one the
    // client was told.
    if let Some(previous) = previous
        && previous.cltt > lease.cltt
    {
        lease.cltt = previous.cltt;
        lease.granted = lease.granted.map(|granted| granted.min(lease.cltt));
    }
    let encode = |error: StoreError| BuildError::Encode(error.to_string());
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
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
    let mut history = change.to_event(node);
    history.at = lease.cltt;
    Ok(LeaseBatch {
        batch,
        history,
        lease,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tenko_core::{PrefixId, VrfId, clock::testing::hold_jump, dhcp::BindingState};

    use super::*;

    fn at(now: Timestamp, secs: i64) -> Timestamp {
        Timestamp::from_unix_nanos(now.unix_nanos() + i128::from(secs) * 1_000_000_000)
            .expect("a time")
    }

    /// Client `client` (an RFC 7042 MAC address) takes 192.0.2.10 from `cltt` to `ends`.
    fn change(scope: PrefixId, client: u8, cltt: Timestamp, ends: Timestamp) -> PendingChange {
        PendingChange::new(
            LeaseEventKind::Granted,
            VrfId(uuid::Uuid::nil()),
            scope,
            Ipv4Addr::new(192, 0, 2, 10),
            1,
            &[0x00, 0x00, 0x5e, 0x00, 0x53, client],
            None,
            BindingState::Active,
            cltt,
            ends,
        )
    }

    #[test]
    fn a_forward_hold_keeps_another_clients_address_from_before_the_jump() {
        let (scope, now) = (PrefixId::generate(), Timestamp::now());
        // Client 1's bindings ended 30 s and 10 s ago by the wall clock: one written before a
        // jump of a minute, one written since.
        let row =
            |cltt, ends| change(scope, 1, at(now, cltt), at(now, ends)).to_lease(NodeId(1), None);
        let (old, new) = (row(-3_630, -30), row(-20, -10));
        let other = change(scope, 2, now, at(now, 3_600));
        let jump = hold_jump(60_000);
        assert!(held_by_other(&other, Some(&old), now));
        assert!(
            !held_by_other(&other, Some(&new), now),
            "written during the hold"
        );
        drop(jump);
        assert!(!held_by_other(&other, Some(&old), now));
        // Any amount: the time saturates instead of wrapping or panicking.
        let _far = hold_jump(i64::MAX);
        assert_eq!(reuse_now(now, Timestamp::UNIX_EPOCH), Timestamp::UNIX_EPOCH);
    }

    #[test]
    fn after_a_backward_step_the_stored_end_is_the_end_the_client_was_told() {
        let (scope, now) = (PrefixId::generate(), Timestamp::now());
        let first = change(scope, 1, at(now, 60), at(now, 3_660)).to_lease(NodeId(1), None);
        // The clock stepped back a minute: the renewal's client time lies before the row's.
        let renewal = change(scope, 1, now, at(now, 3_600));
        let built = build(&renewal, NodeId(1), Some(&first), |_| Vec::new(), now).expect("built");
        assert_eq!(built.lease.cltt, at(now, 60), "never back in client time");
        assert_eq!(
            (built.lease.ends, built.history.ends),
            (at(now, 3_600), at(now, 3_600))
        );
    }
}
