//! Lease expiry as a leader service (plan section 2.1, WP7.2 content 3): bindings that ran
//! out become `expired` in the store, in batches, with a history row each.
//!
//! Every [`ExpirySettings::period`] the leader finds the rows due (an `active` binding past
//! its end, an `abandoned` address past its hold) in the role's table when it has one, else
//! by a scan of `dhcp.leases`, and writes them as `expired` in batches of
//! [`ExpirySettings::batch`] rows: each batch carries the leader fence
//! (`tenko_store::fence`) and a version precondition per row, so a renewal committed in
//! between makes the batch fail and nothing stale is written (the rows are tried again on
//! the next round), and a deposed leader writes nothing. The client index does not move: an
//! expired row keeps its client and its `cltt`. The same round prunes the offer hold.
//!
//! Expiry does not decide whether an address is free: the allocator already treats a
//! binding past its end as free (`Lease::blocks`). The state change makes the row say so,
//! puts the event in the history and lets DDNS (WP8.3) remove the client's records.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    NodeId, Principal, SystemComponent, Timestamp, VrfId,
    cluster::LeaderService,
    dhcp::{BindingState, Lease, LeaseEvent, LeaseEventKind, tables},
};
use tenko_store::{
    FailedPrecondition, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use super::{follow::PAGE, metrics, offer::OfferTable, table::SharedLeases};

/// The expiry service's timer and batch size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirySettings {
    /// Time between rounds.
    pub period: Duration,
    /// Rows per batch.
    pub batch: usize,
}

impl Default for ExpirySettings {
    fn default() -> Self {
        Self {
            period: Duration::from_secs(10),
            batch: 256,
        }
    }
}

/// What one round did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpiryRound {
    /// Rows found due.
    pub due: usize,
    /// Rows written as expired.
    pub expired: usize,
    /// Batches that failed on a row that changed meanwhile (tried again next round).
    pub raced: usize,
}

/// The expiry leader service (`dhcp.expiry`).
#[derive(Clone)]
pub struct ExpiryService {
    store: Arc<dyn Store>,
    node: NodeId,
    settings: ExpirySettings,
    leases: Option<SharedLeases>,
    offers: Option<Arc<OfferTable>>,
}

impl std::fmt::Debug for ExpiryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpiryService")
            .field("node", &self.node)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The row of `lease` after its expiry at `now`, written by `node`.
pub fn expired(lease: &Lease, node: NodeId, now: Timestamp) -> Lease {
    Lease {
        state: BindingState::Expired,
        ends: now,
        node,
        ..lease.clone()
    }
}

fn is_due(lease: &Lease, now: Timestamp) -> bool {
    matches!(lease.state, BindingState::Active | BindingState::Abandoned) && lease.ends <= now
}

impl ExpiryService {
    /// Expiry over `store`, written as `node`.
    pub fn new(store: Arc<dyn Store>, node: NodeId, settings: ExpirySettings) -> Self {
        Self {
            store,
            node,
            settings,
            leases: None,
            offers: None,
        }
    }

    /// Finds the due rows in the role's table and applies the expired rows to it at once.
    #[must_use]
    pub fn with_table(mut self, leases: SharedLeases) -> Self {
        self.leases = Some(leases);
        self
    }

    /// Prunes this offer hold every round.
    #[must_use]
    pub fn with_offers(mut self, offers: Arc<OfferTable>) -> Self {
        self.offers = Some(offers);
        self
    }

    /// The keys of the rows due at `now`.
    fn due(
        &self,
        view: &dyn ReadView,
        now: Timestamp,
    ) -> Result<Vec<(VrfId, std::net::Ipv4Addr)>, StoreError> {
        if let Some(leases) = &self.leases {
            return Ok(leases.read().due(now));
        }
        let mut due = Vec::new();
        let mut range = KeyRange::all();
        loop {
            let page = view.scan_typed(&tables::LEASES, range.clone(), PAGE, false)?;
            let full = page.len() == PAGE;
            let Some((last, _, _)) = page.last() else {
                break;
            };
            let last = tables::LEASES.key(last);
            due.extend(
                page.iter()
                    .filter(|(_, lease, _)| is_due(lease, now))
                    .map(|(key, _, _)| *key),
            );
            if !full {
                break;
            }
            range = KeyRange::all().after(last);
        }
        Ok(due)
    }

    /// One round at `now` under the leader `epoch`.
    ///
    /// # Errors
    ///
    /// A store error other than a row that changed meanwhile; a fence that failed (another
    /// controller took office) ends the round with [`StoreError::PreconditionFailed`].
    pub async fn round(&self, epoch: u64, now: Timestamp) -> Result<ExpiryRound, StoreError> {
        if let Some(offers) = &self.offers {
            offers.prune(now);
        }
        let view = self.store.read(ReadConsistency::Local).await?;
        let keys = self.due(view.as_ref(), now)?;
        let mut round = ExpiryRound {
            due: keys.len(),
            ..ExpiryRound::default()
        };
        for chunk in keys.chunks(self.settings.batch.max(1)) {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
            batch.preconditions.push(fence(epoch));
            let mut rows = Vec::with_capacity(chunk.len());
            for key in chunk {
                let Some((lease, revision)) = view.get_typed(&tables::LEASES, key)? else {
                    continue;
                };
                if !is_due(&lease, now) {
                    continue;
                }
                let row = expired(&lease, self.node, now);
                let event = LeaseEvent::of(&row, LeaseEventKind::Expired, now);
                batch.expect_typed(&tables::LEASES, key, Some(revision));
                batch.put_typed(&tables::LEASES, key, &row)?;
                batch.put_typed(&tables::HISTORY, &(now, row.vrf, row.addr), &event)?;
                rows.push(row);
            }
            if rows.is_empty() {
                continue;
            }
            match self.store.propose(batch).await {
                Ok(committed) => {
                    let count = rows.len();
                    if let Some(leases) = &self.leases {
                        let mut table = leases.write();
                        for row in rows {
                            table.apply_at(row, committed.revision);
                        }
                        drop(table);
                        leases.changed();
                    }
                    round.expired += count;
                    let count = u64::try_from(count).unwrap_or(u64::MAX);
                    metrics::EXPIRED.add(count);
                    metrics::HISTORY_WRITTEN.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
                }
                Err(StoreError::PreconditionFailed(failures))
                    if failures
                        .iter()
                        .all(|failure| matches!(failure, FailedPrecondition::Version { .. })) =>
                {
                    round.raced += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(round)
    }
}

#[async_trait::async_trait]
impl LeaderService for ExpiryService {
    fn name(&self) -> &'static str {
        "dhcp.expiry"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        loop {
            match self.round(epoch, Timestamp::now()).await {
                Ok(_) => {}
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err("another controller took office; expiry stops here".to_owned());
                }
                Err(error) => tracing::warn!(%error, "a lease expiry round failed"),
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.settings.period) => {}
            }
        }
    }
}
