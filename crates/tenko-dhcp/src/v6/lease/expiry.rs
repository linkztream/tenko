//! DHCPv6 lease expiry as the leader service `dhcp.expiry6` (plan section 2.1): the rules
//! of [`crate::lease::ExpiryService`] over `dhcp.leases6`. Every round finds the bindings
//! past their valid lifetime and the abandoned addresses past their hold, in the role's
//! table when it has one, else by a scan, and writes them as `expired` in batches under
//! the leader fence with a version precondition per row and a history row each; a
//! renewal committed in between makes the batch fail and the rows are tried again.

use std::{net::Ipv6Addr, sync::Arc};

use tenko_core::{
    NodeId, Principal, SystemComponent, Timestamp, VrfId,
    cluster::LeaderService,
    dhcp::{BindingState, Lease6, Lease6Event, LeaseEventKind, tables},
};
use tenko_store::{
    FailedPrecondition, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use super::{super::engine::offers::Offers6, SharedLeases6};
use crate::lease::{ExpirySettings, expiry::ExpiryRound, follow::PAGE, metrics};

/// The DHCPv6 expiry leader service (`dhcp.expiry6`).
#[derive(Clone)]
pub struct Expiry6Service {
    store: Arc<dyn Store>,
    node: NodeId,
    settings: ExpirySettings,
    leases: Option<SharedLeases6>,
    offers: Option<Arc<Offers6>>,
}

impl std::fmt::Debug for Expiry6Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Expiry6Service")
            .field("node", &self.node)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The row of `lease` after its expiry at `now`, written by `node`.
pub fn expired6(lease: &Lease6, node: NodeId, now: Timestamp) -> Lease6 {
    Lease6 {
        state: BindingState::Expired,
        ends: now,
        preferred_ends: lease.preferred_ends.min(now),
        node,
        ..lease.clone()
    }
}

fn is_due(lease: &Lease6, now: Timestamp) -> bool {
    matches!(lease.state, BindingState::Active | BindingState::Abandoned) && lease.ends <= now
}

impl Expiry6Service {
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

    /// Finds the due rows in the role's table and applies the expired rows to it.
    #[must_use]
    pub fn with_table(mut self, leases: SharedLeases6) -> Self {
        self.leases = Some(leases);
        self
    }

    /// Prunes this offer hold every round.
    #[must_use]
    pub fn with_offers(mut self, offers: Arc<Offers6>) -> Self {
        self.offers = Some(offers);
        self
    }

    fn due(
        &self,
        view: &dyn ReadView,
        now: Timestamp,
    ) -> Result<Vec<(VrfId, Ipv6Addr)>, StoreError> {
        if let Some(leases) = &self.leases {
            return Ok(leases.read().due(now));
        }
        let mut due = Vec::new();
        let mut range = KeyRange::all();
        loop {
            let page = view.scan_typed(&tables::LEASES6, range.clone(), PAGE, false)?;
            let full = page.len() == PAGE;
            let Some((last, _, _)) = page.last() else {
                break;
            };
            let last = tables::LEASES6.key(last);
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
    /// A store error other than a row that changed meanwhile; a failed fence ends the
    /// round with [`StoreError::PreconditionFailed`].
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
                let Some((lease, revision)) = view.get_typed(&tables::LEASES6, key)? else {
                    continue;
                };
                if !is_due(&lease, now) {
                    continue;
                }
                let row = expired6(&lease, self.node, now);
                let event = Lease6Event::of(&row, LeaseEventKind::Expired, now);
                batch.expect_typed(&tables::LEASES6, key, Some(revision));
                batch.put_typed(&tables::LEASES6, key, &row)?;
                batch.put_typed(&tables::HISTORY6, &(now, key.0, key.1), &event)?;
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
impl LeaderService for Expiry6Service {
    fn name(&self) -> &'static str {
        "dhcp.expiry6"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        loop {
            match self.round(epoch, Timestamp::now()).await {
                Ok(_) => {}
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err("another controller took office; expiry stops here".to_owned());
                }
                Err(error) => tracing::warn!(%error, "a DHCPv6 lease expiry round failed"),
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.settings.period) => {}
            }
        }
    }
}
