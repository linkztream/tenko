//! DHCPv6 lease expiry as the leader service `dhcp.expiry6` (plan section 2.1): the rules
//! of [`crate::lease::ExpiryService`] over `dhcp.leases6`. Every round finds the bindings
//! past their valid lifetime and the abandoned addresses past their hold, in the role's
//! table when it has one, else by a scan, and writes them as `expired` in batches under
//! the leader fence with a version precondition per row and a history row each; a
//! renewal committed in between makes the batch fail and the rows are tried again.
//!
//! The same service deletes the rows that ended ([`Expiry6Service::delete_ended`]): a
//! released or expired row (an abandoned one is expired at the end of its hold first) whose
//! names the DDNS worker has removed, once a round period has passed since it ended. Nothing
//! in an IPv6 network bounds the rows otherwise, since a client may invent a DUID per
//! request. In a scope that holds its `bindings_per_scope` rows the hold of an abandoned
//! (declined) row yields: it is deleted as an ended row is, so a burst of DECLINEs under
//! invented DUIDs keeps no new client out once its host has gone. Its address is parked for
//! no client in the offer table ([`Offers6::park`]) until the hold would have ended, so it
//! goes to no client meanwhile. A park takes only a free slot and gives way to any client's
//! offer, so it never costs a client its offer; under pressure, as at a restart, it is not
//! kept and the address may be offered again. Each batch
//! only deletes (at most [`DELETES_PER_BATCH`] rows), under the leader fence and the version
//! of every row, so a commit in between keeps its row; the history keeps the whole event.
//! While the clock guard holds the clock nothing is deleted.

use std::{net::Ipv6Addr, sync::Arc};

use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
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

/// The most rows one deletion batch deletes: a delete and its version precondition encode
/// in under 128 octets, so a batch stays under half of 256 KiB.
pub const DELETES_PER_BATCH: usize = 1_024;

/// The rows a scope holds at most in force (`bindings_per_scope`; 0: off).
pub type Ceiling = Arc<dyn Fn() -> u32 + Send + Sync>;

/// The DHCPv6 expiry leader service (`dhcp.expiry6`).
#[derive(Clone)]
pub struct Expiry6Service {
    store: Arc<dyn Store>,
    node: NodeId,
    settings: ExpirySettings,
    leases: Option<SharedLeases6>,
    offers: Option<Arc<Offers6>>,
    ceiling: Option<Ceiling>,
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

/// Whether `lease` ended at least `after` before `now` and holds no name: a row DDNS has
/// nothing left to remove for. The wait gives the DDNS worker, whose window is 100 ms, the
/// time to record names it was still writing when the row ended.
fn is_ended(lease: &Lease6, now: Timestamp, after: std::time::Duration) -> bool {
    !matches!(lease.state, BindingState::Active | BindingState::Abandoned)
        && lease.ddns.forward.is_none()
        && lease.ddns.reverse.is_none()
        && lease.ends <= now
        && now.saturating_since(lease.ends) >= after
}

/// Whether `lease` is deleted at `now`: ended ([`is_ended`]), or an abandoned row of a scope
/// in `full` declined at least `after` ago that holds no name.
fn is_gone(lease: &Lease6, now: Timestamp, after: std::time::Duration, full: &[PrefixId]) -> bool {
    is_ended(lease, now, after)
        || (lease.state == BindingState::Abandoned
            && full.contains(&lease.scope)
            && lease.ddns.forward.is_none()
            && lease.ddns.reverse.is_none()
            && now.saturating_since(lease.cltt) >= after)
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
            ceiling: None,
        }
    }

    /// Lets the hold of abandoned rows yield in a scope that holds `ceiling` rows; needs
    /// the role's table, which counts them.
    #[must_use]
    pub fn with_ceiling(mut self, ceiling: Ceiling) -> Self {
        self.ceiling = Some(ceiling);
        self
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

    /// The keys of the rows `keep` selects, from the role's table when there is one, else
    /// by a scan.
    fn select(
        &self,
        view: &dyn ReadView,
        keep: impl Fn(&Lease6) -> bool,
    ) -> Result<Vec<(VrfId, Ipv6Addr)>, StoreError> {
        if let Some(leases) = &self.leases {
            return Ok(leases.read().select(keep));
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
                    .filter(|(_, lease, _)| keep(lease))
                    .map(|(key, _, _)| *key),
            );
            if !full {
                break;
            }
            range = KeyRange::all().after(last);
        }
        Ok(due)
    }

    /// One round at `now` under the leader `epoch`; nothing is due while the clock guard
    /// holds the clock.
    ///
    /// # Errors
    ///
    /// A store error other than a row that changed meanwhile; a failed fence ends the
    /// round with [`StoreError::PreconditionFailed`].
    pub async fn round(&self, epoch: u64, now: Timestamp) -> Result<ExpiryRound, StoreError> {
        if let Some(offers) = &self.offers {
            offers.prune(now);
        }
        if let Err(held) = tenko_core::clock::trusted_now() {
            tracing::debug!(?held, "the clock is held: no DHCPv6 lease expires");
            return Ok(ExpiryRound::default());
        }
        let view = self.store.read(ReadConsistency::Local).await?;
        let keys = self.select(view.as_ref(), |lease| is_due(lease, now))?;
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

    /// Deletes the rows that ended at `now` under the leader `epoch` (see the module
    /// documentation); returns how many. Nothing is deleted while the clock guard holds the
    /// clock.
    ///
    /// # Errors
    ///
    /// A store error other than a row that changed meanwhile; a failed fence ends the
    /// pass with [`StoreError::PreconditionFailed`].
    pub async fn delete_ended(&self, epoch: u64, now: Timestamp) -> Result<usize, StoreError> {
        if let Err(held) = tenko_core::clock::trusted_now() {
            tracing::debug!(?held, "the clock is held: no ended DHCPv6 lease is deleted");
            return Ok(0);
        }
        let after = self.settings.period;
        let full = match (&self.leases, &self.ceiling) {
            (Some(leases), Some(ceiling)) => leases.read().full_scopes(ceiling()),
            _ => Vec::new(),
        };
        let view = self.store.read(ReadConsistency::Local).await?;
        let keys = self.select(view.as_ref(), |lease| is_gone(lease, now, after, &full))?;
        let mut deleted = 0;
        for chunk in keys.chunks(self.settings.batch.clamp(1, DELETES_PER_BATCH)) {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
            batch.preconditions.push(fence(epoch));
            let mut gone = Vec::with_capacity(chunk.len());
            for key in chunk {
                if let Some((lease, revision)) = view.get_typed(&tables::LEASES6, key)?
                    && is_gone(&lease, now, after, &full)
                {
                    batch.expect_typed(&tables::LEASES6, key, Some(revision));
                    batch.delete_typed(&tables::LEASES6, key);
                    let held = (lease.state == BindingState::Abandoned)
                        .then_some((lease.scope, lease.ends));
                    gone.push((*key, revision, held));
                }
            }
            if gone.is_empty() {
                continue;
            }
            match self.store.propose(batch).await {
                Ok(_) => {
                    if let Some(leases) = &self.leases {
                        // Only the row deleted: one a later commit wrote stays (the feed's
                        // copy of the delete comes before it in any case).
                        let mut table = leases.write();
                        for ((vrf, addr), revision, _) in &gone {
                            if table
                                .row_revision(*vrf, *addr)
                                .is_some_and(|held| held <= *revision)
                            {
                                table.take(*vrf, *addr);
                            }
                        }
                        drop(table);
                        leases.changed();
                    }
                    // A yielded declined address goes to no client until its hold ends.
                    if let Some(offers) = &self.offers {
                        for ((_, addr), _, held) in &gone {
                            if let Some((scope, ends)) = held {
                                offers.park(*scope, *addr, *ends, now);
                            }
                        }
                    }
                    deleted += gone.len();
                }
                Err(StoreError::PreconditionFailed(failures))
                    if failures
                        .iter()
                        .all(|failure| matches!(failure, FailedPrecondition::Version { .. })) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(deleted)
    }
}

#[async_trait::async_trait]
impl LeaderService for Expiry6Service {
    fn name(&self) -> &'static str {
        "dhcp.expiry6"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        loop {
            let now = Timestamp::now();
            match self.round(epoch, now).await {
                Ok(_) => {}
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err("another controller took office; expiry stops here".to_owned());
                }
                Err(error) => tracing::warn!(%error, "a DHCPv6 lease expiry round failed"),
            }
            match self.delete_ended(epoch, now).await {
                Ok(_) => {}
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err("another controller took office; expiry stops here".to_owned());
                }
                Err(error) => tracing::warn!(%error, "ended DHCPv6 leases could not be deleted"),
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.settings.period) => {}
            }
        }
    }
}
