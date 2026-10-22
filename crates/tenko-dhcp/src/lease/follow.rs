//! The lease table derived from the rows (plan section 2.2): an image at a revision, the
//! deltas in revision order, a new image after a snapshot install.
//!
//! [`LeaseFollower`] keeps a [`SharedLeases`] equal to `dhcp.leases` from a
//! [`DhcpFeed`](crate::feed::DhcpFeed): [`LeaseFollower::install`] builds a table aside from
//! an image and swaps it in whole; [`LeaseFollower::apply`] applies the lease rows of a
//! delta at the delta's revision. The committer has applied the role's own commits already;
//! the feed's copy of them changes nothing, and an older copy never overwrites a newer row
//! (the revision rule of [`LeaseIndex::apply_at`]). A delta that does not follow the
//! revision the follower holds is a gap (`FeedError::Gap`); the role then asks the feed for
//! a new image.
//!
//! [`rebuild_from_view`] builds the table straight from a store view, page by page: the
//! start of a node before its feed runs, and the measurement of the plan's acceptance (a
//! 100,000-lease table in under 5 seconds, `bench/phase3-dhcp/results`).

use tenko_core::{Revision, dhcp::tables};
use tenko_store::{KeyRange, ReadView, StoreError};

use super::table::{LeaseIndex, SharedLeases};
use crate::feed::{Change, Delta, DhcpData, DhcpFeed, FeedError, FeedEvent};

/// Rows read per scan while a table is rebuilt from the store.
pub const PAGE: usize = 4_096;

/// A table built from an image of the feed: every row at the image's revision.
pub fn index_from_data(data: &DhcpData) -> LeaseIndex {
    LeaseIndex::from_rows(
        data.leases
            .values()
            .map(|lease| (lease.clone(), data.revision)),
        data.revision,
    )
}

/// Builds the lease table from the rows of `dhcp.leases` in `view`, each at the revision
/// that wrote it.
///
/// # Errors
///
/// A storage or decoding failure of the scan.
pub fn rebuild_from_view(view: &dyn ReadView) -> Result<LeaseIndex, StoreError> {
    let mut table = LeaseIndex::new();
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(tables::LEASES.name(), range.clone(), PAGE, false)?;
        let Some((last, _)) = page.last() else {
            break;
        };
        let last = last.clone();
        let full = page.len() == PAGE;
        for (_, versioned) in page {
            let lease = tables::LEASES.decode(&versioned.value)?;
            table.apply_at(lease, versioned.revision);
        }
        if !full {
            break;
        }
        range = KeyRange::all().after(last);
    }
    table.advance(view.revision());
    Ok(table)
}

/// Keeps a shared lease table equal to the rows a feed delivers.
#[derive(Debug, Clone)]
pub struct LeaseFollower {
    leases: SharedLeases,
    held: Revision,
}

impl LeaseFollower {
    /// A follower of `leases`, holding nothing yet.
    pub fn new(leases: SharedLeases) -> Self {
        Self {
            leases,
            held: Revision::ZERO,
        }
    }

    /// The table it keeps.
    pub fn leases(&self) -> &SharedLeases {
        &self.leases
    }

    /// The feed revision it holds.
    pub fn held(&self) -> Revision {
        self.held
    }

    /// Replaces the table with one built from `data`, aside, then swapped whole. Rows the
    /// table holds from commits after the image's revision (the role's own, applied before
    /// the feed delivers them) are carried over, so no committed lease is missing from the
    /// table between the swap and the deltas that follow the image.
    pub fn install(&mut self, data: &DhcpData) {
        let mut table = index_from_data(data);
        let newer = self.leases.read().rows_after(data.revision);
        for (lease, revision) in newer {
            table.apply_at(lease, revision);
        }
        self.held = data.revision;
        self.leases.install(table);
    }

    /// Applies the lease rows of a delta that follows the revision held.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] when the delta does not start at the revision held; nothing is
    /// applied.
    pub fn apply(&mut self, delta: &Delta) -> Result<(), FeedError> {
        if delta.from != self.held || delta.to <= delta.from {
            return Err(FeedError::Gap {
                held: self.held,
                from: delta.from,
            });
        }
        {
            let mut table = self.leases.write();
            for change in &delta.changes {
                if let Change::Lease((vrf, addr), value) = change {
                    match value {
                        Some(lease) => {
                            table.apply_at(lease.clone(), delta.to);
                        }
                        None => {
                            table.take(*vrf, *addr);
                        }
                    }
                }
            }
            table.advance(delta.to);
        }
        self.held = delta.to;
        self.leases.changed();
        Ok(())
    }

    /// Applies one event of the feed.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] as [`LeaseFollower::apply`].
    pub fn on_event(&mut self, event: &FeedEvent) -> Result<(), FeedError> {
        match event {
            FeedEvent::Delta(delta) => self.apply(delta),
            FeedEvent::Reset(data) => {
                self.install(data);
                Ok(())
            }
        }
    }

    /// Installs the feed's image, then follows its events until the feed closes; a gap
    /// reads a new image.
    ///
    /// # Errors
    ///
    /// The feed's error when it fails or closes.
    pub async fn follow<F: DhcpFeed>(&mut self, feed: &mut F) -> Result<(), FeedError> {
        let data = feed.snapshot().await?;
        self.install(&data);
        loop {
            let event = feed.next().await?;
            if let Err(FeedError::Gap { .. }) = self.on_event(&event) {
                let data = feed.snapshot().await?;
                self.install(&data);
            }
        }
    }
}
