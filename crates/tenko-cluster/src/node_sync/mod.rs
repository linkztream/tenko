//! Configuration sync to nodes, commands to nodes, ingest cursors and node secrets (OPS-28,
//! SCAN-05, SCAN-09, IAM-16): the controller side of the `Config` and `Commands` services
//! and the parts a node uses to apply what it receives.
//!
//! | Module | Contents |
//! |---|---|
//! | [`codes`] | the error codes of this module |
//! | [`tables`] | the store tables: node commands, ingest cursors, the node configuration tables |
//! | [`payload`] | the wire form of configuration deltas, snapshots and command arguments |
//! | [`rate`] | the token bucket of the bandwidth cap (`[cluster] sync_kbps`) |
//! | [`source`] | the controller side of `Config.Watch`: deltas from the journal, snapshots |
//! | [`commands`] | node commands: records, issue, reports, the pending commands of a node |
//! | [`cursors`] | the last ingested batch of each node, shared by every controller |
//! | [`secrets`] | the secrets a node's configuration names, resolved with audit |
//! | [`local`] | the node side: the configuration on the node's disk, applied atomically |
//! | [`roles`] | the stored role set of each node, which every node receives (node-roles) |
//!
//! [`NodeSync`] bundles what the services need on a controller: the store, the vault (for
//! node secrets) and the bandwidth cap. The `nodes` start step hands it to the node
//! registry, and every service of the cluster port reaches it there.
//!
//! docs/node-sync.md describes the protocol, the payloads and the files.

pub mod codes;
pub mod commands;
pub mod cursors;
pub mod local;
pub mod payload;
pub mod rate;
// node-roles: the stored role set of each node.
pub mod roles;
pub mod secrets;
pub mod source;
pub mod tables;

use std::{
    fmt,
    sync::{Arc, PoisonError, RwLock},
};

use async_trait::async_trait;
use tenko_store::{Store, StoreError};
use tenko_vault::Vault;

use crate::{error::ClusterError, model::NodeRecord};

/// A store error as the node transport reports it: `cluster.no_quorum` (503) when the
/// controller cannot write or confirm a read, the store's own code otherwise.
pub fn store_error(error: StoreError) -> ClusterError {
    match error {
        StoreError::NoQuorum => ClusterError::new(
            codes::NO_QUORUM,
            503,
            "this controller is cut off from the cluster and cannot write; try another one",
        ),
        other => ClusterError::from(other),
    }
}

/// Takes the configuration a node offers as its initial one for one table (a probe's
/// `[scan]` section), checks it like an edit through the API and stores it when the
/// installation holds none for the node. Implemented by the package that owns the table
/// (`tenko_scan::control` for `scan.probe_config`).
#[async_trait]
pub trait OfferHandler: Send + Sync {
    /// The table this handler takes offers for.
    fn table(&self) -> &str;

    /// Takes the offer of `node`; `Ok(false)` when a configuration exists already.
    ///
    /// # Errors
    ///
    /// The coded refusal of a payload that does not decode or does not validate, or a
    /// store error.
    async fn offer(
        &self,
        node: &NodeRecord,
        encoding: &str,
        payload: &[u8],
    ) -> Result<bool, ClusterError>;
}

struct Inner {
    store: Arc<dyn Store>,
    vault: Option<Arc<dyn Vault>>,
    rate_kbps: u64,
    offers: RwLock<Vec<Arc<dyn OfferHandler>>>,
}

/// What the node-sync services of a controller need: the store, the vault and the
/// bandwidth cap per configuration stream. Cheap to clone; clones share their state.
#[derive(Clone)]
pub struct NodeSync {
    inner: Arc<Inner>,
}

impl fmt::Debug for NodeSync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeSync")
            .field("vault", &self.inner.vault.is_some())
            .field("rate_kbps", &self.inner.rate_kbps)
            .finish_non_exhaustive()
    }
}

impl NodeSync {
    /// The services over `store`, without a vault (nodes get no secrets) and without a
    /// bandwidth cap.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                vault: None,
                rate_kbps: 0,
                offers: RwLock::new(Vec::new()),
            }),
        }
    }

    /// With the vault the node secrets come from.
    #[must_use]
    pub fn with_vault(self, vault: Arc<dyn Vault>) -> Self {
        self.rebuild(|inner| inner.vault = Some(vault))
    }

    /// With a bandwidth cap per configuration stream in kilobits per second; 0 is no cap
    /// (`[cluster] sync_kbps`).
    #[must_use]
    pub fn with_rate_kbps(self, kbps: u64) -> Self {
        self.rebuild(|inner| inner.rate_kbps = kbps)
    }

    fn rebuild(self, change: impl FnOnce(&mut Inner)) -> Self {
        let offers = self
            .inner
            .offers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut inner = Inner {
            store: Arc::clone(&self.inner.store),
            vault: self.inner.vault.clone(),
            rate_kbps: self.inner.rate_kbps,
            offers: RwLock::new(offers),
        };
        change(&mut inner);
        Self {
            inner: Arc::new(inner),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.inner.store
    }

    /// The vault, when node secrets are served.
    pub fn vault(&self) -> Option<&Arc<dyn Vault>> {
        self.inner.vault.as_ref()
    }

    /// The bandwidth cap per configuration stream in kilobits per second; 0 is no cap.
    pub fn rate_kbps(&self) -> u64 {
        self.inner.rate_kbps
    }

    /// Adds the handler of offers for one table; a later handler for the same table
    /// replaces the earlier one. Every clone sees it.
    pub fn add_offer_handler(&self, handler: Arc<dyn OfferHandler>) {
        let mut offers = self
            .inner
            .offers
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        offers.retain(|existing| existing.table() != handler.table());
        offers.push(handler);
    }

    /// The handler of offers for `table`, if one is registered.
    pub fn offer_handler(&self, table: &str) -> Option<Arc<dyn OfferHandler>> {
        self.inner
            .offers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|handler| handler.table() == table)
            .cloned()
    }
}

#[cfg(test)]
mod tests;
