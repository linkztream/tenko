//! Inventory sources (CONN-02 to CONN-04).

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenko_core::{Timestamp, observe::ObservedHost};

use crate::{CallContext, ConnectorError};

/// Supplies observed hosts: name, MACs, IPs, OS, platform, parent host and tags.
///
/// Implemented by a plugin (capability `inventory`, and `webhook` for
/// [`webhook`](InventorySource::webhook)); the host polls it on the schedule of the
/// connector instance and normalizes the hosts into observations.
#[async_trait::async_trait]
pub trait InventorySource: Send + Sync + 'static {
    /// Polls the source. With a cursor from the previous batch the source may return only
    /// changes; without one it returns everything and sets `complete`. A large inventory
    /// is returned in pages: a batch with `more` set makes the host poll again at once with
    /// the batch's cursor.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`]; the host records the failure and polls again on the
    /// next schedule.
    async fn poll(
        &self,
        ctx: &CallContext,
        cursor: Option<Cursor>,
    ) -> Result<InventoryBatch, ConnectorError>;

    /// Verifies (signature or shared secret) and parses a webhook call the host received
    /// for this instance. `None` means the call carried nothing relevant.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Unauthorized`] for a call that fails verification,
    /// [`ConnectorError::Protocol`] for one that does not parse, and
    /// [`ConnectorError::Unsupported`] (the default) for sources without webhooks.
    async fn webhook(
        &self,
        ctx: &CallContext,
        request: WebhookRequest,
    ) -> Result<Option<InventoryBatch>, ConnectorError> {
        let _ = (ctx, request);
        Err(ConnectorError::Unsupported)
    }
}

/// One poll result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryBatch {
    /// When the source produced the data.
    pub observed_at: Timestamp,
    /// The hosts.
    pub hosts: Vec<ObservedHost>,
    /// Whether this batch, with the pages before it, is the full inventory: hosts absent
    /// from it are gone.
    pub complete: bool,
    /// Where the next poll or page continues.
    #[serde(default)]
    pub cursor: Option<Cursor>,
    /// Another page is ready: poll again at once with `cursor`.
    #[serde(default)]
    pub more: bool,
}

impl InventoryBatch {
    /// A complete batch of one page.
    pub fn complete(observed_at: Timestamp, hosts: Vec<ObservedHost>) -> Self {
        Self {
            observed_at,
            hosts,
            complete: true,
            cursor: None,
            more: false,
        }
    }
}

/// An opaque position in a source's change feed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cursor(pub String);

/// A webhook call as received by the API, before any parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRequest {
    /// Header names (lowercase) and values.
    pub headers: Vec<(String, String)>,
    /// The raw body.
    pub body: Bytes,
}
