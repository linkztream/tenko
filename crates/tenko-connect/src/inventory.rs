//! Inventory sources (CONN-02 to CONN-04).

use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenko_core::{Timestamp, observe::ObservedHost};

use crate::{Connector, ConnectorError};

/// Supplies observed hosts: name, MACs, IPs, OS, platform, parent host and tags.
#[async_trait::async_trait]
pub trait InventorySource: Connector {
    /// Polls the source. With a cursor from the previous batch the source may return only
    /// changes; without one it returns everything and sets `complete`.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`]; the scheduler backs off and retries.
    async fn poll(&self, cursor: Option<Cursor>) -> Result<InventoryBatch, ConnectorError>;

    /// The webhook handler, for sources that push changes.
    fn webhook(&self) -> Option<Arc<dyn WebhookHandler>> {
        None
    }
}

/// One poll result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryBatch {
    /// When the source produced the data.
    pub observed_at: Timestamp,
    /// The hosts.
    pub hosts: Vec<ObservedHost>,
    /// Whether this is the full inventory: hosts absent from it are gone.
    pub complete: bool,
    /// Where the next poll continues.
    #[serde(default)]
    pub cursor: Option<Cursor>,
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

/// Verifies and parses webhook calls of one source.
#[async_trait::async_trait]
pub trait WebhookHandler: Send + Sync + 'static {
    /// Verifies the call (signature or shared secret) and turns it into hosts. `None`
    /// means the call carried nothing relevant.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Unauthorized`] for a call that fails verification, or
    /// [`ConnectorError::Protocol`] for one that does not parse.
    async fn handle(
        &self,
        request: WebhookRequest,
    ) -> Result<Option<InventoryBatch>, ConnectorError>;
}
