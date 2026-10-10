//! A probe's offer of its own `[scan]` section as its initial configuration (OPS-28).
//!
//! At its first connection a probe without a stored configuration offers its file's,
//! without passwords ([`ScanConfig::offer_form`]). The controller keeps it only when it
//! holds none for the probe, after the checks of an edit through the API, with the audit
//! record `scan.config.offer` under the node's principal. From then on the stored
//! configuration wins.

use async_trait::async_trait;
use tenko_cluster::{
    error::ClusterError,
    model::NodeRecord,
    node_sync::{OfferHandler, codes as sync_codes, payload, store_error},
};
use tenko_core::{ObjectRef, Principal, RequestCtx, Timestamp, audit::AuditDraft};
use tenko_store::{ReadConsistency, ReadViewExt, StoreError, WriteBatch};

use super::{
    Shared, actions,
    model::{ProbeConfigOrigin, ProbeConfigRecord, tables::PROBE_CONFIG},
    secret_uses,
};
use crate::config::ScanConfig;

/// The table the offers are for (`tenko_cluster::node_sync::tables::PROBE_CONFIG`).
pub(crate) const TABLE: &str = "scan.probe_config";

/// The handler of offers for `scan.probe_config`.
pub(crate) struct Offers {
    shared: Shared,
}

impl Offers {
    pub(crate) fn new(shared: Shared) -> Self {
        Self { shared }
    }
}

/// Decodes and checks an offered configuration.
///
/// # Errors
///
/// `node.config.payload` (400) for bytes that do not decode, `node.config.invalid` (422)
/// for a configuration that does not validate as a stored one.
pub fn decode_offer(encoding: &str, bytes: &[u8]) -> Result<ScanConfig, ClusterError> {
    if encoding != payload::CBOR {
        return Err(ClusterError::new(
            sync_codes::CONFIG_ENCODING,
            400,
            format!(
                "the offer encoding `{}` is not one this controller knows",
                encoding.chars().take(40).collect::<String>()
            ),
        ));
    }
    if bytes.len() > payload::MAX_ARGS_BYTES * 16 {
        return Err(ClusterError::new(
            sync_codes::CONFIG_PAYLOAD,
            400,
            "the offered configuration is too large",
        ));
    }
    let config: ScanConfig = tenko_core::codec::from_cbor(bytes).map_err(|error| {
        ClusterError::new(
            sync_codes::CONFIG_PAYLOAD,
            400,
            format!("the offered configuration does not decode: {error}"),
        )
    })?;
    config.validate_stored().map_err(|error| {
        ClusterError::new(sync_codes::CONFIG_INVALID, 422, error.detail().to_owned())
    })?;
    Ok(config)
}

#[async_trait]
impl OfferHandler for Offers {
    fn table(&self) -> &str {
        TABLE
    }

    async fn offer(
        &self,
        node: &NodeRecord,
        encoding: &str,
        bytes: &[u8],
    ) -> Result<bool, ClusterError> {
        let mut config = decode_offer(encoding, bytes)?;
        let store = &self.shared.store;
        let view = store
            .read(ReadConsistency::Local)
            .await
            .map_err(store_error)?;
        if view.get_typed(&PROBE_CONFIG, &node.id.0)?.is_some() {
            return Ok(false);
        }
        drop(view);
        // A node cannot name vault secrets it was never given: those references are
        // dropped, so an administrator picks them.
        for device in &mut config.snmp.devices {
            device.auth_secret = None;
            device.privacy_secret = None;
        }
        let now = Timestamp::now();
        let record = ProbeConfigRecord {
            node: node.id,
            secrets: secret_uses(&config),
            config,
            origin: ProbeConfigOrigin::Offer,
            updated_at: now,
            updated_by: None,
        };
        let ctx = RequestCtx::new(Principal::Node { id: node.id });
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&PROBE_CONFIG, &node.id.0, None);
        batch.put_typed(&PROBE_CONFIG, &node.id.0, &record)?;
        batch.audit(
            AuditDraft::success(actions::CONFIG_OFFER, vec![ObjectRef::node(node.id)])
                .with_context("node", node.name.clone())
                .with_context("prefixes", record.config.prefixes.join(",")),
        );
        match store.propose(batch).await {
            Ok(_) => Ok(true),
            Err(StoreError::PreconditionFailed(_)) => Ok(false),
            Err(error) => Err(store_error(error)),
        }
    }
}
