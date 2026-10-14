//! The connector instances as the import reads them (`connect.instances`), to know which
//! secrets a connector still references.
//!
//! The table belongs to the connector host (`tenko_connect`); this is a read-only view of
//! the one field the import needs, decoded from the same rows (fields it does not name are
//! ignored), so the IPAM crate does not depend on the connector crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{ConnectorId, SecretId, secret::SecretRef, table::TableDef};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::error::IpamResult;

/// The connector instances by id.
pub const INSTANCES: TableDef<ConnectorId, ConnectorSecrets> = TableDef::new("connect.instances");

/// What the import reads of a connector instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorSecrets {
    /// The instance's secrets by purpose.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
}

/// The ids of the connector instances that reference `secret`, sorted.
///
/// # Errors
///
/// Fails when the table cannot be read or a row cannot be decoded.
pub fn referencing(view: &dyn ReadView, secret: SecretId) -> IpamResult<Vec<ConnectorId>> {
    let mut ids: Vec<ConnectorId> = view
        .scan_typed(&INSTANCES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, instance, _)| instance.secrets.values().any(|r| r.secret == secret))
        .map(|(id, _, _)| id)
        .collect();
    ids.sort();
    Ok(ids)
}
