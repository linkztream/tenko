//! Migration sources (ADR 0006, MIG-01): canonical IR plus a loss report. Drivers arrive in
//! Phase 4; the spreadsheet import of Slice 1 produces the same pair.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tenko_core::{
    ir::{Ir, LossReport},
    net::Fqdn,
};

use crate::{Connector, ConnectorError};

/// Reads a system to migrate from.
#[async_trait::async_trait]
pub trait MigrationSource: Connector {
    /// Reads the scope into IR and reports what could not be mapped.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn read(&self, scope: &MigrationScope) -> Result<(Ir, LossReport), ConnectorError>;
}

/// What to read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationScope {
    /// Areas to read; empty means everything the source has.
    #[serde(default)]
    pub areas: BTreeSet<MigrationArea>,
    /// DNS zones to read; empty means all.
    #[serde(default)]
    pub zones: Vec<Fqdn>,
}

/// Areas of a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationArea {
    /// Networks, VLANs, hosts and addresses.
    Ipam,
    /// Zones and records.
    Dns,
    /// Scopes, reservations and options.
    Dhcp,
}
