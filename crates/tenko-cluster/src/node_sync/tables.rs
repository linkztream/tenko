//! The store tables of the node sync.
//!
//! | Table | Key | Value | Written by |
//! |---|---|---|---|
//! | `cluster.node_commands` | (node id, command id) | [`CommandRecord`] | scan jobs, the kill switch, node reports |
//! | `cluster.ingest_cursors` | node id | [`IngestCursor`] | the `Observations` service |
//! | `scan.run_results` | (command id, batch sequence) | [`RunResult`] | the `Observations` service, for batches tagged with a command |
//! | `scan.probe_config` | node id | the probe configuration (`tenko_scan::control`) | the API, a node's offer |
//!
//! The configuration of a node is the set of rows keyed by its node id in the tables of
//! [`CONFIG_TABLES`] whose role it has. Each such row is a CBOR map; a field `secrets`
//! (a list of [`SecretUse`](super::secrets::SecretUse)) names the vault secrets the node may
//! fetch with `Config.Secrets`.

use tenko_core::{Role, TableName, table::TableDef};
use uuid::Uuid;

use super::{
    commands::{CommandRecord, RunResult},
    cursors::IngestCursor,
};

/// Commands to nodes by (node id, command id); command ids are UUIDv7, so a node's
/// commands scan in the order they were issued.
pub const NODE_COMMANDS: TableDef<(u64, Uuid), CommandRecord> =
    TableDef::new("cluster.node_commands");

/// The last batch ingested from each node: (epoch, sequence).
pub const INGEST_CURSORS: TableDef<u64, IngestCursor> = TableDef::new("cluster.ingest_cursors");

/// What the batches of an on-demand scan reported, by (command id, batch sequence), so the
/// scan job can compare it with the facts from before the scan.
pub const RUN_RESULTS: TableDef<(Uuid, u64), RunResult> = TableDef::new("scan.run_results");

/// The probe configuration of each probe node, keyed by node id.
pub const PROBE_CONFIG: TableName = TableName::from_static("scan.probe_config");

/// A table that holds part of the configuration of nodes with a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigTable {
    /// The table; keys are node ids.
    pub table: TableName,
    /// The role whose nodes receive its rows.
    pub role: Role,
}

/// The tables that make up node configurations. DNS and DHCP nodes (Phases 2 and 3) add
/// their tables here.
pub const CONFIG_TABLES: [ConfigTable; 1] = [ConfigTable {
    table: PROBE_CONFIG,
    role: Role::Probe,
}];

/// The configuration tables a node with `roles` receives.
pub fn tables_for(roles: &[Role]) -> Vec<TableName> {
    CONFIG_TABLES
        .iter()
        .filter(|table| roles.contains(&table.role))
        .map(|table| table.table.clone())
        .collect()
}
