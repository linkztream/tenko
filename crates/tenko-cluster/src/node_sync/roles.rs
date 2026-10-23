//! The stored role set of each node (OPS-01): which roles a node runs from its next start.
//!
//! `nodes.roles` holds one row per node, keyed by node id, written by
//! `PUT /api/v1/nodes/{id}/roles` and seeded by a controller from the `roles` of its own
//! `tenko.toml` at its first start. Every node receives its own row through the
//! configuration stream, whatever its roles ([`super::tables::EVERY_NODE_TABLES`]); a
//! controller reads its row from the store. Unless `--roles` pins the set on the command
//! line, the stored set decides over the file's at start, and a change to it makes the node
//! restart through its service manager.

use serde::{Deserialize, Serialize};
use tenko_core::{Role, RoleSet, Timestamp, table::TableDef};

/// The stored role set of each node, keyed by node id.
pub const NODE_ROLES: TableDef<u64, NodeRolesRecord> = TableDef::new("nodes.roles");

/// Where a stored role set came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolesOrigin {
    /// The `roles` of the node's own `tenko.toml`, written at its first start.
    Seed,
    /// An administrator, through the API.
    Api,
}

/// One row of [`NODE_ROLES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRolesRecord {
    /// The roles, in canonical order.
    pub roles: Vec<Role>,
    /// Where they came from.
    pub origin: RolesOrigin,
    /// When they were written.
    pub changed_at: Timestamp,
}

impl NodeRolesRecord {
    /// A record of `roles`.
    pub fn new(roles: RoleSet, origin: RolesOrigin, changed_at: Timestamp) -> Self {
        Self {
            roles: roles.roles().collect(),
            origin,
            changed_at,
        }
    }

    /// The roles as a set.
    pub fn role_set(&self) -> RoleSet {
        self.roles.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::codec::{from_cbor, to_cbor};

    use super::*;

    #[test]
    fn a_record_round_trips_in_canonical_order() {
        let roles: RoleSet = "dns,controller".parse().expect("roles");
        let record = NodeRolesRecord::new(roles, RolesOrigin::Seed, Timestamp::UNIX_EPOCH);
        assert_eq!(record.roles, [Role::Controller, Role::Dns]);
        let bytes = to_cbor(&record).expect("encode");
        let back: NodeRolesRecord = from_cbor(&bytes).expect("decode");
        assert_eq!(back, record);
        assert_eq!(back.role_set(), roles);
    }
}
