//! Format 4: the Phase 3 contract format (WP7.0), an empty migration.
//!
//! The DHCP contracts add values that a binary of format 3 cannot read: the namespace
//! `dhcp` of table names, audit actions and error codes (a format 3 binary refuses a
//! `dhcp.*` table name when it decodes the journal, a snapshot or an audit record), the
//! object kinds `dhcp_scope`, `dhcp_class`, `dhcp_policy`, `dhcp_option_def` and
//! `dhcp_filter`, and the system component `dhcp` (ADR 0019 point 11). A binary of format 3
//! must therefore not open a directory that Phase 3 wrote; the format is raised once for the
//! phase, and the tables that later Phase 3 packages add in the namespace (`dhcp.leases6`,
//! `dhcp.pd_pools`) are additive and need no format of their own.
//!
//! Nothing stored in format 3 changes meaning, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 3 to format 4.
pub struct V4;

impl Migration for V4 {
    fn to(&self) -> u32 {
        4
    }

    fn summary(&self) -> &'static str {
        "raises the format to 4, the Phase 3 contract format, so that a format 3 binary refuses a \
         Phase 3 data directory (the dhcp namespace of tables, actions and codes, the DHCP object \
         kinds and the system component dhcp); no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        ObjectKind, RequestCtx, SystemComponent, codec::key::encode_key, dhcp::tables::SCOPES,
    };
    use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

    use super::*;

    #[test]
    fn the_migration_produces_format_4() {
        assert_eq!(V4.to(), 4);
        assert!(V4.summary().contains("Phase 3"));
        // The values the format exists for.
        assert!(tenko_core::names::is_valid_name("dhcp.leases.by_client"));
        assert_eq!(
            "dhcp_scope".parse::<ObjectKind>(),
            Ok(ObjectKind::DhcpScope)
        );
        assert_eq!(SystemComponent::Dhcp.as_str(), "dhcp");
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V4.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }

    #[tokio::test]
    async fn a_store_with_dhcp_rows_plans_no_mutations_either() {
        let store = MemStore::default();
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Dhcp));
        batch.put(SCOPES.name().clone(), encode_key(&1u64), vec![0xa0]);
        store.propose(batch).await.expect("propose");
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V4.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
