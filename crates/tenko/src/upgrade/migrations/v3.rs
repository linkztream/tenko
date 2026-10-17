//! Format 3: the Phase 2 contract format (WP4.0), an empty migration.
//!
//! The DNS contracts add values that a binary of format 2 cannot read: the namespace `dns`
//! of table names, audit actions and error codes (a format 2 binary refuses a `dns.*` table
//! name when it decodes the journal, a snapshot or an audit record), the object kinds `zone`,
//! `dns_view`, `dns_forwarder`, `dns_acl`, `dns_key` and `dns_list`, and the system
//! component `dns`. A binary of format 2 must therefore not open a directory that Phase 2
//! wrote; the format is raised once for the phase, and the tables that later Phase 2
//! packages add in the namespace are additive and need no format of their own.
//!
//! Nothing stored in format 2 changes meaning, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 2 to format 3.
pub struct V3;

impl Migration for V3 {
    fn to(&self) -> u32 {
        3
    }

    fn summary(&self) -> &'static str {
        "raises the format to 3, the Phase 2 contract format, so that a format 2 binary refuses a \
         Phase 2 data directory (the dns namespace of tables, actions and codes, the DNS object \
         kinds and the system component dns); no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        ObjectKind, RequestCtx, SystemComponent, codec::key::encode_key, dns::tables::ZONES,
    };
    use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

    use super::*;

    #[test]
    fn the_migration_produces_format_3() {
        assert_eq!(V3.to(), 3);
        assert!(V3.summary().contains("Phase 2"));
        // The values the format exists for.
        assert!(tenko_core::names::is_valid_name("dns.zones"));
        assert_eq!("zone".parse::<ObjectKind>(), Ok(ObjectKind::Zone));
        assert_eq!(SystemComponent::Dns.as_str(), "dns");
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V3.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }

    #[tokio::test]
    async fn a_store_with_dns_rows_plans_no_mutations_either() {
        let store = MemStore::default();
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Dns));
        batch.put(ZONES.name().clone(), encode_key(&1u64), vec![0xa0]);
        store.propose(batch).await.expect("propose");
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V3.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
