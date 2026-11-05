//! Format 6: the Phase 4 contract format (WP14.0), an empty migration.
//!
//! The contracts of the Windows takeover add values that a binary of format 5 cannot read:
//! the namespace `migrate` of table names, audit actions and error codes (a format 5 binary
//! refuses a `migrate.*` name when it decodes the journal, a snapshot or an audit record,
//! because `tenko_core::names::NAMESPACES` does not hold the namespace), the object kinds
//! `mirror` and `takeover` in audit records, and the token scope `mirror:<id>` in a scoped
//! token record (`docs/plans/windows-takeover-plan.md` section 3.1, ADR 0033). A binary of
//! format 5 must therefore not open a directory that Phase 4 wrote; the format is raised
//! once for the phase, and the tables that later Phase 4 packages add in the namespace are
//! additive and need no format of their own. The cold field `adopted` of a lease row is a
//! serde default, like `granted` (ADR 0031), and needs no format.
//!
//! Nothing stored in format 5 changes meaning, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 5 to format 6.
pub struct V6;

impl Migration for V6 {
    fn to(&self) -> u32 {
        6
    }

    fn summary(&self) -> &'static str {
        "raises the format to 6, the Phase 4 contract format, so that a format 5 binary refuses a \
         Phase 4 data directory (the migrate namespace of tables, actions and codes, the object \
         kinds mirror and takeover, the token scope mirror:<id>); no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{ObjectKind, names::is_valid_name};
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    #[test]
    fn the_migration_produces_format_6() {
        assert_eq!(V6.to(), 6);
        assert!(V6.summary().contains("migrate"));
        // The values the format exists for.
        assert!(is_valid_name("migrate.mirrors"));
        assert_eq!(
            serde_json::to_string(&ObjectKind::Mirror).expect("json"),
            "\"mirror\""
        );
        assert_eq!(
            serde_json::to_string(&ObjectKind::Takeover).expect("json"),
            "\"takeover\""
        );
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V6.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
