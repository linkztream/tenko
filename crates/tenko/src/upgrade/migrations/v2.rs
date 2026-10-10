//! Format 2: the Slice 3 contract format, an empty migration.
//!
//! Slice 3 adds values to enums that are stored: the system components `audit_export`,
//! `backup`, `languages` and `leader`, and the role `auditor`. A binary of format 1 would
//! fail to decode those values, or would treat the role as unknown, so it must not open a
//! directory that Slice 3 wrote. The format is therefore raised once, for the whole slice,
//! and a binary of format 1 refuses the directory with `upgrade.format_newer`. The tables
//! that later Slice 3 packages add are additive and need no format of their own.
//!
//! Nothing stored in format 1 changes meaning, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record, which is all
//! that format 2 takes.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 1 to format 2.
pub struct V2;

impl Migration for V2 {
    fn to(&self) -> u32 {
        2
    }

    fn summary(&self) -> &'static str {
        "raises the format to 2, the Slice 3 contract format, so that a Slice 2 binary refuses \
         a Slice 3 data directory (new stored enum values: the system components audit_export, \
         backup, languages and leader, and the role auditor); no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    #[test]
    fn the_migration_produces_format_2() {
        assert_eq!(V2.to(), 2);
        assert!(V2.summary().contains("Slice 3"));
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V2.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
