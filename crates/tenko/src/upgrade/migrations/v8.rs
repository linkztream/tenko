//! Format 8: a DNS zone records whether it is served (ADR 0038), an empty migration.
//!
//! A DNS zone records whether this node serves it (`Zone::served`). A takeover run creates
//! its zones unserved: they refresh from the domain's controllers and answer nothing until a
//! flip serves them. A row written before reads as served, so the new binary reads every old
//! row as it is. A binary of format 7 ignores the key and would answer for an unserved zone,
//! so it must not open a directory that may hold one. Nothing is rewritten: the runner still
//! commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 7 to format 8.
pub struct V8;

impl Migration for V8 {
    fn to(&self) -> u32 {
        8
    }

    fn summary(&self) -> &'static str {
        "raises the format to 8, in which a DNS zone records whether it is served, so that a \
         format 7 binary refuses a data directory that may hold an unserved DNS zone (dns.zones, \
         served), which it would answer for; no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    #[tokio::test]
    async fn the_migration_produces_format_8_and_changes_no_row() {
        assert_eq!(V8.to(), 8);
        assert!(V8.summary().contains("served"));
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V8.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
