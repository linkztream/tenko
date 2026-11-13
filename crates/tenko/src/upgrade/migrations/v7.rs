//! Format 7: the contracts of the cluster recovery (`docs/plans/cluster-recovery-plan.md`
//! section 3.1), an empty migration.
//!
//! A forced step starts a new generation of a cluster's history: it writes the signed
//! generation records of the history (`cluster.generation`, by number) and marks the
//! controllers it superseded (`cluster.superseded`). A binary of format 6 reads neither table: it would open such a
//! store as if nothing had happened, take calls from the superseded controllers and let a
//! superseded controller of its own history write on. The fence is a property of the
//! stored data, so a format 6 binary must not open a directory that may hold it. A store
//! at generation 0 has no row in either table, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 6 to format 7.
pub struct V7;

impl Migration for V7 {
    fn to(&self) -> u32 {
        7
    }

    fn summary(&self) -> &'static str {
        "raises the format to 7, the cluster recovery contract format, so that a format 6 \
         binary refuses a data directory that may hold generation records \
         (cluster.generation) or controllers marked superseded (cluster.superseded); no \
         stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_cluster::generation::{GENERATION, SUPERSEDED};
    use tenko_core::names::is_valid_name;
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    #[test]
    fn the_migration_produces_format_7() {
        assert_eq!(V7.to(), 7);
        assert!(V7.summary().contains("cluster.generation"));
        assert!(is_valid_name(GENERATION.name().as_str()));
        assert!(is_valid_name(SUPERSEDED.name().as_str()));
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V7.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
