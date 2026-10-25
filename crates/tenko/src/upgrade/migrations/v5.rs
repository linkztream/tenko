//! Format 5: delegation pools (WP9.2), an empty migration.
//!
//! A delegation pool of DHCPv6 prefix delegation is an IPAM range of the new role
//! `dhcp_pd_pool` with a `delegated_len` (`docs/dhcp.md` section 19.10). A binary of format
//! 4 cannot decode a range of that role: it would fail on every read of the ranges of its
//! network (the IPAM tree, the DHCP image, the range routes) instead of ignoring it, so it
//! must not open a directory that may hold one. Format 4 had promised no new stored enum
//! value for the rest of Phase 3; the delegation pool is that one value, and the range keeps
//! it in IPAM where the operator plans the space.
//!
//! Nothing stored in format 4 changes meaning, so there is nothing to rewrite: the runner
//! still commits the bump of the stored format record and its audit record.

use tenko_store::{Mutation, ReadView};

use super::{Migration, MigrationError};

/// The migration from format 4 to format 5.
pub struct V5;

impl Migration for V5 {
    fn to(&self) -> u32 {
        5
    }

    fn summary(&self) -> &'static str {
        "raises the format to 5, so that a format 4 binary refuses a data directory that may hold \
         an IPAM range of the role dhcp_pd_pool (a DHCPv6 delegation pool), which it cannot \
         decode; no stored row changes"
    }

    fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::ipam::RangeRole;
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    #[test]
    fn the_migration_produces_format_5() {
        assert_eq!(V5.to(), 5);
        assert!(V5.summary().contains("dhcp_pd_pool"));
        // The value the format exists for.
        assert_eq!(
            serde_json::to_string(&RangeRole::DhcpPdPool).expect("json"),
            "\"dhcp_pd_pool\""
        );
    }

    #[tokio::test]
    async fn an_empty_store_plans_no_mutations() {
        let store = MemStore::default();
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V5.plan(view.as_ref()).expect("plan");
        assert!(mutations.is_empty(), "{mutations:?}");
    }
}
