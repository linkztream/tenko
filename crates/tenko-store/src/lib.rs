//! The replicated store of Tenko DDI (ADR 0002, ADR 0011): the [`Store`] contract every
//! package builds against, the in-memory [`MemStore`] with the full
//! semantics, and the conformance suite (module `testing`, feature `testing`) that every
//! implementation must pass.
//!
//! # A home of shared code
//!
//! This crate is a home of shared code (`CONTRIBUTING.md`, "Where shared code lives") for the
//! primitives of putting bytes on disk and of following what the store changed, in the
//! modules `layout` (the store's file names), `fs` (the private-file writer and the atomic
//! replace, with their guarantees stated and tested there), `follow` (follow one table's
//! changes from a revision), `feed` (send tables to a node) and `codes` (the store's error
//! codes as constants). A module named here that does not exist yet is created by the change
//! that first needs it, with this charter in its header.
//!
//! - **Never:** a file format or the content of one feature's file (a zone file writer, an
//!   export or a configuration writer uses `fs` and lives with its feature), a domain type,
//!   or a table of another crate.
//! - **Who depends on it:** every crate that writes a private file or follows a table
//!   already does. An addition inside this charter needs no permission; a change to the
//!   [`Store`] contract or to what an existing item does goes through the maintainers.
//!
//! # Modules
//!
//! - [`api`] holds the contract: `Store`, `ReadView`, `WriteBatch`, preconditions, mutations,
//!   change sets and watch streams, derived indexes, errors, status — and the invariants
//!   every implementation upholds.
//! - [`mem`] holds `MemStore`.
//! - `testing` (feature `testing`) holds the conformance suite and the `conformance_tests!` macro.
//!
//! # Extension point: the Raft store (WP1.1)
//!
//! WP1.1 adds `pub mod raft;` here with `RaftStore`, which implements [`Store`] with
//! openraft 0.9 (one voter in Slice 1, three in Slice 3) over redb (`log.redb` and
//! `sm.redb`), and keeps it behind the same trait so no other package changes:
//!
//! - `propose` calls [`WriteBatch::validate`] first, then hands the batch to the coalescer
//!   ([`CoalescerConfig`]); never one Raft entry per batch (ADR 0002 decision 4, risk R4).
//! - The state machine applies the batches of an entry in order, each against its own
//!   preconditions, with the exact semantics of `MemStore`: idempotency records, audit
//!   sealing (`tenko_core::audit::AuditRecord::seal` with `at = proposed_at`), counters,
//!   the `sys.journal` change set and its retention, all in the same redb write
//!   transaction, then [`DerivedIndex::apply`] with a view of that transaction.
//! - Reads are redb read transactions wrapped as [`ReadView`]; `Linearizable` asks the
//!   leader for its commit index first.
//! - Snapshot install builds every registered index aside from the new state and installs
//!   it atomically.
//! - Its integration test runs the same suite with a factory that opens the store under
//!   `std::env::temp_dir()`:
//!   `tenko_store::conformance_tests!(|config| async move { RaftStore::open_temp(config).await });`

pub mod api;
pub mod format;
mod layout;
pub mod mem;
#[cfg(feature = "raft")]
pub mod raft;
#[cfg(feature = "testing")]
pub mod testing;
// WP6.2: a store that refuses writes on one node, for the acceptance tests.
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks;

pub use api::{
    AnchorResolver, ApplyStopped, Change, ChangeSet, ChangeStream, CoalescerConfig, Committed,
    DerivedIndex, FailedPrecondition, FenceReason, IndexImage, IndexStatus, KeyRange, Leadership,
    MemberStatus, Mutation, Precondition, QuorumState, ReadConsistency, ReadView, ReadViewExt,
    Store, StoreError, StoreRole, StoreStatus, Versioned, WatchError, WatchFilter, WriteBatch,
    downcast_image, fence, tables,
};
pub use layout::sync_dir;
pub use mem::{MemStore, MemStoreConfig};
pub use tenko_core::{CounterKey, TableName};

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-store";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
