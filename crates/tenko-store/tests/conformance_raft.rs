//! The conformance suite against `RaftStore` (openraft over redb), unchanged.

use tenko_store::{
    raft::{RaftStore, RaftStoreConfig},
    testing::ConformanceConfig,
};

tenko_store::conformance_tests!(|config: ConformanceConfig| async move {
    RaftStore::open_temp(RaftStoreConfig::for_conformance(&config))
        .await
        .expect("open a temporary Raft store")
});
