//! The conformance suite against `RaftStore` (openraft over redb), unchanged, and the
//! follower cases through a member that does not lead in a cluster of three stores in one
//! process (writes forwarded over the in-process leader link).

use tenko_store::{
    raft::{RaftStore, RaftStoreConfig, fixture::InProcessCluster},
    testing::ConformanceConfig,
};

tenko_store::conformance_tests!(|config: ConformanceConfig| async move {
    RaftStore::open_temp(RaftStoreConfig::for_conformance(&config))
        .await
        .expect("open a temporary Raft store")
});

tenko_store::follower_conformance_tests!(|config: ConformanceConfig| async move {
    InProcessCluster::start(3, &config).await
});
