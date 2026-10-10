//! The conformance suite against `MemStore`, and the follower cases through two simulated
//! members over one `MemStore`.

use tenko_store::{
    mem::MemStore,
    testing::{ConformanceConfig, SimulatedCluster},
};

tenko_store::conformance_tests!(|config: ConformanceConfig| async move {
    MemStore::new(config.mem_store_config())
});

tenko_store::follower_conformance_tests!(|config: ConformanceConfig| async move {
    SimulatedCluster::new(MemStore::new(config.mem_store_config()))
});
