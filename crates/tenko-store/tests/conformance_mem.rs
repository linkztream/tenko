//! The conformance suite against `MemStore`.

use tenko_store::{mem::MemStore, testing::ConformanceConfig};

tenko_store::conformance_tests!(|config: ConformanceConfig| async move {
    MemStore::new(config.mem_store_config())
});
