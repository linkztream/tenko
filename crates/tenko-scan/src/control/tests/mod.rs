//! Tests of the scan control against the in-memory store and a job engine.

mod config;
mod kill_switch;
mod offers;
mod runs;
mod submit;
mod support;

use super::*;

#[test]
fn the_probe_config_table_is_the_one_the_node_sync_streams() {
    assert_eq!(
        PROBE_CONFIG.name(),
        &tenko_cluster::node_sync::tables::PROBE_CONFIG
    );
    assert_eq!(offer::TABLE, PROBE_CONFIG.name().as_str());
}
