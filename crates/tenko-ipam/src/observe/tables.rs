//! The `ipam.obs.*` tables of the observation layer (IPAM-12). Intent tables never hold
//! observed data, and these tables never hold intent.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | [`FACTS`] `ipam.obs.facts` | (source key, subject key) | [`ObservedFact`] |
//! | [`BY_MAC`] `ipam.obs.by_mac` | (MAC, source key, subject key) | `()` |
//! | [`BY_IP`] `ipam.obs.by_ip` | (IP, source key, subject key) | `()` |
//! | [`BY_NAME`] `ipam.obs.by_name` | (lowercase name, source key, subject key) | `()` |
//! | [`LAST_SEEN`] `ipam.obs.last_seen` | intent object (address or interface) | [`IntentSighting`] |
//!
//! The three index tables list every fact that names a MAC address, an IP address or a
//! name; they follow the fact in the same batch. A fact is purged with its index rows when
//! its last sighting is older than the retention.

use std::net::IpAddr;

use tenko_core::{MacAddr, ObjectRef, table::TableDef};

use super::model::{IntentSighting, ObservedFact};

/// Facts per source and subject.
pub static FACTS: TableDef<(String, String), ObservedFact> = TableDef::new("ipam.obs.facts");
/// Facts by MAC address.
pub static BY_MAC: TableDef<(MacAddr, String, String), ()> = TableDef::new("ipam.obs.by_mac");
/// Facts by IP address.
pub static BY_IP: TableDef<(IpAddr, String, String), ()> = TableDef::new("ipam.obs.by_ip");
/// Facts by lowercase name.
pub static BY_NAME: TableDef<(String, String, String), ()> = TableDef::new("ipam.obs.by_name");
/// The last sighting of addresses and interfaces of intent.
pub static LAST_SEEN: TableDef<ObjectRef, IntentSighting> = TableDef::new("ipam.obs.last_seen");

/// Every table of the observation layer.
pub fn all_tables() -> Vec<tenko_core::TableName> {
    [
        FACTS.name(),
        BY_MAC.name(),
        BY_IP.name(),
        BY_NAME.name(),
        LAST_SEEN.name(),
    ]
    .into_iter()
    .cloned()
    .collect()
}
