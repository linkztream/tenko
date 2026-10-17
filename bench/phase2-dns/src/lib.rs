//! Phase 2 DNS bench harness: a load generator for any DNS server, a zone
//! file and query file generator for the Phase 2 data sets, and a report
//! renderer for the result records. It contains no server code.
#![forbid(unsafe_code)]

pub mod load;
pub mod names;
pub mod procstats;
pub mod record;
pub mod report;
pub mod wire;
pub mod zonegen;
