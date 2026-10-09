//! Spike B: raw UDP DNS request/response throughput and a comparison of the
//! `domain` and `hickory-proto` wire-format crates.
//!
//! The hot path (`backend::respond`) is generic over a [`backend::Codec`],
//! so the two crates are exercised through identical I/O and lookup code.
#![forbid(unsafe_code)]

pub mod backend;
pub mod load;
pub mod matrix;
pub mod procstats;
pub mod record;
pub mod report;
pub mod server;
pub mod wire;
pub mod zone;
