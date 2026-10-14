//! Measurement M8 of the slice 3 plan: the cost of the metrics core
//! (`tenko_core::metrics`, OPS-21) on the hot path of the Spike B UDP responder, in paired
//! runs with the metrics off and on. The zero-allocation check of the update path is the
//! test `tests/zero_alloc.rs`.
#![forbid(unsafe_code)]

pub mod pairs;
pub mod responder;
