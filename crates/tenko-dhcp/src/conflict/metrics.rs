//! The metric families conflict detection counts (`docs/dhcp-contracts.md` section 8):
//! `tenko_dhcp_conflicts_total` (addresses a probe found in use) and
//! `tenko_dhcp_probe_duration_seconds` (each probe from its start to its outcome, cut at the
//! cap, in microseconds). Process-wide statics that the role registers
//! ([`crate::role::metrics`]). The DECLINEs are the engine's `tenko_dhcp_declines_total`,
//! and a DECLINE beyond the per-client limit is
//! `tenko_dhcp_dropped_total{reason="rate_limited"}`.

pub(crate) use crate::role::metrics::{CONFLICTS, PROBE_DURATION};
