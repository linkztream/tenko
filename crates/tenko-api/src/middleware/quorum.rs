//! The quorum gate of the API (OPS-26, plan section 2.7): the slot where the partition
//! package (WP3.9) refuses every mutating request on a controller that is isolated or
//! electing, with 503 `cluster.no_quorum`, `Retry-After` and the parameters `since` and
//! `queueable`, before any planning; reads keep serving the local copy.
//!
//! It runs in the API route layer after authentication and before the idempotency replay,
//! so a refused request records no idempotency key. Until WP3.9 fills it the gate lets
//! every request through.

use axum::{extract::Request, response::Response};

use crate::state::AppState;

/// The refusal for `request`, or `None` to let it through. Pass-through until WP3.9.
pub(crate) fn check(_state: &AppState, _request: &Request) -> Option<Response> {
    None
}
