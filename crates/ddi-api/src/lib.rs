//! HTTP API: axum routes, the generated OpenAPI document, and server-sent event (SSE)
//! streams.
//!
//! Placeholder crate: the implementation lands in a later phase (see `docs/ROADMAP.md`).

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "ddi-api";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
