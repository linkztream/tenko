//! IP address management: the address tree, the reconciler between declared intent and
//! observed state, and import/export.
//!
//! Placeholder crate: the implementation lands in a later phase (see `docs/ROADMAP.md`).

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-ipam";

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
