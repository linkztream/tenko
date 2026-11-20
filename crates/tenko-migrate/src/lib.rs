//! Migration pipeline: plan, apply, and verify migrations from existing systems over the
//! connector traits.
//!
//! Built so far: the mirrored sources of the Windows takeover ([`mirror`], WP14.1). The
//! pipeline of plan, apply and verify lands in a later phase (see `docs/ROADMAP.md`).

// WP14.1: mirrored sources (ADR 0033).
pub mod mirror;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-migrate";

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
