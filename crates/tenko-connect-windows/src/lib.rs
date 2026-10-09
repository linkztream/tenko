//! Windows Server reference plugin: a migration source that reads DNS zones and DHCP scopes
//! from Windows DNS and DHCP servers, and later a coexistence actuator (ADR 0006), built on
//! the plugin SDK of `tenko-connect` and bundled in the `tenko` binary (CONN-20, ADR 0012).
//! It speaks the `tenko.connect.v1` protocol like any third-party plugin and never runs
//! inside the controller.
//!
//! Placeholder crate: the plugin lands in Phase 4 (see `docs/ROADMAP.md`).

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect-windows";

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
