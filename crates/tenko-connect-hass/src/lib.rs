//! Home Assistant reference plugin: an inventory source of devices from the device
//! registry (CONN-04), built on the plugin SDK of `tenko-connect` and bundled in the `tenko`
//! binary as `tenko plugin run hass` (CONN-20, ADR 0012). It speaks the `tenko.connect.v1`
//! protocol like any third-party plugin and never runs inside the controller.
//!
//! Placeholder crate: the plugin lands in WP2.5 (see `docs/plans/phase-1-execution.md`).

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect-hass";

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
