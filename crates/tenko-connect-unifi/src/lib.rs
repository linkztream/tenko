//! UniFi Network reference plugin: a network controller that reads devices, clients, ports,
//! LLDP, uplinks and wireless networks and performs the L2 writes the host has planned and
//! checked against its guardrails (CONN-05 to CONN-09, CONN-18), built on the plugin SDK of
//! `tenko-connect` and bundled in the `tenko` binary as `tenko plugin run unifi` (CONN-20,
//! ADR 0012). It speaks the `tenko.connect.v1` protocol like any third-party plugin and
//! never runs inside the controller.

pub mod classic;
pub mod detect;
pub mod fuzzing;
pub mod http;
pub mod integration;
pub mod json;
pub mod manifest;
pub mod model;
pub mod plugin;
pub mod settings;
pub mod write;

use std::{process::ExitCode, sync::Arc};

pub use manifest::{NAME, manifest};
pub use plugin::Unifi;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect-unifi";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The plugin as the SDK runs it.
pub fn plugin() -> tenko_connect::sdk::Plugin {
    let unifi = Arc::new(Unifi);
    tenko_connect::sdk::Plugin::new(manifest(), unifi.clone())
        .with_inventory(unifi.clone())
        .with_network_controller(unifi)
}

/// Runs the plugin on standard input and output and returns the exit status (the entry
/// point of `tenko plugin run unifi`).
pub fn run_status() -> u8 {
    plugin().run_status()
}

/// The entry point of the `tenko-plugin-unifi` executable.
pub fn main() -> ExitCode {
    if std::env::args().len() > 1 {
        eprintln!("usage: tenko-plugin-unifi (started by the Tenko plugin host)");
        return ExitCode::from(2);
    }
    ExitCode::from(run_status())
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
