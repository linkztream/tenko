//! Probe role: passive and active network discovery and SNMP polling, feeding observations
//! to the IPAM reconciler (SCAN-01 to SCAN-09).
//!
//! | Module | Contents |
//! |---|---|
//! | [`scanner`] | the scheduler: schedules, on-demand runs, the kill switch, one batch per run |
//! | [`config`] | the `[scan]` section of `tenko.toml`, and the configuration the controllers hold for a probe |
//! | [`control`] | the controller side: probe configurations, scans on demand as jobs, the remote kill switch |
//! | [`method`] | the methods, the [`method::Method`] trait the scheduler drives |
//! | [`scope`] | the prefixes a probe covers; scans never leave them |
//! | [`secrets`] | vault secrets of the SNMP devices, fetched from the controllers, in memory only |
//! | [`limit`] | probes per second, spacing per address, probes in flight (TGL-19) |
//! | [`blackout`] | blackout windows (SCAN-06) |
//! | [`oui`] | vendor names from the OUI of a MAC address |
//! | [`dns`] | DNS messages for mDNS, LLMNR and reverse DNS |
//! | [`snmp`] | SNMPv3 polling of switches (SCAN-05) |
//! | [`methods`] | the methods themselves |
//! | [`known`] | the addresses this probe saw recently, which the deeper methods work on |
//! | [`status`] | the status file, the known addresses and the kill switch in `<data_dir>/scan/` |
//! | [`capability`] | raw sockets and ICMP on this host |
//! | [`sys`] | commands and files of the operating system, replayable in tests |
//!
//! docs/scanning.md describes the methods, what they need and what they report.

pub mod blackout;
pub mod capability;
pub mod config;
pub mod control;
pub mod dns;
pub mod error;
pub mod known;
pub mod limit;
pub mod method;
pub mod methods;
pub mod oui;
pub mod scanner;
pub mod scope;
pub mod secrets;
pub mod snmp;
pub mod status;
pub mod sys;

pub use error::ScanError;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-scan";

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
