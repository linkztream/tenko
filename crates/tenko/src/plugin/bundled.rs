//! The plugins compiled into the `tenko` binary (CONN-20). The host starts each as
//! `tenko plugin run <name>`, exactly like a third-party plugin: its own process, the stdio
//! handshake, gRPC on a private endpoint.
//!
//! Each entry is a manifest and an entry point: the sample plugin, and the reference plugins
//! for Proxmox VE (`proxmox`) and Home Assistant (`hass`). The UniFi plugin joins the table
//! in its own work package.

use std::path::PathBuf;

use tenko_connect::{
    Manifest,
    host::{launch::LaunchSpec, registry::Bundled},
    sample,
};

/// A bundled plugin: its name, its manifest and its entry point.
pub struct Entry {
    /// The plugin name.
    pub name: &'static str,
    /// The manifest compiled into the binary.
    pub manifest: fn() -> Manifest,
    /// Runs the plugin on standard input and output and returns its exit status.
    pub run: fn() -> u8,
}

/// The bundled plugins.
pub const BUNDLED: &[Entry] = &[
    Entry {
        name: sample::NAME,
        manifest: sample::manifest,
        run: run_sample,
    },
    Entry {
        name: tenko_connect_proxmox::NAME,
        manifest: tenko_connect_proxmox::manifest,
        run: tenko_connect_proxmox::run_status,
    },
    Entry {
        name: tenko_connect_hass::NAME,
        manifest: tenko_connect_hass::manifest,
        run: tenko_connect_hass::run_status,
    },
    Entry {
        name: tenko_connect_unifi::NAME,
        manifest: tenko_connect_unifi::manifest,
        run: tenko_connect_unifi::run_status,
    },
];

fn run_sample() -> u8 {
    sample::run_status(sample::Mode::Normal)
}

/// The bundled plugin of a name.
pub fn find(name: &str) -> Option<&'static Entry> {
    BUNDLED.iter().find(|entry| entry.name == name)
}

/// The registry entries of the bundled plugins, started through `exe`.
pub fn registry_entries(exe: &std::path::Path) -> Vec<Bundled> {
    BUNDLED
        .iter()
        .map(|entry| {
            let manifest = (entry.manifest)();
            Bundled {
                launch: LaunchSpec::bundled(manifest.clone(), PathBuf::from(exe)),
                manifest,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_manifests_are_valid_and_named_like_their_entries() {
        for entry in BUNDLED {
            let manifest = (entry.manifest)();
            manifest.validate().expect("valid manifest");
            assert_eq!(manifest.name, entry.name);
            assert!(manifest.entry.is_none(), "bundled plugins have no entry");
        }
        assert!(find("sample").is_some());
        assert!(find("proxmox").is_some());
        assert!(find("hass").is_some());
        assert!(find("unknown").is_none());
        let entries = registry_entries(std::path::Path::new("tenko"));
        assert_eq!(entries[0].launch.args, ["plugin", "run", "sample"]);
    }
}
