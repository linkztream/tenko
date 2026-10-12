#![no_main]

//! The release manifest an update check downloads (WP2.10, `docs/upgrades.md`): the parser
//! and validator, then what the update check reads out of a valid manifest (the newest
//! release, the releases between two versions, the asset of a platform and its URL
//! resolved against the manifest's own URL) and the version parser on the raw text.

use libfuzzer_sys::fuzz_target;
use tenko_api::dto::release::{ReleaseManifest, ReleaseVersion, resolve_url};

const BASE: &str = "https://releases.example.test/tenko/manifest.json";

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = text.parse::<ReleaseVersion>();
    }
    let Ok(manifest) = ReleaseManifest::parse(data) else {
        return;
    };
    let running = ReleaseVersion::new(0, 1, 0);
    let _ = manifest.latest(true);
    let _ = manifest.newer_than(&running, false);
    if let Some(latest) = manifest.latest(false) {
        let _ = manifest.between(&running, &latest.version);
        let _ = manifest.release(&latest.version);
    }
    for release in &manifest.releases {
        let _ = release.version.to_string().parse::<ReleaseVersion>();
        for asset in &release.assets {
            let _ = resolve_url(BASE, &asset.url);
            let _ = release.asset(&asset.platform);
        }
    }
});
