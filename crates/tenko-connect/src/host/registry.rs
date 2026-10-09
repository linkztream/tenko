//! The plugins a host can run: bundled in its binary, and installed in a directory.
//!
//! An installed plugin is a directory `<plugins>/<name>/` with a `plugin.json` and the files
//! its `entry` names. The registry reads the directory on every listing, validates each
//! manifest ([`Manifest::validate_installed`]) and reports what is wrong with a plugin
//! instead of hiding it. A bundled plugin's name takes precedence over an installed plugin
//! of the same name.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::launch::LaunchSpec;
use crate::{
    SUPPORTED_PROTOCOLS,
    manifest::{MANIFEST_FILE, MAX_MANIFEST_BYTES, Manifest, ManifestProblem},
};

/// Where a plugin comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginSource {
    /// Compiled into the `tenko` binary, started as `tenko plugin run <name>`.
    Bundled,
    /// Installed in the plugins directory.
    Installed,
}

/// A plugin and whether it can run here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PluginInfo {
    /// The plugin name (the directory name of an installed plugin).
    pub name: String,
    /// Where it comes from.
    pub source: PluginSource,
    /// The manifest, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    /// Whether instances of it can run on this host: a valid manifest, this platform, a
    /// common protocol version.
    pub usable: bool,
    /// What is wrong with it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<ManifestProblem>,
}

/// A bundled plugin: its manifest and how the host starts it.
#[derive(Debug, Clone)]
pub struct Bundled {
    /// The manifest compiled into the binary.
    pub manifest: Manifest,
    /// How to start it (normally [`LaunchSpec::bundled`]).
    pub launch: LaunchSpec,
}

/// The bundled and installed plugins of a host.
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    bundled: Vec<Bundled>,
    installed: Option<PathBuf>,
}

/// Most installed plugins the registry reads.
const MAX_INSTALLED: usize = 256;

impl PluginRegistry {
    /// A registry of bundled plugins and, optionally, a directory of installed ones.
    pub fn new(bundled: Vec<Bundled>, installed: Option<PathBuf>) -> Self {
        Self { bundled, installed }
    }

    /// The directory of installed plugins.
    pub fn installed_dir(&self) -> Option<&Path> {
        self.installed.as_deref()
    }

    /// Every plugin, bundled first, then installed by name.
    pub fn list(&self) -> Vec<PluginInfo> {
        let mut plugins: Vec<PluginInfo> = self
            .bundled
            .iter()
            .map(|bundled| {
                info(
                    bundled.manifest.name.clone(),
                    PluginSource::Bundled,
                    Ok(bundled.manifest.clone()),
                )
            })
            .collect();
        for (name, dir) in self.installed_dirs() {
            let mut entry = info(
                name.clone(),
                PluginSource::Installed,
                read_installed(&name, &dir),
            );
            if self
                .bundled
                .iter()
                .any(|bundled| bundled.manifest.name == name)
            {
                entry.usable = false;
                entry.problems.push(ManifestProblem::new(
                    "/name",
                    format!("the bundled plugin `{name}` takes precedence over this installed one"),
                ));
            }
            plugins.push(entry);
        }
        plugins
    }

    /// One plugin by name: the bundled one when there is one.
    pub fn find(&self, name: &str) -> Option<PluginInfo> {
        if let Some(bundled) = self.bundled.iter().find(|b| b.manifest.name == name) {
            return Some(info(
                name.to_owned(),
                PluginSource::Bundled,
                Ok(bundled.manifest.clone()),
            ));
        }
        let dir = self.installed.as_ref()?.join(name);
        if !is_plugin_name(name) || !dir.join(MANIFEST_FILE).is_file() {
            return None;
        }
        Some(info(
            name.to_owned(),
            PluginSource::Installed,
            read_installed(name, &dir),
        ))
    }

    /// How to start a usable plugin.
    ///
    /// # Errors
    ///
    /// The plugin's problems, or one problem saying it does not exist.
    pub fn launch_spec(&self, name: &str) -> Result<(Manifest, LaunchSpec), Vec<ManifestProblem>> {
        if let Some(bundled) = self.bundled.iter().find(|b| b.manifest.name == name) {
            let found = info(
                name.to_owned(),
                PluginSource::Bundled,
                Ok(bundled.manifest.clone()),
            );
            if !found.usable {
                return Err(found.problems);
            }
            return Ok((bundled.manifest.clone(), bundled.launch.clone()));
        }
        let Some(found) = self.find(name) else {
            return Err(vec![ManifestProblem::new(
                "",
                format!("no plugin `{name}` is bundled or installed"),
            )]);
        };
        let (true, Some(manifest), Some(root)) =
            (found.usable, found.manifest, self.installed.as_ref())
        else {
            return Err(found.problems);
        };
        LaunchSpec::installed(manifest.clone(), &root.join(name))
            .map(|spec| (manifest, spec))
            .map_err(|error| error.problems)
    }

    /// The plugin directories under the installed directory, by name.
    fn installed_dirs(&self) -> Vec<(String, PathBuf)> {
        let Some(root) = &self.installed else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(root) else {
            return Vec::new();
        };
        let mut dirs: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().join(MANIFEST_FILE).is_file())
            .filter_map(|entry| Some((entry.file_name().into_string().ok()?, entry.path())))
            .take(MAX_INSTALLED)
            .collect();
        dirs.sort();
        dirs
    }
}

/// Whether a directory name can be a plugin name (the manifest rule, checked again by the
/// manifest validation).
fn is_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Reads and validates an installed plugin's manifest.
fn read_installed(name: &str, dir: &Path) -> Result<Manifest, Vec<ManifestProblem>> {
    let path = dir.join(MANIFEST_FILE);
    let bytes = match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > MAX_MANIFEST_BYTES as u64 => {
            return Err(vec![ManifestProblem::new(
                "",
                format!("{MANIFEST_FILE} is larger than {MAX_MANIFEST_BYTES} bytes"),
            )]);
        }
        Ok(_) => std::fs::read(&path).map_err(|error| {
            vec![ManifestProblem::new(
                "",
                format!("cannot read {MANIFEST_FILE}: {error}"),
            )]
        })?,
        Err(error) => {
            return Err(vec![ManifestProblem::new(
                "",
                format!("cannot read {MANIFEST_FILE}: {error}"),
            )]);
        }
    };
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| {
        vec![ManifestProblem::new(
            "",
            format!(
                "{MANIFEST_FILE} is not a valid manifest at line {}, column {}: {error}",
                error.line(),
                error.column()
            ),
        )]
    })?;
    let mut problems = match manifest.validate_installed(dir) {
        Ok(()) => Vec::new(),
        Err(error) => error.problems,
    };
    if manifest.name != name {
        problems.push(ManifestProblem::new(
            "/name",
            format!(
                "the manifest names `{}` but its directory is `{name}`",
                manifest.name
            ),
        ));
    }
    if problems.is_empty() {
        Ok(manifest)
    } else {
        Err(problems)
    }
}

/// The information of a plugin from its manifest or its problems.
fn info(
    name: String,
    source: PluginSource,
    manifest: Result<Manifest, Vec<ManifestProblem>>,
) -> PluginInfo {
    match manifest {
        Err(problems) => PluginInfo {
            name,
            source,
            manifest: None,
            usable: false,
            problems,
        },
        Ok(manifest) => {
            let mut problems = Vec::new();
            if !manifest.supports_this_platform() {
                problems.push(ManifestProblem::new(
                    "/platforms",
                    format!(
                        "the plugin runs on {:?}, not on {}",
                        manifest.platforms,
                        crate::manifest::current_platform()
                    ),
                ));
            }
            if manifest.negotiate(SUPPORTED_PROTOCOLS).is_none() {
                problems.push(ManifestProblem::new(
                    "/protocol",
                    format!(
                        "the plugin speaks protocol {:?}; this host speaks {SUPPORTED_PROTOCOLS:?}",
                        manifest.protocol
                    ),
                ));
            }
            PluginInfo {
                name,
                source,
                usable: problems.is_empty(),
                manifest: Some(manifest),
                problems,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample;

    fn bundled() -> Bundled {
        Bundled {
            manifest: sample::manifest(),
            launch: LaunchSpec::bundled(sample::manifest(), PathBuf::from("tenko")),
        }
    }

    fn install(root: &Path, name: &str, manifest: &serde_json::Value) {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("bin")).expect("dir");
        std::fs::write(dir.join("bin").join("plugin"), b"#!/bin/sh\n").expect("file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("bin").join("plugin"),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("mode");
        }
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec(manifest).expect("json"),
        )
        .expect("manifest");
    }

    fn manifest_of(name: &str) -> serde_json::Value {
        let mut manifest = serde_json::to_value(sample::manifest()).expect("json");
        manifest["name"] = serde_json::json!(name);
        manifest["entry"] = serde_json::json!({ "executable": "bin/plugin" });
        manifest
    }

    #[test]
    fn bundled_and_installed_plugins_are_listed_with_their_problems() {
        let root = tempfile::tempdir().expect("dir");
        install(root.path(), "inventory-a", &manifest_of("inventory-a"));
        install(root.path(), "renamed", &manifest_of("other-name"));
        let mut future = manifest_of("future");
        future["protocol"] = serde_json::json!([2]);
        install(root.path(), "future", &future);
        install(root.path(), "sample", &manifest_of("sample"));
        std::fs::create_dir_all(root.path().join("broken")).expect("dir");
        std::fs::write(
            root.path().join("broken").join(MANIFEST_FILE),
            b"{ not json",
        )
        .expect("file");

        let registry = PluginRegistry::new(vec![bundled()], Some(root.path().to_path_buf()));
        let plugins = registry.list();
        let names: Vec<(&str, PluginSource, bool)> = plugins
            .iter()
            .map(|p| (p.name.as_str(), p.source, p.usable))
            .collect();
        assert_eq!(
            names,
            [
                ("sample", PluginSource::Bundled, true),
                ("broken", PluginSource::Installed, false),
                ("future", PluginSource::Installed, false),
                ("inventory-a", PluginSource::Installed, true),
                ("renamed", PluginSource::Installed, false),
                ("sample", PluginSource::Installed, false),
            ]
        );
        let broken = &plugins[1];
        assert!(broken.problems[0].message.contains("line 1"), "{broken:?}");
        assert!(plugins[2].problems.iter().any(|p| p.path == "/protocol"));
        assert!(
            plugins[4]
                .problems
                .iter()
                .any(|p| p.message.contains("directory is `renamed`"))
        );

        let (manifest, spec) = registry.launch_spec("inventory-a").expect("usable");
        assert_eq!(manifest.name, "inventory-a");
        assert!(
            spec.program
                .ends_with(Path::new("inventory-a").join("bin").join("plugin"))
        );
        assert_eq!(
            spec.cwd.as_deref(),
            Some(root.path().join("inventory-a").as_path())
        );
        let (manifest, spec) = registry.launch_spec("sample").expect("bundled");
        assert_eq!(manifest.name, "sample");
        assert_eq!(spec.args, ["plugin", "run", "sample"]);
        assert!(registry.launch_spec("future").is_err());
        assert!(registry.launch_spec("missing").is_err());
        assert!(registry.find("../etc").is_none());
    }

    #[test]
    fn a_registry_without_a_directory_lists_the_bundled_plugins() {
        let registry = PluginRegistry::new(vec![bundled()], Some(PathBuf::from("does/not/exist")));
        assert_eq!(registry.list().len(), 1);
    }
}
