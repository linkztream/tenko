//! The plugin manifest (`plugin.json`): what a plugin is, what it implements, the settings
//! it takes, the secrets and network targets it needs and how to start it (CONN-19).
//!
//! The host validates a manifest before it starts the plugin ([`Manifest::validate`] and,
//! for plugins installed on disk, [`Manifest::validate_installed`]) and validates the
//! settings of every connector instance against the manifest's settings schema
//! ([`Manifest::validate_settings`]). Errors are precise: each [`ManifestProblem`] names
//! the JSON pointer of the offending member.
//!
//! # Example
//!
//! ```json
//! {
//!   "manifest_version": 1,
//!   "name": "sample",
//!   "version": "0.1.0",
//!   "description": "Sample inventory source with documentation data",
//!   "protocol": [1],
//!   "capabilities": ["inventory"],
//!   "settings": {
//!     "type": "object",
//!     "properties": {
//!       "url": { "type": "string", "format": "uri", "title": "Address" },
//!       "site": { "type": "string", "default": "lab" }
//!     },
//!     "required": ["url"]
//!   },
//!   "secrets": [{ "purpose": "api_key", "description": "API key", "required": true }],
//!   "network": [{ "setting": "/url", "description": "The source system" }],
//!   "platforms": ["any"],
//!   "entry": { "executable": "bin/sample-plugin" }
//! }
//! ```
//!
//! # Settings schema
//!
//! The settings schema is a JSON Schema (draft 2020-12) restricted to what a form can show,
//! so that the UI builds the configuration form of any plugin: a flat object of
//! `string`, `integer`, `number`, `boolean` and `array` (of strings or integers)
//! properties, with `title`, `description`, `default`, `enum`, `minLength`, `maxLength`,
//! `pattern`, `format` (`uri`, `hostname`, `ipv4`, `ipv6`), `minimum`, `maximum`,
//! `items`, `minItems`, `maxItems` and `uniqueItems`. Unknown settings are refused. Secrets
//! never go into settings: they are declared in `secrets` and injected per call.

mod settings;
mod validate;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub use settings::{SettingsProblem, validate_settings_schema};

/// The file name of a manifest in a plugin directory.
pub const MANIFEST_FILE: &str = "plugin.json";

/// The manifest format this host reads.
pub const MANIFEST_VERSION: u32 = 1;

/// Largest manifest file the host reads, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// A plugin manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The manifest format; `1`.
    pub manifest_version: u32,
    /// The plugin name: lowercase ASCII letters, digits and `-`, starting with a letter, at
    /// most 63 characters. Unique among the plugins of an installation.
    pub name: String,
    /// The plugin version (semantic versioning, `MAJOR.MINOR.PATCH` with an optional
    /// pre-release and build suffix).
    pub version: String,
    /// One or two English sentences for the operator.
    pub description: String,
    /// Where to read more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// SPDX licence expression of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// The protocol major versions the plugin speaks.
    pub protocol: Vec<u32>,
    /// The interfaces the plugin implements.
    pub capabilities: Vec<Capability>,
    /// The JSON Schema of the settings of an instance (see the module documentation for
    /// the supported subset). Absent means no settings.
    #[serde(default = "empty_settings_schema")]
    #[schema(value_type = Object)]
    pub settings: serde_json::Value,
    /// The secrets the plugin may receive. The host injects nothing else.
    #[serde(default)]
    pub secrets: Vec<SecretDecl>,
    /// The network targets the plugin contacts, shown to the operator before an instance
    /// is created.
    #[serde(default)]
    pub network: Vec<NetworkTarget>,
    /// The platforms the plugin runs on: `any` (scripts) or `<os>-<arch>` as Rust names
    /// them, for example `linux-x86_64`, `linux-aarch64`, `windows-x86_64`.
    pub platforms: Vec<String>,
    /// How to start the plugin. Required for installed plugins; bundled plugins are started
    /// by the host as `tenko plugin run <name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<Entry>,
    /// Defaults the host applies to new instances.
    #[serde(default)]
    pub defaults: Defaults,
}

/// The settings schema of a plugin without settings: an empty object.
pub fn empty_settings_schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// An interface a plugin implements.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// [`InventorySource`](crate::InventorySource): the `Inventory` service.
    Inventory,
    /// Webhooks of an inventory source (`Inventory.HandleWebhook`); needs `inventory`.
    Webhook,
    /// [`NetworkController`](crate::NetworkController): the `NetworkController` service.
    NetworkController,
    /// [`Actuator`](crate::Actuator): the `Actuator` service.
    Actuator,
    /// [`MigrationSource`](crate::MigrationSource): the `Migration` service.
    Migration,
    /// Port bounces (`BouncePort` and its `EnablePort`) of the `NetworkController` service;
    /// needs `network_controller` (ADR 0028).
    PortBounce,
    /// Client kicks (`KickClient`) of the `NetworkController` service; needs
    /// `network_controller` (ADR 0028).
    ClientKick,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Capability; 7] = [
        Capability::Inventory,
        Capability::Webhook,
        Capability::NetworkController,
        Capability::Actuator,
        Capability::Migration,
        Capability::PortBounce,
        Capability::ClientKick,
    ];

    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Inventory => "inventory",
            Capability::Webhook => "webhook",
            Capability::NetworkController => "network_controller",
            Capability::Actuator => "actuator",
            Capability::Migration => "migration",
            Capability::PortBounce => "port_bounce",
            Capability::ClientKick => "client_kick",
        }
    }
}

/// A secret a plugin may receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretDecl {
    /// The purpose: lowercase ASCII letters, digits and `_`, starting with a letter, at most
    /// 64 characters, for example `password` or `api_key`. Unique in the manifest.
    pub purpose: String,
    /// What the secret is, for the operator.
    pub description: String,
    /// Whether an instance needs it.
    #[serde(default)]
    pub required: bool,
}

/// A network target a plugin contacts: the host named by a settings member, or a fixed
/// host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkTarget {
    /// A JSON pointer to the settings member that holds the address (a URI, host name or
    /// IP address), for example `/url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    /// A fixed host name or IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The ports, when known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// What the target is, for the operator.
    pub description: String,
}

/// How to start an installed plugin: an executable, or a script with its interpreter.
/// Paths are relative to the plugin directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The executable, relative to the plugin directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// The interpreter of a script, found on `PATH` (`python3`, `node`) or as an absolute
    /// path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    /// The script, relative to the plugin directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Arguments after the executable or script.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// Defaults a manifest suggests for new instances; the host enforces its own bounds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Seconds between inventory polls (60 to 86,400; the host default is 300).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u32>,
    /// Timeout of one call in seconds (1 to 600; the host default is 30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_timeout_secs: Option<u32>,
}

/// One problem of a manifest or of instance settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ManifestProblem {
    /// JSON pointer of the offending member, for example `/secrets/0/purpose`; empty for
    /// the document as a whole.
    pub path: String,
    /// What is wrong, in English.
    pub message: String,
}

impl ManifestProblem {
    /// A problem at `path`.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ManifestProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// A manifest that cannot be used: every problem found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid plugin manifest: {}", render(.problems))]
pub struct ManifestError {
    /// The problems, in document order.
    pub problems: Vec<ManifestProblem>,
}

fn render(problems: &[ManifestProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

impl ManifestError {
    /// An error with one problem.
    pub fn single(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            problems: vec![ManifestProblem::new(path, message)],
        }
    }
}

impl tenko_core::Coded for ManifestError {
    fn code(&self) -> &'static str {
        "connect.plugin.manifest_invalid"
    }

    fn http_status(&self) -> u16 {
        422
    }

    fn title(&self) -> &'static str {
        "Invalid plugin manifest"
    }

    fn field_errors(&self) -> Vec<tenko_core::FieldError> {
        self.problems
            .iter()
            .map(|problem| {
                field_error(
                    problem.path.clone(),
                    "connect.plugin.manifest_invalid",
                    &problem.message,
                )
            })
            .collect()
    }
}

/// A JSON pointer below `root` in the field notation of API errors: `/hosts` becomes
/// `settings.hosts`, `/tags/2` becomes `settings.tags[2]`.
pub fn pointer_to_field(root: &str, pointer: &str) -> String {
    let mut field = root.to_owned();
    for segment in pointer.split('/').skip(1) {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
            field.push('[');
            field.push_str(&segment);
            field.push(']');
        } else {
            field.push('.');
            field.push_str(&segment);
        }
    }
    field
}

/// A field error with the English detail as the `detail` parameter.
fn field_error(field: String, code: &'static str, detail: &str) -> tenko_core::FieldError {
    let mut error = tenko_core::FieldError::new(field, code);
    error.params.insert("detail".to_owned(), detail.to_owned());
    error
}

/// Settings of an instance that do not satisfy the settings schema.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid settings: {}", render_settings(.problems))]
pub struct SettingsError {
    /// The problems, in document order.
    pub problems: Vec<SettingsProblem>,
}

fn render_settings(problems: &[SettingsProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

impl tenko_core::Coded for SettingsError {
    fn code(&self) -> &'static str {
        "connect.settings.invalid"
    }

    fn http_status(&self) -> u16 {
        422
    }

    fn title(&self) -> &'static str {
        "Invalid connector settings"
    }

    fn field_errors(&self) -> Vec<tenko_core::FieldError> {
        self.problems
            .iter()
            .map(|problem| {
                field_error(
                    pointer_to_field("settings", &problem.path),
                    problem.code,
                    &problem.message,
                )
            })
            .collect()
    }
}

impl Manifest {
    /// Parses and validates a manifest document ([`validate`](Manifest::validate)).
    ///
    /// # Errors
    ///
    /// [`ManifestError`] with the JSON error (line and column) or every validation problem.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::single(
                "",
                format!("the manifest is larger than {MAX_MANIFEST_BYTES} bytes"),
            ));
        }
        let manifest: Manifest = serde_json::from_slice(bytes).map_err(|error| {
            ManifestError::single(
                "",
                format!(
                    "not a valid manifest at line {}, column {}: {error}",
                    error.line(),
                    error.column()
                ),
            )
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Checks every rule that does not depend on the plugin directory: format version,
    /// name, version, description, protocol versions, capabilities, settings schema,
    /// secret purposes, network targets, platforms, entry shape and defaults.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] listing every problem found.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate::validate(self)
    }

    /// [`validate`](Manifest::validate), plus the rules of a plugin installed on disk: an
    /// `entry` is present and its paths are relative paths inside the plugin directory
    /// that exist.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] listing every problem found.
    pub fn validate_installed(&self, dir: &std::path::Path) -> Result<(), ManifestError> {
        validate::validate_installed(self, dir)
    }

    /// Validates the settings of an instance against the settings schema and returns them
    /// with the schema defaults filled in.
    ///
    /// # Errors
    ///
    /// [`SettingsError`] listing every problem found.
    pub fn validate_settings(
        &self,
        settings: &serde_json::Value,
    ) -> Result<serde_json::Value, SettingsError> {
        settings::validate_settings(&self.settings, settings)
            .map_err(|problems| SettingsError { problems })
    }

    /// Whether the manifest declares a capability.
    pub fn has(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// The declaration of a secret purpose.
    pub fn secret(&self, purpose: &str) -> Option<&SecretDecl> {
        self.secrets.iter().find(|decl| decl.purpose == purpose)
    }

    /// Whether the plugin runs on the platform of this host.
    pub fn supports_this_platform(&self) -> bool {
        let here = current_platform();
        self.platforms
            .iter()
            .any(|platform| platform == "any" || *platform == here)
    }

    /// The highest protocol version both sides speak.
    pub fn negotiate(&self, host: &[u32]) -> Option<u32> {
        self.protocol
            .iter()
            .copied()
            .filter(|version| host.contains(version))
            .max()
    }
}

/// The platform of this host as manifests name it: `<os>-<arch>`, for example
/// `windows-x86_64`.
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
