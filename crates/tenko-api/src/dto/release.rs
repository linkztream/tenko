//! Release manifests (`releases.json`), release versions and changelog sections (OPS-23,
//! OPS-24).
//!
//! A release manifest is a JSON document that is published next to the release files and
//! lists every release, newest first or in any order (the parser sorts):
//!
//! ```json
//! {
//!   "schema": 1,
//!   "project": "tenko",
//!   "releases": [
//!     {
//!       "version": "0.2.0",
//!       "date": "2026-10-09",
//!       "notes": "### Added\n\n- An entry.",
//!       "security": false,
//!       "requires_action": false,
//!       "format": 1,
//!       "assets": [
//!         {
//!           "platform": "linux-x86_64",
//!           "name": "tenko-0.2.0-linux-x86_64",
//!           "url": "tenko-0.2.0-linux-x86_64",
//!           "sha256": "<64 lowercase hexadecimal digits>",
//!           "size": 12345678
//!         }
//!       ],
//!       "image": "ghcr.io/example/tenko:0.2.0"
//!     }
//!   ]
//! }
//! ```
//!
//! The manifest is untrusted input: [`ReleaseManifest::parse`] bounds its size, rejects
//! unknown schemas and projects, and validates every field before the rest of the product
//! sees it. Unknown JSON fields are ignored so that a newer manifest of the same schema
//! still parses. The `notes` of a release are the changelog section of its version, which
//! [`parse_changelog`] reads out of `CHANGELOG.md` (Keep a Changelog 1.1.0 with one project
//! addition, the `### Action required` subsection).

use std::{
    cmp::Ordering,
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

/// Schema number of the manifest format this build reads.
pub const MANIFEST_SCHEMA: u32 = 1;

/// Largest manifest accepted, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Largest release file accepted, in bytes.
pub const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;

/// The only project a manifest may describe.
const PROJECT: &str = "tenko";
/// Most releases a manifest may list.
const MAX_RELEASES: usize = 1_000;
/// Largest `notes` of a release, in bytes.
const MAX_NOTES_BYTES: usize = 64 * 1024;
/// Largest `action` of a release, in bytes.
const MAX_ACTION_BYTES: usize = 16 * 1024;
/// Longest asset file name, in characters.
const MAX_NAME_CHARS: usize = 200;
/// Longest asset URL, in characters.
const MAX_URL_CHARS: usize = 2_048;
/// Longest container image reference, in characters.
const MAX_IMAGE_CHARS: usize = 256;
/// Longest version text accepted, in bytes.
const MAX_VERSION_BYTES: usize = 128;
/// Longest piece of untrusted text repeated in an error message, in characters.
const MAX_ECHO_CHARS: usize = 64;

/// The text for an error message: at most [`MAX_ECHO_CHARS`] characters, control characters
/// replaced by `?`.
fn printable(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(MAX_ECHO_CHARS)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if text.chars().nth(MAX_ECHO_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

/// Whether `text` is a calendar date written `YYYY-MM-DD` (month 1 to 12, day 1 to 31; the
/// length of the month is not checked).
fn is_valid_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits_ok = bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !digits_ok {
        return false;
    }
    let month = u32::from(bytes[5] - b'0') * 10 + u32::from(bytes[6] - b'0');
    let day = u32::from(bytes[8] - b'0') * 10 + u32::from(bytes[9] - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

// ---------------------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------------------

/// The text is not a release version.
///
/// Holds the offending text, cut to 64 characters with control characters replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidVersion(pub String);

impl fmt::Display for InvalidVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a release version such as 1.2.3 or 1.2.3-rc.1",
            self.0
        )
    }
}

impl std::error::Error for InvalidVersion {}

/// One dot-separated identifier of a pre-release. Numeric identifiers rank below
/// alphanumeric ones, which the order of the variants gives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Identifier {
    /// Digits only, without a leading zero.
    Numeric(u64),
    /// Anything else of `[0-9A-Za-z-]`.
    Alpha(String),
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identifier::Numeric(n) => write!(f, "{n}"),
            Identifier::Alpha(s) => f.write_str(s),
        }
    }
}

/// A release version: `MAJOR.MINOR.PATCH`, optionally followed by a pre-release
/// (`-rc.1`) and build metadata (`+build.5`).
///
/// The text form accepts one leading `v` (`v0.2.0`), which [`fmt::Display`] does not
/// print. Numbers have no leading zeros. Ordering follows `SemVer` 2.0.0 precedence: the
/// numbers compare numerically, a pre-release ranks below its release, and the identifiers
/// of a pre-release compare one by one (numeric identifiers numerically and below
/// alphanumeric ones, which compare in ASCII order; a shorter list ranks below a longer one
/// that starts with it). Build metadata is kept for display and ignored for ordering,
/// equality and hashing. Serialized as a string.
#[derive(Debug, Clone)]
pub struct ReleaseVersion {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Identifier>,
    build: Option<String>,
}

/// Parses a number of a version core: digits only, no leading zero except `0` itself.
fn parse_number(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Parses one identifier of a pre-release.
fn parse_identifier(text: &str) -> Option<Identifier> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        parse_number(text).map(Identifier::Numeric)
    } else {
        Some(Identifier::Alpha(text.to_owned()))
    }
}

/// Whether `text` is one identifier of build metadata (leading zeros allowed).
fn is_build_identifier(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl ReleaseVersion {
    /// The release `major.minor.patch` without pre-release and build metadata.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: Vec::new(),
            build: None,
        }
    }

    /// The major number.
    pub fn major(&self) -> u64 {
        self.major
    }

    /// The minor number.
    pub fn minor(&self) -> u64 {
        self.minor
    }

    /// The patch number.
    pub fn patch(&self) -> u64 {
        self.patch
    }

    /// Whether the version has a pre-release part such as `-rc.1`.
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// The build metadata after `+`, if any. It does not take part in ordering.
    pub fn build(&self) -> Option<&str> {
        self.build.as_deref()
    }

    fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_VERSION_BYTES {
            return None;
        }
        let text = text.strip_prefix('v').unwrap_or(text);
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let mut numbers = core.split('.');
        let major = parse_number(numbers.next()?)?;
        let minor = parse_number(numbers.next()?)?;
        let patch = parse_number(numbers.next()?)?;
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre {
            Some(pre) => pre
                .split('.')
                .map(parse_identifier)
                .collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        let build = match build {
            Some(build) if build.split('.').all(is_build_identifier) => Some(build.to_owned()),
            Some(_) => return None,
            None => None,
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
            build,
        })
    }
}

impl FromStr for ReleaseVersion {
    type Err = InvalidVersion;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text).ok_or_else(|| InvalidVersion(printable(text)))
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, identifier) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            write!(f, "{identifier}")?;
        }
        if let Some(build) = &self.build {
            write!(f, "+{build}")?;
        }
        Ok(())
    }
}

impl PartialEq for ReleaseVersion {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major
            && self.minor == other.minor
            && self.patch == other.patch
            && self.pre == other.pre
    }
}

impl Eq for ReleaseVersion {}

impl Hash for ReleaseVersion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.major.hash(state);
        self.minor.hash(state);
        self.patch.hash(state);
        self.pre.hash(state);
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for ReleaseVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ReleaseVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl utoipa::PartialSchema for ReleaseVersion {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .description(Some(
                "Release version: MAJOR.MINOR.PATCH with an optional pre-release and build \
                 metadata, ordered by SemVer 2.0.0 precedence.",
            ))
            .examples(["1.2.0", "1.2.0-rc.1"])
            .into()
    }
}

impl ToSchema for ReleaseVersion {}

// ---------------------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------------------

/// The release manifest (`releases.json`): every release of the product with its notes and
/// downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReleaseManifest {
    /// Format of the manifest; the only schema is 1.
    pub schema: u32,
    /// The project the manifest describes; always `tenko`.
    pub project: String,
    /// The releases; [`ReleaseManifest::parse`] sorts them newest first.
    pub releases: Vec<Release>,
}

/// One release. Also the body of the release endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Release {
    /// The version of the release.
    pub version: ReleaseVersion,
    /// Release date, `YYYY-MM-DD`.
    pub date: String,
    /// Markdown: the changelog section of the version.
    pub notes: String,
    /// The release contains security fixes.
    #[serde(default)]
    pub security: bool,
    /// The operator must do something when upgrading to this release.
    #[serde(default)]
    pub requires_action: bool,
    /// Markdown: what the operator must do; present when `requires_action` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Format of the data directory this release writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<u32>,
    /// The downloadable files, one per platform.
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
    /// Container image of the release, for example `ghcr.io/example/tenko:0.2.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// One downloadable file of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReleaseAsset {
    /// `<os>-<arch>` as Rust's `std::env::consts::OS` and `ARCH` name them: `linux-x86_64`,
    /// `linux-aarch64`, `windows-x86_64`.
    pub platform: String,
    /// File name, for example `tenko-0.2.0-linux-x86_64`.
    pub name: String,
    /// Absolute `http` or `https` URL, or a URL relative to the manifest URL.
    pub url: String,
    /// SHA-256 of the file: 64 lowercase hexadecimal digits.
    pub sha256: String,
    /// Size of the file in bytes.
    pub size: u64,
    /// Detached signature; reserved for signed releases (API-19) and not checked yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The manifest is larger than [`MAX_MANIFEST_BYTES`].
    TooLarge {
        /// Size of the refused document.
        bytes: usize,
    },
    /// The document is not JSON of the expected shape; holds the parser message.
    Json(String),
    /// The schema number is not 1.
    Schema {
        /// The schema the manifest declares.
        found: u32,
    },
    /// The manifest describes another project; holds that project.
    Project(String),
    /// A field has a value that is not allowed.
    Invalid {
        /// The release the field belongs to; `None` for fields of the manifest itself.
        version: Option<String>,
        /// The field, for asset fields written `assets.<field>`.
        field: &'static str,
        /// What is wrong, as a predicate on the field.
        reason: String,
    },
    /// Two releases have the same version (build metadata ignored); holds that version.
    DuplicateVersion(String),
}

impl ManifestError {
    /// The stable error code of the API (`update.manifest.*`).
    pub fn code(&self) -> &'static str {
        match self {
            ManifestError::TooLarge { .. } => "update.manifest.too_large",
            ManifestError::Json(_) => "update.manifest.json",
            ManifestError::Schema { .. } => "update.manifest.schema",
            ManifestError::Project(_) => "update.manifest.project",
            ManifestError::Invalid { .. } | ManifestError::DuplicateVersion(_) => {
                "update.manifest.invalid"
            }
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::TooLarge { bytes } => write!(
                f,
                "the manifest is {bytes} bytes; at most {MAX_MANIFEST_BYTES} bytes are accepted"
            ),
            ManifestError::Json(message) => {
                write!(f, "the manifest is not valid release JSON: {message}")
            }
            ManifestError::Schema { found } if *found > MANIFEST_SCHEMA => write!(
                f,
                "the manifest has schema {found} and is written for a newer Tenko; this \
                 version reads schema {MANIFEST_SCHEMA}"
            ),
            ManifestError::Schema { found } => write!(
                f,
                "the manifest schema {found} is not supported; this version reads schema \
                 {MANIFEST_SCHEMA}"
            ),
            ManifestError::Project(project) => write!(
                f,
                "the manifest describes the project `{project}`, not `{PROJECT}`"
            ),
            ManifestError::Invalid {
                version: Some(version),
                field,
                reason,
            } => write!(f, "release {version}: `{field}` {reason}"),
            ManifestError::Invalid {
                version: None,
                field,
                reason,
            } => write!(f, "`{field}` {reason}"),
            ManifestError::DuplicateVersion(version) => {
                write!(f, "the version {version} is listed more than once")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// The `Invalid` error of a release field.
fn invalid(version: &ReleaseVersion, field: &'static str, reason: String) -> ManifestError {
    ManifestError::Invalid {
        version: Some(version.to_string()),
        field,
        reason,
    }
}

/// Only the schema number of a document, to tell a newer manifest from a broken one.
#[derive(Deserialize)]
struct SchemaProbe {
    schema: u32,
}

impl ReleaseManifest {
    /// Parses and validates a manifest and sorts its releases newest first.
    ///
    /// # Errors
    ///
    /// [`ManifestError::TooLarge`] before any parsing when the document exceeds
    /// [`MAX_MANIFEST_BYTES`]; [`ManifestError::Json`] when it is not JSON of the manifest
    /// shape (a document that declares another schema number reports
    /// [`ManifestError::Schema`] instead, so a manifest of a newer format is recognised even
    /// when its shape changed); otherwise the errors of [`ReleaseManifest::validate`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge { bytes: bytes.len() });
        }
        let mut manifest: Self = match serde_json::from_slice(bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                return Err(match serde_json::from_slice::<SchemaProbe>(bytes) {
                    Ok(probe) if probe.schema != MANIFEST_SCHEMA => ManifestError::Schema {
                        found: probe.schema,
                    },
                    _ => ManifestError::Json(error.to_string()),
                });
            }
        };
        manifest.validate()?;
        manifest.releases.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(manifest)
    }

    /// Checks every rule of the format: the schema and project, at most 1,000 releases with
    /// unique versions, and the fields of each release and asset (dates, sizes, digests,
    /// file names and URLs).
    ///
    /// # Errors
    ///
    /// The first violation found, in the order of the manifest: [`ManifestError::Schema`],
    /// [`ManifestError::Project`], [`ManifestError::DuplicateVersion`] or
    /// [`ManifestError::Invalid`].
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(ManifestError::Schema { found: self.schema });
        }
        if self.project != PROJECT {
            return Err(ManifestError::Project(printable(&self.project)));
        }
        if self.releases.len() > MAX_RELEASES {
            return Err(ManifestError::Invalid {
                version: None,
                field: "releases",
                reason: format!(
                    "lists {} releases; at most {MAX_RELEASES} are accepted",
                    self.releases.len()
                ),
            });
        }
        let mut seen = HashSet::new();
        for release in &self.releases {
            if !seen.insert(&release.version) {
                return Err(ManifestError::DuplicateVersion(release.version.to_string()));
            }
            release.check()?;
        }
        Ok(())
    }

    /// The newest release, skipping pre-releases unless `include_prereleases` is set.
    pub fn latest(&self, include_prereleases: bool) -> Option<&Release> {
        self.releases
            .iter()
            .filter(|r| include_prereleases || !r.version.is_prerelease())
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    /// The release of exactly this version (build metadata ignored).
    pub fn release(&self, version: &ReleaseVersion) -> Option<&Release> {
        self.releases.iter().find(|r| r.version == *version)
    }

    /// The releases above `running`, newest first. Pre-releases are included only when
    /// `include_prereleases` is set; a pre-release at or below `running` is never included.
    pub fn newer_than(&self, running: &ReleaseVersion, include_prereleases: bool) -> Vec<&Release> {
        let mut found: Vec<&Release> = self
            .releases
            .iter()
            .filter(|r| r.version > *running)
            .filter(|r| include_prereleases || !r.version.is_prerelease())
            .collect();
        found.sort_by(|a, b| b.version.cmp(&a.version));
        found
    }

    /// The releases in the half-open range above `from` up to and including `to`, newest
    /// first, pre-releases included.
    pub fn between(&self, from: &ReleaseVersion, to: &ReleaseVersion) -> Vec<&Release> {
        let mut found: Vec<&Release> = self
            .releases
            .iter()
            .filter(|r| r.version > *from && r.version <= *to)
            .collect();
        found.sort_by(|a, b| b.version.cmp(&a.version));
        found
    }
}

impl Release {
    /// The asset for `platform` (`linux-x86_64`, see [`current_platform`]).
    pub fn asset(&self, platform: &str) -> Option<&ReleaseAsset> {
        self.assets.iter().find(|a| a.platform == platform)
    }

    /// Validates the fields of the release and of its assets.
    fn check(&self) -> Result<(), ManifestError> {
        let version = &self.version;
        if !is_valid_date(&self.date) {
            return Err(invalid(
                version,
                "date",
                format!(
                    "must be a date written YYYY-MM-DD (found `{}`)",
                    printable(&self.date)
                ),
            ));
        }
        if self.notes.len() > MAX_NOTES_BYTES {
            return Err(invalid(
                version,
                "notes",
                format!(
                    "must be at most {MAX_NOTES_BYTES} bytes (found {})",
                    self.notes.len()
                ),
            ));
        }
        if let Some(action) = &self.action
            && action.len() > MAX_ACTION_BYTES
        {
            return Err(invalid(
                version,
                "action",
                format!(
                    "must be at most {MAX_ACTION_BYTES} bytes (found {})",
                    action.len()
                ),
            ));
        }
        if self.requires_action && self.action.as_deref().is_none_or(|a| a.trim().is_empty()) {
            return Err(invalid(
                version,
                "action",
                "must say what to do when `requires_action` is set".to_owned(),
            ));
        }
        if self.format == Some(0) {
            return Err(invalid(version, "format", "must be at least 1".to_owned()));
        }
        if let Some(image) = &self.image
            && !is_valid_image(image)
        {
            return Err(invalid(
                version,
                "image",
                format!(
                    "must be a container image reference without whitespace, at most \
                     {MAX_IMAGE_CHARS} characters (found `{}`)",
                    printable(image)
                ),
            ));
        }
        let mut platforms = HashSet::new();
        for (index, asset) in self.assets.iter().enumerate() {
            asset.check(version, index)?;
            if !platforms.insert(asset.platform.as_str()) {
                return Err(invalid(
                    version,
                    "assets.platform",
                    format!(
                        "must be unique within the release (asset {}: `{}` is listed twice)",
                        index + 1,
                        printable(&asset.platform)
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Whether `image` is a plausible container image reference.
fn is_valid_image(image: &str) -> bool {
    !image.is_empty()
        && image.chars().count() <= MAX_IMAGE_CHARS
        && !image.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether `platform` matches `^[a-z0-9_]+-[a-z0-9_]+$`.
fn is_valid_platform(platform: &str) -> bool {
    let part_ok = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    platform
        .split_once('-')
        .is_some_and(|(os, arch)| part_ok(os) && part_ok(arch))
}

/// Whether `name` is a plain file name: no separators, no `..`, no control characters, no
/// leading dot, at most 200 characters.
fn is_valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.starts_with('.')
        && !name.contains("..")
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

/// Whether `url` is an absolute `http` or `https` URL with a host part.
fn is_absolute_http(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|rest| !rest.starts_with(['/', '?', '#']) && !rest.is_empty())
}

/// Whether `url` is a relative reference of the same host: no scheme (no `:` before the
/// first `/`, `?` or `#`) and no network-path form (`//host/...`).
fn is_relative_reference(url: &str) -> bool {
    if url.starts_with("//") {
        return false;
    }
    let end = url.find(['/', '?', '#']).unwrap_or(url.len());
    !url[..end].contains(':')
}

/// Whether `url` is acceptable as the URL of an asset.
fn is_valid_asset_url(url: &str) -> bool {
    !url.is_empty()
        && url.chars().count() <= MAX_URL_CHARS
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
        && (is_absolute_http(url) || is_relative_reference(url))
}

impl ReleaseAsset {
    /// Validates the fields of the asset at `index` of the release `version`.
    fn check(&self, version: &ReleaseVersion, index: usize) -> Result<(), ManifestError> {
        let at = || format!("(asset {}: `{}`)", index + 1, printable(&self.platform));
        if !is_valid_platform(&self.platform) {
            return Err(invalid(
                version,
                "assets.platform",
                format!(
                    "must be <os>-<arch> in lowercase, such as linux-x86_64 (asset {}: found \
                     `{}`)",
                    index + 1,
                    printable(&self.platform)
                ),
            ));
        }
        if !is_valid_file_name(&self.name) {
            return Err(invalid(
                version,
                "assets.name",
                format!(
                    "must be a plain file name of at most {MAX_NAME_CHARS} characters without \
                     separators, `..`, control characters or a leading dot (found `{}`) {}",
                    printable(&self.name),
                    at()
                ),
            ));
        }
        let digest_ok = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !digest_ok {
            return Err(invalid(
                version,
                "assets.sha256",
                format!("must be 64 lowercase hexadecimal digits {}", at()),
            ));
        }
        if self.size == 0 || self.size > MAX_ASSET_BYTES {
            return Err(invalid(
                version,
                "assets.size",
                format!(
                    "must be between 1 and {MAX_ASSET_BYTES} bytes (found {}) {}",
                    self.size,
                    at()
                ),
            ));
        }
        if !is_valid_asset_url(&self.url) {
            return Err(invalid(
                version,
                "assets.url",
                format!(
                    "must be an http(s) URL or a URL relative to the manifest, at most \
                     {MAX_URL_CHARS} characters without whitespace (found `{}`) {}",
                    printable(&self.url),
                    at()
                ),
            ));
        }
        Ok(())
    }
}

/// The platform this build runs on, as the assets name it: `<os>-<arch>` from
/// `std::env::consts::OS` and `ARCH`, for example `linux-x86_64`.
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Resolves the `url` of an asset against the URL the manifest was fetched from.
///
/// An absolute `http` or `https` URL is returned as it is. A URL that starts with `/`
/// replaces the path of `base`; any other relative URL replaces the last path segment of
/// `base`. The query and the fragment of `base` are dropped. Dot segments are not
/// normalised. Returns `None` when `url` is empty, contains whitespace or control
/// characters, names another scheme or a network path (`//host/...`), or when it is
/// relative and `base` is not an absolute `http` or `https` URL.
pub fn resolve_url(base: &str, url: &str) -> Option<String> {
    if url.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if is_absolute_http(url) {
        return Some(url.to_owned());
    }
    if !is_relative_reference(url) {
        return None;
    }
    let (origin, path) = split_base(base)?;
    if url.starts_with('/') {
        return Some(format!("{origin}{url}"));
    }
    let directory = path.rfind('/').map_or("/", |i| &path[..=i]);
    Some(format!("{origin}{directory}{url}"))
}

/// Splits an absolute `http(s)` URL into its origin (`scheme://authority`) and its path
/// without query and fragment.
fn split_base(base: &str) -> Option<(&str, &str)> {
    if base.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let scheme_len = if base.starts_with("https://") {
        "https://".len()
    } else if base.starts_with("http://") {
        "http://".len()
    } else {
        return None;
    };
    let rest = &base[scheme_len..];
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let origin = &base[..scheme_len + authority_len];
    let after = &rest[authority_len..];
    let path_len = after.find(['?', '#']).unwrap_or(after.len());
    Some((origin, &after[..path_len]))
}

// ---------------------------------------------------------------------------------------
// Changelog sections
// ---------------------------------------------------------------------------------------

/// One `## ` section of `CHANGELOG.md`: the unreleased changes or one released version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogSection {
    /// The version; `None` for the `[Unreleased]` section.
    pub version: Option<ReleaseVersion>,
    /// Release date, `YYYY-MM-DD`; `None` for the `[Unreleased]` section.
    pub date: Option<String>,
    /// The Markdown of the section without its `## ` heading, trimmed of leading and trailing
    /// blank lines, with LF line ends and without link reference definitions.
    pub body: String,
    /// Number of list items (lines that start with `- ` or `* `) in the section.
    pub entries: usize,
    /// The section has a `### Security` subsection with text.
    pub security: bool,
    /// The section has a `### Action required` subsection with text.
    pub requires_action: bool,
    /// The text of the `### Action required` subsection, trimmed.
    pub action: Option<String>,
}

impl ChangelogSection {
    /// The release this section describes, for released sections only: `notes` is the body,
    /// and the assets, format and image are left empty for the release process to fill.
    pub fn to_release(&self) -> Option<Release> {
        Some(Release {
            version: self.version.clone()?,
            date: self.date.clone()?,
            notes: self.body.clone(),
            security: self.security,
            requires_action: self.requires_action,
            action: self.action.clone(),
            format: None,
            assets: Vec::new(),
            image: None,
        })
    }
}

/// Why `CHANGELOG.md` does not follow the format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogError {
    /// Line of the problem, counted from 1.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

impl fmt::Display for ChangelogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CHANGELOG line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ChangelogError {}

fn changelog_error(line: usize, reason: impl Into<String>) -> ChangelogError {
    ChangelogError {
        line,
        reason: reason.into(),
    }
}

/// The subsection names of a section.
const SUBSECTIONS: [&str; 7] = [
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Action required",
];

/// The subsections the parser reads the flags from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubsectionKind {
    Security,
    ActionRequired,
    Other,
}

/// A section that is being read.
struct OpenSection<'a> {
    /// Line of its heading.
    line: usize,
    version: Option<ReleaseVersion>,
    date: Option<String>,
    /// Every line after the heading, link reference definitions removed.
    lines: Vec<&'a str>,
    /// The subsections in order, with the lines below their headings.
    subsections: Vec<(SubsectionKind, Vec<&'a str>)>,
}

/// Whether `line` is a link reference definition: `^\[[^\]]+\]: \S+`.
fn is_link_definition(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let Some(close) = rest.find(']') else {
        return false;
    };
    if close == 0 {
        return false;
    }
    rest[close + 1..]
        .strip_prefix(": ")
        .and_then(|target| target.chars().next())
        .is_some_and(|c| !c.is_whitespace())
}

/// The lines without leading and trailing blank lines, joined with LF.
fn join_trimmed(lines: &[&str]) -> String {
    let Some(start) = lines.iter().position(|l| !l.trim().is_empty()) else {
        return String::new();
    };
    let end = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(start + 1, |i| i + 1);
    lines[start..end].join("\n")
}

impl OpenSection<'_> {
    fn finish(self) -> ChangelogSection {
        let entries = self
            .lines
            .iter()
            .filter(|l| l.starts_with("- ") || l.starts_with("* "))
            .count();
        let security = self.subsections.iter().any(|(kind, lines)| {
            *kind == SubsectionKind::Security && lines.iter().any(|l| !l.trim().is_empty())
        });
        let actions: Vec<String> = self
            .subsections
            .iter()
            .filter(|(kind, _)| *kind == SubsectionKind::ActionRequired)
            .map(|(_, lines)| join_trimmed(lines).trim().to_owned())
            .filter(|text| !text.is_empty())
            .collect();
        let action = if actions.is_empty() {
            None
        } else {
            Some(actions.join("\n\n"))
        };
        ChangelogSection {
            version: self.version,
            date: self.date,
            body: join_trimmed(&self.lines),
            entries,
            security,
            requires_action: action.is_some(),
            action,
        }
    }
}

/// A parsed `## ` heading.
enum Heading {
    Unreleased,
    Released(ReleaseVersion, String),
}

/// Reads a `## ` heading (already trimmed at the end).
fn parse_heading(heading: &str, line: usize) -> Result<Heading, ChangelogError> {
    const EXPECTED: &str = "expected `## [Unreleased]` or `## [X.Y.Z] - YYYY-MM-DD`";
    let unknown = || {
        changelog_error(
            line,
            format!(
                "unrecognised section heading `{}`; {EXPECTED}",
                printable(heading)
            ),
        )
    };
    let rest = heading.strip_prefix("## [").ok_or_else(unknown)?;
    let (name, tail) = rest.split_once(']').ok_or_else(unknown)?;
    if name == "Unreleased" {
        return if tail.is_empty() {
            Ok(Heading::Unreleased)
        } else {
            Err(unknown())
        };
    }
    if tail.is_empty() {
        return Err(changelog_error(
            line,
            format!(
                "the heading of version {} has no release date; {EXPECTED}",
                printable(name)
            ),
        ));
    }
    let date = tail.strip_prefix(" - ").ok_or_else(unknown)?;
    if name.starts_with('v') {
        return Err(changelog_error(
            line,
            format!(
                "the version `{}` must be written without a leading `v`",
                printable(name)
            ),
        ));
    }
    let version = name
        .parse::<ReleaseVersion>()
        .map_err(|e| changelog_error(line, e.to_string()))?;
    if !is_valid_date(date) {
        return Err(changelog_error(
            line,
            format!(
                "`{}` is not a release date written YYYY-MM-DD",
                printable(date)
            ),
        ));
    }
    Ok(Heading::Released(version, date.to_owned()))
}

/// Parses `CHANGELOG.md` (Keep a Changelog 1.1.0 with the `### Action required`
/// subsection) into its sections, in file order.
///
/// The text before the first `## ` heading and the link reference definitions
/// (`[0.1.0]: https://...`) are ignored. A section heading is `## [Unreleased]` (first and
/// at most once) or `## [X.Y.Z] - YYYY-MM-DD`; the versions are unique and strictly
/// descending. A `### ` heading must name one of Added, Changed, Deprecated, Removed, Fixed,
/// Security and Action required; deeper headings are body text. CRLF line ends are read as
/// LF, and a leading byte order mark is skipped.
///
/// # Errors
///
/// The first line that breaks a rule, with its 1-based line number.
pub fn parse_changelog(text: &str) -> Result<Vec<ChangelogSection>, ChangelogError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut sections: Vec<ChangelogSection> = Vec::new();
    // The line of each finished section's heading, parallel to `sections`.
    let mut heading_lines: Vec<usize> = Vec::new();
    let mut open: Option<OpenSection<'_>> = None;

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        if is_link_definition(raw) {
            continue;
        }
        if raw.starts_with("## ") {
            if let Some(done) = open.take() {
                heading_lines.push(done.line);
                sections.push(done.finish());
            }
            let (version, date) = match parse_heading(raw.trim_end(), line)? {
                Heading::Unreleased => (None, None),
                Heading::Released(version, date) => (Some(version), Some(date)),
            };
            check_order(&sections, &heading_lines, version.as_ref(), line)?;
            open = Some(OpenSection {
                line,
                version,
                date,
                lines: Vec::new(),
                subsections: Vec::new(),
            });
            continue;
        }
        // Text before the first section is the preamble.
        let Some(section) = open.as_mut() else {
            continue;
        };
        if let Some(name) = raw.strip_prefix("### ") {
            let kind = match name.trim_end() {
                "Security" => SubsectionKind::Security,
                "Action required" => SubsectionKind::ActionRequired,
                other if SUBSECTIONS.contains(&other) => SubsectionKind::Other,
                other => {
                    return Err(changelog_error(
                        line,
                        format!(
                            "unknown subsection `### {}`; expected one of {}",
                            printable(other),
                            SUBSECTIONS.join(", ")
                        ),
                    ));
                }
            };
            section.subsections.push((kind, Vec::new()));
        } else if let Some((_, lines)) = section.subsections.last_mut() {
            lines.push(raw);
        }
        section.lines.push(raw);
    }
    if let Some(done) = open.take() {
        sections.push(done.finish());
    }
    Ok(sections)
}

/// Checks that a new section heading keeps the order of the file: `[Unreleased]` first and
/// once, versions unique and strictly descending.
fn check_order(
    sections: &[ChangelogSection],
    heading_lines: &[usize],
    version: Option<&ReleaseVersion>,
    line: usize,
) -> Result<(), ChangelogError> {
    let Some(version) = version else {
        if sections.is_empty() {
            return Ok(());
        }
        return Err(if sections.iter().any(|s| s.version.is_none()) {
            changelog_error(line, "`## [Unreleased]` appears more than once")
        } else {
            changelog_error(line, "`## [Unreleased]` must be the first section")
        });
    };
    if let Some(at) = sections
        .iter()
        .position(|s| s.version.as_ref() == Some(version))
    {
        return Err(changelog_error(
            line,
            format!(
                "version {version} is listed twice (first at line {})",
                heading_lines[at]
            ),
        ));
    }
    if let Some(above) = sections.iter().rev().find_map(|s| s.version.as_ref())
        && version > above
    {
        return Err(changelog_error(
            line,
            format!(
                "version {version} is newer than {above} above it; sections must run from the \
                 newest version to the oldest"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn v(text: &str) -> ReleaseVersion {
        text.parse().expect("test version")
    }

    // ------------------------------------------------------------------ versions

    #[test]
    fn versions_parse_in_every_documented_form() {
        let plain = v("1.2.3");
        assert_eq!((plain.major(), plain.minor(), plain.patch()), (1, 2, 3));
        assert!(!plain.is_prerelease());
        assert_eq!(plain.build(), None);

        assert_eq!(v("v0.2.0"), v("0.2.0"));
        assert_eq!(v("v0.2.0").to_string(), "0.2.0");
        assert_eq!(v("0.0.0"), ReleaseVersion::new(0, 0, 0));

        let rc = v("1.2.0-rc.1");
        assert!(rc.is_prerelease());
        assert_eq!(rc.to_string(), "1.2.0-rc.1");

        let built = v("1.2.0+build.5");
        assert!(!built.is_prerelease());
        assert_eq!(built.build(), Some("build.5"));
        assert_eq!(built.to_string(), "1.2.0+build.5");

        let both = v("1.0.0-alpha-1.x.0a+meta-1.007");
        assert!(both.is_prerelease());
        assert_eq!(both.to_string(), "1.0.0-alpha-1.x.0a+meta-1.007");
    }

    #[test]
    fn invalid_versions_are_refused() {
        for text in [
            "",
            "x",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-+x",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3-a_b",
            "1.2.3-\u{e9}",
            "1.2.3+a..b",
            "1.-2.3",
            "+1.2.3",
            "-1.2.3",
            "V1.2.3",
            "vv1.2.3",
            "v",
            " 1.2.3",
            "1.2.3 ",
            "1.2.3\n",
            "18446744073709551616.0.0",
            "1.0.0-18446744073709551616",
        ] {
            assert_eq!(
                text.parse::<ReleaseVersion>(),
                Err(InvalidVersion(printable(text))),
                "{text:?}"
            );
        }
        let too_long = format!("1.0.0-{}", "a".repeat(MAX_VERSION_BYTES));
        assert!(too_long.parse::<ReleaseVersion>().is_err());
    }

    #[test]
    fn invalid_version_message_names_the_text_and_is_bounded() {
        let error = "x".parse::<ReleaseVersion>().expect_err("not a version");
        assert_eq!(error, InvalidVersion("x".to_owned()));
        assert_eq!(
            error.to_string(),
            "`x` is not a release version such as 1.2.3 or 1.2.3-rc.1"
        );
        let long = "z\n".repeat(500);
        let echoed = long.parse::<ReleaseVersion>().expect_err("not a version").0;
        assert!(echoed.chars().count() <= MAX_ECHO_CHARS + 3);
        assert!(!echoed.contains('\n'));
    }

    #[test]
    fn precedence_follows_semver() {
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in chain.windows(2) {
            let (low, high) = (v(pair[0]), v(pair[1]));
            assert!(low < high, "{low} < {high}");
            assert!(high > low, "{high} > {low}");
            assert_ne!(low, high);
        }
        let mut shuffled: Vec<ReleaseVersion> = chain.iter().rev().map(|t| v(t)).collect();
        shuffled.sort();
        let sorted: Vec<String> = shuffled.iter().map(ToString::to_string).collect();
        assert_eq!(sorted, chain);

        assert!(v("1.2.10") > v("1.2.9"));
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("2.0.0") > v("1.99.99"));
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert!(v("1.0.0-2") < v("1.0.0-10"));
        assert!(v("1.0.0-rc.1") < v("1.0.1-alpha"));
    }

    #[test]
    fn build_metadata_is_ignored_for_equality_ordering_and_hashing() {
        let (a, b) = (v("1.0.0+build.5"), v("1.0.0+other"));
        assert_eq!(a, b);
        assert_eq!(a, v("1.0.0"));
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a.partial_cmp(&v("1.0.0")), Some(Ordering::Equal));
        let mut set = HashSet::new();
        assert!(set.insert(a));
        assert!(!set.insert(b));
        assert!(!set.insert(v("1.0.0")));
        assert!(v("1.0.0-rc.1+a") < v("1.0.0+b"));
    }

    #[test]
    fn versions_are_strings_in_json() {
        assert_eq!(
            serde_json::to_value(v("v1.2.0-rc.1+b.5")).expect("json"),
            json!("1.2.0-rc.1+b.5")
        );
        assert_eq!(
            serde_json::from_value::<ReleaseVersion>(json!("v0.2.0")).expect("version"),
            v("0.2.0")
        );
        let error = serde_json::from_value::<ReleaseVersion>(json!("1.2"))
            .expect_err("not a version")
            .to_string();
        assert!(error.contains("`1.2` is not a release version"), "{error}");
        assert!(serde_json::from_value::<ReleaseVersion>(json!(1)).is_err());
    }

    #[test]
    fn version_schema_is_a_string() {
        use utoipa::PartialSchema;
        let schema = serde_json::to_value(ReleaseVersion::schema()).expect("json");
        assert_eq!(schema["type"], "string");
        assert!(schema["examples"].is_array() || schema["example"].is_string());
    }

    #[test]
    fn openapi_document_describes_the_manifest() {
        #[derive(utoipa::OpenApi)]
        #[openapi(components(schemas(ReleaseManifest)))]
        struct Doc;

        let doc = serde_json::to_value(<Doc as utoipa::OpenApi>::openapi()).expect("json");
        let schemas = &doc["components"]["schemas"];
        for name in [
            "ReleaseManifest",
            "Release",
            "ReleaseAsset",
            "ReleaseVersion",
        ] {
            assert!(schemas.get(name).is_some(), "{name} in {schemas}");
        }
        assert_eq!(schemas["ReleaseVersion"]["type"], "string");
    }

    // ------------------------------------------------------------------ the manifest

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn asset(platform: &str) -> ReleaseAsset {
        ReleaseAsset {
            platform: platform.to_owned(),
            name: format!("tenko-0.2.0-{platform}"),
            url: format!("tenko-0.2.0-{platform}"),
            sha256: DIGEST.to_owned(),
            size: 1_234_567,
            signature: None,
        }
    }

    fn release(version: &str) -> Release {
        Release {
            version: v(version),
            date: "2026-10-09".to_owned(),
            notes: format!("### Added\n\n- Notes of {version}."),
            security: false,
            requires_action: false,
            action: None,
            format: None,
            assets: Vec::new(),
            image: None,
        }
    }

    fn manifest(versions: &[&str]) -> ReleaseManifest {
        ReleaseManifest {
            schema: MANIFEST_SCHEMA,
            project: "tenko".to_owned(),
            releases: versions.iter().map(|t| release(t)).collect(),
        }
    }

    /// A manifest with every optional field set on its one release.
    fn full_manifest() -> ReleaseManifest {
        let mut full = release("0.2.0");
        full.security = true;
        full.requires_action = true;
        full.action = Some("Run `tenko migrate` before starting.".to_owned());
        full.format = Some(2);
        full.assets = vec![
            asset("linux-x86_64"),
            ReleaseAsset {
                signature: Some("c2lnbmF0dXJl".to_owned()),
                url: "https://downloads.example.com/tenko-0.2.0-windows-x86_64.exe".to_owned(),
                name: "tenko-0.2.0-windows-x86_64.exe".to_owned(),
                ..asset("windows-x86_64")
            },
        ];
        full.image = Some("ghcr.io/example/tenko:0.2.0".to_owned());
        ReleaseManifest {
            releases: vec![full, release("0.1.0")],
            ..manifest(&[])
        }
    }

    fn assert_invalid(manifest: &ReleaseManifest, field: &str) -> ManifestError {
        let error = manifest.validate().expect_err("invalid manifest");
        assert_eq!(error.code(), "update.manifest.invalid", "{error}");
        match &error {
            ManifestError::Invalid {
                field: found,
                version,
                reason,
            } => {
                assert_eq!(*found, field, "{error}");
                assert_ne!(reason.len(), 0);
                assert!(version.is_some() || field == "releases");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        error
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let original = full_manifest();
        let bytes = serde_json::to_vec(&original).expect("json");
        let parsed = ReleaseManifest::parse(&bytes).expect("valid manifest");
        assert_eq!(parsed, original);

        let value: Value = serde_json::to_value(&original).expect("json");
        let first = &value["releases"][0];
        assert_eq!(first["version"], "0.2.0");
        assert_eq!(first["assets"][0].get("signature"), None);
        assert_eq!(first["assets"][1]["signature"], "c2lnbmF0dXJl");
        let bare = &value["releases"][1];
        for absent in ["action", "format", "image"] {
            assert_eq!(bare.get(absent), None, "{absent}");
        }
        assert_eq!(bare["assets"], json!([]));
        assert_eq!(bare["security"], false);
    }

    #[test]
    fn optional_fields_default_and_unknown_fields_are_ignored() {
        let text = json!({
            "schema": 1,
            "project": "tenko",
            "generated_by": "release pipeline",
            "releases": [{
                "version": "v0.1.0",
                "date": "2026-01-02",
                "notes": "First release.",
                "channel": "stable",
                "assets": [{
                    "platform": "linux-x86_64",
                    "name": "tenko-0.1.0-linux-x86_64",
                    "url": "/downloads/tenko-0.1.0-linux-x86_64",
                    "sha256": DIGEST,
                    "size": 10,
                    "mirrors": ["https://mirror.example.net/x"]
                }]
            }]
        });
        let parsed = ReleaseManifest::parse(text.to_string().as_bytes()).expect("valid");
        let release = &parsed.releases[0];
        assert_eq!(release.version, v("0.1.0"));
        assert!(!release.security && !release.requires_action);
        assert_eq!(
            (&release.action, release.format, &release.image),
            (&None, None, &None)
        );
        assert_eq!(release.assets[0].signature, None);
    }

    #[test]
    fn parse_sorts_newest_first() {
        let unsorted = manifest(&["0.1.0", "1.0.0-rc.1", "0.10.0", "1.0.0", "0.9.0"]);
        let parsed =
            ReleaseManifest::parse(&serde_json::to_vec(&unsorted).expect("json")).expect("valid");
        let order: Vec<String> = parsed
            .releases
            .iter()
            .map(|r| r.version.to_string())
            .collect();
        assert_eq!(order, ["1.0.0", "1.0.0-rc.1", "0.10.0", "0.9.0", "0.1.0"]);
    }

    #[test]
    fn parse_refuses_oversized_documents_before_parsing() {
        let error = ReleaseManifest::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1]).expect_err("big");
        assert_eq!(
            error,
            ManifestError::TooLarge {
                bytes: MAX_MANIFEST_BYTES + 1
            }
        );
        assert_eq!(error.code(), "update.manifest.too_large");
        assert!(error.to_string().contains("1048577"));
        // At the limit the document is parsed (and refused for its content).
        let at_limit = ReleaseManifest::parse(&vec![b' '; MAX_MANIFEST_BYTES]).expect_err("empty");
        assert_eq!(at_limit.code(), "update.manifest.json");
    }

    #[test]
    fn parse_reports_json_problems() {
        for bytes in [
            &b"not json"[..],
            b"",
            b"[]",
            br#"{"schema":1,"project":"tenko"}"#,
            br#"{"schema":1,"project":"tenko","releases":[{"version":"1.2"}]}"#,
            br#"{"schema":"one","project":"tenko","releases":[]}"#,
        ] {
            let error = ReleaseManifest::parse(bytes).expect_err("not a manifest");
            assert!(matches!(error, ManifestError::Json(_)), "{error:?}");
            assert_eq!(error.code(), "update.manifest.json");
        }
        let error = ReleaseManifest::parse(
            br#"{"schema":1,"project":"tenko","releases":[{"version":"1.2"}]}"#,
        )
        .expect_err("bad version");
        assert!(
            error.to_string().contains("`1.2` is not a release version"),
            "{error}"
        );
    }

    #[test]
    fn schema_other_than_one_is_refused() {
        let newer = ReleaseManifest::parse(br#"{"schema":2,"project":"tenko","releases":[]}"#)
            .expect_err("newer");
        assert_eq!(newer, ManifestError::Schema { found: 2 });
        assert_eq!(newer.code(), "update.manifest.schema");
        assert!(newer.to_string().contains("newer Tenko"), "{newer}");

        // A newer schema may change the shape; it is still recognised as newer.
        let reshaped = ReleaseManifest::parse(br#"{"schema":3,"channels":{"stable":[]}}"#)
            .expect_err("reshaped");
        assert_eq!(reshaped, ManifestError::Schema { found: 3 });

        let zero = ReleaseManifest::parse(br#"{"schema":0,"project":"tenko","releases":[]}"#)
            .expect_err("zero");
        assert_eq!(zero, ManifestError::Schema { found: 0 });
        assert!(zero.to_string().contains("not supported"), "{zero}");
        assert!(!zero.to_string().contains("newer"), "{zero}");

        let mut direct = manifest(&[]);
        direct.schema = 7;
        assert_eq!(direct.validate(), Err(ManifestError::Schema { found: 7 }));
    }

    #[test]
    fn project_must_be_tenko() {
        let error = ReleaseManifest::parse(br#"{"schema":1,"project":"other","releases":[]}"#)
            .expect_err("project");
        assert_eq!(error, ManifestError::Project("other".to_owned()));
        assert_eq!(error.code(), "update.manifest.project");
        assert!(error.to_string().contains("`other`"), "{error}");
        let mut empty = manifest(&[]);
        empty.project = "Tenko".to_owned();
        assert!(matches!(empty.validate(), Err(ManifestError::Project(_))));
        assert!(manifest(&[]).validate().is_ok());
    }

    #[test]
    fn release_count_is_limited() {
        let mut many = manifest(&[]);
        many.releases = (0..=MAX_RELEASES as u64)
            .map(|n| release(&format!("1.{n}.0")))
            .collect();
        assert_invalid(&many, "releases");
        many.releases.pop();
        assert_eq!(many.validate(), Ok(()));
    }

    #[test]
    fn versions_must_be_unique() {
        let error = manifest(&["1.0.0", "0.9.0", "1.0.0"])
            .validate()
            .expect_err("duplicate");
        assert_eq!(error, ManifestError::DuplicateVersion("1.0.0".to_owned()));
        assert_eq!(error.code(), "update.manifest.invalid");
        assert!(error.to_string().contains("1.0.0"), "{error}");
        // Build metadata does not make a version different.
        assert!(matches!(
            manifest(&["1.0.0+a", "1.0.0+b"]).validate(),
            Err(ManifestError::DuplicateVersion(_))
        ));
    }

    #[test]
    fn dates_must_be_written_yyyy_mm_dd() {
        for good in ["2026-10-09", "1999-12-31", "2026-01-01", "2026-02-31"] {
            let mut m = manifest(&["1.0.0"]);
            m.releases[0].date = good.to_owned();
            assert_eq!(m.validate(), Ok(()), "{good}");
        }
        for bad in [
            "",
            "2026-1-9",
            "2026-13-01",
            "2026-00-10",
            "2026-10-00",
            "2026-10-32",
            "26-10-09",
            "2026/10/09",
            "2026-10-09 ",
            "2026-10-09T10:00:00Z",
            "20261009",
            "abcd-ef-gh",
            "2026-1\u{e9}-09",
            "\u{663}026-10-09",
        ] {
            let mut m = manifest(&["1.0.0"]);
            m.releases[0].date = bad.to_owned();
            let error = assert_invalid(&m, "date");
            assert!(
                error.to_string().starts_with("release 1.0.0: `date`"),
                "{error}"
            );
        }
    }

    #[test]
    fn notes_and_action_are_bounded() {
        let mut m = manifest(&["1.0.0"]);
        m.releases[0].notes = "n".repeat(MAX_NOTES_BYTES);
        assert_eq!(m.validate(), Ok(()));
        m.releases[0].notes.push('n');
        assert_invalid(&m, "notes");

        let mut m = manifest(&["1.0.0"]);
        m.releases[0].action = Some("a".repeat(MAX_ACTION_BYTES));
        assert_eq!(m.validate(), Ok(()));
        m.releases[0].action = Some("a".repeat(MAX_ACTION_BYTES + 1));
        assert_invalid(&m, "action");
    }

    #[test]
    fn required_action_needs_a_text() {
        for action in [None, Some(String::new()), Some(" \n\t ".to_owned())] {
            let mut m = manifest(&["1.0.0"]);
            m.releases[0].requires_action = true;
            m.releases[0].action = action;
            assert_invalid(&m, "action");
        }
        let mut ok = manifest(&["1.0.0"]);
        ok.releases[0].requires_action = true;
        ok.releases[0].action = Some("Back up the data directory.".to_owned());
        assert_eq!(ok.validate(), Ok(()));
        // An action without the flag is allowed.
        let mut hint = manifest(&["1.0.0"]);
        hint.releases[0].action = Some("Optional hint.".to_owned());
        assert_eq!(hint.validate(), Ok(()));
    }

    #[test]
    fn format_starts_at_one() {
        let mut m = manifest(&["1.0.0"]);
        m.releases[0].format = Some(0);
        assert_invalid(&m, "format");
        m.releases[0].format = Some(1);
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn image_is_a_reference_without_whitespace() {
        for bad in [
            String::new(),
            "ghcr.io/example/tenko 0.2.0".to_owned(),
            "ghcr.io/example/tenko:0.2.0\n".to_owned(),
            format!("ghcr.io/example/{}", "t".repeat(MAX_IMAGE_CHARS)),
        ] {
            let mut m = manifest(&["1.0.0"]);
            m.releases[0].image = Some(bad);
            assert_invalid(&m, "image");
        }
        let mut ok = manifest(&["1.0.0"]);
        ok.releases[0].image = Some("t".repeat(MAX_IMAGE_CHARS));
        assert_eq!(ok.validate(), Ok(()));
        ok.releases[0].image = Some("ghcr.io/example/tenko@sha256:".to_owned() + DIGEST);
        assert_eq!(ok.validate(), Ok(()));
    }

    fn with_asset(edit: impl FnOnce(&mut ReleaseAsset)) -> ReleaseManifest {
        let mut m = manifest(&["1.0.0"]);
        let mut a = asset("linux-x86_64");
        edit(&mut a);
        m.releases[0].assets = vec![a];
        m
    }

    #[test]
    fn asset_platform_is_os_dash_arch() {
        for good in [
            "linux-x86_64",
            "linux-aarch64",
            "windows-x86_64",
            "macos-aarch64",
            "a-b",
        ] {
            assert_eq!(
                with_asset(|a| a.platform = good.to_owned()).validate(),
                Ok(()),
                "{good}"
            );
        }
        for bad in [
            "",
            "linux",
            "linux-",
            "-x86_64",
            "linux-x86-64",
            "Linux-x86_64",
            "linux x86_64",
            "linux_x86_64",
            "linux-x86_64\n",
            "linux-x86.64",
            "linux-\u{e9}",
        ] {
            let error = assert_invalid(
                &with_asset(|a| a.platform = bad.to_owned()),
                "assets.platform",
            );
            assert!(error.to_string().contains("asset 1"), "{error}");
        }
    }

    #[test]
    fn asset_platforms_are_unique_within_a_release() {
        let mut m = manifest(&["1.0.0", "0.9.0"]);
        m.releases[0].assets = vec![asset("linux-x86_64"), asset("windows-x86_64")];
        // The same platform in another release is fine.
        m.releases[1].assets = vec![asset("linux-x86_64")];
        assert_eq!(m.validate(), Ok(()));
        m.releases[0].assets.push(asset("linux-x86_64"));
        let error = assert_invalid(&m, "assets.platform");
        assert!(error.to_string().contains("listed twice"), "{error}");
    }

    #[test]
    fn asset_names_are_plain_file_names() {
        let longest = "n".repeat(MAX_NAME_CHARS);
        for good in [
            "tenko",
            "tenko-0.2.0-windows-x86_64.exe",
            "a.b.c",
            longest.as_str(),
        ] {
            assert_eq!(
                with_asset(|a| a.name = good.to_owned()).validate(),
                Ok(()),
                "{good}"
            );
        }
        for bad in [
            String::new(),
            "dir/tenko".to_owned(),
            "dir\\tenko".to_owned(),
            "..".to_owned(),
            "tenko..exe".to_owned(),
            ".tenko".to_owned(),
            "ten\u{0}ko".to_owned(),
            "ten\nko".to_owned(),
            "ten\u{7f}ko".to_owned(),
            "n".repeat(MAX_NAME_CHARS + 1),
        ] {
            assert_invalid(&with_asset(|a| a.name = bad.clone()), "assets.name");
        }
    }

    #[test]
    fn asset_digest_is_64_lowercase_hex_digits() {
        for bad in [
            String::new(),
            DIGEST[..63].to_owned(),
            format!("{DIGEST}0"),
            DIGEST.to_uppercase(),
            DIGEST.replacen('0', "g", 1),
            format!("sha256:{}", &DIGEST[..58]),
            format!(" {}", &DIGEST[..63]),
        ] {
            assert_invalid(&with_asset(|a| a.sha256 = bad.clone()), "assets.sha256");
        }
    }

    #[test]
    fn asset_size_is_between_one_byte_and_the_limit() {
        assert_invalid(&with_asset(|a| a.size = 0), "assets.size");
        assert_invalid(&with_asset(|a| a.size = MAX_ASSET_BYTES + 1), "assets.size");
        assert_eq!(with_asset(|a| a.size = 1).validate(), Ok(()));
        assert_eq!(with_asset(|a| a.size = MAX_ASSET_BYTES).validate(), Ok(()));
    }

    #[test]
    fn asset_urls_are_http_or_relative() {
        for good in [
            "https://downloads.example.com/tenko-0.2.0-linux-x86_64",
            "http://downloads.example.org:8080/a/b?x=1#f",
            "tenko-0.2.0-linux-x86_64",
            "/downloads/tenko",
            "../tenko",
            "./tenko",
            "sub/dir/tenko",
            "tenko?token=a:b",
            "tenko#a:b",
            "a/b:c",
        ] {
            assert_eq!(
                with_asset(|a| a.url = good.to_owned()).validate(),
                Ok(()),
                "{good}"
            );
        }
        let long_tail = "u".repeat(MAX_URL_CHARS - "https://example.com/".len());
        assert_eq!(
            with_asset(|a| a.url = format!("https://example.com/{long_tail}")).validate(),
            Ok(())
        );
        for bad in [
            String::new(),
            "ftp://example.com/tenko".to_owned(),
            "file:///tenko".to_owned(),
            "javascript:alert(1)".to_owned(),
            "HTTPS://example.com/tenko".to_owned(),
            "c:\\tenko".to_owned(),
            "tenko:1".to_owned(),
            "//example.com/tenko".to_owned(),
            "https://".to_owned(),
            "https:///tenko".to_owned(),
            "https://example.com/ten ko".to_owned(),
            "https://example.com/ten\tko".to_owned(),
            "https://example.com/ten\nko".to_owned(),
            " tenko".to_owned(),
            "ten\u{0}ko".to_owned(),
            format!("https://example.com/{long_tail}u"),
        ] {
            assert_invalid(&with_asset(|a| a.url = bad.clone()), "assets.url");
        }
    }

    #[test]
    fn errors_name_the_release_and_the_asset() {
        let mut m = manifest(&["0.2.0"]);
        m.releases[0].assets = vec![asset("linux-x86_64"), {
            let mut broken = asset("windows-x86_64");
            broken.sha256 = "zz".to_owned();
            broken
        }];
        let text = m.validate().expect_err("bad digest").to_string();
        assert!(
            text.starts_with("release 0.2.0: `assets.sha256` must be 64"),
            "{text}"
        );
        assert!(text.contains("asset 2: `windows-x86_64`"), "{text}");
    }

    // ------------------------------------------------------------------ queries

    fn query_manifest() -> ReleaseManifest {
        let mut m = manifest(&[
            "0.1.0",
            "0.2.0-rc.1",
            "0.2.0",
            "0.3.0-beta.1",
            "0.2.1",
            "1.0.0-rc.1",
        ]);
        m.releases.sort_by(|a, b| b.version.cmp(&a.version));
        m.releases[0].assets = vec![asset("linux-x86_64"), asset("windows-x86_64")];
        m
    }

    fn versions(releases: &[&Release]) -> Vec<String> {
        releases.iter().map(|r| r.version.to_string()).collect()
    }

    #[test]
    fn latest_skips_prereleases_unless_asked() {
        let m = query_manifest();
        assert_eq!(
            m.latest(true).map(|r| r.version.to_string()).as_deref(),
            Some("1.0.0-rc.1")
        );
        assert_eq!(
            m.latest(false).map(|r| r.version.to_string()).as_deref(),
            Some("0.2.1")
        );
        assert!(manifest(&[]).latest(true).is_none());
        assert!(manifest(&["1.0.0-rc.1"]).latest(false).is_none());
        // Does not rely on the order of the list.
        let unsorted = manifest(&["0.1.0", "0.3.0", "0.2.0"]);
        assert_eq!(
            unsorted
                .latest(false)
                .map(|r| r.version.to_string())
                .as_deref(),
            Some("0.3.0")
        );
    }

    #[test]
    fn release_finds_a_version_ignoring_build_metadata() {
        let m = query_manifest();
        assert_eq!(
            m.release(&v("0.2.0"))
                .map(|r| r.version.to_string())
                .as_deref(),
            Some("0.2.0")
        );
        assert_eq!(
            m.release(&v("0.2.0+build.9")).map(|r| &r.version),
            Some(&v("0.2.0"))
        );
        assert!(m.release(&v("0.2.2")).is_none());
        assert!(m.release(&v("0.2.0-rc.2")).is_none());
    }

    #[test]
    fn newer_than_lists_releases_above_the_running_version() {
        let m = query_manifest();
        assert_eq!(versions(&m.newer_than(&v("0.2.0"), false)), ["0.2.1"]);
        assert_eq!(
            versions(&m.newer_than(&v("0.2.0"), true)),
            ["1.0.0-rc.1", "0.3.0-beta.1", "0.2.1"]
        );
        assert_eq!(
            versions(&m.newer_than(&v("0.1.0"), false)),
            ["0.2.1", "0.2.0"]
        );
        assert_eq!(
            versions(&m.newer_than(&v("0.1.0"), true)),
            ["1.0.0-rc.1", "0.3.0-beta.1", "0.2.1", "0.2.0", "0.2.0-rc.1"]
        );
        // A pre-release at or below the running version is never included.
        assert_eq!(m.newer_than(&v("1.0.0-rc.1"), true).len(), 0);
        assert_eq!(m.newer_than(&v("2.0.0"), true).len(), 0);
        assert_eq!(
            versions(&m.newer_than(&v("0.2.0-rc.1"), false)),
            ["0.2.1", "0.2.0"]
        );
        // Build metadata of the running version does not matter.
        assert_eq!(
            versions(&m.newer_than(&v("0.2.1+local"), true)),
            ["1.0.0-rc.1", "0.3.0-beta.1"]
        );
        // Sorted even when the list is not.
        let mut shuffled = query_manifest();
        shuffled.releases.reverse();
        assert_eq!(
            versions(&shuffled.newer_than(&v("0.1.0"), false)),
            ["0.2.1", "0.2.0"]
        );
    }

    #[test]
    fn between_is_open_below_and_closed_above() {
        let m = query_manifest();
        assert_eq!(
            versions(&m.between(&v("0.1.0"), &v("0.2.1"))),
            ["0.2.1", "0.2.0", "0.2.0-rc.1"]
        );
        assert_eq!(versions(&m.between(&v("0.2.0"), &v("0.2.1"))), ["0.2.1"]);
        assert_eq!(
            versions(&m.between(&v("0.2.0"), &v("0.3.0-beta.1"))),
            ["0.3.0-beta.1", "0.2.1"]
        );
        assert_eq!(m.between(&v("0.2.1"), &v("0.2.1")).len(), 0);
        assert_eq!(m.between(&v("0.3.0"), &v("0.2.0")).len(), 0);
        assert_eq!(m.between(&v("0.0.1"), &v("9.9.9")).len(), 6);
    }

    #[test]
    fn asset_lookup_by_platform() {
        let m = query_manifest();
        let newest = &m.releases[0];
        assert_eq!(
            newest.asset("windows-x86_64").map(|a| a.name.as_str()),
            Some("tenko-0.2.0-windows-x86_64")
        );
        assert!(newest.asset("linux-aarch64").is_none());
        assert!(m.releases[1].asset("linux-x86_64").is_none());
    }

    #[test]
    fn current_platform_is_os_dash_arch() {
        let platform = current_platform();
        assert_eq!(
            platform,
            format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        );
        assert!(is_valid_platform(&platform), "{platform}");
    }

    // ------------------------------------------------------------------ URLs

    #[test]
    fn absolute_urls_are_returned_as_they_are() {
        let base = "https://releases.example.com/tenko/releases.json";
        for url in [
            "https://downloads.example.org/tenko-0.2.0?x=1#f",
            "http://downloads.example.org:8080/a/../b",
            "https://example.com",
        ] {
            assert_eq!(resolve_url(base, url).as_deref(), Some(url));
            // The base does not matter for an absolute URL.
            assert_eq!(resolve_url("not a url", url).as_deref(), Some(url));
        }
    }

    #[test]
    fn root_relative_urls_replace_the_path() {
        assert_eq!(
            resolve_url(
                "https://releases.example.com/tenko/releases.json",
                "/files/tenko"
            )
            .as_deref(),
            Some("https://releases.example.com/files/tenko")
        );
        assert_eq!(
            resolve_url(
                "http://releases.example.com:8080/a/b.json?x=1#top",
                "/files/tenko?v=2"
            )
            .as_deref(),
            Some("http://releases.example.com:8080/files/tenko?v=2")
        );
        assert_eq!(
            resolve_url("https://releases.example.com", "/tenko").as_deref(),
            Some("https://releases.example.com/tenko")
        );
        assert_eq!(
            resolve_url("https://releases.example.com?x=1", "/tenko").as_deref(),
            Some("https://releases.example.com/tenko")
        );
    }

    #[test]
    fn sibling_urls_replace_the_last_segment() {
        assert_eq!(
            resolve_url(
                "https://releases.example.com/tenko/releases.json",
                "tenko-0.2.0-linux-x86_64"
            )
            .as_deref(),
            Some("https://releases.example.com/tenko/tenko-0.2.0-linux-x86_64")
        );
        assert_eq!(
            resolve_url(
                "https://releases.example.com/tenko/releases.json?token=a/b#frag/ment",
                "files/x.exe"
            )
            .as_deref(),
            Some("https://releases.example.com/tenko/files/x.exe")
        );
        assert_eq!(
            resolve_url("https://releases.example.com/tenko/", "x").as_deref(),
            Some("https://releases.example.com/tenko/x")
        );
        assert_eq!(
            resolve_url("https://releases.example.com/releases.json", "x").as_deref(),
            Some("https://releases.example.com/x")
        );
        assert_eq!(
            resolve_url("https://releases.example.com", "x").as_deref(),
            Some("https://releases.example.com/x")
        );
        assert_eq!(
            resolve_url("https://releases.example.com#frag", "x").as_deref(),
            Some("https://releases.example.com/x")
        );
        assert_eq!(
            resolve_url("https://releases.example.com/a/b/c.json", "../x").as_deref(),
            Some("https://releases.example.com/a/b/../x")
        );
    }

    #[test]
    fn unresolvable_urls_give_none() {
        let base = "https://releases.example.com/tenko/releases.json";
        for url in [
            "",
            "ftp://example.com/x",
            "javascript:alert(1)",
            "file:///x",
            "//other.example.net/x",
            "has space",
            "tab\there",
            "new\nline",
        ] {
            assert_eq!(resolve_url(base, url), None, "{url:?}");
        }
        for bad_base in [
            "",
            "releases.json",
            "/tenko/releases.json",
            "ftp://example.com/releases.json",
            "https://",
            "https:///x",
            "https://?x=1",
            "HTTPS://example.com/x",
            "https://example.com/a b",
        ] {
            assert_eq!(resolve_url(bad_base, "x"), None, "{bad_base:?}");
            assert_eq!(resolve_url(bad_base, "/x"), None, "{bad_base:?}");
        }
    }

    // ------------------------------------------------------------------ changelog

    const CHANGELOG: &str = "\
# Changelog

Free preamble text.

## [Unreleased]

### Added

- An entry.

## [0.1.0] - 2026-10-09

### Added

- An entry.

### Security

- A security fix.

### Action required

Text or bullets: what an operator must do when upgrading to this version.

[Unreleased]: https://github.com/example/tenko/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/example/tenko/releases/tag/v0.1.0
";

    fn changelog_error_of(text: &str) -> ChangelogError {
        parse_changelog(text).expect_err("invalid changelog")
    }

    #[test]
    fn the_documented_example_parses_into_two_sections() {
        let sections = parse_changelog(CHANGELOG).expect("valid changelog");
        assert_eq!(sections.len(), 2);

        let unreleased = &sections[0];
        assert_eq!((&unreleased.version, &unreleased.date), (&None, &None));
        assert_eq!(unreleased.body, "### Added\n\n- An entry.");
        assert_eq!(unreleased.entries, 1);
        assert!(!unreleased.security && !unreleased.requires_action);
        assert_eq!(unreleased.action, None);
        assert_eq!(unreleased.to_release(), None);

        let released = &sections[1];
        assert_eq!(released.version, Some(v("0.1.0")));
        assert_eq!(released.date.as_deref(), Some("2026-10-09"));
        assert_eq!(
            released.body,
            "### Added\n\n- An entry.\n\n### Security\n\n- A security fix.\n\n### Action required\n\n\
             Text or bullets: what an operator must do when upgrading to this version."
        );
        assert_eq!(released.entries, 2);
        assert!(released.security);
        assert!(released.requires_action);
        assert_eq!(
            released.action.as_deref(),
            Some("Text or bullets: what an operator must do when upgrading to this version.")
        );

        let release = released.to_release().expect("released section");
        assert_eq!(release.version, v("0.1.0"));
        assert_eq!(release.date, "2026-10-09");
        assert_eq!(release.notes, released.body);
        assert!(release.security && release.requires_action);
        assert_eq!(release.action, released.action);
        assert_eq!(release.assets.len(), 0);
        assert_eq!((release.format, &release.image), (None, &None));
        // A manifest built from the changelog passes the manifest rules.
        let from_changelog = ReleaseManifest {
            releases: vec![release],
            ..manifest(&[])
        };
        assert_eq!(from_changelog.validate(), Ok(()));
    }

    #[test]
    fn crlf_input_gives_the_same_sections() {
        let crlf = CHANGELOG.replace('\n', "\r\n");
        assert_eq!(
            parse_changelog(&crlf).expect("valid"),
            parse_changelog(CHANGELOG).expect("valid")
        );
        let bom = format!("\u{feff}{CHANGELOG}");
        assert_eq!(
            parse_changelog(&bom).expect("valid"),
            parse_changelog(CHANGELOG).expect("valid")
        );
    }

    #[test]
    fn empty_and_preamble_only_changelogs_have_no_sections() {
        assert_eq!(parse_changelog("").expect("empty").len(), 0);
        let preamble = "# Changelog\n\n### Not a subsection here\n\ntext\n";
        assert_eq!(parse_changelog(preamble).expect("preamble only").len(), 0);
    }

    #[test]
    fn flags_need_text_in_the_subsection() {
        // The line below `### Security` holds two spaces only.
        let text = "## [1.0.0] - 2026-10-09\n\n### Security\n\n  \n\n### Action required\n\n### Fixed\n\n- Something.\n";
        let section = &parse_changelog(text).expect("valid")[0];
        assert!(!section.security);
        assert!(!section.requires_action);
        assert_eq!(section.action, None);
        assert_eq!(section.entries, 1);
        assert_eq!(
            section.body,
            "### Security\n\n  \n\n### Action required\n\n### Fixed\n\n- Something."
        );
    }

    #[test]
    fn entries_count_list_items_at_column_zero() {
        let text = "\
## [1.0.0] - 2026-10-09

### Added

- One.
* Two.
  - Nested, not counted.
-Not an item.
Text - with a dash.
#### Deeper heading is body text

- Three.
";
        let section = &parse_changelog(text).expect("valid")[0];
        assert_eq!(section.entries, 3);
        assert!(section.body.contains("#### Deeper heading is body text"));
    }

    #[test]
    fn link_definitions_are_never_part_of_a_body() {
        let text = "\
[Unreleased]: https://example.com/compare/v1.0.0...HEAD

## [Unreleased]

Words.
[nested label]: https://example.com/inside
More words.

## [1.0.0] - 2026-10-09

### Added

- [Item][1] with a link.

[1]: https://example.com/one
";
        let sections = parse_changelog(text).expect("valid");
        assert_eq!(sections[0].body, "Words.\nMore words.");
        assert_eq!(sections[1].body, "### Added\n\n- [Item][1] with a link.");
        // Not a definition: no colon and space, no target, an empty label.
        for line in [
            "[x] y",
            "[x]:y",
            "[x]: ",
            "[]: https://example.com",
            "[x: y",
            "x: [y]: z",
        ] {
            assert!(!is_link_definition(line), "{line:?}");
        }
        for line in ["[x]: y", "[a b]: https://example.com/x z", "[[x]: y"] {
            assert!(is_link_definition(line), "{line:?}");
        }
    }

    #[test]
    fn trailing_whitespace_on_headings_is_ignored() {
        let text = "## [1.0.0] - 2026-10-09  \n\n### Added \n\n- One.\n";
        let section = &parse_changelog(text).expect("valid")[0];
        assert_eq!(section.version, Some(v("1.0.0")));
        assert_eq!(section.entries, 1);
    }

    #[test]
    fn prerelease_and_build_versions_are_accepted_in_headings() {
        let text = "\
## [1.0.0] - 2026-10-09

## [1.0.0-rc.1] - 2026-10-01

## [0.9.0+build.5] - 2026-09-01
";
        let sections = parse_changelog(text).expect("valid");
        let found: Vec<String> = sections
            .iter()
            .map(|s| s.version.as_ref().expect("released").to_string())
            .collect();
        assert_eq!(found, ["1.0.0", "1.0.0-rc.1", "0.9.0+build.5"]);
        assert!(sections.iter().all(|s| s.body.is_empty() && s.entries == 0));
    }

    #[test]
    fn bad_headings_are_errors() {
        for (text, line) in [
            ("## Unreleased\n", 1),
            ("## [unreleased]\n", 1),
            ("## [Unreleased] - 2026-10-09\n", 1),
            ("## 0.1.0 - 2026-10-09\n", 1),
            ("## [0.1.0](https://example.com) - 2026-10-09\n", 1),
            ("## [0.1.0] 2026-10-09\n", 1),
            ("## [0.1.0] - \n", 1),
            ("## [0.1.0 - 2026-10-09\n", 1),
            ("preamble\n\n## \n", 3),
            ("## [Unreleased]\n\n## Something else\n", 3),
        ] {
            let error = changelog_error_of(text);
            assert_eq!(error.line, line, "{text:?}: {error}");
            assert!(error.reason.contains("heading"), "{error}");
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("CHANGELOG line {line}: "))
            );
        }
        for (text, needle) in [
            ("## [v0.1.0] - 2026-10-09\n", "leading `v`"),
            ("## [0.1] - 2026-10-09\n", "not a release version"),
            ("## [01.2.3] - 2026-10-09\n", "not a release version"),
            ("## [0.1.0] - 2026-13-09\n", "not a release date"),
            ("## [0.1.0] - 09/10/2026\n", "not a release date"),
            ("## [0.1.0] - 2026-10-09 (yanked)\n", "not a release date"),
        ] {
            let error = changelog_error_of(text);
            assert_eq!(error.line, 1, "{text:?}");
            assert!(error.reason.contains(needle), "{text:?}: {error}");
        }
    }

    #[test]
    fn a_version_without_a_date_is_an_error() {
        let error = changelog_error_of("## [Unreleased]\n\n## [0.1.0]\n");
        assert_eq!(error.line, 3);
        assert!(error.reason.contains("no release date"), "{error}");
        assert_eq!(
            error.to_string(),
            format!("CHANGELOG line 3: {}", error.reason)
        );
    }

    #[test]
    fn unreleased_must_be_first_and_single() {
        let late = changelog_error_of("## [0.1.0] - 2026-10-09\n\n## [Unreleased]\n");
        assert_eq!(late.line, 3);
        assert!(late.reason.contains("must be the first section"), "{late}");

        let twice = changelog_error_of("## [Unreleased]\n\n## [Unreleased]\n");
        assert_eq!(twice.line, 3);
        assert!(twice.reason.contains("more than once"), "{twice}");

        let after_release =
            changelog_error_of("## [Unreleased]\n\n## [0.1.0] - 2026-10-09\n\n## [Unreleased]\n");
        assert_eq!(after_release.line, 5);
        assert!(
            after_release.reason.contains("more than once"),
            "{after_release}"
        );
    }

    #[test]
    fn changelog_versions_must_be_unique() {
        let text =
            "## [0.2.0] - 2026-10-09\n\n## [0.1.0] - 2026-09-01\n\n## [0.1.0] - 2026-08-01\n";
        let error = changelog_error_of(text);
        assert_eq!(error.line, 5);
        assert!(error.reason.contains("listed twice"), "{error}");
        assert!(error.reason.contains("line 3"), "{error}");

        // Also when the earlier section is not the one above.
        let far = changelog_error_of(
            "## [0.3.0] - 2026-10-09\n\n## [0.2.0] - 2026-09-01\n\n## [0.3.0] - 2026-08-01\n",
        );
        assert_eq!(far.line, 5);
        assert!(far.reason.contains("listed twice"), "{far}");

        let built = changelog_error_of("## [0.1.0] - 2026-10-09\n\n## [0.1.0+b] - 2026-09-01\n");
        assert!(built.reason.contains("listed twice"), "{built}");
    }

    #[test]
    fn versions_must_descend() {
        let error = changelog_error_of("## [0.1.0] - 2026-09-01\n\n## [0.2.0] - 2026-10-09\n");
        assert_eq!(error.line, 3);
        assert!(
            error.reason.contains("newest version to the oldest"),
            "{error}"
        );

        let pre = changelog_error_of("## [1.0.0-rc.1] - 2026-09-01\n\n## [1.0.0] - 2026-10-09\n");
        assert_eq!(pre.line, 3);

        // The Unreleased section does not take part in the order.
        assert!(parse_changelog("## [Unreleased]\n\n## [0.1.0] - 2026-09-01\n").is_ok());
        // Dates are not compared.
        assert!(parse_changelog("## [0.2.0] - 2020-01-01\n\n## [0.1.0] - 2026-09-01\n").is_ok());
    }

    #[test]
    fn unknown_subsections_are_errors() {
        for heading in [
            "### Misc",
            "### added",
            "### Action Required",
            "### Breaking changes",
            "###  Added",
        ] {
            let text = format!("## [0.1.0] - 2026-10-09\n\n### Added\n\n- One.\n\n{heading}\n");
            let error = changelog_error_of(&text);
            assert_eq!(error.line, 7, "{heading}: {error}");
            assert!(error.reason.contains("unknown subsection"), "{error}");
            assert!(error.reason.contains("Action required"), "{error}");
        }
        // `###` without a space after it, and deeper headings, are body text.
        let ok = "## [0.1.0] - 2026-10-09\n\n###Misc\n\n#### Misc\n";
        assert_eq!(
            parse_changelog(ok).expect("valid")[0].body,
            "###Misc\n\n#### Misc"
        );
        for known in SUBSECTIONS {
            let text = format!("## [0.1.0] - 2026-10-09\n\n### {known}\n\ntext\n");
            assert!(parse_changelog(&text).is_ok(), "{known}");
        }
    }

    #[test]
    fn repeated_subsections_are_merged_for_the_flags() {
        let text = "\
## [1.0.0] - 2026-10-09

### Action required

First step.

### Security

### Action required

Second step.

### Security

- Fixed.
";
        let section = &parse_changelog(text).expect("valid")[0];
        assert!(section.security);
        assert_eq!(
            section.action.as_deref(),
            Some("First step.\n\nSecond step.")
        );
    }

    #[test]
    fn error_display_and_trait_impls() {
        let error = ChangelogError {
            line: 12,
            reason: "bad".to_owned(),
        };
        assert_eq!(error.to_string(), "CHANGELOG line 12: bad");
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(boxed.to_string(), "CHANGELOG line 12: bad");
        let boxed: Box<dyn std::error::Error> = Box::new(ManifestError::Json("x".to_owned()));
        assert!(boxed.to_string().contains('x'));
        let boxed: Box<dyn std::error::Error> = Box::new(InvalidVersion("x".to_owned()));
        assert!(boxed.to_string().contains("`x`"));
    }

    #[test]
    fn manifest_error_codes_match_the_api() {
        assert_eq!(
            ManifestError::TooLarge { bytes: 1 }.code(),
            "update.manifest.too_large"
        );
        assert_eq!(
            ManifestError::Json(String::new()).code(),
            "update.manifest.json"
        );
        assert_eq!(
            ManifestError::Schema { found: 2 }.code(),
            "update.manifest.schema"
        );
        assert_eq!(
            ManifestError::Project(String::new()).code(),
            "update.manifest.project"
        );
        assert_eq!(
            ManifestError::Invalid {
                version: None,
                field: "releases",
                reason: "x".to_owned()
            }
            .code(),
            "update.manifest.invalid"
        );
        assert_eq!(
            ManifestError::DuplicateVersion("1.0.0".to_owned()).code(),
            "update.manifest.invalid"
        );
        let top = ManifestError::Invalid {
            version: None,
            field: "releases",
            reason: "lists too many".to_owned(),
        };
        assert_eq!(top.to_string(), "`releases` lists too many");
    }
}
