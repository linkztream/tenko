//! Request and response types of `/i18n`, also the stored form of a pack version.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{Principal, Timestamp};
use utoipa::ToSchema;

pub use super::validate::{Problem, Report, Severity};

/// A language the UI offers to everyone (`GET /i18n/languages`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LanguageInfo {
    /// The BCP 47 tag.
    pub tag: String,
    /// The language's name in itself.
    pub name: String,
    /// Whether the UI has the language built in.
    pub built_in: bool,
    /// The content hash of the active uploaded pack, which `GET /i18n/packs/{tag}` serves;
    /// absent for a built-in language without an uploaded override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// The languages of the installation (`GET /i18n/languages`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LanguageList {
    /// The built-in languages, then the active uploaded ones by tag.
    pub languages: Vec<LanguageInfo>,
    /// The installation's default language, once setup has run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_language: Option<String>,
}

/// The messages of a pack, ready for the UI (`GET /i18n/packs/{tag}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackMessages {
    /// The BCP 47 tag.
    pub tag: String,
    /// The content hash of the messages (also the `ETag`).
    pub hash: String,
    /// ICU message text by key; keys the pack lacks fall back to the built-in language of the
    /// same tag, then to English.
    pub messages: BTreeMap<String, String>,
}

/// Where a pack version came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackOrigin {
    /// Uploaded through the API.
    Upload,
    /// Imported at start from `<data_dir>/i18n/`.
    DataDir,
}

/// One uploaded version of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackVersion {
    /// The SHA-256 of the uploaded document, hex.
    pub id: String,
    /// The content hash of its messages (the `ETag` of `GET /i18n/packs/{tag}`).
    pub hash: String,
    /// The language's name in itself.
    pub display_name: String,
    /// Who made the pack.
    #[serde(default)]
    pub author: String,
    /// The pack's own version.
    #[serde(default)]
    pub version: String,
    /// Keys of the running UI the version translates, when it was uploaded.
    pub translated: u32,
    /// Keys of the running UI when it was uploaded.
    pub total: u32,
    /// `translated` in percent of `total`, rounded down.
    pub percent: u32,
    /// Where it came from.
    pub origin: PackOrigin,
    /// When it was uploaded or imported.
    pub uploaded_at: Timestamp,
    /// Who uploaded it.
    pub uploaded_by: Principal,
    /// When an administrator first previewed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previewed_at: Option<Timestamp>,
    /// Who previewed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previewed_by: Option<Principal>,
}

/// Where a language is in its life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    /// Built in, nothing uploaded.
    BuiltIn,
    /// A version is uploaded and validated; nobody sees it.
    Uploaded,
    /// The uploaded version was previewed; it can be activated.
    Previewed,
    /// A version is active: offered to everyone (a newer version may wait as candidate).
    Active,
}

/// A language and its packs, for administrators (`GET /i18n/packs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackInfo {
    /// The BCP 47 tag.
    pub tag: String,
    /// The language's name in itself.
    pub name: String,
    /// Whether the UI has the language built in (it can be overridden, never removed).
    pub built_in: bool,
    /// The life cycle state.
    pub status: PackStatus,
    /// The active version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<PackVersion>,
    /// The version waiting for preview and activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<PackVersion>,
}

/// Every language with its packs (`GET /i18n/packs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackList {
    /// The built-in languages, then the others by tag.
    pub packs: Vec<PackInfo>,
    /// The number of keys of the running UI.
    pub keys: u32,
}

/// An accepted upload (`POST /i18n/packs`): the language and the report of the new version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackUpload {
    /// The language after the upload; the new version is its candidate.
    pub pack: PackInfo,
    /// The validation report.
    pub report: Report,
}

/// The multipart form of `POST /i18n/packs`.
#[derive(ToSchema)]
pub struct PackUploadForm {
    /// The XLIFF 2.0 document, at most 2 MiB; its `trgLang` names the language.
    #[schema(value_type = String, format = Binary)]
    pub file: Vec<u8>,
}
