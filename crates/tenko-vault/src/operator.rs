//! Operator secrets (IAM-15, IAM-16, API-11, WP2.1): the first-class model of the
//! revealable secrets of the vault, their bindings to hosts and their reveals.
//!
//! # Model
//!
//! An operator secret is a vault secret of class [`SecretClass::Operator`] (envelope in
//! `vault.secrets`, per-secret DEK, IAM-15) plus a metadata record in
//! [`tables::META`]: a name, a [kind](OperatorSecretKind), purpose tags, an optional user
//! name, notes, its [origin](SecretOrigin) and the [format](ValueFormat) of its value. The
//! value never appears in a record, a list, a log line, an audit record, an event or an
//! error message; only [`OperatorSecrets::reveal`] returns it, after the audit record of
//! the reveal committed.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `vault.operator_meta` | [`SecretId`] | [`OperatorSecretRecord`] |
//! | `vault.reveals` | [`SecretId`] | [`RevealStamp`] (the last reveal) |
//! | `vault.host_bindings` | ([`HostId`], [`SecretId`]) | [`HostBinding`] |
//! | `vault.secret_hosts` | ([`SecretId`], [`HostId`]) | `()` (the reverse index) |
//!
//! The counter [`host_counter`] of a host versions its set of bindings (the `ETag` of
//! `GET /hosts/{id}/credentials`), and [`secret_counter`] of a secret guards its deletion
//! against a binding made meanwhile.
//!
//! # Who uses the same secrets
//!
//! - **Hosts** bind secrets as credentials with a [role](CredentialRole): `admin`, `rdp`,
//!   `ssh`, `web` or `other`. The remote hand-off of API-11 takes the user name of the
//!   `rdp` or `ssh` credential (else `admin`).
//! - **Connector instances** (ADR 0012) reference operator secrets by purpose in their own
//!   records; the host injects them per call. The purpose tags of a secret say which
//!   purposes it is meant for, so the connector form can offer the matching secrets.
//! - **Imports** (WP1.5) store each host's login and password as one operator secret in
//!   [`ValueFormat::LoginPassword`], with a record ([`imported_record`]) and an `admin`
//!   binding to the host. Secrets stored before this model existed are adopted once at
//!   start ([`OperatorSecrets::adopt_unmanaged`]).
//!
//! # Writes
//!
//! Every change is one write batch with its audit records, proposed directly (like user
//! and settings administration), not as an inline job: an inline job keeps its batch in
//! the job record, which would keep a copy of the envelope after the secret is deleted.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, CounterKey, FieldError, HostId, ObjectRef, RequestCtx, Revision, SecretId, Timestamp,
    UserId,
    audit::{AuditAction, AuditDraft, FieldChange},
    codec::key::encode_key,
    secret::{SecretClass, SecretRef},
};
use tenko_store::{
    FailedPrecondition, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch,
};
use zeroize::Zeroizing;

use crate::{
    KEK_EPOCH, MAX_SECRET_LEN, RevealAudit, SecretBytes, SecretMeta, SecretPurpose, SecretSpec,
    Vault, VaultError,
};

/// The store tables of the model.
pub mod tables {
    use tenko_core::{HostId, SecretId, table::TableDef};

    use super::{HostBinding, OperatorSecretRecord, RevealStamp};

    /// Metadata records by secret. Not secret-bearing: a name ending in `_secrets` would be.
    pub const META: TableDef<SecretId, OperatorSecretRecord> = TableDef::new("vault.operator_meta");
    /// The last reveal of each secret.
    pub const REVEALS: TableDef<SecretId, RevealStamp> = TableDef::new("vault.reveals");
    /// Bindings by host.
    pub const HOST_BINDINGS: TableDef<(HostId, SecretId), HostBinding> =
        TableDef::new("vault.host_bindings");
    /// Bindings by secret (the reverse index).
    pub const SECRET_HOSTS: TableDef<(SecretId, HostId), ()> = TableDef::new("vault.secret_hosts");
}

/// Audit actions of the model, besides the vault's own (`vault.secret.create`,
/// `vault.secret.replace`, `vault.secret.delete`, `vault.secret.reveal`).
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// The metadata of an operator secret changed.
    pub const UPDATE: AuditAction = AuditAction::from_static("vault.secret.update");
    /// The credentials bound to a host changed.
    pub const BIND: AuditAction = AuditAction::from_static("vault.host.credentials");
    /// Operator secrets without a record were adopted into the model.
    pub const ADOPT: AuditAction = AuditAction::from_static("vault.secret.adopt");
}

/// The purpose of secrets created through the operator API.
pub const OPERATOR_PURPOSE: &str = "vault.operator";

/// The purpose of the host credentials an import stores (WP1.5).
pub const IMPORT_PURPOSE: &str = "import.host_credential";

/// The counter that versions the bindings of a host.
pub fn host_counter(host: HostId) -> CounterKey {
    CounterKey::with("vault.host_credentials", &host)
}

/// The counter that moves with every binding change of a secret.
pub fn secret_counter(secret: SecretId) -> CounterKey {
    CounterKey::with("vault.secret_bindings", &secret)
}

/// Longest name, in characters.
pub const MAX_NAME_CHARS: usize = 128;
/// Longest user name, in characters.
pub const MAX_USERNAME_CHARS: usize = 256;
/// Longest notes, in characters.
pub const MAX_NOTES_CHARS: usize = 2_000;
/// Longest purpose tag, in characters.
pub const MAX_TAG_CHARS: usize = 64;
/// Most purpose tags per secret.
pub const MAX_TAGS: usize = 16;
/// Most credentials bound to one host.
pub const MAX_HOST_CREDENTIALS: usize = 32;
/// Longest reveal reason, in characters.
pub const MAX_REASON_CHARS: usize = 200;
/// Reveals one person may make per [`REVEAL_WINDOW`].
pub const REVEALS_PER_WINDOW: usize = 10;
/// The window of the reveal rate limit.
pub const REVEAL_WINDOW: Duration = Duration::from_secs(60);
/// Seconds after which the UI clears a revealed value from the clipboard.
pub const CLIPBOARD_CLEAR_SECS: u32 = 30;

/// Attempts of a write that lost the race against a KEK rotation.
const EPOCH_RETRIES: usize = 4;

/// Records adopted per batch.
const ADOPT_BATCH: usize = 256;

/// What an operator secret is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSecretKind {
    /// A password (with an optional user name).
    Password,
    /// An API key.
    ApiKey,
    /// An SSH private key, as text.
    SshKey,
    /// A bearer or access token.
    Token,
    /// Anything else.
    Other,
}

impl OperatorSecretKind {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::SshKey => "ssh_key",
            Self::Token => "token",
            Self::Other => "other",
        }
    }
}

/// How the stored value is laid out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueFormat {
    /// The value itself, as UTF-8 text.
    #[default]
    Plain,
    /// A JSON object with `login` and `password` (the credentials of an import, WP1.5); a
    /// reveal returns the password as the value and the login as the user name.
    LoginPassword,
}

/// Where an operator secret came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOrigin {
    /// Created by a person through the API.
    #[default]
    Manual,
    /// Stored by an import from a credential column.
    Import,
}

/// The role of a credential on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRole {
    /// The administrative login of the device.
    Admin,
    /// Remote Desktop.
    Rdp,
    /// SSH.
    Ssh,
    /// The web interface.
    Web,
    /// Anything else.
    Other,
}

impl CredentialRole {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Rdp => "rdp",
            Self::Ssh => "ssh",
            Self::Web => "web",
            Self::Other => "other",
        }
    }
}

/// The metadata record of an operator secret. Never holds the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSecretRecord {
    /// The secret.
    pub id: SecretId,
    /// The name people see (not unique).
    pub name: String,
    /// What it is.
    pub kind: OperatorSecretKind,
    /// Purpose tags: lower case, `[a-z0-9._-]`, sorted, for example `api_key` or `unifi`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The user name that goes with it, when it has one. Not a secret: the remote hand-off
    /// puts it into `.rdp` files and `ssh://` links.
    #[serde(default)]
    pub username: Option<String>,
    /// Notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// How the value is laid out.
    #[serde(default)]
    pub format: ValueFormat,
    /// Where it came from.
    #[serde(default)]
    pub origin: SecretOrigin,
    /// When it was created.
    pub created_at: Timestamp,
    /// When the record or the value last changed.
    pub updated_at: Timestamp,
}

/// The last reveal of a secret. Never holds the value or the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealStamp {
    /// When.
    pub at: Timestamp,
    /// Who.
    #[serde(default)]
    pub user: Option<UserId>,
    /// Their login name at the time.
    #[serde(default)]
    pub user_name: Option<String>,
    /// The host the person was looking at, if any.
    #[serde(default)]
    pub host: Option<HostId>,
}

/// A binding of a secret to a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBinding {
    /// The role of the credential on the host.
    pub role: CredentialRole,
    /// When it was bound.
    pub bound_at: Timestamp,
}

/// An operator secret as reads return it: the record and what goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSecret {
    /// The record.
    pub record: OperatorSecretRecord,
    /// The revision of the record; `None` for a secret not adopted yet, whose record is
    /// derived from its vault metadata.
    pub revision: Option<Revision>,
    /// When the value was last written (creation, replacement, DEK rotation).
    pub value_updated_at: Timestamp,
    /// The last reveal.
    pub last_revealed: Option<RevealStamp>,
    /// The hosts it is bound to, with the role.
    pub hosts: Vec<(HostId, CredentialRole)>,
}

/// A new operator secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOperatorSecret {
    /// The name.
    pub name: String,
    /// What it is.
    pub kind: OperatorSecretKind,
    /// Purpose tags.
    pub tags: Vec<String>,
    /// The user name.
    pub username: Option<String>,
    /// Notes.
    pub notes: Option<String>,
    /// The value.
    pub value: SecretBytes,
}

/// A change of an operator secret. Absent members stay; `Some(None)` clears an optional
/// member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorSecretPatch {
    /// A new name.
    pub name: Option<String>,
    /// A new kind.
    pub kind: Option<OperatorSecretKind>,
    /// New purpose tags (the whole list).
    pub tags: Option<Vec<String>>,
    /// A new user name, or `Some(None)` to clear it.
    pub username: Option<Option<String>>,
    /// New notes, or `Some(None)` to clear them.
    pub notes: Option<Option<String>>,
    /// A new value.
    pub value: Option<SecretBytes>,
}

impl OperatorSecretPatch {
    /// Whether the patch changes nothing.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.kind.is_none()
            && self.tags.is_none()
            && self.username.is_none()
            && self.notes.is_none()
            && self.value.is_none()
    }
}

/// One credential of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCredential {
    /// The secret.
    pub secret: OperatorSecret,
    /// Its role on the host.
    pub role: CredentialRole,
    /// When it was bound.
    pub bound_at: Timestamp,
}

/// The credentials of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCredentials {
    /// The host.
    pub host: HostId,
    /// The credentials, by role and name.
    pub items: Vec<HostCredential>,
    /// The version of the set ([`host_counter`]), for `ETag` and `If-Match`.
    pub version: u64,
}

/// A binding a caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingRequest {
    /// The secret.
    pub secret: SecretId,
    /// Its role on the host.
    pub role: CredentialRole,
}

/// A reveal a caller asks for, after its own authorization checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevealRequest {
    /// The host the person looks at; the secret must be bound to it.
    pub host: Option<HostId>,
    /// Why, in the person's words (audited, at most [`MAX_REASON_CHARS`]).
    pub reason: Option<String>,
    /// The reveal policy asks for a host the secret is bound to (TGL-24, Hardened).
    pub bound_host_only: bool,
    /// The person, for the last-revealed stamp.
    pub user: Option<UserId>,
    /// Their login name, for the last-revealed stamp.
    pub user_name: Option<String>,
}

/// A revealed value. Zeroized on drop; `Debug` prints no value.
pub struct Revealed {
    /// The value (the password of a [`ValueFormat::LoginPassword`] secret).
    pub value: Zeroizing<String>,
    /// The user name: the record's, else the login of a [`ValueFormat::LoginPassword`]
    /// value.
    pub username: Option<String>,
    /// What it is.
    pub kind: OperatorSecretKind,
    /// When the reveal was recorded.
    pub at: Timestamp,
}

impl std::fmt::Debug for Revealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revealed")
            .field(
                "value",
                &format_args!("<{} bytes redacted>", self.value.len()),
            )
            .field("username", &self.username)
            .field("kind", &self.kind)
            .field("at", &self.at)
            .finish()
    }
}

/// Errors of the model. Messages and parameters never contain a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperatorError {
    /// No operator secret with this id.
    #[error("operator secret {secret} not found")]
    NotFound {
        /// The secret.
        secret: SecretId,
    },
    /// A value of the request is invalid.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// The field.
        field: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// The secret changed since it was read (`If-Match` or a concurrent writer).
    #[error("the secret was changed concurrently; read it again and retry")]
    Conflict,
    /// The credentials of the host changed since they were read.
    #[error("the credentials of the host were changed concurrently; read them again and retry")]
    BindingsConflict,
    /// The secret is still bound to hosts or referenced by connectors.
    #[error(
        "the secret is still referenced by {} hosts and {} connectors",
        .hosts.len(),
        .connectors.len()
    )]
    InUse {
        /// The hosts that bind it.
        hosts: Vec<HostId>,
        /// The connector instances that reference it (filled in by the caller).
        connectors: Vec<String>,
    },
    /// A binding names a secret that is not an operator secret.
    #[error("secret {secret} is not an operator secret")]
    BindingMissing {
        /// The secret.
        secret: SecretId,
    },
    /// The reveal policy needs the host the person looks at (TGL-24).
    #[error("the reveal policy reveals only secrets bound to the host in view; name the host")]
    HostRequired,
    /// The secret is not bound to the host the request names.
    #[error("the secret is not bound to this host")]
    NotBound,
    /// Too many reveals in a short time.
    #[error("too many reveals; retry in {retry_after} seconds")]
    RateLimited {
        /// Seconds until the next reveal is allowed.
        retry_after: u64,
    },
    /// The stored value is not text, so it cannot be revealed as a string.
    #[error("the stored value is not text")]
    NotText,
    /// The vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl From<StoreError> for OperatorError {
    fn from(error: StoreError) -> Self {
        Self::Vault(VaultError::Store(error))
    }
}

impl From<tenko_core::codec::CodecError> for OperatorError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::Vault(VaultError::from(error))
    }
}

impl OperatorError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

impl Coded for OperatorError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "vault.secret.not_found",
            Self::Invalid { .. } => "vault.secret.invalid",
            Self::Conflict => "vault.secret.conflict",
            Self::BindingsConflict => "vault.host_credentials.conflict",
            Self::InUse { .. } => "vault.secret.in_use",
            Self::BindingMissing { .. } => "vault.host_credentials.secret_missing",
            Self::HostRequired => "vault.reveal.host_required",
            Self::NotBound => "vault.reveal.not_bound",
            Self::RateLimited { .. } => "vault.reveal.rate_limited",
            Self::NotText => "vault.secret.not_text",
            Self::Vault(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::NotFound { .. } => 404,
            Self::Invalid { .. } | Self::BindingMissing { .. } | Self::NotText => 422,
            Self::Conflict | Self::BindingsConflict | Self::InUse { .. } => 409,
            Self::HostRequired | Self::NotBound => 403,
            Self::RateLimited { .. } => 429,
            Self::Vault(error) => error.http_status(),
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::NotFound { secret } | Self::BindingMissing { secret } => {
                BTreeMap::from([("secret", secret.to_string())])
            }
            Self::Invalid { field, reason } => {
                BTreeMap::from([("field", (*field).to_owned()), ("reason", reason.clone())])
            }
            Self::InUse { hosts, connectors } => BTreeMap::from([
                ("hosts", hosts.len().to_string()),
                ("connectors", connectors.len().to_string()),
            ]),
            Self::RateLimited { retry_after } => {
                BTreeMap::from([("retry_after", retry_after.to_string())])
            }
            Self::Vault(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::InUse { .. } => "Secret in use",
            Self::HostRequired | Self::NotBound => "Reveal not allowed here",
            Self::RateLimited { .. } => "Too many reveals",
            _ => tenko_core::error::status_title(self.http_status()),
        }
    }

    fn field_errors(&self) -> Vec<FieldError> {
        match self {
            Self::Invalid { field, .. } => vec![FieldError::new(*field, "vault.secret.invalid")],
            Self::BindingMissing { .. } => vec![FieldError::new(
                "credentials",
                "vault.host_credentials.secret_missing",
            )],
            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Validation.

fn visible(text: &str) -> bool {
    !text.chars().any(char::is_control)
}

/// A name: trimmed, 1 to [`MAX_NAME_CHARS`] characters, no control characters.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for `name`.
pub fn valid_name(name: &str) -> Result<String, OperatorError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || !visible(name) {
        return Err(OperatorError::invalid(
            "name",
            format!("a name has 1 to {MAX_NAME_CHARS} visible characters"),
        ));
    }
    Ok(name.to_owned())
}

/// A user name: trimmed, at most [`MAX_USERNAME_CHARS`] characters, no control characters;
/// an empty one is none.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for `username`.
pub fn valid_username(username: Option<&str>) -> Result<Option<String>, OperatorError> {
    let Some(username) = username.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if username.chars().count() > MAX_USERNAME_CHARS || !visible(username) {
        return Err(OperatorError::invalid(
            "username",
            format!("a user name has at most {MAX_USERNAME_CHARS} visible characters"),
        ));
    }
    Ok(Some(username.to_owned()))
}

/// Notes: at most [`MAX_NOTES_CHARS`] characters; line breaks and tabs are the only control
/// characters allowed; empty notes are none.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for `notes`.
pub fn valid_notes(notes: Option<&str>) -> Result<Option<String>, OperatorError> {
    let Some(notes) = notes.filter(|text| !text.trim().is_empty()) else {
        return Ok(None);
    };
    if notes.chars().count() > MAX_NOTES_CHARS
        || notes
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(OperatorError::invalid(
            "notes",
            format!("notes have at most {MAX_NOTES_CHARS} characters"),
        ));
    }
    Ok(Some(notes.to_owned()))
}

/// Purpose tags: lower-cased, trimmed, 1 to [`MAX_TAG_CHARS`] characters of
/// `[a-z0-9._-]`, at most [`MAX_TAGS`]; sorted without duplicates.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for `tags`.
pub fn valid_tags(tags: &[String]) -> Result<Vec<String>, OperatorError> {
    let mut out = BTreeSet::new();
    for tag in tags {
        let tag = tag.trim().to_lowercase();
        if tag.is_empty()
            || tag.chars().count() > MAX_TAG_CHARS
            || !tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(OperatorError::invalid(
                "tags",
                format!(
                    "a tag has 1 to {MAX_TAG_CHARS} characters of a to z, 0 to 9, dot, underscore and hyphen"
                ),
            ));
        }
        out.insert(tag);
    }
    if out.len() > MAX_TAGS {
        return Err(OperatorError::invalid(
            "tags",
            format!("at most {MAX_TAGS} tags"),
        ));
    }
    Ok(out.into_iter().collect())
}

/// A value: 1 to [`MAX_SECRET_LEN`] bytes.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for an empty value, [`VaultError::TooLarge`] (413) for one
/// above the limit.
pub fn valid_value(value: &SecretBytes) -> Result<(), OperatorError> {
    if value.is_empty() {
        return Err(OperatorError::invalid(
            "value",
            "a value has at least 1 byte",
        ));
    }
    if value.len() > MAX_SECRET_LEN {
        return Err(OperatorError::Vault(VaultError::TooLarge {
            size: value.len(),
            limit: MAX_SECRET_LEN,
        }));
    }
    Ok(())
}

/// A reveal reason: trimmed, at most [`MAX_REASON_CHARS`] visible characters; empty is
/// none.
///
/// # Errors
///
/// [`OperatorError::Invalid`] for `reason`.
pub fn valid_reason(reason: Option<&str>) -> Result<Option<String>, OperatorError> {
    let Some(reason) = reason.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if reason.chars().count() > MAX_REASON_CHARS || !visible(reason) {
        return Err(OperatorError::invalid(
            "reason",
            format!("a reason has at most {MAX_REASON_CHARS} visible characters"),
        ));
    }
    Ok(Some(reason.to_owned()))
}

// ---------------------------------------------------------------------------------------
// Staging helpers, shared with the import (WP1.5).

/// The record of a credential an import stores for a host: the login becomes the user
/// name, the value keeps the import's layout ([`ValueFormat::LoginPassword`]).
pub fn imported_record(
    secret: SecretId,
    host_name: &str,
    login: Option<&str>,
    now: Timestamp,
) -> OperatorSecretRecord {
    let name: String = format!("Login of {host_name}")
        .chars()
        .take(MAX_NAME_CHARS)
        .collect();
    OperatorSecretRecord {
        id: secret,
        name,
        kind: OperatorSecretKind::Password,
        tags: Vec::new(),
        username: login
            .map(|login| {
                login
                    .trim()
                    .chars()
                    .take(MAX_USERNAME_CHARS)
                    .collect::<String>()
            })
            .filter(|login| !login.is_empty() && visible(login)),
        notes: None,
        format: ValueFormat::LoginPassword,
        origin: SecretOrigin::Import,
        created_at: now,
        updated_at: now,
    }
}

/// Adds a record to a batch.
///
/// # Errors
///
/// The store's encoding error.
pub fn stage_record(
    batch: &mut WriteBatch,
    record: &OperatorSecretRecord,
) -> Result<(), StoreError> {
    batch.put_typed(&tables::META, &record.id, record)?;
    Ok(())
}

/// Adds a binding of `secret` to `host` (both directions) and bumps both counters.
///
/// # Errors
///
/// The store's encoding error.
pub fn stage_bind(
    batch: &mut WriteBatch,
    host: HostId,
    secret: SecretId,
    role: CredentialRole,
    now: Timestamp,
) -> Result<(), StoreError> {
    batch.put_typed(
        &tables::HOST_BINDINGS,
        &(host, secret),
        &HostBinding {
            role,
            bound_at: now,
        },
    )?;
    batch.put_typed(&tables::SECRET_HOSTS, &(secret, host), &())?;
    batch.bump(host_counter(host));
    batch.bump(secret_counter(secret));
    Ok(())
}

/// Removes a binding of `secret` to `host` (both directions) and bumps both counters.
pub fn stage_unbind(batch: &mut WriteBatch, host: HostId, secret: SecretId) {
    batch.delete_typed(&tables::HOST_BINDINGS, &(host, secret));
    batch.delete_typed(&tables::SECRET_HOSTS, &(secret, host));
    batch.bump(host_counter(host));
    batch.bump(secret_counter(secret));
}

/// Removes the record and the reveal stamp of a secret (with the vault's own
/// [`stage_delete`](crate::Vault::stage_delete)); its bindings must be removed with
/// [`stage_unbind`].
pub fn stage_forget(batch: &mut WriteBatch, secret: SecretId) {
    batch.delete_typed(&tables::META, &secret);
    batch.delete_typed(&tables::REVEALS, &secret);
}

/// The hosts a secret is bound to.
///
/// # Errors
///
/// The store's error.
pub fn hosts_of(view: &dyn ReadView, secret: SecretId) -> Result<Vec<HostId>, StoreError> {
    Ok(view
        .scan_typed(
            &tables::SECRET_HOSTS,
            KeyRange::prefix(encode_key(&(secret,))),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|((_, host), (), _)| host)
        .collect())
}

/// Whether `secret` is bound to `host`, with the role.
///
/// # Errors
///
/// The store's error.
pub fn binding(
    view: &dyn ReadView,
    host: HostId,
    secret: SecretId,
) -> Result<Option<HostBinding>, StoreError> {
    Ok(view
        .get_typed(&tables::HOST_BINDINGS, &(host, secret))?
        .map(|(binding, _)| binding))
}

/// The record derived from the vault metadata of a secret that has none yet.
pub fn derived_record(meta: &SecretMeta) -> OperatorSecretRecord {
    let import = meta.purpose.as_str() == IMPORT_PURPOSE;
    let name = meta
        .label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty() && visible(label))
        .map_or_else(
            || format!("Secret {}", meta.purpose.as_str()),
            ToOwned::to_owned,
        );
    OperatorSecretRecord {
        id: meta.id,
        name: name.chars().take(MAX_NAME_CHARS).collect(),
        kind: OperatorSecretKind::Password,
        tags: Vec::new(),
        username: None,
        notes: None,
        format: if import {
            ValueFormat::LoginPassword
        } else {
            ValueFormat::Plain
        },
        origin: if import {
            SecretOrigin::Import
        } else {
            SecretOrigin::Manual
        },
        created_at: meta.created_at,
        updated_at: meta.updated_at,
    }
}

/// Whether a batch failed only because a KEK rotation moved the epoch.
fn lost_to_rotation(failures: &[FailedPrecondition]) -> bool {
    !failures.is_empty()
        && failures.iter().all(|failure| {
            matches!(failure, FailedPrecondition::Counter { counter, .. } if *counter == KEK_EPOCH)
        })
}

fn change(field: &str, old: Option<String>, new: Option<String>) -> FieldChange {
    FieldChange {
        object: None,
        field: field.to_owned(),
        old,
        new,
    }
}

/// Decodes a revealed value by its format into the value and the login.
fn decode_value(
    format: ValueFormat,
    bytes: &SecretBytes,
) -> Result<(Zeroizing<String>, Option<String>), OperatorError> {
    match format {
        ValueFormat::Plain => {
            let text = std::str::from_utf8(bytes.expose()).map_err(|_| OperatorError::NotText)?;
            Ok((Zeroizing::new(text.to_owned()), None))
        }
        ValueFormat::LoginPassword => {
            /// A string that zeroizes on drop.
            struct Text(Zeroizing<String>);
            impl<'de> Deserialize<'de> for Text {
                fn deserialize<D: serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Self, D::Error> {
                    String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
                }
            }
            #[derive(Deserialize)]
            struct LoginPassword {
                #[serde(default)]
                login: Option<Text>,
                #[serde(default)]
                password: Option<Text>,
            }
            let parsed: LoginPassword =
                serde_json::from_slice(bytes.expose()).map_err(|_| OperatorError::NotText)?;
            Ok((
                parsed.password.map(|text| text.0).unwrap_or_default(),
                parsed.login.map(|text| text.0.to_string()),
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------
// The service.

/// The operator secrets of the vault: reads, edits, host bindings and reveals.
pub struct OperatorSecrets {
    store: Arc<dyn Store>,
    vault: Arc<dyn Vault>,
    reveals: Mutex<HashMap<UserOrSubject, VecDeque<Instant>>>,
}

type UserOrSubject = String;

impl std::fmt::Debug for OperatorSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorSecrets").finish_non_exhaustive()
    }
}

impl OperatorSecrets {
    /// The service over the store and the vault on it.
    pub fn new(store: Arc<dyn Store>, vault: Arc<dyn Vault>) -> Self {
        Self {
            store,
            vault,
            reveals: Mutex::new(HashMap::new()),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, OperatorError> {
        Ok(self.store.read(ReadConsistency::Local).await?)
    }

    /// The operator secret `id` as of `view`: its record (derived when it has none yet) and
    /// what goes with it. `None` for a missing secret or a system secret.
    fn load(view: &dyn ReadView, id: SecretId) -> Result<Option<OperatorSecret>, OperatorError> {
        let Some((meta, _)) = view.get_typed(&crate::tables::META, &id)? else {
            return Ok(None);
        };
        if meta.class != SecretClass::Operator {
            return Ok(None);
        }
        let (record, revision) = match view.get_typed(&tables::META, &id)? {
            Some((record, revision)) => (record, Some(revision)),
            None => (derived_record(&meta), None),
        };
        let last_revealed = view
            .get_typed(&tables::REVEALS, &id)?
            .map(|(stamp, _)| stamp);
        let mut hosts = Vec::new();
        for host in hosts_of(view, id)? {
            if let Some(binding) = binding(view, host, id)? {
                hosts.push((host, binding.role));
            }
        }
        Ok(Some(OperatorSecret {
            record,
            revision,
            value_updated_at: meta.updated_at,
            last_revealed,
            hosts,
        }))
    }

    fn must_load(view: &dyn ReadView, id: SecretId) -> Result<OperatorSecret, OperatorError> {
        Self::load(view, id)?.ok_or(OperatorError::NotFound { secret: id })
    }

    /// Every operator secret, by name (ignoring case), then id.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list(&self) -> Result<Vec<OperatorSecret>, OperatorError> {
        let view = self.view().await?;
        let ids: Vec<SecretId> = view
            .scan_typed(
                &crate::tables::OPERATOR_INDEX,
                KeyRange::all(),
                usize::MAX,
                false,
            )?
            .into_iter()
            .map(|(id, (), _)| id)
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(secret) = Self::load(view.as_ref(), id)? {
                out.push(secret);
            }
        }
        out.sort_by(|a, b| {
            a.record
                .name
                .to_lowercase()
                .cmp(&b.record.name.to_lowercase())
                .then(a.record.id.cmp(&b.record.id))
        });
        Ok(out)
    }

    /// One operator secret.
    ///
    /// # Errors
    ///
    /// [`OperatorError::NotFound`] (also for a system secret) or the store's error.
    pub async fn get(&self, id: SecretId) -> Result<OperatorSecret, OperatorError> {
        let view = self.view().await?;
        Self::must_load(view.as_ref(), id)
    }

    /// The store revision now, for list pages.
    pub fn revision(&self) -> Revision {
        self.store.status().revision
    }

    /// Creates an operator secret: the envelope, the vault metadata and the record in one
    /// write with one audit record (`vault.secret.create`, with the name and the kind).
    ///
    /// # Errors
    ///
    /// [`OperatorError::Invalid`], a vault or store error.
    pub async fn create(
        &self,
        ctx: &RequestCtx,
        new: NewOperatorSecret,
    ) -> Result<OperatorSecret, OperatorError> {
        let name = valid_name(&new.name)?;
        let tags = valid_tags(&new.tags)?;
        let username = valid_username(new.username.as_deref())?;
        let notes = valid_notes(new.notes.as_deref())?;
        valid_value(&new.value)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut batch = WriteBatch::for_request(ctx);
            // A new envelope never replays under an idempotency key (random DEK and nonce).
            batch.idempotency = None;
            let spec = SecretSpec::new(SecretPurpose::from_static(OPERATOR_PURPOSE))
                .labelled(name.clone());
            let secret =
                self.vault
                    .stage_put(&mut batch, ctx, SecretClass::Operator, spec, &new.value)?;
            if let Some(draft) = batch.audit.last_mut() {
                draft
                    .details
                    .context
                    .insert("name".to_owned(), name.clone());
                draft
                    .details
                    .context
                    .insert("kind".to_owned(), new.kind.as_str().to_owned());
            }
            let record = OperatorSecretRecord {
                id: secret.secret,
                name: name.clone(),
                kind: new.kind,
                tags: tags.clone(),
                username: username.clone(),
                notes: notes.clone(),
                format: ValueFormat::Plain,
                origin: SecretOrigin::Manual,
                created_at: ctx.now,
                updated_at: ctx.now,
            };
            batch.expect_typed(&tables::META, &record.id, None);
            stage_record(&mut batch, &record)?;
            match self.store.propose(batch).await {
                Ok(_) => return self.get(secret.secret).await,
                Err(StoreError::PreconditionFailed(failures))
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Changes the metadata and, with `patch.value`, the value of an operator secret in
    /// one write: `vault.secret.update` with the changed fields (the notes only as
    /// changed, never their text) and, for a new value, `vault.secret.replace`. With
    /// `expect`, the change applies only to that revision of the record.
    ///
    /// # Errors
    ///
    /// [`OperatorError::NotFound`], [`OperatorError::Invalid`], [`OperatorError::Conflict`],
    /// a vault or store error.
    pub async fn update(
        &self,
        ctx: &RequestCtx,
        id: SecretId,
        patch: OperatorSecretPatch,
        expect: Option<Revision>,
    ) -> Result<OperatorSecret, OperatorError> {
        if let Some(value) = &patch.value {
            valid_value(value)?;
        }
        let mut attempt = 0;
        loop {
            attempt += 1;
            let view = self.view().await?;
            let current = Self::must_load(view.as_ref(), id)?;
            if expect.is_some_and(|expect| Some(expect) != current.revision) {
                return Err(OperatorError::Conflict);
            }
            let mut next = current.record.clone();
            let mut changes = Vec::new();
            if let Some(name) = &patch.name {
                next.name = valid_name(name)?;
                if next.name != current.record.name {
                    changes.push(change(
                        "name",
                        Some(current.record.name.clone()),
                        Some(next.name.clone()),
                    ));
                }
            }
            if let Some(kind) = patch.kind
                && kind != current.record.kind
            {
                next.kind = kind;
                changes.push(change(
                    "kind",
                    Some(current.record.kind.as_str().to_owned()),
                    Some(kind.as_str().to_owned()),
                ));
            }
            if let Some(tags) = &patch.tags {
                next.tags = valid_tags(tags)?;
                if next.tags != current.record.tags {
                    changes.push(change(
                        "tags",
                        Some(current.record.tags.join(",")),
                        Some(next.tags.join(",")),
                    ));
                }
            }
            if let Some(username) = &patch.username {
                next.username = valid_username(username.as_deref())?;
                if next.username != current.record.username {
                    changes.push(change(
                        "username",
                        current.record.username.clone(),
                        next.username.clone(),
                    ));
                }
            }
            if let Some(notes) = &patch.notes {
                next.notes = valid_notes(notes.as_deref())?;
                if next.notes != current.record.notes {
                    changes.push(change("notes", None, None));
                }
            }
            if patch.value.is_some() {
                // A new value is the value itself, whatever the import stored before.
                next.format = ValueFormat::Plain;
            }
            if changes.is_empty() && patch.value.is_none() {
                return Ok(current);
            }
            next.updated_at = ctx.now;
            let mut batch = WriteBatch::for_request(ctx);
            batch.idempotency = None;
            batch.expect_typed(&tables::META, &id, current.revision);
            stage_record(&mut batch, &next)?;
            if !changes.is_empty() {
                let mut draft = AuditDraft::success(actions::UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(ctx.source_ip)
                    .with_context("name", next.name.clone());
                for change in changes {
                    draft = draft.with_change(change);
                }
                batch.audit(draft);
            }
            if let Some(value) = &patch.value {
                self.vault
                    .stage_replace(&mut batch, ctx, SecretRef { secret: id }, value)
                    .await?;
            }
            match self.store.propose(batch).await {
                Ok(_) => return self.get(id).await,
                Err(StoreError::PreconditionFailed(failures))
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) => {}
                Err(StoreError::PreconditionFailed(_)) => return Err(OperatorError::Conflict),
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Deletes an operator secret: the envelope, the vault metadata, the record and the
    /// reveal stamp. Refused with [`OperatorError::InUse`] while a host binds it; the
    /// caller checks the other references (connectors) first and fills them in.
    ///
    /// # Errors
    ///
    /// [`OperatorError::NotFound`], [`OperatorError::Conflict`], [`OperatorError::InUse`],
    /// or the store's error.
    pub async fn delete(
        &self,
        ctx: &RequestCtx,
        id: SecretId,
        expect: Option<Revision>,
    ) -> Result<(), OperatorError> {
        let view = self.view().await?;
        let current = Self::must_load(view.as_ref(), id)?;
        if expect.is_some_and(|expect| Some(expect) != current.revision) {
            return Err(OperatorError::Conflict);
        }
        if !current.hosts.is_empty() {
            return Err(OperatorError::InUse {
                hosts: current.hosts.iter().map(|(host, _)| *host).collect(),
                connectors: Vec::new(),
            });
        }
        let bindings = view.counter(&secret_counter(id))?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.expect_counter(secret_counter(id), bindings);
        batch.expect_typed(&tables::META, &id, current.revision);
        self.vault
            .stage_delete(&mut batch, ctx, SecretRef { secret: id });
        if let Some(draft) = batch.audit.last_mut() {
            draft
                .details
                .context
                .insert("name".to_owned(), current.record.name.clone());
        }
        stage_forget(&mut batch, id);
        match self.store.propose(batch).await {
            Ok(_) => Ok(()),
            Err(StoreError::PreconditionFailed(_)) => Err(OperatorError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    /// The credentials bound to a host, by role and name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn host_credentials(&self, host: HostId) -> Result<HostCredentials, OperatorError> {
        let view = self.view().await?;
        Self::credentials_in(view.as_ref(), host)
    }

    fn credentials_in(view: &dyn ReadView, host: HostId) -> Result<HostCredentials, OperatorError> {
        let version = view.counter(&host_counter(host))?;
        let rows = view.scan_typed(
            &tables::HOST_BINDINGS,
            KeyRange::prefix(encode_key(&(host,))),
            usize::MAX,
            false,
        )?;
        let mut items = Vec::new();
        for ((_, secret), binding, _) in rows {
            if let Some(loaded) = Self::load(view, secret)? {
                items.push(HostCredential {
                    secret: loaded,
                    role: binding.role,
                    bound_at: binding.bound_at,
                });
            }
        }
        items.sort_by(|a, b| {
            a.role
                .cmp(&b.role)
                .then_with(|| {
                    a.secret
                        .record
                        .name
                        .to_lowercase()
                        .cmp(&b.secret.record.name.to_lowercase())
                })
                .then(a.secret.record.id.cmp(&b.secret.record.id))
        });
        Ok(HostCredentials {
            host,
            items,
            version,
        })
    }

    /// Replaces the credentials bound to a host with `wanted`: one entry per secret, at
    /// most [`MAX_HOST_CREDENTIALS`], every secret an operator secret. One write with one
    /// audit record (`vault.host.credentials`) listing what was bound and unbound. With
    /// `expect`, the change applies only to that version of the set. The caller checks
    /// that the host exists.
    ///
    /// # Errors
    ///
    /// [`OperatorError::Invalid`], [`OperatorError::BindingMissing`],
    /// [`OperatorError::BindingsConflict`] or the store's error.
    pub async fn set_host_credentials(
        &self,
        ctx: &RequestCtx,
        host: HostId,
        wanted: &[BindingRequest],
        expect: Option<u64>,
    ) -> Result<HostCredentials, OperatorError> {
        if wanted.len() > MAX_HOST_CREDENTIALS {
            return Err(OperatorError::invalid(
                "credentials",
                format!("at most {MAX_HOST_CREDENTIALS} credentials per host"),
            ));
        }
        let mut seen = BTreeSet::new();
        for request in wanted {
            if !seen.insert(request.secret) {
                return Err(OperatorError::invalid(
                    "credentials",
                    "a secret is bound to a host once, with one role",
                ));
            }
        }
        let view = self.view().await?;
        let current = Self::credentials_in(view.as_ref(), host)?;
        if expect.is_some_and(|expect| expect != current.version) {
            return Err(OperatorError::BindingsConflict);
        }
        for request in wanted {
            if Self::load(view.as_ref(), request.secret)?.is_none() {
                return Err(OperatorError::BindingMissing {
                    secret: request.secret,
                });
            }
        }
        let before: BTreeMap<SecretId, CredentialRole> = current
            .items
            .iter()
            .map(|item| (item.secret.record.id, item.role))
            .collect();
        let after: BTreeMap<SecretId, CredentialRole> = wanted
            .iter()
            .map(|request| (request.secret, request.role))
            .collect();
        if before == after {
            return Ok(current);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.expect_counter(host_counter(host), current.version);
        let mut objects = vec![ObjectRef::from(host)];
        let mut draft_changes = Vec::new();
        for (secret, role) in &before {
            if !after.contains_key(secret) {
                stage_unbind(&mut batch, host, *secret);
                objects.push(ObjectRef::from(*secret));
                draft_changes.push(FieldChange {
                    object: Some(ObjectRef::from(*secret)),
                    field: "role".to_owned(),
                    old: Some(role.as_str().to_owned()),
                    new: None,
                });
            }
        }
        for (secret, role) in &after {
            let previous = before.get(secret);
            if previous == Some(role) {
                continue;
            }
            stage_bind(&mut batch, host, *secret, *role, ctx.now)?;
            objects.push(ObjectRef::from(*secret));
            draft_changes.push(FieldChange {
                object: Some(ObjectRef::from(*secret)),
                field: "role".to_owned(),
                old: previous.map(|role| role.as_str().to_owned()),
                new: Some(role.as_str().to_owned()),
            });
        }
        let mut draft = AuditDraft::success(actions::BIND, objects).with_source_ip(ctx.source_ip);
        for change in draft_changes {
            draft = draft.with_change(change);
        }
        batch.audit(draft);
        match self.store.propose(batch).await {
            Ok(_) => self.host_credentials(host).await,
            Err(StoreError::PreconditionFailed(_)) => Err(OperatorError::BindingsConflict),
            Err(error) => Err(error.into()),
        }
    }

    /// Counts a reveal of the person behind `ctx` against [`REVEALS_PER_WINDOW`].
    fn take_reveal(&self, ctx: &RequestCtx) -> Result<(), OperatorError> {
        let key = ctx.principal.subject();
        let now = Instant::now();
        let mut reveals = self.reveals.lock().unwrap_or_else(PoisonError::into_inner);
        // Forget idle people so the map stays small.
        reveals.retain(|_, times| {
            times
                .back()
                .is_some_and(|last| now.duration_since(*last) < REVEAL_WINDOW)
        });
        let times = reveals.entry(key).or_default();
        while times
            .front()
            .is_some_and(|first| now.duration_since(*first) >= REVEAL_WINDOW)
        {
            times.pop_front();
        }
        if times.len() >= REVEALS_PER_WINDOW {
            let retry_after = times.front().map_or(REVEAL_WINDOW, |first| {
                REVEAL_WINDOW.saturating_sub(now.duration_since(*first))
            });
            return Err(OperatorError::RateLimited {
                retry_after: retry_after.as_secs().max(1),
            });
        }
        times.push_back(now);
        Ok(())
    }

    /// Reveals an operator secret after the caller's authorization checks (the role, the
    /// PIN coupling rule and the step-up of TGL-24): checks the host binding the request
    /// names (required when `bound_host_only`), the rate limit of the person, then commits
    /// the audit record (`vault.secret.reveal` with the host, the reason and the kind) and
    /// the last-revealed stamp in one write, and only then returns the value. Refusals are
    /// audited too, except the rate limit.
    ///
    /// # Errors
    ///
    /// [`OperatorError::NotFound`], [`OperatorError::HostRequired`],
    /// [`OperatorError::NotBound`], [`OperatorError::RateLimited`],
    /// [`OperatorError::Invalid`] (the reason), [`OperatorError::NotText`], a vault or store
    /// error.
    pub async fn reveal(
        &self,
        ctx: &RequestCtx,
        id: SecretId,
        request: RevealRequest,
    ) -> Result<Revealed, OperatorError> {
        let reason = match valid_reason(request.reason.as_deref()) {
            Ok(reason) => reason,
            Err(error) => {
                self.audit_refused_reveal(ctx, id, request.host, None, &error)
                    .await;
                return Err(error);
            }
        };
        let view = self.view().await?;
        let checked = (|| {
            let secret = Self::must_load(view.as_ref(), id)?;
            match request.host {
                Some(host) => {
                    if binding(view.as_ref(), host, id)?.is_none() {
                        return Err(OperatorError::NotBound);
                    }
                }
                None if request.bound_host_only => return Err(OperatorError::HostRequired),
                None => {}
            }
            Ok(secret)
        })();
        let secret = match checked {
            Ok(secret) => secret,
            Err(error) => {
                self.audit_refused_reveal(ctx, id, request.host, reason.as_deref(), &error)
                    .await;
                return Err(error);
            }
        };
        if let Err(error) = self.take_reveal(ctx) {
            tracing::warn!(secret = %id, principal = %ctx.principal, "reveal rate limit reached");
            return Err(error);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.put_typed(
            &tables::REVEALS,
            &id,
            &RevealStamp {
                at: ctx.now,
                user: request.user.or_else(|| ctx.principal.user()),
                user_name: request.user_name.clone(),
                host: request.host,
            },
        )?;
        let audit = reveal_audit(
            request.host,
            reason.as_deref(),
            Some(secret.record.kind),
            Some(&secret.record.name),
        );
        let bytes = self
            .vault
            .reveal_with(ctx, SecretRef { secret: id }, batch, audit)
            .await?;
        let (value, login) = decode_value(secret.record.format, &bytes)?;
        drop(bytes);
        Ok(Revealed {
            value,
            username: secret.record.username.clone().or(login),
            kind: secret.record.kind,
            at: ctx.now,
        })
    }

    /// Records a refused reveal (IAM-16): `vault.secret.reveal` denied, with the code of the
    /// refusal, the host and the reason. Best effort: the caller returns its own error.
    pub async fn audit_refused_reveal(
        &self,
        ctx: &RequestCtx,
        id: SecretId,
        host: Option<HostId>,
        reason: Option<&str>,
        error: &(dyn Coded + Sync),
    ) {
        let audit = reveal_audit(host, reason, None, None);
        let mut objects = vec![ObjectRef::from(id)];
        objects.extend(audit.objects.iter().copied());
        let mut draft = AuditDraft::denied(crate::actions::REVEAL, objects)
            .with_source_ip(ctx.source_ip)
            .with_context("code", error.code());
        for (key, value) in audit.context {
            draft = draft.with_context(key, value);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(draft);
        if let Err(audit_error) = self.store.propose(batch).await {
            tracing::warn!(%audit_error, secret = %id, "could not audit a refused reveal");
        }
    }

    /// Adopts operator secrets that have no record yet (credentials imported before this
    /// model existed, or secrets stored by other means): writes the derived record and,
    /// when the vault metadata names a host as the owner, an `admin` binding to it. Safe to
    /// run at every start; returns how many secrets it adopted.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn adopt_unmanaged(&self, ctx: &RequestCtx) -> Result<usize, OperatorError> {
        let view = self.view().await?;
        let mut pending = Vec::new();
        for (id, (), _) in view.scan_typed(
            &crate::tables::OPERATOR_INDEX,
            KeyRange::all(),
            usize::MAX,
            false,
        )? {
            if view.get_typed(&tables::META, &id)?.is_some() {
                continue;
            }
            let Some((meta, _)) = view.get_typed(&crate::tables::META, &id)? else {
                continue;
            };
            pending.push(meta);
        }
        let mut adopted = 0;
        for chunk in pending.chunks(ADOPT_BATCH) {
            let mut batch = WriteBatch::for_request(ctx);
            batch.idempotency = None;
            let mut objects = Vec::new();
            for meta in chunk {
                let record = derived_record(meta);
                batch.expect_typed(&tables::META, &record.id, None);
                stage_record(&mut batch, &record)?;
                if let Some(owner) = meta.owner
                    && owner.kind == tenko_core::ObjectKind::Host
                {
                    let host = HostId::from(owner.id);
                    if binding(view.as_ref(), host, meta.id)?.is_none() {
                        stage_bind(&mut batch, host, meta.id, CredentialRole::Admin, ctx.now)?;
                    }
                }
                objects.push(ObjectRef::from(meta.id));
            }
            batch.audit(
                AuditDraft::success(actions::ADOPT, objects)
                    .with_context("count", chunk.len().to_string()),
            );
            match self.store.propose(batch).await {
                Ok(_) => adopted += chunk.len(),
                // Another node adopted them meanwhile.
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if adopted > 0 {
            tracing::info!(adopted, "operator secrets adopted into the secrets model");
        }
        Ok(adopted)
    }
}

/// The objects and context of a reveal's audit record. Never the value.
fn reveal_audit(
    host: Option<HostId>,
    reason: Option<&str>,
    kind: Option<OperatorSecretKind>,
    name: Option<&str>,
) -> RevealAudit {
    let mut audit = RevealAudit::default();
    if let Some(host) = host {
        audit.objects.push(ObjectRef::from(host));
        audit.context.push(("host".to_owned(), host.to_string()));
    }
    if let Some(reason) = reason {
        audit.context.push(("reason".to_owned(), reason.to_owned()));
    }
    if let Some(kind) = kind {
        audit
            .context
            .push(("kind".to_owned(), kind.as_str().to_owned()));
    }
    if let Some(name) = name {
        audit.context.push(("name".to_owned(), name.to_owned()));
    }
    audit
}

/// The audit action of a reveal, re-exported for callers that audit refusals themselves.
pub const REVEAL: AuditAction = crate::actions::REVEAL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_tags_and_notes_are_checked() {
        assert_eq!(valid_name("  nas admin ").expect("name"), "nas admin");
        assert!(valid_name("").is_err());
        assert!(valid_name("a\u{7}b").is_err());
        assert!(valid_name(&"n".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert_eq!(
            valid_tags(&[
                "UniFi".to_owned(),
                " api_key".to_owned(),
                "unifi".to_owned()
            ])
            .expect("tags"),
            vec!["api_key".to_owned(), "unifi".to_owned()]
        );
        assert!(valid_tags(&["with space".to_owned()]).is_err());
        assert!(valid_tags(&(0..=MAX_TAGS).map(|i| format!("t{i}")).collect::<Vec<_>>()).is_err());
        assert_eq!(valid_username(Some("  ")).expect("empty"), None);
        assert_eq!(
            valid_notes(Some("line one\nline two")).expect("notes"),
            Some("line one\nline two".to_owned())
        );
        assert!(valid_notes(Some("bell\u{7}")).is_err());
        assert!(valid_reason(Some(&"r".repeat(MAX_REASON_CHARS + 1))).is_err());
        assert!(valid_value(&SecretBytes::default()).is_err());
    }

    #[test]
    fn login_password_values_reveal_the_password() {
        let bytes = SecretBytes::from(br#"{"login":"admin","password":"example-pass"}"#.to_vec());
        let (value, login) = decode_value(ValueFormat::LoginPassword, &bytes).expect("decoded");
        assert_eq!(value.as_str(), "example-pass");
        assert_eq!(login.as_deref(), Some("admin"));
        let plain = SecretBytes::from(b"example-plain".to_vec());
        let (value, login) = decode_value(ValueFormat::Plain, &plain).expect("decoded");
        assert_eq!(value.as_str(), "example-plain");
        assert_eq!(login, None);
        assert_eq!(
            decode_value(ValueFormat::Plain, &SecretBytes::from(vec![0xff, 0xfe])).err(),
            Some(OperatorError::NotText)
        );
    }

    #[test]
    fn errors_never_carry_values_and_have_namespaced_codes() {
        let errors = [
            OperatorError::NotFound {
                secret: SecretId::generate(),
            },
            OperatorError::invalid("name", "bad"),
            OperatorError::Conflict,
            OperatorError::BindingsConflict,
            OperatorError::InUse {
                hosts: vec![],
                connectors: vec![],
            },
            OperatorError::HostRequired,
            OperatorError::NotBound,
            OperatorError::RateLimited { retry_after: 5 },
            OperatorError::NotText,
        ];
        for error in errors {
            assert!(error.code().starts_with("vault."), "{}", error.code());
            assert!((400..500).contains(&error.http_status()));
        }
    }

    #[test]
    fn revealed_values_never_print() {
        let revealed = Revealed {
            value: Zeroizing::new("example-secret-marker".to_owned()),
            username: Some("admin".to_owned()),
            kind: OperatorSecretKind::Password,
            at: Timestamp::now(),
        };
        let printed = format!("{revealed:?}");
        assert!(!printed.contains("example-secret-marker"));
        assert!(printed.contains("21 bytes"));
    }

    #[test]
    fn imported_records_take_the_login_as_user_name() {
        let id = SecretId::generate();
        let record = imported_record(id, "nas01", Some(" admin "), Timestamp::now());
        assert_eq!(record.username.as_deref(), Some("admin"));
        assert_eq!(record.format, ValueFormat::LoginPassword);
        assert_eq!(record.origin, SecretOrigin::Import);
        assert_eq!(record.name, "Login of nas01");
    }
}
