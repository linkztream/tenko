//! The wire types of the secrets area. Values travel only in [`NewOperatorSecret`],
//! [`OperatorSecretPatch`] (requests) and [`RevealedSecret`] (the one response that carries
//! a value, sent with `Cache-Control: no-store`); every other type holds metadata only.

use serde::{Deserialize, Serialize};
use tenko_auth::service::SecretString;
use tenko_core::{ConnectorId, HostId, Revision, SecretId, Timestamp, UserId};
use tenko_ipam::command::nullable;
use tenko_vault::operator::{
    self, CredentialRole as ModelRole, OperatorSecret, OperatorSecretKind,
    SecretOrigin as ModelOrigin,
};
use utoipa::{IntoParams, ToSchema};

/// What an operator secret is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// A password, usually with a user name.
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

impl From<OperatorSecretKind> for SecretKind {
    fn from(kind: OperatorSecretKind) -> Self {
        match kind {
            OperatorSecretKind::Password => Self::Password,
            OperatorSecretKind::ApiKey => Self::ApiKey,
            OperatorSecretKind::SshKey => Self::SshKey,
            OperatorSecretKind::Token => Self::Token,
            OperatorSecretKind::Other => Self::Other,
        }
    }
}

impl From<SecretKind> for OperatorSecretKind {
    fn from(kind: SecretKind) -> Self {
        match kind {
            SecretKind::Password => Self::Password,
            SecretKind::ApiKey => Self::ApiKey,
            SecretKind::SshKey => Self::SshKey,
            SecretKind::Token => Self::Token,
            SecretKind::Other => Self::Other,
        }
    }
}

/// Where an operator secret came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretOrigin {
    /// Created by a person.
    Manual,
    /// Stored by an import from a credential column.
    Import,
}

impl From<ModelOrigin> for SecretOrigin {
    fn from(origin: ModelOrigin) -> Self {
        match origin {
            ModelOrigin::Manual => Self::Manual,
            ModelOrigin::Import => Self::Import,
        }
    }
}

/// The role of a credential on a host.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
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

impl From<ModelRole> for CredentialRole {
    fn from(role: ModelRole) -> Self {
        match role {
            ModelRole::Admin => Self::Admin,
            ModelRole::Rdp => Self::Rdp,
            ModelRole::Ssh => Self::Ssh,
            ModelRole::Web => Self::Web,
            ModelRole::Other => Self::Other,
        }
    }
}

impl From<CredentialRole> for ModelRole {
    fn from(role: CredentialRole) -> Self {
        match role {
            CredentialRole::Admin => Self::Admin,
            CredentialRole::Rdp => Self::Rdp,
            CredentialRole::Ssh => Self::Ssh,
            CredentialRole::Web => Self::Web,
            CredentialRole::Other => Self::Other,
        }
    }
}

/// The last reveal of a secret: who and when, never the value or the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LastReveal {
    /// When.
    pub at: Timestamp,
    /// The person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserId>,
    /// Their login name at the time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// The host they were looking at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
}

/// A host a secret is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretHostRef {
    /// The host.
    pub host: HostId,
    /// The role of the credential on it.
    pub role: CredentialRole,
}

/// An operator secret: metadata only, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OperatorSecretView {
    /// The secret.
    pub id: SecretId,
    /// The name (not unique).
    pub name: String,
    /// What it is.
    pub kind: SecretKind,
    /// Purpose tags (lower case, sorted), for example `api_key` or `unifi`; a connector form
    /// offers the secrets whose tags include the purpose it needs.
    pub tags: Vec<String>,
    /// The user name that goes with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Where it came from.
    pub origin: SecretOrigin,
    /// When it was created.
    pub created_at: Timestamp,
    /// When its metadata or value last changed.
    pub updated_at: Timestamp,
    /// When its value was last written (creation, replacement, key rotation).
    pub value_updated_at: Timestamp,
    /// The last reveal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revealed: Option<LastReveal>,
    /// The hosts it is bound to, with the role.
    pub hosts: Vec<SecretHostRef>,
    /// The revision of the metadata, as in the `ETag`; absent for a secret stored before
    /// the secrets model whose record is not written yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

impl From<&OperatorSecret> for OperatorSecretView {
    fn from(secret: &OperatorSecret) -> Self {
        let record = &secret.record;
        Self {
            id: record.id,
            name: record.name.clone(),
            kind: record.kind.into(),
            tags: record.tags.clone(),
            username: record.username.clone(),
            notes: record.notes.clone(),
            origin: record.origin.into(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            value_updated_at: secret.value_updated_at,
            last_revealed: secret.last_revealed.as_ref().map(|stamp| LastReveal {
                at: stamp.at,
                user: stamp.user,
                user_name: stamp.user_name.clone(),
                host: stamp.host,
            }),
            hosts: secret
                .hosts
                .iter()
                .map(|(host, role)| SecretHostRef {
                    host: *host,
                    role: (*role).into(),
                })
                .collect(),
            revision: secret.revision,
        }
    }
}

/// A new operator secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewOperatorSecret {
    /// The name: 1 to 128 visible characters.
    pub name: String,
    /// What it is.
    pub kind: SecretKind,
    /// Purpose tags: up to 16, each 1 to 64 characters of `a-z`, `0-9`, `.`, `_` and `-`
    /// (upper case is folded).
    #[serde(default)]
    pub tags: Vec<String>,
    /// The user name that goes with it (at most 256 characters).
    #[serde(default)]
    pub username: Option<String>,
    /// Notes (at most 2,000 characters). Notes are not secret: never put a value here.
    #[serde(default)]
    pub notes: Option<String>,
    /// The value, as text (1 byte to 64 KiB). Stored encrypted; never returned except by
    /// the reveal.
    pub value: SecretString,
}

/// A change of an operator secret. Absent members stay; `null` clears `username` and
/// `notes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorSecretPatch {
    /// A new name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A new kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SecretKind>,
    /// New purpose tags (the whole list).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// A new user name; `null` clears it.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, nullable)]
    pub username: Option<Option<String>>,
    /// New notes; `null` clears them.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, nullable)]
    pub notes: Option<Option<String>>,
    /// A new value (replaces the stored one under a fresh data key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretString>,
}

/// A reveal request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealRequest {
    /// The host the person is looking at; the secret must be bound to it. Required when
    /// the reveal policy (TGL-24) reveals only secrets bound to the host in view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// Why, in the person's words (at most 200 characters); written to the audit record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A revealed value. Sent once with `Cache-Control: no-store`, never stored for an
/// idempotent replay; the reveal is in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RevealedSecret {
    /// The secret.
    pub id: SecretId,
    /// The value (the password of an imported login).
    pub value: SecretString,
    /// The user name that goes with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// What it is.
    pub kind: SecretKind,
    /// When the reveal was recorded in the audit log.
    pub revealed_at: Timestamp,
    /// Seconds after which the UI clears the value from the clipboard.
    pub clear_after_secs: u32,
}

/// A host that binds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretHostReference {
    /// The host.
    pub host: HostId,
    /// Its name, when the host still exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The role of the credential on it.
    pub role: CredentialRole,
    /// Whether the host is deleted.
    #[serde(default)]
    pub deleted: bool,
}

/// A connector instance that references a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretConnectorReference {
    /// The connector instance.
    pub connector: ConnectorId,
    /// Its name.
    pub name: String,
    /// Its plugin.
    pub plugin: String,
    /// The purpose the secret serves for the plugin.
    pub purpose: String,
}

/// What references a secret. A secret with any reference cannot be deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretReferences {
    /// The secret.
    pub id: SecretId,
    /// The hosts that bind it as a credential.
    pub hosts: Vec<SecretHostReference>,
    /// The connector instances that use it.
    pub connectors: Vec<SecretConnectorReference>,
}

impl SecretReferences {
    /// Whether nothing references the secret.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.connectors.is_empty()
    }
}

/// One credential of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostCredentialItem {
    /// The role of the credential on the host.
    pub role: CredentialRole,
    /// When it was bound.
    pub bound_at: Timestamp,
    /// The secret (metadata only).
    pub secret: OperatorSecretView,
}

/// The credentials bound to a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostCredentialsView {
    /// The host.
    pub host: HostId,
    /// The credentials, by role and name.
    pub items: Vec<HostCredentialItem>,
    /// The version of the set, as in the `ETag`; send it as `If-Match` with a change.
    pub version: u64,
}

impl From<&operator::HostCredentials> for HostCredentialsView {
    fn from(credentials: &operator::HostCredentials) -> Self {
        Self {
            host: credentials.host,
            items: credentials
                .items
                .iter()
                .map(|item| HostCredentialItem {
                    role: item.role.into(),
                    bound_at: item.bound_at,
                    secret: OperatorSecretView::from(&item.secret),
                })
                .collect(),
            version: credentials.version,
        }
    }
}

/// One binding of a change of a host's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialBinding {
    /// The operator secret.
    pub secret: SecretId,
    /// Its role on the host.
    pub role: CredentialRole,
}

/// The new set of credentials of a host: every binding not listed is removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialsUpdate {
    /// The bindings: one per secret, at most 32.
    pub credentials: Vec<HostCredentialBinding>,
}

/// The filters of `GET /secrets`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SecretFilters {
    /// Case-insensitive text search over the name, the user name and the tags.
    pub q: Option<String>,
    /// Only secrets of this kind.
    pub kind: Option<SecretKind>,
    /// Only secrets that carry this purpose tag.
    pub tag: Option<String>,
    /// Only secrets bound to this host.
    pub host: Option<HostId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_never_print_their_values() {
        let new: NewOperatorSecret = serde_json::from_value(serde_json::json!({
            "name": "nas admin",
            "kind": "password",
            "value": "example-value-marker"
        }))
        .expect("a new secret");
        assert!(!format!("{new:?}").contains("example-value-marker"));
        let patch: OperatorSecretPatch =
            serde_json::from_value(serde_json::json!({ "value": "example-value-marker" }))
                .expect("a patch");
        assert!(!format!("{patch:?}").contains("example-value-marker"));
    }

    #[test]
    fn patches_tell_null_from_absent() {
        let patch: OperatorSecretPatch =
            serde_json::from_value(serde_json::json!({ "username": null })).expect("a patch");
        assert_eq!(patch.username, Some(None));
        assert_eq!(patch.notes, None);
        let patch: OperatorSecretPatch =
            serde_json::from_value(serde_json::json!({ "notes": "rack 4" })).expect("a patch");
        assert_eq!(patch.notes, Some(Some("rack 4".to_owned())));
        assert!(
            serde_json::from_value::<OperatorSecretPatch>(serde_json::json!({ "secret": 1 }))
                .is_err()
        );
    }

    #[test]
    fn enums_use_snake_case() {
        assert_eq!(
            serde_json::to_value(SecretKind::SshKey).expect("json"),
            "ssh_key"
        );
        assert_eq!(
            serde_json::to_value(CredentialRole::Rdp).expect("json"),
            "rdp"
        );
        assert_eq!(
            serde_json::to_value(SecretOrigin::Import).expect("json"),
            "import"
        );
    }
}
