//! Stored records of the authentication service and their tables (namespace `auth`).
//!
//! Secrets never enter these tables: passwords, session ids, token secrets and recovery
//! codes are stored as hashes, TOTP seeds live in the vault (only the [`SecretRef`] is
//! here), and WebAuthn credentials hold public keys only.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `auth.users` | [`UserId`] | [`UserRecord`] |
//! | `auth.user_names` | lowercase user name | [`UserId`] |
//! | `auth.sessions` | SHA-256 of the session secret | [`SessionRecord`] |
//! | `auth.user_sessions` | ([`UserId`], [`SessionId`]) | SHA-256 of the session secret |
//! | `auth.tokens` | SHA-256 of the token | [`TokenRecord`] |
//! | `auth.user_tokens` | ([`UserId`], [`ApiTokenId`]) | SHA-256 of the token |
//! | `auth.credentials` | ([`UserId`], credential id) | [`CredentialRecord`] |
//! | `auth.credential_ids` | credential id | [`UserId`] |
//! | `auth.settings` | `()` | [`SecuritySettings`] |
//! | `auth.installation` | `()` | [`Installation`] |
//! | `auth.last_logins` | [`UserId`] | time of the last login |
//! | `auth.alarms` | alarm id (UUIDv7) | [`AlarmRecord`] |
//! | `auth.grants` | [`GrantId`] | [`GrantRecord`] (scoped grants, IAM-01) |
//! | `auth.role_policies` | role name | [`RolePolicy`] (MFA per role, IAM-06) |
//! | `auth.scoped_tokens` | SHA-256 of the token | [`ScopedTokenRecord`] (IAM-10) |
//! | `auth.user_scoped_tokens` | ([`UserId`], [`ApiTokenId`]) | SHA-256 of the token |
//! | `auth.preferences` | ([`UserId`], key) | [`StoredPreference`] (the person's saved table layouts) |
//! | `auth.providers`, `auth.mappings`, `auth.oidc_flows`, `auth.external_ids` | see [`crate::directory`] | directory sign-in (WP13.0) |
//!
//! Scoped grants, role policies and scoped tokens live in tables that builds before
//! WP3.2 do not read: after a rollback a scoped grant or token grants nothing instead of
//! being read as a global one (plan section 2.1, R25).
//!
//! `auth.preferences` is additive in the same way: a build before it does not read the
//! table, and a backup taken before it restores with the table empty, so every table shows
//! its default layout until the person changes it again. Its changes are not routed to the
//! event stream (`tenko_api::sse`): a person's layout is nobody else's event.

use std::{fmt, net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ApiTokenId, AuthStrength, MessageKey, MirrorId, ScopeRule, SessionId, Timestamp, UserId,
    error::InvalidValue, secret::SecretRef, table::TableDef,
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, Type},
};

pub use crate::preferences::StoredPreference;
use crate::{
    directory::{SessionSource, UserSource},
    password::hash::PasswordHash,
    recovery::StoredRecoveryCode,
    roles::RoleName,
    settings::SecuritySettings,
    webauthn::AttestationKind,
};

/// Users by id.
pub const USERS: TableDef<UserId, UserRecord> = TableDef::new("auth.users");
/// User ids by lowercase name (uniqueness).
pub const USER_NAMES: TableDef<String, UserId> = TableDef::new("auth.user_names");
/// Sessions by the hash of their secret.
pub const SESSIONS: TableDef<Vec<u8>, SessionRecord> = TableDef::new("auth.sessions");
/// Session hashes by user, for listing and revocation.
pub const USER_SESSIONS: TableDef<(UserId, SessionId), Vec<u8>> =
    TableDef::new("auth.user_sessions");
/// Personal tokens by the hash of the token.
pub const TOKENS: TableDef<Vec<u8>, TokenRecord> = TableDef::new("auth.tokens");
/// Token hashes by owner.
pub const USER_TOKENS: TableDef<(UserId, ApiTokenId), Vec<u8>> = TableDef::new("auth.user_tokens");
/// WebAuthn credentials by user and credential id.
pub const CREDENTIALS: TableDef<(UserId, Vec<u8>), CredentialRecord> =
    TableDef::new("auth.credentials");
/// Owners of credential ids (discoverable login).
pub const CREDENTIAL_IDS: TableDef<Vec<u8>, UserId> = TableDef::new("auth.credential_ids");
/// The security settings singleton.
pub const SETTINGS: TableDef<(), SecuritySettings> = TableDef::new("auth.settings");
/// The installation record; its presence means first-run setup is complete.
pub const INSTALLATION: TableDef<(), Installation> = TableDef::new("auth.installation");
/// The last login of each user, kept apart from [`USERS`] so that logins do not contend
/// with changes to the account.
pub const LAST_LOGINS: TableDef<UserId, Timestamp> = TableDef::new("auth.last_logins");
/// Security alarms (break-glass use, locks with alert); routed to the `system` SSE topic.
pub const ALARMS: TableDef<uuid::Uuid, AlarmRecord> = TableDef::new("auth.alarms");
/// Scoped grants by id (IAM-01).
pub const GRANTS: TableDef<GrantId, GrantRecord> = TableDef::new("auth.grants");
/// MFA policies by role name (IAM-06); a role without a row follows the profile.
pub const ROLE_POLICIES: TableDef<String, RolePolicy> = TableDef::new("auth.role_policies");
/// Scoped tokens by the hash of the token (IAM-10).
pub const SCOPED_TOKENS: TableDef<Vec<u8>, ScopedTokenRecord> = TableDef::new("auth.scoped_tokens");
/// Scoped token hashes by owner.
pub const USER_SCOPED_TOKENS: TableDef<(UserId, ApiTokenId), Vec<u8>> =
    TableDef::new("auth.user_scoped_tokens");
/// The personal preferences of each person by (user, key), such as `table:addresses`
/// (`crate::preferences`).
pub const PREFERENCES: TableDef<(UserId, String), StoredPreference> =
    TableDef::new("auth.preferences");
/// Counts the new preference keys of each person: a write that adds a key expects the value
/// it read and bumps it, so two concurrent additions cannot pass the key limit together.
pub fn preference_keys_counter(user: UserId) -> tenko_core::CounterKey {
    tenko_core::CounterKey::with("auth.preferences", &user)
}

tenko_core::id_type! {
    /// Identifier of a scoped grant.
    GrantId,
}

/// What kind of account a user record is (IAM-10).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    /// A person: signs in with a password, passkeys and second factors.
    #[default]
    Person,
    /// A service account: no password, passkey or session; it holds roles and grants and
    /// acts through scoped tokens that an administrator creates for it.
    Service,
}

impl UserKind {
    /// Whether the value is the default, for `skip_serializing_if`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_person(&self) -> bool {
        *self == Self::Person
    }
}

/// A scoped grant: a role over a VRF, a site or a prefix (IAM-01). Global roles stay in
/// [`UserRecord::roles`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    /// The id.
    pub id: GrantId,
    /// The person or service account that holds the grant.
    pub subject: UserId,
    /// The role: `operator` or `viewer`.
    pub role: RoleName,
    /// Where the role applies: a VRF, a site or a prefix, with or without its subtree.
    pub scope: ScopeRule,
    /// Whether the holder may grant a role no higher over a scope inside this one.
    #[serde(default)]
    pub delegable: bool,
    /// Who created the grant; `None` for the system.
    #[serde(default)]
    pub granted_by: Option<UserId>,
    /// When it was created.
    pub granted_at: Timestamp,
    /// The delegable grant it was issued under; revoking that one revokes this one.
    #[serde(default)]
    pub parent: Option<GrantId>,
}

/// The MFA requirement of a role (IAM-06), from the weakest to the strongest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleMfa {
    /// No second factor needed by the role.
    Optional,
    /// A password with TOTP or a recovery code, or a passkey.
    TotpOrStronger,
    /// A passkey or a hardware security key.
    Passkey,
}

impl RoleMfa {
    /// The weakest session strength that meets the requirement.
    pub const fn strength(self) -> AuthStrength {
        match self {
            Self::Optional => AuthStrength::Pin,
            Self::TotpOrStronger => AuthStrength::PasswordTotp,
            Self::Passkey => AuthStrength::Passkey,
        }
    }

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::TotpOrStronger => "totp_or_stronger",
            Self::Passkey => "passkey",
        }
    }
}

/// A stored MFA policy of one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePolicy {
    /// The role.
    pub role: RoleName,
    /// The requirement.
    pub mfa: RoleMfa,
    /// When it was set.
    pub updated_at: Timestamp,
    /// Who set it.
    #[serde(default)]
    pub updated_by: Option<UserId>,
}

/// A special scope of a scoped token, beyond its grants (IAM-10, S3-Q7). On the wire and
/// in the store it is a string: `metrics`, `audit:read`, or `mirror:<id>` for the token of
/// a mirrored source (WP14.0, Windows takeover plan section 2.1).
///
/// The mirror scope carries the mirror's identifier as its payload. `MirrorId` is a
/// sixteen-octet UUID, so the enum keeps `Copy` and the scope stays a value that is passed
/// and compared by value, as before; the alternative, a field of its own on the token
/// record beside `scopes`, would have put the mirror's right outside the list every check
/// reads and would have needed a second rule for "no other scope with a mirror scope".
/// The mirror scope is never requested through the token API: the creation of a mirror
/// mints it (`AuthService::validate_token_grants` refuses it in a request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TokenScope {
    /// Reads the metrics endpoint (OPS-05).
    Metrics,
    /// Reads the audit log (IAM-18).
    AuditRead,
    /// Pushes the snapshots of one mirrored source, and nothing else (WP14.0).
    Mirror(MirrorId),
}

impl TokenScope {
    /// The prefix of the wire form of a mirror scope.
    pub const MIRROR_PREFIX: &'static str = "mirror:";

    /// The stable name of a scope without a payload; the mirror scope's wire form is
    /// [`TokenScope::to_string`] (`mirror:<id>`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::AuditRead => "audit:read",
            Self::Mirror(_) => "mirror",
        }
    }

    /// The mirror a mirror scope names.
    pub const fn mirror(self) -> Option<MirrorId> {
        match self {
            Self::Mirror(id) => Some(id),
            Self::Metrics | Self::AuditRead => None,
        }
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] for anything but `metrics`, `audit:read` and `mirror:<uuid>`.
    pub fn parse(text: &str) -> Result<Self, InvalidValue> {
        match text {
            "metrics" => Ok(Self::Metrics),
            "audit:read" => Ok(Self::AuditRead),
            _ => text
                .strip_prefix(Self::MIRROR_PREFIX)
                .and_then(|id| id.parse::<MirrorId>().ok())
                .map(Self::Mirror)
                .ok_or_else(|| {
                    InvalidValue::new(
                        "token scope",
                        text,
                        "one of metrics, audit:read, mirror:<id>",
                    )
                }),
        }
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mirror(id) => write!(f, "{}{id}", Self::MIRROR_PREFIX),
            other => f.write_str(other.label()),
        }
    }
}

impl FromStr for TokenScope {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for TokenScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TokenScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for TokenScope {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .description(Some(
                    "A special scope of a scoped token: `metrics`, `audit:read`, or                      `mirror:<id>` (the push of one mirrored source; minted when the                      mirror is created, never requested here)",
                ))
                .examples(["metrics", "audit:read"])
                .build(),
        ))
    }
}

impl ToSchema for TokenScope {}

/// One grant of a scoped token: a role, globally or over one scope rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TokenGrant {
    /// The role.
    pub role: RoleName,
    /// Where it applies (`{kind, value}` as in a grant); absent for the whole installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<crate::service::types::ScopeRuleSchema>)]
    pub scope: Option<ScopeRule>,
}

/// A scoped API token (IAM-10). Stored under the SHA-256 of the token. The effective right
/// of a request is the intersection of the token's grants and its owner's at request time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenRecord {
    /// The token id.
    pub id: ApiTokenId,
    /// The person or service account the token acts for.
    pub owner: UserId,
    /// A name chosen at creation.
    pub name: String,
    /// When it was created.
    pub created_at: Timestamp,
    /// Who created it (the owner, or the administrator of a service account).
    pub created_by: UserId,
    /// When it expires; `None` only where TGL-05 allows non-expiring tokens.
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
    /// The last use (recorded at most hourly).
    #[serde(default)]
    pub last_used_at: Option<Timestamp>,
    /// The strength of the session that created the token.
    pub issued_with: AuthStrength,
    /// The first characters of the token, for recognition in listings.
    pub prefix: String,
    /// The grants: each a role, globally or over a scope rule.
    #[serde(default)]
    pub grants: Vec<TokenGrant>,
    /// The special scopes.
    #[serde(default)]
    pub scopes: Vec<TokenScope>,
}

/// How a password was set, which decides the strength of a password login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasswordKind {
    /// Set under the PIN preset: a login is [`AuthStrength::Pin`].
    Pin,
    /// Any other preset: a login is [`AuthStrength::Password`].
    Password,
}

/// The stored password of an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPassword {
    /// The Argon2id PHC string.
    pub hash: PasswordHash,
    /// PIN or password.
    pub kind: PasswordKind,
    /// When it was set.
    pub changed_at: Timestamp,
}

/// The TOTP factor of an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpFactor {
    /// The vault secret holding the seed (a `System` secret).
    pub secret: SecretRef,
    /// When it was enrolled.
    pub enrolled_at: Timestamp,
    /// The last accepted time step (replay protection).
    #[serde(default)]
    pub last_used_step: Option<u64>,
}

/// A persisted lock (IAM-05, TGL-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AccountLock {
    /// When the lock started.
    pub since: Timestamp,
    /// When it lifts by itself.
    pub until: Timestamp,
    /// Whether only an administrator should lift it early (Hardened).
    pub until_unlock: bool,
}

/// A local user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// The id; its 16 bytes are the WebAuthn user handle.
    pub id: UserId,
    /// The login name, as entered (unique case-insensitively).
    pub name: String,
    /// The display name.
    pub display_name: String,
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// The password, if the account has one (break-glass accounts do not log in with it).
    #[serde(default)]
    pub password: Option<StoredPassword>,
    /// TOTP, if enrolled.
    #[serde(default)]
    pub totp: Option<TotpFactor>,
    /// Hashed recovery codes.
    #[serde(default)]
    pub recovery_codes: Vec<StoredRecoveryCode>,
    /// A disabled account cannot log in.
    #[serde(default)]
    pub disabled: bool,
    /// The break-glass account (IAM-09): hardware security key only, rate limited, alarms.
    #[serde(default)]
    pub break_glass: bool,
    /// A persisted lock.
    #[serde(default)]
    pub lock: Option<AccountLock>,
    /// The password must be changed at the next opportunity (it no longer meets the policy).
    #[serde(default)]
    pub password_change_required: bool,
    /// The UI language of the account (`en`, `sv`), when fixed (API-08).
    #[serde(default)]
    pub language: Option<String>,
    /// When the account was created.
    pub created_at: Timestamp,
    /// A person or a service account (IAM-10).
    #[serde(default)]
    pub kind: UserKind,
    /// The administrator who created and owns a service account.
    #[serde(default)]
    pub owner: Option<UserId>,
    /// The last unlock by an administrator; every controller clears its login throttle for
    /// the account when it sees the change (WP3.2; the throttle is per controller).
    #[serde(default)]
    pub unlocked_at: Option<Timestamp>,
    // WP13.0: the external identity of a directory user (identity plan section 3.16).
    /// Where the account comes from: local, or created at the first sign-in through a
    /// provider, keyed by the immutable subject. Absent in records of 0.0.11: local.
    #[serde(default, skip_serializing_if = "UserSource::is_local")]
    pub source: UserSource,
    // WP13.0: end.
}

impl UserRecord {
    /// A new enabled account without factors.
    pub fn new(name: String, display_name: String, roles: Vec<RoleName>, now: Timestamp) -> Self {
        Self {
            id: UserId::generate(),
            name,
            display_name,
            roles,
            password: None,
            totp: None,
            recovery_codes: Vec::new(),
            disabled: false,
            break_glass: false,
            lock: None,
            password_change_required: false,
            language: None,
            created_at: now,
            kind: UserKind::Person,
            owner: None,
            unlocked_at: None,
            source: UserSource::Local,
        }
    }

    /// Whether the record is a service account.
    pub fn is_service(&self) -> bool {
        self.kind == UserKind::Service
    }

    /// The key under [`USER_NAMES`].
    pub fn name_key(name: &str) -> String {
        name.trim().to_lowercase()
    }

    /// The WebAuthn user handle: the 16 bytes of the id.
    pub fn user_handle(&self) -> [u8; 16] {
        *self.id.0.as_bytes()
    }

    /// Whether the account holds the `admin` role.
    pub fn is_admin(&self) -> bool {
        self.roles.contains(&RoleName::Admin)
    }

    /// Unused recovery codes.
    pub fn recovery_codes_left(&self) -> usize {
        crate::recovery::remaining(&self.recovery_codes)
    }

    /// Whether the account has a second factor or a passkey (`credentials` is the number
    /// of registered WebAuthn credentials).
    pub fn has_strong_factor(&self, credentials: usize) -> bool {
        self.totp.is_some() || credentials > 0
    }

    /// The lock in force at `now`, if any.
    pub fn active_lock(&self, now: Timestamp) -> Option<AccountLock> {
        self.lock.filter(|lock| now < lock.until)
    }
}

/// A login session (IAM-08). Stored under the SHA-256 of its 256-bit secret; the secret
/// itself exists only in the client's cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The session id used in references, listings and audit records.
    pub id: SessionId,
    /// The user.
    pub user: UserId,
    /// How strongly the session was authenticated.
    pub strength: AuthStrength,
    /// When the session started.
    pub created_at: Timestamp,
    /// The last full authentication (login or step-up), for actions that need a fresh one.
    pub authenticated_at: Timestamp,
    /// The absolute end.
    pub expires_at: Timestamp,
    /// The idle end, moved forward by activity.
    pub idle_expires_at: Timestamp,
    /// The last recorded activity.
    pub last_seen_at: Timestamp,
    /// The client address at login.
    #[serde(default)]
    pub source_ip: Option<IpAddr>,
    /// The client's user agent at login (truncated).
    #[serde(default)]
    pub user_agent: Option<String>,
    /// The session belongs to the break-glass account.
    #[serde(default)]
    pub break_glass: bool,
    /// The profile requires a second factor that the user has not enrolled yet; the
    /// session may only enroll factors.
    // Stored sessions of 0.0.11 carry the old name.
    #[serde(default, alias = "mfa_enrolment_required")] // spelling: alias permanently
    pub mfa_enrollment_required: bool,
    // WP13.0: directory sessions (identity plan section 3.17).
    /// How the session was signed in: locally, or through a provider. Absent in records
    /// of 0.0.11: local.
    #[serde(default, skip_serializing_if = "SessionSource::is_local")]
    pub source: SessionSource,
    /// When the directory last confirmed the user and the groups (the check of section
    /// 3.13); none for a local session or before the first check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_checked_at: Option<Timestamp>,
    // WP13.0: end.
}

/// A personal API token (IAM-10). Stored under the SHA-256 of the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    /// The token id.
    pub id: ApiTokenId,
    /// The owner, whose roles the token acts with.
    pub owner: UserId,
    /// A name chosen by the owner.
    pub name: String,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it expires; `None` only where TGL-05 allows non-expiring tokens.
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
    /// The last use (recorded at most hourly).
    #[serde(default)]
    pub last_used_at: Option<Timestamp>,
    /// The strength of the session that created the token.
    pub issued_with: AuthStrength,
    /// The first characters of the token, for recognition in listings.
    pub prefix: String,
}

/// A registered WebAuthn credential (public data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The owner.
    pub user: UserId,
    /// A label chosen by the user.
    pub label: String,
    /// The COSE public key.
    pub public_key: Vec<u8>,
    /// The COSE algorithm.
    pub alg: i64,
    /// The last signature counter.
    pub sign_count: u32,
    /// The authenticator model.
    pub aaguid: [u8; 16],
    /// Backup eligible (a synced passkey).
    pub backup_eligible: bool,
    /// Backed up at the last use.
    pub backup_state: bool,
    /// What the attestation proved.
    pub attestation: AttestationKind,
    /// Counts as a hardware security key (ADR 0010).
    pub hardware_key: bool,
    /// Transports reported at registration.
    #[serde(default)]
    pub transports: Vec<String>,
    /// When it was registered.
    pub created_at: Timestamp,
    /// The last successful use.
    #[serde(default)]
    pub last_used_at: Option<Timestamp>,
}

/// The installation record written by first-run setup (API-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Installation {
    /// When setup completed.
    pub completed_at: Timestamp,
    /// The host name: TLS certificate subject and WebAuthn RP ID (Q5).
    pub host_name: String,
    /// The default UI language (`en` or `sv`).
    pub language: String,
    /// The first administrator.
    pub first_admin: UserId,
}

/// What raised an alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlarmKind {
    /// The break-glass account logged in (IAM-09).
    BreakGlassLogin,
    /// A break-glass login attempt failed.
    BreakGlassFailure,
    /// An account was locked under the Hardened lockout mode (TGL-07).
    AccountLocked,
}

/// A security alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AlarmRecord {
    /// When it was raised.
    pub at: Timestamp,
    /// What happened.
    pub kind: AlarmKind,
    /// The UI message key.
    pub message: MessageKey,
    /// The account concerned.
    #[serde(default)]
    pub user: Option<UserId>,
    /// The client address.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub source_ip: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use tenko_core::{AuthStrength, MirrorId, SessionId, Timestamp, UserId};

    use super::{SESSIONS, SessionRecord, SessionSource, TokenScope};

    // WP14.0: the wire form `mirror:<id>` of the mirror scope.
    #[test]
    fn token_scopes_round_trip_through_their_wire_form() {
        let mirror = MirrorId::generate();
        for scope in [
            TokenScope::Metrics,
            TokenScope::AuditRead,
            TokenScope::Mirror(mirror),
        ] {
            let text = scope.to_string();
            assert_eq!(text.parse::<TokenScope>(), Ok(scope));
            let json = serde_json::to_string(&scope).expect("json");
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(
                serde_json::from_str::<TokenScope>(&json).expect("json"),
                scope
            );
            let cbor = tenko_core::codec::to_cbor(&scope).expect("cbor");
            assert_eq!(
                tenko_core::codec::from_cbor::<TokenScope>(&cbor).expect("cbor"),
                scope
            );
        }
        assert_eq!(
            TokenScope::Mirror(mirror).to_string(),
            format!("mirror:{mirror}")
        );
        assert_eq!(TokenScope::Mirror(mirror).mirror(), Some(mirror));
        assert_eq!(TokenScope::Metrics.mirror(), None);
        for bad in ["mirror", "mirror:", "mirror:not-a-uuid", "Metrics", ""] {
            assert!(bad.parse::<TokenScope>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_session_stored_by_0_0_11_keeps_its_enrollment_restriction() {
        let at: Timestamp = "2026-10-10T08:00:00Z".parse().expect("time");
        let record = SessionRecord {
            id: SessionId::generate(),
            user: UserId::generate(),
            strength: AuthStrength::Password,
            created_at: at,
            authenticated_at: at,
            expires_at: at,
            idle_expires_at: at,
            last_seen_at: at,
            source_ip: None,
            user_agent: None,
            break_glass: false,
            mfa_enrollment_required: true,
            source: SessionSource::Local,
            directory_checked_at: None,
        };
        let new = SESSIONS.encode(&record).expect("cbor").to_vec();
        // The bytes 0.0.11 wrote: the same map with the CBOR text key of the old name
        // (major type 3, the length in the header byte).
        let text = |key: &str| {
            let mut out = vec![0x60 | u8::try_from(key.len()).expect("short")];
            out.extend_from_slice(key.as_bytes());
            out
        };
        let new_key = text("mfa_enrollment_required");
        let old_key = text("mfa_enrolment_required"); // spelling: alias permanently
        let at = new
            .windows(new_key.len())
            .position(|window| window == new_key)
            .expect("the key");
        let mut old = new[..at].to_vec();
        old.extend_from_slice(&old_key);
        old.extend_from_slice(&new[at + new_key.len()..]);
        let read = SESSIONS.decode(&old).expect("an old session decodes");
        assert!(read.mfa_enrollment_required);
        assert_eq!(read, record);
    }
}
