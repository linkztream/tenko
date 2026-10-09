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

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::{
    ApiTokenId, AuthStrength, MessageKey, SessionId, Timestamp, UserId, secret::SecretRef,
    table::TableDef,
};
use utoipa::ToSchema;

use crate::{
    password::hash::PasswordHash, recovery::StoredRecoveryCode, roles::RoleName,
    settings::SecuritySettings, webauthn::AttestationKind,
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
        }
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
    /// session may only enrol factors.
    #[serde(default)]
    pub mfa_enrolment_required: bool,
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
