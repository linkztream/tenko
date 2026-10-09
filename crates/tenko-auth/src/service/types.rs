//! Request and response bodies of the authentication service. The API routes use them as
//! their JSON bodies, so they carry the OpenAPI schemas too.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tenko_core::{ApiTokenId, AuthStrength, Revision, SessionId, Timestamp, UserId};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, Type},
};
use zeroize::Zeroizing;

use crate::{
    model::AccountLock,
    password::{PolicyViolation, policy::PasswordPolicy},
    roles::RoleName,
    settings::{Banner, Profile, SecuritySettings, ToggleState},
    totp::TotpParams,
    webauthn::{
        AttestationKind, AuthenticationResponse, CreationOptions, RegistrationResponse,
        RequestOptions,
    },
};

/// A secret string in a request or a one-time response (a password, a code, a token).
/// Zeroized on drop; `Debug` never shows it.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plaintext. Keep the borrow short and never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl PartialSchema for SecretString {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .format(Some(utoipa::openapi::SchemaFormat::Custom(
                    "password".to_owned(),
                )))
                .build(),
        ))
    }
}

impl ToSchema for SecretString {}

/// `POST /auth/login/password`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct PasswordLogin {
    /// The user name.
    pub user_name: String,
    /// The password or PIN.
    pub password: SecretString,
}

/// `POST /auth/login/totp` and `POST /auth/login/recovery`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CodeLogin {
    /// The challenge from the password step.
    pub challenge_id: String,
    /// The TOTP code or recovery code.
    pub code: SecretString,
}

/// A second factor that completes a password login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecondFactorMethod {
    /// A TOTP code (`POST /auth/login/totp`).
    Totp,
    /// A recovery code (`POST /auth/login/recovery`).
    Recovery,
    /// A passkey or security key (`POST /auth/webauthn/login/start` with the challenge).
    Webauthn,
}

/// The answer of a login step.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginResponse {
    /// The login is complete; the session cookie is set.
    Authenticated {
        /// The new session.
        session: SessionInfo,
    },
    /// A second factor is required.
    SecondFactor {
        /// Pass this to the next step.
        challenge_id: String,
        /// The methods the account can use.
        methods: Vec<SecondFactorMethod>,
        /// Seconds until the challenge expires.
        expires_in: u64,
    },
}

/// `POST /auth/webauthn/login/start`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct WebAuthnLoginStart {
    /// A user name for a login with that account's credentials; absent for a
    /// discoverable login.
    #[serde(default)]
    pub user_name: Option<String>,
    /// The challenge of a password login that this passkey completes.
    #[serde(default)]
    pub challenge_id: Option<String>,
}

/// Options of a WebAuthn login.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebAuthnLoginOptions {
    /// Pass this to the finish step.
    pub ceremony_id: String,
    /// The options for `navigator.credentials.get()`.
    pub public_key: RequestOptions,
}

/// `POST /auth/webauthn/login/finish`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct WebAuthnLoginFinish {
    /// From the start step.
    pub ceremony_id: String,
    /// The browser's result.
    pub credential: AuthenticationResponse,
}

/// `POST /auth/webauthn/register/start`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct WebAuthnRegisterStart {
    /// A label for the credential, for example `YubiKey 5` or `Laptop`.
    #[serde(default)]
    pub label: Option<String>,
    /// Ask for a security key with `direct` attestation (needed for break-glass).
    #[serde(default)]
    pub security_key: bool,
}

/// Options of a WebAuthn registration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebAuthnRegisterOptions {
    /// Pass this to the finish step.
    pub ceremony_id: String,
    /// The options for `navigator.credentials.create()`.
    pub public_key: CreationOptions,
}

/// `POST /auth/webauthn/register/finish`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct WebAuthnRegisterFinish {
    /// From the start step.
    pub ceremony_id: String,
    /// The browser's result.
    pub credential: RegistrationResponse,
}

/// The account of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UserSummary {
    /// The user id.
    pub id: UserId,
    /// The login name.
    pub name: String,
    /// The display name.
    pub display_name: String,
    /// The fixed UI language, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Flags of a session that the UI acts on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SessionFlags {
    /// The password no longer meets the policy and must be changed.
    pub password_change_required: bool,
    /// The profile requires a stronger factor than this session used; enrol one.
    pub mfa_enrolment_required: bool,
    /// The break-glass account is in use.
    pub break_glass: bool,
}

/// `GET /auth/session` (IAM-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SessionInfo {
    /// The session id.
    pub session_id: SessionId,
    /// The account.
    pub user: UserSummary,
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// How strongly the session was authenticated.
    pub strength: AuthStrength,
    /// The strength the profile requires of this account.
    pub required_strength: AuthStrength,
    /// When the session started.
    pub created_at: Timestamp,
    /// When the session ends unless used (the earlier of the idle and absolute ends).
    pub expires_at: Timestamp,
    /// The absolute end.
    pub absolute_expires_at: Timestamp,
    /// Flags.
    pub flags: SessionFlags,
    /// The selected profile.
    pub profile: Profile,
    /// The warning banner (API-10).
    pub banner: Banner,
    /// The default UI language of the installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_language: Option<String>,
}

/// One session in `GET /auth/sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SessionSummary {
    /// The session id.
    pub id: SessionId,
    /// When it started.
    pub created_at: Timestamp,
    /// The last recorded activity.
    pub last_seen_at: Timestamp,
    /// When it ends unless used.
    pub expires_at: Timestamp,
    /// Its strength.
    pub strength: AuthStrength,
    /// The client address at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// The client's user agent at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Whether this is the session of the request.
    pub current: bool,
}

/// `POST /auth/password`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct PasswordChange {
    /// The current password; required when the account has one.
    #[serde(default)]
    pub current_password: Option<SecretString>,
    /// The new password.
    pub new_password: SecretString,
}

/// `POST /auth/password/check`: live policy feedback.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct PasswordCheck {
    /// The candidate password.
    pub password: SecretString,
    /// The user name it is meant for (context-specific words), when not the caller's own.
    #[serde(default)]
    pub user_name: Option<String>,
    /// The profile whose preset applies, during first-run setup.
    #[serde(default)]
    pub profile: Option<Profile>,
}

/// The result of the breached-password check (IAM-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreachStatus {
    /// Not found in the corpus.
    Clean,
    /// Found in the corpus.
    Breached,
    /// The check could not run; the password was accepted (TGL-06 fails open).
    Unavailable,
    /// TGL-06 is off.
    Off,
}

/// The answer of `POST /auth/password/check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PasswordCheckResult {
    /// Whether the password would be accepted.
    pub acceptable: bool,
    /// What is wrong with it.
    pub violations: Vec<PolicyViolation>,
    /// The breached-password check.
    pub breach_check: BreachStatus,
    /// The preset that applies.
    pub policy: PasswordPolicy,
}

/// The answer of a password change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PasswordChanged {
    /// The breached-password check.
    pub breach_check: BreachStatus,
    /// Other sessions of the account that were ended.
    pub sessions_revoked: usize,
}

/// The answer of `POST /auth/totp/enroll/start`. The secret is shown once.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TotpEnrolment {
    /// Pass this to the finish step.
    pub enrolment_id: String,
    /// The seed in base32, for manual entry.
    pub secret: SecretString,
    /// The `otpauth://` URI for a QR code.
    pub otpauth_uri: SecretString,
    /// The code parameters.
    pub params: TotpParams,
}

/// `POST /auth/totp/enroll/finish`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct TotpEnrolFinish {
    /// From the start step.
    pub enrolment_id: String,
    /// A current code from the authenticator app.
    pub code: SecretString,
}

/// The answer of a factor enrolment. Enrolling a factor does not raise the strength of the
/// session that enrolled it: when the session is below what the profile requires, the UI
/// logs in again with the new factor.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FactorEnrolled {
    /// New recovery codes, shown once, when the account had none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<SecretString>>,
    /// A credential registered by the ceremony.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialInfo>,
    /// Whether the session must log in again to reach the required strength.
    pub reauthenticate: bool,
}

/// A registered WebAuthn credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialInfo {
    /// The credential id, base64url.
    pub id: String,
    /// The label.
    pub label: String,
    /// The COSE algorithm.
    pub alg: i64,
    /// The authenticator model (AAGUID), hexadecimal.
    pub aaguid: String,
    /// When it was registered.
    pub created_at: Timestamp,
    /// The last use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
    /// A synced passkey.
    pub backup_eligible: bool,
    /// Backed up at the last use.
    pub backup_state: bool,
    /// Counts as a hardware security key.
    pub hardware_key: bool,
    /// What the attestation proved.
    pub attestation: AttestationKind,
}

/// New recovery codes, shown once.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecoveryCodes {
    /// The codes.
    pub codes: Vec<SecretString>,
}

/// `POST /auth/tokens`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct TokenCreate {
    /// A name for the token.
    pub name: String,
    /// Lifetime in days; defaults to the TGL-05 maximum (or no expiry where it allows).
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

/// A personal token without its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TokenInfo {
    /// The token id.
    pub id: ApiTokenId,
    /// The name.
    pub name: String,
    /// The first characters of the token.
    pub prefix: String,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The last use (recorded at most hourly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
}

/// A new token: the secret is shown once.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatedToken {
    /// The token, for `Authorization: Bearer`.
    pub token: SecretString,
    /// Its metadata.
    pub info: TokenInfo,
}

/// The factors of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FactorSummary {
    /// A password or PIN is set.
    pub password: bool,
    /// TOTP is enrolled.
    pub totp: bool,
    /// Registered passkeys and security keys.
    pub webauthn: usize,
    /// Of those, hardware security keys.
    pub hardware_keys: usize,
    /// Unused recovery codes.
    pub recovery_codes: usize,
}

/// A user as administrators see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UserInfo {
    /// The id.
    pub id: UserId,
    /// The login name.
    pub name: String,
    /// The display name.
    pub display_name: String,
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// Disabled accounts cannot log in.
    pub disabled: bool,
    /// The break-glass account.
    pub break_glass: bool,
    /// A lock in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<AccountLock>,
    /// The factors.
    pub factors: FactorSummary,
    /// The password must be changed.
    pub password_change_required: bool,
    /// The fixed UI language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// When the account was created.
    pub created_at: Timestamp,
    /// The last login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<Timestamp>,
    /// The revision for `If-Match`.
    pub revision: Revision,
}

/// `POST /users`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct UserCreate {
    /// The login name: 1 to 64 characters, no spaces or control characters.
    pub name: String,
    /// The display name; defaults to the login name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// An initial password; the user must change it at first login.
    #[serde(default)]
    pub password: Option<SecretString>,
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// A fixed UI language.
    #[serde(default)]
    pub language: Option<String>,
}

/// `PATCH /users/{id}`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct UserUpdate {
    /// A new display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Disable or enable the account.
    #[serde(default)]
    pub disabled: Option<bool>,
    /// A fixed UI language; an empty string removes it.
    #[serde(default)]
    pub language: Option<String>,
    /// A new password set by an administrator; the user must change it at next login.
    #[serde(default)]
    pub password: Option<SecretString>,
}

/// `PUT /users/{id}/roles`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct RolesUpdate {
    /// The new roles.
    pub roles: Vec<RoleName>,
}

/// A role in `GET /roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleInfo {
    /// The role.
    pub name: RoleName,
    /// What it grants.
    pub description: String,
}

/// `PUT /system/break-glass` (IAM-09).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct BreakGlassChange {
    /// The account.
    pub user_id: UserId,
    /// Make it the break-glass account, or a normal account again.
    pub enabled: bool,
}

/// `GET /settings/security`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecuritySettingsView {
    /// The settings.
    pub settings: SecuritySettings,
    /// Each toggle with its profile default and markers.
    pub toggles: Vec<ToggleState>,
    /// The warning banner.
    pub banner: Banner,
    /// Whether the vault holds operator secrets (the PIN coupling rule applies).
    pub vault_has_operator_secrets: bool,
    /// The revision for `If-Match`; absent before setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

/// A profile offered by the first-run wizard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProfileInfo {
    /// The profile.
    pub profile: Profile,
    /// Its toggle values.
    pub settings: SecuritySettings,
    /// Its banner state.
    pub banner: Banner,
}

/// `GET /setup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetupState {
    /// Whether setup is still open.
    pub open: bool,
    /// The profiles to choose from (while open).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<ProfileInfo>,
}

/// The first administrator in `POST /setup`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SetupAdmin {
    /// The login name.
    pub name: String,
    /// The display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The password or PIN, checked against the chosen profile's preset.
    pub password: SecretString,
}

/// `POST /setup` (API-10).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SetupRequest {
    /// The one-time token from the console or log.
    pub setup_token: SecretString,
    /// The security profile.
    pub profile: Profile,
    /// The first administrator.
    pub admin: SetupAdmin,
    /// The host name: TLS subject and WebAuthn RP ID; not an IP address (Q5).
    pub host_name: String,
    /// The default UI language: `en` or `sv`.
    #[serde(default = "default_language")]
    pub language: String,
}

fn default_language() -> String {
    "en".to_owned()
}
