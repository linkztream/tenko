//! Errors of the authentication service and their stable codes (API-08).
//!
//! Codes live in the namespaces this package owns: `auth.*` (login, sessions, factors,
//! tokens, setup, grants, service accounts, scopes), `users.*` (user administration) and
//! `settings.*` (security settings). Login failures never tell an unauthenticated caller
//! whether an account exists.
//!
//! Codes of scoped authorization (WP3.2, `docs/access.md`): `auth.out_of_scope` (403, an
//! object outside the principal's grants), `auth.password_change_required` (403, every
//! route but the password change, sign-out and the session answers it while the account
//! must change its password), `auth.grant.not_found` (404), `auth.grant.invalid_scope`
//! (422), `auth.grant.invalid_role` (422), `auth.grant.exceeds_own` (403),
//! `auth.grant.duplicate` (409), `auth.service_account.not_found` (404),
//! `auth.service_account.no_login` (409) and `auth.scope.unavailable` (503).
//!
//! Codes of the personal preferences (`crate::preferences`): `auth.preference.not_found`
//! (404), `auth.preference.too_large` (413, a document over 16 KiB) and
//! `auth.preference.limit` (409, a new key beyond the 64 of a person).

use std::{borrow::Cow, collections::BTreeMap};

use tenko_core::{AuthFailure, Coded, Denied, FieldError};
use tenko_store::StoreError;

use crate::{password::PolicyViolation, webauthn::WebAuthnError};

/// An error of the authentication service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The request carries no valid session or token.
    #[error("authentication required")]
    Unauthenticated,
    /// The session or token has expired.
    #[error("the session has expired")]
    SessionExpired,
    /// The user name, password, code or credential was not accepted.
    #[error("the credentials were not accepted")]
    InvalidCredentials,
    /// Too many failed attempts: retry later (IAM-05). Also used while an account is
    /// locked, so a caller cannot tell a locked account from an unknown one.
    #[error("too many failed attempts; retry later")]
    Throttled {
        /// Seconds until the next attempt is allowed; `None` until an administrator
        /// unlocks the account.
        retry_after: Option<u64>,
    },
    /// The login or enrolment challenge is unknown or has expired.
    #[error("the challenge is unknown or has expired")]
    ChallengeInvalid,
    /// The action needs a stronger or fresher authentication.
    #[error("the action needs a fresh authentication with a stronger factor")]
    StepUpRequired {
        /// The minimum strength, as its `snake_case` name.
        required: &'static str,
    },
    /// Authorization refused the action.
    #[error(transparent)]
    Denied(#[from] Denied),
    /// The password breaks the policy (IAM-03, IAM-04).
    #[error("the password does not meet the policy")]
    PasswordPolicy(Vec<PolicyViolation>),
    /// The current password given for a change is wrong.
    #[error("the current password is not correct")]
    PasswordIncorrect,
    /// The breached-password check could not run and the policy fails closed.
    #[error("the breached-password check is not available")]
    BreachCheckUnavailable,
    /// A WebAuthn ceremony failed.
    #[error(transparent)]
    WebAuthn(#[from] WebAuthnError),
    /// The break-glass account logs in with a hardware security key only (IAM-09).
    #[error("the break-glass account logs in with a hardware security key only")]
    BreakGlassHardwareKeyOnly,
    /// TOTP is already enrolled for the account.
    #[error("TOTP is already enrolled")]
    TotpAlreadyEnrolled,
    /// The account has no TOTP enrolled.
    #[error("TOTP is not enrolled")]
    TotpNotEnrolled,
    /// The TOTP code of an enrolment does not match the new secret.
    #[error("the TOTP code does not match")]
    TotpCodeMismatch,
    /// The requested token lifetime exceeds the maximum of the profile (TGL-05).
    #[error("the token lifetime exceeds the maximum of {max_days} days")]
    TokenLifetime {
        /// The maximum lifetime in days.
        max_days: u64,
    },
    /// An object does not exist (or is not visible to the caller).
    #[error("{kind} not found")]
    NotFound {
        /// What was looked up: `user`, `session`, `token` or `credential`.
        kind: &'static str,
    },
    /// A user with the name exists already.
    #[error("the user name is taken")]
    UserNameTaken,
    /// The change would leave no active administrator.
    #[error("the change would leave no active administrator")]
    LastAdministrator,
    /// The factor is the last one that satisfies the profile; enrol another first.
    #[error("the profile requires this factor; enrol another one first")]
    LastFactor,
    /// The object changed since it was read (`If-Match` or a concurrent writer).
    #[error("the object was changed concurrently; reload and retry")]
    Conflict,
    /// First-run setup has completed; `/setup` is closed (API-10).
    #[error("setup has already been completed")]
    SetupClosed,
    /// The one-time setup token is wrong.
    #[error("the setup token is not valid")]
    SetupTokenInvalid,
    /// The host name cannot serve as a WebAuthn relying-party ID (Q5, R10).
    #[error("the host name `{0}` is not valid for passkeys")]
    InvalidHostName(String),
    /// A request value is invalid.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// The field.
        field: &'static str,
        /// What is wrong.
        reason: Cow<'static, str>,
    },
    /// A setting change would break the PIN coupling rule (IAM-07, CON-07).
    #[error("a PIN may be the only factor only while the vault holds no operator secrets")]
    PinCoupling,
    /// A setting change would start to require the audit export while no sink is enabled
    /// (TGL-21).
    #[error("the profile requires an audit export sink; enable one first")]
    AuditExportRequired,
    /// The account must change its password before it does anything else.
    #[error("the password must be changed first")]
    PasswordChangeRequired,
    /// A grant names a rule that cannot be granted or an object that does not exist.
    #[error("invalid grant scope: {0}")]
    GrantInvalidScope(Cow<'static, str>),
    /// A grant names a role that is global only.
    #[error("the role `{role}` cannot be granted over a scope")]
    GrantInvalidRole {
        /// The role.
        role: &'static str,
    },
    /// A delegated grant or a token grant goes beyond the caller's own grants.
    #[error("the grant goes beyond the grants of its issuer")]
    GrantExceedsOwn,
    /// The subject already holds the same role over the same scope.
    #[error("the subject already holds this grant")]
    GrantDuplicate,
    /// A service account has no password, passkey, second factor or session.
    #[error("a service account cannot sign in")]
    ServiceAccountNoLogin,
    /// Scope checks need the anchors of IPAM, which this server does not provide.
    #[error("scoped authorization is not available")]
    ScopeUnavailable,
    /// A preference document exceeds its size limit.
    #[error("the preference exceeds {max_bytes} bytes")]
    PreferenceTooLarge {
        /// The limit in bytes.
        max_bytes: usize,
    },
    /// A new preference key would exceed the number of keys a person may store.
    #[error("a person stores at most {max_keys} preferences")]
    PreferenceLimit {
        /// The limit.
        max_keys: usize,
    },
    /// The service is not configured (no relying party, no host name yet).
    #[error("authentication is not available: {0}")]
    Unavailable(&'static str),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An unexpected internal failure. Never carries secrets.
    #[error("internal authentication error: {0}")]
    Internal(Cow<'static, str>),
}

impl AuthError {
    /// An internal error.
    pub fn internal(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::Internal(detail.into())
    }

    /// An invalid request value.
    pub fn invalid(field: &'static str, reason: impl Into<Cow<'static, str>>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }

    /// The failure an [`Authenticator`](tenko_core::Authenticator) reports for this error.
    pub fn to_failure(&self) -> AuthFailure {
        match self {
            Self::SessionExpired => AuthFailure::Expired,
            Self::Throttled { .. } => AuthFailure::Locked,
            Self::Unavailable(_) | Self::Store(_) | Self::Internal(_) => AuthFailure::Unavailable,
            _ => AuthFailure::Invalid,
        }
    }
}

impl From<tenko_core::codec::CodecError> for AuthError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::Store(StoreError::from(error))
    }
}

impl Coded for AuthError {
    fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "auth.unauthenticated",
            Self::SessionExpired => "auth.session_expired",
            Self::InvalidCredentials => "auth.invalid_credentials",
            Self::Throttled { .. } => "auth.throttled",
            Self::ChallengeInvalid => "auth.challenge_invalid",
            Self::StepUpRequired { .. } => "auth.step_up_required",
            Self::Denied(denied) => denied.code(),
            Self::PasswordPolicy(_) => "auth.password.policy",
            Self::PasswordIncorrect => "auth.password.incorrect",
            Self::BreachCheckUnavailable => "auth.password.breach_check_unavailable",
            Self::WebAuthn(error) => error.code(),
            Self::BreakGlassHardwareKeyOnly => "auth.break_glass.hardware_key_only",
            Self::TotpAlreadyEnrolled => "auth.totp.already_enrolled",
            Self::TotpNotEnrolled => "auth.totp.not_enrolled",
            Self::TotpCodeMismatch => "auth.totp.code_mismatch",
            Self::TokenLifetime { .. } => "auth.token.lifetime_exceeded",
            Self::NotFound { kind } => match *kind {
                "user" => "users.not_found",
                "session" => "auth.session.not_found",
                "token" => "auth.token.not_found",
                "credential" => "auth.webauthn.credential_not_found",
                "grant" => "auth.grant.not_found",
                "service_account" => "auth.service_account.not_found",
                "preference" => "auth.preference.not_found",
                _ => "auth.not_found",
            },
            Self::UserNameTaken => "users.name_taken",
            Self::LastAdministrator => "users.last_administrator",
            Self::LastFactor => "auth.factor.last_required",
            Self::Conflict => "auth.conflict",
            Self::SetupClosed => "auth.setup.closed",
            Self::SetupTokenInvalid => "auth.setup.token_invalid",
            Self::InvalidHostName(_) => "auth.setup.invalid_host_name",
            Self::Invalid { .. } => "auth.invalid_request",
            Self::PinCoupling => "settings.pin_coupling",
            Self::AuditExportRequired => "audit.export.required",
            Self::PasswordChangeRequired => "auth.password_change_required",
            Self::GrantInvalidScope(_) => "auth.grant.invalid_scope",
            Self::GrantInvalidRole { .. } => "auth.grant.invalid_role",
            Self::GrantExceedsOwn => "auth.grant.exceeds_own",
            Self::GrantDuplicate => "auth.grant.duplicate",
            Self::ServiceAccountNoLogin => "auth.service_account.no_login",
            Self::ScopeUnavailable => "auth.scope.unavailable",
            Self::PreferenceTooLarge { .. } => "auth.preference.too_large",
            Self::PreferenceLimit { .. } => "auth.preference.limit",
            Self::Unavailable(_) => "auth.unavailable",
            Self::Store(error) => error.code(),
            Self::Internal(_) => "auth.internal",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Unauthenticated
            | Self::SessionExpired
            | Self::InvalidCredentials
            | Self::SetupTokenInvalid => 401,
            Self::Throttled { .. } => 429,
            Self::ChallengeInvalid | Self::Invalid { .. } | Self::InvalidHostName(_) => 400,
            Self::StepUpRequired { .. }
            | Self::PasswordIncorrect
            | Self::BreakGlassHardwareKeyOnly
            | Self::PasswordChangeRequired
            | Self::GrantExceedsOwn => 403,
            Self::Denied(denied) => denied.http_status(),
            Self::PasswordPolicy(_)
            | Self::TotpCodeMismatch
            | Self::TokenLifetime { .. }
            | Self::GrantInvalidScope(_)
            | Self::GrantInvalidRole { .. } => 422,
            Self::WebAuthn(error) => error.http_status(),
            Self::NotFound { .. } => 404,
            Self::TotpAlreadyEnrolled
            | Self::TotpNotEnrolled
            | Self::UserNameTaken
            | Self::LastAdministrator
            | Self::LastFactor
            | Self::Conflict
            | Self::SetupClosed
            | Self::PinCoupling
            | Self::AuditExportRequired
            | Self::GrantDuplicate
            | Self::ServiceAccountNoLogin
            | Self::PreferenceLimit { .. } => 409,
            Self::PreferenceTooLarge { .. } => 413,
            Self::BreachCheckUnavailable | Self::Unavailable(_) | Self::ScopeUnavailable => 503,
            Self::Store(error) => error.http_status(),
            Self::Internal(_) => 500,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::Throttled { retry_after } => retry_after.map_or_else(
                || BTreeMap::from([("until", "unlock".to_owned())]),
                |seconds| BTreeMap::from([("retry_after", seconds.to_string())]),
            ),
            Self::StepUpRequired { required } => {
                BTreeMap::from([("required", (*required).to_owned())])
            }
            Self::Denied(denied) => denied.params(),
            Self::WebAuthn(error) => error.params(),
            Self::TokenLifetime { max_days } => {
                BTreeMap::from([("max_days", max_days.to_string())])
            }
            Self::NotFound { kind } => BTreeMap::from([("kind", (*kind).to_owned())]),
            Self::InvalidHostName(name) => BTreeMap::from([("host_name", name.clone())]),
            Self::GrantInvalidScope(reason) => {
                BTreeMap::from([("reason", reason.clone().into_owned())])
            }
            Self::GrantInvalidRole { role } => BTreeMap::from([("role", (*role).to_owned())]),
            Self::PreferenceTooLarge { max_bytes } => {
                BTreeMap::from([("max_bytes", max_bytes.to_string())])
            }
            Self::PreferenceLimit { max_keys } => {
                BTreeMap::from([("max_keys", max_keys.to_string())])
            }
            Self::Invalid { field, reason } => BTreeMap::from([
                ("field", (*field).to_owned()),
                ("reason", reason.clone().into_owned()),
            ]),
            Self::Store(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Login failed",
            Self::Throttled { .. } => "Too many attempts",
            Self::PasswordPolicy(_) => "Password does not meet the policy",
            Self::StepUpRequired { .. } => "Fresh authentication required",
            Self::SetupClosed => "Setup is closed",
            Self::PinCoupling => "PIN coupling rule",
            Self::AuditExportRequired => "Audit export required",
            Self::PasswordChangeRequired => "Password change required",
            _ => tenko_core::error::status_title(self.http_status()),
        }
    }

    fn field_errors(&self) -> Vec<FieldError> {
        match self {
            Self::PasswordPolicy(violations) => violations
                .iter()
                .map(|violation| {
                    let mut error = FieldError::new("password", violation.code());
                    error.params = violation
                        .params()
                        .into_iter()
                        .map(|(key, value)| (key.to_owned(), value))
                        .collect();
                    error
                })
                .collect(),
            Self::Invalid { field, .. } => vec![FieldError::new(*field, "auth.invalid_request")],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_failures_share_codes_that_do_not_reveal_accounts() {
        assert_eq!(
            AuthError::InvalidCredentials.code(),
            "auth.invalid_credentials"
        );
        assert_eq!(AuthError::InvalidCredentials.http_status(), 401);
        let throttled = AuthError::Throttled {
            retry_after: Some(30),
        };
        assert_eq!(throttled.code(), "auth.throttled");
        assert_eq!(throttled.http_status(), 429);
        assert_eq!(throttled.params()["retry_after"], "30");
        let locked = AuthError::Throttled { retry_after: None };
        assert_eq!(locked.params()["until"], "unlock");
    }

    #[test]
    fn codes_stay_in_the_namespaces_of_this_package() {
        for error in [
            AuthError::UserNameTaken,
            AuthError::LastAdministrator,
            AuthError::PinCoupling,
            AuthError::SetupClosed,
            AuthError::NotFound { kind: "user" },
            AuthError::NotFound { kind: "token" },
            AuthError::TokenLifetime { max_days: 90 },
            AuthError::internal("x"),
            AuthError::PasswordChangeRequired,
            AuthError::GrantInvalidScope("x".into()),
            AuthError::GrantInvalidRole { role: "admin" },
            AuthError::GrantExceedsOwn,
            AuthError::GrantDuplicate,
            AuthError::NotFound { kind: "grant" },
            AuthError::NotFound {
                kind: "service_account",
            },
            AuthError::ServiceAccountNoLogin,
            AuthError::ScopeUnavailable,
            AuthError::NotFound { kind: "preference" },
            AuthError::PreferenceTooLarge { max_bytes: 16_384 },
            AuthError::PreferenceLimit { max_keys: 64 },
        ] {
            let code = error.code();
            assert!(
                code.starts_with("auth.")
                    || code.starts_with("users.")
                    || code.starts_with("settings."),
                "{code}"
            );
        }
    }

    #[test]
    fn failures_map_for_the_authenticator() {
        assert_eq!(AuthError::SessionExpired.to_failure(), AuthFailure::Expired);
        assert_eq!(
            AuthError::InvalidCredentials.to_failure(),
            AuthFailure::Invalid
        );
        assert_eq!(
            AuthError::internal("x").to_failure(),
            AuthFailure::Unavailable
        );
    }
}
