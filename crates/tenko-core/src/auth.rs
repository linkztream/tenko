//! Authentication contract between the API layer and the authentication service.
//!
//! The API layer (`tenko-api`) parses the credentials of a request and asks an
//! [`Authenticator`] to resolve them into a [`Principal`]. The authentication service
//! (`tenko-auth`) implements the trait; the server binary wires it into the API state. The
//! trait lives here so that the API layer never depends on the concrete service, and so that
//! tests can supply a fake authenticator.
//!
//! Public endpoints (first-run setup, the login ceremonies) do not go through this contract:
//! they take no authenticated context and parse what they need themselves.

use std::{collections::BTreeSet, fmt, future::Future, net::IpAddr, pin::Pin, sync::Arc};

use crate::{AuthStrength, Coded, Principal, Timestamp, UserId};

/// Name of the session cookie set by the API.
pub const SESSION_COOKIE: &str = "tenko_session";

/// Credentials presented with a request, as parsed from its headers.
///
/// The variants carry secrets, so the [`fmt::Debug`] output redacts them.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// No credentials were presented.
    None,
    /// The value of the [`SESSION_COOKIE`] cookie.
    Session(String),
    /// The token of an `Authorization: Bearer` header.
    Bearer(String),
    /// The token of an `Authorization: Bearer` header on a connection of the integration
    /// listener, whose client certificate belongs to the certificate lineage `lineage`
    /// (ADR 0035): a token bound to that lineage is accepted only so.
    CertifiedBearer {
        /// The token.
        token: String,
        /// The lineage of the connection's certificate.
        lineage: uuid::Uuid,
    },
}

impl Credentials {
    /// Picks the credentials from the `Cookie` session value and the `Authorization` header.
    ///
    /// A bearer token takes precedence over a session cookie, so that an automation client
    /// that happens to carry a browser cookie is still authenticated as its token. An
    /// `Authorization` header with another scheme is ignored.
    #[must_use]
    pub fn from_headers(session_cookie: Option<&str>, authorization: Option<&str>) -> Self {
        if let Some(token) = authorization
            .and_then(|value| value.trim_start().split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
        {
            return Self::Bearer(token.to_owned());
        }
        match session_cookie
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => Self::Session(value.to_owned()),
            None => Self::None,
        }
    }

    /// Whether any credentials were presented.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Session(_) => f.write_str("Session(<redacted>)"),
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::CertifiedBearer { lineage, .. } => {
                write!(f, "CertifiedBearer(<redacted>, lineage {lineage})")
            }
        }
    }
}

/// Facts about an authenticated request that handlers may need beyond the principal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthFlags {
    /// The user must change the password before doing anything else.
    pub password_change_required: bool,
    /// The profile requires a second factor that the user has not enrolled yet.
    pub mfa_enrollment_required: bool,
    /// The request is authenticated through the break-glass account.
    pub break_glass: bool,
    /// The request is authenticated with the token of this mirrored source, which reaches
    /// that mirror's push and nothing else (ADR 0033 decision 3).
    pub mirror: Option<crate::MirrorId>,
    /// The request is authenticated with a delegated session (ADR 0038), which reaches only
    /// the routes of its allow-list (`tenko_auth::delegation`).
    pub delegation: Option<Delegated>,
}

/// What a delegated session carries beyond an ordinary one (ADR 0038): the run it acts for,
/// the approval it came from and when the person approved it, on the approving controller's
/// clock. Stored on the session record and copied into [`AuthFlags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Delegated {
    /// The run.
    pub id: crate::DelegationId,
    /// The approval.
    pub approval: crate::ApprovalId,
    /// When the person approved.
    pub approved_at: Timestamp,
}

/// The outcome of a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The principal every domain call runs as.
    pub principal: Principal,
    /// The user behind the principal, when there is one (tokens carry their owner).
    pub user: Option<UserId>,
    /// Role names granted to the principal, as the authorization service defines them.
    pub roles: BTreeSet<String>,
    /// How strongly the principal authenticated.
    pub strength: AuthStrength,
    /// When the session or token expires, when it does.
    pub expires_at: Option<Timestamp>,
    /// Further facts for handlers and the UI.
    pub flags: AuthFlags,
}

/// Why a request could not be authenticated.
///
/// `Invalid` and `Locked` share the `auth.unauthenticated` code on purpose: the API never
/// tells an unauthenticated caller whether an account exists or is locked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthFailure {
    /// No credentials were presented.
    #[error("the request carries no credentials")]
    Missing,
    /// The credentials are unknown or wrong.
    #[error("the credentials were not accepted")]
    Invalid,
    /// The session or token has expired.
    #[error("the session or token has expired")]
    Expired,
    /// The account is locked out.
    #[error("the credentials were not accepted")]
    Locked,
    /// The authentication service cannot answer right now.
    #[error("authentication is not available")]
    Unavailable,
    /// A delegated session while the clock guard holds issuing on this controller.
    #[error("this controller's clock is held: an administrator confirms the clock first")]
    ClockHeld,
}

impl Coded for AuthFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Missing | Self::Invalid | Self::Locked => "auth.unauthenticated",
            Self::Expired => "auth.session_expired",
            Self::Unavailable => "auth.unavailable",
            Self::ClockHeld => "auth.approval.clock_held",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Missing | Self::Invalid | Self::Locked | Self::Expired => 401,
            Self::Unavailable | Self::ClockHeld => 503,
        }
    }
}

/// The future returned by [`Authenticator::authenticate`].
pub type AuthFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Authenticated, AuthFailure>> + Send + 'a>>;

/// Resolves presented credentials into an authenticated principal.
pub trait Authenticator: Send + Sync {
    /// Authenticates one request.
    ///
    /// `source_ip` is the client address as the API layer determined it (after the trusted
    /// proxy rules) and `now` the request time, so that expiry and lockout decisions are
    /// deterministic in tests.
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) -> AuthFuture<'a>;
}

impl<T: Authenticator + ?Sized> Authenticator for Arc<T> {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) -> AuthFuture<'a> {
        (**self).authenticate(credentials, source_ip, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_takes_precedence_over_the_cookie() {
        let credentials = Credentials::from_headers(Some("s3ss10n"), Some("Bearer t0k3n"));
        assert_eq!(credentials, Credentials::Bearer("t0k3n".to_owned()));
    }

    #[test]
    fn other_schemes_are_ignored() {
        let credentials = Credentials::from_headers(Some("s3ss10n"), Some("Basic abc"));
        assert_eq!(credentials, Credentials::Session("s3ss10n".to_owned()));
        assert_eq!(
            Credentials::from_headers(None, Some("Basic abc")),
            Credentials::None
        );
    }

    #[test]
    fn empty_values_count_as_absent() {
        assert_eq!(
            Credentials::from_headers(Some("  "), Some("Bearer ")),
            Credentials::None
        );
        assert!(!Credentials::None.is_present());
        assert!(Credentials::Session("x".to_owned()).is_present());
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let text = format!("{:?}", Credentials::Bearer("t0k3n".to_owned()));
        assert!(!text.contains("t0k3n"));
        assert_eq!(text, "Bearer(<redacted>)");
    }

    #[test]
    fn failures_map_to_stable_codes() {
        assert_eq!(AuthFailure::Missing.code(), "auth.unauthenticated");
        assert_eq!(AuthFailure::Locked.code(), "auth.unauthenticated");
        assert_eq!(AuthFailure::Expired.code(), "auth.session_expired");
        assert_eq!(AuthFailure::Expired.http_status(), 401);
        assert_eq!(AuthFailure::Unavailable.http_status(), 503);
        assert_eq!(AuthFailure::ClockHeld.code(), "auth.approval.clock_held");
        assert_eq!(AuthFailure::ClockHeld.http_status(), 503);
    }
}
