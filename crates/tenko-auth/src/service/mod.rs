//! The authentication service: login ceremonies, sessions, factors, personal tokens, user
//! administration, security settings and first-run setup, over the replicated store and
//! the vault.
//!
//! # Sessions (IAM-08)
//!
//! A login creates a 256-bit random secret, sent once in the `tenko_session` cookie
//! (`HttpOnly; SameSite=Strict; Secure`, `Path=/`) and stored only as its SHA-256 under
//! `auth.sessions`. The lifetimes of TGL-04 apply twice: when the session is created and
//! again on every use with the current settings, so tightening TGL-04 takes effect at once.
//! Activity moves the idle end forward with a write at most every [`refresh_interval`]
//! (a quarter of the idle lifetime, between 30 seconds and 5 minutes), so a busy UI does
//! not turn every request into a Raft entry. Logout, revocation by the user or an
//! administrator, password changes and account changes delete the session rows.
//!
//! # Write discipline
//!
//! Every change is one [`WriteBatch`] with its audit drafts (ADR 0011). Failed logins are
//! throttled in memory first ([`crate::lockout`]) and only then written as audit records,
//! so a flood of attempts cannot flood the log.

mod access;
mod account;
mod admin;
mod login;
pub mod reveal;
mod setup;
pub mod types;

pub use reveal::{RevealGrant, STEP_UP_FRESH, STEP_UP_PASSKEY, check_step_up};

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures::StreamExt;

use arc_swap::ArcSwapOption;
use tenko_core::{
    AuthFailure, AuthFlags, AuthStrength, Authenticated, Authenticator, Authorizer, Credentials,
    ObjectRef, Principal, RequestCtx, SessionId, SystemComponent, Timestamp, UserId,
    audit::{AuditAction, AuditDraft},
    auth::{AuthFuture, SESSION_COOKIE},
};
use tenko_store::{
    AnchorResolver, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WatchFilter, WriteBatch,
};
use tenko_vault::Vault;

use crate::{
    authz::{AuthIndex, RbacAuthorizer, ScopeSupport},
    challenge::Ceremonies,
    error::AuthError,
    hibp::{BreachChecker, HibpFilter, HibpRangeSource},
    lockout::{Throttle, ThrottleKey},
    model::{
        CREDENTIALS, CredentialRecord, INSTALLATION, Installation, LAST_LOGINS, SCOPED_TOKENS,
        SESSIONS, SETTINGS, ScopedTokenRecord, SessionRecord, TOKENS, TokenRecord, USER_SESSIONS,
        USERS, UserRecord,
    },
    roles::RoleName,
    secret::{BearerSecret, SetupTokenVerifier, hash_secret, looks_like_session_secret},
    settings::SecuritySettings,
    webauthn::{RelyingParty, RpConfig},
};

pub use types::*;

/// Audit actions of this package.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// First-run setup completed.
    pub const SETUP_COMPLETE: AuditAction = AuditAction::from_static("auth.setup.complete");
    /// A password login step.
    pub const LOGIN_PASSWORD: AuditAction = AuditAction::from_static("auth.login.password");
    /// A TOTP login step.
    pub const LOGIN_TOTP: AuditAction = AuditAction::from_static("auth.login.totp");
    /// A recovery-code login step.
    pub const LOGIN_RECOVERY: AuditAction = AuditAction::from_static("auth.login.recovery");
    /// A WebAuthn login.
    pub const LOGIN_WEBAUTHN: AuditAction = AuditAction::from_static("auth.login.webauthn");
    /// A break-glass login (IAM-09).
    pub const LOGIN_BREAK_GLASS: AuditAction = AuditAction::from_static("auth.login.break_glass");
    /// A logout.
    pub const LOGOUT: AuditAction = AuditAction::from_static("auth.logout");
    /// A session ended by its user or an administrator.
    pub const SESSION_REVOKE: AuditAction = AuditAction::from_static("auth.session.revoke");
    /// A password change.
    pub const PASSWORD_CHANGE: AuditAction = AuditAction::from_static("auth.password.change");
    /// TOTP enrolled.
    pub const TOTP_ENROL: AuditAction = AuditAction::from_static("auth.totp.enrol");
    /// TOTP removed.
    pub const TOTP_REMOVE: AuditAction = AuditAction::from_static("auth.totp.remove");
    /// A WebAuthn credential registered.
    pub const WEBAUTHN_REGISTER: AuditAction = AuditAction::from_static("auth.webauthn.register");
    /// A WebAuthn credential removed.
    pub const WEBAUTHN_REMOVE: AuditAction = AuditAction::from_static("auth.webauthn.remove");
    /// Recovery codes regenerated.
    pub const RECOVERY_REGENERATE: AuditAction =
        AuditAction::from_static("auth.recovery.regenerate");
    /// A personal token created.
    pub const TOKEN_CREATE: AuditAction = AuditAction::from_static("auth.token.create");
    /// A personal token revoked.
    pub const TOKEN_REVOKE: AuditAction = AuditAction::from_static("auth.token.revoke");
    /// A user created.
    pub const USER_CREATE: AuditAction = AuditAction::from_static("auth.user.create");
    /// A user changed.
    pub const USER_UPDATE: AuditAction = AuditAction::from_static("auth.user.update");
    /// A user deleted.
    pub const USER_DELETE: AuditAction = AuditAction::from_static("auth.user.delete");
    /// A user locked by the lockout policy.
    pub const USER_LOCK: AuditAction = AuditAction::from_static("auth.user.lock");
    /// A user unlocked by an administrator.
    pub const USER_UNLOCK: AuditAction = AuditAction::from_static("auth.user.unlock");
    /// A user's roles changed.
    pub const USER_ROLES: AuditAction = AuditAction::from_static("auth.user.roles");
    /// The break-glass designation changed.
    pub const BREAK_GLASS_SET: AuditAction = AuditAction::from_static("auth.break_glass.set");
    /// The security settings changed.
    pub const SETTINGS_UPDATE: AuditAction = AuditAction::from_static("auth.settings.update");
    /// Authorization refused an administrative action.
    pub const ACCESS_DENIED: AuditAction = AuditAction::from_static("auth.access.denied");
    /// A scoped grant created (IAM-01).
    pub const GRANT_CREATE: AuditAction = AuditAction::from_static("auth.grant.create");
    /// A scoped grant revoked, with the grants issued under it.
    pub const GRANT_REVOKE: AuditAction = AuditAction::from_static("auth.grant.revoke");
    /// A service account created (IAM-10).
    pub const SERVICE_ACCOUNT_CREATE: AuditAction =
        AuditAction::from_static("auth.service_account.create");
    /// The default UI language of the installation changed (API-21).
    pub const INSTALLATION_LANGUAGE: AuditAction =
        AuditAction::from_static("auth.installation.language");
    /// The MFA policy of a role set or cleared (IAM-06).
    pub const ROLE_POLICY_UPDATE: AuditAction = AuditAction::from_static("auth.role_policy.update");
}

/// Configuration of the service, set by the server at start.
#[derive(Clone)]
pub struct AuthConfig {
    /// The WebAuthn RP ID; defaults to the installation's host name (`localhost` in
    /// development).
    pub rp_id: Option<String>,
    /// The origins the UI is served from; defaults to `https://<rp id>`.
    pub origins: Vec<String>,
    /// The name browsers show for the relying party.
    pub rp_name: String,
    /// DER attestation roots for hardware keys (ADR 0010).
    pub attestation_roots: Vec<Vec<u8>>,
    /// The `Secure` cookie attribute; off only for plain HTTP under TGL-08 (Lab) and
    /// `localhost` development.
    pub cookie_secure: bool,
    /// The online HIBP range source (feature `online` provides one).
    pub hibp_online: Option<Arc<dyn HibpRangeSource>>,
    /// The offline breach filter built by `tenko hibp build`.
    pub hibp_offline: Option<Arc<HibpFilter>>,
    /// Keys tracked by the in-memory throttle.
    pub throttle_capacity: usize,
    /// Open ceremonies kept in memory.
    pub ceremony_capacity: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            rp_id: None,
            origins: Vec::new(),
            rp_name: "Tenko DDI".to_owned(),
            attestation_roots: Vec::new(),
            cookie_secure: true,
            hibp_online: None,
            hibp_offline: None,
            throttle_capacity: 100_000,
            ceremony_capacity: 10_000,
        }
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("rp_id", &self.rp_id)
            .field("origins", &self.origins)
            .field("cookie_secure", &self.cookie_secure)
            .field("attestation_roots", &self.attestation_roots.len())
            .field("hibp_online", &self.hibp_online.is_some())
            .field("hibp_offline", &self.hibp_offline.is_some())
            .finish_non_exhaustive()
    }
}

/// The authentication service. Cheap to share as `Arc<AuthService>`.
pub struct AuthService {
    store: Arc<dyn Store>,
    vault: Arc<dyn Vault>,
    config: AuthConfig,
    index: Arc<AuthIndex>,
    scope: Arc<ScopeSupport>,
    throttle: Arc<Throttle>,
    ceremonies: Ceremonies,
    setup_token: Mutex<Option<SetupTokenVerifier>>,
    relying_party: ArcSwapOption<RelyingParty>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A new session: the secret for the cookie, its description and the `Set-Cookie` value.
#[derive(Debug, Clone)]
pub struct NewSession {
    /// The secret. Goes into the cookie only.
    pub secret: BearerSecret,
    /// The session as `GET /auth/session` describes it.
    pub info: SessionInfo,
    /// The `Set-Cookie` header value.
    pub set_cookie: String,
}

/// What a login step produced.
#[allow(clippy::large_enum_variant)] // Built once per login, never stored.
#[derive(Debug, Clone)]
pub enum LoginOutcome {
    /// A session was created.
    Session(NewSession),
    /// A second factor is required.
    SecondFactor {
        /// The challenge id.
        challenge_id: String,
        /// The methods available.
        methods: Vec<SecondFactorMethod>,
    },
}

impl LoginOutcome {
    /// The JSON answer and, for a session, the `Set-Cookie` value.
    pub fn into_response(self) -> (LoginResponse, Option<String>) {
        match self {
            Self::Session(session) => (
                LoginResponse::Authenticated {
                    session: session.info,
                },
                Some(session.set_cookie),
            ),
            Self::SecondFactor {
                challenge_id,
                methods,
            } => (
                LoginResponse::SecondFactor {
                    challenge_id,
                    methods,
                    expires_in: crate::challenge::CEREMONY_TTL.as_secs(),
                },
                None,
            ),
        }
    }
}

/// Lifetime of a break-glass session regardless of TGL-04.
const BREAK_GLASS_SESSION: Duration = Duration::from_secs(3_600);
/// Idle lifetime of a break-glass session.
const BREAK_GLASS_IDLE: Duration = Duration::from_secs(900);
/// How recent the last full authentication must be for sensitive changes.
pub const FRESH_AUTHENTICATION: Duration = Duration::from_secs(300);
/// Largest number of rows read for a listing.
const LIST_LIMIT: usize = 10_000;

/// How often activity is written for a session with the idle lifetime `idle`.
pub fn refresh_interval(idle: Duration) -> Duration {
    (idle / 4).clamp(Duration::from_secs(30), Duration::from_secs(300))
}

impl AuthService {
    /// Creates the service and registers its authorization index with the store.
    ///
    /// # Errors
    ///
    /// The store's error if the index cannot be built, or a WebAuthn configuration error.
    pub async fn new(
        store: Arc<dyn Store>,
        vault: Arc<dyn Vault>,
        config: AuthConfig,
    ) -> Result<Arc<Self>, AuthError> {
        let index = Arc::new(AuthIndex::new());
        store.register_index(index.clone())?;
        let service = Arc::new(Self {
            throttle: Arc::new(Throttle::new(config.throttle_capacity)),
            scope: Arc::new(ScopeSupport::default()),
            ceremonies: Ceremonies::new(config.ceremony_capacity),
            store,
            vault,
            config,
            index,
            setup_token: Mutex::new(None),
            relying_party: ArcSwapOption::empty(),
        });
        let installation = service.view().await?.get_typed(&INSTALLATION, &())?;
        service.configure_relying_party(installation.as_ref().map(|(i, _)| i))?;
        service.spawn_unlock_watch();
        Ok(service)
    }

    /// The [`Authorizer`] for every package (roles, scoped grants and tokens, TGL-02,
    /// TGL-03, MFA per role, IAM-07).
    pub fn authorizer(&self) -> Arc<dyn Authorizer> {
        Arc::new(self.rbac())
    }

    /// The concrete authorizer, for callers that need its reach.
    pub fn rbac(&self) -> RbacAuthorizer {
        RbacAuthorizer::with_scope(self.index.clone(), self.scope.clone())
    }

    /// Wires the resolver of anchors (`tenko_ipam::scope::ScopeIndex`) that scoped
    /// authorization needs (IAM-01). Until it is set, scoped principals are refused on every
    /// object, and grants over a scope cannot be created.
    pub fn set_anchor_resolver(&self, resolver: Arc<dyn AnchorResolver>) {
        self.scope.set(resolver, Arc::clone(&self.store));
    }

    /// Seals ceremonies under `key` (the installation's ceremony key, derived from the
    /// cluster key), so a ceremony started on one controller finishes on another. Until it
    /// is set, ceremonies are sealed under a key of this process.
    pub fn set_ceremony_key(&self, key: crate::challenge::CeremonyKey) {
        self.ceremonies.set_key(key);
    }

    /// The authorization index (roles, grants, tokens, policies and settings).
    pub fn index(&self) -> &Arc<AuthIndex> {
        &self.index
    }

    /// The current security settings (from the index: no store read).
    pub fn settings(&self) -> SecuritySettings {
        self.index.image().settings().clone()
    }

    /// The relying party, once a host name is known.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unavailable`] before setup when no RP ID is configured.
    pub fn relying_party(&self) -> Result<Arc<RelyingParty>, AuthError> {
        self.relying_party.load_full().ok_or(AuthError::Unavailable(
            "passkeys need a host name; complete setup first",
        ))
    }

    fn configure_relying_party(
        &self,
        installation: Option<&Installation>,
    ) -> Result<(), AuthError> {
        let rp_id = self
            .config
            .rp_id
            .clone()
            .or_else(|| installation.map(|i| i.host_name.clone()));
        let Some(rp_id) = rp_id else {
            return Ok(());
        };
        let mut config = RpConfig::for_host(&rp_id);
        config.rp_name.clone_from(&self.config.rp_name);
        if !self.config.origins.is_empty() {
            config.origins.clone_from(&self.config.origins);
        } else if rp_id == "localhost" {
            // Browsers treat plain-HTTP localhost as a secure context (development).
            config.origins.push("http://localhost:*".to_owned());
        }
        config
            .trust_anchors
            .clone_from(&self.config.attestation_roots);
        self.relying_party
            .store(Some(Arc::new(RelyingParty::new(config)?)));
        Ok(())
    }

    /// The `Set-Cookie` value for a session secret.
    pub fn session_cookie(&self, secret: &BearerSecret, max_age: Duration) -> String {
        let secure = if self.config.cookie_secure {
            "; Secure"
        } else {
            ""
        };
        format!(
            "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
            secret.expose(),
            max_age.as_secs()
        )
    }

    /// The `Set-Cookie` value that removes the session cookie.
    pub fn clear_cookie(&self) -> String {
        let secure = if self.config.cookie_secure {
            "; Secure"
        } else {
            ""
        };
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, AuthError> {
        Ok(self.store.read(ReadConsistency::Local).await?)
    }

    async fn commit(&self, batch: WriteBatch) -> Result<tenko_store::Committed, AuthError> {
        match self.store.propose(batch).await {
            Ok(committed) => Ok(committed),
            Err(StoreError::PreconditionFailed(_)) => Err(AuthError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    fn breach_checker(&self, settings: &SecuritySettings) -> BreachChecker {
        BreachChecker::new(
            settings.breach_check,
            self.config.hibp_online.clone(),
            self.config.hibp_offline.clone(),
        )
    }

    async fn has_operator_secrets(&self) -> Result<bool, AuthError> {
        self.vault
            .has_operator_secrets()
            .await
            .map_err(|error| AuthError::internal(format!("vault: {error}")))
    }

    /// The user behind an interactive session principal.
    fn session_principal(ctx: &RequestCtx) -> Result<(UserId, SessionId, AuthStrength), AuthError> {
        match ctx.principal {
            Principal::User {
                id,
                session,
                strength,
            } => Ok((id, session, strength)),
            _ => Err(AuthError::Unauthenticated),
        }
    }

    /// Whether the principal may act, without recording anything.
    fn authorized(
        &self,
        ctx: &RequestCtx,
        action: tenko_core::Action,
        object: ObjectRef,
    ) -> Result<(), AuthError> {
        self.rbac()
            .check(&ctx.principal, action, &object)
            .map_err(AuthError::from)
    }

    /// Checks an administrative action; a refusal is written to the audit log
    /// (`auth.access.denied`, NEVER-02) before it is returned.
    async fn authorize(
        &self,
        ctx: &RequestCtx,
        action: tenko_core::Action,
        object: ObjectRef,
    ) -> Result<(), AuthError> {
        let Err(error) = self.authorized(ctx, action, object) else {
            return Ok(());
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::denied(actions::ACCESS_DENIED, vec![object])
                .with_source_ip(ctx.source_ip)
                .with_context("action", action.as_str()),
        );
        if let Err(store_error) = self.store.propose(batch).await {
            tracing::warn!(error = %store_error, "could not record a refused action");
        }
        Err(error)
    }

    /// The strength the account must sign in with: the profile, the PIN coupling rule and
    /// the MFA policy of every role it holds at any scope (IAM-06).
    fn required_for(&self, user: &UserRecord) -> AuthStrength {
        self.index
            .image()
            .required_strength(user.id, tenko_core::Action::Read)
    }

    /// Adds a new session for `user` to `batch` and returns its secret and record.
    #[allow(clippy::too_many_arguments)]
    fn stage_session(
        &self,
        batch: &mut WriteBatch,
        settings: &SecuritySettings,
        user: &UserRecord,
        strength: AuthStrength,
        now: Timestamp,
        source_ip: Option<IpAddr>,
        user_agent: Option<&str>,
        break_glass: bool,
    ) -> Result<(BearerSecret, SessionRecord), AuthError> {
        let (absolute, idle) = if break_glass {
            (BREAK_GLASS_SESSION, BREAK_GLASS_IDLE)
        } else {
            (settings.session.absolute(), settings.session.idle())
        };
        let secret = crate::secret::new_session_secret()?;
        let record = SessionRecord {
            id: SessionId::generate(),
            user: user.id,
            strength,
            created_at: now,
            authenticated_at: now,
            expires_at: now.checked_add(absolute).unwrap_or(now),
            idle_expires_at: now.checked_add(idle.min(absolute)).unwrap_or(now),
            last_seen_at: now,
            source_ip,
            user_agent: user_agent.map(|agent| agent.chars().take(200).collect()),
            break_glass,
            mfa_enrolment_required: strength < self.required_for(user),
        };
        let hash = secret.hash();
        batch.put_typed(&SESSIONS, &hash, &record)?;
        batch.put_typed(&USER_SESSIONS, &(user.id, record.id), &hash)?;
        Ok((secret, record))
    }

    /// Describes a session.
    async fn session_info(
        &self,
        user: &UserRecord,
        session: &SessionRecord,
    ) -> Result<SessionInfo, AuthError> {
        let settings = self.settings();
        let installation = self.view().await?.get_typed(&INSTALLATION, &())?;
        let (expires_at, absolute) = effective_expiry(session, &settings);
        Ok(SessionInfo {
            session_id: session.id,
            user: UserSummary {
                id: user.id,
                name: user.name.clone(),
                display_name: user.display_name.clone(),
                language: user.language.clone(),
            },
            roles: user.roles.clone(),
            strength: session.strength,
            required_strength: self.required_for(user),
            created_at: session.created_at,
            expires_at,
            absolute_expires_at: absolute,
            flags: SessionFlags {
                password_change_required: user.password_change_required,
                mfa_enrolment_required: session.strength < self.required_for(user),
                break_glass: session.break_glass,
            },
            profile: settings.profile,
            banner: settings.banner(),
            default_language: installation.map(|(installation, _)| installation.language),
            grants: self
                .index
                .image()
                .grants_of(user.id)
                .iter()
                .map(SessionGrant::from)
                .collect(),
        })
    }

    /// Finishes a login: the session, its cookie and its description.
    async fn complete_login(
        &self,
        mut batch: WriteBatch,
        user: &UserRecord,
        secret: BearerSecret,
        record: SessionRecord,
    ) -> Result<NewSession, AuthError> {
        batch.put_typed(&LAST_LOGINS, &user.id, &record.created_at)?;
        // Sessions of the account that have ended are removed with the login.
        let settings = self.settings();
        let view = self.view().await?;
        let ended: Vec<_> = Self::user_sessions(view.as_ref(), user.id)?
            .into_iter()
            .filter(|(_, session)| effective_expiry(session, &settings).0 <= record.created_at)
            .collect();
        Self::stage_revoke(&mut batch, &ended);
        self.commit(batch).await?;
        let info = self.session_info(user, &record).await?;
        let max_age = record.expires_at.saturating_since(record.created_at);
        let set_cookie = self.session_cookie(&secret, max_age);
        Ok(NewSession {
            secret,
            info,
            set_cookie,
        })
    }

    /// Resolves a session cookie or bearer token (the [`Authenticator`] contract).
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`], [`AuthError::SessionExpired`], or a store error.
    pub async fn authenticate_credentials(
        &self,
        credentials: &Credentials,
        now: Timestamp,
    ) -> Result<Authenticated, AuthError> {
        match credentials {
            Credentials::None => Err(AuthError::Unauthenticated),
            Credentials::Session(secret) => self.authenticate_session(secret, now).await,
            Credentials::Bearer(token) => self.authenticate_token(token, now).await,
        }
    }

    async fn authenticate_session(
        &self,
        secret: &str,
        now: Timestamp,
    ) -> Result<Authenticated, AuthError> {
        if !looks_like_session_secret(secret) {
            return Err(AuthError::Unauthenticated);
        }
        let hash = hash_secret(secret);
        let mut view = self.view().await?;
        let mut found = view.get_typed(&SESSIONS, &hash)?;
        if found.is_none() {
            // A session created on another controller may not have reached this one's copy
            // yet: read once more at the leader's commit index before refusing it.
            if let Some(confirmed) = self.confirmed_view().await {
                found = confirmed.get_typed(&SESSIONS, &hash)?;
                view = confirmed;
            }
        }
        let Some((mut session, revision)) = found else {
            return Err(AuthError::Unauthenticated);
        };
        let settings = self.settings();
        let (expires_at, _) = effective_expiry(&session, &settings);
        if now >= expires_at {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            batch.delete_typed(&SESSIONS, &hash);
            batch.delete_typed(&USER_SESSIONS, &(session.user, session.id));
            if let Err(error) = self.store.propose(batch).await {
                tracing::warn!(%error, "could not remove an expired session");
            }
            return Err(AuthError::SessionExpired);
        }
        let user = view
            .get_typed(&USERS, &session.user)?
            .map(|(user, _)| user)
            .filter(|user| !user.disabled && !user.is_service())
            .ok_or(AuthError::Unauthenticated)?;
        if session.break_glass && !user.break_glass {
            return Err(AuthError::Unauthenticated);
        }
        let idle = if session.break_glass {
            BREAK_GLASS_IDLE
        } else {
            settings.session.idle()
        };
        // Without quorum the refresh would wait for a leader and fail, and every later
        // request of the session would wait again (OPS-26): the refresh waits for the quorum.
        if now.saturating_since(session.last_seen_at) >= refresh_interval(idle)
            && self.store.status().quorum.accepts_writes()
        {
            session.last_seen_at = now;
            session.idle_expires_at = now.checked_add(idle).unwrap_or(now).min(session.expires_at);
            let principal = Principal::User {
                id: user.id,
                session: session.id,
                strength: session.strength,
            };
            let mut batch = WriteBatch::new(principal, now);
            batch.expect_typed(&SESSIONS, &hash, Some(revision));
            batch.put_typed(&SESSIONS, &hash, &session)?;
            // A concurrent request may have refreshed it already; that is fine.
            if let Err(error) = self.store.propose(batch).await
                && !matches!(error, StoreError::PreconditionFailed(_))
            {
                tracing::warn!(%error, "could not record session activity");
            }
        }
        let (expires_at, _) = effective_expiry(&session, &settings);
        Ok(Authenticated {
            principal: Principal::User {
                id: user.id,
                session: session.id,
                strength: session.strength,
            },
            user: Some(user.id),
            roles: role_names(&user.roles),
            strength: session.strength,
            expires_at: Some(expires_at),
            flags: AuthFlags {
                password_change_required: user.password_change_required,
                mfa_enrolment_required: session.strength < self.required_for(&user),
                break_glass: session.break_glass,
            },
        })
    }

    async fn authenticate_token(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<Authenticated, AuthError> {
        if !token.starts_with(crate::secret::TOKEN_PREFIX) || token.len() > 128 {
            return Err(AuthError::Unauthenticated);
        }
        let hash = hash_secret(token);
        let view = self.view().await?;
        let mut found = Self::find_token(view.as_ref(), &hash)?;
        let mut view = view;
        if found.is_none()
            && let Some(confirmed) = self.confirmed_view().await
        {
            // A token created on another controller: read at the leader's commit index.
            found = Self::find_token(confirmed.as_ref(), &hash)?;
            view = confirmed;
        }
        let settings = self.settings();
        match found {
            None => Err(AuthError::Unauthenticated),
            Some(FoundToken::Personal(mut record, revision)) => {
                if token_expired(record.created_at, record.expires_at, &settings, now) {
                    return Err(AuthError::SessionExpired);
                }
                let user = view
                    .get_typed(&USERS, &record.owner)?
                    .map(|(user, _)| user)
                    .filter(|user| !user.disabled && !user.break_glass && !user.is_service())
                    .ok_or(AuthError::Unauthenticated)?;
                let principal = Principal::Token {
                    id: record.id,
                    owner: user.id,
                };
                if record
                    .last_used_at
                    .is_none_or(|last| now.saturating_since(last) >= Duration::from_secs(3_600))
                {
                    record.last_used_at = Some(now);
                    let mut batch = WriteBatch::new(principal.clone(), now);
                    batch.expect_typed(&TOKENS, &hash, Some(revision));
                    batch.put_typed(&TOKENS, &hash, &record)?;
                    self.record_token_use(batch).await;
                }
                Ok(Authenticated {
                    principal,
                    user: Some(user.id),
                    roles: role_names(&user.roles),
                    strength: record.issued_with,
                    expires_at: effective_token_expiry(
                        record.created_at,
                        record.expires_at,
                        &settings,
                    ),
                    flags: AuthFlags::default(),
                })
            }
            Some(FoundToken::Scoped(mut record, revision)) => {
                if token_expired(record.created_at, record.expires_at, &settings, now) {
                    return Err(AuthError::SessionExpired);
                }
                let user = view
                    .get_typed(&USERS, &record.owner)?
                    .map(|(user, _)| user)
                    .filter(|user| !user.disabled && !user.break_glass)
                    .ok_or(AuthError::Unauthenticated)?;
                let principal = Principal::Token {
                    id: record.id,
                    owner: user.id,
                };
                if record
                    .last_used_at
                    .is_none_or(|last| now.saturating_since(last) >= Duration::from_secs(3_600))
                {
                    record.last_used_at = Some(now);
                    let mut batch = WriteBatch::new(principal.clone(), now);
                    batch.expect_typed(&SCOPED_TOKENS, &hash, Some(revision));
                    batch.put_typed(&SCOPED_TOKENS, &hash, &record)?;
                    self.record_token_use(batch).await;
                }
                // The global roles the token acts with: its global grants the owner covers.
                let roles: Vec<RoleName> = record
                    .grants
                    .iter()
                    .filter(|grant| grant.scope.is_none())
                    .map(|grant| grant.role)
                    .filter(|role| user.roles.iter().any(|held| held.covers(*role)))
                    .collect();
                Ok(Authenticated {
                    principal,
                    user: Some(user.id),
                    roles: role_names(&roles),
                    strength: record.issued_with,
                    expires_at: effective_token_expiry(
                        record.created_at,
                        record.expires_at,
                        &settings,
                    ),
                    flags: AuthFlags::default(),
                })
            }
        }
    }

    /// The personal or scoped token stored under `hash`.
    fn find_token(view: &dyn ReadView, hash: &Vec<u8>) -> Result<Option<FoundToken>, AuthError> {
        if let Some((record, revision)) = view.get_typed(&TOKENS, hash)? {
            return Ok(Some(FoundToken::Personal(record, revision)));
        }
        Ok(view
            .get_typed(&SCOPED_TOKENS, hash)?
            .map(|(record, revision)| FoundToken::Scoped(Box::new(record), revision)))
    }

    /// Records the hourly use of a token; a concurrent request may have done it already.
    async fn record_token_use(&self, batch: WriteBatch) {
        if let Err(error) = self.store.propose(batch).await
            && !matches!(error, StoreError::PreconditionFailed(_))
        {
            tracing::warn!(%error, "could not record token use");
        }
    }

    /// A view at the commit index of the leader (a read index on a follower), or `None`
    /// when the cluster cannot confirm one now.
    async fn confirmed_view(&self) -> Option<Arc<dyn ReadView>> {
        self.store.read(ReadConsistency::Linearizable).await.ok()
    }

    /// Follows the user records so that an unlock by an administrator on any controller
    /// clears this controller's login throttle for the account (WP3.1b section 7): the
    /// throttle lives in memory per controller, the unlock is a write of the user record.
    fn spawn_unlock_watch(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = Arc::clone(&self.store);
        let throttle = Arc::clone(&self.throttle);
        handle.spawn(unlock_watch(store, throttle));
    }

    /// Loads a session of `user` by id.
    fn load_session(
        view: &dyn ReadView,
        user: UserId,
        session: SessionId,
    ) -> Result<Option<(Vec<u8>, SessionRecord)>, AuthError> {
        let Some((hash, _)) = view.get_typed(&USER_SESSIONS, &(user, session))? else {
            return Ok(None);
        };
        Ok(view
            .get_typed(&SESSIONS, &hash)?
            .map(|(record, _)| (hash, record)))
    }

    /// Every session of a user as (hash, record).
    fn user_sessions(
        view: &dyn ReadView,
        user: UserId,
    ) -> Result<Vec<(Vec<u8>, SessionRecord)>, AuthError> {
        let range = KeyRange::prefix(tenko_core::codec::encode_key(&(user,)));
        let mut sessions = Vec::new();
        for (_, hash, _) in view.scan_typed(&USER_SESSIONS, range, LIST_LIMIT, false)? {
            if let Some((record, _)) = view.get_typed(&SESSIONS, &hash)? {
                sessions.push((hash, record));
            }
        }
        Ok(sessions)
    }

    /// Adds the deletion of sessions to a batch.
    fn stage_revoke(batch: &mut WriteBatch, sessions: &[(Vec<u8>, SessionRecord)]) {
        for (hash, record) in sessions {
            batch.delete_typed(&SESSIONS, hash);
            batch.delete_typed(&USER_SESSIONS, &(record.user, record.id));
        }
    }

    /// Every WebAuthn credential of a user.
    fn user_credentials(
        view: &dyn ReadView,
        user: UserId,
    ) -> Result<Vec<CredentialRecord>, AuthError> {
        let range = KeyRange::prefix(tenko_core::codec::encode_key(&(user,)));
        Ok(view
            .scan_typed(&CREDENTIALS, range, LIST_LIMIT, false)?
            .into_iter()
            .map(|(_, record, _)| record)
            .collect())
    }

    fn load_user(
        view: &dyn ReadView,
        id: UserId,
    ) -> Result<(UserRecord, tenko_core::Revision), AuthError> {
        view.get_typed(&USERS, &id)?
            .ok_or(AuthError::NotFound { kind: "user" })
    }

    fn find_user(view: &dyn ReadView, name: &str) -> Result<Option<UserRecord>, AuthError> {
        let Some((id, _)) =
            view.get_typed(&crate::model::USER_NAMES, &UserRecord::name_key(name))?
        else {
            return Ok(None);
        };
        Ok(view.get_typed(&USERS, &id)?.map(|(user, _)| user))
    }

    fn audit(action: AuditAction, objects: Vec<ObjectRef>, ctx: &RequestCtx) -> AuditDraft {
        AuditDraft::success(action, objects).with_source_ip(ctx.source_ip)
    }

    /// Whether setup has completed.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn is_installed(&self) -> Result<bool, AuthError> {
        Ok(self.view().await?.get_typed(&INSTALLATION, &())?.is_some())
    }

    /// The stored settings with their revision (`None` before setup).
    async fn stored_settings(
        &self,
    ) -> Result<Option<(SecuritySettings, tenko_core::Revision)>, AuthError> {
        Ok(self.view().await?.get_typed(&SETTINGS, &())?)
    }

    fn setup_verifier(&self) -> std::sync::MutexGuard<'_, Option<SetupTokenVerifier>> {
        self.setup_token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Authenticator for AuthService {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        now: Timestamp,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            self.authenticate_credentials(credentials, now)
                .await
                .map_err(|error| match error {
                    AuthError::Unauthenticated if !credentials.is_present() => AuthFailure::Missing,
                    other => other.to_failure(),
                })
        })
    }
}

/// The effective end of a session and its absolute end under the current settings.
fn effective_expiry(
    session: &SessionRecord,
    settings: &SecuritySettings,
) -> (Timestamp, Timestamp) {
    let (absolute, idle) = if session.break_glass {
        (BREAK_GLASS_SESSION, BREAK_GLASS_IDLE)
    } else {
        (settings.session.absolute(), settings.session.idle())
    };
    let absolute_end = session.expires_at.min(
        session
            .created_at
            .checked_add(absolute)
            .unwrap_or(session.expires_at),
    );
    let idle_end = session.idle_expires_at.min(
        session
            .last_seen_at
            .checked_add(idle)
            .unwrap_or(session.idle_expires_at),
    );
    (absolute_end.min(idle_end), absolute_end)
}

/// A token found by its hash.
enum FoundToken {
    Personal(TokenRecord, tenko_core::Revision),
    Scoped(Box<ScopedTokenRecord>, tenko_core::Revision),
}

/// The end of a token under the current TGL-05 cap: a tightened cap shortens existing
/// tokens (IAM-10).
pub(crate) fn effective_token_expiry(
    created_at: Timestamp,
    expires_at: Option<Timestamp>,
    settings: &SecuritySettings,
) -> Option<Timestamp> {
    let cap = settings
        .token_max_days
        .and_then(|days| created_at.checked_add(Duration::from_secs(u64::from(days) * 86_400)));
    match (expires_at, cap) {
        (Some(expires), Some(cap)) => Some(expires.min(cap)),
        (expires, None) => expires,
        (None, cap) => cap,
    }
}

fn token_expired(
    created_at: Timestamp,
    expires_at: Option<Timestamp>,
    settings: &SecuritySettings,
    now: Timestamp,
) -> bool {
    effective_token_expiry(created_at, expires_at, settings).is_some_and(|end| now >= end)
}

/// The loop of [`AuthService::spawn_unlock_watch`]: ends when the store shuts down.
async fn unlock_watch(store: Arc<dyn Store>, throttle: Arc<Throttle>) {
    let filter = WatchFilter::tables([USERS.name().clone()]);
    // Names by id, so that the throttle of a deleted account is cleared too.
    let mut names: HashMap<UserId, String> = HashMap::new();
    let mut unlocked: HashMap<UserId, Timestamp> = HashMap::new();
    loop {
        let Ok(mut changes) = store.watch(None, filter.clone()) else {
            return;
        };
        // What this controller knows now; unlocks before this point find nothing to clear.
        if let Ok(view) = store.read(ReadConsistency::Local).await
            && let Ok(users) = view.scan_typed(&USERS, KeyRange::all(), usize::MAX, false)
        {
            for (id, user, _) in users {
                if let Some(at) = user.unlocked_at {
                    unlocked.insert(id, at);
                }
                names.insert(id, user.name);
            }
        }
        while let Some(item) = changes.next().await {
            let Ok(change_set) = item else {
                break;
            };
            let Ok(view) = store
                .read(ReadConsistency::AtLeast(change_set.revision))
                .await
            else {
                break;
            };
            for change in &change_set.changes {
                let Ok(id) = USERS.decode_key(&change.key) else {
                    continue;
                };
                match view.get_typed(&USERS, &id) {
                    Ok(Some((user, _))) => {
                        if let Some(at) = user.unlocked_at
                            && unlocked.get(&id) != Some(&at)
                        {
                            throttle.unlock(&ThrottleKey::account(&user.name));
                            unlocked.insert(id, at);
                        }
                        if let Some(old) = names.insert(id, user.name.clone())
                            && old != user.name
                        {
                            throttle.unlock(&ThrottleKey::account(&old));
                        }
                    }
                    Ok(None) => {
                        if let Some(name) = names.remove(&id) {
                            throttle.unlock(&ThrottleKey::account(&name));
                        }
                        unlocked.remove(&id);
                    }
                    Err(error) => tracing::debug!(%error, "unlock watch could not read a user"),
                }
            }
        }
        if store.read(ReadConsistency::Local).await.is_err() {
            return;
        }
    }
}

fn role_names(roles: &[RoleName]) -> std::collections::BTreeSet<String> {
    roles.iter().map(|role| role.as_str().to_owned()).collect()
}

/// Runs a CPU-heavy closure (Argon2id) off the async workers.
async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AuthError> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|_| AuthError::internal("password hashing task failed"))
}
