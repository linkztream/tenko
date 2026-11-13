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
//! not turn every request into a Raft entry. Logout and the revocation of one session delete
//! its rows; a password change or reset, signing out everywhere, disabling, deleting and the
//! break-glass designation end every session of the account at once (`end`).
//!
//! # Write discipline
//!
//! Every change is one [`WriteBatch`] with its audit drafts (ADR 0011). Failed logins are
//! throttled in memory first ([`crate::lockout`]) and only then written as audit records,
//! so a flood of attempts cannot flood the log.

mod access;
mod account;
mod admin;
pub mod devices;
mod end;
mod guard;
mod hold;
mod login;
mod misses;
mod pins;
// U6 of the UI plan: the person's saved table layouts.
mod preferences;
pub mod reveal;
mod setup;
pub mod types;

pub use admin::{OfflineUnlock, unlock_offline};
pub use devices::{
    DEVICE_COOKIE, DeviceCookie, DeviceMarks, HOST_DEVICE_COOKIE, device_cookie_name,
};
pub use guard::default_hash_memory_mib;
pub use hold::{Follow, Hold};
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
    lockout::Throttle,
    model::{
        CREDENTIALS, CredentialRecord, INSTALLATION, Installation, Issued, LAST_LOGINS,
        SCOPED_TOKENS, SESSIONS, SETTINGS, ScopedTokenRecord, SessionRecord, TOKENS, TokenRecord,
        USER_SESSIONS, USERS, UserRecord,
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
    /// Known devices of an account were removed; context `known_devices`: how many.
    pub const KNOWN_DEVICE_REMOVE: AuditAction =
        AuditAction::from_static("auth.known_device.remove");
    /// A password change.
    pub const PASSWORD_CHANGE: AuditAction = AuditAction::from_static("auth.password.change");
    /// TOTP enrolled.
    pub const TOTP_ENROLL: AuditAction = AuditAction::from_static("auth.totp.enroll");
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
    /// The ports the server listens on for the API and the UI: the default WebAuthn origins
    /// are `https://<rp id>` and `https://<rp id>:<port>` for each of them (no other port).
    pub listen_ports: Vec<u16>,
    /// The online HIBP range source (feature `online` provides one).
    pub hibp_online: Option<Arc<dyn HibpRangeSource>>,
    /// The offline breach filter built by `tenko hibp build`.
    pub hibp_offline: Option<Arc<HibpFilter>>,
    /// Keys tracked by the in-memory throttle.
    pub throttle_capacity: usize,
    /// Open ceremonies kept in memory.
    pub ceremony_capacity: usize,
    /// The memory, in MiB, that password computations in flight may take together
    /// (`[auth] password_hash_memory_mib`); an attempt beyond it is refused at once with
    /// `auth.throttled`. Default [`default_hash_memory_mib`].
    pub password_hash_memory_mib: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            rp_id: None,
            origins: Vec::new(),
            rp_name: "Tenko DDI".to_owned(),
            attestation_roots: Vec::new(),
            listen_ports: Vec::new(),
            hibp_online: None,
            hibp_offline: None,
            throttle_capacity: 100_000,
            ceremony_capacity: 10_000,
            password_hash_memory_mib: default_hash_memory_mib(),
        }
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("rp_id", &self.rp_id)
            .field("origins", &self.origins)
            .field("listen_ports", &self.listen_ports)
            .field("attestation_roots", &self.attestation_roots.len())
            .field("hibp_online", &self.hibp_online.is_some())
            .field("hibp_offline", &self.hibp_offline.is_some())
            .field("password_hash_memory_mib", &self.password_hash_memory_mib)
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
    hash_gate: guard::HashGate,
    dummy_timing: guard::DummyTiming,
    known_networks: Arc<guard::KnownNetworks>,
    devices_in_flight: devices::DevicesInFlight,
    misses: misses::Misses,
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
    /// How long the cookie lives: the session's lifetime.
    pub max_age: Duration,
    /// The device cookie to set beside it (`devices`), when the sign-in issued a mark.
    pub device: Option<DeviceCookie>,
}

impl NewSession {
    /// The `Set-Cookie` header value for a request over HTTPS or plain HTTP
    /// ([`session_cookie_name`]).
    pub fn set_cookie(&self, https: bool) -> String {
        session_cookie(self.secret.expose(), self.max_age, https)
    }

    /// Every `Set-Cookie` value of the sign-in: the session cookie, and the device cookie
    /// when a mark was issued.
    pub fn set_cookies(&self, https: bool) -> Vec<String> {
        let mut cookies = vec![self.set_cookie(https)];
        cookies.extend(self.device.as_ref().map(|device| device.set_cookie(https)));
        cookies
    }
}

/// The name of the session cookie over HTTPS. A browser keeps a `__Host-` cookie only when
/// it was set `Secure`, with `Path=/` and without `Domain`, by this host itself, so no other
/// host (a sibling subdomain included) and no plain-HTTP answer can set or replace it.
pub const HOST_SESSION_COOKIE: &str = "__Host-tenko_session";

/// The name of the session cookie for a request over HTTPS or over plain HTTP: the one
/// place that decides it, for the server, the CLI and the tests. Over plain HTTP (the Lab
/// profile under TGL-08, and `localhost` in development) a browser refuses a `__Host-`
/// cookie, so the plain name serves there, and only there.
pub fn session_cookie_name(https: bool) -> &'static str {
    if https {
        HOST_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

/// The `Set-Cookie` value of a session secret: `HttpOnly`, `SameSite=Strict`, `Path=/`,
/// and `Secure` with the `__Host-` name over HTTPS.
pub fn session_cookie(secret: &str, max_age: Duration, https: bool) -> String {
    let secure = if https { "; Secure" } else { "" };
    format!(
        "{}={secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        session_cookie_name(https),
        max_age.as_secs()
    )
}

/// The `Set-Cookie` value that removes the session cookie of the scheme.
pub fn clear_session_cookie(https: bool) -> String {
    let secure = if https { "; Secure" } else { "" };
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}",
        session_cookie_name(https)
    )
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
    /// The JSON answer and, for a session, the `Set-Cookie` values for a request over
    /// HTTPS or plain HTTP ([`NewSession::set_cookies`]).
    pub fn into_response(self, https: bool) -> (LoginResponse, Vec<String>) {
        match self {
            Self::Session(session) => {
                let cookies = session.set_cookies(https);
                (
                    LoginResponse::Authenticated {
                        session: session.info,
                    },
                    cookies,
                )
            }
            Self::SecondFactor {
                challenge_id,
                methods,
            } => (
                LoginResponse::SecondFactor {
                    challenge_id,
                    methods,
                    expires_in: crate::challenge::CEREMONY_TTL.as_secs(),
                },
                Vec::new(),
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
pub(super) const LIST_LIMIT: usize = 10_000;

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
            hash_gate: guard::HashGate::new(config.password_hash_memory_mib),
            dummy_timing: guard::DummyTiming::default(),
            known_networks: Arc::new(guard::KnownNetworks::default()),
            devices_in_flight: devices::DevicesInFlight::default(),
            misses: misses::Misses::default(),
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
        service.spawn_pin_sweep();
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
        let mut config = RpConfig::for_host_ports(&rp_id, &self.config.listen_ports);
        config.rp_name.clone_from(&self.config.rp_name);
        if !self.config.origins.is_empty() {
            config.origins.clone_from(&self.config.origins);
        } else if rp_id == "localhost" {
            // Development: any port of localhost, and plain HTTP, which browsers treat as a
            // secure context there.
            config.origins = vec![
                "https://localhost:*".to_owned(),
                "http://localhost:*".to_owned(),
            ];
        } else {
            tracing::info!(
                origins = %config.origins.join(", "),
                "passkeys work from these origins; list others in [auth] origins"
            );
        }
        config
            .trust_anchors
            .clone_from(&self.config.attestation_roots);
        self.relying_party
            .store(Some(Arc::new(RelyingParty::new(config)?)));
        Ok(())
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
            mfa_enrollment_required: strength < self.required_for(user),
            // WP13.0: every session the service makes today is a local one.
            source: crate::directory::SessionSource::Local,
            directory_checked_at: None,
            generation: user.sessions_generation,
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
                mfa_enrollment_required: session.strength < self.required_for(user),
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

    /// Finishes a login: the session, its cookie and its description, and with `marks`
    /// (the device cookie of a sign-in; `None` for setup) a new mark of the device in the
    /// same write.
    async fn complete_login(
        &self,
        mut batch: WriteBatch,
        user: &UserRecord,
        secret: BearerSecret,
        record: SessionRecord,
        marks: Option<&DeviceMarks>,
    ) -> Result<NewSession, AuthError> {
        batch.put_typed(&LAST_LOGINS, &user.id, &record.created_at)?;
        // Sessions of the account that have ended are removed with the login.
        let settings = self.settings();
        let view = self.view().await?;
        let device = match marks {
            Some(marks) => {
                Self::stage_known_device(view.as_ref(), &mut batch, user, marks, record.created_at)?
            }
            None => None,
        };
        let ended: Vec<_> = Self::user_sessions(view.as_ref(), user.id)?
            .into_iter()
            .filter(|(_, session)| {
                effective_expiry(session, &settings).0 <= record.created_at
                    || !user.admits(Issued::Session(session.generation))
            })
            .collect();
        Self::stage_revoke(&mut batch, &ended);
        self.commit(batch).await?;
        let info = self.session_info(user, &record).await?;
        let max_age = record.expires_at.saturating_since(record.created_at);
        Ok(NewSession {
            secret,
            info,
            max_age,
            device,
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
        let (hash, mut session, revision, view) = self.session_of(secret, now).await?;
        let settings = self.settings();
        let user = match Self::session_holds(view.as_ref(), &session, &settings, now) {
            Err(AuthError::SessionExpired) => {
                let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
                batch.delete_typed(&SESSIONS, &hash);
                batch.delete_typed(&USER_SESSIONS, &(session.user, session.id));
                if let Err(error) = self.store.propose(batch).await {
                    tracing::warn!(%error, "could not remove an expired session");
                }
                return Err(AuthError::SessionExpired);
            }
            held => held?.0,
        };
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
                mfa_enrollment_required: session.strength < self.required_for(&user),
                break_glass: session.break_glass,
            },
        })
    }

    async fn authenticate_token(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<Authenticated, AuthError> {
        let (hash, found, view) = self.token_of(token, now).await?;
        let settings = self.settings();
        let (user, expires_at) = Self::token_holds(view.as_ref(), &found, &settings, now)?;
        let (id, strength, roles) = match &found {
            FoundToken::Personal(record, _) => (record.id, record.issued_with, user.roles.clone()),
            // The global roles the token acts with: its global grants the owner covers.
            FoundToken::Scoped(record, _) => (
                record.id,
                record.issued_with,
                record
                    .grants
                    .iter()
                    .filter(|grant| grant.scope.is_none())
                    .map(|grant| grant.role)
                    .filter(|role| user.roles.iter().any(|held| held.covers(*role)))
                    .collect(),
            ),
        };
        let principal = Principal::Token { id, owner: user.id };
        let mut batch = WriteBatch::new(principal.clone(), now);
        let due = |last: Option<Timestamp>| {
            last.is_none_or(|last| now.saturating_since(last) >= Duration::from_secs(3_600))
        };
        match found {
            FoundToken::Personal(mut record, revision) if due(record.last_used_at) => {
                record.last_used_at = Some(now);
                batch.expect_typed(&TOKENS, &hash, Some(revision));
                batch.put_typed(&TOKENS, &hash, &record)?;
            }
            FoundToken::Scoped(mut record, revision) if due(record.last_used_at) => {
                record.last_used_at = Some(now);
                batch.expect_typed(&SCOPED_TOKENS, &hash, Some(revision));
                batch.put_typed(&SCOPED_TOKENS, &hash, &*record)?;
            }
            _ => {}
        }
        if !batch.mutations.is_empty() {
            self.record_token_use(batch).await;
        }
        Ok(Authenticated {
            principal,
            user: Some(user.id),
            roles: role_names(&roles),
            strength,
            expires_at,
            flags: AuthFlags::default(),
        })
    }

    /// The session a presented secret names, with its hash, its revision and the view it was
    /// found in: this controller's copy, else (a session created on another controller that
    /// has not reached this one yet) the leader's commit index, within the bound of
    /// [`AuthService::confirmed_view_for_miss`].
    async fn session_of(&self, secret: &str, now: Timestamp) -> Result<FoundSession, AuthError> {
        if !looks_like_session_secret(secret) {
            return Err(AuthError::Unauthenticated);
        }
        let hash = hash_secret(secret);
        let mut view = self.view().await?;
        let mut found = view.get_typed(&SESSIONS, &hash)?;
        if found.is_none()
            && let Some(confirmed) = self.confirmed_view_for_miss(&hash, now).await
        {
            found = confirmed.get_typed(&SESSIONS, &hash)?;
            if found.is_none() {
                self.misses.remember(&hash, now);
            }
            view = confirmed;
        }
        let (session, revision) = found.ok_or(AuthError::Unauthenticated)?;
        Ok((hash, session, revision, view))
    }

    /// The token a presented bearer secret names, with its hash and the view it was found in
    /// ([`AuthService::lookup_token`]).
    async fn token_of(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<(Vec<u8>, FoundToken, Arc<dyn ReadView>), AuthError> {
        if !token.starts_with(crate::secret::TOKEN_PREFIX) || token.len() > 128 {
            return Err(AuthError::Unauthenticated);
        }
        let hash = hash_secret(token);
        let (found, view) = self.lookup_token(&hash, now).await?;
        Ok((hash, found.ok_or(AuthError::Unauthenticated)?, view))
    }

    /// The account a session acts for at `now` and when the session ends: the rules every
    /// request with the session meets, and every check of a stream it opened
    /// ([`AuthService::standing`]). [`AuthError::SessionExpired`] once its time is over.
    fn session_holds(
        view: &dyn ReadView,
        session: &SessionRecord,
        settings: &SecuritySettings,
        now: Timestamp,
    ) -> Result<(UserRecord, Timestamp), AuthError> {
        let (expires_at, _) = effective_expiry(session, settings);
        if now >= expires_at {
            return Err(AuthError::SessionExpired);
        }
        let (user, _) = Self::holder(view, session.user, Issued::Session(session.generation))?;
        if user.is_service() || (session.break_glass && !user.break_glass) {
            return Err(AuthError::Unauthenticated);
        }
        Ok((user, expires_at))
    }

    /// The account a personal or scoped token acts for at `now` and when the token ends, as
    /// [`AuthService::session_holds`] for sessions. Service accounts act through scoped tokens
    /// only, the break-glass account through none.
    fn token_holds(
        view: &dyn ReadView,
        token: &FoundToken,
        settings: &SecuritySettings,
        now: Timestamp,
    ) -> Result<(UserRecord, Option<Timestamp>), AuthError> {
        let (owner, generation, created_at, expires_at, scoped) = match token {
            FoundToken::Personal(record, _) => (
                record.owner,
                record.generation,
                record.created_at,
                record.expires_at,
                false,
            ),
            FoundToken::Scoped(record, _) => (
                record.owner,
                record.generation,
                record.created_at,
                record.expires_at,
                true,
            ),
        };
        if token_expired(created_at, expires_at, settings, now) {
            return Err(AuthError::SessionExpired);
        }
        let (user, _) = Self::holder(view, owner, Issued::Token(generation))?;
        if user.break_glass || (!scoped && user.is_service()) {
            return Err(AuthError::Unauthenticated);
        }
        Ok((
            user,
            effective_token_expiry(created_at, expires_at, settings),
        ))
    }

    /// The account a session or token acts for, if the credential may still act: the one
    /// place every session and token passes on its way to authenticating. A disabled account
    /// and a credential issued before the last end of the account's access
    /// ([`UserRecord::admits`]) are refused.
    fn holder(
        view: &dyn ReadView,
        owner: UserId,
        issued: Issued,
    ) -> Result<(UserRecord, tenko_core::Revision), AuthError> {
        view.get_typed(&USERS, &owner)?
            .filter(|(user, _)| !user.disabled && user.admits(issued))
            .ok_or(AuthError::Unauthenticated)
    }

    /// The account and the session of a session principal, read again by a handler, with
    /// the session's hash: only while the session still holds ([`AuthService::holder`]),
    /// since an end of the account's access may have come after the request authenticated.
    fn live_session(
        view: &dyn ReadView,
        user: UserId,
        session: SessionId,
    ) -> Result<(UserRecord, tenko_core::Revision, Vec<u8>, SessionRecord), AuthError> {
        let (hash, record) =
            Self::load_session(view, user, session)?.ok_or(AuthError::Unauthenticated)?;
        let (account, revision) = Self::holder(view, user, Issued::Session(record.generation))?;
        Ok((account, revision, hash, record))
    }

    /// The token stored under `hash` and the view it was found in: this controller's copy,
    /// else (a token created on another controller) the leader's commit index, within the
    /// bound of [`AuthService::confirmed_view_for_miss`].
    async fn lookup_token(
        &self,
        hash: &Vec<u8>,
        now: Timestamp,
    ) -> Result<(Option<FoundToken>, Arc<dyn ReadView>), AuthError> {
        let view = self.view().await?;
        let found = Self::find_token(view.as_ref(), hash)?;
        if found.is_some() {
            return Ok((found, view));
        }
        let Some(confirmed) = self.confirmed_view_for_miss(hash, now).await else {
            return Ok((None, view));
        };
        let found = Self::find_token(confirmed.as_ref(), hash)?;
        if found.is_none() {
            self.misses.remember(hash, now);
        }
        Ok((found, confirmed))
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

    /// A view at the commit index of the leader (a read index on a follower) for a secret
    /// this controller's copy does not hold, or `None` when the cluster cannot confirm one
    /// now, when the same secret was refused after such a read a moment ago, or when
    /// [`misses::CONFIRMING`] such reads are already under way. Unknown secrets therefore cost
    /// the leader a bounded number of reads, whatever their rate.
    async fn confirmed_view_for_miss(
        &self,
        hash: &[u8],
        now: Timestamp,
    ) -> Option<Arc<dyn ReadView>> {
        if self.misses.recent(hash, now) {
            return None;
        }
        let _slot = self.misses.confirming()?;
        self.store.read(ReadConsistency::Linearizable).await.ok()
    }

    /// Follows the user records so that an unlock by an administrator on any controller
    /// clears this controller's login throttle for the account (WP3.1b section 7), and an
    /// end of the account's access forgets its known networks: both live in memory per
    /// controller, and both changes are writes of the user record.
    fn spawn_unlock_watch(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = Arc::clone(&self.store);
        let throttle = Arc::clone(&self.throttle);
        let known = Arc::clone(&self.known_networks);
        handle.spawn(unlock_watch(store, throttle, known));
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

/// A session found by its secret: its hash, the record, its revision and the view it was
/// found in.
type FoundSession = (
    Vec<u8>,
    SessionRecord,
    tenko_core::Revision,
    Arc<dyn ReadView>,
);

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

/// What the watch of the user records remembers of an account.
struct Seen {
    name: String,
    unlocked_at: Option<Timestamp>,
    sessions_generation: u64,
}

impl Seen {
    fn of(user: &UserRecord) -> Self {
        Self {
            name: user.name.clone(),
            unlocked_at: user.unlocked_at,
            sessions_generation: user.sessions_generation,
        }
    }
}

/// Clears this controller's memory of an account whose record went from `old` to `new`
/// (`None`: absent, or not seen before): an unlock lifts the throttle, an end of the
/// account's access forgets its known networks, and a rename or a deletion does both for
/// the old name. The one place that clears this memory: the controller that served the
/// change sees it here too.
fn observe(
    throttle: &Throttle,
    known: &guard::KnownNetworks,
    old: Option<&Seen>,
    new: Option<&Seen>,
) {
    match (old, new) {
        (_, Some(new)) => {
            let unseen = Seen {
                name: new.name.clone(),
                unlocked_at: None,
                sessions_generation: 0,
            };
            let old = old.unwrap_or(&unseen);
            if new.unlocked_at.is_some() && new.unlocked_at != old.unlocked_at {
                throttle.unlock_account(&new.name);
            }
            if new.sessions_generation != old.sessions_generation {
                known.forget(&new.name);
            }
            if new.name != old.name {
                throttle.unlock_account(&old.name);
                known.forget(&old.name);
            }
        }
        (Some(old), None) => {
            throttle.unlock_account(&old.name);
            known.forget(&old.name);
        }
        (None, None) => {}
    }
}

/// The loop of [`AuthService::spawn_unlock_watch`]: ends when the store shuts down. After
/// the change stream lags, a scan of every user record applies what the gap held.
async fn unlock_watch(
    store: Arc<dyn Store>,
    throttle: Arc<Throttle>,
    known: Arc<guard::KnownNetworks>,
) {
    let filter = WatchFilter::tables([USERS.name().clone()]);
    let mut seen: HashMap<UserId, Seen> = HashMap::new();
    'watch: loop {
        let mut changes = match store.watch(None, filter.clone()) {
            Ok(changes) => changes,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the watch of user records ended: unlocks and ends of access made elsewhere no longer clear this controller's memory"
                );
                return;
            }
        };
        let scanned = match store.read(ReadConsistency::Local).await {
            Ok(view) => view
                .scan_typed(&USERS, KeyRange::all(), usize::MAX, false)
                .map_err(AuthError::from),
            Err(error) => Err(error.into()),
        };
        match scanned {
            Ok(users) => {
                let mut now: HashMap<UserId, Seen> = HashMap::with_capacity(users.len());
                for (id, user, _) in users {
                    let current = Seen::of(&user);
                    observe(&throttle, &known, seen.get(&id), Some(&current));
                    now.insert(id, current);
                }
                for (id, old) in &seen {
                    if !now.contains_key(id) {
                        observe(&throttle, &known, Some(old), None);
                    }
                }
                seen = now;
            }
            Err(error) => tracing::warn!(%error, "the watch of user records could not scan them"),
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
                    Ok(user) => {
                        let current = user.map(|(user, _)| Seen::of(&user));
                        observe(&throttle, &known, seen.get(&id), current.as_ref());
                        match current {
                            Some(current) => seen.insert(id, current),
                            None => seen.remove(&id),
                        };
                    }
                    // A change it could not read is read again by the scan.
                    Err(error) => {
                        tracing::warn!(%error, "the watch of user records could not read a user");
                        continue 'watch;
                    }
                }
            }
        }
        if let Err(error) = store.read(ReadConsistency::Local).await {
            tracing::warn!(%error, "the watch of user records ended with the store");
            return;
        }
    }
}

fn role_names(roles: &[RoleName]) -> std::collections::BTreeSet<String> {
    roles.iter().map(|role| role.as_str().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use tenko_core::testing::wait_until_async;
    use tenko_store::{ChangeStream, Committed, DerivedIndex, MemStore, StoreStatus, WatchError};
    use tokio::sync::oneshot;

    use super::*;
    use crate::lockout::ThrottleKey;

    /// A store whose first watch lags when the test lets it: what was written before that
    /// reaches the watch only through its scan after the lag.
    struct LaggingStore {
        inner: Arc<MemStore>,
        lag: Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl Store for LaggingStore {
        async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
            self.inner.propose(batch).await
        }

        async fn read(
            &self,
            consistency: ReadConsistency,
        ) -> Result<Arc<dyn ReadView>, StoreError> {
            self.inner.read(consistency).await
        }

        fn watch(
            &self,
            from: Option<tenko_core::Revision>,
            filter: WatchFilter,
        ) -> Result<ChangeStream, StoreError> {
            let lagging = self
                .lag
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            match lagging {
                Some(lagging) => Ok(Box::pin(futures::stream::once(async move {
                    lagging.await.ok();
                    Err(WatchError::Lagged {
                        last: tenko_core::Revision(0),
                    })
                }))),
                None => self.inner.watch(from, filter),
            }
        }

        fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
            self.inner.register_index(index)
        }

        fn status(&self) -> StoreStatus {
            self.inner.status()
        }

        fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
            self.inner.leadership()
        }
    }

    async fn put(store: &MemStore, user: &UserRecord, now: Timestamp) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        batch.put_typed(&USERS, &user.id, user).expect("encode");
        store.propose(batch).await.expect("the user is written");
    }

    /// Another controller's memory of two accounts follows what the user records say: an
    /// unlock written while its watch lagged lifts the lock, and every end of an account's
    /// access forgets that account's known networks, through the lag and after it.
    #[tokio::test]
    async fn the_watch_forgets_known_networks_at_every_end_and_after_a_lag() {
        let now: Timestamp = "2026-11-12T10:00:00Z".parse().expect("a time");
        let later = now
            .checked_add(Duration::from_secs(86_400))
            .expect("a time");
        let network: Option<IpAddr> = Some("198.51.100.7".parse().expect("an address"));
        let inner = Arc::new(MemStore::default());
        let (lag, lagging) = oneshot::channel();
        let store: Arc<dyn Store> = Arc::new(LaggingStore {
            inner: inner.clone(),
            lag: Mutex::new(Some(lagging)),
        });
        let mut ada = UserRecord::new("ada".to_owned(), "Ada".to_owned(), Vec::new(), now);
        let mut bo = UserRecord::new("bo".to_owned(), "Bo".to_owned(), Vec::new(), now);
        put(&inner, &ada, now).await;
        put(&inner, &bo, now).await;
        let throttle = Arc::new(Throttle::new(64));
        let known = Arc::new(guard::KnownNetworks::default());
        throttle.restore_lock(ThrottleKey::account("ada"), later);
        known.note("ada", (ada.id, 0), network, now);
        known.note("bo", (bo.id, 0), network, now);
        // Read through the records as they were before: what is asked is that the watch
        // forgot, not that a later generation refuses the entry.
        let (ada_before, bo_before) = (ada.clone(), bo.clone());
        let watch = tokio::spawn(unlock_watch(store, throttle.clone(), known.clone()));

        // Written while the watch lags: an unlock of one account, a reset of the other.
        ada.unlocked_at = Some(now);
        put(&inner, &ada, now).await;
        bo.sessions_generation = 1;
        put(&inner, &bo, now).await;
        lag.send(()).ok();
        wait_until_async("the scan after the lag applies both changes", || async {
            throttle
                .lock_of(&ThrottleKey::account("ada"), now)
                .is_none()
                && !known.contains(&bo_before, network, now)
        })
        .await;
        assert!(
            known.contains(&ada_before, network, now),
            "only an end of its access forgets an account's networks"
        );

        // Through the change stream: an end of the other account's access.
        ada.sessions_generation = 1;
        put(&inner, &ada, now).await;
        wait_until_async("the end forgets the account's networks", || async {
            !known.contains(&ada_before, network, now)
        })
        .await;
        watch.abort();
    }
}
