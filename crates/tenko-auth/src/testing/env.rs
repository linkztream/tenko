//! A ready-made test environment: a [`MemStore`], a [`MemVault`] on the same store, a
//! [`MockClock`] and an [`AuthService`], optionally already set up with an administrator.

use std::{net::IpAddr, sync::Arc};

use tenko_core::{Credentials, RequestCtx, SystemComponent, Timestamp};
use tenko_store::MemStore;
use tenko_vault::{MemVault, Vault};

use crate::{
    clock::{Clock, MockClock},
    error::AuthError,
    service::{AuthConfig, AuthService, NewSession, SetupAdmin, SetupRequest, types::SecretString},
    settings::Profile,
};

/// The host name of test installations.
pub const HOST: &str = "tenko.example.test";
/// The origin of test installations.
pub const ORIGIN: &str = "https://tenko.example.test";
/// The first administrator's name.
pub const ADMIN: &str = "admin";
/// A fake passphrase that passes every preset except PIN (16+ characters, no context
/// words).
pub const ADMIN_PASSWORD: &str = "plover quartz mitten ember";
/// A fake PIN for the PIN preset.
pub const ADMIN_PIN: &str = "4812";
/// The client address of test requests.
pub const CLIENT: &str = "192.0.2.10";

/// A test environment.
pub struct TestEnv {
    /// The store.
    pub store: Arc<MemStore>,
    /// The vault over the same store.
    pub vault: Arc<MemVault>,
    /// The clock that drives request times.
    pub clock: Arc<MockClock>,
    /// The service.
    pub service: Arc<AuthService>,
}

impl std::fmt::Debug for TestEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestEnv").finish_non_exhaustive()
    }
}

impl TestEnv {
    /// A fresh installation before setup.
    ///
    /// # Panics
    ///
    /// If the service cannot start, which is a broken test environment.
    pub async fn new() -> Self {
        Self::with_config(AuthConfig::default()).await
    }

    /// A fresh installation with a configuration.
    ///
    /// # Panics
    ///
    /// If the service cannot start.
    pub async fn with_config(config: AuthConfig) -> Self {
        let store = Arc::new(MemStore::default());
        let vault = Arc::new(MemVault::with_store(store.clone()));
        let dyn_vault: Arc<dyn Vault> = vault.clone();
        let service = AuthService::new(store.clone(), dyn_vault, config)
            .await
            .expect("the service starts");
        Self {
            store,
            vault,
            clock: Arc::new(MockClock::fixed()),
            service,
        }
    }

    /// An installation set up under `profile` with the administrator [`ADMIN`] (password
    /// [`ADMIN_PASSWORD`], or [`ADMIN_PIN`] under a PIN preset), and its first session.
    ///
    /// # Panics
    ///
    /// If setup fails.
    pub async fn installed(profile: Profile) -> (Self, NewSession) {
        let env = Self::new().await;
        let session = env.setup(profile).await.expect("setup succeeds");
        (env, session)
    }

    /// Runs first-run setup.
    ///
    /// # Errors
    ///
    /// The error of [`AuthService::complete_setup`].
    ///
    /// # Panics
    ///
    /// If setup was already closed before the call.
    pub async fn setup(&self, profile: Profile) -> Result<NewSession, AuthError> {
        let token = self.service.prepare_setup().await?.expect("setup is open");
        let password = if profile.defaults().password_policy.is_pin() {
            ADMIN_PIN
        } else {
            ADMIN_PASSWORD
        };
        self.service
            .complete_setup(
                &self.public_ctx(),
                Some("test-agent"),
                &SetupRequest {
                    setup_token: SecretString::new(token.expose()),
                    profile,
                    admin: SetupAdmin {
                        name: ADMIN.to_owned(),
                        display_name: Some("Test Administrator".to_owned()),
                        password: SecretString::new(password),
                    },
                    host_name: HOST.to_owned(),
                    language: "en".to_owned(),
                },
            )
            .await
    }

    /// The current time.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn client() -> IpAddr {
        CLIENT.parse().unwrap_or(IpAddr::from([192, 0, 2, 10]))
    }

    /// The context of an unauthenticated request (login, setup).
    pub fn public_ctx(&self) -> RequestCtx {
        RequestCtx::system(SystemComponent::Api)
            .at(self.now())
            .with_source_ip(Self::client())
    }

    /// The context of a request carrying `credentials`, as the API would build it.
    ///
    /// # Errors
    ///
    /// The authentication error.
    pub async fn ctx_for(&self, credentials: &Credentials) -> Result<RequestCtx, AuthError> {
        let authenticated = self
            .service
            .authenticate_credentials(credentials, self.now())
            .await?;
        Ok(RequestCtx::new(authenticated.principal)
            .at(self.now())
            .with_source_ip(Self::client()))
    }

    /// The context of a request on `session`.
    ///
    /// # Errors
    ///
    /// The authentication error.
    pub async fn session_ctx(&self, session: &NewSession) -> Result<RequestCtx, AuthError> {
        self.ctx_for(&Credentials::Session(session.secret.expose().to_owned()))
            .await
    }
}
