//! The end of an account's access (`tenko_auth::service::end`): whichever path ends it (a
//! password change, an administrator's reset, disabling, deleting, signing out everywhere),
//! no session, token, known-device mark or pending second factor issued before it holds
//! afterwards, however many the account holds, also when a sign-in races it or a crash
//! interrupts it. The break-glass designation is proved in `service_flows.rs`, beside the
//! hardware key it needs.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tenko_auth::{
    AuthConfig, AuthError, AuthService, LoginOutcome, NewSession,
    clock::MockClock,
    encoding::base32_decode,
    model::{
        ACCESS_ENDS, KNOWN_DEVICES, SCOPED_TOKENS, SESSIONS, SessionRecord, TOKENS, TokenGrant,
        USER_KNOWN_DEVICES, USER_SCOPED_TOKENS, USER_SESSIONS, USER_TOKENS,
    },
    roles::RoleName,
    service::{
        CodeLogin, PasswordChange, PasswordLogin, TokenRequest, TotpEnrollFinish, UserCreate,
        UserUpdate, types::SecretString,
    },
    settings::Profile,
    testing::TestEnv,
    totp::{self, TotpParams},
};
use tenko_core::{
    AuthStrength, Credentials, Principal, RequestCtx, Revision, SessionId, SystemComponent, UserId,
    testing::wait_until_async,
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, MemStore, Mutation, ReadConsistency, ReadView,
    ReadViewExt, Store, StoreError, StoreStatus, WatchFilter, WriteBatch, tables,
};
use tenko_vault::{MemVault, Vault};
use tokio::sync::Notify;

/// More sessions than a scan of the store read before the end was one operation, and more
/// than one step of the end removes.
const MANY: usize = 10_000;
const NAME: &str = "pelle";
const PIN: &str = "481273";
const NEW_PIN: &str = "720459";

/// The paths that end an account's access, as the API reaches them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    PasswordChange,
    PasswordReset,
    Disable,
    Delete,
    SignOutEverywhere,
}

impl Path {
    const ALL: [Self; 5] = [
        Self::PasswordChange,
        Self::PasswordReset,
        Self::Disable,
        Self::Delete,
        Self::SignOutEverywhere,
    ];

    /// The audit action that records the end.
    fn action(self) -> &'static str {
        match self {
            Self::PasswordChange => "auth.password.change",
            Self::PasswordReset | Self::Disable => "auth.user.update",
            Self::Delete => "auth.user.delete",
            Self::SignOutEverywhere => "auth.session.revoke",
        }
    }
}

/// What gates the proposals of [`HeldStore`].
#[derive(Default)]
struct Gate {
    /// Hold the next proposal that writes a session until [`Gate::release`] is notified.
    hold_session: AtomicBool,
    held: AtomicBool,
    release: Notify,
    /// Refuse every proposal of the service's own (system) writes, as a crash would.
    refuse_system: AtomicBool,
}

/// A store that can hold back a sign-in's write and refuse the service's own steps.
struct HeldStore {
    inner: Arc<MemStore>,
    gate: Arc<Gate>,
}

#[async_trait::async_trait]
impl Store for HeldStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let writes_session = batch.mutations.iter().any(
            |mutation| matches!(mutation, Mutation::Put { table, .. } if table == SESSIONS.name()),
        );
        if writes_session && self.gate.hold_session.swap(false, Ordering::SeqCst) {
            let released = self.gate.release.notified();
            self.gate.held.store(true, Ordering::SeqCst);
            released.await;
        }
        if self.gate.refuse_system.load(Ordering::SeqCst)
            && batch.principal == Principal::system(SystemComponent::Auth)
        {
            return Err(StoreError::Storage("the controller stopped".to_owned()));
        }
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
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

/// An installation whose service writes through a [`HeldStore`]; `env.store` is the store
/// beneath it, for the test's own reads and writes.
async fn held_installation() -> (TestEnv, Arc<Gate>, NewSession) {
    let inner = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(inner.clone()));
    let gate = Arc::new(Gate::default());
    let held: Arc<dyn Store> = Arc::new(HeldStore {
        inner: inner.clone(),
        gate: gate.clone(),
    });
    let dyn_vault: Arc<dyn Vault> = vault.clone();
    let service = AuthService::new(held, dyn_vault, AuthConfig::default())
        .await
        .expect("the service starts");
    let env = TestEnv {
        store: inner,
        vault,
        clock: Arc::new(MockClock::fixed()),
        service,
    };
    let session = env.setup(Profile::Home).await.expect("setup succeeds");
    (env, gate, session)
}

/// The account [`NAME`] with the PIN [`PIN`], an operator whose PIN is accepted.
async fn account(env: &TestEnv, admin: &RequestCtx) -> UserId {
    let user = env
        .service
        .create_user(
            admin,
            &UserCreate {
                name: NAME.to_owned(),
                display_name: None,
                password: Some(SecretString::new(PIN)),
                roles: vec![RoleName::Operator],
                language: None,
            },
        )
        .await
        .expect("the user is created");
    env.accept_password(user.id).await;
    user.id
}

async fn try_login(env: &TestEnv, password: &str) -> Result<LoginOutcome, AuthError> {
    env.service
        .login_password(
            &env.public_ctx(),
            Some("test-agent"),
            &PasswordLogin {
                user_name: NAME.to_owned(),
                password: SecretString::new(password),
                provider: None,
            },
        )
        .await
}

async fn login(env: &TestEnv) -> NewSession {
    match try_login(env, PIN).await.expect("the sign-in succeeds") {
        LoginOutcome::Session(session) => session,
        LoginOutcome::SecondFactor { methods, .. } => {
            panic!("expected a session, got a second-factor challenge {methods:?}")
        }
    }
}

fn of_session(session: &NewSession) -> Credentials {
    Credentials::Session(session.secret.expose().to_owned())
}

/// Whether `credentials` authenticate now.
async fn holds(env: &TestEnv, credentials: &Credentials) -> bool {
    match env
        .service
        .authenticate_credentials(credentials, env.now())
        .await
    {
        Ok(_) => true,
        Err(AuthError::Unauthenticated | AuthError::SessionExpired) => false,
        Err(other) => panic!("authentication failed with {other:?}"),
    }
}

/// Writes `count` sessions of `user` whose ids sort before every generated one, as many
/// sign-ins would leave them. Their secrets are unknown: they take room in every scan.
async fn fill_sessions(env: &TestEnv, user: UserId, count: usize) {
    let now = env.now();
    let until = now.checked_add(Duration::from_secs(3_600)).expect("a time");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
    for n in 0..count {
        let id: SessionId = format!("00000000-0000-0000-0000-{n:012x}")
            .parse()
            .expect("a session id");
        let hash = format!("filler-{n:08}").into_bytes();
        let record = SessionRecord {
            id,
            user,
            strength: AuthStrength::Pin,
            created_at: now,
            authenticated_at: now,
            expires_at: until,
            idle_expires_at: until,
            last_seen_at: now,
            source_ip: None,
            user_agent: None,
            break_glass: false,
            mfa_enrollment_required: false,
            source: tenko_auth::directory::SessionSource::Local,
            directory_checked_at: None,
            generation: 0,
        };
        batch.put_typed(&SESSIONS, &hash, &record).expect("encode");
        batch
            .put_typed(&USER_SESSIONS, &(user, id), &hash)
            .expect("encode");
    }
    env.store
        .propose(batch)
        .await
        .expect("the sessions are written");
}

/// The rows of each kind of credential `user` holds: sessions, personal tokens, scoped
/// tokens and known-device marks, each counted in its index and its records alike.
async fn rows(env: &TestEnv, user: UserId) -> [usize; 4] {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let range = || KeyRange::prefix(tenko_core::codec::encode_key(&(user,)));
    let all = usize::MAX;
    let sessions = view
        .scan_typed(&USER_SESSIONS, range(), all, false)
        .expect("index");
    let tokens = view
        .scan_typed(&USER_TOKENS, range(), all, false)
        .expect("index");
    let scoped = view
        .scan_typed(&USER_SCOPED_TOKENS, range(), all, false)
        .expect("index");
    let devices = view
        .scan_typed(&USER_KNOWN_DEVICES, range(), all, false)
        .expect("index");
    let records = [
        view.scan(SESSIONS.name(), KeyRange::all(), all, false),
        view.scan(TOKENS.name(), KeyRange::all(), all, false),
        view.scan(SCOPED_TOKENS.name(), KeyRange::all(), all, false),
        view.scan(KNOWN_DEVICES.name(), KeyRange::all(), all, false),
    ];
    let index = [sessions.len(), tokens.len(), scoped.len(), devices.len()];
    // The administrator holds one session; nothing else in these tests holds a credential.
    let others = [1, 0, 0, 0];
    for (kind, records) in records.into_iter().enumerate() {
        assert_eq!(
            records.expect("records").len(),
            index[kind] + others[kind],
            "every record of kind {kind} has its index row"
        );
    }
    index
}

async fn access_ends(env: &TestEnv) -> usize {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&ACCESS_ENDS, KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .len()
}

/// The context of the last audit record of `action`.
async fn audit_context(env: &TestEnv, action: &str, key: &str) -> String {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, true)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .find(|record| record.draft.action.as_str() == action)
        .unwrap_or_else(|| panic!("no audit record {action}"))
        .draft
        .details
        .context
        .get(key)
        .unwrap_or_else(|| panic!("{action} names no {key}"))
        .clone()
}

/// A personal and a scoped token of the signed-in account.
async fn tokens(env: &TestEnv, own: &RequestCtx) -> [Credentials; 2] {
    let request = |grants: Option<Vec<TokenGrant>>| TokenRequest {
        name: "automation".to_owned(),
        expires_in_days: Some(30),
        grants,
        scopes: Vec::new(),
    };
    let personal = env
        .service
        .create_token_with(own, &request(None))
        .await
        .expect("a personal token");
    let scoped = env
        .service
        .create_token_with(
            own,
            &request(Some(vec![TokenGrant {
                role: RoleName::Viewer,
                scope: None,
            }])),
        )
        .await
        .expect("a scoped token");
    [personal.token, scoped.token].map(|token| Credentials::Bearer(token.expose().to_owned()))
}

/// Runs `path` against the account, as an administrator or (a password change) as the
/// account itself in `own`.
async fn end(env: &TestEnv, admin: &RequestCtx, own: &RequestCtx, user: UserId, path: Path) {
    let service = &env.service;
    match path {
        Path::PasswordChange => service
            .change_password(
                own,
                &PasswordChange {
                    current_password: Some(SecretString::new(PIN)),
                    new_password: SecretString::new(NEW_PIN),
                    remove_factors: false,
                },
            )
            .await
            .map(drop),
        Path::PasswordReset | Path::Disable => {
            let update = if path == Path::Disable {
                UserUpdate {
                    disabled: Some(true),
                    ..UserUpdate::default()
                }
            } else {
                UserUpdate {
                    password: Some(SecretString::new(NEW_PIN)),
                    ..UserUpdate::default()
                }
            };
            service
                .update_user(admin, user, &update, None)
                .await
                .map(drop)
        }
        Path::Delete => service.delete_user(admin, user).await,
        Path::SignOutEverywhere => service.revoke_user_sessions(admin, user).await.map(drop),
    }
    .unwrap_or_else(|error| panic!("{path:?} failed: {error:?}"));
}

#[tokio::test]
async fn every_path_ends_every_credential_issued_before_it() {
    for path in Path::ALL {
        let (env, setup) = TestEnv::installed(Profile::Home).await;
        let admin = env.session_ctx(&setup).await.expect("a request context");
        let user = account(&env, &admin).await;
        fill_sessions(&env, user, MANY).await;
        let own = login(&env).await;
        let own_ctx = env.session_ctx(&own).await.expect("a request context");
        let [personal, scoped] = tokens(&env, &own_ctx).await;
        // The newest session sorts after every other one: the scan that stopped at 10,000
        // rows never reached it.
        let newest = login(&env).await;
        let [sessions, _, _, devices] = rows(&env, user).await;
        assert_eq!(sessions, MANY + 2);
        assert!(devices > 0, "the sign-ins left known-device marks");

        end(&env, &admin, &own_ctx, user, path).await;

        let keeps_own = path == Path::PasswordChange;
        let keeps_tokens = path == Path::SignOutEverywhere;
        assert!(
            !holds(&env, &of_session(&newest)).await,
            "{path:?}: the newest session"
        );
        assert_eq!(
            holds(&env, &of_session(&own)).await,
            keeps_own,
            "{path:?}: the own session"
        );
        assert_eq!(
            holds(&env, &personal).await,
            keeps_tokens,
            "{path:?}: the personal token"
        );
        assert_eq!(
            holds(&env, &scoped).await,
            keeps_tokens,
            "{path:?}: the scoped token"
        );
        let tokens_left = usize::from(keeps_tokens);
        assert_eq!(
            rows(&env, user).await,
            [usize::from(keeps_own), tokens_left, tokens_left, 0],
            "{path:?}: what is left of sessions, tokens, scoped tokens and marks"
        );
        assert_eq!(
            access_ends(&env).await,
            1,
            "{path:?}: the end waits for the hourly sweep"
        );
        env.service
            .resume_account_ends(env.now())
            .await
            .expect("the hourly sweep");
        assert_eq!(
            access_ends(&env).await,
            0,
            "{path:?}: the hourly sweep is done with it"
        );
        let action = path.action();
        let ended_sessions = sessions - usize::from(keeps_own);
        assert_eq!(
            audit_context(&env, action, "sessions_revoked").await,
            ended_sessions.to_string(),
            "{path:?}"
        );
        assert_eq!(
            audit_context(&env, action, "tokens_revoked").await,
            if keeps_tokens { "0" } else { "2" },
            "{path:?}"
        );
        assert_eq!(
            audit_context(&env, action, "known_devices").await,
            devices.to_string(),
            "{path:?}"
        );
    }
}

#[tokio::test]
async fn a_sign_in_that_races_a_reset_does_not_survive_it() {
    let (env, gate, setup) = held_installation().await;
    let admin = env.session_ctx(&setup).await.expect("a request context");
    let user = account(&env, &admin).await;
    // The sign-in reads the account and checks the PIN before the reset, and its write
    // reaches the store after the reset's.
    gate.hold_session.store(true, Ordering::SeqCst);
    let racing = tokio::spawn({
        let service = env.service.clone();
        let ctx = env.public_ctx();
        async move {
            service
                .login_password(
                    &ctx,
                    Some("test-agent"),
                    &PasswordLogin {
                        user_name: NAME.to_owned(),
                        password: SecretString::new(PIN),
                        provider: None,
                    },
                )
                .await
        }
    });
    wait_until_async("the sign-in's write is held", || async {
        gate.held.load(Ordering::SeqCst)
    })
    .await;
    env.service
        .update_user(
            &admin,
            user,
            &UserUpdate {
                password: Some(SecretString::new(NEW_PIN)),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("the reset");
    gate.release.notify_one();
    let Ok(Ok(LoginOutcome::Session(late))) = racing.await else {
        panic!("the sign-in completes after the reset");
    };
    assert!(
        !holds(&env, &of_session(&late)).await,
        "the session written after the reset survived it"
    );
    // The hourly sweep removes what the racing sign-in wrote after the end.
    env.service
        .resume_account_ends(env.now())
        .await
        .expect("the hourly sweep");
    assert_eq!(rows(&env, user).await, [0, 0, 0, 0]);
}

/// A request that authenticated before an end and acts after it: the handler reads the
/// session again and finds it ended, so the session cannot mint a token or keep itself
/// through a password change. The session lies beyond the first step and the steps after it
/// fail, so its row is still there.
#[tokio::test]
async fn a_session_that_authenticated_before_an_end_acts_no_more_after_it() {
    for path in [Path::PasswordReset, Path::SignOutEverywhere] {
        let (env, gate, setup) = held_installation().await;
        let admin = env.session_ctx(&setup).await.expect("a request context");
        let user = account(&env, &admin).await;
        fill_sessions(&env, user, MANY).await;
        let newest = env
            .session_ctx(&login(&env).await)
            .await
            .expect("a request context");
        gate.refuse_system.store(true, Ordering::SeqCst);
        end(&env, &admin, &admin, user, path).await;
        assert_eq!(
            env.service
                .create_token_with(
                    &newest,
                    &TokenRequest {
                        name: "late".to_owned(),
                        expires_in_days: Some(30),
                        grants: None,
                        scopes: Vec::new(),
                    },
                )
                .await
                .map(drop),
            Err(AuthError::Unauthenticated),
            "{path:?}: an ended session made a token"
        );
        assert_eq!(
            env.service
                .change_password(
                    &newest,
                    &PasswordChange {
                        current_password: Some(SecretString::new(if path == Path::PasswordReset {
                            NEW_PIN
                        } else {
                            PIN
                        })),
                        new_password: SecretString::new("593017"),
                        remove_factors: false,
                    },
                )
                .await
                .map(drop),
            Err(AuthError::Unauthenticated),
            "{path:?}: an ended session changed the password"
        );
    }
}

#[tokio::test]
async fn an_end_a_crash_interrupts_is_finished_by_the_hourly_sweep() {
    let (env, gate, setup) = held_installation().await;
    let admin = env.session_ctx(&setup).await.expect("a request context");
    let user = account(&env, &admin).await;
    fill_sessions(&env, user, MANY).await;
    let newest = login(&env).await;
    // The reset's own write commits; every step after it fails.
    gate.refuse_system.store(true, Ordering::SeqCst);
    env.service
        .update_user(
            &admin,
            user,
            &UserUpdate {
                disabled: Some(true),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("the account is disabled");
    assert!(!holds(&env, &of_session(&newest)).await);
    assert!(rows(&env, user).await[0] > 0, "rows are left");
    assert_eq!(access_ends(&env).await, 1, "the unfinished end is recorded");

    // Another controller, or this one after a restart, runs the hourly sweep.
    gate.refuse_system.store(false, Ordering::SeqCst);
    let restarted = AuthService::new(
        env.store.clone(),
        env.vault.clone() as Arc<dyn Vault>,
        AuthConfig::default(),
    )
    .await
    .expect("the service starts");
    let removed = restarted
        .resume_account_ends(env.now())
        .await
        .expect("the sweep");
    assert!(removed > 0);
    assert_eq!(rows(&env, user).await, [0, 0, 0, 0]);
    assert_eq!(access_ends(&env).await, 0);
    // A repeated sweep finds nothing left to do.
    assert_eq!(
        restarted
            .resume_account_ends(env.now())
            .await
            .expect("the sweep"),
        0
    );
}

#[tokio::test]
async fn a_second_factor_opened_before_a_reset_does_not_finish_after_it() {
    let (env, setup) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&setup).await.expect("a request context");
    let user = account(&env, &admin).await;
    let own = env
        .session_ctx(&login(&env).await)
        .await
        .expect("a request context");
    let start = env
        .service
        .totp_enroll_start(&own)
        .await
        .expect("enrollment starts");
    let seed = base32_decode(start.secret.expose()).expect("a base32 seed");
    let code_now = |env: &TestEnv| {
        let seconds = u64::try_from(env.now().0.unix_timestamp()).expect("after the epoch");
        SecretString::new(totp::code_at(&seed, &TotpParams::default(), seconds).as_str())
    };
    env.service
        .totp_enroll_finish(
            &own,
            &TotpEnrollFinish {
                enrollment_id: start.enrollment_id,
                code: code_now(&env),
            },
        )
        .await
        .expect("enrollment finishes");
    env.clock.advance(Duration::from_secs(60));
    let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) = try_login(&env, PIN).await else {
        panic!("the PIN opens a second-factor challenge");
    };
    env.service
        .update_user(
            &admin,
            user,
            &UserUpdate {
                password: Some(SecretString::new(NEW_PIN)),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("the reset");
    assert_eq!(
        env.service
            .login_totp(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id,
                    code: code_now(&env),
                },
            )
            .await
            .map(drop),
        Err(AuthError::ChallengeInvalid),
        "the old PIN's challenge finished after the reset"
    );
}
