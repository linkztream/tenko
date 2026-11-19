//! Tokens bound to a certificate lineage (ADR 0035, IAM-23): bound at creation to an active
//! lineage of the service account, accepted only with a certificate of that lineage, refused
//! and audited without one, never revoking anything then; a bound family renews bound; its
//! reuse revokes the lineage; a revoked or lapsed lineage takes its tokens; tightening TGL-47
//! removes the unbound tokens of service accounts.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tenko_auth::{
    AuthError,
    client_cert::{
        ClientCertError, ClientCerts, Issued, Issuer,
        model::{CLIENT_CERTS, CertState, ClientCertRecord, IntegrationPolicy},
    },
    model::{SCOPED_TOKENS, TokenScope, USER_SCOPED_TOKENS},
    roles::RoleName,
    secret::BOUND_PREFIX,
    service::{
        CreatedToken, ServiceAccountCreate, TokenRenew, TokenRequest, UserInfo, types::SecretString,
    },
    settings::{Profile, SettingsPatch},
    testing::TestEnv,
};
use tenko_core::{
    Credentials, Principal, RequestCtx, SystemComponent, Timestamp, UserId, audit::AuditOutcome,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};
use tenko_vault::Vault;
use uuid::Uuid;

/// The certificate authority is not exercised here: lineages are written as records.
struct NoIssuer;

#[async_trait]
impl Issuer for NoIssuer {
    fn request_key(&self, _: &[u8]) -> Result<Vec<u8>, ClientCertError> {
        Err(ClientCertError::Conflict)
    }
    async fn ensure_root(&self, _: &RequestCtx) -> Result<(), ClientCertError> {
        Ok(())
    }
    async fn issue(
        &self,
        _: &RequestCtx,
        _: UserId,
        _: &[u8],
        _: u32,
    ) -> Result<Issued, ClientCertError> {
        Err(ClientCertError::Conflict)
    }
    fn server_root_sha256(&self) -> String {
        String::new()
    }
    fn server_root_pem(&self) -> String {
        String::new()
    }
}

struct Fixture {
    env: TestEnv,
    admin: RequestCtx,
    account: UserInfo,
    lineage: Uuid,
    certs: ClientCerts,
}

async fn fixture() -> Fixture {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&session).await.expect("the admin's ctx");
    let account = service_account(&env, &admin, "backup").await;
    let vault: Arc<dyn Vault> = env.vault.clone();
    let certs = ClientCerts::new(env.store.clone(), vault, Arc::new(NoIssuer));
    let fx = Fixture {
        lineage: Uuid::now_v7(),
        env,
        admin,
        account,
        certs,
    };
    fx.put_cert(fx.account.id, fx.lineage, CertState::Current, 30)
        .await;
    fx
}

async fn service_account(env: &TestEnv, admin: &RequestCtx, name: &str) -> UserInfo {
    env.service
        .create_service_account(
            admin,
            &ServiceAccountCreate {
                name: name.to_owned(),
                display_name: None,
                roles: vec![RoleName::Viewer],
            },
        )
        .await
        .expect("a service account")
}

impl Fixture {
    /// A certificate of `lineage` for `account`, valid for `days` from an hour ago.
    async fn put_cert(&self, account: UserId, lineage: Uuid, state: CertState, days: u64) {
        let now = self.env.now();
        let serial = format!("{:032x}", Uuid::now_v7().as_u128());
        let record = ClientCertRecord {
            serial: serial.clone(),
            account,
            generation: 0,
            lineage,
            label: "host".to_owned(),
            key_sha256: "00".repeat(32),
            not_before: Timestamp(now.0 - Duration::from_secs(3600)),
            not_after: Timestamp(now.0 + Duration::from_secs(days * 86_400)),
            issued_at: now,
            state,
            presented_at: None,
            ended_at: None,
            reason: None,
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        batch
            .put_typed(&CLIENT_CERTS, &serial, &record)
            .expect("encodes");
        self.env.store.propose(batch).await.expect("written");
    }

    async fn create(
        &self,
        account: UserId,
        request: TokenRequest,
    ) -> Result<CreatedToken, AuthError> {
        self.env
            .service
            .create_account_token(&self.admin, account, &request)
            .await
    }

    async fn bound(&self, renewable: bool) -> CreatedToken {
        self.create(
            self.account.id,
            TokenRequest {
                name: "backup".to_owned(),
                scopes: vec![TokenScope::Metrics],
                renewable,
                expires_in_days: Some(30),
                lineage: Some(self.lineage),
                ..TokenRequest::default()
            },
        )
        .await
        .expect("a bound token")
    }

    async fn unbound(&self, account: UserId) -> Result<CreatedToken, AuthError> {
        self.create(
            account,
            TokenRequest {
                name: "plain".to_owned(),
                scopes: vec![TokenScope::Metrics],
                ..TokenRequest::default()
            },
        )
        .await
    }

    async fn present(
        &self,
        token: &CreatedToken,
        lineage: Option<Uuid>,
    ) -> Result<RequestCtx, AuthError> {
        let token = token.token.expose().to_owned();
        let credentials = match lineage {
            Some(lineage) => Credentials::CertifiedBearer { token, lineage },
            None => Credentials::Bearer(token),
        };
        self.env.ctx_for(&credentials).await
    }

    async fn renew(
        &self,
        token: &CreatedToken,
        lineage: Option<Uuid>,
    ) -> Result<CreatedToken, AuthError> {
        let ctx = self.present(token, lineage).await?;
        let secret = token
            .renewal_secret
            .as_ref()
            .expect("renewable")
            .expose()
            .to_owned();
        self.env
            .service
            .renew_own_token(
                &ctx,
                &TokenRenew {
                    renewal_secret: SecretString::new(&secret),
                },
            )
            .await
    }

    async fn audited(&self, action: &str) -> Vec<AuditOutcome> {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
            .expect("audit")
            .into_iter()
            .filter(|(_, record, _)| record.draft.action.as_str() == action)
            .map(|(_, record, _)| record.draft.outcome)
            .collect()
    }

    async fn token_count(&self, account: UserId) -> usize {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view");
        view.scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(account,))),
            1000,
            false,
        )
        .expect("scan")
        .len()
    }

    async fn cert_states(&self) -> Vec<CertState> {
        self.certs
            .list(Some(self.account.id))
            .await
            .expect("list")
            .into_iter()
            .map(|c| c.state)
            .collect()
    }

    async fn failures(&self, token: &CreatedToken) -> u64 {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view");
        let (key, _) = view
            .get_typed(&USER_SCOPED_TOKENS, &(self.account.id, token.info.id))
            .expect("index")
            .expect("indexed");
        let (record, _) = view
            .get_typed(&SCOPED_TOKENS, &key)
            .expect("record")
            .expect("stored");
        record.renewal.expect("renewable").failures
    }
}

fn invalid_lineage<T>(result: &Result<T, AuthError>) -> bool {
    matches!(result, Err(AuthError::Invalid { field, .. }) if *field == "lineage")
}

#[tokio::test]
async fn a_token_binds_at_creation_to_an_active_lineage_of_its_own_account() {
    let fx = fixture().await;
    let token = fx.bound(false).await;
    assert!(token.token.expose().starts_with(BOUND_PREFIX));
    assert_eq!(token.info.lineage, Some(fx.lineage));

    let request = |lineage| TokenRequest {
        name: "x".to_owned(),
        scopes: vec![TokenScope::Metrics],
        lineage: Some(lineage),
        ..TokenRequest::default()
    };
    // An unknown lineage, another account's, and a revoked one.
    assert!(invalid_lineage(
        &fx.create(fx.account.id, request(Uuid::now_v7())).await
    ));
    let other = service_account(&fx.env, &fx.admin, "other").await;
    let foreign = Uuid::now_v7();
    fx.put_cert(other.id, foreign, CertState::Current, 30).await;
    assert!(invalid_lineage(
        &fx.create(fx.account.id, request(foreign)).await
    ));
    let revoked = Uuid::now_v7();
    fx.put_cert(fx.account.id, revoked, CertState::Revoked, 30)
        .await;
    assert!(invalid_lineage(
        &fx.create(fx.account.id, request(revoked)).await
    ));
}

#[tokio::test]
async fn a_bound_token_passes_only_with_a_certificate_of_its_lineage() {
    let fx = fixture().await;
    let token = fx.bound(false).await;
    fx.present(&token, Some(fx.lineage))
        .await
        .expect("with its certificate");
    for lineage in [None, Some(Uuid::now_v7())] {
        assert!(matches!(
            fx.present(&token, lineage).await,
            Err(AuthError::Unauthenticated)
        ));
    }
    // Refusals of one token are audited once per throttle window.
    assert_eq!(
        fx.audited("auth.token.binding_refused").await,
        [AuditOutcome::Denied]
    );
    // An unbound token of the account still passes on its own.
    let plain = fx.unbound(fx.account.id).await.expect("unbound");
    fx.present(&plain, None)
        .await
        .expect("unbound, without a certificate");
}

#[tokio::test]
async fn without_its_certificate_a_bound_token_revokes_nothing_and_its_family_renews_bound() {
    let fx = fixture().await;
    let first = fx.bound(true).await;
    // A renewal without the certificate never reaches the renewal secret.
    assert!(matches!(
        fx.renew(&first, None).await,
        Err(AuthError::Unauthenticated)
    ));
    assert_eq!(fx.failures(&first).await, 0);

    let second = fx
        .renew(&first, Some(fx.lineage))
        .await
        .expect("renewed with the key");
    assert!(second.token.expose().starts_with(BOUND_PREFIX));
    assert_eq!(second.info.lineage, Some(fx.lineage));
    fx.present(&second, Some(fx.lineage))
        .await
        .expect("the successor's first use");
    fx.env.clock.advance(Duration::from_secs(61));

    // The superseded token found in a log, presented without the key: refused, nothing more.
    assert!(matches!(
        fx.present(&first, None).await,
        Err(AuthError::Unauthenticated)
    ));
    fx.present(&second, Some(fx.lineage))
        .await
        .expect("the family stands");
    assert_eq!(fx.cert_states().await, [CertState::Current]);

    // Presented with the key: someone else holds it. The family and the lineage end.
    assert!(matches!(
        fx.present(&first, Some(fx.lineage)).await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        fx.present(&second, Some(fx.lineage)).await,
        Err(AuthError::Unauthenticated)
    ));
    assert_eq!(fx.cert_states().await, [CertState::Revoked]);
}

#[tokio::test]
async fn a_revoked_or_lapsed_lineage_takes_its_tokens() {
    let fx = fixture().await;
    let token = fx.bound(false).await;
    let plain = fx.unbound(fx.account.id).await.expect("unbound");
    let serial = fx.certs.list(Some(fx.account.id)).await.expect("list")[0]
        .serial
        .clone();
    fx.certs
        .revoke(&fx.admin, &serial, "test")
        .await
        .expect("revoked");
    assert!(matches!(
        fx.present(&token, Some(fx.lineage)).await,
        Err(AuthError::Unauthenticated)
    ));
    fx.present(&plain, None)
        .await
        .expect("an unbound token stays");
    assert_eq!(fx.token_count(fx.account.id).await, 1);

    let lapsing = Uuid::now_v7();
    fx.put_cert(fx.account.id, lapsing, CertState::Current, 2)
        .await;
    let bound = fx
        .create(
            fx.account.id,
            TokenRequest {
                name: "lapsing".to_owned(),
                scopes: vec![TokenScope::Metrics],
                lineage: Some(lapsing),
                ..TokenRequest::default()
            },
        )
        .await
        .expect("bound");
    assert_eq!(
        fx.certs
            .remove_lapsed_tokens(fx.env.now())
            .await
            .expect("sweep"),
        0
    );
    fx.env.clock.advance(Duration::from_secs(3 * 86_400));
    assert_eq!(
        fx.certs
            .remove_lapsed_tokens(fx.env.now())
            .await
            .expect("sweep"),
        1
    );
    assert!(matches!(
        fx.present(&bound, Some(lapsing)).await,
        Err(AuthError::Unauthenticated)
    ));
    assert_eq!(
        fx.audited("auth.client_cert.lapse").await,
        [AuditOutcome::Success]
    );
}

#[tokio::test]
async fn requiring_binding_removes_unbound_service_tokens_and_refuses_new_ones() {
    let fx = fixture().await;
    let bound = fx.bound(false).await;
    let plain = fx.unbound(fx.account.id).await.expect("unbound");
    let require = |require_binding| SettingsPatch {
        integrations: Some(IntegrationPolicy {
            require_binding,
            ..IntegrationPolicy::of(Profile::Home)
        }),
        ..SettingsPatch::default()
    };
    fx.env
        .service
        .update_security_settings(&fx.admin, &require(true), None)
        .await
        .expect("tightened");
    assert!(matches!(
        fx.present(&plain, None).await,
        Err(AuthError::Unauthenticated)
    ));
    fx.present(&bound, Some(fx.lineage))
        .await
        .expect("a bound token stays");
    assert!(invalid_lineage(&fx.unbound(fx.account.id).await));
    // Loosening again revives nothing.
    fx.env
        .service
        .update_security_settings(&fx.admin, &require(false), None)
        .await
        .expect("loosened");
    assert!(matches!(
        fx.present(&plain, None).await,
        Err(AuthError::Unauthenticated)
    ));
    fx.unbound(fx.account.id)
        .await
        .expect("unbound tokens again");
}

#[tokio::test]
async fn hardened_refuses_tls_1_2_on_the_integration_listener() {
    let fx = fixture().await;
    let patch = |profile, allow_tls12| SettingsPatch {
        profile,
        integrations: Some(IntegrationPolicy {
            allow_tls12,
            ..IntegrationPolicy::of(Profile::Home)
        }),
        ..SettingsPatch::default()
    };
    let refused = fx
        .env
        .service
        .update_security_settings(&fx.admin, &patch(Some(Profile::Hardened), true), None)
        .await;
    assert!(matches!(refused, Err(AuthError::Invalid { field, .. }) if field == "integrations"));
    fx.env
        .service
        .update_security_settings(&fx.admin, &patch(None, true), None)
        .await
        .expect("allowed outside Hardened");
    let settings = fx.env.service.settings();
    assert!(settings.integrations().allow_tls12);
    let toggle = settings
        .toggles()
        .into_iter()
        .find(|toggle| toggle.id == "TGL-47")
        .expect("TGL-47");
    assert!(toggle.weaker_than_home, "TLS 1.2 is weaker than Home");
}
