//! Self-renewal of service-account tokens (IAM-20, TGL-46) and source binding of scoped
//! tokens (IAM-21): renewal, the old token's grace, the replaced successor, reuse detection
//! of tokens and renewal secrets, wrong secrets, the lifetime cap, the source prefixes, the
//! token's own description, the expiry warning, and the token form that keeps a constrained
//! token away from a build that does not know its constraints.

use std::{net::IpAddr, time::Duration};

use tenko_auth::{
    AuthError,
    model::TokenScope,
    model::{SCOPED_TOKENS, ScopedTokenRecord, USER_SCOPED_TOKENS},
    roles::RoleName,
    secret::{CONSTRAINED_PREFIX, RENEWAL_PREFIX, TOKEN_PREFIX},
    service::{
        CreatedToken, ServiceAccountCreate, TOKEN_EXPIRING, TOKEN_REVOKED, TokenRenew,
        TokenRequest, UserInfo, UserUpdate, types::SecretString,
    },
    settings::{Profile, SettingsPatch},
    testing::TestEnv,
};
use tenko_core::{Credentials, Principal, RequestCtx, SystemComponent, audit::AuditOutcome};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};

const DAY: u64 = 86_400;

struct Fixture {
    env: TestEnv,
    admin: RequestCtx,
    account: UserInfo,
}

async fn fixture() -> Fixture {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&session).await.expect("the admin's ctx");
    let account = env
        .service
        .create_service_account(
            &admin,
            &ServiceAccountCreate {
                name: "dhcp-report".to_owned(),
                display_name: None,
                roles: vec![RoleName::Viewer],
            },
        )
        .await
        .expect("a service account");
    Fixture {
        env,
        admin,
        account,
    }
}

impl Fixture {
    async fn token(&self, renewable: bool, source_prefixes: &[&str]) -> CreatedToken {
        self.try_token(renewable, source_prefixes)
            .await
            .expect("a token")
    }

    async fn try_token(
        &self,
        renewable: bool,
        source_prefixes: &[&str],
    ) -> Result<CreatedToken, AuthError> {
        self.create(TokenRequest {
            name: "dhcp-report".to_owned(),
            scopes: vec![TokenScope::Metrics],
            renewable,
            source_prefixes: source_prefixes.iter().map(|p| (*p).to_owned()).collect(),
            ..TokenRequest::default()
        })
        .await
    }

    async fn create(&self, request: TokenRequest) -> Result<CreatedToken, AuthError> {
        self.env
            .service
            .create_account_token(&self.admin, self.account.id, &request)
            .await
    }

    /// The ctx of a request with `token`: authenticating it is a use.
    async fn use_token(&self, token: &CreatedToken) -> Result<RequestCtx, AuthError> {
        self.env.ctx_for(&bearer(token)).await
    }

    async fn renew(&self, token: &CreatedToken, secret: &str) -> Result<CreatedToken, AuthError> {
        let ctx = self.use_token(token).await?;
        self.env
            .service
            .renew_own_token(
                &ctx,
                &TokenRenew {
                    renewal_secret: SecretString::new(secret),
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

    /// The token warnings after a sweep at the current time.
    async fn warnings(&self) -> Vec<String> {
        self.env
            .service
            .refresh_token_warnings(self.env.now())
            .await
            .expect("the sweep");
        self.env
            .service
            .token_warnings()
            .into_iter()
            .map(|warning| warning.code.into_owned())
            .collect()
    }

    async fn listed(&self) -> Vec<tenko_auth::service::TokenInfo> {
        self.env
            .service
            .list_account_tokens(&self.admin, self.account.id)
            .await
            .expect("the list")
    }
}

/// Changes the stored record of `token` in place, as a tampered or foreign write would.
async fn rewrite(fx: &Fixture, token: &CreatedToken, change: impl FnOnce(&mut ScopedTokenRecord)) {
    let view = fx
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let (key, _) = view
        .get_typed(&USER_SCOPED_TOKENS, &(fx.account.id, token.info.id))
        .expect("index")
        .expect("indexed");
    let (mut record, _) = view
        .get_typed(&SCOPED_TOKENS, &key)
        .expect("record")
        .expect("stored");
    change(&mut record);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), fx.env.now());
    batch
        .put_typed(&SCOPED_TOKENS, &key, &record)
        .expect("encodes");
    fx.env.store.propose(batch).await.expect("written");
}

fn bearer(created: &CreatedToken) -> Credentials {
    Credentials::Bearer(created.token.expose().to_owned())
}

fn secret(created: &CreatedToken) -> String {
    created
        .renewal_secret
        .as_ref()
        .expect("a renewal secret")
        .expose()
        .to_owned()
}

fn unauthenticated<T>(result: &Result<T, AuthError>) -> bool {
    matches!(result, Err(AuthError::Unauthenticated))
}

fn refused<T>(result: &Result<T, AuthError>, why: &str) -> bool {
    matches!(result, Err(AuthError::TokenRenewalRefused { reason }) if *reason == why)
}

/// IAM-20: a renewal answers a new token and a new renewal secret that work, with the
/// profile's lifetime counted from the renewal and never more; it is audited.
#[tokio::test]
async fn a_renewal_returns_a_working_token_and_secret_within_the_cap() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    assert!(secret(&first).starts_with(RENEWAL_PREFIX));
    assert!(first.info.renewable);
    fx.env.clock.advance(Duration::from_secs(300 * DAY));
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    assert_ne!(second.token.expose(), first.token.expose());
    assert_ne!(secret(&second), secret(&first));
    assert_eq!(second.info.name, first.info.name);
    assert_eq!(second.info.scopes, first.info.scopes);
    assert_eq!(second.info.renewed_at, Some(fx.env.now()));
    let cap = fx.env.now().checked_add(Duration::from_secs(365 * DAY));
    assert_eq!(
        second.info.expires_at, cap,
        "Home's 365 days from the renewal"
    );
    fx.use_token(&second).await.expect("the new token works");
    let third = fx
        .renew(&second, &secret(&second))
        .await
        .expect("renewed again");
    fx.use_token(&third).await.expect("and its successor too");
    assert_eq!(fx.audited("auth.token.renew").await.len(), 2);
}

/// IAM-20: the old token works until the new one is first used, and not after; renewing
/// again with the old token meanwhile replaces the unused successor.
#[tokio::test]
async fn the_old_token_works_until_the_new_one_is_used_and_an_unused_one_is_replaced() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let lost = fx.renew(&first, &secret(&first)).await.expect("renewed");
    fx.use_token(&first)
        .await
        .expect("the old token still works");
    let second = fx
        .renew(&first, &secret(&first))
        .await
        .expect("renewed again");
    assert_ne!(lost.info.id, second.info.id);
    fx.use_token(&first)
        .await
        .expect("the old token works until then");
    fx.use_token(&second).await.expect("the new token works");
    assert_eq!(fx.listed().await.len(), 1, "only the new token is listed");
    assert!(
        unauthenticated(&fx.use_token(&first).await),
        "the superseded token is refused"
    );
}

/// IAM-20: a superseded token used again revokes the whole family, is audited, shows as
/// revoked with its reason and raises the warning until the administrator removes it.
#[tokio::test]
async fn reuse_of_a_superseded_token_revokes_the_family() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    fx.use_token(&second)
        .await
        .expect("the first use supersedes");
    // Within a minute the old token is refused without revoking: requests sent before the
    // integration switched may still arrive.
    assert!(unauthenticated(&fx.use_token(&first).await));
    fx.use_token(&second).await.expect("the family stands");
    fx.env.clock.advance(Duration::from_secs(61));
    assert!(unauthenticated(&fx.use_token(&first).await));
    assert!(
        unauthenticated(&fx.use_token(&second).await),
        "the whole family is revoked"
    );
    assert_eq!(
        fx.audited("auth.token.reuse_detected").await,
        [AuditOutcome::Denied]
    );
    let listed = fx.listed().await;
    assert_eq!(listed.len(), 1);
    let revoked = listed[0].revoked.expect("shown as revoked");
    assert_eq!(
        serde_json::to_value(revoked.reason).expect("json"),
        "reuse_detected"
    );
    assert_eq!(fx.warnings().await, [TOKEN_REVOKED]);
    fx.env
        .service
        .revoke_account_token(&fx.admin, fx.account.id, listed[0].id)
        .await
        .expect("removed");
    assert_eq!(fx.listed().await.len(), 0);
    assert_eq!(
        fx.warnings().await,
        Vec::<String>::new(),
        "the removal acknowledges it"
    );
}

/// IAM-20: a superseded renewal secret presented with the current token revokes the family.
#[tokio::test]
async fn reuse_of_a_superseded_renewal_secret_revokes_the_family() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    fx.use_token(&second)
        .await
        .expect("the first use supersedes");
    assert!(unauthenticated(&fx.renew(&second, &secret(&first)).await));
    assert!(unauthenticated(&fx.use_token(&second).await));
    assert_eq!(fx.audited("auth.token.reuse_detected").await.len(), 1);
}

/// IAM-20: a wrong renewal secret fails and is audited; the third revokes the family.
#[tokio::test]
async fn wrong_renewal_secrets_fail_are_audited_and_the_third_revokes() {
    let fx = fixture().await;
    let token = fx.token(true, &[]).await;
    let wrong = format!("{RENEWAL_PREFIX}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    for _ in 0..2 {
        assert!(refused(&fx.renew(&token, &wrong).await, "wrong_secret"));
        fx.use_token(&token).await.expect("the token still works");
    }
    assert_eq!(fx.audited("auth.token.renew").await.len(), 2);
    assert!(refused(&fx.renew(&token, &wrong).await, "wrong_secret"));
    assert!(unauthenticated(&fx.use_token(&token).await));
    assert_eq!(fx.audited("auth.token.reuse_detected").await.len(), 1);
    let listed = fx.listed().await;
    assert_eq!(
        serde_json::to_value(listed[0].revoked.expect("revoked").reason).expect("json"),
        "renewal_failures"
    );
}

/// IAM-20, TGL-46: a token without the right and any token under TGL-46 off never renew;
/// a person's token never gets the right.
#[tokio::test]
async fn without_the_right_or_under_tgl_46_off_no_token_renews() {
    let fx = fixture().await;
    let plain = fx.token(false, &[]).await;
    assert!(plain.renewal_secret.is_none());
    assert!(refused(&fx.renew(&plain, "tnr_x").await, "not_renewable"));
    let renewable = fx.token(true, &[]).await;
    fx.env
        .service
        .update_security_settings(
            &fx.admin,
            &SettingsPatch {
                token_self_renewal: Some(false),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("TGL-46 off");
    assert!(refused(
        &fx.renew(&renewable, &secret(&renewable)).await,
        "disabled"
    ));
    assert!(refused(&fx.try_token(true, &[]).await, "disabled"));
    let own = fx
        .env
        .service
        .describe_own_token(&fx.use_token(&renewable).await.expect("ctx"))
        .await
        .expect("described");
    assert!(!own.token.renewable, "the description applies TGL-46");
    let person = fx
        .env
        .service
        .create_token_with(
            &fx.admin,
            &TokenRequest {
                name: "mine".to_owned(),
                scopes: vec![TokenScope::Metrics],
                renewable: true,
                ..TokenRequest::default()
            },
        )
        .await;
    assert!(matches!(
        person,
        Err(AuthError::Invalid {
            field: "renewable",
            ..
        })
    ));
}

/// IAM-21: a bound token is refused like an unknown token outside its prefixes, IPv4 and
/// IPv6, and without a known address; the refusal is audited. Inside them it acts.
#[tokio::test]
async fn a_token_acts_only_from_inside_its_source_prefixes() {
    let fx = fixture().await;
    let token = fx
        .token(true, &["198.51.100.0/24", "2001:db8:42::/48"])
        .await;
    let credentials = bearer(&token);
    let from = |ip: &str| {
        let ip: IpAddr = ip.parse().expect("an address");
        fx.env
            .service
            .authenticate_from(&credentials, Some(ip), fx.env.now())
    };
    from("198.51.100.7").await.expect("IPv4 inside");
    from("::ffff:198.51.100.8")
        .await
        .expect("IPv4-mapped inside");
    from("2001:db8:42::9").await.expect("IPv6 inside");
    assert!(unauthenticated(&from("203.0.113.7").await), "IPv4 outside");
    assert!(
        unauthenticated(&from("2001:db8:43::9").await),
        "IPv6 outside"
    );
    assert!(
        unauthenticated(&fx.use_token(&token).await),
        "no known address"
    );
    // Three refusals within a minute: one audit record; the next after it counts the others.
    assert_eq!(fx.audited("auth.token.source_refused").await.len(), 1);
    fx.env.clock.advance(Duration::from_secs(60));
    assert!(unauthenticated(&from("203.0.113.7").await));
    let view = fx
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let since: Vec<_> = view
        .scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == "auth.token.source_refused")
        .map(|(_, record, _)| record.draft.details.context.get("refused_since").cloned())
        .collect();
    assert_eq!(since, [None, Some("2".to_owned())]);
    let renewed = fx
        .env
        .service
        .renew_own_token(
            &RequestCtx::new(from("198.51.100.7").await.expect("inside").principal)
                .at(fx.env.now()),
            &TokenRenew {
                renewal_secret: SecretString::new(secret(&token)),
            },
        )
        .await
        .expect("renewed from inside");
    assert_eq!(renewed.info.source_prefixes, token.info.source_prefixes);
    assert!(matches!(
        fx.try_token(false, &["example.test"]).await,
        Err(AuthError::Invalid {
            field: "source_prefixes",
            ..
        })
    ));
}

/// IAM-20, IAM-21: a superseded token presented from outside its prefixes is refused and
/// audited, and does not count as reuse: the family stays intact.
#[tokio::test]
async fn a_superseded_token_from_outside_its_prefixes_does_not_revoke_the_family() {
    let fx = fixture().await;
    let inside: IpAddr = "198.51.100.7".parse().expect("an address");
    let first = fx.token(true, &["198.51.100.0/24"]).await;
    let ctx = |token: &CreatedToken| {
        let credentials = bearer(token);
        let env = &fx.env;
        async move {
            env.service
                .authenticate_from(&credentials, Some(inside), env.now())
                .await
                .map(|done| RequestCtx::new(done.principal).at(env.now()))
        }
    };
    let second = fx
        .env
        .service
        .renew_own_token(
            &ctx(&first).await.expect("inside"),
            &TokenRenew {
                renewal_secret: SecretString::new(secret(&first)),
            },
        )
        .await
        .expect("renewed");
    ctx(&second).await.expect("the first use supersedes");
    fx.env.clock.advance(Duration::from_secs(61));
    let outside = fx
        .env
        .service
        .authenticate_from(
            &bearer(&first),
            Some("203.0.113.7".parse().expect("an address")),
            fx.env.now(),
        )
        .await;
    assert!(unauthenticated(&outside));
    // The current token from outside cannot reach the renewal call either.
    let renewal_from_outside = fx
        .env
        .service
        .authenticate_from(
            &bearer(&second),
            Some("203.0.113.8".parse().expect("an address")),
            fx.env.now(),
        )
        .await;
    assert!(unauthenticated(&renewal_from_outside));
    assert_eq!(fx.audited("auth.token.source_refused").await.len(), 2);
    assert_eq!(fx.audited("auth.token.reuse_detected").await.len(), 0);
    ctx(&second).await.expect("the family is intact");
}

/// IAM-20, IAM-21: a renewable or bound token has the form `tnkc_`, which the prefix check
/// of a build that does not know these constraints (`tnk_` only) refuses before it reads or
/// writes the record; a plain token keeps `tnk_`; a renewal returns the constrained form.
#[tokio::test]
async fn a_constrained_token_never_passes_the_plain_prefix_check() {
    let fx = fixture().await;
    let older_build_accepts = |text: &str| text.starts_with("tnk_") && text.len() <= 128;
    let plain = fx.token(false, &[]).await;
    assert!(plain.token.expose().starts_with(TOKEN_PREFIX));
    assert!(older_build_accepts(plain.token.expose()));
    let renewable = fx.token(true, &[]).await;
    let bound = fx.token(false, &["192.0.2.0/24"]).await;
    let renewed = fx
        .renew(&renewable, &secret(&renewable))
        .await
        .expect("renewed");
    for token in [&renewable, &bound, &renewed] {
        assert!(token.token.expose().starts_with(CONSTRAINED_PREFIX));
        assert!(
            !older_build_accepts(token.token.expose()),
            "{}",
            token.info.name
        );
    }
}

/// IAM-20, IAM-21: a token whose form does not match its record is refused like an unknown
/// token and audited, both ways.
#[tokio::test]
async fn a_token_whose_form_does_not_match_its_record_is_refused_and_audited() {
    let fx = fixture().await;
    let plain = fx.token(false, &[]).await;
    rewrite(&fx, &plain, |record| {
        record.source_prefixes = vec!["192.0.2.0/24".parse().expect("a prefix")];
    })
    .await;
    let inside: IpAddr = "192.0.2.9".parse().expect("an address");
    let presented = fx
        .env
        .service
        .authenticate_from(&bearer(&plain), Some(inside), fx.env.now())
        .await;
    assert!(unauthenticated(&presented), "a constrained record as tnk_");
    let renewable = fx.token(true, &[]).await;
    rewrite(&fx, &renewable, |record| record.renewal = None).await;
    assert!(
        unauthenticated(&fx.use_token(&renewable).await),
        "a plain record as tnkc_"
    );
    assert_eq!(
        fx.audited("auth.token.form_refused").await,
        [AuditOutcome::Denied, AuditOutcome::Denied]
    );
}

/// IAM-20: the renewal secret is never a bearer token.
#[tokio::test]
async fn the_renewal_secret_is_refused_as_a_bearer_token() {
    let fx = fixture().await;
    let token = fx.token(true, &[]).await;
    let result = fx.env.ctx_for(&Credentials::Bearer(secret(&token))).await;
    assert!(unauthenticated(&result));
}

/// IAM-20: a token reads its own description and nothing about other tokens or secrets.
#[tokio::test]
async fn the_own_description_shows_the_caller_only_and_no_secret() {
    let fx = fixture().await;
    let token = fx.token(true, &["192.0.2.0/24"]).await;
    let other = fx.token(false, &[]).await;
    let ctx = RequestCtx::new(
        fx.env
            .service
            .authenticate_from(
                &bearer(&token),
                Some("192.0.2.9".parse().expect("an address")),
                fx.env.now(),
            )
            .await
            .expect("inside")
            .principal,
    );
    let own = fx
        .env
        .service
        .describe_own_token(&ctx)
        .await
        .expect("described");
    assert_eq!(own.account, fx.account.id);
    assert_eq!(own.account_name, "dhcp-report");
    assert_eq!(own.token.id, token.info.id);
    assert!(own.token.renewable);
    let text = serde_json::to_string(&own).expect("json");
    for absent in [
        token.token.expose().to_owned(),
        secret(&token),
        other.info.id.to_string(),
        other.info.prefix.clone(),
    ] {
        assert!(!text.contains(&absent), "{absent} is not shown");
    }
    assert!(
        unauthenticated(&fx.env.service.describe_own_token(&fx.admin).await),
        "a session has no token"
    );
}

/// IAM-20: below 14 days the warning stands and the sweep audits it once; a renewal clears it.
#[tokio::test]
async fn the_expiry_warning_appears_below_14_days_and_clears_after_renewal() {
    let fx = fixture().await;
    let token = fx.token(true, &[]).await;
    fx.env.clock.advance(Duration::from_secs(351 * DAY));
    assert_eq!(fx.warnings().await, Vec::<String>::new(), "14 days left");
    fx.env.clock.advance(Duration::from_secs(DAY));
    assert_eq!(fx.warnings().await, [TOKEN_EXPIRING]);
    for _ in 0..2 {
        fx.env
            .service
            .notice_expiring_tokens(fx.env.now())
            .await
            .expect("the sweep");
    }
    assert_eq!(fx.audited("auth.token.expiring").await.len(), 1, "once");
    let renewed = fx.renew(&token, &secret(&token)).await.expect("renewed");
    assert_eq!(
        fx.warnings().await,
        [TOKEN_EXPIRING],
        "the old token still acts until the new one is used"
    );
    fx.use_token(&renewed).await.expect("the first use");
    assert_eq!(fx.warnings().await, Vec::<String>::new());
}

/// IAM-20: an unused successor that a renewal replaced is kept as superseded: presenting it
/// later revokes the family at once, since the holder who lost the answer never had it.
#[tokio::test]
async fn a_replaced_successor_presented_later_revokes_the_family() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let lost = fx.renew(&first, &secret(&first)).await.expect("renewed");
    let second = fx
        .renew(&first, &secret(&first))
        .await
        .expect("renewed again");
    assert!(unauthenticated(&fx.use_token(&lost).await));
    assert!(unauthenticated(&fx.use_token(&second).await), "revoked");
    assert_eq!(fx.audited("auth.token.reuse_detected").await.len(), 1);
}

/// IAM-20: a renewed token keeps the lifetime its family was created with, capped by the
/// profile at the time of the renewal; a renewable token must expire.
#[tokio::test]
async fn a_renewal_keeps_the_family_lifetime_within_the_profile_cap() {
    let fx = fixture().await;
    let first = fx
        .create(TokenRequest {
            name: "monthly".to_owned(),
            scopes: vec![TokenScope::Metrics],
            renewable: true,
            expires_in_days: Some(30),
            ..TokenRequest::default()
        })
        .await
        .expect("a token");
    fx.env.clock.advance(Duration::from_secs(20 * DAY));
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    assert_eq!(
        second.info.expires_at,
        fx.env.now().checked_add(Duration::from_secs(30 * DAY)),
        "30 days, not the profile's 365"
    );
    fx.env
        .service
        .update_security_settings(
            &fx.admin,
            &SettingsPatch {
                token_max_lifetime: Some(tenko_auth::settings::TokenMaxLifetime::Days(10)),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("a tighter cap");
    let third = fx.renew(&second, &secret(&second)).await.expect("renewed");
    assert_eq!(
        third.info.expires_at,
        fx.env.now().checked_add(Duration::from_secs(10 * DAY)),
        "capped by the profile now"
    );
}

/// IAM-20: under Lab, which allows tokens without expiry, a renewable token still needs one.
#[tokio::test]
async fn a_renewable_token_without_an_expiry_is_refused() {
    let (env, session) = TestEnv::installed(Profile::Lab).await;
    let admin = env.session_ctx(&session).await.expect("ctx");
    let account = env
        .service
        .create_service_account(
            &admin,
            &ServiceAccountCreate {
                name: "lab-report".to_owned(),
                display_name: None,
                roles: vec![RoleName::Viewer],
            },
        )
        .await
        .expect("an account");
    let request = |renewable: bool| TokenRequest {
        name: "lab".to_owned(),
        scopes: vec![TokenScope::Metrics],
        renewable,
        ..TokenRequest::default()
    };
    let refused = env
        .service
        .create_account_token(&admin, account.id, &request(true))
        .await;
    assert!(matches!(
        refused,
        Err(AuthError::Invalid {
            field: "expires_in_days",
            ..
        })
    ));
    let plain = env
        .service
        .create_account_token(&admin, account.id, &request(false))
        .await
        .expect("a plain token without expiry");
    assert_eq!(plain.info.expires_at, None);
}

/// IAM-20: an owner holds a bounded number of scoped tokens, superseded ones included.
#[tokio::test]
async fn an_owner_holds_at_most_the_cap_of_tokens() {
    let fx = fixture().await;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), fx.env.now());
    for _ in 1..tenko_auth::service::types::SCOPED_TOKENS_MAX {
        batch
            .put_typed(
                &USER_SCOPED_TOKENS,
                &(fx.account.id, tenko_core::ApiTokenId::generate()),
                &vec![0_u8; 32],
            )
            .expect("encodes");
    }
    fx.env.store.propose(batch).await.expect("written");
    fx.token(false, &[]).await;
    assert!(matches!(
        fx.try_token(false, &[]).await,
        Err(AuthError::TokenLimit { max: 500 })
    ));
}

/// IAM-20: a renewal drops a grant the account no longer holds; a disabled account's token
/// does not renew at all.
#[tokio::test]
async fn a_renewal_holds_no_more_than_the_account_does() {
    let fx = fixture().await;
    let first = fx
        .create(TokenRequest {
            name: "reader".to_owned(),
            grants: Some(vec![tenko_auth::model::TokenGrant {
                role: RoleName::Viewer,
                scope: None,
            }]),
            scopes: vec![TokenScope::Metrics],
            renewable: true,
            ..TokenRequest::default()
        })
        .await
        .expect("a token");
    assert_eq!(first.info.grants.len(), 1);
    fx.env
        .service
        .set_user_roles(&fx.admin, fx.account.id, &[], None)
        .await
        .expect("the role is taken away");
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    assert_eq!(second.info.grants, Vec::new(), "the lost grant is dropped");
    fx.env
        .service
        .update_user(
            &fx.admin,
            fx.account.id,
            &UserUpdate {
                disabled: Some(true),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("disabled");
    assert!(unauthenticated(&fx.renew(&second, &secret(&second)).await));
}

/// IAM-20: an event stream opened with a token ends when the token is superseded and when
/// its family is revoked.
#[tokio::test]
async fn an_event_stream_ends_on_supersede_and_on_revocation() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let held = fx
        .env
        .service
        .hold(&bearer(&first), fx.env.now())
        .await
        .expect("held");
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    let standing = |hold| {
        let env = &fx.env;
        async move {
            let at = env
                .store
                .read(ReadConsistency::Local)
                .await
                .expect("view")
                .revision();
            env.service.standing(hold, at, env.now()).await
        }
    };
    standing(&held).await.expect("still acting");
    fx.use_token(&second)
        .await
        .expect("the first use supersedes");
    assert!(unauthenticated(&standing(&held).await), "superseded");
    let held = fx
        .env
        .service
        .hold(&bearer(&second), fx.env.now())
        .await
        .expect("held");
    fx.env.clock.advance(Duration::from_secs(61));
    assert!(unauthenticated(&fx.use_token(&first).await), "reuse");
    assert!(unauthenticated(&standing(&held).await), "revoked");
}

/// IAM-20, TGL-46: after a switch to Hardened, renewable tokens keep acting but no longer
/// renew.
#[tokio::test]
async fn a_switch_to_hardened_stops_renewal() {
    let fx = fixture().await;
    let token = fx.token(true, &[]).await;
    fx.env
        .service
        .update_security_settings(
            &fx.admin,
            &SettingsPatch {
                profile: Some(Profile::Hardened),
                audit_export: Some(tenko_auth::settings::AuditExport::Optional),
                // Hardened requires certificate-bound tokens and would remove this one
                // (TGL-47); the deviation keeps it, so that TGL-46 is what refuses.
                integrations: Some(tenko_auth::client_cert::model::IntegrationPolicy {
                    require_binding: false,
                    ..tenko_auth::client_cert::model::IntegrationPolicy::of(Profile::Hardened)
                }),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("Hardened");
    assert!(refused(
        &fx.renew(&token, &secret(&token)).await,
        "disabled"
    ));
}

/// IAM-20: a superseded token past its own expiry is refused like an unknown token and
/// revokes nothing.
#[tokio::test]
async fn an_expired_superseded_token_revokes_nothing() {
    let fx = fixture().await;
    let first = fx
        .create(TokenRequest {
            name: "short".to_owned(),
            scopes: vec![TokenScope::Metrics],
            renewable: true,
            expires_in_days: Some(2),
            ..TokenRequest::default()
        })
        .await
        .expect("a token");
    fx.env.clock.advance(Duration::from_secs(DAY));
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    fx.use_token(&second)
        .await
        .expect("the first use supersedes");
    fx.env.clock.advance(Duration::from_secs(DAY + 60));
    assert!(unauthenticated(&fx.use_token(&first).await));
    assert_eq!(fx.audited("auth.token.reuse_detected").await.len(), 0);
    fx.use_token(&second).await.expect("the family is intact");
}

/// IAM-20: a token that revokes itself takes its unused successor with it.
#[tokio::test]
async fn a_token_that_revokes_itself_revokes_its_family() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    let second = fx.renew(&first, &secret(&first)).await.expect("renewed");
    let ctx = fx.use_token(&first).await.expect("ctx");
    fx.env
        .service
        .revoke_token(&ctx, first.info.id)
        .await
        .expect("revoked");
    assert!(unauthenticated(&fx.use_token(&second).await));
    assert_eq!(fx.listed().await.len(), 0);
}

/// IAM-20: a family keeps at most eight superseded tokens, however often it renews.
#[tokio::test]
async fn a_family_keeps_a_bounded_number_of_superseded_tokens() {
    let fx = fixture().await;
    let mut token = fx.token(true, &[]).await;
    for _ in 0..12 {
        token = fx.renew(&token, &secret(&token)).await.expect("renewed");
        fx.use_token(&token).await.expect("used");
    }
    let view = fx
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let records = view
        .scan_typed(
            &tenko_auth::model::USER_SCOPED_TOKENS,
            KeyRange::all(),
            1_000,
            false,
        )
        .expect("index")
        .len();
    assert_eq!(records, 9, "the live token and eight superseded ones");
}

/// IAM-20: renewing again and again without using a successor keeps the family bounded too:
/// each replaced successor is kept as superseded, the oldest beyond eight go.
#[tokio::test]
async fn renewals_that_replace_successors_keep_the_family_bounded() {
    let fx = fixture().await;
    let first = fx.token(true, &[]).await;
    for _ in 0..12 {
        fx.renew(&first, &secret(&first)).await.expect("renewed");
    }
    let view = fx
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let records = view
        .scan_typed(&USER_SCOPED_TOKENS, KeyRange::all(), 1_000, false)
        .expect("index")
        .len();
    assert_eq!(
        records, 10,
        "the first token, its unused successor and eight replaced ones"
    );
}

/// A token still never creates a token: the session-only routes refuse it.
#[tokio::test]
async fn a_token_cannot_create_tokens() {
    let fx = fixture().await;
    let token = fx.token(true, &[]).await;
    let ctx = fx.use_token(&token).await.expect("ctx");
    let result = fx
        .env
        .service
        .create_account_token(
            &ctx,
            fx.account.id,
            &TokenRequest {
                name: "more".to_owned(),
                scopes: vec![TokenScope::Metrics],
                ..TokenRequest::default()
            },
        )
        .await;
    assert!(matches!(result, Err(AuthError::Denied(_))), "{result:?}");
    let listed = fx
        .env
        .service
        .list_account_tokens(&ctx, fx.account.id)
        .await;
    assert!(matches!(listed, Err(AuthError::Denied(_))), "{listed:?}");
}
