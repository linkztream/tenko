//! Approvals of a takeover script and their delegated sessions (ADR 0038, E145; IAM-10,
//! TGL-03, TGL-04): the code's vector, the request's limits, the person's approval with its
//! code, the collect with the key's signature, and a delegated session that is bound to its
//! source, never fresh, and ends.

use std::{sync::Arc, time::Duration};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tenko_auth::{
    AuthConfig, AuthError, AuthService, NewSession,
    approval::{self, APPROVALS, ApprovalState, Refusal},
    encoding::{base64url_decode, hex_decode},
    model::{SESSIONS, USERS},
    roles::RoleName,
    secret::hash_secret,
    service::{SecretString, TokenCreate},
    settings::Profile,
    testing::{
        TestEnv,
        approval::{ROOT_SHA256, Script, plan},
        env::CLIENT,
    },
};
use tenko_core::{
    ApprovalId, Credentials, Principal, RequestCtx, SystemComponent, Timestamp, audit::AuditRecord,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};
use tenko_vault::Vault;

const VECTOR: &str = include_str!("fixtures/approval-code.json");

fn hex(text: &Value) -> Vec<u8> {
    hex_decode(text.as_str().expect("a hex string")).expect("hex")
}

fn refusal<T: std::fmt::Debug>(result: Result<T, AuthError>) -> Refusal {
    match result {
        Err(AuthError::Approval(refusal)) => refusal,
        other => panic!("not an approval refusal: {other:?}"),
    }
}

/// The code's vector, as the script's own implementation reads it.
#[test]
fn the_code_vector_holds() {
    let vector: Value = serde_json::from_str(VECTOR).expect("the vector");
    let code = &vector["code"];
    let body = code["request_body"].as_str().expect("the body");
    let digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
    assert_eq!(digest.to_vec(), hex(&code["request_sha256"]));
    let key = hex(&code["key_uncompressed"]);
    assert_eq!(
        base64url_decode(code["key_base64url"].as_str().expect("text")).expect("base64url"),
        key
    );
    let id: ApprovalId = code["approval_id"]
        .as_str()
        .expect("an id")
        .parse()
        .expect("an id");
    assert_eq!(
        id.uuid().as_bytes().to_vec(),
        hex(&code["approval_id_octets"])
    );
    let root: [u8; 32] = hex(&code["root_sha256"]).try_into().expect("32 octets");
    assert_eq!(
        approval::code(
            code["domain"].as_str().expect("text"),
            &root,
            &digest,
            &key,
            id
        ),
        code["code"].as_str().expect("the code")
    );
    // The request of the vector is one Tenko accepts, and Tenko hashes it as sent.
    let (_, parsed_key, parsed_hash) = approval::parse_request(body.as_bytes()).expect("accepted");
    assert_eq!((parsed_key, parsed_hash), (key.clone(), digest));
    assert_eq!(
        approval::canonical_code(vector["typed"]["typed"].as_str().expect("text")).as_deref(),
        vector["typed"]["canonical"].as_str()
    );
    let collect = &vector["collect"];
    let nonce = hex(&collect["nonce"]);
    assert_eq!(
        approval::collect_message(id, &nonce),
        hex(&collect["message"])
    );
    let signature =
        base64url_decode(collect["signature_base64url"].as_str().expect("text")).expect("b64");
    assert!(approval::verify_collect(&key, id, &nonce, &signature));
    assert!(!approval::verify_collect(
        &key,
        ApprovalId::generate(),
        &nonce,
        &signature
    ));
}

/// An installation with the administrator's session and its fresh context.
async fn installation() -> (TestEnv, NewSession, RequestCtx) {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let ctx = env.session_ctx(&admin).await.expect("the administrator");
    (env, admin, ctx)
}

fn client() -> std::net::IpAddr {
    CLIENT.parse().expect("an address")
}

/// The context of a delegated session's request from `source` at `now`.
async fn delegated(
    env: &TestEnv,
    secret: &SecretString,
    source: std::net::IpAddr,
    now: Timestamp,
) -> Result<RequestCtx, AuthError> {
    let authenticated = env
        .service
        .authenticate_from(
            &Credentials::Bearer(secret.expose().to_owned()),
            Some(source),
            now,
        )
        .await?;
    assert!(authenticated.flags.delegation.is_some());
    Ok(RequestCtx::new(authenticated.principal)
        .at(now)
        .with_source_ip(source))
}

async fn audit(env: &TestEnv) -> Vec<AuditRecord> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

#[tokio::test]
async fn a_person_approves_and_the_script_collects_once() {
    let (env, _, admin) = installation().await;
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    let view = env
        .service
        .look_up_approval(&admin, &code, &ROOT_SHA256)
        .await
        .expect("the code finds it");
    assert_eq!((view.id, view.state.as_str()), (ticket.id, "pending"));
    assert_eq!(view.reported.user, "CORP\\admin");
    assert_eq!(view.source, CLIENT);
    // The collect waits for the person.
    let collect = script.collect(&ticket);
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&env.public_ctx(), ticket.id, collect.as_bytes())
                .await
        ),
        Refusal::Pending
    );
    env.service
        .approve(&admin, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect("approved");
    let session = env
        .service
        .collect_approval(&env.public_ctx(), ticket.id, collect.as_bytes())
        .await
        .expect("collected");
    assert!(session.secret.expose().starts_with("tnka_"));
    assert_eq!(session.idle_secs, 900);
    // Once.
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&env.public_ctx(), ticket.id, collect.as_bytes())
                .await
        ),
        Refusal::Consumed
    );
    let ctx = delegated(&env, &session.secret, client(), env.now())
        .await
        .expect("the session acts");
    let Principal::User { id, delegation, .. } = ctx.principal else {
        panic!("a session principal");
    };
    assert_eq!(id, admin.principal.user().expect("a user"));
    assert_eq!(delegation, Some(session.delegation));
    // Every step is audited; the collect as the approver acting through the run.
    let records = audit(&env).await;
    for action in [
        "auth.approval.request",
        "auth.approval.approve",
        "auth.approval.collect",
    ] {
        assert!(
            records
                .iter()
                .any(|record| record.draft.action.as_str() == action),
            "{action}"
        );
    }
    let collected = records
        .iter()
        .find(|record| record.draft.action.as_str() == "auth.approval.collect")
        .expect("the collect");
    assert_eq!(collected.principal.delegation(), Some(session.delegation));
    // The stored record holds no secret: the session's secret is only the key of its row.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert!(
        view.get_typed(&SESSIONS, &hash_secret(session.secret.expose()))
            .expect("read")
            .is_some()
    );
}

#[tokio::test]
async fn wrong_late_and_ambiguous_codes_are_refused() {
    let (env, _, admin) = installation().await;
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    // A code over another root: the script reached Tenko through an interceptor.
    let intercepted = SecretString::new(approval::code(
        "corp.example.test",
        &[0x11; 32],
        &Sha256::digest(body.as_bytes()).into(),
        &base64url_decode(&script.key()).expect("the key"),
        ticket.id,
    ));
    assert_eq!(
        refusal(
            env.service
                .look_up_approval(&admin, &intercepted, &ROOT_SHA256)
                .await
        ),
        Refusal::Code
    );
    // A late answer: ten minutes after the request the approval is over, whoever signed in.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (mut old, _) = view
        .get_typed(&APPROVALS, &ticket.id)
        .expect("read")
        .expect("the approval");
    let created = old.created_at;
    old.created_at = created
        .checked_sub(approval::PENDING_LIFETIME)
        .expect("a time");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch
        .put_typed(&APPROVALS, &ticket.id, &old)
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    assert_eq!(
        refusal(
            env.service
                .approve(&admin, ticket.id, &code, &ROOT_SHA256)
                .await
        ),
        Refusal::Expired
    );
    old.created_at = created;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch
        .put_typed(&APPROVALS, &ticket.id, &old)
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    // A code that matches two waiting approvals: a copy of the row under another key.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (record, _) = view
        .get_typed(&APPROVALS, &ticket.id)
        .expect("read")
        .expect("the approval");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch
        .put_typed(&APPROVALS, &ApprovalId::generate(), &record)
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    assert_eq!(
        refusal(
            env.service
                .look_up_approval(&admin, &code, &ROOT_SHA256)
                .await
        ),
        Refusal::Ambiguous
    );
    // Five wrong codes lock the browser session's lookups, the right code included.
    for _ in 0..4 {
        let _ = env
            .service
            .look_up_approval(&admin, &intercepted, &ROOT_SHA256)
            .await;
    }
    assert_eq!(
        refusal(
            env.service
                .approve(&admin, ticket.id, &code, &ROOT_SHA256)
                .await
        ),
        Refusal::Limit("lookups")
    );
}

#[tokio::test]
async fn a_collect_needs_the_key_the_address_and_an_approval() {
    let (env, _, admin) = installation().await;
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    env.service
        .approve(&admin, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect("approved");
    let other_key = Script::default().collect(&ticket);
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&env.public_ctx(), ticket.id, other_key.as_bytes())
                .await
        ),
        Refusal::Signature
    );
    let elsewhere = env
        .public_ctx()
        .with_source_ip("192.0.2.99".parse().expect("an address"));
    let collect = script.collect(&ticket);
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&elsewhere, ticket.id, collect.as_bytes())
                .await
        ),
        Refusal::NotFound
    );
    // A denied request is never collected.
    let second = Script::default();
    let body = second.request();
    let denied = env
        .service
        .request_approval(
            &env.public_ctx()
                .with_source_ip("192.0.2.40".parse().expect("an address")),
            body.as_bytes(),
        )
        .await
        .expect("a request");
    env.service
        .deny_approval(&admin, denied.id)
        .await
        .expect("denied");
    assert_eq!(
        refusal(
            env.service
                .collect_approval(
                    &env.public_ctx()
                        .with_source_ip("192.0.2.40".parse().expect("an address")),
                    denied.id,
                    second.collect(&denied).as_bytes(),
                )
                .await
        ),
        Refusal::Denied
    );
}

#[tokio::test]
async fn a_request_outside_the_limits_is_refused() {
    let (env, _, _) = installation().await;
    let script = Script::default();
    let mut wide = plan();
    wide["zones"] = serde_json::json!(["other.example.test"]);
    assert!(matches!(
        refusal(
            env.service
                .request_approval(&env.public_ctx(), script.request_for(&wide).as_bytes())
                .await
        ),
        Refusal::Plan(_)
    ));
    // One request per source every ten seconds, the refused one included.
    assert_eq!(
        refusal(
            env.service
                .request_approval(&env.public_ctx(), script.request().as_bytes())
                .await
        ),
        Refusal::Limit("spacing")
    );
    for bad in [
        String::new(),
        "[]".to_owned(),
        script
            .request()
            .replace("\"windows-takeover\"", "\"other\""),
        script
            .request()
            .replace("\"client\":", "\"extra\":1,\"client\":"),
        script
            .request()
            .replace("CORP\\\\admin", "CORP\\\\ad\u{202e}min"),
    ] {
        assert!(
            matches!(
                approval::parse_request(bad.as_bytes()),
                Err(Refusal::Plan(_))
            ),
            "{bad}"
        );
    }
    assert_eq!(
        approval::parse_request(&vec![b' '; approval::MAX_REQUEST_BYTES + 1]),
        Err(Refusal::Plan("the body is larger than 64 KiB".to_owned()))
    );
    // Two pending approvals per source: a third, through another controller, is refused.
    let mut services = Vec::new();
    for _ in 0..3 {
        let vault: Arc<dyn Vault> = env.vault.clone();
        services.push(
            AuthService::new(env.store.clone(), vault, AuthConfig::default())
                .await
                .expect("a controller"),
        );
    }
    let source = env
        .public_ctx()
        .with_source_ip("2001:db8::7".parse().expect("an address"));
    for service in &services[..2] {
        service
            .request_approval(&source, script.request().as_bytes())
            .await
            .expect("a request");
    }
    let same_64 = env
        .public_ctx()
        .with_source_ip("2001:db8::8".parse().expect("an address"));
    assert_eq!(
        refusal(
            services[2]
                .request_approval(&same_64, script.request().as_bytes())
                .await
        ),
        Refusal::Limit("source")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One delegated session after another, each to its end.
async fn the_delegated_session_is_bound_never_fresh_and_ends() {
    let (env, admin_session, admin) = installation().await;
    let source = |last: u8| std::net::IpAddr::from([192, 0, 2, last]);
    let session = env
        .delegate(&admin, &Script::default(), client())
        .await
        .expect("a delegated session");
    let now = env.now();
    // From another address, or as a cookie, it is an unknown session.
    assert!(matches!(
        delegated(
            &env,
            &session.secret,
            "192.0.2.99".parse().expect("an address"),
            now
        )
        .await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service
            .authenticate_from(
                &Credentials::Session(session.secret.expose().to_owned()),
                Some(client()),
                now
            )
            .await,
        Err(AuthError::Unauthenticated)
    ));
    // Never fresh, within its first five minutes too: no token, factor, password or
    // session change.
    let ctx = delegated(&env, &session.secret, client(), now)
        .await
        .expect("acts");
    let token = TokenCreate {
        name: "script".to_owned(),
        expires_in_days: Some(1),
    };
    assert!(matches!(
        env.service.create_token(&ctx, &token).await,
        Err(AuthError::DelegationRefused)
    ));
    assert!(matches!(
        env.service.totp_enroll_start(&ctx).await,
        Err(AuthError::DelegationRefused)
    ));
    assert!(matches!(
        env.service.require_fresh_session(&ctx).await,
        Err(AuthError::DelegationRefused)
    ));
    assert!(matches!(
        env.service.current_session(&ctx).await,
        Err(AuthError::DelegationRefused)
    ));
    assert!(matches!(
        env.service.revoke_session(&ctx, session.session).await,
        Err(AuthError::DelegationRefused)
    ));
    // It never approves, not even its own kind.
    assert!(matches!(
        env.service
            .deny_approval(&ctx, ApprovalId::generate())
            .await,
        Err(AuthError::DelegationRefused)
    ));
    let second = env.delegate(&admin, &Script::default(), source(51)).await;
    assert_eq!(
        refusal(second),
        Refusal::Limit("domain"),
        "one run per domain"
    );
    let fresh = env.service.revoke_session(&admin, session.session).await;
    fresh.expect("the person revokes it");
    assert!(matches!(
        delegated(&env, &session.secret, client(), now).await,
        Err(AuthError::Unauthenticated)
    ));
    // A new approval after the revocation; a clock set back ends it rather than extending it.
    let session = env
        .delegate(&admin, &Script::default(), source(52))
        .await
        .expect("a new delegated session");
    let back = now.checked_sub(Duration::from_secs(10)).expect("a time");
    assert!(matches!(
        delegated(&env, &session.secret, source(52), back).await,
        Err(AuthError::SessionExpired)
    ));
    // Idle for 15 minutes: over.
    let session = env
        .delegate(&admin, &Script::default(), source(54))
        .await
        .expect("a delegated session after the clock's");
    let idle = now
        .checked_add(Duration::from_secs(15 * 60))
        .expect("a time");
    assert!(matches!(
        delegated(&env, &session.secret, source(54), idle).await,
        Err(AuthError::SessionExpired)
    ));
    // An approver who loses the administrator role ends it.
    let other = env
        .delegate(&admin, &Script::default(), source(53))
        .await
        .expect("a third one, after the lapse");
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let user = admin_session.info.user.id;
    let (mut record, _) = view
        .get_typed(&USERS, &user)
        .expect("read")
        .expect("the user");
    record.roles = vec![RoleName::Operator];
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
    batch.put_typed(&USERS, &user, &record).expect("encode");
    env.store.propose(batch).await.expect("commit");
    assert!(matches!(
        delegated(&env, &other.secret, source(53), now).await,
        Err(AuthError::Unauthenticated)
    ));
}

#[tokio::test]
async fn tokens_and_weak_sessions_never_approve() {
    let (env, _, admin) = installation().await;
    let token = env
        .service
        .create_token(
            &admin,
            &TokenCreate {
                name: "automation".to_owned(),
                expires_in_days: Some(1),
            },
        )
        .await
        .expect("a personal token");
    let as_token = env
        .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
        .await
        .expect("the token acts");
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    assert!(matches!(
        env.service
            .approve(&as_token, ticket.id, &code, &ROOT_SHA256)
            .await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service
            .look_up_approval(&as_token, &code, &ROOT_SHA256)
            .await,
        Err(AuthError::Unauthenticated)
    ));
    // A sign-in older than five minutes.
    let stale = admin.clone().at(env
        .now()
        .checked_add(Duration::from_secs(301))
        .expect("a time"));
    assert!(matches!(
        env.service
            .approve(&stale, ticket.id, &code, &ROOT_SHA256)
            .await,
        Err(AuthError::StepUpRequired { .. })
    ));
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (record, _) = view
        .get_typed(&APPROVALS, &ticket.id)
        .expect("read")
        .expect("it");
    assert_eq!(record.state, ApprovalState::Pending);

    // Under Hardened an administrator's password session never approves.
    let (hardened, session) = TestEnv::installed(Profile::Hardened).await;
    let ctx = hardened.session_ctx(&session).await.expect("a session");
    let ticket = hardened
        .service
        .request_approval(&hardened.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    let refused = hardened
        .service
        .approve(&ctx, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect_err("refused");
    assert_eq!(tenko_core::Coded::code(&refused), "auth.step_up_required");
}
