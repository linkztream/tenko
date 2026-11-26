//! Approvals of a takeover script and their delegated sessions (ADR 0038, E145; IAM-10,
//! TGL-03, TGL-04): the code's vector, the request's limits, the person's approval with its
//! code, the collect with the key's signature, and a delegated session that is bound to its
//! source, never fresh, and ends.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tenko_auth::{
    AuthError, NewSession,
    approval::{self, APPROVALS, ApprovalState, Refusal},
    encoding::hex_decode,
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
    ApprovalId, Credentials, DelegationId, Principal, RequestCtx, SystemComponent, Timestamp,
    audit::AuditRecord, migrate::tables::RUN_DOMAINS,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};

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
        URL_SAFE_NO_PAD
            .decode(code["key_base64url"].as_str().expect("text"))
            .expect("base64url"),
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
    // Every step a script follows: the preimage from its parts, its digest, the 80 bits.
    let domain = code["domain"].as_str().expect("text");
    let mut preimage = approval::CODE_CONTEXT.to_vec();
    preimage.push(0);
    preimage.push(u8::try_from(domain.len()).expect("a short domain"));
    preimage.extend_from_slice(domain.as_bytes());
    for part in [&root[..], &digest[..], &key[..], id.uuid().as_bytes()] {
        preimage.extend_from_slice(part);
    }
    assert_eq!(preimage, hex(&code["preimage"]));
    let sha = Sha256::digest(&preimage).to_vec();
    assert_eq!(sha, hex(&code["sha256"]));
    assert_eq!(sha[..10].to_vec(), hex(&code["first_80_bits"]));
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
    let signature = URL_SAFE_NO_PAD
        .decode(collect["signature_base64url"].as_str().expect("text"))
        .expect("b64");
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
        &URL_SAFE_NO_PAD.decode(script.key()).expect("the key"),
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
    // The spacing holds one address; the count of two pending ones holds its /64.
    let from = |address: &str| {
        env.public_ctx()
            .with_source_ip(address.parse().expect("an address"))
    };
    for address in ["2001:db8::7", "2001:db8::8"] {
        env.service
            .request_approval(&from(address), script.request().as_bytes())
            .await
            .expect("a request");
    }
    assert_eq!(
        refusal(
            env.service
                .request_approval(&from("2001:db8::9"), script.request().as_bytes())
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
        Err(AuthError::DelegationRefused { reason: "person" })
    ));
    assert!(matches!(
        env.service.totp_enroll_start(&ctx).await,
        Err(AuthError::DelegationRefused { reason: "person" })
    ));
    assert!(matches!(
        env.service.require_fresh_session(&ctx).await,
        Err(AuthError::DelegationRefused { reason: "person" })
    ));
    assert!(matches!(
        env.service.current_session(&ctx).await,
        Err(AuthError::DelegationRefused { reason: "person" })
    ));
    assert!(matches!(
        env.service.revoke_session(&ctx, session.session).await,
        Err(AuthError::DelegationRefused { reason: "person" })
    ));
    // It never approves, not even its own kind.
    assert!(matches!(
        env.service
            .deny_approval(&ctx, ApprovalId::generate())
            .await,
        Err(AuthError::DelegationRefused { reason: "person" })
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

/// Overwrites the stored session of `secret` with `edit`.
async fn rewrite_session(
    env: &TestEnv,
    secret: &SecretString,
    edit: impl FnOnce(&mut tenko_auth::model::SessionRecord),
) {
    let hash = hash_secret(secret.expose());
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (mut record, _) = view
        .get_typed(&SESSIONS, &hash)
        .expect("read")
        .expect("the session");
    edit(&mut record);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch.put_typed(&SESSIONS, &hash, &record).expect("encode");
    env.store.propose(batch).await.expect("commit");
}

/// Overwrites the stored account `user` with `edit`.
async fn rewrite_user(
    env: &TestEnv,
    user: tenko_core::UserId,
    edit: impl FnOnce(&mut tenko_auth::model::UserRecord),
) {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (mut record, _) = view
        .get_typed(&USERS, &user)
        .expect("read")
        .expect("the user");
    edit(&mut record);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch.put_typed(&USERS, &user, &record).expect("encode");
    env.store.propose(batch).await.expect("commit");
}

/// A script that was killed never presents its session again: once the session has lapsed,
/// its row does not hold the domain, and a new run of the domain is approved.
#[tokio::test]
async fn a_killed_script_s_domain_is_approved_again() {
    let (env, _, admin) = installation().await;
    let source = |last: u8| std::net::IpAddr::from([192, 0, 2, last]);
    let first = env
        .delegate(&admin, &Script::default(), source(61))
        .await
        .expect("a delegated session");
    assert_eq!(
        refusal(env.delegate(&admin, &Script::default(), source(62)).await),
        Refusal::Limit("domain"),
        "while the session lives"
    );
    let lapsed = env
        .now()
        .checked_sub(Duration::from_secs(1))
        .expect("a time");
    rewrite_session(&env, &first.secret, |record| {
        record.idle_expires_at = lapsed;
    })
    .await;
    env.delegate(&admin, &Script::default(), source(63))
        .await
        .expect("the lapsed session's row holds nothing");
}

/// A request of `script` from 192.0.2.`last`, approved by `admin`: the request's context
/// and its ticket.
async fn approved(
    env: &TestEnv,
    admin: &RequestCtx,
    script: &Script,
    last: u8,
) -> (RequestCtx, tenko_auth::approval::ApprovalTicket) {
    let ctx = env
        .public_ctx()
        .with_source_ip(std::net::IpAddr::from([192, 0, 2, last]));
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&ctx, body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    env.service
        .approve(admin, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect("approved");
    (ctx, ticket)
}

/// Between the approval and the collect the person can withdraw the approval, and ending
/// the approver's sessions or disabling the approver stops the collect.
#[tokio::test]
async fn the_approver_can_stop_a_collect_that_has_not_happened() {
    let (env, admin_session, admin) = installation().await;
    let user = admin_session.info.user.id;
    // Withdrawn by the person.
    let script = Script::default();
    let (ctx, ticket) = approved(&env, &admin, &script, 71).await;
    env.service
        .deny_approval(&admin, ticket.id)
        .await
        .expect("withdrawn");
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&ctx, ticket.id, script.collect(&ticket).as_bytes())
                .await
        ),
        Refusal::Denied
    );
    // The approver ended every session of the account.
    let script = Script::default();
    let (ctx, ticket) = approved(&env, &admin, &script, 72).await;
    rewrite_user(&env, user, |record| record.sessions_generation += 1).await;
    assert!(matches!(
        env.service
            .collect_approval(&ctx, ticket.id, script.collect(&ticket).as_bytes())
            .await,
        Err(AuthError::Unauthenticated)
    ));
    // The approver was disabled.
    let (env, admin_session, admin) = installation().await;
    let script = Script::default();
    let (ctx, ticket) = approved(&env, &admin, &script, 73).await;
    rewrite_user(&env, admin_session.info.user.id, |record| {
        record.disabled = true;
    })
    .await;
    assert!(matches!(
        env.service
            .collect_approval(&ctx, ticket.id, script.collect(&ticket).as_bytes())
            .await,
        Err(AuthError::Unauthenticated)
    ));
}

/// The person denies every waiting request of one source in one step, and only those; an
/// IPv4-mapped source is its IPv4 address; without a source the uncollected approvals go too,
/// and the answer tells the kinds apart.
#[tokio::test]
async fn an_administrator_clears_the_waiting_requests_of_a_source() {
    let (env, _, admin) = installation().await;
    let script = Script::default();
    let cleared = |waiting, approved| approval::ClearedApprovals { waiting, approved };
    let mut tickets = Vec::new();
    for address in ["2001:db8::1", "2001:db8::2", "192.0.2.80", "192.0.2.81"] {
        let ctx = env
            .public_ctx()
            .with_source_ip(address.parse().expect("an address"));
        tickets.push(
            env.service
                .request_approval(&ctx, script.request().as_bytes())
                .await
                .expect("a request"),
        );
    }
    let (_, approved_ticket) = approved(&env, &admin, &script, 82).await;
    let neighbor = "2001:db8::ffff".parse().expect("an address");
    assert_eq!(
        env.service
            .clear_approvals(&admin, Some(neighbor))
            .await
            .expect("cleared"),
        cleared(2, 0),
        "the two of the /64"
    );
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let state = |id| {
        view.get_typed(&APPROVALS, &id)
            .expect("read")
            .expect("the approval")
            .0
            .state
    };
    assert!(matches!(state(tickets[0].id), ApprovalState::Denied { .. }));
    assert!(matches!(state(tickets[1].id), ApprovalState::Denied { .. }));
    assert_eq!(state(tickets[2].id), ApprovalState::Pending);
    let mapped = "::ffff:192.0.2.80".parse().expect("an address");
    assert_eq!(
        env.service
            .clear_approvals(&admin, Some(mapped))
            .await
            .expect("cleared"),
        cleared(1, 0),
        "the IPv4 address"
    );
    assert_eq!(
        env.service
            .clear_approvals(&admin, None)
            .await
            .expect("cleared"),
        cleared(1, 1),
        "the last waiting one and the uncollected one"
    );
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert!(matches!(
        view.get_typed(&APPROVALS, &approved_ticket.id)
            .expect("read")
            .expect("the approval")
            .0
            .state,
        ApprovalState::Denied { .. }
    ));
    // A source that is not an address is no body of the operation.
    for body in [r#"{"source":"192.0.2.0/24"}"#, r#"{"source":"tenko"}"#] {
        let refused = serde_json::from_str::<approval::ClearApprovals>(body).expect_err(body);
        assert!(
            refused.to_string().contains("invalid IP address"),
            "{refused}"
        );
    }
}

/// No audit record of a whole approval names the session's secret, the nonce or the code.
#[tokio::test]
async fn the_audit_never_holds_a_secret_of_the_approval() {
    let (env, _, admin) = installation().await;
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = script.code(&body, ticket.id);
    env.service
        .approve(
            &admin,
            ticket.id,
            &SecretString::new(code.clone()),
            &ROOT_SHA256,
        )
        .await
        .expect("approved");
    let session = env
        .service
        .collect_approval(
            &env.public_ctx(),
            ticket.id,
            script.collect(&ticket).as_bytes(),
        )
        .await
        .expect("collected");
    let records = audit(&env).await;
    let text = serde_json::to_string(
        &records
            .iter()
            .map(|record| &record.draft)
            .collect::<Vec<_>>(),
    )
    .expect("json");
    for secret in [session.secret.expose(), &ticket.nonce, &code] {
        assert!(!text.contains(secret), "an audit record holds a secret");
    }
    let approve = records
        .iter()
        .find(|record| record.draft.action.as_str() == "auth.approval.approve")
        .expect("the approval's record");
    assert_eq!(
        approve
            .draft
            .details
            .context
            .get("request_sha256")
            .map(String::as_str),
        Some(tenko_auth::encoding::hex_encode(&Sha256::digest(body.as_bytes())).as_str())
    );
}

/// The sweep removes an approval whose time is over within one more pending lifetime, not
/// at the next hourly run: on a paused clock, past the first sweep, a request that is ten
/// minutes old is gone ten minutes later.
#[tokio::test(start_paused = true)]
async fn the_sweep_removes_an_ended_approval_within_ten_minutes() {
    let (env, _, _) = installation().await;
    // Past the first sweep, which runs a minute after the service starts.
    tokio::time::sleep(Duration::from_secs(61)).await;
    let old = Timestamp::now()
        .checked_sub(approval::PENDING_LIFETIME)
        .expect("a time");
    let ticket = env
        .service
        .request_approval(
            &env.public_ctx().at(old),
            Script::default().request().as_bytes(),
        )
        .await
        .expect("a request");
    let written = tokio::time::Instant::now();
    let (store, id) = (&env.store, ticket.id);
    let present = move || async move {
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .get_typed(&APPROVALS, &id)
            .expect("read")
            .is_some()
    };
    assert!(present().await, "stored until the next sweep");
    tokio::time::sleep(approval::PENDING_LIFETIME).await;
    tenko_core::testing::wait_until_async("the ended approval removed", || async move {
        assert!(
            written.elapsed() < approval::PENDING_LIFETIME * 2,
            "still stored two pending lifetimes later"
        );
        !present().await
    })
    .await;
}

/// The one check refuses a listed operation whose condition no longer holds: the mirror
/// create five minutes and one second after the approval.
#[tokio::test]
async fn the_check_refuses_an_operation_past_its_condition() {
    let (env, _, admin) = installation().await;
    let session = env
        .delegate(&admin, &Script::default(), client())
        .await
        .expect("a delegated session");
    let who = env
        .service
        .authenticate_from(
            &Credentials::Bearer(session.secret.expose().to_owned()),
            Some(client()),
            env.now(),
        )
        .await
        .expect("acts");
    let approved_at = who.flags.delegation.expect("delegated").approved_at;
    let late = approved_at
        .checked_add(Duration::from_secs(301))
        .expect("a time");
    let refused = env
        .service
        .admit_delegated(
            &who,
            "POST",
            Some("/migrate/mirrors"),
            &[],
            Some(client()),
            late,
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(AuthError::DelegationRefused {
                reason: "condition"
            })
        ),
        "{refused:?}"
    );
}

/// A domain row whose run is gone holds nothing: the next collect of the domain creates a run
/// and the row names it.
#[tokio::test]
async fn a_domain_row_without_its_run_gives_way_to_a_new_run() {
    let (env, _, admin) = installation().await;
    let domain = plan()["domain"].as_str().expect("a domain").to_owned();
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch
        .put_typed(&RUN_DOMAINS, &domain, &DelegationId::generate())
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    let session = env
        .delegate(&admin, &Script::default(), client())
        .await
        .expect("a new run");
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (run, _) = view
        .get_typed(&RUN_DOMAINS, &domain)
        .expect("read")
        .expect("the row");
    assert_eq!(run, session.delegation);
}
