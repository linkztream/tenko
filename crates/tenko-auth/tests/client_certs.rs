//! Integration client certificates (ADR 0035) against the in-memory store and vault, with a
//! stand-in for the integration CA: enrollment codes, the HMAC proof and its test vector,
//! every refusal of an enrollment, the single recording write, revocation of a lineage, and
//! the index the integration listener asks.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use tenko_auth::{
    client_cert::{
        Acceptance, ClientCertError, ClientCerts, EnrollInput, Issued, Issuer, NewCode, OVERLAP,
        Renewal, alarm_after, enrollment_proof,
        model::{
            CLIENT_CERT_KEYS, CLIENT_CERTS, CertState, ClientCertRecord, CodeState,
            ENROLLMENT_CODES, IntegrationPolicy,
        },
        renew_after,
    },
    encoding::{hex_decode, hex_encode},
    model::{USERS, UserKind, UserRecord},
    settings::Profile,
};
use tenko_core::{
    RequestCtx, SystemComponent, Timestamp, UserId, audit::AuditOutcome, testing::wait_until_async,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt as _, Store, WriteBatch, mem::MemStore, tables,
};
use tenko_vault::{MemVault, Vault};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The internal root's fingerprint the stand-in reports.
const ROOT: &str = "ab";

/// A stand-in for the integration CA: the "request" is the canonical key itself.
#[derive(Default)]
struct FakeIssuer {
    serials: AtomicU64,
    roots: AtomicU64,
}

#[async_trait]
impl Issuer for FakeIssuer {
    fn request_key(&self, csr: &[u8]) -> Result<Vec<u8>, ClientCertError> {
        if csr.len() == 91 {
            Ok(csr.to_vec())
        } else {
            Err(ClientCertError::InvalidRequest {
                reason: "not a key".to_owned(),
            })
        }
    }

    async fn ensure_root(&self, _ctx: &RequestCtx) -> Result<(), ClientCertError> {
        self.roots.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn issue(
        &self,
        ctx: &RequestCtx,
        _account: UserId,
        csr: &[u8],
        days: u32,
    ) -> Result<Issued, ClientCertError> {
        let serial = format!("{:032x}", self.serials.fetch_add(1, Ordering::SeqCst) + 1);
        Ok(Issued {
            pem: format!("PEM {serial}"),
            serial,
            key_sha256: hex_encode(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, csr).as_ref(),
            ),
            not_before: Timestamp(ctx.now.0 - Duration::hours(1)),
            not_after: Timestamp(ctx.now.0 + Duration::days(i64::from(days))),
        })
    }

    fn server_root_sha256(&self) -> String {
        ROOT.to_owned()
    }

    fn server_root_pem(&self) -> String {
        "PEM root".to_owned()
    }
}

struct Env {
    store: Arc<MemStore>,
    issuer: Arc<FakeIssuer>,
    certs: Arc<ClientCerts>,
}

impl Env {
    fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(store.clone()));
        let issuer = Arc::new(FakeIssuer::default());
        let certs = Arc::new(ClientCerts::new(
            store.clone(),
            vault,
            issuer.clone() as Arc<dyn Issuer>,
        ));
        Self {
            store,
            issuer,
            certs,
        }
    }

    async fn put_user(&self, user: &UserRecord) {
        let mut batch = WriteBatch::for_request(&ctx(t0()));
        batch.put_typed(&USERS, &user.id, user).expect("encode");
        self.store.propose(batch).await.expect("write");
    }

    async fn service_account(&self) -> UserRecord {
        let mut user = UserRecord::new(
            format!("svc-{}", Uuid::now_v7().simple()),
            "an integration".to_owned(),
            Vec::new(),
            t0(),
        );
        user.kind = UserKind::Service;
        self.put_user(&user).await;
        user
    }

    async fn user(&self, id: UserId) -> UserRecord {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(&USERS, &id)
            .expect("read")
            .expect("exists")
            .0
    }

    async fn code(&self, account: UserId) -> Code {
        self.code_with(account, None, None).await
    }

    async fn code_with(
        &self,
        account: UserId,
        lifetime_secs: Option<u64>,
        source: Option<&str>,
    ) -> Code {
        let created = self
            .certs
            .create_code(
                &ctx(t0()),
                UserId::generate(),
                &NewCode {
                    account,
                    lifetime_secs,
                    source: source.map(|net| net.parse().expect("network")),
                },
            )
            .await
            .expect("code");
        Code::parse(&created.code)
    }

    async fn enroll(&self, code: &Code, key: &[u8]) -> Result<String, ClientCertError> {
        self.enroll_at(code, key, t0(), "backup-host").await
    }

    async fn enroll_at(
        &self,
        code: &Code,
        key: &[u8],
        at: Timestamp,
        label: &str,
    ) -> Result<String, ClientCertError> {
        self.certs
            .enroll(
                &ctx(at),
                EnrollInput {
                    code: code.id,
                    proof: code.proof(label, key),
                    csr: key.to_vec(),
                    label: label.to_owned(),
                    source: Some(CLIENT.parse().expect("address")),
                },
            )
            .await
    }

    async fn code_state(&self, id: Uuid) -> (CodeState, bool) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let code = view
            .get_typed(&ENROLLMENT_CODES, &id)
            .expect("read")
            .expect("exists")
            .0;
        (code.state, code.secret.is_some())
    }

    async fn audit_outcomes(&self, action: &str) -> Vec<AuditOutcome> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("scan")
            .into_iter()
            .filter(|(_, record, _)| record.draft.action.as_str() == action)
            .map(|(_, record, _)| record.draft.outcome)
            .collect()
    }
}

/// An enrollment code as the integrator reads it.
struct Code {
    id: Uuid,
    account: UserId,
    secret: Vec<u8>,
}

impl Code {
    fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split('.').collect();
        assert_eq!(parts.len(), 5, "{text}");
        assert_eq!(parts[0], "tnki");
        assert_eq!(parts[4], ROOT);
        assert_eq!(parts[3].len(), 64);
        Self {
            id: parts[1].parse().expect("code id"),
            account: parts[2].parse().expect("account id"),
            secret: hex_decode(parts[3]).expect("secret"),
        }
    }

    fn proof(&self, label: &str, key: &[u8]) -> Vec<u8> {
        enrollment_proof(&self.secret, self.id, self.account, label, key)
    }
}

const CLIENT: &str = "192.0.2.10";

fn t0() -> Timestamp {
    Timestamp(OffsetDateTime::from_unix_timestamp(1_790_000_000).expect("timestamp"))
}

fn ctx(at: Timestamp) -> RequestCtx {
    RequestCtx::system(SystemComponent::Api).at(at)
}

/// A canonical P-256 `SubjectPublicKeyInfo` whose point starts with `seed`.
fn key(seed: u8) -> Vec<u8> {
    let mut spki =
        hex_decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004").expect("prefix");
    spki.extend((0..64u8).map(|i| i.wrapping_add(seed)));
    spki
}

#[test]
fn the_proof_matches_the_documented_test_vector() {
    // The vector of docs/integrations.md section 4: Python's hmac, openssl dgst and
    // PowerShell's HMACSHA256 give the same bytes.
    let secret: Vec<u8> = (0..32).collect();
    let code: Uuid = "0190d1c2-0000-7000-8000-000000000001".parse().expect("id");
    let account: UserId = "0190d1c2-0000-7000-8000-000000000002".parse().expect("id");
    let spki = key(1);
    assert_eq!(
        hex_encode(&enrollment_proof(
            &secret,
            code,
            account,
            "backup-host",
            &spki
        )),
        "04e334886c0b67b47232d484cb50b985829581aa8174d80b5a16ab39b6746fe8"
    );
}

#[test]
fn the_policy_follows_the_profile() {
    let values: Vec<_> = Profile::ALL
        .iter()
        .map(|profile| {
            let policy = IntegrationPolicy::of(*profile);
            (
                policy.lifetime_days,
                policy.require_binding,
                policy.allow_tls12,
            )
        })
        .collect();
    assert_eq!(
        values,
        [
            (90, false, false),
            (30, false, false),
            (7, true, false),
            (365, false, false)
        ]
    );
}

#[tokio::test]
async fn a_code_is_shown_once_and_its_secret_kept_in_the_vault() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    assert_eq!(code.account, account.id);
    assert_eq!(env.issuer.roots.load(Ordering::SeqCst), 1);
    assert_eq!(env.code_state(code.id).await, (CodeState::Pending, true));

    let listed = env.certs.list_codes(t0()).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].expired);
    let json = serde_json::to_string(&listed).expect("json");
    assert!(!json.contains(&hex_encode(&code.secret)));

    // The secret is in the vault, not in the record.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let stored = view
        .scan_typed(&ENROLLMENT_CODES, KeyRange::all(), 10, false)
        .expect("scan");
    let record = serde_json::to_string(&stored[0].1).expect("json");
    assert!(!record.contains(&hex_encode(&code.secret)));

    for lifetime in [59, 3601] {
        let refused = env
            .certs
            .create_code(
                &ctx(t0()),
                UserId::generate(),
                &NewCode {
                    account: account.id,
                    lifetime_secs: Some(lifetime),
                    source: None,
                },
            )
            .await;
        assert_eq!(refused.err(), Some(ClientCertError::Lifetime), "{lifetime}");
    }
}

#[tokio::test]
async fn codes_are_only_for_enabled_service_accounts() {
    let env = Env::new();
    let person = UserRecord::new("pat".to_owned(), "Pat".to_owned(), Vec::new(), t0());
    env.put_user(&person).await;
    let mut disabled = env.service_account().await;
    disabled.disabled = true;
    env.put_user(&disabled).await;
    for id in [person.id, disabled.id, UserId::generate()] {
        let refused = env
            .certs
            .create_code(
                &ctx(t0()),
                UserId::generate(),
                &NewCode {
                    account: id,
                    lifetime_secs: None,
                    source: None,
                },
            )
            .await;
        assert_eq!(refused.err(), Some(ClientCertError::Account));
    }
}

#[tokio::test]
async fn an_enrollment_records_the_certificate_and_uses_the_code() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    let pem = env.enroll(&code, &key(1)).await.expect("enroll");
    assert!(pem.starts_with("PEM "));

    let (state, secret_left) = env.code_state(code.id).await;
    assert!(matches!(state, CodeState::Used { .. }));
    assert!(!secret_left);
    let records = env.certs.list(Some(account.id)).await.expect("list");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.state, CertState::Current);
    assert_eq!(record.label, "backup-host");
    assert_eq!(record.generation, account.tokens_generation);
    assert_eq!(record.not_after.0, t0().0 + Duration::days(30));
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert!(
        view.get_typed(&CLIENT_CERT_KEYS, &record.key_sha256)
            .expect("read")
            .is_some()
    );
    assert_eq!(
        env.audit_outcomes("auth.client_cert.issue").await,
        [AuditOutcome::Success]
    );

    // The same code again.
    assert_eq!(
        env.enroll(&code, &key(2)).await.err(),
        Some(ClientCertError::CodeUsed)
    );
}

#[tokio::test]
async fn every_refusal_leaves_the_code_and_is_audited() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code(account.id).await;

    // A proof made with another secret, over another key or for another account.
    let wrong = Code::parse(&format!(
        "tnki.{}.{}.{}.{ROOT}",
        code.id,
        code.account,
        hex_encode(&[7u8; 32])
    ));
    for input in [
        EnrollInput {
            code: code.id,
            proof: wrong.proof("h", &key(1)),
            csr: key(1),
            label: "h".to_owned(),
            source: None,
        },
        EnrollInput {
            code: code.id,
            proof: code.proof("h", &key(2)),
            csr: key(1),
            label: "h".to_owned(),
            source: None,
        },
        EnrollInput {
            code: code.id,
            proof: enrollment_proof(&code.secret, code.id, UserId::generate(), "h", &key(1)),
            csr: key(1),
            label: "h".to_owned(),
            source: None,
        },
        EnrollInput {
            code: Uuid::now_v7(),
            proof: code.proof("h", &key(1)),
            csr: key(1),
            label: "h".to_owned(),
            source: None,
        },
        // The label is part of the proof: a proxy cannot relabel the host.
        EnrollInput {
            code: code.id,
            proof: code.proof("h", &key(1)),
            csr: key(1),
            label: "other".to_owned(),
            source: None,
        },
    ] {
        assert_eq!(
            env.certs.enroll(&ctx(t0()), input).await.err(),
            Some(ClientCertError::CodeInvalid)
        );
    }

    for label in [
        "",
        "   ",
        " padded",
        &"x".repeat(65),
        "line\nbreak",
        "zero\u{200b}width",
        "right\u{202e}to-left",
        "soft\u{ad}hyphen",
        "tag\u{e0041}",
    ] {
        assert_eq!(
            env.enroll_at(&code, &key(1), t0(), label).await.err(),
            Some(ClientCertError::Label),
            "{label:?}"
        );
    }
    assert!(matches!(
        env.enroll(&code, b"not a request").await,
        Err(ClientCertError::InvalidRequest { .. })
    ));
    assert_eq!(env.code_state(code.id).await, (CodeState::Pending, true));
    // Every refusal but the one of the unknown code id.
    assert_eq!(env.audit_outcomes("auth.client_cert.issue").await.len(), 14);
    assert!(
        env.audit_outcomes("auth.client_cert.issue")
            .await
            .iter()
            .all(|outcome| *outcome != AuditOutcome::Success)
    );

    // Expired.
    let late = Timestamp(t0().0 + Duration::hours(1));
    assert_eq!(
        env.enroll_at(&code, &key(1), late, "h").await.err(),
        Some(ClientCertError::CodeExpired)
    );
    // Still good just before.
    let early = Timestamp(late.0 - Duration::seconds(1));
    assert!(env.enroll_at(&code, &key(1), early, "h").await.is_ok());
}

#[tokio::test]
async fn the_source_network_the_account_and_the_key_are_checked() {
    let env = Env::new();
    let account = env.service_account().await;

    let elsewhere = env
        .code_with(account.id, None, Some("198.51.100.0/24"))
        .await;
    assert_eq!(
        env.enroll(&elsewhere, &key(1)).await.err(),
        Some(ClientCertError::CodeSource)
    );
    let here = env.code_with(account.id, None, Some("192.0.2.0/24")).await;
    env.enroll(&here, &key(1)).await.expect("from its network");

    // A key enrolls once, for any account.
    let other = env.service_account().await;
    let again = env.code(other.id).await;
    assert_eq!(
        env.enroll(&again, &key(1)).await.err(),
        Some(ClientCertError::KeyUsed)
    );

    // An end of the account's access since the code was made ends the code.
    let waiting = env.code(account.id).await;
    let mut ended = env.user(account.id).await;
    ended.tokens_generation += 1;
    env.put_user(&ended).await;
    assert_eq!(
        env.enroll(&waiting, &key(3)).await.err(),
        Some(ClientCertError::Account)
    );
    let disabled_code = env.code(other.id).await;
    let mut disabled = env.user(other.id).await;
    disabled.disabled = true;
    env.put_user(&disabled).await;
    assert_eq!(
        env.enroll(&disabled_code, &key(4)).await.err(),
        Some(ClientCertError::Account)
    );
}

#[tokio::test]
async fn an_account_holds_at_most_eight_lineages() {
    let env = Env::new();
    let account = env.service_account().await;
    for seed in 0..8 {
        let code = env.code(account.id).await;
        env.enroll(&code, &key(seed * 10)).await.expect("enroll");
    }
    let code = env.code(account.id).await;
    assert_eq!(
        env.enroll(&code, &key(100)).await.err(),
        Some(ClientCertError::Lineages)
    );
    // A revoked lineage frees its place.
    let first = env.certs.list(Some(account.id)).await.expect("list")[0]
        .serial
        .clone();
    env.certs
        .revoke(&ctx(t0()), &first, "test")
        .await
        .expect("revoke");
    env.enroll(&code, &key(100)).await.expect("a place is free");
}

#[tokio::test]
async fn plain_http_is_refused_and_audited_and_the_code_stays_usable() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    let refused = env
        .certs
        .refuse_transport(&ctx(t0()), code.id, "plain HTTP")
        .await;
    assert_eq!(refused, ClientCertError::Transport("plain HTTP"));
    assert_eq!(
        env.audit_outcomes("auth.client_cert.issue").await,
        [AuditOutcome::Denied]
    );
    assert_eq!(env.code_state(code.id).await.0, CodeState::Pending);
    // Whoever knows only a code id cannot burn the code: it still enrolls over HTTPS.
    env.enroll(&code, &key(1))
        .await
        .expect("enrolled after the refusal");
    // An unknown code answers the same refusal.
    assert_eq!(
        env.certs
            .refuse_transport(&ctx(t0()), Uuid::now_v7(), "plain HTTP")
            .await,
        ClientCertError::Transport("plain HTTP")
    );
    // An administrator withdraws a waiting code.
    let other = env.code(account.id).await;
    env.certs
        .withdraw_code(&ctx(t0()), other.id)
        .await
        .expect("withdraw");
    assert_eq!(
        env.code_state(other.id).await,
        (CodeState::Withdrawn, false)
    );
}

#[tokio::test]
async fn the_index_accepts_only_recorded_certificates_of_usable_accounts() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    env.enroll(&code, &key(1)).await.expect("enroll");
    let serial = env.certs.list(None).await.expect("list")[0].serial.clone();
    let now = Timestamp(t0().0 + Duration::minutes(1));

    // Nothing passes before the first full load.
    assert!(matches!(
        index.accept(&serial, account.id, now),
        Acceptance::Refused(_)
    ));
    index.load(env.store.as_ref()).await.expect("load");
    assert!(index.is_loaded());
    assert!(matches!(
        index.accept(&serial, account.id, now),
        Acceptance::Accepted(_)
    ));
    for (serial, account, at) in [
        ("00", account.id, now),
        (serial.as_str(), UserId::generate(), now),
        (
            serial.as_str(),
            account.id,
            Timestamp(t0().0 + Duration::days(31)),
        ),
    ] {
        assert!(
            matches!(index.accept(serial, account, at), Acceptance::Refused(_)),
            "{serial} {at:?}"
        );
    }

    // An end of the account's access ends its certificates at once.
    let mut ended = env.user(account.id).await;
    ended.tokens_generation += 1;
    env.put_user(&ended).await;
    index.load(env.store.as_ref()).await.expect("load");
    assert!(matches!(
        index.accept(&serial, account.id, now),
        Acceptance::Refused(_)
    ));
}

#[tokio::test]
async fn a_replaced_certificate_passes_for_the_overlap_then_for_renewal_only() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    env.enroll(&code, &key(1)).await.expect("enroll");
    let mut record = env.certs.list(None).await.expect("list")[0].clone();
    let replaced_at = Timestamp(t0().0 + Duration::days(20));
    record.state = CertState::Replaced;
    record.ended_at = Some(replaced_at);
    let mut batch = WriteBatch::for_request(&ctx(replaced_at));
    batch
        .put_typed(&CLIENT_CERTS, &record.serial, &record)
        .expect("encode");
    env.store.propose(batch).await.expect("write");
    index.load(env.store.as_ref()).await.expect("load");

    let inside = Timestamp(replaced_at.0 + OVERLAP - Duration::seconds(1));
    let after = Timestamp(replaced_at.0 + OVERLAP);
    assert!(matches!(
        index.accept(&record.serial, account.id, inside),
        Acceptance::Accepted(_)
    ));
    assert!(matches!(
        index.accept(&record.serial, account.id, after),
        Acceptance::RenewOnly(_)
    ));
}

#[tokio::test]
async fn revoking_ends_the_whole_lineage_once() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    env.enroll(&code, &key(1)).await.expect("enroll");
    let serial = env.certs.list(None).await.expect("list")[0].serial.clone();
    env.certs
        .revoke(&ctx(t0()), &serial, "the host was retired")
        .await
        .expect("revoke");
    let record = env.certs.list(None).await.expect("list")[0].clone();
    assert_eq!(record.state, CertState::Revoked);
    assert_eq!(record.reason.as_deref(), Some("the host was retired"));
    index.load(env.store.as_ref()).await.expect("load");
    assert!(matches!(
        index.accept(&serial, account.id, t0()),
        Acceptance::Refused(_)
    ));
    // Again: nothing more to revoke, one audit record.
    env.certs
        .revoke(&ctx(t0()), &serial, "again")
        .await
        .expect("idempotent");
    assert_eq!(env.audit_outcomes("auth.client_cert.revoke").await.len(), 1);
    assert_eq!(
        env.certs.revoke(&ctx(t0()), "00", "x").await.err(),
        Some(ClientCertError::NotFound("certificate"))
    );
    // A revoked key never enrolls again.
    let again = env.code(account.id).await;
    assert_eq!(
        env.enroll(&again, &key(1)).await.err(),
        Some(ClientCertError::KeyUsed)
    );
}

#[tokio::test]
async fn the_index_says_when_the_listener_is_wanted_and_signals_each_load() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let mut changes = index.subscribe();
    index.load(env.store.as_ref()).await.expect("load");
    assert!(changes.has_changed().expect("open"));
    changes.mark_unchanged();
    let now = Timestamp::now();
    assert!(!index.wanted(now), "nothing uses it");
    assert_eq!(index.policy(), IntegrationPolicy::of(Profile::Standard));

    // The index judges codes and certificates by the clock, so this test lives at `now`.
    let account = env.service_account().await;
    let created = env
        .certs
        .create_code(
            &ctx(now),
            UserId::generate(),
            &NewCode {
                account: account.id,
                lifetime_secs: None,
                source: None,
            },
        )
        .await
        .expect("code");
    let code = Code::parse(&created.code);
    index.load(env.store.as_ref()).await.expect("load");
    assert!(changes.has_changed().expect("open"));
    assert!(index.wanted(now), "a code waits");

    env.enroll_at(&code, &key(1), now, "host")
        .await
        .expect("enroll");
    index.load(env.store.as_ref()).await.expect("load");
    assert!(index.wanted(now), "a certificate is in use");
    let serial = env.certs.list(None).await.expect("list")[0].serial.clone();
    env.certs
        .revoke(&ctx(now), &serial, "test")
        .await
        .expect("revoke");
    index.load(env.store.as_ref()).await.expect("load");
    assert!(!index.wanted(now), "nothing is in use any more");
}

/// `days` and `hours` after `t0`.
fn at(days: i64, hours: i64) -> Timestamp {
    Timestamp(t0().0 + Duration::days(days) + Duration::hours(hours))
}

/// An account with one enrolled certificate over `key(1)`, issued at `t0` for 30 days.
async fn enrolled(env: &Env) -> (UserRecord, ClientCertRecord) {
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    env.enroll(&code, &key(1)).await.expect("enroll");
    let record = env.certs.list(Some(account.id)).await.expect("list")[0].clone();
    (account, record)
}

async fn renew_at(
    env: &Env,
    at: Timestamp,
    record: &ClientCertRecord,
    csr: &[u8],
) -> Result<Renewal, ClientCertError> {
    env.certs
        .renew(&ctx(at), &record.serial, record.account, csr)
        .await
}

async fn state_of(env: &Env, serial: &str) -> CertState {
    env.certs
        .list(None)
        .await
        .expect("list")
        .into_iter()
        .find(|record| record.serial == serial)
        .expect("recorded")
        .state
}

fn renewed(result: Result<Renewal, ClientCertError>) -> String {
    match result {
        Ok(Renewal::Renewed { serial, .. }) => serial,
        other => panic!("expected a renewal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_renewal_is_due_in_the_last_third_and_at_most_hourly() {
    let env = Env::new();
    let (_, current) = enrolled(&env).await;
    // Valid from t0 - 1 h for 30 days and 1 hour: due two thirds in, a little before day 20.
    let due = renew_after(&current);
    assert!(at(19, 0).0 < due.0 && due.0 < at(21, 0).0, "{due:?}");
    let early = renew_at(&env, at(19, 0), &current, &key(2)).await;
    assert_eq!(
        early,
        Ok(Renewal::NotDue {
            renew_after: renew_after(&current)
        })
    );

    let first = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    assert_eq!(state_of(&env, &first).await, CertState::Pending);
    assert_eq!(state_of(&env, &current.serial).await, CertState::Current);
    let successor = env
        .certs
        .list(None)
        .await
        .expect("list")
        .into_iter()
        .find(|record| record.serial == first)
        .expect("recorded");
    assert_eq!(successor.lineage, current.lineage);
    assert_eq!(successor.label, current.label);
    assert_eq!(
        env.audit_outcomes("auth.client_cert.renew").await,
        [AuditOutcome::Success]
    );

    // Within the hour: refused. The answer was lost: an hour later the unseen successor is
    // replaced by a new one.
    assert_eq!(
        renew_at(&env, at(21, 0), &current, &key(3)).await,
        Err(ClientCertError::TooSoon)
    );
    let second = renewed(renew_at(&env, at(21, 2), &current, &key(3)).await);
    assert_eq!(state_of(&env, &first).await, CertState::Withdrawn);
    assert_eq!(state_of(&env, &second).await, CertState::Pending);
    // A withdrawn successor's key does not enroll or renew again.
    assert_eq!(
        renew_at(&env, at(22, 0), &current, &key(2)).await,
        Err(ClientCertError::KeyUsed)
    );
}

#[tokio::test]
async fn the_successor_takes_over_at_its_first_presentation_and_reuse_revokes() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let (account, current) = enrolled(&env).await;
    let successor = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    env.certs
        .note_presented(&ctx(at(21, 1)), &successor)
        .await
        .expect("presented");
    assert_eq!(state_of(&env, &successor).await, CertState::Current);
    assert_eq!(state_of(&env, &current.serial).await, CertState::Replaced);
    index.load(env.store.as_ref()).await.expect("load");
    assert!(matches!(
        index.accept(&current.serial, account.id, at(21, 1)),
        Acceptance::Accepted(_)
    ));
    assert!(matches!(
        index.accept(&current.serial, account.id, at(21, 2)),
        Acceptance::RenewOnly(_)
    ));
    // Presenting it again changes nothing.
    env.certs
        .note_presented(&ctx(at(21, 2)), &successor)
        .await
        .expect("again");

    // A renewal from the replaced certificate: someone else holds a key of the lineage.
    assert_eq!(
        renew_at(&env, at(22, 0), &current, &key(9)).await,
        Err(ClientCertError::Reuse)
    );
    assert_eq!(state_of(&env, &successor).await, CertState::Revoked);
    assert_eq!(state_of(&env, &current.serial).await, CertState::Revoked);
}

#[tokio::test]
async fn the_same_key_renews_and_another_lineages_key_does_not() {
    let env = Env::new();
    let (_, current) = enrolled(&env).await;
    let (_, other) = enrolled_with(&env, &key(50)).await;
    assert_eq!(
        renew_at(&env, at(21, 0), &current, &key(50)).await,
        Err(ClientCertError::KeyUsed)
    );
    let same = renewed(renew_at(&env, at(21, 0), &current, &key(1)).await);
    let records = env.certs.list(None).await.expect("list");
    let successor = records
        .iter()
        .find(|record| record.serial == same)
        .expect("recorded");
    assert_eq!(successor.key_sha256, current.key_sha256);
    assert_ne!(other.lineage, current.lineage);
}

async fn enrolled_with(env: &Env, spki: &[u8]) -> (UserRecord, ClientCertRecord) {
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    env.enroll(&code, spki).await.expect("enroll");
    let record = env.certs.list(Some(account.id)).await.expect("list")[0].clone();
    (account, record)
}

#[tokio::test]
async fn a_lineage_that_does_not_renew_is_listed_as_expiring() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let (_, current) = enrolled(&env).await;
    index.load(env.store.as_ref()).await.expect("load");
    assert!(
        index.expiring(at(24, 0)).is_empty(),
        "not in the last sixth yet"
    );
    let alarm = alarm_after(&current);
    assert!(at(24, 0).0 < alarm.0 && alarm.0 < at(26, 0).0, "{alarm:?}");
    let expiring = index.expiring(at(26, 0));
    assert_eq!(expiring.len(), 1);
    assert_eq!(expiring[0].serial, current.serial);
    assert!(
        index.expiring(at(31, 0)).is_empty(),
        "an expired one alarms no more"
    );

    renewed(renew_at(&env, at(26, 0), &current, &key(2)).await);
    index.load(env.store.as_ref()).await.expect("load");
    assert!(
        index.expiring(at(26, 1)).is_empty(),
        "a renewed lineage does not alarm"
    );
}

#[tokio::test]
async fn a_renewal_needs_a_certificate_that_still_passes() {
    let env = Env::new();
    let (account, current) = enrolled(&env).await;
    assert_eq!(
        env.certs
            .renew(
                &ctx(at(21, 0)),
                &current.serial,
                UserId::generate(),
                &key(2)
            )
            .await,
        Err(ClientCertError::Certificate)
    );
    assert_eq!(
        env.certs
            .renew(&ctx(at(21, 0)), "00", account.id, &key(2))
            .await,
        Err(ClientCertError::Certificate)
    );
    assert_eq!(
        renew_at(&env, at(31, 0), &current, &key(2)).await,
        Err(ClientCertError::Certificate),
        "expired"
    );
    let mut ended = env.user(account.id).await;
    ended.tokens_generation += 1;
    env.put_user(&ended).await;
    assert_eq!(
        renew_at(&env, at(21, 0), &current, &key(2)).await,
        Err(ClientCertError::Certificate),
        "the account's tokens ended"
    );
}

/// A store whose next write waits at a gate until the test opens it, so that another
/// operation can commit between this one's read and its write. It also counts the reads at
/// the leader, and commits `after_read` right after the next read took its snapshot.
struct Gated {
    inner: Arc<MemStore>,
    gate: std::sync::Mutex<Option<Gate>>,
    leader_reads: AtomicU64,
    after_read: std::sync::Mutex<Option<WriteBatch>>,
}

type Gate = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

impl Gated {
    /// Holds the next write: the first receiver hears when it reached the gate, the sender
    /// opens it.
    fn hold(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached, reached_rx) = tokio::sync::oneshot::channel();
        let (open, open_rx) = tokio::sync::oneshot::channel();
        *self.gate.lock().expect("gate") = Some((reached, open_rx));
        (reached_rx, open)
    }
}

#[async_trait]
impl Store for Gated {
    async fn propose(
        &self,
        batch: WriteBatch,
    ) -> Result<tenko_store::Committed, tenko_store::StoreError> {
        let held = self.gate.lock().expect("gate").take();
        if let Some((reached, open)) = held {
            let _ = reached.send(());
            let _ = open.await;
        }
        self.inner.propose(batch).await
    }

    async fn read(
        &self,
        consistency: ReadConsistency,
    ) -> Result<Arc<dyn tenko_store::ReadView>, tenko_store::StoreError> {
        if matches!(consistency, ReadConsistency::Linearizable) {
            self.leader_reads.fetch_add(1, Ordering::SeqCst);
        }
        let view = self.inner.read(consistency).await?;
        let after = self.after_read.lock().expect("batch").take();
        if let Some(batch) = after {
            self.inner.propose(batch).await?;
        }
        Ok(view)
    }

    fn watch(
        &self,
        from: Option<tenko_core::Revision>,
        filter: tenko_store::WatchFilter,
    ) -> Result<tenko_store::ChangeStream, tenko_store::StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(
        &self,
        index: Arc<dyn tenko_store::DerivedIndex>,
    ) -> Result<(), tenko_store::StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> tenko_store::StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// A second service over the same store whose next write the test holds at a gate.
fn racing(env: &Env) -> (Arc<ClientCerts>, Arc<Gated>) {
    let gated = Arc::new(Gated {
        inner: Arc::clone(&env.store),
        gate: std::sync::Mutex::new(None),
        leader_reads: AtomicU64::new(0),
        after_read: std::sync::Mutex::new(None),
    });
    let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(env.store.clone()));
    let certs = Arc::new(ClientCerts::new(
        gated.clone() as Arc<dyn Store>,
        vault,
        env.issuer.clone() as Arc<dyn Issuer>,
    ));
    (certs, gated)
}

/// The pending certificates of a lineage.
async fn pending(env: &Env, lineage: Uuid) -> Vec<String> {
    env.certs
        .list(None)
        .await
        .expect("list")
        .into_iter()
        .filter(|record| record.lineage == lineage && record.state == CertState::Pending)
        .map(|record| record.serial)
        .collect()
}

#[tokio::test]
async fn a_revocation_that_read_the_lineage_before_a_renewal_also_ends_its_successor() {
    let env = Env::new();
    let (_, current) = enrolled(&env).await;
    let (other, gated) = racing(&env);
    let (reached, open) = gated.hold();
    let serial = current.serial.clone();
    let revocation = tokio::spawn(async move {
        other
            .revoke(&ctx(at(21, 0)), &serial, "an administrator ended it")
            .await
    });
    reached.await.expect("the revocation read the lineage");
    let successor = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    open.send(()).expect("open");
    revocation.await.expect("task").expect("revoked");
    assert_eq!(state_of(&env, &current.serial).await, CertState::Revoked);
    assert_eq!(state_of(&env, &successor).await, CertState::Revoked);
}

#[tokio::test]
async fn of_two_renewals_at_once_one_commits_and_the_lineage_keeps_one_pending() {
    let env = Env::new();
    let (_, current) = enrolled(&env).await;
    let (other, gated) = racing(&env);
    let (reached, open) = gated.hold();
    let (serial, account) = (current.serial.clone(), current.account);
    let first = tokio::spawn(async move {
        other
            .renew(&ctx(at(21, 0)), &serial, account, &key(2))
            .await
    });
    reached.await.expect("the first renewal read the lineage");
    let second = renewed(renew_at(&env, at(21, 0), &current, &key(3)).await);
    open.send(()).expect("open");
    assert_eq!(first.await.expect("task"), Err(ClientCertError::Conflict));
    assert_eq!(pending(&env, current.lineage).await, [second]);
    assert_eq!(state_of(&env, &current.serial).await, CertState::Current);
}

#[tokio::test]
async fn a_presentation_that_read_the_lineage_before_a_renewal_does_not_promote_a_withdrawn_successor()
 {
    let env = Env::new();
    let (_, current) = enrolled(&env).await;
    let unseen = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    let (other, gated) = racing(&env);
    let (reached, open) = gated.hold();
    let serial = unseen.clone();
    let presentation =
        tokio::spawn(async move { other.note_presented(&ctx(at(22, 0)), &serial).await });
    reached.await.expect("the presentation read the lineage");
    // The answer of the first renewal was lost: the host renews again and withdraws it.
    let replacement = renewed(renew_at(&env, at(22, 0), &current, &key(3)).await);
    open.send(()).expect("open");
    assert_eq!(
        presentation.await.expect("task"),
        Err(ClientCertError::Conflict)
    );
    assert_eq!(state_of(&env, &unseen).await, CertState::Withdrawn);
    assert_eq!(state_of(&env, &replacement).await, CertState::Pending);
    assert_eq!(state_of(&env, &current.serial).await, CertState::Current);
}

#[tokio::test]
async fn an_index_that_cannot_read_a_change_refuses_after_the_bound_and_names_its_boundaries() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let (account, current) = enrolled(&env).await;
    index.load(env.store.as_ref()).await.expect("load");
    let now = at(1, 0);
    assert_eq!(
        index.next_boundary(&current.serial, now),
        Some(current.not_after),
        "a current certificate changes at its end"
    );
    let changes = index.subscribe();
    index.mark_stale(now);
    assert!(
        changes.has_changed().expect("open"),
        "connections hear of it"
    );
    let bound = Timestamp(now.0 + tenko_auth::client_cert::STALE_LIMIT);
    assert_eq!(index.next_boundary(&current.serial, now), Some(bound));
    assert!(matches!(
        index.accept(
            &current.serial,
            account.id,
            Timestamp(bound.0 - Duration::seconds(1))
        ),
        Acceptance::Accepted(_)
    ));
    assert_eq!(
        index.accept(&current.serial, account.id, bound),
        Acceptance::Refused("the records could not be read for too long")
    );
    // A load that succeeds ends it.
    index.load(env.store.as_ref()).await.expect("load");
    assert!(matches!(
        index.accept(&current.serial, account.id, bound),
        Acceptance::Accepted(_)
    ));

    // A replaced certificate changes at the end of its overlap.
    let successor = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    env.certs
        .note_presented(&ctx(at(21, 0)), &successor)
        .await
        .expect("presented");
    index.load(env.store.as_ref()).await.expect("load");
    assert_eq!(
        index.next_boundary(&current.serial, at(21, 0)),
        Some(Timestamp(at(21, 0).0 + OVERLAP))
    );
}

#[tokio::test]
async fn a_revocation_committed_while_the_index_loads_reaches_it() {
    let env = Env::new();
    let (account, current) = enrolled(&env).await;
    let (certs, gated) = racing(&env);
    let mut revoked = current.clone();
    revoked.state = CertState::Revoked;
    revoked.ended_at = Some(t0());
    let mut batch = WriteBatch::for_request(&ctx(t0()));
    batch
        .put_typed(&CLIENT_CERTS, &revoked.serial, &revoked)
        .expect("encode");
    // Committed after the load's snapshot and before anything else happens.
    *gated.after_read.lock().expect("batch") = Some(batch);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let follower = certs.follow(stopped);
    wait_until_async("the index refuses the revoked certificate", || async {
        certs.index().accept(&current.serial, account.id, at(1, 0)) == Acceptance::Refused("ended")
    })
    .await;
    stop.send(true).expect("the follower listens");
    follower.await.expect("the follower ends");
}

#[tokio::test]
async fn unknown_code_ids_cost_one_leader_read_and_no_audit_record() {
    let env = Env::new();
    let (certs, gated) = racing(&env);
    let unknown = Uuid::now_v7();
    for _ in 0..3 {
        let input = EnrollInput {
            code: unknown,
            proof: vec![0; 32],
            csr: key(1),
            label: "h".to_owned(),
            source: None,
        };
        assert_eq!(
            certs.enroll(&ctx(t0()), input).await.err(),
            Some(ClientCertError::CodeInvalid)
        );
    }
    assert_eq!(
        certs
            .refuse_transport(&ctx(t0()), unknown, "plain HTTP")
            .await,
        ClientCertError::Transport("plain HTTP")
    );
    assert_eq!(gated.leader_reads.load(Ordering::SeqCst), 1);
    assert_eq!(env.audit_outcomes("auth.client_cert.issue").await, []);
}

#[tokio::test]
async fn the_sweep_deletes_ended_certificates_past_their_validity_and_keeps_their_keys() {
    let env = Env::new();
    let (account, current) = enrolled(&env).await;
    let successor = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    env.certs
        .note_presented(&ctx(at(21, 1)), &successor)
        .await
        .expect("presented");
    let serials = || async {
        env.certs
            .list(None)
            .await
            .expect("list")
            .into_iter()
            .map(|record| record.serial)
            .collect::<Vec<_>>()
    };
    env.certs
        .remove_lapsed_tokens(at(29, 0))
        .await
        .expect("sweep");
    assert_eq!(
        serials().await,
        [current.serial.clone(), successor.clone()],
        "still valid"
    );
    env.certs
        .remove_lapsed_tokens(at(31, 0))
        .await
        .expect("sweep");
    assert_eq!(serials().await, [successor]);
    let again = env.code(account.id).await;
    assert_eq!(
        env.enroll(&again, &key(1)).await.err(),
        Some(ClientCertError::KeyUsed)
    );
}

#[tokio::test]
async fn expired_codes_lose_their_secret_at_the_sweep() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code_with(account.id, Some(60), None).await;
    assert!(
        env.code_state(code.id).await.1,
        "the secret is kept while it can be used"
    );
    env.certs
        .prune_codes(&ctx(Timestamp(t0().0 + Duration::minutes(2))))
        .await;
    assert_eq!(env.code_state(code.id).await, (CodeState::Pending, false));
}

#[tokio::test]
async fn a_stale_index_refuses_at_once_while_issuing_is_held() {
    let env = Env::new();
    let index = Arc::clone(env.certs.index());
    let (account, current) = enrolled(&env).await;
    index.load(env.store.as_ref()).await.expect("load");
    let now = at(1, 0);
    index.mark_stale(now);
    assert!(matches!(
        index.accept(&current.serial, account.id, now),
        Acceptance::Accepted(_)
    ));
    // A step back would hold the bound open: while issuing is held it has passed.
    let _held = tenko_core::clock::testing::hold_jump(-3_600_000, now);
    assert_eq!(
        index.accept(&current.serial, account.id, now),
        Acceptance::Refused("the records could not be read for too long")
    );
}

#[tokio::test]
async fn a_code_on_a_clock_set_back_before_its_creation_is_expired() {
    let env = Env::new();
    let account = env.service_account().await;
    let code = env.code(account.id).await;
    let back = Timestamp(t0().0 - Duration::hours(1));
    assert_eq!(
        env.enroll_at(&code, &key(1), back, "h").await.err(),
        Some(ClientCertError::CodeExpired)
    );
    let within = Timestamp(t0().0 - Duration::seconds(4));
    assert!(env.enroll_at(&code, &key(1), within, "h").await.is_ok());
}

#[tokio::test]
async fn a_clock_that_may_not_issue_removes_no_certificate_and_prunes_no_code() {
    let env = Env::new();
    let (account, current) = enrolled(&env).await;
    let successor = renewed(renew_at(&env, at(21, 0), &current, &key(2)).await);
    env.certs
        .note_presented(&ctx(at(21, 1)), &successor)
        .await
        .expect("presented");
    let code = env.code_with(account.id, Some(60), None).await;
    let _held = tenko_core::clock::testing::hold_jump(-86_400_000, t0());
    env.certs
        .remove_lapsed_tokens(at(31, 0))
        .await
        .expect("sweep");
    env.certs
        .prune_codes(&ctx(Timestamp(t0().0 + Duration::minutes(2))))
        .await;
    assert_eq!(env.certs.list(None).await.expect("list").len(), 2);
    assert_eq!(env.code_state(code.id).await, (CodeState::Pending, true));
}
