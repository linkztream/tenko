//! The account's lifecycle (E45) over an in-memory store and vault, against a KDC that
//! this module simulates with Tenko's own codec (it mints real tickets, so the self-test's
//! acceptance runs the real acceptor), and against the exchanges recorded with a Samba AD
//! domain controller in `crates/tenko-krb/tests/fixtures/kdc/samba-adopt.txt`.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{EncryptionType, KeyVersionState, KrbAccount, PrincipalName, Realm, codes, findings},
    testing::wait_until_async,
};
use tenko_krb::{
    acceptor::{Clock, Config as AcceptorConfig, KrbTime, Service, Step},
    cipher::{self, Key, usage},
    client::{
        self, AsExchange, AsResult, AsStep, ChangePassword, ClientError, Credentials, Secret,
        TgsExchange, error_code,
    },
    der::{self, EncKdcRepPart, EncTicketPart, Ticket, TransitedEncoding, name_type, oid},
    keys::KeySet,
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
use tenko_vault::MemVault;
use zeroize::Zeroizing;

use super::*;
use crate::zone::jobs::DirectJobs;

const REALM: &str = "CORP.EXAMPLE.TEST";
const NAME: &str = "TENKO-DNS$";
const SPN: &str = "DNS/tenko.corp.example.test";
const OTP: &[u8] = b"One-Time-Pass-1";
const SALT: &str = "CORP.EXAMPLE.TESThosttenko-dns.corp.example.test";

fn realm() -> Realm {
    Realm::new(REALM).expect("realm")
}

fn principal(text: &str) -> PrincipalName {
    PrincipalName::parse(text).expect("principal")
}

fn account_principal() -> PrincipalName {
    principal("TENKO-DNS$@CORP.EXAMPLE.TEST")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn keys_of(password: &[u8], kvno: u32, state: KeyVersionState) -> KeySet {
    KeySet::from_password(
        &account_principal(),
        kvno,
        state,
        password,
        SALT,
        cipher::DEFAULT_ITERATIONS,
        &client::ETYPES,
    )
    .expect("keys")
}

// ---------------------------------------------------------------------------------------
// The clock and the passwords

/// A clock the test moves; it starts at the real time, as the request contexts do.
#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(SystemClock.now().secs)))
    }

    fn at(secs: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(secs)))
    }

    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> KrbTime {
        KrbTime::from_secs(self.0.load(Ordering::SeqCst))
    }
}

/// Passwords from a list, then random ones; remembers what it gave.
#[derive(Debug, Default)]
struct TestPasswords {
    fixed: Mutex<Vec<Vec<u8>>>,
    given: Mutex<Vec<Vec<u8>>>,
}

impl PasswordSource for TestPasswords {
    fn generate(&self) -> Zeroizing<Vec<u8>> {
        let mut fixed = self.fixed.lock().expect("lock");
        let password = if fixed.is_empty() {
            random_password(PASSWORD_LEN).to_vec()
        } else {
            fixed.remove(0)
        };
        self.given.lock().expect("lock").push(password.clone());
        Zeroizing::new(password)
    }
}

// ---------------------------------------------------------------------------------------
// The simulated KDC

/// Who holds an SPN in the simulated directory.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Holder {
    /// Tenko's account.
    Tenko,
    /// Another account, with its own key.
    Other,
    /// Two accounts (the KDC answers `KDC_ERR_PRINCIPAL_NOT_UNIQUE`).
    Both,
}

/// How the next password change goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeMode {
    /// The change is made and answered.
    Normal,
    /// The server refuses it in an authenticated answer to the only request (the password
    /// policy): the password did not change.
    Definite,
    /// A forged KRB-ERROR answers the request: nothing changed, and the refusal proves
    /// nothing.
    Spoofed,
    /// The first request is applied and its answer lost; the resend is refused by the
    /// password history.
    AppliedRefused,
    /// No KDC answers; nothing changes.
    Unreachable,
    /// The change is made, then the answer is lost and the KDC stops answering: the
    /// restart between the change and the commit.
    LostAnswer,
}

#[derive(Debug)]
struct KdcState {
    password: Vec<u8>,
    kvno: u32,
    /// A key version the KDC names that differs from the one the keys were exported
    /// with (`ktpass /kvno` wrong).
    kvno_offset: u32,
    spns: BTreeMap<String, Holder>,
    rc4: bool,
    disabled: bool,
    unreachable: bool,
    skew: i64,
    change: ChangeMode,
    changes: u32,
    /// A controller that has not replicated the change: service tickets come under this
    /// old key and version.
    stale_tickets: Option<(Key, u32)>,
}

struct TestKdc {
    state: Mutex<KdcState>,
    clock: Arc<TestClock>,
    other_key: Key,
}

impl TestKdc {
    fn new(clock: Arc<TestClock>, password: &[u8], kvno: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(KdcState {
                password: password.to_vec(),
                kvno,
                kvno_offset: 0,
                spns: BTreeMap::from([(SPN.to_owned(), Holder::Tenko)]),
                rc4: false,
                disabled: false,
                unreachable: false,
                skew: 0,
                change: ChangeMode::Normal,
                changes: 0,
                stale_tickets: None,
            }),
            clock,
            other_key: Key::new(EncryptionType::Aes256CtsHmacSha1, &[0x5a; 32]).expect("key"),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&mut KdcState) -> T) -> T {
        f(&mut self.state.lock().expect("lock"))
    }

    /// The account's AES-256 key now.
    fn account_key(&self) -> (Key, u32) {
        self.with(|s| {
            let keys = keys_of(&s.password, s.kvno, KeyVersionState::Current);
            (
                keys.select(18, Some(s.kvno)).expect("aes256")[0].clone(),
                s.kvno + s.kvno_offset,
            )
        })
    }

    fn proves(&self, secret: &Secret) -> bool {
        let (key, _) = self.account_key();
        match secret {
            Secret::Password(password) => {
                let password = password.to_vec();
                self.with(|s| s.password == password)
            }
            // The client pre-authenticates with the first key it selects (current, then
            // pending, then previous), as tenko-krb's AsExchange does.
            Secret::Keys(keys) => keys
                .select(18, None)
                .is_ok_and(|candidates| candidates.first().is_some_and(|k| **k == key)),
        }
    }

    fn now(&self) -> i64 {
        self.clock.now().secs + self.with(|s| s.skew)
    }

    fn part(&self, session: &Key, service: &PrincipalName) -> EncKdcRepPart {
        let now = self.now();
        EncKdcRepPart {
            application: 25,
            key: session.to_wire(),
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: 0,
            authtime: now,
            starttime: Some(now),
            endtime: now + 36_000,
            renew_till: None,
            srealm: REALM.to_owned(),
            sname: der::PrincipalName {
                name_type: name_type::SRV_INST,
                components: service.components().to_vec(),
            },
            caddr: None,
            encrypted_pa_data: None,
        }
    }

    /// A ticket for `service` from `client` under `key`.
    fn ticket(
        &self,
        client: &PrincipalName,
        service: &PrincipalName,
        session: &Key,
        key: Option<(&Key, u32)>,
        etype: i32,
    ) -> Ticket {
        let now = self.now();
        let part = EncTicketPart {
            flags: 0,
            key: session.to_wire(),
            crealm: REALM.to_owned(),
            cname: der::PrincipalName {
                name_type: name_type::PRINCIPAL,
                components: client.components().to_vec(),
            },
            transited: TransitedEncoding {
                tr_type: 1,
                contents: Vec::new(),
            },
            authtime: now,
            starttime: Some(now),
            endtime: now + 36_000,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let enc_part = match key {
            Some((key, kvno)) => {
                let mut enc =
                    cipher::encrypt_data(key, usage::TICKET, &part.encode()).expect("enc");
                enc.kvno = Some(kvno);
                enc
            }
            // An RC4 ticket: Tenko cannot read it, and does not try.
            None => der::EncryptedData {
                etype,
                kvno: Some(1),
                cipher: vec![0; 64],
            },
        };
        Ticket {
            realm: REALM.to_owned(),
            sname: der::PrincipalName {
                name_type: name_type::SRV_HST,
                components: service.components().to_vec(),
            },
            enc_part,
        }
    }

    /// A service ticket for `spn` from alice, as a client of the domain would get one.
    fn client_ticket(&self, spn: &str) -> Credentials {
        let alice = principal("alice@CORP.EXAMPLE.TEST");
        let service = principal(&format!("{spn}@{REALM}"));
        let session = Key::random(EncryptionType::Aes256CtsHmacSha1).expect("session");
        let (key, kvno) = self.account_key();
        Credentials {
            client: alice,
            ticket: self.ticket(
                &principal("alice@CORP.EXAMPLE.TEST"),
                &service,
                &session,
                Some((&key, kvno)),
                18,
            ),
            part: self.part(&session, &service),
            session_key: session,
        }
    }
}

#[async_trait::async_trait]
impl Kdc for TestKdc {
    async fn as_exchange(
        &self,
        _target: &KdcTarget,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError> {
        if self.with(|s| s.unreachable) {
            return Err(ClientError::Unreachable {
                servers: 1,
                last: None,
            });
        }
        if self.with(|s| s.disabled) {
            return Err(ClientError::Kdc {
                code: error_code::CLIENT_REVOKED,
                text: Some("account disabled\r\n".to_owned()),
            });
        }
        if client != &account_principal()
            && client.components() != [SPN.split('/').next().expect("s"), "tenko.corp.example.test"]
        {
            return Err(ClientError::Kdc {
                code: error_code::C_PRINCIPAL_UNKNOWN,
                text: None,
            });
        }
        if !self.proves(&secret) {
            return Err(ClientError::Kdc {
                code: error_code::PREAUTH_FAILED,
                text: Some("Preauthentication failed".to_owned()),
            });
        }
        let session = Key::random(EncryptionType::Aes256CtsHmacSha1).expect("session");
        let tgt_key = Key::new(EncryptionType::Aes256CtsHmacSha1, &[0x77; 32]).expect("key");
        let (_, kvno) = self.account_key();
        Ok(AsResult {
            credentials: Credentials {
                client: client.clone(),
                ticket: self.ticket(client, service, &session, Some((&tgt_key, 1)), 18),
                part: self.part(&session, service),
                session_key: session,
            },
            kdc_time: KrbTime::from_secs(self.now()),
            key_etype: EncryptionType::Aes256CtsHmacSha1,
            key_kvno: Some(kvno),
            salt: Some(SALT.to_owned()),
            iterations: cipher::DEFAULT_ITERATIONS,
        })
    }

    async fn tgs_exchange(
        &self,
        _target: &KdcTarget,
        tgt: &Credentials,
        service: &PrincipalName,
    ) -> Result<Credentials, ClientError> {
        if self.with(|s| s.unreachable) {
            return Err(ClientError::Timeout);
        }
        let spn = service.without_realm();
        let holder = self.with(|s| s.spns.get(&spn).cloned());
        let session = Key::random(EncryptionType::Aes256CtsHmacSha1).expect("session");
        let (key, kvno) = self.account_key();
        let ticket = match holder {
            None => {
                return Err(ClientError::Kdc {
                    code: error_code::S_PRINCIPAL_UNKNOWN,
                    text: None,
                });
            }
            Some(Holder::Both) => {
                return Err(ClientError::Kdc {
                    code: 9,
                    text: None,
                });
            }
            Some(Holder::Other) => self.ticket(
                &tgt.client,
                service,
                &session,
                Some((&self.other_key, 1)),
                18,
            ),
            Some(Holder::Tenko) if self.with(|s| s.rc4) => {
                self.ticket(&tgt.client, service, &session, None, 23)
            }
            Some(Holder::Tenko) => match self.with(|s| s.stale_tickets.clone()) {
                Some((old, old_kvno)) => {
                    self.ticket(&tgt.client, service, &session, Some((&old, old_kvno)), 18)
                }
                None => self.ticket(&tgt.client, service, &session, Some((&key, kvno)), 18),
            },
        };
        Ok(Credentials {
            client: tgt.client.clone(),
            ticket,
            part: self.part(&session, service),
            session_key: session,
        })
    }

    async fn change_password(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        secret: Secret,
        new_password: &[u8],
    ) -> Result<(), ClientError> {
        // As the real client: a failure before the request leaves is marked.
        let changepw = client::changepw_principal(client)
            .map_err(|e| ClientError::BeforeChange(Box::new(e)))?;
        self.as_exchange(target, client, &changepw, secret)
            .await
            .map_err(|e| ClientError::BeforeChange(Box::new(e)))?;
        let refused = |definite| ClientError::PasswordRefused {
            code: 4,
            message: "Password does not meet the policy\u{0}".to_owned(),
            definite,
        };
        let apply = |s: &mut KdcState| {
            s.password = new_password.to_vec();
            s.kvno += 1;
            s.changes += 1;
        };
        match self.with(|s| s.change) {
            ChangeMode::Normal => {
                self.with(apply);
                Ok(())
            }
            ChangeMode::Definite => Err(refused(true)),
            ChangeMode::Spoofed => Err(refused(false)),
            ChangeMode::AppliedRefused => {
                self.with(apply);
                Err(refused(false))
            }
            ChangeMode::Unreachable => {
                self.with(|s| s.unreachable = true);
                Err(ClientError::Timeout)
            }
            ChangeMode::LostAnswer => {
                self.with(|s| {
                    apply(s);
                    s.unreachable = true;
                });
                Err(ClientError::Timeout)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The harness

struct Lab {
    store: Arc<MemStore>,
    vault: Arc<MemVault>,
    clock: Arc<TestClock>,
    kdc: Arc<TestKdc>,
    passwords: Arc<TestPasswords>,
    service: Arc<KerberosService>,
}

impl Lab {
    fn new() -> Self {
        Self::with(KerberosConfig::default())
    }

    fn with(config: KerberosConfig) -> Self {
        let store = Arc::new(MemStore::default());
        let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
        let clock = TestClock::new();
        let kdc = TestKdc::new(Arc::clone(&clock), OTP, 1);
        let passwords = Arc::new(TestPasswords::default());
        let service = Self::service_over(&store, &vault, &clock, &kdc, &passwords, config);
        Self {
            store,
            vault,
            clock,
            kdc,
            passwords,
            service,
        }
    }

    fn service_over(
        store: &Arc<MemStore>,
        vault: &Arc<MemVault>,
        clock: &Arc<TestClock>,
        kdc: &Arc<TestKdc>,
        passwords: &Arc<TestPasswords>,
        config: KerberosConfig,
    ) -> Arc<KerberosService> {
        KerberosService::new(
            Arc::clone(store) as Arc<dyn Store>,
            Some(Arc::clone(vault) as Arc<dyn Vault>),
            Arc::clone(kdc) as Arc<dyn Kdc>,
            Arc::clone(clock) as Arc<dyn Clock>,
            Arc::clone(passwords) as Arc<dyn PasswordSource>,
            config,
        )
    }

    /// The same store, vault and KDC with a new service: a restart of the controller.
    fn restart(&mut self) {
        self.service = Self::service_over(
            &self.store,
            &self.vault,
            &self.clock,
            &self.kdc,
            &self.passwords,
            self.service.config(),
        );
    }
}

fn adopt_request() -> AdoptRequest {
    {
        AdoptRequest {
            realm: Realm::new("corp.example.test").expect("realm"),
            name: NAME.to_owned(),
            password: Zeroizing::new(OTP.to_vec()),
            spns: vec![SPN.to_owned()],
            kdcs: vec!["dc1.corp.example.test".to_owned()],
            rotation_days: None,
        }
    }
}

impl Lab {
    async fn adopt(&self) -> CheckOutcome {
        self.service
            .adopt(&cx(), adopt_request())
            .await
            .expect("adopt")
    }

    async fn account(&self) -> KrbAccount {
        self.service
            .status()
            .await
            .expect("status")
            .expect("an account")
    }

    async fn keys(&self) -> KeySet {
        let account = self.account().await;
        self.service.keys(&account).await.expect("keys")
    }

    /// The acceptor of the dns role with the keys held now.
    async fn acceptor(&self) -> Arc<Service> {
        Service::new(
            AcceptorConfig::new(realm(), &[SPN]),
            self.keys().await,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    fn audit(&self) -> Vec<(String, BTreeMap<String, String>)> {
        let view =
            futures::executor::block_on(self.store.read(ReadConsistency::Local)).expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| {
            (
                record.draft.action.as_str().to_owned(),
                record.draft.details.context.clone().into_iter().collect(),
            )
        })
        .collect()
    }
}

/// Accepts `ticket` with `acceptor` as a client would present it, each time with a new
/// authenticator.
fn accepts(acceptor: &Arc<Service>, ticket: &Credentials, clock: &TestClock) -> Result<(), String> {
    static USEC: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let now = clock.now();
    let (token, _) = client::initiator_token(
        ticket,
        oid::KRB5,
        KrbTime {
            secs: now.secs + 1,
            usec: USEC.fetch_add(1, Ordering::SeqCst),
        },
        7,
    )
    .expect("token");
    match acceptor.negotiation().step(&token) {
        Ok(Step::Established { .. }) => Ok(()),
        Ok(other) => Err(format!("{other:?}")),
        Err(error) => Err(error.to_string()),
    }
}

fn codes_of(account: &KrbAccount) -> Vec<&str> {
    account.findings.iter().map(|f| f.code.as_str()).collect()
}

// ---------------------------------------------------------------------------------------
// Adopt (E45)

/// DNS-28, OPS-11 (E45): the pre-staged computer account is taken over with its one-time
/// password: the KDC now holds a password only Tenko knew, the keys derived from it with
/// the KDC's salt are the vault secret of purpose `dns.krb`, the version is the one the
/// KDC issues, the self-test passes, and the one-time password no longer works.
#[tokio::test]
async fn dns_28_adopt_takes_over_the_pre_staged_account() {
    let lab = Lab::new();
    let outcome = lab.adopt().await;
    let account = outcome.account;
    assert!(!outcome.unreachable);
    assert_eq!(account.realm, realm());
    assert_eq!(account.name, NAME);
    assert!(account.owned);
    assert_eq!(account.rotation_days, 30);
    assert!(account.findings.is_empty(), "{:?}", account.findings);
    assert!(account.last_check.is_some() && account.last_rotation.is_some());
    assert_eq!(account.versions.len(), 1);
    assert_eq!(account.versions[0].kvno, 2);
    assert_eq!(account.versions[0].state, KeyVersionState::Current);
    // The KDC holds the generated password, 120 printable characters, not the one-time one.
    let given = lab.passwords.given.lock().expect("lock").clone();
    assert_eq!(given.len(), 1);
    assert_eq!(given[0].len(), PASSWORD_LEN);
    assert!(lab.kdc.with(|s| s.password == given[0] && s.kvno == 2));
    assert!(
        !lab.kdc
            .proves(&Secret::Password(Zeroizing::new(OTP.to_vec())))
    );
    // The vault secret holds the keys of that password with the MS-KILE salt.
    let keys = lab.keys().await;
    assert_eq!(keys, keys_of(&given[0], 2, KeyVersionState::Current));
    let secret = account.secret.expect("secret");
    let meta = lab.vault.meta(secret).await.expect("meta").expect("exists");
    assert_eq!(meta.purpose.as_str(), VAULT_PURPOSE);
    assert_eq!(meta.class, tenko_vault::SecretClass::System);
    // A client's ticket for the SPN is accepted with them.
    let acceptor = lab.acceptor().await;
    accepts(&acceptor, &lab.kdc.client_ticket(SPN), &lab.clock).expect("accepted");
    // Audited as an adopt with the version and no secret.
    let audit = lab.audit();
    let adopt = audit
        .iter()
        .find(|(action, _)| action == audit::KRB_ACCOUNT_ADOPT.as_str())
        .expect("dns.krb.account.adopt");
    assert_eq!(adopt.1["kvno"], "2");
    assert_eq!(adopt.1["realm"], REALM);
}

/// DNS-28: a wrong one-time password is refused by the KDC and nothing is stored; a second
/// account is refused while one exists; a user account is not adopted.
#[tokio::test]
async fn dns_28_adopt_refuses_a_wrong_password_a_second_account_and_a_user() {
    let lab = Lab::new();
    let mut wrong = adopt_request();
    wrong.password = Zeroizing::new(b"not-it".to_vec());
    let error = lab.service.adopt(&cx(), wrong).await.expect_err("refused");
    assert!(error.is(codes::KRB_PASSWORD_REFUSED), "{error:?}");
    assert!(lab.service.status().await.expect("status").is_none());
    let mut user = adopt_request();
    user.name = "svc-dns".to_owned();
    let error = lab.service.adopt(&cx(), user).await.expect_err("user");
    assert!(error.is(codes::KRB_ACCOUNT_INVALID), "{error:?}");
    let mut off = adopt_request();
    off.rotation_days = Some(0);
    let error = lab.service.adopt(&cx(), off).await.expect_err("off");
    assert!(error.is(codes::KRB_ACCOUNT_INVALID), "{error:?}");
    lab.adopt().await;
    let error = lab
        .service
        .adopt(&cx(), adopt_request())
        .await
        .expect_err("exists");
    assert!(error.is(codes::KRB_ACCOUNT_EXISTS), "{error:?}");
    lab.kdc.with(|s| s.unreachable = true);
    let other = Lab::new();
    other.kdc.with(|s| s.unreachable = true);
    let error = other
        .service
        .adopt(&cx(), adopt_request())
        .await
        .expect_err("unreachable");
    assert!(error.is(codes::KRB_KDC_UNREACHABLE), "{error:?}");
    assert!(other.service.status().await.expect("status").is_none());
}

/// DNS-28 (R123): the answer to the adopt's change is lost after the KDC made it; the
/// recovery asks the KDC with the pending keys, finds them taken and finishes the adopt.
#[tokio::test]
async fn dns_28_an_adopt_whose_answer_was_lost_finishes() {
    let lab = Lab::new();
    lab.kdc.with(|s| s.change = ChangeMode::LostAnswer);
    let error = lab
        .service
        .adopt(&cx(), adopt_request())
        .await
        .expect_err("no answer");
    assert!(error.is(codes::KRB_KDC_UNREACHABLE), "{error:?}");
    let account = lab.account().await;
    assert_eq!(account.versions[0].state, KeyVersionState::Pending);
    // The acceptor already holds the pending keys: a ticket under the new key is accepted.
    accepts(
        &lab.acceptor().await,
        &lab.kdc.client_ticket(SPN),
        &lab.clock,
    )
    .expect("pending keys accept");
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.change = ChangeMode::Normal;
    });
    let mut lab = lab;
    lab.restart();
    assert!(matches!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Changed { from: None, to: 2 }
    ));
    let account = lab.account().await;
    assert_eq!(account.versions.len(), 1);
    assert_eq!(account.versions[0].state, KeyVersionState::Current);
    assert_eq!(account.versions[0].kvno, 2);
}

/// DNS-28 (R123): a refused change removes the pending account; a change that never
/// reached the KDC is undone by the recovery and leaves a finding that says what to do.
#[tokio::test]
async fn dns_28_a_refused_or_unsent_adopt_change_leaves_no_keys() {
    let lab = Lab::new();
    lab.kdc.with(|s| s.change = ChangeMode::Definite);
    let error = lab
        .service
        .adopt(&cx(), adopt_request())
        .await
        .expect_err("refused");
    assert!(error.is(codes::KRB_PASSWORD_REFUSED), "{error:?}");
    // The KDC's text is cleaned of its control characters.
    assert!(!error.coded().detail.contains('\u{0}'), "{error:?}");
    assert!(lab.service.status().await.expect("status").is_none());

    let lab = Lab::new();
    lab.kdc.with(|s| s.change = ChangeMode::Unreachable);
    lab.service
        .adopt(&cx(), adopt_request())
        .await
        .expect_err("unsent");
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.change = ChangeMode::Normal;
    });
    // Within the grace a refusal of the new keys proves nothing: the request may still be
    // on its way (R123).
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    // After it, an adopt has no old keys to prove the refusal with: the new keys stay,
    // with the finding that says what to do.
    lab.clock.advance(16 * 60);
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    let account = lab.account().await;
    assert_eq!(account.versions.len(), 1);
    assert_eq!(account.versions[0].state, KeyVersionState::Pending);
    assert_eq!(codes_of(&account), [findings::GSS_SELF_TEST_FAILED]);
    assert_eq!(account.findings[0].params["reason"], "adopt_incomplete");
}

// ---------------------------------------------------------------------------------------
// Import (E45)

fn keytab_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tenko-krb/tests/fixtures/keytabs")
            .join(name),
    )
    .expect("keytab fixture")
}

fn import_request(keytab: &str) -> ImportRequest {
    ImportRequest {
        realm: realm(),
        name: None,
        keytab: Zeroizing::new(keytab_fixture(keytab)),
        spns: vec![SPN.to_owned()],
        kdcs: Vec::new(),
    }
}

/// DNS-28, OPS-11 (E45): a keytab as `ktpass` writes it (the account and its SPN, versions
/// 2 and 3) imports: the AES entries are kept, version 3 current and 2 previous, the
/// account is not owned and not rotated, and the self-test passes against a KDC that holds
/// the same password.
#[tokio::test]
async fn dns_28_a_ktpass_keytab_imports_and_works() {
    let lab = Lab::new();
    lab.kdc.with(|s| {
        s.password = b"Lab-Machine-Pass-1-3".to_vec();
        s.kvno = 3;
    });
    let outcome = lab
        .service
        .import(&cx(), import_request("computer-tenko-dns.keytab"))
        .await
        .expect("import");
    let account = outcome.account;
    assert_eq!(account.name, NAME);
    assert!(!account.owned);
    assert!(account.findings.is_empty(), "{:?}", account.findings);
    let states: Vec<(u32, KeyVersionState)> =
        account.versions.iter().map(|v| (v.kvno, v.state)).collect();
    assert_eq!(
        states,
        [
            (2, KeyVersionState::Previous),
            (3, KeyVersionState::Current)
        ]
    );
    accepts(
        &lab.acceptor().await,
        &lab.kdc.client_ticket(SPN),
        &lab.clock,
    )
    .expect("accepted");
    let error = lab
        .service
        .rotate(&cx(), None)
        .await
        .expect_err("not owned");
    assert!(error.is(codes::KRB_ACCOUNT_NOT_OWNED), "{error:?}");
    let audit = lab.audit();
    let import = audit
        .iter()
        .find(|(action, _)| action == audit::KRB_ACCOUNT_IMPORT.as_str())
        .expect("dns.krb.account.import");
    assert_eq!(import.1["kvnos"], "2,3");
    assert_eq!(import.1["refused"], "0");
}

/// DNS-28 (review M6): a keytab with another principal of the realm imports only the
/// account's entries and its SPNs'.
#[tokio::test]
async fn dns_28_the_import_keeps_only_the_account_and_its_spns() {
    let lab = Lab::new();
    lab.kdc.with(|s| {
        s.password = b"Lab-Machine-Pass-1-3".to_vec();
        s.kvno = 3;
    });
    let mut request = import_request("computer-tenko-dns.keytab");
    // Only the account named, no SPN of the keytab: the SPN's entries are not kept.
    request.spns = vec!["DNS/other.corp.example.test".to_owned()];
    lab.kdc.with(|s| {
        s.spns
            .insert("DNS/other.corp.example.test".to_owned(), Holder::Tenko);
    });
    lab.service.import(&cx(), request).await.expect("import");
    let principals: std::collections::BTreeSet<String> = lab
        .keys()
        .await
        .entries()
        .iter()
        .map(|e| e.principal.to_string())
        .collect();
    assert_eq!(
        principals.into_iter().collect::<Vec<_>>(),
        ["TENKO-DNS$@CORP.EXAMPLE.TEST"]
    );
    // A keytab of nothing the account names is refused.
    let lab = Lab::new();
    let mut request = import_request("user-alice.keytab");
    request.name = Some(NAME.to_owned());
    let error = lab
        .service
        .import(&cx(), request)
        .await
        .expect_err("refused");
    assert!(error.is(codes::KRB_KEYTAB_INVALID), "{error:?}");
}

/// DNS-28: RC4 and 3DES entries are refused and counted; a keytab without an AES entry,
/// a file that is not a keytab and a keytab of another realm are refused with the reason
/// and without a key in the text.
#[tokio::test]
async fn dns_28_keytab_entries_tenko_does_not_take_are_refused() {
    let lab = Lab::new();
    let mut request = import_request("mixed-enctypes.keytab");
    request.name = Some(NAME.to_owned());
    lab.kdc.with(|s| {
        s.password = b"Lab-Machine-Pass-1".to_vec();
        s.kvno = 4;
    });
    let outcome = lab.service.import(&cx(), request).await.expect("import");
    assert_eq!(outcome.account.versions.len(), 1);
    assert_eq!(
        outcome.account.versions[0].etypes,
        [EncryptionType::Aes256CtsHmacSha1]
    );
    let refused = lab
        .audit()
        .into_iter()
        .find(|(action, _)| action == audit::KRB_ACCOUNT_IMPORT.as_str())
        .expect("import")
        .1;
    assert_eq!(refused["refused"], "2");

    let lab = Lab::new();
    let mut not_a_keytab = import_request("computer-tenko-dns.keytab");
    not_a_keytab.keytab = Zeroizing::new(b"not a keytab".to_vec());
    let error = lab
        .service
        .import(&cx(), not_a_keytab)
        .await
        .expect_err("refused");
    assert!(error.is(codes::KRB_KEYTAB_INVALID), "{error:?}");
    let mut other_realm = import_request("computer-tenko-dns.keytab");
    other_realm.realm = Realm::new("OTHER.EXAMPLE.TEST").expect("realm");
    let error = lab
        .service
        .import(&cx(), other_realm)
        .await
        .expect_err("realm");
    assert!(error.is(codes::KRB_KEYTAB_INVALID), "{error:?}");
    // Only an SPN in the keytab: the name must be given.
    let error = lab
        .service
        .import(&cx(), import_request("mixed-enctypes.keytab"))
        .await
        .expect_err("no name");
    assert!(error.is(codes::KRB_ACCOUNT_INVALID), "{error:?}");
    assert!(lab.service.status().await.expect("status").is_none());
}

// ---------------------------------------------------------------------------------------
// Rotation (E45)

/// DNS-28, IAM-16 (E45): a forced rotation moves the key version; a ticket issued before
/// the rotation is still accepted with the previous keys until the next rotation, which
/// drops them.
#[tokio::test]
async fn dns_28_a_rotation_moves_the_version_and_older_tickets_still_accept() {
    let lab = Lab::new();
    lab.adopt().await;
    let before = lab.kdc.client_ticket(SPN);
    let rotated = lab.service.rotate(&cx(), None).await.expect("rotate");
    assert_eq!(
        rotated,
        Rotated::Changed {
            from: Some(2),
            to: 3
        }
    );
    let account = lab.account().await;
    let states: Vec<(u32, KeyVersionState)> =
        account.versions.iter().map(|v| (v.kvno, v.state)).collect();
    assert_eq!(
        states,
        [
            (2, KeyVersionState::Previous),
            (3, KeyVersionState::Current)
        ]
    );
    assert_eq!(lab.kdc.with(|s| s.kvno), 3);
    let acceptor = lab.acceptor().await;
    accepts(&acceptor, &before, &lab.clock).expect("the ticket from before");
    accepts(&acceptor, &lab.kdc.client_ticket(SPN), &lab.clock).expect("a new ticket");
    // A second rotation soon after keeps version 2 too: version 3 became current less
    // than KEEP_PREVIOUS ago, so a ticket under 2 may still be valid.
    let rotated = lab.service.rotate(&cx(), None).await.expect("rotate");
    assert_eq!(
        rotated,
        Rotated::Changed {
            from: Some(3),
            to: 4
        }
    );
    assert_eq!(lab.keys().await.kvnos(), [2, 3, 4]);
    accepts(&lab.acceptor().await, &before, &lab.clock).expect("still accepted");
    // A rotation after the ticket lifetime drops the versions before the current one.
    lab.clock.advance(13 * 3600);
    lab.service.rotate(&cx(), None).await.expect("rotate");
    assert_eq!(lab.keys().await.kvnos(), [4, 5]);
    let error = accepts(&lab.acceptor().await, &before, &lab.clock).expect_err("gone");
    assert!(error.contains("version 2"), "{error}");
    let rotations = lab
        .audit()
        .into_iter()
        .filter(|(action, _)| action == audit::KRB_ACCOUNT_ROTATE.as_str())
        .map(|(_, context)| (context["from_kvno"].clone(), context["kvno"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        rotations,
        [
            ("2".to_owned(), "3".to_owned()),
            ("3".to_owned(), "4".to_owned()),
            ("4".to_owned(), "5".to_owned())
        ]
    );
}

/// DNS-28 (R123, E45): the controller stops between the KDC taking the new password and
/// the commit (the answer lost, the KDC gone): the pending keys are in the vault; after the
/// restart the recovery finds that the KDC issues the new version and commits it.
#[tokio::test]
async fn dns_28_a_restart_between_the_change_and_the_commit_is_recovered() {
    let mut lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::LostAnswer);
    let error = lab.service.rotate(&cx(), None).await.expect_err("lost");
    assert!(error.is(codes::KRB_KDC_UNREACHABLE), "{error:?}");
    let account = lab.account().await;
    assert!(
        account
            .versions
            .iter()
            .any(|v| v.state == KeyVersionState::Pending)
    );
    assert_eq!(lab.kdc.with(|s| s.kvno), 3, "the KDC made the change");
    // Restart; the KDC answers again.
    lab.restart();
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.change = ChangeMode::Normal;
    });
    let rotated = lab.service.recover(&cx(), None).await.expect("recover");
    assert_eq!(
        rotated,
        Rotated::Changed {
            from: Some(2),
            to: 3
        }
    );
    let account = lab.account().await;
    let states: Vec<(u32, KeyVersionState)> =
        account.versions.iter().map(|v| (v.kvno, v.state)).collect();
    assert_eq!(
        states,
        [
            (2, KeyVersionState::Previous),
            (3, KeyVersionState::Current)
        ]
    );
    let passed = lab.service.check(&cx(), None).await.expect("check").account;
    assert!(passed.findings.is_empty(), "{:?}", passed.findings);
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("again"),
        Rotated::Nothing
    );
}

/// DNS-28 (R123): a change that never reached the KDC, then a restart: the recovery finds
/// the pending keys refused, drops them, and the old keys stay current and work.
#[tokio::test]
async fn dns_28_a_restart_before_the_change_reached_the_kdc_is_undone() {
    let mut lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::Unreachable);
    lab.service.rotate(&cx(), None).await.expect_err("unsent");
    lab.restart();
    // While no KDC answers, nothing moves.
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.change = ChangeMode::Normal;
    });
    // Within the grace the refusal of the new keys proves nothing.
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    // After it, the KDC refuses the new keys and takes the current ones: the proof.
    lab.clock.advance(16 * 60);
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Undone
    );
    let account = lab.account().await;
    let states: Vec<(u32, KeyVersionState)> =
        account.versions.iter().map(|v| (v.kvno, v.state)).collect();
    assert_eq!(states, [(2, KeyVersionState::Current)]);
    let undone = lab
        .audit()
        .into_iter()
        .filter(|(action, context)| {
            action == audit::KRB_ACCOUNT_ROTATE.as_str()
                && context.get("outcome").map(String::as_str) == Some("undone")
        })
        .count();
    assert_eq!(undone, 1, "the undone change is audited");
    accepts(
        &lab.acceptor().await,
        &lab.kdc.client_ticket(SPN),
        &lab.clock,
    )
    .expect("accepted");
}

/// DNS-28, TGL-32: a refused rotation leaves the current keys; the finding
/// `dns.gss.rotation_failed` comes at the second failure in a row (the first under
/// Hardened), names the failures, and the next successful rotation clears it.
#[tokio::test]
async fn dns_28_rotation_failures_raise_the_finding_and_a_success_clears_it() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::Definite);
    lab.service.rotate(&cx(), None).await.expect_err("first");
    let findings_now = lab.account().await.findings;
    assert!(findings_now.is_empty(), "{findings_now:?}");
    lab.service.rotate(&cx(), None).await.expect_err("second");
    let account = lab.account().await;
    assert_eq!(codes_of(&account), [findings::GSS_ROTATION_FAILED]);
    assert_eq!(account.findings[0].params["failures"], "2");
    assert_eq!(
        account.findings[0].params["reason"],
        codes::KRB_PASSWORD_REFUSED
    );
    assert_eq!(account.current().map(|v| v.kvno), Some(2));
    assert!(!has_pending(&account));
    lab.kdc.with(|s| s.change = ChangeMode::Normal);
    lab.service.rotate(&cx(), None).await.expect("rotates");
    let findings_now = lab.account().await.findings;
    assert!(findings_now.is_empty(), "{findings_now:?}");

    let hardened = Lab::with(KerberosConfig {
        rotation_failures_before_finding: 1,
        ..KerberosConfig::default()
    });
    hardened.adopt().await;
    hardened.kdc.with(|s| s.change = ChangeMode::Definite);
    hardened
        .service
        .rotate(&cx(), None)
        .await
        .expect_err("first");
    assert_eq!(
        codes_of(&hardened.account().await),
        [findings::GSS_ROTATION_FAILED]
    );
}

/// DNS-28: the rotation job runs the rotation once; run again after it succeeded (an
/// engine retry), it does not rotate a second time.
#[tokio::test]
async fn dns_28_the_rotation_job_rotates_once() {
    let lab = Lab::new();
    lab.adopt().await;
    let mut jobs = DirectJobs::new(Arc::clone(&lab.store) as Arc<dyn Store>);
    jobs.register(lab.service.rotate_step());
    let id = lab.service.start_rotation(&jobs, &cx()).await.expect("job");
    let job = jobs.job(id).expect("ran");
    assert_eq!(
        job.state,
        tenko_jobs::JobState::Succeeded,
        "{:?}",
        job.error
    );
    assert_eq!(lab.account().await.current().map(|v| v.kvno), Some(3));
    let step = lab.service.rotate_step();
    let params = tenko_core::codec::to_cbor(&RotateParams {
        realm: realm(),
        from_kvno: Some(2),
    })
    .expect("params");
    let step_cx = StepContext {
        job: id,
        step: 0,
        attempt: 2,
        request: cx(),
        store: Arc::clone(&lab.store) as Arc<dyn Store>,
        deadline: None,
    };
    step.execute(&params, &step_cx).await.expect("again");
    assert_eq!(lab.account().await.current().map(|v| v.kvno), Some(3));
}

/// DNS-28, TGL-32: the leader finishes a pending change first, runs the self-test daily,
/// and starts the rotation when the interval has passed since the last one.
#[tokio::test]
async fn dns_28_the_leader_rotates_when_due_and_checks_daily() {
    let lab = Lab::new();
    lab.adopt().await;
    let mut jobs = DirectJobs::new(Arc::clone(&lab.store) as Arc<dyn Store>);
    jobs.register(lab.service.rotate_step());
    let jobs: Arc<dyn ZoneJobs> = Arc::new(jobs);
    let leader = LeaderLoop::new(Arc::clone(&lab.service), Arc::clone(&jobs));
    let mut retry = None;
    assert_eq!(
        leader.tick(None, &mut retry).await.expect("tick"),
        Due::Nothing
    );
    lab.clock.advance(25 * 3600);
    assert_eq!(
        leader.tick(None, &mut retry).await.expect("tick"),
        Due::Checked
    );
    lab.clock.advance(30 * 86_400);
    assert_eq!(
        leader.tick(None, &mut retry).await.expect("tick"),
        Due::Rotated
    );
    assert_eq!(lab.account().await.current().map(|v| v.kvno), Some(3));
    // A pending change is finished before anything else.
    lab.kdc.with(|s| s.change = ChangeMode::LostAnswer);
    lab.service.rotate(&cx(), None).await.expect_err("lost");
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.change = ChangeMode::Normal;
    });
    assert_eq!(
        leader.tick(None, &mut retry).await.expect("tick"),
        Due::Recovered
    );
    assert_eq!(lab.account().await.current().map(|v| v.kvno), Some(4));
}

/// DNS-28: a write of the leader carries its epoch; a deposed leader's write fails.
#[tokio::test]
async fn dns_28_leader_writes_are_fenced_by_the_epoch() {
    let lab = Lab::new();
    lab.adopt().await;
    let error = lab.service.check(&cx(), Some(7)).await.expect_err("fenced");
    assert!(error.coded().code.contains("precondition"), "{error:?}");
}

/// DNS-28 (R123, review C1): the first change request is applied, its answer lost, and
/// the resend is refused by the password history. The refusal of a resend proves nothing,
/// so the pending keys are not dropped; the KDC takes them and they are committed.
#[tokio::test]
async fn dns_28_a_refusal_of_a_resent_change_does_not_lose_the_account() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::AppliedRefused);
    let rotated = lab.service.rotate(&cx(), None).await.expect("committed");
    assert_eq!(
        rotated,
        Rotated::Changed {
            from: Some(2),
            to: 3
        }
    );
    let given = lab.passwords.given.lock().expect("lock").clone();
    assert!(lab.kdc.with(|s| s.password == given[1]));
    accepts(
        &lab.acceptor().await,
        &lab.kdc.client_ticket(SPN),
        &lab.clock,
    )
    .expect("the KDC's tickets are accepted");
    // The same for an adopt: the account stays Tenko's.
    let other = Lab::new();
    other.kdc.with(|s| s.change = ChangeMode::AppliedRefused);
    let account = other.adopt().await.account;
    assert_eq!(account.current().map(|v| v.kvno), Some(2));
}

/// DNS-28 (R123, review C1): a forged KRB-ERROR answers the change. It proves nothing: the
/// pending keys stay through the grace and are dropped only when the KDC refuses them and
/// takes the current ones.
#[tokio::test]
async fn dns_28_a_spoofed_refusal_drops_nothing_without_proof() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::Spoofed);
    let error = lab.service.rotate(&cx(), None).await.expect_err("unknown");
    assert!(
        error.coded().detail.contains("keeps the new keys"),
        "{error:?}"
    );
    assert!(has_pending(&lab.account().await));
    lab.kdc.with(|s| s.change = ChangeMode::Normal);
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    lab.clock.advance(16 * 60);
    assert_eq!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Undone
    );
    assert_eq!(lab.account().await.current().map(|v| v.kvno), Some(2));
    // A refusal that proves it (authenticated, the only request) drops at once.
    lab.kdc.with(|s| s.change = ChangeMode::Definite);
    lab.service.rotate(&cx(), None).await.expect_err("refused");
    assert!(!has_pending(&lab.account().await));
}

/// DNS-28 (review H3): a controller that has not replicated the change issues the service
/// ticket under the old key. The version is read from the AS-REP, which the new keys
/// decrypted, not from that ticket, and the old keys stay held.
#[tokio::test]
async fn dns_28_a_stale_controller_does_not_set_the_version() {
    let lab = Lab::new();
    lab.adopt().await;
    let (old, old_kvno) = lab.kdc.account_key();
    lab.kdc.with(|s| s.stale_tickets = Some((old, old_kvno)));
    let rotated = lab.service.rotate(&cx(), None).await.expect("rotate");
    assert_eq!(
        rotated,
        Rotated::Changed {
            from: Some(2),
            to: 3
        }
    );
    assert_eq!(lab.keys().await.kvnos(), [2, 3]);
}

/// DNS-28 (review H2): a second controller recovers while the first is inside its
/// change: the new keys are refused (the change has not happened yet) but young, so they
/// stay, and the first controller commits them when its change succeeds.
#[tokio::test]
async fn dns_28_a_second_controller_does_not_drop_a_change_in_flight() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::Unreachable);
    lab.service
        .rotate(&cx(), None)
        .await
        .expect_err("in flight");
    let other = Lab::service_over(
        &lab.store,
        &lab.vault,
        &lab.clock,
        &lab.kdc,
        &lab.passwords,
        KerberosConfig::default(),
    );
    lab.kdc.with(|s| s.unreachable = false);
    assert_eq!(
        other.recover(&cx(), None).await.expect("recover"),
        Rotated::Unknown
    );
    // The first controller's change reaches the KDC late.
    let given = lab.passwords.given.lock().expect("lock").clone();
    lab.kdc.with(|s| {
        s.password = given[1].clone();
        s.kvno = 3;
    });
    assert!(matches!(
        lab.service.recover(&cx(), None).await.expect("recover"),
        Rotated::Changed { to: 3, .. }
    ));
}

/// DNS-28 (review M5): a rotation job run again after its rotation committed rotates
/// nothing.
#[tokio::test]
async fn dns_28_a_retried_rotation_step_rotates_once() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.service
        .rotate_from(&cx(), None, Some(Some(2)))
        .await
        .expect("rotate");
    assert_eq!(
        lab.service
            .rotate_from(&cx(), None, Some(Some(2)))
            .await
            .expect("again"),
        Rotated::Nothing
    );
    assert_eq!(lab.keys().await.kvnos(), [2, 3]);
}

/// DNS-28 (review M1): a pending change whose account the KDC disabled does not stop the
/// self-test: the finding is stored.
#[tokio::test]
async fn dns_28_a_pending_change_does_not_hide_a_disabled_account() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.change = ChangeMode::Unreachable);
    lab.service
        .rotate(&cx(), None)
        .await
        .expect_err("in flight");
    lab.kdc.with(|s| {
        s.unreachable = false;
        s.disabled = true;
    });
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_SELF_TEST_FAILED]);
    assert_eq!(account.findings[0].params["reason"], "disabled");
}

// ---------------------------------------------------------------------------------------
// The self-test and its findings (E45, section 3.10)

/// DNS-28 (E45): an SPN of a node that no account holds is `dns.gss.spn_missing`, naming
/// the SPN; the others still pass.
#[tokio::test]
async fn dns_28_a_missing_spn_is_a_finding() {
    let lab = Lab::new();
    let mut request = adopt_request();
    request.spns.push("DNS/ns2.corp.example.test".to_owned());
    let account = lab
        .service
        .adopt(&cx(), request)
        .await
        .expect("adopt")
        .account;
    assert_eq!(codes_of(&account), [findings::GSS_SPN_MISSING]);
    assert_eq!(
        account.findings[0].params["spn"],
        "DNS/ns2.corp.example.test"
    );
}

/// DNS-28 (E45): an SPN held by two accounts (the KDC says so), and an SPN whose ticket is
/// under another account's key, are `dns.gss.spn_duplicate`.
#[tokio::test]
async fn dns_28_a_duplicate_spn_is_a_finding() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| {
        s.spns.insert(SPN.to_owned(), Holder::Both);
    });
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_SPN_DUPLICATE]);
    assert_eq!(account.findings[0].params["kdc_error"], "9");
    lab.kdc.with(|s| {
        s.spns.insert(SPN.to_owned(), Holder::Other);
    });
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_SPN_DUPLICATE]);
    assert_eq!(account.findings[0].params["spn"], SPN);
}

/// DNS-28 (E45): the KDC issues a key version Tenko does not hold (a keytab exported with
/// the wrong version, a password reset that kept the keys' derivation): `dns.gss.kvno_unknown`
/// with the version seen and the versions held.
#[tokio::test]
async fn dns_28_a_key_version_tenko_does_not_hold_is_a_finding() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.kvno_offset = 5);
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert!(
        codes_of(&account).contains(&findings::GSS_KVNO_UNKNOWN),
        "{:?}",
        account.findings
    );
    let finding = account
        .findings
        .iter()
        .find(|f| f.code == findings::GSS_KVNO_UNKNOWN)
        .expect("finding");
    assert_eq!(finding.params["kvno"], "7");
    assert_eq!(finding.params["held"], "2");
}

/// DNS-28 (E45): an account that lost its AES types gets RC4 tickets: `dns.gss.weak_etype`
/// with the type seen.
#[tokio::test]
async fn dns_28_an_rc4_only_account_is_a_finding() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.rc4 = true);
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_WEAK_ETYPE]);
    assert_eq!(account.findings[0].params["etype"], "23");
}

/// OPS-09 (E45): a KDC whose clock is more than 60 s from the node's is
/// `dns.gss.clock_skew` with the skew measured; 30 s is not.
#[tokio::test]
async fn ops_09_clock_skew_above_60_s_is_a_finding() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.skew = 30);
    let passed = lab.service.check(&cx(), None).await.expect("check").account;
    assert!(passed.findings.is_empty(), "{:?}", passed.findings);
    lab.kdc.with(|s| s.skew = 120);
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_CLOCK_SKEW]);
    assert_eq!(account.findings[0].params["skew_secs"], "120");
    lab.kdc.with(|s| s.skew = -90);
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(account.findings[0].params["skew_secs"], "-90");
    assert!(account.findings[0].detail.contains("ahead"));
}

/// DNS-28 (section 3.10): a disabled account, a password reset outside Tenko and a KDC
/// that does not answer are `dns.gss.self_test_failed` with the reason; the KDC's text is
/// cleaned; the check is audited on a failure and when it passes again.
#[tokio::test]
async fn dns_28_a_failing_self_test_names_the_reason() {
    let lab = Lab::new();
    lab.adopt().await;
    lab.kdc.with(|s| s.disabled = true);
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(codes_of(&account), [findings::GSS_SELF_TEST_FAILED]);
    assert_eq!(account.findings[0].params["reason"], "disabled");
    lab.kdc.with(|s| {
        s.disabled = false;
        s.password = b"reset-by-an-administrator".to_vec();
        s.kvno = 9;
    });
    let account = lab.service.check(&cx(), None).await.expect("check").account;
    assert_eq!(account.findings[0].params["reason"], "keys_refused");
    lab.kdc.with(|s| s.unreachable = true);
    let outcome = lab.service.check(&cx(), None).await.expect("check");
    assert!(outcome.unreachable);
    assert_eq!(
        outcome.account.findings[0].params["reason"],
        "kdc_unreachable"
    );
    let checks = lab
        .audit()
        .into_iter()
        .filter(|(action, _)| action == audit::KRB_ACCOUNT_CHECK.as_str())
        .count();
    assert_eq!(checks, 3, "one record per failing check");
}

// ---------------------------------------------------------------------------------------
// Secrets (IAM-16)

/// IAM-16, NEVER-01: no password and no key octet is in an audit record, the account row,
/// a finding, an error text or a debug print, through an adopt, a refused adopt, a
/// rotation, a rotation refused and one whose refusal proves nothing, an import and a
/// delete.
#[tokio::test]
async fn iam_16_no_password_or_key_leaves_the_vault() {
    let lab = Lab::new();
    let mut wrong = adopt_request();
    wrong.password = Zeroizing::new(b"Wrong-Secret-Pass-9".to_vec());
    let refused = lab.service.adopt(&cx(), wrong).await.expect_err("refused");
    lab.adopt().await;
    lab.service.rotate(&cx(), None).await.expect("rotate");
    lab.kdc.with(|s| s.change = ChangeMode::Definite);
    let failed_once = lab.service.rotate(&cx(), None).await.expect_err("refused");
    lab.kdc.with(|s| s.change = ChangeMode::Spoofed);
    let failed_twice = lab.service.rotate(&cx(), None).await.expect_err("refused");
    let mut keys = lab.keys().await;
    let account = lab.account().await;
    // An import beside it, in a lab of its own: its keys must not leave the vault either.
    let imported = Lab::new();
    imported
        .service
        .import(&cx(), import_request("computer-tenko-dns.keytab"))
        .await
        .expect("import");
    for entry in imported.keys().await.entries() {
        let _ = keys.insert(entry.clone());
    }
    let mut secrets: Vec<Vec<u8>> = lab.passwords.given.lock().expect("lock").clone();
    secrets.push(OTP.to_vec());
    secrets.push(b"Wrong-Secret-Pass-9".to_vec());
    let mut hex_keys = Vec::new();
    for entry in keys.entries() {
        secrets.push(entry.key.as_bytes().to_vec());
        hex_keys.push(
            entry
                .key
                .as_bytes()
                .iter()
                .fold(String::new(), |mut out, b| {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{b:02x}");
                    out
                }),
        );
    }
    let mut stored = Vec::new();
    for store in [&lab.store, &imported.store] {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        for name in [
            tenko_store::tables::AUDIT.name(),
            KRB_ACCOUNTS.name(),
            tenko_vault::tables::META.name(),
        ] {
            for (key, value) in view
                .scan(name, KeyRange::all(), usize::MAX, false)
                .expect("scan")
            {
                stored.extend_from_slice(&key);
                stored.extend_from_slice(&value.value);
            }
        }
    }
    let texts = format!(
        "{refused:?} {} {failed_once:?} {} {failed_twice:?} {} {account:?} {keys:?} {:?} {:?} {:?}",
        refused.coded().detail,
        failed_once.coded().detail,
        failed_twice.coded().detail,
        lab.audit(),
        imported.audit(),
        imported.account().await,
    );
    for secret in &secrets {
        assert!(
            !stored.windows(secret.len()).any(|w| w == secret.as_slice()),
            "a secret in the store outside the vault"
        );
        let text = String::from_utf8_lossy(secret);
        assert!(!texts.contains(text.as_ref()), "a secret in a text");
    }
    for hex in &hex_keys {
        assert!(!texts.contains(hex.as_str()), "a key in a text");
    }
    lab.service.delete(&cx()).await.expect("delete");
    let secret = account.secret.expect("secret");
    assert!(lab.vault.meta(secret).await.expect("meta").is_none());
    assert!(lab.service.status().await.expect("status").is_none());
}

/// DNS-28: the password Tenko sets: 120 characters from `!` to `~`, every class present,
/// different every time.
#[test]
fn dns_28_the_password_tenko_sets() {
    let first = random_password(PASSWORD_LEN);
    let second = random_password(PASSWORD_LEN);
    assert_eq!(first.len(), PASSWORD_LEN);
    assert!(first.iter().all(|b| (b'!'..=b'~').contains(b)));
    assert!(first.iter().any(u8::is_ascii_lowercase));
    assert!(first.iter().any(u8::is_ascii_uppercase));
    assert!(first.iter().any(u8::is_ascii_digit));
    assert!(first.iter().any(u8::is_ascii_punctuation));
    assert_ne!(*first, *second);
}

#[test]
fn kdc_lists_parse() {
    assert_eq!(
        split_host_port("dc1.corp.example.test"),
        Some(("dc1.corp.example.test".to_owned(), None))
    );
    assert_eq!(
        split_host_port(" dc1.corp.example.test:1088 "),
        Some(("dc1.corp.example.test".to_owned(), Some(1088)))
    );
    assert_eq!(
        split_host_port("192.0.2.10"),
        Some(("192.0.2.10".to_owned(), None))
    );
    assert_eq!(
        split_host_port("[2001:db8::10]:88"),
        Some(("2001:db8::10".to_owned(), Some(88)))
    );
    assert_eq!(
        split_host_port("2001:db8::10"),
        Some(("2001:db8::10".to_owned(), None))
    );
    assert_eq!(split_host_port("dc1:port"), None);
    assert_eq!(split_host_port("[2001:db8::10"), None);
}

// ---------------------------------------------------------------------------------------
// The watcher

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<Option<Vec<u32>>>>,
    installed: Mutex<Option<(Realm, Vec<String>)>>,
    refuse: std::sync::atomic::AtomicBool,
}

impl KeySink for RecordingSink {
    fn install(&self, realm: Realm, spns: &[String], keys: KeySet) -> Result<(), String> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err("a malformed SPN".to_owned());
        }
        self.events.lock().expect("lock").push(Some(keys.kvnos()));
        *self.installed.lock().expect("lock") = Some((realm, spns.to_vec()));
        Ok(())
    }

    fn clear(&self) {
        self.events.lock().expect("lock").push(None);
        *self.installed.lock().expect("lock") = None;
    }

    fn installed(&self) -> Option<(Realm, Vec<String>)> {
        self.installed.lock().expect("lock").clone()
    }
}

/// DNS-28: the watcher hands the keys to the acceptor after the adopt and after a rotation
/// (the previous version with the current one), and clears them when the account goes.
#[tokio::test]
async fn dns_28_the_watcher_hands_the_keys_to_the_acceptor() {
    let lab = Lab::new();
    let sink = Arc::new(RecordingSink::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(follow(
        Arc::clone(&lab.service),
        Arc::clone(&sink) as Arc<dyn KeySink>,
        stop.clone(),
    ));
    let wait_for = |want: Option<Vec<u32>>| {
        let sink = Arc::clone(&sink);
        async move {
            wait_until_async(&format!("the watcher installs {want:?}"), async || {
                let events = sink.events.lock().expect("lock");
                if events.last() == Some(&want) {
                    Ok(())
                } else {
                    Err(events.clone())
                }
            })
            .await;
        }
    };
    lab.adopt().await;
    wait_for(Some(vec![2])).await;
    lab.service.rotate(&cx(), None).await.expect("rotate");
    wait_for(Some(vec![2, 3])).await;
    assert_eq!(sink.installed(), Some((realm(), vec![SPN.to_owned()])));
    lab.service.delete(&cx()).await.expect("delete");
    wait_for(None).await;
    // A key set the acceptor refuses is a finding on the account, recorded once.
    sink.refuse.store(true, Ordering::SeqCst);
    lab.kdc.with(|s| s.password = OTP.to_vec());
    lab.adopt().await;
    let found: Vec<String> = wait_until_async("a finding on the account", async || {
        let found: Vec<String> = codes_of(&lab.account().await)
            .into_iter()
            .map(str::to_owned)
            .collect();
        (!found.is_empty()).then_some(found)
    })
    .await;
    assert_eq!(found, [findings::GSS_SELF_TEST_FAILED]);
    assert_eq!(
        lab.account().await.findings[0].params["reason"],
        "install_refused"
    );
    stop.cancel();
    task.await.expect("stopped");
}

// ---------------------------------------------------------------------------------------
// The recorded Samba adopt

/// The `key=value` lines of a recorded exchange.
struct Record(BTreeMap<String, String>);

impl Record {
    fn load(name: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tenko-krb/tests/fixtures/kdc")
            .join(format!("{name}.txt"));
        let text = std::fs::read_to_string(path).expect("record");
        Self(
            text.lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        )
    }

    fn get(&self, key: &str) -> &str {
        &self.0[key]
    }

    fn octets(&self, key: &str) -> Vec<u8> {
        let text = self.get(key);
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn number<T: std::str::FromStr>(&self, key: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        self.get(key).parse().expect("number")
    }

    fn time(&self, prefix: &str) -> KrbTime {
        KrbTime {
            secs: self.number(&format!("{prefix}_secs")),
            usec: self.number(&format!("{prefix}_usec")),
        }
    }

    fn replay_as(
        &self,
        prefix: &str,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError> {
        let now = self.time(&format!("{prefix}now"));
        let mut exchange = AsExchange::new(
            client.clone(),
            service.clone(),
            secret,
            now,
            self.number(&format!("{prefix}nonce")),
        );
        exchange.first_request(now)?;
        for leg in 1..=2 {
            match exchange.handle(&self.octets(&format!("{prefix}reply{leg}")), now)? {
                AsStep::Send(_) => {}
                AsStep::Done(result) => return Ok(*result),
            }
        }
        Err(ClientError::Reply("pre-authentication twice"))
    }
}

const ADOPTED_PW: &[u8] = b"Tenko-Owned-Pass-2";
const ALICE_PW: &[u8] = b"Al1ce-Pass-lab";

/// The Samba domain controller as it answered in the recording: the AS exchange of
/// `TENKO-DNS$` for `kadmin/changepw` with the one-time password and the RFC 3244 change
/// are replayed octet for octet; the service ticket for `DNS/tenko.corp.example.test` is
/// the one Samba issued under the new password's key (kvno 11), obtained in the recording
/// with alice's TGT, which stands in for the account's own TGT (an AS exchange with the
/// new keys was not recorded, so this one checks the keys and returns alice's).
struct SambaReplay {
    record: Record,
}

#[async_trait::async_trait]
impl Kdc for SambaReplay {
    async fn as_exchange(
        &self,
        _target: &KdcTarget,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError> {
        if service.components() == ["kadmin", "changepw"] {
            return self.record.replay_as("changepw_", client, service, secret);
        }
        // Samba takes keys of the adopted password with the MS-KILE salt, and no others.
        let kvno: u32 = self.record.number("kvno");
        let adopted = keys_of(ADOPTED_PW, kvno, KeyVersionState::Current);
        let Secret::Keys(keys) = &secret else {
            return Err(ClientError::Reply("the replay takes keys"));
        };
        let theirs = keys
            .select(18, None)
            .map_err(|_| ClientError::Reply("no AES-256"))?;
        let wanted = adopted.select(18, Some(kvno)).expect("key")[0];
        if !theirs.contains(&wanted) {
            return Err(ClientError::Kdc {
                code: error_code::PREAUTH_FAILED,
                text: None,
            });
        }
        let mut tgt = self.record.replay_as(
            "alice_",
            &principal("alice@CORP.EXAMPLE.TEST"),
            &principal("krbtgt/CORP.EXAMPLE.TEST@CORP.EXAMPLE.TEST"),
            Secret::Password(Zeroizing::new(ALICE_PW.to_vec())),
        )?;
        tgt.key_kvno = Some(kvno);
        Ok(tgt)
    }

    async fn tgs_exchange(
        &self,
        _target: &KdcTarget,
        tgt: &Credentials,
        service: &PrincipalName,
    ) -> Result<Credentials, ClientError> {
        let tgs = TgsExchange::new(
            tgt.clone(),
            service.clone(),
            self.record.time("tgs"),
            self.record.number("tgs_nonce"),
        );
        tgs.handle(&self.record.octets("tgs_reply"))
    }

    async fn change_password(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        secret: Secret,
        new_password: &[u8],
    ) -> Result<(), ClientError> {
        assert_eq!(new_password, ADOPTED_PW, "the password the source gave");
        let changepw = client::changepw_principal(client)?;
        let ticket = self.as_exchange(target, client, &changepw, secret).await?;
        let subkey = Key::new(
            ticket.credentials.session_key.etype(),
            &self.record.octets("subkey"),
        )
        .map_err(ClientError::Cipher)?;
        let mut change = ChangePassword::with(
            ticket.credentials,
            new_password,
            self.record.time("change"),
            subkey,
            self.record.number("seq"),
        );
        for _ in 0..self.record.number::<u32>("change_builds") {
            change.request("127.0.0.1".parse().expect("ip"))?;
        }
        change.handle(&self.record.octets("change_reply"))
    }
}

/// DNS-28, OPS-11 (E45): the adopt of the controller against the exchanges recorded with a
/// Samba 4.19 AD domain controller: the one-time password gives the change-password ticket
/// with the MS-KILE salt, Samba took the change without a target, the version is the one
/// Samba's service ticket names (11), the keys Tenko derived accept that ticket, and the
/// self-test passes on the recorded time.
#[tokio::test]
async fn dns_28_the_recorded_samba_adopt_replays_through_the_controller() {
    let record = Record::load("samba-adopt");
    let clock = TestClock::at(record.time("tgs").secs);
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let passwords = Arc::new(TestPasswords::default());
    passwords
        .fixed
        .lock()
        .expect("lock")
        .push(ADOPTED_PW.to_vec());
    let service = KerberosService::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(Arc::clone(&vault) as Arc<dyn Vault>),
        Arc::new(SambaReplay { record }),
        Arc::clone(&clock) as Arc<dyn Clock>,
        passwords,
        KerberosConfig::default(),
    );
    let outcome = service
        .adopt(
            &cx(),
            AdoptRequest {
                realm: realm(),
                name: NAME.to_owned(),
                password: Zeroizing::new(OTP.to_vec()),
                spns: vec![SPN.to_owned()],
                kdcs: vec!["127.0.0.1".to_owned()],
                rotation_days: None,
            },
        )
        .await
        .expect("adopt");
    let account = outcome.account;
    assert!(account.findings.is_empty(), "{:?}", account.findings);
    assert_eq!(account.versions.len(), 1);
    assert_eq!(account.versions[0].kvno, 11);
    assert_eq!(account.versions[0].state, KeyVersionState::Current);
    let keys = service.keys(&account).await.expect("keys");
    assert_eq!(keys, keys_of(ADOPTED_PW, 11, KeyVersionState::Current));
}
