//! The client against a live MIT KDC (`live_mit_kdc`, ignored unless `TENKO_KRB_LAB`
//! names a lab started by `tests/fixtures/kdc/lab-mit.sh`) and against the exchanges that
//! test recorded under `tests/fixtures/kdc/` (every other test here).

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use tenko_core::dns::{KeyVersionState, PrincipalName, Realm};
use zeroize::Zeroizing;

use super::*;
use crate::{
    acceptor::{Acceptor, Config, FixedClock, Service, Step},
    cipher::Key,
    der::oid,
    fixtures::{hex, hex_string},
    keytab,
};

const ALICE_PW: &[u8] = b"Al1ce-Pass-lab";
const ROTATE_PW: [&[u8]; 2] = [b"Rotate-Pass-0", b"Rotate-Pass-1"];

fn principal(text: &str) -> PrincipalName {
    PrincipalName::parse(text).expect("principal")
}

fn krbtgt() -> PrincipalName {
    principal("krbtgt/CORP.EXAMPLE.TEST@CORP.EXAMPLE.TEST")
}

fn changepw() -> PrincipalName {
    principal("kadmin/changepw@CORP.EXAMPLE.TEST")
}

fn dns_spn() -> PrincipalName {
    principal("DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST")
}

fn password(pw: &[u8]) -> Secret {
    Secret::Password(Zeroizing::new(pw.to_vec()))
}

/// A recorded exchange: `key=value` lines, values in hex where they are octets.
#[derive(Default)]
struct Record(BTreeMap<String, String>);

impl Record {
    fn set(&mut self, key: &str, value: impl Into<String>) {
        self.0.insert(key.to_owned(), value.into());
    }

    fn get(&self, key: &str) -> &str {
        self.0
            .get(key)
            .unwrap_or_else(|| panic!("{key} in the record"))
    }

    fn octets(&self, key: &str) -> Vec<u8> {
        hex(self.get(key))
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

    fn set_time(&mut self, prefix: &str, time: KrbTime) {
        self.set(&format!("{prefix}_secs"), time.secs.to_string());
        self.set(&format!("{prefix}_usec"), time.usec.to_string());
    }

    fn path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kdc")
            .join(format!("{name}.txt"))
    }

    fn load(name: &str) -> Self {
        let text =
            std::fs::read_to_string(Self::path(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        Self(
            text.lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .map(|l| {
                    let (k, v) = l.split_once('=').expect("key=value");
                    (k.to_owned(), v.to_owned())
                })
                .collect(),
        )
    }

    fn save(&self, name: &str, comment: &str) {
        use std::fmt::Write;
        let mut text = format!("# {comment}\n");
        for (k, v) in &self.0 {
            let _ = writeln!(text, "{k}={v}");
        }
        std::fs::write(Self::path(name), text).expect("write the record");
    }
}

fn clock_now() -> KrbTime {
    // The live test is the one place that reads the system clock: it stands in for the
    // caller, which owns the clock.
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970");
    KrbTime {
        secs: i64::try_from(since.as_secs()).expect("secs"),
        usec: since.subsec_micros(),
    }
}

/// Runs an AS exchange over the network and records it.
async fn live_as(
    config: &TransportConfig,
    kdc: SocketAddr,
    client: &PrincipalName,
    service: &PrincipalName,
    secret: Secret,
    record: &mut Record,
) -> Result<AsResult, ClientError> {
    let now = clock_now();
    let nonce = super::nonce()?;
    record.set_time("now", now);
    record.set("nonce", nonce.to_string());
    let mut exchange = AsExchange::new(client.clone(), service.clone(), secret, now, nonce);
    let mut request = exchange.first_request(now)?;
    for leg in 1..=2 {
        let reply = transport::exchange(config, &[kdc], |_| Ok(request.clone())).await?;
        record.set(&format!("reply{leg}"), hex_string(&reply));
        match exchange.handle(&reply, now)? {
            AsStep::Send(next) => request = next,
            AsStep::Done(result) => return Ok(*result),
        }
    }
    Err(ClientError::Reply("pre-authentication twice"))
}

/// Replays a recorded AS exchange.
fn replay_as(
    record: &Record,
    client: &PrincipalName,
    service: &PrincipalName,
    secret: Secret,
) -> Result<AsResult, ClientError> {
    let now = record.time("now");
    let mut exchange = AsExchange::new(
        client.clone(),
        service.clone(),
        secret,
        now,
        record.number("nonce"),
    );
    exchange.first_request(now)?;
    for leg in 1..=2 {
        match exchange.handle(&record.octets(&format!("reply{leg}")), now)? {
            AsStep::Send(_) => {}
            AsStep::Done(result) => return Ok(*result),
        }
    }
    Err(ClientError::Reply("pre-authentication twice"))
}

fn lab_service(keytab_bytes: &[u8], now: KrbTime) -> Arc<Service> {
    let keys = keytab::parse(keytab_bytes)
        .expect("keytab")
        .key_set(|_| true, KeyVersionState::Current)
        .expect("keys");
    Service::for_test(
        Config::new(
            Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
            &["DNS/tenko.corp.example.test"],
        ),
        keys,
        Arc::new(FixedClock(KrbTime::from_secs(now.secs + 1))),
        now.secs - 60,
        None,
    )
}

/// The self-test's last step: the service ticket accepted by the node's own acceptor.
fn accept_service_ticket(
    ticket: &Credentials,
    keytab_bytes: &[u8],
    now: KrbTime,
) -> crate::acceptor::Context {
    let (token, _) = initiator_token(ticket, oid::KRB5, now, 0x0bad_cafe).expect("token");
    match lab_service(keytab_bytes, now).negotiation().step(&token) {
        Ok(Step::Established { context, .. }) => *context,
        other => panic!("the acceptor did not accept the service ticket: {other:?}"),
    }
}

/// DNS-28: AS with pre-authentication, TGS for the DNS SPN, the ticket accepted by Tenko's
/// acceptor, and two password changes, against a live MIT KDC; with `TENKO_WRITE_FIXTURES`
/// the exchanges are recorded under `tests/fixtures/kdc/`.
#[tokio::test]
#[ignore = "needs the MIT lab of tests/fixtures/kdc/lab-mit.sh: TENKO_KRB_LAB=<dir>"]
#[allow(clippy::too_many_lines)]
async fn dns_28_live_mit_kdc() {
    let lab = PathBuf::from(std::env::var("TENKO_KRB_LAB").expect("TENKO_KRB_LAB"));
    let write = std::env::var_os("TENKO_WRITE_FIXTURES").is_some();
    let kdc: SocketAddr = "127.0.0.1:1088".parse().expect("kdc");
    let kpasswd: SocketAddr = "127.0.0.1:1464".parse().expect("kpasswd");
    let config = TransportConfig::default();
    let keytab_bytes = std::fs::read(lab.join("dns.keytab")).expect("dns.keytab");

    // AS with pre-authentication, then TGS for the SPN, then the acceptor.
    let alice = principal("alice@CORP.EXAMPLE.TEST");
    let mut as_record = Record::default();
    let tgt = live_as(
        &config,
        kdc,
        &alice,
        &krbtgt(),
        password(ALICE_PW),
        &mut as_record,
    )
    .await
    .expect("AS");
    assert!(
        as_record.0.contains_key("reply2"),
        "the KDC asked for pre-authentication"
    );
    let mut tgs_record = Record::default();
    let now = clock_now();
    let nonce = super::nonce().expect("nonce");
    tgs_record.set_time("now", now);
    tgs_record.set("nonce", nonce.to_string());
    let tgs = TgsExchange::new(tgt.credentials.clone(), dns_spn(), now, nonce);
    let request = tgs.request(now).expect("request");
    let reply = transport::exchange(&config, &[kdc], |_| Ok(request.clone()))
        .await
        .expect("TGS");
    tgs_record.set("reply", hex_string(&reply));
    let service_ticket = tgs.handle(&reply).expect("TGS-REP");
    let context = accept_service_ticket(&service_ticket, &keytab_bytes, now);
    assert_eq!(context.client, alice);
    assert_eq!(context.ticket_kvno, Some(2), "ktadd made version 2");

    // The pre-authentication refuses a wrong password.
    let error = Client::new(vec![kdc], vec![kpasswd], Arc::new(FixedClock(clock_now())))
        .as_exchange(&alice, &krbtgt(), password(b"wrong"))
        .await
        .expect_err("refused");
    assert!(
        matches!(
            error,
            ClientError::Kdc {
                code: error_code::PREAUTH_FAILED,
                ..
            }
        ),
        "{error}"
    );

    // A password change and back, with a ticket for the new password in between.
    let rotate = principal("rotate@CORP.EXAMPLE.TEST");
    let mut kpasswd_record = Record::default();
    let ticket = live_as(
        &config,
        kdc,
        &rotate,
        &changepw(),
        password(ROTATE_PW[0]),
        &mut kpasswd_record,
    )
    .await
    .expect("AS for kadmin/changepw");
    assert_ne!(
        ticket.credentials.part.flags & der::ticket_flags::INITIAL,
        0
    );
    let now = clock_now();
    let subkey = Key::random(ticket.credentials.session_key.etype()).expect("subkey");
    let mut change = ChangePassword::with(
        ticket.credentials.clone(),
        ROTATE_PW[1],
        now,
        subkey.clone(),
        0x0123_4567,
    );
    let reply = transport::exchange(&config, &[kpasswd], |local| change.request(local))
        .await
        .expect("kpasswd");
    // MIT's kadmind asks for the target to be named (the AD form leaves it out).
    assert!(matches!(
        change.handle(&reply),
        Err(ClientError::PasswordRefused { code: 1, .. })
    ));
    kpasswd_record.set("unnamed_reply", hex_string(&reply));
    change.name_target();
    let reply = transport::exchange(&config, &[kpasswd], |local| change.request(local))
        .await
        .expect("kpasswd");
    change.handle(&reply).expect("the password is changed");
    kpasswd_record.set_time("change", now);
    kpasswd_record.set("subkey", hex_string(subkey.as_bytes()));
    kpasswd_record.set("seq", "19088743");
    kpasswd_record.set("change_reply", hex_string(&reply));
    let client = Client::new(vec![kdc], vec![kpasswd], Arc::new(FixedClock(clock_now())));
    client
        .as_exchange(&rotate, &krbtgt(), password(ROTATE_PW[1]))
        .await
        .expect("a ticket with the new password");
    let error = client
        .as_exchange(&rotate, &krbtgt(), password(ROTATE_PW[0]))
        .await
        .expect_err("old password");
    assert!(
        matches!(
            error,
            ClientError::Kdc {
                code: error_code::PREAUTH_FAILED,
                ..
            }
        ),
        "{error}"
    );
    client
        .change_password(&rotate, ROTATE_PW[1], ROTATE_PW[0])
        .await
        .expect("and back");
    // The high-level client: AS and TGS, and the service ticket accepted.
    let tgt = client
        .as_exchange(&alice, &krbtgt(), password(ALICE_PW))
        .await
        .expect("AS");
    let ticket = client
        .tgs_exchange(&tgt.credentials, &dns_spn())
        .await
        .expect("TGS");
    accept_service_ticket(&ticket, &keytab_bytes, clock_now());
    // The same over TCP only (no request fits the UDP limit of zero).
    let mut tcp = client.clone();
    tcp.transport.udp_limit = 0;
    tcp.as_exchange(&alice, &krbtgt(), password(ALICE_PW))
        .await
        .expect("AS over TCP");
    tcp.change_password(&rotate, ROTATE_PW[0], ROTATE_PW[1])
        .await
        .expect("kpasswd over TCP");
    tcp.change_password(&rotate, ROTATE_PW[1], ROTATE_PW[0])
        .await
        .expect("and back over TCP");

    if write {
        as_record.save(
            "as-alice",
            "AS exchange of alice for krbtgt with PA-ENC-TIMESTAMP, MIT krb5 1.20.1 KDC",
        );
        tgs_record.save(
            "tgs-dns",
            "TGS exchange of alice for DNS/tenko.corp.example.test with the TGT of as-alice",
        );
        kpasswd_record.save("kpasswd-rotate", "AS exchange of rotate for kadmin/changepw and the RFC 3244 change from Rotate-Pass-0 to Rotate-Pass-1, MIT kadmind 1.20.1");
        std::fs::write(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdc/dns.keytab"),
            &keytab_bytes,
        )
        .expect("keytab");
    }
}

fn recorded_tgt() -> AsResult {
    replay_as(
        &Record::load("as-alice"),
        &principal("alice@CORP.EXAMPLE.TEST"),
        &krbtgt(),
        password(ALICE_PW),
    )
    .expect("the recorded AS exchange")
}

/// DNS-28: the recorded AS exchange: pre-authentication with the KDC's salt, the TGT and
/// the KDC's time.
#[test]
fn dns_28_recorded_as_exchange() {
    let record = Record::load("as-alice");
    let result = recorded_tgt();
    assert_eq!(
        result.credentials.ticket.sname.components,
        ["krbtgt", "CORP.EXAMPLE.TEST"]
    );
    assert_eq!(result.credentials.part.nonce, record.number::<u32>("nonce"));
    assert_eq!(result.key_etype, EncryptionType::Aes256CtsHmacSha1);
    assert_eq!(result.iterations, cipher::DEFAULT_ITERATIONS);
    assert!(
        (result.kdc_time.secs - record.time("now").secs).abs() < 5,
        "the KDC's time"
    );
    assert_ne!(
        result.credentials.part.flags & der::ticket_flags::PRE_AUTHENT,
        0
    );
    // The wrong password does not decrypt the reply.
    let error = replay_as(
        &record,
        &principal("alice@CORP.EXAMPLE.TEST"),
        &krbtgt(),
        password(b"wrong"),
    )
    .expect_err("refused");
    assert_eq!(error, ClientError::Cipher(CipherError::Integrity));
    // Another nonce is not this reply's.
    let mut other = AsExchange::new(
        principal("alice@CORP.EXAMPLE.TEST"),
        krbtgt(),
        password(ALICE_PW),
        record.time("now"),
        1,
    );
    assert!(matches!(
        other.handle(&record.octets("reply1"), record.time("now")),
        Ok(AsStep::Send(_))
    ));
    assert_eq!(
        other
            .handle(&record.octets("reply2"), record.time("now"))
            .expect_err("nonce"),
        ClientError::Reply("the nonce is not the request's")
    );
    // Another client is not this reply's.
    let mut bob = AsExchange::new(
        principal("bob@CORP.EXAMPLE.TEST"),
        krbtgt(),
        password(ALICE_PW),
        record.time("now"),
        record.number("nonce"),
    );
    bob.handle(&record.octets("reply1"), record.time("now"))
        .expect("pre-authentication asked");
    assert!(
        bob.handle(&record.octets("reply2"), record.time("now"))
            .is_err()
    );
}

/// DNS-28: the recorded TGS exchange for the DNS SPN, and the service ticket accepted by
/// Tenko's acceptor with the lab's keytab: the self-test's path.
#[test]
fn dns_28_recorded_tgs_exchange_and_the_self_test_acceptance() {
    let record = Record::load("tgs-dns");
    let tgt = recorded_tgt();
    let tgs = TgsExchange::new(
        tgt.credentials.clone(),
        dns_spn(),
        record.time("now"),
        record.number("nonce"),
    );
    let ticket = tgs.handle(&record.octets("reply")).expect("TGS-REP");
    assert_eq!(
        ticket.ticket.enc_part.kvno,
        Some(2),
        "the key version the KDC issues"
    );
    assert_eq!(
        ticket.part.sname.components,
        ["DNS", "tenko.corp.example.test"]
    );
    let keytab_bytes = crate::fixtures::file("kdc/dns.keytab");
    let context = accept_service_ticket(&ticket, &keytab_bytes, record.time("now"));
    assert_eq!(context.client.to_string(), "alice@CORP.EXAMPLE.TEST");
    // A request of ours has the body's checksum under the TGT's session key.
    let request =
        KdcReq::decode(&tgs.request(record.time("now")).expect("request")).expect("TGS-REQ");
    let padata = request.padata.expect("padata");
    let ap_req = ApReq::decode(&padata[0].value).expect("PA-TGS-REQ");
    let auth = cipher::decrypt_data(
        &tgt.credentials.session_key,
        usage::TGS_REQ_AUTHENTICATOR,
        &ap_req.authenticator,
    )
    .expect("authenticator");
    let auth = Authenticator::decode(&auth).expect("authenticator");
    let cksum = auth.cksum.expect("checksum");
    cipher::verify_checksum(
        &tgt.credentials.session_key,
        usage::TGS_REQ_AUTH_CKSUM,
        cksum.cksumtype,
        &request.req_body.encode(),
        &cksum.checksum,
    )
    .expect("the body's checksum");
    // Another nonce is refused.
    let other = TgsExchange::new(tgt.credentials, dns_spn(), record.time("now"), 7);
    assert_eq!(
        other.handle(&record.octets("reply")).expect_err("nonce"),
        ClientError::Reply("the nonce is not the request's")
    );
}

/// DNS-28: the recorded change-password exchange of RFC 3244.
#[test]
fn dns_28_recorded_change_password_exchange() {
    let record = Record::load("kpasswd-rotate");
    let rotate = principal("rotate@CORP.EXAMPLE.TEST");
    let ticket = replay_as(&record, &rotate, &changepw(), password(ROTATE_PW[0]))
        .expect("kadmin/changepw ticket");
    assert_eq!(
        ticket.credentials.part.sname.components,
        ["kadmin", "changepw"]
    );
    let subkey = Key::new(
        ticket.credentials.session_key.etype(),
        &record.octets("subkey"),
    )
    .expect("subkey");
    let mut change = ChangePassword::with(
        ticket.credentials.clone(),
        ROTATE_PW[1],
        record.time("change"),
        subkey.clone(),
        record.number("seq"),
    );
    // An answer is bound to the last request (RFC 4120 section 3.2.5: the AP-REP echoes
    // the authenticator's time): none before a request is sent, and only the last one's.
    let ip: IpAddr = "127.0.0.1".parse().expect("ip");
    let not_ours = Err(ClientError::Reply("the answer is not to the last request"));
    assert_eq!(change.handle(&record.octets("change_reply")), not_ours);
    change.request(ip).expect("the request without a target");
    // The answer to it was MIT's "malformed".
    assert!(matches!(
        change.handle(&record.octets("unnamed_reply")),
        Err(ClientError::PasswordRefused { code: 1, .. })
    ));
    assert_eq!(change.handle(&record.octets("change_reply")), not_ours);
    change.name_target();
    let request = change.request(ip).expect("the request with the target");
    change
        .handle(&record.octets("change_reply"))
        .expect("the server's result is success");
    // The older answer replayed after the retry is not taken for this one.
    assert_eq!(change.handle(&record.octets("unnamed_reply")), not_ours);
    // A request carries the new password in ChangePasswdData under the subkey.
    assert_eq!(
        u16::from_be_bytes([request[2], request[3]]),
        KPASSWD_VERSION
    );
    let ap_len = usize::from(u16::from_be_bytes([request[4], request[5]]));
    let private = KrbPriv::decode(&request[6 + ap_len..]).expect("KRB-PRIV");
    let plain = cipher::decrypt_data(&subkey, usage::KRB_PRIV_ENC_PART, &private.enc_part)
        .expect("decrypts");
    let part = EncKrbPrivPart::decode(&plain).expect("EncKrbPrivPart");
    assert_eq!(
        &ChangePasswdData::decode(&part.user_data)
            .expect("data")
            .newpasswd[..],
        ROTATE_PW[1]
    );
    assert_eq!(
        part.s_address,
        Some(HostAddress::from_ip("127.0.0.1".parse().expect("ip")))
    );
}

#[test]
fn change_password_results_and_malformed_answers() {
    assert_eq!(result(&[0, 0]), Some((0, String::new())));
    assert_eq!(
        result(&[0, 4, b'p', b'o', b'l', 0]),
        Some((4, "pol".to_owned()))
    );
    assert_eq!(result(&[0, 4, 0xff, 0xfe]), Some((4, "fffe".to_owned())));
    assert_eq!(result(&[0]), None);
    let record = Record::load("kpasswd-rotate");
    let ticket = replay_as(
        &record,
        &principal("rotate@CORP.EXAMPLE.TEST"),
        &changepw(),
        password(ROTATE_PW[0]),
    )
    .expect("ticket");
    let change = ChangePassword::with(
        ticket.credentials,
        ROTATE_PW[1],
        record.time("change"),
        Key::random(EncryptionType::Aes256CtsHmacSha1).expect("key"),
        1,
    );
    let reply = record.octets("change_reply");
    for len in 0..reply.len() {
        assert!(change.handle(&reply[..len]).is_err(), "prefix {len}");
    }
    let mut version = reply.clone();
    version[3] = 7;
    assert_eq!(
        change.handle(&version),
        Err(ClientError::Reply("not a change-password answer"))
    );
}

const ONE_TIME_PW: &[u8] = b"One-Time-Pass-1";
const ADOPTED_PW: &[u8] = b"Tenko-Owned-Pass-2";

fn tenko_dns_account() -> tenko_core::dns::KrbAccount {
    tenko_core::dns::KrbAccount {
        realm: Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
        name: "TENKO-DNS$".into(),
        spns: vec!["DNS/tenko.corp.example.test".into()],
        kdcs: vec![],
        owned: true,
        rotation_days: 30,
        versions: vec![],
        last_rotation: None,
        last_check: None,
    }
}

/// The keys of the adopted password with the MS-KILE salt, under `kvno`.
fn adopted_keys(kvno: u32) -> KeySet {
    let account = tenko_dns_account();
    KeySet::from_password(
        &account.principal().expect("principal"),
        kvno,
        KeyVersionState::Current,
        ADOPTED_PW,
        &cipher::salt::account(&account),
        cipher::DEFAULT_ITERATIONS,
        &ETYPES,
    )
    .expect("keys")
}

fn samba_service(keys: KeySet, now: KrbTime) -> Arc<Service> {
    Service::for_test(
        Config::new(
            Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
            &["DNS/tenko.corp.example.test"],
        ),
        keys,
        Arc::new(FixedClock(KrbTime::from_secs(now.secs + 1))),
        now.secs - 60,
        None,
    )
}

/// DNS-28: the adopt flow of identity plan section 3.1 against a live Samba AD domain
/// controller: a ticket for `kadmin/changepw` with the one-time password of the pre-staged
/// computer account (the KDC's salt is the MS-KILE salt `tenko-core` computes), the RFC
/// 3244 change without a target, keys derived from the new password, a ticket with them,
/// and alice's service ticket for the SPN accepted with them, her SIDs from the PAC. The
/// account is set back to the one-time password at the end. Needs the Samba lab of the
/// spike's `scripts/lab-samba.sh` with `TENKO-DNS$` pre-staged: `TENKO_SAMBA_LAB=1`.
#[tokio::test]
#[ignore = "needs a Samba AD DC on 127.0.0.1:88 with TENKO-DNS$ pre-staged: TENKO_SAMBA_LAB=1"]
#[allow(clippy::too_many_lines)]
async fn dns_28_live_samba_adopt() {
    assert!(
        std::env::var_os("TENKO_SAMBA_LAB").is_some(),
        "set TENKO_SAMBA_LAB"
    );
    let write = std::env::var_os("TENKO_WRITE_FIXTURES").is_some();
    let kdc: SocketAddr = "127.0.0.1:88".parse().expect("kdc");
    let kpasswd: SocketAddr = "127.0.0.1:464".parse().expect("kpasswd");
    let config = TransportConfig::default();
    let account = tenko_dns_account();
    let tenko = account.principal().expect("principal");
    let mut record = Record::default();

    // The one-time password gives a kadmin/changepw ticket; the KDC names the MS-KILE salt.
    let mut as_record = Record::default();
    let ticket = live_as(
        &config,
        kdc,
        &tenko,
        &changepw(),
        password(ONE_TIME_PW),
        &mut as_record,
    )
    .await
    .expect("AS with the one-time password");
    assert_eq!(
        ticket.salt.as_deref(),
        Some(cipher::salt::account(&account).as_str())
    );
    for (k, v) in as_record.0 {
        record.set(&format!("changepw_{k}"), v);
    }

    // The change as AD reads it: no target.
    let now = clock_now();
    let subkey = Key::random(ticket.credentials.session_key.etype()).expect("subkey");
    let mut change = ChangePassword::with(
        ticket.credentials.clone(),
        ADOPTED_PW,
        now,
        subkey.clone(),
        0x0765_4321,
    );
    let mut builds = 0_u32;
    let reply = transport::exchange(&config, &[kpasswd], |local| {
        builds += 1;
        change.request(local)
    })
    .await
    .expect("kpasswd");
    change
        .handle(&reply)
        .expect("Samba takes the change without a target");
    record.set_time("change", now);
    // The requests built: two when the UDP attempt failed and TCP answered.
    record.set("change_builds", builds.to_string());
    record.set("subkey", hex_string(subkey.as_bytes()));
    record.set("seq", (0x0765_4321_u32).to_string());
    record.set("change_reply", hex_string(&reply));

    // A ticket with the new password names the new key version; keys derived from the
    // password and the MS-KILE salt authenticate.
    let client = Client::new(vec![kdc], vec![kpasswd], Arc::new(FixedClock(clock_now())));
    let fresh = client
        .as_exchange(&tenko, &krbtgt(), password(ADOPTED_PW))
        .await
        .expect("the new password");
    let kvno = fresh.key_kvno.expect("the AS-REP names the key version");
    let keys = adopted_keys(kvno);
    client
        .as_exchange(&tenko, &krbtgt(), Secret::Keys(keys.clone()))
        .await
        .expect("the derived keys");
    record.set("kvno", kvno.to_string());

    // alice's service ticket for the SPN is accepted with the derived keys.
    let alice = principal("alice@CORP.EXAMPLE.TEST");
    let mut alice_record = Record::default();
    let tgt = live_as(
        &config,
        kdc,
        &alice,
        &krbtgt(),
        password(ALICE_PW),
        &mut alice_record,
    )
    .await
    .expect("alice");
    for (k, v) in alice_record.0 {
        record.set(&format!("alice_{k}"), v);
    }
    let now = clock_now();
    let nonce = super::nonce().expect("nonce");
    let tgs = TgsExchange::new(tgt.credentials.clone(), dns_spn(), now, nonce);
    let request = tgs.request(now).expect("request");
    let reply = transport::exchange(&config, &[kdc], |_| Ok(request.clone()))
        .await
        .expect("TGS");
    record.set_time("tgs", now);
    record.set("tgs_nonce", nonce.to_string());
    record.set("tgs_reply", hex_string(&reply));
    let service_ticket = tgs.handle(&reply).expect("TGS-REP");
    assert_eq!(service_ticket.ticket.enc_part.kvno, Some(kvno));
    let (token, _) = initiator_token(&service_ticket, oid::MS_KRB5, now, 7).expect("token");
    let Ok(Step::Established { context, .. }) = samba_service(keys, now).negotiation().step(&token)
    else {
        panic!("the acceptor did not accept the ticket with the derived keys");
    };
    assert_eq!(context.client, alice);
    assert!(
        context.user_sid().is_some(),
        "Samba's PAC names alice's SID"
    );

    // Back to the one-time password, so that the test can run again.
    client
        .change_password(&tenko, ADOPTED_PW, ONE_TIME_PW)
        .await
        .expect("and back");
    if write {
        record.save("samba-adopt", "The adopt flow against a Samba 4.19 AD DC: TENKO-DNS$ with its one-time password, the RFC 3244 change without a target, alice's TGS for DNS/tenko.corp.example.test");
    }
}

/// DNS-28: the recorded adopt flow against Samba, offline: the KDC's salt is the MS-KILE
/// salt, the change without a target succeeded, and alice's service ticket decrypts and is
/// accepted with keys that Tenko derives from the new password with that salt alone.
#[test]
fn dns_28_recorded_samba_adopt() {
    let record = Record::load("samba-adopt");
    let account = tenko_dns_account();
    let tenko = account.principal().expect("principal");
    let sub = |prefix: &str| {
        Record(
            record
                .0
                .iter()
                .filter_map(|(k, v)| k.strip_prefix(prefix).map(|k| (k.to_owned(), v.clone())))
                .collect(),
        )
    };
    let ticket = replay_as(
        &sub("changepw_"),
        &tenko,
        &changepw(),
        password(ONE_TIME_PW),
    )
    .expect("changepw ticket");
    assert_eq!(
        ticket.salt.as_deref(),
        Some("CORP.EXAMPLE.TESThosttenko-dns.corp.example.test")
    );
    assert_eq!(
        ticket.salt.as_deref(),
        Some(cipher::salt::account(&account).as_str())
    );
    let subkey = Key::new(
        ticket.credentials.session_key.etype(),
        &record.octets("subkey"),
    )
    .expect("subkey");
    let mut change = ChangePassword::with(
        ticket.credentials,
        ADOPTED_PW,
        record.time("change"),
        subkey,
        record.number("seq"),
    );
    for _ in 0..record.number::<u32>("change_builds") {
        change
            .request("127.0.0.1".parse().expect("ip"))
            .expect("request");
    }
    change
        .handle(&record.octets("change_reply"))
        .expect("the change without a target succeeded");
    let tgt = replay_as(
        &sub("alice_"),
        &principal("alice@CORP.EXAMPLE.TEST"),
        &krbtgt(),
        password(ALICE_PW),
    )
    .expect("alice");
    let tgs = TgsExchange::new(
        tgt.credentials,
        dns_spn(),
        record.time("tgs"),
        record.number("tgs_nonce"),
    );
    let service_ticket = tgs.handle(&record.octets("tgs_reply")).expect("TGS-REP");
    let kvno: u32 = record.number("kvno");
    assert_eq!(service_ticket.ticket.enc_part.kvno, Some(kvno));
    let now = record.time("tgs");
    let (token, _) = initiator_token(&service_ticket, oid::KRB5, now, 7).expect("token");
    let Ok(Step::Established { context, .. }) = samba_service(adopted_keys(kvno), now)
        .negotiation()
        .step(&token)
    else {
        panic!("the keys derived with the MS-KILE salt do not accept the ticket");
    };
    let user = context.user_sid().expect("Samba's PAC names alice's SID");
    assert!(
        user.rid().is_some_and(|rid| rid >= 1000),
        "an ordinary account"
    );
    let domain_users = user.parent().map(|domain| domain.to_string() + "-513");
    assert!(
        context
            .group_sids()
            .iter()
            .any(|g| Some(g.to_string()) == domain_users),
        "Domain Users of alice's own domain"
    );
}
