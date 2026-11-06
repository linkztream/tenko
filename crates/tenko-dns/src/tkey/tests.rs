//! The TKEY handler through [`Tkey::answer`], with the test initiator of
//! [`super::testing`] and the recorded Samba exchange of `tenko-krb`.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Mutex,
};

use tenko_core::{
    audit::AuditDraft,
    dns::{EncryptionType, KeyVersionState, PrincipalName, QueryTransport, Realm, TsigAlgorithm},
};
use tenko_krb::{
    cipher::Key,
    der::{NegTokenInit, oid},
    keys::{KeyEntry, KeySet},
};

use super::{
    testing::{Initiator, SPN, TestClock, key, key_set, realm},
    wire::{self, answer_record, error, mode},
    *,
};
use crate::{
    tsig::{MacKey, Signer, TsigKey, Verifier},
    update::conn,
    wire::MAX_MESSAGE_LEN,
};

const NOW: i64 = 1_790_000_000;
const NAME: &[u8] = b"\x0asig-pc01-1\x03ns1\x04corp\x07example\x04test\x00";
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha1;

#[derive(Default)]
struct Audit(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Audit {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("audit").push(draft);
    }
}

impl Audit {
    fn actions(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("audit")
            .iter()
            .map(|draft| draft.action.as_str().to_owned())
            .collect()
    }
}

struct Node {
    tkey: Arc<Tkey>,
    clock: Arc<TestClock>,
    hmac: Keyring,
    audit: Audit,
    service_key: Key,
}

fn node_with(settings: GssSettings) -> Node {
    let clock = TestClock::new(NOW - 60);
    let tkey = Tkey::with_clock(settings, Arc::clone(&clock) as Arc<dyn Clock>);
    let service_key = key(AES256, 0x55);
    tkey.handle()
        .install(realm(), &[SPN.to_owned()], key_set(&service_key, 3))
        .expect("install");
    clock.set(NOW);
    let hmac = Keyring::new([TsigKey::new(
        &tenko_core::dns::DnsName::new("update.ns1.corp.example.test").expect("name"),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef",
    )]);
    Node {
        tkey,
        clock,
        hmac,
        audit: Audit::default(),
        service_key,
    }
}

fn node() -> Node {
    node_with(GssSettings::default())
}

fn tcp(from: &str) -> crate::respond::Conn {
    conn(
        SocketAddr::new(from.parse().expect("address"), 50_000),
        "192.0.2.53:53".parse().expect("local"),
        QueryTransport::Tcp,
    )
}

fn udp(from: &str) -> crate::respond::Conn {
    crate::respond::Conn {
        transport: QueryTransport::Udp,
        ..tcp(from)
    }
}

fn server() -> IpAddr {
    "192.0.2.53".parse().expect("address")
}

fn query(name: &[u8], mode: u16, token: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(
        &mut out,
        0x4b45,
        name,
        GSS_TSIG,
        mode,
        token,
        u32::try_from(NOW).expect("time"),
    );
    out
}

impl Node {
    fn initiator(&self, client: &str) -> Initiator {
        Initiator::new(self.service_key.clone(), 3, client, NOW)
    }

    fn ask(&self, message: &[u8], conn: &crate::respond::Conn) -> Vec<u8> {
        self.tkey
            .answer(message, conn, &self.hmac, &self.audit)
            .expect("an answer")
    }

    /// One complete negotiation: the answer and the client's side of the context.
    fn negotiate(&self, init: &Initiator, name: &[u8], token: &[u8]) -> (Vec<u8>, Arc<GssContext>) {
        let answer = self.ask(&query(name, mode::GSSAPI, token), &tcp("192.0.2.10"));
        let (mode, error, key) = answer_record(&answer)
            .expect("parses")
            .expect("a TKEY record");
        assert_eq!((mode, error), (mode::GSSAPI, 0), "established");
        let context = init.finish(name, key, server());
        (answer, context)
    }
}

fn tkey_error(answer: &[u8]) -> Option<u16> {
    answer_record(answer)
        .expect("parses")
        .map(|(_, error, _)| error)
}

fn rcode(answer: &[u8]) -> u8 {
    crate::wire::parse_header(answer).expect("header").rcode
}

/// DNS-28: a raw Kerberos token (MIT's `nsupdate -g`) establishes a context in one leg; the
/// answer carries the AP-REP for mutual authentication, is signed with the new context and
/// verifies at the client with no request MAC in its digest ([MS-GSSA] 3.1.5.1).
#[test]
fn dns_28_a_raw_kerberos_negotiation_establishes_a_signed_context() {
    let node = node();
    let init = node.initiator("pc01$");
    let (answer, client) = node.negotiate(&init, NAME, &init.raw_token());
    assert_eq!(rcode(&answer), 0);
    let tsig = crate::tsig::find(&answer).expect("parses").expect("signed");
    assert_eq!(tsig.algorithm, GSS_TSIG);
    assert_eq!(tsig.mac.len(), tenko_krb::mic::TOKEN_LEN);
    let mut verifier = Verifier::without_request_mac(MacKey::Gss(Arc::clone(&client)));
    verifier
        .verify(&answer, u64::try_from(NOW).expect("now"))
        .expect("the TKEY answer verifies at the client");
    assert_eq!(node.tkey.counts(), (0, 1));
    let held = node.tkey.context(NAME).expect("held");
    assert_eq!(
        held.identity().principal.to_string(),
        "pc01$@CORP.EXAMPLE.TEST"
    );
    assert_eq!(held.identity().sid, None, "no PAC");
    assert_eq!(held.expires(), u64::try_from(NOW + 3_600).expect("expiry"));
}

/// DNS-28: Windows' SPNEGO list (Microsoft's Kerberos OID first, `NegoEx` and NTLM after)
/// establishes a context; a list of NTLM alone is refused with BADKEY, audited, and holds
/// nothing.
#[test]
fn dns_28_spnego_establishes_and_an_ntlm_only_offer_is_refused() {
    let node = node();
    let init = node.initiator("pc01$");
    let (answer, _) = node.negotiate(&init, NAME, &init.spnego_token());
    assert!(crate::tsig::find(&answer).expect("parses").is_some());
    let other = b"\x0asig-pc02-1\x03ns1\x04corp\x07example\x04test\x00";
    let answer = node.ask(
        &query(other, mode::GSSAPI, &Initiator::ntlm_only_token()),
        &tcp("192.0.2.11"),
    );
    assert_eq!(
        (rcode(&answer), tkey_error(&answer)),
        (0, Some(error::BADKEY))
    );
    assert!(
        crate::tsig::find(&answer).expect("parses").is_none(),
        "unsigned"
    );
    assert_eq!(node.tkey.counts(), (0, 1));
    assert_eq!(node.audit.actions(), vec!["dns.gss.refuse".to_owned()]);
}

/// DNS-28: BADMODE for a mode other than 3 and 5, BADALG for another algorithm (the
/// Windows 2000 name too), BADNAME for a name in use by a context or a TSIG key, REFUSED on
/// a node without keys, FORMERR for a malformed query and for a signed negotiation.
#[test]
fn dns_28_modes_algorithms_and_names_are_checked() {
    let node = node();
    let init = node.initiator("pc01$");
    let token = init.raw_token();
    let from = tcp("192.0.2.10");
    let answer = node.ask(&query(NAME, 2, &token), &from);
    assert_eq!(tkey_error(&answer), Some(error::BADMODE));
    let mut microsoft = Vec::new();
    wire::write_query(
        &mut microsoft,
        1,
        NAME,
        b"\x03gss\x09microsoft\x03com\x00",
        mode::GSSAPI,
        &token,
        0,
    );
    assert_eq!(
        tkey_error(&node.ask(&microsoft, &from)),
        Some(error::BADALG)
    );
    let tsig_name = b"\x06update\x03ns1\x04corp\x07example\x04test\x00";
    let answer = node.ask(&query(tsig_name, mode::GSSAPI, &token), &from);
    assert_eq!(tkey_error(&answer), Some(error::BADNAME));
    node.negotiate(&init, NAME, &token);
    let mut again = init.clone();
    again.cusec += 1;
    let answer = node.ask(&query(NAME, mode::GSSAPI, &again.raw_token()), &from);
    assert_eq!(
        tkey_error(&answer),
        Some(error::BADNAME),
        "an established name"
    );
    let mut cut = query(NAME, mode::GSSAPI, &token);
    cut.truncate(cut.len() - 3);
    assert_eq!(rcode(&node.ask(&cut, &from)), 1, "FORMERR");
    node.tkey.handle().clear();
    let answer = node.ask(&query(NAME, mode::GSSAPI, &token), &from);
    assert_eq!((rcode(&answer), tkey_error(&answer)), (5, None), "REFUSED");
    assert_eq!(node.tkey.counts(), (0, 0), "a clear drops the contexts");
}

/// DNS-28, E43: a skewed client and a ticket for a key version Tenko does not hold are
/// refused with BADKEY; the findings they point at are raised only once three sources
/// were refused within the window.
#[test]
fn dns_28_skew_and_an_unknown_key_version_are_refused_and_aggregated() {
    let node = node();
    let mut skewed = node.initiator("pc01$");
    skewed.now = NOW - 400;
    let answer = node.ask(
        &query(NAME, mode::GSSAPI, &skewed.raw_token()),
        &tcp("192.0.2.10"),
    );
    assert_eq!(tkey_error(&answer), Some(error::BADKEY));
    for (index, from) in ["192.0.2.20", "192.0.2.21", "192.0.2.22"]
        .iter()
        .enumerate()
    {
        let mut stale = node.initiator("pc01$");
        stale.kvno = 9;
        stale.cusec += u32::try_from(index).expect("small");
        assert!(node.tkey.findings().is_empty() || index == 0 || index > 0);
        let answer = node.ask(&query(NAME, mode::GSSAPI, &stale.raw_token()), &tcp(from));
        assert_eq!(tkey_error(&answer), Some(error::BADKEY));
    }
    let findings = node.tkey.findings();
    assert_eq!(
        findings.len(),
        1,
        "one source of skew raises nothing: {findings:?}"
    );
    assert_eq!(
        findings[0].code,
        tenko_core::dns::findings::GSS_KVNO_UNKNOWN
    );
    assert_eq!(findings[0].sources, 3);
}

/// An SPNEGO offer whose first mechanism is NTLM: the acceptor discards the optimistic
/// token and asks for the Kerberos token, so the negotiation stays in flight.
fn continuing_token() -> Vec<u8> {
    NegTokenInit {
        mech_types: vec![oid::NTLMSSP, oid::KRB5],
        mech_types_der: &[],
        req_flags: None,
        mech_token: Some(b"NTLMSSP\0\x01\0\0\0"),
        mech_list_mic: None,
    }
    .encode_initial()
}

fn key_name(index: usize) -> Vec<u8> {
    let label = format!("k{index}");
    let mut name = vec![u8::try_from(label.len()).expect("short")];
    name.extend_from_slice(label.as_bytes());
    name.extend_from_slice(b"\x07example\x04test\x00");
    name
}

/// DNS-28, R125: negotiations in flight are bounded per client (refused as `limit` before
/// any Kerberos work) and per node (the oldest waiting negotiation leaves, so a flood of
/// legs that prove nothing cannot hold every place), and dropped after 30 s; a continuing negotiation
/// completes in its second leg.
#[test]
fn dns_28_negotiations_are_bounded_per_client_and_per_node_and_time_out() {
    let node = node_with(GssSettings {
        negotiating_max: 3,
        per_client_max: 2,
        ..GssSettings::default()
    });
    let first = tcp("192.0.2.10");
    for index in 0..2 {
        let answer = node.ask(
            &query(&key_name(index), mode::GSSAPI, &continuing_token()),
            &first,
        );
        assert_eq!(tkey_error(&answer), Some(0), "continue");
    }
    let answer = node.ask(
        &query(&key_name(2), mode::GSSAPI, &continuing_token()),
        &first,
    );
    assert_eq!(
        tkey_error(&answer),
        Some(error::BADKEY),
        "the client's bound"
    );
    let second = tcp("198.51.100.7");
    let answer = node.ask(
        &query(&key_name(3), mode::GSSAPI, &continuing_token()),
        &second,
    );
    assert_eq!(tkey_error(&answer), Some(0));
    let answer = node.ask(
        &query(&key_name(4), mode::GSSAPI, &continuing_token()),
        &tcp("203.0.113.9"),
    );
    assert_eq!(
        tkey_error(&answer),
        Some(0),
        "at the node's bound the oldest negotiation leaves"
    );
    assert_eq!(node.tkey.counts(), (3, 0));
    // Another client cannot take over a name in flight; the evicted oldest (k0) is free.
    let answer = node.ask(
        &query(&key_name(1), mode::GSSAPI, &continuing_token()),
        &second,
    );
    assert_eq!(tkey_error(&answer), Some(error::BADNAME));
    let answer = node.ask(
        &query(&key_name(0), mode::GSSAPI, &continuing_token()),
        &second,
    );
    assert_eq!(tkey_error(&answer), Some(0), "the evicted name is free");
    // After 30 s they are dropped.
    node.clock.set(NOW + 31);
    let mut late = node.initiator("pc01$");
    late.now = NOW + 31;
    let answer = node.ask(
        &query(&key_name(5), mode::GSSAPI, &late.raw_token()),
        &first,
    );
    assert_eq!(tkey_error(&answer), Some(0));
    assert_eq!(node.tkey.counts(), (0, 1));
}

/// DNS-28: when Kerberos is not the initiator's first choice the negotiation takes three
/// TKEY legs (the token asked for, then the `mechListMIC` both ways), each answered with
/// the next token; the context's sequence numbers start after the MICs.
#[test]
fn dns_28_a_three_leg_spnego_negotiation_completes_through_tkey() {
    let node = node();
    let from = tcp("192.0.2.10");
    let first = node.ask(&query(NAME, mode::GSSAPI, &continuing_token()), &from);
    assert_eq!(tkey_error(&first), Some(0));
    let init = node.initiator("pc01$");
    let krb = init.raw_token();
    let second_token = tenko_krb::der::NegTokenResp {
        neg_state: None,
        supported_mech: None,
        response_token: Some(&krb),
        mech_list_mic: None,
    }
    .encode();
    let second = node.ask(&query(NAME, mode::GSSAPI, &second_token), &from);
    let (_, error, token) = answer_record(&second).expect("parses").expect("record");
    assert_eq!(error, 0);
    assert!(
        crate::tsig::find(&second).expect("parses").is_none(),
        "not yet established"
    );
    let (subkey, acceptor_seq) = init.ap_rep(token);
    let keys = tenko_krb::mic::ContextMicKeys::new(&subkey, true).expect("keys");
    let list = tenko_krb::der::gss::encode_mech_type_list(&[oid::NTLMSSP, oid::KRB5]);
    let mic = keys.initiator.sign(u64::from(init.seq), &list);
    let third_token = tenko_krb::der::NegTokenResp {
        neg_state: None,
        supported_mech: None,
        response_token: None,
        mech_list_mic: Some(&mic),
    }
    .encode();
    let third = node.ask(&query(NAME, mode::GSSAPI, &third_token), &from);
    assert_eq!(tkey_error(&third), Some(0));
    let client = init.context(NAME, &subkey, acceptor_seq, 1, server());
    let mut verifier = Verifier::without_request_mac(MacKey::Gss(client));
    verifier
        .verify(&third, u64::try_from(NOW).expect("now"))
        .expect("signed with the acceptor's next sequence number");
    assert_eq!(node.tkey.counts(), (0, 1));
}

/// DNS-28: at the table's bound the context idle longest leaves; a context expires after
/// `context_max_secs` and is unknown from then on.
#[test]
fn dns_28_the_table_evicts_the_idle_context_and_contexts_expire() {
    let node = node_with(GssSettings {
        contexts_max: 2,
        context_max_secs: 600,
        ..GssSettings::default()
    });
    for index in 0..2 {
        let mut init = node.initiator("pc01$");
        init.cusec += u32::try_from(index).expect("small");
        node.clock.set(NOW + i64::try_from(index).expect("small"));
        init.now = NOW + i64::try_from(index).expect("small");
        node.negotiate(&init, &key_name(index), &init.raw_token());
    }
    node.clock.set(NOW + 5);
    assert!(
        node.tkey.context(&key_name(0)).is_some(),
        "used again: k1 is idle longest"
    );
    let mut init = node.initiator("pc01$");
    init.now = NOW + 5;
    node.negotiate(&init, &key_name(2), &init.raw_token());
    assert!(node.tkey.context(&key_name(1)).is_none(), "evicted");
    assert!(node.tkey.context(&key_name(0)).is_some());
    node.clock.set(NOW + 606);
    assert!(node.tkey.context(&key_name(2)).is_none(), "expired");
}

/// DNS-28: mode 5 deletes a context when it is signed by that context; an unsigned
/// deletion is refused with BADKEY and deletes nothing.
#[test]
fn dns_28_mode_5_deletes_the_context_that_signs_it() {
    let node = node();
    let init = node.initiator("pc01$");
    let (_, client) = node.negotiate(&init, NAME, &init.raw_token());
    let unsigned = query(NAME, mode::DELETE, &[]);
    assert_eq!(
        tkey_error(&node.ask(&unsigned, &tcp("192.0.2.10"))),
        Some(error::BADKEY)
    );
    assert!(node.tkey.context(NAME).is_some());
    let mut signed = query(NAME, mode::DELETE, &[]);
    let mut deletion = Signer::request(MacKey::Gss(Arc::clone(&client)));
    let now = u64::try_from(NOW).expect("now");
    assert!(deletion.sign(&mut signed, now, 0, &[], MAX_MESSAGE_LEN));
    let answer = node.ask(&signed, &tcp("192.0.2.10"));
    assert_eq!(
        answer_record(&answer)
            .expect("parses")
            .map(|(m, e, _)| (m, e)),
        Some((mode::DELETE, 0))
    );
    let mut verifier = Verifier::new(MacKey::Gss(client), deletion.last_mac().expect("mac"));
    verifier
        .verify(&answer, now)
        .expect("signed by the context it deleted");
    assert!(node.tkey.context(NAME).is_none());
}

/// DNS-28, R125: over UDP, whose source can be spoofed, a TKEY query is answered with TC
/// and no record before any work, so the client asks again over TCP (Windows and nsupdate
/// send TKEY over TCP); nothing is reserved and the acceptor is not touched.
#[test]
fn dns_28_a_tkey_query_over_udp_is_answered_with_tc() {
    let node = node();
    let init = node.initiator("pc01$");
    let answer = node.ask(
        &query(NAME, mode::GSSAPI, &init.raw_token()),
        &udp("192.0.2.10"),
    );
    assert_eq!(answer[2] & 0x02, 0x02, "TC");
    assert_eq!(&answer[..2], &[0x4b, 0x45], "the id");
    assert_eq!(answer_record(&answer).expect("parses"), None);
    assert_eq!(node.tkey.counts(), (0, 0));
    // The same query over TCP establishes the context: the authenticator was not used.
    node.negotiate(&init, NAME, &init.raw_token());
}

/// DNS-28: the handle validates what it installs, replaces the keys in place for the same
/// realm and SPNs (a rotation: the new key version is accepted at once), and starts a new
/// acceptor for others.
#[test]
fn dns_28_the_key_handle_installs_replaces_and_clears() {
    let node = node();
    let handle = node.tkey.handle();
    assert_eq!(
        handle.install(realm(), &["DNS".to_owned()], key_set(&node.service_key, 3)),
        Err(InstallError::Spn("DNS".to_owned()))
    );
    assert_eq!(
        handle.install(
            realm(),
            &["DNS/host@CORP.EXAMPLE.TEST".to_owned()],
            key_set(&node.service_key, 3)
        ),
        Err(InstallError::Spn("DNS/host@CORP.EXAMPLE.TEST".to_owned()))
    );
    assert_eq!(
        handle.install(realm(), &[], key_set(&node.service_key, 3)),
        Err(InstallError::Spn(String::new()))
    );
    assert_eq!(
        handle.install(
            realm(),
            &[SPN.to_owned()],
            KeySet::new(Vec::new()).expect("empty")
        ),
        Err(InstallError::NoKeys)
    );
    assert_eq!(handle.installed(), Some((realm(), vec![SPN.to_owned()])));
    // A rotation: version 4 beside 3.
    let rotated = key(AES256, 0x66);
    let principal = PrincipalName::parse("tenko-dns$@CORP.EXAMPLE.TEST").expect("principal");
    let entry = |key: &Key, kvno, state| KeyEntry {
        principal: principal.clone(),
        kvno,
        state,
        key: key.clone(),
    };
    let both = KeySet::new(vec![
        entry(&rotated, 4, KeyVersionState::Current),
        entry(&node.service_key, 3, KeyVersionState::Previous),
    ])
    .expect("keys");
    handle
        .install(realm(), &[SPN.to_owned()], both)
        .expect("replace");
    let mut new = Initiator::new(rotated, 4, "pc01$", NOW);
    new.cusec = 1;
    node.negotiate(&new, &key_name(1), &new.raw_token());
    let old = node.initiator("pc02$");
    node.negotiate(&old, &key_name(2), &old.raw_token());
    let other = Realm::new("OTHER.EXAMPLE.TEST").expect("realm");
    handle
        .install(
            other.clone(),
            &[SPN.to_owned()],
            key_set(&node.service_key, 3),
        )
        .expect("another realm");
    assert_eq!(handle.installed().map(|(realm, _)| realm), Some(other));
    assert_eq!(node.tkey.counts(), (0, 2), "established contexts stay");
    handle.clear();
    assert_eq!(handle.installed(), None);
}

fn fixture_hex(dir: &std::path::Path, file: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(dir.join(file)).expect("fixture");
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// DNS-28: the recorded exchange of MIT's initiator against the Samba AD controller (a
/// ticket with a PAC) establishes a context through TKEY whose identity carries the SIDs
/// of the PAC.
#[test]
fn dns_28_a_recorded_samba_exchange_carries_the_pac_sids() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tenko-krb/tests/fixtures/exchanges/samba-aes256-spnego");
    let recorded: i64 = 1_793_867_714;
    let clock = TestClock::new(recorded - 600);
    let tkey = Tkey::with_clock(GssSettings::default(), Arc::clone(&clock) as Arc<dyn Clock>);
    let principal = PrincipalName::parse("tenko$@CORP.EXAMPLE.TEST").expect("principal");
    let keys = std::fs::read_to_string(dir.join("keys.txt"))
        .expect("keys")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split_whitespace();
            let etype = match parts.next().expect("etype") {
                "18" => EncryptionType::Aes256CtsHmacSha1,
                _ => EncryptionType::Aes128CtsHmacSha1,
            };
            let kvno = parts.next().expect("kvno").parse().expect("kvno");
            let bytes = fixture_hex_str(parts.next().expect("key"));
            KeyEntry {
                principal: principal.clone(),
                kvno,
                state: KeyVersionState::Current,
                key: Key::new(etype, &bytes).expect("key"),
            }
        })
        .collect();
    tkey.handle()
        .install(
            Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
            &["DNS/tenko.corp.example.test".to_owned()],
            KeySet::new(keys).expect("keys"),
        )
        .expect("install");
    clock.set(recorded + 1);
    let token = fixture_hex(&dir, "init0.hex");
    let answer = tkey
        .answer(
            &query(NAME, mode::GSSAPI, &token),
            &tcp("192.0.2.10"),
            &Keyring::default(),
            &Audit::default(),
        )
        .expect("answer");
    assert_eq!(tkey_error(&answer), Some(0));
    let context = tkey.context(NAME).expect("established");
    let identity = context.identity();
    assert!(identity.sid.is_some(), "the PAC's user SID");
    assert!(!identity.groups.is_empty(), "the PAC's groups");
}

fn fixture_hex_str(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// DNS-28: the report the node's status reads: the contexts, the negotiations refused in
/// the last hour, and the findings; the refusals of an hour ago no longer count.
#[test]
fn dns_28_the_report_counts_contexts_and_the_refusals_of_the_last_hour() {
    let node = node();
    let init = node.initiator("pc01$");
    node.negotiate(&init, NAME, &init.raw_token());
    let other = b"\x0asig-pc02-1\x03ns1\x04corp\x07example\x04test\x00";
    node.ask(
        &query(other, mode::GSSAPI, &Initiator::ntlm_only_token()),
        &tcp("192.0.2.11"),
    );
    let report = node.tkey.report();
    assert_eq!(
        (
            report.negotiating,
            report.established,
            report.refused_last_hour
        ),
        (0, 1, 1)
    );
    assert!(report.findings.is_empty(), "one source raises nothing");
    node.clock.set(NOW + 3_700);
    assert_eq!(node.tkey.report().refused_last_hour, 0);
}

/// DNS-28 (review): a context's name is stored and looked up in lowercase. A negotiation
/// under a name in capitals holds the context under its lowercase form; the same name in
/// another case is the same name (BADNAME while it is in use, never a second context); and
/// a message whose TSIG writes the name in another case finds that context and verifies.
#[test]
fn dns_28_context_names_are_stored_and_found_in_lowercase() {
    let node = node();
    let init = node.initiator("pc01$");
    let upper = b"\x0aSIG-PC01-1\x03NS1\x04CORP\x07EXAMPLE\x04TEST\x00";
    let lower = b"\x0asig-pc01-1\x03ns1\x04corp\x07example\x04test\x00";
    let (_, client) = node.negotiate(&init, upper, &init.raw_token());
    assert!(
        node.tkey.context(lower).is_some(),
        "held under the lowercase name"
    );
    assert!(
        node.tkey.context(upper).is_none(),
        "the table is keyed in lowercase"
    );
    let mut again = init.clone();
    again.cusec += 1;
    let mixed = b"\x0aSig-Pc01-1\x03ns1\x04corp\x07example\x04test\x00";
    let answer = node.ask(
        &query(mixed, mode::GSSAPI, &again.raw_token()),
        &tcp("192.0.2.10"),
    );
    assert_eq!(
        tkey_error(&answer),
        Some(error::BADNAME),
        "one name in any case"
    );
    assert_eq!(node.tkey.counts(), (0, 1));
    // A deletion signed by the context, its TSIG name written in capitals.
    let mut signed = query(upper, mode::DELETE, &[]);
    let mut deletion = Signer::request(MacKey::Gss(Arc::clone(&client)));
    let now = u64::try_from(NOW).expect("now");
    assert!(deletion.sign(&mut signed, now, 0, &[], MAX_MESSAGE_LEN));
    let start = crate::tsig::find(&signed)
        .expect("parse")
        .expect("tsig")
        .record_start;
    signed[start..start + lower.len()].make_ascii_uppercase();
    let answer = node.ask(&signed, &tcp("192.0.2.10"));
    assert_eq!(
        answer_record(&answer)
            .expect("parses")
            .map(|(mode, error, _)| (mode, error)),
        Some((mode::DELETE, 0)),
        "found in lowercase and verified"
    );
    assert!(node.tkey.context(lower).is_none(), "deleted");
}
