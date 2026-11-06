#![no_main]

// TKEY and GSS-TSIG (WP13.2, R126, E51): any octets as a TKEY query over UDP and TCP, as
// a query whose TKEY answer is read back, and as a GSS-TSIG signed message verified on an
// established context. Each input gets a fresh handler with the Samba lab account's keys
// and one context negotiated from the recorded Samba exchange (a ticket with a PAC), so
// that the input reaches the context table, the deletion of mode 5 and the MIC check.
// Nothing may panic; an answer is a response with the request's id.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use libfuzzer_sys::fuzz_target;
use tenko_core::{
    audit::AuditDraft,
    dns::{EncryptionType, KeyVersionState, PrincipalName, QueryTransport, Realm},
};
use tenko_dns::{
    respond::Conn,
    tkey::{GssSettings, Tkey, UpdateKeys, wire},
    tsig::{self, GSS_TSIG, Keyring},
    xfr::TransferAudit,
};
use tenko_krb::{
    acceptor::{Clock, KrbTime},
    cipher::Key,
    keys::{KeyEntry, KeySet},
};

/// The time of the recorded Samba exchange.
const RECORDED: i64 = 1_793_867_714;

/// The Samba lab account `tenko$`, version 2 (the throwaway lab realm of the recordings).
const LAB_AES256: &str = "081de73a80dfd9f68eedd23f29f5ddceb9f37db04e07f59c2193ced324343e13";

/// The recorded initiator token (SPNEGO with the AP-REQ).
const INIT0: &str =
    include_str!("../../crates/tenko-krb/tests/fixtures/exchanges/samba-aes256-spnego/init0.hex");

/// The context negotiated before the input.
const CONTEXT: &[u8] = b"\x03ctx\x07example\x04test\x00";

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}

/// Ten minutes before the recording once (the acceptor's start), one second after it from
/// then on.
struct StartThenRecorded(AtomicBool);

impl Clock for StartThenRecorded {
    fn now(&self) -> KrbTime {
        if self.0.swap(true, Ordering::Relaxed) {
            KrbTime::from_secs(RECORDED + 1)
        } else {
            KrbTime::from_secs(RECORDED - 600)
        }
    }
}

struct NoAudit;

impl TransferAudit for NoAudit {
    fn record(&self, _: AuditDraft) {}
}

fn node() -> Arc<Tkey> {
    let tkey = Tkey::with_clock(
        GssSettings::default(),
        Arc::new(StartThenRecorded(AtomicBool::new(false))),
    );
    let principal = PrincipalName::parse("tenko$@CORP.EXAMPLE.TEST").expect("principal");
    let key = Key::new(EncryptionType::Aes256CtsHmacSha1, &unhex(LAB_AES256)).expect("key");
    let keys = KeySet::new(vec![KeyEntry {
        principal,
        kvno: 2,
        state: KeyVersionState::Current,
        key,
    }])
    .expect("keys");
    tkey.handle()
        .install(
            Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
            &["DNS/tenko.corp.example.test".to_owned()],
            keys,
        )
        .expect("install");
    tkey
}

fn conn(transport: QueryTransport) -> Conn {
    Conn {
        client: SocketAddr::from(([192, 0, 2, 10], 40_000)),
        local: SocketAddr::from(([192, 0, 2, 53], 53)),
        transport,
    }
}

fn check_answer(request: &[u8], answer: &[u8]) {
    let header = tenko_dns::wire::parse_header(answer).expect("an answer has a header");
    assert!(header.qr, "an answer is a response");
    assert_eq!(answer[..2], request[..2], "the request's id");
    let _ = wire::answer_record(answer);
}

fuzz_target!(|data: &[u8]| {
    let tkey = node();
    let hmac = Keyring::default();
    let mut negotiation = Vec::new();
    wire::write_query(&mut negotiation, 1, CONTEXT, GSS_TSIG, wire::mode::GSSAPI, &unhex(INIT0), 0);
    let established = tkey.answer(&negotiation, &conn(QueryTransport::Tcp), &hmac, &NoAudit);
    assert!(established.is_some() && tkey.context(CONTEXT).is_some(), "the recorded exchange");

    let _ = wire::is_tkey(data);
    if let Ok(query) = wire::parse(data) {
        assert!(query.key.len() <= wire::MAX_KEY_DATA);
        assert!(query.question_end <= data.len());
    }
    for transport in [QueryTransport::Udp, QueryTransport::Tcp] {
        if let Some(answer) = tkey.answer(data, &conn(transport), &hmac, &NoAudit) {
            check_answer(data, &answer);
        }
    }
    if let Ok(Some(view)) = tsig::find(data) {
        let keys = UpdateKeys {
            hmac: &hmac,
            gss: Some(&tkey),
        };
        let _ = tsig::verify_request(&keys, data, &view, 1_793_867_715);
    }
});
