//! Entry points of the fuzz targets under `fuzz/` (R126, E51). Each takes arbitrary
//! octets, must never panic on them, and asserts the invariants of what it decodes.
//! Not an API: the targets and the crate's tests call these.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tenko_core::dns::{EncryptionType, KeyVersionState, PrincipalName, Realm};

use crate::{
    acceptor::{Acceptor, Clock, Config, KrbTime, Service, Step},
    cipher::{self, Key, usage},
    der::{self, gss},
    keys::{KeyEntry, KeySet},
    keytab,
    mic::ContextMicKeys,
    pac,
};

/// The time of the recorded Samba exchanges.
const RECORDED: i64 = 1_793_867_714;

/// The keys of the Samba lab account `tenko$` (version 2), so that seeds cut from the
/// recorded exchanges decrypt and reach the checks behind the ciphers.
const LAB_AES256: &str = "081de73a80dfd9f68eedd23f29f5ddceb9f37db04e07f59c2193ced324343e13";
const LAB_AES128: &str = "57b17c9f30c101114dafb549450d34d5";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
        .collect()
}

/// A clock that says ten minutes before the recorded time once (the acceptor's start) and
/// one second after it from then on.
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

fn lab_key(etype: EncryptionType) -> Key {
    let hex = match etype {
        EncryptionType::Aes128CtsHmacSha1 => LAB_AES128,
        EncryptionType::Aes256CtsHmacSha1 => LAB_AES256,
    };
    Key::new(etype, &unhex(hex)).expect("a lab key")
}

fn lab_service() -> Arc<Service> {
    let principal = PrincipalName::parse("tenko$@CORP.EXAMPLE.TEST").expect("principal");
    let keys = KeySet::new(
        [
            EncryptionType::Aes256CtsHmacSha1,
            EncryptionType::Aes128CtsHmacSha1,
        ]
        .into_iter()
        .map(|etype| KeyEntry {
            principal: principal.clone(),
            kvno: 2,
            state: KeyVersionState::Current,
            key: lab_key(etype),
        })
        .collect(),
    )
    .expect("keys");
    let realm = Realm::new("CORP.EXAMPLE.TEST").expect("realm");
    Service::new(
        Config::new(realm, &["DNS/tenko.corp.example.test"]),
        keys,
        Arc::new(StartThenRecorded(AtomicBool::new(false))),
    )
}

/// Runs a negotiation over the tokens of `data` (separated by the first `0xff 0xfe` pair, so
/// that the later legs are reached) and checks what an established context holds.
fn negotiate(service: &Arc<Service>, tokens: &[&[u8]]) {
    let mut negotiation = service.negotiation();
    for token in tokens {
        match negotiation.step(token) {
            Ok(Step::Continue(answer)) => {
                assert!(
                    der::NegTokenResp::decode(&answer).is_ok(),
                    "a Continue answer is a negTokenResp"
                );
            }
            Ok(Step::Established { context, .. }) => {
                assert_eq!(
                    context.key.as_bytes().len(),
                    cipher::key_len(context.key.etype())
                );
                assert!(context.acceptor_subkey);
                assert!(context.acceptor_seq <= 1 << 30);
                return;
            }
            Err(error) => {
                let _ = (error.outcome(), error.finding(), error.to_string());
                return;
            }
        }
    }
}

/// `krb_der`: the first octet chooses the structure, the rest is decoded as it. A value
/// that decodes encodes to octets that decode to the same value.
pub fn der(data: &[u8]) {
    let Some((&choice, bytes)) = data.split_first() else {
        return;
    };
    macro_rules! round_trip {
        ($decode:expr, $encode:expr) => {
            if let Ok(value) = $decode(bytes) {
                let encoded = $encode(&value);
                let again = $decode(&encoded).expect("an encoded value decodes");
                assert_eq!(again, value, "decode(encode(x)) == x");
            }
        };
    }
    match choice % 16 {
        0 => round_trip!(der::ApReq::decode, der::ApReq::encode),
        1 => round_trip!(der::ApRep::decode, der::ApRep::encode),
        2 => round_trip!(der::Ticket::decode, der::Ticket::encode),
        3 => round_trip!(der::EncTicketPart::decode, |v: &der::EncTicketPart| v
            .encode()
            .to_vec()),
        4 => round_trip!(der::Authenticator::decode, |v: &der::Authenticator| v
            .encode()
            .to_vec()),
        5 => round_trip!(der::EncApRepPart::decode, |v: &der::EncApRepPart| v
            .encode()
            .to_vec()),
        6 => round_trip!(der::KdcReq::decode, der::KdcReq::encode),
        7 => round_trip!(der::KdcRep::decode, der::KdcRep::encode),
        8 => round_trip!(der::EncKdcRepPart::decode, |v: &der::EncKdcRepPart| v
            .encode()
            .to_vec()),
        9 => round_trip!(der::KrbError::decode, der::KrbError::encode),
        10 => round_trip!(der::KrbPriv::decode, der::KrbPriv::encode),
        11 => round_trip!(der::EncKrbPrivPart::decode, |v: &der::EncKrbPrivPart| v
            .encode()
            .to_vec()),
        12 => {
            round_trip!(der::decode_etype_info2, |v: &Vec<der::EtypeInfo2Entry>| {
                der::encode_etype_info2(v)
            });
            let _ = der::decode_method_data(bytes);
            round_trip!(der::PaEncTsEnc::decode, der::PaEncTsEnc::encode);
        }
        13 => {
            round_trip!(
                der::ChangePasswdData::decode,
                |v: &der::ChangePasswdData| v.encode().to_vec()
            );
            round_trip!(
                der::AuthorizationData::decode,
                der::AuthorizationData::encode
            );
            round_trip!(der::EncryptedData::decode, der::EncryptedData::encode);
        }
        14 => {
            if let Ok(token) = gss::InitialContextToken::decode(bytes) {
                let encoded = gss::InitialContextToken::encode(token.mech, token.inner);
                assert_eq!(encoded, bytes, "the framing is canonical");
                let _ = gss::KrbToken::decode(token.inner);
            }
            if let Ok(init) = gss::NegTokenInit::decode_initial(bytes) {
                let encoded = init.encode_initial();
                let again = gss::NegTokenInit::decode_initial(&encoded).expect("re-decodes");
                assert_eq!(again.mech_types, init.mech_types);
                assert_eq!(again.mech_token, init.mech_token);
                assert_eq!(again.mech_list_mic, init.mech_list_mic);
                assert_eq!(
                    gss::encode_mech_type_list(&init.mech_types),
                    init.mech_types_der
                );
            }
        }
        _ => {
            if let Ok(resp) = gss::NegTokenResp::decode(bytes) {
                let encoded = resp.encode();
                let again = gss::NegTokenResp::decode(&encoded).expect("re-decodes");
                assert_eq!(again, resp);
            }
        }
    }
}

/// `krb_keytab`: a keytab file. What is kept is AES with keys of the right length, every
/// refused entry has another type or a wrong length, and the counts stay bounded.
pub fn keytab(data: &[u8]) {
    if let Ok(parsed) = keytab::parse(data) {
        assert!(parsed.entries.len() + parsed.refused.len() <= keytab::MAX_KEYTAB_RECORDS);
        for entry in &parsed.entries {
            assert_eq!(
                entry.key.as_bytes().len(),
                cipher::key_len(entry.key.etype())
            );
            assert_ne!(entry.principal.components().len(), 0);
        }
        for refused in &parsed.refused {
            match refused.reason {
                cipher::CipherError::UnsupportedEnctype(n) => assert_eq!(n, refused.enctype),
                cipher::CipherError::KeyLength(_) => assert!(matches!(refused.enctype, 17 | 18)),
                other => panic!("unexpected refusal {other:?}"),
            }
        }
        let _ = parsed.key_set(|_| true, tenko_core::dns::KeyVersionState::Current);
    }
}

/// `krb_spnego`: tokens of a negotiation through the acceptor; the legs are separated by
/// `0xff 0xfe`. The acceptor holds the Samba lab key and the recorded time.
pub fn spnego(data: &[u8]) {
    let tokens: Vec<&[u8]> = split_legs(data);
    negotiate(&lab_service(), &tokens);
    for token in &tokens {
        let _ = der::NegotiationToken::decode(token);
    }
}

fn split_legs(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while out.len() < 3 {
        match rest.windows(2).position(|w| w == [0xff, 0xfe]) {
            Some(at) => {
                out.push(&rest[..at]);
                rest = &rest[at + 2..];
            }
            None => break,
        }
    }
    out.push(rest);
    out
}

/// `krb_ap_req`: the first octet chooses the mode. Mode 0: the rest is an AP-REQ, wrapped
/// as a raw Kerberos token. Mode 1: the rest is the plaintext of a ticket and of an
/// authenticator (split at the offset of the next two octets), encrypted under the lab key
/// and the ticket's session key (or a fixed one), so that the checks after the ciphers
/// are fuzzed directly.
pub fn ap_req(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let service = lab_service();
    if mode % 2 == 0 {
        negotiate(
            &service,
            &[&gss::KrbToken::encode(
                gss::oid::KRB5,
                gss::tok_id::AP_REQ,
                rest,
            )],
        );
        return;
    }
    let Some((split, rest)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let at = usize::from(u16::from_be_bytes(*split)).min(rest.len());
    let (ticket_plain, auth_plain) = rest.split_at(at);
    let service_key = lab_key(EncryptionType::Aes256CtsHmacSha1);
    let session = der::EncTicketPart::decode(ticket_plain)
        .ok()
        .and_then(|part| Key::from_wire(&part.key).ok())
        .unwrap_or_else(|| lab_key(EncryptionType::Aes128CtsHmacSha1));
    let (Ok(mut ticket_enc), Ok(authenticator)) = (
        cipher::encrypt_data(&service_key, usage::TICKET, ticket_plain),
        cipher::encrypt_data(&session, usage::AP_REQ_AUTHENTICATOR, auth_plain),
    ) else {
        return;
    };
    ticket_enc.kvno = Some(2);
    let request = der::ApReq {
        ap_options: der::ap_options::MUTUAL_REQUIRED,
        ticket: der::Ticket {
            realm: "CORP.EXAMPLE.TEST".into(),
            sname: der::PrincipalName::new(
                der::name_type::SRV_INST,
                &["DNS", "tenko.corp.example.test"],
            ),
            enc_part: ticket_enc,
        },
        authenticator,
    };
    let token = gss::KrbToken::encode(gss::oid::KRB5, gss::tok_id::AP_REQ, &request.encode());
    negotiate(&service, &[&token]);
}

/// `krb_pac`: a PAC. Read without the signature, and verified with the lab key; a PAC that
/// verifies has its groups once each.
pub fn pac(data: &[u8]) {
    if let Ok(Some(logon)) = pac::read_unverified(data) {
        let groups = logon.groups();
        for (index, sid) in groups.iter().enumerate() {
            assert!(!groups[..index].contains(sid), "each group once");
        }
    }
    for etype in [
        EncryptionType::Aes256CtsHmacSha1,
        EncryptionType::Aes128CtsHmacSha1,
    ] {
        let _ = pac::verify(data, &lab_key(etype), "alice", RECORDED);
    }
}

/// `gss_mic`: the first 28 octets are a MIC token over the rest, verified both ways under a
/// fixed context key; then a token signed over the rest verifies, with its sequence
/// number, and fails with any octet changed.
pub fn mic(data: &[u8]) {
    let key = lab_key(EncryptionType::Aes256CtsHmacSha1);
    let Ok(keys) = ContextMicKeys::new(&key, true) else {
        return;
    };
    let (token, message) = data.split_at(data.len().min(crate::mic::TOKEN_LEN));
    let _ = keys.initiator.verify(token, message);
    let _ = keys.acceptor.verify(token, message);
    let seq = token
        .iter()
        .fold(0_u64, |acc, b| acc.rotate_left(8) ^ u64::from(*b));
    let signed = keys.acceptor.sign(seq, message);
    let header = keys
        .acceptor
        .verify(&signed, message)
        .expect("a signed token verifies");
    assert_eq!(header.seq, seq);
    assert!(
        keys.initiator.verify(&signed, message).is_err(),
        "the other direction refuses it"
    );
    let mut changed = signed;
    let index = usize::try_from(seq % 28).unwrap_or(0);
    changed[index] ^= 0x01;
    assert!(
        keys.acceptor.verify(&changed, message).is_err(),
        "a changed token is refused"
    );
}

#[cfg(test)]
mod tests {
    use crate::{acceptor::Acceptor, cipher, der, fixtures};

    /// The fuzz entry points over the recorded tokens and their prefixes.
    #[test]
    fn fuzz_entry_points_take_the_seeds_and_their_prefixes() {
        for f in fixtures::all() {
            for choice in 0..16_u8 {
                for input in [&f.init0[..], &f.accept0[..]] {
                    for len in [0, 1, 7, input.len() / 2, input.len()] {
                        let mut data = vec![choice];
                        data.extend_from_slice(&input[..len.min(input.len())]);
                        super::der(&data);
                    }
                }
            }
        }
        for name in [
            "user-alice",
            "computer-tenko-dns",
            "mixed-enctypes",
            "kvno-300",
        ] {
            let bytes = fixtures::file(&format!("keytabs/{name}.keytab"));
            for len in 0..=bytes.len() {
                super::keytab(&bytes[..len]);
            }
        }
    }

    /// The acceptor targets reach an established context with a recorded Samba token, so
    /// their seeds get past the ciphers.
    #[test]
    fn the_lab_service_accepts_the_recorded_samba_tokens() {
        for f in fixtures::all()
            .iter()
            .filter(|f| f.name.starts_with("samba-aes256"))
        {
            let step = super::lab_service().negotiation().step(&f.init0);
            assert!(
                matches!(step, Ok(super::Step::Established { .. })),
                "{}: {step:?}",
                f.name
            );
        }
    }

    /// Writes the seeds of the Kerberos fuzz targets from the recorded exchanges:
    /// `TENKO_WRITE_SEEDS=1 cargo test -p tenko-krb write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes fuzz/seeds; run by hand when the fixtures change"]
    fn write_fuzz_seeds() {
        use std::{fs, path::PathBuf};
        assert!(
            std::env::var_os("TENKO_WRITE_SEEDS").is_some(),
            "set TENKO_WRITE_SEEDS"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
        let write = |target: &str, name: &str, bytes: &[u8]| {
            let dir = root.join(target);
            fs::create_dir_all(&dir).expect("seed directory");
            fs::write(dir.join(name), bytes).expect("seed");
        };
        for f in fixtures::all() {
            write("krb_spnego", &f.name, &f.init0);
            let (_, part, pac) = crate::pac::tests::ticket_pac(&f);
            write("krb_pac", &f.name, &pac);
            let mut mic = f.initmic.clone();
            mic.extend_from_slice(&f.msg);
            write("gss_mic", &format!("{}-initiator", f.name), &mic);
            let mut mic = f.accmic.clone();
            mic.extend_from_slice(&f.accmsg);
            write("gss_mic", &format!("{}-acceptor", f.name), &mic);
            // The AP-REQ, and the plaintexts of its ticket and authenticator.
            let outer = der::InitialContextToken::decode(&f.init0).expect("token");
            let mech_token = if outer.mech == der::oid::SPNEGO {
                der::NegTokenInit::decode_initial(&f.init0)
                    .expect("init")
                    .mech_token
                    .expect("t")
                    .to_vec()
            } else {
                f.init0.clone()
            };
            let inner = der::InitialContextToken::decode(&mech_token).expect("inner");
            let message = der::KrbToken::decode(inner.inner)
                .expect("krb")
                .message
                .to_vec();
            write(
                "krb_ap_req",
                &format!("{}-raw", f.name),
                &[&[0][..], &message].concat(),
            );
            let request = der::ApReq::decode(&message).expect("AP-REQ");
            let session = cipher::Key::from_wire(&part.key).expect("session");
            let auth = cipher::decrypt_data(
                &session,
                cipher::usage::AP_REQ_AUTHENTICATOR,
                &request.authenticator,
            )
            .expect("authenticator");
            let ticket = part.encode();
            let split = u16::try_from(ticket.len()).expect("small").to_be_bytes();
            write(
                "krb_ap_req",
                &format!("{}-plain", f.name),
                &[&[1][..], &split, &ticket, &auth].concat(),
            );
            // A two-leg SPNEGO negotiation: NTLM first, then the Kerberos token.
            if f.mech == "spnego" {
                let mechs: [&[u8]; 2] = [der::oid::NTLMSSP, der::oid::KRB5];
                let first = crate::acceptor::testkit::Initiator::spnego(
                    &mechs,
                    Some(b"NTLMSSP\0\x01\0\0\0"),
                    None,
                );
                let second = der::NegTokenResp {
                    neg_state: None,
                    supported_mech: None,
                    response_token: Some(&mech_token),
                    mech_list_mic: None,
                }
                .encode();
                write(
                    "krb_spnego",
                    &format!("{}-two-legs", f.name),
                    &[&first[..], &[0xff, 0xfe], &second].concat(),
                );
            }
        }
    }

    /// A deterministic mutation pass over the seeds of every target (flipped, inserted,
    /// removed and truncated octets), so that a panic shows in every test run and not only
    /// in the weekly fuzz smoke.
    #[test]
    fn mutated_seeds_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut seeds: Vec<Vec<u8>> = Vec::new();
        for f in fixtures::all() {
            seeds.extend([f.init0.clone(), f.accept0.clone()]);
            seeds.push([f.initmic.clone(), f.msg.clone()].concat());
            let (_, _, pac) = crate::pac::tests::ticket_pac(&f);
            seeds.push(pac);
        }
        for name in [
            "user-alice",
            "computer-tenko-dns",
            "mixed-enctypes",
            "kvno-300",
        ] {
            seeds.push(fixtures::file(&format!("keytabs/{name}.keytab")));
        }
        let targets: [fn(&[u8]); 6] = [
            super::der,
            super::keytab,
            super::spnego,
            super::ap_req,
            super::pac,
            super::mic,
        ];
        for round in 0..300 {
            for seed in &seeds {
                let mut data = seed.clone();
                for _ in 0..=(next() % 4) {
                    if data.is_empty() {
                        break;
                    }
                    let at = usize::try_from(next() % u64::try_from(data.len()).expect("len"))
                        .expect("index");
                    match next() % 4 {
                        0 => data[at] ^= 1 << (next() % 8),
                        1 => data.insert(at, u8::try_from(next() % 256).expect("octet")),
                        2 => {
                            data.remove(at);
                        }
                        _ => data.truncate(at),
                    }
                }
                let target = targets[round % targets.len()];
                let choice = u8::try_from(next() % 256).expect("octet");
                target(&[&[choice][..], &data].concat());
                target(&data);
            }
        }
    }
}
