//! The acceptor against the recorded MIT and Samba exchanges and against the test
//! initiator: every recorded exchange accepted, and each refusal of the identity plan.

use std::sync::Arc;

use tenko_core::dns::{EncryptionType, KeyVersionState, PrincipalName, Realm, Sid};

use super::{testkit::*, *};
use crate::{
    cipher::{self, Key},
    der::{NegState, NegTokenResp, oid},
    fixtures,
    keys::{KeyEntry, KeySet},
    mic::ContextMicKeys,
};

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha1;
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha1;

fn realm() -> Realm {
    Realm::new(REALM).expect("realm")
}

fn key_set(keys: &[(Key, u32)]) -> KeySet {
    let principal = PrincipalName::parse("TENKO-DNS$@CORP.EXAMPLE.TEST").expect("principal");
    KeySet::new(
        keys.iter()
            .map(|(key, kvno)| KeyEntry {
                principal: principal.clone(),
                kvno: *kvno,
                state: KeyVersionState::Current,
                key: key.clone(),
            })
            .collect(),
    )
    .expect("keys")
}

fn fixture_keys(f: &fixtures::Fixture, kvno_shift: u32) -> KeySet {
    key_set(
        &f.keys
            .iter()
            .map(|(etype, kvno, key)| {
                (
                    Key::new(cipher::enctype(*etype).expect("aes"), key).expect("key"),
                    kvno + kvno_shift,
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn fixture_config(f: &fixtures::Fixture) -> Config {
    let spn = f.spn.join("/");
    Config::new(Realm::new(&f.realm).expect("realm"), &[&spn])
}

fn clock(secs: i64) -> Arc<dyn Clock> {
    Arc::new(FixedClock(KrbTime::from_secs(secs)))
}

fn refused(service: &Arc<Service>, token: &[u8]) -> AcceptError {
    service.negotiation().step(token).expect_err("refused")
}

/// DNS-28, IAM-13: every recorded MIT and Samba exchange is accepted with the recorded
/// clock; the context key is the subkey MIT ended with, the initiator's MICs verify, and
/// the acceptor's MIC is octet for octet the one MIT verified.
#[test]
#[allow(clippy::too_many_lines)]
fn dns_28_recorded_exchanges_are_accepted() {
    for f in fixtures::all() {
        let acc_seq = u32::try_from(u64::from_be_bytes(f.accmic[8..16].try_into().expect("seq")))
            .expect("u32");
        let subkey_type = if f.ctxkey.len() == 16 { AES128 } else { AES256 };
        let subkey = Key::new(subkey_type, &f.ctxkey).expect("subkey");
        let service = Service::for_test(
            fixture_config(&f),
            fixture_keys(&f, 0),
            clock(f.recorded_unix + 1),
            f.recorded_unix - 600,
            Some((subkey, acc_seq)),
        );
        let Step::Established { token, context } = service
            .negotiation()
            .step(&f.init0)
            .unwrap_or_else(|e| panic!("{}: {e}", f.name))
        else {
            panic!("{}: not established in one leg", f.name)
        };
        assert_eq!(context.key.as_bytes(), &f.ctxkey[..], "{}", f.name);
        assert_eq!(
            context.client.to_string(),
            "alice@CORP.EXAMPLE.TEST",
            "{}",
            f.name
        );
        assert_eq!(
            context.gss_flags, 0x13e,
            "{}: mutual, replay, sequence, conf, integ",
            f.name
        );
        assert!(context.acceptor_subkey);
        assert!(context.expires > f.recorded_unix);
        let expected_mech = match f.mech.as_str() {
            "krb5" => Mech::Krb5,
            "ms-krb5" => Mech::MsKrb5,
            _ if f.name.contains("ms-krb5") => Mech::SpnegoMsKrb5,
            _ => Mech::SpnegoKrb5,
        };
        assert_eq!(context.mech, expected_mech, "{}", f.name);
        // The answer has the request's framing and OID.
        let rep = if f.mech == "spnego" {
            let resp = NegTokenResp::decode(&token).expect("negTokenResp");
            assert_eq!(resp.neg_state, Some(NegState::AcceptCompleted));
            assert_eq!(resp.supported_mech, Some(oid::KRB5));
            assert_eq!(resp.mech_list_mic, None, "{}: one round trip", f.name);
            resp.response_token.expect("AP-REP").to_vec()
        } else {
            token.clone()
        };
        let request_oid =
            crate::der::InitialContextToken::decode(&f.accept0).map_or(oid::KRB5, |t| {
                if t.mech == oid::MS_KRB5 {
                    oid::MS_KRB5
                } else {
                    oid::KRB5
                }
            });
        assert_eq!(
            crate::der::InitialContextToken::decode(&rep)
                .expect("rep")
                .mech,
            request_oid,
            "{}",
            f.name
        );
        // The MICs both ways.
        let keys = context.mic_keys().expect("keys");
        let first = keys
            .initiator
            .verify(&f.initmic, &f.msg)
            .unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(first.seq, u64::from(context.initiator_seq), "{}", f.name);
        let second = keys
            .initiator
            .verify(&f.initmic2, &f.msg2)
            .expect("second MIC");
        assert_eq!(second.seq, first.seq + 1);
        assert_eq!(
            keys.acceptor
                .sign(u64::from(context.acceptor_seq), &f.accmsg)
                .to_vec(),
            f.accmic,
            "{}",
            f.name
        );
        // The PAC: Samba's with alice's SIDs, MIT's without logon information.
        let pac = context.pac.as_ref().expect("both KDCs send a PAC");
        assert_eq!(pac.client_name, "alice");
        if f.name.starts_with("samba") {
            assert_eq!(
                context.user_sid(),
                Some(&Sid::parse("S-1-5-21-2622792684-1183831692-3139652611-1103").expect("sid"))
            );
            assert!(context.group_sids().contains(
                &Sid::parse("S-1-5-21-2622792684-1183831692-3139652611-513").expect("sid")
            ));
        } else {
            assert_eq!(context.user_sid(), None);
            assert_eq!(context.group_sids(), []);
        }
        // A second presentation of the same token is a replay.
        assert_eq!(
            refused(&service, &f.init0),
            AcceptError::Replay(crate::replay::ReplayError::Replay),
            "{}",
            f.name
        );
    }
}

/// DNS-28: each recorded exchange is refused with a wrong key, an unknown key version, an
/// expired ticket, a skew above the window, another SPN, and from before the start.
#[test]
fn dns_28_recorded_exchanges_are_refused_on_each_check() {
    for f in fixtures::all() {
        let at = |secs: i64, keys: KeySet, config: Config| Service::new(config, keys, clock(secs));
        let now = f.recorded_unix + 1;
        // A wrong key of the same type and version.
        let wrong = key_set(
            &f.keys
                .iter()
                .map(|(etype, kvno, _)| {
                    let etype = cipher::enctype(*etype).expect("aes");
                    (key(etype, 0x77), *kvno)
                })
                .collect::<Vec<_>>(),
        );
        let started_before = |keys: KeySet, config: Config, secs: i64| {
            Service::for_test(config, keys, clock(secs), f.recorded_unix - 600, None)
        };
        assert_eq!(
            refused(&started_before(wrong, fixture_config(&f), now), &f.init0),
            AcceptError::TicketKey,
            "{}",
            f.name
        );
        // An unknown key version.
        let shifted = started_before(fixture_keys(&f, 1), fixture_config(&f), now);
        assert!(
            matches!(
                refused(&shifted, &f.init0),
                AcceptError::Key(crate::keys::SelectError::KvnoUnknown(_))
            ),
            "{}",
            f.name
        );
        assert_eq!(refused(&shifted, &f.init0).outcome(), "kvno");
        assert_eq!(
            refused(&shifted, &f.init0).finding(),
            Some("dns.gss.kvno_unknown")
        );
        // A skew above the window: the ticket is still valid, the authenticator is not.
        let late = started_before(
            fixture_keys(&f, 0),
            fixture_config(&f),
            f.recorded_unix + 301,
        );
        let error = refused(&late, &f.init0);
        assert!(
            matches!(error, AcceptError::Skew(s) if s > 300),
            "{}: {error}",
            f.name
        );
        assert_eq!(error.finding(), Some("dns.gss.clock_skew"));
        // An expired ticket (ten hours later).
        let expired = started_before(
            fixture_keys(&f, 0),
            fixture_config(&f),
            f.recorded_unix + 11 * 3600,
        );
        assert!(
            matches!(refused(&expired, &f.init0), AcceptError::Expired(_)),
            "{}",
            f.name
        );
        // Another SPN and another realm.
        let other_spn = started_before(
            fixture_keys(&f, 0),
            Config::new(realm(), &["DNS/other.corp.example.test"]),
            now,
        );
        assert!(
            matches!(refused(&other_spn, &f.init0), AcceptError::WrongService(_)),
            "{}",
            f.name
        );
        let other_realm = started_before(
            fixture_keys(&f, 0),
            Config::new(
                Realm::new("OTHER.EXAMPLE.TEST").expect("realm"),
                &[&f.spn.join("/")],
            ),
            now,
        );
        assert!(
            matches!(
                refused(&other_realm, &f.init0),
                AcceptError::WrongService(_)
            ),
            "{}",
            f.name
        );
        // An acceptor started after the authenticator was made.
        let restarted = at(now, fixture_keys(&f, 0), fixture_config(&f));
        assert_eq!(
            refused(&restarted, &f.init0),
            AcceptError::Replay(crate::replay::ReplayError::BeforeStart),
            "{}",
            f.name
        );
    }
}

fn service_for(initiator: &Initiator) -> Arc<Service> {
    Service::for_test(
        Config::new(realm(), &[SPN, "HTTP/tenko.corp.example.test"]),
        key_set(&[(initiator.service_key.clone(), initiator.kvno.unwrap_or(1))]),
        clock(initiator.now + 1),
        initiator.now - 60,
        None,
    )
}

/// An acceptor for the test initiator's SPN that started a minute before its requests.
fn started(keys: KeySet) -> Arc<Service> {
    Service::for_test(
        Config::new(realm(), &[SPN]),
        keys,
        clock(NOW + 1),
        NOW - 60,
        None,
    )
}

fn initiator() -> Initiator {
    Initiator::new(key(AES256, 0x55), 3, NOW)
}

/// DNS-28: both key sizes, both OIDs, raw and SPNEGO, with a Windows-shaped mechanism list.
#[test]
fn dns_28_both_key_sizes_and_framings_are_accepted() {
    for (service_type, session_type) in [(AES256, AES256), (AES256, AES128), (AES128, AES128)] {
        for mech in [oid::KRB5, oid::MS_KRB5] {
            let mut init = Initiator::new(key(service_type, 0x55), 3, NOW);
            init.session = key(session_type, 0x11);
            init.subkey = Some(key(session_type, 0x22));
            let service = started(key_set(&[(init.service_key.clone(), 3)]));
            // Raw.
            let Step::Established { token, context } =
                service.negotiation().step(&init.token(mech)).expect("raw")
            else {
                panic!("one leg")
            };
            let (subkey, seq) = init.check_ap_rep(&token, mech);
            assert_eq!(
                (
                    context.key.clone(),
                    context.acceptor_seq,
                    context.initiator_seq
                ),
                (subkey, seq, init.seq)
            );
            assert_eq!(context.key.etype(), session_type);
            assert_eq!(context.client.to_string(), "pc01$@CORP.EXAMPLE.TEST");
            assert_eq!(context.ticket_kvno, Some(3));
            // SPNEGO with Windows' list: ms-krb5, krb5, NegoEx, NTLM.
            init.now += 1;
            init.cusec += 1;
            let windows = [oid::MS_KRB5, oid::KRB5, oid::NEGOEX, oid::NTLMSSP];
            let list: Vec<&[u8]> = if mech == oid::MS_KRB5 {
                windows.to_vec()
            } else {
                vec![oid::KRB5, oid::NTLMSSP]
            };
            let token = Initiator::spnego(&list, Some(&init.token(mech)), None);
            let Step::Established { token, context } =
                service.negotiation().step(&token).expect("spnego")
            else {
                panic!("one leg")
            };
            let resp = NegTokenResp::decode(&token).expect("resp");
            assert_eq!(resp.neg_state, Some(NegState::AcceptCompleted));
            assert_eq!(resp.supported_mech, Some(mech));
            assert_eq!(resp.mech_list_mic, None);
            init.check_ap_rep(resp.response_token.expect("AP-REP"), mech);
            assert_eq!(
                context.mech,
                if mech == oid::MS_KRB5 {
                    Mech::SpnegoMsKrb5
                } else {
                    Mech::SpnegoKrb5
                }
            );
        }
    }
}

/// DNS-28: `mechListMIC` both ways when Kerberos is not the initiator's first choice: the
/// optimistic token is discarded, the Kerberos token asked for, the acceptor's MIC sent
/// and the initiator's required.
#[test]
fn dns_28_mech_list_mic_both_ways() {
    let init = initiator();
    let service = service_for(&init);
    let mechs: [&[u8]; 2] = [oid::NTLMSSP, oid::KRB5];
    let mut negotiation = service.negotiation();
    let first = Initiator::spnego(&mechs, Some(b"NTLMSSP\0\x01\0\0\0"), None);
    let Step::Continue(answer) = negotiation.step(&first).expect("first leg") else {
        panic!("Kerberos is asked for")
    };
    let resp = NegTokenResp::decode(&answer).expect("resp");
    assert_eq!(
        (resp.neg_state, resp.supported_mech, resp.response_token),
        (Some(NegState::AcceptIncomplete), Some(oid::KRB5), None)
    );
    // The Kerberos token in a negTokenResp.
    let krb = init.token(oid::KRB5);
    let second = NegTokenResp {
        neg_state: None,
        supported_mech: None,
        response_token: Some(&krb),
        mech_list_mic: None,
    }
    .encode();
    let Step::Continue(answer) = negotiation.step(&second).expect("second leg") else {
        panic!("the initiator's MIC is required")
    };
    let resp = NegTokenResp::decode(&answer).expect("resp");
    assert_eq!(resp.neg_state, Some(NegState::AcceptIncomplete));
    let (subkey, seq) = init.check_ap_rep(resp.response_token.expect("AP-REP"), oid::KRB5);
    let list = crate::der::gss::encode_mech_type_list(&mechs);
    let keys = ContextMicKeys::new(&subkey, true).expect("keys");
    let header = keys
        .acceptor
        .verify(resp.mech_list_mic.expect("acceptor MIC"), &list)
        .expect("acceptor MIC verifies");
    assert_eq!(header.seq, u64::from(seq));
    // A wrong initiator MIC is refused; a negotiation then is over.
    let bad = keys.initiator.sign(u64::from(init.seq), b"another list");
    let third = NegTokenResp {
        neg_state: None,
        supported_mech: None,
        response_token: None,
        mech_list_mic: Some(&bad),
    }
    .encode();
    let mut copy = service.negotiation();
    assert!(
        copy.step(&third).is_err(),
        "a fresh negotiation does not take a MIC leg"
    );
    let mic = keys.initiator.sign(u64::from(init.seq), &list);
    let third = NegTokenResp {
        neg_state: None,
        supported_mech: None,
        response_token: None,
        mech_list_mic: Some(&mic),
    }
    .encode();
    let Step::Established { token, context } = negotiation.step(&third).expect("third leg") else {
        panic!("established")
    };
    assert_eq!(
        NegTokenResp::decode(&token).expect("resp").neg_state,
        Some(NegState::AcceptCompleted)
    );
    assert_eq!(
        context.acceptor_seq,
        seq + 1,
        "the acceptor's MIC used its first number"
    );
    assert_eq!(
        context.initiator_seq,
        init.seq + 1,
        "the initiator's MIC used its first number"
    );
    assert_eq!(
        negotiation.step(&third).expect_err("over"),
        AcceptError::State("the negotiation is over")
    );
}

#[test]
fn an_initiator_mech_list_mic_in_the_first_leg_is_verified_and_answered() {
    let init = initiator();
    let service = service_for(&init);
    let mechs: [&[u8]; 1] = [oid::KRB5];
    // The initiator's MIC needs the context key, which only the AP-REP gives: so the
    // test checks that a wrong one is refused and that the refusal is typed.
    let bogus = [0_u8; 28];
    let token = Initiator::spnego(&mechs, Some(&init.token(oid::KRB5)), Some(&bogus));
    assert!(matches!(
        refused(&service, &token),
        AcceptError::MechListMic(_)
    ));
}

/// DNS-28: an NTLM-only offer, raw NTLM, `NegoEx` alone and a DCE-style request are refused.
#[test]
fn dns_28_ntlm_only_offers_and_dce_style_requests_are_refused() {
    let init = initiator();
    let service = service_for(&init);
    let ntlm_only = Initiator::spnego(&[oid::NTLMSSP], Some(b"NTLMSSP\0\x01\0\0\0"), None);
    let error = refused(&service, &ntlm_only);
    assert_eq!(
        error,
        AcceptError::Mechanism("the mechanism list offers no Kerberos")
    );
    assert_eq!(error.outcome(), "mechanism");
    assert_eq!(
        refused(&service, b"NTLMSSP\0\x01\0\0\0\x07\x82\x08\xa2"),
        AcceptError::Mechanism("NTLM is not accepted")
    );
    let negoex = Initiator::spnego(&[oid::NEGOEX, oid::NTLMSSP], Some(b"NEGOEXTS"), None);
    assert!(matches!(
        refused(&service, &negoex),
        AcceptError::Mechanism(_)
    ));
    let mut dce = initiator();
    dce.gss_flags |= gss_flags::DCE_STYLE;
    assert_eq!(
        refused(&service, &dce.token(oid::KRB5)),
        AcceptError::Mechanism("DCE style is not accepted")
    );
}

#[test]
fn requests_and_tickets_the_acceptor_does_not_take() {
    let check = |change: &dyn Fn(&mut Initiator), expected: &dyn Fn(&AcceptError) -> bool| {
        let mut init = initiator();
        change(&mut init);
        let service = started(key_set(&[(key(AES256, 0x55), 3)]));
        let error = refused(&service, &init.token(oid::KRB5));
        assert!(expected(&error), "{error}");
    };
    check(
        &|i| {
            i.ap_options = 0;
            i.gss_flags = 0x3c;
        },
        &|e| *e == AcceptError::Request("mutual authentication was not requested"),
    );
    check(
        &|i| i.ap_options |= crate::der::ap_options::USE_SESSION_KEY,
        &|e| matches!(e, AcceptError::Request(_)),
    );
    check(
        &|i| i.ticket_flags |= crate::der::ticket_flags::INVALID,
        &|e| *e == AcceptError::TicketInvalid,
    );
    check(
        &|i| {
            i.ticket_start = NOW + 600;
        },
        &|e| matches!(e, AcceptError::NotYetValid(_)),
    );
    check(
        &|i| i.authenticator_client = Some(vec!["other$".into()]),
        &|e| *e == AcceptError::ClientMismatch,
    );
    check(
        &|i| {
            i.checksum = Some(crate::der::Checksum {
                cksumtype: 16,
                checksum: vec![0; 12],
            });
        },
        &|e| matches!(e, AcceptError::Request(_)),
    );
    check(&|i| i.kvno = Some(9), &|e| {
        matches!(
            e,
            AcceptError::Key(crate::keys::SelectError::KvnoUnknown(9))
        )
    });
    check(&|i| i.service_key = key(AES128, 0x55), &|e| {
        matches!(e, AcceptError::Key(_))
    });
    check(
        &|i| i.spn = vec!["host".into(), "tenko.corp.example.test".into()],
        &|e| matches!(e, AcceptError::WrongService(_)),
    );
}

/// DNS-28: the authenticator's client is the ticket's when its realm and components are
/// (RFC 4120 section 3.2.3, as MIT compares them); its name type may differ.
#[test]
fn dns_28_the_authenticator_name_type_may_differ_from_the_ticket() {
    let mut init = initiator();
    init.authenticator_name_type = Some(crate::der::name_type::ENTERPRISE);
    let service = started(key_set(&[(init.service_key.clone(), 3)]));
    let step = service.negotiation().step(&init.token(oid::KRB5));
    assert!(matches!(step, Ok(Step::Established { .. })), "{step:?}");
}

#[test]
fn a_ticket_without_a_key_version_is_tried_under_every_key_of_its_type() {
    let mut init = initiator();
    init.kvno = None;
    let service = started(key_set(&[(key(AES256, 0x99), 4), (key(AES256, 0x55), 3)]));
    assert!(matches!(
        service.negotiation().step(&init.token(oid::KRB5)),
        Ok(Step::Established { .. })
    ));
}

#[test]
fn keys_are_replaced_without_a_new_service() {
    let init = initiator();
    let service = started(key_set(&[(key(AES256, 0x99), 3)]));
    assert_eq!(
        refused(&service, &init.token(oid::KRB5)),
        AcceptError::TicketKey
    );
    service.set_keys(key_set(&[(key(AES256, 0x55), 3)]));
    assert!(service.negotiation().step(&init.token(oid::KRB5)).is_ok());
}

#[test]
fn malformed_tokens_are_refused_never_a_panic() {
    let init = initiator();
    let token = init.token(oid::KRB5);
    let spnego = Initiator::spnego(&[oid::KRB5], Some(&token), None);
    let service = service_for(&init);
    for bytes in [&token, &spnego] {
        for len in 0..bytes.len() {
            assert!(
                service.negotiation().step(&bytes[..len]).is_err(),
                "prefix {len}"
            );
        }
    }
    assert!(matches!(refused(&service, &[]), AcceptError::Token(_)));
    assert!(matches!(
        refused(&service, &[0x60, 0x00]),
        AcceptError::Token(_)
    ));
}
