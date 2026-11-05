//! The spike's tests: both acceptors against the in-code initiator, each observation of
//! `sspi`'s behavior named as RESULT.md names it.

use crate::acceptor::{Acceptor, Context, Enctype, Mech, Step};
use crate::mic::ContextMicKeys;
use crate::own::{Config, OwnAcceptor, ReplayCache};
use crate::testkit::{Initiator, REALM, SPN, service_key};

const NOW: i64 = 1_762_300_000;

fn own_config(enctype: Enctype) -> Config {
    let mut cfg = Config::new(
        &SPN,
        REALM,
        vec![
            service_key(Enctype::Aes256, 2),
            service_key(Enctype::Aes128, 2),
        ],
    );
    cfg.clock = Some(Box::new(|| NOW));
    let _ = enctype;
    cfg
}

fn established(step: Step) -> (Vec<u8>, Context) {
    match step {
        Step::Established { token, context } => (token, context),
        Step::Continue(_) => panic!("expected an established context"),
    }
}

/// Runs the per-message check both ways: the initiator signs with picky-krb, the acceptor
/// verifies with mic.rs, and the other way round.
fn mic_both_ways(
    init: &Initiator,
    ctx: &Context,
    acceptor_subkey: Option<&[u8]>,
    acceptor_seq: u32,
) {
    let key = init.context_key(acceptor_subkey);
    assert_eq!(
        key, ctx.key,
        "the acceptor and the initiator disagree on the context key"
    );
    let keys = ContextMicKeys::new(&ctx.key, ctx.key_enctype);
    let data = b"TSIG digest data";
    let from_init = init.mic(
        &key,
        acceptor_subkey.is_some(),
        false,
        u64::from(init.seq),
        data,
    );
    let h = keys
        .initiator
        .verify(&from_init, data)
        .expect("the initiator's MIC verifies");
    assert_eq!(h.seq, u64::from(init.seq));
    let ours = keys.acceptor.sign(
        keys.acceptor.sender_flags(ctx.acceptor_subkey),
        u64::from(acceptor_seq),
        data,
    );
    let theirs = init.mic(
        &key,
        acceptor_subkey.is_some(),
        true,
        u64::from(acceptor_seq),
        data,
    );
    assert_eq!(
        ours.to_vec(),
        theirs,
        "the acceptor's MIC is what MIT would compute"
    );
}

fn own_roundtrip(ticket_enctype: Enctype, session_enctype: Enctype, mech: Mech) {
    let init = Initiator::new(service_key(ticket_enctype, 2), session_enctype, NOW);
    let cfg = own_config(ticket_enctype);
    let mut replay = ReplayCache::new();
    let mut acc = OwnAcceptor::new(&cfg, &mut replay);
    let (token, ctx) = match mech {
        Mech::Krb5 | Mech::MsKrb5 => {
            established(acc.step(&init.ap_req_token(mech)).expect("accepted"))
        }
        Mech::SpnegoKrb5 | Mech::SpnegoMsKrb5 => {
            let list = if mech == Mech::SpnegoMsKrb5 {
                Initiator::windows_mechs()
            } else {
                Initiator::mit_mechs()
            };
            let (resp, ctx) = established(acc.step(&init.spnego_token(&list)).expect("accepted"));
            let resp = init.check_spnego_resp(&resp).expect("negTokenResp");
            assert!(
                resp.complete,
                "one round trip when the first mechanism is chosen"
            );
            assert_eq!(resp.supported_mech, Some(list[0].clone()));
            assert!(
                resp.mech_list_mic.is_none(),
                "no mechListMIC when the first mechanism is chosen"
            );
            (resp.response_token.expect("AP-REP inside"), ctx)
        }
    };
    let inner = match mech {
        Mech::SpnegoKrb5 => Mech::Krb5,
        Mech::SpnegoMsKrb5 => Mech::MsKrb5,
        m => m,
    };
    let (subkey, seq) = init
        .check_ap_rep(&token, inner)
        .expect("AP-REP accepted by the initiator");
    assert_eq!(ctx.client, "pc01$");
    assert_eq!(ctx.realm, REALM);
    assert_eq!(ctx.mech, mech);
    assert_eq!(ctx.initiator_seq, Some(init.seq));
    assert_eq!(ctx.acceptor_seq, seq);
    assert_eq!(ctx.gss_flags, Some(0x3e));
    assert_eq!(ctx.expires_unix, Some(init.ticket_end));
    assert_eq!(ctx.key_enctype, session_enctype);
    assert!(ctx.acceptor_subkey && subkey.is_some());
    mic_both_ways(&init, &ctx, subkey.as_deref(), seq);
}

#[test]
fn own_accepts_every_framing_and_key_size() {
    for ticket in [Enctype::Aes256, Enctype::Aes128] {
        for session in [Enctype::Aes256, Enctype::Aes128] {
            for mech in [
                Mech::Krb5,
                Mech::MsKrb5,
                Mech::SpnegoKrb5,
                Mech::SpnegoMsKrb5,
            ] {
                own_roundtrip(ticket, session, mech);
            }
        }
    }
}

#[test]
fn own_without_acceptor_subkey_uses_the_initiator_subkey() {
    let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    let mut cfg = own_config(Enctype::Aes256);
    cfg.acceptor_subkey = false;
    let mut replay = ReplayCache::new();
    let mut acc = OwnAcceptor::new(&cfg, &mut replay);
    let (token, ctx) = established(acc.step(&init.ap_req_token(Mech::Krb5)).expect("accepted"));
    let (subkey, seq) = init.check_ap_rep(&token, Mech::Krb5).expect("AP-REP");
    assert!(subkey.is_none() && !ctx.acceptor_subkey);
    assert_eq!(ctx.key, init.subkey.clone().unwrap());
    mic_both_ways(&init, &ctx, None, seq);
}

#[test]
fn own_refuses_what_it_must() {
    let cfg = own_config(Enctype::Aes256);
    let refuse = |init: &Initiator, mech: Mech, why: &str| {
        let mut replay = ReplayCache::new();
        let mut acc = OwnAcceptor::new(&cfg, &mut replay);
        let err = acc
            .step(&init.ap_req_token(mech))
            .err()
            .unwrap_or_else(|| panic!("accepted: {why}"));
        assert!(err.0.contains(why), "{why}: {err}");
    };
    let base = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    // Wrong service key.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.service_key.key[0] ^= 1;
    refuse(&i, Mech::Krb5, "does not decrypt");
    // Unknown kvno.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 7), Enctype::Aes256, NOW);
    i.service_key.kvno = Some(7);
    refuse(&i, Mech::Krb5, "no key for enctype 18 kvno Some(7)");
    // Expired ticket.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.ticket_end = NOW - 400;
    refuse(&i, Mech::Krb5, "expired");
    // Clock skew on the authenticator.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.now = NOW - 301;
    refuse(&i, Mech::Krb5, "clock skew");
    // Another service.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.spn = vec!["HTTP".into(), "tenko.corp.example.test".into()];
    refuse(&i, Mech::Krb5, "not for");
    // Another realm.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.realm = "OTHER.EXAMPLE.TEST".into();
    refuse(&i, Mech::Krb5, "realm");
    // INVALID flag.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.ticket_flags |= 0x0100_0000;
    refuse(&i, Mech::Krb5, "INVALID");
    // DCE style.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.gss_flags |= 0x1000;
    refuse(&i, Mech::Krb5, "DCE");
    // No mutual authentication.
    let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    i.ap_options = 0;
    i.gss_flags &= !0x02;
    refuse(&i, Mech::Krb5, "mutual");
    // Replay: the same token twice through one cache.
    let mut replay = ReplayCache::new();
    let token = base.ap_req_token(Mech::Krb5);
    OwnAcceptor::new(&cfg, &mut replay)
        .step(&token)
        .expect("first");
    let err = OwnAcceptor::new(&cfg, &mut replay)
        .step(&token)
        .expect_err("replay refused");
    assert!(err.0.contains("replayed"), "{err}");
    // A mechanism list without Kerberos.
    let ntlm_only =
        crate::own::spnego::encode_init(&[picky_asn1_x509::oids::ntlm_ssp()], b"NTLMSSP");
    let err = OwnAcceptor::new(&cfg, &mut replay)
        .step(&ntlm_only)
        .expect_err("NTLM refused");
    assert!(err.0.contains("no Kerberos"), "{err}");
}

#[test]
fn own_mech_list_mic_when_kerberos_is_not_the_first_choice() {
    // NTLM first, Kerberos second: RFC 4178 requires the MIC exchange.
    let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, NOW);
    let cfg = own_config(Enctype::Aes256);
    let mut replay = ReplayCache::new();
    let mut acc = OwnAcceptor::new(&cfg, &mut replay);
    let list = vec![
        picky_asn1_x509::oids::ntlm_ssp(),
        picky_asn1_x509::oids::krb5(),
    ];
    // The optimistic token is the AP-REQ although NTLM is listed first (an initiator that
    // lists NTLM first would send an NTLM token; the spike only exercises the MIC leg).
    let token = crate::own::spnego::encode_init(&list, &init.ap_req_token(Mech::Krb5));
    let Step::Continue(resp) = acc.step(&token).expect("accepted") else {
        panic!("expected a MIC leg")
    };
    let resp = init.check_spnego_resp(&resp).expect("negTokenResp");
    assert!(!resp.complete);
    assert_eq!(resp.supported_mech, Some(picky_asn1_x509::oids::krb5()));
    let (subkey, seq) = init
        .check_ap_rep(resp.response_token.as_deref().expect("AP-REP"), Mech::Krb5)
        .expect("AP-REP");
    let key = init.context_key(subkey.as_deref());
    let mech_types_der = picky_asn1_der::to_vec(&picky_krb::gss_api::MechTypeList::from(
        list.iter()
            .cloned()
            .map(picky_asn1::wrapper::ObjectIdentifierAsn1::from)
            .collect::<Vec<_>>(),
    ))
    .unwrap();
    // The acceptor's mechListMIC carries its first sequence number.
    let expected = init.mic(&key, true, true, u64::from(seq), &mech_types_der);
    assert_eq!(resp.mech_list_mic.as_deref(), Some(expected.as_slice()));
    // The initiator's mechListMIC comes back in a negTokenResp.
    let my_mic = init.mic(&key, true, false, u64::from(init.seq), &mech_types_der);
    let leg = crate::own::spnego::encode_resp(true, None, None, Some(&my_mic)).unwrap();
    let (fin, ctx) = established(acc.step(&leg).expect("MIC accepted"));
    assert!(init.check_spnego_resp(&fin).unwrap().complete);
    // The next acceptor MIC uses seq + 1.
    assert_eq!(ctx.acceptor_seq, seq + 1);
}

#[cfg(feature = "sspi")]
mod sspi_observations {
    use std::time::Duration;

    use super::*;
    use crate::sspi_acceptor::SspiAcceptor;

    fn acceptor(enctype: Enctype) -> SspiAcceptor {
        SspiAcceptor::new(&SPN, &service_key(enctype, 2), Duration::from_secs(300))
            .expect("acceptor")
    }

    fn fresh() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    #[test]
    fn sspi_accepts_raw_krb5_with_aes256_and_the_mic_keys_agree() {
        let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, fresh());
        let mut acc = acceptor(Enctype::Aes256);
        let (token, ctx) = established(acc.step(&init.ap_req_token(Mech::Krb5)).expect("accepted"));
        let (subkey, seq) = init.check_ap_rep(&token, Mech::Krb5).expect("AP-REP");
        assert_eq!(ctx.client, "pc01$");
        // Observation S1: the realm comes back lowercased (sspi builds a UPN from it).
        assert_eq!(ctx.realm, REALM.to_ascii_lowercase());
        assert_eq!(
            ctx.acceptor_seq, seq,
            "next_seq_number() returns the AP-REP's sequence number"
        );
        assert!(
            subkey.is_some(),
            "sspi always sends an acceptor subkey under mutual authentication"
        );
        // Observation S2: the initiator's sequence number and the GSS flags are not exposed.
        assert_eq!(ctx.initiator_seq, None);
        assert_eq!(ctx.gss_flags, None);
        mic_both_ways(&init, &ctx, subkey.as_deref(), seq);
    }

    #[test]
    fn sspi_spnego_with_the_windows_list_answers_under_the_wrong_inner_oid() {
        let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, fresh());
        let mut acc = acceptor(Enctype::Aes256);
        let (resp, _ctx) = established(
            acc.step(&init.spnego_token(&Initiator::windows_mechs()))
                .expect("accepted"),
        );
        let resp = init.check_spnego_resp(&resp).expect("negTokenResp");
        assert!(resp.complete);
        assert_eq!(
            resp.supported_mech,
            Some(picky_asn1_x509::oids::ms_krb5()),
            "MS KRB5 is negotiated"
        );
        // Observation S3: the AP-REP inside is wrapped under 1.2.840.113554.1.2.2 although the
        // negotiated mechanism is 1.2.840.48018.1.2.2; MIT refuses that for a raw ms-krb5
        // context (interop run), whether Windows does is the open item of the Windows lab.
        let err = init
            .check_ap_rep(resp.response_token.as_deref().unwrap(), Mech::MsKrb5)
            .expect_err("the inner OID differs");
        assert!(err.contains("1.2.840.113554.1.2.2"), "{err}");
        init.check_ap_rep(resp.response_token.as_deref().unwrap(), Mech::Krb5)
            .expect("the AP-REP itself is correct");
    }

    #[test]
    fn sspi_spnego_with_the_mit_list() {
        let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, fresh());
        let mut acc = acceptor(Enctype::Aes256);
        let (resp, ctx) = established(
            acc.step(&init.spnego_token(&Initiator::mit_mechs()))
                .expect("accepted"),
        );
        let resp = init.check_spnego_resp(&resp).expect("negTokenResp");
        assert!(resp.complete && resp.mech_list_mic.is_none());
        let (subkey, _seq) = init
            .check_ap_rep(resp.response_token.as_deref().unwrap(), Mech::Krb5)
            .unwrap();
        // Observation S4: behind Negotiate the acceptor's sequence number is unreachable.
        assert_eq!(ctx.acceptor_seq, 0);
        assert_eq!(init.context_key(subkey.as_deref()), ctx.key);
    }

    #[test]
    fn sspi_refuses_an_aes128_session_key() {
        // Observation S5: the AP-REP is built with the default AES-256 cipher whatever the
        // ticket says, so an AES-128 session key fails with "invalid key length".
        let init = Initiator::new(service_key(Enctype::Aes128, 2), Enctype::Aes128, fresh());
        let mut acc = acceptor(Enctype::Aes128);
        let err = acc
            .step(&init.ap_req_token(Mech::Krb5))
            .expect_err("refused");
        assert!(err.0.contains("invalid key length"), "{err}");
        // An AES-128 ticket with an AES-256 session key is fine.
        let init = Initiator::new(service_key(Enctype::Aes128, 2), Enctype::Aes256, fresh());
        let mut acc = acceptor(Enctype::Aes128);
        let (token, ctx) = established(acc.step(&init.ap_req_token(Mech::Krb5)).expect("accepted"));
        let (subkey, seq) = init.check_ap_rep(&token, Mech::Krb5).unwrap();
        mic_both_ways(&init, &ctx, subkey.as_deref(), seq);
    }

    #[test]
    fn sspi_replay_cache_is_per_context() {
        // Observation S6: the authenticator cache lives in ServerProperties, which every
        // context clones, so the same AP-REQ is accepted twice by two acceptors.
        let init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, fresh());
        let token = init.ap_req_token(Mech::Krb5);
        established(acceptor(Enctype::Aes256).step(&token).expect("first"));
        established(
            acceptor(Enctype::Aes256)
                .step(&token)
                .expect("second: no replay detection across contexts"),
        );
    }

    #[test]
    fn sspi_does_not_check_the_gss_checksum_or_the_ticket_flags() {
        // Observation S7: the 0x8003 checksum (flags, channel bindings) and the ticket's
        // INVALID flag are not read; the context is established anyway.
        let mut init = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, fresh());
        init.ticket_flags |= 0x0100_0000;
        init.gss_flags |= 0x1000;
        let mut acc = acceptor(Enctype::Aes256);
        established(
            acc.step(&init.ap_req_token(Mech::Krb5))
                .expect("accepted despite INVALID and DCE style"),
        );
    }

    #[test]
    fn sspi_refuses_a_list_without_kerberos() {
        let mut acc = acceptor(Enctype::Aes256);
        let ntlm_only =
            crate::own::spnego::encode_init(&[picky_asn1_x509::oids::ntlm_ssp()], b"NTLMSSP\0");
        assert!(
            acc.step(&ntlm_only).is_err(),
            "package_list kerberos,!ntlm refuses NTLM"
        );
    }

    #[test]
    fn sspi_refuses_expired_ticket_skew_and_wrong_key() {
        let now = fresh();
        let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, now);
        i.ticket_end = now - 400;
        assert!(
            acceptor(Enctype::Aes256)
                .step(&i.ap_req_token(Mech::Krb5))
                .is_err()
        );
        let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, now);
        i.now = now - 301;
        assert!(
            acceptor(Enctype::Aes256)
                .step(&i.ap_req_token(Mech::Krb5))
                .is_err()
        );
        let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, now);
        i.service_key.key[0] ^= 1;
        assert!(
            acceptor(Enctype::Aes256)
                .step(&i.ap_req_token(Mech::Krb5))
                .is_err()
        );
        let mut i = Initiator::new(service_key(Enctype::Aes256, 2), Enctype::Aes256, now);
        i.spn = vec!["HTTP".into(), "tenko.corp.example.test".into()];
        assert!(
            acceptor(Enctype::Aes256)
                .step(&i.ap_req_token(Mech::Krb5))
                .is_err()
        );
    }
}
