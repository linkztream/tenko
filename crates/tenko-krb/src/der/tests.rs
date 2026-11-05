//! The codec against the recorded exchanges: every token decodes and encodes back octet
//! for octet, and malformed structures are refused with the field named.

use super::writer::encode;
use super::*;
use crate::fixtures;

/// The AP-REQ of a fixture's first token, and whether it came inside SPNEGO.
fn ap_req_of(init0: &[u8]) -> (Vec<u8>, &'static [u8], bool) {
    let outer = InitialContextToken::decode(init0).expect("initial context token");
    if outer.mech == oid::SPNEGO {
        let init = NegTokenInit::decode_initial(init0).expect("negTokenInit");
        assert_eq!(init.encode_initial(), init0, "negTokenInit round trip");
        assert_eq!(
            gss::encode_mech_type_list(&init.mech_types),
            init.mech_types_der
        );
        let token = init.mech_token.expect("optimistic token");
        let inner = InitialContextToken::decode(token).expect("inner token");
        let mech = if inner.mech == oid::KRB5 {
            oid::KRB5
        } else {
            oid::MS_KRB5
        };
        let krb = KrbToken::decode(inner.inner).expect("krb token");
        assert_eq!(krb.tok_id, gss::tok_id::AP_REQ);
        (krb.message.to_vec(), mech, true)
    } else {
        let krb = KrbToken::decode(outer.inner).expect("krb token");
        assert_eq!(krb.tok_id, gss::tok_id::AP_REQ);
        let mech = if outer.mech == oid::KRB5 {
            oid::KRB5
        } else {
            oid::MS_KRB5
        };
        assert_eq!(KrbToken::encode(mech, krb.tok_id, krb.message), init0);
        (krb.message.to_vec(), mech, false)
    }
}

/// DNS-28: every recorded MIT and Samba token decodes and encodes back to the same octets.
#[test]
fn dns_28_recorded_tokens_decode_and_encode_octet_for_octet() {
    for f in fixtures::all() {
        let (message, mech, spnego) = ap_req_of(&f.init0);
        assert_eq!(spnego, f.mech == "spnego", "{}", f.name);
        let ap_req = ApReq::decode(&message).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(ap_req.encode(), message, "{}: AP-REQ round trip", f.name);
        assert_eq!(ap_req.ticket.realm, f.realm, "{}", f.name);
        assert_eq!(ap_req.ticket.sname.components, f.spn, "{}", f.name);
        assert_eq!(
            ap_req.ticket.encode(),
            Ticket::decode(&ap_req.ticket.encode())
                .expect("ticket")
                .encode()
        );
        let expected_mech = if f.mech == "ms-krb5" {
            oid::MS_KRB5
        } else {
            oid::KRB5
        };
        assert_eq!(mech, expected_mech, "{}", f.name);

        // The acceptor's answer.
        let rep_token = if spnego {
            let resp = NegTokenResp::decode(&f.accept0).expect("negTokenResp");
            assert_eq!(
                resp.encode(),
                f.accept0,
                "{}: negTokenResp round trip",
                f.name
            );
            assert_eq!(resp.neg_state, Some(NegState::AcceptCompleted));
            resp.response_token.expect("response token").to_vec()
        } else {
            f.accept0.clone()
        };
        let outer = InitialContextToken::decode(&rep_token).expect("AP-REP token");
        assert_eq!(outer.mech, expected_mech, "{}: the request's OID", f.name);
        let krb = KrbToken::decode(outer.inner).expect("krb token");
        assert_eq!(krb.tok_id, gss::tok_id::AP_REP);
        let reply = ApRep::decode(krb.message).expect("AP-REP");
        assert_eq!(reply.encode(), krb.message, "{}: AP-REP round trip", f.name);
    }
}

#[test]
fn structures_round_trip() {
    let name = PrincipalName::new(name_type::SRV_INST, &["krbtgt", "CORP.EXAMPLE.TEST"]);
    let body = KdcReqBody {
        kdc_options: kdc_options::CANONICALIZE,
        cname: Some(PrincipalName::new(name_type::PRINCIPAL, &["TENKO-DNS$"])),
        realm: "CORP.EXAMPLE.TEST".into(),
        sname: Some(name.clone()),
        from: None,
        till: 1_793_900_000,
        rtime: Some(1_794_000_000),
        nonce: 0xdead_beef,
        etype: vec![18, 17],
        addresses: Some(vec![HostAddress::from_ip([192, 0, 2, 1].into())]),
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let req = KdcReq {
        msg_type: msg_type::AS_REQ,
        padata: Some(vec![PaData {
            padata_type: pa_type::PAC_REQUEST,
            value: encode_pac_request(true),
        }]),
        req_body: body,
    };
    assert_eq!(KdcReq::decode(&req.encode()).expect("AS-REQ"), req);
    let error = KrbError {
        ctime: None,
        cusec: None,
        stime: 1_793_867_714,
        susec: 12,
        error_code: 25,
        crealm: Some("CORP.EXAMPLE.TEST".into()),
        cname: Some(PrincipalName::new(1, &["alice"])),
        realm: "CORP.EXAMPLE.TEST".into(),
        sname: name.clone(),
        e_text: Some("NEEDED_PREAUTH".into()),
        e_data: Some(vec![0x30, 0x00]),
    };
    assert_eq!(KrbError::decode(&error.encode()).expect("KRB-ERROR"), error);
    let info = vec![
        EtypeInfo2Entry {
            etype: 18,
            salt: Some("CORP.EXAMPLE.TESThosttenko-dns.corp.example.test".into()),
            s2kparams: Some(vec![0, 0, 0x10, 0]),
        },
        EtypeInfo2Entry {
            etype: 17,
            salt: None,
            s2kparams: None,
        },
    ];
    assert_eq!(
        decode_etype_info2(&encode_etype_info2(&info)).expect("info"),
        info
    );
    let ts = PaEncTsEnc {
        patimestamp: 1_793_867_714,
        pausec: Some(999_999),
    };
    assert_eq!(PaEncTsEnc::decode(&ts.encode()).expect("ts"), ts);
    let change = ChangePasswdData {
        newpasswd: zeroize::Zeroizing::new(b"N3w-Pass".to_vec()),
        targname: None,
        targrealm: None,
    };
    assert_eq!(
        ChangePasswdData::decode(&change.encode()).expect("chpw"),
        change
    );
    let private = EncKrbPrivPart {
        user_data: zeroize::Zeroizing::new(vec![0, 0]),
        timestamp: None,
        usec: None,
        seq_number: Some(0x8000_0001),
        s_address: Some(HostAddress::from_ip([198, 51, 100, 7].into())),
        r_address: None,
    };
    assert_eq!(
        EncKrbPrivPart::decode(&private.encode()).expect("priv"),
        private
    );
    let priv_msg = KrbPriv {
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![1, 2, 3],
        },
    };
    assert_eq!(
        KrbPriv::decode(&priv_msg.encode()).expect("KRB-PRIV"),
        priv_msg
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn malformed_structures_are_refused_with_the_field_named() {
    let (message, _, _) = ap_req_of(&fixtures::all()[0].init0);
    // Every truncation is refused, never a panic.
    for len in 0..message.len() {
        assert!(ApReq::decode(&message[..len]).is_err(), "prefix {len}");
    }
    // A trailing octet.
    let mut longer = message.clone();
    longer.push(0);
    assert_eq!(
        ApReq::decode(&longer).expect_err("trailing").kind,
        DerErrorKind::TrailingData
    );
    // The pvno is 5.
    let ap_req = ApReq::decode(&message).expect("AP-REQ");
    let bad = encode(|d| {
        d.application(14, |a| {
            a.sequence(|s| {
                s.field(0, |f| {
                    f.integer(4);
                });
            });
        });
    });
    let error = ApReq::decode(&bad).expect_err("pvno");
    assert_eq!((error.structure, error.field), ("AP-REQ", "pvno"));
    assert_eq!(error.kind, DerErrorKind::Unsupported);
    // A BER indefinite length inside.
    let mut ber = ap_req.encode();
    ber[1] = 0x80;
    assert_eq!(
        ApReq::decode(&ber).expect_err("indefinite").kind,
        DerErrorKind::IndefiniteLength
    );
    // A missing required field names it.
    let no_ticket = encode(|d| {
        d.application(14, |a| {
            a.sequence(|s| {
                s.field(0, |f| {
                    f.integer(5);
                });
                s.field(1, |f| {
                    f.integer(14);
                });
                s.field(2, |f| {
                    f.flags(0);
                });
            });
        });
    });
    let error = ApReq::decode(&no_ticket).expect_err("ticket");
    assert_eq!((error.field, error.kind), ("ticket", DerErrorKind::Missing));
    // An empty name is refused.
    let empty = encode(|d| {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(1);
            });
            s.field(1, |f| {
                f.sequence(|_| {});
            });
        });
    });
    assert!(PrincipalName::read(&mut Reader::new(&empty, "T")).is_err());
    // A list of more names than allowed.
    let many = encode(|d| {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(1);
            });
            s.field(1, |f| {
                f.sequence(|q| {
                    for _ in 0..=MAX_NAME_COMPONENTS {
                        q.string("a");
                    }
                });
            });
        });
    });
    assert_eq!(
        PrincipalName::read(&mut Reader::new(&many, "T"))
            .expect_err("too many")
            .kind,
        DerErrorKind::TooMany
    );
    // SPNEGO without a mechanism, and a negTokenResp in place of the init.
    let resp = NegTokenResp {
        neg_state: Some(NegState::Reject),
        supported_mech: None,
        response_token: None,
        mech_list_mic: None,
    }
    .encode();
    assert_eq!(
        NegTokenResp::decode(&resp).expect("resp").neg_state,
        Some(NegState::Reject)
    );
    let wrapped = InitialContextToken::encode(oid::SPNEGO, &resp);
    assert!(NegTokenInit::decode_initial(&wrapped).is_err());
    let no_mechs = NegTokenInit {
        mech_types: vec![],
        mech_types_der: &[],
        req_flags: None,
        mech_token: None,
        mech_list_mic: None,
    }
    .encode_initial();
    assert_eq!(
        NegTokenInit::decode_initial(&no_mechs)
            .expect_err("no mechs")
            .field,
        "mechTypes"
    );
}
