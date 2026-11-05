//! The cipher against the published vectors (RFC 3961 appendix A, RFC 3962 appendix B, and
//! MIT Kerberos' encryption and checksum vectors) and against the recorded exchanges.

use super::*;
use crate::{
    der::{
        ApRep, ApReq, Authenticator, EncApRepPart, EncTicketPart, InitialContextToken, KrbToken,
        NegTokenInit, NegTokenResp, oid,
    },
    fixtures::{self, hex},
};

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha1;
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha1;

#[test]
fn nfold_matches_rfc_3961_appendix_a() {
    let cases: &[(&[u8], usize, &str)] = &[
        (b"012345", 64, "be072631276b1955"),
        (b"password", 56, "78a07b6caf85fa"),
        (b"Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0"),
        (
            b"password",
            168,
            "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
        ),
        (
            b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            192,
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        (b"Q", 168, "518a54a215a8452a518a54a215a8452a518a54a215"),
        (b"ba", 168, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"),
        (b"kerberos", 64, "6b65726265726f73"),
        (b"kerberos", 128, "6b65726265726f737b9b5b2b93132b93"),
        (
            b"kerberos",
            168,
            "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4",
        ),
        (
            b"kerberos",
            256,
            "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
        ),
        // MIT's t_nfold.c, 192-fold.
        (
            b"basch",
            192,
            "1aab6b42964b98b21f8cde2d2448ba3455d7862c9731643f",
        ),
        (
            b"eichin",
            192,
            "65696368696e4b732b4b1b43da1a5b995a58d2c6d0d2dcca",
        ),
        (
            b"sommerfeld",
            192,
            "2f7a98557c6ee4abadf4e71192dd442bd4ff5325a5def75c",
        ),
    ];
    for (input, bits, expected) in cases {
        assert_eq!(
            nfold(input, bits / 8),
            hex(expected),
            "{bits}-fold({})",
            String::from_utf8_lossy(input)
        );
    }
}

/// Password, salt, iterations, the AES-128 key and the AES-256 key.
type S2kVector<'a> = (&'a [u8], &'a [u8], u32, &'a str, &'a str);

#[test]
fn string_to_key_matches_rfc_3962_appendix_b() {
    let athena = b"ATHENA.MIT.EDUraeburn";
    let x64 = [b'X'; 64];
    let x65 = [b'X'; 65];
    let cases: &[S2kVector] = &[
        (
            b"password",
            athena,
            1,
            "42263c6e89f4fc28b8df68ee09799f15",
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        ),
        (
            b"password",
            athena,
            2,
            "c651bf29e2300ac27fa469d693bdda13",
            "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
        ),
        (
            b"password",
            athena,
            1200,
            "4c01cd46d632d01e6dbe230a01ed642a",
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
        ),
        (
            b"password",
            &[0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12],
            5,
            "e9b23d52273747dd5c35cb55be619d8e",
            "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
        ),
        (
            &x64,
            b"pass phrase equals block size",
            1200,
            "59d1bb789a828b1aa54ef9c2883f69ed",
            "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
        ),
        (
            &x65,
            b"pass phrase exceeds block size",
            1200,
            "cb8005dc5f90179a7f02104c0018751d",
            "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
        ),
        (
            // The G clef, U+1D11E, as UTF-8.
            &[0xf0, 0x9d, 0x84, 0x9e],
            b"EXAMPLE.COMpianist",
            50,
            "f149c1f2e154a73452d43e7fe62a56e5",
            "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
        ),
    ];
    for (password, salt, count, aes128, aes256) in cases {
        for (etype, expected) in [(AES128, aes128), (AES256, aes256)] {
            let key = string_to_key(etype, password, salt, *count).expect("string-to-key");
            assert_eq!(key.as_bytes(), hex(expected), "{etype:?} {count}");
        }
    }
    assert_eq!(
        string_to_key(AES256, b"password", athena, 0),
        Err(CipherError::Iterations)
    );
    assert_eq!(
        string_to_key(AES256, b"password", athena, MAX_ITERATIONS + 1),
        Err(CipherError::Iterations)
    );
    assert_eq!(iterations(None), Ok(4096));
    assert_eq!(iterations(Some(&[0, 0, 0x10, 0])), Ok(4096));
    assert_eq!(
        iterations(Some(&[0, 0, 0, 0])),
        Err(CipherError::Iterations)
    );
    assert_eq!(iterations(Some(&[0, 0, 1])), Err(CipherError::Iterations));
    assert_eq!(
        iterations(Some(&[0xff, 0, 0, 0])),
        Err(CipherError::Iterations)
    );
}

#[test]
fn cts_matches_rfc_3962_appendix_b() {
    let key = Key::new(AES128, b"chicken teriyaki").expect("key");
    let cases = [
        (
            "4920776f756c64206c696b6520746865 20",
            "c6353568f2bf8cb4d8a580362da7ff7f 97",
        ),
        (
            "4920776f756c64206c696b6520746865 2047656e6572616c20476175277320",
            "fc00783e0efdb2c1d445d4c8eff7ed22 97687268d6ecccc0c07b25e25ecfe5",
        ),
        (
            "4920776f756c64206c696b6520746865 2047656e6572616c2047617527732043",
            "39312523a78662d5be7fcbcc98ebf5a8 97687268d6ecccc0c07b25e25ecfe584",
        ),
        (
            "4920776f756c64206c696b6520746865 2047656e6572616c2047617527732043 6869636b656e2c20706c656173652c",
            "97687268d6ecccc0c07b25e25ecfe584 b3fffd940c16a18c1b5549d2f838029e 39312523a78662d5be7fcbcc98ebf5",
        ),
        (
            "4920776f756c64206c696b6520746865 2047656e6572616c2047617527732043 6869636b656e2c20706c656173652c20",
            "97687268d6ecccc0c07b25e25ecfe584 9dad8bbb96c4cdc03bc103e1a194bbd8 39312523a78662d5be7fcbcc98ebf5a8",
        ),
        (
            "4920776f756c64206c696b6520746865 2047656e6572616c2047617527732043 6869636b656e2c20706c656173652c20 616e6420776f6e746f6e20736f75702e",
            "97687268d6ecccc0c07b25e25ecfe584 39312523a78662d5be7fcbcc98ebf5a8 4807efe836ee89a526730dbc2f7bc840 9dad8bbb96c4cdc03bc103e1a194bbd8",
        ),
    ];
    for (input, output) in cases {
        let mut data = hex(input);
        cts_encrypt(&key, &mut data).expect("encrypt");
        assert_eq!(data, hex(output), "{} octets", data.len());
        cts_decrypt(&key, &mut data).expect("decrypt");
        assert_eq!(data, hex(input));
    }
    // One block is plain AES; shorter input is refused.
    let mut block = [7_u8; 16];
    cts_encrypt(&key, &mut block).expect("one block");
    cts_decrypt(&key, &mut block).expect("one block");
    assert_eq!(block, [7; 16]);
    assert_eq!(cts_encrypt(&key, &mut [0; 15]), Err(CipherError::Truncated));
    assert_eq!(cts_decrypt(&key, &mut [0; 15]), Err(CipherError::Truncated));
}

/// MIT Kerberos' `t_decrypt.c` vectors for the two AES types: the plaintext, the usage, the
/// key and the ciphertext with its confounder.
const ENCRYPTION_VECTORS: &[(EncryptionType, &str, u32, &str, &str)] = &[
    (
        AES128,
        "",
        0,
        "5a5c0f0ba54f3828b2195e66ca24a289",
        "49ff8e11c173d9583a3254fbe7b1f1df36c538e8416784a1672e6676",
    ),
    (
        AES128,
        "1",
        1,
        "98450e3f3baa13f5c99beb936981b06f",
        "f86742f537b35dc2174a4dbaa920faf9042090b065e1ebb1cad9a65394",
    ),
    (
        AES128,
        "9 bytesss",
        2,
        "9062430c8cda3388922e6d6a509f5b7a",
        "68fb9679601f45c78857b2bf820fd6e53eca8d42fd4b1d7024a09205abb7cd2ec26c355d2f",
    ),
    (
        AES128,
        "13 bytes byte",
        3,
        "033ee6502c54fd23e27791e987983827",
        "ec366d0327a933bf49330e650e49bc6b974637fe80bf532fe51795b4809718e6194724db948d1fd637",
    ),
    (
        AES128,
        "30 bytes bytes bytes bytes byt",
        4,
        "dceeb70b3de76562e689226c76429148",
        "c96081032d5d8eeb7e32b4089f789d0faa481dea74c0f97cbf3146ddfcf8e800156ecb532fc203e30ff600b63b350939fece510f02d7ff1e7bac",
    ),
    (
        AES256,
        "",
        0,
        "17f275f2954f2ed1f90c377ba7f4d6a369aa0136e0bf0c927ad6133c693759a9",
        "e5094c55ee7b38262e2b044280b069379a95bf95bd8376fb3281b435",
    ),
    (
        AES256,
        "1",
        1,
        "b9477e1ff0329c0050e20ce6c72d2dff27e8fe541ab0954429a9cb5b4f7b1e2a",
        "406150b97aeb76d43b36b62cc1ecdfbe6f40e95755e0beb5c27825f3a4",
    ),
    (
        AES256,
        "9 bytesss",
        2,
        "b1ae4cd8462aff1677053cc9279aac30b796fb81ce21474dd3ddbcfea4ec76d7",
        "09957aa25fcaf88f7b39e4406e633012d5fea21853f6478da7065caef41fd454a40824eec5",
    ),
    (
        AES256,
        "13 bytes byte",
        3,
        "e5a72be9b7926c1225bafef9c1872e7ba4cdb2b17893d84abd90acdd8764d966",
        "d8f1aafeec84587cc3e700a774e56651a6d693e174ec4473b5e6d96f80297a653fb818ad893e719f96",
    ),
    (
        AES256,
        "30 bytes bytes bytes bytes byt",
        4,
        "f1c795e9248a09338d82c3f8d5b567040b0110736845041347235b1404231398",
        "d1137a4d634cfece924dbc3bf6790648bd5cff7de0e7b99460211d0daef3d79a295c688858f3b34b9cbd6eebae81daf6b734d4d498b6714f1c1d",
    ),
];

#[test]
fn encryption_matches_mit_vectors_and_refuses_changes() {
    for (etype, plain, usage, key, cipher) in ENCRYPTION_VECTORS {
        let key = Key::new(*etype, &hex(key)).expect("key");
        let ciphertext = hex(cipher);
        let decrypted = decrypt(&key, *usage, &ciphertext).expect("decrypts");
        assert_eq!(&decrypted[..], plain.as_bytes(), "{etype:?} usage {usage}");
        // The same confounder gives the same ciphertext.
        let ke = usage_key(&key, *usage, KIND_ENCRYPTION).expect("ke");
        let mut body = ciphertext[..ciphertext.len() - HMAC_LEN].to_vec();
        cts_decrypt(&ke, &mut body).expect("cts");
        let confounder: [u8; 16] = body[..16].try_into().expect("confounder");
        assert_eq!(
            encrypt_with_confounder(&key, *usage, &confounder, plain.as_bytes()).expect("encrypt"),
            ciphertext
        );
        // A changed octet anywhere, another usage, or a truncation is refused.
        for index in 0..ciphertext.len() {
            let mut changed = ciphertext.clone();
            changed[index] ^= 0x01;
            assert_eq!(decrypt(&key, *usage, &changed), Err(CipherError::Integrity));
        }
        assert_eq!(
            decrypt(&key, usage + 1, &ciphertext),
            Err(CipherError::Integrity)
        );
        assert_eq!(
            decrypt(&key, *usage, &ciphertext[..MIN_CIPHERTEXT_LEN - 1]),
            Err(CipherError::Truncated)
        );
        // A fresh encryption decrypts.
        let fresh = encrypt(&key, *usage, plain.as_bytes()).expect("encrypt");
        assert_eq!(
            &decrypt(&key, *usage, &fresh).expect("decrypt")[..],
            plain.as_bytes()
        );
    }
}

#[test]
fn checksums_match_mit_vectors() {
    let cases = [
        (
            b"eight nine ten eleven twelve thirteen".as_slice(),
            AES128,
            3,
            "9062430c8cda3388922e6d6a509f5b7a",
            "01a4b088d45628f6946614e3",
        ),
        (
            b"fourteen".as_slice(),
            AES256,
            4,
            "b1ae4cd8462aff1677053cc9279aac30b796fb81ce21474dd3ddbcfea4ec76d7",
            "e08739e3279e2903ec8e3836",
        ),
    ];
    for (data, etype, usage, key, expected) in cases {
        let key = Key::new(etype, &hex(key)).expect("key");
        assert_eq!(
            checksum(&key, usage, data).expect("checksum").to_vec(),
            hex(expected)
        );
        let cksumtype = checksum_type(etype);
        verify_checksum(&key, usage, cksumtype, data, &hex(expected)).expect("verifies");
        assert_eq!(
            verify_checksum(&key, usage, cksumtype, b"other", &hex(expected)),
            Err(CipherError::Checksum)
        );
        let other = if cksumtype == 15 { 16 } else { 15 };
        assert_eq!(
            verify_checksum(&key, usage, other, data, &hex(expected)),
            Err(CipherError::UnsupportedChecksum(other))
        );
        assert_eq!(
            verify_checksum(&key, usage, -138, data, &hex(expected)),
            Err(CipherError::UnsupportedChecksum(-138))
        );
    }
}

#[test]
fn only_aes_is_accepted() {
    for number in [1, 3, 16, 23, 24, 19, 20, -128, 0] {
        assert_eq!(
            enctype(number),
            Err(CipherError::UnsupportedEnctype(number))
        );
    }
    assert_eq!(enctype(17), Ok(AES128));
    assert_eq!(enctype(18), Ok(AES256));
    assert_eq!(Key::new(AES256, &[0; 16]), Err(CipherError::KeyLength(16)));
    assert_eq!(Key::new(AES128, &[0; 32]), Err(CipherError::KeyLength(32)));
    assert_eq!(
        format!("{:?}", Key::new(AES128, &[9; 16]).expect("key")),
        "Key(Aes128CtsHmacSha1)"
    );
}

/// The AP-REQ inside a fixture's first token.
fn ap_req(init0: &[u8]) -> ApReq {
    let outer = InitialContextToken::decode(init0).expect("token");
    let mech_token = if outer.mech == oid::SPNEGO {
        NegTokenInit::decode_initial(init0)
            .expect("init")
            .mech_token
            .expect("token")
            .to_vec()
    } else {
        init0.to_vec()
    };
    let inner = InitialContextToken::decode(&mech_token).expect("inner");
    ApReq::decode(KrbToken::decode(inner.inner).expect("krb").message).expect("AP-REQ")
}

/// DNS-28: the recorded tickets, authenticators and AP-REPs decrypt with the recorded keys,
/// and their plaintext is DER that the codec encodes back octet for octet.
#[test]
fn dns_28_recorded_exchanges_decrypt_with_their_keys() {
    for f in fixtures::all() {
        let req = ap_req(&f.init0);
        let enc = &req.ticket.enc_part;
        let (etype, _, key) = f
            .keys
            .iter()
            .find(|(etype, kvno, _)| *etype == enc.etype && Some(*kvno) == enc.kvno)
            .unwrap_or_else(|| panic!("{}: a key for the ticket", f.name));
        let service = Key::new(enctype(*etype).expect("aes"), key).expect("key");
        let plain = decrypt_data(&service, usage::TICKET, enc).expect("ticket decrypts");
        let ticket = EncTicketPart::decode(&plain).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(
            &ticket.encode()[..],
            &plain[..],
            "{}: EncTicketPart round trip",
            f.name
        );
        assert_eq!(ticket.cname.components, ["alice"], "{}", f.name);
        // Both KDCs put a PAC inside AD-IF-RELEVANT: MIT 1.20 a small one (client
        // information and the signatures), Samba one with the logon information.
        let ad = ticket
            .authorization_data
            .as_ref()
            .expect("authorization data");
        assert_eq!(ad.0.len(), 1, "{}", f.name);
        assert_eq!(ad.0[0].ad_type, crate::der::ad_type::IF_RELEVANT);
        let inner =
            crate::der::AuthorizationData::decode(&ad.0[0].ad_data).expect("AD-IF-RELEVANT");
        assert_eq!(inner.0.len(), 1);
        assert_eq!(inner.0[0].ad_type, crate::der::ad_type::WIN2K_PAC);
        assert_eq!(inner.encode(), ad.0[0].ad_data);
        // The wrong key and the wrong usage are refused.
        let other = Key::new(service.etype(), &vec![0x42; key_len(service.etype())]).expect("key");
        assert_eq!(
            decrypt_data(&other, usage::TICKET, enc),
            Err(CipherError::Integrity)
        );
        assert_eq!(
            decrypt_data(&service, usage::AP_REQ_AUTHENTICATOR, enc),
            Err(CipherError::Integrity)
        );

        let session = Key::from_wire(&ticket.key).expect("session key");
        let plain = decrypt_data(&session, usage::AP_REQ_AUTHENTICATOR, &req.authenticator)
            .expect("authenticator decrypts");
        let auth = Authenticator::decode(&plain).expect("Authenticator");
        assert_eq!(
            &auth.encode()[..],
            &plain[..],
            "{}: Authenticator round trip",
            f.name
        );
        assert_eq!(auth.cname, ticket.cname);
        assert_eq!(auth.cksum.as_ref().map(|c| c.cksumtype), Some(0x8003));

        let rep_token = if f.mech == "spnego" {
            NegTokenResp::decode(&f.accept0)
                .expect("resp")
                .response_token
                .expect("token")
                .to_vec()
        } else {
            f.accept0.clone()
        };
        let inner = InitialContextToken::decode(&rep_token).expect("rep token");
        let rep =
            ApRep::decode(KrbToken::decode(inner.inner).expect("krb").message).expect("AP-REP");
        let plain =
            decrypt_data(&session, usage::AP_REP_ENC_PART, &rep.enc_part).expect("AP-REP decrypts");
        let part = EncApRepPart::decode(&plain).expect("EncAPRepPart");
        assert_eq!(
            &part.encode()[..],
            &plain[..],
            "{}: EncAPRepPart round trip",
            f.name
        );
        assert_eq!((part.ctime, part.cusec), (auth.ctime, auth.cusec));
        assert_eq!(
            &part.subkey.expect("acceptor subkey").value[..],
            &f.ctxkey[..],
            "{}",
            f.name
        );
    }
}

/// The [MS-KILE] salts of identity plan section 3.1, with the keys MIT derives from them.
#[test]
fn ms_kile_salts_for_user_and_computer_accounts() {
    use tenko_core::dns::{KrbAccount, PrincipalName, Realm};
    let realm = Realm::new("corp.example.test").expect("realm");
    let account = |name: &str| KrbAccount {
        realm: realm.clone(),
        name: name.to_owned(),
        spns: vec!["DNS/tenko.corp.example.test".into()],
        kdcs: vec![],
        owned: true,
        rotation_days: 30,
        versions: vec![],
        last_rotation: None,
        last_check: None,
    };
    assert_eq!(
        salt::account(&account("TENKO-DNS$")),
        "CORP.EXAMPLE.TESThosttenko-dns.corp.example.test"
    );
    assert_eq!(
        salt::account(&account("tenko$")),
        "CORP.EXAMPLE.TESThosttenko.corp.example.test"
    );
    assert_eq!(
        salt::account(&account("svc-dns")),
        "CORP.EXAMPLE.TESTsvc-dns"
    );
    let alice = PrincipalName::parse("alice@CORP.EXAMPLE.TEST").expect("principal");
    assert_eq!(salt::principal(&alice), "CORP.EXAMPLE.TESTalice");
    let service =
        PrincipalName::parse("DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST").expect("principal");
    assert_eq!(
        salt::principal(&service),
        "CORP.EXAMPLE.TESTDNStenko.corp.example.test"
    );
}
