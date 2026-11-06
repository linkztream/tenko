//! The keytab parser against files written by MIT's `ktutil` (`tests/fixtures/keytabs/`,
//! made by `make.sh` there) and against hand-built malformed files.

use tenko_core::dns::{KeyVersionState, KrbAccount, PrincipalName, Realm};

use super::*;
use crate::fixtures::{file, hex_string};

/// `kvno principal enctype key` lines that `klist -Kekt` printed for a fixture.
fn klist(name: &str) -> Vec<(u32, String, String, String)> {
    String::from_utf8(file(&format!("keytabs/{name}.klist")))
        .expect("text")
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            (
                parts[0].parse().expect("kvno"),
                parts[1].to_owned(),
                parts[2].trim_start_matches("DEPRECATED:").to_owned(),
                parts[3].to_owned(),
            )
        })
        .collect()
}

fn enctype_name(number: i32) -> &'static str {
    match number {
        17 => "aes128-cts-hmac-sha1-96",
        18 => "aes256-cts-hmac-sha1-96",
        23 => "arcfour-hmac",
        16 => "des3-cbc-sha1",
        _ => "other",
    }
}

/// DNS-28: keytabs written by `ktutil` are read entry for entry as `klist` reads them.
#[test]
fn dns_28_ktutil_keytabs_are_read_as_klist_reads_them() {
    for name in [
        "user-alice",
        "computer-tenko-dns",
        "mixed-enctypes",
        "kvno-300",
    ] {
        let keytab = parse(&file(&format!("keytabs/{name}.keytab"))).expect(name);
        let expected = klist(name);
        let mut read: Vec<(u32, String, String, String)> = keytab
            .entries
            .iter()
            .map(|e| {
                (
                    e.kvno,
                    e.principal.to_string(),
                    enctype_name(e.key.etype().number()).to_owned(),
                    hex_string(e.key.as_bytes()),
                )
            })
            .collect();
        assert!(
            keytab.entries.iter().all(|e| e.name_type == 1),
            "{name}: KRB5_NT_PRINCIPAL"
        );
        // The refused entries are listed with their type, never their key.
        for refused in &keytab.refused {
            let line = expected
                .iter()
                .find(|l| l.2 == enctype_name(refused.enctype))
                .expect("klist lists it");
            assert_eq!(
                (refused.kvno, refused.principal.to_string()),
                (line.0, line.1.clone())
            );
            assert_eq!(
                refused.reason,
                CipherError::UnsupportedEnctype(refused.enctype)
            );
            read.push(line.clone());
        }
        assert_eq!(read, expected, "{name}");
    }
    let mixed = parse(&file("keytabs/mixed-enctypes.keytab")).expect("mixed");
    assert_eq!(mixed.entries.len(), 1);
    let refused: Vec<i32> = mixed.refused.iter().map(|r| r.enctype).collect();
    assert_eq!(refused, [23, 16], "RC4 and 3DES are refused");
}

/// The keys `ktutil` derived are the keys Tenko's string-to-key derives with the MS-KILE
/// salts: an independent check of RFC 3962 and of both salt rules.
#[test]
fn ktutil_keys_equal_tenko_string_to_key_with_the_ms_kile_salts() {
    let realm = Realm::new("CORP.EXAMPLE.TEST").expect("realm");
    let computer = KrbAccount {
        realm: realm.clone(),
        name: "TENKO-DNS$".into(),
        spns: vec!["DNS/tenko.corp.example.test".into()],
        kdcs: vec![],
        owned: true,
        rotation_days: 30,
        versions: vec![],
        last_rotation: None,
        last_check: None,
        secret: None,
        findings: Vec::new(),
    };
    let alice = PrincipalName::parse("alice@CORP.EXAMPLE.TEST").expect("alice");
    let cases = [
        (
            "user-alice",
            "Al1ce-Pass-lab".to_owned(),
            cipher::salt::principal(&alice),
        ),
        (
            "kvno-300",
            "Lab-Machine-Pass-1".to_owned(),
            cipher::salt::account(&computer),
        ),
    ];
    for (name, password, salt) in cases {
        for entry in parse(&file(&format!("keytabs/{name}.keytab")))
            .expect(name)
            .entries
        {
            let derived = cipher::string_to_key(
                entry.key.etype(),
                password.as_bytes(),
                salt.as_bytes(),
                cipher::DEFAULT_ITERATIONS,
            )
            .expect("string-to-key");
            assert_eq!(derived, entry.key, "{name} {:?}", entry.key.etype());
        }
    }
    for entry in parse(&file("keytabs/computer-tenko-dns.keytab"))
        .expect("computer")
        .entries
    {
        let password = format!("Lab-Machine-Pass-1-{}", entry.kvno);
        let derived = cipher::string_to_key(
            entry.key.etype(),
            password.as_bytes(),
            cipher::salt::account(&computer).as_bytes(),
            cipher::DEFAULT_ITERATIONS,
        )
        .expect("string-to-key");
        assert_eq!(
            derived, entry.key,
            "{} version {}",
            entry.principal, entry.kvno
        );
    }
}

#[test]
fn a_key_set_from_a_keytab() {
    let keytab = parse(&file("keytabs/computer-tenko-dns.keytab")).expect("keytab");
    assert_eq!(keytab.principals().len(), 2);
    let spn = PrincipalName::parse("DNS/tenko.corp.example.test@CORP.EXAMPLE.TEST").expect("spn");
    let set = keytab
        .key_set(|e| e.principal == spn, KeyVersionState::Current)
        .expect("set");
    assert_eq!(set.entries().len(), 4);
    assert_eq!(set.kvnos(), [2, 3]);
    assert_eq!(set.select(18, Some(3)).expect("key").len(), 1);
    // The same keys under both names: one set of the whole file selects one key each.
    let all = keytab
        .key_set(|_| true, KeyVersionState::Current)
        .expect("all");
    assert_eq!(all.entries().len(), 8);
    assert_eq!(all.select(17, Some(2)).expect("key").len(), 1);
}

/// One entry of format 2 with the given fields.
fn entry(
    components: &[&[u8]],
    realm: &[u8],
    kvno8: u8,
    enctype: u16,
    key: &[u8],
    kvno32: Option<u32>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u16::try_from(components.len())
            .expect("count")
            .to_be_bytes(),
    );
    let data = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&u16::try_from(bytes.len()).expect("len").to_be_bytes());
        out.extend_from_slice(bytes);
    };
    data(&mut body, realm);
    for component in components {
        data(&mut body, component);
    }
    body.extend_from_slice(&1_u32.to_be_bytes());
    body.extend_from_slice(&1_793_867_714_u32.to_be_bytes());
    body.push(kvno8);
    body.extend_from_slice(&enctype.to_be_bytes());
    data(&mut body, key);
    if let Some(kvno) = kvno32 {
        body.extend_from_slice(&kvno.to_be_bytes());
    }
    let mut out = i32::try_from(body.len())
        .expect("size")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&body);
    out
}

fn keytab(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = VERSION_2.to_vec();
    for record in records {
        out.extend_from_slice(record);
    }
    out
}

const REALM: &[u8] = b"CORP.EXAMPLE.TEST";

#[test]
fn holes_versions_and_the_end_marker() {
    let good = entry(&[b"TENKO-DNS$"], REALM, 7, 18, &[1; 32], None);
    let mut hole = (-5_i32).to_be_bytes().to_vec();
    hole.extend_from_slice(&[0; 5]);
    let parsed = parse(&keytab(&[hole, good.clone()])).expect("a hole is skipped");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].kvno, 7);
    // A 32-bit version replaces the 8-bit one unless it is zero.
    let wide = entry(&[b"TENKO-DNS$"], REALM, 44, 18, &[1; 32], Some(300));
    assert_eq!(parse(&keytab(&[wide])).expect("wide").entries[0].kvno, 300);
    let zero = entry(&[b"TENKO-DNS$"], REALM, 44, 18, &[1; 32], Some(0));
    assert_eq!(parse(&keytab(&[zero])).expect("zero").entries[0].kvno, 44);
    // A zero size ends the file; what follows is not read.
    let mut ended = keytab(std::slice::from_ref(&good));
    ended.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff]);
    assert_eq!(parse(&ended).expect("end marker").entries.len(), 1);
    // An AES key of the wrong length is refused, not kept.
    let short = entry(&[b"TENKO-DNS$"], REALM, 1, 18, &[1; 16], None);
    let parsed = parse(&keytab(&[short])).expect("parses");
    assert_eq!(parsed.entries.len(), 0);
    assert_eq!(parsed.refused[0].reason, CipherError::KeyLength(16));
}

#[test]
fn malformed_keytabs_are_refused_with_the_reason() {
    let kind = |bytes: &[u8]| parse(bytes).expect_err("refused").kind;
    assert_eq!(kind(&[0x05, 0x01, 0, 0, 0, 0]), KeytabErrorKind::Version1);
    assert!(KeytabErrorKind::Version1.to_string().contains("ktpass"));
    assert_eq!(kind(&[0x05, 0x03]), KeytabErrorKind::NotAKeytab);
    assert_eq!(kind(&[0x05]), KeytabErrorKind::NotAKeytab);
    assert_eq!(kind(&[]), KeytabErrorKind::NotAKeytab);
    assert_eq!(kind(&VERSION_2), KeytabErrorKind::Empty);
    assert_eq!(kind(&[0x05, 0x02, 0, 0, 0, 0]), KeytabErrorKind::Empty);
    assert_eq!(
        kind(&vec![0x05; MAX_KEYTAB_LEN + 1]),
        KeytabErrorKind::TooLarge
    );
    // A record longer than the file, and the most negative size.
    assert_eq!(
        kind(&[0x05, 0x02, 0x7f, 0xff, 0xff, 0xff, 0]),
        KeytabErrorKind::Truncated("record")
    );
    assert_eq!(
        kind(&[0x05, 0x02, 0x80, 0, 0, 0]),
        KeytabErrorKind::Truncated("record")
    );
    // Every prefix of a good file is refused or reads fewer entries, never a panic.
    let good = keytab(&[
        entry(
            &[b"DNS", b"tenko.corp.example.test"],
            REALM,
            3,
            18,
            &[2; 32],
            Some(3),
        ),
        entry(&[b"TENKO-DNS$"], REALM, 3, 17, &[3; 16], Some(3)),
    ]);
    for len in 0..good.len() {
        if let Ok(parsed) = parse(&good[..len]) {
            assert!(parsed.entries.len() < 2, "prefix {len}");
        }
    }
    // Component counts.
    let none = keytab(&[entry(&[], REALM, 1, 18, &[1; 32], None)]);
    assert_eq!(kind(&none), KeytabErrorKind::ComponentCount);
    let many: Vec<&[u8]> = vec![b"a"; MAX_NAME_COMPONENTS + 1];
    assert_eq!(
        kind(&keytab(&[entry(&many, REALM, 1, 18, &[1; 32], None)])),
        KeytabErrorKind::ComponentCount
    );
    // A name that is not UTF-8, an empty component, an empty realm.
    let bad = keytab(&[entry(&[b"\xff\xfe"], REALM, 1, 18, &[1; 32], None)]);
    assert_eq!(kind(&bad), KeytabErrorKind::BadPrincipal);
    assert_eq!(
        kind(&keytab(&[entry(&[b""], REALM, 1, 18, &[1; 32], None)])),
        KeytabErrorKind::BadPrincipal
    );
    assert_eq!(
        kind(&keytab(&[entry(&[b"a"], b"", 1, 18, &[1; 32], None)])),
        KeytabErrorKind::BadPrincipal
    );
    // A component length beyond the record.
    let mut long = entry(&[b"TENKO-DNS$"], REALM, 1, 18, &[1; 32], None);
    let at = 4 + 2 + 2 + REALM.len();
    long[at] = 0xff;
    assert_eq!(
        kind(&keytab(&[long])),
        KeytabErrorKind::Truncated("component")
    );
    // Too many records.
    let mut hole = (-1_i32).to_be_bytes().to_vec();
    hole.push(0);
    let holes = vec![hole; MAX_KEYTAB_RECORDS + 1];
    assert_eq!(kind(&keytab(&holes)), KeytabErrorKind::TooManyRecords);
}
