use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use super::*;

struct Cert {
    der: CertificateDer<'static>,
    key: SecretBytes,
    serial: String,
    sha256: String,
}

fn issuer() -> rcgen::Issuer<'static, KeyPair> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    rcgen::Issuer::new(params, key)
}

fn cert(issuer: &rcgen::Issuer<'static, KeyPair>, node: u64) -> Cert {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.subject_alt_names = vec![
        rcgen::SanType::URI(format!("urn:tenko:node:{node}").try_into().expect("uri")),
        rcgen::SanType::URI("urn:tenko:role:controller".try_into().expect("uri")),
    ];
    let der = params.signed_by(&key, issuer).expect("cert").der().clone();
    let identity = PeerIdentity::from_der(&der).expect("identity");
    Cert {
        der,
        key: SecretBytes::from_slice(&key.serialize_der()),
        serial: identity.serial,
        sha256: identity.sha256,
    }
}

fn step(node: u64, from: &Cert, to: &Cert) -> Step {
    let signature = attest(NodeId(node), &from.key, &to.key).expect("attest");
    Step::new(NodeId(node), &from.der, &to.der, signature).expect("a step")
}

fn held(certs: &[&Cert]) -> Held {
    certs
        .iter()
        .map(|cert| (cert.serial.clone(), cert.sha256.clone()))
        .collect()
}

const NONE: &dyn Fn(&str) -> bool = &|_| false;

/// Renewals from a certificate a receiver holds lead to the newest one; the receiver may
/// hold any certificate on the way. A chain that starts nowhere the receiver holds (a
/// minted certificate), skips a step, ends elsewhere, crosses to another node, or passes a
/// revoked certificate reaches nothing.
#[test]
fn a_chain_reaches_the_newest_certificate_only_from_one_held() {
    let ca = issuer();
    let certs: Vec<Cert> = (0..4).map(|_| cert(&ca, 2)).collect();
    let chain: Vec<Step> = certs
        .windows(2)
        .map(|pair| step(2, &pair[0], &pair[1]))
        .collect();
    let newest = &certs[3].der;
    assert!(Chain(&chain).reaches(NodeId(2), &held(&[&certs[0]]), NONE, newest));
    assert!(Chain(&chain).reaches(NodeId(2), &held(&[&certs[2]]), NONE, newest));
    // A minted certificate of the same node: no step is signed by a held key.
    let minted = cert(&ca, 2);
    let forged = [step(2, &minted, &certs[3])];
    assert!(!Chain(&forged).reaches(NodeId(2), &held(&[&certs[0]]), NONE, newest));
    // A step that names a held certificate as the renewed one, signed by a minted key.
    let claimed = [Step {
        previous: HexBytes(certs[0].der.to_vec()),
        next: HexBytes(minted.der.to_vec()),
        signature: HexBytes(attest(NodeId(2), &minted.key, &minted.key).expect("attest")),
    }];
    assert!(!Chain(&claimed).reaches(NodeId(2), &held(&[&certs[0]]), NONE, &minted.der));
    // The same serial with other bytes is not held.
    let mut other = held(&[&certs[0]]);
    other.insert(certs[0].serial.clone(), "00".to_owned());
    assert!(!Chain(&chain).reaches(NodeId(2), &other, NONE, newest));
    // A gap, another leaf, another node, a revoked certificate on the way.
    let gap = [chain[0].clone(), chain[2].clone()];
    assert!(!Chain(&gap).reaches(NodeId(2), &held(&[&certs[0]]), NONE, newest));
    assert!(!Chain(&chain).reaches(NodeId(2), &held(&[&certs[0]]), NONE, &certs[2].der));
    assert!(!Chain(&chain).reaches(NodeId(3), &held(&[&certs[0]]), NONE, newest));
    let revoked = certs[2].serial.clone();
    assert!(!Chain(&chain).reaches(
        NodeId(2),
        &held(&[&certs[0]]),
        &|serial| serial == revoked,
        newest
    ));
    // A step signed for another node does not verify for this one.
    let wrong = attest(NodeId(3), &certs[0].key, &certs[1].key).expect("attest");
    assert_eq!(
        Step::new(NodeId(2), &certs[0].der, &certs[1].der, wrong)
            .expect_err("signed for another node")
            .code(),
        "cluster.continuity.invalid"
    );
}

/// A chain longer than the bound reaches nothing: the receiver refuses and shows the
/// record, it never acts on a chain it does not check whole.
#[test]
fn a_chain_past_its_bound_reaches_nothing() {
    let ca = issuer();
    let certs: Vec<Cert> = (0..=MAX_STEPS + 1).map(|_| cert(&ca, 2)).collect();
    let chain: Vec<Step> = certs
        .windows(2)
        .map(|pair| step(2, &pair[0], &pair[1]))
        .collect();
    assert_eq!(chain.len(), MAX_STEPS + 1);
    let newest = &certs[MAX_STEPS + 1].der;
    assert!(!Chain(&chain).reaches(NodeId(2), &held(&[&certs[1]]), NONE, newest));
    assert!(Chain(&chain[1..]).reaches(NodeId(2), &held(&[&certs[1]]), NONE, newest));
}

/// A step as a later build may write it, with a field this one does not know.
#[derive(Serialize)]
struct Later {
    previous: HexBytes,
    next: HexBytes,
    signature: HexBytes,
    reason: String,
}

/// A stored step is read tolerantly (a field a later build adds is ignored) and these
/// bytes keep reading.
#[test]
fn the_kept_step_still_reads() {
    let kept = Step {
        previous: HexBytes(vec![0xaa]),
        next: HexBytes(vec![0xbb]),
        signature: HexBytes(vec![0xcc]),
    };
    let bytes = tenko_core::codec::to_cbor(&kept).expect("cbor");
    assert_eq!(
        tenko_core::serde_util::to_hex(&bytes),
        "a36870726576696f757341aa646e65787441bb697369676e617475726541cc"
    );
    let read: Step = tenko_core::codec::from_cbor(&bytes).expect("read");
    assert_eq!(read, kept);
    let later = tenko_core::codec::to_cbor(&Later {
        previous: HexBytes(vec![0xaa]),
        next: HexBytes(vec![0xbb]),
        signature: HexBytes(vec![0xcc]),
        reason: "rotation".to_owned(),
    })
    .expect("cbor");
    assert_eq!(
        tenko_core::codec::from_cbor::<Step>(&later).expect("tolerant"),
        kept
    );
}
