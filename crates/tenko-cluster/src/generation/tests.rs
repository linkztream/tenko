use std::path::PathBuf;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use super::*;

const AT: i128 = 1_789_000_000_000_000_000;

fn body(number: u64, parent: Option<Digest>, forced: u64) -> GenerationBody {
    GenerationBody {
        layout: LAYOUT,
        number,
        parent,
        forced: NodeId(forced),
        fork: ForkPoint {
            term: 7,
            leader: 1,
            index: 88530,
            revision: Revision(88412),
            audit: ChainHead::default(),
        },
        superseded: [1, 3]
            .into_iter()
            .filter(|node| *node != forced)
            .map(NodeId)
            .collect(),
        at: Timestamp::from_unix_nanos(AT).expect("time"),
        nonce: HexBytes(vec![7; 16]),
    }
}

struct Ca {
    root: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

fn ca() -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = params.self_signed(&key).expect("root");
    Ca {
        root: root.der().clone(),
        issuer: rcgen::Issuer::new(params, key),
    }
}

/// A certificate of `node` with `role`, its key, and its serial.
struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: SecretBytes,
    serial: String,
}

fn leaf(ca: &Ca, node: u64, role: &str) -> Leaf {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.subject_alt_names = vec![
        rcgen::SanType::URI(format!("urn:tenko:node:{node}").try_into().expect("uri")),
        rcgen::SanType::URI(format!("urn:tenko:role:{role}").try_into().expect("uri")),
    ];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf");
    let serial = PeerIdentity::from_der(cert.der()).expect("identity").serial;
    Leaf {
        chain: vec![cert.der().clone()],
        key: SecretBytes::from_slice(&key.serialize_der()),
        serial,
    }
}

fn sign(leaf: &Leaf, body: &GenerationBody) -> GenerationRecord {
    GenerationRecord::sign(body, &leaf.chain, &leaf.key).expect("sign")
}

/// The refusal of a record, with its code and the reason in its detail.
#[track_caller]
fn refused<T: std::fmt::Debug>(result: Result<T, ClusterError>, why: &str) {
    let error = result.expect_err(why);
    assert_eq!(error.code(), codes::RECORD_INVALID);
    assert!(error.detail().contains(why), "{}", error.detail());
}

#[test]
fn the_body_layout_is_pinned_and_reads_back() {
    let pinned = concat!(
        "a862617474323032362d30392d31305430303a32363a34305a64666f726ba5647465726d",
        "07656175646974a263736571006468617368582000000000000000000000000000000000",
        "0000000000000000000000000000000065696e6465781a000159d2666c65616465720168",
        "7265766973696f6e1a0001595c656e6f6e63655007070707070707070707070707070707",
        "66666f7263656402666c61796f757401666e756d6265720166706172656e74f66a737570",
        "65727365646564820103",
    );
    // The canonical CBOR of the body: eight fields in the canonical key order; a change
    // here is a change of the signed contract.
    assert_eq!(to_hex(&body(1, None, 2).canonical().expect("cbor")), pinned);
    let record = GenerationRecord {
        body: HexBytes(tenko_core::serde_util::from_hex(pinned).expect("hex")),
        signature: HexBytes(Vec::new()),
        chain: Vec::new(),
    };
    assert_eq!(record.body().expect("body"), Some(body(1, None, 2)));
    let header = record.header().expect("header");
    assert_eq!(
        (header.number, header.forced, header.parent),
        (1, NodeId(2), None)
    );
}

#[test]
fn the_signing_context_is_pinned() {
    assert_eq!(SIGNING_CONTEXT, b"tenko generation record v1\0");
    assert_eq!(
        signed_message(&[0xa0]),
        [&b"tenko generation record v1\0"[..], &[0xa0]].concat()
    );
}

#[test]
fn a_claim_has_one_form() {
    let hash = Digest([0xab; 32]);
    let claim = Claim::of(4, &hash);
    let text = claim.render().expect("a claim");
    assert_eq!(text, format!("4:{}", "ab".repeat(16)));
    assert!(text.len() < 64);
    assert_eq!(Claim::parse(&text), Some(claim));
    assert_eq!(Claim::ZERO.render(), None);
    let ab = "ab".repeat(16);
    for bad in [
        String::new(),
        "4".to_owned(),
        "x:ab".to_owned(),
        "4:abc".to_owned(),
        format!("4:{}", "ab".repeat(17)),
        format!("+4:{ab}"),
        format!("04:{ab}"),
        format!("0:{ab}"),
        format!("4:{}", "AB".repeat(16)),
    ] {
        assert_eq!(Claim::parse(&bad), None, "{bad}");
    }
}

#[test]
fn a_signed_record_verifies_and_is_read_exactly() {
    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    let record = sign(&signer, &body(1, None, 2));
    let bytes = record.encode().expect("cbor");
    let decoded = GenerationRecord::decode(&bytes).expect("decode");
    assert_eq!(decoded, record);
    let checked = decoded.verify(&ca.root).expect("verify");
    assert_eq!(checked.body(), Some(&body(1, None, 2)));
    assert_eq!(checked.signer().node, NodeId(2));
    assert_eq!(checked.hash(), record.hash());

    refused(
        GenerationRecord::decode(&[bytes.as_slice(), &[0x00]].concat()),
        "exact encoding",
    );
    refused(
        GenerationRecord::decode(&bytes[..bytes.len() - 1]),
        "does not decode",
    );
    refused(GenerationRecord::decode(&[0xff; 8]), "does not decode");
    refused(
        GenerationRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]),
        "too large",
    );
    let lineage = encode_lineage(std::slice::from_ref(&record)).expect("lineage");
    assert_eq!(decode_lineage(&lineage).expect("lineage"), vec![record]);
    refused(
        decode_lineage(&[lineage.as_slice(), &[0x00]].concat()),
        "exact encoding",
    );
    refused(decode_lineage(&encode_lineage(&[]).expect("empty")), "1 to");
}

#[test]
fn a_forged_record_does_not_verify() {
    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    let good = sign(&signer, &body(1, None, 2));

    let mut changed = good.clone();
    changed.body = HexBytes(body(9, None, 2).canonical().expect("cbor"));
    refused(changed.verify(&ca.root), "signature does not verify");
    let mut flipped = good.clone();
    let last = flipped.signature.0.len() - 1;
    flipped.signature.0[last] ^= 1;
    refused(flipped.verify(&ca.root), "signature does not verify");
    refused(good.verify(&self::ca().root), "certificate does not verify");
    let probe = leaf(&ca, 2, "probe");
    refused(
        sign(&probe, &body(1, None, 2)).verify(&ca.root),
        "does not verify",
    );
    let other = leaf(&ca, 3, "controller");
    refused(
        sign(&other, &body(1, None, 2)).verify(&ca.root),
        "not signed by the forced controller",
    );
    // A signature over the body alone, without the context, is not a record's signature.
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signer.key.expose())
        .expect("key");
    let mut bare = good.clone();
    bare.signature = HexBytes(
        pair.sign(&SystemRandom::new(), &good.body.0)
            .expect("sign")
            .as_ref()
            .to_vec(),
    );
    refused(bare.verify(&ca.root), "signature does not verify");
}

#[test]
fn a_body_breaking_its_layout_is_refused() {
    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    refused(
        sign(&signer, &body(0, None, 2)).verify(&ca.root),
        "never numbered 0",
    );
    let mut short = body(1, None, 2);
    short.nonce = HexBytes(vec![1; 8]);
    refused(sign(&signer, &short).verify(&ca.root), "rule of its layout");
    let mut itself = body(1, None, 2);
    itself.superseded.push(NodeId(2));
    refused(
        sign(&signer, &itself).verify(&ca.root),
        "rule of its layout",
    );
    // A body that is not in its canonical form: a key the layout does not have.
    let mut extra = sign(&signer, &body(1, None, 2));
    extra.body = HexBytes(extended(&body(1, None, 2)));
    refused(extra.body(), "exact encoding");
}

/// A body with a key layout 1 does not have, in canonical CBOR.
fn extended(body: &GenerationBody) -> Vec<u8> {
    #[derive(Serialize)]
    struct Extended<'a> {
        #[serde(flatten)]
        body: &'a GenerationBody,
        later: &'static str,
    }
    to_canonical_cbor(&Extended {
        body,
        later: "a field of a later layout",
    })
    .expect("cbor")
}

#[test]
fn a_record_of_a_later_layout_is_placed_by_its_header() {
    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    let mut later = body(1, None, 2);
    later.layout = 2;
    let bytes = extended(&later);
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signer.key.expose())
        .expect("key");
    let record = GenerationRecord {
        signature: HexBytes(
            pair.sign(&SystemRandom::new(), &signed_message(&bytes))
                .expect("sign")
                .as_ref()
                .to_vec(),
        ),
        body: HexBytes(bytes),
        chain: signer
            .chain
            .iter()
            .map(|cert| HexBytes(cert.to_vec()))
            .collect(),
    };
    let checked = record.verify(&ca.root).expect("a later layout verifies");
    assert_eq!(checked.body(), None);
    assert_eq!(checked.number(), 1);
    let standing = standing(&[(2, &signer.serial)]);
    let admission = Lineage::default()
        .admit(&[record], &ca.root, &standing)
        .expect("admit");
    assert_eq!(admission.relation, Relation::Descendant);
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generation")
}

/// One signed record, kept byte for byte: a change of the signature scheme, the context,
/// the hash or the encodings in both `sign` and `verify` passes every test that signs at run
/// time, and fails this one. Write it again with `TENKO_REGENERATE_GENERATION_RECORD=1`
/// only together with a new layout.
#[test]
fn the_kept_signed_record_still_verifies() {
    let dir = fixtures();
    if std::env::var("TENKO_REGENERATE_GENERATION_RECORD").is_ok_and(|value| value == "1") {
        let ca = ca();
        let signer = leaf(&ca, 2, "controller");
        fs::create_dir_all(&dir).expect("fixture directory");
        fs::write(dir.join("ca.der"), ca.root.as_ref()).expect("write");
        let record = sign(&signer, &body(1, None, 2));
        fs::write(dir.join("record.cbor"), record.encode().expect("cbor")).expect("write");
    }
    let root = CertificateDer::from(fs::read(dir.join("ca.der")).expect("ca.der"));
    let bytes = fs::read(dir.join("record.cbor")).expect("record.cbor");
    let record = GenerationRecord::decode(&bytes).expect("decode");
    let signed = record.verify(&root).expect("the kept record verifies");
    assert_eq!(signed.body(), Some(&body(1, None, 2)));
    assert_eq!(record.encode().expect("cbor"), bytes);
}

/// A standing in which `holds` are the controllers (node, serial) the store knows; every
/// node in it is a voter.
fn standing(holds: &[(u64, &str)]) -> Standing {
    let mut standing = Standing {
        now: Timestamp::from_unix_nanos(AT).expect("time"),
        ..Standing::default()
    };
    for (node, serial) in holds {
        standing.voters.insert(NodeId(*node));
        standing
            .serials
            .entry(NodeId(*node))
            .or_default()
            .insert((*serial).to_owned());
    }
    standing
}

#[test]
fn relations_follow_the_lineage() {
    let ca = ca();
    let one = leaf(&ca, 1, "controller");
    let two = leaf(&ca, 2, "controller");
    let three = leaf(&ca, 3, "controller");
    let standing = standing(&[(1, &one.serial), (2, &two.serial), (3, &three.serial)]);
    let r1 = sign(&two, &body(1, None, 2));
    let mut b2 = body(2, Some(r1.hash()), 2);
    b2.at = Timestamp::from_unix_nanos(AT + 1).expect("time");
    let r2 = sign(&two, &b2);
    let zero = Lineage::default();
    let admit = |lineage: &Lineage, offer: &[GenerationRecord]| {
        lineage
            .admit(offer, &ca.root, &standing)
            .map(|a| a.relation)
    };

    assert_eq!(
        admit(&zero, std::slice::from_ref(&r1)).expect("r1"),
        Relation::Descendant
    );
    // Two generations behind: the lineage links the newest record to generation 0.
    assert_eq!(
        admit(&zero, &[r1.clone(), r2.clone()]).expect("r1 r2"),
        Relation::Descendant
    );
    // Without the link the newest record cannot be placed, and is not ignored.
    assert_eq!(
        admit(&zero, std::slice::from_ref(&r2)).expect("r2"),
        Relation::Unplaced
    );
    let at_one = Lineage::kept(std::slice::from_ref(&r1)).expect("lineage");
    assert_eq!(
        admit(&at_one, std::slice::from_ref(&r1)).expect("same"),
        Relation::Known
    );
    assert_eq!(
        admit(&at_one, &[r1.clone(), r2.clone()]).expect("r2"),
        Relation::Descendant
    );
    let at_two = Lineage::kept(&[r1.clone(), r2.clone()]).expect("lineage");
    assert_eq!(
        admit(&at_two, std::slice::from_ref(&r1)).expect("older"),
        Relation::Known
    );
    // A sibling: generation 1 forced on controller 3, a voter of the parent history.
    let s1 = sign(&three, &body(1, None, 3));
    assert_eq!(
        admit(&at_one, std::slice::from_ref(&s1)).expect("sibling"),
        Relation::Sibling
    );
    assert_eq!(
        admit(&at_two, &[s1]).expect("older sibling"),
        Relation::Known
    );
    // A newer history of a parent this controller does not know.
    let stranger = sign(&three, &body(5, Some(Digest([9; 32])), 3));
    assert_eq!(
        admit(&at_two, &[stranger]).expect("unplaced"),
        Relation::Unplaced
    );
    // A descendant not numbered above its parent is not a descendant.
    let flat = sign(&three, &body(1, Some(r1.hash()), 3));
    assert_eq!(admit(&at_one, &[flat]).expect("flat"), Relation::Unplaced);
    // Not one lineage.
    refused(
        admit(&zero, &[r2.clone(), s_unlinked(&three)]),
        "not one lineage",
    );
}

fn s_unlinked(signer: &Leaf) -> GenerationRecord {
    sign(signer, &body(3, Some(Digest([4; 32])), 3))
}

#[test]
fn a_signer_without_standing_fences_nothing() {
    let ca = ca();
    let two = leaf(&ca, 2, "controller");
    let r1 = sign(&two, &body(1, None, 2));
    let zero = Lineage::default();
    let admit = |standing: &Standing| zero.admit(std::slice::from_ref(&r1), &ca.root, standing);

    refused(admit(&Standing::default()), "not a voter");
    let mut superseded = standing(&[(2, &two.serial)]);
    superseded.superseded.insert(NodeId(2));
    refused(admit(&superseded), "superseded");
    let mut revoked = standing(&[(2, &two.serial)]);
    revoked.revoked_serials.insert(two.serial.clone());
    refused(admit(&revoked), "revoked");
    let mut revoked_node = standing(&[(2, &two.serial)]);
    revoked_node.revoked_nodes.insert(NodeId(2));
    refused(admit(&revoked_node), "revoked");
    // A voter whose certificate the store does not know: stop and show, never act on it.
    let unknown = standing(&[(2, "00ff")]);
    assert_eq!(
        admit(&unknown).expect("unknown").relation,
        Relation::Unplaced
    );
    // From the future.
    let mut early = standing(&[(2, &two.serial)]);
    early.now = Timestamp::from_unix_nanos(AT - 3_600_000_000_000).expect("time");
    refused(admit(&early), "in the future");
    // A sibling signed by a node that was not a voter of the parent history.
    let nine = leaf(&ca, 9, "controller");
    let at_one = Lineage::kept(std::slice::from_ref(&r1)).expect("lineage");
    refused(
        at_one.admit(
            &[sign(&nine, &body(1, None, 9))],
            &ca.root,
            &standing(&[(9, &nine.serial)]),
        ),
        "not a voter of the parent history",
    );
}

/// A record that `kept` reads without a signature, for the order's property test.
fn unsigned(leaf: &Leaf, body: &GenerationBody) -> Signed {
    Signed::kept(&GenerationRecord {
        body: HexBytes(body.canonical().expect("cbor")),
        signature: HexBytes(Vec::new()),
        chain: leaf
            .chain
            .iter()
            .map(|cert| HexBytes(cert.to_vec()))
            .collect(),
    })
    .expect("kept")
}

#[test]
fn the_suggested_winner_is_a_total_transitive_order() {
    let ca = ca();
    let signer = leaf(&ca, 1, "controller");
    // A small generator: every combination of number, parent, fork, forced node and nonce
    // that the order can tell apart, so that cycles between mixed parents show.
    let parents = [None, Some(Digest([1; 32])), Some(Digest([2; 32]))];
    let mut records = Vec::new();
    let mut seed: u64 = 0x5eed;
    for number in 1..=2 {
        for parent in parents {
            for index in [5, 10] {
                for forced in [1, 2, 3] {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let mut body = body(number, parent, forced);
                    body.superseded.retain(|node| node.0 != forced);
                    body.fork.index = index;
                    body.nonce = HexBytes(seed.to_be_bytes().repeat(2));
                    records.push(unsigned(&signer, &body));
                }
            }
        }
    }
    // The review's cycle: a beats b on the fork, b beats c and c beats a on the node id.
    let a = records
        .iter()
        .find(|r| {
            r.number() == 2
                && r.parent() == parents[1]
                && r.body().is_some_and(|b| b.fork.index == 10)
                && r.forced() == NodeId(3)
        })
        .expect("a");
    let b = records
        .iter()
        .find(|r| {
            r.number() == 2
                && r.parent() == parents[1]
                && r.body().is_some_and(|b| b.fork.index == 5)
                && r.forced() == NodeId(1)
        })
        .expect("b");
    let c = records
        .iter()
        .find(|r| r.number() == 2 && r.parent() == parents[2] && r.forced() == NodeId(2))
        .expect("c");
    let ab = suggested_winner(a, b);
    let bc = suggested_winner(b, c);
    let ac = suggested_winner(a, c);
    assert!(!(ab.is_lt() && bc.is_lt() && ac.is_gt()), "a cycle");
    for x in &records {
        assert_eq!(suggested_winner(x, x), Ordering::Equal);
        for y in &records {
            assert_eq!(suggested_winner(x, y), suggested_winner(y, x).reverse());
            if x.hash() != y.hash() {
                assert_ne!(suggested_winner(x, y), Ordering::Equal);
            }
            for z in &records {
                if suggested_winner(x, y).is_le() && suggested_winner(y, z).is_le() {
                    assert!(suggested_winner(x, z).is_le(), "not transitive");
                }
            }
        }
    }
    // Every member sorts any subset the same way.
    let mut forward = records.clone();
    forward.sort_by(suggested_winner);
    let mut backward: Vec<Signed> = records.iter().rev().cloned().collect();
    backward.sort_by(suggested_winner);
    assert_eq!(forward, backward);
}

#[test]
fn the_fence_file_round_trips_and_an_unknown_kind_is_strict() {
    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    let dir = tenko_core::testing::TempDir::new("generation-fence");
    assert_eq!(FenceFile::load(dir.path()).expect("load"), None);
    let fence = FenceFile {
        kind: FenceReason::Superseded,
        records: vec![sign(&signer, &body(1, None, 2))],
        at: Timestamp::now(),
    };
    fence.save(dir.path()).expect("save");
    assert_eq!(FenceFile::load(dir.path()).expect("load"), Some(fence));
    let unknown: FenceReason = from_cbor(&to_cbor("later_kind").expect("cbor")).expect("kind");
    assert_eq!(unknown.code(), codes::SUPERSEDED);
    fs::write(dir.path().join(NODE_DIR).join(FENCE_FILE), b"\xff").expect("write");
    let error = FenceFile::load(dir.path()).expect_err("an unreadable fence");
    assert_eq!(error.code(), "cluster.node.files");
    assert!(error.detail().contains(FENCE_FILE), "{}", error.detail());
}

#[test]
fn the_superseded_mark_layout_is_pinned() {
    let mark = SupersededMark {
        generation: 1,
        record: Digest([1; 32]),
        rejoin: true,
    };
    let bytes = to_cbor(&mark).expect("cbor");
    assert_eq!(
        to_hex(&bytes),
        format!(
            "a36a67656e65726174696f6e01667265636f72645820{}6672656a6f696ef5",
            "01".repeat(32)
        )
    );
    assert_eq!(from_cbor::<SupersededMark>(&bytes).expect("decode"), mark);
}

#[test]
fn the_record_lineage_and_fence_layouts_are_pinned() {
    let record = GenerationRecord {
        body: HexBytes(vec![0xa0]),
        signature: HexBytes(vec![9; 4]),
        chain: vec![HexBytes(vec![1, 2])],
    };
    let encoded = "a364626f647941a0697369676e6174757265440909090965636861696e81420102";
    assert_eq!(to_hex(&record.encode().expect("cbor")), encoded);
    assert_eq!(
        to_hex(&encode_lineage(std::slice::from_ref(&record)).expect("cbor")),
        format!("81{encoded}")
    );
    let fence = FenceFile {
        kind: FenceReason::Conflict,
        records: vec![record],
        at: Timestamp::from_unix_nanos(AT).expect("time"),
    };
    assert_eq!(
        to_hex(&to_cbor(&fence).expect("cbor")),
        concat!(
            "a3646b696e6468636f6e666c696374677265636f72647381a364626f647941a0697369676e",
            "6174757265440909090965636861696e8142010262617474323032362d30392d313054",
            "30303a32363a34305a",
        )
    );
}
