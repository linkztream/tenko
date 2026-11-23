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

/// A certificate of `node` with `role`, and its key.
struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: SecretBytes,
}

fn leaf(ca: &Ca, node: u64, role: &str) -> Leaf {
    leaf_until(ca, node, role, 2099)
}

/// A certificate of `node` with `role` that ends on the first day of `year`.
fn leaf_until(ca: &Ca, node: u64, role: &str, year: i32) -> Leaf {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.subject_alt_names = vec![
        rcgen::SanType::URI(format!("urn:tenko:node:{node}").try_into().expect("uri")),
        rcgen::SanType::URI(format!("urn:tenko:role:{role}").try_into().expect("uri")),
    ];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(year, 1, 1);
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf");
    Leaf {
        chain: vec![cert.der().clone()],
        key: SecretBytes::from_slice(&key.serialize_der()),
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
    let admission = Lineage::default()
        .admit(&[record], &ca.root)
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

#[test]
fn relations_follow_the_lineage() {
    let ca = ca();
    let two = leaf(&ca, 2, "controller");
    let three = leaf(&ca, 3, "controller");
    let r1 = sign(&two, &body(1, None, 2));
    let mut b2 = body(2, Some(r1.hash()), 2);
    b2.at = Timestamp::from_unix_nanos(AT + 1).expect("time");
    let r2 = sign(&two, &b2);
    let zero = Lineage::default();
    let admit = |lineage: &Lineage, offer: &[GenerationRecord]| {
        lineage.admit(offer, &ca.root).map(|a| a.relation)
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

/// The rule: a record counts when a controller's certificate of the installation's CA
/// signed it, whatever the receiver knows of that certificate. One minted for a node id the
/// receiver never saw stops it like any other (the owner accepts that whoever holds the CA's
/// key can stop the cluster); one of another role, or of another CA, never verifies.
#[test]
fn a_controller_certificate_of_the_ca_is_all_a_record_needs() {
    let ca = ca();
    let minted = leaf(&ca, 99, "controller");
    let zero = Lineage::default();
    let record = sign(&minted, &body(1, None, 99));
    assert_eq!(
        zero.admit(std::slice::from_ref(&record), &ca.root)
            .expect("counts")
            .relation,
        Relation::Descendant
    );
    let at_one =
        Lineage::kept(&[sign(&leaf(&ca, 1, "controller"), &body(1, None, 1))]).expect("lineage");
    assert_eq!(
        at_one
            .admit(&[sign(&minted, &body(1, None, 99))], &ca.root)
            .expect("counts")
            .relation,
        Relation::Sibling
    );
    let probe = leaf(&ca, 7, "probe");
    refused(zero.admit(&[sign(&probe, &body(1, None, 7))], &ca.root), "");
    let foreign = leaf(&self::ca(), 2, "controller");
    refused(
        zero.admit(&[sign(&foreign, &body(1, None, 2))], &ca.root),
        "",
    );
}

/// No difference of clocks makes a receiver ignore a record: a record dated far ahead of
/// the receiver counts, a lineage whose later record carries the earlier date (two hosts
/// whose clocks disagree) is still one lineage, and a signer's certificate that expired
/// before the record's date does not refuse it.
#[test]
fn the_time_a_record_claims_never_refuses_it() {
    let ca = ca();
    let one = leaf(&ca, 1, "controller");
    let ahead = GenerationBody {
        at: Timestamp::from_unix_nanos(AT + 10 * 365 * 86_400 * 1_000_000_000).expect("time"),
        ..body(1, None, 1)
    };
    let first = sign(&one, &ahead);
    let behind = GenerationBody {
        at: Timestamp::from_unix_nanos(AT - 86_400 * 1_000_000_000).expect("time"),
        ..body(2, Some(first.hash()), 1)
    };
    let admission = Lineage::default()
        .admit(&[first, sign(&one, &behind)], &ca.root)
        .expect("counts");
    assert_eq!(admission.relation, Relation::Descendant);
    assert_eq!(admission.new.len(), 2);
    // Signed with a certificate that ended years before the record's date: a controller
    // that was off longer than its certificate lasted, forced on its return.
    let expired = leaf_until(&ca, 2, "controller", 2021);
    assert_eq!(
        Lineage::default()
            .admit(&[sign(&expired, &body(1, None, 2))], &ca.root)
            .expect("counts")
            .relation,
        Relation::Descendant
    );
}

/// The envelope of a record is frozen (its bytes are pinned in
/// `the_record_lineage_and_fence_layouts_are_pinned`): one with a field a later version
/// might add is refused, so a later version puts what it needs into a new body layout.
#[test]
fn an_envelope_with_a_later_field_is_refused() {
    #[derive(Serialize)]
    struct Later {
        body: HexBytes,
        signature: HexBytes,
        chain: Vec<HexBytes>,
        extra: HexBytes,
    }
    let later = to_cbor(&Later {
        body: HexBytes(vec![0xa0]),
        signature: HexBytes(vec![9; 4]),
        chain: vec![HexBytes(vec![1, 2])],
        extra: HexBytes(vec![4]),
    })
    .expect("cbor");
    refused(GenerationRecord::decode(&later), "exact encoding");
}

#[test]
fn the_fence_file_round_trips_and_an_unknown_kind_is_strict() {
    /// The fence file as a binary without the detail reads it.
    #[derive(serde::Deserialize)]
    struct Older {
        kind: FenceReason,
        records: Vec<GenerationRecord>,
        at: Timestamp,
    }

    let ca = ca();
    let signer = leaf(&ca, 2, "controller");
    let dir = tenko_core::testing::TempDir::new("generation-fence");
    assert_eq!(FenceFile::load(dir.path()).expect("load"), None);
    let fence = FenceFile {
        kind: FenceReason::Superseded,
        records: vec![sign(&signer, &body(1, None, 2))],
        at: Timestamp::now(),
        detail: None,
    };
    fence.save(dir.path()).expect("save");
    assert_eq!(FenceFile::load(dir.path()).expect("load"), Some(fence));
    // A binary that knows only the first three fields reads a file with what the store found.
    let found = FenceFile {
        kind: FenceReason::Diverged,
        records: Vec::new(),
        at: Timestamp::now(),
        detail: Some("node 2 sent 3-2-10".to_owned()),
    };
    let older: Older = from_cbor(&to_cbor(&found).expect("cbor")).expect("an older reader");
    assert_eq!(
        (older.kind, older.records.len(), older.at),
        (FenceReason::Diverged, 0, found.at)
    );
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
    };
    let bytes = to_cbor(&mark).expect("cbor");
    assert_eq!(
        to_hex(&bytes),
        format!(
            "a26a67656e65726174696f6e01667265636f72645820{}",
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
        detail: None,
    };
    let bytes = to_cbor(&fence).expect("cbor");
    assert_eq!(
        from_cbor::<FenceFile>(&bytes).expect("a file without a detail"),
        fence
    );
    assert_eq!(
        to_hex(&bytes),
        concat!(
            "a3646b696e6468636f6e666c696374677265636f72647381a364626f647941a0697369676e",
            "6174757265440909090965636861696e8142010262617474323032362d30392d313054",
            "30303a32363a34305a",
        )
    );
}

/// One controller of a cluster in the model of forced steps and meetings: its history, its
/// fence, its voters, whether it saw an older history, and what the rule must not depend on:
/// its current certificate (renewed at will) and the controllers it revoked or marked
/// superseded.
struct Side {
    node: u64,
    leaf: Leaf,
    lineage: Lineage,
    fence: Option<(FenceReason, Lineage)>,
    voters: BTreeSet<NodeId>,
    saw_older: bool,
    revoked: BTreeSet<NodeId>,
    marks: BTreeSet<NodeId>,
}

impl Side {
    /// What it offers on a call: its history, and the records that superseded it.
    fn offer(&self) -> Vec<GenerationRecord> {
        let mut records = self.lineage.offer();
        if let Some((FenceReason::Superseded, fence)) = &self.fence {
            records.extend(fence.records().iter().map(|signed| signed.record().clone()));
        }
        records
    }

    /// An authority: it writes (not fenced).
    fn writes(&self) -> bool {
        self.fence.is_none()
    }

    /// Whether its history holds `record`.
    fn holds(&self, hash: Digest) -> bool {
        self.lineage.records().iter().any(|own| own.hash() == hash)
    }
}

/// A small deterministic generator for the property tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self, below: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(below).expect("small")).expect("small")
    }
}

/// A forced step on `side`, as `tenko cluster recover --force` makes it: allowed on a copy
/// with other voters, or on one another history stopped; the new generation is above every
/// one it has seen; its other voters are superseded and marked.
fn force(side: &mut Side, clock: &mut i128) {
    if side.voters.len() == 1 && side.fence.is_none() {
        return;
    }
    let seen = side
        .lineage
        .number()
        .max(side.fence.as_ref().map_or(0, |(_, fence)| fence.number()));
    *clock += 1;
    let others: BTreeSet<NodeId> = side
        .voters
        .iter()
        .copied()
        .filter(|voter| voter.0 != side.node)
        .collect();
    let body = GenerationBody {
        parent: side.lineage.tip().map(Signed::hash),
        superseded: others.iter().copied().collect(),
        at: Timestamp::from_unix_nanos(AT + *clock).expect("time"),
        nonce: HexBytes([side.node.to_be_bytes(), (seen + 1).to_be_bytes()].concat()),
        ..body(seen + 1, None, side.node)
    };
    let mut records = side.lineage.offer();
    records.push(sign(&side.leaf, &body));
    side.lineage = Lineage::kept(&records).expect("lineage");
    side.marks.extend(others);
    side.voters = [NodeId(side.node)].into_iter().collect();
    side.fence = None;
}

/// `to` receives what another side offers, as `Peers::offer` acts on it.
fn receive(to: &mut Side, offer: &[GenerationRecord], root: &CertificateDer<'_>) {
    let Ok(admission) = to.lineage.admit(offer, root) else {
        return;
    };
    if admission.relation == Relation::Known && !admission.new.is_empty() {
        to.saw_older = true;
    }
    if let Some((reason, records)) = next_fence(to.fence.as_ref(), &admission) {
        to.fence = Some((reason, Lineage::kept(&records).expect("fence")));
    }
}

/// One step of a generated sequence.
#[derive(Debug, Clone, Copy)]
enum Act {
    /// A forced step on a side.
    Force(usize),
    /// A side renews its certificate: a new key and serial that no other side knows.
    Renew(usize),
    /// A side revokes another's certificates.
    Revoke(usize, usize),
    /// A side marks another superseded.
    Mark(usize, usize),
    /// Two sides exchange their records: the cluster port grants that exchange to every
    /// controller certificate of the CA, revoked or not.
    Meet(usize, usize),
}

/// Runs `acts` on `sides` and checks after each meeting: when two controllers that both
/// write, of different histories, exchange their records, at least one stops writing, and
/// each forced one shows the other's history (its fence, or the older history it saw).
fn run(sides: &mut [Side], acts: &[Act], ca: &Ca) {
    let mut clock = 0;
    for (index, act) in acts.iter().enumerate() {
        let (a, b) = match *act {
            Act::Force(a) => {
                force(&mut sides[a], &mut clock);
                continue;
            }
            Act::Renew(who) => {
                sides[who].leaf = leaf(ca, sides[who].node, "controller");
                continue;
            }
            Act::Revoke(by, whom) => {
                let node = NodeId(sides[whom].node);
                sides[by].revoked.insert(node);
                continue;
            }
            Act::Mark(by, whom) => {
                let node = NodeId(sides[whom].node);
                sides[by].marks.insert(node);
                continue;
            }
            Act::Meet(a, b) => (a, b),
        };
        // Different histories: neither holds the other's newest record (a side at
        // generation 0, the old majority, has none and is apart from every forced side).
        let tip = |side: &Side| side.lineage.tip().map(Signed::hash);
        let (tip_a, tip_b) = (tip(&sides[a]), tip(&sides[b]));
        let apart = tip_a != tip_b
            && tip_a.is_none_or(|hash| !sides[b].holds(hash))
            && tip_b.is_none_or(|hash| !sides[a].holds(hash));
        let both_wrote = sides[a].writes() && sides[b].writes();
        let (offer_a, offer_b) = (sides[a].offer(), sides[b].offer());
        receive(&mut sides[b], &offer_a, &ca.root);
        receive(&mut sides[a], &offer_b, &ca.root);
        if both_wrote && apart {
            assert!(
                !sides[a].writes() || !sides[b].writes(),
                "two authorities met and both still write after {:?}",
                &acts[..=index]
            );
            // A side at generation 0 offers no record, so only two forced sides show
            // each other.
            for side in [a, b]
                .into_iter()
                .filter(|_| tip_a.is_some() && tip_b.is_some())
            {
                assert!(
                    !sides[side].writes() || sides[side].saw_older,
                    "side {side} does not show the other history after {:?}",
                    &acts[..=index]
                );
            }
        }
    }
}

/// The cluster's promise after any sequence of forced steps by any number of operators:
/// two controllers that both believe they are the authority stop at least one of them when
/// they exchange one call, and both show the other's history. Generated sequences of forced
/// steps, renewals, revocations, superseded marks and meetings among two and three
/// controllers of one cluster, plus written ones: two operators who each chose their own
/// side after a conflict, and two forced sides that both renewed after the fork, one of them
/// revoked by the other.
#[test]
fn two_authorities_that_meet_never_both_go_on_writing() {
    use Act::{Force, Mark, Meet, Renew, Revoke};
    let ca = ca();
    let sides = |count: u64| -> Vec<Side> {
        let voters: BTreeSet<NodeId> = (1..=count).map(NodeId).collect();
        (1..=count)
            .map(|node| Side {
                node,
                leaf: leaf(&ca, node, "controller"),
                lineage: Lineage::default(),
                fence: None,
                voters: voters.clone(),
                saw_older: false,
                revoked: BTreeSet::new(),
                marks: BTreeSet::new(),
            })
            .collect()
    };
    run(
        &mut sides(3),
        &[
            Force(0),
            Force(1),
            Meet(0, 1),
            Force(0),
            Meet(0, 1),
            Force(1),
            Meet(0, 1),
            Meet(1, 0),
        ],
        &ca,
    );
    run(
        &mut sides(2),
        &[
            Force(0),
            Force(1),
            Renew(0),
            Renew(1),
            Revoke(0, 1),
            Mark(1, 0),
            Meet(0, 1),
            Force(0),
            Force(1),
            Renew(1),
            Meet(1, 0),
        ],
        &ca,
    );
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for count in [2_u64, 3] {
        let n = usize::try_from(count).expect("small");
        for _ in 0..300 {
            let mut sides = sides(count);
            let acts: Vec<Act> = (0..=rng.next(16))
                .map(|_| match rng.next(7) {
                    0 => Renew(rng.next(n)),
                    1 => Revoke(rng.next(n), rng.next(n)),
                    2 => Mark(rng.next(n), rng.next(n)),
                    3 => Force(rng.next(n)),
                    _ => Meet(rng.next(n), rng.next(n)),
                })
                .filter(|act| !matches!(act, Meet(a, b) if a == b))
                .collect();
            run(&mut sides, &acts, &ca);
        }
    }
}
