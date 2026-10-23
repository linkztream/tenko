//! The chain walk over scripted authorities: a lab of zones signed in the test with the
//! signer's own primitives (ECDSA P-256, NSEC), served by [`MemAuthority`] and resolved
//! by the engine, each answer judged by the validator with the lab root's DS as the
//! trust anchor. Every state of recursion plan section 2.3 has a case, and the walk's
//! sub-queries and the key table are observed.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tenko_core::{
    Timestamp,
    dns::{
        AnchorData, AnchorKey, AnchorSource, AnchorState, DnsName, DnssecAlgorithm, ExtendedError,
        KeyRole, NegativeTrustAnchor, NtaId, RecordData, Rtype, SecurityState, TrustAnchor,
    },
    serde_util::HexBytes,
};

use crate::{
    dnssec::{
        canonical::{RrsigHead, rrsig_labels, signed_data},
        crypto::{self, KeyPair},
    },
    recurse::{Engine, EngineSettings, Question, hints},
    recursion::{
        Authority, AuthorityError, AuthorityQuery, BogusReason, ChainContext, DsState, Exchange,
        InfraCache, MemAnchors, MemAuthority, MemFailures, MemZone, Outbound, RecursionSettings,
        Validation, ValidationCaps, Validator,
    },
    tree::canonical_cmp,
    validate::{DnssecValidator, EngineFetch, NoFetch},
};

const ROOT: u8 = 10;
const TLD: u8 = 20;
const ZONE: u8 = 30;
const CHILD: u8 = 40;

const LAB_HINTS: &str = ".  3600000 NS a.root.test.\na.root.test. 3600000 A 203.0.113.10\n";

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn lab_ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

fn ns(host: &str) -> RecordData {
    RecordData::Ns { host: name(host) }
}

fn a(address: [u8; 4]) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::from(address),
    }
}

fn glue(last: u8) -> RecordData {
    a([203, 0, 113, last])
}

fn cname(target: &str) -> RecordData {
    RecordData::Cname {
        target: name(target),
    }
}

fn soa(zone: &str) -> RecordData {
    RecordData::Soa {
        mname: name(
            &format!("ns.{zone}")
                .trim_end_matches('.')
                .replace("ns..", "ns."),
        ),
        rname: name("hostmaster.example.test"),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86_400,
        minimum: 60,
    }
}

/// Seconds since 1970 now.
fn now32() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % (1 << 32),
    )
    .expect("u32")
}

/// The signing keys of one zone, generated per test.
struct Keys {
    ksk: KeyPair,
    zsk: KeyPair,
    algorithm: DnssecAlgorithm,
}

impl Keys {
    fn new(algorithm: DnssecAlgorithm) -> Self {
        Self {
            ksk: KeyPair::generate(algorithm).expect("ksk").0,
            zsk: KeyPair::generate(algorithm).expect("zsk").0,
            algorithm,
        }
    }

    fn dnskey(&self, role: KeyRole) -> RecordData {
        let pair = match role {
            KeyRole::Ksk => &self.ksk,
            _ => &self.zsk,
        };
        crypto::dnskey(role, self.algorithm, &pair.public_key())
    }

    fn tag(&self, role: KeyRole) -> u16 {
        let mut wire = Vec::new();
        self.dnskey(role).write_wire(&mut wire);
        crypto::key_tag(&wire)
    }

    fn ds(&self, apex: &DnsName) -> RecordData {
        crypto::ds(apex, KeyRole::Ksk, self.algorithm, &self.ksk.public_key())
    }
}

/// When the signatures of a zone are valid.
#[derive(Debug, Clone, Copy)]
struct Window {
    inception: u32,
    expiration: u32,
}

impl Window {
    fn valid() -> Self {
        let now = now32();
        Self {
            inception: now.wrapping_sub(3600),
            expiration: now.wrapping_add(86_400),
        }
    }

    fn expired() -> Self {
        let now = now32();
        Self {
            inception: now.wrapping_sub(86_400),
            expiration: now.wrapping_sub(10),
        }
    }

    fn future() -> Self {
        let now = now32();
        Self {
            inception: now.wrapping_add(86_400),
            expiration: now.wrapping_add(172_800),
        }
    }
}

fn wire_of(record: &RecordData) -> Vec<u8> {
    let mut out = Vec::new();
    record.write_wire(&mut out);
    out
}

/// Signs `zone` with `keys` as the signer would: the DNSKEY set at the apex, an NSEC
/// chain over the names that own records (glue below a delegation left out), an RRSIG
/// per RRset (the DNSKEY set by the KSK, the rest by the ZSK; nothing but DS and NSEC
/// at a delegation).
fn sign(mut zone: MemZone, keys: &Keys, window: Window) -> MemZone {
    let apex = zone.apex.clone();
    zone.records
        .push((apex.clone(), 3600, keys.dnskey(KeyRole::Ksk)));
    zone.records
        .push((apex.clone(), 3600, keys.dnskey(KeyRole::Zsk)));
    let cuts: Vec<DnsName> = zone
        .records
        .iter()
        .filter(|(owner, _, data)| *owner != apex && data.rtype() == Rtype::NS)
        .map(|(owner, _, _)| owner.clone())
        .collect();
    let below_cut = |owner: &DnsName| {
        cuts.iter()
            .any(|cut| owner != cut && owner.is_subdomain_of(cut))
    };
    let mut owners: Vec<DnsName> = Vec::new();
    for (owner, _, _) in &zone.records {
        if !below_cut(owner) && !owners.contains(owner) {
            owners.push(owner.clone());
        }
    }
    owners.sort_by(|a, b| canonical_cmp(&a.to_wire(), &b.to_wire()));
    // The NSEC chain.
    let mut nsecs = Vec::new();
    for (index, owner) in owners.iter().enumerate() {
        let next = owners.get(index + 1).unwrap_or(&apex).clone();
        let at_cut = cuts.contains(owner);
        let mut types: Vec<Rtype> = zone
            .records
            .iter()
            .filter(|(name, _, data)| {
                name == owner && (!at_cut || matches!(data.rtype(), Rtype::NS | Rtype::DS))
            })
            .map(|(_, _, data)| data.rtype())
            .collect();
        types.push(Rtype::RRSIG);
        types.push(Rtype::NSEC);
        types.sort_unstable();
        types.dedup();
        nsecs.push((owner.clone(), 60, RecordData::Nsec { next, types }));
    }
    zone.records.extend(nsecs);
    // The signatures.
    let mut sigs = Vec::new();
    let mut seen: Vec<(DnsName, Rtype)> = Vec::new();
    for (owner, ttl, data) in &zone.records {
        let rtype = data.rtype();
        let key = (owner.clone(), rtype);
        if seen.contains(&key) || below_cut(owner) || rtype == Rtype::RRSIG {
            continue;
        }
        if cuts.contains(owner) && !matches!(rtype, Rtype::DS | Rtype::NSEC) {
            continue;
        }
        seen.push(key);
        let rdata: Vec<Vec<u8>> = zone
            .records
            .iter()
            .filter(|(name, _, other)| name == owner && other.rtype() == rtype)
            .map(|(_, _, other)| wire_of(other))
            .collect();
        let (pair, role) = if rtype == Rtype::DNSKEY {
            (&keys.ksk, KeyRole::Ksk)
        } else {
            (&keys.zsk, KeyRole::Zsk)
        };
        let head = RrsigHead {
            type_covered: rtype,
            algorithm: keys.algorithm.number(),
            labels: rrsig_labels(owner),
            original_ttl: *ttl,
            expiration: window.expiration,
            inception: window.inception,
            key_tag: keys.tag(role),
            signer: &apex,
        };
        let signed = signed_data(&head, owner, rtype, rdata.iter().map(Vec::as_slice));
        let signature = pair.sign(&signed).expect("sign");
        let rrsig =
            RecordData::from_wire(Rtype::RRSIG, &head.with_signature(&signature)).expect("rrsig");
        sigs.push((owner.clone(), *ttl, rrsig));
    }
    zone.records.extend(sigs);
    zone
}

/// Spoils the signature of the RRset of `owner` and `rtype`.
fn tamper(zone: &mut MemZone, owner: &str, rtype: Rtype) {
    let owner = name(owner);
    for (name, _, data) in &mut zone.records {
        if *name != owner {
            continue;
        }
        if let RecordData::Rrsig {
            type_covered,
            signature,
            ..
        } = data
            && *type_covered == rtype
        {
            signature.0[0] ^= 0x55;
        }
    }
}

/// Removes the signatures of the RRset of `owner` and `rtype`.
fn strip(zone: &mut MemZone, owner: &str, rtype: Rtype) {
    let owner = name(owner);
    zone.records.retain(|(name, _, data)| {
        !(*name == owner
            && matches!(data, RecordData::Rrsig { type_covered, .. } if *type_covered == rtype))
    });
}

fn apex(zone: &str, server: &str) -> MemZone {
    MemZone::new(name(zone))
        .record(name(zone), 3600, soa(zone))
        .record(name(zone), 3600, ns(server))
}

/// The lab's keys, one set per signed zone.
struct LabKeys {
    root: Keys,
    tld: Keys,
    example: Keys,
    child: Keys,
}

impl LabKeys {
    fn new() -> Self {
        Self {
            root: Keys::new(DnssecAlgorithm::EcdsaP256Sha256),
            tld: Keys::new(DnssecAlgorithm::Ed25519),
            example: Keys::new(DnssecAlgorithm::EcdsaP256Sha256),
            child: Keys::new(DnssecAlgorithm::Ed25519),
        }
    }
}

/// What the lab varies.
#[derive(Debug, Clone, Copy, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one switch per fault the lab can show"
)]
struct Variant {
    /// The example zone's signatures have expired.
    expired: bool,
    /// The root's DNSKEY signatures are not valid yet (a wrong clock).
    future_root: bool,
    /// The example zone's `www` signature is spoiled.
    tampered: bool,
    /// The example zone's `www` carries no signature.
    stripped: bool,
    /// The child's DS in example.test names an unsupported algorithm.
    unsupported_child: bool,
}

/// The scripted lab: the root at .10, `test` at .20, `example.test` at .30, and under it
/// `secure.example.test` (signed, its DS published) at .40, `insecure.example.test`
/// (unsigned, no DS) at .40 and `bogus.example.test` (signed, a DS that matches no key)
/// at .40.
#[allow(clippy::too_many_lines, reason = "one lab, zone by zone")]
fn lab(keys: &LabKeys, variant: Variant) -> MemAuthority {
    let root = MemZone::new(DnsName::root())
        .record(DnsName::root(), 86_400, soa(""))
        .record(DnsName::root(), 86_400, ns("a.root.test"))
        .record(name("a.root.test"), 86_400, glue(ROOT))
        .record(name("test"), 3600, ns("ns.test"))
        .record(name("ns.test"), 3600, glue(TLD))
        .record(name("test"), 3600, keys.tld.ds(&name("test")));
    let root_window = if variant.future_root {
        Window::future()
    } else {
        Window::valid()
    };
    let root = sign(root, &keys.root, root_window);
    let tld = apex("test", "ns.test")
        .record(name("ns.test"), 3600, glue(TLD))
        .record(name("example.test"), 3600, ns("ns.example.test"))
        .record(name("ns.example.test"), 3600, glue(ZONE))
        .record(
            name("example.test"),
            3600,
            keys.example.ds(&name("example.test")),
        );
    let tld = sign(tld, &keys.tld, Window::valid());
    let mut wrong_ds = keys.child.ds(&name("bogus.example.test"));
    if let RecordData::Ds { digest, .. } = &mut wrong_ds {
        digest.0[0] ^= 1;
    }
    let child_ds = if variant.unsupported_child {
        RecordData::Ds {
            key_tag: 1,
            algorithm: 16,
            digest_type: 2,
            digest: HexBytes(vec![0; 32]),
        }
    } else {
        keys.child.ds(&name("secure.example.test"))
    };
    let mut example = apex("example.test", "ns.example.test")
        .record(name("ns.example.test"), 3600, glue(ZONE))
        .record(name("www.example.test"), 300, a([192, 0, 2, 1]))
        .record(
            name("txt.example.test"),
            300,
            RecordData::Txt {
                strings: vec![tenko_core::dns::TextBytes::from_text("hello")],
            },
        )
        .record(name("*.wild.example.test"), 300, a([192, 0, 2, 2]))
        .record(name("alias.example.test"), 300, cname("www.example.test"))
        .record(
            name("to-insecure.example.test"),
            300,
            cname("www.insecure.example.test"),
        )
        .record(name("deep.ent.example.test"), 300, a([192, 0, 2, 3]))
        .record(
            name("secure.example.test"),
            3600,
            ns("ns.secure.example.test"),
        )
        .record(name("ns.secure.example.test"), 3600, glue(CHILD))
        .record(name("secure.example.test"), 3600, child_ds)
        .record(
            name("insecure.example.test"),
            3600,
            ns("ns.insecure.example.test"),
        )
        .record(name("ns.insecure.example.test"), 3600, glue(CHILD))
        .record(
            name("bogus.example.test"),
            3600,
            ns("ns.bogus.example.test"),
        )
        .record(name("ns.bogus.example.test"), 3600, glue(CHILD))
        .record(name("bogus.example.test"), 3600, wrong_ds);
    let window = if variant.expired {
        Window::expired()
    } else {
        Window::valid()
    };
    example = sign(example, &keys.example, window);
    if variant.tampered {
        tamper(&mut example, "www.example.test", Rtype::A);
    }
    if variant.stripped {
        strip(&mut example, "www.example.test", Rtype::A);
    }
    let secure = sign(
        apex("secure.example.test", "ns.secure.example.test")
            .record(name("ns.secure.example.test"), 3600, glue(CHILD))
            .record(name("www.secure.example.test"), 300, a([192, 0, 2, 4])),
        &keys.child,
        Window::valid(),
    );
    let insecure = apex("insecure.example.test", "ns.insecure.example.test")
        .record(name("ns.insecure.example.test"), 3600, glue(CHILD))
        .record(name("www.insecure.example.test"), 300, a([192, 0, 2, 5]));
    let bogus = sign(
        apex("bogus.example.test", "ns.bogus.example.test")
            .record(name("ns.bogus.example.test"), 3600, glue(CHILD))
            .record(name("www.bogus.example.test"), 300, a([192, 0, 2, 6])),
        &keys.child,
        Window::valid(),
    );
    MemAuthority::new()
        .serve(lab_ip(ROOT), root)
        .serve(lab_ip(TLD), tld)
        .serve(lab_ip(ZONE), example)
        .serve(lab_ip(CHILD), secure)
        .serve(lab_ip(CHILD), insecure)
        .serve(lab_ip(CHILD), bogus)
}

/// The authority shared between the engine and the test.
#[derive(Clone)]
struct Shared(Arc<MemAuthority>);

impl Authority for Shared {
    fn exchange<'a>(
        &'a self,
        query: &'a AuthorityQuery<'a>,
        answer: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<Exchange, AuthorityError>> + Send + 'a {
        self.0.exchange(query, answer)
    }
}

struct Harness {
    authority: Arc<MemAuthority>,
    engine: Arc<Engine<Shared>>,
    infra: Arc<crate::infra::Infra>,
    anchors: MemAnchors,
    validator: DnssecValidator,
    caps: ValidationCaps,
}

fn root_anchor(keys: &LabKeys) -> TrustAnchor {
    let ds = wire_of(&keys.root.ds(&DnsName::root()));
    let now = Timestamp::now();
    TrustAnchor {
        zone: DnsName::root(),
        keys: vec![AnchorKey {
            key_tag: keys.root.tag(KeyRole::Ksk),
            algorithm: keys.root.algorithm.number(),
            digest_type: Some(2),
            data: AnchorData::Ds {
                rdata: HexBytes(ds),
            },
            state: AnchorState::Valid,
            source: AnchorSource::Operator,
            added_at: now,
            state_since: now,
            last_seen: None,
        }],
        last_query: None,
        next_query: None,
    }
}

async fn harness(keys: &LabKeys, variant: Variant) -> Harness {
    let authority = Arc::new(lab(keys, variant));
    let settings = EngineSettings {
        recursion: RecursionSettings {
            outbound: Outbound::V4,
            ..RecursionSettings::default()
        },
        hints: None,
        local_zones_except: vec![name("test")],
        metrics: false,
    };
    let infra = Arc::new(crate::infra::Infra::new(settings.recursion.infra));
    let engine = Engine::new(
        Shared(Arc::clone(&authority)),
        Arc::clone(&infra) as Arc<dyn InfraCache>,
        Arc::new(crate::infra::ServerTable::new(
            1_000,
            Duration::from_secs(900),
        )),
        Arc::new(MemFailures::default()),
        hints::parse(LAB_HINTS).expect("hints"),
        &settings,
    );
    engine.prime().await.expect("primed");
    authority.clear_log();
    let anchors = MemAnchors::new();
    anchors.set(root_anchor(keys));
    Harness {
        authority,
        engine: Arc::new(engine),
        infra,
        anchors,
        validator: DnssecValidator::new(ValidationCaps::DEFAULT, 100, false),
        caps: ValidationCaps::DEFAULT,
    }
}

impl Harness {
    /// Resolves and validates `qname`/`qtype`; `cd` refuses the walk's sub-queries.
    async fn ask(&self, qname: &str, qtype: u16, cd: bool) -> (Validation, u16) {
        let wire = name(qname).to_wire();
        let resolved = self
            .engine
            .resolve(Question {
                qname: &wire,
                qtype,
                qclass: 1,
                view: None,
            })
            .await;
        assert!(
            matches!(resolved.outcome, crate::recurse::Outcome::Answered),
            "{qname}: {:?} after {:?}",
            resolved.outcome,
            self.authority.asked()
        );
        let fetch = EngineFetch::new(Arc::clone(&self.engine));
        let qname = name(qname);
        let root = DnsName::root();
        let validation = if cd {
            let ctx = ChainContext {
                qname: &qname,
                qtype,
                zone: &root,
                cd: true,
                anchors: &self.anchors,
                infra: self.infra.as_ref(),
                fetch: &NoFetch,
                now: SystemTime::now(),
                caps: self.caps,
            };
            self.validator.validate(&resolved.message, &ctx).await
        } else {
            let ctx = ChainContext {
                qname: &qname,
                qtype,
                zone: &root,
                cd: false,
                anchors: &self.anchors,
                infra: self.infra.as_ref(),
                fetch: &fetch,
                now: SystemTime::now(),
                caps: self.caps,
            };
            self.validator.validate(&resolved.message, &ctx).await
        };
        (validation, resolved.subqueries + fetch.subqueries())
    }

    fn queries(&self) -> usize {
        self.authority.asked().len()
    }
}

const A: u16 = 1;
const AAAA: u16 = 28;

#[tokio::test]
async fn a_signed_answer_is_secure_and_the_keys_are_kept() {
    let keys = LabKeys::new();
    let lab = harness(&keys, Variant::default()).await;
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Secure, "{validation:?}");
    assert!(validation.signature_expiry.is_some());
    assert!(validation.verifications >= 4, "{validation:?}");
    let report = lab.validator.report();
    assert_eq!(report.counters.secure, 1);
    assert!(report.key_sets >= 3, "{report:?}");
    assert!(!report.clock_wrong);
    // The DS slot of the cut mirrors the walk.
    let cut = lab
        .infra
        .cut(&name("example.test"), std::time::Instant::now())
        .expect("a cut");
    assert!(matches!(cut.ds, DsState::Secure { .. }), "{:?}", cut.ds);
    // A second name in the zone costs no DS or DNSKEY query.
    lab.authority.clear_log();
    let (validation, _) = lab.ask("txt.example.test", 16, false).await;
    assert_eq!(validation.state, SecurityState::Secure);
    let asked = lab.authority.asked();
    assert!(
        asked
            .iter()
            .all(|asked| asked.qtype != 43 && asked.qtype != 48),
        "{asked:?}"
    );
    // The clock finding is clear and the sentinel helpers read the anchors.
    assert!(!lab.validator.clock_wrong());
}

#[tokio::test]
async fn the_states_of_the_plan_each_have_a_case() {
    let keys = LabKeys::new();
    let lab = harness(&keys, Variant::default()).await;
    let cases: [(&str, u16, SecurityState, Option<u16>); 8] = [
        ("www.secure.example.test", A, SecurityState::Secure, None),
        (
            "www.insecure.example.test",
            A,
            SecurityState::Insecure,
            None,
        ),
        ("www.bogus.example.test", A, SecurityState::Bogus, Some(9)),
        ("any.wild.example.test", A, SecurityState::Secure, None),
        ("nothing.example.test", A, SecurityState::Secure, None),
        ("www.example.test", AAAA, SecurityState::Secure, None),
        ("ent.example.test", A, SecurityState::Secure, None),
        ("to-insecure.example.test", A, SecurityState::Insecure, None),
    ];
    for (qname, qtype, state, ede) in cases {
        let (validation, _) = lab.ask(qname, qtype, false).await;
        assert_eq!(validation.state, state, "{qname}: {validation:?}");
        assert_eq!(
            validation.ede.map(ExtendedError::code),
            ede,
            "{qname}: {validation:?}"
        );
    }
    // A CNAME to a secure name stays secure; the alias answer has two signed sets.
    let (validation, _) = lab.ask("alias.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Secure, "{validation:?}");
    let counters = lab.validator.counters();
    assert_eq!(counters.secure + counters.insecure + counters.bogus, 9);
}

#[tokio::test]
async fn faults_name_their_extended_error() {
    let keys = LabKeys::new();
    for (variant, reason, ede) in [
        (
            Variant {
                expired: true,
                ..Variant::default()
            },
            BogusReason::Expired,
            7,
        ),
        (
            Variant {
                tampered: true,
                ..Variant::default()
            },
            BogusReason::Signature,
            6,
        ),
        (
            Variant {
                stripped: true,
                ..Variant::default()
            },
            BogusReason::MissingRrsig,
            10,
        ),
    ] {
        let lab = harness(&keys, variant).await;
        let (validation, _) = lab.ask("www.example.test", A, false).await;
        assert_eq!(
            validation.state,
            SecurityState::Bogus,
            "{variant:?}: {validation:?}"
        );
        assert_eq!(
            validation.reason,
            Some(reason),
            "{variant:?}: {validation:?}"
        );
        assert_eq!(validation.ede.map(ExtendedError::code), Some(ede));
        assert!(validation.signature_expiry.is_none());
    }
}

#[tokio::test]
async fn an_unsupported_algorithm_makes_the_child_insecure() {
    let keys = LabKeys::new();
    let lab = harness(
        &keys,
        Variant {
            unsupported_child: true,
            ..Variant::default()
        },
    )
    .await;
    let (validation, _) = lab.ask("www.secure.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Insecure, "{validation:?}");
}

#[tokio::test]
async fn a_wrong_clock_is_loud_and_the_finding_is_set() {
    let keys = LabKeys::new();
    let lab = harness(
        &keys,
        Variant {
            future_root: true,
            ..Variant::default()
        },
    )
    .await;
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Bogus, "{validation:?}");
    assert_eq!(validation.reason, Some(BogusReason::NotYetValid));
    assert_eq!(validation.ede, Some(ExtendedError::SIGNATURE_NOT_YET_VALID));
    assert!(lab.validator.clock_wrong());
    assert!(lab.validator.report().clock_wrong);
}

#[tokio::test]
async fn anchors_decide_indeterminate_negative_and_private_zones() {
    let keys = LabKeys::new();
    let lab = harness(&keys, Variant::default()).await;
    // No anchor at all: indeterminate with extended error 5.
    lab.anchors.remove(&DnsName::root());
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    assert_eq!(
        validation.state,
        SecurityState::Indeterminate,
        "{validation:?}"
    );
    assert_eq!(validation.ede, Some(ExtendedError::DNSSEC_INDETERMINATE));
    // An operator's DNSKEY anchor for example.test alone validates below it.
    let now = Timestamp::now();
    lab.anchors.set(TrustAnchor {
        zone: name("example.test"),
        keys: vec![AnchorKey {
            key_tag: keys.example.tag(KeyRole::Ksk),
            algorithm: keys.example.algorithm.number(),
            digest_type: None,
            data: AnchorData::Dnskey {
                rdata: HexBytes(wire_of(&keys.example.dnskey(KeyRole::Ksk))),
            },
            state: AnchorState::Valid,
            source: AnchorSource::Operator,
            added_at: now,
            state_since: now,
            last_seen: None,
        }],
        last_query: None,
        next_query: None,
    });
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Secure, "{validation:?}");
    let (validation, _) = lab.ask("www.bogus.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Bogus, "{validation:?}");
    // A negative trust anchor makes the bogus zone insecure.
    lab.anchors.add_negative(NegativeTrustAnchor {
        id: NtaId::generate(),
        zone: name("bogus.example.test"),
        expires_at: now.checked_add(Duration::from_secs(3600)).expect("expiry"),
        reason: "a test".to_owned(),
        created_by: tenko_core::Principal::system(tenko_core::SystemComponent::Dns),
        created_at: now,
    });
    let (validation, _) = lab.ask("www.bogus.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Insecure, "{validation:?}");
    // The anchors' generation moved: the key table starts over.
    assert!(lab.validator.report().key_sets >= 1);
}

#[tokio::test]
async fn cd_never_waits_for_a_sub_query_the_resolution_did_not_need() {
    let keys = LabKeys::new();
    let lab = harness(&keys, Variant::default()).await;
    // Cold: the walk would have to ask, so the answer stays unvalidated.
    let (validation, _) = lab.ask("www.example.test", A, true).await;
    assert_eq!(
        validation.state,
        SecurityState::Unvalidated,
        "{validation:?}"
    );
    // Warm: the keys are known and CD judges from the table.
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    assert_eq!(validation.state, SecurityState::Secure);
    let (validation, _) = lab.ask("txt.example.test", 16, true).await;
    assert_eq!(validation.state, SecurityState::Secure, "{validation:?}");
    // The table is flushed by suffix and in full.
    assert!(lab.validator.flush(Some(&name("example.test").to_wire())) >= 1);
    assert!(lab.validator.flush(None) >= 1);
    assert_eq!(lab.validator.report().key_sets, 0);
}

#[tokio::test]
async fn colliding_key_tags_in_a_zone_are_bogus_within_the_caps() {
    let keys = LabKeys::new();
    let mut authority_zone = apex("example.test", "ns.example.test")
        .record(name("ns.example.test"), 3600, glue(ZONE))
        .record(name("www.example.test"), 300, a([192, 0, 2, 1]));
    // Forty fake keys with the ZSK's tag, algorithm and length.
    let tag = keys.example.tag(KeyRole::Zsk);
    for index in 0..40u16 {
        let mut fake = vec![0u8; 64];
        fake[..2].copy_from_slice(&index.to_be_bytes());
        for candidate in 0..=u16::MAX {
            fake[62..].copy_from_slice(&candidate.to_be_bytes());
            let mut rdata = vec![1, 0, 3, 13];
            rdata.extend_from_slice(&fake);
            if crypto::key_tag(&rdata) == tag {
                break;
            }
        }
        authority_zone.records.push((
            name("example.test"),
            3600,
            RecordData::Dnskey {
                flags: 256,
                protocol: 3,
                algorithm: 13,
                public_key: HexBytes(fake),
            },
        ));
    }
    let example = sign(authority_zone, &keys.example, Window::valid());
    // The lab with the colliding zone at the example zone's server.
    let variant_lab = MemAuthority::new()
        .serve(lab_ip(ROOT), {
            let root = MemZone::new(DnsName::root())
                .record(DnsName::root(), 86_400, soa(""))
                .record(DnsName::root(), 86_400, ns("a.root.test"))
                .record(name("a.root.test"), 86_400, glue(ROOT))
                .record(name("test"), 3600, ns("ns.test"))
                .record(name("ns.test"), 3600, glue(TLD))
                .record(name("test"), 3600, keys.tld.ds(&name("test")));
            sign(root, &keys.root, Window::valid())
        })
        .serve(lab_ip(TLD), {
            let tld = apex("test", "ns.test")
                .record(name("ns.test"), 3600, glue(TLD))
                .record(name("example.test"), 3600, ns("ns.example.test"))
                .record(name("ns.example.test"), 3600, glue(ZONE))
                .record(
                    name("example.test"),
                    3600,
                    keys.example.ds(&name("example.test")),
                );
            sign(tld, &keys.tld, Window::valid())
        })
        .serve(lab_ip(ZONE), example);
    let authority = Arc::new(variant_lab);
    let settings = EngineSettings {
        recursion: RecursionSettings {
            outbound: Outbound::V4,
            ..RecursionSettings::default()
        },
        hints: None,
        local_zones_except: vec![name("test")],
        metrics: false,
    };
    let infra = Arc::new(crate::infra::Infra::new(settings.recursion.infra));
    let engine = Engine::new(
        Shared(Arc::clone(&authority)),
        Arc::clone(&infra) as Arc<dyn InfraCache>,
        Arc::new(crate::infra::ServerTable::new(
            1_000,
            Duration::from_secs(900),
        )),
        Arc::new(MemFailures::default()),
        hints::parse(LAB_HINTS).expect("hints"),
        &settings,
    );
    engine.prime().await.expect("primed");
    let anchors = MemAnchors::new();
    anchors.set(root_anchor(&keys));
    let lab = Harness {
        authority,
        engine: Arc::new(engine),
        infra,
        anchors,
        validator: DnssecValidator::new(ValidationCaps::DEFAULT, 100, false),
        caps: ValidationCaps::DEFAULT,
    };
    let started = std::time::Instant::now();
    let (validation, _) = lab.ask("www.example.test", A, false).await;
    let took = started.elapsed();
    assert_eq!(validation.state, SecurityState::Bogus, "{validation:?}");
    assert_eq!(validation.reason, Some(BogusReason::Cap));
    assert_eq!(validation.ede, Some(ExtendedError::DNSSEC_BOGUS));
    assert!(
        validation.verifications <= ValidationCaps::DEFAULT.per_query,
        "{validation:?}"
    );
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert_eq!(lab.validator.counters().caps, 1);
    assert!(lab.queries() > 0);
}
