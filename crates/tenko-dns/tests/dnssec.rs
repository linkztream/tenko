//! The DNSSEC signer and the signed answers (WP6.3) over an in-memory store and vault.
//!
//! The checks do not trust the signer's own code: the signed data of every RRSIG is put
//! together here from the stored rows or, for answers, from the canonical form that
//! `hickory-proto` writes for the records it decodes, and verified with the DNSKEY of the
//! zone through `aws-lc-rs`. The NSEC and NSEC3 chains are walked here in canonical and in
//! hash order.

mod support;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use aws_lc_rs::{
    digest,
    signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey},
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use support::answer::{Query, query};
use tenko_core::{
    JobId, RequestCtx, SystemComponent,
    dns::{
        Denial, DnsName, DnssecAlgorithm, DnssecMode, DnssecPolicy, KeyRole, KeyState, Origin,
        Rdata, RecordData, RrSet, Rtype, ScopeName, SerialPolicy, SoaDefaults, Zone, ZoneId,
        ZoneKind, codes,
        tables::{JOURNAL, RRSETS},
    },
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData,
    authoritative::{Authoritative, rcode},
    catalog::{Catalog, CatalogHandle},
    cookie::CookieSecret,
    dnssec::{Signer, SignerConfig, Trigger, chain, health, rollover},
    respond::{Clock, Conn, Reply, Responder, Scratch},
    zone::{
        DirectJobs, ImportStaging, NewZone, ZoneChange, ZoneConfig, ZoneJobs, ZoneService,
        records::{Change, Op},
    },
};
use tenko_jobs::{Job, JobError, JobSpec};
use tenko_store::{KeyRange, MemStore, ReadView, ReadViewExt, Store};
use tenko_vault::MemVault;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

// ---------------------------------------------------------------------------------------
// A zone service whose job runner knows the rollover steps

/// Jobs run in place by a runner set after the signer exists.
#[derive(Default)]
struct LateJobs(OnceLock<Arc<DirectJobs>>);

#[async_trait::async_trait]
impl ZoneJobs for LateJobs {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        self.0.get().expect("runner").run_inline(spec, cx).await
    }

    async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError> {
        self.0.get().expect("runner").submit(spec, cx).await
    }
}

struct Setup {
    zones: Arc<ZoneService>,
    signer: Arc<Signer>,
    jobs: Arc<DirectJobs>,
}

fn setup() -> Setup {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let late = Arc::new(LateJobs::default());
    let staging = Arc::new(ImportStaging::default());
    let zones = ZoneService::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::clone(&late) as Arc<dyn ZoneJobs>,
        Some(Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>),
        Arc::clone(&staging),
        ZoneConfig::default(),
    );
    let signer = Signer::new(
        Arc::clone(&zones),
        vault as Arc<dyn tenko_vault::Vault>,
        SignerConfig::default(),
    );
    let mut direct = DirectJobs::new(Arc::clone(&store) as Arc<dyn Store>);
    for handler in tenko_dns::zone::step_handlers(&staging) {
        direct.register(handler);
    }
    for handler in rollover::step_handlers(&signer) {
        direct.register(handler);
    }
    let direct = Arc::new(direct);
    assert!(late.0.set(Arc::clone(&direct)).is_ok());
    Setup {
        zones,
        signer,
        jobs: direct,
    }
}

const APEX: &str = "example.test";

/// A zone with TTLs of a second, so a rollover's waits take seconds.
async fn new_zone(setup: &Setup) -> ZoneId {
    let mut soa = SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test"));
    soa.ttl = 1;
    soa.minimum = 1;
    let written = setup
        .zones
        .create(
            &cx(),
            NewZone {
                name: name(APEX),
                kind: ZoneKind::Primary,
                tenant: None,
                scopes: Vec::new(),
                serial: SerialPolicy::Counter,
                soa,
                name_servers: vec![name("ns1.example.test")],
                transfer: tenko_core::dns::TransferPolicy::default(),
                update: tenko_core::dns::UpdatePolicy::default(),
                dnssec: DnssecPolicy::default(),
                source: None,
                description: None,
                reverse_of: None,
                catalog: false,
            },
        )
        .await
        .expect("zone");
    let id = written.zone.id;
    let changes = vec![
        set("ns1.example.test", vec![a("192.0.2.1")]),
        set("www.example.test", vec![a("192.0.2.10"), a("192.0.2.11")]),
        set(
            "example.test",
            vec![RecordData::Mx {
                preference: 10,
                exchange: name("mail.example.test"),
            }],
        ),
        set("mail.example.test", vec![a("192.0.2.25")]),
        // A delegation with glue, and one with a DS.
        set(
            "sub.example.test",
            vec![RecordData::Ns {
                host: name("ns.sub.example.test"),
            }],
        ),
        set("ns.sub.example.test", vec![a("192.0.2.53")]),
        set(
            "secure.example.test",
            vec![RecordData::Ns {
                host: name("ns1.example.test"),
            }],
        ),
        set(
            "secure.example.test",
            vec![RecordData::Ds {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: HexBytes(vec![7; 32]),
            }],
        ),
        // Empty non-terminals c.example.test and b.c.example.test.
        set("a.b.c.example.test", vec![a("192.0.2.30")]),
        // A wildcard below an empty non-terminal.
        set(
            "*.wild.example.test",
            vec![RecordData::Txt {
                strings: vec![tenko_core::dns::TextBytes(b"wild".to_vec())],
            }],
        ),
        set(
            "alias.example.test",
            vec![RecordData::Cname {
                target: name("www.example.test"),
            }],
        ),
    ];
    setup
        .zones
        .change_records(&cx(), id, &changes, false)
        .await
        .expect("records");
    id
}

fn a(address: &str) -> RecordData {
    RecordData::A {
        address: address.parse().expect("address"),
    }
}

fn set(owner: &str, records: Vec<RecordData>) -> Change {
    Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: records.first().expect("records").rtype(),
        ttl: Some(1),
        records,
        take_over: false,
        origin: Origin::Manual,
    }
}

async fn enable(setup: &Setup, zone: ZoneId, policy: DnssecPolicy) {
    setup
        .zones
        .update(
            &cx(),
            zone,
            ZoneChange {
                dnssec: Some(policy),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect("policy");
    setup
        .signer
        .sync(zone, Trigger::full(false))
        .await
        .expect("signed");
}

fn online(algorithm: DnssecAlgorithm, denial: Denial) -> DnssecPolicy {
    DnssecPolicy {
        mode: DnssecMode::Online,
        algorithm,
        denial,
        ..DnssecPolicy::default()
    }
}

fn nsec3() -> Denial {
    Denial::Nsec3 {
        iterations: 0,
        salt: HexBytes(Vec::new()),
    }
}

async fn view(setup: &Setup) -> Arc<dyn ReadView> {
    setup.zones.view(None).await.expect("view")
}

async fn zone_row(setup: &Setup, id: ZoneId) -> Zone {
    ZoneService::zone(view(setup).await.as_ref(), id)
        .expect("zone")
        .zone
}

async fn zone_rows(setup: &Setup, id: ZoneId) -> Vec<RrSet> {
    view(setup)
        .await
        .scan_typed(
            &RRSETS,
            KeyRange::prefix(tenko_core::codec::key::encode_key(&id)),
            usize::MAX,
            false,
        )
        .expect("rows")
        .into_iter()
        .map(|(_, row, _)| row)
        .collect()
}

// ---------------------------------------------------------------------------------------
// An independent check of a signed zone's rows

/// The canonical order of names (RFC 4034, section 6.1).
fn canonical(name: &DnsName) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name
        .labels()
        .map(|label| label.as_bytes().to_vec())
        .collect();
    labels.reverse();
    if name.is_root() {
        labels.clear();
    }
    labels
}

fn wire(name: &DnsName) -> Vec<u8> {
    let mut out = Vec::new();
    if !name.is_root() {
        for label in name.labels() {
            out.push(u8::try_from(label.len()).expect("label"));
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out
}

fn labels_of(name: &DnsName) -> usize {
    name.label_count() - usize::from(name.is_wildcard())
}

/// A DNSKEY of the zone: algorithm, public key, key tag.
struct Dnskey {
    algorithm: u8,
    key: Vec<u8>,
    tag: u16,
}

fn dnskeys(rows: &[RrSet]) -> Vec<Dnskey> {
    rows.iter()
        .filter(|row| row.rtype == Rtype::DNSKEY)
        .flat_map(|row| row.rdata.iter())
        .map(|rdata| {
            let bytes = rdata.as_bytes();
            let mut sum: u32 = 0;
            for (index, byte) in bytes.iter().enumerate() {
                sum += if index % 2 == 0 {
                    u32::from(*byte) << 8
                } else {
                    u32::from(*byte)
                };
            }
            sum += (sum >> 16) & 0xffff;
            Dnskey {
                algorithm: bytes[3],
                key: bytes[4..].to_vec(),
                tag: u16::try_from(sum & 0xffff).expect("tag"),
            }
        })
        .collect()
}

/// Verifies an RRSIG (record data) over the records of `owner` and `rtype` with `keys`.
fn verifies(
    sig: &[u8],
    keys: &[Dnskey],
    owner: &DnsName,
    rtype: Rtype,
    records: &[Vec<u8>],
) -> bool {
    let covered = u16::from_be_bytes([sig[0], sig[1]]);
    let algorithm = sig[2];
    let labels = sig[3];
    let original_ttl = u32::from_be_bytes([sig[4], sig[5], sig[6], sig[7]]);
    let tag = u16::from_be_bytes([sig[16], sig[17]]);
    // The signer's name: an uncompressed name after the 18 octets.
    let mut end = 18;
    while sig[end] != 0 {
        end += 1 + usize::from(sig[end]);
    }
    end += 1;
    if covered != rtype.0 {
        return false;
    }
    // The owner as signed: the wildcard for a name with more labels than the RRSIG says.
    let owner_labels: Vec<&str> = owner.labels().collect();
    let signed_owner = if owner_labels.len() > usize::from(labels) {
        let keep = &owner_labels[owner_labels.len() - usize::from(labels)..];
        name(&format!("*.{}", keep.join(".")))
    } else {
        owner.clone()
    };
    let mut data = sig[..end].to_vec();
    let mut sorted = records.to_vec();
    sorted.sort();
    sorted.dedup();
    for record in sorted {
        data.extend_from_slice(&wire(&signed_owner));
        data.extend_from_slice(&rtype.0.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&original_ttl.to_be_bytes());
        data.extend_from_slice(&u16::try_from(record.len()).expect("len").to_be_bytes());
        data.extend_from_slice(&record);
    }
    keys.iter()
        .filter(|key| key.tag == tag && key.algorithm == algorithm)
        .any(|key| match algorithm {
            13 => {
                let mut point = vec![4];
                point.extend_from_slice(&key.key);
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                    .verify(&data, &sig[end..])
                    .is_ok()
            }
            15 => UnparsedPublicKey::new(&ED25519, &key.key)
                .verify(&data, &sig[end..])
                .is_ok(),
            _ => false,
        })
}

/// Whether `name` lies below a cut of the zone (or is a cut's glue).
fn occluded(name: &DnsName, rows: &[RrSet]) -> bool {
    let apex = DnsName::new(APEX).expect("apex");
    rows.iter().any(|row| {
        row.rtype == Rtype::NS
            && row.name != apex
            && name != &row.name
            && name.is_subdomain_of(&row.name)
    })
}

fn is_cut(name: &DnsName, rows: &[RrSet]) -> bool {
    name.as_str() != APEX
        && rows
            .iter()
            .any(|row| row.rtype == Rtype::NS && &row.name == name)
}

/// Checks a signed zone: every authoritative RRset is signed by every key that must sign
/// it, nothing else is signed, the chain is complete and in order. Returns the chain's
/// owners (original names for NSEC, hashes for NSEC3).
#[allow(clippy::too_many_lines, reason = "one check of a signed zone")]
fn check_zone(rows: &[RrSet], keys_expected: &[(u16, bool)], nsec3: bool) -> usize {
    let keys = dnskeys(rows);
    assert!(!keys.is_empty(), "the zone has a DNSKEY set");
    let sigs: HashMap<&DnsName, &RrSet> = rows
        .iter()
        .filter(|row| row.rtype == Rtype::RRSIG)
        .map(|row| (&row.name, row))
        .collect();
    for row in rows.iter().filter(|row| row.rtype != Rtype::RRSIG) {
        let glue = occluded(&row.name, rows)
            || (is_cut(&row.name, rows) && !matches!(row.rtype, Rtype::DS | Rtype::NSEC));
        let found: Vec<&Rdata> = sigs
            .get(&row.name)
            .map(|sigs| {
                sigs.rdata
                    .iter()
                    .filter(|sig| {
                        u16::from_be_bytes([sig.as_bytes()[0], sig.as_bytes()[1]]) == row.rtype.0
                    })
                    .collect()
            })
            .unwrap_or_default();
        if glue {
            assert!(
                found.is_empty(),
                "{} {} is glue and not signed",
                row.name,
                row.rtype
            );
            continue;
        }
        let records: Vec<Vec<u8>> = row.rdata.iter().map(|r| r.as_bytes().to_vec()).collect();
        let key_set = matches!(row.rtype, Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY);
        let wanted: Vec<u16> = keys_expected
            .iter()
            .filter(|(_, signs_keys)| *signs_keys == key_set)
            .map(|(tag, _)| *tag)
            .collect();
        assert_eq!(
            found.len(),
            wanted.len(),
            "{} {} signatures",
            row.name,
            row.rtype
        );
        for sig in found {
            let tag = u16::from_be_bytes([sig.as_bytes()[16], sig.as_bytes()[17]]);
            assert!(
                wanted.contains(&tag),
                "{} {} signed by {tag}",
                row.name,
                row.rtype
            );
            assert!(
                verifies(sig.as_bytes(), &keys, &row.name, row.rtype, &records),
                "{} {} signature verifies",
                row.name,
                row.rtype
            );
            assert_eq!(
                usize::from(sig.as_bytes()[3]),
                labels_of(&row.name),
                "labels of {}",
                row.name
            );
        }
    }
    // Every RRSIG covers an RRset that exists.
    for sig_row in sigs.values() {
        for sig in &sig_row.rdata {
            let covered = Rtype(u16::from_be_bytes([sig.as_bytes()[0], sig.as_bytes()[1]]));
            assert!(
                rows.iter()
                    .any(|row| row.name == sig_row.name && row.rtype == covered),
                "the signature of {} {covered} covers an RRset",
                sig_row.name
            );
        }
    }
    let apex = name(APEX);
    // The names of the chain: data names that are not occluded.
    let mut names: BTreeMap<Vec<Vec<u8>>, (DnsName, BTreeSet<u16>)> = BTreeMap::new();
    for row in rows {
        if occluded(&row.name, rows) || chain::hash_of_owner(&row.name, &apex).is_some() && nsec3 {
            continue;
        }
        if matches!(row.rtype, Rtype::NSEC3) {
            continue;
        }
        let entry = names
            .entry(canonical(&row.name))
            .or_insert_with(|| (row.name.clone(), BTreeSet::new()));
        let listed_at_cut = matches!(
            row.rtype,
            Rtype::NS | Rtype::DS | Rtype::RRSIG | Rtype::NSEC
        );
        if listed_at_cut || !is_cut(&row.name, rows) {
            entry.1.insert(row.rtype.0);
        }
    }
    if nsec3 {
        assert!(
            rows.iter().all(|row| row.rtype != Rtype::NSEC),
            "no NSEC in an NSEC3 zone"
        );
        let param = rows
            .iter()
            .find(|row| row.rtype == Rtype::NSEC3PARAM && row.name == apex)
            .expect("NSEC3PARAM at the apex");
        assert_eq!(param.rdata[0].as_bytes(), &[1, 0, 0, 0, 0]);
        // The original names: the chain names and every empty non-terminal above one.
        let mut originals: BTreeMap<[u8; 20], (DnsName, BTreeSet<u16>)> = BTreeMap::new();
        for (owner, types) in names.values() {
            let mut types = types.clone();
            types.remove(&Rtype::NSEC3.0);
            let hash = sha1(&wire(owner));
            originals.insert(hash, (owner.clone(), types));
            let mut parent = owner.parent();
            while let Some(ancestor) = parent {
                if ancestor == apex || !ancestor.is_subdomain_of(&apex) {
                    break;
                }
                originals
                    .entry(sha1(&wire(&ancestor)))
                    .or_insert_with(|| (ancestor.clone(), BTreeSet::new()));
                parent = ancestor.parent();
            }
        }
        let records: BTreeMap<[u8; 20], RecordData> = rows
            .iter()
            .filter(|row| row.rtype == Rtype::NSEC3)
            .map(|row| {
                let hash = chain::hash_of_owner(&row.name, &apex).expect("a hashed owner");
                (hash, row.rdata[0].decode(Rtype::NSEC3).expect("NSEC3"))
            })
            .collect();
        assert_eq!(
            records.keys().collect::<Vec<_>>(),
            originals.keys().collect::<Vec<_>>(),
            "one NSEC3 per chain name and empty non-terminal"
        );
        let order: Vec<&[u8; 20]> = records.keys().collect();
        for (index, (hash, record)) in records.iter().enumerate() {
            let RecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                next_hashed,
                types,
                ..
            } = record
            else {
                panic!("NSEC3");
            };
            assert_eq!((*hash_algorithm, *flags, *iterations), (1, 0, 0));
            assert_eq!(next_hashed.0, order[(index + 1) % order.len()].to_vec());
            let (owner, expected) = &originals[hash];
            let mut expected: BTreeSet<u16> = expected
                .iter()
                .copied()
                .filter(|t| *t != Rtype::NSEC.0)
                .collect();
            if expected.is_empty() || (is_cut(owner, rows) && !expected.contains(&Rtype::DS.0)) {
                expected.remove(&Rtype::RRSIG.0);
            }
            let listed: BTreeSet<u16> = types.iter().map(|t| t.0).collect();
            assert_eq!(listed, expected, "NSEC3 types of {owner}");
        }
        records.len()
    } else {
        let owners: Vec<&(DnsName, BTreeSet<u16>)> = names.values().collect();
        for (index, (owner, types)) in owners.iter().enumerate() {
            let row = rows
                .iter()
                .find(|row| row.rtype == Rtype::NSEC && &row.name == owner)
                .unwrap_or_else(|| panic!("NSEC at {owner}"));
            let RecordData::Nsec {
                next,
                types: listed,
            } = row.rdata[0].decode(Rtype::NSEC).expect("NSEC")
            else {
                panic!("NSEC");
            };
            assert_eq!(
                &next,
                &owners[(index + 1) % owners.len()].0,
                "the NSEC of {owner}"
            );
            let listed: BTreeSet<u16> = listed.iter().map(|t| t.0).collect();
            assert_eq!(&listed, types, "NSEC types of {owner}");
        }
        owners.len()
    }
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref());
    out
}

/// The tags of the keys that sign, with whether each signs the DNSKEY set.
async fn signing_tags(setup: &Setup, zone: ZoneId) -> Vec<(u16, bool)> {
    let (state, _) = ZoneService::sign_state(view(setup).await.as_ref(), zone)
        .expect("read")
        .expect("state");
    let mut tags = Vec::new();
    for key in &state.keys {
        let signs_keys = matches!(key.role, KeyRole::Ksk | KeyRole::Csk)
            && matches!(key.state, KeyState::Published | KeyState::Active);
        let signs_data =
            matches!(key.role, KeyRole::Zsk | KeyRole::Csk) && key.state == KeyState::Active;
        if signs_keys {
            tags.push((key.key_tag, true));
        }
        if signs_data {
            tags.push((key.key_tag, false));
        }
    }
    tags
}

// ---------------------------------------------------------------------------------------
// Signing

#[tokio::test]
async fn a_zone_is_signed_with_nsec_by_each_algorithm_and_every_signature_verifies() {
    for algorithm in [DnssecAlgorithm::EcdsaP256Sha256, DnssecAlgorithm::Ed25519] {
        let setup = setup();
        let zone = new_zone(&setup).await;
        let before = ZoneService::scope_serial(
            view(&setup).await.as_ref(),
            &zone_row(&setup, zone).await,
            &ScopeName::DEFAULT,
        )
        .expect("serial")
        .expect("serial");
        enable(&setup, zone, online(algorithm, Denial::Nsec)).await;
        let rows = zone_rows(&setup, zone).await;
        let (state, _) = ZoneService::sign_state(view(&setup).await.as_ref(), zone)
            .expect("read")
            .expect("state");
        assert_eq!(state.keys.len(), 2);
        assert!(
            state
                .keys
                .iter()
                .all(|key| key.algorithm == algorithm && key.state == KeyState::Active)
        );
        assert!(state.signed_serial.is_some_and(|serial| serial > before));
        assert!(state.expires.is_some() && state.next_resign.is_some());
        let tags = signing_tags(&setup, zone).await;
        let chained = check_zone(&rows, &tags, false);
        // apex, alias, a.b.c, mail, ns1, secure, sub, www, *.wild
        assert_eq!(chained, 9);
        // CDS and CDNSKEY for the KSK (RFC 7344).
        let ksk = state
            .keys
            .iter()
            .find(|key| key.role == KeyRole::Ksk)
            .expect("ksk");
        let cds = rows
            .iter()
            .find(|row| row.rtype == Rtype::CDS)
            .expect("CDS");
        assert_eq!(cds.rdata.len(), 1);
        assert_eq!(&cds.rdata[0].as_bytes()[..2], &ksk.key_tag.to_be_bytes());
        assert!(rows.iter().any(|row| row.rtype == Rtype::CDNSKEY));
        assert!(
            rows.iter()
                .filter(|row| row.origin == Origin::Dnssec)
                .all(|row| matches!(
                    row.rtype,
                    Rtype::RRSIG | Rtype::NSEC | Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY
                ))
        );
        // The signer's rows are left out of the records list unless asked for.
        let zone_value = zone_row(&setup, zone).await;
        let (listed, _) = ZoneService::rrsets(
            view(&setup).await.as_ref(),
            &zone_value,
            &tenko_dns::zone::RrSetFilter::scope(ScopeName::DEFAULT),
            None,
            1000,
        )
        .expect("list");
        assert!(listed.iter().all(|(row, _)| row.origin != Origin::Dnssec));
        // A second pass finds nothing to do.
        let report = setup
            .signer
            .sync(zone, Trigger::full(true))
            .await
            .expect("again");
        assert_eq!(report.rows, 0, "{algorithm:?}");
    }
}

#[tokio::test]
async fn nsec3_covers_every_name_and_empty_non_terminal_in_hash_order() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(
        &setup,
        zone,
        online(DnssecAlgorithm::EcdsaP256Sha256, nsec3()),
    )
    .await;
    let rows = zone_rows(&setup, zone).await;
    let tags = signing_tags(&setup, zone).await;
    // nine chain names and three empty non-terminals: c, b.c, wild
    assert_eq!(check_zone(&rows, &tags, true), 12);
    // Switching to NSEC replaces the chain.
    enable(
        &setup,
        zone,
        online(DnssecAlgorithm::EcdsaP256Sha256, Denial::Nsec),
    )
    .await;
    let rows = zone_rows(&setup, zone).await;
    assert!(
        rows.iter()
            .all(|row| !matches!(row.rtype, Rtype::NSEC3 | Rtype::NSEC3PARAM))
    );
    assert_eq!(check_zone(&rows, &tags, false), 9);
}

#[tokio::test]
async fn a_change_re_signs_only_its_rrsets_and_neighbours_and_is_journaled() {
    for denial in [Denial::Nsec, nsec3()] {
        let setup = setup();
        let zone = new_zone(&setup).await;
        enable(
            &setup,
            zone,
            online(DnssecAlgorithm::EcdsaP256Sha256, denial.clone()),
        )
        .await;
        let nsec3_zone = matches!(denial, Denial::Nsec3 { .. });
        let before = zone_rows(&setup, zone).await;
        // A new name below a new empty non-terminal, and a changed RRset.
        let changes = vec![
            set("x.new.example.test", vec![a("192.0.2.77")]),
            set("www.example.test", vec![a("192.0.2.12")]),
        ];
        setup
            .zones
            .change_records(&cx(), zone, &changes, false)
            .await
            .expect("change");
        let dirty: HashSet<(DnsName, Rtype)> = [
            (name("x.new.example.test"), Rtype::A),
            (name("www.example.test"), Rtype::A),
            (name(APEX), Rtype::SOA),
        ]
        .into_iter()
        .collect();
        let report = setup
            .signer
            .sync(
                zone,
                Trigger {
                    changed: HashMap::from([(ScopeName::DEFAULT, dirty)]),
                    ..Trigger::default()
                },
            )
            .await
            .expect("pass");
        assert!(!report.full);
        // The pass writes the changed owners, their chain neighbours and the apex: a
        // handful of rows, where a full pass writes every one.
        assert!(report.rows > 0 && report.rows <= 14, "{report:?}");
        let after = zone_rows(&setup, zone).await;
        let tags = signing_tags(&setup, zone).await;
        check_zone(&after, &tags, nsec3_zone);
        // The signatures of untouched RRsets stayed as they were.
        let mail = |rows: &[RrSet]| {
            rows.iter()
                .find(|row| row.rtype == Rtype::RRSIG && row.name.as_str() == "ns1.example.test")
                .cloned()
                .expect("ns1 RRSIG")
        };
        assert_eq!(mail(&before).rdata, mail(&after).rdata);
        // The journal entry of the pass carries the new signatures (IXFR needs them).
        let view = view(&setup).await;
        let entries = view
            .scan_typed(
                &JOURNAL,
                KeyRange::prefix(tenko_core::codec::key::encode_key(&zone)),
                usize::MAX,
                true,
            )
            .expect("journal");
        let (_, last, _) = entries.first().expect("an entry");
        assert!(last.added.iter().any(|record| record.rtype == Rtype::RRSIG));
        assert_eq!(last.added[0].rtype, Rtype::SOA);
        // Deleting the name takes it and its empty non-terminal out of the chain.
        let delete = vec![Change {
            op: Op::Delete,
            records: Vec::new(),
            ..set("x.new.example.test", vec![a("192.0.2.77")])
        }];
        setup
            .zones
            .change_records(&cx(), zone, &delete, false)
            .await
            .expect("delete");
        let dirty: HashSet<(DnsName, Rtype)> = [
            (name("x.new.example.test"), Rtype::A),
            (name(APEX), Rtype::SOA),
        ]
        .into_iter()
        .collect();
        setup
            .signer
            .sync(
                zone,
                Trigger {
                    changed: HashMap::from([(ScopeName::DEFAULT, dirty)]),
                    ..Trigger::default()
                },
            )
            .await
            .expect("pass");
        let after = zone_rows(&setup, zone).await;
        check_zone(&after, &tags, nsec3_zone);
        assert!(
            after
                .iter()
                .all(|row| !row.name.as_str().ends_with("new.example.test"))
        );
    }
}

#[tokio::test]
async fn off_removes_the_rows_and_online_again_takes_the_keys_up() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(&setup, zone, online(DnssecAlgorithm::Ed25519, Denial::Nsec)).await;
    let tags: BTreeSet<u16> = signing_tags(&setup, zone)
        .await
        .into_iter()
        .map(|(tag, _)| tag)
        .collect();
    enable(&setup, zone, DnssecPolicy::default()).await;
    let rows_off = zone_rows(&setup, zone).await;
    assert!(rows_off.iter().all(|row| row.origin != Origin::Dnssec));
    let (state, _) = ZoneService::sign_state(view(&setup).await.as_ref(), zone)
        .expect("read")
        .expect("state");
    assert!(state.keys.iter().all(|key| key.state == KeyState::Retired));
    enable(&setup, zone, online(DnssecAlgorithm::Ed25519, Denial::Nsec)).await;
    let again: BTreeSet<u16> = signing_tags(&setup, zone)
        .await
        .into_iter()
        .map(|(tag, _)| tag)
        .collect();
    assert_eq!(again, tags, "the DS at the parent stays valid");
    check_zone(
        &zone_rows(&setup, zone).await,
        &signing_tags(&setup, zone).await,
        false,
    );
}

#[tokio::test]
async fn the_signers_types_are_refused_for_other_writers() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(
        &setup,
        zone,
        online(DnssecAlgorithm::EcdsaP256Sha256, Denial::Nsec),
    )
    .await;
    let nsec = set(
        "www.example.test",
        vec![RecordData::Nsec {
            next: name(APEX),
            types: vec![Rtype::A],
        }],
    );
    let error = setup
        .zones
        .change_records(&cx(), zone, std::slice::from_ref(&nsec), false)
        .await
        .expect_err("refused");
    assert!(error.is(codes::RECORD_ORIGIN), "{error:?}");
    let error = setup
        .zones
        .change_records(
            &cx(),
            zone,
            &[Change {
                take_over: true,
                ..nsec
            }],
            false,
        )
        .await
        .expect_err("refused with take_over too");
    assert!(error.is(codes::RECORD_ORIGIN), "{error:?}");
}

#[tokio::test]
async fn an_imported_zone_keeps_its_signatures_and_warns_before_they_expire() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    let now = tenko_core::Timestamp::now();
    let unix = u32::try_from(now.unix_nanos() / 1_000_000_000).expect("time");
    let sig = RecordData::Rrsig {
        type_covered: Rtype::A,
        algorithm: 13,
        labels: 3,
        original_ttl: 1,
        expiration: unix + 3 * 86_400,
        inception: unix - 3_600,
        key_tag: 1,
        signer: name(APEX),
        signature: HexBytes(vec![1; 64]),
    };
    setup
        .zones
        .change_records(&cx(), zone, &[set("www.example.test", vec![sig])], false)
        .await
        .expect("imported signature");
    enable(
        &setup,
        zone,
        DnssecPolicy {
            mode: DnssecMode::Imported,
            ..DnssecPolicy::default()
        },
    )
    .await;
    let view = view(&setup).await;
    let (state, _) = ZoneService::sign_state(view.as_ref(), zone)
        .expect("read")
        .expect("state");
    let expires = state.expires.expect("the expiry is read");
    assert!(expires.saturating_since(now).as_secs() > 2 * 86_400);
    let findings = health::all(view.as_ref(), now).expect("findings");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].code, health::EXPIRING);
    assert_eq!(findings[0].params["zone"], APEX);
    let rows = zone_rows(&setup, zone).await;
    assert!(
        rows.iter()
            .any(|row| row.rtype == Rtype::RRSIG && row.origin == Origin::Manual)
    );
}

// ---------------------------------------------------------------------------------------
// Signed answers

struct Engine {
    responder: Responder<Authoritative>,
    scratch: Scratch,
    clock: Clock,
}

async fn engine(setup: &Setup) -> Engine {
    let view = view(setup).await;
    let mut image = DnsData {
        revision: view.revision(),
        ..DnsData::default()
    };
    for (id, zone, _) in view
        .scan_typed(
            &tenko_core::dns::tables::ZONES,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("zones")
    {
        image.zones.insert(id, zone);
    }
    for (key, row, _) in view
        .scan_typed(&RRSETS, KeyRange::all(), usize::MAX, false)
        .expect("rows")
    {
        image.rrsets.insert(key, row);
    }
    let catalog = Catalog::build(&image);
    Engine {
        responder: Responder::new(
            Authoritative::new(CatalogHandle::new(catalog)),
            CookieSecret::with_secret([3; 16]),
        )
        .with_metrics(false),
        scratch: Scratch::new(),
        clock: Clock::now(),
    }
}

impl Engine {
    fn ask(&mut self, query: &Query) -> hickory_proto::op::Message {
        let conn = Conn {
            client: SocketAddr::new("192.0.2.200".parse().expect("client"), 40000),
            local: "192.0.2.53:53".parse().expect("local"),
            transport: tenko_core::dns::QueryTransport::Udp,
        };
        let reply = self.responder.respond(
            &query.bytes(0x4242),
            &conn,
            &self.clock,
            Instant::now(),
            &mut self.scratch,
        );
        assert_eq!(reply, Reply::Send);
        hickory_proto::op::Message::from_vec(&self.scratch.out)
            .expect("an independent decoder reads it")
    }
}

/// The canonical record data `hickory-proto` writes for a record it decoded.
fn canonical_rdata(record: &hickory_proto::rr::Record) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = BinEncoder::new(&mut out);
    encoder.set_canonical_form(true);
    record.data.emit(&mut encoder).expect("emit");
    out
}

/// Verifies every RRset of `records` against its RRSIGs in the same list; returns the
/// RRsets by type in the order met. Panics on an RRset without a valid signature.
fn verify_section(records: &[hickory_proto::rr::Record], keys: &[Dnskey]) -> Vec<(DnsName, u16)> {
    let mut sets: Vec<(DnsName, u16, Vec<Vec<u8>>)> = Vec::new();
    let mut sigs: Vec<(DnsName, Vec<u8>)> = Vec::new();
    for record in records {
        let owner = name(&record.name.to_ascii().to_ascii_lowercase());
        let rtype = u16::from(record.record_type());
        let data = canonical_rdata(record);
        if rtype == Rtype::RRSIG.0 {
            sigs.push((owner, data));
        } else if let Some(entry) = sets.iter_mut().find(|(o, t, _)| o == &owner && *t == rtype) {
            entry.2.push(data);
        } else {
            sets.push((owner, rtype, vec![data]));
        }
    }
    for (owner, rtype, data) in &sets {
        if *rtype == Rtype::NS.0 && owner.as_str() != APEX {
            // The NS set of a referral belongs to the child and is not signed.
            continue;
        }
        if *rtype == Rtype::CNAME.0
            && data.len() == 1
            && sigs
                .iter()
                .all(|(o, s)| o != owner || u16::from_be_bytes([s[0], s[1]]) != *rtype)
        {
            // A CNAME synthesized from a DNAME is unsigned.
            continue;
        }
        let ok = sigs
            .iter()
            .filter(|(o, _)| o == owner)
            .any(|(_, sig)| verifies(sig, keys, owner, Rtype(*rtype), data));
        assert!(ok, "{owner} {rtype} has a valid signature");
    }
    sets.into_iter()
        .map(|(owner, rtype, _)| (owner, rtype))
        .collect()
}

fn types_in(records: &[hickory_proto::rr::Record]) -> Vec<u16> {
    records
        .iter()
        .map(|record| u16::from(record.record_type()))
        .collect()
}

#[tokio::test]
async fn answers_with_do_carry_signatures_and_proofs_that_verify() {
    for denial in [Denial::Nsec, nsec3()] {
        let setup = setup();
        let zone = new_zone(&setup).await;
        enable(
            &setup,
            zone,
            online(DnssecAlgorithm::EcdsaP256Sha256, denial.clone()),
        )
        .await;
        let keys = dnskeys(&zone_rows(&setup, zone).await);
        let mut engine = engine(&setup).await;
        let nsec3_zone = matches!(denial, Denial::Nsec3 { .. });
        let denial_type = if nsec3_zone {
            Rtype::NSEC3.0
        } else {
            Rtype::NSEC.0
        };

        // Without DO nothing changes.
        let plain = engine.ask(&query("www.example.test", 1));
        assert_eq!(types_in(&plain.answers), [1, 1]);
        assert_eq!(plain.authorities.len(), 0);

        // A positive answer with its RRSIG; AD is never set.
        let answer = engine.ask(&query("www.example.test", 1).dnssec());
        assert!(!answer.metadata.authentic_data);
        assert_eq!(types_in(&answer.answers), [1, 1, 46]);
        verify_section(&answer.answers, &keys);

        // The DNSKEY set, signed by the KSK.
        let answer = engine.ask(&query(APEX, 48).dnssec());
        verify_section(&answer.answers, &keys);

        // NXDOMAIN: the SOA and the denial records, all signed.
        let answer = engine.ask(&query("nope.example.test", 1).dnssec());
        assert_eq!(u16::from(answer.metadata.response_code), rcode::NXDOMAIN);
        let authority = verify_section(&answer.authorities, &keys);
        assert!(authority.iter().any(|(_, t)| *t == Rtype::SOA.0));
        let proofs = authority.iter().filter(|(_, t)| *t == denial_type).count();
        assert!(proofs >= if nsec3_zone { 2 } else { 1 }, "{authority:?}");

        // NODATA at a name, at an empty non-terminal, and at a wildcard.
        for (qname, qtype) in [
            ("www.example.test", 16),
            ("c.example.test", 1),
            ("any.wild.example.test", 1),
        ] {
            let answer = engine.ask(&query(qname, qtype).dnssec());
            assert_eq!(u16::from(answer.metadata.response_code), 0, "{qname}");
            assert!(answer.answers.is_empty(), "{qname}");
            let authority = verify_section(&answer.authorities, &keys);
            assert!(
                authority.iter().any(|(_, t)| *t == denial_type),
                "{qname}: {authority:?}"
            );
        }

        // An answer from the wildcard proves that the name itself does not exist.
        let answer = engine.ask(&query("any.wild.example.test", 16).dnssec());
        assert_eq!(types_in(&answer.answers), [16, 46]);
        verify_section(&answer.answers, &keys);
        let authority = verify_section(&answer.authorities, &keys);
        assert!(
            authority.iter().any(|(_, t)| *t == denial_type),
            "{authority:?}"
        );

        // A CNAME and its target, both signed.
        let answer = engine.ask(&query("alias.example.test", 1).dnssec());
        assert_eq!(types_in(&answer.answers), [5, 46, 1, 1, 46]);
        verify_section(&answer.answers, &keys);

        // A referral: the signed DS, or the proof of none.
        let answer = engine.ask(&query("host.secure.example.test", 1).dnssec());
        let authority = verify_section(&answer.authorities, &keys);
        assert!(authority.iter().any(|(_, t)| *t == Rtype::DS.0));
        let answer = engine.ask(&query("host.sub.example.test", 1).dnssec());
        let authority = verify_section(&answer.authorities, &keys);
        assert!(
            authority.iter().any(|(_, t)| *t == denial_type),
            "{authority:?}"
        );
        assert!(authority.iter().all(|(_, t)| *t != Rtype::DS.0));
    }
}

// ---------------------------------------------------------------------------------------
// Rollovers

#[tokio::test]
async fn a_zsk_rollover_publishes_signs_and_retires_with_the_zone_valid_throughout() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(
        &setup,
        zone,
        online(DnssecAlgorithm::EcdsaP256Sha256, Denial::Nsec),
    )
    .await;
    let old_zsk = signing_tags(&setup, zone)
        .await
        .into_iter()
        .find(|(_, keys)| !keys)
        .expect("zsk")
        .0;
    let job = setup
        .zones
        .start_rollover(&cx(), zone, KeyRole::Zsk, |zone, _| {
            rollover::job_spec(zone, KeyRole::Zsk)
        })
        .await
        .expect("rollover");
    let job = setup.jobs.job(job).expect("ran");
    assert_eq!(job.state, tenko_jobs::JobState::Succeeded, "{job:?}");
    let (state, _) = ZoneService::sign_state(view(&setup).await.as_ref(), zone)
        .expect("read")
        .expect("state");
    assert!(state.rollover_job.is_none());
    let old = state
        .keys
        .iter()
        .find(|key| key.key_tag == old_zsk)
        .expect("old key");
    assert_eq!(old.state, KeyState::Removed);
    let tags = signing_tags(&setup, zone).await;
    let new_zsk = tags.iter().find(|(_, keys)| !keys).expect("new zsk").0;
    assert_ne!(new_zsk, old_zsk);
    let rows = zone_rows(&setup, zone).await;
    check_zone(&rows, &tags, false);
    assert_eq!(dnskeys(&rows).len(), 2, "the old ZSK left the DNSKEY set");
    // A second rollover is refused while the zone is not signed online.
    enable(&setup, zone, DnssecPolicy::default()).await;
    let error = setup
        .zones
        .start_rollover(&cx(), zone, KeyRole::Zsk, |zone, _| {
            rollover::job_spec(zone, KeyRole::Zsk)
        })
        .await
        .expect_err("not online");
    assert!(error.is(codes::DNSSEC_NOT_ONLINE));
}

#[tokio::test]
async fn a_ksk_rollover_ends_with_the_new_key_alone_in_cds() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(&setup, zone, online(DnssecAlgorithm::Ed25519, Denial::Nsec)).await;
    let job = setup
        .zones
        .start_rollover(&cx(), zone, KeyRole::Ksk, |zone, _| {
            rollover::job_spec(zone, KeyRole::Ksk)
        })
        .await
        .expect("rollover");
    let job = setup.jobs.job(job).expect("ran");
    assert_eq!(job.state, tenko_jobs::JobState::Succeeded, "{job:?}");
    let tags = signing_tags(&setup, zone).await;
    let ksk = tags.iter().find(|(_, keys)| *keys).expect("ksk").0;
    let rows = zone_rows(&setup, zone).await;
    check_zone(&rows, &tags, false);
    let cds = rows
        .iter()
        .find(|row| row.rtype == Rtype::CDS)
        .expect("CDS");
    assert_eq!(cds.rdata.len(), 1);
    assert_eq!(&cds.rdata[0].as_bytes()[..2], &ksk.to_be_bytes());
    // A rollover of a role the zone does not use is refused.
    let error = setup
        .zones
        .start_rollover(&cx(), zone, KeyRole::Csk, |zone, _| {
            rollover::job_spec(zone, KeyRole::Csk)
        })
        .await
        .expect_err("no csk");
    assert!(error.is(codes::ZONE_INVALID));
}

#[tokio::test]
async fn a_csk_zone_signs_everything_with_one_key() {
    let setup = setup();
    let zone = new_zone(&setup).await;
    enable(
        &setup,
        zone,
        DnssecPolicy {
            csk: true,
            ..online(DnssecAlgorithm::EcdsaP256Sha256, nsec3())
        },
    )
    .await;
    let (state, _) = ZoneService::sign_state(view(&setup).await.as_ref(), zone)
        .expect("read")
        .expect("state");
    assert_eq!(state.keys.len(), 1);
    assert_eq!(state.keys[0].role, KeyRole::Csk);
    let rows = zone_rows(&setup, zone).await;
    check_zone(&rows, &signing_tags(&setup, zone).await, true);
    let dnskey = rows
        .iter()
        .find(|row| row.rtype == Rtype::DNSKEY)
        .expect("DNSKEY");
    assert_eq!(&dnskey.rdata[0].as_bytes()[..2], &257u16.to_be_bytes());
}

#[test]
fn health_warns_when_the_clock_went_back() {
    let mut zone = support::zone(APEX);
    zone.dnssec.mode = DnssecMode::Online;
    let now = tenko_core::Timestamp::now();
    let later = now
        .checked_add(std::time::Duration::from_secs(600))
        .expect("later");
    let state = tenko_core::dns::SignState {
        zone: zone.id,
        keys: Vec::new(),
        signed_serial: Some(1),
        last_signed: Some(later),
        next_resign: None,
        signed_revision: None,
        expires: now.checked_add(std::time::Duration::from_secs(10 * 86_400)),
        rollover_job: None,
    };
    let findings = health::findings(&zone, &state, now);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].code, health::CLOCK_SKEW);
    let fine = health::findings(&zone, &state, later);
    assert!(fine.is_empty(), "{fine:?}");
}
