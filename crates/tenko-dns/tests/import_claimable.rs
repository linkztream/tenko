//! DNS-28, MIG-07: what an operator approves of a Windows zone file is what becomes
//! claimable. Each property with a test that fails without it: an import without an
//! approval makes nothing claimable; an approval of another file, or of a store that changed
//! since the preview, is refused; a name on the never-claimable list stays static whatever
//! the file says; the operator's rule narrows the set; the audit record names what was made
//! claimable; and a file of 100,000 aged records stays within the bounds (time and the peak
//! of the bytes held are printed with `--nocapture`).

use std::{
    alloc::System,
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditRecord,
    dns::{
        DnsName, Origin, RecordData, RrSetKey, Rtype, ScopeName, SerialPolicy, SoaDefaults,
        TextBytes, Zone, ZoneKind, tables::RRSETS,
    },
};
use tenko_dns::zone::{
    NewZone, ZoneConfig, ZoneError, ZoneService,
    import::{ClaimRequest, ClaimRule, HeldReason, ImportReport, ImportRequest, claim, report_of},
    records::{Change, Op},
    zonefile::Dialect,
};
use tenko_store::{KeyRange, MemStore, ReadViewExt as _, Store};
use tenko_vault::MemVault;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const APEX: &str = "corp.example.test";
const REVERSE: &str = "2.0.192.in-addr.arpa";

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

struct Lab {
    zones: Arc<ZoneService>,
}

fn lab() -> Lab {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let zones = ZoneService::with_direct_jobs(
        store as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    Lab { zones }
}

impl Lab {
    async fn zone(&self, apex: &str) -> Zone {
        self.zones
            .create(
                &cx(),
                NewZone {
                    name: name(apex),
                    kind: ZoneKind::Primary,
                    tenant: None,
                    scopes: Vec::new(),
                    serial: SerialPolicy::Counter,
                    soa: SoaDefaults::new(
                        name(&format!("ns1.{APEX}")),
                        name(&format!("hostmaster.{APEX}")),
                    ),
                    name_servers: vec![name(&format!("ns1.{APEX}"))],
                    transfer: tenko_core::dns::TransferPolicy::default(),
                    update: tenko_core::dns::UpdatePolicy::default(),
                    dnssec: tenko_core::dns::DnssecPolicy::default(),
                    source: None,
                    description: None,
                    reverse_of: None,
                    catalog: false,
                },
            )
            .await
            .expect("create")
            .zone
    }

    async fn preview(&self, zone: &Zone, text: &str, claim: ClaimRequest) -> ImportReport {
        self.zones
            .preview_import(&cx(), &request(zone, text, claim))
            .await
            .expect("preview")
    }

    async fn import(
        &self,
        zone: &Zone,
        text: &str,
        claim: ClaimRequest,
    ) -> Result<ImportReport, ZoneError> {
        let (job, _) = self
            .zones
            .start_import(&cx(), request(zone, text, claim))
            .await?;
        let direct = self.zones.direct_jobs().expect("direct jobs");
        Ok(report_of(&direct.job(job).expect("job")).expect("report"))
    }

    async fn origin(&self, zone: &Zone, owner: &str, rtype: Rtype) -> Option<Origin> {
        let view = self.zones.view(None).await.expect("view");
        view.get_typed(
            &RRSETS,
            &RrSetKey {
                zone: zone.id,
                scope: ScopeName::DEFAULT,
                name: name(owner),
                rtype,
            },
        )
        .expect("read")
        .map(|(rrset, _)| rrset.origin)
    }

    async fn write(&self, zone: &Zone, owner: &str, data: RecordData, origin: Origin) {
        let rtype = match &data {
            RecordData::A { .. } => Rtype::A,
            RecordData::Aaaa { .. } => Rtype::AAAA,
            _ => Rtype::TXT,
        };
        self.zones
            .change_records(
                &cx(),
                zone.id,
                &[Change {
                    op: Op::Set,
                    scope: ScopeName::DEFAULT,
                    name: name(owner),
                    rtype,
                    ttl: Some(600),
                    records: vec![data],
                    take_over: false,
                    origin,
                }],
                false,
            )
            .await
            .expect("write");
    }

    async fn audit(&self) -> Vec<AuditRecord> {
        let view = self.zones.view(None).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
    }
}

fn request(zone: &Zone, text: &str, claim: ClaimRequest) -> ImportRequest {
    ImportRequest {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        text: text.to_owned(),
        replace: false,
        dialect: Dialect::Windows,
        claim,
    }
}

/// The approval of a preview, with the rule it was made with.
fn approve(preview: &ImportReport, rule: ClaimRule) -> ClaimRequest {
    ClaimRequest {
        rule,
        approval: Some(
            preview
                .claimable_digest
                .as_deref()
                .expect("a digest")
                .parse()
                .expect("the digest reads"),
        ),
        ..ClaimRequest::default()
    }
}

fn listed(report: &ImportReport) -> Vec<String> {
    report
        .claimable_names
        .iter()
        .map(|entry| format!("{}/{}", entry.name, entry.rtype))
        .collect()
}

fn held(report: &ImportReport) -> BTreeMap<String, HeldReason> {
    report
        .held_back_names
        .iter()
        .map(|entry| (format!("{}/{}", entry.name, entry.rtype), entry.reason))
        .collect()
}

const TWO_HOSTS: &str = "\
$ORIGIN corp.example.test.
ws01    [AGE:3660412]   1200    A       192.0.2.21
ws02    [AGE:3660412]   1200    AAAA    2001:db8::22
srv01                   1200    A       192.0.2.30
";

/// An import that carries no approval makes nothing claimable: every candidate comes in
/// static and is reported as not approved, though the preview listed it.
#[tokio::test]
async fn an_import_without_an_approval_makes_nothing_claimable() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let preview = lab.preview(&zone, TWO_HOSTS, ClaimRequest::default()).await;
    assert_eq!(preview.claimable, 2);
    assert_eq!(
        listed(&preview),
        ["ws01.corp.example.test/A", "ws02.corp.example.test/AAAA"]
    );
    let report = lab
        .import(&zone, TWO_HOSTS, ClaimRequest::default())
        .await
        .expect("import");
    assert_eq!(report.claimable, 0);
    assert_eq!(report.claimable_digest, None);
    assert_eq!(report.held_back, 2);
    assert!(
        held(&report)
            .values()
            .all(|reason| *reason == HeldReason::NotApproved)
    );
    for (owner, rtype) in [
        ("ws01.corp.example.test", Rtype::A),
        ("ws02.corp.example.test", Rtype::AAAA),
        ("srv01.corp.example.test", Rtype::A),
    ] {
        assert_eq!(
            lab.origin(&zone, owner, rtype).await,
            Some(Origin::Manual),
            "{owner}"
        );
    }
}

/// The approval of a preview makes exactly the RRsets it listed claimable.
#[tokio::test]
async fn an_approval_makes_exactly_the_listed_names_claimable() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let preview = lab.preview(&zone, TWO_HOSTS, ClaimRequest::default()).await;
    let report = lab
        .import(&zone, TWO_HOSTS, approve(&preview, ClaimRule::default()))
        .await
        .expect("import");
    assert_eq!(report.claimable, 2);
    assert_eq!(listed(&report), listed(&preview));
    assert_eq!(report.claimable_digest, preview.claimable_digest);
    assert_eq!(
        lab.origin(&zone, "ws01.corp.example.test", Rtype::A).await,
        Some(Origin::Ad)
    );
    assert_eq!(
        lab.origin(&zone, "ws02.corp.example.test", Rtype::AAAA)
            .await,
        Some(Origin::Ad)
    );
    assert_eq!(
        lab.origin(&zone, "srv01.corp.example.test", Rtype::A).await,
        Some(Origin::Manual)
    );
}

/// An approval binds the file, the zone and the store: a file that differs from the one
/// previewed (a name more, or only an address changed), the same file in another zone, or a
/// store that gave a listed name another record since, is refused, and nothing is written.
#[tokio::test]
async fn an_approval_of_another_file_or_another_store_is_refused() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let preview = lab.preview(&zone, TWO_HOSTS, ClaimRequest::default()).await;
    let approval = approve(&preview, ClaimRule::default());
    let refused = |result: Result<ImportReport, ZoneError>| {
        let error = result.expect_err("refused");
        assert_eq!(error.coded().code, claim::CLAIMABLE_CHANGED, "{error}");
        assert_eq!(error.coded().status, 409);
    };
    let one_more = format!("{TWO_HOSTS}www [AGE:3660412] 1200 A 192.0.2.80\n");
    refused(lab.import(&zone, &one_more, approval.clone()).await);
    assert_eq!(
        lab.origin(&zone, "www.corp.example.test", Rtype::A).await,
        None
    );
    let other_address = TWO_HOSTS.replace("192.0.2.21", "192.0.2.99");
    refused(lab.import(&zone, &other_address, approval.clone()).await);
    assert_eq!(
        lab.origin(&zone, "ws01.corp.example.test", Rtype::A).await,
        None
    );
    let other_zone = lab.zone("other.example.test").await;
    let moved = TWO_HOSTS.replace(APEX, "other.example.test");
    let moved_preview = lab
        .preview(&other_zone, &moved, ClaimRequest::default())
        .await;
    assert_ne!(moved_preview.claimable_digest, preview.claimable_digest);
    refused(lab.import(&other_zone, &moved, approval.clone()).await);
    // The store changes: an administrator gives ws01 a static TXT record.
    lab.write(
        &zone,
        "ws01.corp.example.test",
        RecordData::Txt {
            strings: vec![TextBytes::from_text("asset 4711")],
        },
        Origin::Manual,
    )
    .await;
    refused(lab.import(&zone, TWO_HOSTS, approval).await);
    assert_eq!(
        lab.origin(&zone, "ws01.corp.example.test", Rtype::A).await,
        None
    );
    // A malformed digest is a bad request, not a refusal of the set.
    let error = "not hex"
        .parse::<tenko_dns::zone::import::ClaimDigest>()
        .expect_err("malformed");
    assert_eq!(error.coded().code, claim::CLAIMABLE_INVALID);
}

/// The never-claimable list: whatever the file says, these names stay static, each with its
/// reason, also after an import that approved the preview.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "the table is the test")]
async fn a_name_on_the_never_claimable_list_stays_static() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    // Records in the store before the import: static, IPAM and DHCP data at three names.
    lab.write(
        &zone,
        "static1.corp.example.test",
        RecordData::Aaaa {
            address: "2001:db8::17".parse().expect("address"),
        },
        Origin::Manual,
    )
    .await;
    lab.write(
        &zone,
        "ipam1.corp.example.test",
        RecordData::Txt {
            strings: vec![TextBytes::from_text("ipam")],
        },
        Origin::Ipam,
    )
    .await;
    lab.write(
        &zone,
        "dhcp1.corp.example.test",
        RecordData::Aaaa {
            address: "2001:db8::19".parse().expect("address"),
        },
        Origin::Dhcp,
    )
    .await;
    let file = "\
$ORIGIN corp.example.test.
@          [AGE:1] 600 A     192.0.2.1
@                  600 MX    10 mail.corp.example.test.
ns1        [AGE:1] 600 A     192.0.2.2
ns2        [AGE:1] 600 A     192.0.2.3
sub                600 NS    ns2.corp.example.test.
mail       [AGE:1] 600 A     192.0.2.4
sip        [AGE:1] 600 A     192.0.2.5
_sip._udp          600 SRV   0 0 5060 sip.corp.example.test.
web        [AGE:1] 600 A     192.0.2.6
www                600 CNAME web.corp.example.test.
wpad       [AGE:1] 600 A     192.0.2.7
isatap     [AGE:1] 600 A     192.0.2.8
_ldap._tcp [AGE:1] 600 A     192.0.2.9
_x         [AGE:1] 600 A     192.0.2.10
*          [AGE:1] 600 A     192.0.2.11
pc.branch  [AGE:1] 600 A     192.0.2.12
tenko1     [AGE:1] 600 A     192.0.2.13
txthost    [AGE:1] 600 A     192.0.2.14
txthost            600 TXT   \"asset\"
mixed      [AGE:1] 600 A     192.0.2.15
                   600 A     192.0.2.16
static1    [AGE:1] 600 A     192.0.2.17
ipam1      [AGE:1] 600 A     192.0.2.18
dhcp1      [AGE:1] 600 A     192.0.2.19
gc._msdcs  [AGE:1] 600 A     192.0.2.20
ws01       [AGE:1] 600 A     192.0.2.21
";
    let claim = ClaimRequest {
        reserved_hosts: vec!["tenko1".to_owned()],
        ..ClaimRequest::default()
    };
    let preview = lab.preview(&zone, file, claim.clone()).await;
    let expect = [
        ("corp.example.test/A", HeldReason::Reserved),
        ("ns1.corp.example.test/A", HeldReason::NameServer),
        ("ns2.corp.example.test/A", HeldReason::NameServer),
        ("mail.corp.example.test/A", HeldReason::ServiceTarget),
        ("sip.corp.example.test/A", HeldReason::ServiceTarget),
        ("web.corp.example.test/A", HeldReason::ServiceTarget),
        ("wpad.corp.example.test/A", HeldReason::ServiceName),
        ("isatap.corp.example.test/A", HeldReason::ServiceName),
        ("_ldap._tcp.corp.example.test/A", HeldReason::Reserved),
        ("_x.corp.example.test/A", HeldReason::Reserved),
        ("*.corp.example.test/A", HeldReason::Reserved),
        ("gc._msdcs.corp.example.test/A", HeldReason::Reserved),
        ("pc.branch.corp.example.test/A", HeldReason::NotAHost),
        ("tenko1.corp.example.test/A", HeldReason::TenkoNode),
        ("txthost.corp.example.test/A", HeldReason::OtherData),
        ("mixed.corp.example.test/A", HeldReason::OtherData),
        ("static1.corp.example.test/A", HeldReason::OtherData),
        ("ipam1.corp.example.test/A", HeldReason::OtherData),
        ("dhcp1.corp.example.test/A", HeldReason::OtherData),
    ];
    let got = held(&preview);
    for (key, reason) in expect {
        assert_eq!(got.get(key), Some(&reason), "{key}: {got:?}");
    }
    assert_eq!(preview.held_back, expect.len() as u64, "{got:?}");
    assert_eq!(listed(&preview), ["ws01.corp.example.test/A"]);
    let report = lab
        .import(
            &zone,
            file,
            ClaimRequest {
                reserved_hosts: claim.reserved_hosts.clone(),
                ..approve(&preview, ClaimRule::default())
            },
        )
        .await
        .expect("import");
    assert_eq!(report.claimable, 1);
    for (key, _) in expect {
        let (owner, _) = key.split_once('/').expect("key");
        let origin = lab.origin(&zone, owner, Rtype::A).await;
        assert_ne!(origin, Some(Origin::Ad), "{owner}");
    }
    assert_eq!(
        lab.origin(&zone, "ws01.corp.example.test", Rtype::A).await,
        Some(Origin::Ad)
    );
}

/// The never-claimable list of a reverse zone: a PTR record is held back by what it points
/// at, and one whose targets name two hosts names none.
#[tokio::test]
async fn a_pointer_to_a_name_on_the_list_stays_static() {
    let lab = lab();
    let zone = lab.zone(REVERSE).await;
    let file = "\
$ORIGIN 2.0.192.in-addr.arpa.
20 [AGE:1] 600 PTR ws01.corp.example.test.
21 [AGE:1] 600 PTR wpad.corp.example.test.
22 [AGE:1] 600 PTR ns1.corp.example.test.
23 [AGE:1] 600 PTR tenko1.corp.example.test.
24 [AGE:1] 600 PTR a.corp.example.test.
24 [AGE:1] 600 PTR b.corp.example.test.
25 [AGE:1] 600 PTR _ldap._tcp.corp.example.test.
26 [AGE:1] 600 PTR single.
";
    let claim = ClaimRequest {
        reserved_hosts: vec!["tenko1.corp.example.test".to_owned()],
        ..ClaimRequest::default()
    };
    let preview = lab.preview(&zone, file, claim).await;
    let got = held(&preview);
    let expect = [
        ("21.2.0.192.in-addr.arpa/PTR", HeldReason::ServiceName),
        ("22.2.0.192.in-addr.arpa/PTR", HeldReason::NameServer),
        ("23.2.0.192.in-addr.arpa/PTR", HeldReason::TenkoNode),
        ("24.2.0.192.in-addr.arpa/PTR", HeldReason::NotAHost),
        ("25.2.0.192.in-addr.arpa/PTR", HeldReason::Reserved),
        ("26.2.0.192.in-addr.arpa/PTR", HeldReason::NotAHost),
    ];
    for (key, reason) in expect {
        assert_eq!(got.get(key), Some(&reason), "{key}: {got:?}");
    }
    assert_eq!(listed(&preview), ["20.2.0.192.in-addr.arpa/PTR"]);
    assert_eq!(preview.claimable_names[0].claimant, "WS01$");
}

/// The operator's rule: only names under a suffix, only addresses in a prefix (for a PTR
/// record, the address its name stands for), never the names excepted.
#[tokio::test]
async fn the_rule_narrows_the_claimable_set() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let file = "\
$ORIGIN corp.example.test.
ws01 [AGE:1] 600 A 192.0.2.21
ws02 [AGE:1] 600 A 198.51.100.22
ws03 [AGE:1] 600 A 192.0.2.23
";
    let rule = ClaimRule {
        within: vec!["192.0.2.0/24".parse().expect("prefix")],
        except: vec![name("ws03.corp.example.test")],
        ..ClaimRule::default()
    };
    let claim = ClaimRequest {
        rule: rule.clone(),
        ..ClaimRequest::default()
    };
    let preview = lab.preview(&zone, file, claim).await;
    assert_eq!(listed(&preview), ["ws01.corp.example.test/A"]);
    let got = held(&preview);
    assert_eq!(got.get("ws02.corp.example.test/A"), Some(&HeldReason::Rule));
    assert_eq!(got.get("ws03.corp.example.test/A"), Some(&HeldReason::Rule));
    // An approval of the narrowed set needs the same rule: without it the set is larger
    // and the digest is not the one approved.
    let mut approval = approve(&preview, rule.clone());
    approval.rule = ClaimRule::default();
    let error = lab
        .import(&zone, file, approval)
        .await
        .expect_err("refused");
    assert_eq!(error.coded().code, claim::CLAIMABLE_CHANGED);
    let report = lab
        .import(&zone, file, approve(&preview, rule))
        .await
        .expect("import");
    assert_eq!(listed(&report), ["ws01.corp.example.test/A"]);
    assert_eq!(
        lab.origin(&zone, "ws02.corp.example.test", Rtype::A).await,
        Some(Origin::Manual)
    );
    // Under a suffix, and the address of a PTR record's name.
    let reverse = lab.zone(REVERSE).await;
    let file = "\
$ORIGIN 2.0.192.in-addr.arpa.
21 [AGE:1] 600 PTR ws01.corp.example.test.
22 [AGE:1] 600 PTR ws02.lab.example.test.
";
    let preview = lab
        .preview(
            &reverse,
            file,
            ClaimRequest {
                rule: ClaimRule {
                    under: vec![name(APEX)],
                    within: vec!["192.0.2.16/28".parse().expect("prefix")],
                    except: Vec::new(),
                },
                ..ClaimRequest::default()
            },
        )
        .await;
    assert_eq!(listed(&preview), ["21.2.0.192.in-addr.arpa/PTR"]);
}

/// The audit record of an import names what it made claimable: the count, the digest, the
/// rule and the names with their types; who imported is the record's principal.
#[tokio::test]
async fn the_audit_record_names_what_was_made_claimable() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let preview = lab.preview(&zone, TWO_HOSTS, ClaimRequest::default()).await;
    lab.import(&zone, TWO_HOSTS, approve(&preview, ClaimRule::default()))
        .await
        .expect("import");
    let audit = lab.audit().await;
    let record = audit
        .iter()
        .rev()
        .find(|record| record.draft.action == tenko_core::dns::audit::RECORD_IMPORT)
        .expect("the import's audit record");
    let context = &record.draft.details.context;
    assert_eq!(context.get("claimable").map(String::as_str), Some("2"));
    assert_eq!(
        context.get("claimable_digest"),
        preview.claimable_digest.as_ref()
    );
    assert_eq!(
        context.get("claimable_names").map(String::as_str),
        Some("ws01.corp.example.test/A ws02.corp.example.test/AAAA")
    );
    assert_eq!(
        context.get("claimable_rule").map(String::as_str),
        Some("every candidate")
    );
    assert_eq!(
        context.get("file_sha256"),
        Some(&claim::file_digest(TWO_HOSTS)),
        "an archived file can be checked against the import"
    );
    assert_eq!(record.principal, cx().principal);
}

/// A PTR record at a name outside the address tree would hand that name to the host it
/// points at: in a forward zone it is never claimable, and the owner name of a PTR RRset is
/// checked against the list like any other.
#[tokio::test]
async fn a_pointer_outside_the_address_tree_stays_static() {
    let lab = lab();
    let zone = lab.zone(APEX).await;
    let file = "$ORIGIN corp.example.test.
wpad    [AGE:1] 600 PTR attacker.corp.example.test.
portal  [AGE:1] 600 PTR attacker.corp.example.test.
ns1     [AGE:1] 600 PTR attacker.corp.example.test.
ws01    [AGE:1] 600 A   192.0.2.21
";
    let preview = lab.preview(&zone, file, ClaimRequest::default()).await;
    let got = held(&preview);
    for (key, reason) in [
        ("wpad.corp.example.test/PTR", HeldReason::ServiceName),
        ("portal.corp.example.test/PTR", HeldReason::NotAHost),
        ("ns1.corp.example.test/PTR", HeldReason::NameServer),
    ] {
        assert_eq!(got.get(key), Some(&reason), "{key}: {got:?}");
    }
    assert_eq!(listed(&preview), ["ws01.corp.example.test/A"]);
    lab.import(&zone, file, approve(&preview, ClaimRule::default()))
        .await
        .expect("import");
    for owner in ["wpad", "portal", "ns1"] {
        assert_eq!(
            lab.origin(&zone, &format!("{owner}.{APEX}"), Rtype::PTR)
                .await,
            Some(Origin::Manual),
            "{owner}"
        );
    }
}

/// The peak of the bytes held while `f` runs, sampled every millisecond, and its time.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, Duration) {
    let held = || {
        let stats = GLOBAL.stats();
        stats
            .bytes_allocated
            .saturating_sub(stats.bytes_deallocated)
    };
    let base = held();
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut peak = 0usize;
            while !stop.load(Ordering::Relaxed) {
                peak = peak.max(held().saturating_sub(base));
                // test-lint: allow sleep the sampling interval of a measurement; no condition waits
                std::thread::sleep(Duration::from_millis(1));
            }
            peak
        })
    };
    let started = Instant::now();
    let out = f();
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let peak = sampler.join().expect("sampler");
    (out, peak, elapsed)
}

/// A file of 100,000 aged A records, the size of a large Windows domain: the preview lists
/// a page of 1,000 with a cursor, a page holds at most 5,000, the import makes all of them
/// claimable with one approval, its report lists the first 1,000 and its audit record the
/// first 100. The time and the peak of the bytes held are printed; the bounds asserted are
/// generous, for a debug build on a loaded machine.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the bounds of one large file, preview to audit"
)]
fn a_file_of_100000_aged_records_stays_within_the_bounds() {
    const COUNT: usize = 100_000;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut text = String::with_capacity(COUNT * 48);
    text.push_str("$ORIGIN corp.example.test.\n");
    for n in 0..COUNT {
        let _ = writeln!(
            text,
            "ws{n:06} [AGE:3660412] 1200 A 192.0.2.{}",
            n % 250 + 1
        );
    }
    let lab = lab();
    let zone = runtime.block_on(lab.zone(APEX));
    let (preview, peak, elapsed) =
        measure(|| runtime.block_on(lab.preview(&zone, &text, ClaimRequest::default())));
    println!(
        "preview of {COUNT} aged records: {elapsed:?}, peak {} KiB held, file {} KiB",
        peak / 1024,
        text.len() / 1024
    );
    assert_eq!(preview.claimable, COUNT as u64);
    assert_eq!(preview.claimable_names.len(), claim::DEFAULT_PAGE);
    assert_eq!(
        preview.claimable_names[0].name,
        name("ws000000.corp.example.test")
    );
    let next = preview.claimable_next.clone().expect("a next page");
    let page = runtime.block_on(lab.preview(
        &zone,
        &text,
        ClaimRequest {
            after: Some(claim::parse_cursor(&next).expect("cursor")),
            limit: Some(claim::MAX_PAGE),
            ..ClaimRequest::default()
        },
    ));
    assert_eq!(page.claimable_names.len(), claim::MAX_PAGE);
    assert_eq!(
        page.claimable_names[0].name,
        name("ws001000.corp.example.test")
    );
    assert_eq!(
        page.claimable_digest, preview.claimable_digest,
        "the page does not move the digest"
    );
    let error = runtime
        .block_on(lab.zones.preview_import(
            &cx(),
            &request(
                &zone,
                &text,
                ClaimRequest {
                    limit: Some(claim::MAX_PAGE + 1),
                    ..ClaimRequest::default()
                },
            ),
        ))
        .expect_err("a page past the bound");
    assert_eq!(error.coded().code, claim::CLAIMABLE_INVALID);
    let json = serde_json::to_vec(&page).expect("json");
    println!(
        "a page of {} entries is {} KiB of JSON",
        claim::MAX_PAGE,
        json.len() / 1024
    );
    assert!(
        json.len() < 2 << 20,
        "a page of short names stays under 2 MiB"
    );
    assert!(peak < 512 << 20, "the preview held {} MiB", peak >> 20);
    let (report, peak, elapsed) = measure(|| {
        runtime
            .block_on(lab.import(&zone, &text, approve(&preview, ClaimRule::default())))
            .expect("import")
    });
    println!(
        "import of {COUNT} claimable records: {elapsed:?}, peak {} KiB held",
        peak / 1024
    );
    assert_eq!(report.claimable, COUNT as u64);
    assert_eq!(report.claimable_names.len(), claim::DEFAULT_PAGE);
    let audit = runtime.block_on(lab.audit());
    let record = audit
        .iter()
        .rev()
        .find(|record| record.draft.action == tenko_core::dns::audit::RECORD_IMPORT)
        .expect("the import's audit record");
    let names = &record.draft.details.context["claimable_names"];
    assert_eq!(names.split(' ').count(), claim::MAX_AUDITED_NAMES);
    assert_eq!(
        record
            .draft
            .details
            .context
            .get("claimable_unlisted")
            .map(String::as_str),
        Some("99900")
    );
}

/// Past `MAX_CANDIDATES` aged records nothing of the file is followed: the preview gives no
/// digest and holds every candidate back, and an approval is refused.
#[test]
fn a_file_past_the_candidate_bound_makes_nothing_claimable() {
    let count = claim::MAX_CANDIDATES + 1;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut text = String::with_capacity(count * 48);
    text.push_str("$ORIGIN corp.example.test.\n");
    for n in 0..count {
        let _ = writeln!(text, "ws{n:06} [AGE:1] 1200 A 192.0.2.{}", n % 250 + 1);
    }
    let lab = lab();
    let zone = runtime.block_on(lab.zone(APEX));
    let preview = runtime.block_on(lab.preview(&zone, &text, ClaimRequest::default()));
    assert!(preview.claimable_overflow);
    assert_eq!(preview.claimable, 0);
    assert_eq!(preview.claimable_digest, None);
    assert_eq!(
        preview.claimable_names,
        Vec::<tenko_dns::zone::import::ClaimableEntry>::new()
    );
    assert_eq!(preview.held_back, count as u64);
    assert_eq!(preview.held_back_names.len(), claim::MAX_LISTED_HELD);
    assert!(
        preview
            .held_back_names
            .iter()
            .all(|entry| entry.reason == HeldReason::TooMany)
    );
    let error = runtime
        .block_on(lab.import(
            &zone,
            &text,
            ClaimRequest {
                approval: Some(tenko_dns::zone::import::ClaimDigest([0; 32])),
                ..ClaimRequest::default()
            },
        ))
        .expect_err("refused");
    assert_eq!(error.coded().code, claim::CLAIMABLE_TOO_MANY);
    assert_eq!(error.coded().status, 422);
}
