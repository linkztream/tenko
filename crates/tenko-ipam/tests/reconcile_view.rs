//! The reconciliation view (IPAM-21, IPAM-23, WP8.2) against seeded truths: intent, lease
//! facts written by the DHCP hook, DNS record facts, probe and inventory sightings. Every
//! seeded case is listed with its rule and nothing else is; the OS field follows the
//! precedence (inventory, then an active scan, then the DHCP fingerprint); the filters and
//! the paging.

mod common;
mod reconcile_support;

use std::{net::IpAddr, sync::Arc, time::Duration};

use common::*;
use reconcile_support::*;
use tenko_core::{
    HostId, NodeId, ObservationId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, ClientKey, DdnsState, Fingerprint, Lease},
    ipam::AssignmentMode,
    net::Fqdn,
    observe::{Observation, ObservationSource, Observed, ProbeMethod},
    serde_util::HexBytes,
};
use tenko_ipam::{
    IpamCommand,
    observe::{
        IngestBatch, ObserveConfig,
        dhcp::{LeaseClassifier, LeaseFacts, OsReading},
    },
    reconcile::view::{
        ReconcileKind, ReconcilePage, ReconcileQuery, ReconcileRow, Truth, WinRule,
        lease_conflicts, reconcile,
    },
};
use tenko_store::{ReadConsistency, WriteBatch};

/// The time the truths are seen: a month after the intent was written, so that an
/// address nothing shows is older than the orphan age.
fn base() -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(30 * 86_400))
        .expect("time")
}

fn later(minutes: u64) -> Timestamp {
    base()
        .checked_add(Duration::from_secs(minutes * 60))
        .expect("time")
}

/// A classifier that reads the vendor class only.
struct ByVendor;

impl LeaseClassifier for ByVendor {
    fn os(&self, fingerprint: &Fingerprint) -> Option<OsReading> {
        match fingerprint.vendor_class.as_deref()? {
            "MSFT 5.0" => Some(OsReading {
                guess: "Windows 10 or 11".to_owned(),
                confidence: 85,
            }),
            vendor if vendor.starts_with("android-dhcp-") => Some(OsReading {
                guess: format!("Android {}", &vendor[13..]),
                confidence: 90,
            }),
            _ => None,
        }
    }
}

struct Lab {
    world: World,
    vrf: VrfId,
    leases: Arc<LeaseFacts>,
    printer: HostId,
    nas: HostId,
    tv: HostId,
}

impl Lab {
    async fn new() -> Self {
        let world = World::new();
        run(
            &world.service,
            vec![
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreatePrefix(prefix(None, "198.51.100.0/24")),
            ],
        )
        .await;
        let vrf = world.default_vrf().await;
        let printer = Self::host(
            &world,
            "printer",
            AssignmentMode::Reserved,
            ":20",
            "192.0.2.20",
            None,
        )
        .await;
        Self::host(
            &world,
            "camera",
            AssignmentMode::Dynamic,
            ":30",
            "192.0.2.30",
            None,
        )
        .await;
        let nas = Self::host(
            &world,
            "nas",
            AssignmentMode::Static,
            ":80",
            "192.0.2.80",
            Some("nas.example.test"),
        )
        .await;
        let tv = Self::host(
            &world,
            "tv",
            AssignmentMode::Unmanaged,
            ":90",
            "192.0.2.90",
            None,
        )
        .await;
        let leases = LeaseFacts::new(NodeId(1), ObserveConfig::default());
        leases.register(world.store.as_ref()).expect("register");
        assert!(leases.set_classifier(Arc::new(ByVendor)));
        Self {
            world,
            vrf,
            leases,
            printer,
            nas,
            tv,
        }
    }

    async fn host(
        world: &World,
        name: &str,
        mode: AssignmentMode,
        mac_suffix: &str,
        ip: &str,
        dns: Option<&str>,
    ) -> HostId {
        let (input, interface) = host(name, mode, Some(&format!("00:00:5e:00:53{mac_suffix}")));
        let id = input.id.expect("id");
        let mut assigned = address(None, ip);
        assigned.interface = Some(interface);
        assigned.dns_name = dns.map(|name| name.parse().expect("name"));
        run(
            &world.service,
            vec![
                IpamCommand::CreateHost(input),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        id
    }

    /// A lease of `ip` to the MAC `00:00:5e:00:53:<low>` committed through the hook.
    async fn lease(&self, ip: &str, low: u8, vendor: Option<&str>) {
        let now = base();
        // Built from its serialized form, so that optional fields other packages add to the
        // row keep their defaults.
        let lease: Lease = serde_json::from_value(serde_json::json!({
            "addr": ip,
            "vrf": self.vrf,
            "scope": tenko_core::PrefixId::generate(),
            "client": ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, low]),
                client_id: None,
            },
            "state": BindingState::Active,
            "cltt": now,
            "ends": now.checked_add(Duration::from_secs(3_600)).expect("end"),
            "node": NodeId(1),
            "ddns": DdnsState::default(),
            "fingerprint": Fingerprint {
                parameters: HexBytes(vec![1, 3, 6, 15]),
                vendor_class: vendor.map(str::to_owned),
                ..Fingerprint::default()
            },
        }))
        .expect("a lease row");
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        self.leases
            .observe(&lease, now, &mut batch)
            .expect("observe");
        self.world.store.propose(batch).await.expect("commit");
    }

    /// Facts of one source at `base`.
    async fn ingest(&self, source: ObservationSource, subjects: Vec<Observed>) {
        let now = base();
        self.world
            .reconciler
            .ingest(IngestBatch {
                source: source.clone(),
                observations: subjects
                    .into_iter()
                    .map(|subject| Observation {
                        id: ObservationId::generate(),
                        source: source.clone(),
                        subject,
                        observed_at: now,
                        received_at: now,
                        expires_at: now.checked_add(Duration::from_secs(3_600)),
                    })
                    .collect(),
                complete: false,
                received_at: now,
            })
            .await
            .expect("ingest");
    }

    async fn view(&self, query: ReconcileQuery) -> ReconcilePage {
        let view = self
            .world
            .store
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view");
        reconcile(view.as_ref(), &query, later(1)).expect("the view")
    }

    /// The seeded world: one case of every kind and three quiet hosts.
    async fn seeded() -> Self {
        let lab = Self::new().await;
        // Quiet: the dynamic camera and the unmanaged TV have their leases; the NAS is seen
        // by a probe and has its forward record.
        lab.lease("192.0.2.30", 0x30, None).await;
        lab.lease("192.0.2.90", 0x90, Some("android-dhcp-13")).await;
        // A rogue: a Windows laptop nobody knows.
        lab.lease("192.0.2.50", 0x50, Some("MSFT 5.0")).await;
        // A conflict: a lease and another device answering ARP at one address.
        lab.lease("192.0.2.60", 0x60, None).await;
        let arp = ObservationSource::Probe {
            node: NodeId(7),
            method: ProbeMethod::Arp,
        };
        let seen = |ip: &str, low: u8| Observed::Address {
            vrf: lab.vrf,
            ip: ip.parse().expect("ip"),
            mac: Some(tenko_core::MacAddr::new([
                0x00, 0x00, 0x5e, 0x00, 0x53, low,
            ])),
        };
        lab.ingest(
            arp,
            vec![seen("192.0.2.60", 0x61), seen("192.0.2.80", 0x80)],
        )
        .await;
        // An orphan (a hand-written record of an address nobody holds) and a PTR mismatch
        // (the NAS's PTR names another host).
        let name = |ip: &str, name: &str| Observed::Name {
            ip: ip.parse().expect("ip"),
            name: name.to_owned(),
        };
        lab.ingest(
            ObservationSource::DnsRecord {
                zone: Fqdn::new("example.test").expect("zone"),
            },
            vec![
                name("192.0.2.70", "old.example.test"),
                name("192.0.2.80", "nas.example.test"),
            ],
        )
        .await;
        lab.ingest(
            ObservationSource::DnsRecord {
                zone: Fqdn::new("2.0.192.in-addr.arpa").expect("zone"),
            },
            vec![name("192.0.2.80", "storage.example.test")],
        )
        .await;
        // The reconciler proposes the rogue as a discovered host.
        lab.world.reconcile(base()).await;
        lab
    }
}

fn kinds(page: &ReconcilePage) -> Vec<(String, ReconcileKind)> {
    page.items
        .iter()
        .map(|row| (row.address.to_string(), row.kind))
        .collect()
}

fn row(page: &ReconcilePage, kind: ReconcileKind) -> &ReconcileRow {
    page.items
        .iter()
        .find(|row| row.kind == kind)
        .unwrap_or_else(|| panic!("a {kind:?} row in {:?}", kinds(page)))
}

#[tokio::test]
async fn the_view_lists_every_seeded_case_and_nothing_else() {
    let lab = Lab::seeded().await;
    let page = lab.view(ReconcileQuery::default()).await;
    assert_eq!(
        kinds(&page),
        [
            ("192.0.2.20".to_owned(), ReconcileKind::Ghost),
            ("192.0.2.50".to_owned(), ReconcileKind::Rogue),
            ("192.0.2.60".to_owned(), ReconcileKind::Conflict),
            ("192.0.2.70".to_owned(), ReconcileKind::Orphan),
            ("192.0.2.80".to_owned(), ReconcileKind::PtrMismatch),
        ]
    );
    assert_eq!(page.next_cursor, None);

    let ghost = row(&page, ReconcileKind::Ghost);
    assert_eq!(ghost.host, Some(lab.printer));
    assert_eq!(
        (ghost.rule_id, ghost.winner),
        (WinRule::IntentManaged, Some(Truth::Intent))
    );
    assert_eq!(ghost.last_seen, None, "never seen");
    assert_eq!(
        ghost
            .intent
            .as_ref()
            .and_then(|intent| intent.host_name.as_deref()),
        Some("printer")
    );

    let rogue = row(&page, ReconcileKind::Rogue);
    assert_eq!(rogue.host, None);
    assert_eq!(
        (rogue.rule_id, rogue.winner),
        (WinRule::NewestSighting, Some(Truth::Lease))
    );
    assert!(
        rogue.proposal.is_some(),
        "the discovered-host proposal is linked"
    );
    assert_eq!(
        rogue.os.as_ref().map(|os| os.guess.as_str()),
        Some("Windows 10 or 11")
    );
    assert_eq!(rogue.vendors, ["MSFT 5.0"]);
    assert_eq!(
        rogue.lease.as_ref().map(|lease| lease.sources.clone()),
        Some(vec!["dhcp:1".to_owned()])
    );

    let conflict = row(&page, ReconcileKind::Conflict);
    assert_eq!(
        (conflict.rule_id, conflict.winner),
        (WinRule::NeverAutomatic, None)
    );
    assert_eq!(
        conflict
            .macs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["00:00:5e:00:53:60", "00:00:5e:00:53:61"]
    );

    let orphan = row(&page, ReconcileKind::Orphan);
    assert_eq!(
        (orphan.rule_id, orphan.winner),
        (WinRule::ManualRecord, Some(Truth::Dns))
    );
    assert_eq!(
        orphan.dns.as_ref().map(|dns| dns.forward.clone()),
        Some(vec!["old.example.test".to_owned()])
    );

    let mismatch = row(&page, ReconcileKind::PtrMismatch);
    assert_eq!(mismatch.host, Some(lab.nas));
    assert_eq!(
        (mismatch.rule_id, mismatch.winner),
        (WinRule::IntentManaged, Some(Truth::Intent))
    );
    assert_eq!(
        mismatch.dns.as_ref().map(|dns| dns.ptr.clone()),
        Some(vec!["storage.example.test".to_owned()])
    );

    // The health view's conflicts are the conflict rows.
    let view = lab
        .world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let conflicts = lease_conflicts(view.as_ref(), later(1)).expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].address.to_string(), "192.0.2.60");
}

#[tokio::test]
async fn filters_and_paging_cut_the_view() {
    let lab = Lab::seeded().await;
    let ghosts = lab
        .view(ReconcileQuery {
            kind: Some(ReconcileKind::Ghost),
            ..ReconcileQuery::default()
        })
        .await;
    assert_eq!(
        kinds(&ghosts),
        [("192.0.2.20".to_owned(), ReconcileKind::Ghost)]
    );

    let view = lab.world.service.view(None).await.expect("view");
    let other = tenko_ipam::query::list::<tenko_core::ipam::Prefix>(
        view.as_ref(),
        &tenko_ipam::query::ListQuery::default(),
    )
    .expect("prefixes")
    .items
    .into_iter()
    .find(|prefix| prefix.cidr.to_string() == "198.51.100.0/24")
    .expect("the other prefix");
    let empty = lab
        .view(ReconcileQuery {
            prefix: Some(other.id),
            ..ReconcileQuery::default()
        })
        .await;
    assert_eq!(empty.items, Vec::new());

    // A host: its rows and its truths.
    let nas = lab
        .view(ReconcileQuery {
            host: Some(lab.nas),
            ..ReconcileQuery::default()
        })
        .await;
    assert_eq!(
        kinds(&nas),
        [("192.0.2.80".to_owned(), ReconcileKind::PtrMismatch)]
    );
    let truths = nas.host.expect("the host's truths");
    assert_eq!(truths.name, "nas");
    assert_eq!(truths.ips, ["192.0.2.80".parse::<IpAddr>().expect("ip")]);
}

#[tokio::test]
async fn pages_carry_on_where_the_last_ended_and_bad_queries_are_refused() {
    let lab = Lab::seeded().await;
    // Pages of two, then the rest; the cursor carries on where the page ended.
    let first = lab
        .view(ReconcileQuery {
            limit: Some(2),
            ..ReconcileQuery::default()
        })
        .await;
    assert_eq!(first.items.len(), 2);
    let second = lab
        .view(ReconcileQuery {
            limit: Some(2),
            cursor: first.next_cursor.clone(),
            ..ReconcileQuery::default()
        })
        .await;
    let third = lab
        .view(ReconcileQuery {
            limit: Some(2),
            cursor: second.next_cursor.clone(),
            ..ReconcileQuery::default()
        })
        .await;
    assert_eq!(third.next_cursor, None);
    let all: Vec<String> = [first, second, third]
        .iter()
        .flat_map(|page| page.items.iter().map(|row| row.address.to_string()))
        .collect();
    assert_eq!(
        all,
        [
            "192.0.2.20",
            "192.0.2.50",
            "192.0.2.60",
            "192.0.2.70",
            "192.0.2.80"
        ]
    );

    // Unknown objects and a bad limit are refused.
    let view = lab
        .world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    for query in [
        ReconcileQuery {
            host: Some(HostId::generate()),
            ..ReconcileQuery::default()
        },
        ReconcileQuery {
            limit: Some(0),
            ..ReconcileQuery::default()
        },
        ReconcileQuery {
            cursor: Some("not hex".to_owned()),
            ..ReconcileQuery::default()
        },
    ] {
        assert!(
            reconcile(view.as_ref(), &query, later(1)).is_err(),
            "{query:?}"
        );
    }
}

#[tokio::test]
async fn the_os_field_follows_the_precedence_of_the_sources() {
    let lab = Lab::seeded().await;
    let truths = |page: ReconcilePage| page.host.expect("the host's truths");
    let tv = ReconcileQuery {
        host: Some(lab.tv),
        ..ReconcileQuery::default()
    };
    // The unmanaged TV: its lease's options 55 and 60 set the OS field.
    let first = truths(lab.view(tv.clone()).await);
    let os = first.os.expect("an OS");
    assert_eq!((os.guess.as_str(), os.truth), ("Android 13", Truth::Lease));
    assert_eq!(os.source, "dhcp:1");
    assert_eq!(first.vendors, ["android-dhcp-13"]);

    // An active scan's guess outranks it, even at a lower confidence.
    lab.ingest(
        ObservationSource::Probe {
            node: NodeId(7),
            method: ProbeMethod::OsFingerprint,
        },
        vec![Observed::Os {
            ip: "192.0.2.90".parse().expect("ip"),
            guess: "Linux 5.x".to_owned(),
            confidence: 60,
        }],
    )
    .await;
    let second = truths(lab.view(tv.clone()).await);
    assert_eq!(
        second.os.as_ref().map(|os| (os.guess.as_str(), os.truth)),
        Some(("Linux 5.x", Truth::Scan))
    );
    assert_eq!(second.os_guesses.len(), 2);

    // An inventory's own statement outranks both.
    lab.world
        .poll(
            vec![vm(
                "media/1",
                Some("tv"),
                Some("00:00:5e:00:53:90"),
                &["192.0.2.90"],
            )],
            base(),
        )
        .await;
    let third = truths(lab.view(tv).await);
    assert_eq!(
        third
            .os
            .as_ref()
            .map(|os| (os.guess.as_str(), os.confidence)),
        Some(("Linux 6.x", 100))
    );
    // The TV is unmanaged and its lease agrees with intent: no row.
    let rows = lab
        .view(ReconcileQuery {
            host: Some(lab.tv),
            ..ReconcileQuery::default()
        })
        .await
        .items;
    assert_eq!(rows, Vec::new());
}
