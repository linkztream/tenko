//! The template of the reverse zones IPAM keeps (the owner's backlog, `docs/dns.md`
//! section 7): the tenant's default zone lends new reverse zones their SOA values and
//! name servers, the reverse zones follow when the template changes or goes, and a zone an
//! operator edited by hand stays as it is.

mod common;

use std::sync::Arc;

use common::{all_of, person, prefix, run, try_run};
use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{
        DnsName, Origin, RecordData, Rtype, ScopeName, SerialPolicy, SoaDefaults, TenantDns,
        ZoneId, ZoneKind, codes::DEFAULT_ZONE_INVALID,
    },
    ipam::Tenant,
};
use tenko_dns::zone::{
    NewZone, ZoneChange, ZoneConfig, ZoneService,
    records::{Change, Op},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    command::{TenantPatch, UpdateTenant},
    dns::{DnsActuation, DnsActuator, PlanOptions, REVERSE_TEMPLATES},
};
use tenko_store::{MemStore, ReadConsistency, ReadViewExt, Store};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

struct Lab {
    ipam: Arc<IpamService>,
    zones: Arc<ZoneService>,
    actuator: DnsActuator,
    store: MemStore,
}

async fn lab() -> Lab {
    let store = MemStore::default();
    let dyn_store = Arc::new(store.clone()) as Arc<dyn Store>;
    let ipam = IpamService::with_direct_jobs(Arc::clone(&dyn_store)).expect("ipam");
    ipam.ensure_defaults(&RequestCtx::system(SystemComponent::Ipam))
        .await
        .expect("defaults");
    let zones = ZoneService::with_direct_jobs(dyn_store, None, ZoneConfig::default());
    let actuator = DnsActuator::new(Arc::clone(&zones));
    Lab {
        ipam,
        zones,
        actuator,
        store,
    }
}

fn reconciler() -> RequestCtx {
    RequestCtx::system(SystemComponent::Reconciler)
}

impl Lab {
    async fn zone(&self, apex: &str, server: &str) -> ZoneId {
        let new = NewZone {
            name: name(apex),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: Vec::new(),
            serial: SerialPolicy::Counter,
            soa: SoaDefaults::new(name(server), name("hostmaster.example.test")),
            name_servers: vec![name(server)],
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: tenko_core::dns::UpdatePolicy::default(),
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            description: None,
            reverse_of: None,
            catalog: false,
        };
        self.zones
            .create(&person(), new)
            .await
            .expect("zone")
            .zone
            .id
    }

    async fn network(&self, cidr: &str) {
        run(
            &self.ipam,
            vec![IpamCommand::CreatePrefix(prefix(None, cidr))],
        )
        .await;
    }

    async fn actuate(&self) -> DnsActuation {
        let report = self
            .actuator
            .run(&reconciler(), &PlanOptions::default())
            .await
            .expect("run");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        report
    }

    /// The SOA values, the apex name servers and the description of a zone.
    async fn apex(&self, apex: &str) -> (SoaDefaults, Vec<String>, Option<String>) {
        let view = self.zones.view(None).await.expect("view");
        let row = ZoneService::zone_by_name(view.as_ref(), &name(apex))
            .expect("zones")
            .expect("zone");
        let (rrsets, _) = ZoneService::rrsets(
            view.as_ref(),
            &row.zone,
            &tenko_dns::zone::RrSetFilter::scope(ScopeName::DEFAULT),
            None,
            usize::MAX,
        )
        .expect("rrsets");
        let mut servers: Vec<String> = rrsets
            .into_iter()
            .map(|(rrset, _)| rrset)
            .filter(|rrset| rrset.rtype == Rtype::NS && rrset.name == row.zone.name)
            .flat_map(|rrset| rrset.records().expect("records"))
            .filter_map(|record| match record {
                RecordData::Ns { host } => Some(host.to_string()),
                _ => None,
            })
            .collect();
        servers.sort();
        (row.zone.soa, servers, row.zone.description)
    }

    async fn servers(&self, apex: &str) -> Vec<String> {
        self.apex(apex).await.1
    }

    /// Sets the apex NS set of a zone as a person does.
    async fn set_servers(&self, apex: &str, servers: &[&str]) {
        let id = self.id_of(apex).await;
        let change = Change {
            op: Op::Set,
            scope: ScopeName::DEFAULT,
            name: name(apex),
            rtype: Rtype::NS,
            ttl: None,
            records: servers
                .iter()
                .map(|host| RecordData::Ns { host: name(host) })
                .collect(),
            take_over: false,
            origin: Origin::Manual,
        };
        self.zones
            .change_records(&person(), id, &[change], false)
            .await
            .expect("name servers");
    }

    async fn id_of(&self, apex: &str) -> ZoneId {
        let view = self.zones.view(None).await.expect("view");
        ZoneService::zone_by_name(view.as_ref(), &name(apex))
            .expect("zones")
            .expect("zone")
            .zone
            .id
    }

    async fn default_tenant(&self) -> Tenant {
        all_of::<Tenant>(&self.ipam)
            .await
            .into_iter()
            .find(|tenant| tenant.name == "default")
            .expect("default tenant")
    }

    fn set_default_zone(tenant: &Tenant, zone: Option<ZoneId>) -> IpamCommand {
        IpamCommand::UpdateTenant(UpdateTenant {
            id: tenant.id,
            expected: None,
            patch: TenantPatch {
                dns: Some(TenantDns { default_zone: zone }),
                ..TenantPatch::default()
            },
        })
    }

    async fn templates(&self) -> usize {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(
            &REVERSE_TEMPLATES,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("scan")
        .len()
    }
}

const REVERSE: &str = "2.0.192.in-addr.arpa";

#[tokio::test]
async fn the_default_zone_lends_new_reverse_zones_their_servers() {
    let lab = lab().await;
    lab.zone("a.example.test", "ns1.example.test").await;
    let home = lab.zone("home.example.test", "ns2.example.test").await;
    let tenant = lab.default_tenant().await;
    run(&lab.ipam, vec![Lab::set_default_zone(&tenant, Some(home))]).await;
    assert_eq!(
        lab.default_tenant().await.dns.default_zone,
        Some(home),
        "the tenant keeps its default zone"
    );

    lab.network("192.0.2.0/24").await;
    let report = lab.actuate().await;
    assert_eq!(report.zones_created, 1);
    let (soa, servers, description) = lab.apex(REVERSE).await;
    assert_eq!(servers, ["ns2.example.test"]);
    assert_eq!(soa.mname, name("ns2.example.test"));
    assert_eq!(
        description.as_deref(),
        Some("Reverse zone kept by IPAM; SOA and name servers from home.example.test")
    );
    assert_eq!(lab.templates().await, 1, "the template is recorded");
}

#[tokio::test]
async fn reverse_zones_follow_a_default_zone_chosen_later() {
    let lab = lab().await;
    lab.zone("a.example.test", "ns1.example.test").await;
    let home = lab.zone("home.example.test", "ns2.example.test").await;
    lab.network("192.0.2.0/24").await;
    lab.actuate().await;
    assert_eq!(
        lab.servers(REVERSE).await,
        ["ns1.example.test"],
        "the first zone"
    );

    let tenant = lab.default_tenant().await;
    run(&lab.ipam, vec![Lab::set_default_zone(&tenant, Some(home))]).await;
    let report = lab.actuate().await;
    assert_eq!(report.zones_followed, 1);
    let (soa, servers, description) = lab.apex(REVERSE).await;
    assert_eq!(servers, ["ns2.example.test"]);
    assert_eq!(soa.mname, name("ns2.example.test"));
    assert!(
        description
            .as_deref()
            .is_some_and(|d| d.ends_with("from home.example.test")),
        "{description:?}"
    );
    assert_eq!(
        lab.actuate().await.zones_followed,
        0,
        "nothing more to follow"
    );
}

#[tokio::test]
async fn reverse_zones_follow_their_template_and_leave_edited_ones_alone() {
    let lab = lab().await;
    let forward = lab.zone("example.test", "ns1.example.test").await;
    lab.network("192.0.2.0/24").await;
    lab.network("198.51.100.0/24").await;
    let report = lab.actuate().await;
    assert_eq!(report.zones_created, 2);
    // An operator edits one reverse zone by hand.
    lab.set_servers("100.51.198.in-addr.arpa", &["ns9.example.test"])
        .await;

    // The template's name servers and SOA change.
    lab.set_servers("example.test", &["ns3.example.test", "ns4.example.test"])
        .await;
    let mut soa = SoaDefaults::new(name("ns3.example.test"), name("hostmaster.example.test"));
    soa.refresh = 7200;
    lab.zones
        .update(
            &person(),
            forward,
            ZoneChange {
                soa: Some(soa.clone()),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect("soa");

    let report = lab.actuate().await;
    assert_eq!(report.zones_followed, 1);
    let (followed_soa, servers, _) = lab.apex(REVERSE).await;
    assert_eq!(servers, ["ns3.example.test", "ns4.example.test"]);
    assert_eq!(followed_soa, soa);
    let (edited_soa, servers, _) = lab.apex("100.51.198.in-addr.arpa").await;
    assert_eq!(servers, ["ns9.example.test"], "the edited zone stays");
    assert_eq!(edited_soa.mname, name("ns1.example.test"));
}

#[tokio::test]
async fn deleting_the_template_moves_the_reverse_zones_to_the_next() {
    let lab = lab().await;
    let first = lab.zone("a.example.test", "ns1.example.test").await;
    lab.zone("b.example.test", "ns2.example.test").await;
    lab.network("192.0.2.0/24").await;
    lab.actuate().await;
    assert_eq!(lab.servers(REVERSE).await, ["ns1.example.test"]);

    lab.zones
        .delete(&person(), first, None)
        .await
        .expect("delete");
    let report = lab.actuate().await;
    assert_eq!(report.zones_followed, 1);
    let (_, servers, description) = lab.apex(REVERSE).await;
    assert_eq!(servers, ["ns2.example.test"]);
    assert!(
        description
            .as_deref()
            .is_some_and(|d| d.ends_with("from b.example.test")),
        "{description:?}"
    );
}

#[tokio::test]
async fn the_default_zone_is_a_primary_forward_zone_of_the_tenant() {
    let lab = lab().await;
    lab.zone("example.test", "ns1.example.test").await;
    lab.network("192.0.2.0/24").await;
    lab.actuate().await;
    let reverse = lab.id_of(REVERSE).await;
    let tenant = lab.default_tenant().await;

    for (zone, reason) in [(reverse, "reverse"), (ZoneId::generate(), "missing")] {
        let error = try_run(&lab.ipam, vec![Lab::set_default_zone(&tenant, Some(zone))])
            .await
            .expect_err("refused");
        assert_eq!(error.code_str(), DEFAULT_ZONE_INVALID);
        assert_eq!(error.coded().status, 409);
        assert_eq!(
            error.coded().params.get("reason").map(String::as_str),
            Some(reason)
        );
    }
    // Clearing it is always allowed.
    run(&lab.ipam, vec![Lab::set_default_zone(&tenant, None)]).await;
    assert_eq!(lab.default_tenant().await.dns.default_zone, None);
}
