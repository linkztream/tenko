//! The DDNS worker over the in-memory store (WP8.3, plan section 2.9, ADR 0020): lease
//! rows are written as the committer and the expiry service write them, and the worker
//! follows them into the zones through the zone service, which writes through the job
//! engine as the server's does.
//!
//! - Name updates write no job: new clients at every address of the pool, round after
//!   round, leave the job tables and the job audit records as they were, and each change
//!   set is audited at the time it was written, while an operator's edit through the same
//!   zone service is a job. Only the DHCP component itself, through
//!   `change_dhcp_names`, writes without a job. A stale name update is planned again; one
//!   the store refuses shows on the lease and in `tenko_dhcp_ddns_total{outcome="failed"}`.
//! - A client with option 81 and a legacy client with option 12 only get their A record,
//!   their DHCID and their PTR; the lease rows record the names and the DHCID.
//! - A second client that claims the first one's name is refused by name protection, and
//!   its lease says why; under `replace` it takes the name over.
//! - A release and an expiry remove the records whose DHCID still matches; while the clock
//!   guard holds the clock, an active row past its end keeps them.
//! - An address IPAM names, and a name held by a manual RRset, are left alone.
//! - Under Standard a zone takes DHCP updates only when its policy allows them.
//! - A client that asks to write its A record itself, where the scope allows that, gets
//!   only its PTR.
//! - The DDNS settings a policy decided for the client (the row's `ddns_policy`) win over
//!   the scope's, both ways.
//! - A name that holds records of another origin of any type (a manual MX or TXT) is
//!   refused like one with a manual A.
//! - A name below a child zone Tenko serves, or below a delegation, is not the forward
//!   zone's: it is cut to its first label under the forward zone or refused, and the
//!   parent zone never holds it.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tenko_core::testing::wait_until_async;
use tenko_core::{
    AddressId, NodeId, PrefixId, Principal, RangeId, RequestCtx, SystemComponent, Timestamp,
    UserId, VrfId,
    cluster::{LEADER_EPOCH, LeaderService as _},
    dhcp::{BindingState, ClientKey, DdnsConflict, DdnsPolicy, DdnsState, Lease, tables::LEASES},
    dns::{
        DnsName, Origin, RecordData, RrSet, RrSetKey, Rtype, ScopeName, SerialPolicy, SoaDefaults,
        TextBytes, UpdatePolicy, ZoneId, ZoneKind, tables::RRSETS,
    },
    ipam::{Address, AllocPolicy, Meta, Prefix, PrefixRole, Range, RangeRole, Stamp, Status},
    net::Fqdn,
    serde_util::HexBytes,
};
use tenko_dhcp::{
    config::{
        ConfigService,
        scopes::{NewScope, ScopeChange},
    },
    ddns::{
        DdnsProfile, DdnsService, DdnsSettings, dhcid,
        metrics::{OLDEST, OUTCOMES, Outcome, QUEUE},
        plan::DHCID,
    },
    v4::ClientFqdn,
};
use tenko_dns::zone::{
    ImportStaging, NewZone, ZoneConfig, ZoneService,
    records::{Change, Op},
    register_steps,
};
use tenko_ipam::tables::{ADDRESS_IPS, ADDRESSES, PREFIX_RANGES, PREFIXES, RANGES};
use tenko_jobs::{
    EngineConfig, JobEngine,
    tables::{BY_STATE, BY_TARGET, IDEMPOTENCY, JOBS, PREVIEWS, TRANSITIONS},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, Leadership, MemStore, Mutation,
    ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter,
    WriteBatch, tables::AUDIT,
};
use tokio_util::sync::CancellationToken;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::new(Principal::system(SystemComponent::Api))
}

fn meta() -> Meta {
    Meta::new(Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    ))
}

fn mac(last: u8) -> Vec<u8> {
    vec![0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

fn client(last: u8) -> ClientKey {
    ClientKey {
        htype: 1,
        chaddr: HexBytes(mac(last)),
        client_id: None,
    }
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

struct Lab {
    store: Arc<dyn Store>,
    zones: Arc<ZoneService>,
    config: Arc<ConfigService>,
    vrf: VrfId,
    scope: PrefixId,
    forward: ZoneId,
    reverse: ZoneId,
    profile: Arc<Mutex<DdnsProfile>>,
    settings: DdnsSettings,
    stop: CancellationToken,
}

/// The spacing of the labs whose test is not about it: short, so that each step's names
/// follow at once.
const SHORT: Duration = Duration::from_millis(10);

fn new_zone(apex: &str, update: UpdatePolicy) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        name_servers: vec![name("ns1.example.test")],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update,
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
        catalog: false,
    }
}

async fn lab(profile: DdnsProfile, update: UpdatePolicy) -> Lab {
    lab_on(profile, update, Arc::new(MemStore::default())).await
}

/// A lab on `store` whose zone service writes through the job engine, as the server's
/// does.
async fn lab_on(profile: DdnsProfile, update: UpdatePolicy, store: Arc<dyn Store>) -> Lab {
    lab_with(profile, update, store, ZoneConfig::default(), SHORT).await
}

/// [`lab_on`] with the zone service's limits `config` and the worker's `spacing`.
#[allow(
    clippy::too_many_lines,
    reason = "the zones, the network, the scope and the worker of one lab"
)]
async fn lab_with(
    profile: DdnsProfile,
    update: UpdatePolicy,
    store: Arc<dyn Store>,
    config: ZoneConfig,
    spacing: Duration,
) -> Lab {
    let staging = Arc::new(ImportStaging::default());
    let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
    register_steps(&mut engine, &staging);
    let zones = ZoneService::new(Arc::clone(&store), Arc::new(engine), None, staging, config);
    let forward = zones
        .create(&cx(), new_zone("lan.example.test", update.clone()))
        .await
        .expect("forward zone")
        .zone
        .id;
    let reverse = zones
        .create(&cx(), new_zone("2.0.192.in-addr.arpa", update))
        .await
        .expect("reverse zone")
        .zone
        .id;
    let config = ConfigService::with_direct_jobs(Arc::clone(&store));
    let vrf = VrfId::generate();
    let prefix = Prefix {
        id: PrefixId::generate(),
        vrf,
        cidr: "192.0.2.0/24".parse().expect("cidr"),
        role: PrefixRole::Network,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        dns_reverse: None,
        meta: meta(),
    };
    let range = Range {
        id: RangeId::generate(),
        prefix: prefix.id,
        first: ip(50).into(),
        last: ip(99).into(),
        role: RangeRole::DhcpPool,
        lease_secs: None,
        delegated_len: None,
        status: Status::Active,
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch
        .put_typed(&PREFIXES, &prefix.id, &prefix)
        .expect("prefix");
    batch.put_typed(&RANGES, &range.id, &range).expect("range");
    batch
        .put_typed(&PREFIX_RANGES, &(prefix.id, range.id), &())
        .expect("index");
    store.propose(batch).await.expect("IPAM rows");
    config
        .create_scope(
            &cx(),
            NewScope {
                v6: None,
                prefix: prefix.id,
                enabled: None,
                lease: None,
                authoritative: None,
                server_id: None,
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(forward),
                    ..DdnsPolicy::default()
                }),
                shared_network: None,
                restricted: false,
                classes: Vec::new(),
                description: None,
            },
        )
        .await
        .expect("scope");
    let mut lab = Lab {
        store,
        zones,
        config,
        vrf,
        scope: prefix.id,
        forward,
        reverse,
        profile: Arc::new(Mutex::new(profile)),
        settings: DdnsSettings {
            backoff: Duration::from_millis(20),
            retry_after: Duration::from_millis(200),
            spacing,
            ..DdnsSettings::default()
        },
        stop: CancellationToken::new(),
    };
    lab.restart();
    lab
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Lab {
    /// Stops the worker, if one runs, and starts a new one, as a restart or a change of
    /// leader does.
    fn restart(&mut self) {
        self.stop.cancel();
        self.stop = CancellationToken::new();
        let service = self.service();
        let token = self.stop.child_token();
        tokio::spawn(async move { service.run(0, token).await });
    }

    /// A worker over the lab's store and zones.
    fn service(&self) -> DdnsService {
        let profile = Arc::clone(&self.profile);
        let source = Arc::new(move |_: &dyn tenko_store::ReadView| {
            *profile.lock().unwrap_or_else(PoisonError::into_inner)
        });
        DdnsService::new(
            Arc::clone(&self.store),
            Arc::clone(&self.zones),
            source,
            self.settings,
        )
    }

    fn lease(&self, last: u8, who: u8, fqdn: Option<(&str, u8)>, hostname: Option<&str>) -> Lease {
        let now = Timestamp::now();
        Lease {
            addr: ip(last),
            vrf: self.vrf,
            scope: self.scope,
            client: client(who),
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: hostname.map(str::to_owned),
            fqdn: fqdn.map(|(name, _)| name.to_owned()),
            fqdn_flags: fqdn.map(|(_, flags)| flags),
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
            granted: None,
            adopted: None,
        }
    }

    /// Writes a lease row as the committer does: the held row's DDNS outcome stays, also
    /// for a new client at the address.
    async fn commit(&self, mut lease: Lease) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        if let Some((held, _)) = view
            .get_typed(&LEASES, &(lease.vrf, lease.addr))
            .expect("row")
        {
            lease.ddns = held.ddns;
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch
            .put_typed(&LEASES, &(lease.vrf, lease.addr), &lease)
            .expect("lease");
        self.store.propose(batch).await.expect("commit");
    }

    /// Writes new lease rows in one batch, so that the worker takes them in one window.
    async fn commit_all(&self, leases: impl IntoIterator<Item = Lease>) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        for lease in leases {
            batch
                .put_typed(&LEASES, &(lease.vrf, lease.addr), &lease)
                .expect("lease");
        }
        self.store.propose(batch).await.expect("commit");
    }

    /// The worker's change sets written to the zone `apex` (their audit records).
    async fn change_sets(&self, apex: &str) -> usize {
        self.set_times(apex).await.len()
    }

    /// The times of the worker's change sets to the zone `apex` (their audit records).
    async fn set_times(&self, apex: &str) -> Vec<Timestamp> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .filter(|(_, record, _)| {
                record.principal == Principal::system(SystemComponent::Dhcp)
                    && record.draft.action.as_str() == "dns.record.change"
                    && record.draft.details.context.get("zone").map(String::as_str) == Some(apex)
            })
            .map(|(_, record, _)| record.at)
            .collect()
    }

    /// Ends a binding as a release or the expiry service does.
    async fn end(&self, last: u8, state: BindingState) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let (mut lease, _) = view
            .get_typed(&LEASES, &(self.vrf, ip(last)))
            .expect("row")
            .expect("lease");
        lease.state = state;
        lease.ends = Timestamp::now();
        self.commit(lease).await;
    }

    async fn rrset(&self, zone: ZoneId, owner: &str, rtype: Rtype) -> Option<RrSet> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(
            &RRSETS,
            &RrSetKey {
                zone,
                scope: ScopeName::DEFAULT,
                name: name(owner),
                rtype,
            },
        )
        .expect("rrset")
        .map(|(set, _)| set)
    }

    async fn ddns(&self, last: u8) -> DdnsState {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(&LEASES, &(self.vrf, ip(last)))
            .expect("row")
            .map(|(lease, _)| lease.ddns)
            .unwrap_or_default()
    }

    async fn a(&self, owner: &str) -> Vec<RecordData> {
        self.rrset(self.forward, owner, Rtype::A)
            .await
            .map(|set| {
                set.rdata
                    .iter()
                    .map(|rdata| rdata.decode(Rtype::A).expect("A"))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn ptr(&self, last: u8) -> Option<RecordData> {
        self.rrset(
            self.reverse,
            &format!("{last}.2.0.192.in-addr.arpa"),
            Rtype::PTR,
        )
        .await
        .map(|set| set.rdata[0].decode(Rtype::PTR).expect("PTR"))
    }
}

fn a_of(last: u8) -> RecordData {
    RecordData::A { address: ip(last) }
}

/// Neither zone holds an A or a DHCID at `owner`.
async fn nothing_at(lab: &Lab, zones: [ZoneId; 2], owner: &str) {
    for zone in zones {
        for rtype in [Rtype::A, DHCID] {
            assert!(
                lab.rrset(zone, owner, rtype).await.is_none(),
                "{owner} {rtype} in a zone"
            );
        }
    }
}

/// The rows of the job engine's tables, and the audit records the engine writes (`jobs.*`).
async fn job_rows(store: &dyn Store) -> (usize, usize) {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let rows = [
        JOBS.name(),
        TRANSITIONS.name(),
        BY_STATE.name(),
        BY_TARGET.name(),
        PREVIEWS.name(),
        IDEMPOTENCY.name(),
    ]
    .into_iter()
    .map(|table| {
        view.scan(table, KeyRange::all(), usize::MAX, false)
            .expect("job rows")
            .len()
    })
    .sum();
    let records = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str().starts_with("jobs."))
        .count();
    (rows, records)
}

#[tokio::test]
async fn new_clients_at_every_address_leave_no_job_and_an_operator_edit_still_is_one() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let before = job_rows(lab.store.as_ref()).await;
    // Four rounds over the pool's 50 addresses, every lease a new MAC address with a name.
    // The last round starts after `last_round`, long after the worker started.
    let mut last_round = Timestamp::now();
    for round in 0..4u8 {
        if round == 3 {
            last_round = Timestamp::now();
        }
        for last in 50..100u8 {
            let who = round * 50 + (last - 50);
            lab.commit(lab.lease(last, who, None, Some(format!("host-{who}").as_str())))
                .await;
        }
        wait_until_async("the round's names", async || {
            for last in 50..100u8 {
                let want = name(&format!(
                    "host-{}.lan.example.test",
                    round * 50 + (last - 50)
                ));
                if lab.ddns(last).await.forward != Some(want) {
                    return false;
                }
            }
            true
        })
        .await;
    }
    assert_eq!(
        job_rows(lab.store.as_ref()).await,
        before,
        "name updates write no job row and no job audit record"
    );
    let view = lab.store.read(ReadConsistency::Local).await.expect("view");
    // What stays per name update is the lease row's DDNS state: one per address.
    let leases = view
        .scan_typed(&LEASES, KeyRange::all(), usize::MAX, false)
        .expect("leases");
    assert_eq!(leases.len(), 50);
    let audited: Vec<_> = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .filter(|record| {
            record.draft.action.as_str() == "dns.record.change"
                && record.principal == Principal::system(SystemComponent::Dhcp)
        })
        .collect();
    assert!(audited.len() >= 4, "the change sets are audited");
    // Each change set is stamped with the time it was written, not the worker's start.
    let last = audited.last().expect("a record");
    assert!(last.at >= last_round, "{} before {last_round}", last.at);

    // An operator's change through the same zone service is still a job.
    lab.zones
        .change_records(
            &cx(),
            lab.forward,
            &[Change {
                op: Op::Set,
                scope: ScopeName::DEFAULT,
                name: name("nas.lan.example.test"),
                rtype: Rtype::A,
                ttl: None,
                records: vec![a_of(9)],
                take_over: false,
                origin: Origin::Manual,
            }],
            false,
        )
        .await
        .expect("manual record");
    let (rows, records) = job_rows(lab.store.as_ref()).await;
    assert!(rows > before.0 && records > before.1, "the edit is a job");
}

/// A store (a memory store by default) that refuses the next `refuse` record change sets:
/// as a stale write when `stale` is set, else as a store without a quorum.
#[derive(Default)]
struct Refusing<S = MemStore> {
    inner: S,
    refuse: Mutex<usize>,
    stale: AtomicBool,
    /// RRsets a change set may write (zero: any number).
    max_rrsets: AtomicUsize,
    /// Lease rows a batch of the worker's outcomes may write (zero: any number).
    max_leases: AtomicUsize,
    /// The record change sets proposed.
    attempts: AtomicUsize,
    /// A writer's RRset put at a name of the next change set after that set was planned,
    /// with the zone's SOA put again (by its key): a race the set then loses.
    race: Mutex<Option<(RrSetKey, RrSet)>>,
    /// How long each change set takes to be written.
    delay: Mutex<Duration>,
    /// The lease rows read through each view the store handed out.
    lease_reads: Mutex<Vec<Arc<AtomicUsize>>>,
}

impl<S> Refusing<S> {
    fn refuse(&self) -> std::sync::MutexGuard<'_, usize> {
        self.refuse.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The most lease rows one view was asked for.
    fn most_lease_reads(&self) -> usize {
        self.lease_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|reads| reads.load(Ordering::SeqCst))
            .max()
            .unwrap_or_default()
    }
}

/// A view that counts the lease rows asked for by key.
struct CountingView {
    inner: Arc<dyn ReadView>,
    lease_reads: Arc<AtomicUsize>,
}

impl ReadView for CountingView {
    fn revision(&self) -> tenko_core::Revision {
        self.inner.revision()
    }

    fn get(
        &self,
        table: &tenko_core::TableName,
        key: &[u8],
    ) -> Result<Option<tenko_store::Versioned>, StoreError> {
        if table == LEASES.name() {
            self.lease_reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(table, key)
    }

    fn scan(
        &self,
        table: &tenko_core::TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(bytes::Bytes, tenko_store::Versioned)>, StoreError> {
        self.inner.scan(table, range, limit, reverse)
    }

    fn counter(&self, counter: &tenko_core::CounterKey) -> Result<u64, StoreError> {
        self.inner.counter(counter)
    }
}

#[async_trait::async_trait]
impl<S: Store> Store for Refusing<S> {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let records = batch
            .audit
            .iter()
            .any(|draft| draft.action.as_str() == "dns.record.change");
        if records {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let delay = *self.delay.lock().unwrap_or_else(PoisonError::into_inner);
            // test-lint: allow sleep a slow store is what the spacing test measures against
            tokio::time::sleep(delay).await;
            let race = self
                .race
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some((soa, rrset)) = race {
                let view = self.inner.read(ReadConsistency::Local).await?;
                let (held, _) = view.get_typed(&RRSETS, &soa)?.expect("the SOA");
                let mut other =
                    WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
                other.put_typed(&RRSETS, &soa, &held).expect("the SOA");
                other
                    .put_typed(&RRSETS, &rrset.key(), &rrset)
                    .expect("the RRset");
                self.inner.propose(other).await?;
            }
        }
        let refused = records && {
            let mut left = self.refuse();
            let refused = *left > 0;
            *left = left.saturating_sub(1);
            refused
        };
        if refused {
            return Err(if self.stale.load(Ordering::SeqCst) {
                StoreError::PreconditionFailed(Vec::new())
            } else {
                StoreError::NoQuorum
            });
        }
        // The store's batch limit, counted in the RRsets of a change set and in the lease
        // rows of the worker's outcomes (the batch behind its fence).
        let puts = |name: &tenko_core::TableName| {
            batch
                .mutations
                .iter()
                .filter(|mutation| matches!(mutation, Mutation::Put { table, .. } if table == name))
                .count()
        };
        for (applies, size, limit) in [
            (records, puts(RRSETS.name()), &self.max_rrsets),
            (
                !batch.preconditions.is_empty(),
                puts(LEASES.name()),
                &self.max_leases,
            ),
        ] {
            let limit = limit.load(Ordering::SeqCst);
            if applies && limit > 0 && size > limit {
                return Err(StoreError::BatchTooLarge { size, limit });
            }
        }
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        let lease_reads = Arc::new(AtomicUsize::new(0));
        self.lease_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&lease_reads));
        Ok(Arc::new(CountingView {
            inner: self.inner.read(consistency).await?,
            lease_reads,
        }))
    }

    fn watch(
        &self,
        from: Option<tenko_core::Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

fn dhcp_a(owner: &str, last: u8) -> Change {
    Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: None,
        records: vec![a_of(last)],
        take_over: false,
        origin: Origin::Dhcp,
    }
}

/// A store that refuses every change set: the failure shows on the lease and in the counter,
/// one zone's retries a batch, the rest of the batch failing with it; the oldest-wait gauge
/// counts the lease while it waits for its retry, and reads 0 once its name is written.
#[tokio::test]
async fn a_name_update_the_store_refuses_shows_on_the_lease_and_in_the_counter() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    *store.refuse() = usize::MAX;
    // The counter is the process's: nextest runs each test in a process of its own, so
    // only this test moves it.
    let failed = OUTCOMES.get(Outcome::Failed as u16);
    lab.commit(lab.lease(50, 1, None, Some("printer"))).await;
    wait_until_async("the failure on the lease", async || {
        lab.ddns(50)
            .await
            .last_error
            .is_some_and(|error| error.contains("sys.store.no_quorum"))
    })
    .await;
    assert!(OUTCOMES.get(Outcome::Failed as u16) > failed);
    assert_eq!(
        lab.a("printer.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    // The forward zone's write takes its retries, the reverse zone's fails with it untried:
    // two failed batches make at most three batches' worth of one zone's attempts (a third
    // batch may have started), where every zone's retries would make at least four.
    wait_until_async("a second failed batch", async || {
        OUTCOMES.get(Outcome::Failed as u16) >= failed + 2
    })
    .await;
    let one_zone = usize::try_from(DdnsSettings::default().retries).expect("retries") + 1;
    let attempts = store.attempts.load(Ordering::SeqCst);
    assert!(
        attempts <= 3 * one_zone,
        "{attempts} attempts in two batches"
    );
    // The lease waits for its retry all along, and the gauge shows it.
    wait_until_async("the oldest lease a second old", async || {
        OLDEST.get().is_some_and(|age| age >= 1.0)
    })
    .await;
    *store.refuse() = 0;
    wait_until_async("the name once the store takes it", async || {
        lab.a("printer.lan.example.test").await == vec![a_of(50)]
    })
    .await;
    wait_until_async("no lease waiting", async || OLDEST.get() == Some(0.0)).await;
}

/// A zone whose write keeps losing to other writers is contention on that zone, not an
/// outage: the reverse zone of the same batch is still written, before the forward zone
/// gets its set on the lease's retry.
#[tokio::test]
async fn a_zone_lost_to_contention_does_not_fail_the_other_zones_of_its_batch() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
        ZoneConfig {
            max_attempts: 1,
            ..ZoneConfig::default()
        },
        SHORT,
    )
    .await;
    // Every try of the forward zone's write, the worker's retries included, finds the zone
    // changed; the reverse zone's write that follows does not.
    store.stale.store(true, Ordering::SeqCst);
    *store.refuse() = usize::try_from(DdnsSettings::default().retries).expect("retries") + 1;
    lab.commit(lab.lease(50, 1, None, Some("printer"))).await;
    wait_until_async("both names", async || {
        lab.a("printer.lan.example.test").await == vec![a_of(50)] && lab.ptr(50).await.is_some()
    })
    .await;
    let forward = lab.set_times("lan.example.test").await;
    let reverse = lab.set_times("2.0.192.in-addr.arpa").await;
    assert!(reverse[0] < forward[0], "{reverse:?} {forward:?}");
}

#[tokio::test]
async fn a_stale_name_update_is_planned_again_and_written_without_a_job() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    let before = job_rows(lab.store.as_ref()).await;
    store.stale.store(true, Ordering::SeqCst);
    *store.refuse() = 1;
    let outcome = lab
        .zones
        .change_dhcp_names(
            &RequestCtx::system(SystemComponent::Dhcp),
            lab.forward,
            &[vec![dhcp_a("stale.lan.example.test", 7)]],
            true,
            None,
        )
        .await
        .expect("planned again");
    assert_eq!(*store.refuse(), 0, "one write was stale");
    assert_eq!(outcome.0.written.expect("written").job, None);
    assert_eq!(lab.a("stale.lan.example.test").await, vec![a_of(7)]);
    assert_eq!(job_rows(lab.store.as_ref()).await, before);
}

#[tokio::test]
async fn only_the_dhcp_component_itself_writes_names_without_a_job() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let dhcp = RequestCtx::system(SystemComponent::Dhcp);
    let mut for_user = RequestCtx::system(SystemComponent::Dhcp);
    for_user.principal = Principal::System {
        component: SystemComponent::Dhcp,
        on_behalf_of: Some(UserId::generate()),
    };
    let dns = RequestCtx::system(SystemComponent::Dns);
    for (index, (cx, job)) in [(&dhcp, false), (&for_user, true), (&dns, true)]
        .into_iter()
        .enumerate()
    {
        let before = job_rows(lab.store.as_ref()).await;
        let owner = format!("h{index}.lan.example.test");
        let outcome = lab
            .zones
            .change_dhcp_names(cx, lab.forward, &[vec![dhcp_a(&owner, 10)]], true, None)
            .await
            .expect("names");
        let after = job_rows(lab.store.as_ref()).await;
        assert_eq!(
            outcome.0.written.expect("written").job.is_some(),
            job,
            "{owner}"
        );
        assert_eq!(after.0 > before.0, job, "{owner}");
    }
    // The DHCP component's other record changes are jobs too.
    let before = job_rows(lab.store.as_ref()).await;
    lab.zones
        .change_records(
            &dhcp,
            lab.forward,
            &[dhcp_a("h3.lan.example.test", 10)],
            false,
        )
        .await
        .expect("records");
    assert!(job_rows(lab.store.as_ref()).await.0 > before.0);
}

/// Commits new clients at `addresses` in one batch, client `first` and up, each asking for
/// the name `h<client>`, and waits until every lease records its forward name.
async fn new_clients(lab: &Lab, addresses: std::ops::RangeInclusive<u8>, first: u8) {
    let names: Vec<(u8, u8, String)> = addresses
        .zip(first..)
        .map(|(last, who)| (last, who, format!("h{who}")))
        .collect();
    lab.commit_all(names.iter().map(|(last, who, host)| {
        lab.lease(*last, *who, Some((host.as_str(), ClientFqdn::FLAG_S)), None)
    }))
    .await;
    for (last, _, host) in &names {
        let owner = name(&format!("{host}.lan.example.test"));
        wait_until_async("the forward name", async || {
            lab.ddns(*last).await.forward.as_ref() == Some(&owner)
        })
        .await;
    }
}

/// A client cannot make the worker write lease by lease: a PTR the zone service refuses (a
/// manual TXT stands at the reverse name of the address it took) is left out of its
/// window's change set, round after round of new clients, so every round writes one change
/// set per zone and the lease shows the refusal.
#[tokio::test]
async fn a_lease_the_zone_refuses_does_not_spoil_its_window_round_after_round() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    lab.zones
        .change_records(
            &cx(),
            lab.reverse,
            &[Change {
                op: Op::Set,
                scope: ScopeName::DEFAULT,
                name: name("60.2.0.192.in-addr.arpa"),
                rtype: Rtype::TXT,
                ttl: None,
                records: vec![RecordData::Txt {
                    strings: vec![TextBytes(b"rack=4".to_vec())],
                }],
                take_over: false,
                origin: Origin::Manual,
            }],
            false,
        )
        .await
        .expect("manual TXT");
    for round in 0..3 {
        new_clients(&lab, 50..=60, 1 + round * 11).await;
        assert_eq!(
            lab.change_sets("lan.example.test").await,
            usize::from(round) + 1
        );
        assert_eq!(
            lab.change_sets("2.0.192.in-addr.arpa").await,
            usize::from(round) + 1
        );
        let refused = lab.ddns(60).await;
        assert_eq!(refused.reverse, None);
        assert!(
            refused
                .last_error
                .is_some_and(|error| error.contains(tenko_core::dns::codes::RECORD_ORIGIN)),
            "the refusal on the lease"
        );
    }
}

/// A change set above the store's batch limit is halved: its first half is written and the
/// other leases wait, whole, for the next batch; so the batch of outcomes on the lease rows.
/// A batch above the zone service's `max_changes` stops before the lease that would pass it.
/// Either way no window writes a second set to a zone.
#[tokio::test]
async fn a_batch_too_large_writes_its_first_half_and_the_rest_waits() {
    let store = Arc::new(Refusing::<MemStore>::default());
    // Two leases' A and DHCID sets with the SOA; two lease rows.
    store.max_rrsets.store(5, Ordering::SeqCst);
    store.max_leases.store(2, Ordering::SeqCst);
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    new_clients(&lab, 50..=53, 1).await;
    assert_eq!(lab.change_sets("lan.example.test").await, 2);
    assert_eq!(lab.change_sets("2.0.192.in-addr.arpa").await, 2);

    // Two leases' A and DHCID changes.
    let lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::new(MemStore::default()),
        ZoneConfig {
            max_changes: 4,
            ..ZoneConfig::default()
        },
        SHORT,
    )
    .await;
    new_clients(&lab, 50..=53, 1).await;
    assert_eq!(lab.change_sets("lan.example.test").await, 2);
    assert_eq!(lab.change_sets("2.0.192.in-addr.arpa").await, 2);
}

/// A lease is planned whole or waits whole: with room for one lease's forward set in the
/// window, the second lease writes neither its forward name nor its PTR.
#[tokio::test]
async fn a_lease_that_does_not_fit_its_window_waits_whole() {
    let lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::new(MemStore::default()),
        ZoneConfig {
            max_changes: 3,
            ..ZoneConfig::default()
        },
        Duration::from_secs(3_600),
    )
    .await;
    lab.commit_all([
        lab.lease(50, 1, Some(("first", ClientFqdn::FLAG_S)), None),
        lab.lease(51, 2, Some(("second", ClientFqdn::FLAG_S)), None),
    ])
    .await;
    wait_until_async("the first lease's names", async || {
        lab.ddns(50).await.reverse.is_some()
    })
    .await;
    assert_eq!(
        lab.a("second.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert_eq!(lab.ptr(51).await, None);
    assert_eq!(
        lab.ddns(51).await,
        DdnsState::default(),
        "not planned, not recorded"
    );
    // Two wait for the next batch an hour away: the second lease, and the first one's own
    // outcome row, which the worker reads again before it skips it.
    wait_until_async("the queue gauge", async || {
        tenko_dhcp::ddns::metrics::QUEUE.get() == Some(2.0)
    })
    .await;
}

/// A name taken in a race inside the write (another writer's record at the lease's name
/// after the batch read the zone) refuses that lease's part only, in the same set, and its
/// PTR stays out with it, also when the batch opens with a release in the reverse zone; the
/// other lease of the window gets both names.
#[tokio::test]
async fn a_forward_name_refused_inside_the_write_takes_its_ptr_along() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    let soa = RrSetKey {
        zone: lab.forward,
        scope: ScopeName::DEFAULT,
        name: name("lan.example.test"),
        rtype: Rtype::SOA,
    };
    let txt = RrSet {
        zone: lab.forward,
        scope: ScopeName::DEFAULT,
        name: name("racer.lan.example.test"),
        rtype: Rtype::TXT,
        ttl: 300,
        rdata: vec![tenko_core::dns::Rdata::from_data(&RecordData::Txt {
            strings: vec![TextBytes(b"mine".to_vec())],
        })],
        origin: Origin::Dynamic,
        key: None,
        principal: None,
        updated: Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns)),
    };
    // A client that writes its own A record holds only a PTR. Its release, at an address
    // before the others, opens the batch, so the reverse zone comes first in the batch until
    // the worker puts the forward zones first.
    lab.config
        .update_scope(
            &cx(),
            lab.scope,
            ScopeChange {
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(lab.forward),
                    client_may_update_a: true,
                    ..DdnsPolicy::default()
                }),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    lab.commit(lab.lease(40, 3, Some(("phone", 0)), None)).await;
    wait_until_async("the PTR only", async || lab.ptr(40).await.is_some()).await;
    let mut released = lab.lease(40, 3, Some(("phone", 0)), None);
    released.state = BindingState::Released;
    *store.race.lock().unwrap_or_else(PoisonError::into_inner) = Some((soa, txt));
    lab.commit_all([
        released,
        lab.lease(50, 1, Some(("racer", ClientFqdn::FLAG_S)), None),
        lab.lease(51, 2, Some(("good", ClientFqdn::FLAG_S)), None),
    ])
    .await;
    wait_until_async("the refusal on the lease", async || {
        lab.ddns(50)
            .await
            .last_error
            .is_some_and(|error| error.contains(tenko_core::dns::codes::RECORD_ORIGIN))
    })
    .await;
    assert_eq!(
        lab.a("racer.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert_eq!(lab.ptr(50).await, None, "the PTR stays out with its name");
    assert_eq!(lab.a("good.lan.example.test").await, vec![a_of(51)]);
    assert!(lab.ptr(51).await.is_some());
    assert_eq!(
        lab.change_sets("lan.example.test").await,
        1,
        "one set, not one a lease"
    );
}

/// A real client behind N waiting leases gets its name within ⌈4N / `max_changes`⌉ + 1
/// windows: the waiting leases are taken in the order they changed, and none overtakes it.
#[tokio::test]
async fn a_real_client_behind_a_backlog_gets_its_name_within_a_bounded_number_of_windows() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
        ZoneConfig {
            max_changes: 8,
            ..ZoneConfig::default()
        },
        SHORT,
    )
    .await;
    let backlog: Vec<(u8, String)> = (50..=69).map(|last| (last, format!("bot{last}"))).collect();
    lab.commit_all(
        backlog
            .iter()
            .map(|(last, host)| lab.lease(*last, *last, Some((host, ClientFqdn::FLAG_S)), None)),
    )
    .await;
    lab.commit(lab.lease(70, 99, Some(("real", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the real client's name", async || {
        lab.ddns(70).await.forward.is_some()
    })
    .await;
    let windows = lab.change_sets("lan.example.test").await;
    let bound = (4 * backlog.len()).div_ceil(8) + 1;
    assert!(windows <= bound, "{windows} windows, bound {bound}");
    // A batch reads the rows of no more leases than the zone service takes changes.
    let most = store.most_lease_reads();
    assert!(most <= 8, "{most} lease rows read through one view");
}

/// A restart writes at most one set before the spacing applies again: the new worker's
/// first set may follow the old one's at once, the next waits the spacing after it.
#[tokio::test]
async fn a_restart_writes_at_most_one_set_before_the_spacing() {
    let spacing = Duration::from_secs(2);
    let mut lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::new(MemStore::default()),
        ZoneConfig::default(),
        spacing,
    )
    .await;
    for (last, host) in [(50, "one"), (51, "two"), (52, "three")] {
        if last == 51 {
            lab.restart();
        }
        lab.commit(lab.lease(last, last, Some((host, ClientFqdn::FLAG_S)), None))
            .await;
        wait_until_async("the name", async || lab.ddns(last).await.forward.is_some()).await;
    }
    let times = lab.set_times("lan.example.test").await;
    assert_eq!(times.len(), 3, "{times:?}");
    assert!(times[2].saturating_since(times[1]) >= spacing, "{times:?}");
}

/// The spacing counts from the end of a batch: with a store that takes a while to write a
/// set, consecutive sets of a zone are the batch's two writes (the forward and the reverse
/// set, from the first one's time stamp) plus the spacing apart, so a sliding minute never
/// holds more than one set a spacing. Without the spacing the gap is the two writes and the
/// window alone.
#[tokio::test]
async fn the_spacing_counts_from_the_end_of_the_last_batch() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let delay = Duration::from_millis(1_500);
    let spacing = Duration::from_secs(1);
    let lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
        ZoneConfig::default(),
        spacing,
    )
    .await;
    *store.delay.lock().unwrap_or_else(PoisonError::into_inner) = delay;
    for last in 50..=52 {
        let host = format!("h{last}");
        lab.commit(lab.lease(last, last, Some((&host, ClientFqdn::FLAG_S)), None))
            .await;
        wait_until_async("the name", async || lab.ddns(last).await.forward.is_some()).await;
    }
    let times = lab.set_times("lan.example.test").await;
    for pair in times.windows(2) {
        assert!(
            pair[1].saturating_since(pair[0]) >= 2 * delay + spacing,
            "{times:?}"
        );
    }
}

/// On a Raft store below its disk margin, which refuses the worker's change sets: the
/// lease's release goes through, the removal fails once per window (no retries in the
/// window, one log line per change set), shows in the counter, and is written once the
/// disk has room again.
#[tokio::test]
async fn below_the_disk_margin_a_name_update_fails_once_a_window_and_follows_with_room() {
    use tenko_store::{
        Pressure,
        raft::{RaftStore, RaftStoreConfig},
        test_hooks::FREE_BYTES,
    };
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    let store = Arc::new(Refusing {
        inner: RaftStore::open_temp(config).await.expect("open"),
        refuse: Mutex::default(),
        stale: AtomicBool::default(),
        max_rrsets: AtomicUsize::default(),
        max_leases: AtomicUsize::default(),
        attempts: AtomicUsize::default(),
        race: Mutex::default(),
        delay: Mutex::default(),
        lease_reads: Mutex::default(),
    });
    let free = async |bytes: u64, pressure: Pressure| {
        let file = store.inner.config().data_dir.join(FREE_BYTES);
        std::fs::write(file, bytes.to_string()).expect("the free space");
        wait_until_async("the store reads its free space", async || {
            let safety = store.inner.safety().expect("safety");
            safety.free_bytes == bytes && safety.pressure == pressure
        })
        .await;
    };
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    new_clients(&lab, 50..=50, 1).await;
    let reserve = store.inner.safety().expect("safety").reserve_bytes;
    free(reserve / 2 * 3, Pressure::Margin).await;

    // The counter is the process's: nextest runs each test in a process of its own.
    let failed = OUTCOMES.get(Outcome::Failed as u16);
    let attempts = store.attempts.load(Ordering::SeqCst);
    // The binding ends with a row no larger than before, which the store takes below its
    // margin, as it takes a renewal.
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let (mut lease, _) = view
        .get_typed(&LEASES, &(lab.vrf, ip(50)))
        .expect("row")
        .expect("lease");
    drop(view);
    lease.state = BindingState::Free;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    batch
        .put_typed(&LEASES, &(lab.vrf, ip(50)), &lease)
        .expect("lease");
    store.propose(batch).await.expect("the end of the binding");
    wait_until_async("the refused removal", async || {
        OUTCOMES.get(Outcome::Failed as u16) > failed
    })
    .await;
    // A window writes the forward and the reverse change set once each; the next window
    // may have started.
    let rounds = usize::try_from(OUTCOMES.get(Outcome::Failed as u16) - failed).expect("rounds");
    let tried = store.attempts.load(Ordering::SeqCst) - attempts;
    assert!(
        tried <= 2 * rounds + 2,
        "{tried} attempts in {rounds} windows"
    );
    assert_eq!(lab.a("h1.lan.example.test").await, vec![a_of(50)]);

    free(u64::MAX, Pressure::Normal).await;
    wait_until_async("the removal", async || {
        lab.a("h1.lan.example.test").await.is_empty() && lab.ptr(50).await.is_none()
    })
    .await;
}

#[tokio::test]
async fn names_come_on_ack_and_go_on_release_and_expiry() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    // A client with option 81 (S set: the server writes A) and a legacy client.
    lab.commit(lab.lease(50, 1, Some(("laptop", ClientFqdn::FLAG_S)), Some("ignored")))
        .await;
    lab.commit(lab.lease(51, 2, None, Some("printer"))).await;
    wait_until_async("the names", async || {
        lab.a("laptop.lan.example.test").await == vec![a_of(50)]
            && lab.a("printer.lan.example.test").await == vec![a_of(51)]
            && lab.ptr(51).await.is_some()
            && lab.ddns(51).await.reverse.is_some()
    })
    .await;
    assert_eq!(
        lab.ptr(50).await,
        Some(RecordData::Ptr {
            target: name("laptop.lan.example.test")
        })
    );
    let set = lab
        .rrset(lab.forward, "laptop.lan.example.test", DHCID)
        .await
        .expect("DHCID");
    assert_eq!(set.origin, Origin::Dhcp);
    let expected = dhcid::dhcid(&client(1), &name("laptop.lan.example.test"));
    assert_eq!(set.rdata[0].as_bytes(), expected.as_slice());
    let a = lab
        .rrset(lab.forward, "laptop.lan.example.test", Rtype::A)
        .await
        .expect("A");
    assert_eq!(a.origin, Origin::Dhcp);
    assert_eq!(a.ttl, 1_200, "a third of the lease time");
    wait_until_async("the outcome on the row", async || {
        lab.ddns(50).await.dhcid.is_some()
    })
    .await;
    let state = lab.ddns(50).await;
    assert_eq!(state.forward, Some(name("laptop.lan.example.test")));
    assert_eq!(state.reverse, Some(name("50.2.0.192.in-addr.arpa")));
    assert_eq!(state.dhcid, Some(HexBytes(expected)));
    assert_eq!(state.last_error, None);

    // A second client claims the first one's name: refused, and the lease says why.
    lab.commit(lab.lease(
        52,
        3,
        Some(("LAPTOP.lan.example.test", ClientFqdn::FLAG_S)),
        None,
    ))
    .await;
    wait_until_async("the refusal", async || {
        lab.ddns(52)
            .await
            .last_error
            .is_some_and(|error| error.contains("name protection"))
    })
    .await;
    assert_eq!(lab.a("laptop.lan.example.test").await, vec![a_of(50)]);
    assert!(lab.ptr(52).await.is_none());

    // A renewal changes nothing in the zones.
    let serial_before = lab
        .rrset(lab.forward, "lan.example.test", Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    lab.commit(lab.lease(50, 1, Some(("laptop", ClientFqdn::FLAG_S)), None))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let serial_after = lab
        .rrset(lab.forward, "lan.example.test", Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    assert_eq!(serial_before, serial_after);

    // The release removes the first client's names; the expiry the second's.
    lab.end(50, BindingState::Released).await;
    lab.end(51, BindingState::Expired).await;
    wait_until_async("the removal", async || {
        lab.a("laptop.lan.example.test").await.is_empty()
            && lab.a("printer.lan.example.test").await.is_empty()
            && lab.ptr(50).await.is_none()
            && lab.ptr(51).await.is_none()
            && lab
                .rrset(lab.forward, "laptop.lan.example.test", DHCID)
                .await
                .is_none()
    })
    .await;
    wait_until_async("the cleared rows", async || {
        lab.ddns(50).await.forward.is_none() && lab.ddns(51).await.reverse.is_none()
    })
    .await;
    // Now the third client may have the name, on its next renewal.
    lab.commit(lab.lease(52, 3, Some(("laptop", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the name for the third client", async || {
        lab.a("laptop.lan.example.test").await == vec![a_of(52)]
    })
    .await;
}

/// While the clock guard holds the clock, an active row past its end still holds its
/// address, so it keeps (here: gets) its names; a release removes them all the same.
#[tokio::test]
async fn a_held_clock_keeps_the_name_of_an_active_lease_past_its_end_and_a_release_removes_it() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let _held = tenko_core::clock::testing::hold_jump(60_000, Timestamp::now());
    let mut ended = lab.lease(60, 1, None, Some("sensor"));
    ended.ends = ended
        .cltt
        .checked_sub(Duration::from_secs(10))
        .expect("a time");
    ended.cltt = ended
        .ends
        .checked_sub(Duration::from_secs(3_600))
        .expect("a time");
    lab.commit(ended).await;
    wait_until_async("the name of the active row", async || {
        lab.a("sensor.lan.example.test").await == vec![a_of(60)] && lab.ptr(60).await.is_some()
    })
    .await;
    lab.end(60, BindingState::Released).await;
    wait_until_async("the removal", async || {
        lab.a("sensor.lan.example.test").await.is_empty() && lab.ptr(60).await.is_none()
    })
    .await;
}

#[tokio::test]
async fn ipam_names_manual_records_and_zone_policy_are_respected() {
    let lab = lab(DdnsProfile::STANDARD, UpdatePolicy::default()).await;
    // Under Standard a zone that says nothing takes no DHCP updates.
    lab.commit(lab.lease(60, 1, None, Some("desk"))).await;
    wait_until_async("the refusal of the zone", async || {
        lab.ddns(60)
            .await
            .last_error
            .is_some_and(|error| error.contains("does not allow DHCP"))
    })
    .await;
    assert_eq!(
        lab.a("desk.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    // The operator allows DHCP in both zones: the worker reads everything again.
    for zone in [lab.forward, lab.reverse] {
        lab.zones
            .update(
                &cx(),
                zone,
                tenko_dns::zone::ZoneChange {
                    update: Some(UpdatePolicy {
                        dhcp: Some(true),
                        ..UpdatePolicy::default()
                    }),
                    ..tenko_dns::zone::ZoneChange::default()
                },
                None,
            )
            .await
            .expect("zone policy");
    }
    wait_until_async("the name after the policy change", async || {
        lab.a("desk.lan.example.test").await == vec![a_of(60)] && lab.ptr(60).await.is_some()
    })
    .await;

    // A manual record holds the name: refused.
    lab.zones
        .change_records(
            &cx(),
            lab.forward,
            &[Change {
                op: Op::Set,
                scope: ScopeName::DEFAULT,
                name: name("nas.lan.example.test"),
                rtype: Rtype::A,
                ttl: None,
                records: vec![a_of(9)],
                take_over: false,
                origin: Origin::Manual,
            }],
            false,
        )
        .await
        .expect("manual record");
    lab.commit(lab.lease(61, 2, None, Some("nas"))).await;
    wait_until_async("the refusal of the manual name", async || {
        lab.ddns(61)
            .await
            .last_error
            .is_some_and(|error| error.contains("origin manual"))
    })
    .await;
    assert_eq!(lab.a("nas.lan.example.test").await, vec![a_of(9)]);

    // An address IPAM names is skipped.
    let address = Address {
        id: AddressId::generate(),
        vrf: lab.vrf,
        ip: IpAddr::V4(ip(62)),
        prefix: lab.scope,
        status: Status::Active,
        interface: None,
        dns_name: Some(Fqdn::new("server.lan.example.test").expect("fqdn")),
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch
        .put_typed(&ADDRESSES, &address.id, &address)
        .expect("address");
    batch
        .put_typed(&ADDRESS_IPS, &(lab.vrf, address.ip), &address.id)
        .expect("index");
    lab.store.propose(batch).await.expect("IPAM address");
    lab.commit(lab.lease(62, 3, None, Some("server"))).await;
    wait_until_async("the skip", async || {
        lab.ddns(62)
            .await
            .last_error
            .is_some_and(|error| error.contains("IPAM manages"))
    })
    .await;
    assert_eq!(
        lab.a("server.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert!(lab.ptr(62).await.is_none());
}

#[tokio::test]
async fn replace_moves_a_name_and_a_client_may_write_its_own_a_record() {
    let lab = lab(DdnsProfile::LAB, UpdatePolicy::default()).await;
    lab.config
        .update_scope(
            &cx(),
            lab.scope,
            ScopeChange {
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(lab.forward),
                    conflict: DdnsConflict::Replace,
                    client_may_update_a: true,
                    ..DdnsPolicy::default()
                }),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    lab.commit(lab.lease(70, 1, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the first name", async || {
        lab.a("tv.lan.example.test").await == vec![a_of(70)]
    })
    .await;
    // Under `replace` the last client wins.
    lab.commit(lab.lease(71, 2, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the moved name", async || {
        lab.a("tv.lan.example.test").await == vec![a_of(71)]
    })
    .await;
    // The first client's expiry leaves the name alone: its DHCID is gone.
    lab.end(70, BindingState::Expired).await;
    wait_until_async("the first PTR gone", async || lab.ptr(70).await.is_none()).await;
    assert_eq!(lab.a("tv.lan.example.test").await, vec![a_of(71)]);
    // A client that writes its A record itself (S clear) gets only its PTR.
    lab.commit(lab.lease(72, 3, Some(("phone", 0)), None)).await;
    wait_until_async("the PTR only", async || lab.ptr(72).await.is_some()).await;
    assert_eq!(
        lab.a("phone.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert_eq!(
        lab.ptr(72).await,
        Some(RecordData::Ptr {
            target: name("phone.lan.example.test")
        })
    );
    // Hardened forces name protection whatever the scope says.
    *lab.profile.lock().unwrap_or_else(PoisonError::into_inner) = DdnsProfile::HARDENED;
    let forced = AtomicBool::new(false);
    lab.zones
        .update(
            &cx(),
            lab.forward,
            tenko_dns::zone::ZoneChange {
                update: Some(UpdatePolicy {
                    dhcp: Some(true),
                    ..UpdatePolicy::default()
                }),
                ..tenko_dns::zone::ZoneChange::default()
            },
            None,
        )
        .await
        .expect("zone policy");
    lab.zones
        .update(
            &cx(),
            lab.reverse,
            tenko_dns::zone::ZoneChange {
                update: Some(UpdatePolicy {
                    dhcp: Some(true),
                    ..UpdatePolicy::default()
                }),
                ..tenko_dns::zone::ZoneChange::default()
            },
            None,
        )
        .await
        .expect("zone policy");
    lab.commit(lab.lease(73, 4, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the protected name", async || {
        let refused = lab
            .ddns(73)
            .await
            .last_error
            .is_some_and(|error| error.contains("name protection"));
        forced.store(refused, Ordering::Relaxed);
        refused
    })
    .await;
    assert!(forced.load(Ordering::Relaxed));
    assert_eq!(lab.a("tv.lan.example.test").await, vec![a_of(71)]);
}

/// The DDNS settings the class and policy matcher decided at the commit (the row's
/// `ddns_policy`) win over the scope's: a policy turns DDNS off for a vendor class while
/// the scope has it on, and on while the scope has it off.
#[tokio::test]
async fn the_policys_ddns_settings_decide_over_the_scopes() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let off = DdnsPolicy::default();
    let on = DdnsPolicy {
        enabled: true,
        forward_zone: Some(lab.forward),
        ..DdnsPolicy::default()
    };
    // The scope has DDNS on; the printer's policy turns it off.
    let mut printer = lab.lease(80, 1, Some(("printer", ClientFqdn::FLAG_S)), None);
    printer.ddns_policy = Some(off.clone());
    lab.commit(printer).await;
    lab.commit(lab.lease(81, 2, Some(("laptop", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the scope's client's name", async || {
        lab.a("laptop.lan.example.test").await == vec![a_of(81)] && lab.ptr(81).await.is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        lab.a("printer.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert!(lab.ptr(80).await.is_none());
    assert_eq!(lab.ddns(80).await.forward, None);

    // The scope turns DDNS off; a policy that has it on still gets its client a name.
    lab.config
        .update_scope(
            &cx(),
            lab.scope,
            ScopeChange {
                ddns: Some(off),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    tokio::time::sleep(Duration::from_millis(300)).await;
    lab.commit(lab.lease(82, 3, Some(("tablet", ClientFqdn::FLAG_S)), None))
        .await;
    let mut sensor = lab.lease(83, 4, Some(("sensor", ClientFqdn::FLAG_S)), None);
    sensor.ddns_policy = Some(on);
    lab.commit(sensor).await;
    wait_until_async("the policy's client's name", async || {
        lab.a("sensor.lan.example.test").await == vec![a_of(83)] && lab.ptr(83).await.is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        lab.a("tablet.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert!(lab.ptr(82).await.is_none());
}

/// A name is one owner's whatever the types of its records (RFC 4703 section 5, ADR 0020
/// point 2): a manual MX and a manual TXT at the name refuse a DHCP A as a manual A does,
/// and the DHCID is not written either.
#[tokio::test]
async fn a_manual_mx_or_txt_at_the_name_refuses_a_dhcp_a() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let manual = |owner: &str, record: RecordData| Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: record.rtype(),
        ttl: None,
        records: vec![record],
        take_over: false,
        origin: Origin::Manual,
    };
    lab.zones
        .change_records(
            &cx(),
            lab.forward,
            &[
                manual(
                    "mail.lan.example.test",
                    RecordData::Mx {
                        preference: 10,
                        exchange: name("mx.example.test"),
                    },
                ),
                manual(
                    "info.lan.example.test",
                    RecordData::Txt {
                        strings: vec![TextBytes(b"owner=ops".to_vec())],
                    },
                ),
            ],
            false,
        )
        .await
        .expect("manual records");
    lab.commit(lab.lease(63, 1, None, Some("mail"))).await;
    lab.commit(lab.lease(64, 2, Some(("info", ClientFqdn::FLAG_S)), None))
        .await;
    for (last, owner, rtype) in [
        (63, "mail.lan.example.test", "MX"),
        (64, "info.lan.example.test", "TXT"),
    ] {
        wait_until_async("the refusal", async || {
            lab.ddns(last).await.last_error.is_some_and(|error| {
                error.contains(&format!("holds {rtype} records of the origin manual"))
            })
        })
        .await;
        assert_eq!(lab.a(owner).await, Vec::<RecordData>::new());
        assert!(lab.rrset(lab.forward, owner, DHCID).await.is_none());
        assert!(lab.ptr(last).await.is_none());
        assert_eq!(lab.ddns(last).await.forward, None);
    }
}

/// A name below a child zone Tenko serves, or below a delegation of the forward zone, is
/// not the scope's forward zone's (ADR 0020 points 3 and 6): it counts as a name outside
/// the zone, cut to its first label under the forward zone, or refused when the scope
/// says `refuse_foreign`; the parent zone never holds a name of the child's, and what is
/// written is removed from the zone it was written into.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the cut name, the refused name and the delegated name of one lab"
)]
async fn a_name_below_a_child_zone_is_written_and_removed_in_the_forward_zone_only() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    let child = lab
        .zones
        .create(
            &cx(),
            new_zone("sub.lan.example.test", UpdatePolicy::default()),
        )
        .await
        .expect("child zone")
        .zone
        .id;
    lab.zones
        .change_records(
            &cx(),
            lab.forward,
            &[Change {
                op: Op::Set,
                scope: ScopeName::DEFAULT,
                name: name("dl.lan.example.test"),
                rtype: Rtype::NS,
                ttl: None,
                records: vec![RecordData::Ns {
                    host: name("ns1.example.test"),
                }],
                take_over: false,
                origin: Origin::Manual,
            }],
            false,
        )
        .await
        .expect("the delegation");

    // Cut to the first label under the forward zone, and removed from there.
    lab.commit(lab.lease(
        65,
        1,
        Some(("h.sub.lan.example.test", ClientFqdn::FLAG_S)),
        None,
    ))
    .await;
    wait_until_async("the name under the forward zone", async || {
        lab.a("h.lan.example.test").await == vec![a_of(65)] && lab.ptr(65).await.is_some()
    })
    .await;
    assert_eq!(lab.ddns(65).await.forward, Some(name("h.lan.example.test")));
    nothing_at(&lab, [lab.forward, child], "h.sub.lan.example.test").await;
    lab.end(65, BindingState::Released).await;
    wait_until_async("the removal", async || {
        lab.a("h.lan.example.test").await.is_empty()
            && lab
                .rrset(lab.forward, "h.lan.example.test", DHCID)
                .await
                .is_none()
            && lab.ptr(65).await.is_none()
    })
    .await;
    nothing_at(&lab, [lab.forward, child], "h.sub.lan.example.test").await;

    // With `refuse_foreign`, refused with the reason; nothing is written anywhere.
    lab.config
        .update_scope(
            &cx(),
            lab.scope,
            ScopeChange {
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(lab.forward),
                    refuse_foreign: true,
                    ..DdnsPolicy::default()
                }),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    lab.commit(lab.lease(
        66,
        2,
        Some(("h.sub.lan.example.test", ClientFqdn::FLAG_S)),
        None,
    ))
    .await;
    wait_until_async("the refusal of the child's name", async || {
        lab.ddns(66).await.last_error.is_some_and(|error| {
            error.contains("lies in the zone sub.lan.example.test, not in the scope's forward zone")
        })
    })
    .await;
    nothing_at(&lab, [lab.forward, child], "h.sub.lan.example.test").await;
    assert_eq!(lab.a("h.lan.example.test").await, Vec::<RecordData>::new());
    assert!(lab.ptr(66).await.is_none());

    // Below a delegation of the forward zone: the same.
    lab.commit(lab.lease(
        67,
        3,
        Some(("h.dl.lan.example.test", ClientFqdn::FLAG_S)),
        None,
    ))
    .await;
    wait_until_async("the refusal of the delegated name", async || {
        lab.ddns(67)
            .await
            .last_error
            .is_some_and(|error| error.contains("lies below the delegation dl.lan.example.test"))
    })
    .await;
    nothing_at(&lab, [lab.forward, child], "h.dl.lan.example.test").await;
    assert!(lab.ptr(67).await.is_none());
}

/// A new client takes an address while no worker runs: the row it gets carries the names
/// of the last client, so the worker that starts removes them under that client's DHCID and
/// writes the new client's.
#[tokio::test]
async fn a_new_client_followed_by_a_restart_has_the_last_clients_names_removed() {
    let mut lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    new_clients(&lab, 50..=50, 1).await;
    lab.stop.cancel();
    lab.commit(lab.lease(50, 2, Some(("h2", ClientFqdn::FLAG_S)), None))
        .await;
    assert_eq!(
        lab.ddns(50).await.forward,
        Some(name("h1.lan.example.test"))
    );
    lab.restart();
    wait_until_async("the new client's name only", async || {
        lab.a("h1.lan.example.test").await.is_empty()
            && lab.a("h2.lan.example.test").await == vec![a_of(50)]
    })
    .await;
}

/// A worker that stops (its controller no longer leads) leaves the DDNS gauges out of the
/// snapshots, so the old leader shows no queue beside the new one.
#[tokio::test]
async fn the_ddns_gauges_go_when_the_worker_stops() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    new_clients(&lab, 50..=50, 1).await;
    wait_until_async("the gauges", async || {
        QUEUE.get().is_some() && OLDEST.get().is_some()
    })
    .await;
    lab.stop.cancel();
    wait_until_async("no gauges", async || {
        QUEUE.get().is_none() && OLDEST.get().is_none()
    })
    .await;
}

/// A failed lease counts in the queue until its retry: here an hour away, beside its own
/// outcome row, which waits for the next batch an hour away too. The gauge is the process's:
/// one worker.
#[tokio::test]
async fn a_failed_lease_waits_in_the_queue_for_its_retry() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let mut lab = lab_with(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
        ZoneConfig::default(),
        Duration::from_secs(3_600),
    )
    .await;
    lab.settings.retry_after = Duration::from_secs(3_600);
    lab.restart();
    store.stale.store(true, Ordering::SeqCst);
    *store.refuse() = usize::MAX;
    lab.commit(lab.lease(52, 3, Some(("h3", ClientFqdn::FLAG_S)), None))
        .await;
    wait_until_async("the failed lease and its row in the queue", async || {
        lab.ddns(52).await.last_error.is_some() && QUEUE.get() == Some(2.0)
    })
    .await;
}

/// A worker whose term has ended plans its fenced set once and stops: planning again cannot
/// bring its office back.
#[tokio::test]
async fn a_worker_that_lost_its_office_plans_its_set_once_and_stops() {
    let store = Arc::new(Refusing::<MemStore>::default());
    let lab = lab_on(
        DdnsProfile::HOME,
        UpdatePolicy::default(),
        Arc::clone(&store) as _,
    )
    .await;
    lab.stop.cancel();
    let mut bump = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    bump.bump(LEADER_EPOCH);
    lab.store
        .propose(bump)
        .await
        .expect("another member takes office");
    lab.commit(lab.lease(50, 1, Some(("h1", ClientFqdn::FLAG_S)), None))
        .await;
    let ended = tokio::time::timeout(
        Duration::from_secs(60),
        lab.service().run(0, CancellationToken::new()),
    )
    .await
    .expect("the deposed worker stops");
    assert_eq!(
        ended,
        Err("the DDNS worker is no longer the leader".to_owned())
    );
    assert_eq!(store.attempts.load(Ordering::SeqCst), 1, "planned once");
    assert_eq!(lab.a("h1.lan.example.test").await, Vec::new());
}
