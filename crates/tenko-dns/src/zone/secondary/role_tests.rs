//! The role's starts: a served copy lives until a transfer replaces it or its expiry
//! passes, whichever way the role starts (cold, restart, leader change, upgrade).

use std::sync::Mutex;

use tenko_core::{
    Principal,
    dns::{SecondarySource, SerialPolicy, SoaDefaults, TransferPolicy, UpdatePolicy},
};
use tenko_store::{MemStore, Store};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

use super::*;
use crate::xfr::message::{MessageWriter, TYPE_SOA, read_request};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn soa(serial: u32) -> RecordData {
    RecordData::Soa {
        mname: name("ns.example.test"),
        rname: name("hostmaster.example.test"),
        serial,
        refresh: 60,
        retry: 10,
        expire: 3600,
        minimum: 5,
    }
}

fn a(last: u8) -> Rdata {
    Rdata::from_data(&RecordData::A {
        address: std::net::Ipv4Addr::new(192, 0, 2, last),
    })
}

/// What the primary on loopback answers.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// The whole zone at this serial, to AXFR and IXFR alike.
    Zone(u32),
    /// The SOA alone with this serial: the copy is current.
    Current(u32),
    /// Nothing: the connection is closed at once.
    Closed,
}

struct Primary {
    address: SocketAddr,
    answer: Arc<Mutex<Answer>>,
}

impl Primary {
    async fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let answer = Arc::new(Mutex::new(answer));
        let shared = Arc::clone(&answer);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answer = *shared.lock().expect("answer");
                let serial = match answer {
                    Answer::Zone(serial) | Answer::Current(serial) => serial,
                    Answer::Closed => continue,
                };
                let Ok(len) = stream.read_u16().await else {
                    continue;
                };
                let mut message = vec![0u8; usize::from(len)];
                if stream.read_exact(&mut message).await.is_err() {
                    continue;
                }
                let request = read_request(&message).expect("a request");
                let mut writer = MessageWriter::new(&message, &request, 16 * 1024);
                let apex = name("example.test").to_wire();
                let soa = Rdata::from_data(&soa(serial));
                writer.push(&apex, TYPE_SOA, 60, soa.as_bytes());
                if let Answer::Zone(_) = answer {
                    let www = name("www.example.test").to_wire();
                    writer.push(&www, 1, 300, a(1).as_bytes());
                    writer.push(&apex, TYPE_SOA, 60, soa.as_bytes());
                }
                let out = writer.take();
                let mut framed = u16::try_from(out.len())
                    .expect("size")
                    .to_be_bytes()
                    .to_vec();
                framed.extend_from_slice(&out);
                let _ = stream.write_all(&framed).await;
            }
        });
        Self { address, answer }
    }

    fn answer(&self, answer: Answer) {
        *self.answer.lock().expect("answer") = answer;
    }
}

/// A store with one secondary zone of a primary, shared by the nodes of a test.
struct Lab {
    store: Arc<MemStore>,
    zones: Arc<ZoneService>,
    zone: Zone,
}

impl Lab {
    async fn new(primary: &Primary) -> Self {
        let store = Arc::new(MemStore::default());
        let zones = ZoneService::with_direct_jobs(
            Arc::clone(&store) as Arc<dyn Store>,
            None,
            super::super::ZoneConfig::default(),
        );
        let written = zones
            .create(
                &system(),
                NewZone {
                    name: name("example.test"),
                    kind: ZoneKind::Secondary,
                    tenant: None,
                    scopes: Vec::new(),
                    serial: SerialPolicy::default(),
                    soa: SoaDefaults::new(name("ns.example.test"), name("hostmaster.example.test")),
                    name_servers: Vec::new(),
                    transfer: TransferPolicy::default(),
                    update: UpdatePolicy::default(),
                    dnssec: tenko_core::dns::DnssecPolicy::default(),
                    source: Some(SecondarySource {
                        primaries: vec![PrimaryServer {
                            address: primary.address.ip(),
                            port: primary.address.port(),
                            key: None,
                            xot: false,
                            tls_name: None,
                        }],
                    }),
                    description: None,
                    reverse_of: None,
                    catalog: false,
                },
            )
            .await
            .expect("zone");
        Self {
            store,
            zones,
            zone: written.zone,
        }
    }

    /// A node of the cluster: a service with its own memory over the shared store.
    fn node(&self) -> Arc<Inner> {
        let keys = Arc::new(KeyLoader::new(Arc::clone(&self.zones)));
        let service =
            SecondaryService::new(Arc::clone(&self.zones), keys, SecondarySettings::default());
        Arc::clone(&service.inner)
    }

    async fn view(&self) -> Arc<dyn ReadView> {
        self.zones.view(None).await.expect("view")
    }

    /// The serial of the copy the store holds, when it holds the records too.
    async fn served(&self) -> Option<u32> {
        let view = self.view().await;
        let www = RrSetKey {
            name: name("www.example.test"),
            rtype: Rtype::A,
            ..soa_key(&self.zone)
        };
        view.get_typed(&RRSETS, &www)
            .expect("read")
            .and(held_copy(view.as_ref(), &self.zone).expect("read"))
            .map(|held| held.serial)
    }

    async fn stamp(&self) -> Option<TransferStamp> {
        self.view()
            .await
            .get_typed(&TRANSFER_STATE, &self.zone.id)
            .expect("read")
            .map(|(stamp, _)| stamp)
    }

    /// Stores `stamp`, or none, as the zone's last refresh, as an earlier version or an
    /// earlier hour left it.
    async fn set_stamp(&self, stamp: Option<TransferStamp>) {
        let mut batch = WriteBatch::for_request(&system());
        match stamp {
            Some(stamp) => {
                batch
                    .put_typed(&TRANSFER_STATE, &self.zone.id, &stamp)
                    .expect("stage");
            }
            None => {
                batch.delete_typed(&TRANSFER_STATE, &self.zone.id);
            }
        }
        self.store.propose(batch).await.expect("write");
    }

    /// Writes the SOA again with `at` as its time: the copy's serial last changed then.
    async fn soa_written_at(&self, at: Timestamp) {
        let (mut soa, _) = self
            .view()
            .await
            .get_typed(&RRSETS, &soa_key(&self.zone))
            .expect("read")
            .expect("an SOA");
        soa.updated.at = at;
        let mut batch = WriteBatch::for_request(&system());
        batch.put_typed(&RRSETS, &soa.key(), &soa).expect("stage");
        self.store.propose(batch).await.expect("write");
    }
}

const EPOCH: u64 = 0;

/// A term's start: the state is rebuilt from the store.
async fn start(node: &Arc<Inner>) {
    node.begin();
    node.reconcile(EPOCH).await.expect("reconcile");
}

/// One look of the term, and the end of every refresh it started.
async fn look(node: &Arc<Inner>) {
    let mut refreshes = Refreshes::default();
    node.pass(EPOCH, &mut refreshes).await;
    while let Some((id, outcome)) = refreshes.next().await {
        node.finish(id, outcome).await;
    }
}

/// A term that starts, refreshes what is due and looks again (expiry included).
async fn term(node: &Arc<Inner>) {
    start(node).await;
    look(node).await;
    look(node).await;
}

fn hours_ago(hours: u64) -> Timestamp {
    Timestamp::now()
        .checked_sub(Duration::from_secs(hours * 3600))
        .expect("time")
}

/// The register's first case: a copy whose serial last changed longer ago than its expire
/// (3600 s), found current a moment ago, is still served after a restart while its
/// primary is unreachable, and its expiry counts from that last refresh.
#[tokio::test]
async fn a_current_copy_outlives_a_restart_with_its_primary_unreachable() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    // A cold start: nothing to expire, the zone is transferred at once.
    let first = lab.node();
    term(&first).await;
    assert_eq!(lab.served().await, Some(7));
    lab.soa_written_at(hours_ago(2)).await;
    primary.answer(Answer::Current(7));
    first
        .lock()
        .get_mut(&lab.zone.id)
        .expect("state")
        .force(Timestamp::now());
    look(&first).await;
    let confirmed = lab.stamp().await.expect("the refresh is recorded");
    assert_eq!(confirmed.serial, 7);

    // A restart: a new process over the same store, the primary gone.
    primary.answer(Answer::Closed);
    let restarted = lab.node();
    term(&restarted).await;
    assert_eq!(lab.served().await, Some(7), "the copy is still served");
    let state = restarted.lock()[&lab.zone.id].clone();
    assert!(
        state.primaries[0].last_error.is_some(),
        "the refresh after the restart failed"
    );
    assert_eq!(state.expires, Some(after(confirmed.refreshed, 3600)));
}

/// The same copy on a node that led before: what it remembers of its earlier term is
/// not used; the store is.
#[tokio::test]
async fn a_new_term_reads_the_store_not_an_earlier_term() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    let node = lab.node();
    term(&node).await;
    // The node remembers an expiry an hour gone; another leader refreshed since.
    node.lock().get_mut(&lab.zone.id).expect("state").expires = Some(hours_ago(1));
    primary.answer(Answer::Closed);
    term(&node).await;
    assert_eq!(lab.served().await, Some(7));
}

/// A copy with no record of its last refresh (written before the record existed) counts
/// as refreshed when the term starts, once: a later restart does not extend it.
#[tokio::test]
async fn a_copy_without_a_record_counts_from_the_first_term_start_once() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    term(&lab.node()).await;
    lab.set_stamp(None).await;
    lab.soa_written_at(hours_ago(2)).await;
    primary.answer(Answer::Closed);
    term(&lab.node()).await;
    assert_eq!(
        lab.served().await,
        Some(7),
        "never let go for want of a record"
    );
    let assumed = lab.stamp().await.expect("the term start is recorded");
    let again = lab.node();
    term(&again).await;
    assert_eq!(lab.stamp().await, Some(assumed.clone()), "given once");
    assert_eq!(
        again.lock()[&lab.zone.id].expires,
        Some(after(assumed.refreshed, 3600))
    );
}

/// A copy whose last refresh is older than its expire is let go at the term start, before
/// any refresh of it, and its record with it.
#[tokio::test]
async fn a_copy_past_its_expiry_is_not_served_after_a_restart() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    term(&lab.node()).await;
    lab.set_stamp(Some(TransferStamp {
        zone: lab.zone.id,
        serial: 7,
        refreshed: hours_ago(2),
    }))
    .await;
    primary.answer(Answer::Closed);
    let node = lab.node();
    start(&node).await;
    let mut refreshes = Refreshes::default();
    node.pass(EPOCH, &mut refreshes).await;
    assert_eq!(lab.served().await, None);
    assert_eq!(lab.stamp().await, None);
}

/// A leader that lost its term while its refresh ran cannot record it: the fence refuses
/// the write, so the new leader's view stays the store's.
#[tokio::test]
async fn a_refresh_of_a_deposed_leader_records_nothing() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    let old = lab.node();
    term(&old).await;
    let recorded = lab.stamp().await.expect("recorded");
    let mut batch = WriteBatch::for_request(&system());
    batch.bump(tenko_core::cluster::LEADER_EPOCH);
    lab.store.propose(batch).await.expect("a new term");
    primary.answer(Answer::Current(7));
    let outcome = old.try_refresh(lab.zone.id, EPOCH).await;
    assert!(matches!(outcome, Some(Refreshed::Failed)), "{outcome:?}");
    assert_eq!(lab.stamp().await, Some(recorded));
    assert_eq!(lab.served().await, Some(7));
}

/// A refresh that panics ends like a failed one: its zone no longer runs and its slot is
/// free, so refreshes and expiry go on.
#[tokio::test]
async fn a_refresh_that_panics_frees_its_zone_and_its_slot() {
    let primary = Primary::start(Answer::Closed).await;
    let lab = Lab::new(&primary).await;
    let node = lab.node();
    start(&node).await;
    assert_eq!(node.take_due(1), vec![lab.zone.id]);
    let mut refreshes = Refreshes::default();
    let task = refreshes
        .set
        .spawn(async { panic!("a refresh that panics") });
    refreshes.zones.insert(task.id(), lab.zone.id);
    let (id, outcome) = refreshes.next().await.expect("the refresh ended");
    assert_eq!(id, lab.zone.id);
    assert!(outcome.is_none());
    node.finish(id, outcome).await;
    assert!(!node.lock()[&lab.zone.id].running);
}

/// RFC 1912 section 2.2: an expire shorter than refresh plus retry is read as their sum,
/// so the copy cannot expire before its next refresh.
#[test]
fn an_expire_shorter_than_refresh_and_retry_is_raised_to_their_sum() {
    let short = Rdata::from_data(&RecordData::Soa {
        mname: name("ns.example.test"),
        rname: name("hostmaster.example.test"),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 60,
        minimum: 5,
    });
    let (timers, given) = Timers::read(&short);
    assert_eq!(
        (timers.refresh, timers.retry, timers.expire),
        (3600, 600, 4200)
    );
    assert_eq!(given, Some(60));
    assert_eq!(Timers::read(&Rdata::from_data(&soa(1))).1, None);
}

/// The records a delete left behind (its purge failed) are removed by the sweep; the
/// records of a zone that exists are not.
#[tokio::test]
async fn the_records_a_cut_delete_left_are_swept() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    term(&lab.node()).await;
    let stamp = Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns));
    let mut orphan = transfer_rrset(&lab.zone, name("www.example.test"), Rtype::A, 60, &stamp);
    orphan.zone = ZoneId::generate();
    orphan.rdata = vec![a(9)];
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(&RRSETS, &orphan.key(), &orphan)
        .expect("stage");
    lab.store.propose(batch).await.expect("write");
    assert_eq!(lab.zones.purge_orphans().await.expect("sweep"), 1);
    let view = lab.view().await;
    assert_eq!(view.get_typed(&RRSETS, &orphan.key()).expect("read"), None);
    drop(view);
    assert_eq!(lab.served().await, Some(7));
    assert_eq!(lab.zones.purge_orphans().await.expect("sweep"), 0);
}

/// A refresh that wrote its transfer and then failed (a catalog's members, say) ends with
/// the expiry of what it wrote: the end of a refresh reads the copy from the store.
#[tokio::test]
async fn the_end_of_a_refresh_takes_the_copy_from_the_store() {
    let primary = Primary::start(Answer::Zone(7)).await;
    let lab = Lab::new(&primary).await;
    let node = lab.node();
    term(&node).await;
    let written = TransferStamp {
        zone: lab.zone.id,
        serial: 7,
        refreshed: Timestamp::now(),
    };
    lab.set_stamp(Some(written.clone())).await;
    node.lock().get_mut(&lab.zone.id).expect("state").expires = Some(hours_ago(1));
    node.finish(lab.zone.id, None).await;
    assert_eq!(
        node.lock()[&lab.zone.id].expires,
        Some(after(written.refreshed, 3600))
    );
}

/// The record of a zone deleted while its refresh ran is swept with the zone's records.
#[tokio::test]
async fn the_record_of_a_deleted_zone_is_swept() {
    let primary = Primary::start(Answer::Closed).await;
    let lab = Lab::new(&primary).await;
    let gone = ZoneId::generate();
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(
            &TRANSFER_STATE,
            &gone,
            &TransferStamp {
                zone: gone,
                serial: 1,
                refreshed: Timestamp::now(),
            },
        )
        .expect("stage");
    lab.store.propose(batch).await.expect("write");
    assert_eq!(lab.zones.purge_orphans().await.expect("sweep"), 1);
    let view = lab.view().await;
    assert_eq!(view.get_typed(&TRANSFER_STATE, &gone).expect("read"), None);
}
