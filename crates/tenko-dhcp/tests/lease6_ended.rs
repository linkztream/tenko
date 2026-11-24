//! Ended DHCPv6 rows are deleted (`Expiry6Service::delete_ended`), over the in-memory store:
//!
//! - a released or expired address and a released prefix whose names are gone are deleted
//!   once a round period has passed; a row that still holds a name, one that ended less than
//!   a period ago, an active binding and an abandoned address stay;
//! - the deletion leaves the role's table (the row and the scope's count) and IPAM's lease
//!   view;
//! - its batch only deletes: every change is a delete of `dhcp.leases6`, no audit record;
//!   the largest batch the code makes stays under 256 KiB, as payload and encoded;
//! - a renewal committed after the delete stays in the role's table;
//! - an abandoned row keeps its hold below the scope's ceiling and yields at it;
//! - nothing is deleted while the clock guard holds the clock.

use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures::StreamExt as _;
use tenko_core::{
    NodeId, PrefixId, Principal, Revision, SystemComponent, Timestamp, VrfId,
    clock::testing::hold_jump,
    dhcp::{BindingState, DdnsState, Lease6, Lease6Kind, tables::LEASES6},
    dns::DnsName,
    net::Duid,
    testing::wait_until_async,
};
use tenko_dhcp::{
    lease::ExpirySettings,
    v6::lease::{
        Lease6Index, Lease6Table as _, SharedLeases6,
        expiry::{DELETES_PER_BATCH, Expiry6Service},
    },
};
use tenko_ipam::observe::{ObserveConfig, dhcp::LeaseFacts};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, MemStore, ReadConsistency, ReadView,
    ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tokio_util::sync::CancellationToken;

const NODE: NodeId = NodeId(1);

fn ago(secs: u64) -> Timestamp {
    Timestamp::now()
        .checked_sub(Duration::from_secs(secs))
        .expect("a time")
}

fn from_now(secs: u64) -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(secs))
        .expect("a time")
}

fn addr(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x100 + last)
}

/// A row of the address `last` of client `last` in `scope`, in `state` until `ends`.
fn row(vrf: VrfId, scope: PrefixId, last: u16, state: BindingState, ends: Timestamp) -> Lease6 {
    let [high, low] = last.to_be_bytes();
    Lease6 {
        addr: IpAddr::V6(addr(last)),
        prefix_len: 128,
        kind: Lease6Kind::Na,
        vrf,
        scope,
        iaid: 1,
        duid: Duid::new(vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, high, low]).expect("a DUID"),
        link_layer: None,
        link_layer_type: None,
        state,
        cltt: ago(3_600),
        ends,
        preferred_ends: ends,
        node: NODE,
        fqdn: None,
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        ddns: DdnsState::default(),
        granted: None,
    }
}

/// A store that records the size of every batch, and commits a renewal of one row right
/// after the next batch and applies it to the role's table, as a commit the feed delivers
/// before the expiry task resumes.
struct Watched {
    inner: Arc<dyn Store>,
    /// The payload and the encoded size of each batch.
    sizes: Mutex<Vec<(usize, usize)>>,
    renewal: Mutex<Option<(Lease6, SharedLeases6)>>,
}

impl Watched {
    fn new(inner: Arc<dyn Store>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            sizes: Mutex::new(Vec::new()),
            renewal: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl Store for Watched {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                batch.payload_size(),
                tenko_core::codec::to_cbor(&batch).map_or(usize::MAX, |bytes| bytes.len()),
            ));
        let committed = self.inner.propose(batch).await?;
        let renewal = self
            .renewal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((row, table)) = renewal {
            let mut again =
                WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
            again.put_typed(&LEASES6, &(row.vrf, row.addr6()), &row)?;
            let renewed = self.inner.propose(again).await?;
            table.apply_at(row, renewed.revision);
        }
        Ok(committed)
    }
    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }
    fn watch(
        &self,
        from: Option<Revision>,
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

struct Rows {
    store: Arc<dyn Store>,
    table: SharedLeases6,
    vrf: VrfId,
    scope: PrefixId,
}

/// The store and the role's table holding, by the last word of the address: 1 released and
/// 2 expired a minute ago, 3 a delegated prefix released a minute ago, 4 expired a minute
/// ago and still holding its name, 5 released a second ago, 6 active, 7 abandoned.
async fn rows() -> Rows {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let mut prefix = row(vrf, scope, 3, BindingState::Released, ago(60));
    prefix.kind = Lease6Kind::Pd;
    prefix.prefix_len = 60;
    let mut named = row(vrf, scope, 4, BindingState::Expired, ago(60));
    named.ddns.forward = Some(DnsName::new("laptop.example.test").expect("a name"));
    let leases = [
        row(vrf, scope, 1, BindingState::Released, ago(60)),
        row(vrf, scope, 2, BindingState::Expired, ago(60)),
        prefix,
        named,
        row(vrf, scope, 5, BindingState::Released, ago(1)),
        row(vrf, scope, 6, BindingState::Active, from_now(600)),
        row(vrf, scope, 7, BindingState::Abandoned, from_now(600)),
    ];
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    for lease in &leases {
        batch
            .put_typed(&LEASES6, &(vrf, lease.addr6()), lease)
            .expect("a row");
    }
    let committed = store.propose(batch).await.expect("committed");
    let table = SharedLeases6::new(Lease6Index::from_rows(
        leases
            .iter()
            .cloned()
            .map(|lease| (lease, committed.revision)),
        committed.revision,
    ));
    Rows {
        store,
        table,
        vrf,
        scope,
    }
}

impl Rows {
    fn service(&self) -> Expiry6Service {
        Expiry6Service::new(Arc::clone(&self.store), NODE, ExpirySettings::default())
            .with_table(self.table.clone())
    }

    async fn stored(&self) -> Vec<u16> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        (1..=7)
            .filter(|last| {
                view.get_typed(&LEASES6, &(self.vrf, addr(*last)))
                    .expect("a read")
                    .is_some()
            })
            .collect()
    }

    fn held(&self) -> Vec<u16> {
        let table = self.table.read();
        (1..=7)
            .filter(|last| table.get(self.vrf, addr(*last)).is_some())
            .collect()
    }
}

#[tokio::test]
async fn an_ended_row_whose_names_are_gone_is_deleted_and_leaves_the_table_and_ipams_view() {
    let rows = rows().await;
    let view = LeaseFacts::new(ObserveConfig::default());
    let stop = CancellationToken::new();
    let follower = view.spawn(Arc::clone(&rows.store), stop.child_token());
    wait_until_async("the lease view to be built", async || view.len() == 7).await;
    assert_eq!(rows.table.read().scope_rows(rows.scope), 7);

    let deleted = rows
        .service()
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 3);
    let kept = vec![4, 5, 6, 7];
    assert_eq!(rows.stored().await, kept);
    // The role's table: the rows and the scope's count.
    assert_eq!(rows.held(), kept);
    assert_eq!(rows.table.read().scope_rows(rows.scope), 4);
    // IPAM's lease view.
    let revision = rows
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view")
        .revision();
    assert!(view.caught_up(revision).await);
    assert_eq!(view.len(), 4);
    // A second pass finds nothing.
    let again = rows.service().delete_ended(0, Timestamp::now()).await;
    assert_eq!(again.expect("a pass"), 0);
    stop.cancel();
    follower.await.expect("the follower");
}

#[tokio::test]
async fn the_deletion_batch_only_deletes() {
    let rows = rows().await;
    let from = rows
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view")
        .revision();
    let mut watch = rows
        .store
        .watch(Some(from), WatchFilter::all())
        .expect("a watch");
    let deleted = rows
        .service()
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 3);
    let set = tokio::time::timeout(Duration::from_secs(30), watch.next())
        .await
        .expect("a change set")
        .expect("the stream")
        .expect("no lag");
    assert_eq!(set.changes.len(), 3, "{set:?}");
    for change in &set.changes {
        assert!(change.deleted, "{change:?}");
        assert_eq!(
            change.table,
            *LEASES6.name(),
            "no other row, no audit record"
        );
    }
}

#[tokio::test]
async fn nothing_is_deleted_while_the_clock_is_held() {
    let rows = rows().await;
    let service = rows.service();
    let held = hold_jump(60_000, Timestamp::now());
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 0);
    assert_eq!(rows.stored().await, (1..=7).collect::<Vec<_>>());
    assert_eq!(rows.held(), (1..=7).collect::<Vec<_>>());
    drop(held);
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 3);
}

#[tokio::test]
async fn a_renewal_committed_after_the_delete_stays_in_the_table() {
    let rows = rows().await;
    let store = Watched::new(Arc::clone(&rows.store));
    let mut renewed = row(
        rows.vrf,
        rows.scope,
        1,
        BindingState::Active,
        from_now(3_600),
    );
    renewed.cltt = Timestamp::now();
    *store.renewal.lock().unwrap_or_else(PoisonError::into_inner) =
        Some((renewed.clone(), rows.table.clone()));
    let watched: Arc<dyn Store> = store;
    let service = Expiry6Service::new(watched, NODE, ExpirySettings::default())
        .with_table(rows.table.clone());
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 3);
    // The store holds the renewed row; so does the table, with the scope's count.
    assert_eq!(rows.stored().await, vec![1, 4, 5, 6, 7]);
    assert_eq!(rows.held(), vec![1, 4, 5, 6, 7]);
    assert_eq!(
        rows.table
            .read()
            .get(rows.vrf, addr(1))
            .map(|lease| lease.state),
        Some(BindingState::Active)
    );
    assert_eq!(rows.table.read().scope_rows(rows.scope), 5);
}

#[tokio::test]
async fn the_largest_deletion_batch_stays_under_256_kib() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let ended: Vec<Lease6> = (1..=1_100)
        .map(|last| row(vrf, scope, last, BindingState::Released, ago(60)))
        .collect();
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    for lease in &ended {
        batch
            .put_typed(&LEASES6, &(vrf, lease.addr6()), lease)
            .expect("a row");
    }
    let committed = store.propose(batch).await.expect("committed");
    let table = SharedLeases6::new(Lease6Index::from_rows(
        ended.into_iter().map(|lease| (lease, committed.revision)),
        committed.revision,
    ));
    let watched = Watched::new(store);
    let inner: Arc<dyn Store> = Arc::clone(&watched) as Arc<dyn Store>;
    // A batch size past the cap: the cap decides.
    let settings = ExpirySettings {
        batch: 100_000,
        ..ExpirySettings::default()
    };
    let service = Expiry6Service::new(inner, NODE, settings).with_table(table);
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 1_100);
    let sizes = watched
        .sizes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(sizes.len(), 2, "{DELETES_PER_BATCH} rows, then the rest");
    let payload = sizes.iter().map(|(payload, _)| *payload).max().unwrap_or(0);
    let encoded = sizes.iter().map(|(_, encoded)| *encoded).max().unwrap_or(0);
    println!(
        "DELETE-BATCH rows={DELETES_PER_BATCH} payload_octets={payload} encoded_octets={encoded}"
    );
    assert!(payload <= 262_144, "{payload}");
    assert!(encoded <= 262_144, "{encoded}");
}

#[tokio::test]
async fn an_abandoned_row_keeps_its_hold_below_the_ceiling_and_yields_at_it() {
    // Seven rows; with a ceiling of eight the declined row 7 keeps its hold.
    let below = rows().await;
    let service = below.service().with_ceiling(Arc::new(|| 8));
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 3);
    assert_eq!(below.stored().await, vec![4, 5, 6, 7]);
    // With a ceiling of seven the scope is full: the declined row yields.
    let at = rows().await;
    let service = at.service().with_ceiling(Arc::new(|| 7));
    let deleted = service
        .delete_ended(0, Timestamp::now())
        .await
        .expect("a pass");
    assert_eq!(deleted, 4);
    assert_eq!(at.stored().await, vec![4, 5, 6]);
    assert_eq!(at.held(), vec![4, 5, 6]);
}

/// A row that still holds names an earlier version wrote goes once the DDNS worker's record
/// of its address has taken in those names, and not while it holds others.
#[tokio::test]
async fn a_row_with_names_goes_once_the_record_took_them_in() {
    use tenko_core::dhcp::{DdnsNames, tables::DDNS_NAMES};
    let rows = rows().await;
    let put = async |took_in| {
        let record = DdnsNames {
            took_in,
            ..DdnsNames::default()
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch
            .put_typed(&DDNS_NAMES, &(rows.vrf, IpAddr::V6(addr(4))), &record)
            .expect("a record");
        rows.store.propose(batch).await.expect("committed");
    };
    // The record took in names of another time.
    put(Some(Timestamp::UNIX_EPOCH)).await;
    let pass = async || {
        rows.service()
            .delete_ended(0, Timestamp::now())
            .await
            .expect("a pass")
    };
    assert_eq!(pass().await, 3);
    assert!(rows.stored().await.contains(&4));
    // The row's own names, whose time is none.
    put(None).await;
    assert_eq!(pass().await, 1);
    assert!(!rows.stored().await.contains(&4));
}
