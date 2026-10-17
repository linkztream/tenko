//! Tests of the in-process feed over an in-memory store, with the zone service writing.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{DnsName, RecordData, Rtype, ScopeName, SerialPolicy, SoaDefaults, ZoneKind},
};
use tenko_store::{MemStore, Store, WriteBatch};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    catalog,
    zone::{
        NewZone, ZoneConfig, ZoneService,
        records::{Change as RecordChange, Op},
    },
};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn service() -> (Arc<ZoneService>, Arc<dyn Store>) {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let service = ZoneService::with_direct_jobs(Arc::clone(&store), None, ZoneConfig::default());
    (service, store)
}

fn new_zone(apex: &str) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(
            name(&format!("ns1.{apex}")),
            name(&format!("hostmaster.{apex}")),
        ),
        name_servers: vec![name(&format!("ns1.{apex}"))],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
    }
}

fn a(owner: &str, address: &str, op: Op) -> RecordChange {
    RecordChange {
        op,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: Some(300),
        records: if op == Op::Delete {
            Vec::new()
        } else {
            vec![RecordData::A {
                address: address.parse().expect("address"),
            }]
        },
        take_over: false,
        origin: tenko_core::dns::Origin::Manual,
    }
}

async fn next_event(feed: &mut StoreFeed) -> FeedEvent {
    tokio::time::timeout(Duration::from_secs(5), feed.next())
        .await
        .expect("an event in time")
        .expect("an event")
}

#[tokio::test]
async fn the_first_image_holds_the_zones_written_before_registration() {
    let (service, store) = service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone")
        .zone;
    service
        .change_records(
            &cx(),
            zone.id,
            &[a("www.example.test", "192.0.2.1", Op::Set)],
            false,
        )
        .await
        .expect("records");
    let mut feed = register(Arc::clone(&store)).expect("register");
    let data = feed.snapshot().await.expect("image");
    assert_eq!(data.revision, store.status().revision);
    assert!(data.zones.contains_key(&zone.id));
    // SOA, NS and the A record.
    assert_eq!(data.rrsets.len(), 3, "{:?}", data.rrsets.keys());
    let handle = catalog::CatalogHandle::new(catalog::Catalog::build(&data));
    assert_eq!(handle.load().index().stats().zones, 1);
    assert_eq!(feed.progress().lag(handle.revision()), 0);
}

#[tokio::test]
async fn changes_arrive_as_deltas_in_revision_order() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let image = feed.snapshot().await.expect("image");
    assert!(image.zones.is_empty());
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    let FeedEvent::Delta(delta) = next_event(&mut feed).await else {
        panic!("a delta");
    };
    assert_eq!(delta.from, image.revision);
    assert_eq!(delta.to, created.revision);
    assert!(
        delta
            .changes
            .iter()
            .any(|change| matches!(change, Change::Zone(id, Some(_)) if *id == created.zone.id))
    );
    // A write outside the dns tables reaches no one; the next delta starts at the last one.
    let mut other = WriteBatch::for_request(&cx());
    other.put(
        tenko_core::TableName::from_static("ipam.feed_test"),
        bytes::Bytes::from_static(b"k"),
        bytes::Bytes::from_static(b"v"),
    );
    let unrelated = store
        .propose(other)
        .await
        .expect("unrelated write")
        .revision;
    service
        .change_records(
            &cx(),
            created.zone.id,
            &[a("www.example.test", "192.0.2.1", Op::Set)],
            false,
        )
        .await
        .expect("records");
    let FeedEvent::Delta(next) = next_event(&mut feed).await else {
        panic!("a delta");
    };
    assert_eq!(next.from, delta.to);
    assert!(next.to > unrelated);
    // A removal is a row without a value.
    service
        .change_records(
            &cx(),
            created.zone.id,
            &[a("www.example.test", "", Op::Delete)],
            false,
        )
        .await
        .expect("records");
    let FeedEvent::Delta(removed) = next_event(&mut feed).await else {
        panic!("a delta");
    };
    assert!(
        removed
            .changes
            .iter()
            .any(|change| matches!(change, Change::RrSet(key, None) if key.rtype == Rtype::A))
    );
    let mut data = image;
    for delta in [delta, next, removed] {
        data.apply(&delta).expect("deltas follow each other");
    }
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let fresh = read_image(view.as_ref()).expect("read");
    assert_eq!(data.zones, fresh.zones);
    assert_eq!(data.rrsets, fresh.rrsets);
}

#[tokio::test]
async fn a_batch_of_1000_rrsets_is_served_within_one_second() {
    let (service, store) = service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone")
        .zone;
    let mut feed = register(Arc::clone(&store)).expect("register");
    let handle = catalog::initial(&mut feed).await.expect("catalog");
    let stop = CancellationToken::new();
    let progress = feed.progress();
    let follower = tokio::spawn(catalog::follow(feed, handle.clone(), stop.clone()));
    let changes: Vec<RecordChange> = (0..1_000)
        .map(|n| {
            a(
                &format!("host-{n}.example.test"),
                &format!("198.51.100.{}", n % 250 + 1),
                Op::Set,
            )
        })
        .collect();
    let written = service
        .change_records(&cx(), zone.id, &changes, false)
        .await
        .expect("records")
        .written
        .expect("a write")
        .revision;
    let started = Instant::now();
    while handle.revision() < written {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the change is not served after one second"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(progress.lag(handle.revision()), 0);
    let catalog = handle.load();
    let owner = name("host-999.example.test").to_wire();
    let found = crate::index::Index::lookup(
        catalog.index(),
        &crate::index::DefaultScopes,
        &owner,
        Rtype::A,
    );
    assert!(
        matches!(found, crate::index::Lookup::Answer { .. }),
        "{found:?}"
    );
    stop.cancel();
    follower.await.expect("joins").expect("follows");
}

#[tokio::test]
async fn an_image_installed_later_resets_the_catalog() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let handle = catalog::initial(&mut feed).await.expect("catalog");
    assert_eq!(handle.load().index().stats().zones, 0);
    // A follower that installs a snapshot applies no entries for the revisions it covers:
    // the store rebuilds its indexes instead, and the index installs a new image, which the
    // feed hands over as one reset.
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    feed.queue
        .items
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let index = StoreIndex {
        queue: Arc::clone(&feed.queue),
        pushed: Arc::clone(&feed.pushed),
    };
    index.install(index.build(view.as_ref()).expect("build"));
    let stop = CancellationToken::new();
    let follower = tokio::spawn(catalog::follow(feed, handle.clone(), stop.clone()));
    let started = Instant::now();
    while handle.revision() < created.revision {
        assert!(started.elapsed() < Duration::from_secs(5), "no reset");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(handle.load().index().stats().zones, 1);
    stop.cancel();
    follower.await.expect("joins").expect("follows");
}

#[tokio::test]
async fn an_image_newer_than_the_held_revision_is_a_reset() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let _ = feed.snapshot().await.expect("image");
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let index = StoreIndex {
        queue: Arc::clone(&feed.queue),
        pushed: Arc::clone(&feed.pushed),
    };
    feed.queue
        .items
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    index.install(index.build(view.as_ref()).expect("build"));
    let FeedEvent::Reset(data) = next_event(&mut feed).await else {
        panic!("a reset");
    };
    assert!(data.zones.contains_key(&created.zone.id));
}

#[tokio::test]
async fn a_snapshot_without_a_queued_image_reads_the_store() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let _ = feed.snapshot().await.expect("first image");
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    // A gap makes the catalog ask again: the feed reads the store and skips the queued
    // delta it already holds.
    let again = feed.snapshot().await.expect("second image");
    assert_eq!(again.revision, created.revision);
    assert!(again.zones.contains_key(&created.zone.id));
    service
        .change_records(
            &cx(),
            created.zone.id,
            &[a("www.example.test", "192.0.2.1", Op::Set)],
            false,
        )
        .await
        .expect("records");
    let FeedEvent::Delta(delta) = next_event(&mut feed).await else {
        panic!("a delta");
    };
    assert_eq!(delta.from, created.revision);
}

#[tokio::test]
async fn a_change_set_that_could_not_be_read_becomes_a_reset() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let _ = feed.snapshot().await.expect("image");
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    feed.queue
        .items
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    feed.queue.push(Pushed::Lost(created.revision));
    let FeedEvent::Reset(data) = next_event(&mut feed).await else {
        panic!("a reset");
    };
    assert_eq!(data.revision, created.revision);
    assert!(data.zones.contains_key(&created.zone.id));
}

#[tokio::test]
async fn change_sets_queued_behind_each_other_become_one_delta() {
    let (service, store) = service();
    let mut feed = register(Arc::clone(&store)).expect("register");
    let image = feed.snapshot().await.expect("image");
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("zone");
    let mut last = created.revision;
    for n in 0..3 {
        last = service
            .change_records(
                &cx(),
                created.zone.id,
                &[a(&format!("host-{n}.example.test"), "192.0.2.1", Op::Set)],
                false,
            )
            .await
            .expect("records")
            .written
            .expect("a write")
            .revision;
    }
    let FeedEvent::Delta(delta) = next_event(&mut feed).await else {
        panic!("a delta");
    };
    assert_eq!((delta.from, delta.to), (image.revision, last));
    let mut data = image;
    data.apply(&delta)
        .expect("the merged delta follows the image");
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let fresh = read_image(view.as_ref()).expect("read");
    assert_eq!(data.rrsets, fresh.rrsets);
    assert_eq!(data.zones, fresh.zones);
}
