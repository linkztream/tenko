//! The record of an address whose DHCPv6 row is deleted: the worker finds it, and its row
//! goes once it holds no name. The status batch drops nothing from a row that moved.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

use tenko_core::{
    Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{DdnsNames, DdnsState, tables::DDNS_NAMES},
    dns::DnsName,
    serde_util::HexBytes,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, ReadConsistency, ReadViewExt as _, Store, WriteBatch};

use super::{DdnsService, DdnsSettings, Done, Lease1, Part, Worker};
use crate::ddns::DdnsProfile;

fn service(store: &Arc<dyn Store>) -> DdnsService {
    let zones = ZoneService::with_direct_jobs(Arc::clone(store), None, ZoneConfig::default());
    DdnsService::new(
        Arc::clone(store),
        zones,
        Arc::new(|_: &dyn tenko_store::ReadView| DdnsProfile::HOME),
        DdnsSettings::default(),
    )
}

#[tokio::test]
async fn the_record_of_a_deleted_lease_row_goes_once_it_holds_no_name() {
    // The record of a refused name, and the empty record kept for the names an earlier
    // version left on the row, whose lease row the expiry service deleted.
    for last_error in [Some("refused".to_owned()), None] {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let service = service(&store);
        let key = (
            VrfId::generate(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x110)),
        );
        let row = DdnsNames {
            last_error,
            ..DdnsNames::default()
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch.put_typed(&DDNS_NAMES, &key, &row).expect("row");
        store.propose(batch).await.expect("committed");
        let mut worker = Worker::new(&service, 0);
        let view = store.read(ReadConsistency::Local).await.expect("view");
        worker.reload(view.as_ref()).expect("reload");
        drop(view);
        // The reload finds the record without a lease row, and the queue gauge shows it.
        worker.gauge();
        assert_eq!(super::QUEUE.get(), Some(1.0));
        worker.batch().await;
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert_eq!(view.get_typed(&DDNS_NAMES, &key).expect("read"), None);
    }
}

/// A record that moved after the batch read it (a late commit of the worker's own): the
/// status batch drops none of its entries and plans the lease again.
#[tokio::test]
async fn the_status_batch_leaves_a_moved_record_and_plans_its_lease_again() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let service = service(&store);
    let key = (
        VrfId::generate(),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x111)),
    );
    let owner = DnsName::new("h1.example.test").expect("a name");
    let mut row = DdnsNames::default();
    row.put_forward(owner.clone(), HexBytes(vec![1]));
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    batch.put_typed(&DDNS_NAMES, &key, &row).expect("row");
    store.propose(batch).await.expect("committed");
    // The batch read no row; nothing was planned for the entry.
    let lease = Lease1 {
        key,
        request: None,
        legacy: DdnsState::default(),
        marked: Instant::now(),
        record: row.clone(),
        version: None,
        later: vec![(Part::Unforward(owner, HexBytes(vec![1])), Done::Written)],
        refusal: None,
        failure: None,
        note: None,
        waits: false,
    };
    let mut worker = Worker::new(&service, 0);
    worker
        .status(&[lease], &HashMap::new(), Timestamp::now())
        .await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let held = view
        .get_typed(&DDNS_NAMES, &key)
        .expect("read")
        .map(|(row, _)| row);
    assert_eq!(held, Some(row));
    assert!(
        worker.dirty.iter().any(|(at, _)| *at == key),
        "planned again"
    );
}
