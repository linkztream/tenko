//! The worker's memo per address: a DHCPv6 row deleted once its names are gone leaves it,
//! and a row that is still there keeps it.

use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, DdnsState, Lease6, Lease6Kind, tables::LEASES6},
    net::Duid,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

use super::{DdnsService, DdnsSettings, Worker};
use crate::ddns::DdnsProfile;

async fn write(store: &Arc<dyn Store>, change: impl FnOnce(&mut WriteBatch)) {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    change(&mut batch);
    store.propose(batch).await.expect("committed");
}

#[tokio::test]
async fn a_deleted_row_whose_names_are_gone_leaves_the_memo() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let zones = ZoneService::with_direct_jobs(Arc::clone(&store), None, ZoneConfig::default());
    let service = DdnsService::new(
        Arc::clone(&store),
        zones,
        Arc::new(|_: &dyn tenko_store::ReadView| DdnsProfile::HOME),
        DdnsSettings::default(),
    );
    let (vrf, addr) = (
        VrfId::generate(),
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x110),
    );
    let now = Timestamp::now();
    // An expired row whose names the worker removed.
    let row = Lease6 {
        addr: IpAddr::V6(addr),
        prefix_len: 128,
        kind: Lease6Kind::Na,
        vrf,
        scope: PrefixId::generate(),
        iaid: 1,
        duid: Duid::new(vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x10]).expect("a DUID"),
        link_layer: None,
        link_layer_type: None,
        state: BindingState::Expired,
        cltt: now,
        ends: now,
        preferred_ends: now,
        node: NodeId(1),
        fqdn: None,
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        ddns: DdnsState::default(),
        granted: None,
    };
    write(&store, |batch| {
        batch.put_typed(&LEASES6, &(vrf, addr), &row).expect("row");
    })
    .await;
    let mut worker = Worker::new(&service, 0);
    let view = store.read(ReadConsistency::Local).await.expect("view");
    worker.reload(view.as_ref()).expect("reload");
    drop(view);
    let key = (vrf, IpAddr::V6(addr));
    assert!(worker.memory.contains_key(&key));

    // While the row is there the worker keeps what it knows of the address.
    worker.batch().await;
    assert!(worker.memory.contains_key(&key));

    // Deleted, as the expiry service deletes it: the memo goes with the row.
    write(&store, |batch| {
        batch.delete_typed(&LEASES6, &(vrf, addr));
    })
    .await;
    worker.mark(key);
    worker.batch().await;
    assert!(!worker.memory.contains_key(&key), "{:?}", worker.memory);
}

#[test]
fn the_memo_of_an_address_stays_small() {
    // The inline size of an entry; the client identifier, the names and the last request
    // add their heap.
    let inline = std::mem::size_of::<super::Memo>() + std::mem::size_of::<super::Key>();
    println!("DDNS-MEMO inline_bytes_per_entry={inline}");
    assert!(inline <= MEMO_CAP, "{inline}");
}

/// The measured inline size (369 bytes on 2026-11-22) plus a quarter.
const MEMO_CAP: usize = 461;
