//! Shared helpers of the lease tests (WP7.2): clients with documentation addresses, lease
//! changes, stores, and the wait for completions.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};

use tenko_core::{
    NodeId, PrefixId, Timestamp, VrfId,
    dhcp::{
        BindingState, Lease, LeaseEventKind, LeaseRef, lease::MAX_IDENTITY, tables, write_identity,
    },
};
use tenko_dhcp::{
    lease::{CommitSettings, LeaseIndex, PendingChange, SharedLeases, StoreLeases},
    store::{Completion, LeaseStore},
};
use tenko_store::{KeyRange, MemStore, MemStoreConfig, ReadConsistency, ReadViewExt, Store};
use tokio_util::sync::CancellationToken;

/// The node of the tests.
pub const NODE: NodeId = NodeId(1);

/// A fixed time.
pub fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("time")
}

/// `t0` plus `secs`.
pub fn at(secs: u64) -> Timestamp {
    t0().checked_add(Duration::from_secs(secs)).expect("a time")
}

/// Now plus `secs`.
pub fn from_now(secs: u64) -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(secs))
        .expect("a time")
}

/// The hardware address of client `k` (RFC 7042 documentation range).
pub fn mac(k: u32) -> [u8; 6] {
    [
        0x00,
        0x00,
        0x5e,
        0x00,
        0x53,
        u8::try_from(k % 256).expect("below 256"),
    ]
}

/// Odd clients and every client above 255 send a client identifier (so that thousands of
/// clients stay distinct within the documentation MAC range); even ones below 256 are known
/// by their hardware address.
pub fn client_id(k: u32) -> Option<Vec<u8>> {
    (k % 2 == 1 || k > 255).then(|| {
        let mut id = vec![0xff];
        id.extend_from_slice(&k.to_be_bytes());
        id
    })
}

/// The identity octets of client `k`.
pub fn identity_of(k: u32) -> Vec<u8> {
    let mut out = [0u8; MAX_IDENTITY];
    let len = write_identity(1, &mac(k), client_id(k).as_deref(), &mut out);
    out[..len].to_vec()
}

/// A change of client `k` at `addr`.
#[allow(clippy::too_many_arguments, reason = "the identity of a test change")]
pub fn change(
    kind: LeaseEventKind,
    vrf: VrfId,
    scope: PrefixId,
    addr: Ipv4Addr,
    client: u32,
    state: BindingState,
    cltt: Timestamp,
    ends: Timestamp,
) -> PendingChange {
    PendingChange::new(
        kind,
        vrf,
        scope,
        addr,
        1,
        &mac(client),
        client_id(client).as_deref(),
        state,
        cltt,
        ends,
    )
}

/// An address of 192.0.2.0/24.
pub fn addr(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

/// A memory store.
pub fn mem_store() -> Arc<dyn Store> {
    Arc::new(MemStore::new(MemStoreConfig::default()))
}

/// A lease store on `store` with its committer running; the token stops it.
pub fn start(
    store: Arc<dyn Store>,
    settings: CommitSettings,
) -> (
    StoreLeases,
    SharedLeases,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let leases = SharedLeases::new(LeaseIndex::new());
    let (lease_store, committer) = StoreLeases::new(store, leases.clone(), NODE, settings);
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    (lease_store, leases, stop, task)
}

/// Waits for `count` completions, at most `bound`.
pub async fn completions(store: &StoreLeases, count: usize, bound: Duration) -> Vec<Completion> {
    let deadline = tokio::time::Instant::now() + bound;
    let mut out = Vec::new();
    loop {
        store.completions(&mut out);
        if out.len() >= count {
            return out;
        }
        if tokio::time::timeout_at(deadline, store.completed())
            .await
            .is_err()
        {
            store.completions(&mut out);
            return out;
        }
    }
}

/// The rows of `dhcp.leases`, the client index and the history in a store.
pub struct Rows {
    /// `dhcp.leases`.
    pub leases: BTreeMap<(VrfId, Ipv4Addr), Lease>,
    /// The revision of each lease row.
    pub revisions: BTreeMap<(VrfId, Ipv4Addr), tenko_core::Revision>,
    /// `dhcp.leases.by_client`.
    pub index: BTreeMap<(PrefixId, Vec<u8>), LeaseRef>,
    /// `dhcp.history`, in key order.
    pub history: Vec<tenko_core::dhcp::LeaseEvent>,
}

/// Reads every lease row, index entry and history row of `store`.
pub async fn rows(store: &dyn Store) -> Rows {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let mut leases = BTreeMap::new();
    let mut revisions = BTreeMap::new();
    for (key, lease, revision) in view
        .scan_typed(&tables::LEASES, KeyRange::all(), usize::MAX, false)
        .expect("the leases")
    {
        leases.insert(key, lease);
        revisions.insert(key, revision);
    }
    let index = view
        .scan_typed(
            &tables::LEASES_BY_CLIENT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("the index")
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect();
    let history = view
        .scan_typed(&tables::HISTORY, KeyRange::all(), usize::MAX, false)
        .expect("the history")
        .into_iter()
        .map(|(_, value, _)| value)
        .collect();
    Rows {
        leases,
        revisions,
        index,
        history,
    }
}
