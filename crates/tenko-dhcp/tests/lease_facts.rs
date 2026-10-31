//! The lease tables as the observation source (ADR 0031): the `dhcp` role writes no fact
//! rows. A lease commit and its writer's flush put nothing into `ipam.obs.facts`,
//! `ipam.obs.by_mac`, `ipam.obs.by_ip` or `ipam.obs.by_name`, for DHCPv4 and DHCPv6, for a
//! grant, a renewal and a release through the role's command; and the lease view of IPAM
//! (`LeaseFacts`) presents the committed lease as its address and name facts, current while
//! the binding holds and expired when it ended, at the revision of the lease row.

mod lease_support;

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use lease_support::{NODE, addr, change, from_now, mac, mem_store, rows};
use tenko_core::dhcp::{BindingState, LeaseEventKind};
use tenko_core::{
    MacAddr, PrefixId, Revision, Timestamp, VrfId,
    codec::to_cbor,
    dhcp::{Lease6Kind, tables},
    observe::{ObservationSource, Observed},
};
use tenko_dhcp::{
    lease::{CommitSettings, PendingChange},
    role::{DhcpNode, LocalNode, Outcome, Role, RoleSettings, commands},
    server::ServerConfig,
    store::{LeaseStore as _, Ticket},
    v6::{
        lease::{Binding6, PendingChange6, store::Lease6Store as _},
        server::Server6Config,
    },
};
use tenko_ipam::observe::{ObserveConfig, dhcp::LeaseFacts, model::ObservedFact, tables as obs};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store};

/// The role on an empty in-memory store, without listeners.
async fn role_on(store: &Arc<dyn Store>) -> Role {
    Role::start(
        Arc::clone(store),
        NODE,
        RoleSettings {
            server: ServerConfig::default(),
            commit: CommitSettings::default(),
            probe: false,
            probe_expected: false,
            server6: Server6Config::default(),
        },
    )
    .await
    .expect("the role starts")
}

/// The rows in `ipam.obs.facts`, `ipam.obs.by_mac`, `ipam.obs.by_ip` and `ipam.obs.by_name`.
async fn fact_rows(store: &Arc<dyn Store>) -> [usize; 4] {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let all = || KeyRange::all();
    [
        view.scan_typed(&obs::FACTS, all(), usize::MAX, false)
            .expect("facts")
            .len(),
        view.scan_typed(&obs::BY_MAC, all(), usize::MAX, false)
            .expect("by mac")
            .len(),
        view.scan_typed(&obs::BY_IP, all(), usize::MAX, false)
            .expect("by ip")
            .len(),
        view.scan_typed(&obs::BY_NAME, all(), usize::MAX, false)
            .expect("by name")
            .len(),
    ]
}

/// A grant of `addr(10)` to client 2 with a host name, and its renewal a minute later.
fn v4_changes(
    vrf: VrfId,
    scope: PrefixId,
    granted: Timestamp,
) -> [tenko_dhcp::lease::PendingChange; 2] {
    let mut grant = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(10),
        2,
        BindingState::Active,
        granted,
        from_now(3_600),
    );
    grant.hostname.set(b"laptop");
    let mut renewal = change(
        LeaseEventKind::Renewed,
        vrf,
        scope,
        addr(10),
        2,
        BindingState::Active,
        later(granted, 60),
        from_now(3_660),
    );
    renewal.hostname.set(b"laptop");
    [grant, renewal]
}

/// The DUID-LL of client `k` over the documentation MAC of `lease_support::mac`.
fn later(at: Timestamp, secs: u64) -> Timestamp {
    at.checked_add(Duration::from_secs(secs)).expect("a time")
}

fn duid(k: u32) -> Vec<u8> {
    let mut out = vec![0, 3, 0, 1];
    out.extend_from_slice(&mac(k));
    out
}

fn v6_address() -> Ipv6Addr {
    "2001:db8:1::100".parse().expect("an address")
}

/// A grant or a renewal of `v6_address()` to client 2, with a name.
fn v6_change(
    event: LeaseEventKind,
    vrf: VrfId,
    scope: PrefixId,
    cltt: Timestamp,
    ends: Timestamp,
) -> PendingChange6 {
    let mut pending = PendingChange6::new(&duid(2), cltt);
    pending.fqdn.set(b"laptop6.example.net");
    pending.link_layer = Some((1, tenko_dhcp::lease::InlineBytes::new(&mac(2)).0));
    assert!(pending.push(Binding6 {
        event,
        kind: Lease6Kind::Na,
        vrf,
        scope,
        iaid: 1,
        addr: v6_address(),
        prefix_len: 128,
        state: BindingState::Active,
        preferred_ends: ends,
        ends,
    }));
    pending
}

/// Commits a DHCPv4 change through the role's lease store and waits until its row is in the
/// store and the writer has flushed. (The role's server takes the completions, so the test
/// reads the store.)
async fn commit4(node: &LocalNode, store: &Arc<dyn Store>, pending: &PendingChange, ticket: u64) {
    node.lease_store()
        .submit(pending, Ticket(ticket))
        .expect("the queue has room");
    for _ in 0..2_000 {
        let found = rows(store.as_ref()).await;
        if found
            .leases
            .get(&(pending.vrf, pending.addr))
            .is_some_and(|lease| lease.cltt == pending.cltt)
        {
            node.lease_store().derived().flush().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the change did not commit");
}

/// [`commit4`] for a DHCPv6 change of one binding.
async fn commit6(node: &LocalNode, store: &Arc<dyn Store>, pending: &PendingChange6, ticket: u64) {
    node.lease_store6()
        .submit6(pending, Ticket(ticket))
        .expect("the queue has room");
    let binding = pending.bindings()[0];
    for _ in 0..2_000 {
        let view = store.read(ReadConsistency::Local).await.expect("a view");
        let row = view
            .get_typed(&tables::LEASES6, &(binding.vrf, binding.addr))
            .expect("read");
        if row.is_some_and(|(lease, _)| lease.cltt == pending.cltt) {
            node.lease_store6().derived().flush().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the change did not commit");
}

/// The facts of the lease view over the store as it is now.
async fn view_facts(store: &Arc<dyn Store>) -> (Vec<ObservedFact>, Revision) {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let leases = LeaseFacts::new(ObserveConfig::default());
    leases.ensure(view.as_ref()).expect("the view builds");
    (leases.facts(Timestamp::now()), view.revision())
}

fn address_fact(facts: &[ObservedFact], ip: std::net::IpAddr) -> &ObservedFact {
    facts
        .iter()
        .find(|fact| matches!(&fact.observed, Observed::Address { ip: own, .. } if *own == ip))
        .unwrap_or_else(|| panic!("the address fact of {ip}"))
}

fn name_of(facts: &[ObservedFact], ip: std::net::IpAddr) -> Option<&str> {
    facts.iter().find_map(|fact| match &fact.observed {
        Observed::Name { ip: own, name, .. } if *own == ip => Some(name.as_str()),
        _ => None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dhcpv4_commit_and_its_flush_write_no_fact_rows() {
    let store = mem_store();
    let role = role_on(&store).await;
    let node = role.node();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let [grant, renewal] = v4_changes(vrf, scope, Timestamp::now());
    let lease_store = node.lease_store();

    for (ticket, pending) in [grant, renewal].iter().enumerate() {
        commit4(&node, &store, pending, ticket as u64).await;
        assert_eq!(fact_rows(&store).await, [0; 4], "after change {ticket}");
    }

    let released = node
        .execute(
            commands::LEASE_RELEASE,
            &to_cbor(&commands::ReleaseArgs {
                vrf: Some(vrf),
                addr: addr(10),
                reason: None,
            })
            .expect("arguments"),
        )
        .await;
    assert_eq!(released.outcome, Outcome::Done, "{}", released.detail);
    lease_store.derived().flush().await;
    assert_eq!(fact_rows(&store).await, [0; 4], "after the release");

    // The lease row and the history rows are there: the change was written, only the facts
    // are not.
    let found = rows(store.as_ref()).await;
    assert_eq!(found.leases.len(), 1);
    assert_eq!(found.history.len(), 3, "a grant, a renewal and a release");
    role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dhcpv6_commit_and_its_flush_write_no_fact_rows() {
    let store = mem_store();
    let role = role_on(&store).await;
    let node = role.node();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let granted = Timestamp::now();

    let grant = v6_change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        granted,
        from_now(3_600),
    );
    let renewal = v6_change(
        LeaseEventKind::Renewed,
        vrf,
        scope,
        later(granted, 60),
        from_now(3_660),
    );
    for (ticket, pending) in [grant, renewal].iter().enumerate() {
        commit6(&node, &store, pending, ticket as u64).await;
        assert_eq!(fact_rows(&store).await, [0; 4], "after change {ticket}");
    }

    let released = node
        .execute(
            commands::LEASE6_RELEASE,
            &to_cbor(&commands::Release6Args {
                vrf: Some(vrf),
                addr: v6_address(),
                reason: None,
            })
            .expect("arguments"),
        )
        .await;
    assert_eq!(released.outcome, Outcome::Done, "{}", released.detail);
    node.lease_store6().derived().flush().await;
    assert_eq!(fact_rows(&store).await, [0; 4], "after the release");

    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let leases = view
        .scan_typed(&tables::LEASES6, KeyRange::all(), usize::MAX, false)
        .expect("the leases");
    let history = view
        .scan_typed(&tables::HISTORY6, KeyRange::all(), usize::MAX, false)
        .expect("the history");
    assert_eq!(leases.len(), 1);
    assert_eq!(history.len(), 3, "a grant, a renewal and a release");
    role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lease_view_presents_the_committed_lease_as_its_address_and_name_facts() {
    let store = mem_store();
    let role = role_on(&store).await;
    let node = role.node();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let granted = Timestamp::now();

    // Nothing committed, nothing to present.
    assert_eq!(view_facts(&store).await.0.len(), 0);

    let [grant, _] = v4_changes(vrf, scope, granted);
    commit4(&node, &store, &grant, 1).await;
    commit6(
        &node,
        &store,
        &v6_change(
            LeaseEventKind::Granted,
            vrf,
            scope,
            granted,
            from_now(3_600),
        ),
        2,
    )
    .await;
    assert_eq!(fact_rows(&store).await, [0; 4]);

    let (facts, revision) = view_facts(&store).await;
    let now = Timestamp::now();
    let source = ObservationSource::DhcpLease { node: NODE };
    assert!(facts.iter().all(|fact| fact.source == source));
    let found = rows(store.as_ref()).await;
    let ip4 = std::net::IpAddr::V4(addr(10));
    let v4_fact = address_fact(&facts, ip4);
    assert_eq!(
        v4_fact.observed,
        Observed::Address {
            vrf,
            ip: ip4,
            mac: Some(MacAddr::new(mac(2))),
        }
    );
    assert!(v4_fact.is_current(now));
    assert_eq!(v4_fact.revision, found.revisions[&(vrf, addr(10))]);
    assert_eq!(v4_fact.first_seen, granted);
    assert_eq!(name_of(&facts, ip4), Some("laptop"));

    let ip6 = std::net::IpAddr::V6(v6_address());
    let v6_fact = address_fact(&facts, ip6);
    assert_eq!(
        v6_fact.observed,
        Observed::Address {
            vrf,
            ip: ip6,
            mac: Some(MacAddr::new(mac(2))),
        }
    );
    assert!(v6_fact.is_current(now));
    assert!(v6_fact.revision <= revision);
    assert_eq!(name_of(&facts, ip6), Some("laptop6.example.net"));

    // The release ends the binding: the facts are there, expired.
    let released = node
        .execute(
            commands::LEASE_RELEASE,
            &to_cbor(&commands::ReleaseArgs {
                vrf: Some(vrf),
                addr: addr(10),
                reason: None,
            })
            .expect("arguments"),
        )
        .await;
    assert_eq!(released.outcome, Outcome::Done, "{}", released.detail);
    let (facts, _) = view_facts(&store).await;
    let now = Timestamp::now();
    assert!(!address_fact(&facts, ip4).is_current(now));
    assert!(address_fact(&facts, ip6).is_current(now));
    assert_eq!(fact_rows(&store).await, [0; 4]);
    role.stop().await;
}
