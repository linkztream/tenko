//! Shared helpers of the integration tests.

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use tenko_core::{
    AddressId, HostId, InterfaceId, PrefixId, Principal, RequestCtx, SessionId, SystemComponent,
    UserId, VrfId,
    ipam::{AssignmentMode, PrefixRole, RangeRole, UtilizationAlarm},
};
use tenko_ipam::{
    Applied, IpamCommand, IpamService, PlanOptions,
    command::{
        AddressInput, AllocateAddress, HostInput, InterfaceInput, PrefixInput, RangeInput, VrfInput,
    },
};
use tenko_store::{MemStore, Store};

/// A service over a fresh in-memory store.
pub fn service() -> (Arc<IpamService>, MemStore) {
    let store = MemStore::default();
    let service =
        IpamService::with_direct_jobs(Arc::new(store.clone()) as Arc<dyn Store>).expect("service");
    (service, store)
}

/// A request of a person.
pub fn person() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: tenko_core::AuthStrength::Passkey,
    })
}

/// A request of automation (the reconciler).
pub fn automation() -> RequestCtx {
    RequestCtx::system(SystemComponent::Reconciler)
}

/// Runs commands as a person and expects success.
pub async fn run(service: &IpamService, commands: Vec<IpamCommand>) -> Applied {
    service
        .execute(&commands, &person(), &PlanOptions::default())
        .await
        .expect("execute")
}

/// A prefix command.
pub fn prefix(vrf: Option<VrfId>, cidr: &str) -> PrefixInput {
    PrefixInput {
        id: Some(PrefixId::generate()),
        vrf,
        cidr: cidr.parse().expect("cidr"),
        role: None,
        status: None,
        vlan: None,
        site: None,
        alarm: None,
        alloc: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

/// A supernet command.
pub fn supernet(vrf: Option<VrfId>, cidr: &str) -> PrefixInput {
    PrefixInput {
        role: Some(PrefixRole::Supernet),
        ..prefix(vrf, cidr)
    }
}

/// A network with alarm thresholds.
pub fn alarmed(vrf: Option<VrfId>, cidr: &str, warn: u8, crit: u8) -> PrefixInput {
    PrefixInput {
        alarm: Some(UtilizationAlarm::new(warn, crit).expect("alarm")),
        ..prefix(vrf, cidr)
    }
}

/// An address command.
pub fn address(vrf: Option<VrfId>, ip: &str) -> AddressInput {
    AddressInput {
        id: Some(AddressId::generate()),
        vrf,
        ip: ip.parse().expect("ip"),
        status: None,
        interface: None,
        dns_name: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

/// A range command.
pub fn range(prefix: PrefixId, first: &str, last: &str, role: RangeRole) -> RangeInput {
    RangeInput {
        id: None,
        prefix,
        first: first.parse().expect("ip"),
        last: last.parse().expect("ip"),
        role,
        status: None,
        lease_secs: None,
        delegated_len: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

/// A VRF command.
pub fn vrf(name: &str) -> VrfInput {
    VrfInput {
        id: Some(VrfId::generate()),
        tenant: None,
        name: name.to_owned(),
        rd: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

/// A host with one interface.
pub fn host(name: &str, mode: AssignmentMode, mac: Option<&str>) -> (HostInput, InterfaceId) {
    let interface = InterfaceId::generate();
    (
        HostInput {
            id: Some(HostId::generate()),
            tenant: None,
            name: name.parse().expect("host name"),
            mode: Some(mode),
            lock: None,
            site: None,
            interfaces: vec![InterfaceInput {
                id: Some(interface),
                host: None,
                name: "eth0".to_owned(),
                mac: mac.map(|m| m.parse().expect("mac")),
                duid: None,
                client_id: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }],
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        },
        interface,
    )
}

/// A next-free address command.
pub fn allocate(prefix: PrefixId) -> AllocateAddress {
    AllocateAddress {
        prefix,
        policy: None,
        range: None,
        id: None,
        status: None,
        interface: None,
        dns_name: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
        hint: None,
    }
}

// ---------------------------------------------------------------------------------------
// Helpers of the property, allocation, performance and rule suites.
// ---------------------------------------------------------------------------------------

use std::net::IpAddr;

use tenko_core::{ObjectRef, Timestamp};
use tenko_ipam::{
    Entity, IpNet, IpamError, IpamResult,
    query::{self, Deleted, ListQuery},
};
use tenko_store::{ReadView, ReadViewExt};
use uuid::Uuid;

/// Parses an IP address.
pub fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip address")
}

/// Parses a network.
pub fn net(text: &str) -> IpNet {
    text.parse().expect("network")
}

/// Runs commands as a person and returns the outcome.
pub async fn try_run(service: &IpamService, commands: Vec<IpamCommand>) -> IpamResult<Applied> {
    service
        .execute(&commands, &person(), &PlanOptions::default())
        .await
}

/// Runs commands as the given request and returns the outcome.
pub async fn try_run_as(
    service: &IpamService,
    commands: Vec<IpamCommand>,
    cx: &RequestCtx,
) -> IpamResult<Applied> {
    service
        .execute(&commands, cx, &PlanOptions::default())
        .await
}

/// Runs commands as a person and expects the error with the given code; returns it.
pub async fn run_err(service: &IpamService, commands: Vec<IpamCommand>, code: &str) -> IpamError {
    let error = try_run(service, commands)
        .await
        .expect_err("the commands must fail");
    assert_eq!(error.code_str(), code, "{error:?}");
    error
}

/// Runs commands as the given request and expects the error with the given code.
pub async fn run_err_as(
    service: &IpamService,
    commands: Vec<IpamCommand>,
    cx: &RequestCtx,
    code: &str,
) -> IpamError {
    let error = try_run_as(service, commands, cx)
        .await
        .expect_err("the commands must fail");
    assert_eq!(error.code_str(), code, "{error:?}");
    error
}

/// The HTTP status of an error.
pub fn status_of(error: &IpamError) -> u16 {
    error.coded().status
}

/// A read view of everything committed so far.
pub async fn snapshot(service: &IpamService) -> Arc<dyn ReadView> {
    service.view(None).await.expect("view")
}

/// One object, deleted ones included; `meta.revision` is the revision that wrote it.
pub async fn fetch<T: Entity>(service: &IpamService, id: T::Id) -> T {
    let view = snapshot(service).await;
    query::get::<T>(view.as_ref(), id).expect("object")
}

/// Whether the object exists.
pub async fn exists<T: Entity>(service: &IpamService, id: T::Id) -> bool {
    let view = snapshot(service).await;
    query::get::<T>(view.as_ref(), id).is_ok()
}

/// Every object of a kind, deleted ones included, in the default order.
pub async fn all_of<T: query::Listable>(service: &IpamService) -> Vec<T> {
    let view = snapshot(service).await;
    let query = ListQuery {
        limit: Some(query::MAX_LIMIT),
        deleted: Deleted::Include,
        ..ListQuery::default()
    };
    query::list::<T>(view.as_ref(), &query).expect("list").items
}

/// The identifier behind the result of a command.
pub fn id_of<I: From<Uuid>>(object: ObjectRef) -> I {
    I::from(object.id)
}

/// The store revision now.
pub fn revision_of(store: &MemStore) -> tenko_core::Revision {
    store.status().revision
}

/// A request of a person that keeps one principal and one time, so that two requests of the
/// same principal share idempotency keys.
pub fn request_of(principal: &Principal, nanos_after_epoch: i128) -> RequestCtx {
    RequestCtx::new(principal.clone())
        .at(Timestamp::from_unix_nanos(nanos_after_epoch).expect("time"))
}

/// A principal of a person.
pub fn principal() -> Principal {
    person().principal
}

/// Checks everything the domain promises about prefixes, ranges and addresses of every VRF:
/// no two live prefixes overlap except as a supernet over its contents, every live address
/// belongs to the most specific live prefix of its VRF, ranges lie in networks and do not
/// overlap, the uniqueness tables hold exactly the live objects, and the prefix tree index
/// agrees with the tables.
#[allow(clippy::too_many_lines)] // One check after the other, each reporting what broke.
pub async fn check_invariants(service: &IpamService) -> Result<(), String> {
    let view = snapshot(service).await;
    let read = |e: tenko_store::StoreError| e.to_string();
    let prefixes: Vec<tenko_core::ipam::Prefix> = view
        .scan_typed(
            &tenko_ipam::tables::PREFIXES,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(read)?
        .into_iter()
        .map(|(_, p, _)| p)
        .collect();
    let addresses: Vec<tenko_core::ipam::Address> = view
        .scan_typed(
            &tenko_ipam::tables::ADDRESSES,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(read)?
        .into_iter()
        .map(|(_, a, _)| a)
        .collect();
    let live_prefixes: Vec<&tenko_core::ipam::Prefix> =
        prefixes.iter().filter(|p| !p.meta.is_deleted()).collect();
    let live_addresses: Vec<&tenko_core::ipam::Address> =
        addresses.iter().filter(|a| !a.meta.is_deleted()).collect();

    // Distinct networks per VRF; an outer prefix is a supernet.
    for (i, a) in live_prefixes.iter().enumerate() {
        for b in &live_prefixes[i + 1..] {
            if a.vrf != b.vrf {
                continue;
            }
            if a.cidr == b.cidr {
                return Err(format!("{} exists twice in one VRF", a.cidr));
            }
            for (outer, inner) in [(a, b), (b, a)] {
                if tenko_ipam::net::contains_net(&outer.cidr, &inner.cidr)
                    && outer.role != tenko_core::ipam::PrefixRole::Supernet
                {
                    return Err(format!(
                        "{} is a network but contains {}",
                        outer.cidr, inner.cidr
                    ));
                }
            }
        }
    }

    // The prefix of an address is the most specific live prefix of its VRF containing it.
    for address in &live_addresses {
        let expected = live_prefixes
            .iter()
            .filter(|p| p.vrf == address.vrf && tenko_ipam::net::contains_ip(&p.cidr, address.ip))
            .max_by_key(|p| p.cidr.prefix_len());
        match expected {
            Some(p) if p.id == address.prefix => {}
            Some(p) => {
                return Err(format!(
                    "{} belongs to {} but its prefix is {}",
                    address.ip, p.cidr, address.prefix
                ));
            }
            None => return Err(format!("{} lies in no live prefix", address.ip)),
        }
    }

    // Ranges lie inside live networks and do not overlap.
    let ranges: Vec<tenko_core::ipam::Range> = view
        .scan_typed(
            &tenko_ipam::tables::RANGES,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(read)?
        .into_iter()
        .map(|(_, r, _)| r)
        .filter(|r| !r.meta.is_deleted())
        .collect();
    for (i, range) in ranges.iter().enumerate() {
        let Some(owner) = live_prefixes.iter().find(|p| p.id == range.prefix) else {
            return Err(format!(
                "range {}-{} belongs to no live prefix",
                range.first, range.last
            ));
        };
        if owner.role != tenko_core::ipam::PrefixRole::Network
            || !tenko_ipam::net::contains_ip(&owner.cidr, range.first)
            || !tenko_ipam::net::contains_ip(&owner.cidr, range.last)
        {
            return Err(format!(
                "range {}-{} does not fit {}",
                range.first, range.last, owner.cidr
            ));
        }
        for other in &ranges[i + 1..] {
            if other.prefix == range.prefix
                && range.first <= other.last
                && other.first <= range.last
            {
                return Err(format!(
                    "ranges {}-{} and {}-{} overlap",
                    range.first, range.last, other.first, other.last
                ));
            }
        }
    }

    // The uniqueness tables hold exactly the live objects.
    let cidrs: std::collections::BTreeMap<(VrfId, tenko_ipam::IpNet), PrefixId> = view
        .scan_typed(
            &tenko_ipam::tables::PREFIX_CIDRS,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(read)?
        .into_iter()
        .map(|(key, id, _)| (key, id))
        .collect();
    let expected: std::collections::BTreeMap<(VrfId, tenko_ipam::IpNet), PrefixId> = live_prefixes
        .iter()
        .map(|p| ((p.vrf, p.cidr), p.id))
        .collect();
    if cidrs != expected {
        return Err(format!(
            "ipam.prefix_cidrs {cidrs:?} differs from live {expected:?}"
        ));
    }
    let ips: std::collections::BTreeMap<_, AddressId> = view
        .scan_typed(
            &tenko_ipam::tables::ADDRESS_IPS,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .map_err(read)?
        .into_iter()
        .map(|(key, id, _)| (key, id))
        .collect();
    let expected: std::collections::BTreeMap<_, AddressId> = live_addresses
        .iter()
        .map(|a| ((a.vrf, a.ip), a.id))
        .collect();
    if ips != expected {
        return Err(format!(
            "ipam.address_ips {ips:?} differs from live {expected:?}"
        ));
    }

    // The prefix tree index follows the tables.
    let tree = service.tree();
    for prefix in &prefixes {
        let indexed = tree.prefix(prefix.id);
        if prefix.meta.is_deleted() {
            if indexed.is_some() {
                return Err(format!("the tree still holds deleted {}", prefix.cidr));
            }
            continue;
        }
        if indexed != Some((prefix.vrf, prefix.cidr)) {
            return Err(format!("the tree holds {indexed:?} for {}", prefix.cidr));
        }
        let mut children: Vec<PrefixId> = live_prefixes
            .iter()
            .filter(|q| {
                q.vrf == prefix.vrf
                    && q.id != prefix.id
                    && tenko_ipam::net::contains_net(&prefix.cidr, &q.cidr)
                    && !live_prefixes.iter().any(|r| {
                        r.vrf == prefix.vrf
                            && r.id != prefix.id
                            && r.id != q.id
                            && tenko_ipam::net::contains_net(&prefix.cidr, &r.cidr)
                            && tenko_ipam::net::contains_net(&r.cidr, &q.cidr)
                    })
            })
            .map(|q| q.id)
            .collect();
        children.sort();
        let mut indexed_children = tree.children(prefix.id);
        indexed_children.sort();
        if children != indexed_children {
            return Err(format!("the tree lists other children for {}", prefix.cidr));
        }
    }
    for address in &live_addresses {
        if tree.containing(address.vrf, address.ip) != Some(address.prefix) {
            return Err(format!("the tree places {} elsewhere", address.ip));
        }
    }

    // An index built from scratch gives the same tree as the one kept up to date, with the
    // same utilization everywhere.
    let fresh = tenko_ipam::PrefixTree::new();
    let image = tenko_store::DerivedIndex::build(&fresh, view.as_ref()).map_err(read)?;
    tenko_store::DerivedIndex::install(&fresh, image);
    let vrfs: std::collections::BTreeSet<VrfId> = prefixes.iter().map(|p| p.vrf).collect();
    for vrf in vrfs {
        if tree.tree(vrf, None, None) != fresh.tree(vrf, None, None) {
            return Err(format!(
                "the tree of VRF {vrf} differs from one built from the tables"
            ));
        }
    }
    Ok(())
}
