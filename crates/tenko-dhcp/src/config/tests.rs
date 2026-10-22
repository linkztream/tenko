//! The configuration service on an in-memory store: the scope's link to its prefix and the
//! deletion rule on IPAM's side, the cascade of a scope's deletion, the option types, the
//! in-use rules, the utilization and the effective options of a reserved client.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};

use tenko_core::{
    NodeId, ObjectRef, PrefixId, RangeId, Revision, Timestamp,
    dhcp::{
        BindingState, ClientKey, Condition, DdnsState, FilterKind, Join, Lease, LeaseTimes,
        MacPattern, Match, OptionData, OptionKind, OptionOwner, OptionSpace, PolicyAction, Term,
        codes,
        tables::{EXCLUSIONS, LEASES, OPTION_SETS, POOLS, SCOPES},
    },
    ipam::{AssignmentMode, PrefixRole, RangeRole},
    serde_util::HexBytes,
};
use tenko_ipam::{IpamCommand, IpamService, PlanOptions, command::PrefixInput};
use tenko_store::{ReadViewExt, Store, WriteBatch};

use super::{
    ConfigService,
    classes::NewPolicy,
    effective::{ClientFacts, NoMatcher},
    options::{NewOptionDef, OptionInput},
    pools::PoolChange,
    scopes::{NewScope, ScopeChange},
    testkit::{Ipam, address, cx, host, interface, ip, prefix, principal, range, stamp, store},
};

fn new_scope(prefix: PrefixId) -> NewScope {
    NewScope {
        prefix,
        enabled: None,
        lease: None,
        authoritative: None,
        server_id: None,
        ddns: None,
        shared_network: None,
        restricted: false,
        classes: Vec::new(),
        description: None,
    }
}

/// A network 192.0.2.0/24 with a pool .100-.199, an infrastructure range .1-.9, a reserved
/// host at .150 (inside the pool, MAC ...:01), a static server at .160 and a dynamic laptop
/// at .170.
struct World {
    store: Arc<dyn Store>,
    service: Arc<ConfigService>,
    prefix: PrefixId,
    pool: RangeId,
    reserved_interface: tenko_core::InterfaceId,
}

async fn world() -> World {
    let store = store();
    let service = ConfigService::with_direct_jobs(Arc::clone(&store));
    let network = prefix(
        tenko_core::VrfId::generate(),
        "192.0.2.0/24",
        PrefixRole::Network,
    );
    let pool = range(
        network.id,
        "192.0.2.100",
        "192.0.2.199",
        RangeRole::DhcpPool,
    );
    let infra = range(
        network.id,
        "192.0.2.1",
        "192.0.2.9",
        RangeRole::Infrastructure,
    );
    let printer = host("printer", AssignmentMode::Reserved);
    let server = host("server", AssignmentMode::Static);
    let laptop = host("laptop", AssignmentMode::Dynamic);
    let printer_if = interface(printer.id, Some(1), None);
    let server_if = interface(server.id, Some(2), None);
    let laptop_if = interface(laptop.id, Some(3), None);
    let ipam = Ipam {
        addresses: vec![
            address(&network, "192.0.2.150", Some(printer_if.id)),
            address(&network, "192.0.2.160", Some(server_if.id)),
            address(&network, "192.0.2.170", Some(laptop_if.id)),
        ],
        prefixes: vec![network.clone()],
        ranges: vec![pool.clone(), infra],
        hosts: vec![printer, server, laptop],
        interfaces: vec![printer_if.clone(), server_if, laptop_if],
    };
    ipam.write(&store).await;
    World {
        store,
        service,
        prefix: network.id,
        pool: pool.id,
        reserved_interface: printer_if.id,
    }
}

fn lease(
    prefix: PrefixId,
    vrf: tenko_core::VrfId,
    addr: Ipv4Addr,
    state: BindingState,
    last: u8,
) -> Lease {
    let now = Timestamp::now();
    Lease {
        addr,
        vrf,
        scope: prefix,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, last]),
            client_id: None,
        },
        state,
        cltt: now,
        ends: "2099-01-01T00:00:00Z".parse().expect("time"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NodeId(1),
        share: None,
        hostname: None,
        fqdn: None,
        fqdn_flags: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
    }
}

#[tokio::test]
async fn a_scope_serves_a_network_once_and_not_a_supernet() {
    let world = world().await;
    let (scope, written) = world
        .service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("create");
    assert!(scope.enabled);
    assert!(written.revision > Revision::ZERO);
    let error = world
        .service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect_err("twice");
    assert!(error.is(codes::SCOPE_EXISTS), "{error:?}");

    let supernet = prefix(
        tenko_core::VrfId::generate(),
        "198.51.100.0/24",
        PrefixRole::Supernet,
    );
    Ipam {
        prefixes: vec![supernet.clone()],
        ..Ipam::default()
    }
    .write(&world.store)
    .await;
    let error = world
        .service
        .create_scope(&cx(), new_scope(supernet.id))
        .await
        .expect_err("supernet");
    assert!(error.is(codes::SCOPE_NOT_NETWORK), "{error:?}");
    let error = world
        .service
        .create_scope(&cx(), new_scope(PrefixId::generate()))
        .await
        .expect_err("missing");
    assert!(error.is("ipam.not_found"), "{error:?}");
}

#[tokio::test]
async fn ipam_refuses_to_delete_a_prefix_a_scope_serves() {
    let store = store();
    let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("IPAM");
    let service = ConfigService::with_direct_jobs(Arc::clone(&store));
    let id = PrefixId::generate();
    let input = PrefixInput {
        id: Some(id),
        vrf: None,
        cidr: "192.0.2.0/24".parse().expect("cidr"),
        role: None,
        status: None,
        vlan: None,
        site: None,
        alarm: None,
        alloc: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    };
    ipam.execute(
        &[IpamCommand::CreatePrefix(input)],
        &cx(),
        &PlanOptions::default(),
    )
    .await
    .expect("prefix");
    service
        .create_scope(&cx(), new_scope(id))
        .await
        .expect("scope");
    let delete = IpamCommand::Delete {
        object: ObjectRef::from(id),
        expected: None,
        cascade: true,
    };
    let error = ipam
        .execute(
            std::slice::from_ref(&delete),
            &cx(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code_str(), codes::SCOPE_ATTACHED);
    assert_eq!(tenko_core::Coded::http_status(&error), 409);

    service
        .delete_scope(&cx(), id, None)
        .await
        .expect("scope deleted");
    ipam.execute(&[delete], &cx(), &PlanOptions::default())
        .await
        .expect("the prefix goes once the scope is gone");
}

#[tokio::test]
async fn deleting_a_scope_takes_its_exclusions_pool_settings_policies_and_option_sets() {
    let world = world().await;
    let service = &world.service;
    service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("scope");
    let (exclusion, _) = service
        .create_exclusion(
            &cx(),
            world.prefix,
            ip("192.0.2.120"),
            ip("192.0.2.129"),
            None,
        )
        .await
        .expect("exclusion");
    service
        .set_pool(
            &cx(),
            world.pool,
            PoolChange {
                classes: Vec::new(),
                lease: Some(LeaseTimes::fixed(600)),
            },
            None,
        )
        .await
        .expect("pool");
    let (policy, _) = service
        .create_policy(
            &cx(),
            NewPolicy {
                name: "uefi".to_owned(),
                scope: Some(world.prefix),
                order: None,
                enabled: None,
                condition: Condition {
                    join: Join::And,
                    terms: vec![Term::Match(Match::Architecture { code: 7 })],
                },
                action: PolicyAction::default(),
                description: None,
            },
        )
        .await
        .expect("policy");
    let dns = OptionInput {
        space: OptionSpace::dhcp4(),
        code: 6,
        data: None,
        typed: Some(OptionData::Ipv4 {
            values: vec![Ipv4Addr::new(192, 0, 2, 53)],
        }),
    };
    for owner in [
        OptionOwner::Scope(world.prefix),
        OptionOwner::Pool(world.pool),
        OptionOwner::Policy(policy.id),
    ] {
        service
            .set_option_set(&cx(), owner, vec![dns.clone()], None)
            .await
            .expect("options");
    }
    let written = service
        .delete_scope(&cx(), world.prefix, None)
        .await
        .expect("delete");
    let view = service.view(Some(written.revision)).await.expect("view");
    assert!(
        view.get_typed(&SCOPES, &world.prefix)
            .expect("read")
            .is_none()
    );
    assert!(
        view.get_typed(&EXCLUSIONS, &(world.prefix, exclusion.id))
            .expect("read")
            .is_none()
    );
    assert!(view.get_typed(&POOLS, &world.pool).expect("read").is_none());
    assert!(ConfigService::policy(view.as_ref(), policy.id).is_err());
    for owner in [
        OptionOwner::Scope(world.prefix),
        OptionOwner::Pool(world.pool),
        OptionOwner::Policy(policy.id),
    ] {
        assert!(
            view.get_typed(&OPTION_SETS, &owner)
                .expect("read")
                .is_none()
        );
    }
}

#[tokio::test]
async fn option_values_are_typed_and_checked_against_their_definition() {
    let world = world().await;
    let service = &world.service;
    // A server-managed code and an unknown code are refused.
    let raw = |code: u16, data: Vec<u8>| OptionInput {
        space: OptionSpace::dhcp4(),
        code,
        data: Some(data),
        typed: None,
    };
    let error = service
        .set_option_set(
            &cx(),
            OptionOwner::Server,
            vec![raw(51, vec![0, 0, 1, 0])],
            None,
        )
        .await
        .expect_err("managed");
    assert!(error.is(codes::OPTION_CODE_RESERVED), "{error:?}");
    let error = service
        .set_option_set(&cx(), OptionOwner::Server, vec![raw(230, vec![1])], None)
        .await
        .expect_err("unknown");
    assert!(error.is(codes::OPTION_UNKNOWN), "{error:?}");
    // A definition for a catalog code is refused; a site-specific one is accepted.
    let def = |code: u16| NewOptionDef {
        space: OptionSpace::dhcp4(),
        code,
        name: "site-flag".to_owned(),
        kind: OptionKind::U16,
        array: false,
        vendor_class: None,
        description: None,
    };
    let error = service
        .create_option_def(&cx(), def(6))
        .await
        .expect_err("catalog");
    assert!(error.is(codes::OPTION_CODE_RESERVED), "{error:?}");
    let (custom, _) = service
        .create_option_def(&cx(), def(230))
        .await
        .expect("define");
    let error = service
        .create_option_def(&cx(), def(230))
        .await
        .expect_err("twice");
    assert!(error.is(codes::OPTION_DEF_EXISTS), "{error:?}");
    // Wire data of the wrong length is invalid; typed data is encoded.
    let error = service
        .set_option_set(&cx(), OptionOwner::Server, vec![raw(230, vec![1])], None)
        .await
        .expect_err("short");
    assert!(error.is(codes::OPTION_INVALID), "{error:?}");
    let (set, _) = service
        .set_option_set(
            &cx(),
            OptionOwner::Server,
            vec![OptionInput {
                space: OptionSpace::dhcp4(),
                code: 230,
                data: None,
                typed: Some(OptionData::Unsigned(vec![513])),
            }],
            None,
        )
        .await
        .expect("typed");
    assert_eq!(set.values[0].data.0, vec![2, 1]);
    // A used definition keeps its type and is not deleted.
    let error = service
        .update_option_def(
            &cx(),
            custom.id,
            super::options::OptionDefChange {
                kind: Some(OptionKind::U32),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("in use");
    assert!(error.is(codes::OPTION_DEF_IN_USE), "{error:?}");
    let error = service
        .delete_option_def(&cx(), custom.id, None)
        .await
        .expect_err("in use");
    assert!(error.is(codes::OPTION_DEF_IN_USE), "{error:?}");
    service
        .delete_option_set(&cx(), OptionOwner::Server, None)
        .await
        .expect("clear");
    service
        .delete_option_def(&cx(), custom.id, None)
        .await
        .expect("unused now");
}

#[tokio::test]
async fn a_class_in_use_stays_and_names_are_unique() {
    let world = world().await;
    let service = &world.service;
    let matches = vec![Match::VendorClass {
        value: "PXEClient".to_owned(),
        prefix: true,
    }];
    let (class, _) = service
        .create_class(&cx(), "pxe".to_owned(), matches.clone(), None)
        .await
        .expect("class");
    let error = service
        .create_class(&cx(), "pxe".to_owned(), matches, None)
        .await
        .expect_err("taken");
    assert!(error.is(codes::CLASS_INVALID), "{error:?}");
    let mut scope = new_scope(world.prefix);
    scope.classes = vec![class.id];
    service.create_scope(&cx(), scope).await.expect("scope");
    let error = service
        .delete_class(&cx(), class.id, None)
        .await
        .expect_err("in use");
    assert!(error.is(codes::CLASS_IN_USE), "{error:?}");
    assert_eq!(
        error.coded().params["by"],
        format!("scope:{}", world.prefix)
    );
    service
        .update_scope(
            &cx(),
            world.prefix,
            ScopeChange {
                classes: Some(Vec::new()),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("drop the class");
    service
        .delete_class(&cx(), class.id, None)
        .await
        .expect("unused now");
    // A filter pattern is unique.
    let pattern = MacPattern::new("00:00:5e:00:53:*").expect("pattern");
    service
        .create_filter(&cx(), pattern, FilterKind::Deny, None)
        .await
        .expect("filter");
    let error = service
        .create_filter(&cx(), pattern, FilterKind::Allow, None)
        .await
        .expect_err("twice");
    assert!(error.is(codes::FILTER_EXISTS), "{error:?}");
}

#[tokio::test]
async fn a_policy_range_outside_its_scope_is_refused() {
    let world = world().await;
    world
        .service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("scope");
    let error = world
        .service
        .create_policy(
            &cx(),
            NewPolicy {
                name: "far".to_owned(),
                scope: Some(world.prefix),
                order: None,
                enabled: None,
                condition: Condition {
                    join: Join::Or,
                    terms: vec![Term::Match(Match::Architecture { code: 0 })],
                },
                action: PolicyAction {
                    range: Some(tenko_core::dhcp::AddressRange {
                        first: ip("203.0.113.1"),
                        last: ip("203.0.113.9"),
                    }),
                    ..PolicyAction::default()
                },
                description: None,
            },
        )
        .await
        .expect_err("outside");
    assert!(error.is(codes::POOL_OUTSIDE), "{error:?}");
}

#[tokio::test]
async fn a_stale_if_match_is_answered_with_412() {
    let world = world().await;
    let (_, written) = world
        .service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("scope");
    let change = ScopeChange {
        enabled: Some(false),
        ..ScopeChange::default()
    };
    let error = world
        .service
        .update_scope(
            &cx(),
            world.prefix,
            change.clone(),
            Some(Revision(written.revision.0 + 99)),
        )
        .await
        .expect_err("stale");
    assert_eq!(error.coded().status, 412);
    world
        .service
        .update_scope(&cx(), world.prefix, change, Some(written.revision))
        .await
        .expect("current");
}

#[tokio::test]
async fn the_utilization_counts_dynamic_reserved_leased_and_abandoned_addresses() {
    let world = world().await;
    world
        .service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("scope");
    world
        .service
        .create_exclusion(
            &cx(),
            world.prefix,
            ip("192.0.2.190"),
            ip("192.0.2.199"),
            None,
        )
        .await
        .expect("exclusion");
    let view = world.service.view(None).await.expect("view");
    let row = ConfigService::scope(view.as_ref(), world.prefix).expect("row");
    let vrf = row.prefix.vrf;
    let mut batch = WriteBatch::new(principal(), stamp().at);
    for (addr, state, last) in [
        (Ipv4Addr::new(192, 0, 2, 100), BindingState::Active, 10),
        (Ipv4Addr::new(192, 0, 2, 101), BindingState::Active, 11),
        (Ipv4Addr::new(192, 0, 2, 102), BindingState::Abandoned, 12),
        (Ipv4Addr::new(192, 0, 2, 103), BindingState::Expired, 13),
    ] {
        batch
            .put_typed(
                &LEASES,
                &(vrf, addr),
                &lease(world.prefix, vrf, addr, state, last),
            )
            .expect("lease");
    }
    world.store.propose(batch).await.expect("leases");
    let view = world.service.view(None).await.expect("view");
    let figures =
        ConfigService::utilization(view.as_ref(), world.prefix, Timestamp::now()).expect("figures");
    // 100 pool addresses, 10 excluded, .160 is a static server: 89 dynamic, and the
    // reserved .150 is held for its client.
    assert_eq!(figures.pool_size, 89);
    assert_eq!(figures.reserved, 1);
    assert_eq!(figures.leased, 2);
    assert_eq!(figures.abandoned, 1);
    assert_eq!(figures.free, 85);
    let row = ConfigService::scope(view.as_ref(), world.prefix).expect("row");
    assert_eq!((row.pools, row.leases), (1, 2));
    let pools = ConfigService::pools(view.as_ref(), Some(world.prefix)).expect("pools");
    assert_eq!(pools.len(), 1);
    assert_eq!((pools[0].size, pools[0].leased), (88, 2));
}

#[tokio::test]
async fn a_reserved_client_gets_its_host_options_over_the_scope_and_server() {
    let world = world().await;
    let service = &world.service;
    service
        .create_scope(&cx(), new_scope(world.prefix))
        .await
        .expect("scope");
    let typed = |code: u16, last: u8| OptionInput {
        space: OptionSpace::dhcp4(),
        code,
        data: None,
        typed: Some(OptionData::Ipv4 {
            values: vec![Ipv4Addr::new(192, 0, 2, last)],
        }),
    };
    service
        .set_option_set(
            &cx(),
            OptionOwner::Server,
            vec![typed(6, 53), typed(42, 123)],
            None,
        )
        .await
        .expect("server");
    service
        .set_option_set(
            &cx(),
            OptionOwner::Scope(world.prefix),
            vec![typed(3, 1), typed(6, 54)],
            None,
        )
        .await
        .expect("scope");
    service
        .set_option_set(
            &cx(),
            OptionOwner::Host(world.reserved_interface),
            vec![typed(6, 55)],
            None,
        )
        .await
        .expect("host");
    let view = service.view(None).await.expect("view");
    let reserved = ConfigService::effective_options(
        view.as_ref(),
        world.prefix,
        &ClientFacts {
            mac: Some([0, 0, 0x5e, 0, 0x53, 1]),
            ..ClientFacts::default()
        },
        &NoMatcher,
    )
    .expect("effective");
    assert_eq!(reserved.reservation, Some(world.reserved_interface));
    let summary: Vec<(u16, OptionOwner)> = reserved
        .options
        .iter()
        .map(|entry| (entry.value.code, entry.owner))
        .collect();
    assert_eq!(
        summary,
        vec![
            (6, OptionOwner::Host(world.reserved_interface)),
            (42, OptionOwner::Server),
            (3, OptionOwner::Scope(world.prefix)),
        ]
    );
    let stranger = ConfigService::effective_options(
        view.as_ref(),
        world.prefix,
        &ClientFacts {
            mac: Some([0, 0, 0x5e, 0, 0x53, 0x77]),
            ..ClientFacts::default()
        },
        &NoMatcher,
    )
    .expect("effective");
    assert_eq!(stranger.reservation, None);
    assert_eq!(stranger.options[0].owner, OptionOwner::Scope(world.prefix));
    assert_eq!(stranger.options[0].value.data.0, vec![192, 0, 2, 54]);
}
