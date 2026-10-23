//! Tests of the view service over an in-memory store, with the jobs run in place: the
//! positions, the checks against other rows and the in-use rules in both directions.

use std::sync::Arc;

use tenko_core::{
    Coded, RequestCtx, SystemComponent,
    dns::{
        AclEntry, DnsName, ForwardTransport, QueryTransport, SerialPolicy, SoaDefaults, Upstream,
        ZoneKind, ZoneScope,
    },
};
use tenko_store::{MemStore, ReadConsistency, Store};

use super::*;
use crate::{
    forwarders::NewRule,
    zone::{NewZone, ZoneChange, ZoneConfig, acl::NewAcl},
};

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn service() -> (Arc<ZoneService>, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        None,
        ZoneConfig::default(),
    );
    (service, store)
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn scope(text: &str) -> ScopeName {
    ScopeName::new(text).expect("scope")
}

async fn zone_with(service: &ZoneService, apex: &str, scopes: &[&str]) -> Zone {
    service
        .create(
            &cx(),
            NewZone {
                name: name(apex),
                kind: ZoneKind::Primary,
                tenant: None,
                scopes: scopes
                    .iter()
                    .map(|text| ZoneScope {
                        name: scope(text),
                        description: None,
                    })
                    .collect(),
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
                catalog: false,
            },
        )
        .await
        .expect("zone")
        .zone
}

fn view(name: &str, order: u32) -> NewView {
    NewView {
        name: name.to_owned(),
        rules: vec![MatchRule::ClientSubnet {
            prefixes: vec!["192.0.2.0/24".parse().expect("prefix")],
        }],
        scope_map: Vec::new(),
        order,
        recursion: None,
        description: Some("  lab  ".to_owned()),
    }
}

async fn read(store: &Arc<MemStore>) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("view")
}

async fn names_in_order(store: &Arc<MemStore>) -> Vec<(String, u32)> {
    let read = read(store).await;
    ZoneService::dns_views(read.as_ref())
        .expect("views")
        .into_iter()
        .map(|row| (row.view.name, row.view.order))
        .collect()
}

fn audit_actions(view: &dyn ReadView) -> Vec<String> {
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record.draft.action.as_str().to_owned())
    .collect()
}

#[tokio::test]
async fn positions_stay_unique_and_without_gaps() {
    let (service, store) = service();
    let (first, _) = service
        .create_view(&cx(), view("first", 1))
        .await
        .expect("first");
    assert_eq!(first.order, 1);
    assert_eq!(first.description.as_deref(), Some("lab"), "trimmed");
    // Past the end is the end; at 1 pushes the others down.
    service
        .create_view(&cx(), view("last", 99))
        .await
        .expect("last");
    service
        .create_view(&cx(), view("top", 1))
        .await
        .expect("top");
    service
        .create_view(&cx(), view("middle", 3))
        .await
        .expect("middle");
    assert_eq!(
        names_in_order(&store).await,
        [
            ("top".to_owned(), 1),
            ("first".to_owned(), 2),
            ("middle".to_owned(), 3),
            ("last".to_owned(), 4)
        ]
    );
    // A move down and a move to the top.
    let (moved, written) = service
        .update_view(
            &cx(),
            first.id,
            ViewChange {
                order: Some(4),
                ..ViewChange::default()
            },
            None,
        )
        .await
        .expect("move");
    assert_eq!(moved.order, 4);
    assert!(written.is_some());
    assert_eq!(
        names_in_order(&store).await,
        [
            ("top".to_owned(), 1),
            ("middle".to_owned(), 2),
            ("last".to_owned(), 3),
            ("first".to_owned(), 4)
        ]
    );
    // A change without a new position keeps the position; nothing new writes nothing.
    let (same, written) = service
        .update_view(&cx(), first.id, ViewChange::default(), None)
        .await
        .expect("no-op");
    assert_eq!(same.order, 4);
    assert!(written.is_none(), "nothing to write");
    // A deletion closes the gap.
    let read_now = read(&store).await;
    let top = ZoneService::dns_views(read_now.as_ref()).expect("views")[0].clone();
    service
        .delete_view(&cx(), top.view.id, Some(top.revision))
        .await
        .expect("delete");
    assert_eq!(
        names_in_order(&store).await,
        [
            ("middle".to_owned(), 1),
            ("last".to_owned(), 2),
            ("first".to_owned(), 3)
        ]
    );
    let actions = audit_actions(read(&store).await.as_ref());
    assert_eq!(
        actions
            .iter()
            .filter(|a| a.starts_with("dns.view."))
            .count(),
        6,
        "{actions:?}"
    );
    assert!(actions.contains(&"dns.view.delete".to_owned()));
}

#[tokio::test]
async fn the_model_rules_and_the_limits_are_checked() {
    let (service, _) = service();
    for (new, field) in [
        (
            NewView {
                name: " padded".to_owned(),
                ..view("x", 1)
            },
            "name",
        ),
        (
            NewView {
                rules: vec![MatchRule::Transport {
                    transports: Vec::new(),
                }],
                ..view("x", 1)
            },
            "rules",
        ),
        (
            NewView {
                rules: vec![MatchRule::TimeOfDay {
                    from_minute: 0,
                    to_minute: 1440,
                }],
                ..view("x", 1)
            },
            "rules",
        ),
        (
            NewView {
                rules: vec![
                    MatchRule::Transport {
                        transports: vec![QueryTransport::Udp],
                    };
                    33
                ],
                ..view("x", 1)
            },
            "rules",
        ),
        (
            NewView {
                description: Some("d".repeat(1001)),
                ..view("x", 1)
            },
            "description",
        ),
    ] {
        let error = service.create_view(&cx(), new).await.expect_err("invalid");
        assert!(error.is(codes::VIEW_INVALID), "{error:?}");
        assert_eq!(
            error.coded().params.get("field").map(String::as_str),
            Some(field)
        );
    }
    service
        .create_view(&cx(), view("Inside", 1))
        .await
        .expect("first");
    let error = service
        .create_view(&cx(), view("inside", 1))
        .await
        .expect_err("taken without case");
    assert!(error.is(codes::VIEW_INVALID), "{error:?}");
    assert_eq!(error.http_status(), 400);
}

#[tokio::test]
async fn the_scope_map_names_scopes_its_zones_have() {
    let (service, _) = service();
    let zone = zone_with(&service, "example.test", &["internal", "external"]).await;
    let weighted = |scope_name: &str, weight: u16| ScopeWeight {
        zone: zone.id,
        scope: scope(scope_name),
        weight,
    };
    let error = service
        .create_view(
            &cx(),
            NewView {
                scope_map: vec![weighted("missing", 1)],
                ..view("v", 1)
            },
        )
        .await
        .expect_err("no such scope");
    assert!(error.is(codes::VIEW_INVALID), "{error:?}");
    assert_eq!(
        error.coded().params.get("scope").map(String::as_str),
        Some("missing")
    );
    let error = service
        .create_view(
            &cx(),
            NewView {
                scope_map: vec![ScopeWeight {
                    zone: ZoneId::generate(),
                    scope: ScopeName::DEFAULT,
                    weight: 1,
                }],
                ..view("v", 1)
            },
        )
        .await
        .expect_err("no such zone");
    assert!(error.is(codes::VIEW_INVALID), "{error:?}");
    for (map, reason) in [
        (vec![weighted("internal", 0)], "weight 0"),
        (vec![weighted("internal", 1001)], "weight 1001"),
        (
            vec![weighted("internal", 1), weighted("internal", 2)],
            "twice",
        ),
    ] {
        let error = service
            .create_view(
                &cx(),
                NewView {
                    scope_map: map,
                    ..view("v", 1)
                },
            )
            .await
            .expect_err(reason);
        assert!(error.is(codes::VIEW_INVALID), "{reason}: {error:?}");
    }
    let (created, _) = service
        .create_view(
            &cx(),
            NewView {
                scope_map: vec![weighted("internal", 700), weighted("external", 300)],
                ..view("v", 1)
            },
        )
        .await
        .expect("a weighted pair");
    assert_eq!(created.scope_map.len(), 2);
}

#[tokio::test]
async fn a_named_scope_or_zone_stays_until_no_view_names_it() {
    let (service, store) = service();
    let zone = zone_with(&service, "example.test", &["internal", "spare"]).await;
    let (created, _) = service
        .create_view(
            &cx(),
            NewView {
                scope_map: vec![ScopeWeight {
                    zone: zone.id,
                    scope: scope("internal"),
                    weight: 1,
                }],
                ..view("inside", 1)
            },
        )
        .await
        .expect("view");
    // Removing the named scope is refused; removing the other one is not.
    let only_default = vec![ZoneScope::default_scope()];
    let error = service
        .update(
            &cx(),
            zone.id,
            ZoneChange {
                scopes: Some(only_default.clone()),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect_err("named scope");
    assert!(error.is(codes::VIEW_IN_USE), "{error:?}");
    assert_eq!(error.http_status(), 409);
    assert_eq!(
        error.coded().params.get("by").map(String::as_str),
        Some("view:inside")
    );
    let keep_internal = vec![
        ZoneScope::default_scope(),
        ZoneScope {
            name: scope("internal"),
            description: None,
        },
    ];
    service
        .update(
            &cx(),
            zone.id,
            ZoneChange {
                scopes: Some(keep_internal),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect("the spare scope goes");
    let error = service
        .delete(&cx(), zone.id, None)
        .await
        .expect_err("named zone");
    assert!(error.is(codes::VIEW_IN_USE), "{error:?}");
    // Once the view lets go, both work.
    service
        .update_view(
            &cx(),
            created.id,
            ViewChange {
                scope_map: Some(Vec::new()),
                ..ViewChange::default()
            },
            None,
        )
        .await
        .expect("let go");
    service
        .update(
            &cx(),
            zone.id,
            ZoneChange {
                scopes: Some(only_default),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect("scope removed");
    service
        .delete(&cx(), zone.id, None)
        .await
        .expect("zone deleted");
    assert_eq!(names_in_order(&store).await.len(), 1);
}

#[tokio::test]
async fn the_recursion_list_is_in_use_and_a_view_of_a_rule_stays() {
    let (service, _) = service();
    let (acl, _) = service
        .create_acl(
            &cx(),
            NewAcl {
                name: "clients".to_owned(),
                entries: vec![AclEntry::Prefix {
                    prefix: "192.0.2.0/24".parse().expect("prefix"),
                    deny: false,
                }],
                description: None,
            },
        )
        .await
        .expect("acl");
    let error = service
        .create_view(
            &cx(),
            NewView {
                recursion: Some(AclId::generate()),
                ..view("inside", 1)
            },
        )
        .await
        .expect_err("no such list");
    assert!(error.is(codes::VIEW_INVALID), "{error:?}");
    let (created, _) = service
        .create_view(
            &cx(),
            NewView {
                recursion: Some(acl.id),
                ..view("inside", 1)
            },
        )
        .await
        .expect("view");
    assert_eq!(created.recursion, Some(acl.id));
    let read_now = service.view(None).await.expect("read");
    assert_eq!(
        ZoneService::acl(read_now.as_ref(), acl.id)
            .expect("acl")
            .used_by,
        ["view:inside"]
    );
    let error = service
        .delete_acl(&cx(), acl.id, None)
        .await
        .expect_err("in use");
    assert!(error.is(codes::ACL_IN_USE), "{error:?}");
    // The profile's default again: the list is free.
    let (changed, _) = service
        .update_view(
            &cx(),
            created.id,
            ViewChange {
                default_recursion: true,
                ..ViewChange::default()
            },
            None,
        )
        .await
        .expect("default");
    assert_eq!(changed.recursion, None);
    service.delete_acl(&cx(), acl.id, None).await.expect("free");

    // A forwarding rule of the view keeps it.
    service
        .create_forward_rule(
            &cx(),
            NewRule {
                suffix: name("example.net"),
                upstreams: vec![Upstream {
                    address: "192.0.2.53".parse().expect("address"),
                    port: None,
                    path: None,
                }],
                transport: ForwardTransport::Plain,
                tls_name: None,
                view: Some(created.id),
                description: None,
                validate: None,
            },
        )
        .await
        .expect("rule");
    let error = service
        .delete_view(&cx(), created.id, None)
        .await
        .expect_err("named by a rule");
    assert!(error.is(codes::VIEW_IN_USE), "{error:?}");
    assert_eq!(
        error.coded().params.get("by").map(String::as_str),
        Some("forwarder:example.net")
    );
    let error = service
        .delete_view(&cx(), ViewId::generate(), None)
        .await
        .expect_err("missing");
    assert!(error.is(codes::VIEW_NOT_FOUND), "{error:?}");
}

#[tokio::test]
async fn a_stale_revision_is_refused() {
    let (service, _) = service();
    let (created, written) = service
        .create_view(&cx(), view("inside", 1))
        .await
        .expect("view");
    let stale = Revision(written.revision.0 - 1);
    let error = service
        .update_view(
            &cx(),
            created.id,
            ViewChange {
                name: Some("renamed".to_owned()),
                ..ViewChange::default()
            },
            Some(stale),
        )
        .await
        .expect_err("stale");
    assert_eq!(error.http_status(), 412);
    let error = service
        .delete_view(&cx(), created.id, Some(stale))
        .await
        .expect_err("stale");
    assert_eq!(error.http_status(), 412);
}
