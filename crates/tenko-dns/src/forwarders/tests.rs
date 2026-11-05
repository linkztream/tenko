//! Tests of the forwarding rule service over an in-memory store, with the jobs run in
//! place.

use std::sync::Arc;

use tenko_core::{
    Coded, RequestCtx, SystemComponent,
    dns::{View, tables::VIEWS},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, Store, WriteBatch};

use super::*;
use crate::zone::ZoneConfig;

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

fn upstream(address: &str) -> Upstream {
    Upstream {
        address: address.parse().expect("address"),
        port: None,
        path: None,
    }
}

fn rule(suffix: &str) -> NewRule {
    NewRule {
        suffix: DnsName::new(suffix).expect("name"),
        upstreams: vec![upstream("192.0.2.53")],
        transport: ForwardTransport::Plain,
        tls_name: None,
        view: None,
        description: Some("  lab  ".to_owned()),
        validate: None,
        mode: None,
    }
}

async fn read(store: &Arc<MemStore>) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("view")
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
async fn a_rule_is_created_read_changed_and_deleted_with_its_audit() {
    let (service, store) = service();
    let (created, written) = service
        .create_forward_rule(&cx(), rule("example.net"), false)
        .await
        .expect("create");
    assert_eq!(created.description.as_deref(), Some("lab"), "trimmed");
    let view = read(&store).await;
    let row = ZoneService::forward_rule(view.as_ref(), created.id).expect("row");
    assert_eq!(row.rule, created);
    assert_eq!(row.revision, written.revision);
    let (changed, written) = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange {
                upstreams: Some(vec![upstream("192.0.2.54"), upstream("2001:db8::53")]),
                transport: Some(ForwardTransport::Dot),
                tls_name: Some("resolver.example.net".to_owned()),
                description: Some(String::new()),
                ..RuleChange::default()
            },
            false,
            Some(row.revision),
        )
        .await
        .expect("update");
    assert!(written.is_some());
    assert_eq!(changed.upstreams.len(), 2);
    assert_eq!(changed.description, None, "an empty description clears it");
    // The same change again writes nothing.
    let (_, again) = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange {
                transport: Some(ForwardTransport::Dot),
                ..RuleChange::default()
            },
            false,
            None,
        )
        .await
        .expect("no-op");
    assert!(again.is_none());
    // A stale revision is refused.
    let stale = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange::default(),
            false,
            Some(row.revision),
        )
        .await
        .expect_err("stale");
    assert_eq!(stale.coded().status, 412);
    service
        .delete_forward_rule(&cx(), created.id, None)
        .await
        .expect("delete");
    let view = read(&store).await;
    assert_eq!(
        ZoneService::forward_rule(view.as_ref(), created.id)
            .expect_err("gone")
            .code(),
        codes::FORWARDER_NOT_FOUND
    );
    assert_eq!(
        audit_actions(view.as_ref()),
        vec![
            "dns.forwarder.create",
            "dns.forwarder.update",
            "dns.forwarder.delete"
        ]
    );
}

#[tokio::test]
async fn invalid_rules_are_refused() {
    let (service, store) = service();
    let mut dot = rule("example.net");
    dot.transport = ForwardTransport::Dot;
    let error = service
        .create_forward_rule(&cx(), dot, false)
        .await
        .expect_err("no tls name");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    let mut none = rule("example.net");
    none.upstreams.clear();
    assert_eq!(
        service
            .create_forward_rule(&cx(), none, false)
            .await
            .expect_err("no upstream")
            .code(),
        codes::FORWARDER_INVALID
    );
    let mut unknown_view = rule("example.net");
    unknown_view.view = Some(ViewId::generate());
    let error = service
        .create_forward_rule(&cx(), unknown_view, false)
        .await
        .expect_err("no such view");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    assert_eq!(
        error.coded().params.get("field").map(String::as_str),
        Some("view")
    );
    // One rule per suffix and view; the same suffix in a view is another rule.
    service
        .create_forward_rule(&cx(), rule("."), false)
        .await
        .expect("root");
    let error = service
        .create_forward_rule(&cx(), rule("."), false)
        .await
        .expect_err("taken");
    assert_eq!(
        error.coded().params.get("field").map(String::as_str),
        Some("suffix")
    );
    let view = View {
        id: ViewId::generate(),
        name: "lab".to_owned(),
        rules: Vec::new(),
        scope_map: Vec::new(),
        order: 1,
        recursion: None,
        resolution: None,
        description: None,
    };
    let mut batch = WriteBatch::for_request(&cx());
    batch.put_typed(&VIEWS, &view.id, &view).expect("encode");
    store.propose(batch).await.expect("view");
    let mut in_view = rule(".");
    in_view.view = Some(view.id);
    let (scoped, _) = service
        .create_forward_rule(&cx(), in_view, false)
        .await
        .expect("a root rule of a view");
    let (moved, _) = service
        .update_forward_rule(
            &cx(),
            scoped.id,
            RuleChange {
                suffix: Some(DnsName::new("example.org").expect("name")),
                all_views: true,
                ..RuleChange::default()
            },
            false,
            None,
        )
        .await
        .expect("move to all views");
    assert_eq!(moved.view, None);
    let view = read(&store).await;
    let suffixes: Vec<String> = ZoneService::forward_rules(view.as_ref())
        .expect("rules")
        .into_iter()
        .map(|row| row.rule.suffix.to_string())
        .collect();
    assert_eq!(suffixes, vec![".", "example.org"]);
}

fn field(error: &ZoneError) -> Option<&str> {
    error.coded().params.get("field").map(String::as_str)
}

#[tokio::test]
async fn validation_off_is_refused_on_the_root_and_under_hardened_and_audited() {
    let (service, store) = service();
    // The root rule never relays answers unvalidated, under any profile.
    let mut root = rule(".");
    root.validate = Some(false);
    let error = service
        .create_forward_rule(&cx(), root, false)
        .await
        .expect_err("the root validates");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    assert_eq!(field(&error), Some("validate"));
    // The Hardened profile refuses it for every suffix (TGL-12 "On").
    let mut off = rule("stripped.example.net");
    off.validate = Some(false);
    let error = service
        .create_forward_rule(&cx(), off.clone(), true)
        .await
        .expect_err("hardened");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    assert_eq!(field(&error), Some("validate"));
    // The other profiles accept it, and the audit record says so.
    let (created, _) = service
        .create_forward_rule(&cx(), off, false)
        .await
        .expect("standard");
    assert!(!created.validate);
    let view = read(&store).await;
    let records: Vec<_> = view
        .scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft)
        .collect();
    let create = records
        .iter()
        .find(|draft| draft.action.as_str() == "dns.forwarder.create")
        .expect("the create record");
    assert_eq!(
        create.details.context.get("validate").map(String::as_str),
        Some("off")
    );
    assert_eq!(
        create.details.context.get("id").map(String::as_str),
        Some(created.id.to_string().as_str())
    );
}

#[tokio::test]
async fn a_change_keeps_the_rules_of_validation_off() {
    let (service, store) = service();
    let mut off = rule("stripped.example.net");
    off.validate = Some(false);
    let (created, _) = service
        .create_forward_rule(&cx(), off, false)
        .await
        .expect("standard");
    // A change that keeps validation off is refused under Hardened, and so is a change
    // that moves the rule to the root; turning validation on is accepted under Hardened.
    let error = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange {
                description: Some("still off".to_owned()),
                ..RuleChange::default()
            },
            true,
            None,
        )
        .await
        .expect_err("hardened keeps validation off out");
    assert_eq!(field(&error), Some("validate"));
    let error = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange {
                suffix: Some(DnsName::root()),
                ..RuleChange::default()
            },
            false,
            None,
        )
        .await
        .expect_err("the root validates");
    assert_eq!(field(&error), Some("validate"));
    let (changed, _) = service
        .update_forward_rule(
            &cx(),
            created.id,
            RuleChange {
                validate: Some(true),
                ..RuleChange::default()
            },
            true,
            None,
        )
        .await
        .expect("validation on under hardened");
    assert!(changed.validate);
    let view = read(&store).await;
    let updates: Vec<_> = view
        .scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft)
        .filter(|draft| draft.action.as_str() == "dns.forwarder.update")
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(
        !updates[0].details.context.contains_key("validate"),
        "a rule that validates is an ordinary record"
    );
}

#[test]
fn stored_rules_with_validation_off_are_reported_as_problems() {
    let make = |suffix: &str, validate: bool| ForwardRule {
        id: ForwardRuleId::generate(),
        suffix: DnsName::new(suffix).expect("name"),
        upstreams: vec![upstream("192.0.2.53")],
        transport: ForwardTransport::Plain,
        tls_name: None,
        view: None,
        mode: RuleMode::Forward,
        validate,
        description: None,
    };
    let rules = [
        make(".", false),
        make("example.net", false),
        make("example.org", true),
    ];
    let standard = forward_rule_problems(rules.iter(), false);
    assert_eq!(standard.len(), 1, "{standard:?}");
    assert!(
        standard[0].starts_with("forwarding rule . ("),
        "{standard:?}"
    );
    assert!(standard[0].contains("the root rule always validates"));
    let hardened = forward_rule_problems(rules.iter(), true);
    assert_eq!(hardened.len(), 2, "{hardened:?}");
    assert!(hardened[1].starts_with("forwarding rule example.net ("));
    assert!(hardened[1].contains("Hardened"));
    assert_eq!(
        forward_rule_problems(std::iter::empty(), true),
        Vec::<String>::new()
    );
}
