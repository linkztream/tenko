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
        .create_forward_rule(&cx(), rule("example.net"))
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
            None,
        )
        .await
        .expect("no-op");
    assert!(again.is_none());
    // A stale revision is refused.
    let stale = service
        .update_forward_rule(&cx(), created.id, RuleChange::default(), Some(row.revision))
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
        .create_forward_rule(&cx(), dot)
        .await
        .expect_err("no tls name");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    let mut none = rule("example.net");
    none.upstreams.clear();
    assert_eq!(
        service
            .create_forward_rule(&cx(), none)
            .await
            .expect_err("no upstream")
            .code(),
        codes::FORWARDER_INVALID
    );
    let mut unknown_view = rule("example.net");
    unknown_view.view = Some(ViewId::generate());
    let error = service
        .create_forward_rule(&cx(), unknown_view)
        .await
        .expect_err("no such view");
    assert_eq!(error.code(), codes::FORWARDER_INVALID);
    assert_eq!(
        error.coded().params.get("field").map(String::as_str),
        Some("view")
    );
    // One rule per suffix and view; the same suffix in a view is another rule.
    service
        .create_forward_rule(&cx(), rule("."))
        .await
        .expect("root");
    let error = service
        .create_forward_rule(&cx(), rule("."))
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
        .create_forward_rule(&cx(), in_view)
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
