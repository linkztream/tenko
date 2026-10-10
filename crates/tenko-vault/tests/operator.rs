//! The operator secrets model (WP2.1) over `MemVault`: metadata records, value
//! replacement, host bindings and their versions, deletion while referenced, reveals with
//! the host check, the stamp and the audit record, the rate limit, the layout of imported
//! credentials, and the adoption of secrets stored before the model existed.

mod common;

use std::sync::Arc;

use common::{
    audit_for, audit_of, ctx, mem_store, spec, tables_containing, unique_marker, value, view,
};
use tenko_core::{
    AuthStrength, Coded, HostId, ObjectKind, ObjectRef, Principal, RequestCtx, SessionId, UserId,
    audit::AuditOutcome,
    secret::{SecretClass, SecretRef},
};
use tenko_store::{Store, WriteBatch};
use tenko_vault::{
    MemVault, SecretBytes, Vault,
    operator::{
        BindingRequest, CredentialRole, NewOperatorSecret, OperatorError, OperatorSecretKind,
        OperatorSecretPatch, OperatorSecrets, REVEALS_PER_WINDOW, RevealRequest, SecretOrigin,
        ValueFormat, imported_record, stage_record,
    },
};

struct Env {
    vault: Arc<MemVault>,
    secrets: OperatorSecrets,
}

fn env() -> Env {
    let store = mem_store();
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let dyn_store: Arc<dyn Store> = store;
    let secrets = OperatorSecrets::new(dyn_store, Arc::clone(&vault) as Arc<dyn Vault>);
    Env { vault, secrets }
}

/// A person with a password session.
fn person() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Password,
    })
    .at(ctx().now)
}

fn new_secret(name: &str, secret: &str) -> NewOperatorSecret {
    NewOperatorSecret {
        name: name.to_owned(),
        kind: OperatorSecretKind::Password,
        tags: vec!["Unifi".to_owned(), "api_key".to_owned()],
        username: Some(" admin ".to_owned()),
        notes: Some("rack 4".to_owned()),
        value: value(secret),
    }
}

fn bind(secret: tenko_core::SecretId, role: CredentialRole) -> BindingRequest {
    BindingRequest { secret, role }
}

#[tokio::test]
async fn a_created_secret_carries_its_metadata_and_never_its_value() {
    let env = env();
    let cx = person();
    let marker = unique_marker();
    let created = env
        .secrets
        .create(&cx, new_secret("nas admin", &marker))
        .await
        .expect("created");
    let record = &created.record;
    assert_eq!(record.name, "nas admin");
    assert_eq!(record.tags, ["api_key", "unifi"]);
    assert_eq!(record.username.as_deref(), Some("admin"));
    assert_eq!(record.format, ValueFormat::Plain);
    assert_eq!(record.origin, SecretOrigin::Manual);
    assert!(created.revision.is_some());
    assert_eq!(created.hosts, Vec::new());
    assert_eq!(created.last_revealed, None);

    let meta = env
        .vault
        .meta(SecretRef { secret: record.id })
        .await
        .expect("meta")
        .expect("vault metadata");
    assert_eq!(meta.class, SecretClass::Operator);
    assert_eq!(meta.purpose.as_str(), "vault.operator");

    let store = env.vault.mem_store();
    let records = audit_of(store.as_ref(), "vault.secret.create").await;
    assert_eq!(records.len(), 1, "one audit record for the create");
    let context = &records[0].draft.details.context;
    assert_eq!(context.get("name").map(String::as_str), Some("nas admin"));
    assert_eq!(context.get("kind").map(String::as_str), Some("password"));
    let view = view(store.as_ref()).await;
    assert_eq!(
        tables_containing(view.as_ref(), marker.as_bytes()),
        Vec::new(),
        "the value is nowhere in plain text"
    );
    assert_eq!(
        env.secrets.list().await.expect("list"),
        vec![created.clone()]
    );
    assert_eq!(env.secrets.get(record.id).await.expect("get"), created);
}

#[tokio::test]
async fn invalid_metadata_and_empty_values_are_refused() {
    let env = env();
    let cx = person();
    for (new, field) in [
        (
            NewOperatorSecret {
                name: " ".to_owned(),
                ..new_secret("x", "example-value")
            },
            "name",
        ),
        (
            NewOperatorSecret {
                tags: vec!["two words".to_owned()],
                ..new_secret("x", "example-value")
            },
            "tags",
        ),
        (
            NewOperatorSecret {
                value: SecretBytes::default(),
                ..new_secret("x", "example-value")
            },
            "value",
        ),
    ] {
        match env.secrets.create(&cx, new).await {
            Err(OperatorError::Invalid { field: got, .. }) => assert_eq!(got, field),
            other => panic!("expected an invalid {field}, got {other:?}"),
        }
    }
    assert_eq!(env.secrets.list().await.expect("list"), Vec::new());
}

#[tokio::test]
async fn an_update_changes_metadata_and_replaces_the_value_in_one_write() {
    let env = env();
    let cx = person();
    let created = env
        .secrets
        .create(&cx, new_secret("nas admin", "example-old"))
        .await
        .expect("created");
    let id = created.record.id;
    let updated = env
        .secrets
        .update(
            &cx,
            id,
            OperatorSecretPatch {
                name: Some("nas root".to_owned()),
                tags: Some(vec![]),
                username: Some(None),
                notes: Some(Some("moved to rack 5".to_owned())),
                value: Some(value("example-new")),
                ..OperatorSecretPatch::default()
            },
            created.revision,
        )
        .await
        .expect("updated");
    assert_eq!(updated.record.name, "nas root");
    assert_eq!(updated.record.tags, Vec::<String>::new());
    assert_eq!(updated.record.username, None);
    assert_ne!(updated.revision, created.revision);
    let revealed = env
        .secrets
        .reveal(&cx, id, RevealRequest::default())
        .await
        .expect("revealed");
    assert_eq!(revealed.value.as_str(), "example-new");

    let store = env.vault.mem_store();
    let records = audit_of(store.as_ref(), "vault.secret.update").await;
    assert_eq!(records.len(), 1);
    let fields: Vec<&str> = records[0]
        .draft
        .details
        .changes
        .iter()
        .map(|change| change.field.as_str())
        .collect();
    assert_eq!(fields, ["name", "tags", "username", "notes"]);
    let notes = &records[0].draft.details.changes[3];
    assert_eq!((notes.old.as_ref(), notes.new.as_ref()), (None, None));
    assert_eq!(
        audit_for(
            store.as_ref(),
            "vault.secret.replace",
            SecretRef { secret: id }
        )
        .await
        .len(),
        1
    );
    // The same revision again is stale now.
    let stale = env
        .secrets
        .update(
            &cx,
            id,
            OperatorSecretPatch {
                name: Some("again".to_owned()),
                ..OperatorSecretPatch::default()
            },
            created.revision,
        )
        .await;
    assert_eq!(stale.err(), Some(OperatorError::Conflict));
    // A patch that changes nothing writes nothing.
    let same = env
        .secrets
        .update(&cx, id, OperatorSecretPatch::default(), None)
        .await
        .expect("no change");
    assert_eq!(same.revision, updated.revision);
}

#[tokio::test]
async fn host_bindings_are_versioned_checked_and_audited() {
    let env = env();
    let cx = person();
    let host = HostId::generate();
    let a = env
        .secrets
        .create(&cx, new_secret("a", "example-a"))
        .await
        .expect("a")
        .record
        .id;
    let b = env
        .secrets
        .create(&cx, new_secret("b", "example-b"))
        .await
        .expect("b")
        .record
        .id;
    let empty = env.secrets.host_credentials(host).await.expect("empty");
    assert_eq!(empty.items, Vec::new());
    let bound = env
        .secrets
        .set_host_credentials(
            &cx,
            host,
            &[bind(a, CredentialRole::Rdp), bind(b, CredentialRole::Admin)],
            Some(empty.version),
        )
        .await
        .expect("bound");
    let roles: Vec<CredentialRole> = bound.items.iter().map(|item| item.role).collect();
    assert_eq!(roles, [CredentialRole::Admin, CredentialRole::Rdp]);
    assert!(bound.version > empty.version);
    assert_eq!(
        env.secrets.get(a).await.expect("a").hosts,
        vec![(host, CredentialRole::Rdp)]
    );

    let stale = env
        .secrets
        .set_host_credentials(&cx, host, &[], Some(empty.version))
        .await;
    assert_eq!(stale.err(), Some(OperatorError::BindingsConflict));
    let twice = env
        .secrets
        .set_host_credentials(
            &cx,
            host,
            &[bind(a, CredentialRole::Rdp), bind(a, CredentialRole::Ssh)],
            None,
        )
        .await;
    assert!(matches!(twice, Err(OperatorError::Invalid { .. })));
    let system = env
        .vault
        .put_system(&cx, spec("auth.totp"), value("example-seed"))
        .await
        .expect("system secret");
    let refused = env
        .secrets
        .set_host_credentials(
            &cx,
            host,
            &[bind(system.secret, CredentialRole::Admin)],
            None,
        )
        .await;
    assert_eq!(
        refused.err(),
        Some(OperatorError::BindingMissing {
            secret: system.secret
        })
    );

    let changed = env
        .secrets
        .set_host_credentials(
            &cx,
            host,
            &[bind(a, CredentialRole::Ssh)],
            Some(bound.version),
        )
        .await
        .expect("changed");
    assert_eq!(changed.items.len(), 1);
    assert_eq!(env.secrets.get(b).await.expect("b").hosts, Vec::new());
    let store = env.vault.mem_store();
    let records = audit_of(store.as_ref(), "vault.host.credentials").await;
    assert_eq!(records.len(), 2);
    let last = &records[1].draft;
    assert!(last.objects.contains(&ObjectRef::from(host)));
    let roles: Vec<(Option<&str>, Option<&str>)> = last
        .details
        .changes
        .iter()
        .map(|change| (change.old.as_deref(), change.new.as_deref()))
        .collect();
    assert!(roles.contains(&(Some("admin"), None)), "{roles:?}");
    assert!(roles.contains(&(Some("rdp"), Some("ssh"))), "{roles:?}");
}

#[tokio::test]
async fn a_bound_secret_cannot_be_deleted_until_it_is_unbound() {
    let env = env();
    let cx = person();
    let host = HostId::generate();
    let created = env
        .secrets
        .create(&cx, new_secret("nas admin", "example-value"))
        .await
        .expect("created");
    let id = created.record.id;
    env.secrets
        .set_host_credentials(&cx, host, &[bind(id, CredentialRole::Admin)], None)
        .await
        .expect("bound");
    match env.secrets.delete(&cx, id, None).await {
        Err(OperatorError::InUse { hosts, .. }) => assert_eq!(hosts, vec![host]),
        other => panic!("expected in use, got {other:?}"),
    }
    let error = OperatorError::InUse {
        hosts: vec![host],
        connectors: vec![],
    };
    assert_eq!(error.code(), "vault.secret.in_use");
    assert_eq!(error.http_status(), 409);

    env.secrets
        .set_host_credentials(&cx, host, &[], None)
        .await
        .expect("unbound");
    env.secrets
        .reveal(&cx, id, RevealRequest::default())
        .await
        .expect("a reveal leaves a stamp");
    env.secrets
        .delete(&cx, id, created.revision)
        .await
        .expect("deleted");
    assert_eq!(
        env.secrets.get(id).await.err(),
        Some(OperatorError::NotFound { secret: id })
    );
    assert_eq!(
        env.vault
            .meta(SecretRef { secret: id })
            .await
            .expect("meta"),
        None
    );
    let store = env.vault.mem_store();
    let view = view(store.as_ref()).await;
    for table in ["vault.operator_meta", "vault.reveals", "vault.secret_hosts"] {
        let rows = view
            .scan(
                &tenko_core::TableName::new(table).expect("a table name"),
                tenko_store::KeyRange::all(),
                usize::MAX,
                false,
            )
            .expect("scan");
        assert!(rows.is_empty(), "{table} still has rows");
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One reveal from the refusals to the record.
async fn a_reveal_checks_the_host_stamps_and_audits_without_the_value() {
    let env = env();
    let cx = person();
    let host = HostId::generate();
    let other = HostId::generate();
    let marker = unique_marker();
    let id = env
        .secrets
        .create(&cx, new_secret("nas admin", &marker))
        .await
        .expect("created")
        .record
        .id;
    env.secrets
        .set_host_credentials(&cx, host, &[bind(id, CredentialRole::Admin)], None)
        .await
        .expect("bound");

    let required = env
        .secrets
        .reveal(
            &cx,
            id,
            RevealRequest {
                bound_host_only: true,
                ..RevealRequest::default()
            },
        )
        .await;
    assert_eq!(required.err(), Some(OperatorError::HostRequired));
    let not_bound = env
        .secrets
        .reveal(
            &cx,
            id,
            RevealRequest {
                host: Some(other),
                ..RevealRequest::default()
            },
        )
        .await;
    assert_eq!(not_bound.err(), Some(OperatorError::NotBound));

    let revealed = env
        .secrets
        .reveal(
            &cx,
            id,
            RevealRequest {
                host: Some(host),
                reason: Some("RDP to the NAS".to_owned()),
                bound_host_only: true,
                user: cx.principal.user(),
                user_name: Some("alex".to_owned()),
            },
        )
        .await
        .expect("revealed");
    assert_eq!(revealed.value.as_str(), marker);
    assert_eq!(revealed.username.as_deref(), Some("admin"));
    let stamp = env
        .secrets
        .get(id)
        .await
        .expect("secret")
        .last_revealed
        .expect("a stamp");
    assert_eq!(stamp.host, Some(host));
    assert_eq!(stamp.user_name.as_deref(), Some("alex"));
    assert_eq!(stamp.user, cx.principal.user());

    let store = env.vault.mem_store();
    let records = audit_for(
        store.as_ref(),
        "vault.secret.reveal",
        SecretRef { secret: id },
    )
    .await;
    let outcomes: Vec<AuditOutcome> = records
        .iter()
        .map(|record| record.draft.outcome.clone())
        .collect();
    assert_eq!(outcomes.len(), 3, "two refusals and one reveal");
    assert!(matches!(outcomes[0], AuditOutcome::Denied));
    assert!(matches!(outcomes[1], AuditOutcome::Denied));
    assert_eq!(outcomes[2], AuditOutcome::Success);
    assert_eq!(
        records[0]
            .draft
            .details
            .context
            .get("code")
            .map(String::as_str),
        Some("vault.reveal.host_required")
    );
    let success = &records[2].draft;
    assert!(success.objects.contains(&ObjectRef::from(host)));
    assert_eq!(
        success.details.context.get("reason").map(String::as_str),
        Some("RDP to the NAS")
    );
    assert_eq!(
        success.details.context.get("host").map(String::as_str),
        Some(host.to_string().as_str())
    );
    assert_eq!(records[2].principal, cx.principal);
    let view = view(store.as_ref()).await;
    assert_eq!(
        tables_containing(view.as_ref(), marker.as_bytes()),
        Vec::new(),
        "a reveal leaves no plain value behind"
    );
}

#[tokio::test]
async fn reveals_are_rate_limited_per_person() {
    let env = env();
    let cx = person();
    let id = env
        .secrets
        .create(&cx, new_secret("nas admin", "example-value"))
        .await
        .expect("created")
        .record
        .id;
    for _ in 0..REVEALS_PER_WINDOW {
        env.secrets
            .reveal(&cx, id, RevealRequest::default())
            .await
            .expect("within the limit");
    }
    match env.secrets.reveal(&cx, id, RevealRequest::default()).await {
        Err(OperatorError::RateLimited { retry_after }) => assert!(retry_after >= 1),
        other => panic!("expected the rate limit, got {other:?}"),
    }
    // Another person has a budget of their own.
    env.secrets
        .reveal(&person(), id, RevealRequest::default())
        .await
        .expect("another person");
}

#[tokio::test]
async fn an_imported_credential_reveals_its_password_with_the_login() {
    let env = env();
    let cx = person();
    let host = HostId::generate();
    let mut batch = WriteBatch::for_request(&cx);
    let secret = env
        .vault
        .stage_put(
            &mut batch,
            &cx,
            SecretClass::Operator,
            spec("import.host_credential").owned_by(ObjectRef::from(host)),
            &value(r#"{"login":"admin","password":"example-gw-pass"}"#),
        )
        .expect("staged");
    stage_record(
        &mut batch,
        &imported_record(secret.secret, "gateway", Some("admin"), cx.now),
    )
    .expect("record");
    env.vault.mem_store().propose(batch).await.expect("stored");
    let revealed = env
        .secrets
        .reveal(&cx, secret.secret, RevealRequest::default())
        .await
        .expect("revealed");
    assert_eq!(revealed.value.as_str(), "example-gw-pass");
    assert_eq!(revealed.username.as_deref(), Some("admin"));
    let record = env.secrets.get(secret.secret).await.expect("secret").record;
    assert_eq!(record.origin, SecretOrigin::Import);
    assert_eq!(record.format, ValueFormat::LoginPassword);

    // A new value is the value itself.
    env.secrets
        .update(
            &cx,
            secret.secret,
            OperatorSecretPatch {
                value: Some(value("example-new-pass")),
                ..OperatorSecretPatch::default()
            },
            None,
        )
        .await
        .expect("replaced");
    let revealed = env
        .secrets
        .reveal(&cx, secret.secret, RevealRequest::default())
        .await
        .expect("revealed");
    assert_eq!(revealed.value.as_str(), "example-new-pass");
    assert_eq!(revealed.username.as_deref(), Some("admin"));
}

#[tokio::test]
async fn secrets_stored_before_the_model_are_adopted_once() {
    let env = env();
    let cx = ctx();
    let host = HostId::generate();
    let imported = env
        .vault
        .put_operator(
            &cx,
            spec("import.host_credential")
                .owned_by(ObjectRef::from(host))
                .labelled("Login and password of nas01"),
            value(r#"{"login":"admin","password":"example-pass"}"#),
        )
        .await
        .expect("an imported credential");
    let other = env
        .vault
        .put_operator(&cx, spec("connect.test"), value("example-token"))
        .await
        .expect("another operator secret");
    env.vault
        .put_system(&cx, spec("auth.totp"), value("example-seed"))
        .await
        .expect("a system secret");

    // Before adoption the records are derived.
    let listed = env.secrets.list().await.expect("list");
    assert_eq!(listed.len(), 2, "system secrets are not operator secrets");
    assert!(listed.iter().all(|secret| secret.revision.is_none()));

    assert_eq!(env.secrets.adopt_unmanaged(&cx).await.expect("adopt"), 2);
    assert_eq!(env.secrets.adopt_unmanaged(&cx).await.expect("again"), 0);
    let adopted = env.secrets.get(imported.secret).await.expect("imported");
    assert!(adopted.revision.is_some());
    assert_eq!(adopted.record.name, "Login and password of nas01");
    assert_eq!(adopted.record.format, ValueFormat::LoginPassword);
    assert_eq!(adopted.record.origin, SecretOrigin::Import);
    assert_eq!(adopted.hosts, vec![(host, CredentialRole::Admin)]);
    let plain = env.secrets.get(other.secret).await.expect("other");
    assert_eq!(plain.record.format, ValueFormat::Plain);
    assert_eq!(plain.hosts, Vec::new());
    let store = env.vault.mem_store();
    assert_eq!(
        audit_of(store.as_ref(), "vault.secret.adopt").await.len(),
        1
    );
    let credentials = env.secrets.host_credentials(host).await.expect("host");
    assert_eq!(credentials.items.len(), 1);
    assert_eq!(ObjectKind::Secret.as_str(), "secret");
}
