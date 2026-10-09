//! Behaviour of the vault over `MemStore`: round trips, reveal and its audit trail,
//! operator-secret tracking, replacement and DEK rotation, atomic staging into the
//! caller's batch, and tamper detection on the stored envelopes.

mod common;

use std::net::IpAddr;

use bytes::Bytes;
use common::{
    assert_none, audit_for, audit_of, audit_records, contains, ctx, ctx_at, envelope_of,
    is_success, object, put_envelope, put_raw, revision, spec, stored, stored_row, unique_marker,
    value, view,
};
use tenko_core::{
    Coded, ObjectRef, Revision, SecretId, TableName, UserId,
    audit::AuditOutcome,
    codec::{encode_key, to_cbor},
    secret::{SecretClass, SecretRef, VAULT_ENVELOPE_MARKER, VaultEnvelope},
};
use tenko_store::{ReadViewExt, Store, StoreError, WriteBatch};
use tenko_vault::{
    MAX_SECRET_LEN, MemVault, SecretBytes, SecretMeta, SecretPurpose, Vault, VaultError, envelope,
    tables,
};

const CANARY: TableName = TableName::from_static("vault.canary_rows");

fn unknown_ref() -> SecretRef {
    SecretRef {
        secret: SecretId::generate(),
    }
}

// ---------------------------------------------------------------------------------------
// 1. Round trips
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn system_secret_round_trips() {
    let vault = MemVault::new();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("12345678901234567890"))
        .await
        .expect("put_system");
    let back = vault.get_system(&ctx, secret).await.expect("get_system");
    assert_eq!(back.expose(), b"12345678901234567890");
    let info =
        envelope::inspect(&envelope_of(vault.mem_store().as_ref(), secret).await).expect("inspect");
    assert_eq!(info.class, SecretClass::System);
    assert_eq!(info.format, envelope::FORMAT_V1);
    assert_eq!(info.key_id, "mem-1");
    assert_eq!(info.dek_generation, 1);
}

#[tokio::test]
async fn operator_secret_round_trips_through_get_system() {
    let vault = MemVault::new();
    let ctx = ctx();
    let secret = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token"),
            value("root@pam!tenko=abc"),
        )
        .await
        .expect("put_operator");
    let back = vault.get_system(&ctx, secret).await.expect("get_system");
    assert_eq!(back.expose(), b"root@pam!tenko=abc");
    let info =
        envelope::inspect(&envelope_of(vault.mem_store().as_ref(), secret).await).expect("inspect");
    assert_eq!(info.class, SecretClass::Operator);
}

#[tokio::test]
async fn empty_and_binary_values_round_trip() {
    let vault = MemVault::new();
    let ctx = ctx();

    let empty = vault
        .put_system(&ctx, spec("auth.totp"), SecretBytes::new(Vec::new()))
        .await
        .expect("empty value");
    let back = vault.get_system(&ctx, empty).await.expect("get empty");
    assert!(back.is_empty());
    assert_eq!(back.len(), 0);
    // An empty plaintext still occupies a real row: nonce, wrapped key and tag.
    assert!(
        stored_row(vault.mem_store().as_ref(), empty)
            .await
            .value
            .len()
            > 60
    );

    let every_byte: Vec<u8> = (0..=255u8).collect();
    let binary = vault
        .put_operator(
            &ctx,
            spec("cluster.tls_key"),
            SecretBytes::new(every_byte.clone()),
        )
        .await
        .expect("binary value");
    assert_eq!(
        vault.get_system(&ctx, binary).await.expect("get").expose(),
        every_byte.as_slice()
    );
    assert_eq!(
        vault.reveal(&ctx, binary).await.expect("reveal").expose(),
        every_byte.as_slice()
    );
}

#[tokio::test]
async fn largest_value_works_and_one_byte_more_is_too_large() {
    let vault = MemVault::new();
    let ctx = ctx();
    let exact = vec![0xA5; MAX_SECRET_LEN];
    let secret = vault
        .put_system(
            &ctx,
            spec("cluster.ca_key"),
            SecretBytes::new(exact.clone()),
        )
        .await
        .expect("a value of exactly MAX_SECRET_LEN is accepted");
    assert_eq!(
        vault.get_system(&ctx, secret).await.expect("get").expose(),
        exact.as_slice()
    );

    let too_large = VaultError::TooLarge {
        size: MAX_SECRET_LEN + 1,
        limit: MAX_SECRET_LEN,
    };
    let over = || SecretBytes::new(vec![0xA5; MAX_SECRET_LEN + 1]);
    let revision_before = revision(vault.mem_store().as_ref()).await;
    assert_eq!(
        vault
            .put_system(&ctx, spec("cluster.ca_key"), over())
            .await
            .expect_err("system"),
        too_large
    );
    assert_eq!(
        vault
            .put_operator(&ctx, spec("connect.proxmox_token"), over())
            .await
            .expect_err("operator"),
        too_large
    );
    assert_eq!(
        vault
            .replace(&ctx, secret, over())
            .await
            .expect_err("replace"),
        too_large
    );
    // Nothing was written by the refused calls, and the replaced secret is untouched.
    assert_eq!(revision(vault.mem_store().as_ref()).await, revision_before);
    assert_eq!(vault.list().await.expect("list").len(), 1);
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect("still there")
            .len(),
        MAX_SECRET_LEN
    );
}

#[tokio::test]
async fn meta_records_class_purpose_owner_label_and_creation_time() {
    let vault = MemVault::new();
    let owner = ObjectRef::from(UserId::generate());
    let ctx = ctx_at("2026-10-09T08:30:15Z");

    let operator = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token")
                .owned_by(owner)
                .labelled("Proxmox cluster A"),
            value("token"),
        )
        .await
        .expect("put_operator");
    assert_eq!(
        vault.meta(operator).await.expect("meta"),
        Some(SecretMeta {
            id: operator.secret,
            class: SecretClass::Operator,
            purpose: SecretPurpose::from_static("connect.proxmox_token"),
            owner: Some(owner),
            label: Some("Proxmox cluster A".to_owned()),
            created_at: ctx.now,
            updated_at: ctx.now,
        })
    );

    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put_system");
    let meta = vault.meta(system).await.expect("meta").expect("present");
    assert_eq!(meta.class, SecretClass::System);
    assert_eq!(meta.purpose, SecretPurpose::from_static("auth.totp"));
    assert_eq!(meta.owner, None);
    assert_eq!(meta.label, None);
    assert_eq!(meta.created_at, ctx.now);
    assert_eq!(meta.updated_at, ctx.now);
}

#[tokio::test]
async fn creating_a_secret_writes_an_audit_record_that_names_the_secret() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let owner = ObjectRef::from(UserId::generate());
    let ctx = ctx();
    let secret = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token").owned_by(owner),
            value("token"),
        )
        .await
        .expect("put_operator");

    let records = audit_for(store.as_ref(), "vault.secret.create", secret).await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert!(is_success(record));
    assert_eq!(record.principal, ctx.principal);
    assert_eq!(record.request, Some(ctx.request));
    assert_eq!(record.at, ctx.now);
    assert_eq!(record.draft.objects, vec![object(secret), owner]);
    let context = &record.draft.details.context;
    assert_eq!(context.get("class").map(String::as_str), Some("operator"));
    assert_eq!(
        context.get("purpose").map(String::as_str),
        Some("connect.proxmox_token")
    );
    assert_eq!(context.get("kek").map(String::as_str), Some("mem-1"));
}

#[tokio::test]
async fn unknown_secret_is_not_found() {
    let vault = MemVault::new();
    let ctx = ctx();
    let unknown = unknown_ref();
    let error = vault
        .get_system(&ctx, unknown)
        .await
        .expect_err("unknown secret");
    assert_eq!(
        error,
        VaultError::NotFound {
            secret: unknown.secret
        }
    );
    assert_eq!(error.code(), "vault.secret.not_found");
    assert_eq!(error.http_status(), 404);
    assert_eq!(vault.meta(unknown).await.expect("meta"), None);
    assert!(stored(vault.mem_store().as_ref(), unknown).await.is_none());
}

#[tokio::test]
async fn list_returns_metadata_of_every_secret_in_identifier_order() {
    let vault = MemVault::new();
    let ctx = ctx();
    assert_none(&vault.list().await.expect("empty list"), "metadata");

    let mut created = Vec::new();
    for index in 0..6 {
        let secret = if index % 2 == 0 {
            vault.put_system(&ctx, spec("auth.totp"), value("v")).await
        } else {
            vault
                .put_operator(&ctx, spec("connect.proxmox_token"), value("v"))
                .await
        }
        .expect("put");
        created.push(secret.secret);
    }
    let listed = vault.list().await.expect("list");
    let ids: Vec<SecretId> = listed.iter().map(|meta| meta.id).collect();
    let mut sorted = created.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "metadata is listed in identifier order");
    let operators = listed
        .iter()
        .filter(|meta| meta.class == SecretClass::Operator)
        .count();
    assert_eq!(operators, 3);
}

// ---------------------------------------------------------------------------------------
// 2. Reveal (IAM-16)
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn operator_secret_reveals_and_the_reveal_is_audited() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ip: IpAddr = "192.0.2.7".parse().expect("ip");
    let ctx = ctx().with_source_ip(ip);
    let secret = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("hunter2"))
        .await
        .expect("put_operator");
    assert_none(
        &audit_of(store.as_ref(), "vault.secret.reveal").await,
        "reveal records",
    );

    let revealed = vault.reveal(&ctx, secret).await.expect("reveal");
    assert_eq!(revealed.expose(), b"hunter2");

    let records = audit_for(store.as_ref(), "vault.secret.reveal", secret).await;
    assert_eq!(records.len(), 1, "exactly one reveal record");
    let record = &records[0];
    assert_eq!(record.draft.outcome, AuditOutcome::Success);
    assert_eq!(record.principal, ctx.principal);
    assert_eq!(record.request, Some(ctx.request));
    assert_eq!(record.draft.source_ip, Some(ip));
    assert_eq!(
        record
            .draft
            .details
            .context
            .get("class")
            .map(String::as_str),
        Some("operator")
    );

    // Every further reveal is another record.
    vault.reveal(&ctx, secret).await.expect("second reveal");
    assert_eq!(
        audit_for(store.as_ref(), "vault.secret.reveal", secret)
            .await
            .len(),
        2
    );
}

#[tokio::test]
async fn system_secret_is_refused_and_the_refusal_is_audited() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("seed-value"))
        .await
        .expect("put_system");

    let error = vault.reveal(&ctx, secret).await.expect_err("system secret");
    assert_eq!(
        error,
        VaultError::NotRevealable {
            secret: secret.secret
        }
    );
    assert_eq!(error.code(), "vault.secret.not_revealable");
    assert_eq!(error.http_status(), 403);

    let records = audit_for(store.as_ref(), "vault.secret.reveal", secret).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].draft.outcome, AuditOutcome::Denied);
    assert_eq!(records[0].principal, ctx.principal);

    // The secret is untouched and still usable by Tenko itself.
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect("still usable")
            .expose(),
        b"seed-value"
    );
}

#[tokio::test]
async fn revealing_an_unknown_secret_is_not_found() {
    let vault = MemVault::new();
    let unknown = unknown_ref();
    assert_eq!(
        vault.reveal(&ctx(), unknown).await.expect_err("unknown"),
        VaultError::NotFound {
            secret: unknown.secret
        }
    );
    // The failed attempt is audited too (IAM-16), with the error code as the outcome.
    let records = audit_of(vault.mem_store().as_ref(), "vault.secret.reveal").await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        records[0].draft.outcome,
        tenko_core::audit::AuditOutcome::Failed {
            code: "vault.secret.not_found".into()
        }
    );
}

#[tokio::test]
async fn get_system_leaves_no_audit_record() {
    let vault = MemVault::new();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put_system");
    let before = audit_records(vault.mem_store().as_ref()).await.len();
    for _ in 0..3 {
        vault.get_system(&ctx, secret).await.expect("get_system");
    }
    assert_eq!(
        audit_records(vault.mem_store().as_ref()).await.len(),
        before
    );
}

#[tokio::test]
async fn no_audit_record_contains_a_secret_value() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let marker = unique_marker();

    let system = vault
        .put_system(&ctx, spec("auth.totp"), value(&format!("{marker}-system")))
        .await
        .expect("system");
    let operator = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token").labelled("proxmox"),
            value(&format!("{marker}-operator")),
        )
        .await
        .expect("operator");
    vault.reveal(&ctx, operator).await.expect("reveal");
    vault.reveal(&ctx, system).await.expect_err("refused");
    vault
        .replace(&ctx, operator, value(&format!("{marker}-replaced")))
        .await
        .expect("replace");
    vault.rotate_dek(&ctx, system).await.expect("rotate_dek");
    vault.delete(&ctx, operator).await.expect("delete");
    let too_large = SecretBytes::new([marker.as_bytes(), &vec![b'x'; MAX_SECRET_LEN]].concat());
    vault
        .put_system(&ctx, spec("auth.totp"), too_large)
        .await
        .expect_err("too large");

    let records = audit_records(store.as_ref()).await;
    // create x2, reveal (ok), reveal (denied), replace, rotate_dek, delete.
    assert_eq!(records.len(), 7);
    for record in &records {
        let encoded = to_cbor(record).expect("cbor");
        let json = serde_json::to_string(record).expect("json");
        let debug = format!("{record:?}");
        assert!(!contains(&encoded, marker.as_bytes()), "CBOR of {record:?}");
        assert!(!json.contains(&marker), "JSON of {record:?}");
        assert!(!debug.contains(&marker), "Debug of {record:?}");
    }
}

// ---------------------------------------------------------------------------------------
// 3. Operator secrets (IAM-07, Q3) and deletion
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn has_operator_secrets_counts_operator_secrets_only() {
    let vault = MemVault::new();
    let ctx = ctx();
    assert!(!vault.has_operator_secrets().await.expect("empty vault"));

    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("system");
    assert!(
        !vault.has_operator_secrets().await.expect("system only"),
        "system secrets do not count"
    );

    let operator = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("token"))
        .await
        .expect("operator");
    assert!(vault.has_operator_secrets().await.expect("operator"));

    vault.delete(&ctx, operator).await.expect("delete");
    assert!(
        !vault.has_operator_secrets().await.expect("after delete"),
        "false again after the only operator secret is deleted"
    );
    // The system secret is still there and still does not count.
    vault
        .get_system(&ctx, system)
        .await
        .expect("system survives");
}

#[tokio::test]
async fn has_operator_secrets_stays_true_while_any_operator_secret_remains() {
    let vault = MemVault::new();
    let ctx = ctx();
    let first = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("a"))
        .await
        .expect("first");
    let second = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("b"))
        .await
        .expect("second");
    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("c"))
        .await
        .expect("system");

    vault.delete(&ctx, system).await.expect("delete system");
    assert!(vault.has_operator_secrets().await.expect("two left"));
    vault.delete(&ctx, first).await.expect("delete first");
    assert!(vault.has_operator_secrets().await.expect("one left"));
    // Replacing and rotating do not change the class bookkeeping.
    vault
        .replace(&ctx, second, value("b2"))
        .await
        .expect("replace");
    vault.rotate_dek(&ctx, second).await.expect("rotate");
    assert!(vault.has_operator_secrets().await.expect("still one"));
    vault.delete(&ctx, second).await.expect("delete second");
    assert!(!vault.has_operator_secrets().await.expect("none left"));
}

#[tokio::test]
async fn deleting_an_absent_secret_is_ok_and_writes_nothing() {
    let vault = MemVault::new();
    let ctx = ctx();
    let kept = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put");
    let unknown = unknown_ref();
    let records_before = audit_records(vault.mem_store().as_ref()).await.len();

    vault.delete(&ctx, unknown).await.expect("absent delete");
    vault
        .delete(&ctx, unknown)
        .await
        .expect("absent delete again");

    assert_eq!(
        audit_records(vault.mem_store().as_ref()).await.len(),
        records_before
    );
    vault
        .get_system(&ctx, kept)
        .await
        .expect("other secret untouched");
}

#[tokio::test]
async fn delete_removes_every_row_and_is_audited() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("token"))
        .await
        .expect("put");
    let id = secret.secret;
    assert!(stored(store.as_ref(), secret).await.is_some());
    assert!(
        view(store.as_ref())
            .await
            .get_typed(&tables::OPERATOR_INDEX, &id)
            .expect("index")
            .is_some()
    );

    vault.delete(&ctx, secret).await.expect("delete");
    vault
        .delete(&ctx, secret)
        .await
        .expect("delete is idempotent");

    assert!(stored(store.as_ref(), secret).await.is_none());
    assert_eq!(vault.meta(secret).await.expect("meta"), None);
    assert!(
        view(store.as_ref())
            .await
            .get_typed(&tables::OPERATOR_INDEX, &id)
            .expect("index")
            .is_none()
    );
    assert_eq!(
        vault.get_system(&ctx, secret).await.expect_err("deleted"),
        VaultError::NotFound { secret: id }
    );
    assert_eq!(
        vault.reveal(&ctx, secret).await.expect_err("deleted"),
        VaultError::NotFound { secret: id }
    );
    let deletes = audit_for(store.as_ref(), "vault.secret.delete", secret).await;
    assert_eq!(deletes.len(), 1, "the no-op delete is not audited");
    assert!(is_success(&deletes[0]));
}

// ---------------------------------------------------------------------------------------
// 4. replace and rotate_dek
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn replace_changes_the_value_and_keeps_the_reference() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let created = ctx_at("2026-10-09T12:00:00Z");
    let later = ctx_at("2026-10-09T13:45:00Z");
    let secret = vault
        .put_operator(
            &created,
            spec("connect.proxmox_token").labelled("proxmox"),
            value("old-value"),
        )
        .await
        .expect("put");
    let before = stored_row(store.as_ref(), secret).await;

    vault
        .replace(&later, secret, value("new-value"))
        .await
        .expect("replace");

    assert_eq!(
        vault
            .get_system(&later, secret)
            .await
            .expect("get")
            .expose(),
        b"new-value"
    );
    assert_eq!(
        vault.reveal(&later, secret).await.expect("reveal").expose(),
        b"new-value"
    );
    let after = stored_row(store.as_ref(), secret).await;
    assert_ne!(after.value, before.value);
    assert!(after.revision > before.revision);
    let info = envelope::inspect(&envelope_of(store.as_ref(), secret).await).expect("inspect");
    assert_eq!(info.class, SecretClass::Operator);
    assert_eq!(info.dek_generation, 2, "a replacement uses a fresh DEK");

    let meta = vault.meta(secret).await.expect("meta").expect("present");
    assert_eq!(meta.id, secret.secret);
    assert_eq!(meta.class, SecretClass::Operator);
    assert_eq!(meta.label.as_deref(), Some("proxmox"));
    assert_eq!(meta.created_at, created.now);
    assert_eq!(meta.updated_at, later.now);
    assert_eq!(vault.list().await.expect("list").len(), 1, "no new secret");
    assert!(vault.has_operator_secrets().await.expect("index kept"));
}

#[tokio::test]
async fn rotate_dek_keeps_the_value_but_changes_the_stored_envelope() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let created = ctx_at("2026-10-09T12:00:00Z");
    let later = ctx_at("2026-10-09T14:00:00Z");
    let secret = vault
        .put_system(&created, spec("cluster.ca_key"), value("keep-me"))
        .await
        .expect("put");

    let mut previous = stored_row(store.as_ref(), secret).await;
    let mut generation = envelope::inspect(&envelope_of(store.as_ref(), secret).await)
        .expect("inspect")
        .dek_generation;
    assert_eq!(generation, 1);
    for _ in 0..3 {
        vault.rotate_dek(&later, secret).await.expect("rotate_dek");
        let current = stored_row(store.as_ref(), secret).await;
        assert_ne!(current.value, previous.value, "stored bytes change");
        assert!(current.revision > previous.revision);
        let info = envelope::inspect(&envelope_of(store.as_ref(), secret).await).expect("inspect");
        assert_eq!(info.dek_generation, generation + 1);
        assert_eq!(info.class, SecretClass::System);
        assert_eq!(info.key_id, "mem-1");
        generation = info.dek_generation;
        previous = current;
        assert_eq!(
            vault
                .get_system(&later, secret)
                .await
                .expect("get")
                .expose(),
            b"keep-me"
        );
    }
    assert_eq!(generation, 4);

    let meta = vault.meta(secret).await.expect("meta").expect("present");
    assert_eq!(meta.created_at, created.now);
    assert_eq!(meta.updated_at, later.now);
}

#[tokio::test]
async fn replace_and_rotate_dek_write_audit_records() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("v1"))
        .await
        .expect("put");

    vault
        .replace(&ctx, secret, value("v2"))
        .await
        .expect("replace");
    vault.rotate_dek(&ctx, secret).await.expect("rotate_dek");

    for action in ["vault.secret.replace", "vault.secret.rotate_dek"] {
        let records = audit_for(store.as_ref(), action, secret).await;
        assert_eq!(records.len(), 1, "{action}");
        let record = &records[0];
        assert!(is_success(record), "{action}");
        assert_eq!(record.principal, ctx.principal);
        let context = &record.draft.details.context;
        assert_eq!(context.get("class").map(String::as_str), Some("operator"));
        assert_eq!(context.get("kek").map(String::as_str), Some("mem-1"));
    }
    // The audit chain is gap-free: create, replace, rotate_dek.
    let seqs: Vec<u64> = audit_records(store.as_ref())
        .await
        .iter()
        .map(|record| record.seq.0)
        .collect();
    assert_eq!(seqs, [1, 2, 3]);
}

#[tokio::test]
async fn replace_and_rotate_dek_reject_unknown_secrets() {
    let vault = MemVault::new();
    let ctx = ctx();
    let unknown = unknown_ref();
    let not_found = VaultError::NotFound {
        secret: unknown.secret,
    };
    assert_eq!(
        vault
            .replace(&ctx, unknown, value("x"))
            .await
            .expect_err("replace"),
        not_found
    );
    assert_eq!(
        vault.rotate_dek(&ctx, unknown).await.expect_err("rotate"),
        not_found
    );
    assert_none(
        &audit_records(vault.mem_store().as_ref()).await,
        "audit records",
    );
}

// ---------------------------------------------------------------------------------------
// 5. stage_put and stage_delete: atomicity with the caller's batch
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn stage_put_with_a_failing_precondition_creates_nothing() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let mut batch = WriteBatch::for_request(&ctx);
    let secret = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::Operator,
            spec("connect.proxmox_token"),
            &value("staged"),
        )
        .expect("stage_put");
    batch.put(CANARY, vec![1], vec![2]);
    batch.expect_version(CANARY, vec![9], Some(Revision(99)));

    // Staging alone writes nothing.
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect_err("not proposed"),
        VaultError::NotFound {
            secret: secret.secret
        }
    );
    let revision_before = revision(store.as_ref()).await;

    let error = store.propose(batch).await.expect_err("precondition fails");
    assert!(
        matches!(error, StoreError::PreconditionFailed(_)),
        "{error:?}"
    );

    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect_err("rolled back"),
        VaultError::NotFound {
            secret: secret.secret
        }
    );
    assert!(stored(store.as_ref(), secret).await.is_none());
    assert_eq!(vault.meta(secret).await.expect("meta"), None);
    assert!(!vault.has_operator_secrets().await.expect("index"));
    assert!(
        view(store.as_ref())
            .await
            .get(&CANARY, &[1])
            .expect("canary")
            .is_none()
    );
    assert_none(&audit_records(store.as_ref()).await, "audit records");
    assert_eq!(revision(store.as_ref()).await, revision_before);
}

#[tokio::test]
async fn stage_put_commits_with_the_callers_own_rows() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let mut batch = WriteBatch::for_request(&ctx);
    let secret = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::System,
            spec("auth.totp"),
            &value("staged-seed"),
        )
        .expect("stage_put");
    batch.put(CANARY, vec![1], vec![2]);
    batch.expect_version(CANARY, vec![1], None);

    let committed = store.propose(batch).await.expect("commit");

    assert_eq!(
        vault.get_system(&ctx, secret).await.expect("get").expose(),
        b"staged-seed"
    );
    assert!(vault.meta(secret).await.expect("meta").is_some());
    let secret_row = stored_row(store.as_ref(), secret).await;
    let canary_row = view(store.as_ref())
        .await
        .get(&CANARY, &[1])
        .expect("canary")
        .expect("caller's row committed");
    assert_eq!(canary_row.value.as_ref(), [2]);
    assert_eq!(secret_row.revision, committed.revision);
    assert_eq!(
        canary_row.revision, committed.revision,
        "one atomic revision"
    );

    let records = audit_for(store.as_ref(), "vault.secret.create", secret).await;
    assert_eq!(records.len(), 1);
    assert_eq!(committed.audit, vec![records[0].seq]);
}

#[tokio::test]
async fn several_secrets_staged_into_one_batch_commit_together() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let mut batch = WriteBatch::for_request(&ctx);
    let system = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::System,
            spec("cluster.ca_key"),
            &value("ca"),
        )
        .expect("system");
    let operator = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::Operator,
            spec("connect.proxmox_token"),
            &value("token"),
        )
        .expect("operator");
    assert_ne!(system, operator);

    let committed = store.propose(batch).await.expect("commit");
    assert_eq!(committed.audit.len(), 2);
    assert_eq!(
        stored_row(store.as_ref(), system).await.revision,
        stored_row(store.as_ref(), operator).await.revision
    );
    assert!(vault.has_operator_secrets().await.expect("operator staged"));
}

#[tokio::test]
async fn stage_put_of_an_oversized_value_leaves_the_batch_untouched() {
    let vault = MemVault::new();
    let ctx = ctx();
    let mut batch = WriteBatch::for_request(&ctx);
    batch.put(CANARY, vec![1], vec![2]);
    let before = batch.clone();

    let error = vault
        .stage_put(
            &mut batch,
            &ctx,
            SecretClass::System,
            spec("auth.totp"),
            &SecretBytes::new(vec![0; MAX_SECRET_LEN + 1]),
        )
        .expect_err("too large");

    assert_eq!(
        error,
        VaultError::TooLarge {
            size: MAX_SECRET_LEN + 1,
            limit: MAX_SECRET_LEN
        }
    );
    assert_eq!(batch, before, "a refused stage adds nothing to the batch");
}

#[tokio::test]
async fn stage_delete_is_atomic_with_the_callers_batch() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("token"))
        .await
        .expect("put");

    // A failing precondition keeps the secret.
    let mut failing = WriteBatch::for_request(&ctx);
    vault.stage_delete(&mut failing, &ctx, secret);
    failing.expect_version(CANARY, vec![9], Some(Revision(99)));
    store
        .propose(failing)
        .await
        .expect_err("precondition fails");
    assert_eq!(
        vault.get_system(&ctx, secret).await.expect("kept").expose(),
        b"token"
    );
    assert!(vault.meta(secret).await.expect("meta").is_some());
    assert!(vault.has_operator_secrets().await.expect("index kept"));
    assert_none(
        &audit_for(store.as_ref(), "vault.secret.delete", secret).await,
        "delete records",
    );

    // A good batch deletes the secret together with the caller's row.
    let mut batch = WriteBatch::for_request(&ctx);
    vault.stage_delete(&mut batch, &ctx, secret);
    batch.put(CANARY, vec![5], vec![6]);
    let committed = store.propose(batch).await.expect("commit");
    assert!(stored(store.as_ref(), secret).await.is_none());
    assert_eq!(vault.meta(secret).await.expect("meta"), None);
    assert!(!vault.has_operator_secrets().await.expect("index gone"));
    let canary = view(store.as_ref())
        .await
        .get(&CANARY, &[5])
        .expect("canary")
        .expect("row");
    assert_eq!(canary.revision, committed.revision);
}

// ---------------------------------------------------------------------------------------
// 6. Tamper detection at store level
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn envelope_copied_into_another_row_fails_authentication() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let a = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("secret-a"))
        .await
        .expect("a");
    let b = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("secret-b"))
        .await
        .expect("b");
    let c = vault
        .put_system(&ctx, spec("auth.totp"), value("secret-c"))
        .await
        .expect("c");

    // Direct store write: the bytes of A under the key of B.
    let bytes_of_a = stored_row(store.as_ref(), a).await.value;
    let mut batch = WriteBatch::for_request(&ctx);
    batch.put(
        tables::SECRETS.clone(),
        encode_key(&b.secret),
        bytes_of_a.clone(),
    );
    store
        .propose(batch)
        .await
        .expect("the store accepts an envelope");

    assert_eq!(
        vault.get_system(&ctx, b).await.expect_err("moved envelope"),
        VaultError::Integrity
    );
    assert_eq!(
        vault.reveal(&ctx, b).await.expect_err("moved envelope"),
        VaultError::Integrity
    );
    assert_eq!(
        vault.rotate_dek(&ctx, b).await.expect_err("moved envelope"),
        VaultError::Integrity
    );
    assert_eq!(
        vault
            .replace(&ctx, b, value("x"))
            .await
            .expect_err("moved envelope"),
        VaultError::Integrity
    );
    // A itself is fine, and so is every other secret.
    assert_eq!(
        vault.get_system(&ctx, a).await.expect("a").expose(),
        b"secret-a"
    );
    assert_eq!(
        vault.get_system(&ctx, c).await.expect("c").expose(),
        b"secret-c"
    );

    // A system envelope moved under the key of an operator secret fails the same way.
    let bytes_of_c = stored_row(store.as_ref(), c).await.value;
    put_raw(store.as_ref(), a, bytes_of_c).await.expect("put");
    assert_eq!(
        vault.get_system(&ctx, a).await.expect_err("moved"),
        VaultError::Integrity
    );
}

#[tokio::test]
async fn flipping_any_byte_of_a_stored_envelope_is_detected() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("tamper-me"))
        .await
        .expect("put");
    let original = stored_row(store.as_ref(), secret).await.value;
    let envelope = VaultEnvelope::from_bytes(&original).expect("decode");
    let wrapped_len = usize::from(u16::from_be_bytes([
        envelope.payload[5],
        envelope.payload[6],
    ]));
    let nonce_at = 7 + wrapped_len;
    let ciphertext_at = nonce_at + 12;
    assert_eq!(
        envelope.payload.len(),
        ciphertext_at + "tamper-me".len() + 16
    );

    for index in 0..envelope.payload.len() {
        let mut payload = envelope.payload.to_vec();
        payload[index] ^= 0x01;
        let tampered = VaultEnvelope {
            payload: Bytes::from(payload),
            ..envelope.clone()
        };
        put_envelope(store.as_ref(), secret, &tampered).await;
        let error = vault
            .get_system(&ctx, secret)
            .await
            .expect_err(&format!("payload byte {index} went unnoticed"));
        // Everything past the plain header is authenticated; the header itself is either
        // authenticated (generation) or structurally checked (class, wrapped-key length).
        if index >= 1 && !(5..7).contains(&index) {
            assert_eq!(error, VaultError::Integrity, "payload byte {index}");
        }
    }

    // The positions that matter, by name: wrapped DEK, nonce, ciphertext and the tag.
    for (name, index) in [
        ("generation", 4),
        ("wrapped DEK", 7 + 5),
        ("data nonce", nonce_at + 3),
        ("ciphertext", ciphertext_at),
        ("tag", envelope.payload.len() - 1),
    ] {
        let mut payload = envelope.payload.to_vec();
        payload[index] ^= 0x80;
        let tampered = VaultEnvelope {
            payload: Bytes::from(payload),
            ..envelope.clone()
        };
        put_envelope(store.as_ref(), secret, &tampered).await;
        assert_eq!(
            vault.reveal(&ctx, secret).await.expect_err(name),
            VaultError::Integrity,
            "{name}"
        );
    }

    // Restoring the original bytes makes the secret readable again.
    put_raw(store.as_ref(), secret, original)
        .await
        .expect("restore");
    assert_eq!(
        vault.reveal(&ctx, secret).await.expect("restored").expose(),
        b"tamper-me"
    );
}

#[tokio::test]
async fn relabelling_a_system_secret_as_operator_does_not_make_it_revealable() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("never-shown"))
        .await
        .expect("put");
    let mut envelope = envelope_of(store.as_ref(), secret).await;
    let mut payload = envelope.payload.to_vec();
    assert_eq!(payload[0], 1, "system class code");
    payload[0] = 2;
    envelope.payload = Bytes::from(payload);
    put_envelope(store.as_ref(), secret, &envelope).await;

    assert_eq!(
        vault.reveal(&ctx, secret).await.expect_err("relabelled"),
        VaultError::Integrity
    );
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect_err("relabelled"),
        VaultError::Integrity
    );
}

#[tokio::test]
async fn envelopes_naming_an_unknown_kek_or_a_newer_format_are_reported() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put");
    let original = envelope_of(store.as_ref(), secret).await;

    let foreign = VaultEnvelope {
        key_id: "mem-9".to_owned(),
        ..original.clone()
    };
    put_envelope(store.as_ref(), secret, &foreign).await;
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect_err("unknown KEK"),
        VaultError::UnknownKek {
            key_id: "mem-9".to_owned()
        }
    );

    let future = VaultEnvelope {
        format: 2,
        ..original.clone()
    };
    put_envelope(store.as_ref(), secret, &future).await;
    assert_eq!(
        vault.get_system(&ctx, secret).await.expect_err("format"),
        VaultError::UnsupportedFormat { format: 2 }
    );

    // A renamed KEK that is loaded but did not wrap this key fails authentication.
    put_envelope(store.as_ref(), secret, &original).await;
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect("restored")
            .expose(),
        b"seed"
    );
}

#[tokio::test]
async fn malformed_envelopes_are_errors_not_panics() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put");

    for payload in [
        Bytes::new(),
        Bytes::from_static(&[1]),
        Bytes::from_static(&[1, 0, 0, 0, 1, 0xFF, 0xFF]),
        Bytes::from_static(&[9, 0, 0, 0, 1, 0, 0]),
        Bytes::from(vec![1; 40]),
    ] {
        let envelope = VaultEnvelope {
            format: 1,
            key_id: "mem-1".to_owned(),
            payload,
        };
        put_envelope(store.as_ref(), secret, &envelope).await;
        let error = vault
            .get_system(&ctx, secret)
            .await
            .expect_err("malformed envelope");
        assert!(
            matches!(error, VaultError::Malformed { .. } | VaultError::Integrity),
            "{error:?}"
        );
    }

    // The marker without a decodable CBOR envelope behind it passes the store's marker
    // check but surfaces as a coded store error from the vault.
    let mut garbage = VAULT_ENVELOPE_MARKER.to_vec();
    garbage.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    put_raw(store.as_ref(), secret, garbage)
        .await
        .expect("marker only");
    let error = vault
        .get_system(&ctx, secret)
        .await
        .expect_err("undecodable envelope");
    assert!(
        matches!(error, VaultError::Store(StoreError::Codec(_))),
        "{error:?}"
    );
    assert_eq!(error.code(), "sys.store.codec");
}

#[tokio::test]
async fn the_store_refuses_plaintext_in_the_secrets_table() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let secret = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("put");

    for plaintext in [
        b"hunter2".to_vec(),
        Vec::new(),
        to_cbor(&"hunter2").expect("cbor").to_vec(),
        // Almost the marker, but not quite.
        VAULT_ENVELOPE_MARKER[..4].to_vec(),
    ] {
        let error = put_raw(store.as_ref(), secret, plaintext)
            .await
            .expect_err("plaintext");
        assert!(
            matches!(&error, StoreError::PlaintextSecret { table } if table.as_str() == "vault.secrets"),
            "{error:?}"
        );
        assert_eq!(error.code(), "sys.store.plaintext_secret");
    }

    // The same rule covers every secret-bearing table, not only the vault's.
    let mut batch = WriteBatch::for_request(&ctx);
    batch.put(
        TableName::from_static("auth.totp_secrets"),
        vec![1],
        b"JBSWY3DPEHPK3PXP".to_vec(),
    );
    let error = store.propose(batch).await.expect_err("plaintext");
    assert!(
        matches!(error, StoreError::PlaintextSecret { .. }),
        "{error:?}"
    );

    // The refused writes changed nothing.
    assert_eq!(
        vault
            .get_system(&ctx, secret)
            .await
            .expect("intact")
            .expose(),
        b"seed"
    );
}
