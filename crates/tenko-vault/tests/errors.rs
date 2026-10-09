//! Stable error codes and HTTP statuses of every `VaultError` variant that the vault can
//! produce, reached through real operations where possible.

mod common;

use std::collections::BTreeSet;

use bytes::Bytes;
use common::{ctx, envelope_of, put_envelope, put_raw, scratch_dir, spec, unique_marker, value};
use tenko_core::{Coded, SecretId, secret::SecretRef, secret::VaultEnvelope};
use tenko_store::{Store, StoreError, WriteBatch};
use tenko_vault::{
    KekConfig, KekInit, MAX_SECRET_LEN, MemVault, SecretBytes, Vault, VaultError, tables,
};

/// Checks code namespace, status and that the problem snapshot agrees.
fn check(error: &VaultError, code: &str, status: u16) {
    assert_eq!(error.code(), code, "{error:?}");
    assert_eq!(error.http_status(), status, "{error:?}");
    assert!(
        code.starts_with("vault.") || code.starts_with("sys.store."),
        "{code} is outside the vault and store namespaces"
    );
    let snapshot = error.to_coded_error();
    assert_eq!(snapshot.code, code);
    assert_eq!(snapshot.status, status);
    assert!(!snapshot.title.is_empty());
    assert!(!snapshot.detail.is_empty(), "detail of {error:?}");
    assert!((400..600).contains(&status), "{status} is an error status");
}

#[tokio::test]
async fn errors_produced_by_vault_operations_are_coded() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("seed"))
        .await
        .expect("system");
    let unknown = SecretRef {
        secret: SecretId::generate(),
    };

    // NotFound: 404, carries the secret as a parameter.
    let error = vault.get_system(&ctx, unknown).await.expect_err("unknown");
    check(&error, "vault.secret.not_found", 404);
    assert_eq!(
        error.params().get("secret").map(String::as_str),
        Some(unknown.secret.to_string().as_str())
    );

    // NotRevealable: 403.
    let error = vault.reveal(&ctx, system).await.expect_err("system secret");
    check(&error, "vault.secret.not_revealable", 403);
    assert_eq!(
        error.params().get("secret").map(String::as_str),
        Some(system.secret.to_string().as_str())
    );

    // TooLarge: 413, carries size and limit.
    let error = vault
        .put_system(
            &ctx,
            spec("auth.totp"),
            SecretBytes::new(vec![0; MAX_SECRET_LEN + 1]),
        )
        .await
        .expect_err("too large");
    check(&error, "vault.secret.too_large", 413);
    let params = error.params();
    assert_eq!(
        params.get("size").map(String::as_str),
        Some((MAX_SECRET_LEN + 1).to_string().as_str())
    );
    assert_eq!(
        params.get("limit").map(String::as_str),
        Some(MAX_SECRET_LEN.to_string().as_str())
    );

    // Integrity: a flipped ciphertext byte.
    let mut tampered = envelope_of(store.as_ref(), system).await;
    let mut payload = tampered.payload.to_vec();
    let last = payload.len() - 1;
    payload[last] ^= 0xFF;
    tampered.payload = Bytes::from(payload);
    let original = envelope_of(store.as_ref(), system).await;
    put_envelope(store.as_ref(), system, &tampered).await;
    let error = vault.get_system(&ctx, system).await.expect_err("tampered");
    check(&error, "vault.envelope.integrity", 500);

    // UnknownKek: the envelope names a KEK that is not loaded.
    let foreign = VaultEnvelope {
        key_id: "mem-9".to_owned(),
        ..original.clone()
    };
    put_envelope(store.as_ref(), system, &foreign).await;
    let error = vault.get_system(&ctx, system).await.expect_err("foreign");
    check(&error, "vault.kek.unknown", 500);
    assert_eq!(
        error.params().get("key_id").map(String::as_str),
        Some("mem-9")
    );

    // UnsupportedFormat.
    let future = VaultEnvelope {
        format: 7,
        ..original.clone()
    };
    put_envelope(store.as_ref(), system, &future).await;
    let error = vault.get_system(&ctx, system).await.expect_err("format");
    check(&error, "vault.envelope.unsupported_format", 500);
    assert_eq!(error.params().get("format").map(String::as_str), Some("7"));

    // Malformed.
    let short = VaultEnvelope {
        payload: Bytes::from_static(&[1, 0]),
        ..original
    };
    put_envelope(store.as_ref(), system, &short).await;
    let error = vault.get_system(&ctx, system).await.expect_err("malformed");
    check(&error, "vault.envelope.malformed", 500);

    // Store(PlaintextSecret): the store's own code, reached through a vault error.
    let error = VaultError::from(
        put_raw(store.as_ref(), system, b"plaintext".to_vec())
            .await
            .expect_err("plaintext"),
    );
    check(&error, "sys.store.plaintext_secret", 500);
    assert!(error.params().contains_key("table"));

    // Store(Codec): an envelope marker with undecodable CBOR behind it.
    let mut garbage = tenko_core::secret::VAULT_ENVELOPE_MARKER.to_vec();
    garbage.extend_from_slice(&[0xFF, 0xFF]);
    put_raw(store.as_ref(), system, garbage)
        .await
        .expect("marker");
    let error = vault.get_system(&ctx, system).await.expect_err("codec");
    check(&error, "sys.store.codec", 500);
}

#[tokio::test]
async fn a_failed_precondition_surfaces_as_a_conflict() {
    let vault = MemVault::new();
    let store = vault.mem_store();
    let ctx = ctx();
    let mut batch = WriteBatch::for_request(&ctx);
    vault
        .stage_put(
            &mut batch,
            &ctx,
            tenko_core::secret::SecretClass::System,
            spec("auth.totp"),
            &value("seed"),
        )
        .expect("stage");
    // The same row key as an existing secret would also fail; use a stale revision.
    batch.expect_version(
        tables::SECRETS.clone(),
        vec![0xEE],
        Some(tenko_core::Revision(99)),
    );
    let store_error = store.propose(batch).await.expect_err("conflict");
    assert!(matches!(store_error, StoreError::PreconditionFailed(_)));
    let error = VaultError::from(store_error);
    check(&error, "sys.store.precondition_failed", 409);
}

#[test]
fn provider_failures_are_coded() {
    let dir = scratch_dir("coded-errors");
    let missing = KekConfig::File {
        path: dir.join("absent.key"),
        retired: Vec::new(),
    };
    let error = missing.load(KekInit::Require).expect_err("missing");
    check(&error, "vault.kek.unavailable", 500);
    assert!(
        error.params().is_empty(),
        "no path or key material in params"
    );

    let error = missing
        .create_next()
        .expect_err("file KEKs cannot rotate in place");
    check(&error, "vault.unsupported", 501);
}

#[test]
fn variants_that_only_a_provider_can_raise_are_coded_too() {
    let crypto = VaultError::Crypto {
        operation: "encrypt secret",
    };
    check(&crypto, "vault.crypto", 500);

    let provider = VaultError::Provider {
        provider: "dpapi",
        reason: "access denied".to_owned(),
    };
    check(&provider, "vault.kek.provider", 500);
    assert_eq!(
        provider.params().get("provider").map(String::as_str),
        Some("dpapi")
    );

    for (store_error, code, status) in [
        (StoreError::NoQuorum, "sys.store.no_quorum", 503),
        (StoreError::Timeout, "sys.store.timeout", 503),
        (StoreError::ShuttingDown, "sys.store.shutting_down", 503),
        (
            StoreError::Storage("disk".to_owned()),
            "sys.store.storage",
            500,
        ),
    ] {
        check(&VaultError::from(store_error), code, status);
    }
}

#[tokio::test]
async fn codes_are_distinct_per_variant_and_params_never_hold_values() {
    let marker = unique_marker();
    let vault = MemVault::new();
    let ctx = ctx();
    let system = vault
        .put_system(&ctx, spec("auth.totp"), value(&format!("{marker}-seed")))
        .await
        .expect("system");

    let mut errors: Vec<VaultError> = vec![
        vault
            .reveal(&ctx, system)
            .await
            .expect_err("not revealable"),
        vault
            .get_system(
                &ctx,
                SecretRef {
                    secret: SecretId::generate(),
                },
            )
            .await
            .expect_err("not found"),
        vault
            .put_system(
                &ctx,
                spec("auth.totp"),
                SecretBytes::new([marker.as_bytes(), &vec![b'x'; MAX_SECRET_LEN]].concat()),
            )
            .await
            .expect_err("too large"),
        VaultError::Integrity,
        VaultError::UnknownKek {
            key_id: "mem-9".to_owned(),
        },
        VaultError::UnsupportedFormat { format: 2 },
        VaultError::Malformed { what: "envelope" },
        VaultError::Crypto { operation: "x" },
        VaultError::Provider {
            provider: "file",
            reason: "x".to_owned(),
        },
        VaultError::Unsupported {
            what: "x".to_owned(),
        },
        VaultError::RotationInProgress,
        VaultError::KekUnavailable {
            reason: "x".to_owned(),
        },
    ];
    errors.push(VaultError::from(StoreError::NoQuorum));

    let codes: BTreeSet<&str> = errors.iter().map(Coded::code).collect();
    assert_eq!(codes.len(), errors.len(), "one code per variant: {codes:?}");
    for error in &errors {
        let snapshot = error.to_coded_error();
        let rendered = format!(
            "{error} | {error:?} | {} | {:?} | {:?}",
            snapshot.detail, snapshot.params, snapshot.title
        );
        assert!(!rendered.contains(&marker), "{rendered}");
        assert!(!rendered.contains("seed"), "{rendered}");
    }
}
