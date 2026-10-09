//! Best-effort hygiene for secret material: types that zeroize on drop, buffers that clear
//! on request, and `Debug` output that never carries values or key bytes.

mod common;

use std::sync::Arc;

use common::{contains, ctx, envelope_of, spec, unique_marker, value};
use tenko_core::{
    SecretId,
    secret::{SecretClass, SecretRef},
};
use tenko_vault::{
    DataKey, KekProvider, KekRing, MemKek, MemVault, SecretBytes, StoreVault, Vault, VaultError,
    envelope::{self, RowBinding},
    tables,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// A key whose bytes are all different, so that no repeated-byte pattern hides a leak.
fn patterned_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    for (slot, step) in key.iter_mut().zip(0u8..) {
        *slot = step.wrapping_mul(37).wrapping_add(0x91);
    }
    key
}

/// Text renderings of `bytes` that a careless `Debug` might produce.
fn renderings(bytes: &[u8]) -> Vec<String> {
    let hex = tenko_core::serde_util::to_hex(bytes);
    let decimal: Vec<String> = bytes.iter().map(u8::to_string).collect();
    vec![
        hex.clone(),
        hex.to_uppercase(),
        hex[..16].to_owned(),
        hex[..16].to_uppercase(),
        format!("{bytes:?}"),
        decimal[..6].join(", "),
        decimal[..6].join(" "),
        decimal[..6].join(","),
        String::from_utf8_lossy(bytes).into_owned(),
    ]
}

#[test]
fn secret_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<SecretBytes>();
    assert_zeroize_on_drop::<DataKey>();
    assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
}

#[test]
fn into_zeroizing_then_zeroize_clears_the_buffer() {
    let secret = SecretBytes::from(b"TENKO-ZEROIZE-ME-0123456789".to_vec());
    let mut buffer = secret.into_zeroizing();
    assert_eq!(buffer.as_slice(), b"TENKO-ZEROIZE-ME-0123456789");

    buffer.zeroize();

    assert!(
        buffer.is_empty() || buffer.iter().all(|byte| *byte == 0),
        "the buffer still holds {} non-zero bytes",
        buffer.iter().filter(|byte| **byte != 0).count()
    );
    assert!(!contains(&buffer, b"ZEROIZE"));
}

#[test]
fn zeroizing_buffers_round_trip_into_secret_bytes_without_copying_the_value_out() {
    let buffer = Zeroizing::new(b"round-trip".to_vec());
    let secret = SecretBytes::from(buffer);
    assert_eq!(secret.expose(), b"round-trip");
    assert_eq!(secret.len(), 10);
    assert!(!secret.is_empty());
    let cloned = secret.clone();
    assert_eq!(cloned, secret);
    drop(secret);
    assert_eq!(cloned.expose(), b"round-trip");
    assert!(SecretBytes::default().is_empty());
}

#[test]
fn secret_bytes_debug_prints_only_the_length() {
    let marker = unique_marker();
    let secret = SecretBytes::from(marker.clone().into_bytes());
    let printed = format!("{secret:?}");
    assert!(!printed.contains(&marker));
    assert!(!printed.contains("TENKO"));
    assert!(printed.contains(&marker.len().to_string()), "{printed}");
    for rendering in renderings(marker.as_bytes()) {
        assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
    }
    // The alternate form is no different.
    assert!(!format!("{secret:#?}").contains(&marker));
}

#[test]
fn data_key_debug_is_redacted() {
    let key = DataKey::from_bytes(patterned_key());
    for printed in [format!("{key:?}"), format!("{key:#?}")] {
        assert!(printed.contains("redacted"), "{printed}");
        for rendering in renderings(key.as_bytes()) {
            assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
        }
    }
}

#[test]
fn mem_kek_debug_never_prints_key_bytes() {
    let key = patterned_key();
    let kek = MemKek::from_bytes("mem-debug", &key);
    for printed in [format!("{kek:?}"), format!("{kek:#?}")] {
        assert!(
            printed.contains("mem-debug"),
            "the identifier is public: {printed}"
        );
        for rendering in renderings(key.as_ref()) {
            assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
        }
    }
    // The same through a ring, which is what StoreVault prints.
    let ring = KekRing::new(Arc::new(MemKek::from_bytes("mem-ring", &key)))
        .with_retired(Arc::new(MemKek::from_bytes("mem-old", &key)));
    let printed = format!("{ring:?}");
    for rendering in renderings(key.as_ref()) {
        assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
    }
}

#[tokio::test]
async fn store_vault_and_mem_vault_debug_never_print_values_or_keys() {
    let marker = unique_marker();
    let key = patterned_key();
    let store = common::mem_store();
    let ring = KekRing::new(Arc::new(MemKek::from_bytes("mem-1", &key)));
    let vault = MemVault::with_ring(Arc::clone(&store), ring);
    let ctx = ctx();
    vault
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
    // A revealed value lives in a SecretBytes: printing it must not leak it either.
    let revealed = vault.reveal(&ctx, operator).await.expect("reveal");

    let opened = StoreVault::open(
        Arc::clone(&store) as Arc<dyn tenko_store::Store>,
        KekRing::new(Arc::new(MemKek::from_bytes("mem-1", &key))),
    )
    .await
    .expect("open");

    for printed in [
        format!("{vault:?}"),
        format!("{vault:#?}"),
        format!("{opened:?}"),
        format!("{:?}", vault.ring()),
        format!("{revealed:?}"),
        format!("{:?}", vault.list().await.expect("list")),
        format!("{:?}", vault.meta(operator).await.expect("meta")),
    ] {
        assert!(!printed.contains(&marker), "{printed}");
        for rendering in renderings(key.as_ref()) {
            assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
        }
    }
    assert!(format!("{opened:?}").contains("StoreVault"));
}

#[tokio::test]
async fn opened_envelopes_and_vault_errors_never_print_values() {
    let marker = unique_marker();
    let vault = MemVault::new();
    let ctx = ctx();
    let secret = vault
        .put_operator(
            &ctx,
            spec("connect.proxmox_token"),
            value(&format!("{marker}-value")),
        )
        .await
        .expect("put");

    // The decrypted form returned by the envelope layer prints redacted.
    let envelope = envelope_of(vault.mem_store().as_ref(), secret).await;
    let key = tenko_core::codec::encode_key(&secret.secret);
    let opened = envelope::open(
        &vault.ring(),
        RowBinding {
            table: &tables::SECRETS,
            key: &key,
        },
        &envelope,
    )
    .expect("open");
    assert_eq!(opened.class, SecretClass::Operator);
    assert!(!format!("{opened:?}").contains(&marker));
    assert_eq!(opened.value.expose().len(), marker.len() + "-value".len());

    // Errors caused by operations on this secret name the secret id, never its value.
    let wrong_row = SecretId::generate();
    let wrong_key = tenko_core::codec::encode_key(&wrong_row);
    let integrity = envelope::open(
        &vault.ring(),
        RowBinding {
            table: &tables::SECRETS,
            key: &wrong_key,
        },
        &envelope,
    )
    .expect_err("moved envelope");
    let mut errors = vec![
        integrity,
        vault
            .replace(
                &ctx,
                SecretRef { secret: wrong_row },
                value(&format!("{marker}-other")),
            )
            .await
            .expect_err("unknown"),
        vault
            .put_system(
                &ctx,
                spec("auth.totp"),
                SecretBytes::new([marker.as_bytes(), &vec![b'z'; 70_000]].concat()),
            )
            .await
            .expect_err("too large"),
    ];
    errors.push(VaultError::NotRevealable {
        secret: secret.secret,
    });
    for error in &errors {
        for printed in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!printed.contains(&marker), "{printed}");
            assert!(!printed.contains("zzzz"), "{printed}");
        }
    }
}

#[test]
fn kek_provider_trait_objects_print_without_key_material() {
    let key = patterned_key();
    let kek: Arc<dyn KekProvider> = Arc::new(MemKek::from_bytes("mem-dyn", &key));
    let printed = format!("{kek:?}");
    for rendering in renderings(key.as_ref()) {
        assert!(!printed.contains(&rendering), "{printed} leaks {rendering}");
    }
}
