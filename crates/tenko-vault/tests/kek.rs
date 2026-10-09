//! Key-encryption-key lifecycle: rotation, start-up refusal without the right KEK, and the
//! explicit key-file provider including a full restart.

mod common;

use std::{fs, sync::Arc};

use common::{
    audit_of, cleanup, ctx, envelope_of, mem_store, scan_all, scratch_dir, spec, value, view,
};
use tenko_core::{
    Coded,
    secret::{SecretClass, SecretRef, VaultEnvelope},
};
use tenko_store::{MemStore, Store};
use tenko_vault::{
    KekConfig, KekInit, KekProtection, KekProvider, KekRing, KekRotation, MemKek, MemVault,
    StoreVault, Vault, VaultError, envelope, tables,
};
use zeroize::Zeroizing;

/// The values stored by [`populate`], by reference.
type Stored = Vec<(SecretRef, String)>;

/// Stores `count` secrets, alternating system and operator, each with its own value.
async fn populate(vault: &(impl Vault + ?Sized), count: usize) -> Stored {
    let ctx = ctx();
    let mut stored = Vec::with_capacity(count);
    for index in 0..count {
        let text = format!("value-{index}");
        let secret = if index % 2 == 0 {
            vault
                .put_system(&ctx, spec("auth.totp"), value(&text))
                .await
        } else {
            vault
                .put_operator(&ctx, spec("connect.proxmox_token"), value(&text))
                .await
        }
        .expect("put");
        stored.push((secret, text));
    }
    stored
}

async fn assert_all_readable(vault: &(impl Vault + ?Sized), stored: &Stored) {
    let ctx = ctx();
    for (secret, text) in stored {
        let back = vault.get_system(&ctx, *secret).await.expect("get_system");
        assert_eq!(back.expose(), text.as_bytes());
    }
}

fn dyn_store(store: &Arc<MemStore>) -> Arc<dyn Store> {
    Arc::clone(store) as Arc<dyn Store>
}

async fn all_envelopes(store: &MemStore) -> Vec<VaultEnvelope> {
    let view = view(store).await;
    scan_all(view.as_ref(), &tables::SECRETS)
        .into_iter()
        .map(|(_, row)| VaultEnvelope::from_bytes(&row.value).expect("envelope"))
        .collect()
}

// ---------------------------------------------------------------------------------------
// 8. KEK rotation
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn rotating_the_kek_rewraps_every_envelope() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let secrets = populate(&vault, 40).await;
    let ctx = ctx();

    let mut generations = Vec::new();
    for (secret, _) in &secrets {
        let envelope = envelope_of(store.as_ref(), *secret).await;
        assert_eq!(envelope.key_id, "mem-1");
        generations.push(envelope::inspect(&envelope).expect("inspect"));
    }

    let rotation = vault
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect("rotate_kek");
    assert_eq!(
        rotation,
        KekRotation {
            active: "mem-2".to_owned(),
            rewrapped: 40,
            retired: vec!["mem-1".to_owned()],
        }
    );
    assert_eq!(vault.ring().active().id(), "mem-2");

    // Every envelope names mem-2 now; class and DEK generation are untouched, and the
    // values read back through the rotated vault.
    for ((secret, _), before) in secrets.iter().zip(&generations) {
        let envelope = envelope_of(store.as_ref(), *secret).await;
        assert_eq!(envelope.key_id, "mem-2");
        let info = envelope::inspect(&envelope).expect("inspect");
        assert_eq!(info.class, before.class);
        assert_eq!(info.dek_generation, before.dek_generation);
    }
    assert_eq!(all_envelopes(store.as_ref()).await.len(), 40);
    assert!(
        all_envelopes(store.as_ref())
            .await
            .iter()
            .all(|envelope| envelope.key_id == "mem-2")
    );
    assert_all_readable(&vault, &secrets).await;

    // Class semantics survive the re-wrap.
    let (operator, text) = &secrets[1];
    assert_eq!(
        vault
            .reveal(&ctx, *operator)
            .await
            .expect("reveal")
            .expose(),
        text.as_bytes()
    );
    let (system, _) = &secrets[0];
    assert!(matches!(
        vault.reveal(&ctx, *system).await,
        Err(VaultError::NotRevealable { .. })
    ));

    // The rotation is audited, without any key material.
    let records = audit_of(store.as_ref(), "vault.kek.rotate").await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        record.draft.outcome,
        tenko_core::audit::AuditOutcome::Success
    );
    assert_eq!(record.principal, ctx.principal);
    let context = &record.draft.details.context;
    assert_eq!(context.get("kek").map(String::as_str), Some("mem-2"));
    assert_eq!(context.get("retired").map(String::as_str), Some("mem-1"));
    assert_eq!(context.get("rewrapped").map(String::as_str), Some("40"));
}

#[tokio::test]
async fn a_rotated_store_opens_with_the_new_kek_alone_and_not_with_the_old_one() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let secrets = populate(&vault, 40).await;
    vault
        .rotate_kek(&ctx(), mem2.clone())
        .await
        .expect("rotate_kek");

    // A fresh process that only knows mem-2 starts and reads everything.
    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone()))
        .await
        .expect("open with the new KEK");
    assert_all_readable(&reopened, &secrets).await;

    // A process that only knows the old KEK refuses to start, naming the missing KEK.
    let error = StoreVault::open(dyn_store(&store), KekRing::new(mem1.clone()))
        .await
        .expect_err("old KEK alone must not open a rotated store");
    match &error {
        VaultError::KekUnavailable { reason } => {
            assert!(reason.contains("mem-2"), "{reason}");
        }
        other => panic!("expected KekUnavailable, got {other:?}"),
    }
    assert_eq!(error.code(), "vault.kek.unavailable");

    // Both KEKs together (an operator who has not retired mem-1 yet) are fine.
    StoreVault::open(
        dyn_store(&store),
        KekRing::new(mem2.clone()).with_retired(mem1.clone()),
    )
    .await
    .expect("open with both KEKs");
}

#[tokio::test]
async fn a_second_rotation_with_nothing_left_to_rewrap_is_a_no_op_in_counts() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let secrets = populate(&vault, 12).await;
    let ctx = ctx();

    let first = vault.rotate_kek(&ctx, mem2.clone()).await.expect("first");
    assert_eq!(first.rewrapped, 12);
    let rows_after_first: Vec<_> = {
        let view = view(store.as_ref()).await;
        scan_all(view.as_ref(), &tables::SECRETS)
            .into_iter()
            .map(|(key, row)| (key, row.value, row.revision))
            .collect()
    };

    let second = vault.rotate_kek(&ctx, mem2.clone()).await.expect("second");
    assert_eq!(
        second,
        KekRotation {
            active: "mem-2".to_owned(),
            rewrapped: 0,
            retired: vec!["mem-1".to_owned()],
        }
    );
    // Nothing was rewritten: same bytes at the same revisions.
    let rows_after_second: Vec<_> = {
        let view = view(store.as_ref()).await;
        scan_all(view.as_ref(), &tables::SECRETS)
            .into_iter()
            .map(|(key, row)| (key, row.value, row.revision))
            .collect()
    };
    assert_eq!(rows_after_first, rows_after_second);
    assert_all_readable(&vault, &secrets).await;
    // Each rotation, even an empty one, leaves an audit record.
    assert_eq!(audit_of(store.as_ref(), "vault.kek.rotate").await.len(), 2);
}

#[tokio::test]
async fn rotating_again_to_a_third_kek_keeps_every_older_one_in_the_retired_list() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let mem3 = Arc::new(MemKek::generate("mem-3"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let secrets = populate(&vault, 10).await;
    let ctx = ctx();

    vault
        .rotate_kek(&ctx, mem2.clone())
        .await
        .expect("to mem-2");
    let third = vault
        .rotate_kek(&ctx, mem3.clone())
        .await
        .expect("to mem-3");
    assert_eq!(third.active, "mem-3");
    assert_eq!(third.rewrapped, 10);
    assert_eq!(third.retired, ["mem-1", "mem-2"]);
    assert!(
        all_envelopes(store.as_ref())
            .await
            .iter()
            .all(|envelope| envelope.key_id == "mem-3")
    );
    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem3.clone()))
        .await
        .expect("open with the last KEK alone");
    assert_all_readable(&reopened, &secrets).await;
}

#[tokio::test]
async fn writes_after_a_rotation_use_the_new_kek() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let old = populate(&vault, 4).await;
    vault
        .rotate_kek(&ctx(), mem2.clone())
        .await
        .expect("rotate");
    let ctx = ctx();

    let system = vault
        .put_system(&ctx, spec("auth.totp"), value("after-system"))
        .await
        .expect("put_system");
    let operator = vault
        .put_operator(&ctx, spec("connect.proxmox_token"), value("after-operator"))
        .await
        .expect("put_operator");
    assert_eq!(envelope_of(store.as_ref(), system).await.key_id, "mem-2");
    assert_eq!(envelope_of(store.as_ref(), operator).await.key_id, "mem-2");

    // Replacement and DEK rotation of an old secret also land under the new KEK.
    let (first, _) = &old[0];
    vault
        .replace(&ctx, *first, value("replaced"))
        .await
        .expect("replace");
    assert_eq!(envelope_of(store.as_ref(), *first).await.key_id, "mem-2");
    let (second, text) = &old[1];
    vault.rotate_dek(&ctx, *second).await.expect("rotate_dek");
    assert_eq!(envelope_of(store.as_ref(), *second).await.key_id, "mem-2");
    assert_eq!(
        vault.get_system(&ctx, *second).await.expect("get").expose(),
        text.as_bytes()
    );

    // A staged secret uses the active KEK too, and the audit context says which.
    let created = audit_of(store.as_ref(), "vault.secret.create").await;
    let last = created.last().expect("create record");
    assert_eq!(
        last.draft.details.context.get("kek").map(String::as_str),
        Some("mem-2")
    );

    // Everything is readable by a process that only has mem-2.
    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone()))
        .await
        .expect("open");
    for (secret, text) in &old[1..] {
        assert_eq!(
            reopened
                .get_system(&ctx, *secret)
                .await
                .expect("get")
                .expose(),
            text.as_bytes()
        );
    }
    assert_eq!(
        reopened
            .get_system(&ctx, system)
            .await
            .expect("get")
            .expose(),
        b"after-system"
    );
}

#[tokio::test]
async fn rotation_pages_through_more_envelopes_than_one_batch_holds() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    // The vault pages by 512 rows; 1100 crosses two page boundaries.
    let secrets = populate(&vault, 1100).await;

    let rotation = vault
        .rotate_kek(&ctx(), mem2.clone())
        .await
        .expect("rotate_kek");
    assert_eq!(rotation.rewrapped, 1100);
    assert_eq!(rotation.retired, ["mem-1"]);

    let envelopes = all_envelopes(store.as_ref()).await;
    assert_eq!(envelopes.len(), 1100);
    assert!(envelopes.iter().all(|envelope| envelope.key_id == "mem-2"));
    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone()))
        .await
        .expect("open");
    assert_all_readable(&reopened, &secrets).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_concurrent_with_replacements_loses_no_value() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = Arc::new(MemVault::with_ring(
        Arc::clone(&store),
        KekRing::new(mem1.clone()),
    ));
    let secrets = populate(vault.as_ref(), 40).await;

    let rotator = {
        let vault = Arc::clone(&vault);
        let mem2 = mem2.clone();
        tokio::spawn(async move {
            // Under write contention a rotation may give up with a timeout after its retries
            // (every batch it builds is invalidated by a concurrent write); running it
            // again is the documented remedy.
            let mut gave_up = 0usize;
            loop {
                match vault.rotate_kek(&ctx(), mem2.clone()).await {
                    Ok(rotation) => return (rotation, gave_up),
                    Err(VaultError::Store(tenko_store::StoreError::Timeout)) if gave_up < 200 => {
                        gave_up += 1;
                        tokio::task::yield_now().await;
                    }
                    Err(other) => panic!("rotation failed: {other:?}"),
                }
            }
        })
    };
    let mut writers = Vec::new();
    for (index, (secret, _)) in secrets.iter().enumerate() {
        let vault = Arc::clone(&vault);
        let secret = *secret;
        writers.push(tokio::spawn(async move {
            let ctx = ctx();
            let text = format!("replaced-{index}");
            loop {
                match vault.replace(&ctx, secret, value(&text)).await {
                    Ok(()) => return text,
                    // The rotation re-wrapped the row between read and write: read again.
                    Err(VaultError::Store(tenko_store::StoreError::PreconditionFailed(_))) => {}
                    Err(other) => panic!("replace failed: {other:?}"),
                }
            }
        }));
    }
    let mut expected = Vec::new();
    for (writer, (secret, _)) in writers.into_iter().zip(&secrets) {
        expected.push((*secret, writer.await.expect("writer task")));
    }
    let (rotation, _gave_up) = rotator.await.expect("rotator task");
    assert_eq!(rotation.active, "mem-2");
    assert_eq!(rotation.retired, ["mem-1"]);

    // No value was lost or garbled, whichever KEK ended up wrapping each row.
    assert_all_readable(vault.as_ref(), &expected).await;

    // A final rotation settles every row under mem-2 and a mem-2-only process reads all.
    vault
        .rotate_kek(&ctx(), mem2.clone())
        .await
        .expect("settle");
    assert!(
        all_envelopes(store.as_ref())
            .await
            .iter()
            .all(|envelope| envelope.key_id == "mem-2")
    );
    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone()))
        .await
        .expect("open");
    assert_all_readable(&reopened, &expected).await;
}

// ---------------------------------------------------------------------------------------
// 9. Start fails without the KEK
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn opening_fails_when_the_ring_lacks_the_kek_of_a_stored_envelope() {
    let store = mem_store();
    let vault = MemVault::with_ring(
        Arc::clone(&store),
        KekRing::new(Arc::new(MemKek::generate("mem-1"))),
    );
    populate(&vault, 3).await;

    let error = StoreVault::open(
        dyn_store(&store),
        KekRing::new(Arc::new(MemKek::generate("mem-other"))),
    )
    .await
    .expect_err("a ring with another identifier must not open the store");
    match &error {
        VaultError::KekUnavailable { reason } => {
            assert!(reason.contains("mem-1"), "names the missing KEK: {reason}");
        }
        other => panic!("expected KekUnavailable, got {other:?}"),
    }
    assert_eq!(error.code(), "vault.kek.unavailable");
    assert_eq!(error.http_status(), 500);
}

#[tokio::test]
async fn opening_fails_when_the_identifier_matches_but_the_key_bytes_differ() {
    let store = mem_store();
    let original = Zeroizing::new([0x11u8; 32]);
    let impostor = Zeroizing::new([0x22u8; 32]);
    let vault = MemVault::with_ring(
        Arc::clone(&store),
        KekRing::new(Arc::new(MemKek::from_bytes("mem-1", &original))),
    );
    let secrets = populate(&vault, 3).await;

    let error = StoreVault::open(
        dyn_store(&store),
        KekRing::new(Arc::new(MemKek::from_bytes("mem-1", &impostor))),
    )
    .await
    .expect_err("a replaced key must not open the store");
    assert!(
        matches!(error, VaultError::KekUnavailable { .. }),
        "{error:?}"
    );

    // The genuine bytes under the same identifier open it again.
    let reopened = StoreVault::open(
        dyn_store(&store),
        KekRing::new(Arc::new(MemKek::from_bytes("mem-1", &original))),
    )
    .await
    .expect("genuine KEK");
    assert_all_readable(&reopened, &secrets).await;
}

#[tokio::test]
async fn an_empty_store_opens_with_any_ring() {
    for id in ["mem-1", "anything-at-all", "file-deadbeef"] {
        let store = mem_store();
        let vault = StoreVault::open(
            dyn_store(&store),
            KekRing::new(Arc::new(MemKek::generate(id))),
        )
        .await
        .expect("an empty store needs no particular KEK");
        assert_eq!(vault.ring().active().id(), id);
        // And the new vault is usable.
        let secret = vault
            .put_system(&ctx(), spec("auth.totp"), value("seed"))
            .await
            .expect("put");
        assert_eq!(envelope_of(store.as_ref(), secret).await.key_id, id);
    }
}

#[tokio::test]
async fn opening_checks_every_kek_in_use_not_only_the_first() {
    // Secrets under mem-1 and, after a rotation that was cut short by a crash, under
    // mem-2 as well: a ring that knows only one of them must fail.
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let before = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let old = populate(&before, 3).await;
    let after = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem2.clone()));
    let new = populate(&after, 3).await;

    let only_old = StoreVault::open(dyn_store(&store), KekRing::new(mem1.clone())).await;
    assert!(matches!(only_old, Err(VaultError::KekUnavailable { .. })));
    let only_new = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone())).await;
    assert!(matches!(only_new, Err(VaultError::KekUnavailable { .. })));
    let both = StoreVault::open(
        dyn_store(&store),
        KekRing::new(mem2.clone()).with_retired(mem1.clone()),
    )
    .await
    .expect("both KEKs");
    assert_all_readable(&both, &old).await;
    assert_all_readable(&both, &new).await;
}

#[test]
fn a_missing_key_file_is_unavailable() {
    let dir = scratch_dir("missing-key");
    let config = KekConfig::File {
        path: dir.join("does-not-exist.key"),
        retired: Vec::new(),
    };
    let error = config.load(KekInit::Require).expect_err("missing file");
    assert!(
        matches!(error, VaultError::KekUnavailable { .. }),
        "{error:?}"
    );
    assert_eq!(error.code(), "vault.kek.unavailable");
    // Failing to load must not create anything.
    assert!(!dir.exists());
}

#[test]
fn an_unreadable_key_file_or_retired_file_is_unavailable() {
    let dir = scratch_dir("bad-key");
    fs::create_dir_all(&dir).expect("dir");
    let bad = dir.join("bad.key");
    fs::write(&bad, b"definitely not a key").expect("write");
    let good = dir.join("good.key");
    KekConfig::File {
        path: good.clone(),
        retired: Vec::new(),
    }
    .load(KekInit::CreateIfMissing)
    .expect("create");

    for config in [
        KekConfig::File {
            path: bad.clone(),
            retired: Vec::new(),
        },
        KekConfig::File {
            path: good.clone(),
            retired: vec![bad.clone()],
        },
        KekConfig::File {
            path: good.clone(),
            retired: vec![dir.join("absent.key")],
        },
    ] {
        for init in [KekInit::Require, KekInit::CreateIfMissing] {
            let error = config.load(init).expect_err("unusable key file");
            assert!(
                matches!(error, VaultError::KekUnavailable { .. }),
                "{error:?}"
            );
        }
    }
    cleanup(&dir);
}

#[test]
fn create_if_missing_creates_the_key_file_once() {
    let dir = scratch_dir("create-key");
    let path = dir.join("nested").join("kek.key");
    let config = KekConfig::File {
        path: path.clone(),
        retired: Vec::new(),
    };
    assert!(!path.exists());

    let first = config.load(KekInit::CreateIfMissing).expect("create");
    assert!(path.is_file(), "the key file exists after the first run");
    let text = fs::read_to_string(&path).expect("read key file");
    assert_eq!(text.trim().len(), 64, "64 hexadecimal digits");
    assert!(text.trim().bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(first.active().id().starts_with("file-"));
    assert_eq!(first.active().protection(), KekProtection::PlainFile);
    assert!(first.active().protection().is_weak());
    assert_eq!(first.retired_ids().count(), 0);

    // A second run with CreateIfMissing opens the same key instead of replacing it.
    let second = config.load(KekInit::CreateIfMissing).expect("reopen");
    assert_eq!(second.active().id(), first.active().id());
    assert_eq!(fs::read_to_string(&path).expect("read again"), text);
    // Require finds it too.
    let third = config.load(KekInit::Require).expect("require");
    assert_eq!(third.active().id(), first.active().id());
    cleanup(&dir);
}

#[test]
fn key_files_in_raw_hex_and_base64_form_load_the_same_kek() {
    let dir = scratch_dir("key-forms");
    fs::create_dir_all(&dir).expect("dir");
    let raw: Vec<u8> = (0u8..32).collect();
    let forms: [(&str, Vec<u8>); 4] = [
        ("raw.key", raw.clone()),
        (
            "hex.key",
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n".to_vec(),
        ),
        (
            "upper.key",
            b"  000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F  ".to_vec(),
        ),
        (
            "b64.key",
            b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n".to_vec(),
        ),
    ];
    let mut ids = Vec::new();
    for (name, bytes) in &forms {
        let path = dir.join(name);
        fs::write(&path, bytes).expect("write");
        let ring = KekConfig::File {
            path,
            retired: Vec::new(),
        }
        .load(KekInit::Require)
        .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        ids.push(ring.active().id().to_owned());
    }
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]), "{ids:?}");
    cleanup(&dir);
}

#[tokio::test]
async fn a_file_kek_survives_a_full_restart() {
    let dir = scratch_dir("restart");
    let config = KekConfig::File {
        path: dir.join("kek").join("kek.key"),
        retired: Vec::new(),
    };
    let store = mem_store();

    // First run: create the KEK, open the vault, store a secret.
    let secret = {
        let ring = config.load(KekInit::CreateIfMissing).expect("first run");
        let vault = StoreVault::open(dyn_store(&store), ring)
            .await
            .expect("open on an empty store");
        vault
            .put_system(&ctx(), spec("cluster.ca_key"), value("survives-restart"))
            .await
            .expect("put")
    };

    // Second run: everything dropped, the KEK is loaded again from disk.
    let ring = config.load(KekInit::Require).expect("restart");
    let vault = StoreVault::open(dyn_store(&store), ring)
        .await
        .expect("open after restart");
    assert_eq!(
        vault
            .get_system(&ctx(), secret)
            .await
            .expect("get after restart")
            .expose(),
        b"survives-restart"
    );
    drop(vault);

    // The key file disappears: the server must not start.
    fs::remove_file(dir.join("kek").join("kek.key")).expect("remove key file");
    let error = config.load(KekInit::Require).expect_err("key file deleted");
    assert!(
        matches!(error, VaultError::KekUnavailable { .. }),
        "{error:?}"
    );

    // ... and creating a replacement is possible only on a first run, and the replacement
    // does not open the store.
    let replacement = config
        .load(KekInit::CreateIfMissing)
        .expect("a first-run style load creates a new key");
    let error = StoreVault::open(dyn_store(&store), replacement)
        .await
        .expect_err("a new KEK cannot open existing secrets");
    assert!(
        matches!(error, VaultError::KekUnavailable { .. }),
        "{error:?}"
    );
    cleanup(&dir);
}

#[tokio::test]
async fn a_file_kek_rotates_through_a_new_file_and_the_retired_list() {
    let dir = scratch_dir("file-rotation");
    let old_path = dir.join("old.key");
    let new_path = dir.join("new.key");
    let store = mem_store();

    let old_config = KekConfig::File {
        path: old_path.clone(),
        retired: Vec::new(),
    };
    let old_ring = old_config.load(KekInit::CreateIfMissing).expect("old");
    let old_id = old_ring.active().id().to_owned();
    let vault = StoreVault::open(dyn_store(&store), old_ring)
        .await
        .expect("open");
    let secrets = populate(&vault, 9).await;

    // File providers cannot rotate in place: the operator supplies a new file.
    let error = old_config.create_next().expect_err("no in-place rotation");
    assert!(matches!(error, VaultError::Unsupported { .. }), "{error:?}");
    assert_eq!(error.code(), "vault.unsupported");
    let error = old_config.remove_retired(&old_id).expect_err("no removal");
    assert!(matches!(error, VaultError::Unsupported { .. }), "{error:?}");

    let new_config = KekConfig::File {
        path: new_path.clone(),
        retired: vec![old_path.clone()],
    };
    let new_ring = new_config.load(KekInit::CreateIfMissing).expect("new");
    let new_id = new_ring.active().id().to_owned();
    assert_ne!(new_id, old_id);
    assert_eq!(
        new_ring.retired_ids().collect::<Vec<_>>(),
        [old_id.as_str()]
    );

    // The new ring opens the old store because the old file is listed as retired.
    let rotating = StoreVault::open(dyn_store(&store), new_ring.clone())
        .await
        .expect("open with the retired KEK");
    let rotation = rotating
        .rotate_kek(&ctx(), Arc::clone(new_ring.active()))
        .await
        .expect("rotate");
    assert_eq!(rotation.active, new_id);
    assert_eq!(rotation.rewrapped, 9);
    assert_eq!(rotation.retired, [old_id.as_str()]);
    drop(rotating);
    drop(vault);

    // Now the old file can go: the new file alone opens the store.
    let alone = KekConfig::File {
        path: new_path,
        retired: Vec::new(),
    }
    .load(KekInit::Require)
    .expect("new file alone");
    let reopened = StoreVault::open(dyn_store(&store), alone)
        .await
        .expect("open without the old file");
    assert_all_readable(&reopened, &secrets).await;
    assert!(
        all_envelopes(store.as_ref())
            .await
            .iter()
            .all(|envelope| envelope.key_id == new_id)
    );

    // And the old file alone no longer does.
    let old_alone = old_config
        .load(KekInit::Require)
        .expect("old file still loads");
    let error = StoreVault::open(dyn_store(&store), old_alone)
        .await
        .expect_err("the old KEK alone is useless after rotation");
    assert!(
        matches!(error, VaultError::KekUnavailable { .. }),
        "{error:?}"
    );
    cleanup(&dir);
}

#[test]
fn memory_keks_report_weak_protection() {
    let kek = MemKek::generate("mem-1");
    assert_eq!(kek.protection(), KekProtection::Memory);
    assert!(kek.protection().is_weak());
    let ring = KekRing::new(Arc::new(kek));
    assert_eq!(ring.ids().collect::<Vec<_>>(), ["mem-1"]);
    assert_eq!(ring.retired_ids().count(), 0);
}

#[tokio::test]
async fn operator_secrets_keep_their_class_across_kek_rotation_and_reopen() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let mem2 = Arc::new(MemKek::generate("mem-2"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    let secrets = populate(&vault, 6).await;
    vault
        .rotate_kek(&ctx(), mem2.clone())
        .await
        .expect("rotate");

    let reopened = StoreVault::open(dyn_store(&store), KekRing::new(mem2.clone()))
        .await
        .expect("open");
    for (secret, text) in &secrets {
        let class = envelope::inspect(&envelope_of(store.as_ref(), *secret).await)
            .expect("inspect")
            .class;
        let revealed = reopened.reveal(&ctx(), *secret).await;
        match class {
            SecretClass::Operator => {
                assert_eq!(revealed.expect("operator reveal").expose(), text.as_bytes());
            }
            SecretClass::System => {
                assert!(matches!(revealed, Err(VaultError::NotRevealable { .. })));
            }
        }
    }
    assert!(reopened.has_operator_secrets().await.expect("index"));
}

#[tokio::test]
async fn opening_reports_an_envelope_of_a_newer_format_instead_of_guessing() {
    let store = mem_store();
    let mem1 = Arc::new(MemKek::generate("mem-1"));
    let vault = MemVault::with_ring(Arc::clone(&store), KekRing::new(mem1.clone()));
    // The start-up check unwraps one data key per KEK, so the store holds a single secret.
    let secrets = populate(&vault, 1).await;
    let (secret, _) = &secrets[0];
    let mut envelope = envelope_of(store.as_ref(), *secret).await;
    envelope.format = 2;
    common::put_envelope(store.as_ref(), *secret, &envelope).await;

    let error = StoreVault::open(dyn_store(&store), KekRing::new(mem1.clone()))
        .await
        .expect_err("a format this build does not know must stop the start");
    assert_eq!(error, VaultError::UnsupportedFormat { format: 2 });
    assert_eq!(error.code(), "vault.envelope.unsupported_format");
}
