//! The KEK transfer to a joining controller (S3-Q5, ADR 0014): the joiner receives every
//! generation sealed to its one-time key, seals them with its own provider, and its vault
//! opens every envelope of the installation.

mod common;

use std::{path::Path, sync::Arc};

use common::{cleanup, ctx, scratch_dir, spec, value};
use tenko_core::{NodeId, secret::SecretRef};
use tenko_store::{MemStore, Store};
use tenko_vault::{
    KekConfig, KekInit, KekOptions, KekProvider, KekRing, MemVault, StoreVault, TransferFailure,
    Vault, VaultError,
    transfer::{self, TransferKey},
};

/// A `file` provider with a generation directory under `root`.
fn file_provider(root: &Path) -> (KekConfig, KekOptions) {
    (
        KekConfig::File {
            path: root.join("key").join("kek.key"),
            retired: Vec::new(),
        },
        KekOptions {
            allow_plain: false,
            file_dir: Some(root.join("kek")),
        },
    )
}

/// The installation: two generations, envelopes under each, the second active.
async fn installation(root: &Path) -> (Arc<MemStore>, KekRing, Vec<SecretRef>) {
    let (config, options) = file_provider(root);
    let first = config
        .load_with(KekInit::CreateIfMissing, &options)
        .expect("first generation");
    let store = Arc::new(MemStore::default());
    let ctx = ctx();
    let mut secrets = Vec::new();
    let old = MemVault::with_ring(Arc::clone(&store), first.clone());
    for index in 0..3 {
        secrets.push(
            old.put_operator(&ctx, spec("vault.test_old"), value(&format!("old-{index}")))
                .await
                .expect("put"),
        );
    }
    config
        .create_next_with(&options)
        .expect("second generation");
    let ring = config.load_with(KekInit::Require, &options).expect("load");
    assert_eq!(ring.ids().count(), 2);
    let new = MemVault::with_ring(Arc::clone(&store), ring.clone());
    for index in 0..3 {
        secrets.push(
            new.put_system(&ctx, spec("vault.test_new"), value(&format!("new-{index}")))
                .await
                .expect("put"),
        );
    }
    (store, ring, secrets)
}

async fn opens_everything(store: &Arc<MemStore>, ring: KekRing, secrets: &[SecretRef]) {
    let vault = StoreVault::open(Arc::clone(store) as Arc<dyn Store>, ring)
        .await
        .expect("the joiner's vault opens");
    for secret in secrets {
        vault
            .get_system(&ctx(), *secret)
            .await
            .expect("every envelope opens");
    }
}

#[tokio::test]
async fn a_joined_controller_opens_every_envelope() {
    let sender_root = scratch_dir("transfer-sender");
    let joiner_root = scratch_dir("transfer-joiner");
    let (store, ring, secrets) = installation(&sender_root).await;

    // The joiner makes a one-time key; the member seals the generations to it.
    let joiner = TransferKey::generate().expect("transfer key");
    let context = transfer::join_context(NodeId(1001), [0x5a; 16]);
    let sealed = transfer::seal_ring(&ring, &joiner.public_key(), &context).expect("seal");
    assert_eq!(sealed.generation_ids, ring.ids().collect::<Vec<_>>());
    assert_eq!(
        sealed.generation_ids.last().map(String::as_str),
        Some(ring.active().id())
    );
    let received = joiner
        .open(sealed.format, &sealed.sealed, &context)
        .expect("open");

    // The joiner seals them with its own provider (here: a key file of its own and a
    // generation directory), keeping the identifiers.
    let (config, options) = file_provider(&joiner_root);
    config
        .load_with(KekInit::CreateIfMissing, &options)
        .expect("own root key");
    let imported = config.import_with(&received, &options).expect("import");
    assert_eq!(imported.active().id(), ring.active().id());
    for id in ring.ids() {
        assert!(imported.contains(id), "{id} was not imported");
    }
    // The ring survives a restart, and a second import changes nothing.
    let reloaded = config
        .load_with(KekInit::Require, &options)
        .expect("reload");
    assert_eq!(reloaded.active().id(), ring.active().id());
    let again = config.import_with(&received, &options).expect("again");
    assert_eq!(again.ids().count(), reloaded.ids().count());

    opens_everything(&store, imported, &secrets).await;
    cleanup(&sender_root);
    cleanup(&joiner_root);
}

#[cfg(windows)]
#[tokio::test]
async fn a_joined_windows_controller_seals_the_generations_with_dpapi() {
    let sender_root = scratch_dir("transfer-dpapi-sender");
    let joiner_root = scratch_dir("transfer-dpapi-joiner");
    let (store, ring, secrets) = installation(&sender_root).await;
    let joiner = TransferKey::generate().expect("transfer key");
    let context = transfer::join_context(NodeId(1002), [1; 16]);
    let sealed = transfer::seal_ring(&ring, &joiner.public_key(), &context).expect("seal");
    let received = joiner
        .open(transfer::FORMAT, &sealed.sealed, &context)
        .expect("open");
    let config = KekConfig::Dpapi {
        dir: joiner_root.join("kek"),
        scope: tenko_vault::kek::DpapiScope::User,
    };
    let imported = config.import(&received).expect("import");
    assert_eq!(imported.active().id(), ring.active().id());
    assert!(imported.active().protection().rank() > ring.active().protection().rank());
    assert!(joiner_root.join("kek").join("kek-000001.dpapi").exists());
    assert!(joiner_root.join("kek").join("kek-000002.dpapi").exists());
    let reloaded = config.load(KekInit::Require).expect("reload");
    assert_eq!(reloaded.active().id(), ring.active().id());
    opens_everything(&store, reloaded, &secrets).await;
    cleanup(&sender_root);
    cleanup(&joiner_root);
}

#[tokio::test]
async fn a_transfer_opens_once_and_only_for_its_context() {
    let root = scratch_dir("transfer-once");
    let (_, ring, _) = installation(&root).await;
    let joiner = TransferKey::generate().expect("transfer key");
    let public = joiner.public_key();
    let context = transfer::join_context(NodeId(1003), [2; 16]);
    let sealed = transfer::seal_ring(&ring, &public, &context).expect("seal");
    // Another token, another node or a fetch context: the derived key differs.
    for other in [
        transfer::join_context(NodeId(1003), [3; 16]),
        transfer::join_context(NodeId(1004), [2; 16]),
        transfer::fetch_context(NodeId(1003)),
    ] {
        let probe = TransferKey::generate().expect("key");
        let resealed = transfer::seal_ring(&ring, &probe.public_key(), &context).expect("seal");
        assert_eq!(
            probe
                .open(transfer::FORMAT, &resealed.sealed, &other)
                .expect_err("context"),
            VaultError::Transfer {
                failure: TransferFailure::Integrity
            }
        );
    }
    // The key is consumed by the first open; the same frame does not open for anyone else.
    assert!(
        joiner
            .open(transfer::FORMAT, &sealed.sealed, &context)
            .is_ok()
    );
    let stranger = TransferKey::generate().expect("key");
    assert!(
        stranger
            .open(transfer::FORMAT, &sealed.sealed, &context)
            .is_err()
    );
    cleanup(&root);
}

#[tokio::test]
async fn an_import_never_replaces_a_different_key_under_the_same_id() {
    let sender_root = scratch_dir("transfer-conflict-sender");
    let joiner_root = scratch_dir("transfer-conflict-joiner");
    let (_, ring, _) = installation(&sender_root).await;
    let joiner = TransferKey::generate().expect("transfer key");
    let context = transfer::fetch_context(NodeId(1005));
    let sealed = transfer::seal_ring(&ring, &joiner.public_key(), &context).expect("seal");
    let mut received = joiner
        .open(transfer::FORMAT, &sealed.sealed, &context)
        .expect("open");
    let (config, options) = file_provider(&joiner_root);
    config
        .load_with(KekInit::CreateIfMissing, &options)
        .expect("own root key");
    config.import_with(&received, &options).expect("import");
    received[0].material[0] ^= 0xff;
    let error = config
        .import_with(&received, &options)
        .expect_err("conflict");
    assert_eq!(
        error,
        VaultError::Transfer {
            failure: TransferFailure::Conflict {
                id: received[0].id.clone()
            }
        }
    );
    // An empty transfer is malformed.
    assert!(matches!(
        config.import_with(&[], &options),
        Err(VaultError::Transfer {
            failure: TransferFailure::Malformed
        })
    ));
    // Without a generation directory the file provider cannot hold a received generation.
    let bare = KekOptions::default();
    assert!(matches!(
        config.import_with(&received[1..], &bare),
        Err(VaultError::Unsupported { .. })
    ));
    cleanup(&sender_root);
    cleanup(&joiner_root);
}

#[test]
fn the_active_generation_travels_last_even_with_a_newer_pending_one() {
    let pending: Arc<dyn KekProvider> = Arc::new(tenko_vault::MemKek::generate("mem-3"));
    let ring = KekRing::new(Arc::new(tenko_vault::MemKek::generate("mem-2")))
        .with_retired(Arc::new(tenko_vault::MemKek::generate("mem-1")))
        .with_newer(pending);
    let joiner = TransferKey::generate().expect("key");
    let sealed = transfer::seal_ring(&ring, &joiner.public_key(), b"test context").expect("seal");
    assert_eq!(sealed.generation_ids, ["mem-1", "mem-3", "mem-2"]);
}
