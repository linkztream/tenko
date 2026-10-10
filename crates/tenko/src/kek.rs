//! `tenko kek rotate`: rotates the key-encryption key of a stopped single controller
//! (IAM-15).
//!
//! The rotation runs with the server stopped, because the store's files are locked by the
//! process that has them open. It creates the next KEK generation of the configured
//! provider, makes it active (with a new KEK epoch in the installation's KEK state),
//! re-wraps every envelope under it, and then deletes the generations no envelope uses any
//! more. It is crash-safe: until it ends, every earlier generation stays on disk, and
//! running it again finishes an interrupted rotation.
//!
//! The `file` and systemd credential providers keep the new generation in the generation
//! directory (`<data_dir>/kek`), wrapped under their root key; the root key itself stays
//! in the configuration and is never removed by this command.
//!
//! A member of a cluster of controllers rotates online instead (`POST /system/kek/rotate`,
//! which distributes the new generation to every controller first); this command refuses
//! to run there.

use std::{fmt::Write as _, io::Write, sync::Arc, time::Duration};

use clap::{Args, Subcommand};
use tenko_core::{RequestCtx, principal::SystemComponent};
use tenko_store::raft::RaftStore;
use tenko_vault::{KekInit, KekOptions, StoreVault};

use crate::{config, exit, logging, serve};

/// Subcommands of `tenko kek`.
#[derive(Debug, Clone, Subcommand)]
pub enum KekCommand {
    /// Create the next key-encryption key, re-wrap every secret under it and remove the
    /// keys no secret uses any more. Stop `tenko serve` first.
    Rotate(RotateArgs),
}

/// Arguments of `tenko kek rotate`.
#[derive(Debug, Clone, Args)]
pub struct RotateArgs {
    /// The configuration file of the node.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// The data directory; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<std::path::PathBuf>,

    /// Keep the retired key generations on disk instead of deleting them.
    #[arg(long)]
    pub keep_retired: bool,
}

/// Runs `tenko kek rotate`.
pub fn rotate(args: &RotateArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let resolved =
        match config::load(&sources, std::env::vars()).and_then(|loaded| loaded.config.resolve()) {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = writeln!(err, "tenko kek rotate: {error}");
                return exit::CONFIG;
            }
        };
    if resolved.layout().is_fresh() {
        let _ = writeln!(
            err,
            "tenko kek rotate: {} holds no store yet; start the server once first",
            resolved.data_dir.display()
        );
        return exit::USAGE;
    }
    if let Err(error) = logging::init_server(&resolved.config.log, None, logging::Sink::Console) {
        let _ = writeln!(err, "tenko kek rotate: {error}");
        return exit::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko kek rotate: runtime: {error}");
            return exit::FAILURE;
        }
    };
    let result = runtime.block_on(run(&resolved, args.keep_retired));
    runtime.shutdown_timeout(Duration::from_secs(5));
    match result {
        Ok(report) => {
            let _ = write!(out, "{report}");
            exit::OK
        }
        Err((status, message)) => {
            let _ = writeln!(err, "tenko kek rotate: {message}");
            status
        }
    }
}

/// The policy of the key generations. `kek.allow_plain` is not a setting yet, so plain
/// generations beside sealed ones stay refused; the `file` provider keeps its generations
/// in the data directory's `kek/`.
fn options(resolved: &config::Resolved) -> KekOptions {
    KekOptions {
        allow_plain: false,
        file_dir: Some(resolved.layout().kek()),
    }
}

async fn run(resolved: &config::Resolved, keep_retired: bool) -> Result<String, (u8, String)> {
    let kek = resolved.kek.clone();
    let options = options(resolved);
    let ring = tokio::task::spawn_blocking(move || kek.load_with(KekInit::Require, &options))
        .await
        .map_err(|error| (exit::FAILURE, error.to_string()))?
        .map_err(|error| (exit::START, format!("loading the keys: {error}")))?;
    let store = RaftStore::open(serve::store_config(resolved))
        .await
        .map_err(|error| {
            (
                exit::START,
                format!(
                    "opening the store (is `tenko serve` still running? stop it first): {error}"
                ),
            )
        })?;
    let members = {
        let metrics = store.raft().metrics();
        let metrics = metrics.borrow();
        let membership = metrics.membership_config.membership();
        membership.voter_ids().count() + membership.learner_ids().count()
    };
    let result = if members > 1 {
        Err((
            exit::USAGE,
            format!(
                "this controller is a member of a cluster of {members} controllers; rotate \
                 online with POST /system/kek/rotate (or the web UI), which hands the new key \
                 to every controller first. `tenko kek rotate` is for a stopped single \
                 controller"
            ),
        ))
    } else {
        rotate_open(resolved, &store, ring, keep_retired).await
    };
    if let Err(error) = store.shutdown().await {
        tracing::error!(%error, "store shutdown failed");
    }
    result
}

async fn rotate_open(
    resolved: &config::Resolved,
    store: &RaftStore,
    ring: tenko_vault::KekRing,
    keep_retired: bool,
) -> Result<String, (u8, String)> {
    let vault = StoreVault::open(Arc::new(store.clone()), ring)
        .await
        .map_err(|error| (exit::START, format!("opening the vault: {error}")))?;
    let kek = resolved.kek.clone();
    let policy = options(resolved);
    let next = tokio::task::spawn_blocking(move || kek.create_next_with(&policy))
        .await
        .map_err(|error| (exit::FAILURE, error.to_string()))?
        .map_err(|error| (exit::USAGE, format!("creating the next key: {error}")))?;
    let ctx = RequestCtx::system(SystemComponent::Vault);
    let rotation = vault.rotate_kek(&ctx, next).await.map_err(|error| {
        (
            exit::FAILURE,
            format!("rotation stopped (run it again): {error}"),
        )
    })?;
    let mut report = format!(
        "rotated to {}: {} secret(s) re-wrapped\n",
        rotation.active, rotation.rewrapped
    );
    for id in &rotation.retired {
        if keep_retired {
            let _ = writeln!(report, "kept retired key {id}");
            continue;
        }
        match resolved.kek.remove_retired_with(id, &options(resolved)) {
            Ok(()) => {
                let _ = writeln!(report, "removed retired key {id}");
            }
            // The root key of the `file` or systemd credential provider stays in the
            // configuration.
            Err(tenko_vault::VaultError::Unsupported { what }) => {
                let _ = writeln!(report, "kept retired key {id} ({what})");
            }
            Err(error) => {
                let _ = writeln!(report, "could not remove retired key {id}: {error}");
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tenko_core::secret::SecretClass;
    use tenko_store::{ReadConsistency, Store, WriteBatch};
    use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault, VaultStart, tables};

    use super::*;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn resolved(root: &Path) -> config::Resolved {
        std::fs::create_dir_all(root.join("secrets")).expect("dirs");
        let key = root.join("secrets").join("kek.key");
        std::fs::write(
            &key,
            format!(
                "{}
",
                "3c".repeat(32)
            ),
        )
        .expect("key file");
        let file = root.join("tenko.toml");
        std::fs::write(
            &file,
            format!(
                "data_dir = '{}'
[kek]
provider = \"file\"
path = '{}'
",
                root.join("data").display(),
                key.display()
            ),
        )
        .expect("config");
        let sources = config::Sources {
            file: Some(file),
            data_dir: None,
            roles: None,
        };
        config::load(&sources, std::iter::empty())
            .and_then(|loaded| loaded.config.resolve())
            .expect("configuration")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_provider_rotates_into_the_generation_directory() {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "tenko-kek-rotate-{}",
            tenko_core::SecretId::generate()
        )));
        let resolved = resolved(&scratch.0);
        let policy = options(&resolved);
        let ring = resolved
            .kek
            .load_with(KekInit::Require, &policy)
            .expect("key file");
        let root = ring.active().id().to_owned();
        assert!(root.starts_with("file-"));

        // A first start: the store, the vault and one secret.
        let store = RaftStore::open(serve::store_config(&resolved))
            .await
            .expect("store");
        let vault = StoreVault::start(
            Arc::new(store.clone()),
            ring,
            &VaultStart {
                node: tenko_core::NodeId(1),
                provider: "file".to_owned(),
            },
        )
        .await
        .expect("vault");
        let ctx = RequestCtx::system(SystemComponent::Vault);
        let mut batch = WriteBatch::for_request(&ctx);
        let secret = vault
            .stage_put(
                &mut batch,
                &ctx,
                SecretClass::System,
                SecretSpec::new(SecretPurpose::from_static("auth.totp")),
                &SecretBytes::from(b"example-seed".to_vec()),
            )
            .expect("staged");
        store.propose(batch).await.expect("stored");
        drop(vault);
        store.shutdown().await.expect("shutdown");
        drop(store);
        // The store's background tasks let go of the database files shortly after.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // The rotation of a stopped single controller.
        let report = run(&resolved, false).await.expect("rotated");
        assert!(report.contains("rotated to wrap-1-"), "{report}");
        assert!(report.contains("1 secret(s) re-wrapped"), "{report}");
        assert!(
            report.contains(&format!("kept retired key {root}")),
            "{report}"
        );
        assert!(resolved.layout().kek().join("kek-000001.wrap").exists());

        // The next start: the new generation is active and opens the secret.
        let ring = resolved
            .kek
            .load_with(KekInit::Require, &policy)
            .expect("ring");
        assert!(ring.active().id().starts_with("wrap-1-"));
        let store = RaftStore::open(serve::store_config(&resolved))
            .await
            .expect("store");
        let vault = StoreVault::open(Arc::new(store.clone()), ring.clone())
            .await
            .expect("vault");
        assert_eq!(
            vault
                .get_system(&ctx, secret)
                .await
                .expect("secret")
                .expose(),
            b"example-seed"
        );
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let envelope = tenko_core::secret::VaultEnvelope::from_bytes(
            &view
                .get(
                    &tables::SECRETS,
                    &tenko_core::codec::encode_key(&secret.secret),
                )
                .expect("read")
                .expect("row")
                .value,
        )
        .expect("envelope");
        assert_eq!(envelope.key_id, ring.active().id());
        drop(vault);
        store.shutdown().await.expect("shutdown");
    }
}
