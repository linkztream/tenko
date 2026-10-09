//! `tenko kek rotate`: rotates the key-encryption key of the vault (IAM-15).
//!
//! The rotation runs with the server stopped, because the store's files are locked by the
//! process that has them open. It creates the next KEK generation of the configured
//! provider, makes it active, re-wraps every envelope under it, and then deletes the
//! generations no envelope uses any more. It is crash-safe: until it ends, every earlier
//! generation stays on disk, and running it again finishes an interrupted rotation.
//!
//! A `file` provider cannot rotate in place: configure a new key file and list the old one
//! under `kek.retired`, start the server once (envelopes are re-wrapped on rotation only),
//! or run this command after switching to a directory-based provider.

use std::{fmt::Write as _, io::Write, sync::Arc, time::Duration};

use clap::{Args, Subcommand};
use tenko_core::{RequestCtx, principal::SystemComponent};
use tenko_store::raft::RaftStore;
use tenko_vault::{KekInit, StoreVault};

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

async fn run(resolved: &config::Resolved, keep_retired: bool) -> Result<String, (u8, String)> {
    let kek = resolved.kek.clone();
    let ring = tokio::task::spawn_blocking(move || kek.load(KekInit::Require))
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
    let result = rotate_open(resolved, &store, ring, keep_retired).await;
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
    let next = tokio::task::spawn_blocking(move || kek.create_next())
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
        match resolved.kek.remove_retired(id) {
            Ok(()) => {
                let _ = writeln!(report, "removed retired key {id}");
            }
            Err(error) => {
                let _ = writeln!(report, "could not remove retired key {id}: {error}");
            }
        }
    }
    Ok(report)
}
