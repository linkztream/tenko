//! The node process of `tenko serve` on a node without the controller role (OPS-28).
//!
//! For the `probe` role it keeps the supervised connection to the controllers
//! ([`tenko_cluster::client::Agent`]): handshake, heartbeats, renewal and the replay of the
//! observation buffer, which batches dropped into its `incoming/` directory reach
//! (`tenko node inject`); the scanner ([`crate::node::scan`]) puts its batches into the same
//! buffer. The node needs neither the store nor the vault: its key and certificate are files
//! of `<data_dir>/node/`, so it keeps buffering while every controller is away.
//!
//! [`command`] is `tenko serve` on a console; [`serve`] is the shared part, which the
//! Windows service calls with its own shutdown and status callbacks.

use std::{
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_cluster::{
    buffer::BufferConfig,
    client::{Agent, AgentConfig},
    identity::NodePaths,
};
use tenko_core::Role;
use tokio::sync::watch;

use crate::{
    config::Resolved,
    exit, logging,
    serve::{Hooks, Ready, Shutdown},
    version,
};

/// How long the node process may take to stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the node cannot run, with its exit status; `None` when it can.
fn refusal(resolved: &Resolved) -> Option<(u8, String)> {
    let paths = NodePaths::new(&resolved.data_dir);
    if !paths.is_enrolled() {
        return Some((
            exit::CONFIG,
            format!(
                "[cluster.node.not_enrolled] this node is not enrolled; run `tenko node enrol \
                 --controller <url> --token <token> --data-dir {}` first",
                resolved.data_dir.display()
            ),
        ));
    }
    if !resolved.roles.contains(Role::Probe) {
        return Some((
            exit::USAGE,
            "this node runs none of its roles yet; only probe runs without the controller role \
             in Phase 1"
                .to_owned(),
        ));
    }
    None
}

/// `tenko serve` on a node without the controller role: runs the data-plane roles until a
/// signal (or the end of standard input with `stop_on_eof`) and returns the exit status, 3
/// when the node is not enrolled or its credentials do not load.
pub fn command(resolved: Resolved, stop_on_eof: bool, err: &mut impl Write) -> u8 {
    if let Some((status, message)) = refusal(&resolved) {
        let _ = writeln!(err, "tenko serve: {message}");
        return status;
    }
    if let Err(error) = logging::init_server(
        &resolved.config.log,
        resolved.config.log.file.as_deref(),
        logging::Sink::Console,
    ) {
        let _ = writeln!(err, "tenko serve: {error}");
        return exit::FAILURE;
    }
    let status = serve(
        resolved,
        move || shutdown(stop_on_eof),
        crate::platform::notify_hooks(),
    );
    if status == exit::CONFIG {
        let _ = writeln!(
            err,
            "tenko serve: the node credentials could not be loaded; see the log"
        );
    }
    status
}

/// Runs the node process with the logging already set up, until `shutdown` resolves, and
/// returns the exit status. The Windows service calls this for a node without the
/// controller role.
pub fn serve(
    resolved: Resolved,
    shutdown: impl FnOnce() -> Shutdown + Send + 'static,
    hooks: Hooks,
) -> u8 {
    if let Some((status, message)) = refusal(&resolved) {
        tracing::error!("{message}");
        return status;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(resolved.config.runtime.workers)
        .thread_name("tenko-node")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "the runtime of the node process cannot be built");
            return exit::FAILURE;
        }
    };
    // The start-up future runs on a thread with a large stack, as the controller's does.
    crate::serve::on_start_thread("tenko-node-serve", move || {
        let status = runtime.block_on(async move { run(resolved, shutdown(), hooks).await });
        runtime.shutdown_timeout(Duration::from_secs(5));
        status
    })
    .unwrap_or_else(|error| {
        tracing::error!(%error, "the start thread of the node process cannot be spawned");
        exit::FAILURE
    })
}

async fn run(resolved: Resolved, shutdown: Shutdown, hooks: Hooks) -> u8 {
    let started = Instant::now();
    let paths = NodePaths::new(&resolved.data_dir);
    let mut config = AgentConfig::new(paths.clone(), version());
    let mut buffer = BufferConfig::new(paths.buffer());
    buffer.max_bytes = resolved
        .config
        .cluster
        .buffer_mib
        .saturating_mul(1024 * 1024);
    buffer.max_batch_bytes = buffer
        .max_batch_bytes
        .min(usize::try_from(buffer.max_bytes).unwrap_or(usize::MAX));
    config.buffer = buffer;
    let agent = match Agent::new(config) {
        Ok(agent) => agent,
        Err(error) => {
            tracing::error!(code = %error.code(), "{}", error.detail());
            return exit::CONFIG;
        }
    };
    let credentials = agent.credentials();
    let identity = &credentials.identity;
    let roles = identity
        .roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",");
    tracing::info!(
        node = %identity.node,
        name = %identity.name,
        roles = %roles,
        endpoints = %identity.dial_targets().join(", "),
        not_after = %credentials.info.not_after,
        "tenko {} node starting",
        version()
    );
    let (stop, stopped) = watch::channel(false);
    let scanner = crate::node::scan::start_on_node(&resolved, &agent, stopped.clone());
    let task = tokio::spawn(Arc::clone(&agent).run(stopped));
    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "tenko {} node {} ({}) running role(s) {roles}; controller endpoint(s) {}",
            version(),
            identity.node,
            identity.name,
            identity.dial_targets().join(", ")
        );
        let _ = out.flush();
    }
    let Hooks { ready, stopping } = hooks;
    if let Some(ready) = ready {
        ready(&Ready {
            addrs: Vec::new(),
            elapsed: started.elapsed(),
        });
    }
    shutdown.await;
    tracing::info!("shutdown requested");
    if let Some(stopping) = stopping {
        stopping();
    }
    let _ = stop.send(true);
    for task in scanner {
        if tokio::time::timeout(crate::node::scan::STOP_TIMEOUT, task)
            .await
            .is_err()
        {
            tracing::warn!("the scanner did not stop in time");
        }
    }
    if tokio::time::timeout(STOP_TIMEOUT, task).await.is_err() {
        tracing::warn!("the node process did not stop in time");
    }
    tracing::info!("tenko node stopped");
    exit::OK
}

fn shutdown(stop_on_eof: bool) -> Shutdown {
    Box::pin(async move {
        if stop_on_eof {
            tokio::select! {
                () = crate::serve::shutdown_signal() => {}
                () = stdin_closed() => tracing::info!("standard input closed"),
            }
        } else {
            crate::serve::shutdown_signal().await;
        }
    })
}

/// Resolves when standard input reaches its end (`--stop-on-eof`).
async fn stdin_closed() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("tenko-stdin".to_owned())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = [0u8; 256];
            while let Ok(read) = std::io::Read::read(&mut stdin, &mut buffer) {
                if read == 0 {
                    break;
                }
            }
            let _ = tx.send(());
        });
    if spawned.is_err() {
        std::future::pending::<()>().await;
    }
    let _ = rx.await;
}
