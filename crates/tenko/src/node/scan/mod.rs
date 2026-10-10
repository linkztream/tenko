//! The scanner of the probe role (SCAN-01 to SCAN-09) inside `tenko serve`, and `tenko node
//! scan`.
//!
//! On a probe node the scanner hands its batches to the agent's observation buffer, which
//! sends them to the controller over the mutual TLS node transport and keeps them through
//! outages. On a controller node that also runs the probe role, the batches go straight to
//! the reconciler through the controller's probe sink, under the controller's node id. The
//! probe reads the `[scan]` section of its own `tenko.toml`; the controller hands out scan
//! configuration with the configuration sync of WP3.1. docs/scanning.md describes the
//! methods, the limits and the files.

use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use tenko_cluster::{
    buffer::{DEFAULT_MAX_BATCH_BYTES, ObservationBuffer},
    client::Agent,
    identity::create_private_dir,
    probe::{ProbeBatch, ProbeSink},
};
use tenko_core::NodeId;
use tenko_scan::{
    ScanError,
    scanner::{BatchSink, Environment, Mode, Scanner},
    status::ScanPaths,
};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use crate::config::Resolved;

pub mod cli;

pub use cli::{ScanArgs, ScanCommand};

/// How long the scanner may take to stop.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Batches into the observation buffer of a probe node's agent.
#[derive(Debug)]
pub struct AgentSink(Arc<Agent>);

impl AgentSink {
    /// A sink into `agent`'s buffer.
    pub fn new(agent: Arc<Agent>) -> Self {
        Self(agent)
    }
}

#[async_trait]
impl BatchSink for AgentSink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        self.0
            .push_run(&batch, run)
            .map_err(|error| ScanError::io(format!("[{}] {}", error.code(), error.detail())))
    }
}

/// Batches straight into the reconciler of a controller node that runs the probe role.
pub struct ControllerSink {
    sink: Arc<dyn ProbeSink>,
    node: NodeId,
}

impl std::fmt::Debug for ControllerSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerSink")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl ControllerSink {
    /// A sink into `sink` under the node id `node`.
    pub fn new(sink: Arc<dyn ProbeSink>, node: NodeId) -> Self {
        Self { sink, node }
    }
}

#[async_trait]
impl BatchSink for ControllerSink {
    async fn deliver(&self, batch: ProbeBatch, _run: Option<Uuid>) -> Result<u32, ScanError> {
        let vrf = batch.vrf;
        self.sink
            .ingest(self.node, vrf, batch)
            .await
            .map(|_| 1)
            .map_err(|error| ScanError::io(format!("[{}] {}", error.code(), error.detail())))
    }
}

/// Batches dropped into the `incoming/` directory of a node's buffer, which the running
/// node process adopts within a second (`tenko node scan run`).
#[derive(Debug, Clone)]
pub struct IncomingSink {
    buffer: PathBuf,
}

impl IncomingSink {
    /// A sink into the buffer directory `buffer`.
    pub fn new(buffer: PathBuf) -> Self {
        Self { buffer }
    }
}

#[async_trait]
impl BatchSink for IncomingSink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        create_private_dir(&self.buffer)
            .map_err(|error| ScanError::io(error.detail().to_owned()))?;
        let mut count = 0u32;
        for part in batch.split_to_fit(DEFAULT_MAX_BATCH_BYTES - 128) {
            ObservationBuffer::drop_incoming(&self.buffer, &part.encode_with_run(run))
                .map_err(|error| ScanError::io(error.to_string()))?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

/// Warns about SNMP passwords written into the configuration file in clear.
fn warn_inline_secrets(resolved: &Resolved) {
    for device in &resolved.config.scan.snmp.devices {
        if device.auth_password.is_some() || device.privacy_password.is_some() {
            tracing::warn!(
                device = %device.address,
                "an SNMP password is written in clear in tenko.toml; prefer \
                 auth_password_file and privacy_password_file with restricted permissions"
            );
        }
    }
}

/// A started scanner and its task.
pub type Started = (Arc<Scanner>, JoinHandle<()>);

/// Starts the scanner of the probe role with `sink`, until `stop` turns true. `None` when
/// the scanner is switched off (`[scan] enabled = false`).
///
/// # Errors
///
/// The [`ScanError`] of a configuration the scanner cannot run with.
pub fn start(
    resolved: &Resolved,
    sink: Arc<dyn BatchSink>,
    stop: watch::Receiver<bool>,
) -> Result<Option<Started>, ScanError> {
    let config = &resolved.config.scan;
    if !config.enabled {
        tracing::info!("the scanner is switched off ([scan] enabled = false)");
        return Ok(None);
    }
    warn_inline_secrets(resolved);
    let scanner = Scanner::new(
        config.clone(),
        ScanPaths::new(&resolved.data_dir),
        sink,
        &Environment::host(),
        Mode::Service,
    )?;
    if scanner.scope().is_empty() {
        tracing::warn!(
            "no prefixes in [scan]: the scanner scans nothing until prefixes are configured"
        );
    }
    let task = tokio::spawn(Arc::clone(&scanner).run(stop));
    Ok(Some((scanner, task)))
}

/// Starts the scanner of a controller node that runs the probe role: batches go to the
/// controller's own probe sink under `node`. Returns the task (none when the scanner is
/// switched off) and a summary for the start log.
///
/// # Errors
///
/// The [`ScanError`] of a configuration the scanner cannot run with.
pub fn start_on_controller(
    resolved: &Resolved,
    sink: Arc<dyn ProbeSink>,
    node: NodeId,
    stop: watch::Receiver<bool>,
) -> Result<(Option<JoinHandle<()>>, String), ScanError> {
    let sink: Arc<dyn BatchSink> = Arc::new(ControllerSink::new(sink, node));
    Ok(match start(resolved, sink, stop)? {
        Some((scanner, task)) => (
            Some(task),
            format!("scanner over {}", scanner.scope().describe()),
        ),
        None => (None, "scanner switched off".to_owned()),
    })
}
