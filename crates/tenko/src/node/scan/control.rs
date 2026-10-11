//! The `scans` start step of a controller (SCAN-05, SCAN-09, OPS-28): the scan control
//! behind `/api/v1/scans` and `/api/v1/nodes/{id}/scan-config`, the probes' offers of
//! their own configuration on the cluster port, and the probe role in process.
//!
//! The probe role in process runs like a probe node, with the store in place of the
//! cluster port: it follows its row of `scan.probe_config` (its `[scan]` section until the
//! installation holds one, which it offers at the first start), carries out the commands
//! of `cluster.node_commands` addressed to this controller's node id, fetches the SNMP
//! secrets its configuration names from the vault with the audit record of a probe's
//! fetch, writes its scope to `scan.scopes`, and hands its batches through the relay
//! buffer of [`super::relay`].

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::StreamExt as _;
use tenko_cluster::{
    node_sync::{NodeSync, commands, secrets::resolve_for},
    probe::{ProbeScope, ProbeSink, record_scope},
    proto::v1,
    registry::NodeRegistry,
};
use tenko_core::{NodeId, Role, SecretId, Timestamp, cluster::LeaderService};
use tenko_jobs::JobEngine;
use tenko_scan::{
    ScanError,
    config::SNMP_SECRET_PURPOSE,
    control::{ScanControl, model::tables::PROBE_CONFIG},
    scanner::{Environment, Mode, Scanner},
    secrets::{SecretSource, VaultSecrets},
    status::ScanPaths,
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tenko_vault::Vault;
use tokio::{sync::watch, task::JoinHandle};

use super::{
    relay::Relay,
    supervisor::{Build, Desired, ScanCommands, ScopeReports, Supervisor},
    vault_secrets, warn_inline_secrets,
};
use crate::{config::Resolved, serve::StartError};

/// How often the probe role in process reads its configuration again without a change.
const REFRESH: Duration = Duration::from_secs(30);
/// The pause before a scope report that could not be written is tried again.
const REPORT_RETRY: Duration = Duration::from_secs(5);

/// What the step needs.
pub struct Parts<'a> {
    /// The resolved configuration.
    pub resolved: &'a Resolved,
    /// The store.
    pub store: Arc<dyn Store>,
    /// The vault, to check the SNMP secrets a configuration names.
    pub vault: Arc<dyn Vault>,
    /// The job engine, which runs the scans on demand.
    pub engine: JobEngine,
    /// The node registry of the `nodes` step, whose node sync takes the offers.
    pub registry: Arc<NodeRegistry>,
    /// Where the probe role's batches go: the controller's ingest.
    pub probe_sink: Arc<dyn ProbeSink>,
    /// The server's stop signal.
    pub stop: watch::Receiver<bool>,
}

/// The running scan control of a controller.
pub struct Scans {
    control: Arc<ScanControl>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Scans {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scans").finish_non_exhaustive()
    }
}

impl Scans {
    /// The background tasks, for the server's stop sequence. A second call returns nothing.
    pub fn tasks(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.tasks)
    }

    /// Adds the scan control to the request extensions of the API.
    pub fn register(&self, server: &mut tenko_api::ServerConfig) {
        server.extensions.insert(Arc::clone(&self.control));
    }

    /// The scan control.
    pub fn control(&self) -> &Arc<ScanControl> {
        &self.control
    }
}

/// The leader service `scan.housekeeping` for the leader runner, which starts before the
/// job engine and the scan control exist.
pub fn housekeeping(resolved: &Resolved, store: Arc<dyn Store>) -> Arc<dyn LeaderService> {
    tenko_scan::control::housekeeping_service(store, local_probe(resolved))
}

fn local_probe(resolved: &Resolved) -> Option<NodeId> {
    resolved
        .roles
        .contains(Role::Probe)
        .then_some(resolved.node_id)
}

/// Starts the scan control and, when this controller runs the probe role, the probe in
/// process.
///
/// # Errors
///
/// A [`StartError`] of the step `scans` when the relay buffer cannot be opened.
pub async fn start(parts: Parts<'_>) -> Result<(Scans, String), StartError> {
    let Parts {
        resolved,
        store,
        vault,
        engine,
        registry,
        probe_sink,
        stop,
    } = parts;
    let local = local_probe(resolved);
    let control = ScanControl::new(Arc::clone(&store), &engine, Some(vault), local);
    control.take_offers(registry.node_sync());
    let mut tasks = Vec::new();
    let summary = match local {
        Some(node) => {
            let scan = &resolved.config.scan;
            warn_inline_secrets(scan);
            match control.offer_local(scan).await {
                Ok(true) => tracing::info!(
                    "the [scan] section became the stored configuration of this controller's probe role"
                ),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(code = %error.code, "the [scan] section could not be offered: {}", error.detail);
                }
            }
            let relay = Relay::open(
                &resolved.data_dir,
                resolved
                    .config
                    .cluster
                    .buffer_mib
                    .saturating_mul(1024 * 1024),
            )
            .map_err(|error| StartError::new("scans", error.code(), error.detail()))?;
            let environment = Environment::host().with_secrets(Arc::new(LocalSecrets {
                sync: registry.node_sync().clone(),
                node,
            }));
            let sink = relay.sink();
            let paths = ScanPaths::new(&resolved.data_dir);
            let build: Build = Arc::new(move |config| {
                Scanner::new(
                    config.clone(),
                    paths.clone(),
                    Arc::clone(&sink),
                    &environment,
                    Mode::Service,
                )
            });
            let reports = StoreReports::spawn(Arc::clone(&store), node, stop.clone());
            let supervisor = Supervisor::new(&resolved.data_dir, build, reports);
            let (desired_tx, desired) =
                watch::channel(Desired::local(resolved.config.scan.clone()));
            tasks.push(tokio::spawn(follow_config(
                Arc::clone(&store),
                node,
                resolved.config.scan.clone(),
                desired_tx,
                stop.clone(),
            )));
            tasks.push(tokio::spawn(
                Arc::clone(&supervisor).run(desired, stop.clone()),
            ));
            tasks.push(tokio::spawn(commands::follow_local(
                Arc::clone(&store),
                node,
                Arc::new(ScanCommands(supervisor)),
                stop.clone(),
            )));
            tasks.push(tokio::spawn(relay.run(
                Arc::clone(&store),
                probe_sink,
                node,
                stop,
            )));
            format!("scan control; probe role of node {node} in process")
        }
        None => "scan control".to_owned(),
    };
    Ok((Scans { control, tasks }, summary))
}

/// Publishes what the probe role in process should apply: its row of
/// `scan.probe_config`, else the `[scan]` section, each time the row changes.
async fn follow_config(
    store: Arc<dyn Store>,
    node: NodeId,
    local: tenko_scan::config::ScanConfig,
    desired: watch::Sender<Desired>,
    mut stop: watch::Receiver<bool>,
) {
    let filter = WatchFilter::tables([PROBE_CONFIG.name().clone()]);
    let mut changes = None;
    loop {
        let revision = match store.read(ReadConsistency::Local).await {
            Ok(view) => {
                let wanted = match view.get_typed(&PROBE_CONFIG, &node.0) {
                    Ok(Some((record, revision))) => {
                        Some(Desired::synced(record.config, revision.0))
                    }
                    Ok(None) => Some(Desired::local(local.clone())),
                    Err(error) => {
                        tracing::warn!(%error, "the stored probe configuration does not read");
                        None
                    }
                };
                if let Some(wanted) = wanted {
                    desired.send_if_modified(|current| {
                        if *current == wanted {
                            false
                        } else {
                            *current = wanted;
                            true
                        }
                    });
                }
                Some(view.revision())
            }
            Err(error) => {
                tracing::debug!(%error, "the probe configuration could not be read");
                None
            }
        };
        if changes.is_none() {
            changes =
                revision.and_then(|revision| store.watch(Some(revision), filter.clone()).ok());
        }
        let woke = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            () = tokio::time::sleep(REFRESH) => true,
            item = async {
                if let Some(stream) = changes.as_mut() {
                    stream.next().await
                } else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    None
                }
            } => matches!(item, Some(Ok(_))),
        };
        if !woke {
            changes = None;
        }
    }
}

/// The scope reports of the probe role in process, written to `scan.scopes` in a task of
/// their own; a report that cannot be written (the controller cannot write) is tried again
/// until a newer one replaces it.
struct StoreReports {
    latest: watch::Sender<Option<v1::ConfigReport>>,
}

impl StoreReports {
    fn spawn(store: Arc<dyn Store>, node: NodeId, mut stop: watch::Receiver<bool>) -> Arc<Self> {
        let (latest, mut reports) = watch::channel::<Option<v1::ConfigReport>>(None);
        tokio::spawn(async move {
            loop {
                let report = reports.borrow_and_update().clone();
                if let Some(report) = report
                    && let Some(probe) = &report.probe
                {
                    let scope = ProbeScope::from_report(node, &report, probe, Timestamp::now());
                    if let Err(error) = record_scope(store.as_ref(), node, scope).await {
                        tracing::debug!(code = %error.code(), "the probe scope could not be written; trying again: {}", error.detail());
                        tokio::select! {
                            _ = stop.wait_for(|stopped| *stopped) => return,
                            () = tokio::time::sleep(REPORT_RETRY) => {}
                            changed = reports.changed() => if changed.is_err() { return; },
                        }
                        continue;
                    }
                }
                tokio::select! {
                    _ = stop.wait_for(|stopped| *stopped) => return,
                    changed = reports.changed() => if changed.is_err() { return; },
                }
            }
        });
        Arc::new(Self { latest })
    }
}

impl ScopeReports for StoreReports {
    fn report(&self, report: v1::ConfigReport) {
        self.latest.send_replace(Some(report));
    }
}

/// The SNMP secrets of the probe role in process, from this controller's vault, resolved
/// like a probe node's (`cluster.node.secrets` in the audit log) and held in memory only.
struct LocalSecrets {
    sync: NodeSync,
    node: NodeId,
}

impl std::fmt::Debug for LocalSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSecrets")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SecretSource for LocalSecrets {
    async fn fetch(&self, secrets: &[SecretId]) -> Result<VaultSecrets, ScanError> {
        let values = resolve_for(
            &self.sync,
            self.node,
            &format!("controller-{}", self.node),
            &[Role::Probe],
            &[SNMP_SECRET_PURPOSE.to_owned()],
        )
        .await
        .map_err(|error| {
            ScanError::unavailable(format!("[{}] {}", error.code(), error.detail()))
        })?;
        Ok(vault_secrets(
            values
                .iter()
                .map(|value| (value.secret, value.value.expose())),
            secrets,
        ))
    }
}
