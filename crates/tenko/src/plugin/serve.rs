//! The connector service of `tenko serve`: the plugin registry (bundled and
//! `<data_dir>/plugins`), the connector host with its job steps, its supervisor task, the
//! request extension of the API, and the `connectors` events of process and health changes.

use std::{path::Path, sync::Arc};

use tenko_api::{
    sse::{EventData, EventHub, Topic},
    state::AppState,
};
use tenko_connect::host::{
    ConnectorHost, HostConfig, normalize::ObservationSink, registry::PluginRegistry,
};
use tenko_core::{ConnectorId, ObjectRef};
use tenko_jobs::JobEngine;
use tenko_store::Store;
use tenko_vault::{StoreVault, Vault};
use tokio::{
    sync::{broadcast::error::RecvError, watch},
    task::JoinHandle,
};

use crate::serve::StartError;

/// The directory of installed plugins under the data directory.
pub const PLUGINS_DIR: &str = "plugins";

/// The `kind` of the `connectors` event that announces a change of an instance's plugin
/// process or health (no store change, so no revision).
pub const HEALTH_EVENT: &str = "connect.health";

/// The running connector service.
pub struct Connectors {
    host: Arc<ConnectorHost>,
    task: Option<JoinHandle<()>>,
    /// Turns true when the server stops.
    stop: watch::Receiver<bool>,
}

impl std::fmt::Debug for Connectors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connectors").finish_non_exhaustive()
    }
}

/// The registry of this binary: its bundled plugins and the plugins installed under
/// `plugins_dir`.
///
/// # Errors
///
/// A message when the path of this executable cannot be found.
pub fn registry(plugins_dir: Option<std::path::PathBuf>) -> Result<PluginRegistry, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("the path of this executable is unknown: {error}"))?;
    Ok(PluginRegistry::new(
        super::bundled::registry_entries(&exe),
        plugins_dir,
    ))
}

/// Builds the connector service, registers its job steps and starts its supervisor task,
/// which stops every plugin when `stop` turns true. Observations go to `sink`: the
/// reconciler's ingest when the IPAM module runs, else a sink that keeps nothing (each run
/// still records its counts).
///
/// # Errors
///
/// A [`StartError`] of the step `connectors` when the registry cannot be built.
pub async fn start(
    store: &Arc<dyn Store>,
    vault: &Arc<StoreVault>,
    engine: &JobEngine,
    data_dir: &Path,
    stop: watch::Receiver<bool>,
    sink: Arc<dyn ObservationSink>,
) -> Result<(Connectors, String), StartError> {
    let plugins_dir = data_dir.join(PLUGINS_DIR);
    let registry = registry(Some(plugins_dir.clone()))
        .map_err(|message| StartError::new("connectors", "start.connectors.registry", message))?;
    let plugins = registry.list();
    let usable = plugins.iter().filter(|plugin| plugin.usable).count();
    for plugin in plugins.iter().filter(|plugin| !plugin.usable) {
        tracing::warn!(
            plugin = %plugin.name,
            "plugin `{}` cannot run here: {}",
            plugin.name,
            plugin
                .problems
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let host = ConnectorHost::new(
        Arc::clone(store),
        Some(Arc::clone(vault) as Arc<dyn Vault>),
        registry,
        HostConfig::default(),
        sink,
    );
    host.register_steps(engine);
    let task = host.start(stop.clone());
    let summary = format!(
        "{usable} of {} plugin(s) usable, installed plugins in {}",
        plugins.len(),
        plugins_dir.display()
    );
    Ok((
        Connectors {
            host,
            task: Some(task),
            stop,
        },
        summary,
    ))
}

impl Connectors {
    /// The supervisor task, for the server's stop sequence (it ends after every plugin
    /// stopped). A second call returns a finished task.
    pub fn task(&mut self) -> JoinHandle<()> {
        self.task.take().unwrap_or_else(|| tokio::spawn(async {}))
    }

    /// Adds the connector host to the request extensions of the API.
    pub fn register(&self, server: &mut tenko_api::ServerConfig) {
        server.extensions.insert(Arc::clone(&self.host));
    }

    /// The connector host.
    pub fn host(&self) -> &Arc<ConnectorHost> {
        &self.host
    }

    /// Publishes a `connectors` event on the event hub of `state` whenever the plugin
    /// process or the health of an instance changes on this node, until the server stops.
    /// The process state and the remote health are not in the store, so no store write
    /// announces them; without these events the instance page, the connectors list and the
    /// dashboard tile would keep showing `starting` until something else is written.
    ///
    /// The events go through the same hub, topic and authorization filter as the store's
    /// events of the instance (objects: the instance), as system events: no revision and no
    /// SSE id, so they are not replayed.
    pub fn publish_health(&self, state: &AppState) {
        let mut changes = self.host.health_changes();
        let host = Arc::clone(&self.host);
        let events = state.events().clone();
        let mut stop = self.stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                    received = changes.recv() => match received {
                        Ok(id) => publish(&events, &[id]),
                        // Some changes were missed: every instance may have changed.
                        Err(RecvError::Lagged(_)) => publish(&events, &host.supervised()),
                        Err(RecvError::Closed) => return,
                    },
                }
            }
        });
    }
}

/// Publishes one `connectors` health event naming `ids` (none: nothing to publish).
fn publish(events: &EventHub, ids: &[ConnectorId]) {
    if ids.is_empty() {
        return;
    }
    let mut data = EventData::new(Topic::Connectors, None);
    data.objects = ids.iter().copied().map(ObjectRef::from).collect();
    data.kind = Some(HEALTH_EVENT.to_owned());
    events.publish_system(&data);
}
