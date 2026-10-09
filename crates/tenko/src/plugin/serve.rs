//! The connector service of `tenko serve`: the plugin registry (bundled and
//! `<data_dir>/plugins`), the connector host with its job steps, its supervisor task, and
//! the request extension of the API.

use std::{path::Path, sync::Arc};

use tenko_connect::host::{
    ConnectorHost, HostConfig,
    normalize::{DiscardSink, ObservationSink},
    registry::PluginRegistry,
};
use tenko_jobs::JobEngine;
use tenko_store::Store;
use tenko_vault::{StoreVault, Vault};
use tokio::{sync::watch, task::JoinHandle};

use crate::serve::StartError;

/// The directory of installed plugins under the data directory.
pub const PLUGINS_DIR: &str = "plugins";

/// The running connector service.
pub struct Connectors {
    host: Arc<ConnectorHost>,
    task: Option<JoinHandle<()>>,
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
/// which stops every plugin when `stop` turns true. Observations go nowhere until the
/// reconciler (WP2.4) provides its sink; each run still records its counts.
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
        Arc::new(DiscardSink) as Arc<dyn ObservationSink>,
    );
    host.register_steps(engine);
    let task = host.start(stop);
    let summary = format!(
        "{usable} of {} plugin(s) usable, installed plugins in {}",
        plugins.len(),
        plugins_dir.display()
    );
    Ok((
        Connectors {
            host,
            task: Some(task),
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
}
