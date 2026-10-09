//! The import service of WP1.5 (cargo feature `import`, on by default): staged uploads under
//! `<data_dir>/imports`, its job steps registered with the engine, and a purge of expired
//! uploads at start and every hour. Without the feature the import routes answer 503
//! `import.unavailable`; nothing else depends on it.
//!
//! Uploads are encrypted under a key that lives in this process only, so the files a
//! previous run staged can never be read again: the staging directory is emptied at start,
//! their sessions report `import.upload.lost` until the purge removes them, and an apply
//! job that was running rolls back.

use std::sync::Arc;
#[cfg(feature = "import")]
use std::time::Duration;

use tenko_ipam::IpamService;
use tenko_jobs::JobEngine;
use tenko_vault::StoreVault;
use tokio::{sync::watch, task::JoinHandle};

use super::StartError;
use crate::config::DataLayout;

/// How often expired uploads are removed.
#[cfg(feature = "import")]
const PURGE_INTERVAL: Duration = Duration::from_secs(3_600);

/// The import service, when this build has it.
pub(super) struct Imports {
    #[cfg(feature = "import")]
    service: Arc<tenko_ipam::import::ImportService>,
}

impl Imports {
    /// Creates the service and registers its job steps; returns a summary for the log.
    #[cfg(feature = "import")]
    pub(super) fn start(
        ipam: &Arc<IpamService>,
        engine: &JobEngine,
        vault: &Arc<StoreVault>,
        layout: &DataLayout,
    ) -> Result<(Self, String), StartError> {
        use tenko_ipam::import::{ImportConfig, ImportService};
        clear_staging(&layout.imports())?;
        let config = ImportConfig {
            staging_dir: layout.imports(),
            ..ImportConfig::default()
        };
        let summary = format!("import staging in {}", config.staging_dir.display());
        let service = ImportService::new(
            Arc::clone(ipam),
            engine.clone(),
            Some(Arc::clone(vault) as Arc<dyn tenko_vault::Vault>),
            config,
        )
        .map_err(|error| StartError::coded("ipam", &error))?;
        Ok((Self { service }, summary))
    }

    /// Without the feature: nothing to start.
    #[cfg(not(feature = "import"))]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the same signature as with the feature"
    )]
    pub(super) fn start(
        _ipam: &Arc<IpamService>,
        _engine: &JobEngine,
        _vault: &Arc<StoreVault>,
        _layout: &DataLayout,
    ) -> Result<(Self, String), StartError> {
        Ok((Self {}, "import service not in this build".to_owned()))
    }

    /// Adds the service to the request extensions of the API.
    #[cfg(feature = "import")]
    pub(super) fn register(&self, server: &mut tenko_api::ServerConfig) {
        server.extensions.insert(Arc::clone(&self.service));
    }

    /// Removes expired uploads at start and every hour until `stop` is set.
    #[cfg(feature = "import")]
    pub(super) fn spawn_purge(&self, stop: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
        vec![tokio::spawn(purge(Arc::clone(&self.service), stop))]
    }

    /// Without the feature: nothing to register.
    #[cfg(not(feature = "import"))]
    #[allow(clippy::unused_self, reason = "the same signature as with the feature")]
    pub(super) fn register(&self, _server: &mut tenko_api::ServerConfig) {}

    /// Without the feature: nothing to purge.
    #[cfg(not(feature = "import"))]
    #[allow(
        clippy::unused_self,
        clippy::needless_pass_by_value,
        reason = "the same signature as with the feature"
    )]
    pub(super) fn spawn_purge(&self, _stop: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
        Vec::new()
    }
}

/// Removes what a previous run staged; its key is gone, so the files are unreadable.
#[cfg(feature = "import")]
fn clear_staging(dir: &std::path::Path) -> Result<(), StartError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StartError::new(
            "ipam",
            "start.ipam.import_staging",
            format!(
                "cannot clear the import staging directory {}: {error}",
                dir.display()
            ),
        )),
    }
}

#[cfg(feature = "import")]
async fn purge(service: Arc<tenko_ipam::import::ImportService>, mut stop: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(PURGE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticker.tick() => {}
        }
        if *stop.borrow() {
            return;
        }
        match service.purge_expired().await {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "expired import uploads removed"),
            Err(error) => tracing::warn!(%error, "expired import uploads could not be removed"),
        }
    }
}
