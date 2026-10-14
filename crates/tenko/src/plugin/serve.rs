//! The connector service of `tenko serve`: the plugin registry (bundled and
//! `<data_dir>/plugins`), the connector host with its job steps, its supervisor task, the
//! request extension of the API, and the `connectors` events of process and health changes.
//!
//! The plugin processes run on every controller; the poll schedule is the leader service
//! `connect.poll` ([`Connectors::leader_service`]). The host follows the security profile
//! in force (the stored one after setup, else the bootstrap profile of the configuration
//! file, as the `tls` step reads it): `tls = insecure` is allowed under the Lab profile only.

use std::{path::Path, sync::Arc, time::Duration};

use futures::StreamExt as _;

use tenko_api::{
    sse::{EventData, EventHub, Topic},
    state::AppState,
};
use tenko_auth::{model::SETTINGS, settings::Profile};
use tenko_connect::host::{
    ConnectorHost, HostConfig, normalize::ObservationSink, registry::PluginRegistry,
};
use tenko_core::{ConnectorId, ObjectRef, cluster::LeaderService};
use tenko_jobs::JobEngine;
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tenko_vault::{StoreVault, Vault};
use tokio::{
    sync::{
        broadcast::{self, error::RecvError},
        watch,
    },
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
/// still records its counts). `bootstrap` is the profile of the configuration file, which
/// applies until setup stores one.
///
/// # Errors
///
/// A [`StartError`] of the step `connectors` when the registry cannot be built or the
/// stored profile cannot be read.
pub async fn start(
    store: &Arc<dyn Store>,
    vault: &Arc<StoreVault>,
    engine: &JobEngine,
    data_dir: &Path,
    stop: watch::Receiver<bool>,
    sink: Arc<dyn ObservationSink>,
    bootstrap: Profile,
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
    // The stream opens before the first read, so no change falls between the two.
    let changes = store
        .watch(None, WatchFilter::tables([SETTINGS.name().clone()]))
        .ok();
    let lab = profile(store.as_ref(), bootstrap)
        .await
        .map_err(|error| StartError::coded("connectors", &error))?
        == Profile::Lab;
    let (insecure_tls, insecure_rx) = watch::channel(lab);
    tokio::spawn(follow_profile(
        Arc::clone(store),
        changes,
        bootstrap,
        insecure_tls,
        stop.clone(),
    ));
    let host = ConnectorHost::new(
        Arc::clone(store),
        Some(Arc::clone(vault) as Arc<dyn Vault>),
        registry,
        HostConfig {
            insecure_tls: insecure_rx,
            ..HostConfig::default()
        },
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

    /// The leader service `connect.poll` that runs the poll schedule.
    pub fn leader_service(&self) -> Arc<dyn LeaderService> {
        self.host.poll_service()
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
        let host = Arc::clone(&self.host);
        tokio::spawn(forward(
            self.host.health_changes(),
            move || host.supervised(),
            state.events().clone(),
            self.stop.clone(),
        ));
    }
}

/// Publishes a health event per received id, one event naming every id of `supervised`
/// after missed changes, until `stop` turns true or `changes` closes.
async fn forward(
    mut changes: broadcast::Receiver<ConnectorId>,
    supervised: impl Fn() -> Vec<ConnectorId> + Send + 'static,
    events: EventHub,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            received = changes.recv() => match received {
                Ok(id) => publish(&events, &[id]),
                // Some changes were missed: every instance may have changed.
                Err(RecvError::Lagged(_)) => publish(&events, &supervised()),
                Err(RecvError::Closed) => return,
            },
        }
    }
}

/// Publishes one `connectors` health event naming `ids` (none: nothing to publish).
fn publish(events: &EventHub, ids: &[ConnectorId]) {
    if let Some(data) = health_event(ids) {
        events.publish_system(&data);
    }
}

/// The `connectors` health event naming `ids` in order (none: no event).
fn health_event(ids: &[ConnectorId]) -> Option<EventData> {
    if ids.is_empty() {
        return None;
    }
    let mut data = EventData::new(Topic::Connectors, None);
    data.objects = ids.iter().copied().map(ObjectRef::from).collect();
    data.kind = Some(HEALTH_EVENT.to_owned());
    Some(data)
}

/// The profile in force: the stored one after setup, else `bootstrap`.
async fn profile(
    store: &dyn Store,
    bootstrap: Profile,
) -> Result<Profile, tenko_store::StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(view
        .get_typed(&SETTINGS, &())?
        .map_or(bootstrap, |(settings, _)| settings.profile))
}

/// Follows the security settings and tells the host whether `tls = insecure` is allowed,
/// until `stop` turns true.
async fn follow_profile(
    store: Arc<dyn Store>,
    mut stream: Option<tenko_store::ChangeStream>,
    bootstrap: Profile,
    allowed: watch::Sender<bool>,
    mut stop: watch::Receiver<bool>,
) {
    let filter = || WatchFilter::tables([SETTINGS.name().clone()]);
    loop {
        let alive = tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            alive = next_change(&mut stream) => alive,
        };
        if !alive {
            stream = store.watch(None, filter()).ok();
        }
        match profile(store.as_ref(), bootstrap).await {
            Ok(profile) => {
                allowed.send_if_modified(|lab| {
                    let next = profile == Profile::Lab;
                    std::mem::replace(lab, next) != next
                });
            }
            Err(error) => tracing::warn!(%error, "the security profile could not be read"),
        }
    }
}

/// Waits for the next change set; `false` when the stream ended or failed (it is opened
/// again).
async fn next_change(stream: &mut Option<tenko_store::ChangeStream>) -> bool {
    if let Some(stream) = stream {
        matches!(stream.next().await, Some(Ok(_)))
    } else {
        tokio::time::sleep(Duration::from_secs(5)).await;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tenko_api::sse::{EventRoutes, SseConfig};
    use tenko_core::Revision;

    use super::*;

    fn hub() -> EventHub {
        EventHub::new(SseConfig::default(), EventRoutes::empty(), Revision(0))
    }

    /// Waits until `events` has published `count` events.
    async fn published(events: &EventHub, count: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while events.published() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the event is published");
    }

    #[test]
    fn no_ids_make_no_event() {
        assert!(health_event(&[]).is_none());
    }

    #[test]
    fn the_event_names_the_ids_in_order() {
        let (a, b) = (ConnectorId::generate(), ConnectorId::generate());
        let data = health_event(&[a, b]).expect("an event");
        assert_eq!(data.topic, Topic::Connectors);
        assert_eq!(data.objects, vec![ObjectRef::from(a), ObjectRef::from(b)]);
        assert_eq!(data.kind.as_deref(), Some(HEALTH_EVENT));
        assert!(data.revision.is_none());
        assert_eq!(data.deleted.len(), 0);
    }

    #[tokio::test]
    async fn a_change_is_published() {
        let events = hub();
        let (tx, rx) = broadcast::channel(2);
        let (_stop_tx, stop) = watch::channel(false);
        let handle = tokio::spawn(forward(rx, Vec::new, events.clone(), stop));
        tx.send(ConnectorId::generate()).expect("a receiver");
        published(&events, 1).await;
        assert_eq!(events.published(), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn missed_changes_publish_the_supervised_instances() {
        let events = hub();
        let (tx, rx) = broadcast::channel(2);
        let (_stop_tx, stop) = watch::channel(false);
        let calls = Arc::new(AtomicUsize::new(0));
        let ids = vec![ConnectorId::generate(), ConnectorId::generate()];
        let supervised = {
            let calls = Arc::clone(&calls);
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                ids.clone()
            }
        };
        // Three ids before the task first receives overflow the capacity of two.
        for _ in 0..3 {
            tx.send(ConnectorId::generate()).expect("a receiver");
        }
        let handle = tokio::spawn(forward(rx, supervised, events.clone(), stop));
        published(&events, 1).await;
        assert!(calls.load(Ordering::SeqCst) >= 1);
        handle.abort();
    }

    #[tokio::test]
    async fn stopping_ends_the_task() {
        let events = hub();
        let (_tx, rx) = broadcast::channel(2);
        let (stop_tx, stop) = watch::channel(false);
        let handle = tokio::spawn(forward(rx, Vec::new, events, stop));
        stop_tx.send(true).expect("a receiver");
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the task ends")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_closed_channel_ends_the_task() {
        let events = hub();
        let (tx, rx) = broadcast::channel(2);
        let (_stop_tx, stop) = watch::channel(false);
        let handle = tokio::spawn(forward(rx, Vec::new, events, stop));
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the task ends")
            .expect("no panic");
    }
}
