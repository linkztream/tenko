//! Supervision of one plugin process: start, liveness pings, restart with backoff, the
//! circuit breaker, and graceful shutdown.
//!
//! A [`SupervisorHandle`] owns a task that keeps the plugin running. The task publishes a
//! [`SupervisorStatus`] after every change and the current [`PluginClient`] while the
//! plugin runs; callers take the client for one call ([`SupervisorHandle::client`]) and
//! never hold the process. A crash, a failed start or a plugin that stops answering its
//! pings is a failure: the task waits for the backoff of [`Restarts`] and starts the plugin
//! again; too many failures open the circuit for a while. Starts that cannot succeed (a
//! protocol mismatch, an invalid or different manifest) leave the supervisor `failed`
//! until it is restarted. Nothing here touches the API or the data plane: a failing plugin
//! is a status, never an error that leaves this task.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tenko_core::{Coded, CodedError, Timestamp};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use utoipa::ToSchema;

use super::{
    backoff::{BackoffPolicy, CircuitPolicy, Decision, Restarts},
    client::PluginClient,
    launch::{LaunchError, LaunchOptions, LaunchSpec, Launched, launch},
};
use crate::ConnectorError;

/// How a plugin is supervised.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// How it is started.
    pub launch: LaunchOptions,
    /// Interval of liveness pings.
    pub ping_interval: Duration,
    /// Timeout of one ping.
    pub ping_timeout: Duration,
    /// Consecutive failed pings after which the plugin is restarted.
    pub ping_failures: u32,
    /// How long a stopping plugin may take before it is killed.
    pub shutdown_grace: Duration,
    /// Delays between restarts.
    pub backoff: BackoffPolicy,
    /// When restarts pause.
    pub circuit: CircuitPolicy,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            launch: LaunchOptions::default(),
            ping_interval: Duration::from_secs(10),
            ping_timeout: Duration::from_secs(3),
            ping_failures: 3,
            shutdown_grace: Duration::from_secs(5),
            backoff: BackoffPolicy::default(),
            circuit: CircuitPolicy::default(),
        }
    }
}

/// The state of a supervised plugin process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessState {
    /// Not running and not about to start (stopped by the host, or never started).
    Stopped,
    /// Starting: spawn, handshake, connect.
    Starting {
        /// The start attempt since the last healthy run, from 1.
        attempt: u32,
    },
    /// Running and answering.
    Running {
        /// Since when.
        since: Timestamp,
        /// The process id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// The protocol version in use.
        protocol: u32,
        /// The plugin version.
        version: String,
    },
    /// Waiting before the next start after a failure.
    Backoff {
        /// When the next start happens.
        until: Timestamp,
        /// The start attempt that follows.
        attempt: u32,
    },
    /// Too many failures: no start before `until`, then one trial start.
    CircuitOpen {
        /// When the trial start happens.
        until: Timestamp,
    },
    /// The plugin cannot start until something changes (a protocol mismatch, an invalid
    /// or different manifest); `last_error` says why.
    Failed,
}

impl ProcessState {
    /// The stable `snake_case` name of the state.
    pub fn name(&self) -> &'static str {
        match self {
            ProcessState::Stopped => "stopped",
            ProcessState::Starting { .. } => "starting",
            ProcessState::Running { .. } => "running",
            ProcessState::Backoff { .. } => "backoff",
            ProcessState::CircuitOpen { .. } => "circuit_open",
            ProcessState::Failed => "failed",
        }
    }
}

/// What the supervisor publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SupervisorStatus {
    /// The process state.
    #[serde(flatten)]
    pub state: ProcessState,
    /// How many times the plugin was started after its first start.
    pub restarts: u32,
    /// Failures since the last healthy run.
    pub consecutive_failures: u32,
    /// The last failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<CodedError>,
    /// When the status last changed.
    pub changed_at: Timestamp,
}

impl SupervisorStatus {
    fn new(state: ProcessState) -> Self {
        Self {
            state,
            restarts: 0,
            consecutive_failures: 0,
            last_error: None,
            changed_at: Timestamp::now(),
        }
    }

    /// Whether the plugin runs.
    pub fn is_running(&self) -> bool {
        matches!(self.state, ProcessState::Running { .. })
    }
}

enum Control {
    Restart,
    Stop(Option<oneshot::Sender<()>>),
}

/// The handle of one supervised plugin. Dropping it stops the plugin (without waiting).
pub struct SupervisorHandle {
    label: String,
    status: watch::Receiver<SupervisorStatus>,
    client: watch::Receiver<Option<PluginClient>>,
    control: mpsc::Sender<Control>,
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for SupervisorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorHandle")
            .field("label", &self.label)
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl SupervisorHandle {
    /// Starts supervising: the plugin starts at once.
    pub fn spawn(spec: LaunchSpec, config: SupervisorConfig) -> Self {
        let label = config
            .launch
            .log_label
            .clone()
            .unwrap_or_else(|| spec.label());
        let (status_tx, status) =
            watch::channel(SupervisorStatus::new(ProcessState::Starting { attempt: 1 }));
        let (client_tx, client) = watch::channel(None);
        let (control, control_rx) = mpsc::channel(8);
        let task = tokio::spawn(
            Supervisor {
                spec,
                config,
                label: label.clone(),
                status: status_tx,
                client: client_tx,
                control: control_rx,
                restarts_total: 0,
                started_once: false,
            }
            .run(),
        );
        Self {
            label,
            status,
            client,
            control,
            task: std::sync::Mutex::new(Some(task)),
        }
    }

    /// The current status.
    pub fn status(&self) -> SupervisorStatus {
        self.status.borrow().clone()
    }

    /// A receiver of every status change.
    pub fn subscribe(&self) -> watch::Receiver<SupervisorStatus> {
        self.status.clone()
    }

    /// The client of the running plugin, waiting up to `wait` for a start in progress.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::PluginUnavailable`] naming the state when the plugin does not run
    /// within `wait`.
    pub async fn client(&self, wait: Duration) -> Result<PluginClient, ConnectorError> {
        let mut client = self.client.clone();
        let current = client.borrow_and_update().clone();
        if let Some(current) = current {
            return Ok(current);
        }
        let waited = tokio::time::timeout(wait, async {
            loop {
                if client.changed().await.is_err() {
                    return None;
                }
                let current = client.borrow_and_update().clone();
                if current.is_some() {
                    return current;
                }
            }
        })
        .await;
        match waited {
            Ok(Some(client)) => Ok(client),
            _ => Err(self.unavailable()),
        }
    }

    /// The error of a call that finds the plugin not running.
    pub fn unavailable(&self) -> ConnectorError {
        let status = self.status();
        let detail = match &status.last_error {
            Some(error) => format!(
                "plugin `{}` is {} (last error {}: {})",
                self.label,
                status.state.name(),
                error.code,
                error.detail
            ),
            None => format!("plugin `{}` is {}", self.label, status.state.name()),
        };
        ConnectorError::PluginUnavailable(detail)
    }

    /// Restarts the plugin: a running plugin stops gracefully and starts again; a failed or
    /// backed-off one starts at once, with the failure count reset.
    pub async fn restart(&self) {
        let _ = self.control.send(Control::Restart).await;
    }

    /// Stops the plugin gracefully and waits for the supervisor to end.
    pub async fn stop(&self) {
        let (ack, acked) = oneshot::channel();
        if self.control.send(Control::Stop(Some(ack))).await.is_ok() {
            let _ = acked.await;
        }
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        // The task sees the closed channel and stops the plugin itself.
        let _ = self.control.try_send(Control::Stop(None));
    }
}

/// How a run of the plugin ended.
enum Ended {
    Exited(String),
    Unresponsive(u32),
    Restart,
    Stop(Option<oneshot::Sender<()>>),
}

/// What follows a run of the plugin.
enum After {
    /// It failed: back off and start again.
    Failed(CodedError),
    /// A restart was requested: start again at once.
    Restart,
    /// The supervisor ends.
    Done,
}

/// What a wait ended with.
enum Woken {
    Time,
    Restart,
    Stop(Option<oneshot::Sender<()>>),
}

struct Supervisor {
    spec: LaunchSpec,
    config: SupervisorConfig,
    label: String,
    status: watch::Sender<SupervisorStatus>,
    client: watch::Sender<Option<PluginClient>>,
    control: mpsc::Receiver<Control>,
    restarts_total: u32,
    started_once: bool,
}

impl Supervisor {
    async fn run(mut self) {
        let mut restarts = Restarts::new(self.config.backoff.clone(), self.config.circuit.clone());
        loop {
            if let Err(until) = restarts.may_start(Instant::now()) {
                self.publish(ProcessState::CircuitOpen { until: wall(until) }, &restarts);
                match self.wait_until(until).await {
                    Woken::Time => continue,
                    Woken::Restart => {
                        restarts.reset();
                        continue;
                    }
                    Woken::Stop(ack) => return self.stopped(ack, &restarts),
                }
            }
            let attempt = restarts.consecutive_failures() + 1;
            self.publish(ProcessState::Starting { attempt }, &restarts);
            let launched = tokio::select! {
                launched = launch(&self.spec, &self.config.launch) => launched,
                control = self.control.recv() => match control {
                    Some(Control::Restart) => {
                        restarts.reset();
                        continue;
                    }
                    Some(Control::Stop(ack)) => return self.stopped(ack, &restarts),
                    None => return self.stopped(None, &restarts),
                },
            };
            let failure = match launched {
                Ok(launched) => match self.supervise(launched, &mut restarts).await {
                    After::Failed(failure) => failure,
                    After::Restart => {
                        restarts.reset();
                        continue;
                    }
                    After::Done => return,
                },
                Err(error) if error.is_permanent() => {
                    tracing::error!(plugin = %self.label, %error, "the plugin cannot start");
                    self.fail(&error);
                    self.publish(ProcessState::Failed, &restarts);
                    match self.wait_for_control().await {
                        Woken::Restart | Woken::Time => {
                            restarts.reset();
                            continue;
                        }
                        Woken::Stop(ack) => return self.stopped(ack, &restarts),
                    }
                }
                Err(error) => {
                    tracing::warn!(plugin = %self.label, %error, "the plugin did not start");
                    error.to_coded_error()
                }
            };
            self.status
                .send_modify(|status| status.last_error = Some(failure.clone()));
            match restarts.on_failure(Instant::now(), random_u64()) {
                Decision::RetryAt { at, attempt } => {
                    self.publish(
                        ProcessState::Backoff {
                            until: wall(at),
                            attempt: attempt + 1,
                        },
                        &restarts,
                    );
                    match self.wait_until(at).await {
                        Woken::Time => {}
                        Woken::Restart => restarts.reset(),
                        Woken::Stop(ack) => return self.stopped(ack, &restarts),
                    }
                }
                Decision::OpenUntil(until) => {
                    tracing::error!(
                        plugin = %self.label,
                        failures = restarts.consecutive_failures(),
                        "the plugin keeps failing; restarts pause until {}",
                        wall(until)
                    );
                }
            }
        }
    }

    /// Runs one start of the plugin until it fails, is restarted on request or the
    /// supervisor ends.
    async fn supervise(&mut self, mut launched: Launched, restarts: &mut Restarts) -> After {
        restarts.on_started(Instant::now());
        if self.started_once {
            self.restarts_total = self.restarts_total.saturating_add(1);
        }
        self.started_once = true;
        let _ = self.client.send(Some(launched.client.clone()));
        self.publish(
            ProcessState::Running {
                since: Timestamp::now(),
                pid: launched.pid(),
                protocol: launched.protocol,
                version: launched.manifest.version.clone(),
            },
            restarts,
        );
        let ended = self.monitor(&mut launched, restarts).await;
        let _ = self.client.send(None);
        match ended {
            Ended::Exited(status) => {
                tracing::warn!(plugin = %self.label, %status, "the plugin exited");
                for task in launched.log_tasks.drain(..) {
                    // Let the forwarders take the last lines before they go.
                    let _ = tokio::time::timeout(Duration::from_millis(200), task).await;
                }
                After::Failed(CodedError::new(
                    "connect.plugin.exited",
                    503,
                    format!("the plugin exited ({status})"),
                ))
            }
            Ended::Unresponsive(misses) => {
                tracing::warn!(
                    plugin = %self.label,
                    misses,
                    "the plugin stopped answering its pings; it is killed"
                );
                let _ = launched.child.kill().await;
                After::Failed(CodedError::new(
                    "connect.plugin.unresponsive",
                    503,
                    format!("the plugin did not answer {misses} pings in a row"),
                ))
            }
            Ended::Restart => {
                let ended = launched.stop(self.config.shutdown_grace).await;
                tracing::info!(plugin = %self.label, %ended, "the plugin restarts on request");
                After::Restart
            }
            Ended::Stop(ack) => {
                let ended = launched.stop(self.config.shutdown_grace).await;
                tracing::info!(plugin = %self.label, %ended, "the plugin stopped");
                self.stopped(ack, restarts);
                After::Done
            }
        }
    }

    /// Watches a running plugin: its exit, its pings and the control channel.
    async fn monitor(&mut self, launched: &mut Launched, restarts: &mut Restarts) -> Ended {
        let mut ticker = tokio::time::interval(self.config.ping_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        let mut misses = 0u32;
        loop {
            tokio::select! {
                status = launched.child.wait() => {
                    return Ended::Exited(match status {
                        Ok(status) => status.to_string(),
                        Err(error) => error.to_string(),
                    });
                }
                _ = ticker.tick() => {
                    match launched.client.ping(self.config.ping_timeout).await {
                        Ok(_) => {
                            misses = 0;
                            restarts.on_healthy(Instant::now());
                            self.status.send_if_modified(|status| {
                                let changed = status.consecutive_failures
                                    != restarts.consecutive_failures();
                                status.consecutive_failures = restarts.consecutive_failures();
                                changed
                            });
                        }
                        Err(error) => {
                            misses += 1;
                            tracing::debug!(plugin = %self.label, %error, misses, "ping failed");
                            if misses >= self.config.ping_failures.max(1) {
                                return Ended::Unresponsive(misses);
                            }
                        }
                    }
                }
                control = self.control.recv() => {
                    return match control {
                        Some(Control::Restart) => Ended::Restart,
                        Some(Control::Stop(ack)) => Ended::Stop(ack),
                        None => Ended::Stop(None),
                    };
                }
            }
        }
    }

    /// Waits until `at` or a control message.
    async fn wait_until(&mut self, at: Instant) -> Woken {
        tokio::select! {
            () = tokio::time::sleep_until(at) => Woken::Time,
            control = self.control.recv() => match control {
                Some(Control::Restart) => Woken::Restart,
                Some(Control::Stop(ack)) => Woken::Stop(ack),
                None => Woken::Stop(None),
            },
        }
    }

    /// Waits for a control message.
    async fn wait_for_control(&mut self) -> Woken {
        match self.control.recv().await {
            Some(Control::Restart) => Woken::Restart,
            Some(Control::Stop(ack)) => Woken::Stop(ack),
            None => Woken::Stop(None),
        }
    }

    fn fail(&self, error: &LaunchError) {
        let coded = error.to_coded_error();
        self.status
            .send_modify(|status| status.last_error = Some(coded));
    }

    fn publish(&self, state: ProcessState, restarts: &Restarts) {
        let restarts_total = self.restarts_total;
        let failures = restarts.consecutive_failures();
        self.status.send_modify(|status| {
            status.state = state;
            status.restarts = restarts_total;
            status.consecutive_failures = failures;
            status.changed_at = Timestamp::now();
        });
    }

    fn stopped(&self, ack: Option<oneshot::Sender<()>>, restarts: &Restarts) {
        let _ = self.client.send(None);
        self.publish(ProcessState::Stopped, restarts);
        if let Some(ack) = ack {
            let _ = ack.send(());
        }
    }
}

/// The wall-clock time of a monotonic instant.
fn wall(at: Instant) -> Timestamp {
    let now = Instant::now();
    let ahead = at.saturating_duration_since(now);
    Timestamp::now()
        .checked_add(ahead)
        .unwrap_or_else(Timestamp::now)
}

/// A random number for the backoff jitter.
fn random_u64() -> u64 {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_serialize_flat_with_the_state_name() {
        let status = SupervisorStatus::new(ProcessState::Backoff {
            until: "2026-10-09T12:00:00Z".parse().expect("time"),
            attempt: 2,
        });
        let json = serde_json::to_value(&status).expect("json");
        assert_eq!(json["state"], "backoff");
        assert_eq!(json["attempt"], 2);
        assert_eq!(status.state.name(), "backoff");
        let back: SupervisorStatus = serde_json::from_value(json).expect("json");
        assert_eq!(back, status);
    }

    #[test]
    fn wall_times_are_in_the_future_for_future_instants() {
        let later = wall(Instant::now() + Duration::from_secs(60));
        assert!(later > Timestamp::now());
    }
}
