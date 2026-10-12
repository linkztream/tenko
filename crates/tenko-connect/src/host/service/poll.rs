//! The leader service of the poll schedule (`connect.poll`) and the refusal of
//! `tls = insecure` outside the Lab profile.

use std::sync::{Arc, PoisonError, Weak};

use tenko_core::{CodedError, Timestamp, cluster::LeaderService};
use tokio_util::sync::CancellationToken;

use super::{ConnectorHost, Runtime, model::HostError};
use crate::{Health, HealthReport};

/// The name of the leader service that runs the poll schedule.
pub const POLL_SERVICE: &str = "connect.poll";

/// The code of the refusal of `tls = insecure` outside the Lab profile.
pub const INSECURE_REFUSED: &str = "connect.tls.insecure_refused";

/// Whether `settings` turn the certificate checks off (`tls = insecure`).
pub(super) fn insecure_tls(settings: &serde_json::Value) -> bool {
    settings.get("tls").and_then(serde_json::Value::as_str) == Some("insecure")
}

/// The refusal of `tls = insecure`.
fn refusal() -> HostError {
    HostError::new(
        INSECURE_REFUSED,
        422,
        "tls = insecure turns the certificate checks off and is allowed under the Lab profile \
         only; choose system, ca or fingerprint",
    )
    .with_param("field", "settings.tls")
}

impl ConnectorHost {
    /// The leader service `connect.poll`: while the supervisor runs it on this controller,
    /// the host starts the scheduled runs of its instances and fences their records with
    /// the epoch of the term.
    pub fn poll_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(PollService {
            host: Arc::downgrade(self),
        })
    }

    /// The leader epoch while this controller runs the poll schedule.
    pub(super) fn poll_epoch(&self) -> Option<u64> {
        *self
            .poll_epoch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether this controller runs the poll schedule now.
    pub fn polls(&self) -> bool {
        self.poll_epoch().is_some()
    }

    /// Refuses settings with `tls = insecure` unless the Lab profile is in force.
    pub(super) fn refuse_insecure_tls(
        &self,
        settings: &serde_json::Value,
    ) -> Result<(), HostError> {
        if insecure_tls(settings) && !*self.config.insecure_tls.borrow() {
            return Err(refusal());
        }
        Ok(())
    }

    /// Whether a running instance is refused for `tls = insecure`; if so, its health shows
    /// the refusal (degraded, with the code), and the refusal is logged once until the
    /// instance or the profile changes.
    pub(super) fn refused_at_run_time(&self, runtime: &Runtime) -> bool {
        let instance = runtime.instance();
        let refused = self.refuse_insecure_tls(&instance.settings).is_err();
        let mut logged = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if !refused {
            if logged.remove(&runtime.id).is_some() {
                // The next check replaces the refusal shown as health.
                let mut remote = runtime
                    .remote
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                remote.checked = None;
            }
            return false;
        }
        if logged.get(&runtime.id) == Some(&instance.updated.at) {
            return true;
        }
        logged.insert(runtime.id, instance.updated.at);
        drop(logged);
        tracing::warn!(
            connector = %runtime.id,
            plugin = %instance.plugin,
            code = INSECURE_REFUSED,
            "connector `{}` has tls = insecure, which only the Lab profile allows; it is not \
             polled or checked until its TLS settings change",
            instance.name
        );
        let error: CodedError = refusal().into_coded();
        {
            let mut remote = runtime
                .remote
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            remote.report = Some(HealthReport {
                health: Health::Degraded,
                checked_at: Timestamp::now(),
                latency_ms: None,
                remote_version: None,
                detail: Some(error.detail.clone()),
            });
            remote.error = Some(error);
        }
        self.health_changed(runtime.id);
        true
    }
}

/// The leader service `connect.poll` (see [`ConnectorHost::poll_service`]).
struct PollService {
    host: Weak<ConnectorHost>,
}

/// Clears the epoch of a term when the service ends, however it ends.
struct Term {
    host: Weak<ConnectorHost>,
    epoch: u64,
}

impl Drop for Term {
    fn drop(&mut self) {
        if let Some(host) = self.host.upgrade() {
            let mut current = host
                .poll_epoch
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *current == Some(self.epoch) {
                *current = None;
            }
        }
    }
}

#[async_trait::async_trait]
impl LeaderService for PollService {
    fn name(&self) -> &'static str {
        POLL_SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let Some(host) = self.host.upgrade() else {
            return Ok(());
        };
        *host
            .poll_epoch
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(epoch);
        drop(host);
        tracing::info!(epoch, "this controller polls the connector instances");
        let _term = Term {
            host: Weak::clone(&self.host),
            epoch,
        };
        stop.cancelled().await;
        tracing::info!(
            epoch,
            "this controller stopped polling the connector instances"
        );
        Ok(())
    }
}
