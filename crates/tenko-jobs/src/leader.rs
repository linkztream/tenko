//! The job runner as a leader-only service (plan section 2.3, WP3.1b).
//!
//! In a cluster of controllers one runner drives the jobs of the installation: the one of
//! the leader. [`JobEngine::leader_service`] hands it to the leader supervisor of
//! `tenko serve`, which starts it with the leader epoch of each term of office and stops it
//! when the controller loses leadership or shuts down. Jobs pinned to a controller run on
//! that controller's own runner ([`JobEngine::start_pinned`]) instead.

use std::{sync::Arc, time::Duration};

use tenko_core::cluster::LeaderService;
use tokio_util::sync::CancellationToken;

use crate::{JobEngine, runner::RunnerExit};

/// How long a stopping runner may take to let the steps in flight reach a boundary.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The name of the service in the log and in `/system/status`.
pub const RUNNER_SERVICE: &str = "jobs.runner";

/// The leader's job runner (`jobs.runner`).
struct RunnerService {
    engine: JobEngine,
}

impl JobEngine {
    /// The job runner of this engine as a leader-only service (`jobs.runner`): each term of
    /// office runs [`start_leader`](Self::start_leader) with its epoch; a deposed runner
    /// ends the service with an error, so the supervisor takes office again if this
    /// controller still leads.
    pub fn leader_service(&self) -> Arc<dyn LeaderService> {
        Arc::new(RunnerService {
            engine: self.clone(),
        })
    }
}

#[async_trait::async_trait]
impl LeaderService for RunnerService {
    fn name(&self) -> &'static str {
        RUNNER_SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut runner = self
            .engine
            .start_leader(epoch)
            .map_err(|error| error.to_string())?;
        let exit = tokio::select! {
            () = stop.cancelled() => None,
            exit = runner.wait() => Some(exit),
        };
        match exit {
            None => {
                if tokio::time::timeout(STOP_TIMEOUT, runner.stop())
                    .await
                    .is_err()
                {
                    tracing::warn!("the leader's job runner did not stop in time");
                }
                Ok(())
            }
            Some(RunnerExit::Deposed { epoch }) => Err(format!(
                "deposed: the leader epoch moved past {epoch}, another controller took office"
            )),
            Some(RunnerExit::Stopped) => Err("the job runner ended".to_owned()),
        }
    }
}
