//! The interim leader runner: starts the leader-only services
//! ([`LeaderService`]) when the store says this controller leads, and stops them when it
//! stops leading or the server stops. Taking office bumps the counter [`LEADER_EPOCH`]
//! atomically against its current value, so a service's fenced writes
//! (`tenko_store::fence`) fail once another controller has taken office.
//!
//! The leader supervisor of WP3.1b (restarts with a backoff, the services in
//! `/system/status`) replaces this module; until then the online KEK rotation runs here.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    RequestCtx, SystemComponent,
    cluster::{LEADER_EPOCH, LeaderService},
};
use tenko_store::{ReadConsistency, Store, StoreError, WriteBatch, fence};
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

/// How long to wait before trying to take office again after a store error.
const RETRY: Duration = Duration::from_secs(5);

/// A cancellation token that fires when `stop` is set (or its sender is gone).
pub(super) fn stop_token(mut stop: watch::Receiver<bool>) -> CancellationToken {
    let token = CancellationToken::new();
    let fire = token.clone();
    tokio::spawn(async move {
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                break;
            }
        }
        fire.cancel();
    });
    token
}

/// Runs `services` while this controller leads, until `stop` is set.
pub(super) fn spawn(
    store: Arc<dyn Store>,
    services: Vec<Arc<dyn LeaderService>>,
    stop: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(store, services, stop_token(stop)))
}

fn leads(leadership: &mut watch::Receiver<Option<tenko_store::Leadership>>) -> bool {
    leadership
        .borrow_and_update()
        .as_ref()
        .is_some_and(|leadership| leadership.is_self)
}

async fn run(
    store: Arc<dyn Store>,
    services: Vec<Arc<dyn LeaderService>>,
    stop: CancellationToken,
) {
    let mut leadership = store.leadership();
    loop {
        if !leads(&mut leadership) {
            tokio::select! {
                () = stop.cancelled() => return,
                changed = leadership.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue;
                }
            }
        }
        let epoch = match take_office(store.as_ref()).await {
            Ok(epoch) => epoch,
            Err(error) => {
                tracing::warn!(%error, "could not record the leader epoch; retrying");
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(RETRY) => continue,
                }
            }
        };
        tracing::info!(
            epoch,
            services = services.len(),
            "this controller leads: starting the leader services"
        );
        let term = stop.child_token();
        let mut set = JoinSet::new();
        for service in &services {
            let service = Arc::clone(service);
            let term = term.clone();
            set.spawn(async move {
                match service.run(epoch, term).await {
                    Ok(()) => tracing::info!(service = service.name(), "leader service stopped"),
                    Err(error) => {
                        tracing::error!(service = service.name(), %error, "leader service gave up");
                    }
                }
            });
        }
        while leads(&mut leadership) {
            tokio::select! {
                () = stop.cancelled() => break,
                changed = leadership.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
        term.cancel();
        while set.join_next().await.is_some() {}
        if stop.is_cancelled() {
            return;
        }
        tracing::info!("this controller no longer leads: the leader services stopped");
    }
}

/// Bumps [`LEADER_EPOCH`] against its current value and returns the new epoch.
async fn take_office(store: &dyn Store) -> Result<u64, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let current = view.counter(&LEADER_EPOCH)?;
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.preconditions.push(fence(current));
    batch.bump(LEADER_EPOCH);
    store.propose(batch).await?;
    Ok(current + 1)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use tenko_store::MemStore;
    use tokio::sync::Notify;

    use super::*;

    struct Recorder {
        epoch: AtomicU64,
        started: Notify,
    }

    #[async_trait::async_trait]
    impl LeaderService for Recorder {
        fn name(&self) -> &'static str {
            "test.recorder"
        }

        async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
            self.epoch.store(epoch, Ordering::Release);
            self.started.notify_one();
            stop.cancelled().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_runner_bumps_the_epoch_and_starts_the_services_on_a_single_controller() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let recorder = Arc::new(Recorder {
            epoch: AtomicU64::new(0),
            started: Notify::new(),
        });
        let (stop, receiver) = watch::channel(false);
        let runner = spawn(
            Arc::clone(&store),
            vec![Arc::clone(&recorder) as Arc<dyn LeaderService>],
            receiver,
        );
        tokio::time::timeout(Duration::from_secs(5), recorder.started.notified())
            .await
            .expect("the service starts");
        assert_eq!(recorder.epoch.load(Ordering::Acquire), 1);
        let view = store.read(ReadConsistency::Local).await.expect("a view");
        assert_eq!(view.counter(&LEADER_EPOCH).expect("a counter"), 1);
        stop.send(true).expect("a receiver");
        tokio::time::timeout(Duration::from_secs(5), runner)
            .await
            .expect("the runner ends")
            .expect("no panic");
    }
}
