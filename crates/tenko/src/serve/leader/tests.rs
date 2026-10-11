//! The supervisor on a single controller (`MemStore` always leads as node 1) and on two
//! simulated members over one store (`SimulatedCluster`), whose leadership the tests move.

use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};

use tenko_store::{
    MemStore,
    testing::{ClusterFixture, SimulatedCluster},
};
use tokio::sync::Notify;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

fn quick() -> SupervisorConfig {
    SupervisorConfig {
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
    }
}

/// Records the epochs it ran with and waits for its stop.
struct Recorder {
    name: &'static str,
    epoch: AtomicU64,
    runs: AtomicU32,
    stops: AtomicU32,
    started: Notify,
}

impl Recorder {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            epoch: AtomicU64::new(0),
            runs: AtomicU32::new(0),
            stops: AtomicU32::new(0),
            started: Notify::new(),
        })
    }
}

#[async_trait::async_trait]
impl LeaderService for Recorder {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        self.epoch.store(epoch, Ordering::SeqCst);
        self.runs.fetch_add(1, Ordering::SeqCst);
        self.started.notify_waiters();
        stop.cancelled().await;
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Gives up `failures` times, then runs until stopped.
struct Flaky {
    failures: u32,
    runs: AtomicU32,
}

#[async_trait::async_trait]
impl LeaderService for Flaky {
    fn name(&self) -> &'static str {
        "test.flaky"
    }

    async fn run(&self, _epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let run = self.runs.fetch_add(1, Ordering::SeqCst);
        if run < self.failures {
            return Err(format!("failure {run}"));
        }
        stop.cancelled().await;
        Ok(())
    }
}

/// Panics at its first run.
struct Panics {
    runs: AtomicU32,
}

#[async_trait::async_trait]
impl LeaderService for Panics {
    fn name(&self) -> &'static str {
        "test.panics"
    }

    async fn run(&self, _epoch: u64, stop: CancellationToken) -> Result<(), String> {
        assert!(
            self.runs.fetch_add(1, Ordering::SeqCst) > 0,
            "the first run panics"
        );
        stop.cancelled().await;
        Ok(())
    }
}

async fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn epoch_of(store: &dyn Store) -> u64 {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    view.counter(&LEADER_EPOCH).expect("the counter")
}

fn state_of(view: &LeaderView, name: &str) -> LeaderServiceStatus {
    view.status()
        .services
        .into_iter()
        .find(|service| service.name == name)
        .expect("a registered service")
}

#[tokio::test]
async fn a_single_controller_takes_office_and_runs_every_service() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let first = Recorder::new("test.first");
    let second = Recorder::new("test.second");
    let registry = LeaderRegistry::new();
    registry.register(Arc::clone(&first) as Arc<dyn LeaderService>);
    registry.extend([Arc::clone(&second) as Arc<dyn LeaderService>]);
    assert_eq!(registry.names(), ["test.first", "test.second"]);
    let view = LeaderView::default();
    let handle = spawn(Arc::clone(&store), &registry, view.clone(), None, quick());
    until("both services run", || {
        first.runs.load(Ordering::SeqCst) == 1 && second.runs.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(first.epoch.load(Ordering::SeqCst), 1);
    assert_eq!(epoch_of(store.as_ref()).await, 1);
    let status = view.status();
    assert!(status.leads);
    assert_eq!(status.epoch, Some(1));
    assert_eq!(
        state_of(&view, "test.second").state,
        LeaderServiceState::Running
    );
    // The source of `GET /system/status` reads the same state.
    assert_eq!(view.source().current(), status);

    handle.stop(WAIT).await;
    assert_eq!(first.stops.load(Ordering::SeqCst), 1);
    assert_eq!(second.stops.load(Ordering::SeqCst), 1);
    let status = view.status();
    assert!(!status.leads);
    assert_eq!(
        state_of(&view, "test.first").state,
        LeaderServiceState::Idle
    );
}

#[tokio::test]
async fn a_service_that_gives_up_is_restarted_with_a_backoff() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let flaky = Arc::new(Flaky {
        failures: 3,
        runs: AtomicU32::new(0),
    });
    let panics = Arc::new(Panics {
        runs: AtomicU32::new(0),
    });
    let registry = LeaderRegistry::new();
    registry.register(Arc::clone(&flaky) as Arc<dyn LeaderService>);
    registry.register(Arc::clone(&panics) as Arc<dyn LeaderService>);
    let view = LeaderView::default();
    let handle = spawn(Arc::clone(&store), &registry, view.clone(), None, quick());
    until("the flaky service runs for good", || {
        flaky.runs.load(Ordering::SeqCst) == 4
            && state_of(&view, "test.flaky").state == LeaderServiceState::Running
    })
    .await;
    let status = state_of(&view, "test.flaky");
    assert_eq!(status.restarts, 3);
    assert_eq!(status.last_error.as_deref(), Some("failure 2"));
    until("the panicking service runs again", || {
        panics.runs.load(Ordering::SeqCst) == 2
    })
    .await;
    let status = state_of(&view, "test.panics");
    assert_eq!(status.restarts, 1);
    assert_eq!(status.last_error.as_deref(), Some("the service panicked"));
    // Restarts stay within the term: the epoch was taken once.
    assert_eq!(epoch_of(store.as_ref()).await, 1);
    handle.stop(WAIT).await;
}

#[tokio::test]
async fn a_service_registered_after_the_start_does_not_run() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let registry = LeaderRegistry::new();
    let early = Recorder::new("test.early");
    registry.register(Arc::clone(&early) as Arc<dyn LeaderService>);
    let view = LeaderView::default();
    let handle = spawn(Arc::clone(&store), &registry, view.clone(), None, quick());
    let late = Recorder::new("test.late");
    registry.register(Arc::clone(&late) as Arc<dyn LeaderService>);
    until("the early service runs", || {
        early.runs.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(late.runs.load(Ordering::SeqCst), 0);
    assert_eq!(view.status().services.len(), 1);
    handle.stop(WAIT).await;
}

#[tokio::test]
async fn leadership_moves_the_services_and_fences_the_old_epoch() {
    let cluster = SimulatedCluster::new(MemStore::default());
    let one: Arc<dyn Store> = cluster.member(tenko_core::NodeId(1));
    let two: Arc<dyn Store> = cluster.member(tenko_core::NodeId(2));
    let on_one = Recorder::new("test.service");
    let on_two = Recorder::new("test.service");
    let (registry_one, registry_two) = (LeaderRegistry::new(), LeaderRegistry::new());
    registry_one.register(Arc::clone(&on_one) as Arc<dyn LeaderService>);
    registry_two.register(Arc::clone(&on_two) as Arc<dyn LeaderService>);
    let (view_one, view_two) = (LeaderView::default(), LeaderView::default());
    let one_handle = spawn(
        Arc::clone(&one),
        &registry_one,
        view_one.clone(),
        None,
        quick(),
    );
    let two_handle = spawn(
        Arc::clone(&two),
        &registry_two,
        view_two.clone(),
        None,
        quick(),
    );

    until("member 1 runs the service", || {
        on_one.runs.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(on_one.epoch.load(Ordering::SeqCst), 1);
    assert_eq!(on_two.runs.load(Ordering::SeqCst), 0);
    assert!(!view_two.status().leads);
    assert_eq!(
        state_of(&view_two, "test.service").state,
        LeaderServiceState::Idle
    );

    cluster.change_leader().await;
    until("member 2 runs the service", || {
        on_two.runs.load(Ordering::SeqCst) == 1
    })
    .await;
    until("member 1 stopped it", || {
        on_one.stops.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(on_two.epoch.load(Ordering::SeqCst), 2);
    assert!(!view_one.status().leads);
    assert_eq!(view_two.status().epoch, Some(2));

    // A write of the deposed term fails on the epoch.
    let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Jobs));
    batch.preconditions.push(fence(1));
    batch.bump(tenko_core::CounterKey::new("jobs.test_fenced"));
    assert!(matches!(
        one.propose(batch).await,
        Err(StoreError::PreconditionFailed(_))
    ));

    one_handle.stop(WAIT).await;
    two_handle.stop(WAIT).await;
}

/// Fails once its epoch is no longer the store's, like a fenced service.
struct Fenced {
    store: Arc<dyn Store>,
    epochs: Mutex<Vec<u64>>,
}

#[async_trait::async_trait]
impl LeaderService for Fenced {
    fn name(&self) -> &'static str {
        "test.fenced"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        self.epochs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(epoch);
        loop {
            if epoch_of(self.store.as_ref()).await != epoch {
                return Err("deposed".to_owned());
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    }
}

#[tokio::test]
async fn a_leader_whose_epoch_moved_takes_office_again() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let fenced = Arc::new(Fenced {
        store: Arc::clone(&store),
        epochs: Mutex::new(Vec::new()),
    });
    let registry = LeaderRegistry::new();
    registry.register(Arc::clone(&fenced) as Arc<dyn LeaderService>);
    let view = LeaderView::default();
    let handle = spawn(Arc::clone(&store), &registry, view.clone(), None, quick());
    until("the service runs with epoch 1", || {
        view.status().epoch == Some(1)
    })
    .await;
    // Another writer bumps the epoch, as a forwarded bump of a deposed leader would.
    take_office(store.as_ref()).await.expect("a bump");
    until("a new term with epoch 3", || view.status().epoch == Some(3)).await;
    let epochs = fenced
        .epochs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(epochs.first(), Some(&1));
    assert_eq!(epochs.last(), Some(&3));
    handle.stop(WAIT).await;
}
