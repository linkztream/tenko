//! Shared state of the API router.
//!
//! [`AppState`] carries the authenticator and authorizer (set by the server binary), the
//! store, and the platform services of this crate (event hub, metrics, node and listener
//! information). Domain services (IPAM, jobs, the concrete auth service) are not here:
//! the server binary adds them as `axum::Extension` layers.
//!
//! Build it with [`AppState::default`] (an in-memory store, for development and tests),
//! [`AppState::new`] or [`AppState::with_options`], then assign `auth` and `authorizer`:
//!
//! ```ignore
//! let mut state = AppState::new(store);
//! state.auth = Some(authenticator);
//! state.authorizer = Some(authorizer);
//! ```

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use arc_swap::ArcSwapOption;
use tenko_core::{Action, Authenticator, Authorizer, ObjectRef, Principal, Timestamp};
use tenko_store::{MemStore, Store};

use crate::{
    dto::system::NodeStatus,
    middleware::{idempotency::InFlight, metrics::Metrics},
    problem::ApiError,
    server::ListenerInfo,
    sse::{EventHub, EventRoutes, SseConfig},
};

/// Options of [`AppState::with_options`].
#[derive(Debug, Clone, Default)]
pub struct StateOptions {
    /// Settings of the event hub.
    pub sse: SseConfig,
    /// Routing of store tables to event topics.
    pub event_routes: EventRoutes,
    /// Identity and roles of this node, for `/system/status`.
    pub node: NodeStatus,
}

/// Shared services of the API.
///
/// The state is cloned for every request, so every member is a cheap handle.
#[derive(Clone)]
pub struct AppState {
    /// Resolves the credentials of a request into a principal.
    ///
    /// `None` only in development and in tests: every request then acts as the API itself.
    /// The server binary always sets it.
    pub auth: Option<Arc<dyn Authenticator>>,
    /// Decides what a principal may do. `None` means every check passes (development and
    /// tests only); the server binary always sets it.
    pub authorizer: Option<Arc<dyn Authorizer>>,
    /// The replicated store.
    pub store: Arc<dyn Store>,
    /// Services of the platform itself.
    pub(crate) platform: Arc<Platform>,
}

/// Services of the API platform.
pub(crate) struct Platform {
    /// The event hub of `GET /events`.
    pub(crate) events: EventHub,
    /// Request counters of `GET /metrics`.
    pub(crate) metrics: Metrics,
    /// Requests with an idempotency key that are being processed.
    pub(crate) in_flight: InFlight,
    /// When the state was built.
    pub(crate) started_at: Timestamp,
    pub(crate) started: Instant,
    /// This node.
    pub(crate) node: NodeStatus,
    /// The listener, once the server runs.
    pub(crate) listener: ArcSwapOption<ListenerInfo>,
    /// Readiness as set by the server binary.
    pub(crate) ready: AtomicBool,
}

impl Default for AppState {
    /// A state over an empty in-memory store, without authenticator or authorizer
    /// (development and tests).
    fn default() -> Self {
        Self::new(Arc::new(MemStore::default()))
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("auth", &self.auth.as_ref().map(|_| "<authenticator>"))
            .field(
                "authorizer",
                &self.authorizer.as_ref().map(|_| "<authorizer>"),
            )
            .field("events", &self.platform.events)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// A state over `store` with default options.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self::with_options(store, StateOptions::default())
    }

    /// A state over `store`. The event hub starts at the store's current revision.
    pub fn with_options(store: Arc<dyn Store>, options: StateOptions) -> Self {
        let start = store.status().revision;
        Self {
            auth: None,
            authorizer: None,
            platform: Arc::new(Platform {
                events: EventHub::new(options.sse, options.event_routes, start),
                metrics: Metrics::default(),
                in_flight: InFlight::default(),
                started_at: Timestamp::now(),
                started: Instant::now(),
                node: options.node,
                listener: ArcSwapOption::empty(),
                ready: AtomicBool::new(true),
            }),
            store,
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The event hub, for system events that do not come from the store
    /// ([`EventHub::publish_system`]) and for the authorization filter.
    pub fn events(&self) -> &EventHub {
        &self.platform.events
    }

    /// Marks the node ready or not ready for `GET /health/ready` (for example while the
    /// store catches up after a restart). Ready by default.
    pub fn set_ready(&self, ready: bool) {
        self.platform.ready.store(ready, Ordering::SeqCst);
    }

    /// Whether the node reports itself ready.
    pub fn is_ready(&self) -> bool {
        self.platform.ready.load(Ordering::SeqCst)
    }

    /// Checks an action with the authorizer; passes when none is configured.
    ///
    /// # Errors
    ///
    /// The authorizer's denial as problem details (401 or 403).
    pub fn authorize(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), ApiError> {
        match &self.authorizer {
            Some(authorizer) => Ok(authorizer.check(principal, action, object)?),
            None => Ok(()),
        }
    }
}
