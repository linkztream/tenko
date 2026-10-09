//! Shared state of the API router.

use std::sync::Arc;

use tenko_core::{Authenticator, Authorizer};

/// Shared services of the API. The server binary fills it at start; WP1.7 adds the store
/// and the domain services as they land.
///
/// The state is cloned for every request, so every member is a cheap handle (`Arc` or a
/// channel sender).
#[derive(Clone, Default)]
pub struct AppState {
    /// Resolves the credentials of a request into a principal.
    ///
    /// `None` only in development and in tests: every request then acts as the API itself.
    /// The server binary always sets it.
    pub auth: Option<Arc<dyn Authenticator>>,
    /// Decides what a principal may do. `None` means every check passes (development and
    /// tests only); the server binary always sets it.
    pub authorizer: Option<Arc<dyn Authorizer>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("auth", &self.auth.as_ref().map(|_| "<authenticator>"))
            .field(
                "authorizer",
                &self.authorizer.as_ref().map(|_| "<authorizer>"),
            )
            .finish()
    }
}
