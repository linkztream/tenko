//! Shared state of the API router.

/// Shared services of the API. WP1.7 fills it (store, authorizer, domain services).
///
/// The state is cloned for every request, so every member is a cheap handle (`Arc` or a
/// channel sender).
#[derive(Clone, Default)]
pub struct AppState {}
