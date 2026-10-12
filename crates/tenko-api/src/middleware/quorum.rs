//! The quorum gate of the API (OPS-26, ADR 0013): what a controller does while it is cut
//! off from the quorum of its cluster.
//!
//! A controller whose store reports [`QuorumState::Electing`] or [`QuorumState::Isolated`]
//! is in the isolated mode:
//!
//! - **Every API answer** carries [`STALENESS_HEADER`],
//!   `Tenko-Staleness: since=<RFC 3339>; revision=<n>`: when the state began and the
//!   revision of the local copy the answer was read from ([`Staleness`]).
//! - **Every mutating request** is refused with 503 [`NO_QUORUM`], `Retry-After` and the
//!   parameters `since`, `state`, `revision` and `queueable` (whether `POST /queue` takes
//!   the request, see [`crate::routes::queue`]), before any planning. Reads keep serving
//!   the local copy.
//! - **Exempt** are the requests that write nothing to the store: a dry run
//!   (`?dry_run=true` on an operation that documents the parameter) and the operations of
//!   the controller's local queue (`POST /queue`, `DELETE /queue/{id}`).
//!
//! A controller that is `single` or `healthy` adds nothing. The gate runs in the API route
//! layer after authentication and before the idempotency replay, so a refused request
//! records no idempotency key. It is a courtesy, not the guard: a write that slips through
//! (the state changed in between) fails in the store with `sys.store.no_quorum`.

use std::{collections::BTreeSet, fmt, str::FromStr, sync::OnceLock};

use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue, Method, header},
    response::{IntoResponse, Response},
};
use tenko_core::{Revision, Timestamp};
use tenko_store::QuorumState;

use crate::{API_BASE, problem::ApiError, state::AppState};

/// The error code of a write refused by a controller without quorum.
pub const NO_QUORUM: &str = "cluster.no_quorum";

/// The header of every answer of a controller in the isolated mode.
pub const STALENESS_HEADER: HeaderName = HeaderName::from_static("tenko-staleness");

/// `Retry-After` of a refusal while an election runs, in seconds.
pub const RETRY_ELECTING_SECS: u32 = 5;

/// `Retry-After` of a refusal while the controller is isolated, in seconds.
pub const RETRY_ISOLATED_SECS: u32 = 15;

/// The age of the local copy of a controller in the isolated mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Staleness {
    /// When the controller lost its leader (electing) or its quorum (isolated).
    pub since: Timestamp,
    /// The revision of the local copy.
    pub revision: Revision,
}

impl Staleness {
    /// The staleness of a controller in `quorum` whose store is at `revision`; `None` for a
    /// controller that accepts writes.
    pub fn of(quorum: &QuorumState, revision: Revision) -> Option<Self> {
        match *quorum {
            QuorumState::Single | QuorumState::Healthy => None,
            QuorumState::Electing { since } => Some(Self { since, revision }),
            QuorumState::Isolated { since, applied, .. } => Some(Self {
                since,
                revision: applied,
            }),
        }
    }
}

impl fmt::Display for Staleness {
    /// The header value: `since=<RFC 3339>; revision=<n>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "since={}; revision={}",
            self.since.to_rfc3339(),
            self.revision.0
        )
    }
}

/// The value of [`STALENESS_HEADER`] cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidStaleness;

impl fmt::Display for InvalidStaleness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected `since=<RFC 3339>; revision=<n>`")
    }
}

impl std::error::Error for InvalidStaleness {}

impl FromStr for Staleness {
    type Err = InvalidStaleness;

    /// Reads a header value; the parameters may come in any order, unknown ones are
    /// ignored, both known ones are required.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut since = None;
        let mut revision = None;
        for part in text.split(';') {
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match name.trim().to_ascii_lowercase().as_str() {
                "since" => since = value.parse::<Timestamp>().ok(),
                "revision" => revision = value.parse::<u64>().ok().map(Revision),
                _ => {}
            }
        }
        match (since, revision) {
            (Some(since), Some(revision)) => Ok(Self { since, revision }),
            _ => Err(InvalidStaleness),
        }
    }
}

/// The quorum state of the controller, read once per request.
#[derive(Debug, Clone)]
pub(crate) struct Quorum {
    state: QuorumState,
    staleness: Option<Staleness>,
}

impl Quorum {
    /// The state of the store of `app`.
    pub(crate) fn read(app: &AppState) -> Self {
        let status = app.store.status();
        let staleness = Staleness::of(&status.quorum, status.revision);
        Self {
            state: status.quorum,
            staleness,
        }
    }

    /// The refusal of `request`, or `None` to let it through.
    pub(crate) fn check(&self, request: &Request) -> Option<Response> {
        let staleness = self.staleness?;
        let template = request
            .extensions()
            .get::<MatchedPath>()
            .map(|path| relative(path.as_str()).to_owned());
        if !writes(request.method(), template.as_deref(), request.uri().query()) {
            return None;
        }
        let queueable = template
            .as_deref()
            .is_some_and(|template| crate::routes::queue::queueable(request.method(), template));
        Some(refusal(&self.state, staleness, queueable))
    }

    /// Adds [`STALENESS_HEADER`] to an answer of a controller in the isolated mode.
    pub(crate) fn stamp(&self, response: &mut Response) {
        if let Some(staleness) = self.staleness
            && let Ok(value) = HeaderValue::from_str(&staleness.to_string())
        {
            response.headers_mut().insert(STALENESS_HEADER, value);
        }
    }
}

/// The 503 [`NO_QUORUM`] answer.
fn refusal(state: &QuorumState, staleness: Staleness, queueable: bool) -> Response {
    let (name, retry) = match state {
        QuorumState::Electing { .. } => ("electing", RETRY_ELECTING_SECS),
        _ => ("isolated", RETRY_ISOLATED_SECS),
    };
    let detail = if queueable {
        format!(
            "this controller has no contact with the quorum of its cluster ({name} since {}); \
             the change was not made: retry in {retry} s, use another controller, or queue \
             it with POST {API_BASE}/queue",
            staleness.since.to_rfc3339()
        )
    } else {
        format!(
            "this controller has no contact with the quorum of its cluster ({name} since {}); \
             the change was not made: retry in {retry} s or use another controller",
            staleness.since.to_rfc3339()
        )
    };
    let mut response = ApiError::new(NO_QUORUM, 503, detail)
        .with_param("since", staleness.since.to_rfc3339())
        .with_param("state", name)
        .with_param("revision", staleness.revision.0.to_string())
        .with_param("queueable", queueable.to_string())
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry));
    response
}

/// A route template relative to [`API_BASE`].
fn relative(template: &str) -> &str {
    template.strip_prefix(API_BASE).unwrap_or(template)
}

/// Whether a request would write to the store: a method other than `GET`, `HEAD` and
/// `OPTIONS`, unless it is a dry run of an operation that takes `dry_run` or an operation
/// of the local queue.
fn writes(method: &Method, template: Option<&str>, query: Option<&str>) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let Some(template) = template else {
        // No route matched: the answer is a 404 or 405 that writes nothing.
        return false;
    };
    if crate::routes::queue::local(method, template) {
        return false;
    }
    !(is_dry_run(query) && takes_dry_run(method, template))
}

/// Whether the query asks for a dry run: exactly one `dry_run` parameter with a true value.
fn is_dry_run(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    let Ok(uri) = format!("/?{query}").parse::<axum::http::Uri>() else {
        return false;
    };
    let Ok(filters) = crate::list::Filters::from_uri(&uri) else {
        return false;
    };
    matches!(
        filters.all("dry_run").as_slice(),
        [value] if matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
    )
}

/// Whether the operation documents the `dry_run` parameter, from the OpenAPI document.
fn takes_dry_run(method: &Method, template: &str) -> bool {
    static OPERATIONS: OnceLock<BTreeSet<(String, String)>> = OnceLock::new();
    OPERATIONS
        .get_or_init(dry_run_operations)
        .contains(&(method.as_str().to_owned(), template.to_owned()))
}

/// Every (method, template relative to [`API_BASE`]) whose operation takes `dry_run`.
fn dry_run_operations() -> BTreeSet<(String, String)> {
    use utoipa::openapi::{
        RefOr,
        path::{HttpMethod, ParameterIn},
    };
    let document = crate::openapi();
    let mut operations = BTreeSet::new();
    for (path, item) in &document.paths.paths {
        let methods = [
            (HttpMethod::Post, &item.post),
            (HttpMethod::Put, &item.put),
            (HttpMethod::Patch, &item.patch),
            (HttpMethod::Delete, &item.delete),
        ];
        for (method, operation) in methods {
            let Some(operation) = operation else {
                continue;
            };
            let takes = operation.parameters.iter().flatten().any(|parameter| {
                matches!(
                    parameter,
                    RefOr::T(parameter)
                        if parameter.name == "dry_run"
                            && matches!(parameter.parameter_in, ParameterIn::Query)
                )
            });
            if takes {
                let name = match method {
                    HttpMethod::Post => "POST",
                    HttpMethod::Put => "PUT",
                    HttpMethod::Patch => "PATCH",
                    _ => "DELETE",
                };
                operations.insert((name.to_owned(), relative(path).to_owned()));
            }
        }
    }
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("timestamp")
    }

    #[test]
    fn staleness_is_absent_while_writes_commit() {
        assert_eq!(Staleness::of(&QuorumState::Single, Revision(4)), None);
        assert_eq!(Staleness::of(&QuorumState::Healthy, Revision(4)), None);
    }

    #[test]
    fn staleness_of_an_isolated_controller_names_its_applied_revision() {
        let since = at("2026-10-11T12:00:00Z");
        let isolated = QuorumState::Isolated {
            since,
            last_contact: None,
            applied: Revision(41),
        };
        assert_eq!(
            Staleness::of(&isolated, Revision(42)),
            Some(Staleness {
                since,
                revision: Revision(41)
            })
        );
        let electing = QuorumState::Electing { since };
        assert_eq!(
            Staleness::of(&electing, Revision(42)).map(|s| s.revision),
            Some(Revision(42))
        );
    }

    #[test]
    fn the_header_value_round_trips() {
        let staleness = Staleness {
            since: at("2026-10-11T12:00:00Z"),
            revision: Revision(7),
        };
        let text = staleness.to_string();
        assert_eq!(text, "since=2026-10-11T12:00:00Z; revision=7");
        assert_eq!(text.parse::<Staleness>(), Ok(staleness));
        assert_eq!(
            "revision=7;since=\"2026-10-11T12:00:00Z\"; extra=1".parse::<Staleness>(),
            Ok(staleness)
        );
        assert_eq!(
            "since=yesterday; revision=7".parse::<Staleness>(),
            Err(InvalidStaleness)
        );
        assert_eq!("revision=7".parse::<Staleness>(), Err(InvalidStaleness));
    }

    #[test]
    fn only_a_single_true_dry_run_counts() {
        assert!(is_dry_run(Some("dry_run=true")));
        assert!(is_dry_run(Some("acknowledge=x&dry_run=1")));
        assert!(!is_dry_run(Some("dry_run=false")));
        assert!(!is_dry_run(Some("dry_run=true&dry_run=false")));
        assert!(!is_dry_run(None));
    }

    #[test]
    fn reads_unmatched_paths_dry_runs_and_the_local_queue_write_nothing() {
        assert!(!writes(&Method::GET, Some("/addresses"), None));
        assert!(!writes(&Method::POST, None, None));
        assert!(writes(&Method::POST, Some("/addresses"), None));
        assert!(!writes(
            &Method::POST,
            Some("/addresses"),
            Some("dry_run=true")
        ));
        assert!(!writes(
            &Method::PATCH,
            Some("/addresses/{id}"),
            Some("dry_run=true")
        ));
        assert!(!writes(&Method::POST, Some("/queue"), None));
        assert!(!writes(&Method::DELETE, Some("/queue/{id}"), None));
        // The conflicts of the queue live in the store.
        assert!(writes(&Method::DELETE, Some("/queue/conflicts/{id}"), None));
    }

    #[test]
    fn a_dry_run_only_passes_where_the_operation_takes_one() {
        assert!(takes_dry_run(&Method::POST, "/addresses"));
        assert!(takes_dry_run(&Method::DELETE, "/prefixes/{id}"));
        // Users have no dry run: the parameter would be ignored and the write made.
        assert!(!takes_dry_run(&Method::POST, "/users"));
        assert!(writes(&Method::POST, Some("/users"), Some("dry_run=true")));
    }
}
