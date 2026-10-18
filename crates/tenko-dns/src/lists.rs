//! Block lists and allow lists (`dns.lists`, `dns.list_versions`; DNS-21, P2-Q6): the
//! list compiler and the version format, shared by the controller service that fetches and
//! compiles and by the policy engine that matches.
//!
//! - [`compile`]: the list text (hosts files and domain lists), the compiled version (a
//!   sorted suffix set, front-coded) and the [`ListMatcher`] of the query path.
//! - [`service`]: the rows, written through the zone service's inline jobs with their
//!   `dns.list.*` audit records.
//! - [`job`]: the compile job `dns.list.compile`. Its one step reads the source (the URL
//!   with `If-None-Match` and the stored entity tag, or the uploaded file), compiles it and
//!   writes the next [`ListVersion`](tenko_core::dns::ListVersion) with the audit record
//!   `dns.list.compile`, replacing the one before; a source that did not change writes
//!   nothing, a source that fails keeps the version and is reported in the list's status.
//!   The leader service `dns.lists` (in `tenko serve`) submits the job for every URL list
//!   on its interval; `POST /dns/lists/{id}/fetch` and `PUT /dns/lists/{id}/file` submit it
//!   at once.
//!
//! The catalog follows the versions through the feed and builds one matcher per enabled
//! list from the newest version; nodes receive the versions through node sync in Phase 5.

pub mod compile;
pub mod job;
pub mod service;

pub use compile::{CompileError, Compiled, ListMatcher, Parsed, compile as compile_keys, parse};
pub use job::{
    COMPILE_JOB, COMPILE_STEP, CompileStep, FetchFailure, FetchStatus, Fetched, ListFetcher,
    ListStaging, fetch_status,
};
pub use service::{ListChange, ListRow, NewList, VersionMeta};

/// Parses and compiles a list's text in one go.
///
/// # Errors
///
/// [`CompileError`] when the list is too large.
pub fn compile_text(
    text: &[u8],
    format: tenko_core::dns::ListFormat,
) -> Result<(Compiled, u64), CompileError> {
    let parsed = parse(text, format);
    let skipped = parsed.skipped;
    compile::compile(parsed.keys).map(|compiled| (compiled, skipped))
}
