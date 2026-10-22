//! The configuration service (WP7.4, plan sections 2.3 and 2.4, ADR 0019): the DHCP
//! configuration in the replicated store, and the configuration image built from it.
//!
//! The `dhcp` role reads what this service writes and never writes it. Every write is
//! planned against a read view, checked with the rules of the model (`tenko_core::dhcp`)
//! and committed as one batch with its audit record through an inline job ([`jobs`]); a
//! batch expects the versions it read, so a concurrent change makes it stale and the
//! service plans again ([`ConfigLimits::max_attempts`]).
//!
//! | Module | What |
//! |---|---|
//! | [`settings`] | the server settings (`dhcp.settings`) |
//! | [`scopes`] | scopes keyed by their IPAM prefix, exclusions, the utilization of a scope |
//! | [`networks`] | shared networks |
//! | [`pools`] | pools: IPAM ranges of role `dhcp_pool` with their DHCP settings |
//! | [`options`] | the catalog, custom definitions, option sets by owner |
//! | [`classes`] | classes, policies and MAC filters as rows (their matching is WP8.4's) |
//! | [`effective`] | the options a client gets in a scope, and the matcher hook of WP8.4 |
//! | [`load`] | the rows of the image from a read view: everything, or what one scope needs |
//! | [`image`] | the configuration image built from the rows plus IPAM's reserved hosts |
//! | [`jobs`] | the inline job of every change |
//!
//! # One model with IPAM
//!
//! A scope is keyed by the prefix it serves (P3-Q4): the prefix must be a live IPAM network
//! (`dhcp.scope.not_network` for a supernet), and the scope's batch expects the prefix's
//! version, so a prefix deleted meanwhile makes it stale. IPAM refuses to delete a prefix
//! that has a scope (`dhcp.scope.attached`). Pools are IPAM ranges of role `dhcp_pool`,
//! created and changed through the IPAM routes; this service adds their settings
//! (`dhcp.pools`). Reservations are IPAM hosts of mode `reserved` and are never written
//! here.
//!
//! # Deleting
//!
//! Deleting an owner deletes its option set in the same batch (`docs/dhcp-contracts.md`
//! section 14). Deleting a scope deletes its exclusions, the settings and option sets of
//! its pools, and its policies with their option sets; the prefix and its ranges stay.
//! A class named by a scope, a pool or a policy, a definition an option set uses and a
//! shared network with scopes refuse deletion (`*.in_use`).

pub mod classes;
pub mod effective;
mod error;
pub mod image;
pub mod jobs;
pub mod load;
pub mod networks;
pub mod options;
pub mod pools;
pub mod scopes;
pub mod settings;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod image_tests;

#[cfg(test)]
mod testkit;

use std::sync::Arc;

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    dhcp::{OptionOwner, OptionSet, tables::OPTION_SETS},
    ipam::{Prefix, Stamp},
};
use tenko_ipam::jobs::{DirectJobs, JobSink};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};

pub use error::{ConfigError, ConfigResult};
pub use jobs::{WriteStep, Written};

/// Limits of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigLimits {
    /// Plans before a contended write gives up.
    pub max_attempts: u32,
}

impl Default for ConfigLimits {
    fn default() -> Self {
        Self { max_attempts: 16 }
    }
}

/// The configuration service. Cheap to share as `Arc<ConfigService>`.
pub struct ConfigService {
    store: Arc<dyn Store>,
    jobs: Arc<dyn JobSink>,
    limits: ConfigLimits,
}

impl std::fmt::Debug for ConfigService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigService")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Registers the step handler of the service (`dhcp.write`) with the job engine.
pub fn register_steps(engine: &mut tenko_jobs::JobEngine) {
    engine.register(Arc::new(WriteStep));
}

impl ConfigService {
    /// The service over `store`, writing through `jobs` (the job engine, with
    /// [`register_steps`] called before it starts).
    pub fn new(store: Arc<dyn Store>, jobs: Arc<dyn JobSink>, limits: ConfigLimits) -> Arc<Self> {
        Arc::new(Self {
            store,
            jobs,
            limits,
        })
    }

    /// A service that runs its jobs in place, for tests and tools.
    pub fn with_direct_jobs(store: Arc<dyn Store>) -> Arc<Self> {
        let mut direct = DirectJobs::new(Arc::clone(&store));
        direct.register(Arc::new(WriteStep));
        Self::new(store, Arc::new(direct), ConfigLimits::default())
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// A read view, at least at `at_least` when given (read-your-writes).
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn view(&self, at_least: Option<Revision>) -> ConfigResult<Arc<dyn ReadView>> {
        let consistency = match at_least {
            Some(revision) => ReadConsistency::AtLeast(revision),
            None => ReadConsistency::Local,
        };
        Ok(self.store.read(consistency).await?)
    }

    // WP7.5: the record of a node command executed in place.
    /// Commits `batch` (the row of a node command of the `dhcp` role and its audit
    /// record, staged by the caller) as an inline job `dhcp.edit`, as every write is.
    ///
    /// # Errors
    ///
    /// The job's or the store's error.
    pub async fn commit_record(
        &self,
        cx: &RequestCtx,
        summary: String,
        targets: Vec<ObjectRef>,
        batch: WriteBatch,
    ) -> ConfigResult<Written> {
        jobs::commit(self.jobs.as_ref(), cx, summary, targets, batch).await
    }

    /// Plans with `plan` against fresh views and commits its batch as an inline job,
    /// planning again after a stale write.
    pub(crate) async fn execute<T, F>(
        &self,
        cx: &RequestCtx,
        mut plan: F,
    ) -> ConfigResult<(T, Option<Written>)>
    where
        F: FnMut(&dyn ReadView) -> ConfigResult<Planned<T>>,
    {
        let mut last = None;
        for attempt in 0..self.limits.max_attempts {
            let consistency = if attempt == 0 {
                ReadConsistency::Local
            } else {
                ReadConsistency::Linearizable
            };
            let view = self.store.read(consistency).await?;
            let planned = plan(view.as_ref())?;
            drop(view);
            let Some(write) = planned.write else {
                return Ok((planned.result, None));
            };
            match jobs::commit(
                self.jobs.as_ref(),
                cx,
                write.summary,
                write.targets,
                write.batch,
            )
            .await
            {
                Ok(written) => return Ok((planned.result, Some(written))),
                Err(error) if error.is_stale() => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            ConfigError::new(
                error::PRECONDITION_FAILED,
                409,
                "the configuration changed meanwhile",
            )
        }))
    }

    /// [`ConfigService::execute`] for a plan that always writes.
    pub(crate) async fn execute_write<T, F>(
        &self,
        cx: &RequestCtx,
        plan: F,
    ) -> ConfigResult<(T, Written)>
    where
        F: FnMut(&dyn ReadView) -> ConfigResult<Planned<T>>,
    {
        let (result, written) = self.execute(cx, plan).await?;
        Ok((result, written.ok_or_else(nothing_written)?))
    }
}

/// A planned change: its result and, unless nothing changes, the batch.
pub(crate) struct Planned<T> {
    pub(crate) result: T,
    pub(crate) write: Option<PlannedWrite>,
}

pub(crate) struct PlannedWrite {
    pub(crate) batch: WriteBatch,
    pub(crate) summary: String,
    pub(crate) targets: Vec<ObjectRef>,
}

impl<T> Planned<T> {
    pub(crate) fn write(
        result: T,
        batch: WriteBatch,
        summary: String,
        targets: Vec<ObjectRef>,
    ) -> Self {
        Self {
            result,
            write: Some(PlannedWrite {
                batch,
                summary,
                targets,
            }),
        }
    }

    pub(crate) fn nothing(result: T) -> Self {
        Self {
            result,
            write: None,
        }
    }
}

/// A 412 when the caller's `If-Match` revision is not the row's.
pub(crate) fn check_expect(expect: Option<Revision>, current: Revision) -> ConfigResult<()> {
    match expect {
        Some(expect) if expect != current => Err(ConfigError::new(
            error::PRECONDITION_FAILED,
            412,
            format!(
                "the object changed since revision {}; it is at {}",
                expect.0, current.0
            ),
        )
        .param("expected", expect.0.to_string())
        .param("current", current.0.to_string())),
        _ => Ok(()),
    }
}

fn nothing_written() -> ConfigError {
    ConfigError::new(
        tenko_core::error::codes::INTERNAL,
        500,
        "the write reported no commit",
    )
}

/// The stamp of a write by `cx`.
pub(crate) fn stamp(cx: &RequestCtx) -> Stamp {
    Stamp::new(cx.now, cx.principal.clone())
}

/// Free text as stored: trimmed, and none when empty.
pub(crate) fn text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A live IPAM prefix.
///
/// # Errors
///
/// `ipam.not_found` when the prefix does not exist or is deleted.
pub(crate) fn live_prefix(
    view: &dyn ReadView,
    id: tenko_core::PrefixId,
) -> ConfigResult<(Prefix, Revision)> {
    match view.get_typed(&tenko_ipam::tables::PREFIXES, &id)? {
        Some((prefix, revision)) if !prefix.meta.is_deleted() => Ok((prefix, revision)),
        _ => Err(
            ConfigError::new("ipam.not_found", 404, format!("prefix {id} does not exist"))
                .param("kind", "prefix")
                .param("id", id.to_string()),
        ),
    }
}

/// Stages the deletion of an owner's option set, when it has one.
pub(crate) fn delete_option_set(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    owner: OptionOwner,
) -> ConfigResult<()> {
    if let Some((_, revision)) = view.get_typed::<OptionOwner, OptionSet>(&OPTION_SETS, &owner)? {
        batch.expect_typed(&OPTION_SETS, &owner, Some(revision));
        batch.delete_typed(&OPTION_SETS, &owner);
    }
    Ok(())
}
