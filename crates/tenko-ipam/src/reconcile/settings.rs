//! The settings of the reconciler in the store (`ipam.reconciler_settings`, plan 2.6):
//! the same on every controller, changed through the API with audit, read by the
//! reconciler at every run so that a change needs no restart.
//!
//! The `ipam` start step seeds the table from the code defaults when it is empty
//! ([`seed`]); until a seed or an update is stored, the reconciler uses the settings it was
//! built with. `max_attempts` stays a code constant.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectKind, ObjectRef, RequestCtx, Revision, SystemComponent,
    audit::{AuditAction, AuditDraft, FieldChange},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::ReconcilerConfig;
use crate::{
    error::{IpamError, IpamResult},
    observe::ObserveConfig,
};

/// The settings (singleton).
pub const SETTINGS: TableDef<(), ReconcilerSettings> = TableDef::new("ipam.reconciler_settings");

/// The audit action of a change of the settings.
pub const UPDATE_ACTION: &str = "ipam.reconciler.settings.update";

/// The code of settings outside their limits.
pub const INVALID: &str = "ipam.reconciler.settings.invalid";

/// Limits of the settings, in seconds (inclusive).
pub mod limits {
    /// Interval of periodic runs: 30 seconds to one day.
    pub const INTERVAL: (u64, u64) = (30, 86_400);
    /// Delay of a run after an ingest or an intent change: none to five minutes.
    pub const DEBOUNCE: (u64, u64) = (0, 300);
    /// Orphan age: one hour to one year.
    pub const ORPHAN_AFTER: (u64, u64) = (3_600, 31_536_000);
    /// Retention of facts: one day to one year.
    pub const RETENTION: (u64, u64) = (86_400, 31_536_000);
    /// Refresh of an unchanged fact: one minute to one day, and shorter than the retention.
    pub const REFRESH: (u64, u64) = (60, 86_400);
    /// Interval of retention purges: five minutes to one day.
    pub const PURGE_INTERVAL: (u64, u64) = (300, 86_400);
}

/// The settings of the reconciler, the same on every controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ReconcilerSettings {
    /// Seconds between periodic runs, 30 to 86,400 (default 300).
    pub interval_secs: u64,
    /// Seconds a run waits after an ingest or an intent change to collect what follows,
    /// 0 to 300 (default 2).
    pub debounce_secs: u64,
    /// Seconds an intended address may go unseen (after it was seen) before it is
    /// proposed as orphaned, 3,600 to 31,536,000 (default 604,800: seven days).
    pub orphan_after_secs: u64,
    /// Seconds a fact is kept after its last sighting, 86,400 to 31,536,000 (default
    /// 2,592,000: 30 days).
    pub retention_secs: u64,
    /// Seconds after which an unchanged fact is written again with a new last sighting,
    /// and the shortest interval between two counted sightings, 60 to 86,400 and shorter
    /// than the retention (default 900).
    pub refresh_secs: u64,
    /// Seconds between retention purges, 300 to 86,400 (default 3,600).
    pub purge_interval_secs: u64,
    /// Whether adoption policies are applied; off, every proposal waits for a person
    /// (default on).
    pub adopt: bool,
}

impl Default for ReconcilerSettings {
    fn default() -> Self {
        Self::of(&ReconcilerConfig::default())
    }
}

impl ReconcilerSettings {
    /// The settings of a configuration.
    pub fn of(config: &ReconcilerConfig) -> Self {
        Self {
            interval_secs: config.interval.as_secs(),
            debounce_secs: config.debounce.as_secs(),
            orphan_after_secs: config.orphan_after.as_secs(),
            retention_secs: config.observe.retention.as_secs(),
            refresh_secs: config.observe.refresh.as_secs(),
            purge_interval_secs: config.purge_interval.as_secs(),
            adopt: config.adopt,
        }
    }

    /// `base` with these settings; the code constants of `base` stay.
    pub fn apply(&self, base: ReconcilerConfig) -> ReconcilerConfig {
        ReconcilerConfig {
            observe: ObserveConfig {
                refresh: Duration::from_secs(self.refresh_secs),
                retention: Duration::from_secs(self.retention_secs),
                ..base.observe
            },
            interval: Duration::from_secs(self.interval_secs),
            debounce: Duration::from_secs(self.debounce_secs),
            orphan_after: Duration::from_secs(self.orphan_after_secs),
            purge_interval: Duration::from_secs(self.purge_interval_secs),
            adopt: self.adopt,
            ..base
        }
    }

    /// Checks the limits ([`limits`]).
    ///
    /// # Errors
    ///
    /// 422 `ipam.reconciler.settings.invalid` naming the first field out of its limits.
    pub fn validate(&self) -> IpamResult<()> {
        let fields = [
            ("interval_secs", self.interval_secs, limits::INTERVAL),
            ("debounce_secs", self.debounce_secs, limits::DEBOUNCE),
            (
                "orphan_after_secs",
                self.orphan_after_secs,
                limits::ORPHAN_AFTER,
            ),
            ("retention_secs", self.retention_secs, limits::RETENTION),
            ("refresh_secs", self.refresh_secs, limits::REFRESH),
            (
                "purge_interval_secs",
                self.purge_interval_secs,
                limits::PURGE_INTERVAL,
            ),
        ];
        for (field, value, (min, max)) in fields {
            if !(min..=max).contains(&value) {
                return Err(invalid(field, format!("{field} is {min} to {max} seconds")));
            }
        }
        if self.refresh_secs >= self.retention_secs {
            return Err(invalid(
                "refresh_secs",
                "refresh_secs must be shorter than retention_secs",
            ));
        }
        Ok(())
    }

    fn changes(&self, old: &Self) -> Vec<FieldChange> {
        let pairs = [
            ("interval_secs", old.interval_secs, self.interval_secs),
            ("debounce_secs", old.debounce_secs, self.debounce_secs),
            (
                "orphan_after_secs",
                old.orphan_after_secs,
                self.orphan_after_secs,
            ),
            ("retention_secs", old.retention_secs, self.retention_secs),
            ("refresh_secs", old.refresh_secs, self.refresh_secs),
            (
                "purge_interval_secs",
                old.purge_interval_secs,
                self.purge_interval_secs,
            ),
        ];
        let mut changes: Vec<FieldChange> = pairs
            .into_iter()
            .filter(|(_, old, new)| old != new)
            .map(|(field, old, new)| change(field, old.to_string(), new.to_string()))
            .collect();
        if old.adopt != self.adopt {
            changes.push(change(
                "adopt",
                old.adopt.to_string(),
                self.adopt.to_string(),
            ));
        }
        changes
    }
}

fn change(field: &str, old: String, new: String) -> FieldChange {
    FieldChange {
        object: None,
        field: field.to_owned(),
        old: Some(old),
        new: Some(new),
    }
}

fn invalid(field: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(INVALID, 422, detail)
        .titled("Invalid reconciler settings")
        .param("field", field)
        .field(field, INVALID)
}

/// The object of the audit records: the system.
fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

/// The stored settings in `view` with their revision; `None` while none were stored.
///
/// # Errors
///
/// Store errors.
pub fn stored(view: &dyn ReadView) -> IpamResult<Option<(ReconcilerSettings, Revision)>> {
    Ok(view.get_typed(&SETTINGS, &())?)
}

/// The settings in force (the stored ones, else the code defaults) with the revision of
/// the stored ones.
///
/// # Errors
///
/// Store errors.
pub async fn read(store: &dyn Store) -> IpamResult<(ReconcilerSettings, Option<Revision>)> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(match stored(view.as_ref())? {
        Some((settings, revision)) => (settings, Some(revision)),
        None => (ReconcilerSettings::default(), None),
    })
}

/// The stored settings; `None` while none were stored.
///
/// # Errors
///
/// Store errors.
pub async fn read_stored(store: &dyn Store) -> IpamResult<Option<ReconcilerSettings>> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(stored(view.as_ref())?.map(|(settings, _)| settings))
}

/// Stores `defaults` when no settings are stored yet; `true` when it wrote them. A
/// concurrent seed of another controller is not an error.
///
/// # Errors
///
/// Store errors.
pub async fn seed(store: &dyn Store, defaults: ReconcilerSettings) -> IpamResult<bool> {
    let view = store.read(ReadConsistency::Local).await?;
    if stored(view.as_ref())?.is_some() {
        return Ok(false);
    }
    drop(view);
    let ctx = RequestCtx::system(SystemComponent::Ipam);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.expect_typed(&SETTINGS, &(), None);
    batch.put_typed(&SETTINGS, &(), &defaults)?;
    match store.propose(batch).await {
        Ok(_) => Ok(true),
        Err(StoreError::PreconditionFailed(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Replaces the settings, if they are still at `expect` (`None`: whatever is stored);
/// audited as `ipam.reconciler.settings.update` with one change per field. Returns the
/// settings and their new revision.
///
/// # Errors
///
/// 422 `ipam.reconciler.settings.invalid`, the store's precondition error when `expect`
/// is stale or a concurrent change won, or other store errors.
pub async fn update(
    store: &dyn Store,
    ctx: &RequestCtx,
    settings: ReconcilerSettings,
    expect: Option<Revision>,
) -> IpamResult<(ReconcilerSettings, Revision)> {
    settings.validate()?;
    let view = store.read(ReadConsistency::Local).await?;
    let current = stored(view.as_ref())?;
    drop(view);
    let current_revision = current.as_ref().map(|(_, revision)| *revision);
    if expect.is_some() && expect != current_revision {
        return Err(StoreError::PreconditionFailed(Vec::new()).into());
    }
    let old = current.map_or_else(ReconcilerSettings::default, |(old, _)| old);
    let mut batch = WriteBatch::for_request(ctx);
    batch.expect_typed(&SETTINGS, &(), current_revision);
    batch.put_typed(&SETTINGS, &(), &settings)?;
    let mut draft = AuditDraft::success(
        AuditAction::from_static(UPDATE_ACTION),
        vec![system_object()],
    )
    .with_source_ip(ctx.source_ip);
    for change in settings.changes(&old) {
        draft = draft.with_change(change);
    }
    batch.audit(draft);
    let committed = store.propose(batch).await?;
    Ok((settings, committed.revision))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_code_defaults_and_valid() {
        let defaults = ReconcilerSettings::default();
        assert_eq!(defaults.interval_secs, 300);
        assert_eq!(defaults.debounce_secs, 2);
        assert_eq!(defaults.orphan_after_secs, 7 * 24 * 3600);
        assert_eq!(defaults.retention_secs, 30 * 24 * 3600);
        assert_eq!(defaults.refresh_secs, 15 * 60);
        assert_eq!(defaults.purge_interval_secs, 3600);
        assert!(defaults.adopt);
        defaults.validate().expect("valid");
        assert_eq!(
            defaults.apply(ReconcilerConfig::default()),
            ReconcilerConfig::default()
        );
    }

    #[test]
    fn values_outside_the_limits_are_refused_with_the_field() {
        let cases = [
            ReconcilerSettings {
                interval_secs: 29,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                debounce_secs: 301,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                orphan_after_secs: 60,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                retention_secs: 31_536_001,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                refresh_secs: 59,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                purge_interval_secs: 0,
                ..ReconcilerSettings::default()
            },
            ReconcilerSettings {
                retention_secs: 86_400,
                refresh_secs: 86_400,
                ..ReconcilerSettings::default()
            },
        ];
        for settings in cases {
            let error = settings.validate().expect_err("refused").into_coded();
            assert_eq!(error.code, INVALID);
            assert_eq!(error.status, 422);
            assert!(error.params.contains_key("field"));
        }
    }

    #[test]
    fn apply_keeps_the_code_constants() {
        let base = ReconcilerConfig {
            max_attempts: 3,
            ..ReconcilerConfig::default()
        };
        let settings = ReconcilerSettings {
            interval_secs: 60,
            adopt: false,
            ..ReconcilerSettings::default()
        };
        let config = settings.apply(base);
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.interval, Duration::from_secs(60));
        assert!(!config.adopt);
        assert_eq!(config.observe.max_attempts, base.observe.max_attempts);
    }
}
