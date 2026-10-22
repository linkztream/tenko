//! Lease history retention (P3-Q13, DHCP-07): `dhcp.history` is a bounded table, purged by
//! a leader service after the retention of the security profile.
//!
//! Every lease change writes one history row in its batch (`batch.rs`, `expiry.rs`). The
//! retention in days is, first that wins: the node's `[dhcp.history] days`, the replicated
//! `DhcpSettings::history_days`, the profile's default ([`HistoryProfile::default_days`]:
//! Home 30, Standard 90, Hardened 90, Lab 7). The Hardened profile keeps its history by
//! policy; its default is the Standard value, and the audit export carries every purge.
//!
//! [`PurgeService`] (`dhcp.history.purge`) deletes the rows older than the retention every
//! [`PurgeSettings::period`], in batches of [`PurgeSettings::batch`] rows under the leader
//! fence, with one audit record `dhcp.history.purge` per batch (the cut-off and the count),
//! and keeps the metrics `tenko_dhcp_history_rows` and `tenko_dhcp_history_purged_total`.
//! The row count is taken by a scan once per term of office and then kept by adding the
//! rows this process writes and subtracting the ones it purges.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    Principal, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::LeaderService,
    dhcp::{self, tables},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use super::{follow::PAGE, metrics};

/// Seconds in a day.
const DAY: i128 = 86_400;

/// The security profile, as far as the history retention needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum HistoryProfile {
    /// Home: 30 days.
    Home = 0,
    /// Standard: 90 days.
    #[default]
    Standard = 1,
    /// Hardened: by policy, 90 days unless set.
    Hardened = 2,
    /// Lab: 7 days.
    Lab = 3,
}

impl HistoryProfile {
    /// The retention in days when neither the node nor the settings give one.
    pub const fn default_days(self) -> u32 {
        match self {
            Self::Home => 30,
            Self::Standard | Self::Hardened => 90,
            Self::Lab => 7,
        }
    }

    /// The profile of a stable name (`home`, `standard`, `hardened`, `lab`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "home" => Some(Self::Home),
            "standard" => Some(Self::Standard),
            "hardened" => Some(Self::Hardened),
            "lab" => Some(Self::Lab),
            _ => None,
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Home,
            2 => Self::Hardened,
            3 => Self::Lab,
            _ => Self::Standard,
        }
    }
}

/// The retention in force: the profile (which the role follows as the settings change) and
/// the node's override.
#[derive(Debug, Default)]
pub struct HistoryRetention {
    profile: AtomicU8,
    node_days: Option<u32>,
}

impl HistoryRetention {
    /// The retention of `profile` with the node's `[dhcp.history] days`, if set.
    pub fn new(profile: HistoryProfile, node_days: Option<u32>) -> Self {
        Self {
            profile: AtomicU8::new(profile as u8),
            node_days,
        }
    }

    /// The profile in force.
    pub fn profile(&self) -> HistoryProfile {
        HistoryProfile::from_u8(self.profile.load(Ordering::Relaxed))
    }

    /// Follows a change of the profile.
    pub fn set_profile(&self, profile: HistoryProfile) {
        self.profile.store(profile as u8, Ordering::Relaxed);
    }

    /// The days to keep, given the replicated settings' value.
    pub fn days(&self, settings_days: Option<u32>) -> u32 {
        self.node_days
            .or(settings_days)
            .unwrap_or_else(|| self.profile().default_days())
            .max(1)
    }

    /// The oldest time kept at `now`: rows before it are purged.
    pub fn cutoff(&self, settings_days: Option<u32>, now: Timestamp) -> Timestamp {
        let nanos = i128::from(self.days(settings_days)) * DAY * 1_000_000_000;
        Timestamp::from_unix_nanos(now.unix_nanos() - nanos).unwrap_or(Timestamp::UNIX_EPOCH)
    }
}

/// The purge's timer and batch size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeSettings {
    /// Time between rounds.
    pub period: Duration,
    /// Rows deleted per batch.
    pub batch: usize,
}

impl Default for PurgeSettings {
    fn default() -> Self {
        Self {
            period: Duration::from_secs(3_600),
            batch: 1_000,
        }
    }
}

/// What one purge round did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeRound {
    /// Rows older than this were purged.
    pub cutoff: Timestamp,
    /// Rows purged.
    pub purged: u64,
}

/// The history purge leader service.
#[derive(Clone)]
pub struct PurgeService {
    store: Arc<dyn Store>,
    retention: Arc<HistoryRetention>,
    settings: PurgeSettings,
}

impl std::fmt::Debug for PurgeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PurgeService")
            .field("retention", &self.retention)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The rows of `dhcp.history` in a view.
///
/// # Errors
///
/// A storage failure of the scan.
pub fn count_rows(view: &dyn ReadView) -> Result<u64, StoreError> {
    let mut count = 0u64;
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(tables::HISTORY.name(), range.clone(), PAGE, false)?;
        count += u64::try_from(page.len()).unwrap_or(u64::MAX);
        if page.len() < PAGE {
            return Ok(count);
        }
        let Some((last, _)) = page.last() else {
            return Ok(count);
        };
        range = KeyRange::all().after(last.clone());
    }
}

/// Where the row count of a term starts: the rows counted and the process's history
/// writes at that moment.
#[derive(Debug, Clone, Copy)]
struct Base {
    rows: u64,
    written: u64,
    purged: u64,
}

impl PurgeService {
    /// The purge of `store` under `retention`.
    pub fn new(
        store: Arc<dyn Store>,
        retention: Arc<HistoryRetention>,
        settings: PurgeSettings,
    ) -> Self {
        Self {
            store,
            retention,
            settings,
        }
    }

    /// The rows of `dhcp.history` now.
    async fn counted(&self) -> Result<u64, StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        count_rows(view.as_ref())
    }

    /// One round at `now` under the leader `epoch`.
    ///
    /// # Errors
    ///
    /// A store error; a failed fence ends the round with
    /// [`StoreError::PreconditionFailed`].
    pub async fn round(&self, epoch: u64, now: Timestamp) -> Result<PurgeRound, StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let settings_days = view
            .get_typed(&tables::SETTINGS, &())?
            .and_then(|(settings, _)| settings.history_days);
        let cutoff = self.retention.cutoff(settings_days, now);
        let mut purged = 0u64;
        let mut view = view;
        loop {
            let page = view.scan_typed(
                &tables::HISTORY,
                KeyRange::all(),
                self.settings.batch.max(1),
                false,
            )?;
            let old: Vec<_> = page
                .iter()
                .filter(|((at, _, _), _, _)| *at < cutoff)
                .map(|(key, _, _)| *key)
                .collect();
            if old.is_empty() {
                break;
            }
            let count = u64::try_from(old.len()).unwrap_or(u64::MAX);
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
            batch.preconditions.push(fence(epoch));
            for key in &old {
                batch.delete_typed(&tables::HISTORY, key);
            }
            batch.audit(
                AuditDraft::success(dhcp::audit::HISTORY_PURGE, vec![dhcp::server_object()])
                    .with_context("rows", count.to_string())
                    .with_context("before", cutoff.to_rfc3339()),
            );
            self.store.propose(batch).await?;
            purged += count;
            metrics::HISTORY_PURGED.add(count);
            if old.len() < page.len() {
                break;
            }
            view = self.store.read(ReadConsistency::Local).await?;
        }
        Ok(PurgeRound { cutoff, purged })
    }
}

#[async_trait::async_trait]
impl LeaderService for PurgeService {
    fn name(&self) -> &'static str {
        "dhcp.history.purge"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut base: Option<Base> = None;
        let mut purged_in_term = 0u64;
        loop {
            match self.round(epoch, Timestamp::now()).await {
                Ok(round) => {
                    purged_in_term += round.purged;
                    let written = metrics::HISTORY_WRITTEN.load(Ordering::Relaxed);
                    if base.is_none() {
                        match self.counted().await {
                            Ok(rows) => {
                                base = Some(Base {
                                    rows,
                                    written,
                                    purged: purged_in_term,
                                });
                            }
                            Err(error) => {
                                tracing::warn!(%error, "the lease history could not be counted");
                            }
                        }
                    }
                    let rows = base.map_or(0, |base| {
                        (base.rows + written.saturating_sub(base.written))
                            .saturating_sub(purged_in_term - base.purged)
                    });
                    #[allow(clippy::cast_precision_loss, reason = "a gauge of a row count")]
                    metrics::HISTORY_ROWS.set(rows as f64);
                    if round.purged > 0 {
                        tracing::info!(
                            purged = round.purged,
                            before = %round.cutoff,
                            "lease history purged by retention"
                        );
                    }
                }
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err(
                        "another controller took office; the history purge stops here".to_owned(),
                    );
                }
                Err(error) => tracing::warn!(%error, "a lease history purge round failed"),
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.settings.period) => {}
            }
        }
    }
}
