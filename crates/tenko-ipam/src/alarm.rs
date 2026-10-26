//! Utilization alarms (IPAM-10).
//!
//! A prefix with alarm thresholds is `warning` from `warn_pct` and `critical` from
//! `crit_pct` of its usable addresses in use, the same figure as the meter, for a supernet
//! summed over its tree and never the space allocated to its children (see
//! [`Utilization`](crate::tree::Utilization)).
//! The prefix tree marks prefixes whose utilization may have changed; [`flush`] computes
//! their level from the tree and, when it differs from the stored level, writes an
//! [`AlarmEvent`] into `ipam.alarms` as principal `system:ipam` with an audit record. A
//! change set touching `ipam.alarms` is a `system` topic event on the SSE stream; the row
//! keeps the current level, so the UI and the tree endpoint can show it.
//!
//! The write expects the row's revision, so several controllers that detect the same
//! transition write it once.

use std::sync::Arc;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectRef, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::{ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch};
use utoipa::ToSchema;

use crate::{error::IpamResult, tables::ALARMS, tree::PrefixTree};

/// Alarm level of a prefix.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AlarmLevel {
    /// Below the warning threshold, or no thresholds.
    #[default]
    Normal,
    /// At or above the warning threshold.
    Warning,
    /// At or above the critical threshold.
    Critical,
}

impl AlarmLevel {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            AlarmLevel::Normal => "normal",
            AlarmLevel::Warning => "warning",
            AlarmLevel::Critical => "critical",
        }
    }
}

/// The alarm state of a prefix after a level change; the value of `ipam.alarms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AlarmEvent {
    /// The prefix.
    pub prefix: PrefixId,
    /// Its VRF.
    pub vrf: VrfId,
    /// Its network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// The new level.
    pub level: AlarmLevel,
    /// The level before.
    pub previous: AlarmLevel,
    /// Utilization in tenths of a percent (0 to 1000).
    pub permille: u16,
    /// Address objects inside the prefix (for a supernet: in its tree), saturated at
    /// `u64::MAX`.
    pub used: u64,
    /// Addresses held by ranges, saturated.
    pub reserved: u64,
    /// Capacity, saturated.
    pub capacity: u64,
    /// The warning threshold in percent.
    #[serde(default)]
    pub warn_pct: Option<u8>,
    /// The critical threshold in percent.
    #[serde(default)]
    pub crit_pct: Option<u8>,
    /// When the change was detected.
    pub at: Timestamp,
}

/// Writes the alarm transitions of the prefixes the tree marked since the last flush and
/// returns the events written, stamped `now` (the request time when a change triggers the
/// flush). Retries a few times when another writer got there first.
///
/// # Errors
///
/// Returns store errors other than failed preconditions; the marked prefixes are kept for
/// the next flush.
pub async fn flush(
    store: &Arc<dyn Store>,
    tree: &PrefixTree,
    now: Timestamp,
) -> IpamResult<Vec<AlarmEvent>> {
    let mut written = Vec::new();
    for _round in 0..4 {
        let dirty = tree.take_dirty();
        if dirty.is_empty() {
            break;
        }
        let view = store.read(ReadConsistency::Local).await?;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), now);
        let mut events = Vec::new();
        for prefix in &dirty {
            let stored = view.get_typed(&ALARMS, prefix)?;
            let previous = stored.as_ref().map_or(AlarmLevel::Normal, |(e, _)| e.level);
            let state = tree.alarm_state(*prefix);
            let level = state.as_ref().map_or(AlarmLevel::Normal, |s| s.level);
            if level == previous {
                continue;
            }
            let event = match state {
                Some(state) => AlarmEvent {
                    prefix: *prefix,
                    vrf: state.vrf,
                    cidr: state.cidr,
                    level,
                    previous,
                    permille: state.utilization.permille(),
                    used: saturate(state.utilization.used),
                    reserved: saturate(state.utilization.reserved),
                    capacity: saturate(state.utilization.capacity),
                    warn_pct: state.alarm.map(|a| a.warn_pct),
                    crit_pct: state.alarm.map(|a| a.crit_pct),
                    at: now,
                },
                None => match &stored {
                    Some((old, _)) => AlarmEvent {
                        level,
                        previous,
                        at: now,
                        ..old.clone()
                    },
                    None => continue,
                },
            };
            batch.put_typed(&ALARMS, prefix, &event)?;
            batch.expect_typed(&ALARMS, prefix, stored.map(|(_, revision)| revision));
            batch.audit(
                AuditDraft::success(
                    AuditAction::from_static("ipam.prefix.alarm"),
                    vec![ObjectRef::from(*prefix)],
                )
                .with_context("level", level.as_str())
                .with_context("previous", previous.as_str())
                .with_context("cidr", event.cidr.to_string())
                .with_context("permille", event.permille.to_string()),
            );
            events.push(event);
        }
        if events.is_empty() {
            continue;
        }
        match store.propose(batch).await {
            Ok(_) => written.extend(events),
            Err(StoreError::PreconditionFailed(_)) => tree.mark_dirty(dirty),
            Err(error) => {
                tree.mark_dirty(dirty);
                return Err(error.into());
            }
        }
    }
    Ok(written)
}

fn saturate(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
