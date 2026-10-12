//! The status of the export as every controller sees it: the state of each sink from its
//! cursor, the TGL-21 policy, and the warnings for `/system/status`.
//!
//! A sink is `failing` while its last attempt failed, `alarm` once that lasted the
//! settings' `alert_after_secs`, and `behind` when records wait and its cursor has not
//! moved for as long (the exporter does not run, for example). The warning
//! `audit.export.failing` names every sink in `alarm` or `behind`; the warning
//! `audit.export.required` shows while TGL-21 requires an export and no sink is enabled.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    AuditSeq, Timestamp,
    audit::{AuditRecord, ChainHead},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError, tables};
use utoipa::ToSchema;

use super::{
    error::{FAILING, REQUIRED},
    model::{
        AuditExportSettings, CURSORS, CheckpointMark, ExportCursor, SETTINGS, START, Sink,
        SinkFailure,
    },
};
use crate::settings::AuditExport;

/// The state of a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SinkState {
    /// The sink is switched off.
    Disabled,
    /// The sink has not delivered yet.
    Pending,
    /// The sink is current or catching up.
    Ok,
    /// Records wait and the cursor has not moved for the alarm delay.
    Behind,
    /// The last attempt failed.
    Failing,
    /// The sink has failed for at least the alarm delay (`audit.export.failing`).
    Alarm,
}

/// The status of one sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SinkStatus {
    /// The state.
    pub state: SinkState,
    /// The last record handed to the sink.
    pub delivered: ChainHead,
    /// Records of the log after `delivered`.
    pub lag: u64,
    /// When the exporter last wrote the cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// When the sink last delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<Timestamp>,
    /// Since when it fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<Timestamp>,
    /// The last failure (kept after a recovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<SinkFailure>,
    /// The last checkpoint sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointMark>,
}

/// The status of a sink from its cursor.
pub fn sink_status(
    sink: &Sink,
    cursor: Option<&ExportCursor>,
    store_head: AuditSeq,
    now: Timestamp,
    alert_after: Duration,
) -> SinkStatus {
    let delivered = cursor.map_or(START, |cursor| cursor.delivered);
    let lag = store_head.0.saturating_sub(delivered.seq.0);
    let state = match cursor {
        _ if !sink.enabled => SinkState::Disabled,
        Some(cursor) if cursor.failing_since.is_some() => {
            if cursor.alarm_due(now, alert_after) {
                SinkState::Alarm
            } else {
                SinkState::Failing
            }
        }
        Some(cursor) if lag > 0 && now.saturating_since(cursor.updated_at) >= alert_after => {
            SinkState::Behind
        }
        None => SinkState::Pending,
        Some(cursor) if cursor.last_success_at.is_none() && lag > 0 => SinkState::Pending,
        Some(_) => SinkState::Ok,
    };
    SinkStatus {
        state,
        delivered,
        lag,
        updated_at: cursor.map(|cursor| cursor.updated_at),
        last_success_at: cursor.and_then(|cursor| cursor.last_success_at),
        failing_since: cursor.and_then(|cursor| cursor.failing_since),
        last_error: cursor.and_then(|cursor| cursor.last_error.clone()),
        checkpoint: cursor.and_then(|cursor| cursor.checkpoint),
    }
}

/// What TGL-21 asks of the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExportPolicy {
    /// The effective value of TGL-21.
    pub audit_export: AuditExport,
    /// Whether an export is required (`required`, the Hardened profile).
    pub required: bool,
    /// Whether the settings satisfy the toggle: not required, or at least one sink enabled.
    pub satisfied: bool,
}

impl ExportPolicy {
    /// The policy of `toggle` over `settings`.
    pub fn of(toggle: AuditExport, settings: &AuditExportSettings) -> Self {
        let required = toggle == AuditExport::Required;
        Self {
            audit_export: toggle,
            required,
            satisfied: !required || settings.has_enabled_sink(),
        }
    }
}

/// A warning for `/system/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExportWarning {
    /// `audit.export.failing` or `audit.export.required`.
    pub code: String,
    /// An English description.
    pub detail: String,
    /// Parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

/// A sink with its status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SinkView {
    /// The sink.
    #[serde(flatten)]
    pub sink: Sink,
    /// Its status.
    pub status: SinkStatus,
}

/// The settings with the status of every sink (`GET /settings/audit-export`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportView {
    /// The revision of the settings (0 before they were first stored), for `If-Match`.
    pub revision: u64,
    /// Seconds a sink may fail before the alarm.
    pub alert_after_secs: u32,
    /// The sinks in their order, with their status.
    pub sinks: Vec<SinkView>,
    /// What TGL-21 asks.
    pub policy: ExportPolicy,
    /// The newest record of the audit log.
    pub store_head: AuditSeq,
    /// The warnings the status shows.
    pub warnings: Vec<ExportWarning>,
}

/// The warnings of the export.
pub fn warnings(policy: &ExportPolicy, sinks: &[SinkView]) -> Vec<ExportWarning> {
    let mut out = Vec::new();
    let stuck: Vec<&SinkView> = sinks
        .iter()
        .filter(|view| matches!(view.status.state, SinkState::Alarm | SinkState::Behind))
        .collect();
    if !stuck.is_empty() {
        let names: Vec<&str> = stuck.iter().map(|view| view.sink.name.as_str()).collect();
        let mut params = BTreeMap::from([
            ("sinks".to_owned(), names.join(", ")),
            ("count".to_owned(), stuck.len().to_string()),
        ]);
        if let Some(since) = stuck
            .iter()
            .filter_map(|view| view.status.failing_since)
            .min()
        {
            params.insert("since".to_owned(), since.to_rfc3339());
        }
        let only = policy.required
            && sinks
                .iter()
                .filter(|view| view.sink.enabled)
                .all(|view| matches!(view.status.state, SinkState::Alarm | SinkState::Behind));
        params.insert("required".to_owned(), only.to_string());
        out.push(ExportWarning {
            code: FAILING.to_owned(),
            detail: format!(
                "the audit export does not reach {}: {}",
                if stuck.len() == 1 { "a sink" } else { "sinks" },
                names.join(", ")
            ),
            params,
        });
    }
    if !policy.satisfied {
        out.push(ExportWarning {
            code: REQUIRED.to_owned(),
            detail: "the security settings require an audit export (TGL-21) and no sink is enabled"
                .to_owned(),
            params: BTreeMap::new(),
        });
    }
    out
}

/// The effective TGL-21 value stored in the security settings (`optional` before setup).
///
/// # Errors
///
/// The store's error.
pub fn toggle(view: &dyn ReadView) -> Result<AuditExport, StoreError> {
    Ok(view
        .get_typed(&crate::model::SETTINGS, &())?
        .map_or(AuditExport::Optional, |(settings, _)| {
            settings.audit_export()
        }))
}

/// The newest record of the audit log in `view`.
///
/// # Errors
///
/// The store's error.
pub fn store_head(view: &dyn ReadView) -> Result<AuditSeq, StoreError> {
    let last: Vec<(AuditSeq, AuditRecord, _)> =
        view.scan_typed(&tables::AUDIT, KeyRange::all(), 1, true)?;
    Ok(last.first().map_or(AuditSeq::NONE, |(seq, _, _)| *seq))
}

/// The settings, their revision, the cursors and the policy in `view`, as one document.
///
/// # Errors
///
/// The store's error.
pub fn read_view(view: &dyn ReadView, now: Timestamp) -> Result<AuditExportView, StoreError> {
    let (settings, revision) = view
        .get_typed(&SETTINGS, &())?
        .map_or_else(|| (AuditExportSettings::default(), 0), |(s, r)| (s, r.0));
    let store_head = store_head(view)?;
    let alert_after = Duration::from_secs(u64::from(settings.alert_after_secs));
    let policy = ExportPolicy::of(toggle(view)?, &settings);
    let mut sinks = Vec::with_capacity(settings.sinks.len());
    for sink in &settings.sinks {
        let cursor = view
            .get_typed(&CURSORS, &sink.id)?
            .map(|(cursor, _)| cursor);
        let status = sink_status(sink, cursor.as_ref(), store_head, now, alert_after);
        sinks.push(SinkView {
            sink: sink.clone(),
            status,
        });
    }
    let warnings = warnings(&policy, &sinks);
    Ok(AuditExportView {
        revision,
        alert_after_secs: settings.alert_after_secs,
        sinks,
        policy,
        store_head,
        warnings,
    })
}

/// Whether switching TGL-21 to `next` would leave a required export without a sink: the
/// check for the security settings and the profile switch (TGL-21 in Hardened refuses to
/// start without a sink).
///
/// # Errors
///
/// The store's error.
pub fn required_unmet(view: &dyn ReadView, next: AuditExport) -> Result<bool, StoreError> {
    let settings = view
        .get_typed(&SETTINGS, &())?
        .map(|(settings, _)| settings)
        .unwrap_or_default();
    Ok(!ExportPolicy::of(next, &settings).satisfied)
}

#[cfg(test)]
mod tests {
    use tenko_core::audit::Digest;
    use uuid::Uuid;

    use super::super::model::{ExportFormat, FileTarget, SinkTarget};
    use super::*;

    fn sink(name: &str, enabled: bool) -> Sink {
        Sink {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            enabled,
            format: ExportFormat::Json,
            target: SinkTarget::File(FileTarget {
                file: "audit.jsonl".to_owned(),
                max_bytes: 1 << 20,
                keep: 1,
            }),
        }
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_unix_nanos(i128::from(1_800_000_000 + seconds) * 1_000_000_000)
            .expect("time")
    }

    const DELAY: Duration = Duration::from_secs(300);

    fn cursor(seq: u64, updated: i64) -> ExportCursor {
        let mut cursor = ExportCursor::start(at(updated));
        cursor.delivered = ChainHead {
            seq: AuditSeq(seq),
            hash: Digest([1; 32]),
        };
        if seq > 0 {
            cursor.last_success_at = Some(at(updated));
        }
        cursor
    }

    #[test]
    fn states_follow_the_cursor() {
        let on = sink("a", true);
        let state = |cursor: Option<&ExportCursor>, head: u64, now: i64| {
            sink_status(&on, cursor, AuditSeq(head), at(now), DELAY).state
        };
        assert_eq!(
            sink_status(&sink("off", false), None, AuditSeq(5), at(0), DELAY).state,
            SinkState::Disabled
        );
        assert_eq!(state(None, 5, 0), SinkState::Pending);
        assert_eq!(state(Some(&cursor(0, 0)), 5, 10), SinkState::Pending);
        assert_eq!(state(Some(&cursor(5, 0)), 5, 1000), SinkState::Ok);
        assert_eq!(state(Some(&cursor(3, 0)), 5, 10), SinkState::Ok);
        assert_eq!(state(Some(&cursor(3, 0)), 5, 300), SinkState::Behind);
        let mut failing = cursor(3, 0);
        failing.failing_since = Some(at(0));
        assert_eq!(state(Some(&failing), 5, 299), SinkState::Failing);
        assert_eq!(state(Some(&failing), 5, 360), SinkState::Alarm);
        let status = sink_status(&on, Some(&failing), AuditSeq(5), at(360), DELAY);
        assert_eq!(status.lag, 2);
        assert_eq!(status.failing_since, Some(at(0)));
    }

    #[test]
    fn warnings_name_stuck_sinks_and_the_policy() {
        let settings = AuditExportSettings::default();
        let required = ExportPolicy::of(AuditExport::Required, &settings);
        assert!(required.required && !required.satisfied);
        let found = warnings(&required, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, REQUIRED);
        assert!(ExportPolicy::of(AuditExport::Optional, &settings).satisfied);

        let mut failing = cursor(3, 0);
        failing.failing_since = Some(at(0));
        let a = sink("a", true);
        let b = sink("b", true);
        let views = vec![
            SinkView {
                status: sink_status(&a, Some(&failing), AuditSeq(5), at(400), DELAY),
                sink: a,
            },
            SinkView {
                status: sink_status(&b, Some(&cursor(5, 0)), AuditSeq(5), at(400), DELAY),
                sink: b,
            },
        ];
        let settings = AuditExportSettings {
            sinks: views.iter().map(|view| view.sink.clone()).collect(),
            ..AuditExportSettings::default()
        };
        let policy = ExportPolicy::of(AuditExport::Required, &settings);
        let found = warnings(&policy, &views);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, FAILING);
        assert_eq!(found[0].params["sinks"], "a");
        assert_eq!(found[0].params["required"], "false");
        assert_eq!(found[0].params["since"], at(0).to_rfc3339());
        let found = warnings(&policy, &views[..1]);
        assert_eq!(found[0].params["required"], "true");
    }
}
