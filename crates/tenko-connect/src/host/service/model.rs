//! The stored and returned shapes of the connector service, its tables, audit actions,
//! job kinds and errors.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, CodedError, ConnectorId, JobId, Revision, Timestamp, ipam::Stamp, secret::SecretRef,
};
use utoipa::ToSchema;

use crate::{
    ConnectorError, HealthReport,
    host::supervisor::SupervisorStatus,
    manifest::{ManifestError, SettingsError},
};

/// The store tables of the `connect` namespace.
pub mod tables {
    use tenko_core::{ConnectorId, table::TableDef};

    use super::{ConnectorInstance, LastRun};

    /// Connector instances by id.
    pub const INSTANCES: TableDef<ConnectorId, ConnectorInstance> =
        TableDef::new("connect.instances");
    /// Instance ids by lower-case name: keeps names unique.
    pub const NAMES: TableDef<String, ConnectorId> = TableDef::new("connect.names");
    /// The last run of each instance.
    pub const RUNS: TableDef<ConnectorId, LastRun> = TableDef::new("connect.runs");
}

/// Audit actions of the `connect` namespace.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A connector instance was created.
    pub const CREATE: AuditAction = AuditAction::from_static("connect.instance.create");
    /// A connector instance was changed.
    pub const UPDATE: AuditAction = AuditAction::from_static("connect.instance.update");
    /// A connector instance was enabled.
    pub const ENABLE: AuditAction = AuditAction::from_static("connect.instance.enable");
    /// A connector instance was disabled.
    pub const DISABLE: AuditAction = AuditAction::from_static("connect.instance.disable");
    /// A connector instance was deleted.
    pub const DELETE: AuditAction = AuditAction::from_static("connect.instance.delete");
    /// Secrets were injected into a plugin call (purposes and references, never values).
    pub const SECRET_INJECT: AuditAction = AuditAction::from_static("connect.secret.inject");
}

/// Job and step kinds of the `connect` namespace.
pub mod kinds {
    /// The inline job of an edit.
    pub const EDIT_JOB: &str = "connect.edit";
    /// Its step: stage the write batch.
    pub const WRITE_STEP: &str = "connect.write";
    /// The job of a run requested by a person.
    pub const RUN_JOB: &str = "connect.run";
    /// Its step: read the plugin and hand the observations on.
    pub const POLL_STEP: &str = "connect.poll";
    /// Title of the edit job (a UI message key).
    pub const EDIT_TITLE: &str = "connect.job.edit";
    /// Title of the run job (a UI message key).
    pub const RUN_TITLE: &str = "connect.job.run";
    /// Summary of the write step preview (a UI message key).
    pub const WRITE_PREVIEW: &str = "connect.job.write_preview";
    /// Summary of the poll step preview (a UI message key).
    pub const POLL_PREVIEW: &str = "connect.job.poll_preview";
}

/// Bounds of instance settings the host enforces.
pub mod bounds {
    /// Shortest poll interval in seconds.
    pub const MIN_POLL_SECS: u32 = 60;
    /// Longest poll interval in seconds.
    pub const MAX_POLL_SECS: u32 = 86_400;
    /// Default poll interval in seconds.
    pub const DEFAULT_POLL_SECS: u32 = 300;
    /// Shortest call timeout in seconds.
    pub const MIN_CALL_SECS: u32 = 1;
    /// Longest call timeout in seconds.
    pub const MAX_CALL_SECS: u32 = 600;
    /// Default call timeout in seconds.
    pub const DEFAULT_CALL_SECS: u32 = 30;
    /// Longest instance name in characters.
    pub const MAX_NAME: usize = 100;
}

/// A configured connector instance: one plugin, its settings and its secret references.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ConnectorInstance {
    /// Identifier.
    pub id: ConnectorId,
    /// The plugin name.
    pub plugin: String,
    /// The display name, unique (ignoring case).
    pub name: String,
    /// Whether the plugin runs and its schedule is active.
    pub enabled: bool,
    /// The settings, valid against the plugin's settings schema, with defaults filled in.
    #[schema(value_type = Object)]
    pub settings: serde_json::Value,
    /// Vault references by secret purpose; only purposes the manifest declares.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
    /// Seconds between scheduled reads; the manifest's default or 300 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u32>,
    /// Timeout of one call in seconds; the manifest's default or 30 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_timeout_secs: Option<u32>,
    /// Whether writes through this connector are allowed (TGL-20); off by default.
    #[serde(default)]
    pub writes_enabled: bool,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

/// The body of a create request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewConnector {
    /// The plugin name.
    pub plugin: String,
    /// The display name.
    pub name: String,
    /// The settings; validated against the plugin's settings schema.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub settings: serde_json::Value,
    /// Vault references by secret purpose.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
    /// Seconds between scheduled reads (60 to 86,400).
    #[serde(default)]
    pub poll_interval_secs: Option<u32>,
    /// Timeout of one call in seconds (1 to 600).
    #[serde(default)]
    pub call_timeout_secs: Option<u32>,
    /// Whether writes are allowed (TGL-20).
    #[serde(default)]
    pub writes_enabled: bool,
    /// Whether the instance starts enabled.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// The body of a change request: absent members stay as they are.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPatch {
    /// A new display name.
    #[serde(default)]
    pub name: Option<String>,
    /// New settings (the whole object; validated against the schema).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub settings: Option<serde_json::Value>,
    /// New secret references (the whole map).
    #[serde(default)]
    pub secrets: Option<BTreeMap<String, SecretRef>>,
    /// A new poll interval; `0` returns to the default.
    #[serde(default)]
    pub poll_interval_secs: Option<u32>,
    /// A new call timeout; `0` returns to the default.
    #[serde(default)]
    pub call_timeout_secs: Option<u32>,
    /// Whether writes are allowed.
    #[serde(default)]
    pub writes_enabled: Option<bool>,
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

const fn yes() -> bool {
    true
}

/// What started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunTrigger {
    /// The host's schedule.
    Schedule,
    /// A person (`POST /connectors/{id}/run`), as a job.
    Manual,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// The plugin answered and the observations were handed on.
    Succeeded,
    /// The run failed; `error` says why.
    Failed,
}

/// The last run of an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LastRun {
    /// What started it.
    pub trigger: RunTrigger,
    /// The job of a manual run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobId>,
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
    /// How it ended.
    pub outcome: RunOutcome,
    /// Observations handed on.
    pub observations: u32,
    /// Pages read.
    pub pages: u32,
    /// Values the host dropped or replaced (at most 20).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CodedError>,
    /// Failed runs in a row, this one included.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// When a run last succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<Timestamp>,
    /// The cursor of the last successful inventory read, for an incremental next poll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// When the inventory was last read in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_at: Option<Timestamp>,
}

/// The health of an instance: its process and its remote system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ConnectorHealth {
    /// The plugin process on this node.
    pub process: SupervisorStatus,
    /// The last remote check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<HealthReport>,
    /// Why the last remote check could not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_error: Option<CodedError>,
}

/// An instance as the API shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ConnectorView {
    /// The instance.
    #[serde(flatten)]
    pub instance: ConnectorInstance,
    /// The store revision of the instance (for `If-Match` style preconditions).
    pub revision: Revision,
    /// The plugin's capabilities, when the plugin is known.
    #[serde(default)]
    pub capabilities: Vec<crate::Capability>,
    /// Health of the process and the remote system.
    pub health: ConnectorHealth,
    /// The last run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<LastRun>,
}

/// A failure of the connector service, as a coded error for the API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.detail)]
pub struct HostError(pub Box<CodedError>);

impl HostError {
    /// An error with a code of this service.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self(Box::new(CodedError::new(code, status, detail)))
    }

    /// The error of any coded error.
    pub fn coded(error: &(impl Coded + ?Sized)) -> Self {
        Self(Box::new(error.to_coded_error()))
    }

    /// No such instance.
    pub fn not_found(id: ConnectorId) -> Self {
        Self::new(
            "connect.instance.not_found",
            404,
            format!("no connector instance {id}"),
        )
        .with_param("id", id.to_string())
    }

    /// An invalid value of a request member.
    pub fn invalid(code: &'static str, field: &str, detail: impl Into<String>) -> Self {
        Self::new(code, 422, detail).with_param("field", field)
    }

    /// Adds a parameter.
    #[must_use]
    pub fn with_param(mut self, key: &str, value: impl Into<String>) -> Self {
        self.0.params.insert(key.to_owned(), value.into());
        self
    }

    /// The coded error.
    pub fn into_coded(self) -> CodedError {
        *self.0
    }

    /// The stable code.
    pub fn code(&self) -> &str {
        &self.0.code
    }
}

impl From<tenko_store::StoreError> for HostError {
    fn from(error: tenko_store::StoreError) -> Self {
        if matches!(error, tenko_store::StoreError::PreconditionFailed(_)) {
            return Self::new(
                "connect.instance.conflict",
                409,
                "the connector instance changed at the same time; read it again and retry",
            );
        }
        Self::coded(&error)
    }
}

impl From<ConnectorError> for HostError {
    fn from(error: ConnectorError) -> Self {
        Self::coded(&error)
    }
}

impl From<SettingsError> for HostError {
    fn from(error: SettingsError) -> Self {
        Self::coded(&error)
    }
}

impl From<ManifestError> for HostError {
    fn from(error: ManifestError) -> Self {
        Self::coded(&error)
    }
}

impl From<tenko_core::codec::CodecError> for HostError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::coded(&error)
    }
}

impl From<tenko_jobs::JobError> for HostError {
    fn from(error: tenko_jobs::JobError) -> Self {
        if let tenko_jobs::JobError::Store(store) = error {
            return store.into();
        }
        let coded = error.to_coded_error();
        if coded.code == "sys.store.precondition_failed" {
            return Self::new(
                "connect.instance.conflict",
                409,
                "the connector instance changed at the same time; read it again and retry",
            );
        }
        Self(Box::new(coded))
    }
}

/// The effective interval of a poll interval setting.
pub fn poll_interval(instance: Option<u32>, manifest: Option<u32>) -> Duration {
    Duration::from_secs(u64::from(
        instance
            .or(manifest)
            .unwrap_or(bounds::DEFAULT_POLL_SECS)
            .clamp(bounds::MIN_POLL_SECS, bounds::MAX_POLL_SECS),
    ))
}

/// The effective timeout of a call timeout setting.
pub fn call_timeout(instance: Option<u32>, manifest: Option<u32>) -> Duration {
    Duration::from_secs(u64::from(
        instance
            .or(manifest)
            .unwrap_or(bounds::DEFAULT_CALL_SECS)
            .clamp(bounds::MIN_CALL_SECS, bounds::MAX_CALL_SECS),
    ))
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        Principal, SecretId,
        codec::{from_cbor, to_cbor},
        principal::SystemComponent,
    };

    use super::*;

    #[test]
    fn instances_round_trip_through_cbor_with_json_settings() {
        let stamp = Stamp::new(
            "2026-10-09T12:00:00Z".parse().expect("time"),
            Principal::system(SystemComponent::Connector),
        );
        let instance = ConnectorInstance {
            id: ConnectorId::generate(),
            plugin: "sample".to_owned(),
            name: "Lab inventory".to_owned(),
            enabled: true,
            settings: serde_json::json!({
                "site": "lab",
                "hosts": 8,
                "ratio": 0.5,
                "tags": ["a", "b"],
                "nested": { "flag": true, "none": null }
            }),
            secrets: BTreeMap::from([(
                "api_key".to_owned(),
                SecretRef {
                    secret: SecretId::generate(),
                },
            )]),
            poll_interval_secs: Some(600),
            call_timeout_secs: None,
            writes_enabled: false,
            created: stamp.clone(),
            updated: stamp,
        };
        let bytes = to_cbor(&instance).expect("cbor");
        assert_eq!(
            from_cbor::<ConnectorInstance>(&bytes).expect("cbor"),
            instance
        );
    }

    #[test]
    fn intervals_follow_instance_manifest_and_bounds() {
        assert_eq!(poll_interval(None, None), Duration::from_secs(300));
        assert_eq!(poll_interval(None, Some(120)), Duration::from_secs(120));
        assert_eq!(poll_interval(Some(10), Some(120)), Duration::from_secs(60));
        assert_eq!(call_timeout(Some(5000), None), Duration::from_secs(600));
    }

    #[test]
    fn requests_refuse_unknown_members() {
        let body = serde_json::json!({ "plugin": "sample", "name": "x", "colour": 1 });
        assert!(serde_json::from_value::<NewConnector>(body).is_err());
        let body = serde_json::json!({ "plugin": "sample", "name": "x" });
        let new: NewConnector = serde_json::from_value(body).expect("defaults");
        assert!(new.enabled);
        assert!(new.settings.is_object());
    }
}
