//! The settings of the export as the API changes them: read with status, replace with
//! audit, and send a test message.
//!
//! Every change is one write batch with its audit record `sys.audit_export.update`: the
//! settings row, a fresh cursor for every new sink and the removal of the cursors of
//! removed sinks. A change that TGL-21 forbids (a required export without an enabled
//! sink) is refused with `audit.export.required` and audited as failed. A test is
//! audited as `sys.audit_export.test` with its outcome.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    sync::Arc,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    FieldError, RequestCtx, Timestamp,
    audit::{AuditAction, AuditDraft, AuditOutcome, FieldChange},
};
use tenko_store::{ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    error::{ExportError, SinkError},
    exporter::framing,
    format::{self, Event, Origin, TestMessage},
    model::{
        AuditExportSettings, AuditExportUpdate, CURSORS, ExportCursor, SETTINGS, START, Sink,
        SinkFailure, SinkSpec, SinkTarget, SyslogTransport, certificate_digests,
    },
    sink::{Opener, client_key_of},
    status::{AuditExportView, ExportPolicy, read_view, toggle},
};

/// The audit action of a settings change.
pub const UPDATE_ACTION: AuditAction = AuditAction::from_static("sys.audit_export.update");
/// The audit action of a test message.
pub const TEST_ACTION: AuditAction = AuditAction::from_static("sys.audit_export.test");

/// What `POST /settings/audit-export/test` sends to: a stored sink by id, or a sink as
/// the form holds it before it is saved. Exactly one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportTest {
    /// The id of a stored sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<Uuid>,
    /// An unsaved sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<SinkSpec>,
}

/// The result of a test message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportTestResult {
    /// Whether the message was handed to the sink (for UDP: sent; nothing confirms
    /// receipt).
    pub delivered: bool,
    /// The failure, when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SinkFailure>,
    /// How long the attempt took.
    pub elapsed_ms: u64,
}

/// The export's settings service.
pub struct AuditExportAdmin {
    store: Arc<dyn Store>,
    opener: Opener,
    hostname: String,
    version: String,
}

impl std::fmt::Debug for AuditExportAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditExportAdmin")
            .field("opener", &self.opener)
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

impl AuditExportAdmin {
    /// The service over `store`; `opener`, `hostname` and `version` as for the exporter.
    pub fn new(
        store: Arc<dyn Store>,
        opener: Opener,
        hostname: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            store,
            opener,
            hostname: hostname.into(),
            version: version.into(),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The settings with the status of every sink.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn view(&self, now: Timestamp) -> Result<AuditExportView, ExportError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(read_view(view.as_ref(), now)?)
    }

    /// Replaces the settings. `if_match` is the revision the client read.
    ///
    /// # Errors
    ///
    /// [`ExportError::Invalid`], [`ExportError::Required`], [`ExportError::Conflict`] or
    /// the store's error.
    pub async fn update(
        &self,
        ctx: &RequestCtx,
        update: AuditExportUpdate,
        if_match: Option<u64>,
    ) -> Result<AuditExportView, ExportError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let (before, revision) = match view.get_typed(&SETTINGS, &())? {
            Some((settings, revision)) => (settings, Some(revision)),
            None => (AuditExportSettings::default(), None),
        };
        let current = revision.map_or(0, |revision| revision.0);
        if let Some(expected) = if_match
            && expected != current
        {
            return Err(ExportError::Conflict { expected, current });
        }
        let known: BTreeSet<Uuid> = before.sinks.iter().map(|sink| sink.id).collect();
        let after = update.validate(&known)?;
        self.check_client_keys(&after, |index| format!("sinks[{index}]"))
            .await?;
        let policy = ExportPolicy::of(toggle(view.as_ref())?, &after);
        if !policy.satisfied {
            self.audit_refusal(ctx, &ExportError::Required).await;
            return Err(ExportError::Required);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&SETTINGS, &(), revision);
        batch.put_typed(&SETTINGS, &(), &after)?;
        let mut restarted = Vec::new();
        for sink in &after.sinks {
            let moved = before
                .sink(sink.id)
                .is_some_and(|was| was.destination_differs(sink));
            if moved {
                // Another place gets the whole log, as a new sink does: the records sent to
                // the place before are not taken as delivered to this one.
                let from = view
                    .get_typed(&CURSORS, &sink.id)?
                    .map_or(START.seq, |(cursor, _)| cursor.delivered.seq);
                restarted.push((sink.id, from));
            }
            if moved || !known.contains(&sink.id) {
                batch.put_typed(&CURSORS, &sink.id, &ExportCursor::start(ctx.now))?;
            }
        }
        for id in super::exporter::removed_sinks(&before, &after) {
            batch.delete_typed(&CURSORS, &id);
        }
        let mut draft =
            AuditDraft::success(UPDATE_ACTION, Vec::new()).with_source_ip(ctx.source_ip);
        for change in changes(&before, &after) {
            draft = draft.with_change(change);
        }
        for (id, from) in restarted {
            draft = draft.with_change(FieldChange {
                object: None,
                field: format!("cursor:{id}"),
                old: Some(from.0.to_string()),
                new: Some(START.seq.0.to_string()),
            });
        }
        batch.audit(draft);
        match self.store.propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => {
                let now = self.store.read(ReadConsistency::Local).await?;
                let current = now
                    .get_typed(&SETTINGS, &())?
                    .map_or(0, |(_, revision)| revision.0);
                return Err(ExportError::Conflict {
                    expected: if_match.unwrap_or(revision.map_or(0, |r| r.0)),
                    current,
                });
            }
            Err(error) => return Err(error.into()),
        }
        self.view(ctx.now).await
    }

    /// Refuses a TLS client key that is not an operator secret of the vault: a system
    /// secret (a CA key, a TOTP seed) is never a sink's key, and a missing secret answers
    /// the same, so the refusal tells nothing about what a secret is. `at` names the sink
    /// of an index in the field of the error.
    async fn check_client_keys(
        &self,
        settings: &AuditExportSettings,
        at: impl Fn(usize) -> String,
    ) -> Result<(), ExportError> {
        let mut problems = Vec::new();
        for (index, sink) in settings.sinks.iter().enumerate() {
            let Some(secret) = client_key_of(sink) else {
                continue;
            };
            let operator = self
                .opener
                .is_operator_secret(secret)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "the class of an audit export client key cannot be read");
                    false
                });
            if !operator {
                problems.push(FieldError::new(
                    format!("{}.target.tls.client_key", at(index)),
                    "audit.export.client_key",
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ExportError::Invalid(problems))
        }
    }

    async fn audit_refusal(&self, ctx: &RequestCtx, error: &ExportError) {
        let mut batch = WriteBatch::for_request(ctx);
        let mut draft =
            AuditDraft::success(UPDATE_ACTION, Vec::new()).with_source_ip(ctx.source_ip);
        draft.outcome = AuditOutcome::failed(error);
        batch.audit(draft);
        if let Err(store) = self.store.propose(batch).await {
            tracing::warn!(error = %store, "the refused audit export change could not be audited");
        }
    }

    /// Sends a test message from this controller to a stored or an unsaved sink.
    ///
    /// # Errors
    ///
    /// [`ExportError::Invalid`] for a malformed request or sink, [`ExportError::NotFound`]
    /// for an unknown id, or the store's error. A failed delivery is not an error: the
    /// result says why.
    pub async fn test(
        &self,
        ctx: &RequestCtx,
        request: AuditExportTest,
    ) -> Result<AuditExportTestResult, ExportError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let settings = view
            .get_typed(&SETTINGS, &())?
            .map(|(settings, _)| settings)
            .unwrap_or_default();
        let sink = match (request.sink, request.spec) {
            (Some(id), None) => settings
                .sink(id)
                .cloned()
                .ok_or(ExportError::NotFound(id))?,
            (None, Some(spec)) => {
                let known: BTreeSet<Uuid> = settings.sinks.iter().map(|sink| sink.id).collect();
                let mut validated = AuditExportUpdate {
                    sinks: vec![spec],
                    alert_after_secs: settings.alert_after_secs,
                }
                .validate(&known)
                .map_err(|error| match error {
                    ExportError::Invalid(problems) => ExportError::Invalid(
                        problems
                            .into_iter()
                            .map(|mut problem| {
                                problem.field = problem.field.replacen("sinks[0]", "spec", 1);
                                problem
                            })
                            .collect(),
                    ),
                    other => other,
                })?;
                self.check_client_keys(&validated, |_| "spec".to_owned())
                    .await?;
                validated.sinks.remove(0)
            }
            _ => {
                return Err(ExportError::Invalid(vec![FieldError::new(
                    "sink",
                    "audit.export.test_target",
                )]));
            }
        };
        let started = Instant::now();
        let outcome = self.send_test(ctx, &sink).await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut draft = AuditDraft::success(TEST_ACTION, Vec::new())
            .with_source_ip(ctx.source_ip)
            .with_context("sink_name", sink.name.clone())
            .with_context("target", summary(&sink));
        if request.sink.is_some() {
            draft = draft.with_context("sink", sink.id.to_string());
        }
        let result = match outcome {
            Ok(()) => AuditExportTestResult {
                delivered: true,
                error: None,
                elapsed_ms,
            },
            Err(error) => {
                draft.outcome = AuditOutcome::Failed {
                    code: std::borrow::Cow::Borrowed(error.kind.code()),
                };
                AuditExportTestResult {
                    delivered: false,
                    error: Some(SinkFailure {
                        code: error.kind.code().to_owned(),
                        detail: error.detail,
                        at: ctx.now,
                    }),
                    elapsed_ms,
                }
            }
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(draft);
        self.store.propose(batch).await?;
        Ok(result)
    }

    async fn send_test(&self, ctx: &RequestCtx, sink: &Sink) -> Result<(), SinkError> {
        let origin = Origin {
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            sink: sink.name.clone(),
        };
        let test = TestMessage {
            at: ctx.now,
            by: ctx.principal.subject(),
        };
        let message = format::render(sink.format, framing(sink), &origin, &Event::Test(&test))
            .map_err(|error| SinkError::new(super::FailureKind::Config, error.to_string()))?;
        let key = match client_key_of(sink) {
            Some(secret) => Some(self.read_client_key(ctx, sink, secret).await?),
            None => None,
        };
        let mut transport = self
            .opener
            .open_with_key(sink, key.as_ref().map(|key| key.as_slice()))
            .await?;
        transport.send(&[message]).await
    }

    /// Records the use of a sink's client key for a test, then reads it: as the exporter
    /// does, a key of another class is refused before anything is recorded, and a key whose
    /// use cannot be recorded is not read.
    async fn read_client_key(
        &self,
        ctx: &RequestCtx,
        sink: &Sink,
        secret: tenko_core::SecretId,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SinkError> {
        let unusable = |detail: String| SinkError::new(super::FailureKind::ClientKey, detail);
        match self.opener.is_operator_secret(secret).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(unusable(format!(
                    "the client key {secret} is not an operator secret of the vault"
                )));
            }
            Err(error) => {
                return Err(unusable(format!(
                    "the client key {secret} cannot be read from the vault: {error}"
                )));
            }
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(
            AuditDraft::success(
                super::exporter::CLIENT_KEY_ACTION,
                vec![tenko_core::ObjectRef::from(secret)],
            )
            .with_source_ip(ctx.source_ip)
            .with_context("sink_name", sink.name.clone())
            .with_context("test", "true"),
        );
        self.store.propose(batch).await.map_err(|error| {
            unusable(format!(
                "the use of the client key could not be audited, so it was not read: {error}"
            ))
        })?;
        self.opener.client_key(secret).await
    }
}

/// A one-line description of a sink for the audit trail; never a secret.
pub fn summary(sink: &Sink) -> String {
    let target = match &sink.target {
        SinkTarget::Syslog(target) => {
            let mut text = format!(
                "syslog {} {}:{}",
                target.transport.as_str(),
                target.host,
                target.port()
            );
            if target.transport == SyslogTransport::Tls {
                text.push_str(if target.tls.ca_pem.is_some() {
                    " ca=pinned"
                } else {
                    " ca=system"
                });
                // The fingerprints of the pinned authorities and of the client chain, so that
                // a swapped certificate shows in the record of the change.
                if let Some(pem) = &target.tls.ca_pem {
                    let _ = write!(text, " ca_sha256={}", fingerprints(pem));
                }
                if let Some(name) = &target.tls.server_name {
                    let _ = write!(text, " server_name={name}");
                }
                if let Some(pem) = &target.tls.client_cert_pem {
                    let _ = write!(text, " client_cert_sha256={}", fingerprints(pem));
                }
                if let Some(key) = target.tls.client_key {
                    let _ = write!(text, " client_key={key}");
                }
            }
            text
        }
        SinkTarget::File(target) => format!(
            "file {} max_bytes={} keep={}",
            target.file, target.max_bytes, target.keep
        ),
    };
    format!(
        "{} {} {}",
        target,
        sink.format.as_str(),
        if sink.enabled { "enabled" } else { "disabled" }
    )
}

/// The SHA-256 fingerprints of the certificates of a PEM text, comma-separated, or
/// `unreadable` for a text that does not parse (a row stored before the check).
fn fingerprints(pem: &str) -> String {
    certificate_digests(pem).map_or_else(|| "unreadable".to_owned(), |digests| digests.join(","))
}

/// The field changes between two settings: one per added, removed or changed sink
/// (`sink:<id>`), and the alarm delay.
fn changes(before: &AuditExportSettings, after: &AuditExportSettings) -> Vec<FieldChange> {
    let old: BTreeMap<Uuid, &Sink> = before.sinks.iter().map(|sink| (sink.id, sink)).collect();
    let new: BTreeMap<Uuid, &Sink> = after.sinks.iter().map(|sink| (sink.id, sink)).collect();
    let mut out = Vec::new();
    let line = |sink: &Sink| format!("{}: {}", sink.name, summary(sink));
    for id in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let (was, is) = (old.get(id), new.get(id));
        if was.copied() != is.copied() {
            out.push(FieldChange {
                object: None,
                field: format!("sink:{id}"),
                old: was.map(|sink| line(sink)),
                new: is.map(|sink| line(sink)),
            });
        }
    }
    if before.alert_after_secs != after.alert_after_secs {
        out.push(FieldChange {
            object: None,
            field: "alert_after_secs".to_owned(),
            old: Some(before.alert_after_secs.to_string()),
            new: Some(after.alert_after_secs.to_string()),
        });
    }
    out
}
