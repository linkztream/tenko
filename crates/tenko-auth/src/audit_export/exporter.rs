//! The exporter: a leader-only service ([`LeaderService`], plan section 2.3) that follows
//! `sys.audit` and hands every record to every enabled sink.
//!
//! # Delivery
//!
//! Each sink has a worker. It reads the records after the sink's cursor in batches, renders
//! them in the sink's format and sends them. The cursor is written to the store, fenced
//! with the leader epoch, every 5 seconds or 500 records and when the worker stops. A
//! worker that reconnects, and a controller that takes over after a leader change, resumes
//! at the stored cursor, so records after it may arrive twice but none is skipped: delivery
//! is at least once, and a receiver drops duplicates by sequence number (R28).
//!
//! # Checkpoints
//!
//! A checkpoint names the last record sent and the newest record of the log. A worker
//! sends one when it connects, after every 100 records, every 5 minutes (also while idle)
//! and at the top of every new file after a rotation, so a file verifies on its own.
//!
//! # Failure
//!
//! A failing sink is retried with a pause that doubles from one second up to a minute.
//! The first failure, a change of the failure's code and the recovery are written to the
//! cursor at once. Once a sink has failed for the settings' `alert_after_secs` (5 minutes
//! by default), the worker records the alarm `audit.export.failing` as the audit record
//! `sys.audit_export.failing`,
//! and `sys.audit_export.recovered` when the sink works again; every controller shows the
//! warning from the cursor ([`super::status`]).

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use futures::StreamExt;
use tenko_core::{
    AuditSeq, Principal, Revision, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft, AuditRecord, ChainHead},
    cluster::{LEADER_EPOCH, LeaderService},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt, Store, StoreError, WatchFilter, WriteBatch, fence,
    tables,
};
use tokio::{sync::watch, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    error::SinkError,
    format::{self, Checkpoint, Event, Framing, Origin},
    model::{
        AuditExportSettings, CURSORS, CheckpointMark, ExportCursor, SETTINGS, Sink, SinkFailure,
        SinkTarget,
    },
    sink::{Opener, Transport},
};

/// The name of the leader service.
pub const SERVICE: &str = "audit.export";
/// The audit action of a raised alarm (the alarm itself is `audit.export.failing`; audit
/// actions live in a store namespace).
pub const ALARM_ACTION: AuditAction = AuditAction::from_static("sys.audit_export.failing");
/// The audit action of a recovery after an alarm.
pub const RECOVERED_ACTION: AuditAction = AuditAction::from_static("sys.audit_export.recovered");

/// The rhythm of the exporter. The defaults are those of the plan; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// Records read and sent per batch.
    pub batch: usize,
    /// The cursor is written after this many records.
    pub cursor_records: u64,
    /// The cursor is written at least this often while records flow.
    pub cursor_every: Duration,
    /// A checkpoint follows this many records.
    pub checkpoint_records: u64,
    /// A checkpoint is sent at least this often, also while idle.
    pub checkpoint_every: Duration,
    /// The first pause after a failure.
    pub retry_min: Duration,
    /// The longest pause after failures.
    pub retry_max: Duration,
    /// How often an idle worker looks for new records when no change wakes it.
    pub idle_poll: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            batch: 500,
            cursor_records: 500,
            cursor_every: Duration::from_secs(5),
            checkpoint_records: 100,
            checkpoint_every: Duration::from_secs(300),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            idle_poll: Duration::from_secs(1),
        }
    }
}

/// The exporter service.
pub struct AuditExporter {
    store: Arc<dyn Store>,
    opener: Opener,
    hostname: String,
    version: String,
    tuning: Tuning,
}

impl std::fmt::Debug for AuditExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditExporter")
            .field("opener", &self.opener)
            .field("hostname", &self.hostname)
            .field("tuning", &self.tuning)
            .finish_non_exhaustive()
    }
}

/// Why a worker stopped.
enum Ended {
    /// The service was stopped.
    Stopped,
    /// A fenced write failed: the settings changed or another controller took office.
    Fenced,
}

impl AuditExporter {
    /// An exporter over `store`. `hostname` is the HOSTNAME of the syslog header (`-` when
    /// empty), `version` the product version of the CEF header.
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
            tuning: Tuning::default(),
        }
    }

    /// Replaces the rhythm.
    #[must_use]
    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// The settings and their revision (`None`: never stored).
    async fn settings(&self) -> Result<(AuditExportSettings, Option<Revision>), StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(match view.get_typed(&SETTINGS, &())? {
            Some((settings, revision)) => (settings, Some(revision)),
            None => (AuditExportSettings::default(), None),
        })
    }

    /// Whether the leader epoch moved past `epoch`.
    async fn deposed(&self, epoch: u64) -> bool {
        match self.store.read(ReadConsistency::Local).await {
            Ok(view) => view
                .counter(&LEADER_EPOCH)
                .is_ok_and(|value| value != epoch),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl LeaderService for AuditExporter {
    fn name(&self) -> &'static str {
        SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let (wake_tx, wake_rx) = watch::channel(0u64);
        let follower = follow_audit(Arc::clone(&self.store), wake_tx, stop.clone());
        let result = self.supervise(epoch, &stop, &wake_rx).await;
        follower.abort();
        result
    }
}

impl AuditExporter {
    async fn supervise(
        &self,
        epoch: u64,
        stop: &CancellationToken,
        wake: &watch::Receiver<u64>,
    ) -> Result<(), String> {
        loop {
            let (settings, revision) = self
                .settings()
                .await
                .map_err(|error| format!("reading the audit export settings: {error}"))?;
            let mut changes = self
                .store
                .watch(None, WatchFilter::tables([SETTINGS.name().clone()]))
                .map_err(|error| format!("watching the audit export settings: {error}"))?;
            let workers = stop.child_token();
            let mut tasks = JoinSet::new();
            for sink in settings.sinks.iter().filter(|sink| sink.enabled) {
                let worker = Worker {
                    store: Arc::clone(&self.store),
                    opener: self.opener.clone(),
                    origin: Origin {
                        hostname: self.hostname.clone(),
                        version: self.version.clone(),
                        sink: sink.name.clone(),
                    },
                    sink: sink.clone(),
                    alert_after: Duration::from_secs(u64::from(settings.alert_after_secs)),
                    settings_revision: revision,
                    epoch,
                    tuning: self.tuning,
                    wake: wake.clone(),
                };
                tasks.spawn(worker.run(workers.clone()));
            }
            tracing::info!(
                sinks = tasks.len(),
                epoch,
                "the audit export runs with {} sink(s)",
                tasks.len()
            );
            let fenced = loop {
                tokio::select! {
                    () = stop.cancelled() => break false,
                    change = changes.next() => match change {
                        Some(Ok(_)) => break false,
                        Some(Err(error)) => {
                            tracing::warn!(%error, "the watch of the audit export settings failed; restarting the sinks");
                            break false;
                        }
                        None => return Err("the store closed the settings watch".to_owned()),
                    },
                    Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                        if matches!(joined, Ok(Ended::Fenced)) {
                            break true;
                        }
                    }
                }
            };
            workers.cancel();
            while tasks.join_next().await.is_some() {}
            if stop.is_cancelled() {
                return Ok(());
            }
            if fenced && self.deposed(epoch).await {
                return Err("another controller took over the audit export".to_owned());
            }
        }
    }
}

/// Follows the commits that add audit records and publishes their revision.
fn follow_audit(
    store: Arc<dyn Store>,
    wake: watch::Sender<u64>,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let stream = store.watch(None, WatchFilter::tables([tables::AUDIT.name().clone()]));
            let Ok(mut stream) = stream else {
                // Workers poll on their own; try the watch again later.
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_secs(5)) => continue,
                }
            };
            loop {
                tokio::select! {
                    () = stop.cancelled() => return,
                    change = stream.next() => match change {
                        Some(Ok(change)) => {
                            wake.send_replace(change.revision.0);
                        }
                        Some(Err(_)) | None => break,
                    },
                }
            }
        }
    })
}

/// The export of one sink during one term.
struct Worker {
    store: Arc<dyn Store>,
    opener: Opener,
    origin: Origin,
    sink: Sink,
    alert_after: Duration,
    settings_revision: Option<Revision>,
    epoch: u64,
    tuning: Tuning,
    wake: watch::Receiver<u64>,
}

/// The worker's view of its cursor: the stored row and what has happened since.
struct Progress {
    /// The row as last written (or read).
    stored: ExportCursor,
    /// The row as it is now.
    current: ExportCursor,
    /// Records sent since the row was written.
    unsaved: u64,
    /// When the row was written.
    saved_at: Instant,
    /// Records sent since the last checkpoint.
    since_checkpoint: u64,
    /// When the last checkpoint was sent.
    checkpoint_at: Instant,
}

/// What stopped the inner loop of a connection.
enum Break {
    Ended(Ended),
    Failed(SinkError),
}

impl From<Ended> for Break {
    fn from(ended: Ended) -> Self {
        Break::Ended(ended)
    }
}

impl Worker {
    async fn run(mut self, stop: CancellationToken) -> Ended {
        let now = Timestamp::now();
        let stored = match self.read_cursor().await {
            Ok(cursor) => cursor.unwrap_or_else(|| ExportCursor::start(now)),
            Err(error) => {
                tracing::warn!(sink = %self.sink.name, %error, "reading the cursor of the audit export sink failed");
                ExportCursor::start(now)
            }
        };
        let mut progress = Progress {
            current: stored.clone(),
            stored,
            unsaved: 0,
            saved_at: Instant::now(),
            since_checkpoint: 0,
            checkpoint_at: Instant::now(),
        };
        let mut pause = self.tuning.retry_min;
        loop {
            let opened = tokio::select! {
                () = stop.cancelled() => return self.finish(&mut progress).await,
                opened = self.opener.open(&self.sink) => opened,
            };
            let failure = match opened {
                Ok(mut transport) => {
                    // Resume at the stored position: records sent after it on a broken
                    // connection may not have arrived (at least once).
                    progress.current.delivered = progress.stored.delivered;
                    progress.unsaved = 0;
                    match self
                        .connected(transport.as_mut(), &mut progress, &stop, &mut pause)
                        .await
                    {
                        Break::Ended(Ended::Stopped) => {
                            return self.finish(&mut progress).await;
                        }
                        Break::Ended(Ended::Fenced) => return Ended::Fenced,
                        Break::Failed(error) => error,
                    }
                }
                Err(error) => error,
            };
            tracing::warn!(sink = %self.sink.name, code = failure.kind.code(), error = %failure.detail, "the audit export sink failed");
            if let Err(ended) = self.failed(&mut progress, &failure).await {
                return ended;
            }
            tokio::select! {
                () = stop.cancelled() => return self.finish(&mut progress).await,
                () = tokio::time::sleep(pause) => {}
            }
            pause = (pause * 2).min(self.tuning.retry_max);
        }
    }

    /// Exports over an open transport until it fails or the worker stops.
    async fn connected(
        &mut self,
        transport: &mut dyn Transport,
        progress: &mut Progress,
        stop: &CancellationToken,
        pause: &mut Duration,
    ) -> Break {
        if let Err(error) = self.checkpoint(transport, progress).await {
            return Break::Failed(error);
        }
        if let Err(ended) = self.succeeded(progress).await {
            return ended.into();
        }
        *pause = self.tuning.retry_min;
        loop {
            if stop.is_cancelled() {
                return Ended::Stopped.into();
            }
            let records = match self.next_records(progress.current.delivered.seq).await {
                Ok(records) => records,
                Err(error) => {
                    tracing::warn!(sink = %self.sink.name, %error, "reading the audit log for the export failed");
                    Vec::new()
                }
            };
            if !records.is_empty() {
                if let Err(error) = self.send_records(transport, progress, &records).await {
                    return Break::Failed(error);
                }
                if let Err(ended) = self.succeeded(progress).await {
                    return ended.into();
                }
            }
            if progress.checkpoint_at.elapsed() >= self.tuning.checkpoint_every
                && let Err(error) = self.checkpoint(transport, progress).await
            {
                return Break::Failed(error);
            }
            if (progress.unsaved >= self.tuning.cursor_records
                || (progress.unsaved > 0
                    && progress.saved_at.elapsed() >= self.tuning.cursor_every))
                && let Err(ended) = self.save(progress, None).await
            {
                return ended.into();
            }
            if records.len() < self.tuning.batch {
                tokio::select! {
                    () = stop.cancelled() => return Ended::Stopped.into(),
                    changed = self.wake.changed() => {
                        if changed.is_err() {
                            tokio::time::sleep(self.tuning.idle_poll).await;
                        }
                    }
                    () = tokio::time::sleep(self.tuning.idle_poll) => {}
                }
            }
        }
    }

    /// Sends a batch of records with the checkpoints and rotations they call for.
    async fn send_records(
        &self,
        transport: &mut dyn Transport,
        progress: &mut Progress,
        records: &[AuditRecord],
    ) -> Result<(), SinkError> {
        let mut queued: Vec<Vec<u8>> = Vec::new();
        let mut queued_bytes = 0usize;
        let mut queued_head = progress.current.delivered;
        for record in records {
            let message = self.render(&Event::Record(record))?;
            if transport.needs_rotation(queued_bytes + message.len()) {
                if !queued.is_empty() {
                    transport.send(&queued).await?;
                    self.sent(progress, queued_head, &queued);
                    queued.clear();
                    queued_bytes = 0;
                }
                if transport.needs_rotation(message.len()) {
                    transport.rotate().await?;
                    let anchor = self.checkpoint_message(progress.current.delivered)?;
                    queued_bytes += anchor.len() + 1;
                    queued.push(anchor);
                    progress.since_checkpoint = 0;
                    progress.checkpoint_at = Instant::now();
                }
            }
            queued_bytes += message.len() + 1;
            queued.push(message);
            queued_head = ChainHead {
                seq: record.seq,
                hash: record.hash,
            };
            progress.since_checkpoint += 1;
            if progress.since_checkpoint >= self.tuning.checkpoint_records {
                let checkpoint = self.checkpoint_message(queued_head)?;
                queued_bytes += checkpoint.len() + 1;
                queued.push(checkpoint);
                progress.since_checkpoint = 0;
                progress.checkpoint_at = Instant::now();
                progress.current.checkpoint = Some(CheckpointMark {
                    head: queued_head,
                    at: Timestamp::now(),
                });
            }
        }
        if !queued.is_empty() {
            transport.send(&queued).await?;
            self.sent(progress, queued_head, &queued);
        }
        Ok(())
    }

    /// Records that the queued messages up to `head` went out.
    fn sent(&self, progress: &mut Progress, head: ChainHead, queued: &[Vec<u8>]) {
        let records = head.seq.0.saturating_sub(progress.current.delivered.seq.0);
        progress.unsaved += records;
        progress.current.delivered = head;
        tracing::trace!(sink = %self.sink.name, messages = queued.len(), seq = %head.seq, "audit records exported");
    }

    /// Sends a checkpoint now.
    async fn checkpoint(
        &self,
        transport: &mut dyn Transport,
        progress: &mut Progress,
    ) -> Result<(), SinkError> {
        let head = progress.current.delivered;
        let message = self.checkpoint_message(head)?;
        transport.send(&[message]).await?;
        progress.since_checkpoint = 0;
        progress.checkpoint_at = Instant::now();
        progress.current.checkpoint = Some(CheckpointMark {
            head,
            at: Timestamp::now(),
        });
        Ok(())
    }

    fn checkpoint_message(&self, head: ChainHead) -> Result<Vec<u8>, SinkError> {
        let checkpoint = Checkpoint {
            head,
            store_head: self.store.status().audit_head,
            at: Timestamp::now(),
        };
        self.render(&Event::Checkpoint(&checkpoint))
    }

    fn render(&self, event: &Event<'_>) -> Result<Vec<u8>, SinkError> {
        format::render(self.sink.format, framing(&self.sink), &self.origin, event).map_err(
            |error| {
                SinkError::new(
                    super::FailureKind::Config,
                    format!("an audit record cannot be encoded: {error}"),
                )
            },
        )
    }

    async fn next_records(&self, after: AuditSeq) -> Result<Vec<AuditRecord>, StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let range = KeyRange::all().after(tables::AUDIT.key(&after));
        Ok(view
            .scan_typed(&tables::AUDIT, range, self.tuning.batch, false)?
            .into_iter()
            .map(|(_, record, _)| record)
            .collect())
    }

    async fn read_cursor(&self) -> Result<Option<ExportCursor>, StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(view
            .get_typed(&CURSORS, &self.sink.id)?
            .map(|(cursor, _)| cursor))
    }

    /// Clears a failure after a success, writing at once when the state changes.
    async fn succeeded(&mut self, progress: &mut Progress) -> Result<(), Ended> {
        if progress.current.failing_since.is_none() {
            return Ok(());
        }
        let alarmed = progress.current.alarmed;
        let since = progress.current.failing_since.take();
        progress.current.alarmed = false;
        tracing::info!(sink = %self.sink.name, "the audit export sink works again");
        let draft = alarmed.then(|| {
            let mut draft = self.draft(RECOVERED_ACTION);
            if let Some(since) = since {
                draft = draft.with_context("failing_since", since.to_rfc3339());
            }
            draft
        });
        self.save(progress, draft).await
    }

    /// Records a failure: at once on the first failure, on a new failure code and when
    /// the alarm becomes due.
    async fn failed(&mut self, progress: &mut Progress, error: &SinkError) -> Result<(), Ended> {
        let now = Timestamp::now();
        let cursor = &mut progress.current;
        let first = cursor.failing_since.is_none();
        let new_code = cursor
            .last_error
            .as_ref()
            .is_none_or(|last| last.code != error.kind.code());
        if first {
            cursor.failing_since = Some(now);
        }
        cursor.last_error = Some(SinkFailure {
            code: error.kind.code().to_owned(),
            detail: error.detail.clone(),
            at: now,
        });
        let alarm = !cursor.alarmed && cursor.alarm_due(now, self.alert_after);
        let draft = if alarm {
            cursor.alarmed = true;
            tracing::error!(sink = %self.sink.name, code = error.kind.code(), "the audit export sink has been failing for {} s: alarm audit.export.failing", self.alert_after.as_secs());
            let since = cursor.failing_since.unwrap_or(now);
            Some(
                self.draft(ALARM_ACTION)
                    .with_context("code", error.kind.code())
                    .with_context("failing_since", since.to_rfc3339()),
            )
        } else {
            None
        };
        if first || new_code || alarm {
            self.save(progress, draft).await
        } else {
            Ok(())
        }
    }

    fn draft(&self, action: AuditAction) -> AuditDraft {
        AuditDraft::success(action, Vec::new())
            .with_context("sink", self.sink.id.to_string())
            .with_context("sink_name", self.sink.name.clone())
    }

    /// Writes the cursor (fenced with the epoch and the settings' revision), with an audit
    /// record when `draft` is set.
    async fn save(&self, progress: &mut Progress, draft: Option<AuditDraft>) -> Result<(), Ended> {
        let now = Timestamp::now();
        let mut row = progress.current.clone();
        row.updated_at = now;
        if progress.unsaved > 0 || row.delivered != progress.stored.delivered {
            row.last_success_at = Some(now);
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::AuditExport), now);
        batch.preconditions.push(fence(self.epoch));
        batch.expect_typed(&SETTINGS, &(), self.settings_revision);
        if let Err(error) = batch.put_typed(&CURSORS, &self.sink.id, &row) {
            tracing::warn!(sink = %self.sink.name, %error, "the cursor of the audit export sink cannot be encoded");
            return Ok(());
        }
        if let Some(draft) = draft {
            batch.audit(draft);
        }
        match self.store.propose(batch).await {
            Ok(_) => {
                progress.current = row.clone();
                progress.stored = row;
                progress.unsaved = 0;
                progress.saved_at = Instant::now();
                Ok(())
            }
            Err(StoreError::PreconditionFailed(_)) => Err(Ended::Fenced),
            Err(error) => {
                // Not fatal: the next save carries the same state.
                tracing::warn!(sink = %self.sink.name, %error, "writing the cursor of the audit export sink failed");
                Ok(())
            }
        }
    }

    /// Saves the final position when the worker stops.
    async fn finish(&self, progress: &mut Progress) -> Ended {
        if (progress.current != progress.stored || progress.unsaved > 0)
            && let Err(ended) = self.save(progress, None).await
        {
            return ended;
        }
        Ended::Stopped
    }
}

/// The framing of a sink's messages.
pub fn framing(sink: &Sink) -> Framing {
    match &sink.target {
        SinkTarget::Syslog(target) => Framing::Syslog(target.facility),
        SinkTarget::File(_) => Framing::File,
    }
}

/// Ids of the sinks whose cursors a settings change removes.
pub fn removed_sinks(before: &AuditExportSettings, after: &AuditExportSettings) -> Vec<Uuid> {
    let kept: BTreeSet<Uuid> = after.sinks.iter().map(|sink| sink.id).collect();
    before
        .sinks
        .iter()
        .filter(|sink| !kept.contains(&sink.id))
        .map(|sink| sink.id)
        .collect()
}
