//! Commands to nodes (SCAN-09): rows in `cluster.node_commands` that every controller
//! streams to the nodes connected to it, and the reports that come back.
//!
//! A command is issued by a scan job or the kill switch with [`stage_issue`] in the
//! issuer's own write batch. Its id is a UUIDv7, so a node's commands sort in issue order.
//! The node reports `accepted`, `running` with a progress, then `done`, `failed` or
//! `rejected` ([`apply_report`]); a report never moves a command backwards, and one that
//! arrives twice changes nothing. A command that is not final when its `expires_at` passes
//! is not sent again; the issuer marks it `expired` ([`stage_expire`]).
//!
//! Results of a scan run travel through the observation buffer as batches tagged with the
//! command id; the ingest counts them in `ingested`, and the node names their number with
//! `done` (`batches`), so the issuer knows when every result has arrived.

use std::{fmt, str::FromStr, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, Principal, RequestCtx, Revision, Timestamp, UserId, serde_util::HexBytes,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};
use uuid::Uuid;

use super::{codes, store_error, tables::NODE_COMMANDS};
use crate::{error::ClusterError, probe::timestamp_from_proto, proto::v1};

/// Run scan methods now: [`ScanRunArgs`](super::payload::ScanRunArgs).
pub const SCAN_RUN: &str = "scan.run";
/// Cancel a running `scan.run`: [`CancelArgs`](super::payload::CancelArgs).
pub const SCAN_CANCEL: &str = "scan.cancel";
/// Switch the kill switch on: [`StopArgs`](super::payload::StopArgs).
pub const SCAN_STOP: &str = "scan.stop";
/// Switch the kill switch off; no arguments.
pub const SCAN_RESUME: &str = "scan.resume";

/// How many times a report is planned before a conflict is returned.
const REPORT_ATTEMPTS: usize = 4;

/// The state of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    /// Issued; the node has not confirmed it yet.
    Pending,
    /// The node took it.
    Accepted,
    /// The node works on it.
    Running,
    /// Finished.
    Done,
    /// The node tried and failed.
    Failed,
    /// The node refused it (an unknown kind, arguments it cannot use).
    Rejected,
    /// Not finished before its deadline.
    Expired,
    /// Withdrawn by the issuer.
    Cancelled,
}

impl CommandState {
    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the command is over.
    pub const fn is_final(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Failed | Self::Rejected | Self::Expired | Self::Cancelled
        )
    }

    /// The order of the states a report may move through.
    const fn rank(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Accepted => 1,
            Self::Running => 2,
            _ => 3,
        }
    }
}

impl fmt::Display for CommandState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CommandState {
    type Err = ClusterError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match text {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "running" => Self::Running,
            "done" => Self::Done,
            "failed" => Self::Failed,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            other => {
                return Err(ClusterError::new(
                    codes::COMMAND_INVALID,
                    400,
                    format!("`{other}` is not a command state"),
                ));
            }
        })
    }
}

/// A command to a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// The command id (UUIDv7).
    pub id: Uuid,
    /// The node it is for.
    pub node: NodeId,
    /// What to do ([`SCAN_RUN`] and the others).
    pub kind: String,
    /// The encoding of `payload` (`cbor/1`).
    pub encoding: String,
    /// The arguments.
    pub payload: HexBytes,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// Who asked for it, when a person did.
    #[serde(default)]
    pub issued_by: Option<UserId>,
    /// The scan run it belongs to (`scan.runs`), if any.
    #[serde(default)]
    pub run: Option<Uuid>,
    /// When it is no longer sent; `None` keeps it until the node reports.
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
    /// The state.
    pub state: CommandState,
    /// Progress in percent.
    #[serde(default)]
    pub progress: u8,
    /// The node's last detail, in English.
    #[serde(default)]
    pub detail: Option<String>,
    /// The batches the node queued for the command, reported with `done`.
    #[serde(default)]
    pub batches: Option<u32>,
    /// The batches tagged with the command id that controllers ingested.
    #[serde(default)]
    pub ingested: u32,
    /// When the record last changed.
    pub updated_at: Timestamp,
    /// The node's clock at its last report.
    #[serde(default)]
    pub reported_at: Option<Timestamp>,
}

impl CommandRecord {
    /// A new pending command for `node`.
    pub fn new(
        node: NodeId,
        kind: impl Into<String>,
        payload: Vec<u8>,
        issued_at: Timestamp,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            node,
            kind: kind.into(),
            encoding: super::payload::CBOR.to_owned(),
            payload: HexBytes(payload),
            issued_at,
            issued_by: None,
            run: None,
            expires_at: None,
            state: CommandState::Pending,
            progress: 0,
            detail: None,
            batches: None,
            ingested: 0,
            updated_at: issued_at,
            reported_at: None,
        }
    }

    /// Whether every result the node announced has been ingested.
    pub fn results_in(&self) -> bool {
        self.batches.is_none_or(|batches| self.ingested >= batches)
    }

    /// Whether the command is over and its results are in (or it ended without any).
    pub fn settled(&self) -> bool {
        self.state.is_final() && (self.state != CommandState::Done || self.results_in())
    }

    /// Whether a node should still receive it at `now`.
    pub fn deliverable(&self, now: Timestamp) -> bool {
        !self.state.is_final() && self.expires_at.is_none_or(|at| at > now)
    }

    /// The command as the node receives it.
    pub fn to_proto(&self) -> v1::Command {
        v1::Command {
            id: self.id.to_string(),
            kind: self.kind.clone(),
            issued_at: Some(crate::probe::timestamp_to_proto(self.issued_at)),
            encoding: self.encoding.clone(),
            payload: self.payload.0.clone(),
        }
    }

    /// Applies a report; whether the record changed.
    pub fn apply(&mut self, report: &Report, now: Timestamp) -> bool {
        if self.state.is_final() {
            return false;
        }
        let before = self.clone();
        if report.state.rank() >= self.state.rank() {
            self.state = report.state;
        }
        let progress = if self.state == CommandState::Done {
            100
        } else {
            report.progress.min(100)
        };
        self.progress = self.progress.max(progress);
        if let Some(detail) = report.detail.as_ref().filter(|detail| !detail.is_empty()) {
            self.detail = Some(detail.clone());
        }
        if self.state == CommandState::Done && report.batches.is_some() {
            self.batches = report.batches;
        }
        if *self == before {
            return false;
        }
        self.reported_at = report.at.or(self.reported_at);
        self.updated_at = now;
        true
    }
}

/// Most sightings of one batch kept as the result of a command; the rest is counted.
pub const MAX_RESULT_SIGHTINGS: usize = 20_000;

/// What one batch tagged with a command reported (`scan.run_results`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    /// The node.
    pub node: NodeId,
    /// The batch, cut to [`MAX_RESULT_SIGHTINGS`] sightings.
    pub batch: crate::probe::ProbeBatch,
    /// Sightings left out by the cut.
    #[serde(default)]
    pub left_out: u32,
    /// When a controller ingested it.
    pub ingested_at: Timestamp,
}

impl RunResult {
    /// The result of `batch` from `node`, cut to the limit.
    pub fn of(node: NodeId, batch: &crate::probe::ProbeBatch, now: Timestamp) -> Self {
        let mut batch = batch.clone();
        let left_out = batch.sightings.len().saturating_sub(MAX_RESULT_SIGHTINGS);
        batch.sightings.truncate(MAX_RESULT_SIGHTINGS);
        Self {
            node,
            batch,
            left_out: u32::try_from(left_out).unwrap_or(u32::MAX),
            ingested_at: now,
        }
    }
}

/// Every result of a command, in batch order.
///
/// # Errors
///
/// A store error.
pub fn results_of(view: &dyn ReadView, command: Uuid) -> Result<Vec<RunResult>, StoreError> {
    let prefix = tenko_core::codec::key::encode_key(&(command,));
    Ok(view
        .scan_typed(
            &super::tables::RUN_RESULTS,
            KeyRange::prefix(prefix),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, result, _)| result)
        .collect())
}

/// A node's report on a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The command.
    pub command: Uuid,
    /// The state reached; never `pending`, `expired` or `cancelled`.
    pub state: CommandState,
    /// Progress in percent.
    pub progress: u8,
    /// English detail.
    pub detail: Option<String>,
    /// The node's clock.
    pub at: Option<Timestamp>,
    /// The batches queued for the command (with `done`).
    pub batches: Option<u32>,
}

impl Report {
    /// The report of a protobuf event.
    ///
    /// # Errors
    ///
    /// `node.command.invalid` (400) for an id that is not a UUID or a state a node does
    /// not report.
    pub fn from_proto(event: &v1::CommandEvent) -> Result<Self, ClusterError> {
        let command = event.command_id.parse::<Uuid>().map_err(|_| {
            ClusterError::new(
                codes::COMMAND_INVALID,
                400,
                format!("`{}` is not a command id", event.command_id),
            )
        })?;
        let state: CommandState = event.state.parse()?;
        if matches!(
            state,
            CommandState::Pending | CommandState::Expired | CommandState::Cancelled
        ) {
            return Err(ClusterError::new(
                codes::COMMAND_INVALID,
                400,
                format!("a node does not report the state `{state}`"),
            ));
        }
        Ok(Self {
            command,
            state,
            progress: u8::try_from(event.progress_percent.min(100)).unwrap_or(100),
            detail: Some(event.detail.chars().take(2000).collect::<String>())
                .filter(|detail| !detail.is_empty()),
            at: event.at.as_ref().and_then(timestamp_from_proto),
            batches: (state == CommandState::Done).then_some(event.batches),
        })
    }

    /// The report as a protobuf event.
    pub fn to_proto(&self) -> v1::CommandEvent {
        v1::CommandEvent {
            command_id: self.command.to_string(),
            state: self.state.as_str().to_owned(),
            progress_percent: u32::from(self.progress),
            detail: self.detail.clone().unwrap_or_default(),
            at: self.at.map(crate::probe::timestamp_to_proto),
            batches: self.batches.unwrap_or(0),
        }
    }
}

/// Adds a new command to `batch`; the key must be free.
///
/// # Errors
///
/// The codec error of a record that does not encode.
pub fn stage_issue(batch: &mut WriteBatch, record: &CommandRecord) -> Result<(), StoreError> {
    let key = (record.node.0, record.id);
    batch.expect_typed(&NODE_COMMANDS, &key, None);
    batch.put_typed(&NODE_COMMANDS, &key, record)?;
    Ok(())
}

/// Marks a command that is not final as `state` (`expired` or `cancelled`) in `batch`,
/// guarded by its revision; returns whether anything was staged.
///
/// # Errors
///
/// The codec error of a record that does not encode.
pub fn stage_expire(
    batch: &mut WriteBatch,
    record: &CommandRecord,
    revision: Revision,
    state: CommandState,
    now: Timestamp,
) -> Result<bool, StoreError> {
    if record.state.is_final() {
        return Ok(false);
    }
    let mut next = record.clone();
    next.state = state;
    next.updated_at = now;
    let key = (record.node.0, record.id);
    batch.expect_typed(&NODE_COMMANDS, &key, Some(revision));
    batch.put_typed(&NODE_COMMANDS, &key, &next)?;
    Ok(true)
}

/// One command of a node with its revision.
///
/// # Errors
///
/// A store error.
pub fn get(
    view: &dyn ReadView,
    node: NodeId,
    command: Uuid,
) -> Result<Option<(CommandRecord, Revision)>, StoreError> {
    view.get_typed(&NODE_COMMANDS, &(node.0, command))
}

/// Every command of a node in issue order, with revisions.
///
/// # Errors
///
/// A store error.
pub fn of_node(
    view: &dyn ReadView,
    node: NodeId,
) -> Result<Vec<(CommandRecord, Revision)>, StoreError> {
    let prefix = tenko_core::codec::key::encode_key(&(node.0,));
    Ok(view
        .scan_typed(&NODE_COMMANDS, KeyRange::prefix(prefix), usize::MAX, false)?
        .into_iter()
        .map(|(_, record, revision)| (record, revision))
        .collect())
}

/// The commands a node should receive at `now`, in issue order, after `after` (exclusive).
///
/// # Errors
///
/// A store error.
pub fn deliverable(
    view: &dyn ReadView,
    node: NodeId,
    after: Option<Uuid>,
    now: Timestamp,
) -> Result<Vec<CommandRecord>, StoreError> {
    Ok(of_node(view, node)?
        .into_iter()
        .map(|(record, _)| record)
        .filter(|record| after.is_none_or(|after| record.id > after))
        .filter(|record| record.deliverable(now))
        .collect())
}

/// Applies a node's report to its command and returns the record as stored.
///
/// # Errors
///
/// `node.command.not_found` (404) for a command of another node or none,
/// `cluster.no_quorum` (503) while the store cannot write, `node.command.conflict` (409)
/// when every attempt lost a race, or a store error.
pub async fn apply_report(
    store: &dyn Store,
    node: NodeId,
    report: &Report,
) -> Result<CommandRecord, ClusterError> {
    for attempt in 0..REPORT_ATTEMPTS {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = store.read(consistency).await.map_err(store_error)?;
        let Some((mut record, revision)) = get(view.as_ref(), node, report.command)? else {
            return Err(ClusterError::new(
                codes::COMMAND_NOT_FOUND,
                404,
                format!("node {node} has no command {}", report.command),
            ));
        };
        drop(view);
        let now = Timestamp::now();
        if !record.apply(report, now) {
            return Ok(record);
        }
        let ctx = RequestCtx::new(Principal::Node { id: node });
        let mut batch = WriteBatch::for_request(&ctx);
        let key = (node.0, record.id);
        batch.expect_typed(&NODE_COMMANDS, &key, Some(revision));
        batch.put_typed(&NODE_COMMANDS, &key, &record)?;
        match store.propose(batch).await {
            Ok(_) => return Ok(record),
            Err(StoreError::PreconditionFailed(_)) => {
                tokio::time::sleep(Duration::from_millis(10 << attempt)).await;
            }
            Err(error) => return Err(store_error(error)),
        }
    }
    Err(ClusterError::new(
        codes::COMMAND_CONFLICT,
        409,
        format!(
            "the report on command {} lost every race for the record",
            report.command
        ),
    ))
}

/// A command as a node receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingCommand {
    /// The command id.
    pub id: Uuid,
    /// What to do.
    pub kind: String,
    /// When it was issued.
    pub issued_at: Option<Timestamp>,
    /// The encoding of the arguments.
    pub encoding: String,
    /// The arguments.
    pub payload: Vec<u8>,
}

impl IncomingCommand {
    /// The command of a protobuf message; `None` when its id is not a UUID.
    pub fn from_proto(command: v1::Command) -> Option<Self> {
        Some(Self {
            id: command.id.parse().ok()?,
            kind: command.kind,
            issued_at: command.issued_at.as_ref().and_then(timestamp_from_proto),
            encoding: command.encoding,
            payload: command.payload,
        })
    }

    /// The command of a stored record (the in-process probe of a controller).
    pub fn from_record(record: &CommandRecord) -> Self {
        Self {
            id: record.id,
            kind: record.kind.clone(),
            issued_at: Some(record.issued_at),
            encoding: record.encoding.clone(),
            payload: record.payload.0.clone(),
        }
    }
}

/// Where a node's reports go: the agent's queue to the controllers, or the store directly
/// for the in-process probe of a controller.
pub trait ReportSink: Send + Sync {
    /// Queues a report; reports of one command arrive in the order they were queued.
    fn push(&self, report: Report);
}

/// Reports the progress of one command.
#[derive(Clone)]
pub struct CommandReporter {
    command: Uuid,
    sink: Arc<dyn ReportSink>,
}

impl fmt::Debug for CommandReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandReporter")
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}

impl CommandReporter {
    /// A reporter for `command` into `sink`.
    pub fn new(command: Uuid, sink: Arc<dyn ReportSink>) -> Self {
        Self { command, sink }
    }

    /// The command.
    pub fn command(&self) -> Uuid {
        self.command
    }

    fn push(
        &self,
        state: CommandState,
        progress: u8,
        detail: Option<String>,
        batches: Option<u32>,
    ) {
        self.sink.push(Report {
            command: self.command,
            state,
            progress,
            detail,
            at: Some(Timestamp::now()),
            batches,
        });
    }

    /// The node took the command.
    pub fn accepted(&self) {
        self.push(CommandState::Accepted, 0, None, None);
    }

    /// The node works on it, `progress` percent done.
    pub fn running(&self, progress: u8, detail: Option<String>) {
        self.push(CommandState::Running, progress, detail, None);
    }

    /// Finished, having queued `batches` observation batches tagged with the command id.
    pub fn done(&self, batches: u32, detail: Option<String>) {
        self.push(CommandState::Done, 100, detail, Some(batches));
    }

    /// The node tried and failed.
    pub fn failed(&self, detail: impl Into<String>) {
        self.push(CommandState::Failed, 0, Some(detail.into()), None);
    }

    /// The node refuses the command.
    pub fn rejected(&self, detail: impl Into<String>) {
        self.push(CommandState::Rejected, 0, Some(detail.into()), None);
    }
}

/// Carries out the commands a node receives (the scanner of a probe). It reports through
/// the reporter it is given; it should return soon and run long work in a task of its own.
#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync {
    /// Handles one command.
    async fn handle(&self, command: IncomingCommand, reporter: CommandReporter);
}

/// A report sink that applies reports to the store at once, in order (the in-process probe
/// of a controller).
pub struct StoreReports {
    tx: tokio::sync::mpsc::UnboundedSender<Report>,
}

impl fmt::Debug for StoreReports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreReports").finish_non_exhaustive()
    }
}

impl StoreReports {
    /// A sink that writes the reports of `node` to `store` in a task of its own.
    pub fn spawn(store: Arc<dyn Store>, node: NodeId) -> Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Report>();
        tokio::spawn(async move {
            while let Some(report) = rx.recv().await {
                for attempt in 0..5u32 {
                    match apply_report(store.as_ref(), node, &report).await {
                        Ok(_) => break,
                        Err(error) if error.code() == codes::COMMAND_NOT_FOUND => break,
                        Err(error) => {
                            tracing::debug!(code = %error.code(), attempt, "a command report could not be written; retrying");
                            tokio::time::sleep(Duration::from_millis(200 << attempt)).await;
                        }
                    }
                }
            }
        });
        Arc::new(Self { tx })
    }
}

impl ReportSink for StoreReports {
    fn push(&self, report: Report) {
        let _ = self.tx.send(report);
    }
}

/// Follows the commands of `node` in the store and hands each new deliverable one to
/// `handler` (the in-process probe of a controller), until `stop` turns true.
pub async fn follow_local(
    store: Arc<dyn Store>,
    node: NodeId,
    handler: Arc<dyn CommandHandler>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let server = tokio::spawn(serve_subscribe(Arc::clone(&store), node, None, tx));
    let reports: Arc<dyn ReportSink> = StoreReports::spawn(store, node);
    loop {
        let item = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => break,
            item = rx.recv() => item,
        };
        let Some(Ok(command)) = item else {
            break;
        };
        let Some(command) = IncomingCommand::from_proto(command) else {
            continue;
        };
        let reporter = CommandReporter::new(command.id, Arc::clone(&reports));
        handler.handle(command, reporter).await;
    }
    server.abort();
}

/// How often a subscription looks at the commands again without a change (expiry).
const SUBSCRIBE_REFRESH: Duration = Duration::from_secs(30);

type CommandSink = tokio::sync::mpsc::Sender<Result<v1::Command, tonic::Status>>;

/// Serves one `Commands.Subscribe` stream of `node` into `tx` until the node closes it:
/// the deliverable commands after `after`, then each new one as the store applies it.
/// Every controller does this for the nodes connected to it, from its own copy.
pub async fn serve_subscribe(
    store: Arc<dyn Store>,
    node: NodeId,
    after: Option<Uuid>,
    tx: CommandSink,
) {
    use futures::StreamExt as _;
    let filter = tenko_store::WatchFilter::tables([NODE_COMMANDS.name().clone()]);
    let mut sent: std::collections::BTreeSet<Uuid> = std::collections::BTreeSet::new();
    let mut changes = None;
    loop {
        let view = match store.read(ReadConsistency::Local).await {
            Ok(view) => view,
            Err(error) => {
                let _ = tx
                    .send(Err(crate::server::status_of(&store_error(error))))
                    .await;
                return;
            }
        };
        let revision = view.revision();
        let pending = match deliverable(view.as_ref(), node, after, Timestamp::now()) {
            Ok(pending) => pending,
            Err(error) => {
                let _ = tx
                    .send(Err(crate::server::status_of(&ClusterError::from(error))))
                    .await;
                return;
            }
        };
        drop(view);
        for record in pending {
            if sent.insert(record.id) {
                tracing::debug!(node = %node, command = %record.id, kind = %record.kind, "command sent to the node");
                if tx.send(Ok(record.to_proto())).await.is_err() {
                    return;
                }
            }
        }
        if changes.is_none() {
            changes = store.watch(Some(revision), filter.clone()).ok();
        }
        let woke = tokio::select! {
            () = tx.closed() => return,
            () = tokio::time::sleep(SUBSCRIBE_REFRESH) => true,
            item = async {
                if let Some(stream) = changes.as_mut() {
                    stream.next().await
                } else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    None
                }
            } => matches!(item, Some(Ok(_))),
        };
        if !woke {
            changes = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(state: CommandState, progress: u8) -> Report {
        Report {
            command: Uuid::nil(),
            state,
            progress,
            detail: None,
            at: None,
            batches: None,
        }
    }

    #[test]
    fn reports_never_move_a_command_backwards() {
        let now = Timestamp::now();
        let mut record = CommandRecord::new(NodeId(1001), SCAN_RUN, Vec::new(), now);
        assert!(record.deliverable(now));
        assert!(record.apply(&report(CommandState::Running, 40), now));
        assert_eq!(record.state, CommandState::Running);
        // A late `accepted` keeps the state; a lower progress is ignored.
        assert!(!record.apply(&report(CommandState::Accepted, 10), now));
        assert_eq!((record.state, record.progress), (CommandState::Running, 40));
        let mut done = report(CommandState::Done, 0);
        done.batches = Some(2);
        assert!(record.apply(&done, now));
        assert_eq!(
            (record.state, record.progress, record.batches),
            (CommandState::Done, 100, Some(2))
        );
        assert!(!record.settled(), "two batches announced, none ingested");
        record.ingested = 2;
        assert!(record.settled());
        // A final command takes no more reports, not even the same one twice.
        assert!(!record.apply(&done, now));
        assert!(!record.apply(&report(CommandState::Failed, 0), now));
        assert!(!record.deliverable(now));
    }

    #[test]
    fn expired_commands_are_not_delivered() {
        let now = Timestamp::now();
        let mut record = CommandRecord::new(NodeId(1001), SCAN_STOP, Vec::new(), now);
        record.expires_at = Some(now);
        assert!(!record.deliverable(now));
        record.expires_at = now.checked_add(Duration::from_secs(60));
        assert!(record.deliverable(now));
    }

    #[test]
    fn events_parse_and_refuse_issuer_states() {
        let event = v1::CommandEvent {
            command_id: Uuid::now_v7().to_string(),
            state: "done".to_owned(),
            progress_percent: 250,
            detail: "ok".to_owned(),
            at: None,
            batches: 3,
        };
        let parsed = Report::from_proto(&event).expect("report");
        assert_eq!(parsed.progress, 100);
        assert_eq!(parsed.batches, Some(3));
        assert_eq!(
            Report::from_proto(&parsed.to_proto()).expect("again"),
            parsed
        );
        for state in ["pending", "expired", "cancelled", "bogus"] {
            let event = v1::CommandEvent {
                state: state.to_owned(),
                ..event.clone()
            };
            assert_eq!(
                Report::from_proto(&event).expect_err(state).code(),
                codes::COMMAND_INVALID
            );
        }
        let event = v1::CommandEvent {
            command_id: "seven".to_owned(),
            ..event
        };
        assert!(Report::from_proto(&event).is_err());
    }
}
