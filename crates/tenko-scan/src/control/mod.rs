//! The controller side of scanning (SCAN-05, SCAN-09, OPS-28): the configuration the
//! controllers hold for each probe, scans on demand as jobs with progress and a diff, and
//! the remote kill switch.
//!
//! | Module | Contents |
//! |---|---|
//! | [`model`] | the records and the views |
//! | [`target`] | targets of scans and the probes that cover them |
//! | [`diff`] | the diff of a scan run against the facts before it |
//! | `steps` (private) | the job steps: edits, dispatch, waiting, diff |
//! | `offer` (private) | a probe's offer of its own configuration |
//! | `housekeeping` (private) | the leader service that prunes old commands and runs |
//!
//! # Probe configuration
//!
//! `scan.probe_config` holds one [`ScanConfig`] per probe, keyed by node id, with the SNMP
//! passwords named as vault secrets only ([`ScanConfig::validate_stored`]). The node sync
//! streams the row to its probe, which applies it atomically; once a probe has a stored
//! configuration, it wins over the probe's own `[scan]` section. A probe without one runs
//! on its file and offers it at its first connection (passwords stay on the probe). Every
//! change is an inline job (`scan.edit`) with the audit record `scan.config.update`.
//!
//! # Scans on demand
//!
//! [`ScanControl::submit`] resolves the target (a prefix, a host, an address or a network)
//! to networks, picks the probes whose scope covers them and starts a job `scan.run` with
//! three steps: `scan.dispatch` takes the baseline of facts and issues one `scan.run`
//! command per probe and network part; `scan.await` waits until every command finished and
//! its batches arrived, or the deadline; `scan.diff` compares what arrived with the
//! baseline. Progress and the diff are on the run ([`ScanControl::scan`]).
//!
//! # Kill switch
//!
//! [`ScanControl::stop`] and [`ScanControl::resume`] issue `scan.stop` and `scan.resume`
//! commands to one probe or to every probe; a probe that is offline gets them when it
//! connects again, in order.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

mod diff;
mod housekeeping;
pub mod model;
mod offer;
mod steps;
pub mod target;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use tenko_cluster::{
    model::tables::NODES,
    node_sync::{
        NodeSync, OfferHandler,
        commands::{self, CommandRecord, SCAN_RESUME, SCAN_STOP},
        payload::{StopArgs, encode_args},
        secrets::SecretUse,
    },
    probe::tables::SCOPES,
};
use tenko_core::{
    Coded, CodedError, MessageKey, NodeId, ObjectRef, RequestCtx, Revision,
    audit::{AuditAction, AuditDraft},
    cluster::LeaderService,
    codec::to_cbor,
    secret::{SecretClass, SecretRef},
    serde_util::HexBytes,
};
use tenko_jobs::{JobEngine, JobKind, JobSpec, StepKind, StepSpec};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};
use tenko_vault::Vault;
use uuid::Uuid;

pub use diff::{compare, seen};
use model::{
    KillSwitchCommand, KillSwitchResult, KillSwitchView, ProbeConfigOrigin, ProbeConfigRecord,
    ProbeConfigView, ProbeProgress, ProbeSummary, ScanKind, ScanRequest, ScanRun, ScanState,
    ScanTarget, ScanView,
    tables::{PROBE_CONFIG, RUNS},
};

use crate::config::{SNMP_SECRET_PURPOSE, ScanConfig};

/// The error codes of the scan control.
pub mod codes {
    /// The node is not enrolled (404).
    pub const NODE_NOT_FOUND: &str = "cluster.node.not_found";
    /// The node has no probe role (409).
    pub const NOT_A_PROBE: &str = "node.config.not_a_probe";
    /// The configuration does not validate (422).
    pub const CONFIG_INVALID: &str = "node.config.invalid";
    /// A vault secret the configuration names does not exist or is not an operator secret
    /// (422).
    pub const CONFIG_SECRET: &str = "node.config.secret";
    /// `If-Match` is stale (412).
    pub const CONFIG_STALE: &str = "node.config.revision_mismatch";
    /// No vault to check the secrets against (503).
    pub const VAULT_UNAVAILABLE: &str = "node.config.vault_unavailable";
    /// A target that does not exist or cannot be scanned (404, 422).
    pub const JOB_TARGET: &str = "scan.job.target";
    /// No probe covers the target (422).
    pub const JOB_NO_PROBE: &str = "scan.job.no_probe";
    /// A request value out of range (422).
    pub const JOB_INVALID: &str = "scan.job.invalid";
    /// No such scan run (404).
    pub const JOB_NOT_FOUND: &str = "scan.job.not_found";
    /// The IPAM module is off: scans need the facts of the observation layer (503).
    pub const JOB_UNAVAILABLE: &str = "scan.job.unavailable";
}

/// Audit actions of the scan control.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A probe's configuration changed through the API.
    pub const CONFIG_UPDATE: AuditAction = AuditAction::from_static("scan.config.update");
    /// A probe's own configuration became its stored one.
    pub const CONFIG_OFFER: AuditAction = AuditAction::from_static("scan.config.offer");
    /// The kill switch went on for one probe or every probe.
    pub const STOP: AuditAction = AuditAction::from_static("scan.stop");
    /// The kill switch went off.
    pub const RESUME: AuditAction = AuditAction::from_static("scan.resume");
    /// A scan on demand was asked for.
    pub const RUN: AuditAction = AuditAction::from_static("scan.run");
}

/// The job and step kinds of the scan control.
pub mod kinds {
    /// The inline job of an edit.
    pub const EDIT_JOB: &str = "scan.edit";
    /// Its step.
    pub const WRITE_STEP: &str = "scan.write";
    /// The job of a scan on demand.
    pub const RUN_JOB: &str = "scan.run";
    /// Issues the commands and takes the baseline.
    pub const DISPATCH_STEP: &str = "scan.dispatch";
    /// Waits for the probes.
    pub const AWAIT_STEP: &str = "scan.await";
    /// Computes the diff.
    pub const DIFF_STEP: &str = "scan.diff";
}

/// Translatable texts of the jobs (keys of the UI's message catalogue).
pub mod messages {
    /// Title of an edit job.
    pub const EDIT_TITLE: &str = "scan.job.edit";
    /// Preview of an edit.
    pub const WRITE_PREVIEW: &str = "scan.job.write_preview";
    /// Title of a scan job.
    pub const RUN_TITLE: &str = "scan.job.run";
    /// Preview of the dispatch step.
    pub const DISPATCH_PREVIEW: &str = "scan.job.dispatch";
    /// Preview of the waiting step.
    pub const AWAIT_PREVIEW: &str = "scan.job.await";
    /// Preview of the diff step.
    pub const DIFF_PREVIEW: &str = "scan.job.diff";
}

/// The deadline of a scan when the request names none.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(600);
/// The shortest and the longest deadline of a scan.
pub const DEADLINE_RANGE: (u32, u32) = (30, 3600);
/// Longest reason of a kill switch.
pub const MAX_REASON_CHARS: usize = 200;

fn store_coded(error: &StoreError) -> CodedError {
    error.to_coded_error()
}

/// What the steps share with the service.
#[derive(Clone)]
pub(crate) struct Shared {
    pub(crate) store: Arc<dyn Store>,
    pub(crate) local: Option<NodeId>,
}

/// The scan control of a controller.
pub struct ScanControl {
    shared: Shared,
    engine: JobEngine,
    vault: Option<Arc<dyn Vault>>,
}

impl std::fmt::Debug for ScanControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanControl")
            .field("local", &self.shared.local)
            .finish_non_exhaustive()
    }
}

impl ScanControl {
    /// The scan control over `store`, running its jobs on `engine`, checking SNMP secrets
    /// against `vault`. `local` is this controller's node id when it runs the probe role
    /// itself. Registers the job steps.
    pub fn new(
        store: Arc<dyn Store>,
        engine: &JobEngine,
        vault: Option<Arc<dyn Vault>>,
        local: Option<NodeId>,
    ) -> Arc<Self> {
        let shared = Shared { store, local };
        let mut registered = engine.clone();
        steps::register(&mut registered, &shared);
        Arc::new(Self {
            shared,
            engine: engine.clone(),
            vault,
        })
    }

    /// Takes the probes' offers of their own configuration on the cluster port.
    pub fn take_offers(self: &Arc<Self>, sync: &NodeSync) {
        let handler: Arc<dyn OfferHandler> = Arc::new(offer::Offers::new(self.shared.clone()));
        sync.add_offer_handler(handler);
    }

    /// The leader service that prunes finished commands and old scan runs.
    pub fn housekeeping(&self) -> Arc<dyn LeaderService> {
        Arc::new(housekeeping::Housekeeping::new(self.shared.clone()))
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.shared.store
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, CodedError> {
        self.shared
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| store_coded(&error))
    }

    /// Every probe with its configuration state.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn probes(&self) -> Result<Vec<ProbeSummary>, CodedError> {
        let view = self.view().await?;
        target::candidates(view.as_ref(), self.shared.local)?
            .into_iter()
            .map(|candidate| {
                let revision = candidate.stored.as_ref().map(|(_, revision)| revision.0);
                let kill_switch =
                    kill_switch_view(view.as_ref(), candidate.node, candidate.applied.as_ref())?;
                Ok(ProbeSummary {
                    node: candidate.node,
                    name: candidate.name,
                    in_process: candidate.in_process,
                    stored: candidate.stored.is_some(),
                    revision,
                    in_sync: in_sync(revision, candidate.applied.as_ref()),
                    applied: candidate.applied,
                    kill_switch,
                })
            })
            .collect()
    }

    /// Requires that `node` is a probe: this controller's own probe role, or an enrolled
    /// node with the role `probe`.
    fn require_probe(&self, view: &dyn ReadView, node: NodeId) -> Result<(), CodedError> {
        if Some(node) == self.shared.local {
            return Ok(());
        }
        let (record, _) = view
            .get_typed(&NODES, &node.0)
            .map_err(|error| store_coded(&error))?
            .ok_or_else(|| {
                CodedError::new(
                    codes::NODE_NOT_FOUND,
                    404,
                    format!("there is no enrolled node {node}"),
                )
                .with_param("node", node.to_string())
            })?;
        if record.roles.contains(&tenko_core::Role::Probe) {
            Ok(())
        } else {
            Err(CodedError::new(
                codes::NOT_A_PROBE,
                409,
                format!("node {node} does not have the role probe"),
            ))
        }
    }

    /// The scan configuration of a probe.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `node.config.not_a_probe` (409), a store error.
    pub async fn config(&self, node: NodeId) -> Result<ProbeConfigView, CodedError> {
        let view = self.view().await?;
        self.require_probe(view.as_ref(), node)?;
        config_view(view.as_ref(), node)
    }

    /// Replaces the scan configuration of a probe; `expect` is the revision of `If-Match`.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found`, `node.config.not_a_probe`, `node.config.invalid` (422,
    /// naming the key), `node.config.secret` (422), `node.config.revision_mismatch` (412),
    /// `node.config.vault_unavailable` (503), a job or store error.
    pub async fn put_config(
        &self,
        cx: &RequestCtx,
        node: NodeId,
        config: ScanConfig,
        expect: Option<Revision>,
    ) -> Result<ProbeConfigView, CodedError> {
        config.validate_stored().map_err(|error| {
            CodedError::new(codes::CONFIG_INVALID, 422, error.detail().to_owned())
                .with_param("field", "config")
        })?;
        self.check_secrets(&config).await?;
        let view = self.view().await?;
        self.require_probe(view.as_ref(), node)?;
        let current = view
            .get_typed(&PROBE_CONFIG, &node.0)
            .map_err(|error| store_coded(&error))?;
        let current_revision = current.as_ref().map(|(_, revision)| *revision);
        if let Some(expect) = expect
            && current_revision != Some(expect)
        {
            return Err(CodedError::new(
                codes::CONFIG_STALE,
                412,
                "the scan configuration changed since it was read; read it again",
            ));
        }
        drop(view);
        let record = ProbeConfigRecord {
            node,
            secrets: secret_uses(&config),
            config,
            origin: ProbeConfigOrigin::Api,
            updated_at: cx.now,
            updated_by: cx.principal.user(),
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&PROBE_CONFIG, &node.0, current_revision);
        batch
            .put_typed(&PROBE_CONFIG, &node.0, &record)
            .map_err(|error| store_coded(&error))?;
        batch.audit(
            AuditDraft::success(actions::CONFIG_UPDATE, vec![ObjectRef::node(node)])
                .with_context("prefixes", record.config.prefixes.join(","))
                .with_context("secrets", record.secrets.len().to_string()),
        );
        self.commit(
            cx,
            format!("scan configuration of node {node}"),
            vec![ObjectRef::node(node)],
            batch,
        )
        .await
        .map_err(|error| {
            if error.code == "sys.store.precondition_failed" {
                CodedError::new(
                    codes::CONFIG_STALE,
                    412,
                    "the scan configuration changed meanwhile; read it again",
                )
            } else {
                error
            }
        })?;
        let view = self.view().await?;
        config_view(view.as_ref(), node)
    }

    /// Requires that every vault secret the configuration names is an operator secret.
    async fn check_secrets(&self, config: &ScanConfig) -> Result<(), CodedError> {
        let secrets = config.secrets();
        if secrets.is_empty() {
            return Ok(());
        }
        let vault = self.vault.as_ref().ok_or_else(|| {
            CodedError::new(
                codes::VAULT_UNAVAILABLE,
                503,
                "this controller has no vault to check the SNMP secrets against",
            )
        })?;
        for secret in secrets {
            let meta = vault
                .meta(SecretRef { secret })
                .await
                .map_err(|error| error.to_coded_error())?;
            match meta {
                Some(meta) if meta.class == SecretClass::Operator => {}
                Some(_) => {
                    return Err(CodedError::new(
                        codes::CONFIG_SECRET,
                        422,
                        format!("{secret} is a system secret; a probe gets operator secrets only"),
                    )
                    .with_param("field", "snmp.devices"));
                }
                None => {
                    return Err(CodedError::new(
                        codes::CONFIG_SECRET,
                        422,
                        format!("the secret {secret} does not exist"),
                    )
                    .with_param("field", "snmp.devices"));
                }
            }
        }
        Ok(())
    }

    /// Switches the kill switch on for one probe (`node`) or every probe.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found`, `node.config.not_a_probe`, a job or store error.
    pub async fn stop(
        &self,
        cx: &RequestCtx,
        node: Option<NodeId>,
        reason: Option<&str>,
    ) -> Result<KillSwitchResult, CodedError> {
        let reason: String = reason
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .unwrap_or("stopped from the controllers")
            .chars()
            .take(MAX_REASON_CHARS)
            .collect();
        let payload = encode_args(&StopArgs {
            reason: reason.clone(),
        })
        .map_err(tenko_cluster::error::ClusterError::into_coded)?;
        self.kill_switch(cx, node, SCAN_STOP, payload, actions::STOP, Some(reason))
            .await
    }

    /// Switches the kill switch off for one probe (`node`) or every probe.
    ///
    /// # Errors
    ///
    /// As [`stop`](Self::stop).
    pub async fn resume(
        &self,
        cx: &RequestCtx,
        node: Option<NodeId>,
    ) -> Result<KillSwitchResult, CodedError> {
        self.kill_switch(cx, node, SCAN_RESUME, Vec::new(), actions::RESUME, None)
            .await
    }

    async fn kill_switch(
        &self,
        cx: &RequestCtx,
        node: Option<NodeId>,
        kind: &str,
        payload: Vec<u8>,
        action: AuditAction,
        reason: Option<String>,
    ) -> Result<KillSwitchResult, CodedError> {
        let view = self.view().await?;
        let nodes: Vec<NodeId> = match node {
            Some(node) => {
                self.require_probe(view.as_ref(), node)?;
                vec![node]
            }
            None => target::candidates(view.as_ref(), self.shared.local)?
                .into_iter()
                .map(|candidate| candidate.node)
                .collect(),
        };
        drop(view);
        let mut batch = WriteBatch::for_request(cx);
        let mut commands = Vec::with_capacity(nodes.len());
        for node in &nodes {
            let mut record = CommandRecord::new(*node, kind, payload.clone(), cx.now);
            record.issued_by = cx.principal.user();
            commands::stage_issue(&mut batch, &record).map_err(|error| store_coded(&error))?;
            commands.push(KillSwitchCommand {
                node: *node,
                command: record.id,
            });
        }
        let targets: Vec<ObjectRef> = nodes.iter().map(|node| ObjectRef::node(*node)).collect();
        let mut draft = AuditDraft::success(action, targets.clone()).with_context(
            "scope",
            if node.is_some() {
                "node"
            } else {
                "installation"
            },
        );
        if let Some(reason) = &reason {
            draft = draft.with_context("reason", reason.clone());
        }
        batch.audit(draft);
        if !commands.is_empty() {
            self.commit(
                cx,
                format!("{kind} for {} probe(s)", nodes.len()),
                targets,
                batch,
            )
            .await?;
        }
        Ok(KillSwitchResult { commands })
    }

    /// Starts a scan on demand.
    ///
    /// # Errors
    ///
    /// `scan.job.invalid` (422) for a deadline out of range, `scan.job.target` (404, 422),
    /// `scan.job.no_probe` (422), a job or store error.
    #[allow(
        clippy::too_many_lines,
        reason = "the submission checks the request and records the run as one sequence"
    )]
    pub async fn submit(
        &self,
        cx: &RequestCtx,
        request: ScanRequest,
    ) -> Result<ScanView, CodedError> {
        let deadline_secs = request
            .deadline_secs
            .unwrap_or(u32::try_from(DEFAULT_DEADLINE.as_secs()).unwrap_or(600));
        if !(DEADLINE_RANGE.0..=DEADLINE_RANGE.1).contains(&deadline_secs) {
            return Err(CodedError::new(
                codes::JOB_INVALID,
                422,
                format!(
                    "deadline_secs must be between {} and {}",
                    DEADLINE_RANGE.0, DEADLINE_RANGE.1
                ),
            )
            .with_param("field", "deadline_secs"));
        }
        let mut kinds: Vec<ScanKind> = request.kinds.clone();
        if kinds.is_empty() {
            kinds.push(ScanKind::PassiveRefresh);
        }
        kinds.sort();
        kinds.dedup();
        let view = self.view().await?;
        let (networks, vrf) = target::resolve(view.as_ref(), &request.target, request.vrf)?;
        let default_vrf = target::default_vrf(view.as_ref())?;
        let candidates = target::candidates(view.as_ref(), self.shared.local)?;
        if target::shares(&candidates, &networks, vrf, default_vrf).is_empty() {
            return Err(CodedError::new(
                codes::JOB_NO_PROBE,
                422,
                "no probe's scope covers the target; set the prefixes of a probe first",
            )
            .with_param("field", "target"));
        }
        drop(view);
        let deadline = cx
            .now
            .checked_add(Duration::from_secs(u64::from(deadline_secs)))
            .unwrap_or(cx.now);
        let run = ScanRun {
            id: Uuid::now_v7(),
            job: None,
            target: request.target.clone(),
            networks,
            vrf,
            kinds,
            requested_by: cx.principal.user(),
            created_at: cx.now,
            deadline,
            state: ScanState::Queued,
            parts: Vec::new(),
            diff: None,
            finished_at: None,
            error: None,
        };
        let target_ref = target_object(&request.target);
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&RUNS, &run.id, None);
        batch
            .put_typed(&RUNS, &run.id, &run)
            .map_err(|error| store_coded(&error))?;
        batch.audit(
            AuditDraft::success(actions::RUN, target_ref.iter().copied().collect())
                .with_context("run", run.id.to_string())
                .with_context(
                    "networks",
                    run.networks
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .with_context(
                    "kinds",
                    run.kinds
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
        );
        self.shared
            .store
            .propose(batch)
            .await
            .map_err(|error| store_coded(&error))?;
        let params = steps::RunParams { run: run.id };
        let params = HexBytes(
            to_cbor(&params)
                .map_err(|error| error.to_coded_error())?
                .to_vec(),
        );
        let wait = Duration::from_secs(u64::from(deadline_secs));
        let spec = JobSpec {
            kind: JobKind::from_static(kinds::RUN_JOB),
            title: MessageKey::from_static(messages::RUN_TITLE),
            targets: target_ref.into_iter().collect(),
            steps: vec![
                StepSpec {
                    kind: StepKind::from_static(kinds::DISPATCH_STEP),
                    params: params.clone(),
                    timeout: Some(Duration::from_secs(60)),
                },
                StepSpec {
                    kind: StepKind::from_static(kinds::AWAIT_STEP),
                    params: params.clone(),
                    timeout: Some(wait + Duration::from_secs(60)),
                },
                StepSpec {
                    kind: StepKind::from_static(kinds::DIFF_STEP),
                    params,
                    timeout: Some(Duration::from_secs(120)),
                },
            ],
            timeout: wait + Duration::from_secs(300),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        let job = self
            .engine
            .submit(spec, cx)
            .await
            .map_err(|error| error.to_coded_error())?;
        steps::set_job(self.shared.store.as_ref(), run.id, job).await;
        self.scan(run.id).await
    }

    /// A scan run with the progress of every probe.
    ///
    /// # Errors
    ///
    /// `scan.job.not_found` (404), a store error.
    pub async fn scan(&self, id: Uuid) -> Result<ScanView, CodedError> {
        let view = self.view().await?;
        let (run, _) = view
            .get_typed(&RUNS, &id)
            .map_err(|error| store_coded(&error))?
            .ok_or_else(|| {
                CodedError::new(
                    codes::JOB_NOT_FOUND,
                    404,
                    format!("there is no scan run {id}"),
                )
            })?;
        scan_view(view.as_ref(), run, true)
    }

    /// Scan runs, newest first, after the run `before` (exclusive) when given; at most
    /// `limit`, and whether more follow. Diffs list their counts only.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn scans(
        &self,
        limit: usize,
        before: Option<Uuid>,
    ) -> Result<(Vec<ScanView>, bool), CodedError> {
        let view = self.view().await?;
        let mut range = KeyRange::all();
        if let Some(before) = before {
            range = range.before(RUNS.key(&before));
        }
        let rows = view
            .scan_typed(&RUNS, range, limit.saturating_add(1), true)
            .map_err(|error| store_coded(&error))?;
        let more = rows.len() > limit;
        let mut out = Vec::with_capacity(limit.min(rows.len()));
        for (_, run, _) in rows.into_iter().take(limit) {
            out.push(scan_view(view.as_ref(), run, false)?);
        }
        Ok((out, more))
    }

    /// Commits an edit as an inline job `scan.edit`.
    async fn commit(
        &self,
        cx: &RequestCtx,
        summary: String,
        targets: Vec<ObjectRef>,
        batch: WriteBatch,
    ) -> Result<Revision, CodedError> {
        steps::commit(&self.engine, cx, summary, targets, batch).await
    }
}

/// The vault secrets a configuration names, as node secret uses.
pub fn secret_uses(config: &ScanConfig) -> Vec<SecretUse> {
    config
        .secrets()
        .into_iter()
        .map(|secret| SecretUse {
            purpose: SNMP_SECRET_PURPOSE.to_owned(),
            secret,
        })
        .collect()
}

/// The kill switch of `node`: the newest switch command, else the probe's report.
fn kill_switch_view(
    view: &dyn ReadView,
    node: NodeId,
    applied: Option<&tenko_cluster::probe::ProbeScope>,
) -> Result<KillSwitchView, CodedError> {
    let newest = commands::of_node(view, node)
        .map_err(|error| store_coded(&error))?
        .into_iter()
        .map(|(record, _)| record)
        .filter(|record| record.kind == SCAN_STOP || record.kind == SCAN_RESUME)
        .max_by_key(|record| record.id);
    Ok(match newest {
        Some(record) => {
            let stopped = record.kind == SCAN_STOP;
            KillSwitchView {
                stopped,
                reason: if stopped {
                    tenko_cluster::node_sync::payload::decode_args::<StopArgs>(
                        &record.encoding,
                        &record.payload.0,
                    )
                    .ok()
                    .map(|args| args.reason)
                } else {
                    None
                },
                at: Some(record.issued_at),
                by: record.issued_by,
                confirmed: record.state == commands::CommandState::Done,
            }
        }
        None => KillSwitchView {
            stopped: applied.is_some_and(|applied| applied.stopped),
            reason: applied.and_then(|applied| applied.stop_reason.clone()),
            at: None,
            by: None,
            confirmed: true,
        },
    })
}

fn in_sync(stored: Option<u64>, applied: Option<&tenko_cluster::probe::ProbeScope>) -> bool {
    match (stored, applied) {
        (Some(stored), Some(applied)) => {
            applied.origin == tenko_cluster::probe::ConfigOrigin::Synced
                && applied.revision >= stored
                && applied.error.is_none()
        }
        (None, _) => true,
        (Some(_), None) => false,
    }
}

fn config_view(view: &dyn ReadView, node: NodeId) -> Result<ProbeConfigView, CodedError> {
    let stored = view
        .get_typed(&PROBE_CONFIG, &node.0)
        .map_err(|error| store_coded(&error))?;
    let applied = view
        .get_typed(&SCOPES, &node.0)
        .map_err(|error| store_coded(&error))?
        .map(|(scope, _)| scope);
    let revision = stored.as_ref().map(|(_, revision)| revision.0);
    let in_sync = in_sync(revision, applied.as_ref());
    let kill_switch = kill_switch_view(view, node, applied.as_ref())?;
    Ok(match stored {
        Some((record, revision)) => ProbeConfigView {
            node,
            lacking_secrets: record
                .config
                .snmp
                .devices
                .iter()
                .filter(|device| !device.has_credentials())
                .map(|device| device.address.to_string())
                .collect(),
            config: record.config,
            stored: true,
            origin: Some(record.origin),
            revision: Some(revision.0),
            updated_at: Some(record.updated_at),
            updated_by: record.updated_by,
            applied,
            in_sync,
            kill_switch,
        },
        None => ProbeConfigView {
            node,
            config: ScanConfig::default(),
            stored: false,
            origin: None,
            revision: None,
            updated_at: None,
            updated_by: None,
            applied,
            in_sync,
            lacking_secrets: Vec::new(),
            kill_switch,
        },
    })
}

fn target_object(target: &ScanTarget) -> Option<ObjectRef> {
    match target.parse()? {
        model::Target::Prefix(id) => Some(ObjectRef::from(id)),
        model::Target::Host(id) => Some(ObjectRef::from(id)),
        model::Target::Address(_) | model::Target::Network(_) => None,
    }
}

fn scan_view(view: &dyn ReadView, run: ScanRun, with_items: bool) -> Result<ScanView, CodedError> {
    let mut probes = Vec::with_capacity(run.parts.len());
    for part in &run.parts {
        let command = commands::get(view, part.node, part.command)
            .map_err(|error| store_coded(&error))?
            .map(|(record, _)| record);
        probes.push(match command {
            Some(command) => ProbeProgress {
                node: part.node,
                command: part.command,
                target: part.target.clone(),
                state: command.state.as_str().to_owned(),
                progress: command.progress,
                detail: command.detail,
                batches: command.batches,
                ingested: command.ingested,
            },
            None => ProbeProgress {
                node: part.node,
                command: part.command,
                target: part.target.clone(),
                state: "expired".to_owned(),
                progress: 0,
                detail: Some("the command record was pruned".to_owned()),
                batches: None,
                ingested: 0,
            },
        });
    }
    let progress = if run.finished_at.is_some() {
        100
    } else if probes.is_empty() {
        0
    } else {
        let total: u32 = probes.iter().map(|probe| u32::from(probe.progress)).sum();
        u8::try_from(total / u32::try_from(probes.len()).unwrap_or(1)).unwrap_or(100)
    };
    let mut diff = run.diff;
    if !with_items && let Some(diff) = diff.as_mut() {
        diff.items.clear();
    }
    Ok(ScanView {
        id: run.id,
        job_id: run.job,
        target: run.target,
        networks: run.networks,
        vrf: run.vrf,
        kinds: run.kinds,
        requested_by: run.requested_by,
        created_at: run.created_at,
        deadline: run.deadline,
        state: run.state,
        progress,
        probes,
        diff,
        finished_at: run.finished_at,
        error: run.error,
    })
}

/// The method names of the kinds of a run.
pub(crate) fn methods_of(kinds: &[ScanKind]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for kind in kinds {
        for method in kind.methods() {
            if !out.iter().any(|known| known == method) {
                out.push((*method).to_owned());
            }
        }
    }
    out
}

/// The probes of a run's parts.
pub(crate) fn nodes_of(run: &ScanRun) -> BTreeSet<NodeId> {
    run.parts.iter().map(|part| part.node).collect()
}

#[cfg(test)]
mod tests;
