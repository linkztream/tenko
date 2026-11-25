//! `tenko cluster recover`: one stopped controller takes over a cluster that lost its
//! quorum for good (OPS-03, OPS-26; `docs/plans/cluster-recovery-plan.md` sections 3.2 to
//! 3.5).
//!
//! The command runs on the controller's host, on a stopped controller, as the account that
//! owns the data directory (`exec.unsafe_owner` refuses root over that account's files). It
//! has no API route, no UI and no listener: a forced step that a stolen session could start
//! from a browser is what this keeps out. It writes nothing to the network; the first start
//! after it probes the old voters (`start::probe_after_recover`).
//!
//! - `--inspect` prints what this copy holds and its fingerprint
//!   (`tkfp1:<generation>:<record>:<last term>:<last index>:<revision>:<node>`), reading
//!   only; with `--compare <fingerprint>...` it orders the copies of the same history by
//!   their last log id, Raft's own vote rule.
//! - `--force` makes this copy the only voter of a new generation after a typed
//!   confirmation (the node id; without a terminal `--confirm <node>:<generation>`, with the
//!   generation `--inspect` names, so that a script cannot pass one without reading it). On a controller that a competing forced history
//!   stopped (a fence of its own), it is also how an operator chooses this side: the new
//!   generation is above both, for the records the step counts (up to 2^32 above its own), and
//!   `--revoke` takes the other side's signer out.
//! - `--undo` puts the copy kept aside back, until the first start took office.
//!
//! # The offline step and its crash points
//!
//! 1. The notice `recover.notice.json` is written with the phase `prepared`; from now on
//!    `tenko serve` refuses to start ([`check_start`]) until the step is finished or undone.
//! 2. `store/` is renamed to `recover-gen<n>/`: the copy kept aside, never written again.
//! 3. A copy of it in `recover-gen<n>.work/` gets its whole log applied, the uncommitted
//!    tail included, as an election of this controller would; the tail is also written, decoded, to
//!    `recover-gen<n>.tail.jsonl`.
//! 4. A new `store/` is installed from a snapshot of that state with this controller as the
//!    only voter, through the restore's install path.
//! 5. One batch writes the signed generation record, the superseded marks, the revocations
//!    of `--revoke` and the audit record `cluster.recover.force`.
//! 6. The work directory goes, and the notice turns `committed`.
//!
//! A failure before step 5 undoes the steps before it. After a crash at any point the notice
//! keeps the server from starting, and `--undo` puts the kept copy back. Every rename and
//! removal in the data directory is followed by a sync of the directory, so a power loss
//! after a step never brings an earlier state of the notice or the store back.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    io::{BufRead as _, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
};

use clap::Args;
use serde::{Deserialize, Serialize};
use tenko_cluster::{
    generation::{
        self, Claim, FenceFile, ForkPoint, GENERATION, GenerationBody, GenerationRecord, LAYOUT,
        Lineage, SUPERSEDED, SupersededMark, codes,
    },
    identity::{Credentials, NodePaths},
    model::{MemberRecord, tables},
    registry,
};
use tenko_core::{
    NodeId, ObjectRef, RequestCtx, SystemComponent, Timestamp,
    audit::AuditDraft,
    serde_util::{HexBytes, to_hex},
};
use tenko_store::{
    KeyRange, ReadViewExt as _, Store as _, WriteBatch,
    fs::write_private,
    raft::{
        recover::{CopyFacts, OfflineCopy, Replayed, inspect, replay},
        types::TypeConfig,
    },
};

use crate::{
    backup::{archive::SnapshotRecord, restore::install_at},
    client::{Failure, Output},
    config::{self, Resolved},
    exit,
    serve::StartError,
};

/// The notice of a forced step in the data directory.
pub const NOTICE_FILE: &str = "recover.notice.json";

/// `tenko cluster recover`.
#[derive(Debug, Clone, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is one of the plan's switches"
)]
pub struct RecoverArgs {
    /// The configuration file of the stopped controller.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,
    /// Its data directory; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
    /// Print what this copy holds and its fingerprint; change nothing.
    #[arg(long, conflicts_with_all = ["force", "undo"])]
    pub inspect: bool,
    /// The fingerprints of the other survivors, from their `--inspect`.
    #[arg(long, value_name = "FINGERPRINT", num_args = 1..)]
    pub compare: Vec<String>,
    /// Make this controller the only voter of a new generation of the cluster.
    #[arg(long, conflicts_with = "undo")]
    pub force: bool,
    /// A controller whose certificates the step revokes (repeatable): a member of this
    /// copy's cluster, or one an earlier forced step superseded. A revoked controller never
    /// learns of the new generation.
    #[arg(long, value_name = "NODE")]
    pub revoke: Vec<u64>,
    /// Put the copy kept aside back, before the first start took office.
    #[arg(long)]
    pub undo: bool,
    /// The confirmation without a terminal: `<node>:<generation>`.
    #[arg(long, value_name = "NODE:GENERATION")]
    pub confirm: Option<String>,
    /// Force a copy behind a fingerprint given with `--compare`.
    #[arg(long)]
    pub accept_older: bool,
    /// Force while a member runs a binary without generations.
    #[arg(long)]
    pub accept_mixed: bool,
    /// Take office at the first start even when an old majority answers.
    #[arg(long)]
    pub despite_majority: bool,
    /// Force a copy that stopped as older than its cluster (`cluster.member.reverted`): only
    /// when this copy is all that is left of the cluster.
    #[arg(long)]
    pub despite_older_copy: bool,
}

/// The phase of a forced step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The step is under way or was interrupted: the server does not start.
    Prepared,
    /// The step is done: the first start probes the old voters.
    Committed,
    /// The first start took office: nothing to undo or probe. Written in place over
    /// `committed` (the same length), so it never depends on a rename or a removal being
    /// durable.
    InOffice,
    /// A phase this build does not know: as strict as `prepared`.
    #[serde(other)]
    Unknown,
}

/// An old voter the first start probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldVoter {
    /// Its node id.
    pub node: NodeId,
    /// Its cluster port, from its member record.
    pub address: String,
}

/// The notice of a forced step, read by `tenko serve` and by `--undo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Where the step stands.
    pub phase: Phase,
    /// The generation it creates.
    pub generation: u64,
    /// This controller.
    pub node: NodeId,
    /// The claim of the parent history, which the first start's probe speaks for.
    #[serde(default)]
    pub parent: Option<String>,
    /// The voters and learners of the parent history.
    #[serde(default)]
    pub old: Vec<OldVoter>,
    /// Take office even when an old majority answers.
    #[serde(default)]
    pub despite_majority: bool,
    /// When the step began.
    pub at: Timestamp,
}

impl Notice {
    /// The notice of `data_dir`, if any.
    ///
    /// # Errors
    ///
    /// A message when the file exists but does not read.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, String> {
        let path = data_dir.join(NOTICE_FILE);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// Writes the notice, replacing the old one atomically.
    ///
    /// # Errors
    ///
    /// A message naming the file.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        // Durable before the store moves: a power loss after the rename must find the
        // notice, or the next start would make an empty installation.
        write_private(&data_dir.join(NOTICE_FILE), &text).map_err(|error| error.to_string())
    }

    /// Writes the first notice of a step: only when there is none, so of two steps run at
    /// once the second finds the first one's notice and changes nothing (and never removes
    /// it). Durable, with the directory synced.
    ///
    /// # Errors
    ///
    /// A message naming the file; [`std::io::ErrorKind::AlreadyExists`] when a notice is
    /// there.
    fn create(&self, data_dir: &Path) -> Result<(), std::io::Error> {
        let text = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        // The notice holds node ids and addresses, no secret: the account's default mode.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(data_dir.join(NOTICE_FILE))?;
        file.write_all(&text)?;
        file.sync_all()?;
        tenko_store::sync_dir(data_dir);
        Ok(())
    }
}

/// Removes the notice, durably: a power loss after the removal must not bring it back.
fn remove_notice(data_dir: &Path) -> Result<(), std::io::Error> {
    fs::remove_file(data_dir.join(NOTICE_FILE))?;
    tenko_store::sync_dir(data_dir);
    Ok(())
}

/// Refuses the start while a forced step is under way or was interrupted; the store step
/// of `tenko serve` calls it before it opens the store.
///
/// # Errors
///
/// [`StartError`] `cluster.recover.interrupted` naming the commands that finish or undo it.
pub fn check_start(data_dir: &Path, store: &Path) -> Result<(), StartError> {
    match Notice::load(data_dir) {
        Ok(None) => Ok(()),
        Ok(Some(notice)) if notice.phase == Phase::InOffice => Ok(()),
        // A finished step has a store; without one the server would make an empty
        // installation beside the kept copy.
        Ok(Some(notice))
            if notice.phase == Phase::Committed && tenko_store::format::store_exists(store) =>
        {
            Ok(())
        }
        Ok(Some(notice)) if notice.phase == Phase::Committed => Err(StartError::new(
            "store",
            codes::INTERRUPTED,
            format!(
                "a forced step of the cluster recovery (generation {}) finished, but its store \
                 is missing at {}; run `tenko cluster recover --undo` to put the copy kept \
                 aside back",
                notice.generation,
                store.display()
            ),
        )),
        Ok(Some(notice)) => Err(StartError::new(
            "store",
            codes::INTERRUPTED,
            format!(
                "a forced step of the cluster recovery (generation {}) did not finish; run \
                 `tenko cluster recover --undo` to put the copy kept aside back, then force \
                 again if you still mean to",
                notice.generation
            ),
        )),
        Err(error) => Err(StartError::new("store", codes::INTERRUPTED, error)),
    }
}

/// Refuses an offline command that writes the store (`tenko user unlock`, `tenko kek
/// rotate`) while a forced step is under way or was interrupted, or while another history
/// stopped this controller: a write there goes into a history that takes no writes.
///
/// # Errors
///
/// The exit status and the reason.
pub fn check_offline_write(resolved: &Resolved) -> Result<(), (u8, String)> {
    check_start(&resolved.data_dir, &resolved.layout().store())
        .map_err(|error| (exit::START, error.to_string()))?;
    match FenceFile::load(&resolved.data_dir) {
        Ok(None) => Ok(()),
        Ok(Some(fence)) => Err((
            exit::USAGE,
            format!(
                "this controller stopped writing ({}); nothing is written here until an operator acts on it (docs/cluster.md sections 12.3 and 12.11)",
                fence.kind.code()
            ),
        )),
        Err(error) => Err((exit::START, error.detail().to_owned())),
    }
}

/// The directories of a forced step to generation `n`.
struct Dirs {
    store: PathBuf,
    kept: PathBuf,
    work: PathBuf,
    tail: PathBuf,
    /// The fence of the old store, kept beside its copy: the new history starts unfenced,
    /// and `--undo` puts the fence back with the store.
    fence: PathBuf,
    kept_fence: PathBuf,
}

impl Dirs {
    /// Moves the fence file of the old store aside (`back`: back again).
    fn move_fence(&self, back: bool) -> Result<(), Failure> {
        let (from, to) = if back {
            (&self.kept_fence, &self.fence)
        } else {
            (&self.fence, &self.kept_fence)
        };
        match fs::rename(from, to) {
            Ok(()) => {
                for dir in [from.parent(), to.parent()].into_iter().flatten() {
                    tenko_store::sync_dir(dir);
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Failure::other(format!("{}: {error}", from.display()))),
        }
    }
}

impl Dirs {
    fn new(resolved: &Resolved, generation: u64) -> Self {
        Self::at(&resolved.data_dir, &resolved.layout().store(), generation)
    }

    fn at(data: &Path, store: &Path, generation: u64) -> Self {
        Self {
            store: store.to_path_buf(),
            kept: data.join(format!("recover-gen{generation}")),
            work: data.join(format!("recover-gen{generation}.work")),
            tail: data.join(format!("recover-gen{generation}.tail.jsonl")),
            fence: NodePaths::new(data).root().join(generation::FENCE_FILE),
            kept_fence: data.join(format!("recover-gen{generation}.fence")),
        }
    }
}

fn failure(code: &str, status: u8, message: impl std::fmt::Display) -> Failure {
    Failure::new(status, format!("[{code}] {message}"))
}

fn store_failure(error: impl std::fmt::Display) -> Failure {
    failure(codes::IN_USE, exit::USAGE, error)
}

fn resolve(args: &RecoverArgs) -> Result<Resolved, Failure> {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    config::load(&sources, std::env::vars())
        .and_then(|loaded| loaded.config.resolve())
        .map_err(|error| Failure::new(exit::CONFIG, error.to_string()))
}

/// Runs `tenko cluster recover` on a runtime of its own (the stores it opens need worker
/// threads), printing to `out` and `err`.
pub fn block_on(
    name: &str,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
    args: &RecoverArgs,
) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return Failure::other(format!("runtime: {error}")).report(name, false, out, err);
        }
    };
    match runtime.block_on(run(args)) {
        Ok(output) => {
            let _ = out.write_all(output.stdout.as_bytes());
            let _ = err.write_all(output.stderr.as_bytes());
            output.status
        }
        Err(failure) => failure.report(name, false, out, err),
    }
}

/// Runs `tenko cluster recover`.
///
/// # Errors
///
/// A [`Failure`] with the code of the refusal.
pub async fn run(args: &RecoverArgs) -> Result<Output, Failure> {
    let resolved = resolve(args)?;
    if args.undo {
        return undo(&resolved);
    }
    if !args.force && !args.inspect && args.despite_majority {
        return despite(&resolved, args);
    }
    let copy = inspect(&resolved.layout().store())
        .await
        .map_err(store_failure)?;
    let facts = Facts::read(&resolved, &copy)?;
    let mut stdout = facts.describe();
    let ordering = compare(&facts, &args.compare, &mut stdout)?;
    if !args.force {
        return Ok(Output {
            stdout,
            ..Output::default()
        });
    }
    drop(copy);
    force(&resolved, args, &facts, ordering, stdout).await
}

/// How far above its own generation a forced step counts the records it has seen. A
/// generation counts forced steps, each one above the highest number it counted, so forced
/// steps alone never take a history this far above a copy of it; counting a record further
/// up could leave no number for the next step.
const STEP_REACH: u64 = 1 << 32;

/// What a closed store and the files beside it say, for the inspection and the step.
struct Facts {
    copy: CopyFacts,
    node: NodeId,
    own: Option<generation::Signed>,
    /// The highest generation this copy has seen: its own or its fence's.
    seen: u64,
    /// The highest generation a forced step here counts: its own, or its fence's below
    /// [`STEP_REACH`] above its own.
    counted: u64,
    /// What stopped this controller, when a fence is kept here.
    fence: Option<tenko_store::FenceReason>,
    /// When the store stopped on what a leader sent, and what it found.
    found: Option<String>,
    members: BTreeMap<NodeId, MemberRecord>,
    /// The nodes with a record in the registry: the ones `--revoke` can revoke.
    enrolled: BTreeSet<NodeId>,
    /// The controllers an earlier forced step superseded: the new history offers its record
    /// to them too.
    marked: BTreeSet<NodeId>,
    /// The nodes this copy holds as removed ([`registry::revoked_nodes`]): a copy of one is
    /// never forced, since its first start refuses it.
    removed: BTreeSet<NodeId>,
    /// When this controller was removed, as this copy holds it ([`registry::removed_at`]).
    removed_at: Option<Timestamp>,
    /// The newest record of the history that stopped this controller, if one did.
    stopped_by: Option<generation::Signed>,
    /// `[cluster] peer_address_map`: the address dialed for one a member advertises.
    address_map: BTreeMap<String, String>,
}

impl Facts {
    fn read(resolved: &Resolved, copy: &OfflineCopy) -> Result<Self, Failure> {
        let view = copy.view();
        let own = Lineage::read(view.as_ref())
            .map_err(store_failure)?
            .tip()
            .cloned();
        let fence = FenceFile::load(&resolved.data_dir).map_err(store_failure)?;
        let fenced = || {
            fence
                .iter()
                .flat_map(|fence| &fence.records)
                .filter_map(|record| record.header().ok())
                .map(|header| header.number)
        };
        let own_generation = own.as_ref().map_or(0, generation::Signed::number);
        let reach = own_generation.saturating_add(STEP_REACH);
        let members = view
            .scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)
            .map_err(store_failure)?
            .into_iter()
            .map(|(node, record, _)| (NodeId(node), record))
            .collect();
        let node = copy.facts.node.unwrap_or(resolved.node_id);
        let records = view
            .scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)
            .map_err(store_failure)?;
        let enrolled = records.into_iter().map(|(id, _, _)| NodeId(id)).collect();
        let stopped_by = fence
            .as_ref()
            .and_then(|fence| Lineage::kept(&fence.records).ok())
            .and_then(|lineage| lineage.tip().cloned());
        let marked = view
            .scan_typed(&SUPERSEDED, KeyRange::all(), usize::MAX, false)
            .map_err(store_failure)?
            .into_iter()
            .map(|(node, _, _)| NodeId(node))
            .collect();
        Ok(Self {
            removed: registry::revoked_nodes(view.as_ref())
                .map_err(store_failure)?
                .into_iter()
                .collect(),
            removed_at: registry::removed_at(view.as_ref(), node).map_err(store_failure)?,
            enrolled,
            marked,
            stopped_by,
            address_map: resolved.config.cluster.peer_address_map.clone(),
            fence: fence.as_ref().map(|fence| fence.kind),
            found: fence.as_ref().and_then(|fence| fence.detail.clone()),
            seen: fenced().fold(own_generation, u64::max),
            counted: fenced()
                .filter(|number| *number < reach)
                .fold(own_generation, u64::max),
            copy: copy.facts.clone(),
            node,
            own,
            members,
        })
    }

    fn generation(&self) -> u64 {
        self.own.as_ref().map_or(0, generation::Signed::number)
    }

    /// The generation a forced step here creates: above every one this copy counts
    /// ([`STEP_REACH`]). Saturating: a copy just below the highest number takes it.
    fn next(&self) -> u64 {
        self.counted.saturating_add(1)
    }

    /// `tkfp1:<generation>:<record>:<last term>:<last index>:<revision>:<node>`.
    fn fingerprint(&self) -> String {
        let record = self
            .own
            .as_ref()
            .map_or_else(|| "0".to_owned(), |own| to_hex(&own.hash().0[..4]));
        let (term, index) = self
            .copy
            .last_log
            .map_or((0, 0), |log| (log.leader_id.term, log.index));
        format!(
            "tkfp1:{}:{record}:{term}:{index}:{}:{}",
            self.generation(),
            self.copy.revision.0,
            self.node
        )
    }

    /// Whether the binary of `node` knows generations (data format 7 or later).
    fn knows_generations(&self, node: NodeId) -> Option<bool> {
        self.members
            .get(&node)
            .map(|member| member.known_formats().iter().any(|format| *format >= 7))
    }

    fn describe(&self) -> String {
        let log = |id: Option<tenko_store::raft::types::LogId>| {
            id.map_or_else(|| "none".to_owned(), log_id)
        };
        let mut text = String::new();
        let _ = writeln!(
            text,
            "generation       {}{}",
            self.generation(),
            self.own
                .as_ref()
                .map_or_else(String::new, |own| format!(" (record {})", own.hash()))
        );
        let _ = writeln!(text, "node             {}", self.node);
        if let Some(at) = self.removed_at {
            let _ = writeln!(
                text,
                "removed          at {}: this copy holds the removal of this controller, so it \
                 is never forced and `tenko serve` does not start it",
                at.to_rfc3339()
            );
        }
        let _ = writeln!(
            text,
            "last log id      {} (committed {}, applied {}; {} entries not known as committed)",
            log(self.copy.last_log),
            log(self.copy.committed),
            log(self.copy.applied),
            self.copy.unknown_commit()
        );
        let _ = writeln!(text, "revision         {}", self.copy.revision.0);
        let _ = writeln!(
            text,
            "audit head       {} ({})",
            self.copy.audit_head.seq, self.copy.audit_head.hash
        );
        for (role, nodes) in [
            ("voter", &self.copy.voters),
            ("learner", &self.copy.learners),
        ] {
            for node in nodes {
                let member = self.members.get(node);
                let generations = match self.knows_generations(*node) {
                    Some(true) => "knows generations",
                    Some(false) => "does not know generations",
                    None => "no member record",
                };
                let _ = writeln!(
                    text,
                    "{role:<16} {node} {} {}, {generations}",
                    member.map_or("-", |member| member.address.as_str()),
                    member.map_or("-", |member| member.version.as_str()),
                );
            }
        }
        let _ = writeln!(
            text,
            "space needed     {} bytes beside the store",
            self.copy.bytes
        );
        let _ = writeln!(text, "fingerprint      {}", self.fingerprint());
        if let (Some(fence), Some(found)) = (self.fence, &self.found)
            && fence.way_out(self.node).is_some()
        {
            let _ = writeln!(text, "stopped          {} at {found}", fence.code());
        } else if let Some(fence) = self.fence {
            let _ = writeln!(
                text,
                "stopped          {} (generation {} of another history{})",
                fence.code(),
                self.seen,
                self.stopped_by
                    .as_ref()
                    .map_or_else(String::new, |tip| format!(
                        ", forced on controller {}",
                        tip.forced()
                    ))
            );
            if let Some(found) = &self.found {
                let _ = writeln!(text, "found            {found}");
            }
        }
        self.describe_step(&mut text);
        text
    }

    /// The inspection's lines on a forced step here: a record it does not count, and the
    /// generation it creates or its refusal.
    fn describe_step(&self, text: &mut String) {
        let next = self.next();
        if self.seen > self.counted {
            let _ = writeln!(
                text,
                "not counted      generation {} is not below {}, the limit of what a forced step \
                 here counts; it creates {next}, not above it, and a controller stopped as \
                 superseded by that record stops the new generation whenever they meet, until \
                 that controller is stopped and its data directory moved aside",
                self.seen,
                self.generation().saturating_add(STEP_REACH)
            );
        }
        if self.generation() == u64::MAX {
            let _ = writeln!(
                text,
                "a forced step    is refused here ({})",
                codes::NO_GENERATION_LEFT
            );
        } else {
            let _ = writeln!(
                text,
                "a forced step    creates generation {next} here; without a terminal its \
                 confirmation names this node and that generation (--confirm \
                 <node>:<generation>) after `--force` printed what it does"
            );
        }
    }
}

/// A fingerprint of another copy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    generation: u64,
    record: String,
    term: u64,
    index: u64,
    revision: u64,
    node: u64,
}

impl Fingerprint {
    fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.trim().split(':').collect();
        let ["tkfp1", generation, record, term, index, revision, node] = parts.as_slice() else {
            return None;
        };
        Some(Self {
            generation: generation.parse().ok()?,
            record: (*record).to_owned(),
            term: term.parse().ok()?,
            index: index.parse().ok()?,
            revision: revision.parse().ok()?,
            node: node.parse().ok()?,
        })
    }
}

/// Orders the given fingerprints of this copy's history with this copy by the last log
/// id; returns the fresher ones.
fn compare(facts: &Facts, given: &[String], out: &mut String) -> Result<Vec<String>, Failure> {
    if given.is_empty() {
        return Ok(Vec::new());
    }
    let ours = Fingerprint::parse(&facts.fingerprint())
        .ok_or_else(|| Failure::other("this copy's own fingerprint does not read"))?;
    let mut same = vec![(ours.clone(), true)];
    let _ = writeln!(
        out,
        "\ncopies of this history, freshest first (Raft's vote rule):"
    );
    for text in given {
        let theirs = Fingerprint::parse(text).ok_or_else(|| {
            failure(
                codes::FINGERPRINT,
                exit::USAGE,
                format!("`{text}` is not a fingerprint of `tenko cluster recover --inspect`"),
            )
        })?;
        if theirs.generation == ours.generation && theirs.record == ours.record {
            same.push((theirs, false));
        } else {
            let _ = writeln!(
                out,
                "  {text}: another history (generation {}); its log ids do not compare with this copy's",
                theirs.generation
            );
        }
    }
    same.sort_by_key(|(fingerprint, _)| std::cmp::Reverse((fingerprint.term, fingerprint.index)));
    let mut fresher = Vec::new();
    let mut behind_us = true;
    for (fingerprint, mine) in &same {
        // A removed controller's copy never starts, however fresh: it is no choice.
        let removed = facts.removed.contains(&NodeId(fingerprint.node));
        let _ = writeln!(
            out,
            "  node {} at {}:{} (revision {}){}{}",
            fingerprint.node,
            fingerprint.term,
            fingerprint.index,
            fingerprint.revision,
            if removed {
                "  removed, never forced"
            } else {
                ""
            },
            if *mine { "  <- this copy" } else { "" }
        );
        if *mine {
            behind_us = false;
        } else if behind_us
            && !removed
            && (fingerprint.term, fingerprint.index) > (ours.term, ours.index)
        {
            fresher.push(format!("node {}", fingerprint.node));
        }
    }
    Ok(fresher)
}

/// The confirmation: the node id typed on a terminal, or `--confirm <node>:<generation>`.
fn confirmed(args: &RecoverArgs, node: NodeId, generation: u64, text: &str) -> Result<(), Failure> {
    let refused = || {
        failure(
            codes::CONFIRM,
            exit::USAGE,
            "the confirmation did not match; nothing was changed (`--inspect` names the \
             generation a forced step here creates)",
        )
    };
    // What the step does is printed before every confirmation, the one of a script too.
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{text}");
    if let Some(given) = &args.confirm {
        return if given.trim() == format!("{node}:{generation}") {
            Ok(())
        } else {
            Err(refused())
        };
    }
    if !std::io::stdin().is_terminal() {
        // The answer is never printed here: a script that reads it from the refusal would
        // pass a confirmation nobody read.
        return Err(failure(
            codes::CONFIRM,
            exit::USAGE,
            "no terminal to confirm on: read what the step does above, then pass \
             `--confirm <node>:<generation>` with this controller's node id and the \
             generation `--inspect` names",
        ));
    }
    let _ = write!(err, "Type the node id of this controller to continue: ");
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| Failure::other(format!("reading the confirmation: {error}")))?;
    if line.trim() == node.to_string() {
        Ok(())
    } else {
        Err(refused())
    }
}

/// A point of the forced step: after it, a test stops the step as a crash would, or fails
/// it as an error would ([`force_with`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The notice `prepared` is written; nothing moved.
    Noticed,
    /// The store is renamed aside and the old fence moved beside it.
    Moved,
    /// The copy's log is applied in the work directory and the tail written.
    Replayed,
    /// The new store is installed.
    Installed,
    /// The step's batch is written to the new store.
    Written,
}

/// How a test interrupts the forced step at a [`Step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "only the tests interrupt the step")
)]
enum Interrupt {
    /// An error: the step undoes what it did before.
    Fail,
    /// The process ends: nothing is undone.
    Crash,
}

/// The outcome of an interrupted step: a failure, or a crash that undoes nothing.
enum Stopped {
    Failed(Failure),
    Crashed,
}

impl From<Failure> for Stopped {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}

async fn force(
    resolved: &Resolved,
    args: &RecoverArgs,
    facts: &Facts,
    fresher: Vec<String>,
    stdout: String,
) -> Result<Output, Failure> {
    match force_with(resolved, args, facts, fresher, stdout, &|_| None).await {
        Ok(output) => Ok(output),
        Err(Stopped::Failed(failure)) => Err(failure),
        Err(Stopped::Crashed) => Err(Failure::other("the forced step was stopped")),
    }
}

/// The checks of `--force` before anything is written: returns the nodes the step
/// supersedes (every other voter and learner of the copy).
fn force_checks(
    args: &RecoverArgs,
    facts: &Facts,
    fresher: &[String],
) -> Result<(BTreeSet<NodeId>, Vec<String>), Failure> {
    let node = facts.node;
    if let Some(at) = facts.removed_at {
        return Err(removed(node, at));
    }
    if !facts.copy.voters.contains(&node) {
        return Err(failure(
            codes::NOT_NEEDED,
            exit::USAGE,
            format!("controller {node} is not a voter of its cluster; force a voter's copy"),
        ));
    }
    // A controller alone needs no step, unless another history stopped it: then a step
    // is how an operator chooses this side.
    if facts.copy.voters.len() == 1 && facts.fence.is_none() {
        return Err(failure(
            codes::NOT_NEEDED,
            exit::USAGE,
            format!("controller {node} is the only voter already; it needs no forced step"),
        ));
    }
    if facts.fence == Some(tenko_store::FenceReason::Reverted) && !args.despite_older_copy {
        let reverted = tenko_store::FenceReason::Reverted;
        let way_out = reverted.way_out(node).unwrap_or_default();
        return Err(failure(
            reverted.code(),
            exit::USAGE,
            format!("controller {node} stopped writing: {way_out}"),
        ));
    }
    // The numbers saturate: a second step at the largest one would replace this copy's own
    // record under the same number and break its lineage.
    if facts
        .own
        .as_ref()
        .is_some_and(|own| own.number() == u64::MAX)
    {
        return Err(failure(
            codes::NO_GENERATION_LEFT,
            exit::USAGE,
            "this copy's generation is the largest number already, so no forced step can go \
             above it: force the copy of a controller at an earlier generation instead, if \
             one is left, with every controller at this number stopped and its data directory \
             moved aside; otherwise restore a backup from before this generation into empty \
             data directories on every controller (docs/cluster.md section 12.11)",
        ));
    }
    if !fresher.is_empty() && !args.accept_older {
        return Err(failure(
            codes::NOT_FRESHEST,
            exit::USAGE,
            format!(
                "{} holds a fresher copy of this history; force that one, or pass \
                 --accept-older",
                fresher.join(", ")
            ),
        ));
    }
    let others: BTreeSet<NodeId> = facts
        .copy
        .voters
        .iter()
        .chain(&facts.copy.learners)
        .copied()
        .filter(|other| *other != node)
        .collect();
    let mixed: Vec<String> = others
        .iter()
        .filter(|other| facts.knows_generations(**other) != Some(true))
        .map(ToString::to_string)
        .collect();
    if !mixed.is_empty() && !args.accept_mixed {
        return Err(failure(
            codes::MIXED,
            exit::USAGE,
            format!(
                "controllers {} run a binary without generations: they would not stop when \
                 they return; update them first, or pass --accept-mixed",
                mixed.join(", ")
            ),
        ));
    }
    // This function is where the step's preconditions are checked.
    if let Some(named) = args
        .revoke
        .iter()
        .find(|named| NodeId(**named) == node || !facts.enrolled.contains(&NodeId(**named)))
    {
        return Err(failure(
            codes::UNKNOWN_NODE,
            exit::USAGE,
            format!(
                "controller {named} is not another controller with a record in the node \
                 registry of this copy, so there are no certificates to revoke; remove it \
                 later with `tenko cluster remove`"
            ),
        ));
    }
    Ok((others, mixed))
}

/// The refusal of a copy that holds the removal of its controller: `tenko serve` would
/// refuse every start from it (`cluster.member.removed`).
fn removed(node: NodeId, at: Timestamp) -> Failure {
    failure(
        codes::REMOVED,
        exit::USAGE,
        format!(
            "controller {node} was removed from the cluster at {}, as this copy holds it, so \
             it would never start from a forced step here; force the copy of another \
             controller, or, when no other copy is left, restore a backup from before the \
             removal, or one under another node id, into an empty data directory \
             (docs/backup.md section 7): a backup that holds the removal, restored under \
             this node id, is refused the same way",
            at.to_rfc3339()
        ),
    )
}

/// The forced step, with `interrupt` asked at every [`Step`] (never in production).
#[allow(
    clippy::too_many_lines,
    reason = "the forced step reads best as one sequence with its undo"
)]
async fn force_with(
    resolved: &Resolved,
    args: &RecoverArgs,
    facts: &Facts,
    fresher: Vec<String>,
    mut stdout: String,
    interrupt: &(dyn Fn(Step) -> Option<Interrupt> + Sync),
) -> Result<Output, Stopped> {
    let at = |step: Step| match interrupt(step) {
        None => Ok(()),
        Some(Interrupt::Fail) => Err(Stopped::Failed(Failure::other(format!(
            "the step failed after {step:?}"
        )))),
        Some(Interrupt::Crash) => Err(Stopped::Crashed),
    };
    // The record of a step that took office ends here; a later step writes its own.
    if Notice::load(&resolved.data_dir)
        .map_err(Failure::other)?
        .is_some_and(|notice| notice.phase == Phase::InOffice)
    {
        remove_notice(&resolved.data_dir).map_err(Failure::other)?;
    }
    if let Some(notice) = Notice::load(&resolved.data_dir).map_err(Failure::other)? {
        return Err(failure(
            codes::INTERRUPTED,
            exit::USAGE,
            format!(
                "a forced step to generation {} is already here; run `tenko cluster recover \
                 --undo` first",
                notice.generation
            ),
        )
        .into());
    }
    let node = facts.node;
    let (others, mixed) = force_checks(args, facts, &fresher)?;
    let credentials = Credentials::load(&NodePaths::new(&resolved.data_dir))
        .map_err(|error| failure(error.code(), exit::USAGE, error.detail()))?;
    let generation = facts.next();
    let text = confirmation(facts, generation, &others, args);
    confirmed(args, node, generation, &text)?;

    let data = &resolved.data_dir;
    let dirs = Dirs::new(resolved, generation);
    let old_voter = |other: &NodeId| OldVoter {
        node: *other,
        address: facts
            .members
            .get(other)
            .map(|member| member.address.clone())
            .unwrap_or_default(),
    };
    let mut notice = Notice {
        phase: Phase::Prepared,
        generation,
        node,
        parent: facts.own.as_ref().and_then(|own| own.claim().render()),
        old: others.iter().map(old_voter).collect(),
        despite_majority: args.despite_majority,
        at: Timestamp::now(),
    };
    if dirs.kept.exists() || dirs.work.exists() {
        return Err(failure(
            codes::INTERRUPTED,
            exit::USAGE,
            format!(
                "{} or {} exists from an earlier step; move it away first",
                dirs.kept.display(),
                dirs.work.display()
            ),
        )
        .into());
    }
    notice.create(data).map_err(|error| {
        failure(
            codes::INTERRUPTED,
            exit::USAGE,
            format!(
                "the notice of a forced step could not be written ({error}); another step may \
                 be under way here"
            ),
        )
    })?;
    if let Err(stopped) = at(Step::Noticed) {
        if let Stopped::Failed(_) = stopped {
            let _ = remove_notice(data);
        }
        return Err(stopped);
    }
    // Again now that the notice keeps a server from starting: one started since the
    // inspection would write into the copy that is to be kept.
    let moved = tenko_store::format::ensure_closed(&dirs.store)
        .map_err(store_failure)
        .and_then(|()| {
            fs::rename(&dirs.store, &dirs.kept)
                .map_err(|error| Failure::other(format!("renaming the store aside: {error}")))
        });
    if let Err(error) = moved {
        let _ = remove_notice(data);
        return Err(error.into());
    }
    tenko_store::sync_dir(data);
    let committed = async {
        dirs.move_fence(false)?;
        at(Step::Moved)?;
        let replayed = replay(&dirs.kept, &dirs.work)
            .await
            .map_err(|error| Failure::other(format!("applying the copy's log: {error}")))?;
        // The tail this copy never knew as committed may hold the removal.
        if let Some(at) =
            registry::removed_at(replayed.copy.view().as_ref(), node).map_err(store_failure)?
        {
            return Err(removed(node, at).into());
        }
        write_tail(&dirs.tail, &replayed)?;
        at(Step::Replayed)?;
        // A controller the tail added is superseded and probed like the others.
        let replayed_members: BTreeSet<NodeId> = replayed
            .copy
            .facts
            .voters
            .iter()
            .chain(&replayed.copy.facts.learners)
            .copied()
            .filter(|other| *other != node)
            .collect();
        let fork = fork_point(&replayed)?;
        let position = SnapshotRecord {
            last_log_term: fork.term,
            last_log_node: fork.leader,
            last_log_index: fork.index,
            snapshot_id: replayed.meta.snapshot_id.clone(),
        };
        let address = crate::cluster::own_address(resolved);
        let store = install_at(
            &dirs.store,
            node,
            &address,
            &position,
            replayed.before.highest_term(),
            &replayed.snapshot,
        )
        .await
        .map_err(|error| Failure::other(format!("installing the new store: {error}")))?;
        tenko_store::sync_dir(data);
        if let Err(stopped) = at(Step::Installed) {
            let _ = store.shutdown().await;
            return Err(stopped);
        }
        let superseded: BTreeSet<NodeId> = others.union(&replayed_members).copied().collect();
        let body = GenerationBody {
            layout: LAYOUT,
            number: generation,
            parent: facts.own.as_ref().map(generation::Signed::hash),
            forced: node,
            fork,
            superseded: facts
                .copy
                .voters
                .iter()
                .chain(&replayed.copy.facts.voters)
                .copied()
                .filter(|voter| *voter != node)
                .collect(),
            at: Timestamp::now(),
            nonce: HexBytes(nonce()?),
        };
        let record = GenerationRecord::sign(&body, &credentials.chain, &credentials.key)
            .map_err(|error| failure(error.code(), exit::FAILURE, error.detail()))?;
        let written = write_batch(
            &store,
            &record,
            &body,
            &superseded,
            args,
            replayed.tail.len(),
            data,
        )
        .await;
        let _ = store.shutdown().await;
        drop(replayed);
        written?;
        at(Step::Written)?;
        Ok::<_, Stopped>((record, superseded))
    }
    .await;
    let (record, superseded) = match committed {
        Ok(done) => done,
        Err(Stopped::Crashed) => return Err(Stopped::Crashed),
        Err(Stopped::Failed(error)) => {
            let _ = fs::remove_dir_all(&dirs.store);
            let _ = fs::remove_dir_all(&dirs.work);
            let _ = fs::remove_file(&dirs.tail);
            tenko_store::sync_dir(data);
            // The notice goes only when the old store and its fence are both back; else it
            // keeps the server from starting until `--undo`.
            if dirs.move_fence(true).is_ok() && fs::rename(&dirs.kept, &dirs.store).is_ok() {
                tenko_store::sync_dir(data);
                let _ = remove_notice(data);
            }
            return Err(error.into());
        }
    };
    let _ = fs::remove_dir_all(&dirs.work);
    tenko_store::sync_dir(data);
    notice.old = superseded.iter().map(old_voter).collect();
    notice.phase = Phase::Committed;
    notice.save(data).map_err(Failure::other)?;
    let _ = writeln!(
        stdout,
        "\ngeneration {generation} created (record {}); the copy before it is kept in {}.\n\
         Start this controller now: its first start looks for a live majority of the old \
         voters for [cluster] recover_probe_secs before it takes office.",
        record.hash(),
        dirs.kept.display()
    );
    let added: Vec<String> = superseded
        .difference(&others)
        .map(ToString::to_string)
        .collect();
    if !added.is_empty() {
        let _ = writeln!(
            stdout,
            "note: the entries not known as committed added controllers {}: they are superseded and probed too",
            added.join(", ")
        );
    }
    if !mixed.is_empty() {
        let _ = writeln!(
            stdout,
            "warning: controllers {} do not know generations and will not stop by themselves",
            mixed.join(", ")
        );
    }
    Ok(Output {
        stdout,
        ..Output::default()
    })
}

fn confirmation(
    facts: &Facts,
    generation: u64,
    others: &BTreeSet<NodeId>,
    args: &RecoverArgs,
) -> String {
    let list = |nodes: &mut dyn Iterator<Item = String>| nodes.collect::<Vec<_>>().join(", ");
    let position = facts
        .copy
        .last_log
        .map_or_else(|| "the start".to_owned(), log_id);
    let mut text = format!(
        "This controller (node {}) becomes the only voter of the cluster, generation {generation}.\n\
         Its copy ends at log position {position} (revision {}); {} of its entries were not yet \
         known as committed and are kept.\n",
        facts.node,
        facts.copy.revision.0,
        facts.copy.unknown_commit(),
    );
    if let Some(stopped) = stopped_text(facts) {
        let _ = writeln!(text, "{stopped}");
    }
    let earlier: Vec<&NodeId> = facts
        .marked
        .iter()
        .filter(|node| !others.contains(node))
        .collect();
    if !earlier.is_empty() {
        let _ = writeln!(
            text,
            "\nThis controller will also offer the new record to the controllers an earlier \
             step superseded:"
        );
        addresses(&mut text, facts, earlier.into_iter());
    }
    if !others.is_empty() {
        let _ = writeln!(
            text,
            "\nControllers {} stop being members. When one comes back, it stops writing at once \
             and keeps its copy aside on its own host; it waits until you act on that host. \
             Whatever they wrote after this position does not come into this cluster. Any \
             holder of the installation's CA key, these controllers included, can stop this \
             cluster's writes with a record of its own, again and again: a forced step on the \
             side you choose lifts each stop, and a new CA ends it.\n\
             This controller will call them at:",
            list(&mut others.iter().map(ToString::to_string)),
        );
        addresses(&mut text, facts, others.iter());
    }
    if !args.revoke.is_empty() {
        let _ = writeln!(
            text,
            "\nThe certificates of {} are revoked in the same write: they reach none of the \
             cluster's data and services again. They still exchange generation records, so a \
             revoked controller that comes back learns of this generation and stops writing.",
            list(&mut args.revoke.iter().map(ToString::to_string))
        );
    }
    let _ = write!(
        text,
        "\nDo this only if those controllers are stopped or gone and cannot reach each other. If \
         they are running and reach each other, they are still a cluster, and this makes a \
         second one.\n\
         If this host is a clone or a restored copy of a controller (a virtual machine clone, \
         a snapshot, a lab restore), stop here: the addresses above are the ones the step \
         reaches, and a clone that reaches them stops the real cluster.\n\n\
         The copy this controller has now is kept in recover-gen{generation}/ until you remove \
         it; `--undo` restores it until the first start.\n"
    );
    text
}

/// What stopped this controller, beside this copy's own history: every figure of the other
/// record is that record's claim, as its signer chose it. No side is recommended.
fn stopped_text(facts: &Facts) -> Option<String> {
    let fence = facts.fence?;
    let describe = |signed: &generation::Signed| {
        let fork = signed.body().map_or_else(String::new, |body| {
            format!(
                ", fork point {}:{} (revision {})",
                body.fork.term, body.fork.index, body.fork.revision.0
            )
        });
        format!(
            "generation {}, forced on controller {} ({}), dated {}{fork}",
            signed.number(),
            signed.forced(),
            facts
                .members
                .get(&signed.forced())
                .map_or("no address known", |member| member.address.as_str()),
            signed.at().to_rfc3339(),
        )
    };
    if let Some(way_out) = fence.way_out(facts.node) {
        let found = facts.found.as_deref().unwrap_or("no detail kept");
        return Some(format!(
            "It stopped on what a leader sent ({found}): {way_out}."
        ));
    }
    let claim = match fence {
        tenko_store::FenceReason::Conflict => "that it competes with this controller's history",
        tenko_store::FenceReason::MajorityAlive => {
            return Some(
                "It stopped at its first start: the old voters answered its probe as a live \
                 majority."
                    .to_owned(),
            );
        }
        _ => "that it supersedes this controller's history",
    };
    let outcome = if facts.seen > facts.counted {
        "does not count the other record, which lies beyond the limit of what it counts: the \
         new generation is not above it, and a controller stopped as superseded by it stops \
         the new one whenever they meet, until its data directory is moved aside"
    } else {
        "makes this copy the newer history; the other side stops writing when it meets it"
    };
    Some(format!(
        "It was stopped by a record that claims {claim}.\n  \
         The other record claims: {}\n  \
         This copy holds:         {}\n\
         A forced step here {outcome}, and what that side wrote since its own step does not \
         come here. The operators of both sides decide together: if both force their own \
         side, both stop again when they meet.",
        facts
            .stopped_by
            .as_ref()
            .map_or_else(|| "nothing readable".to_owned(), describe),
        facts
            .own
            .as_ref()
            .map_or_else(|| "generation 0 (no forced step)".to_owned(), describe),
    ))
}

/// One line per controller: its node id and the cluster port it is called at (its member
/// record's, through `[cluster] peer_address_map` as the push dials it).
fn addresses<'a>(text: &mut String, facts: &Facts, nodes: impl Iterator<Item = &'a NodeId>) {
    for node in nodes {
        let address = facts.members.get(node).map_or_else(
            || "(no address known)".to_owned(),
            |member| {
                facts
                    .address_map
                    .get(&member.address)
                    .cloned()
                    .unwrap_or_else(|| member.address.clone())
            },
        );
        let _ = writeln!(text, "  node {node}  {address}");
    }
}

fn nonce() -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| Failure::other("no random bytes"))?;
    Ok(bytes)
}

fn fork_point(replayed: &Replayed) -> Result<ForkPoint, Failure> {
    let facts = &replayed.copy.facts;
    let last = facts
        .applied
        .ok_or_else(|| Failure::other("the copy holds no log entry to start from"))?;
    Ok(ForkPoint {
        term: last.leader_id.term,
        leader: last.leader_id.node_id,
        index: last.index,
        revision: facts.revision,
        audit: facts.audit_head,
    })
}

/// The uncommitted tail, one JSON line per entry: its log id and, per batch, what it wrote.
fn write_tail(path: &Path, replayed: &Replayed) -> Result<(), Failure> {
    let mut text = String::new();
    for entry in &replayed.tail {
        let line = serde_json::json!({
            "log_id": log_id(entry.log_id),
            "entry": describe(&entry.payload),
        });
        let _ = writeln!(text, "{line}");
    }
    write_private(path, text.as_bytes()).map_err(Failure::other)
}

/// An entry of the tail as JSON: each write batch decoded (its keys and values stay bytes).
fn describe(payload: &tenko_store::raft::openraft::EntryPayload<TypeConfig>) -> serde_json::Value {
    use tenko_store::raft::openraft::EntryPayload;
    match payload {
        EntryPayload::Blank => serde_json::json!("blank"),
        EntryPayload::Membership(membership) => {
            serde_json::json!({ "membership": format!("{membership:?}") })
        }
        EntryPayload::Normal(proposal) => proposal
            .batches
            .iter()
            .map(|proposed| {
                tenko_core::codec::from_cbor::<WriteBatch>(&proposed.batch)
                    .ok()
                    .and_then(|batch| serde_json::to_value(batch).ok())
                    .unwrap_or_else(|| serde_json::json!("a batch this build does not decode"))
            })
            .collect(),
    }
}

/// The step's one batch: the record, the marks, the revocations and the audit record.
async fn write_batch(
    store: &tenko_store::raft::RaftStore,
    record: &GenerationRecord,
    body: &GenerationBody,
    others: &BTreeSet<NodeId>,
    args: &RecoverArgs,
    tail: usize,
    data: &Path,
) -> Result<(), Failure> {
    let cx = RequestCtx::system(SystemComponent::Cluster);
    let view = store
        .read(tenko_store::ReadConsistency::Local)
        .await
        .map_err(Failure::other)?;
    let mut batch = WriteBatch::for_request(&cx);
    batch
        .put_typed(&GENERATION, &body.number, record)
        .map_err(Failure::other)?;
    let hash = record.hash();
    for other in others {
        batch
            .put_typed(
                &SUPERSEDED,
                &other.0,
                &SupersededMark {
                    generation: body.number,
                    record: hash,
                },
            )
            .map_err(Failure::other)?;
    }
    let mut revoked = Vec::new();
    for node in &args.revoke {
        revoked.extend(
            registry::stage_revocation(view.as_ref(), &mut batch, &cx, NodeId(*node))
                .map_err(|error| failure(error.code(), exit::FAILURE, error.detail()))?,
        );
    }
    let fork = &body.fork;
    batch.audit(
        AuditDraft::success(
            generation::actions::FORCE,
            vec![ObjectRef::node(body.forced)],
        )
        .with_context("generation", body.number.to_string())
        .with_context("record", hash.to_string())
        .with_context(
            "fork",
            format!(
                "{}:{} revision {} audit {}:{}",
                fork.term, fork.index, fork.revision.0, fork.audit.seq, fork.audit.hash
            ),
        )
        .with_context(
            "superseded",
            body.superseded
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        .with_context("revoked", revoked.join(","))
        .with_context("tail_entries", tail.to_string())
        .with_context("account", account(data))
        .with_context("host", crate::node::enroll::host_name().unwrap_or_default()),
    );
    drop(view);
    store.propose(batch).await.map_err(Failure::other)?;
    Ok(())
}

/// The account that ran the step: the owner of the data directory, which the command
/// runs as (`exec` refuses another account), not what the environment claims.
fn account(data: &Path) -> String {
    use crate::exec::Facts as _;
    crate::exec::Host
        .owner(data)
        .ok()
        .flatten()
        .map_or_else(String::new, |owner| owner.to_string())
}

/// A log id as `term:index`.
fn log_id(id: tenko_store::raft::types::LogId) -> String {
    format!("{}:{}", id.leader_id.term, id.index)
}

/// `--undo`: before the first start took office, the copy kept aside goes back.
fn undo(resolved: &Resolved) -> Result<Output, Failure> {
    undo_at(&resolved.data_dir, &resolved.layout().store())
}

/// [`undo`] for the data directory `data` and its store directory `store`.
fn undo_at(data: &Path, store: &Path) -> Result<Output, Failure> {
    let notice = Notice::load(data)
        .map_err(Failure::other)?
        .filter(|notice| notice.phase != Phase::InOffice)
        .ok_or_else(|| {
            failure(
                codes::UNDO_REFUSED,
                exit::USAGE,
                "there is no forced step to undo: none was made here, or the first start after \
                 it took office",
            )
        })?;
    let dirs = Dirs::at(data, store, notice.generation);
    if !dirs.kept.exists() {
        if notice.phase == Phase::Prepared {
            // The step stopped before it renamed the store: nothing moved.
            remove_notice(data).map_err(Failure::other)?;
            return Ok(Output {
                stdout: "the interrupted forced step changed nothing; its notice is gone\n"
                    .to_owned(),
                ..Output::default()
            });
        }
        return Err(failure(
            codes::UNDO_REFUSED,
            exit::USAGE,
            format!("the copy kept aside is missing: {}", dirs.kept.display()),
        ));
    }
    // The copy kept aside must be this controller's before anything is removed: a planted
    // notice must not make `--undo` replace the store with another one.
    let kept_node = fs::read_to_string(dirs.kept.join(tenko_store::raft::NODE_ID_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    if kept_node != Some(notice.node.0) {
        return Err(failure(
            codes::UNDO_REFUSED,
            exit::USAGE,
            format!(
                "{} is not the copy of controller {} that the notice names; nothing was changed",
                dirs.kept.display(),
                notice.node
            ),
        ));
    }
    if tenko_store::format::store_exists(&dirs.store) {
        tenko_store::format::ensure_closed(&dirs.store).map_err(store_failure)?;
        fs::remove_dir_all(&dirs.store).map_err(Failure::other)?;
    } else if dirs.store.exists() {
        fs::remove_dir_all(&dirs.store).map_err(Failure::other)?;
    }
    let _ = fs::remove_dir_all(&dirs.work);
    let _ = fs::remove_file(&dirs.tail);
    fs::rename(&dirs.kept, &dirs.store).map_err(Failure::other)?;
    tenko_store::sync_dir(data);
    if notice.phase == Phase::Committed && !dirs.kept_fence.exists() {
        // The old store had no fence; one written since belongs to the history undone.
        match fs::remove_file(&dirs.fence) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Failure::other(format!("{}: {error}", dirs.fence.display())));
            }
        }
    }
    dirs.move_fence(true)?;
    remove_notice(data).map_err(Failure::other)?;
    Ok(Output {
        stdout: format!(
            "the forced step to generation {} is undone: the copy from before it is the store \
             again, and this controller starts as the member it was\n",
            notice.generation
        ),
        ..Output::default()
    })
}

/// `--despite-majority` alone: the next start takes office whatever the old voters answer.
fn despite(resolved: &Resolved, args: &RecoverArgs) -> Result<Output, Failure> {
    let mut notice = Notice::load(&resolved.data_dir)
        .map_err(Failure::other)?
        .filter(|notice| notice.phase == Phase::Committed)
        .ok_or_else(|| {
            failure(
                codes::UNDO_REFUSED,
                exit::USAGE,
                "there is no forced step waiting for its first start here",
            )
        })?;
    let text = format!(
        "The next start of this controller takes office as generation {} even when the old \
         voters answer and hold a majority: two clusters would write side by side until they \
         meet.\n",
        notice.generation
    );
    confirmed(args, notice.node, notice.generation, &text)?;
    notice.despite_majority = true;
    notice.save(&resolved.data_dir).map_err(Failure::other)?;
    Ok(Output {
        stdout: "the next start takes office whatever the old voters answer\n".to_owned(),
        ..Output::default()
    })
}

/// Whether the first start's probe should run, and for which voters: the committed notice.
pub fn pending(data_dir: &Path) -> Option<Notice> {
    Notice::load(data_dir)
        .ok()
        .flatten()
        .filter(|notice| notice.phase == Phase::Committed)
}

/// The claim the first start's probe speaks for: the parent history's.
pub fn parent_claim(notice: &Notice) -> Claim {
    notice
        .parent
        .as_deref()
        .and_then(Claim::parse)
        .unwrap_or(Claim::ZERO)
}

/// Ends the notice once the first start took office: from then on `--undo` is refused.
///
/// # Errors
///
/// A message naming the file.
pub fn took_office(data_dir: &Path) -> Result<(), String> {
    // The phase is written in place and the file synced before the record is sent: after a
    // power loss the notice says `in_office`, never `committed` again, which would allow
    // `--undo` after the record reached the old voters. A rename or a removal would rest on
    // the directory reaching the disk, which Windows does not let a program force.
    let path = data_dir.join(NOTICE_FILE);
    let named = |error: std::io::Error| format!("{}: {error}", path.display());
    let bytes = fs::read(&path).map_err(named)?;
    let (from, to) = (b"\"phase\": \"committed\"", b"\"phase\": \"in_office\"");
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .ok_or_else(|| format!("{}: not the notice of a committed step", path.display()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(named)?;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(at as u64)).map_err(named)?;
    file.write_all(to).map_err(named)?;
    file.sync_all().map_err(named)
}

#[cfg(test)]
pub(crate) mod tests {
    use tenko_core::{Revision, audit::ChainHead, testing::TempDir};
    use tenko_store::raft::{openraft::LeaderId, types::LogId};

    use super::*;

    fn notice(phase: Phase) -> Notice {
        Notice {
            phase,
            generation: 1,
            node: NodeId(2),
            parent: None,
            old: Vec::new(),
            despite_majority: false,
            at: Timestamp::now(),
        }
    }

    /// A data directory with a store whose log file holds `content`.
    fn data_dir(content: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new("recover-undo");
        let store = dir.path().join("store");
        fs::create_dir_all(&store).expect("store");
        fs::write(store.join("log.redb"), content).expect("log");
        fs::write(
            store.join(tenko_store::raft::NODE_ID_FILE),
            "2
",
        )
        .expect("node id");
        (dir, store)
    }

    fn log_of(store: &Path) -> String {
        fs::read_to_string(store.join("log.redb")).expect("the log")
    }

    #[track_caller]
    fn refused(result: Result<Output, Failure>, code: &str) {
        let failure = result.expect_err(code);
        assert!(format!("{failure:?}").contains(code), "{failure:?}");
    }

    #[test]
    fn a_crash_before_the_store_moved_is_undone_without_a_trace() {
        let (dir, store) = data_dir("old");
        notice(Phase::Prepared).save(dir.path()).expect("notice");
        let refusal = check_start(dir.path(), &store).expect_err("an unfinished step");
        assert_eq!(refusal.code, codes::INTERRUPTED);
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert!(check_start(dir.path(), &store).is_ok());
        refused(undo_at(dir.path(), &store), codes::UNDO_REFUSED);
    }

    #[test]
    fn a_crash_after_the_store_moved_aside_is_undone() {
        let (dir, store) = data_dir("old");
        notice(Phase::Prepared).save(dir.path()).expect("notice");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::rename(&store, &dirs.kept).expect("aside");
        assert_eq!(
            check_start(dir.path(), &store)
                .expect_err("an unfinished step")
                .code,
            codes::INTERRUPTED
        );
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert!(!dirs.kept.exists());
        assert!(check_start(dir.path(), &store).is_ok());
    }

    #[test]
    fn a_crash_after_the_new_store_was_installed_is_undone_with_the_fence() {
        let (dir, store) = data_dir("old");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::create_dir_all(dirs.fence.parent().expect("node dir")).expect("node dir");
        fs::write(&dirs.fence, "the old fence").expect("fence");
        notice(Phase::Prepared).save(dir.path()).expect("notice");
        fs::rename(&store, &dirs.kept).expect("aside");
        dirs.move_fence(false).expect("fence aside");
        fs::create_dir_all(&dirs.work).expect("work");
        fs::create_dir_all(&store).expect("new store");
        fs::write(store.join("log.redb"), "new").expect("new log");
        fs::write(&dirs.tail, "{}").expect("tail");
        assert_eq!(
            check_start(dir.path(), &store)
                .expect_err("an unfinished step")
                .code,
            codes::INTERRUPTED
        );
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert_eq!(
            fs::read_to_string(&dirs.fence).expect("fence back"),
            "the old fence"
        );
        assert!(!dirs.work.exists() && !dirs.tail.exists() && !dirs.kept_fence.exists());
        assert!(check_start(dir.path(), &store).is_ok());
    }

    #[test]
    fn an_undo_before_the_first_start_drops_a_fence_of_the_new_history() {
        let (dir, store) = data_dir("old");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::rename(&store, &dirs.kept).expect("aside");
        fs::create_dir_all(&store).expect("new store");
        fs::write(store.join("log.redb"), "new").expect("new log");
        notice(Phase::Committed).save(dir.path()).expect("notice");
        assert!(
            check_start(dir.path(), &store).is_ok(),
            "a finished step starts"
        );
        fs::create_dir_all(dirs.fence.parent().expect("node dir")).expect("node dir");
        fs::write(&dirs.fence, "written by the new history").expect("fence");
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert!(!dirs.fence.exists(), "the old store had no fence");
    }

    fn facts(node: u64, term: u64, index: u64) -> Facts {
        let log = Some(LogId::new(LeaderId::new(term, 1), index));
        Facts {
            copy: CopyFacts {
                node: Some(NodeId(node)),
                last_log: log,
                committed: log,
                applied: log,
                vote_term: term,
                revision: Revision(index),
                audit_head: ChainHead::default(),
                voters: [1, 2, 3].into_iter().map(NodeId).collect(),
                learners: BTreeSet::new(),
                bytes: 0,
            },
            node: NodeId(node),
            own: None,
            seen: 0,
            counted: 0,
            fence: None,
            found: None,
            marked: BTreeSet::new(),
            removed: BTreeSet::new(),
            removed_at: None,
            address_map: BTreeMap::new(),
            stopped_by: None,
            members: BTreeMap::new(),
            enrolled: BTreeSet::new(),
        }
    }

    /// A copy that holds its own controller's removal is never forced, and a removed
    /// controller's copy is never the one `--compare` names as fresher, however fresh.
    #[test]
    fn a_removed_controller_is_never_forced_nor_named_fresher() {
        let mut gone = facts(1, 5, 120);
        gone.removed = [NodeId(1)].into_iter().collect();
        gone.removed_at = Some(Timestamp::now());
        let refused = format!(
            "{:?}",
            force_checks(&args(), &gone, &[]).expect_err("removed")
        );
        for part in [
            codes::REMOVED,
            "another controller",
            "a backup from before the removal, or one under another node id",
        ] {
            assert!(refused.contains(part), "{part} in {refused}");
        }
        assert!(gone.describe().contains("holds the removal"));

        let mut ours = facts(2, 5, 100);
        ours.removed = [NodeId(1)].into_iter().collect();
        let mut out = String::new();
        let fresher = compare(&ours, &[gone.fingerprint()], &mut out).expect("compare");
        assert!(fresher.is_empty(), "{fresher:?}");
        assert!(
            out.contains("node 1 at 5:120 (revision 120)  removed"),
            "{out}"
        );
    }

    #[test]
    fn copies_of_one_history_are_ordered_by_their_last_log_id() {
        let ours = facts(2, 5, 100);
        assert_eq!(ours.fingerprint(), "tkfp1:0:0:5:100:100:2");
        let fresher = facts(3, 5, 120).fingerprint();
        let older_term = facts(1, 4, 900).fingerprint();
        let other_history = "tkfp1:1:abcd0123:2:7:7:9".to_owned();
        let mut out = String::new();
        let found =
            compare(&ours, &[fresher, older_term, other_history], &mut out).expect("compare");
        assert_eq!(found, vec!["node 3".to_owned()]);
        assert!(out.contains("another history"), "{out}");
        let mut out = String::new();
        let bad = compare(&ours, &["tkfp2:0:0:1:1:1:1".to_owned()], &mut out);
        assert!(
            format!("{:?}", bad.expect_err("not a fingerprint"))
                .contains("cluster.recover.fingerprint")
        );
    }

    // -----------------------------------------------------------------------------------
    // The forced step on a real store, stopped at each of its points.

    /// Rows the copies hold, so that a copy put back can be told from a new one.
    const ROWS: tenko_core::TableName =
        tenko_core::TableName::from_static("ipam.recover_test_rows");

    /// A data directory under `root` whose store is node 1's copy of a cluster of three
    /// voters (closed), with a configuration, an identity under `node/` and a fence of an
    /// earlier history; returns the configuration. A `removed` copy holds node 1's removal
    /// (a revocation and no node record) while it still lists node 1 as a voter.
    #[allow(
        clippy::too_many_lines,
        reason = "the copy, its identity and its fence, in order"
    )]
    async fn three_voter_copy(root: &Path, removed: bool) -> Resolved {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        use tenko_store::raft::{RaftStore, RaftStoreConfig, network::InProcessNetwork};

        let data = root.join("data");
        fs::create_dir_all(&data).expect("data");
        let file = root.join("tenko.toml");
        fs::write(
            &file,
            format!(
                "data_dir = '{}'\n[node]\nid = 1\naddress = \"in-process-1\"\n",
                data.display()
            ),
        )
        .expect("config");
        let resolved = config::load(
            &config::Sources {
                file: Some(file),
                data_dir: None,
                roles: None,
            },
            std::iter::empty(),
        )
        .and_then(|loaded| loaded.config.resolve())
        .expect("configuration");

        let network = InProcessNetwork::new();
        let mut stores = Vec::new();
        for node in 1..=3_u64 {
            let dir = if node == 1 {
                resolved.layout().store()
            } else {
                root.join(format!("peer-{node}"))
            };
            let mut config = RaftStoreConfig::new(&dir);
            config.node_id = NodeId(node);
            config.address = format!("in-process-{node}");
            config.bootstrap = node == 1;
            config.fsync_probe_samples = 0;
            let store = RaftStore::open_with(config, std::sync::Arc::new(network.clone()))
                .await
                .expect("open");
            network.register(&store);
            stores.push(store);
        }
        let first = stores[0].clone();
        for node in 2..=3 {
            first
                .add_learner(NodeId(node), format!("in-process-{node}"), true)
                .await
                .expect("learner");
        }
        first
            .change_membership([NodeId(1), NodeId(2), NodeId(3)].into())
            .await
            .expect("three voters");
        // The identity the step signs with.
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_root = ca_params.self_signed(&ca_key).expect("root").der().clone();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![
            rcgen::SanType::URI("urn:tenko:node:1".try_into().expect("uri")),
            rcgen::SanType::URI("urn:tenko:role:controller".try_into().expect("uri")),
        ];
        let leaf = params.signed_by(&key, &issuer).expect("leaf").der().clone();
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        for index in 0..50_u32 {
            batch.put(
                ROWS,
                format!("row-{index:04}").into_bytes(),
                b"before the step".to_vec(),
            );
        }
        // This controller's record holds the certificate the step signs with.
        let info = tenko_cluster::ca::CertInfo::from_der(&leaf).expect("info");
        let certificate = tenko_cluster::peers::certificate_ref(&info);
        if removed {
            batch
                .put_typed(
                    &tables::REVOCATIONS,
                    &info.serial,
                    &tenko_cluster::model::Revocation {
                        node: NodeId(1),
                        revoked_at: Timestamp::now(),
                        not_after: info.not_after,
                        controller: true,
                    },
                )
                .expect("revocation");
        } else {
            batch
                .put_typed(
                    &tables::NODES,
                    &1_u64,
                    &tenko_cluster::model::NodeRecord {
                        id: NodeId(1),
                        name: "controller-1".to_owned(),
                        roles: vec![tenko_core::Role::Controller],
                        address: None,
                        vrf: None,
                        certificate: certificate.clone(),
                        serials: vec![certificate],
                        enrolled_at: Timestamp::now(),
                        enrollment: uuid::Uuid::nil(),
                        enrolled_by: None,
                        renewed_at: None,
                        last_seen: None,
                        version: None,
                        protocol: tenko_cluster::model::ProtocolState::default(),
                    },
                )
                .expect("record");
        }
        first.propose(batch).await.expect("rows");
        for store in stores {
            store.shutdown().await.expect("shutdown");
        }

        Credentials {
            identity: tenko_cluster::identity::NodeIdentity {
                node: NodeId(1),
                name: "controller-1".to_owned(),
                roles: vec![tenko_core::Role::Controller],
                controller: String::new(),
                endpoints: Vec::new(),
                cluster_port: None,
                heartbeat_secs: 30,
                enrolled_at: Timestamp::now(),
                ca_sha256: String::new(),
            },
            info,
            chain: vec![leaf],
            key: tenko_vault::SecretBytes::from_slice(&key.serialize_der()),
            ca_root,
        }
        .save(&NodePaths::new(&data))
        .expect("identity");
        // A fence of an earlier history: the step moves it aside and puts it back.
        FenceFile {
            kind: tenko_store::FenceReason::Superseded,
            records: Vec::new(),
            at: Timestamp::now(),
            detail: None,
        }
        .save(&data)
        .expect("fence");
        resolved
    }

    fn args() -> RecoverArgs {
        RecoverArgs {
            config: None,
            data_dir: None,
            inspect: false,
            compare: Vec::new(),
            force: true,
            revoke: Vec::new(),
            undo: false,
            confirm: Some("1:1".to_owned()),
            accept_older: false,
            accept_mixed: true,
            despite_majority: false,
            despite_older_copy: false,
        }
    }

    /// What a copy holds, to tell the copy from before the step from another one.
    type CopyState = (
        Option<tenko_store::raft::types::LogId>,
        Revision,
        Vec<NodeId>,
    );

    async fn state(store: &Path) -> CopyState {
        let copy = inspect(store).await.expect("a store");
        (
            copy.facts.last_log,
            copy.facts.revision,
            copy.facts.voters.iter().copied().collect(),
        )
    }

    /// Runs the step on a fresh copy, interrupted after `step` as `how`.
    async fn interrupted(
        root: &TempDir,
        step: Option<(Step, Interrupt)>,
    ) -> (Resolved, CopyState, Result<Output, Stopped>) {
        let resolved = three_voter_copy(root.path(), false).await;
        let before = state(&resolved.layout().store()).await;
        let copy = inspect(&resolved.layout().store()).await.expect("copy");
        let facts = Facts::read(&resolved, &copy).expect("facts");
        drop(copy);
        let outcome = force_with(
            &resolved,
            &args(),
            &facts,
            Vec::new(),
            String::new(),
            &move |at| step.filter(|(when, _)| *when == at).map(|(_, how)| how),
        )
        .await;
        (resolved, before, outcome)
    }

    const STEPS: [Step; 5] = [
        Step::Noticed,
        Step::Moved,
        Step::Replayed,
        Step::Installed,
        Step::Written,
    ];

    /// A failure at every point of the step puts everything back as it was: the store (the
    /// same last log id, revision and voters), the fence, and no notice, kept copy, work
    /// directory or tail; the server starts as the member it was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failure_at_every_point_of_the_step_leaves_the_copy_as_it_was() {
        for step in STEPS {
            let root = TempDir::new("recover-fail");
            let (resolved, before, outcome) =
                interrupted(&root, Some((step, Interrupt::Fail))).await;
            assert!(
                matches!(outcome, Err(Stopped::Failed(_))),
                "a failure after {step:?}"
            );
            let data = &resolved.data_dir;
            let store = resolved.layout().store();
            let dirs = Dirs::new(&resolved, 1);
            assert_eq!(state(&store).await, before, "the copy after {step:?}");
            assert!(Notice::load(data).expect("notice").is_none(), "{step:?}");
            assert!(
                !dirs.kept.exists() && !dirs.work.exists() && !dirs.tail.exists(),
                "{step:?}"
            );
            assert!(dirs.fence.exists() && !dirs.kept_fence.exists(), "{step:?}");
            check_start(data, &store).expect("starts as it was");
        }
    }

    /// A crash at every point of the step (nothing undone) keeps the server from starting,
    /// so the controller never runs on a half-made step; `--undo` puts the copy from before
    /// the step back, with its fence, and the server starts as the member it was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_crash_at_every_point_of_the_step_is_refused_at_start_and_undone() {
        for step in STEPS {
            let root = TempDir::new("recover-crash");
            let (resolved, before, outcome) =
                interrupted(&root, Some((step, Interrupt::Crash))).await;
            assert!(matches!(outcome, Err(Stopped::Crashed)), "{step:?}");
            let data = &resolved.data_dir;
            let store = resolved.layout().store();
            let dirs = Dirs::new(&resolved, 1);
            let refusal = check_start(data, &store).expect_err("no start after a crash");
            assert_eq!(refusal.code, codes::INTERRUPTED, "{step:?}");
            undo_at(data, &store).expect("undo");
            assert_eq!(state(&store).await, before, "the copy after {step:?}");
            assert!(dirs.fence.exists() && !dirs.kept_fence.exists(), "{step:?}");
            assert!(
                !dirs.kept.exists() && !dirs.work.exists() && !dirs.tail.exists(),
                "{step:?}"
            );
            check_start(data, &store).expect("starts as it was");
            refused(undo_at(data, &store), codes::UNDO_REFUSED);
        }
    }

    /// A copy stopped by a record minted with the CA's key (a node id no member knows) is
    /// lifted by a forced step: the step numbers its generation above the record's, and the
    /// new history starts without the stop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_forced_step_lifts_a_stop_by_a_minted_record() {
        let root = TempDir::new("recover-minted");
        let resolved = three_voter_copy(root.path(), false).await;
        let minted = competing(4242, 7);
        generation::FenceFile {
            kind: tenko_store::FenceReason::Superseded,
            records: vec![minted.record().clone()],
            at: Timestamp::now(),
            detail: None,
        }
        .save(&resolved.data_dir)
        .expect("the stop");
        let copy = inspect(&resolved.layout().store()).await.expect("copy");
        let facts = Facts::read(&resolved, &copy).expect("facts");
        drop(copy);
        assert_eq!(facts.next(), 8);
        let lifted = force_with(
            &resolved,
            &RecoverArgs {
                confirm: Some("1:8".to_owned()),
                ..args()
            },
            &facts,
            Vec::new(),
            String::new(),
            &|_| None,
        )
        .await;
        if let Err(Stopped::Failed(failure)) = &lifted {
            panic!("the step: {failure:?}");
        }
        assert!(lifted.is_ok(), "the step");
        assert!(
            !Dirs::new(&resolved, 8).fence.exists(),
            "the new history starts unfenced"
        );
        let installed = tenko_store::raft::recover::inspect(&resolved.layout().store())
            .await
            .expect("the new store");
        assert!(
            installed
                .view()
                .get_typed(&GENERATION, &8_u64)
                .expect("read")
                .is_some()
        );
    }

    /// A forced step counts the records of its fence only below `STEP_REACH` above its own
    /// generation, at generation 0 and after a step to 1; `seen` still names the highest.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn next_ignores_fence_records_beyond_the_bound() {
        async fn fenced(resolved: &Resolved, number: u64) -> Facts {
            FenceFile {
                kind: tenko_store::FenceReason::Superseded,
                records: vec![competing(4242, number).record().clone()],
                at: Timestamp::now(),
                detail: None,
            }
            .save(&resolved.data_dir)
            .expect("the stop");
            let copy = inspect(&resolved.layout().store()).await.expect("copy");
            Facts::read(resolved, &copy).expect("facts")
        }
        let root = TempDir::new("recover-reach");
        let resolved = three_voter_copy(root.path(), false).await;
        for (number, next) in [
            (STEP_REACH - 1, STEP_REACH),
            (STEP_REACH, 1),
            (STEP_REACH + 1, 1),
            (u64::MAX, 1),
        ] {
            let facts = fenced(&resolved, number).await;
            assert_eq!((facts.seen, facts.next()), (number, next), "{number}");
        }
        let step = RecoverArgs {
            confirm: Some("1:1".to_owned()),
            ..args()
        };
        let facts = fenced(&resolved, u64::MAX).await;
        let forced = force_with(&resolved, &step, &facts, Vec::new(), String::new(), &|_| {
            None
        });
        assert!(forced.await.is_ok(), "the step to 1");
        // Below the bound only relative to generation 1, and at that bound.
        for (number, next) in [(STEP_REACH, STEP_REACH + 1), (STEP_REACH + 1, 2)] {
            let facts = fenced(&resolved, number).await;
            assert_eq!(
                (facts.generation(), facts.seen, facts.next()),
                (1, number, next),
                "{number}"
            );
        }
    }

    /// A record at the largest generation number, signed by a controller of the cluster,
    /// stops every member; the documented procedure lifts it. The forced step does not count
    /// the record and makes generation 1; the members keep the record against it and hand it
    /// back, so the authority stops when it meets one of them; a second step makes generation
    /// 2, and with the members moved aside nothing is left that stops it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_forced_step_lifts_a_stop_by_a_record_at_the_largest_number() {
        use tenko_store::FenceReason;
        let root = TempDir::new("recover-largest");
        let resolved = three_voter_copy(root.path(), false).await;
        let own = Credentials::load(&NodePaths::new(&resolved.data_dir)).expect("identity");
        let lineage = |copy: &OfflineCopy| Lineage::read(copy.view().as_ref()).expect("lineage");
        let copy = inspect(&resolved.layout().store()).await.expect("copy");
        // The members' copy: the cluster as it was before the step.
        let members = lineage(&copy);
        drop(copy);
        let minted = GenerationRecord::sign(
            &GenerationBody {
                layout: LAYOUT,
                number: u64::MAX,
                parent: members.tip().map(generation::Signed::hash),
                forced: NodeId(1),
                fork: ForkPoint {
                    term: 1,
                    leader: 1,
                    index: 1,
                    revision: Revision(1),
                    audit: ChainHead::default(),
                },
                superseded: vec![NodeId(2), NodeId(3)],
                at: Timestamp::now(),
                nonce: HexBytes(vec![9; 16]),
            },
            &own.chain,
            &own.key,
        )
        .expect("minted");
        let fence = |held: Option<&(FenceReason, Lineage)>, of: &Lineage, offered: &[_]| {
            generation::next_fence(held, &of.admit(offered, &own.ca_root).expect("admit"))
        };
        let (reason, records) =
            fence(None, &members, std::slice::from_ref(&minted)).expect("the members stop");
        let held = (reason, Lineage::kept(&records).expect("kept"));
        // The operator forces controller 1, stopped by the same record.
        FenceFile {
            kind: reason,
            records,
            at: Timestamp::now(),
            detail: None,
        }
        .save(&resolved.data_dir)
        .expect("the stop");
        let step = |number: u64| {
            let resolved = &resolved;
            async move {
                let copy = inspect(&resolved.layout().store()).await.expect("copy");
                let facts = Facts::read(resolved, &copy).expect("facts");
                drop(copy);
                assert_eq!((facts.seen, facts.next()), (u64::MAX, number));
                assert!(facts.describe().contains("not counted"), "the inspection");
                let args = RecoverArgs {
                    confirm: Some(format!("1:{number}")),
                    ..args()
                };
                let forced =
                    force_with(resolved, &args, &facts, Vec::new(), String::new(), &|_| {
                        None
                    });
                assert!(forced.await.is_ok(), "the step to {number}");
                let copy = inspect(&resolved.layout().store())
                    .await
                    .expect("the new store");
                let authority = lineage(&copy);
                assert_eq!(authority.number(), number);
                assert!(!Dirs::new(resolved, number).fence.exists(), "unfenced");
                authority
            }
        };
        let authority = step(1).await;
        // The members keep the minted record against the authority's below it, and their
        // refusals carry it back.
        let pushed: Vec<_> = authority
            .records()
            .iter()
            .map(|r| r.record().clone())
            .collect();
        assert_eq!(fence(Some(&held), &members, &pushed), None, "kept");
        let (kind, records) =
            fence(None, &authority, std::slice::from_ref(&minted)).expect("the authority stops");
        assert_eq!(kind, FenceReason::Conflict);
        FenceFile {
            kind,
            records,
            at: Timestamp::now(),
            detail: None,
        }
        .save(&resolved.data_dir)
        .expect("the authority's stop");
        // The authority had taken office; a second step lifts its stop the same way.
        took_office(&resolved.data_dir).expect("office");
        // Once the members are moved aside, the minted record is kept nowhere: the new
        // history starts unfenced (checked in `step`) and the server starts.
        step(2).await;
        check_start(&resolved.data_dir, &resolved.layout().store()).expect("it starts");
    }

    /// The whole step: a store with this controller as the only voter and the record, the
    /// notice `committed` (the server starts and probes), and once the first start took
    /// office no `--undo`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_whole_step_commits_and_office_ends_the_undo() {
        let root = TempDir::new("recover-whole");
        let (resolved, _, outcome) = interrupted(&root, None).await;
        assert!(outcome.is_ok(), "the step");
        let data = &resolved.data_dir;
        let store = resolved.layout().store();
        assert_eq!(state(&store).await.2, vec![NodeId(1)]);
        let notice = Notice::load(data).expect("notice").expect("a notice");
        assert_eq!(notice.phase, Phase::Committed);
        assert_eq!(
            notice.old.iter().map(|old| old.node).collect::<Vec<_>>(),
            vec![NodeId(2), NodeId(3)]
        );
        check_start(data, &store).expect("a finished step starts");
        let dirs = Dirs::new(&resolved, 1);
        assert!(!dirs.fence.exists(), "the new history starts unfenced");
        // A committed notice without its store is refused, not a fresh installation.
        fs::rename(&store, root.path().join("moved")).expect("move");
        assert_eq!(
            check_start(data, &store).expect_err("no store").code,
            codes::INTERRUPTED
        );
        fs::rename(root.path().join("moved"), &store).expect("back");
        let before = fs::read(data.join(NOTICE_FILE)).expect("notice").len();
        took_office(data).expect("office");
        // Written in place: the same file, the same length, the phase changed.
        assert_eq!(
            fs::read(data.join(NOTICE_FILE)).expect("notice").len(),
            before
        );
        assert_eq!(
            Notice::load(data).expect("notice").expect("a notice").phase,
            Phase::InOffice
        );
        assert!(pending(data).is_none(), "no probe after office");
        check_start(data, &store).expect("starts");
        refused(undo_at(data, &store), codes::UNDO_REFUSED);
        took_office(data).expect_err("once");
    }

    /// A second step while one is under way changes nothing and leaves the first one's
    /// notice in place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_step_beside_a_running_one_changes_nothing() {
        let root = TempDir::new("recover-twice");
        let (resolved, _, outcome) =
            interrupted(&root, Some((Step::Moved, Interrupt::Crash))).await;
        assert!(matches!(outcome, Err(Stopped::Crashed)));
        let data = &resolved.data_dir;
        let first = fs::read(data.join(NOTICE_FILE)).expect("the first notice");
        let second = notice(Phase::Prepared);
        let error = second.create(data).expect_err("a notice is there");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(data.join(NOTICE_FILE)).expect("notice"), first);
    }

    /// A copy that holds its controller's removal, still listing it as a voter, is refused
    /// before anything moves; when only the log the step applies holds the removal (the
    /// tail this copy never knew as committed), the step is refused after the replay and
    /// everything is put back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_copy_of_a_removed_controller_is_never_forced() {
        let root = TempDir::new("recover-removed");
        let resolved = three_voter_copy(root.path(), true).await;
        let store = resolved.layout().store();
        let before = state(&store).await;
        let copy = inspect(&store).await.expect("copy");
        let mut facts = Facts::read(&resolved, &copy).expect("facts");
        drop(copy);
        assert!(facts.copy.voters.contains(&NodeId(1)) && facts.removed_at.is_some());
        for applied in [true, false] {
            if !applied {
                facts.removed_at = None;
            }
            // With the removal applied, the refusal comes before the first step.
            let interrupt = move |step: Step| -> Option<Interrupt> {
                assert!(!applied, "reached {step:?}");
                None
            };
            let outcome = force_with(
                &resolved,
                &args(),
                &facts,
                Vec::new(),
                String::new(),
                &interrupt,
            )
            .await;
            let Err(Stopped::Failed(failure)) = outcome else {
                panic!("forced a removed controller's copy ({applied})");
            };
            assert!(
                format!("{failure:?}").contains(codes::REMOVED),
                "{failure:?}"
            );
            let dirs = Dirs::new(&resolved, 1);
            assert_eq!(state(&store).await, before, "{applied}");
            assert!(Notice::load(&resolved.data_dir).expect("notice").is_none());
            assert!(!dirs.kept.exists() && !dirs.work.exists() && !dirs.tail.exists());
            assert!(
                dirs.fence.exists() && !dirs.kept_fence.exists(),
                "{applied}"
            );
        }
    }

    /// A controller alone needs no forced step, unless another history stopped it: then the
    /// step is how an operator chooses its side, and it may revoke the other side's
    /// controller (enrolled, not a member of this copy). It never revokes itself or a node
    /// without a record.
    #[test]
    fn a_controller_another_history_stopped_is_forced_to_choose_its_side() {
        let mut alone = facts(1, 5, 100);
        alone.copy.voters = [NodeId(1)].into_iter().collect();
        alone.enrolled = [1, 2].into_iter().map(NodeId).collect();
        let checks = |facts: &Facts, revoke: &[u64]| {
            let args = RecoverArgs {
                revoke: revoke.to_vec(),
                ..args()
            };
            force_checks(&args, facts, &[]).map(|(others, _)| others)
        };
        let refused = checks(&alone, &[]).expect_err("alone and not stopped");
        assert!(format!("{refused:?}").contains(codes::NOT_NEEDED));
        alone.fence = Some(tenko_store::FenceReason::Diverged);
        checks(&alone, &[]).expect("a copy that kept the newer rows");
        alone.fence = Some(tenko_store::FenceReason::Reverted);
        let refused = checks(&alone, &[]).expect_err("an older copy");
        let text = format!("{refused:?}");
        for part in [
            "cluster.member.reverted",
            "tenko cluster join",
            "--despite-older-copy",
        ] {
            assert!(text.contains(part), "{part} in {text}");
        }
        let acknowledged = RecoverArgs {
            despite_older_copy: true,
            ..args()
        };
        force_checks(&acknowledged, &alone, &[]).expect("acknowledged");
        alone.fence = Some(tenko_store::FenceReason::Conflict);
        assert_eq!(checks(&alone, &[]).expect("stopped"), BTreeSet::new());
        checks(&alone, &[2]).expect("the other side's controller");
        for named in [1, 9] {
            let refused = checks(&alone, &[named]).expect_err("not another enrolled controller");
            assert!(format!("{refused:?}").contains(codes::UNKNOWN_NODE));
        }
    }

    /// A record of `number` forced on `node`, kept without its signature checked (enough
    /// for a text and a fence file).
    pub(crate) fn competing(node: u64, number: u64) -> generation::Signed {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![
            rcgen::SanType::URI(format!("urn:tenko:node:{node}").try_into().expect("uri")),
            rcgen::SanType::URI("urn:tenko:role:controller".try_into().expect("uri")),
        ];
        let leaf = params.self_signed(&key).expect("leaf").der().to_vec();
        let body = GenerationBody {
            layout: LAYOUT,
            number,
            parent: None,
            forced: NodeId(node),
            fork: ForkPoint {
                term: 1,
                leader: node,
                index: 1,
                revision: Revision(1),
                audit: ChainHead::default(),
            },
            superseded: Vec::new(),
            at: Timestamp::now(),
            nonce: HexBytes(vec![7; 16]),
        };
        generation::Signed::kept(&GenerationRecord {
            body: HexBytes(body.canonical().expect("body")),
            signature: HexBytes(Vec::new()),
            chain: vec![HexBytes(leaf)],
        })
        .expect("kept")
    }

    /// The text of a stopped copy shows the other record's figures as its claims beside what
    /// this copy holds, and recommends no side, whoever signed the other record.
    #[test]
    fn a_stopped_copy_shows_both_sides_and_recommends_none() {
        let mut copy = facts(1, 5, 100);
        copy.fence = Some(tenko_store::FenceReason::Conflict);
        (copy.seen, copy.counted) = (7, 7);
        copy.stopped_by = Some(competing(2, 1));
        copy.own = Some(competing(1, 1));
        for marked in [true, false] {
            copy.marked = if marked {
                [NodeId(2)].into_iter().collect()
            } else {
                BTreeSet::new()
            };
            let text = stopped_text(&copy).expect("a text");
            assert!(
                text.contains("The other record claims: generation 1, forced on controller 2"),
                "{text}"
            );
            assert!(
                text.contains("This copy holds:         generation 1, forced on controller 1"),
                "{text}"
            );
            assert!(text.contains("competes with"), "{text}");
            for advice in ["suggest", "recommend", "--revoke", "winner"] {
                assert!(!text.contains(advice), "{advice} in {text}");
            }
        }
    }

    /// A record too far above this copy's generation is named as not counted, beside the
    /// line of what stopped the copy, and the explanation of the stop says the step is not
    /// above it; a record within reach changes neither text.
    #[test]
    fn the_inspect_text_names_a_record_it_does_not_count() {
        let mut copy = facts(1, 5, 100);
        copy.fence = Some(tenko_store::FenceReason::Superseded);
        copy.stopped_by = Some(competing(2, u64::MAX));
        copy.own = Some(competing(1, 3));
        (copy.seen, copy.counted) = (u64::MAX, 3);
        let text = copy.describe();
        for line in [
            "stopped          cluster.superseded (generation 18446744073709551615 of another \
             history, forced on controller 2)",
            "not counted      generation 18446744073709551615 is not below 4294967299, the \
             limit of what a forced step here counts; it creates 4, not above it",
            "a forced step    creates generation 4 here",
        ] {
            assert!(text.contains(line), "{line} in {text}");
        }
        let stop = stopped_text(&copy).expect("a text");
        assert!(stop.contains("does not count the other record"), "{stop}");
        // Near the largest number the limit is that number itself.
        copy.own = Some(competing(1, u64::MAX - 10));
        copy.counted = u64::MAX - 10;
        let text = copy.describe();
        assert!(
            text.contains(
                "generation 18446744073709551615 is not below 18446744073709551615, the limit of \
                 what a forced step here counts; it creates 18446744073709551606, not above it"
            ),
            "{text}"
        );
        copy.own = Some(competing(1, 3));
        (copy.seen, copy.counted) = (STEP_REACH + 2, STEP_REACH + 2);
        assert!(!copy.describe().contains("not counted"));
        let stop = stopped_text(&copy).expect("a text");
        assert!(stop.contains("makes this copy the newer history"), "{stop}");
    }

    /// The next generation saturates: a copy that counts the largest number still names
    /// one, and a copy already at that number refuses a further step.
    #[test]
    fn the_next_generation_saturates() {
        let mut copy = facts(1, 5, 100);
        copy.counted = u64::MAX;
        assert_eq!(copy.next(), u64::MAX);
        copy.counted = 3;
        assert_eq!(copy.next(), 4);
        // A copy that holds the largest number already takes no further step: it would
        // replace its own record under the same number.
        copy.own = Some(competing(1, u64::MAX));
        let refused = force_checks(&args(), &copy, &[]).expect_err("no number left");
        assert!(
            format!("{refused:?}").contains(codes::NO_GENERATION_LEFT),
            "{refused:?}"
        );
        // The inspection says so instead of naming a generation the step would create.
        let text = copy.describe();
        assert!(
            text.contains("a forced step    is refused here (cluster.recover.no_generation_left)")
                && !text.contains("creates generation"),
            "{text}"
        );
    }

    /// `--inspect` names the generation a forced step creates; a refused confirmation and
    /// the refusal without a terminal never print the value to pass.
    #[test]
    fn the_confirmation_is_read_never_handed_over() {
        let mut copy = facts(1, 5, 100);
        (copy.seen, copy.counted) = (3, 3);
        copy.fence = Some(tenko_store::FenceReason::Superseded);
        let text = copy.describe();
        assert!(text.contains("creates generation 4"), "{text}");
        assert!(!text.contains("1:4"), "{text}");
        // A detail kept from an earlier finding stays beside the generation that stopped it.
        copy.found = Some("2026-11-20T10:00:00+00:00: node 2 sent 3-2-10".to_owned());
        let text = copy.describe();
        assert!(text.contains("generation 3 of another history"), "{text}");
        assert!(
            text.contains("found            2026-11-20T10:00:00+00:00: node 2"),
            "{text}"
        );
        copy.found = None;
        let wrong = RecoverArgs {
            confirm: Some("1:3".to_owned()),
            ..args()
        };
        let refused = confirmed(&wrong, NodeId(1), 4, "what the step does");
        assert!(!format!("{refused:?}").contains("1:4"));
        // The tests run without a terminal.
        let none = RecoverArgs {
            confirm: None,
            ..args()
        };
        let refused = confirmed(&none, NodeId(1), 4, "what the step does");
        assert!(format!("{refused:?}").contains(codes::CONFIRM));
        assert!(!format!("{refused:?}").contains("1:4"));
        confirmed(&args(), NodeId(1), 1, "what the step does").expect("the right value");
    }

    /// `--undo` puts back only the copy of the controller the notice names: a planted
    /// notice beside another copy changes nothing.
    #[test]
    fn an_undo_needs_the_copy_of_the_noticed_controller() {
        let (dir, store) = data_dir("current");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::create_dir_all(&dirs.kept).expect("kept");
        fs::write(dirs.kept.join("log.redb"), "another").expect("log");
        fs::write(dirs.kept.join(tenko_store::raft::NODE_ID_FILE), "7\n").expect("node id");
        notice(Phase::Committed).save(dir.path()).expect("notice");
        refused(undo_at(dir.path(), &store), codes::UNDO_REFUSED);
        assert_eq!(log_of(&store), "current");
        assert!(dirs.kept.exists());
    }

    /// The notice is a stored file a later binary reads after a crash: these bytes keep
    /// reading, a phase this build does not know reads as strict as `prepared`, and fields
    /// it does not know are ignored.
    #[test]
    fn the_kept_notice_still_reads() {
        let kept = r#"{
  "phase": "committed",
  "generation": 2,
  "node": 3,
  "parent": "1:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "old": [{ "node": 1, "address": "192.0.2.1:8444" }],
  "despite_majority": false,
  "at": "2026-11-13T10:00:00Z"
}"#;
        let notice: Notice = serde_json::from_str(kept).expect("the kept notice");
        assert_eq!(notice.phase, Phase::Committed);
        assert_eq!((notice.generation, notice.node), (2, NodeId(3)));
        assert_eq!(notice.old[0].address, "192.0.2.1:8444");
        let later = kept
            .replace("\"committed\"", "\"resumed\"")
            .replace("\"node\": 3,", "\"node\": 3, \"extra\": true,");
        let notice: Notice = serde_json::from_str(&later).expect("a later notice");
        assert_eq!(notice.phase, Phase::Unknown);
    }
}
