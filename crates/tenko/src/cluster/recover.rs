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
//!   confirmation (the node id; without a terminal `--confirm <node>:<generation>`, CR-Q8).
//! - `--undo` puts the copy kept aside back, until the first start took office.
//!
//! # The offline step and its crash points
//!
//! 1. The notice `recover.notice.json` is written with the phase `prepared`; from now on
//!    `tenko serve` refuses to start ([`check_start`]) until the step is finished or undone.
//! 2. `store/` is renamed to `recover-gen<n>/`: the copy kept aside, never written again.
//! 3. A copy of it in `recover-gen<n>.work/` gets its whole log applied, the uncommitted
//!    tail included (CR-Q5); the tail is also written, decoded, to
//!    `recover-gen<n>.tail.jsonl`.
//! 4. A new `store/` is installed from a snapshot of that state with this controller as the
//!    only voter, through the restore's install path.
//! 5. One batch writes the signed generation record, the superseded marks, the revocations
//!    of `--revoke` and the audit record `cluster.recover.force`.
//! 6. The work directory goes, and the notice turns `committed`.
//!
//! A failure before step 5 undoes the steps before it. After a crash at any point the notice
//! keeps the server from starting, and `--undo` puts the kept copy back.

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
    identity::{Credentials, NodePaths, write_private},
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
    /// A controller that may rejoin by itself when it holds nothing of its own after the
    /// fork (repeatable).
    #[arg(long, value_name = "NODE")]
    pub rejoin: Vec<u64>,
    /// A controller whose certificates the step revokes (repeatable).
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
}

/// The phase of a forced step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The step is under way or was interrupted: the server does not start.
    Prepared,
    /// The step is done: the first start probes the old voters.
    Committed,
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
        write_private(&data_dir.join(NOTICE_FILE), &text).map_err(|error| error.detail().to_owned())
    }
}

/// Refuses the start while a forced step is under way or was interrupted; the store step
/// of `tenko serve` calls it before it opens the store.
///
/// # Errors
///
/// [`StartError`] `cluster.recover.interrupted` naming the commands that finish or undo it.
pub fn check_start(data_dir: &Path) -> Result<(), StartError> {
    match Notice::load(data_dir) {
        Ok(None) => Ok(()),
        Ok(Some(notice)) if notice.phase == Phase::Committed => Ok(()),
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
            Ok(()) => Ok(()),
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

/// What a closed store and the files beside it say, for the inspection and the step.
struct Facts {
    copy: CopyFacts,
    node: NodeId,
    own: Option<generation::Signed>,
    /// The highest generation this copy has seen: its own or its fence's.
    seen: u64,
    members: BTreeMap<NodeId, MemberRecord>,
    /// The nodes with a record in the registry: the ones `--revoke` can revoke.
    enrolled: BTreeSet<NodeId>,
}

impl Facts {
    fn read(resolved: &Resolved, copy: &OfflineCopy) -> Result<Self, Failure> {
        let view = copy.view();
        let own = Lineage::read(view.as_ref())
            .map_err(store_failure)?
            .tip()
            .cloned();
        let fence = FenceFile::load(&resolved.data_dir).map_err(store_failure)?;
        let fence_number = fence
            .iter()
            .flat_map(|fence| &fence.records)
            .filter_map(|record| record.header().ok())
            .map(|header| header.number)
            .max()
            .unwrap_or(0);
        let members = view
            .scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)
            .map_err(store_failure)?
            .into_iter()
            .map(|(node, record, _)| (NodeId(node), record))
            .collect();
        let enrolled = view
            .scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)
            .map_err(store_failure)?
            .into_iter()
            .map(|(node, _, _)| NodeId(node))
            .collect();
        Ok(Self {
            enrolled,
            seen: own
                .as_ref()
                .map_or(0, generation::Signed::number)
                .max(fence_number),
            copy: copy.facts.clone(),
            node: copy.facts.node.unwrap_or(resolved.node_id),
            own,
            members,
        })
    }

    fn generation(&self) -> u64 {
        self.own.as_ref().map_or(0, generation::Signed::number)
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
            id.map_or_else(
                || "none".to_owned(),
                |id| format!("{}:{}", id.leader_id.term, id.index),
            )
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
        text
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
                "cluster.recover.fingerprint",
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
        let _ = writeln!(
            out,
            "  node {} at {}:{} (revision {}){}",
            fingerprint.node,
            fingerprint.term,
            fingerprint.index,
            fingerprint.revision,
            if *mine { "  <- this copy" } else { "" }
        );
        if *mine {
            behind_us = false;
        } else if behind_us && (fingerprint.term, fingerprint.index) > (ours.term, ours.index) {
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
            "the confirmation did not match; nothing was changed",
        )
    };
    if let Some(given) = &args.confirm {
        return if given.trim() == format!("{node}:{generation}") {
            Ok(())
        } else {
            Err(refused())
        };
    }
    if !std::io::stdin().is_terminal() {
        return Err(failure(
            codes::CONFIRM,
            exit::USAGE,
            format!(
                "no terminal to confirm on: pass `--confirm {node}:{generation}` after reading \
                 what the step does (`--inspect`)"
            ),
        ));
    }
    let mut err = std::io::stderr();
    let _ = write!(
        err,
        "{text}\nType the node id of this controller to continue: "
    );
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

#[allow(
    clippy::too_many_lines,
    reason = "the forced step reads best as one sequence with its undo"
)]
async fn force(
    resolved: &Resolved,
    args: &RecoverArgs,
    facts: &Facts,
    fresher: Vec<String>,
    mut stdout: String,
) -> Result<Output, Failure> {
    if let Some(notice) = Notice::load(&resolved.data_dir).map_err(Failure::other)? {
        return Err(failure(
            codes::INTERRUPTED,
            exit::USAGE,
            format!(
                "a forced step to generation {} is already here; run `tenko cluster recover \
                 --undo` first",
                notice.generation
            ),
        ));
    }
    let node = facts.node;
    if !facts.copy.voters.contains(&node) {
        return Err(failure(
            codes::NOT_NEEDED,
            exit::USAGE,
            format!("controller {node} is not a voter of its cluster; force a voter's copy"),
        ));
    }
    if facts.copy.voters.len() == 1 {
        return Err(failure(
            codes::NOT_NEEDED,
            exit::USAGE,
            format!("controller {node} is the only voter already; it needs no forced step"),
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
    for named in args.rejoin.iter().chain(&args.revoke) {
        if !others.contains(&NodeId(*named)) {
            return Err(failure(
                "cluster.recover.unknown_node",
                exit::USAGE,
                format!("controller {named} is not a member of this copy's cluster"),
            ));
        }
    }
    if let Some(named) = args
        .revoke
        .iter()
        .find(|named| !facts.enrolled.contains(&NodeId(**named)))
    {
        return Err(failure(
            "cluster.recover.unknown_node",
            exit::USAGE,
            format!(
                "controller {named} has no record in the node registry of this copy, so there \
                 are no certificates to revoke; remove it later with `tenko cluster remove`"
            ),
        ));
    }
    let credentials = Credentials::load(&NodePaths::new(&resolved.data_dir))
        .map_err(|error| failure(error.code(), exit::USAGE, error.detail()))?;
    let generation = facts.seen + 1;
    let text = confirmation(facts, generation, &others, args);
    confirmed(args, node, generation, &text)?;

    let dirs = Dirs::new(resolved, generation);
    let old: Vec<OldVoter> = others
        .iter()
        .map(|other| OldVoter {
            node: *other,
            address: facts
                .members
                .get(other)
                .map(|member| member.address.clone())
                .unwrap_or_default(),
        })
        .collect();
    let mut notice = Notice {
        phase: Phase::Prepared,
        generation,
        node,
        parent: facts.own.as_ref().and_then(|own| own.claim().render()),
        old,
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
        ));
    }
    notice.save(&resolved.data_dir).map_err(Failure::other)?;
    // Again now that the notice keeps a server from starting: one started since the
    // inspection would write into the copy that is to be kept.
    let moved = tenko_store::format::ensure_closed(&dirs.store)
        .map_err(store_failure)
        .and_then(|()| {
            fs::rename(&dirs.store, &dirs.kept)
                .map_err(|error| Failure::other(format!("renaming the store aside: {error}")))
        });
    if let Err(error) = moved {
        let _ = fs::remove_file(resolved.data_dir.join(NOTICE_FILE));
        return Err(error);
    }
    let committed = async {
        dirs.move_fence(false)?;
        let replayed = replay(&dirs.kept, &dirs.work)
            .await
            .map_err(|error| Failure::other(format!("applying the copy's log: {error}")))?;
        write_tail(&dirs.tail, &replayed)?;
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
                .copied()
                .filter(|voter| *voter != node)
                .collect(),
            at: Timestamp::now(),
            nonce: HexBytes(nonce()?),
        };
        let record = GenerationRecord::sign(&body, &credentials.chain, &credentials.key)
            .map_err(|error| failure(error.code(), exit::FAILURE, error.detail()))?;
        let written = write_batch(&store, &record, &body, &others, args, replayed.tail.len()).await;
        let _ = store.shutdown().await;
        drop(replayed);
        written.map(|()| record)
    }
    .await;
    let record = match committed {
        Ok(record) => record,
        Err(error) => {
            let _ = fs::remove_dir_all(&dirs.store);
            let _ = fs::remove_dir_all(&dirs.work);
            let _ = fs::remove_file(&dirs.tail);
            // The notice goes only when the old store and its fence are both back; else it
            // keeps the server from starting until `--undo`.
            if dirs.move_fence(true).is_ok() && fs::rename(&dirs.kept, &dirs.store).is_ok() {
                let _ = fs::remove_file(resolved.data_dir.join(NOTICE_FILE));
            }
            return Err(error);
        }
    };
    let _ = fs::remove_dir_all(&dirs.work);
    notice.phase = Phase::Committed;
    notice.save(&resolved.data_dir).map_err(Failure::other)?;
    let _ = writeln!(
        stdout,
        "\ngeneration {generation} created (record {}); the copy before it is kept in {}.\n\
         Start this controller now: its first start looks for a live majority of the old \
         voters for [cluster] recover_probe_secs before it takes office.",
        record.hash(),
        dirs.kept.display()
    );
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
    let position = facts.copy.last_log.map_or_else(
        || "the start".to_owned(),
        |id| format!("{}:{}", id.leader_id.term, id.index),
    );
    let mut text = format!(
        "This controller (node {}) becomes the only voter of the cluster, generation {generation}.\n\
         Its copy ends at log position {position} (revision {}); {} of its entries were not yet \
         known as committed and are kept.\n\n\
         Controllers {} stop being members. When one comes back, it stops writing at once and \
         keeps its copy aside on its own host.",
        facts.node,
        facts.copy.revision.0,
        facts.copy.unknown_commit(),
        list(&mut others.iter().map(ToString::to_string)),
    );
    if !args.rejoin.is_empty() {
        let _ = write!(
            text,
            " {} may then rejoin by itself as a learner when it holds nothing of its own after \
             this position;",
            list(&mut args.rejoin.iter().map(ToString::to_string))
        );
    }
    let _ = writeln!(
        text,
        " the others wait until you act on their host. Whatever they wrote after this position \
         does not come into this cluster."
    );
    if !args.revoke.is_empty() {
        let _ = writeln!(
            text,
            "The certificates of {} are revoked in the same write.",
            list(&mut args.revoke.iter().map(ToString::to_string))
        );
    }
    let _ = write!(
        text,
        "\nDo this only if those controllers are stopped or gone and cannot reach each other. If \
         they are running and reach each other, they are still a cluster, and this makes a \
         second one.\n\nThe copy this controller has now is kept in recover-gen{generation}/ \
         until you remove it; `--undo` restores it until the first start.\n"
    );
    text
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
            "log_id": format!("{}:{}", entry.log_id.leader_id.term, entry.log_id.index),
            "entry": describe(&entry.payload),
        });
        let _ = writeln!(text, "{line}");
    }
    write_private(path, text.as_bytes()).map_err(|error| Failure::other(error.detail()))
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
                    rejoin: args.rejoin.contains(&other.0),
                },
            )
            .map_err(Failure::other)?;
    }
    let mut revoked = Vec::new();
    for node in &args.revoke {
        revoked.extend(
            registry::stage_revocation(view.as_ref(), &mut batch, NodeId(*node), cx.now)
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
        .with_context("account", whoami())
        .with_context("host", host_name()),
    );
    drop(view);
    store.propose(batch).await.map_err(Failure::other)?;
    Ok(())
}

fn whoami() -> String {
    ["USER", "USERNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .unwrap_or_default()
}

fn host_name() -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .unwrap_or_default()
}

/// `--undo`: before the first start took office, the copy kept aside goes back.
fn undo(resolved: &Resolved) -> Result<Output, Failure> {
    undo_at(&resolved.data_dir, &resolved.layout().store())
}

/// [`undo`] for the data directory `data` and its store directory `store`.
fn undo_at(data: &Path, store: &Path) -> Result<Output, Failure> {
    let notice = Notice::load(data).map_err(Failure::other)?.ok_or_else(|| {
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
            fs::remove_file(data.join(NOTICE_FILE)).map_err(Failure::other)?;
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
    if tenko_store::format::store_exists(&dirs.store) {
        tenko_store::format::ensure_closed(&dirs.store).map_err(store_failure)?;
        fs::remove_dir_all(&dirs.store).map_err(Failure::other)?;
    } else if dirs.store.exists() {
        fs::remove_dir_all(&dirs.store).map_err(Failure::other)?;
    }
    let _ = fs::remove_dir_all(&dirs.work);
    let _ = fs::remove_file(&dirs.tail);
    fs::rename(&dirs.kept, &dirs.store).map_err(Failure::other)?;
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
    fs::remove_file(data.join(NOTICE_FILE)).map_err(Failure::other)?;
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
    fs::remove_file(data_dir.join(NOTICE_FILE))
        .map_err(|error| format!("{}: {error}", data_dir.join(NOTICE_FILE).display()))
}

#[cfg(test)]
mod tests {
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
        let refusal = check_start(dir.path()).expect_err("an unfinished step");
        assert_eq!(refusal.code, codes::INTERRUPTED);
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert!(check_start(dir.path()).is_ok());
        refused(undo_at(dir.path(), &store), codes::UNDO_REFUSED);
    }

    #[test]
    fn a_crash_after_the_store_moved_aside_is_undone() {
        let (dir, store) = data_dir("old");
        notice(Phase::Prepared).save(dir.path()).expect("notice");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::rename(&store, &dirs.kept).expect("aside");
        assert!(check_start(dir.path()).is_err());
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert!(!dirs.kept.exists());
        assert!(check_start(dir.path()).is_ok());
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
        assert!(check_start(dir.path()).is_err());
        undo_at(dir.path(), &store).expect("undo");
        assert_eq!(log_of(&store), "old");
        assert_eq!(
            fs::read_to_string(&dirs.fence).expect("fence back"),
            "the old fence"
        );
        assert!(!dirs.work.exists() && !dirs.tail.exists() && !dirs.kept_fence.exists());
        assert!(check_start(dir.path()).is_ok());
    }

    #[test]
    fn an_undo_before_the_first_start_drops_a_fence_of_the_new_history() {
        let (dir, store) = data_dir("old");
        let dirs = Dirs::at(dir.path(), &store, 1);
        fs::rename(&store, &dirs.kept).expect("aside");
        fs::create_dir_all(&store).expect("new store");
        fs::write(store.join("log.redb"), "new").expect("new log");
        notice(Phase::Committed).save(dir.path()).expect("notice");
        assert!(check_start(dir.path()).is_ok(), "a finished step starts");
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
            members: BTreeMap::new(),
            enrolled: BTreeSet::new(),
        }
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
}
