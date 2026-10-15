//! [`ClusterLab`]: one to five controllers as separate `tenko serve` processes on the
//! loopback, joined through the real `tenko cluster join`, with a [`Relay`] on every
//! directed link between two controllers.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant},
};

use reqwest::Method;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    http::Http,
    relay::{Fault, Relay},
};
use crate::serve_support::{ADMIN, Node, Outcome, PASSWORD, Proc, Transport, api::Api, run, tenko};

/// One lab at a time per test binary: several three-process clusters at once on one
/// machine measure the machine, not the cluster. `cargo nextest` runs every test in a
/// process of its own; run the lab binaries with `-j 1` there.
static LAB_LOCK: Mutex<()> = Mutex::new(());

/// The most controllers a lab starts with.
pub const MAX_CONTROLLERS: usize = 5;

/// Controllers that may join after the start unless [`LabOptions::spare`] says otherwise.
pub const DEFAULT_SPARE: usize = 2;

/// How long the start of a lab, a join or a start of one controller may take.
pub const START_LIMIT: Duration = Duration::from_secs(180);

/// How long a membership or leadership change may take to settle.
pub const SETTLE_LIMIT: Duration = Duration::from_secs(90);

/// How many log lines of each process a failure prints.
pub const LOG_TAIL: usize = 60;

/// How long `tenko cluster join` may wait for its copy of the cluster's data.
const JOIN_TIMEOUT_SECS: u64 = 300;

/// The prefix of the lab's IPv4 test data (RFC 5737).
pub const LAB_PREFIX_V4: &str = "198.51.100.0/24";

/// Options of a lab.
#[derive(Debug, Clone, Default)]
pub struct LabOptions {
    /// Configuration text appended to every controller's file: whole tables, such as a
    /// `[telemetry]` section.
    pub config: String,
    /// Controllers that may join after the start (default [`DEFAULT_SPARE`]).
    pub spare: Option<usize>,
    /// The `tenko` binary every controller runs and joins with at the start; default the
    /// binary under test. [`ClusterLab::set_binary`] changes it per controller.
    pub binary: Option<PathBuf>,
    /// Controllers dial each other directly: no `[cluster] peer_address_map` and no faults
    /// of links (for a binary that predates the key).
    pub direct_links: bool,
    /// Worker threads of each controller's API runtime (`[server] workers`); default the
    /// harness's 1. The measurements use 4, the upper end of the recommendation.
    pub workers: Option<u32>,
}

/// The state of one controller slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No controller has joined in this slot yet.
    Empty,
    /// The process runs.
    Running,
    /// Stopped gracefully.
    Stopped,
    /// Killed.
    Killed,
    /// Removed from the cluster; the slot stays empty.
    Removed,
}

/// One controller slot: its ports are fixed for the lab's life, so the relays and every
/// controller's `[cluster] peer_address_map` are written once.
struct Slot {
    /// The running process; it is killed before the directory below goes away.
    proc: Option<Proc>,
    /// The last process that ended, kept for its log.
    ended: Option<Proc>,
    node: Option<Node>,
    api_port: u16,
    cluster_port: u16,
    id: Option<u64>,
    joins: u32,
    state: State,
    binary: Option<PathBuf>,
    workers: Option<u32>,
}

impl Slot {
    fn node(&self) -> &Node {
        self.node.as_ref().expect("a node in the slot")
    }

    /// Writes the node's configuration and starts `tenko serve --config <file>
    /// --stop-on-eof` with the slot's binary.
    fn spawn(&self) -> Proc {
        let node = self.node();
        node.write_config();
        let mut command = program(self.binary.as_deref());
        if let Some(workers) = self.workers {
            // Over the harness's `[server] workers = 1` in the file.
            command.env("TENKO_SERVER__WORKERS", workers.to_string());
        }
        command
            .arg("serve")
            .arg("--config")
            .arg(node.config_path())
            .arg("--stop-on-eof");
        Proc::spawn(command)
    }

    fn cluster_addr(&self) -> String {
        format!("127.0.0.1:{}", self.cluster_port)
    }
}

/// The sizes of a controller's store files, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreSize {
    /// `store/sm.redb`: the state machine, the state file of M6.
    pub state: u64,
    /// `store/log.redb`: the Raft log.
    pub log: u64,
    /// `store/snapshots/`: every file in it.
    pub snapshots: u64,
}

impl StoreSize {
    /// Everything together.
    pub fn total(&self) -> u64 {
        self.state + self.log + self.snapshots
    }
}

/// A cluster of controllers on one machine; see the module documentation of
/// `cluster_support`. Dropping it kills every process and removes every directory.
pub struct ClusterLab {
    // Field order matters: processes end before their directories go.
    slots: Vec<Slot>,
    relays: BTreeMap<(usize, usize), Relay>,
    http: Http,
    ca_file: PathBuf,
    fingerprint: String,
    cookie: String,
    token: String,
    options: LabOptions,
    started: Instant,
    last_join: Option<Duration>,
    probes: u32,
    root: TempDir,
    _lock: MutexGuard<'static, ()>,
}

/// The largest odd number of voters at most `members`: what auto-promotion reaches.
pub fn odd_voters(members: usize) -> usize {
    if members % 2 == 1 {
        members
    } else {
        members.saturating_sub(1)
    }
}

/// The last `count` lines of `text`.
pub fn tail(text: &str, count: usize) -> String {
    // A peer that is down makes the leader log every failed append: count those lines
    // instead of letting them fill the tail.
    let noisy =
        |line: &str| line.contains("openraft::replication") || line.contains("replication_handler");
    let skipped: Vec<&str> = text.lines().filter(|line| noisy(line)).collect();
    let lines: Vec<&str> = text.lines().filter(|line| !noisy(line)).collect();
    let from = lines.len().saturating_sub(count);
    let mut tail = lines[from..].join("\n");
    if let Some(last) = skipped.last() {
        let _ = write!(
            tail,
            "\n({} lines of failed replication to a peer left out; the last: {last})",
            skipped.len()
        );
    }
    tail
}

/// The voters of a members view.
pub fn voters(view: &Value) -> Vec<u64> {
    members_with_role(view, "voter")
}

/// The learners of a members view.
pub fn learners(view: &Value) -> Vec<u64> {
    members_with_role(view, "learner")
}

fn members_with_role(view: &Value, role: &str) -> Vec<u64> {
    view["members"]
        .as_array()
        .map(|members| {
            members
                .iter()
                .filter(|member| member["role"] == role)
                .filter_map(|member| member["node"].as_u64())
                .collect()
        })
        .unwrap_or_default()
}

impl ClusterLab {
    /// Starts `n` controllers (1 to 5) and waits until the membership shows `n` members and
    /// an odd number of voters with one leader.
    #[track_caller]
    pub fn start(n: usize) -> Self {
        Self::start_with(n, LabOptions::default())
    }

    /// [`ClusterLab::start`] with options.
    #[track_caller]
    pub fn start_with(n: usize, options: LabOptions) -> Self {
        assert!(
            (1..=MAX_CONTROLLERS).contains(&n),
            "a lab has 1 to {MAX_CONTROLLERS} controllers"
        );
        let lock = LAB_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let started = Instant::now();
        let root = tempfile::Builder::new()
            .prefix("tenko-lab-")
            .tempdir()
            .expect("the lab's temporary directory");
        let total = n + options.spare.unwrap_or(DEFAULT_SPARE);
        // The ports stay bound until every relay has its own, so no relay takes the port of
        // a controller (the kernel may hand a just-released port out again).
        let held: Vec<(TcpListener, TcpListener)> = (0..total)
            .map(|_| {
                let bind = || TcpListener::bind(("127.0.0.1", 0)).expect("a free loopback port");
                (bind(), bind())
            })
            .collect();
        let port = |listener: &TcpListener| listener.local_addr().expect("an address").port();
        let mut slots: Vec<Slot> = held
            .iter()
            .map(|(api, cluster)| Slot {
                proc: None,
                ended: None,
                node: None,
                api_port: port(api),
                cluster_port: port(cluster),
                id: None,
                joins: 0,
                state: State::Empty,
                binary: options.binary.clone(),
                workers: options.workers,
            })
            .collect();
        let mut relays = BTreeMap::new();
        for from in (0..total).filter(|_| !options.direct_links) {
            for (to, slot) in slots.iter().enumerate() {
                if from != to {
                    let target: SocketAddr = slot.cluster_addr().parse().expect("address");
                    relays.insert((from, to), Relay::start(target));
                }
            }
        }
        drop(held);

        // The first controller: setup, the command-line client and a session.
        let mut first = Node::new()
            .with_transport(Transport::InternalCa)
            .with_config(&common_config(&options));
        first.port = slots[0].api_port;
        slots[0].node = Some(first.with_config(&member_config(&slots, &relays, 0, 1)));
        let server = slots[0].spawn();
        assert!(
            server
                .wait_stdout_line(START_LIMIT, |line| line.contains(" ready at "))
                .is_some(),
            "the first controller did not start\n{}",
            server.diagnostics()
        );
        let first = slots[0].node();
        first.setup_and_login(&server);
        let ca_file = root.path().join("ca-root.pem");
        std::fs::copy(first.ca_file().expect("an internal CA"), &ca_file)
            .expect("copy the CA root");
        let credentials: Value = serde_json::from_slice(
            &std::fs::read(first.credentials_path()).expect("the credentials of tenko login"),
        )
        .expect("JSON credentials");
        let token = credentials["token"]
            .as_str()
            .expect("a personal API token")
            .to_owned();
        slots[0].proc = Some(server);
        slots[0].id = Some(1);
        slots[0].joins = 1;
        slots[0].state = State::Running;
        let http = Http::new(&ca_file);
        let mut lab = Self {
            slots,
            relays,
            http,
            ca_file,
            fingerprint: String::new(),
            cookie: String::new(),
            token,
            options,
            started,
            last_join: None,
            probes: 0,
            root,
            _lock: lock,
        };
        lab.login();
        for index in 1..n {
            lab.join_slot(index);
        }
        lab.wait_for_members(n);
        lab
    }

    /// The time since the lab started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// The lab's temporary directory (the CA root, the probes).
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The CA root every controller's API and cluster port present.
    pub fn ca_file(&self) -> &Path {
        &self.ca_file
    }

    /// The SHA-256 fingerprint of the CA root.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The session cookie of the administrator, valid on every controller.
    pub fn cookie(&self) -> &str {
        &self.cookie
    }

    /// The lab's HTTP client.
    pub fn http(&self) -> &Http {
        &self.http
    }

    /// Signs the administrator in again (a fresh session, for the five-minute step-up of a
    /// controller token) through any running controller.
    #[track_caller]
    pub fn login(&mut self) {
        let base = self.any_url();
        let reply = self
            .http
            .send(
                Method::POST,
                &base,
                "/auth/login/password",
                None,
                Some(&json!({ "user_name": ADMIN, "password": PASSWORD })),
                &[],
            )
            .unwrap_or_else(|error| panic!("login: {error}\n{}", self.diagnostics()));
        assert_eq!(reply.status, 200, "login: {}", reply.text);
        let cookie = reply
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|text| text.split(';').next())
            .map(str::trim)
            .find(|pair| pair.starts_with("tenko_session=") && pair.len() > "tenko_session=".len())
            .expect("a session cookie")
            .to_owned();
        self.cookie = cookie;
    }

    fn slot_of(&self, id: u64) -> usize {
        self.slots
            .iter()
            .position(|slot| slot.id == Some(id))
            .unwrap_or_else(|| panic!("controller {id} is not in the lab"))
    }

    /// The node ids of the running controllers.
    pub fn ids(&self) -> Vec<u64> {
        self.slots
            .iter()
            .filter(|slot| slot.state == State::Running)
            .filter_map(|slot| slot.id)
            .collect()
    }

    /// The state of a controller.
    pub fn state(&self, id: u64) -> State {
        self.slots[self.slot_of(id)].state
    }

    /// The API URL of a controller (`https://localhost:<port>`).
    pub fn url(&self, id: u64) -> String {
        self.slots[self.slot_of(id)].node().url()
    }

    /// The API URL of some running controller.
    pub fn any_url(&self) -> String {
        self.slots
            .iter()
            .find(|slot| slot.state == State::Running)
            .map(|slot| slot.node().url())
            .expect("a running controller")
    }

    /// The API URLs of every controller that has joined, running or not.
    pub fn urls(&self) -> Vec<String> {
        self.slots
            .iter()
            .filter(|slot| slot.id.is_some() && slot.state != State::Removed)
            .map(|slot| slot.node().url())
            .collect()
    }

    /// The cluster port of a controller as it advertises it.
    pub fn cluster_addr(&self, id: u64) -> String {
        self.slots[self.slot_of(id)].cluster_addr()
    }

    /// The data directory of a controller.
    pub fn data_dir(&self, id: u64) -> PathBuf {
        self.slots[self.slot_of(id)].node().data_dir()
    }

    /// The sizes of a controller's store files.
    pub fn store_size(&self, id: u64) -> StoreSize {
        let store = self.data_dir(id).join("store");
        let size = |path: &Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
        let snapshots = std::fs::read_dir(store.join("snapshots")).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| size(&entry.path()))
                .sum()
        });
        StoreSize {
            state: size(&store.join("sm.redb")),
            log: size(&store.join("log.redb")),
            snapshots,
        }
    }

    /// A client of the public API of a controller, signed in with the lab's session.
    pub fn api(&self, id: u64) -> Api {
        let mut api = Api::new(self.slots[self.slot_of(id)].node());
        api.set_cookie(Some(self.cookie.clone()));
        api
    }

    /// `GET` of an API path on a controller with the lab's session; `None` when the
    /// controller does not answer.
    pub fn get(&self, id: u64, path: &str) -> Option<crate::serve_support::api::Reply> {
        self.http.get(&self.url(id), path, Some(&self.cookie)).ok()
    }

    /// Runs a client command against a controller with the administrator's personal API
    /// token (from the `tenko login` of the first controller).
    #[track_caller]
    pub fn cli(&self, id: u64, args: &[&str]) -> Outcome {
        let mut command = tenko();
        command
            .args(args)
            .arg("--url")
            .arg(self.url(id))
            .arg("--ca-file")
            .arg(&self.ca_file)
            .env("TENKO_TOKEN", &self.token)
            .env("TENKO_CREDENTIALS", self.root().join("no-credentials.json"));
        run(command, None)
    }

    /// The members view of a controller (`GET /cluster/members`), if it answers 200.
    pub fn members(&self, id: u64) -> Option<Value> {
        let reply = self.get(id, "/cluster/members")?;
        (reply.status == 200).then(|| reply.json())
    }

    /// The quorum state a controller reports for itself (`single`, `healthy`, `electing`,
    /// `isolated`).
    pub fn quorum(&self, id: u64) -> Option<String> {
        self.members(id)
            .and_then(|view| view["quorum"]["state"].as_str().map(str::to_owned))
    }

    /// The running controller that says it leads, with its view, if there is one now.
    pub fn current_leader(&self) -> Option<(u64, Value)> {
        self.ids().into_iter().find_map(|id| {
            let view = self.members(id)?;
            (view["leader"].as_u64() == Some(id)).then_some((id, view))
        })
    }

    /// Waits for a leader among the running controllers and returns it.
    #[track_caller]
    pub fn leader(&self) -> u64 {
        self.wait_until("a leader", SETTLE_LIMIT, || {
            self.current_leader().map(|(id, _)| id)
        })
    }

    /// The running controllers that do not lead.
    #[track_caller]
    pub fn followers(&self) -> Vec<u64> {
        let leader = self.leader();
        self.ids().into_iter().filter(|id| *id != leader).collect()
    }

    /// Waits until the membership has `n` members, the largest odd number of voters at most
    /// `n`, no change in progress, and every running controller is healthy and knows the
    /// same leader. Returns the leader's view.
    #[track_caller]
    pub fn wait_for_members(&self, n: usize) -> Value {
        self.wait_until(
            &format!("{n} members with {} voters", odd_voters(n)),
            START_LIMIT,
            || {
                let (leader, view) = self.current_leader()?;
                let members = view["members"].as_array()?.len();
                if members != n || voters(&view).len() != odd_voters(n) || view["changing"] == true
                {
                    return None;
                }
                let settled = self.ids().into_iter().all(|id| {
                    self.members(id).is_some_and(|seen| {
                        seen["leader"].as_u64() == Some(leader)
                            && matches!(
                                seen["quorum"]["state"].as_str(),
                                Some("healthy" | "single")
                            )
                    })
                });
                settled.then_some(view)
            },
        )
    }

    /// Polls `check` every 200 ms until it returns `Some`; after `limit` the test fails
    /// with the diagnostics of every process.
    #[track_caller]
    pub fn wait_until<T>(
        &self,
        what: &str,
        limit: Duration,
        mut check: impl FnMut() -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(found) = check() {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "timed out after {limit:?} waiting for {what}\n{}",
                self.diagnostics()
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// [`ClusterLab::wait_until`] for a condition.
    #[track_caller]
    pub fn wait_for(&self, what: &str, limit: Duration, mut check: impl FnMut() -> bool) {
        self.wait_until(what, limit, || check().then_some(()));
    }

    /// The last [`LOG_TAIL`] lines of every process of the lab, labelled.
    pub fn diagnostics(&self) -> String {
        let mut text = format!("--- lab after {:?} ---\n", self.started.elapsed());
        for id in self.ids() {
            let view = self.members(id).map_or_else(
                || "no answer".to_owned(),
                |view| {
                    let members: Vec<String> = view["members"]
                        .as_array()
                        .map(|members| {
                            members
                                .iter()
                                .map(|member| {
                                    format!(
                                        "{}:{}{} lag {}",
                                        member["node"],
                                        member["role"].as_str().unwrap_or("?"),
                                        if member["leader"] == true { "*" } else { "" },
                                        member["lag_entries"]
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    format!(
                        "leader {} term {} quorum {} changing {} members [{}]",
                        view["leader"],
                        view["term"],
                        view["quorum"]["state"],
                        view["changing"],
                        members.join(", ")
                    )
                },
            );
            let _ = writeln!(text, "--- controller {id} sees: {view}");
        }
        for (index, slot) in self.slots.iter().enumerate() {
            for (label, proc) in [("current", &slot.proc), ("previous", &slot.ended)] {
                if let Some(proc) = proc {
                    let _ = writeln!(
                        text,
                        "--- controller {:?} (slot {index}, {:?}, {label} process) stdout ---\n{}\n--- stderr ---\n{}",
                        slot.id,
                        slot.state,
                        tail(&proc.stdout_text(), LOG_TAIL),
                        tail(&proc.stderr_text(), LOG_TAIL)
                    );
                }
            }
        }
        text
    }

    /// Kills a controller without a graceful shutdown.
    pub fn kill(&mut self, id: u64) {
        let index = self.slot_of(id);
        let slot = &mut self.slots[index];
        let mut proc = slot.proc.take().expect("a running controller");
        proc.kill();
        slot.ended = Some(proc);
        slot.state = State::Killed;
    }

    /// Stops a controller gracefully and returns its output.
    #[track_caller]
    pub fn stop(&mut self, id: u64) -> Outcome {
        let index = self.slot_of(id);
        let slot = &mut self.slots[index];
        let mut proc = slot.proc.take().expect("a running controller");
        let outcome = proc.stop();
        slot.ended = Some(proc);
        slot.state = State::Stopped;
        outcome
    }

    /// Starts a stopped or killed controller again on its data directory and ports and
    /// waits until it is ready.
    #[track_caller]
    pub fn restart(&mut self, id: u64) {
        let index = self.slot_of(id);
        assert!(
            matches!(self.slots[index].state, State::Stopped | State::Killed),
            "controller {id} runs"
        );
        self.launch(index);
    }

    /// Starts several stopped or killed controllers at the same time (each waits for a
    /// quorum while it starts) and waits until every one is ready.
    #[track_caller]
    pub fn restart_all(&mut self, ids: &[u64]) {
        let indexes: Vec<usize> = ids.iter().map(|id| self.slot_of(*id)).collect();
        for index in &indexes {
            assert!(
                matches!(self.slots[*index].state, State::Stopped | State::Killed),
                "controller {:?} runs",
                self.slots[*index].id
            );
            self.spawn_slot(*index);
        }
        for index in indexes {
            self.wait_ready(index);
        }
    }

    /// Spawns the controller of a slot and waits for its `ready at` line.
    #[track_caller]
    fn launch(&mut self, index: usize) {
        self.spawn_slot(index);
        self.wait_ready(index);
    }

    fn spawn_slot(&mut self, index: usize) {
        let proc = self.slots[index].spawn();
        let slot = &mut self.slots[index];
        slot.proc = Some(proc);
        slot.state = State::Running;
    }

    #[track_caller]
    fn wait_ready(&self, index: usize) {
        let slot = &self.slots[index];
        let ready = slot.proc.as_ref().and_then(|proc| {
            proc.wait_stdout_line(START_LIMIT, |line| line.contains(" ready at "))
        });
        assert!(
            ready.is_some(),
            "controller {:?} was not ready within {START_LIMIT:?}\n{}",
            slot.id,
            self.diagnostics()
        );
    }

    /// A controller enrolment token from the API (a fresh session for the step-up); also
    /// remembers the CA fingerprint.
    #[track_caller]
    fn enrolment_token(&mut self, role: &str) -> String {
        if role == "controller" {
            self.login();
        }
        let base = self.any_url();
        let reply = self
            .http
            .send(
                Method::POST,
                &base,
                "/nodes/enrolments",
                Some(&self.cookie),
                Some(&json!({ "roles": [role] })),
                &[("Idempotency-Key", uuid::Uuid::now_v7().to_string())],
            )
            .unwrap_or_else(|error| panic!("token: {error}\n{}", self.diagnostics()));
        assert!(
            (200..300).contains(&reply.status),
            "a {role} token: HTTP {} {}",
            reply.status,
            reply.text
        );
        let body = reply.json();
        body["ca_fingerprint"]
            .as_str()
            .expect("a fingerprint")
            .clone_into(&mut self.fingerprint);
        body["token"].as_str().expect("a token").to_owned()
    }

    /// The enrolment token of a probe.
    #[track_caller]
    pub fn probe_token(&mut self) -> String {
        self.enrolment_token("probe")
    }

    /// Joins a new controller in an empty slot: `tenko cluster join` with a fresh
    /// controller token, then `tenko serve --config`. Returns its node id.
    #[track_caller]
    fn join_slot(&mut self, index: usize) -> u64 {
        assert!(
            matches!(self.slots[index].state, State::Empty | State::Removed),
            "slot {index} is in use"
        );
        let token = self.enrolment_token("controller");
        let controller = self
            .current_leader()
            .map_or_else(|| self.any_url(), |(leader, _)| self.url(leader));
        let mut node = Node::new()
            .with_transport(Transport::InternalCa)
            .with_config(&common_config(&self.options));
        node.port = self.slots[index].api_port;
        node.write_config();
        // `tenko serve` creates a missing key file at its first start; the join expects
        // one, as a container's mounted secret is.
        write_kek(&node.kek_path());
        let slot = &mut self.slots[index];
        slot.joins += 1;
        let address = slot.cluster_addr();
        let name = format!("lab-controller-{index}-{}", slot.joins);
        let mut command = program(slot.binary.as_deref());
        command
            .args(["cluster", "join", "--controller", &controller])
            .args(["--token", &token, "--ca-fingerprint", &self.fingerprint])
            .args(["--address", &address, "--listen", &address, "--name", &name])
            .args(["--timeout-secs", &JOIN_TIMEOUT_SECS.to_string(), "--json"])
            .arg("--config")
            .arg(node.config_path())
            .arg("--data-dir")
            .arg(node.data_dir());
        let begun = Instant::now();
        let mut join = Proc::spawn(command);
        join.close_stdin();
        let outcome = join.finish(Duration::from_secs(JOIN_TIMEOUT_SECS + 60));
        self.last_join = Some(begun.elapsed());
        assert_eq!(
            outcome.code,
            Some(0),
            "tenko cluster join failed\n{}\n{}",
            outcome.diagnostics(),
            self.diagnostics()
        );
        let id = outcome.json()["node"]
            .as_u64()
            .unwrap_or_else(|| panic!("no node id\n{}", outcome.diagnostics()));
        let node = node.with_config(&member_config(&self.slots, &self.relays, index, id));
        let slot = &mut self.slots[index];
        slot.node = Some(node);
        slot.id = Some(id);
        self.launch(index);
        id
    }

    /// How long the last `tenko cluster join` took (the copy of the cluster's data).
    pub fn last_join_time(&self) -> Option<Duration> {
        self.last_join
    }

    /// Joins one more controller in a spare slot and returns its id once it runs; it is a
    /// learner until the leader promotes it.
    #[track_caller]
    pub fn add_controller(&mut self) -> u64 {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == State::Empty)
            .expect("a spare slot: start the lab with more spare slots");
        self.join_slot(index)
    }

    /// Takes a member out of the cluster (`tenko cluster remove <id> --yes` on the leader),
    /// stopping it first when it runs; the slot stays empty.
    #[track_caller]
    pub fn remove(&mut self, id: u64) {
        let index = self.slot_of(id);
        if self.slots[index].state == State::Running {
            let leader = self.leader();
            if leader == id {
                self.cli(id, &["cluster", "step-down"]).assert_code(0);
                self.wait_for("another leader", SETTLE_LIMIT, || {
                    self.current_leader().is_some_and(|(now, _)| now != id)
                });
            }
            self.stop(id);
        }
        let leader = self.leader();
        let removed = self.cli(leader, &["cluster", "remove", &id.to_string(), "--yes"]);
        assert_eq!(
            removed.code,
            Some(0),
            "remove {id}\n{}\n{}",
            removed.diagnostics(),
            self.diagnostics()
        );
        self.slots[index].state = State::Removed;
    }

    /// Records that a member left the cluster by other means (a replacement through
    /// `tenko cluster promote --replace`, or a removal while it ran); its process must have
    /// ended.
    #[track_caller]
    pub fn mark_removed(&mut self, id: u64) {
        let index = self.slot_of(id);
        assert!(
            self.slots[index].proc.is_none(),
            "stop controller {id} before marking it removed"
        );
        self.slots[index].state = State::Removed;
    }

    /// The `tenko` binary a controller starts with from now on (`None`: the binary under
    /// test); takes effect at its next [`ClusterLab::restart`].
    pub fn set_binary(&mut self, id: u64, binary: Option<PathBuf>) {
        let index = self.slot_of(id);
        self.slots[index].binary = binary;
    }

    /// Rejoin with an empty data directory: the member leaves the cluster
    /// ([`ClusterLab::remove`]), its directory is replaced by an empty one, and it joins
    /// again with a fresh token on the same ports. Returns its new node id once the
    /// membership is complete again.
    #[track_caller]
    pub fn wipe_and_restart(&mut self, id: u64) -> u64 {
        let members = self
            .current_leader()
            .and_then(|(_, view)| view["members"].as_array().map(Vec::len))
            .unwrap_or_else(|| self.ids().len());
        self.remove(id);
        let index = self.slot_of(id);
        // The old directory goes once its process is gone.
        let old = self.slots[index].node.take();
        self.slots[index].ended = None;
        drop(old);
        self.slots[index].id = None;
        let new = self.join_slot(index);
        self.wait_for_members(members);
        new
    }

    /// The relay of the link `from -> to` (node ids).
    pub fn relay(&self, from: u64, to: u64) -> &Relay {
        &self.relays[&(self.slot_of(from), self.slot_of(to))]
    }

    /// Sets the fault of one directed link.
    pub fn set_link(&self, from: u64, to: u64, fault: Fault) {
        self.relay(from, to).set(fault);
    }

    /// Cuts every link between the two sets in both directions.
    pub fn partition(&self, one: &[u64], other: &[u64]) {
        for a in one {
            for b in other {
                self.set_link(*a, *b, Fault::Cut);
                self.set_link(*b, *a, Fault::Cut);
            }
        }
    }

    /// Every link back to [`Fault::Pass`].
    pub fn heal(&self) {
        for relay in self.relays.values() {
            relay.set(Fault::Pass);
        }
    }

    /// Delays the link `from -> to` by `ms` in each byte direction.
    pub fn delay(&self, from: u64, to: u64, ms: u64) {
        self.set_link(from, to, Fault::Delay(Duration::from_millis(ms)));
    }

    /// Drops new connections of the link `from -> to` with probability `ratio`.
    pub fn drop_links(&self, from: u64, to: u64, ratio: f64) {
        self.set_link(from, to, Fault::Drop(ratio));
    }

    /// The number of probes this lab enrolled (for unique names).
    pub(super) fn next_probe(&mut self) -> u32 {
        self.probes += 1;
        self.probes
    }
}

/// Writes a key-encryption key file for the `file` provider: 32 bytes as hexadecimal, from
/// the random bits of UUIDs (a test key).
fn write_kek(path: &Path) {
    let mut hex = String::with_capacity(65);
    for _ in 0..4 {
        for byte in &uuid::Uuid::now_v7().into_bytes()[8..] {
            let _ = write!(hex, "{byte:02x}");
        }
    }
    hex.push('\n');
    std::fs::write(path, hex).expect("write the key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict the key file");
    }
}

/// The configuration every controller of a lab gets on top of the harness's defaults.
fn common_config(options: &LabOptions) -> String {
    format!(
        "[rate_limit]\nenabled = false\n\n{}\n",
        options.config.trim_end()
    )
}

/// The `[node]` and `[cluster]` tables of the controller in slot `index` with node id `id`:
/// its cluster port, the lab's timings, and the relay of every link it dials.
fn member_config(
    slots: &[Slot],
    relays: &BTreeMap<(usize, usize), Relay>,
    index: usize,
    id: u64,
) -> String {
    let address = slots[index].cluster_addr();
    let map: Vec<String> = (0..slots.len())
        .filter(|other| *other != index)
        .filter_map(|other| {
            let relay = relays.get(&(index, other))?;
            Some(format!(
                "\"{}\" = \"{}\"",
                slots[other].cluster_addr(),
                relay.addr()
            ))
        })
        .collect();
    let mut text = format!(
        "[node]\nid = {id}\naddress = \"{address}\"\n\n[cluster]\nlisten = [\"{address}\"]\n\
         advertise = [\"{address}\"]\nheartbeat_secs = 1\nisolation_after_ms = 1000\n\
         catch_up_timeout_secs = 30\n"
    );
    if !map.is_empty() {
        let _ = writeln!(text, "peer_address_map = {{ {} }}", map.join(", "));
    }
    text
}

/// A command of the `tenko` binary at `binary` (the binary under test when `None`) with the
/// clean environment of [`tenko`].
fn program(binary: Option<&Path>) -> Command {
    let Some(binary) = binary else {
        return tenko();
    };
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        let inherited = upper.starts_with("TENKO_")
            || matches!(
                upper.as_str(),
                "RUST_LOG" | "NOTIFY_SOCKET" | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY"
            );
        if inherited {
            command.env_remove(&name);
        }
    }
    command
}
