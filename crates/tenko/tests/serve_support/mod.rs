//! Shared harness of the black-box tests of `tenko serve` and the client commands.
//!
//! A [`Node`] owns a temporary directory with a `tenko.toml` it writes, the data directory,
//! the key-encryption key, a private credentials file and a free loopback port. It spawns
//! the real `tenko` binary as a [`Proc`] whose standard output and standard error are
//! collected line by line on reader threads, so tests can wait for a log line, check the
//! order of the log, stop the server gracefully and read the complete output afterwards.
//! Client commands run against the node with [`Node::client`]; they get the node's URL, its
//! CA file when it serves HTTPS, and `TENKO_CREDENTIALS` pointing into the temporary
//! directory, so the credentials of the person running the tests are never read or written.
//!
//! # Transports
//!
//! - [`Transport::Plain`] is plain HTTP on `127.0.0.1`. The server runs in the reverse-proxy
//!   TLS mode with the loopback address as the trusted proxy. Such a server assumes that
//!   every request came in over HTTPS, so the CSRF guard would refuse the `http://` origin
//!   of the command-line client; the node's own origin is therefore listed in
//!   `server.allowed_origins`.
//! - [`Transport::InternalCa`] is the default mode of the product: HTTPS with a certificate
//!   from the internal CA on `localhost`, trusted through the CA root the server writes to
//!   `<data_dir>/tls/ca-root.pem`.
//!
//! Every data directory lives under the operating system's temporary directory, never in
//! the repository. Secrets are never printed: the server writes the setup token to
//! `<data_dir>/setup-token` (its standard output is a pipe here, not a terminal, so it only
//! names the file), [`wait_for_setup_token`] reads it from there, and client commands never
//! print the API token.

#![allow(
    dead_code,
    reason = "each test file uses a different part of the harness"
)]

use std::{
    collections::HashSet,
    fmt::Write as _,
    hash::BuildHasher as _,
    io::{BufRead as _, BufReader, Read, Write as _},
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tempfile::TempDir;

pub mod api;
pub mod otlp;

/// The version the binary reports, which is the version of this package.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The number of start steps: the length of `tenko::serve::START_ORDER`, so that a new step
/// does not break the tests that count them.
pub const STEP_COUNT: usize = tenko::serve::START_ORDER.len();

/// The names of the start steps, in start order, from `tenko::serve::START_ORDER`.
pub const STEPS: [&str; STEP_COUNT] = step_names();

const fn step_names() -> [&'static str; STEP_COUNT] {
    let mut names = [""; STEP_COUNT];
    let mut index = 0;
    while index < STEP_COUNT {
        names[index] = tenko::serve::START_ORDER[index].0;
        index += 1;
    }
    names
}

/// The log marker of a start step, `step <n>/<count> <name> <what>`, for example
/// `step 2/9 store failed` or `step 1/9 kek ready in `.
pub fn step_marker(name: &str, what: &str) -> String {
    let number = STEPS
        .iter()
        .position(|step| *step == name)
        .expect("a start step")
        + 1;
    format!("step {number}/{STEP_COUNT} {name} {what}")
}

/// The lines `tenko serve` logs while it shuts down, in order.
pub const SHUTDOWN_LINES: [&str; 5] = [
    "shutdown requested",
    "API stopped",
    "job runner stopped",
    "store closed: state durable",
    "tenko stopped",
];

/// The login name of the administrator the tests create.
pub const ADMIN: &str = "admin";

/// The password of the administrator: digits only, as the PIN preset of the Home profile
/// demands, and not on the list of common passwords.
pub const PASSWORD: &str = "739153";

/// How long a server may take to become ready.
pub const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a server may take to stop.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a client command may take.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(90);

/// The path of the readiness probe.
pub const READY_PATH: &str = "/api/v1/health/ready";

/// The ports [`free_port`] hands out: below the ephemeral range of Linux (32768 and up, the
/// ports the kernel gives to `bind(0)` and to the outgoing connections of every other
/// test), of Windows and of macOS (49152 and up), so that no test, client or server of the
/// suite takes a picked port in the window between the pick and the bind of the server.
const PORT_POOL: std::ops::Range<u16> = 20_000..32_000;

/// How often a pick is tried before the harness gives up (a pool full of ports in use is a
/// broken machine, not a race).
const PORT_PICKS: u32 = 500;

/// A free port on the loopback interface, for TCP and UDP alike, that no other call of this
/// process handed out and that is not in an ephemeral range.
///
/// The port is drawn at random from [`PORT_POOL`] and checked by binding it for both
/// protocols, so ports the machine uses for something else (and the ranges Windows
/// reserves) are skipped. The check cannot hold the port for a server that binds it later,
/// which is why [`Node::start_by`] starts again on a new port when the server reports that
/// its API listener could not bind.
pub fn free_port() -> u16 {
    static PICKS: AtomicU64 = AtomicU64::new(0);
    static HANDED_OUT: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    let span = u64::from(PORT_POOL.end - PORT_POOL.start);
    for _ in 0..PORT_PICKS {
        // Random per process (the hasher's keys) and different on every call.
        let draw = std::hash::RandomState::new().hash_one(PICKS.fetch_add(1, Ordering::Relaxed));
        let port = PORT_POOL.start + u16::try_from(draw % span).expect("below the pool's end");
        let mut handed_out = HANDED_OUT.lock().unwrap_or_else(PoisonError::into_inner);
        let handed_out = handed_out.get_or_insert_with(HashSet::new);
        if handed_out.contains(&port) || !is_free(port) {
            continue;
        }
        handed_out.insert(port);
        return port;
    }
    panic!("no free loopback port in {PORT_POOL:?} after {PORT_PICKS} picks");
}

/// Whether `port` can be bound on the loopback for TCP and for UDP right now.
fn is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok() && UdpSocket::bind(("127.0.0.1", port)).is_ok()
}

/// How often [`retry_on_bind`] starts a server before the test fails.
pub const START_ATTEMPTS: u32 = 3;

/// Whether the standard error of a server that failed to start says that its API listener
/// could not bind (start step `api`, code `start.api.bind`): another process took the port
/// between the pick and the bind, which a new port cures.
pub fn is_port_race(stderr: &str) -> bool {
    stderr.contains("start.api.bind")
}

/// Calls `attempt` up to [`START_ATTEMPTS`] times with the state and the number of the
/// attempt (from 1). An attempt that fails with an [`Outcome`] showing a lost port race
/// ([`is_port_race`]) is logged to standard error, `repick` gives the state a new port, and
/// the next attempt starts. Any other failure, and the failure of the last attempt, fails
/// the test with the output of the server.
#[track_caller]
pub fn retry_on_bind<S, T>(
    state: &mut S,
    mut attempt: impl FnMut(&mut S, u32) -> Result<T, Outcome>,
    mut repick: impl FnMut(&mut S),
) -> T {
    for number in 1..=START_ATTEMPTS {
        let outcome = match attempt(state, number) {
            Ok(started) => return started,
            Err(outcome) => outcome,
        };
        assert!(
            is_port_race(&outcome.stderr),
            "the server did not start\n{}",
            outcome.diagnostics()
        );
        assert!(
            number < START_ATTEMPTS,
            "the API port was taken in all {START_ATTEMPTS} attempts\n{}",
            outcome.diagnostics()
        );
        eprintln!(
            "start attempt {number} of {START_ATTEMPTS}: the API port was taken between the \
             pick and the bind; picking another port"
        );
        repick(state);
    }
    unreachable!("the loop returns or panics");
}

/// A `tenko` command with an environment that cannot influence the test: no `TENKO_*`
/// variables, no log filter, no service-manager socket and no proxy of the person who runs
/// the tests.
pub fn tenko() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tenko"));
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

/// Runs a command to completion with optional text on standard input.
pub fn run(command: Command, stdin: Option<&str>) -> Outcome {
    let mut process = Proc::spawn(command);
    if let Some(text) = stdin {
        process.write_stdin(text);
    }
    process.close_stdin();
    process.finish(CLIENT_TIMEOUT)
}

/// Runs `tenko` with these arguments, a clean environment plus `env`, and no standard
/// input.
pub fn run_tenko(args: &[&str], env: &[(&str, &str)]) -> Outcome {
    let mut command = tenko();
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    run(command, None)
}

/// The lines of `text` that contain `needle`.
pub fn lines_with<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines().filter(|line| line.contains(needle)).collect()
}

/// Asserts that every needle occurs in `text`, each one after the previous one.
pub fn assert_in_order(text: &str, needles: &[impl AsRef<str>]) {
    let mut from = 0;
    for needle in needles {
        let needle = needle.as_ref();
        match text[from..].find(needle) {
            Some(offset) => from += offset + needle.len(),
            None => {
                panic!("`{needle}` is missing or out of order (searched after byte {from})\n{text}")
            }
        }
    }
}

/// The setup tokens printed on standard output: the value of every `Setup token:` line that
/// has the shape of a token. A server whose standard output is not a terminal prints none:
/// its `Setup token:` line names the file instead.
pub fn stdout_setup_tokens(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("Setup token: "))
        .map(|token| token.trim().to_owned())
        .filter(|token| is_setup_token(token))
        .collect()
}

/// The setup tokens in the log: the value of every `setup_token=` field.
pub fn log_setup_tokens(stderr: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for line in stderr.lines() {
        let mut rest = line;
        while let Some(at) = rest.find("setup_token=") {
            let value = &rest[at + "setup_token=".len()..];
            let value = value.trim_start_matches('"');
            let end = value
                .find(|c: char| c == '"' || c.is_whitespace())
                .unwrap_or(value.len());
            tokens.push(value[..end].to_owned());
            rest = &value[end..];
        }
    }
    tokens
}

/// Whether `token` has the shape of a setup token: four groups of five upper-case letters
/// and digits, joined by dashes.
pub fn is_setup_token(token: &str) -> bool {
    let groups: Vec<&str> = token.split('-').collect();
    groups.len() == 4
        && groups.iter().all(|group| {
            group.len() == 5
                && group
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
}

/// The milliseconds a `step N/<count> <name> ready in <ms> ms` line reports.
pub fn step_millis(stderr: &str, name: &str) -> u64 {
    let marker = step_marker(name, "ready in ");
    let line = lines_with(stderr, &marker)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no `{marker}` line\n{stderr}"));
    let after = &line[line.find(&marker).expect("marker") + marker.len()..];
    after
        .split_whitespace()
        .next()
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("no duration in `{line}`"))
}

/// A plain `GET` returning the status and the body, with the CA file as the only extra
/// trust anchor. The error is a description of the failure (connection, TLS).
pub fn http_get(url: &str, ca_file: Option<&Path>) -> Result<(u16, String), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("runtime: {error}"))?;
    runtime.block_on(async {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10));
        if let Some(path) = ca_file {
            let pem =
                std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| format!("CA file: {error}"))?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder
            .build()
            .map_err(|error| format!("client: {error}"))?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|error| format!("{error:?}"))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|error| format!("body: {error}"))?;
        Ok((status, body))
    })
}

/// A TOML literal string for a path, so that Windows backslashes need no escaping.
fn toml_path(path: &Path) -> String {
    let text = path.to_str().expect("UTF-8 path");
    assert!(
        !text.contains('\''),
        "{text} cannot be a TOML literal string"
    );
    format!("'{text}'")
}

/// The complete output of a finished process.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The exit status; `None` when a signal ended the process.
    pub code: Option<i32>,
    /// Everything written to standard output.
    pub stdout: String,
    /// Everything written to standard error.
    pub stderr: String,
}

impl Outcome {
    /// Standard output and standard error, labelled, for failure messages.
    pub fn diagnostics(&self) -> String {
        format!(
            "exit status: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }

    /// Asserts the exit status and returns the outcome for further checks.
    #[track_caller]
    pub fn assert_code(&self, expected: i32) -> &Self {
        assert_eq!(self.code, Some(expected), "{}", self.diagnostics());
        self
    }

    /// Asserts that standard output contains `needle`.
    #[track_caller]
    pub fn assert_stdout_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stdout.contains(needle),
            "stdout lacks `{needle}`\n{}",
            self.diagnostics()
        );
        self
    }

    /// Asserts that standard error contains `needle`.
    #[track_caller]
    pub fn assert_stderr_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stderr.contains(needle),
            "stderr lacks `{needle}`\n{}",
            self.diagnostics()
        );
        self
    }

    /// Asserts that a server shut down gracefully: exit status 0 and the shutdown lines in
    /// order.
    #[track_caller]
    pub fn assert_graceful_shutdown(&self) -> &Self {
        self.assert_code(0);
        assert_in_order(&self.stderr, &SHUTDOWN_LINES);
        self
    }

    /// The JSON on standard output.
    #[track_caller]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error})\n{}", self.diagnostics()))
    }
}

/// Lines of one output stream, collected by a reader thread.
#[derive(Default)]
struct Buffer {
    lines: Vec<String>,
    closed: bool,
}

/// A stream that is read on its own thread and can be waited on.
struct Capture {
    buffer: Mutex<Buffer>,
    changed: Condvar,
}

impl Capture {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            buffer: Mutex::new(Buffer::default()),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Buffer> {
        self.buffer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, line: String) {
        self.lock().lines.push(line);
        self.changed.notify_all();
    }

    fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// The first line `wanted` accepts, waiting for it; `None` at the end of the stream or
    /// when the time is up.
    fn wait_for(&self, timeout: Duration, wanted: &dyn Fn(&str) -> bool) -> Option<String> {
        let deadline = Instant::now() + timeout;
        let mut buffer = self.lock();
        loop {
            if let Some(line) = buffer.lines.iter().find(|line| wanted(line)) {
                return Some(line.clone());
            }
            if buffer.closed {
                return None;
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            buffer = self
                .changed
                .wait_timeout(buffer, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    fn text(&self) -> String {
        let buffer = self.lock();
        let mut text = buffer.lines.join("\n");
        if !buffer.lines.is_empty() {
            text.push('\n');
        }
        text
    }

    /// Reads `reader` to its end on a new thread.
    fn pump(self: &Arc<Self>, reader: impl Read + Send + 'static) -> JoinHandle<()> {
        let capture = Arc::clone(self);
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut raw = Vec::new();
            loop {
                raw.clear();
                match reader.read_until(b'\n', &mut raw) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => capture.push(
                        String::from_utf8_lossy(&raw)
                            .trim_end_matches(['\r', '\n'])
                            .to_owned(),
                    ),
                }
            }
            capture.close();
        })
    }
}

/// A running `tenko` process with piped standard streams. It is killed when dropped, so a
/// failing test leaves no server behind.
pub struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Capture>,
    stderr: Arc<Capture>,
    readers: Vec<JoinHandle<()>>,
}

impl Proc {
    /// Spawns `command` with all three standard streams piped.
    pub fn spawn(mut command: Command) -> Self {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn the tenko binary");
        let stdin = child.stdin.take();
        let stdout = Capture::new();
        let stderr = Capture::new();
        let readers = vec![
            stdout.pump(child.stdout.take().expect("piped stdout")),
            stderr.pump(child.stderr.take().expect("piped stderr")),
        ];
        Self {
            child,
            stdin,
            stdout,
            stderr,
            readers,
        }
    }

    /// The process identifier.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Writes text to standard input and keeps it open. A process that has already
    /// stopped reading is not an error.
    pub fn write_stdin(&mut self, text: &str) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(text.as_bytes());
            let _ = stdin.flush();
        }
    }

    /// Closes standard input: the end of input a `--stop-on-eof` server waits for.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Waits for a line of standard output.
    pub fn wait_stdout_line(
        &self,
        timeout: Duration,
        wanted: impl Fn(&str) -> bool,
    ) -> Option<String> {
        self.stdout.wait_for(timeout, &wanted)
    }

    /// Waits for a line of standard error.
    pub fn wait_stderr_line(
        &self,
        timeout: Duration,
        wanted: impl Fn(&str) -> bool,
    ) -> Option<String> {
        self.stderr.wait_for(timeout, &wanted)
    }

    /// Whether the process closed its standard output, which it does when it exits (the
    /// exit status may follow a moment later: [`Proc::finish`] waits for it).
    pub fn stdout_closed(&self) -> bool {
        self.stdout.is_closed()
    }

    /// Standard output so far.
    pub fn stdout_text(&self) -> String {
        self.stdout.text()
    }

    /// Standard error so far.
    pub fn stderr_text(&self) -> String {
        self.stderr.text()
    }

    /// The output so far, labelled, for failure messages.
    pub fn diagnostics(&self) -> String {
        format!(
            "--- stdout so far ---\n{}\n--- stderr so far ---\n{}",
            self.stdout_text(),
            self.stderr_text()
        )
    }

    /// Whether the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Kills the process, without a graceful shutdown.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Sends `SIGTERM`.
    #[cfg(unix)]
    pub fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
    }

    /// Waits for the process to exit and returns everything it wrote. A process that does
    /// not exit in time is killed and the test fails.
    #[track_caller]
    pub fn finish(&mut self, timeout: Duration) -> Outcome {
        let deadline = Instant::now() + timeout;
        let status = loop {
            match self.child.try_wait().expect("poll the process") {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    self.kill();
                    panic!(
                        "the process did not exit within {timeout:?}\n{}",
                        self.diagnostics()
                    );
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        };
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Outcome {
            code: status.code(),
            stdout: self.stdout.text(),
            stderr: self.stderr.text(),
        }
    }

    /// Stops a server the way a supervisor without signals does: closes standard input
    /// (the server was started with `--stop-on-eof`) and waits for the exit.
    #[track_caller]
    pub fn stop(&mut self) -> Outcome {
        self.close_stdin();
        self.finish(STOP_TIMEOUT)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// How a node is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain HTTP on `127.0.0.1` (reverse-proxy mode with the loopback as trusted proxy).
    Plain,
    /// HTTPS on `localhost` with a certificate from the internal CA.
    InternalCa,
    /// HTTPS on `localhost` with an imported certificate: a leaf of a test CA that
    /// [`Node::with_transport`] writes into the node's directory (`tls.mode = "imported"`).
    Imported,
}

/// Which key-encryption key provider protects the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kek {
    /// An explicit key file in the node's temporary directory (the same on every platform).
    File,
    /// The platform default: DPAPI on Windows, `systemd-creds` on Linux.
    Platform,
}

/// One `tenko` node: its files, its port and the way to start it and to talk to it.
pub struct Node {
    root: TempDir,
    /// The loopback port the API listens on.
    pub port: u16,
    transport: Transport,
    kek: Kek,
    args: Vec<String>,
    stop_on_eof: bool,
    /// Configuration text appended to the generated file (a section of its own).
    extra_config: String,
}

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    /// A node with plain HTTP and a key file, in a new temporary directory.
    pub fn new() -> Self {
        Self {
            root: tempfile::Builder::new()
                .prefix("tenko-it-")
                .tempdir()
                .expect("temporary directory"),
            port: free_port(),
            transport: Transport::Plain,
            kek: Kek::File,
            args: Vec::new(),
            stop_on_eof: true,
            extra_config: String::new(),
        }
    }

    /// Chooses the transport.
    #[must_use]
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        if transport == Transport::Imported {
            self.write_imported_certificate();
        }
        self
    }

    /// The test CA's root of [`Transport::Imported`].
    pub fn imported_ca_path(&self) -> PathBuf {
        self.root().join("imported-ca.pem")
    }

    /// The certificate chain of [`Transport::Imported`] (the leaf, then the test CA).
    pub fn imported_cert_path(&self) -> PathBuf {
        self.root().join("imported-cert.pem")
    }

    /// The private key of [`Transport::Imported`].
    pub fn imported_key_path(&self) -> PathBuf {
        self.root().join("imported-key.pem")
    }

    /// Writes a test CA and a leaf for `localhost` signed by it, as an operator would
    /// import them.
    fn write_imported_certificate(&self) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Tenko imported test CA");
        let ca_key = rcgen::KeyPair::generate().expect("a CA key");
        let issuer = rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("a CA");
        let key = rcgen::KeyPair::generate().expect("a leaf key");
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("a leaf");
        let ca_pem = issuer.as_ref().pem();
        std::fs::write(self.imported_ca_path(), &ca_pem).expect("write the CA");
        std::fs::write(self.imported_cert_path(), format!("{}{ca_pem}", leaf.pem()))
            .expect("write the chain");
        std::fs::write(self.imported_key_path(), key.serialize_pem()).expect("write the key");
    }

    /// Chooses the key-encryption key provider.
    #[must_use]
    pub fn with_kek(mut self, kek: Kek) -> Self {
        self.kek = kek;
        self
    }

    /// Adds command-line arguments to `tenko serve`.
    #[must_use]
    pub fn with_args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|arg| (*arg).to_owned()));
        self
    }

    /// Appends configuration text, for example a `[cluster]` section, to the generated
    /// file.
    #[must_use]
    pub fn with_config(mut self, text: &str) -> Self {
        self.extra_config.push('\n');
        self.extra_config.push_str(text);
        self.extra_config.push('\n');
        self
    }

    /// Starts the server without `--stop-on-eof`, so that only signals stop it.
    #[must_use]
    pub fn without_stop_on_eof(mut self) -> Self {
        self.stop_on_eof = false;
        self
    }

    /// The temporary directory that holds every file of the node.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The data directory.
    pub fn data_dir(&self) -> PathBuf {
        self.root().join("data")
    }

    /// The configuration file.
    pub fn config_path(&self) -> PathBuf {
        self.root().join("tenko.toml")
    }

    /// The key file of [`Kek::File`].
    pub fn kek_path(&self) -> PathBuf {
        self.root().join("kek.key")
    }

    /// The default key directory of [`Kek::Platform`].
    pub fn kek_dir(&self) -> PathBuf {
        self.data_dir().join("kek")
    }

    /// The file with the setup token while first-run setup is open.
    pub fn setup_token_path(&self) -> PathBuf {
        self.data_dir().join("setup-token")
    }

    /// The token in [`Node::setup_token_path`], if the file exists.
    pub fn read_setup_token(&self) -> Option<String> {
        read_setup_token_file(&self.setup_token_path())
    }

    /// Waits until the setup token file is gone; false when it is still there after
    /// `timeout`.
    pub fn wait_for_setup_token_removal(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.setup_token_path().exists() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
        true
    }

    /// `tenko setup token --data-dir <data_dir>`.
    #[track_caller]
    pub fn print_setup_token(&self) -> Outcome {
        let data_dir = self.data_dir();
        run_tenko(
            &[
                "setup",
                "token",
                "--data-dir",
                data_dir.to_str().expect("UTF-8"),
            ],
            &[],
        )
    }

    /// The credentials file the client commands of this node use.
    pub fn credentials_path(&self) -> PathBuf {
        self.root().join("credentials.json")
    }

    /// The CA root of the internal CA, if this node serves HTTPS.
    pub fn ca_file(&self) -> Option<PathBuf> {
        match self.transport {
            Transport::Plain => None,
            Transport::InternalCa => Some(self.data_dir().join("tls").join("ca-root.pem")),
            Transport::Imported => Some(self.imported_ca_path()),
        }
    }

    /// The base URL clients use.
    pub fn url(&self) -> String {
        self.url_on(self.port)
    }

    fn url_on(&self, port: u16) -> String {
        match self.transport {
            Transport::Plain => format!("http://127.0.0.1:{port}"),
            Transport::InternalCa | Transport::Imported => format!("https://localhost:{port}"),
        }
    }

    /// The configuration file text for a server on `port`.
    pub fn config_text_on(&self, port: u16) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "data_dir = {}", toml_path(&self.data_dir()));
        let _ = writeln!(text, "roles = \"controller\"\n");
        let _ = writeln!(text, "[server]");
        let _ = writeln!(text, "listen = [\"127.0.0.1:{port}\"]");
        let _ = writeln!(text, "workers = 1");
        match self.transport {
            Transport::Plain => {
                let _ = writeln!(text, "allowed_origins = [\"http://127.0.0.1:{port}\"]\n");
                let _ = writeln!(text, "[tls]");
                let _ = writeln!(text, "mode = \"reverse_proxy\"");
                let _ = writeln!(text, "public_host = \"localhost\"");
                let _ = writeln!(text, "trusted_proxies = [\"127.0.0.1\"]\n");
            }
            Transport::InternalCa => {
                let _ = writeln!(text, "\n[tls]");
                let _ = writeln!(text, "mode = \"internal_ca\"\n");
            }
            Transport::Imported => {
                let _ = writeln!(text, "\n[tls]");
                let _ = writeln!(text, "mode = \"imported\"");
                let _ = writeln!(
                    text,
                    "cert_path = {}",
                    toml_path(&self.imported_cert_path())
                );
                let _ = writeln!(
                    text,
                    "key_path = {}\n",
                    toml_path(&self.imported_key_path())
                );
            }
        }
        match self.kek {
            Kek::File => {
                let _ = writeln!(text, "[kek]");
                let _ = writeln!(text, "provider = \"file\"");
                let _ = writeln!(text, "path = {}\n", toml_path(&self.kek_path()));
            }
            Kek::Platform => {
                let _ = writeln!(text, "[kek]");
                let _ = writeln!(text, "provider = \"platform\"\n");
            }
        }
        let _ = writeln!(text, "[hibp]");
        let _ = writeln!(text, "online = false\n");
        let _ = writeln!(text, "[log]");
        let _ = writeln!(text, "level = \"info\"");
        text.push_str(&self.extra_config);
        text
    }

    /// The configuration file text for the node's own port.
    pub fn config_text(&self) -> String {
        self.config_text_on(self.port)
    }

    /// Writes the configuration file.
    pub fn write_config(&self) {
        std::fs::write(self.config_path(), self.config_text()).expect("write tenko.toml");
    }

    /// The `tenko serve` command of this node.
    pub fn serve_command(&self) -> Command {
        let mut command = tenko();
        command.arg("serve").arg("--config").arg(self.config_path());
        if self.stop_on_eof {
            command.arg("--stop-on-eof");
        }
        command.args(&self.args);
        command
    }

    /// Writes the configuration and spawns the server, without waiting for anything.
    pub fn spawn(&self) -> Proc {
        self.write_config();
        Proc::spawn(self.serve_command())
    }

    /// Spawns a second server on the same data directory and the same key, listening on
    /// another port, with a configuration file of its own.
    pub fn spawn_second(&self) -> Proc {
        let path = self.root().join("second.toml");
        std::fs::write(&path, self.config_text_on(free_port())).expect("write second.toml");
        let mut command = tenko();
        command.arg("serve").arg("--config").arg(path);
        if self.stop_on_eof {
            command.arg("--stop-on-eof");
        }
        Proc::spawn(command)
    }

    /// Starts the server and waits until it is ready: the `ready at` line on standard
    /// output and a `200` from the readiness probe. See [`Node::start_by`] for the port
    /// race and for every other failure.
    #[track_caller]
    pub fn start(&mut self) -> Proc {
        self.start_by(Node::spawn)
    }

    /// Like [`Node::start`] with the process spawned by `launch`, which writes the
    /// configuration (for example with other text) and adds arguments or environment
    /// variables to [`Node::serve_command`]; it runs again on every attempt.
    ///
    /// The API port was picked by [`free_port`] and is bound later by the server, so
    /// another process may take it in between. When the server exits during start with the
    /// code `start.api.bind`, the node picks a new port and `launch` runs again, at most
    /// [`START_ATTEMPTS`] times in all; every attempt that lost the race is logged to
    /// standard error. Every other failure fails the test at once with the output of the
    /// server, the bind failure of another listener (cluster, DNS, DHCP, metrics) included:
    /// the test holds those ports, and the node cannot move them.
    #[track_caller]
    pub fn start_by(&mut self, launch: impl Fn(&Node) -> Proc) -> Proc {
        retry_on_bind(
            self,
            |node, _| {
                let mut server = launch(node);
                let ready =
                    server.wait_stdout_line(READY_TIMEOUT, |line| line.contains(" ready at "));
                if ready.is_some() {
                    node.wait_for_ready_probe(&mut server);
                    return Ok(server);
                }
                // `None` is the end of standard output or the time limit. The output ends
                // slightly before the exit status is available, so a server that stopped
                // is never judged by `is_running` here: `finish` waits for the exit.
                assert!(
                    server.stdout_closed(),
                    "the server was not ready within {READY_TIMEOUT:?}\n{}",
                    server.diagnostics()
                );
                Err(server.finish(STOP_TIMEOUT))
            },
            |node| node.port = free_port(),
        )
    }

    #[track_caller]
    fn wait_for_ready_probe(&self, server: &mut Proc) {
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut last = String::new();
        while Instant::now() < deadline {
            assert!(
                server.is_running(),
                "the server stopped while becoming ready\n{}",
                server.diagnostics()
            );
            match self.get(READY_PATH) {
                Ok((200, _)) => return,
                Ok((status, body)) => last = format!("HTTP {status}: {body}"),
                Err(error) => last = error,
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "the readiness probe never answered 200 ({last})\n{}",
            server.diagnostics()
        );
    }

    /// `GET` of a path of this node, trusting the node's CA file when it has one.
    pub fn get(&self, path: &str) -> Result<(u16, String), String> {
        http_get(&format!("{}{path}", self.url()), self.ca_file().as_deref())
    }

    /// Runs a client command against this node: the arguments, then `--url`, `--ca-file`
    /// when the node serves HTTPS, and a credentials file inside the node's directory.
    #[track_caller]
    pub fn client(&self, args: &[&str]) -> Outcome {
        self.run_client(args, None)
    }

    /// Like [`Node::client`] with text on standard input (a password).
    #[track_caller]
    pub fn client_stdin(&self, args: &[&str], stdin: &str) -> Outcome {
        self.run_client(args, Some(stdin))
    }

    #[track_caller]
    fn run_client(&self, args: &[&str], stdin: Option<&str>) -> Outcome {
        let mut command = tenko();
        command.args(args).arg("--url").arg(self.url());
        if let Some(ca) = self.ca_file() {
            command.arg("--ca-file").arg(ca);
        }
        command.env("TENKO_CREDENTIALS", self.credentials_path());
        run(command, stdin)
    }

    /// `tenko setup` with the administrator of the tests.
    #[track_caller]
    pub fn setup(&self, token: &str) -> Outcome {
        self.client_stdin(
            &[
                "setup",
                "--setup-token",
                token,
                "--admin",
                ADMIN,
                "--host-name",
                "localhost",
                "--password-stdin",
            ],
            &format!("{PASSWORD}\n"),
        )
    }

    /// `tenko login` as the administrator of the tests.
    #[track_caller]
    pub fn login(&self) -> Outcome {
        self.client_stdin(
            &["login", "--user", ADMIN, "--password-stdin"],
            &format!("{PASSWORD}\n"),
        )
    }

    /// Completes setup and signs in, each step with exit status 0.
    #[track_caller]
    pub fn setup_and_login(&self, server: &Proc) {
        let token = wait_for_setup_token(server);
        self.setup(&token).assert_code(0);
        self.login().assert_code(0);
    }

    /// The `cidr` values of `tenko prefix list --json`, sorted.
    #[track_caller]
    pub fn prefix_cidrs(&self) -> Vec<String> {
        let list = self.client(&["prefix", "list", "--json"]);
        list.assert_code(0);
        let mut cidrs: Vec<String> = list.json()["items"]
            .as_array()
            .unwrap_or_else(|| panic!("no item list\n{}", list.diagnostics()))
            .iter()
            .map(|item| item["cidr"].as_str().expect("a cidr").to_owned())
            .collect();
        cidrs.sort();
        cidrs
    }
}

/// The file a `Setup token: in <file>; print it with ...` line of standard output names.
pub fn setup_token_file_in(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("Setup token: in ")?;
    let (file, _) = rest.split_once("; print it with ")?;
    Some(PathBuf::from(file))
}

/// The token in a setup token file: the first line, if the file exists.
pub fn read_setup_token_file(file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines().next().map(|line| line.trim().to_owned())
}

/// The setup token of a running server. The server writes it to `<data_dir>/setup-token`
/// before it is ready and says where on standard output (the harness has no terminal, which
/// is the only place the token itself would be printed): this waits for that line, then
/// reads the file.
#[track_caller]
pub fn wait_for_setup_token(server: &Proc) -> String {
    let line = server
        .wait_stdout_line(Duration::from_secs(30), |line| {
            line.starts_with("Setup token: ")
        })
        .unwrap_or_else(|| panic!("no setup token line was printed\n{}", server.diagnostics()));
    let file = setup_token_file_in(&line)
        .unwrap_or_else(|| panic!("`{line}` does not name the setup token file"));
    let deadline = Instant::now() + Duration::from_secs(30);
    let token = loop {
        if let Some(token) = read_setup_token_file(&file) {
            break token;
        }
        assert!(
            Instant::now() < deadline,
            "{} was not written\n{}",
            file.display(),
            server.diagnostics()
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(is_setup_token(&token), "`{token}` is not a setup token");
    token
}
