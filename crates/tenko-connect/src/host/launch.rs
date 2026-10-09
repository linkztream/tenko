//! Starting a plugin process: the command, its environment, the stdio handshake, the
//! connection to its endpoint and the first ping.
//!
//! The plugin runs with a cleared environment: only an allow-list of variables the
//! platform and language runtimes need ([`ENV_ALLOWLIST`]) passes, plus
//! `TENKO_PLUGIN_NAME` and, when the host has it, `TENKO_PLUGIN_LOG`. Secrets never travel
//! in the environment or on the command line. Standard error and, after the handshake,
//! standard output are forwarded to the host's log line by line, and the last lines are kept
//! for the error message when the plugin dies during its start.

use std::{
    collections::VecDeque,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_core::Coded;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, ChildStdin, Command},
    task::JoinHandle,
};

use super::client::PluginClient;
use crate::{
    ConnectorError, SUPPORTED_PROTOCOLS,
    handshake::{self, HANDSHAKE_FORMAT, HostHello, LineError, PluginHello, TOKEN_BYTES, failure},
    manifest::{Manifest, ManifestError},
    transport::{self, Allocation, random_hex},
};

/// Environment variables that pass to a plugin.
pub const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

/// The log level variable the host passes on to plugins when it is set.
pub const LOG_ENV: &str = "TENKO_PLUGIN_LOG";

/// Longest forwarded log line, in bytes.
const MAX_LOG_LINE: usize = 4096;

/// Lines of standard error kept for start errors.
const TAIL_LINES: usize = 8;

/// What to start.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// The manifest the host expects (from `plugin.json` or the bundled registry). `None`
    /// when the conformance suite tests an executable without a manifest file: the
    /// manifest of the handshake is then only validated.
    pub expected: Option<Manifest>,
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// The working directory; the host's when `None`.
    pub cwd: Option<PathBuf>,
    /// Variables added to the environment on top of the allow-list (tests).
    pub env: Vec<(OsString, OsString)>,
}

impl LaunchSpec {
    /// A plugin bundled in a host executable: `<exe> plugin run <name>`.
    pub fn bundled(manifest: Manifest, exe: PathBuf) -> Self {
        let name = manifest.name.clone();
        Self {
            expected: Some(manifest),
            program: exe,
            args: vec!["plugin".into(), "run".into(), name.into()],
            cwd: None,
            env: Vec::new(),
        }
    }

    /// A plugin installed in `dir`, started as its manifest's `entry` says.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] when the manifest is not valid for an installed plugin.
    pub fn installed(manifest: Manifest, dir: &Path) -> Result<Self, ManifestError> {
        manifest.validate_installed(dir)?;
        let entry = manifest
            .entry
            .clone()
            .ok_or_else(|| ManifestError::single("/entry", "an installed plugin needs an entry"))?;
        let (program, mut args): (PathBuf, Vec<OsString>) =
            match (&entry.executable, &entry.interpreter, &entry.script) {
                (Some(executable), _, _) => (dir.join(executable), Vec::new()),
                (None, Some(interpreter), Some(script)) => {
                    (PathBuf::from(interpreter), vec![dir.join(script).into()])
                }
                _ => {
                    return Err(ManifestError::single(
                        "/entry",
                        "the entry names neither an executable nor an interpreter with a script",
                    ));
                }
            };
        args.extend(entry.args.iter().map(OsString::from));
        Ok(Self {
            expected: Some(manifest),
            program,
            args,
            cwd: Some(dir.to_path_buf()),
            env: Vec::new(),
        })
    }

    /// An executable without a known manifest (the conformance suite).
    pub fn executable(program: PathBuf, args: Vec<OsString>) -> Self {
        Self {
            expected: None,
            program,
            args,
            cwd: None,
            env: Vec::new(),
        }
    }

    /// The expected plugin name, or the program's file name.
    pub fn label(&self) -> String {
        self.expected.as_ref().map_or_else(
            || {
                self.program.file_stem().map_or_else(
                    || "plugin".to_owned(),
                    |stem| stem.to_string_lossy().into_owned(),
                )
            },
            |manifest| manifest.name.clone(),
        )
    }
}

/// How to start.
#[derive(Debug, Clone)]
pub struct LaunchOptions {
    /// Where Unix sockets live; the system temporary directory when `None`.
    pub runtime_dir: Option<PathBuf>,
    /// How long the plugin may take to answer the handshake.
    pub handshake_timeout: Duration,
    /// How long connecting to the endpoint and the first ping may take.
    pub connect_timeout: Duration,
    /// The protocol versions offered (the conformance suite offers others).
    pub protocols: Vec<u32>,
    /// The host version told to the plugin.
    pub host_version: String,
    /// The label of the plugin's log lines, for example the instance id.
    pub log_label: Option<String>,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            runtime_dir: None,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            protocols: SUPPORTED_PROTOCOLS.to_vec(),
            host_version: crate::version().to_owned(),
            log_label: None,
        }
    }
}

/// A plugin that could not be started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchError {
    /// The endpoint could not be allocated.
    #[error("no endpoint for the plugin: {0}")]
    Endpoint(String),
    /// The process could not be started.
    #[error("cannot start {program}: {message}")]
    Spawn {
        /// The program.
        program: String,
        /// The operating system's error.
        message: String,
    },
    /// The plugin did not answer the handshake in time.
    #[error("the plugin did not answer the handshake within {0:?}")]
    HandshakeTimeout(Duration),
    /// The plugin answered something that is not a handshake.
    #[error("the plugin's handshake is not valid: {0}")]
    HandshakeInvalid(String),
    /// The plugin exited before or during the handshake.
    #[error("the plugin exited during its start ({status}){}", tail(.stderr))]
    Exited {
        /// The exit status.
        status: String,
        /// The last lines of its standard error.
        stderr: Vec<String>,
    },
    /// The plugin and the host speak no common protocol version.
    #[error("no common protocol version: the host speaks {host:?}, the plugin speaks {plugin:?}")]
    ProtocolMismatch {
        /// The versions the host offered.
        host: Vec<u32>,
        /// The versions the plugin speaks.
        plugin: Vec<u32>,
    },
    /// The plugin refused the handshake for another reason.
    #[error("the plugin refused the handshake ({code}): {message}")]
    Refused {
        /// The plugin's failure code.
        code: String,
        /// The plugin's detail.
        message: String,
    },
    /// The plugin's manifest is not valid.
    #[error(transparent)]
    Manifest(ManifestError),
    /// The plugin's manifest differs from the expected one.
    #[error("the plugin's manifest differs from the installed one: {0}")]
    ManifestMismatch(String),
    /// The endpoint did not answer.
    #[error("cannot reach the plugin on its endpoint: {0}")]
    Connect(String),
}

fn tail(lines: &[String]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("; standard error ended with: {}", lines.join(" | "))
    }
}

impl LaunchError {
    /// Whether restarting cannot help: the manifest or the protocol does not fit, which
    /// only a new plugin version or a configuration change fixes.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            LaunchError::ProtocolMismatch { .. }
                | LaunchError::Manifest(_)
                | LaunchError::ManifestMismatch(_)
                | LaunchError::Refused { .. }
        )
    }
}

impl Coded for LaunchError {
    fn code(&self) -> &'static str {
        match self {
            LaunchError::Endpoint(_) => "connect.plugin.endpoint",
            LaunchError::Spawn { .. } => "connect.plugin.spawn_failed",
            LaunchError::HandshakeTimeout(_) => "connect.plugin.handshake_timeout",
            LaunchError::HandshakeInvalid(_) => "connect.plugin.handshake_invalid",
            LaunchError::Exited { .. } => "connect.plugin.exited",
            LaunchError::ProtocolMismatch { .. } => "connect.plugin.protocol_mismatch",
            LaunchError::Refused { .. } => "connect.plugin.refused",
            LaunchError::Manifest(error) => error.code(),
            LaunchError::ManifestMismatch(_) => "connect.plugin.manifest_mismatch",
            LaunchError::Connect(_) => "connect.plugin.connect_failed",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            LaunchError::ProtocolMismatch { .. }
            | LaunchError::Manifest(_)
            | LaunchError::ManifestMismatch(_) => 422,
            _ => 503,
        }
    }

    fn params(&self) -> std::collections::BTreeMap<&'static str, String> {
        match self {
            LaunchError::ProtocolMismatch { host, plugin } => std::collections::BTreeMap::from([
                ("host", format!("{host:?}")),
                ("plugin", format!("{plugin:?}")),
            ]),
            _ => std::collections::BTreeMap::new(),
        }
    }

    fn title(&self) -> &'static str {
        "Connector plugin did not start"
    }
}

impl From<LaunchError> for ConnectorError {
    fn from(error: LaunchError) -> Self {
        ConnectorError::PluginUnavailable(error.to_string())
    }
}

/// A started plugin. Dropping it kills the process (and closes its standard input, which
/// makes a well-behaved plugin exit by itself).
#[derive(Debug)]
pub struct Launched {
    /// The process.
    pub child: Child,
    /// Its standard input, kept open while it runs.
    pub stdin: Option<ChildStdin>,
    /// The connection.
    pub client: PluginClient,
    /// The manifest from the handshake.
    pub manifest: Manifest,
    /// The protocol version in use.
    pub protocol: u32,
    /// The endpoint (its private directory is removed with this value).
    pub allocation: Allocation,
    /// Forwarders of standard output and standard error.
    pub log_tasks: Vec<JoinHandle<()>>,
}

impl Launched {
    /// The process id, while it runs.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Stops the plugin: asks it to shut down, closes its standard input, waits up to
    /// `grace` for it to exit, then kills it. Returns how it ended.
    pub async fn stop(mut self, grace: Duration) -> String {
        let asked = self
            .client
            .shutdown(grace.min(Duration::from_secs(2)))
            .await;
        if let Err(error) = asked {
            tracing::debug!(%error, "the plugin did not acknowledge the shutdown");
        }
        drop(self.stdin.take());
        let ended = match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(Ok(status)) => format!("exited ({status})"),
            Ok(Err(error)) => format!("wait failed: {error}"),
            Err(_) => {
                let _ = self.child.kill().await;
                "killed after the grace period".to_owned()
            }
        };
        for task in self.log_tasks.drain(..) {
            task.abort();
        }
        ended
    }
}

/// The last lines of a plugin's standard error.
type Tail = Arc<Mutex<VecDeque<String>>>;

/// Starts a plugin: spawn, handshake, connect, ping.
///
/// # Errors
///
/// [`LaunchError`] naming the stage that failed.
#[allow(
    clippy::too_many_lines,
    reason = "the start reads best as one sequence of its stages"
)]
pub async fn launch(spec: &LaunchSpec, options: &LaunchOptions) -> Result<Launched, LaunchError> {
    let allocation = Allocation::new(options.runtime_dir.as_deref())
        .map_err(|error| LaunchError::Endpoint(error.to_string()))?;
    let token =
        random_hex(TOKEN_BYTES).map_err(|error| LaunchError::Endpoint(error.to_string()))?;
    let label = options.log_label.clone().unwrap_or_else(|| spec.label());

    let mut child = command(spec).spawn().map_err(|error| LaunchError::Spawn {
        program: spec.program.display().to_string(),
        message: error.to_string(),
    })?;
    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let tail: Tail = Arc::new(Mutex::new(VecDeque::new()));
    let mut log_tasks = Vec::new();
    if let Some(stderr) = stderr {
        log_tasks.push(forward(stderr, label.clone(), Some(Arc::clone(&tail))));
    }

    let hello = HostHello {
        tenko_plugin: HANDSHAKE_FORMAT,
        protocol: options.protocols.clone(),
        endpoint: allocation.endpoint().clone(),
        token: token.clone(),
        plugin: spec
            .expected
            .as_ref()
            .map(|manifest| manifest.name.clone())
            .unwrap_or_default(),
        host_version: options.host_version.clone(),
    };
    let Some(input) = stdin.as_mut() else {
        return Err(LaunchError::Spawn {
            program: spec.program.display().to_string(),
            message: "no standard input".to_owned(),
        });
    };
    if let Err(error) = handshake::write_line(input, &hello).await {
        return Err(exited(&mut child, &tail, &error.to_string()).await);
    }
    let Some(stdout) = stdout else {
        return Err(LaunchError::Spawn {
            program: spec.program.display().to_string(),
            message: "no standard output".to_owned(),
        });
    };
    let mut reader = BufReader::new(stdout);
    let answer = tokio::time::timeout(
        options.handshake_timeout,
        handshake::read_line::<PluginHello, _>(&mut reader, |line| {
            tracing::info!(target: "tenko::plugin", plugin = %label, "{}", clip(line));
        }),
    )
    .await;
    let answer = match answer {
        Err(_) => {
            let _ = child.kill().await;
            return Err(LaunchError::HandshakeTimeout(options.handshake_timeout));
        }
        Ok(Err(LineError::Closed | LineError::Io(_))) => {
            return Err(exited(&mut child, &tail, "standard output closed").await);
        }
        Ok(Err(error)) => {
            let _ = child.kill().await;
            return Err(LaunchError::HandshakeInvalid(error.to_string()));
        }
        Ok(Ok(answer)) => answer,
    };
    let (protocol, manifest) = match check_answer(spec, options, answer) {
        Ok(accepted) => accepted,
        Err(error) => {
            // A refusing plugin exits by itself; give it a moment, then make sure.
            let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
            let _ = child.kill().await;
            return Err(error);
        }
    };
    log_tasks.push(forward(reader, label.clone(), None));

    let client = match connect(&allocation, &token, &manifest, options).await {
        Ok(client) => client,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error);
        }
    };
    tracing::info!(
        target: "tenko::plugin",
        plugin = %label,
        version = %manifest.version,
        protocol,
        pid = child.id(),
        "plugin started"
    );
    Ok(Launched {
        child,
        stdin,
        client,
        manifest,
        protocol,
        allocation,
        log_tasks,
    })
}

/// The command of a spec, with the cleared environment and piped standard streams.
fn command(spec: &LaunchSpec) -> Command {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for name in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(level) = std::env::var_os(LOG_ENV) {
        command.env(LOG_ENV, level);
    }
    command.env("TENKO_PLUGIN_NAME", spec.label());
    for (name, value) in &spec.env {
        command.env(name, value);
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: a plugin of a service never opens a console window.
        command.creation_flags(0x0800_0000);
    }
    command
}

/// Checks the plugin's answer: the format, a refusal, the protocol version and the
/// manifest.
fn check_answer(
    spec: &LaunchSpec,
    options: &LaunchOptions,
    answer: PluginHello,
) -> Result<(u32, Manifest), LaunchError> {
    if answer.tenko_plugin != HANDSHAKE_FORMAT {
        return Err(LaunchError::HandshakeInvalid(format!(
            "handshake format {} is not {HANDSHAKE_FORMAT}",
            answer.tenko_plugin
        )));
    }
    if let Some(error) = answer.error {
        if error.code == failure::PROTOCOL_MISMATCH {
            return Err(LaunchError::ProtocolMismatch {
                host: options.protocols.clone(),
                plugin: error.supported,
            });
        }
        return Err(LaunchError::Refused {
            code: error.code.chars().take(64).collect(),
            message: clip(&error.message),
        });
    }
    let (Some(protocol), Some(manifest)) = (answer.protocol, answer.manifest) else {
        return Err(LaunchError::HandshakeInvalid(
            "the answer carries neither a protocol version and a manifest nor an error".to_owned(),
        ));
    };
    manifest.validate().map_err(LaunchError::Manifest)?;
    if !options.protocols.contains(&protocol) || !manifest.protocol.contains(&protocol) {
        return Err(LaunchError::ProtocolMismatch {
            host: options.protocols.clone(),
            plugin: manifest.protocol.clone(),
        });
    }
    if let Some(expected) = &spec.expected {
        compare(expected, &manifest)?;
    }
    Ok((protocol, manifest))
}

/// The members of the plugin's manifest that must equal the expected one.
fn compare(expected: &Manifest, actual: &Manifest) -> Result<(), LaunchError> {
    let mut differences = Vec::new();
    if expected.name != actual.name {
        differences.push(format!(
            "name `{}` instead of `{}`",
            actual.name, expected.name
        ));
    }
    if expected.version != actual.version {
        differences.push(format!(
            "version `{}` instead of `{}`",
            actual.version, expected.version
        ));
    }
    let mut want = expected.capabilities.clone();
    let mut have = actual.capabilities.clone();
    want.sort();
    have.sort();
    if want != have {
        differences.push(format!("capabilities {have:?} instead of {want:?}"));
    }
    let purposes = |manifest: &Manifest| {
        let mut purposes: Vec<String> = manifest
            .secrets
            .iter()
            .map(|decl| decl.purpose.clone())
            .collect();
        purposes.sort();
        purposes
    };
    if purposes(expected) != purposes(actual) {
        differences.push("the declared secret purposes differ".to_owned());
    }
    if expected.settings != actual.settings {
        differences.push("the settings schema differs".to_owned());
    }
    if differences.is_empty() {
        Ok(())
    } else {
        Err(LaunchError::ManifestMismatch(differences.join("; ")))
    }
}

/// Connects to the endpoint and pings with the token; the ping must name the plugin.
async fn connect(
    allocation: &Allocation,
    token: &str,
    manifest: &Manifest,
    options: &LaunchOptions,
) -> Result<PluginClient, LaunchError> {
    let channel = transport::channel(allocation.endpoint(), options.connect_timeout)
        .await
        .map_err(|error| LaunchError::Connect(format!("{error:?}")))?;
    let client = PluginClient::new(channel, token)
        .map_err(|error| LaunchError::Connect(error.to_string()))?;
    let pong = client
        .ping(options.connect_timeout)
        .await
        .map_err(|error| LaunchError::Connect(format!("the first ping failed: {error}")))?;
    if pong.name != manifest.name || pong.version != manifest.version {
        return Err(LaunchError::ManifestMismatch(format!(
            "the ping names `{} {}`, the handshake `{} {}`",
            pong.name, pong.version, manifest.name, manifest.version
        )));
    }
    Ok(client)
}

/// The error of a plugin that exited during its start, with its status and last lines.
async fn exited(child: &mut Child, tail: &Tail, fallback: &str) -> LaunchError {
    let status = match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
        Ok(Ok(status)) => status.to_string(),
        Ok(Err(error)) => format!("{fallback}; {error}"),
        Err(_) => {
            let _ = child.kill().await;
            format!("{fallback}; killed")
        }
    };
    // Let the forwarder take the last lines.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stderr = tail
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .cloned()
        .collect();
    LaunchError::Exited { status, stderr }
}

/// Forwards the lines of a stream to the log. A line may start with a level word (`ERROR`,
/// `WARN`, `INFO`, `DEBUG`, `TRACE`); without one it is logged at info level.
fn forward<R>(stream: R, label: String, tail: Option<Tail>) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = clip(&line);
            if line.trim().is_empty() {
                continue;
            }
            if let Some(tail) = &tail {
                let mut tail = tail.lock().unwrap_or_else(PoisonError::into_inner);
                if tail.len() == TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
            }
            log_line(&label, &line);
        }
    })
}

fn log_line(label: &str, line: &str) {
    let (level, rest) = line.split_once(' ').unwrap_or((line, ""));
    match level {
        "ERROR" => tracing::error!(target: "tenko::plugin", plugin = %label, "{rest}"),
        "WARN" => tracing::warn!(target: "tenko::plugin", plugin = %label, "{rest}"),
        "DEBUG" => tracing::debug!(target: "tenko::plugin", plugin = %label, "{rest}"),
        "TRACE" => tracing::trace!(target: "tenko::plugin", plugin = %label, "{rest}"),
        "INFO" => tracing::info!(target: "tenko::plugin", plugin = %label, "{rest}"),
        _ => tracing::info!(target: "tenko::plugin", plugin = %label, "{line}"),
    }
}

fn clip(line: &str) -> String {
    if line.len() <= MAX_LOG_LINE {
        return line.to_owned();
    }
    let mut end = MAX_LOG_LINE;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &line[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample;

    #[test]
    fn manifests_are_compared_member_by_member() {
        let expected = sample::manifest();
        assert!(compare(&expected, &expected).is_ok());
        let mut other = expected.clone();
        "9.9.9".clone_into(&mut other.version);
        other.secrets.clear();
        let Err(LaunchError::ManifestMismatch(detail)) = compare(&expected, &other) else {
            panic!("expected a mismatch");
        };
        assert!(detail.contains("version `9.9.9`"), "{detail}");
        assert!(detail.contains("secret purposes"), "{detail}");
    }

    #[test]
    fn refusals_and_mismatches_are_read() {
        let spec = LaunchSpec::executable(PathBuf::from("x"), Vec::new());
        let options = LaunchOptions::default();
        let refused = PluginHello::failed(failure::PROTOCOL_MISMATCH, "no", vec![2]);
        assert_eq!(
            check_answer(&spec, &options, refused),
            Err(LaunchError::ProtocolMismatch {
                host: vec![1],
                plugin: vec![2]
            })
        );
        let ready = PluginHello::ready(1, sample::manifest());
        assert!(check_answer(&spec, &options, ready).is_ok());
        let wrong = PluginHello::ready(3, sample::manifest());
        assert!(matches!(
            check_answer(&spec, &options, wrong),
            Err(LaunchError::ProtocolMismatch { .. })
        ));
        let empty = PluginHello {
            tenko_plugin: 1,
            protocol: None,
            manifest: None,
            error: None,
        };
        assert!(matches!(
            check_answer(&spec, &options, empty),
            Err(LaunchError::HandshakeInvalid(_))
        ));
    }

    #[test]
    fn errors_are_coded_and_classified() {
        let mismatch = LaunchError::ProtocolMismatch {
            host: vec![1],
            plugin: vec![2],
        };
        assert_eq!(mismatch.code(), "connect.plugin.protocol_mismatch");
        assert!(mismatch.is_permanent());
        assert!(!LaunchError::HandshakeTimeout(Duration::from_secs(1)).is_permanent());
        let exited = LaunchError::Exited {
            status: "exit code: 3".to_owned(),
            stderr: vec!["ERROR boom".to_owned()],
        };
        assert!(exited.to_string().contains("ERROR boom"));
        assert!(tenko_core::names::is_valid_name(exited.code()));
    }
}
