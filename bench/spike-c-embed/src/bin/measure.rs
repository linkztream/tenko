//! Measurement tool for the embedded-SPA + SSE spike.
//!
//! Subcommands: `cold-start`, `idle-rss`, `sse-rss`, `fanout`, `http-load`, `bundle`,
//! `binsize`. Every subcommand prints a human readable summary and, as the last stdout line,
//! `RESULT <single-line JSON>`.
//!
//! The tool spawns the server under test (or attaches to a running one), drives it with a
//! hyper HTTP/1.1 client on a multi-thread tokio runtime and samples the server process through
//! sysinfo (working set, private bytes, accumulated CPU time).
//!
//! Examples (server options are shared by every subcommand that talks to a server):
//!
//! ```text
//! measure cold-start --server spike-c-embed.exe --runs 10 --warmup 1
//! measure idle-rss   --server spike-c-embed.exe --wait-secs 10
//! measure sse-rss    --server spike-c-embed.exe --clients 100,1000,5000 --path /api/events
//! measure fanout     --server spike-c-embed.exe --clients 1000 --rate 100 --duration-secs 10
//! measure http-load  --server spike-c-embed.exe --path / --connections 64 --accept-encoding br
//! measure bundle     --dir ../../ui/dist
//! measure binsize    target/release/spike-c-embed.exe
//! measure idle-rss   --addr 127.0.0.1:8080 --pid 1234      (attach to a running server)
//! measure idle-rss   --server x.exe --server-arg=--workers --server-arg=4
//! ```
//!
//! Limits worth knowing: process CPU time comes from the OS per-process counters, which on
//! Windows advance in scheduler ticks of about 15.6 ms, so CPU deltas over short windows are
//! coarse. Under Git Bash set `MSYS_NO_PATHCONV=1`, otherwise arguments such as `--path /` are
//! rewritten into Windows paths.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use hdrhistogram::Histogram;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, sleep, timeout};

type Res<T> = Result<T, String>;

/// Upper bound for the server to answer its first health request after spawn or attach.
const HEALTH_LIMIT: Duration = Duration::from_secs(30);
/// A failed client connect is retried this many times (so up to `1 + CONNECT_RETRIES` attempts).
const CONNECT_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(20);
const KIB: f64 = 1024.0;
const MIB: f64 = 1024.0 * 1024.0;

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

fn chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

fn ctx<E: std::error::Error + 'static>(what: &'static str) -> impl FnOnce(E) -> String {
    move |e| format!("{what}: {}", chain(&e))
}

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

fn ns_since(base: Instant, at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(base).as_nanos()).unwrap_or(u64::MAX)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn r2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn secs(x: f64) -> Duration {
    Duration::from_secs_f64(x.max(0.0))
}

/// Median, minimum and maximum of a non-empty slice.
fn stats3(values: &[f64]) -> Option<(f64, f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        f64::midpoint(v[n / 2 - 1], v[n / 2])
    };
    Some((median, v[0], v[n - 1]))
}

fn stats_json(values: &[f64]) -> Value {
    match stats3(values) {
        Some((median, min, max)) => json!({
            "median_ms": r2(median),
            "min_ms": r2(min),
            "max_ms": r2(max),
            "runs_ms": values.iter().map(|x| r2(*x)).collect::<Vec<_>>(),
        }),
        None => Value::Null,
    }
}

fn new_hist() -> Histogram<u64> {
    // Auto-resizing histogram: memory grows with the largest recorded value only.
    Histogram::<u64>::new(3).expect("3 significant digits is a valid histogram precision")
}

fn hist_json(h: &Histogram<u64>) -> Value {
    if h.is_empty() {
        return Value::Null;
    }
    json!({
        "count": h.len(),
        "min_us": h.min(),
        "mean_us": r2(h.mean()),
        "p50_us": h.value_at_quantile(0.50),
        "p90_us": h.value_at_quantile(0.90),
        "p99_us": h.value_at_quantile(0.99),
        "p99_9_us": h.value_at_quantile(0.999),
        "max_us": h.max(),
    })
}

fn print_hist(label: &str, h: &Histogram<u64>) {
    if h.is_empty() {
        println!("{label}: no samples");
        return;
    }
    println!(
        "{label}: n={} min={} p50={} p90={} p99={} p99.9={} max={} mean={:.1} (us)",
        h.len(),
        h.min(),
        h.value_at_quantile(0.50),
        h.value_at_quantile(0.90),
        h.value_at_quantile(0.99),
        h.value_at_quantile(0.999),
        h.max(),
        h.mean()
    );
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Child process handling
// ---------------------------------------------------------------------------------------------

/// Children are kept in a global registry so that the panic hook (the release profile aborts on
/// panic, which skips destructors) and the Ctrl-C handler can still kill them.
static CHILDREN: Mutex<Vec<Child>> = Mutex::new(Vec::new());

fn kill_all_children() {
    if let Ok(mut g) = CHILDREN.try_lock() {
        for c in g.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        g.clear();
    }
}

fn install_panic_cleanup() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        kill_all_children();
        prev(info);
    }));
}

/// A spawned server process. Dropping it kills the process and waits for it.
struct ServerProc {
    pid: u32,
    /// Taken immediately before `Command::spawn`.
    spawned_at: Instant,
    /// Time and text of the first stdout line starting with `listening on `.
    listening: Arc<Mutex<Option<(Instant, String)>>>,
}

impl ServerProc {
    fn spawn(exe: &Path, port: u16, extra: &[String], inherit_stderr: bool) -> Res<Self> {
        let mut cmd = Command::new(exe);
        cmd.arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(if inherit_stderr {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        let spawned_at = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot spawn {}: {e}", exe.display()))?;
        let pid = child.id();
        let stdout = child.stdout.take();
        lock(&CHILDREN).push(child);

        let listening: Arc<Mutex<Option<(Instant, String)>>> = Arc::new(Mutex::new(None));
        if let Some(stdout) = stdout {
            let slot = Arc::clone(&listening);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = Vec::new();
                loop {
                    line.clear();
                    match reader.read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if line.starts_with(b"listening on ") {
                                let mut g = lock(&slot);
                                if g.is_none() {
                                    let text = String::from_utf8_lossy(&line).trim_end().to_owned();
                                    *g = Some((Instant::now(), text));
                                }
                            }
                        }
                    }
                }
            });
        }
        Ok(Self {
            pid,
            spawned_at,
            listening,
        })
    }

    /// Exit status if the process has already exited.
    fn exit_status(&self) -> Option<ExitStatus> {
        let mut g = lock(&CHILDREN);
        let child = g.iter_mut().find(|c| c.id() == self.pid)?;
        child.try_wait().ok().flatten()
    }

    fn listening_at(&self) -> Option<Instant> {
        lock(&self.listening).as_ref().map(|(t, _)| *t)
    }

    fn kill(&mut self) {
        let child = {
            let mut g = lock(&CHILDREN);
            g.iter()
                .position(|c| c.id() == self.pid)
                .map(|i| g.remove(i))
        };
        if let Some(mut c) = child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---------------------------------------------------------------------------------------------
// Process sampling (memory and CPU of the server, and of this tool)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct ProcSample {
    working_set: u64,
    private_bytes: u64,
    cpu_ms: u64,
}

struct ProcSampler {
    sys: System,
    pid: Pid,
}

impl ProcSampler {
    fn new(pid: u32) -> Self {
        Self {
            sys: System::new(),
            pid: Pid::from_u32(pid),
        }
    }

    fn sample(&mut self) -> Option<ProcSample> {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_memory().with_cpu(),
        );
        let p = self.sys.process(self.pid)?;
        Some(ProcSample {
            working_set: p.memory(),
            private_bytes: p.virtual_memory(),
            cpu_ms: p.accumulated_cpu_time(),
        })
    }
}

fn sample_json(s: Option<ProcSample>) -> Value {
    match s {
        Some(s) => json!({
            "working_set_bytes": s.working_set,
            "private_bytes": s.private_bytes,
            "cpu_ms": s.cpu_ms,
        }),
        None => Value::Null,
    }
}

fn fmt_sample(s: Option<ProcSample>) -> String {
    match s {
        Some(s) => format!(
            "working set {:.2} MiB ({} B), private {:.2} MiB ({} B), cpu {} ms",
            s.working_set as f64 / MIB,
            s.working_set,
            s.private_bytes as f64 / MIB,
            s.private_bytes,
            s.cpu_ms
        ),
        None => "not measured (server pid unknown)".to_owned(),
    }
}

fn cpu_delta(a: Option<ProcSample>, b: Option<ProcSample>) -> Option<u64> {
    Some(b?.cpu_ms.saturating_sub(a?.cpu_ms))
}

fn opt_f64(x: Option<f64>) -> Value {
    x.map_or(Value::Null, |v| json!(r2(v)))
}

/// Bytes per connected client in KiB (signed), or `None` if there is nothing to divide by.
fn per_client_kib(now: u64, base: u64, clients: u64) -> Option<f64> {
    (clients > 0).then(|| (now as f64 - base as f64) / clients as f64 / KIB)
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "measure",
    version,
    about = "Measurement tool for the embedded SPA and SSE server spike"
)]
struct Cli {
    /// Worker threads of the client runtime (default: number of logical cores).
    #[arg(long, global = true)]
    threads: Option<usize>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Spawn the server repeatedly and time start-up milestones.
    ColdStart(ColdStartArgs),
    /// Memory (working set, private bytes) and CPU of the idle server.
    IdleRss(IdleRssArgs),
    /// Memory with N idle SSE clients attached, and time to deliver one event to all of them.
    SseRss(SseRssArgs),
    /// Event fan-out to many SSE clients at a fixed emit rate: CPU and delivery latency.
    Fanout(FanoutArgs),
    /// Keep-alive HTTP GET load against one path: throughput, latency, CPU.
    HttpLoad(HttpLoadArgs),
    /// Raw, gzip and brotli sizes of every file below a directory.
    Bundle(BundleArgs),
    /// Print file sizes (bytes and KiB).
    Binsize(BinsizeArgs),
}

#[derive(Args, Debug, Clone)]
struct ServerOpts {
    /// Path to the server executable (required unless --addr is given).
    #[arg(long)]
    server: Option<PathBuf>,
    /// TCP port the spawned server listens on (127.0.0.1:<port>).
    #[arg(long, default_value_t = 18080)]
    port: u16,
    /// Extra server argument, repeatable (e.g. --server-arg=--workers --server-arg=4).
    #[arg(long = "server-arg", value_name = "ARG", allow_hyphen_values = true)]
    server_arg: Vec<String>,
    /// Attach to an already running server instead of spawning one.
    #[arg(long, value_name = "IP:PORT")]
    addr: Option<SocketAddr>,
    /// Process id of the attached server (needed for memory and CPU numbers).
    #[arg(long)]
    pid: Option<u32>,
    /// Let the spawned server write to this tool's stderr (default: discarded).
    #[arg(long)]
    server_stderr: bool,
}

#[derive(Args, Debug)]
struct ColdStartArgs {
    #[command(flatten)]
    srv: ServerOpts,
    /// Measured runs.
    #[arg(long, default_value_t = 10)]
    runs: u32,
    /// Additional runs performed first and discarded.
    #[arg(long, default_value_t = 1)]
    warmup: u32,
    /// Accept-Encoding header for the `GET /` request (default: none).
    #[arg(long)]
    accept_encoding: Option<String>,
}

#[derive(Args, Debug)]
struct IdleRssArgs {
    #[command(flatten)]
    srv: ServerOpts,
    /// Seconds to wait with zero clients before the second sample.
    #[arg(long, default_value_t = 10.0)]
    wait_secs: f64,
}

#[derive(Args, Debug)]
struct SseRssArgs {
    #[command(flatten)]
    srv: ServerOpts,
    /// Comma separated client counts, measured in order.
    #[arg(long, value_delimiter = ',', default_value = "100,1000,5000")]
    clients: Vec<usize>,
    /// SSE endpoint path.
    #[arg(long, default_value = "/api/events")]
    path: String,
    /// Seconds to wait before each sample.
    #[arg(long, default_value_t = 3.0)]
    settle_secs: f64,
    /// Maximum concurrent connection attempts.
    #[arg(long, default_value_t = 256)]
    connect_concurrency: usize,
    /// Seconds to wait for all clients to connect.
    #[arg(long, default_value_t = 30.0)]
    connect_timeout_secs: f64,
    /// Seconds to wait for the probe event to reach all clients.
    #[arg(long, default_value_t = 10.0)]
    probe_timeout_secs: f64,
    /// Emit endpoint path.
    #[arg(long, default_value = "/api/events/emit")]
    emit_path: String,
}

#[derive(Args, Debug)]
struct FanoutArgs {
    #[command(flatten)]
    srv: ServerOpts,
    /// Number of SSE clients.
    #[arg(long, default_value_t = 1000)]
    clients: usize,
    /// Events emitted per second.
    #[arg(long, default_value_t = 100)]
    rate: u64,
    /// Seconds of emitting (total emits = rate x duration).
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
    /// SSE endpoint path.
    #[arg(long, default_value = "/api/events")]
    path: String,
    /// Seconds to wait after the clients are connected.
    #[arg(long, default_value_t = 3.0)]
    settle_secs: f64,
    /// Length of the no-emit baseline phase (phase A) in seconds.
    #[arg(long, default_value_t = 5.0)]
    baseline_secs: f64,
    /// Seconds to wait for deliveries after the last emit.
    #[arg(long, default_value_t = 2.0)]
    drain_secs: f64,
    /// Maximum concurrent connection attempts.
    #[arg(long, default_value_t = 256)]
    connect_concurrency: usize,
    /// Seconds to wait for all clients to connect.
    #[arg(long, default_value_t = 30.0)]
    connect_timeout_secs: f64,
    /// Emit endpoint path.
    #[arg(long, default_value = "/api/events/emit")]
    emit_path: String,
}

#[derive(Args, Debug)]
struct HttpLoadArgs {
    #[command(flatten)]
    srv: ServerOpts,
    /// Request path.
    #[arg(long, default_value = "/")]
    path: String,
    /// Keep-alive connections, each driven by its own task.
    #[arg(long, default_value_t = 64)]
    connections: usize,
    /// Measured window in seconds.
    #[arg(long, default_value_t = 10.0)]
    duration_secs: f64,
    /// Accept-Encoding header value (default: none).
    #[arg(long)]
    accept_encoding: Option<String>,
    /// Warm-up seconds before the measured window.
    #[arg(long, default_value_t = 1.0)]
    warmup_secs: f64,
}

#[derive(Args, Debug)]
struct BundleArgs {
    /// Directory to walk recursively.
    #[arg(long)]
    dir: PathBuf,
}

#[derive(Args, Debug)]
struct BinsizeArgs {
    /// Files to measure.
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------------------------
// HTTP client helpers
// ---------------------------------------------------------------------------------------------

/// One HTTP/1.1 client connection. The connection future runs in its own task, which is aborted
/// (closing the socket) when this value is dropped.
struct HttpConn {
    sender: http1::SendRequest<Full<Bytes>>,
    task: JoinHandle<()>,
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Fetched {
    status: u16,
    body_len: u64,
    encoding: Option<HeaderValue>,
}

impl HttpConn {
    async fn connect(addr: SocketAddr) -> Res<Self> {
        let stream = TcpStream::connect(addr).await.map_err(ctx("connect"))?;
        stream.set_nodelay(true).map_err(ctx("set_nodelay"))?;
        let (sender, conn) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(ctx("handshake"))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Self { sender, task })
    }

    async fn ready(&mut self) -> Res<()> {
        self.sender
            .ready()
            .await
            .map_err(ctx("connection not ready"))
    }

    /// Sends one request and reads the whole response body.
    async fn fetch(&mut self, req: Request<Full<Bytes>>) -> Res<Fetched> {
        let resp = self
            .sender
            .send_request(req)
            .await
            .map_err(ctx("request"))?;
        let status = resp.status().as_u16();
        let encoding = resp.headers().get(CONTENT_ENCODING).cloned();
        let mut body = resp.into_body();
        let mut body_len = 0u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(ctx("body"))?;
            if let Some(d) = frame.data_ref() {
                body_len += d.len() as u64;
            }
        }
        Ok(Fetched {
            status,
            body_len,
            encoding,
        })
    }
}

/// Request paths must be origin-form. Git Bash rewrites command-line arguments that start with
/// a slash into Windows paths, which would silently turn `/api/events` into a file path.
fn check_path(path: &str) -> Res<()> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(format!(
            "request path {path:?} must start with '/' (Git Bash rewrites arguments starting with '/', set MSYS_NO_PATHCONV=1)"
        ))
    }
}

fn get_request(
    path: &str,
    accept_encoding: Option<&str>,
    accept: Option<&str>,
) -> Res<Request<Full<Bytes>>> {
    check_path(path)?;
    let mut b = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, "127.0.0.1");
    if let Some(v) = accept_encoding {
        b = b.header(ACCEPT_ENCODING, v);
    }
    if let Some(v) = accept {
        b = b.header(ACCEPT, v);
    }
    b.body(Full::new(Bytes::new()))
        .map_err(ctx("build request"))
}

fn post_json_request(path: &str, body: String) -> Res<Request<Full<Bytes>>> {
    check_path(path)?;
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(HOST, "127.0.0.1")
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(ctx("build request"))
}

/// POSTs to the emit endpoint and returns status and response body.
async fn post_emit(conn: &mut HttpConn, path: &str, body: String) -> Res<(u16, Bytes)> {
    conn.ready().await?;
    let resp = conn
        .sender
        .send_request(post_json_request(path, body)?)
        .await
        .map_err(ctx("emit request"))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(ctx("emit body"))?
        .to_bytes();
    Ok((status, bytes))
}

/// Connects with bounded concurrency (the caller's semaphore) and bounded retries.
async fn connect_retry(addr: SocketAddr, sem: &Semaphore) -> Res<HttpConn> {
    let _permit = sem
        .acquire()
        .await
        .map_err(|_| "semaphore closed".to_owned())?;
    let mut last = String::new();
    for attempt in 0..=CONNECT_RETRIES {
        match timeout(Duration::from_secs(10), HttpConn::connect(addr)).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => last = e,
            Err(_) => last = "connect timed out after 10 s".to_owned(),
        }
        if attempt < CONNECT_RETRIES {
            sleep(RETRY_DELAY).await;
        }
    }
    Err(format!("{last} (after {} attempts)", CONNECT_RETRIES + 1))
}

/// True if something accepts connections on `addr` (a refused or silent port times out fast
/// here; on Windows a closed loopback port would otherwise stall for seconds).
async fn port_in_use(addr: SocketAddr) -> bool {
    matches!(
        timeout(Duration::from_millis(100), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

// ---------------------------------------------------------------------------------------------
// Waiting for the server (cold-start polling)
// ---------------------------------------------------------------------------------------------

async fn health_attempt(addr: SocketAddr) -> Res<Instant> {
    let mut conn = HttpConn::connect(addr).await?;
    conn.ready().await?;
    let f = conn.fetch(get_request("/api/health", None, None)?).await?;
    if f.status == 200 {
        Ok(Instant::now())
    } else {
        Err(format!("health returned HTTP {}", f.status))
    }
}

async fn poll_attempt(addr: SocketAddr, done: Arc<AtomicBool>, tx: mpsc::UnboundedSender<Instant>) {
    if let Ok(Ok(t)) = timeout(Duration::from_millis(50), health_attempt(addr)).await
        && done
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        let _ = tx.send(t);
    }
}

/// Waits for the first `GET /api/health` -> 200 and returns the instant it completed.
///
/// A dedicated thread starts one new connect attempt every millisecond (busy-waiting, because
/// the OS timer is far coarser than 1 ms). Every attempt is its own task with a 50 ms timeout, so
/// a connect that stalls on a port without a listener never delays the next attempt. The first
/// attempt that completes wins and all others are aborted.
async fn wait_health(
    addr: SocketAddr,
    server: Option<&ServerProc>,
    limit: Duration,
) -> Res<Instant> {
    let done = Arc::new(AtomicBool::new(false));
    let handles: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, mut rx) = mpsc::unbounded_channel::<Instant>();
    let rt = tokio::runtime::Handle::current();

    let spinner = {
        let done = Arc::clone(&done);
        let handles = Arc::clone(&handles);
        std::thread::spawn(move || {
            let mut next = Instant::now();
            let mut n = 0u64;
            while !done.load(Ordering::Acquire) {
                let h = rt.spawn(poll_attempt(addr, Arc::clone(&done), tx.clone()));
                {
                    let mut g = lock(&handles);
                    g.push(h);
                    n += 1;
                    if n.is_multiple_of(256) {
                        g.retain(|h| !h.is_finished());
                    }
                }
                next += Duration::from_millis(1);
                while Instant::now() < next && !done.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
            }
        })
    };

    let deadline = Instant::now() + limit;
    let result = loop {
        tokio::select! {
            t = rx.recv() => {
                break t.ok_or_else(|| "health polling stopped without a result".to_owned());
            }
            () = sleep(Duration::from_millis(20)) => {
                if let Some(s) = server
                    && let Some(st) = s.exit_status()
                {
                    break Err(format!(
                        "server exited before answering health ({st}); use --server-stderr to see its output"
                    ));
                }
                if Instant::now() >= deadline {
                    break Err(format!("no 200 from /api/health within {limit:?}"));
                }
            }
        }
    };

    done.store(true, Ordering::Release);
    let _ = spinner.join();
    for h in lock(&handles).drain(..) {
        h.abort();
    }
    result
}

// ---------------------------------------------------------------------------------------------
// Target: spawned or attached server plus its process sampler
// ---------------------------------------------------------------------------------------------

struct Target {
    addr: SocketAddr,
    server: Option<ServerProc>,
    pid: Option<u32>,
    sampler: Option<ProcSampler>,
    /// Spawn to first health 200 (spawned servers only).
    spawn_to_health: Option<Duration>,
}

impl Target {
    async fn start(o: &ServerOpts) -> Res<Self> {
        if let Some(addr) = o.addr {
            wait_health(addr, None, HEALTH_LIMIT).await?;
            let mut sampler = o.pid.map(ProcSampler::new);
            if let Some(s) = sampler.as_mut()
                && s.sample().is_none()
            {
                return Err(format!("process {} not found", o.pid.unwrap_or(0)));
            }
            match o.pid {
                Some(pid) => println!("target: attached to {addr}, pid {pid}"),
                None => println!(
                    "target: attached to {addr}, pid unknown (memory and CPU not measured)"
                ),
            }
            return Ok(Self {
                addr,
                server: None,
                pid: o.pid,
                sampler,
                spawn_to_health: None,
            });
        }
        let exe = o
            .server
            .as_ref()
            .ok_or("--server <path> is required unless --addr is given")?;
        let addr = spawn_addr(o);
        if port_in_use(addr).await {
            return Err(format!(
                "{addr} already accepts connections; stop that server or use --port"
            ));
        }
        let server = ServerProc::spawn(exe, o.port, &o.server_arg, o.server_stderr)?;
        let health = wait_health(addr, Some(&server), HEALTH_LIMIT).await?;
        let spawn_to_health = health.duration_since(server.spawned_at);
        let pid = server.pid;
        println!(
            "target: spawned {} pid {pid} on {addr}, spawn -> health {:.2} ms",
            exe.display(),
            ms(spawn_to_health)
        );
        Ok(Self {
            addr,
            pid: Some(pid),
            sampler: Some(ProcSampler::new(pid)),
            server: Some(server),
            spawn_to_health: Some(spawn_to_health),
        })
    }

    fn sample(&mut self) -> Option<ProcSample> {
        self.sampler.as_mut().and_then(ProcSampler::sample)
    }

    fn header_json(&self) -> Value {
        json!({
            "addr": self.addr.to_string(),
            "pid": self.pid,
            "spawned": self.server.is_some(),
        })
    }
}

fn spawn_addr(o: &ServerOpts) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], o.port))
}

// ---------------------------------------------------------------------------------------------
// SSE frame parsing
// ---------------------------------------------------------------------------------------------

/// One SSE frame (the text between two blank lines), borrowing from the parser buffer.
#[derive(Debug, Default, PartialEq, Eq)]
struct Frame<'a> {
    id: Option<&'a [u8]>,
    event: Option<&'a [u8]>,
    /// First `data:` line.
    data: Option<&'a [u8]>,
    data_lines: usize,
    comment_lines: usize,
}

impl Frame<'_> {
    /// A frame is an event if it carries at least one `data:` line.
    fn is_event(&self) -> bool {
        self.data_lines > 0
    }

    fn is_shutdown(&self) -> bool {
        self.event.is_some_and(|e| e == b"shutdown")
    }
}

fn parse_frame(raw: &[u8]) -> Frame<'_> {
    let mut f = Frame::default();
    for line in raw.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line[0] == b':' {
            f.comment_lines += 1;
            continue;
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (line, &line[line.len()..]),
        };
        match name {
            b"data" => {
                f.data_lines += 1;
                if f.data.is_none() {
                    f.data = Some(value);
                }
            }
            b"event" => f.event = Some(value),
            b"id" => f.id = Some(value),
            _ => {}
        }
    }
    f
}

/// Finds the end of the first complete frame: returns (end of frame content, start of the next
/// frame). Accepts `\n\n` and `\r\n\r\n` terminators.
fn find_frame_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        let p = i + buf[i..].iter().position(|&b| b == b'\n')?;
        match buf.get(p + 1) {
            Some(b'\n') => return Some((p, p + 2)),
            Some(b'\r') if buf.get(p + 2) == Some(&b'\n') => return Some((p, p + 3)),
            _ => i = p + 1,
        }
    }
    None
}

/// Accumulates body bytes and hands out complete frames.
#[derive(Default)]
struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    fn push(&mut self, chunk: &[u8], mut on_frame: impl FnMut(&Frame<'_>)) {
        self.buf.extend_from_slice(chunk);
        let mut start = 0;
        while let Some((end, next)) = find_frame_end(&self.buf[start..]) {
            on_frame(&parse_frame(&self.buf[start..start + end]));
            start += next;
        }
        if start > 0 {
            self.buf.drain(..start);
        }
    }
}

/// Extracts the unsigned integer after `"t":` (unix time in microseconds written by the emitter).
fn extract_t(data: &[u8]) -> Option<u64> {
    const KEY: &[u8] = b"\"t\":";
    let pos = data.windows(KEY.len()).position(|w| w == KEY)?;
    let mut i = pos + KEY.len();
    while data.get(i) == Some(&b' ') {
        i += 1;
    }
    let mut value: u64 = 0;
    let mut any = false;
    while let Some(&b) = data.get(i) {
        if !b.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        any = true;
        i += 1;
    }
    any.then_some(value)
}

// ---------------------------------------------------------------------------------------------
// SSE clients
// ---------------------------------------------------------------------------------------------

struct SseShared {
    base: Instant,
    connected: AtomicU64,
    failed: AtomicU64,
    ended_early: AtomicU64,
    /// Event frames (excluding `shutdown`) received by all clients together.
    events: AtomicU64,
    /// Receive time of the latest event, nanoseconds since `base`.
    last_event_ns: AtomicU64,
    first_error: Mutex<Option<String>>,
}

impl SseShared {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            connected: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            ended_early: AtomicU64::new(0),
            events: AtomicU64::new(0),
            last_event_ns: AtomicU64::new(0),
            first_error: Mutex::new(None),
        }
    }

    fn note_error(&self, e: String) {
        let mut g = lock(&self.first_error);
        if g.is_none() {
            *g = Some(e);
        }
    }

    fn first_error(&self) -> Option<String> {
        lock(&self.first_error).clone()
    }
}

struct SseCfg {
    addr: SocketAddr,
    path: String,
    record_latency: bool,
    attempt_timeout: Duration,
}

#[derive(Default)]
struct SseOut {
    events: u64,
    hist: Option<Histogram<u64>>,
    connected: bool,
    shutdown_seen: bool,
    stream_error: Option<String>,
}

async fn wait_stop(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Opens the stream: connect, request, status 200 and the first body data frame.
async fn sse_open(cfg: &SseCfg) -> Res<(HttpConn, Incoming, Bytes)> {
    let mut conn = HttpConn::connect(cfg.addr).await?;
    conn.ready().await?;
    let req = get_request(&cfg.path, None, Some("text/event-stream"))?;
    let resp = conn
        .sender
        .send_request(req)
        .await
        .map_err(ctx("request"))?;
    if resp.status() != StatusCode::OK {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut body = resp.into_body();
    loop {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data()
                    && !d.is_empty()
                {
                    return Ok((conn, body, d));
                }
            }
            Some(Err(e)) => return Err(ctx("first frame")(e)),
            None => return Err("stream ended before the first frame".to_owned()),
        }
    }
}

/// `sse_open` with a per-attempt timeout and bounded retries; holds a concurrency permit.
async fn sse_open_retry(cfg: &SseCfg, sem: &Semaphore) -> Res<(HttpConn, Incoming, Bytes)> {
    let _permit = sem
        .acquire()
        .await
        .map_err(|_| "semaphore closed".to_owned())?;
    let mut last = String::new();
    for attempt in 0..=CONNECT_RETRIES {
        match timeout(cfg.attempt_timeout, sse_open(cfg)).await {
            Ok(Ok(v)) => return Ok(v),
            Ok(Err(e)) => last = e,
            Err(_) => last = format!("timed out after {:?}", cfg.attempt_timeout),
        }
        if attempt < CONNECT_RETRIES {
            sleep(RETRY_DELAY).await;
        }
    }
    Err(format!("{last} (after {} attempts)", CONNECT_RETRIES + 1))
}

struct SseState {
    parser: SseParser,
    hist: Option<Histogram<u64>>,
    events: u64,
    shutdown: bool,
}

impl SseState {
    fn feed(&mut self, chunk: &[u8], shared: &SseShared) {
        let Self {
            parser,
            hist,
            events,
            shutdown,
        } = self;
        parser.push(chunk, |f| {
            if f.is_shutdown() {
                *shutdown = true;
                return;
            }
            if f.is_event() {
                *events += 1;
                shared.events.fetch_add(1, Ordering::Relaxed);
                shared
                    .last_event_ns
                    .fetch_max(ns_since(shared.base, Instant::now()), Ordering::Relaxed);
                if let Some(h) = hist.as_mut()
                    && let Some(t) = f.data.and_then(extract_t)
                {
                    let _ = h.record(unix_micros().saturating_sub(t));
                }
            }
        });
    }
}

async fn sse_client(
    cfg: Arc<SseCfg>,
    shared: Arc<SseShared>,
    sem: Arc<Semaphore>,
    stop: watch::Receiver<bool>,
) -> SseOut {
    let mut out = SseOut::default();
    let stop_fut = wait_stop(stop);
    tokio::pin!(stop_fut);

    let opened = tokio::select! {
        r = sse_open_retry(&cfg, &sem) => r,
        () = &mut stop_fut => return out,
    };
    let (_conn, mut body, first) = match opened {
        Ok(v) => v,
        Err(e) => {
            shared.failed.fetch_add(1, Ordering::Relaxed);
            shared.note_error(e);
            return out;
        }
    };
    shared.connected.fetch_add(1, Ordering::Relaxed);
    out.connected = true;

    let mut st = SseState {
        parser: SseParser::default(),
        hist: cfg.record_latency.then(new_hist),
        events: 0,
        shutdown: false,
    };
    st.feed(&first, &shared);

    let mut stopped = false;
    while !st.shutdown {
        tokio::select! {
            () = &mut stop_fut => { stopped = true; break; }
            f = body.frame() => match f {
                Some(Ok(frame)) => {
                    if let Some(d) = frame.data_ref() {
                        st.feed(d, &shared);
                    }
                }
                Some(Err(e)) => {
                    out.stream_error = Some(ctx("stream")(e));
                    break;
                }
                None => {
                    out.stream_error = Some("stream closed by server".to_owned());
                    break;
                }
            },
        }
    }
    if !stopped {
        shared.ended_early.fetch_add(1, Ordering::Relaxed);
    }
    out.events = st.events;
    out.shutdown_seen = st.shutdown;
    out.hist = st.hist;
    out
}

/// A group of SSE client tasks.
struct SseGroup {
    shared: Arc<SseShared>,
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<SseOut>>,
    requested: usize,
    opened_at: Instant,
}

impl SseGroup {
    fn open(
        n: usize,
        addr: SocketAddr,
        path: &str,
        record_latency: bool,
        concurrency: usize,
        attempt_timeout: Duration,
    ) -> Self {
        let shared = Arc::new(SseShared::new());
        let (stop, stop_rx) = watch::channel(false);
        let sem = Arc::new(Semaphore::new(concurrency.max(1)));
        let cfg = Arc::new(SseCfg {
            addr,
            path: path.to_owned(),
            record_latency,
            attempt_timeout,
        });
        let opened_at = Instant::now();
        let handles = (0..n)
            .map(|_| {
                tokio::spawn(sse_client(
                    Arc::clone(&cfg),
                    Arc::clone(&shared),
                    Arc::clone(&sem),
                    stop_rx.clone(),
                ))
            })
            .collect();
        Self {
            shared,
            stop,
            handles,
            requested: n,
            opened_at,
        }
    }

    /// Waits until every client is connected or failed, or `limit` has passed.
    /// Returns (connected, failed, time waited).
    async fn wait_ready(&self, limit: Duration) -> (u64, u64, Duration) {
        let n = self.requested as u64;
        let start = Instant::now();
        loop {
            let c = self.shared.connected.load(Ordering::Relaxed);
            let f = self.shared.failed.load(Ordering::Relaxed);
            if c + f >= n || start.elapsed() >= limit {
                return (c, f, self.opened_at.elapsed());
            }
            sleep(Duration::from_millis(5)).await;
        }
    }

    /// Stops all clients (closing their connections) and collects their results.
    async fn close(mut self, limit: Duration) -> Vec<SseOut> {
        let _ = self.stop.send(true);
        let handles = std::mem::take(&mut self.handles);
        let aborts: Vec<_> = handles.iter().map(JoinHandle::abort_handle).collect();
        let deadline = Instant::now() + limit;
        let mut outs = Vec::with_capacity(handles.len());
        for h in handles {
            let left = deadline.saturating_duration_since(Instant::now());
            if let Ok(Ok(o)) = timeout(left, h).await {
                outs.push(o);
            }
        }
        for a in aborts {
            a.abort();
        }
        outs
    }
}

impl Drop for SseGroup {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        for h in &self.handles {
            h.abort();
        }
    }
}

fn emit_body_probe() -> String {
    format!(
        r#"{{"event":"bench","data":{{"probe":true,"t":{}}}}}"#,
        unix_micros()
    )
}

// ---------------------------------------------------------------------------------------------
// cold-start
// ---------------------------------------------------------------------------------------------

struct ColdRun {
    listening_ms: f64,
    health_ms: f64,
    index_ms: f64,
    index_bytes: u64,
}

async fn cold_run(o: &ServerOpts, exe: &Path, accept_encoding: Option<&str>) -> Res<ColdRun> {
    let addr = spawn_addr(o);
    if port_in_use(addr).await {
        return Err(format!("{addr} already accepts connections"));
    }
    let server = ServerProc::spawn(exe, o.port, &o.server_arg, o.server_stderr)?;
    let t0 = server.spawned_at;

    let health_at = wait_health(addr, Some(&server), HEALTH_LIMIT).await?;

    // (c) first complete GET / on a fresh connection, issued right after (b).
    let mut conn = HttpConn::connect(addr).await?;
    conn.ready().await?;
    let f = conn.fetch(get_request("/", accept_encoding, None)?).await?;
    let index_at = Instant::now();
    if f.status != 200 {
        return Err(format!("GET / returned HTTP {}", f.status));
    }
    drop(conn);

    // (a) is recorded by the stdout reader thread; give it a moment if it lags behind.
    let mut listening_at = server.listening_at();
    let wait_until = Instant::now() + Duration::from_secs(2);
    while listening_at.is_none() && Instant::now() < wait_until {
        sleep(Duration::from_millis(5)).await;
        listening_at = server.listening_at();
    }
    let listening_at =
        listening_at.ok_or("no stdout line starting with 'listening on ' was seen")?;
    drop(server);

    Ok(ColdRun {
        listening_ms: ms(listening_at.duration_since(t0)),
        health_ms: ms(health_at.duration_since(t0)),
        index_ms: ms(index_at.duration_since(t0)),
        index_bytes: f.body_len,
    })
}

async fn cmd_cold_start(a: ColdStartArgs) -> Res<Value> {
    if a.srv.addr.is_some() {
        return Err("cold-start spawns the server itself; --addr is not supported".to_owned());
    }
    let exe = a
        .srv
        .server
        .clone()
        .ok_or("--server <path> is required for cold-start")?;
    println!(
        "cold-start: {} measured runs, {} warm-up runs, server {}",
        a.runs,
        a.warmup,
        exe.display()
    );
    let mut listening = Vec::new();
    let mut health = Vec::new();
    let mut index = Vec::new();
    let mut index_bytes = 0u64;
    let mut errors: Vec<String> = Vec::new();

    println!("| run | listening_ms | health_ms | index_ms | note |");
    println!("|---:|---:|---:|---:|---|");
    for i in 0..(a.warmup + a.runs) {
        let warm = i < a.warmup;
        let label = if warm {
            format!("warm-up {}", i + 1)
        } else {
            format!("{}", i - a.warmup + 1)
        };
        match cold_run(&a.srv, &exe, a.accept_encoding.as_deref()).await {
            Ok(r) => {
                println!(
                    "| {label} | {:.2} | {:.2} | {:.2} | {} |",
                    r.listening_ms,
                    r.health_ms,
                    r.index_ms,
                    if warm { "discarded" } else { "" }
                );
                if !warm {
                    listening.push(r.listening_ms);
                    health.push(r.health_ms);
                    index.push(r.index_ms);
                    index_bytes = r.index_bytes;
                }
            }
            Err(e) => {
                println!("| {label} | - | - | - | error: {e} |");
                if !warm {
                    errors.push(e);
                }
            }
        }
        sleep(Duration::from_millis(300)).await;
    }

    for (name, v) in [
        ("spawn -> 'listening on' line", &listening),
        ("spawn -> first health 200", &health),
        ("spawn -> first complete GET /", &index),
    ] {
        match stats3(v) {
            Some((m, lo, hi)) => {
                println!("{name}: median {m:.2} ms, min {lo:.2} ms, max {hi:.2} ms")
            }
            None => println!("{name}: no successful runs"),
        }
    }
    println!("GET / body bytes (as received, content-encoding as negotiated): {index_bytes}");
    if a.runs > 0 && listening.is_empty() {
        return Err(format!(
            "every measured run failed; first error: {}",
            errors.first().map_or("unknown", String::as_str)
        ));
    }

    Ok(json!({
        "cmd": "cold-start",
        "runs": a.runs,
        "warmup": a.warmup,
        "ok_runs": listening.len(),
        "errors": errors,
        "accept_encoding": a.accept_encoding,
        "index_body_bytes": index_bytes,
        "listening": stats_json(&listening),
        "health": stats_json(&health),
        "index": stats_json(&index),
    }))
}

// ---------------------------------------------------------------------------------------------
// idle-rss
// ---------------------------------------------------------------------------------------------

async fn cmd_idle_rss(a: IdleRssArgs) -> Res<Value> {
    let mut t = Target::start(&a.srv).await?;
    let started = Instant::now();
    let s0 = t.sample();
    println!("after health 200 : {}", fmt_sample(s0));
    sleep(secs(a.wait_secs)).await;
    let waited = started.elapsed();
    let s1 = t.sample();
    println!(
        "after {:.1} s idle: {}",
        waited.as_secs_f64(),
        fmt_sample(s1)
    );
    let idle_cpu = cpu_delta(s0, s1);
    match idle_cpu {
        Some(c) => println!(
            "CPU during idle wait: {c} ms over {:.2} s ({:.2} ms/s)",
            waited.as_secs_f64(),
            c as f64 / waited.as_secs_f64()
        ),
        None => println!("CPU during idle wait: not measured"),
    }
    Ok(json!({
        "cmd": "idle-rss",
        "target": t.header_json(),
        "spawn_to_health_ms": opt_f64(t.spawn_to_health.map(ms)),
        "wait_secs": r3(waited.as_secs_f64()),
        "initial": sample_json(s0),
        "after_wait": sample_json(s1),
        "idle_cpu_ms": idle_cpu,
        "idle_cpu_ms_per_s": opt_f64(idle_cpu.map(|c| c as f64 / waited.as_secs_f64())),
    }))
}

// ---------------------------------------------------------------------------------------------
// sse-rss
// ---------------------------------------------------------------------------------------------

struct Probe {
    status: u16,
    receivers: Option<u64>,
    received: u64,
    deliver_ms: Option<f64>,
    post_ms: f64,
}

/// Emits one event and waits until all connected clients have received it (or the timeout).
async fn run_probe(
    addr: SocketAddr,
    emit_path: &str,
    shared: &SseShared,
    connected: u64,
    limit: Duration,
) -> Res<Probe> {
    let mut conn = HttpConn::connect(addr).await?;
    let before = shared.events.load(Ordering::Relaxed);
    shared.last_event_ns.store(0, Ordering::Relaxed);
    let body = emit_body_probe();
    let t0 = Instant::now();
    let (status, resp) = post_emit(&mut conn, emit_path, body).await?;
    let post_ms = ms(t0.elapsed());
    let receivers = serde_json::from_slice::<Value>(&resp)
        .ok()
        .and_then(|v| v["receivers"].as_u64());

    let deadline = t0 + limit;
    loop {
        let got = shared.events.load(Ordering::Relaxed).saturating_sub(before);
        if got >= connected || Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(1)).await;
    }
    let received = shared.events.load(Ordering::Relaxed).saturating_sub(before);
    let last = shared.last_event_ns.load(Ordering::Relaxed);
    let t0_ns = ns_since(shared.base, t0);
    let deliver_ms = (received > 0).then(|| last.saturating_sub(t0_ns) as f64 / 1e6);
    Ok(Probe {
        status,
        receivers,
        received,
        deliver_ms,
        post_ms,
    })
}

async fn cmd_sse_rss(a: SseRssArgs) -> Res<Value> {
    check_path(&a.path)?;
    check_path(&a.emit_path)?;
    let mut t = Target::start(&a.srv).await?;
    let settle = secs(a.settle_secs);
    sleep(settle).await;
    let baseline = t.sample();
    println!("baseline (no clients): {}", fmt_sample(baseline));

    let mut rounds = Vec::new();
    for &n in &a.clients {
        println!();
        println!("== {n} SSE clients on {} ==", a.path);
        let start_sample = t.sample();
        let group = SseGroup::open(
            n,
            t.addr,
            &a.path,
            false,
            a.connect_concurrency,
            Duration::from_secs(10),
        );
        let (connected, failed, took) = group.wait_ready(secs(a.connect_timeout_secs)).await;
        let pending = (n as u64).saturating_sub(connected + failed);
        let first_error = group.shared.first_error();
        println!(
            "connected {connected}/{n} in {:.2} s, failed {failed}, still connecting {pending}",
            took.as_secs_f64()
        );
        if let Some(e) = &first_error {
            println!("first error: {e}");
        }
        sleep(settle).await;
        let loaded = t.sample();
        println!("with clients: {}", fmt_sample(loaded));

        let probe = if connected > 0 {
            match run_probe(
                t.addr,
                &a.emit_path,
                &group.shared,
                connected,
                secs(a.probe_timeout_secs),
            )
            .await
            {
                Ok(p) => Some(p),
                Err(e) => {
                    println!("probe failed: {e}");
                    None
                }
            }
        } else {
            None
        };
        if let Some(p) = &probe {
            println!(
                "probe: POST -> HTTP {} ({} receivers reported) in {:.2} ms; received by {}/{} clients; last delivery {} after the POST was sent",
                p.status,
                p.receivers
                    .map_or_else(|| "?".to_owned(), |r| r.to_string()),
                p.post_ms,
                p.received,
                connected,
                p.deliver_ms
                    .map_or_else(|| "n/a".to_owned(), |d| format!("{d:.2} ms")),
            );
        }
        let ended_early = group.shared.ended_early.load(Ordering::Relaxed);

        let outs = group.close(Duration::from_secs(15)).await;
        sleep(settle).await;
        let after = t.sample();
        println!("after closing: {}", fmt_sample(after));
        println!(
            "client tasks finished: {} of {n}; streams ended before close: {ended_early}",
            outs.len()
        );

        let ws_kib = loaded
            .zip(baseline)
            .and_then(|(l, b)| per_client_kib(l.working_set, b.working_set, connected));
        let priv_kib = loaded
            .zip(baseline)
            .and_then(|(l, b)| per_client_kib(l.private_bytes, b.private_bytes, connected));
        let ws_kib_prev = loaded
            .zip(start_sample)
            .and_then(|(l, b)| per_client_kib(l.working_set, b.working_set, connected));
        let priv_kib_prev = loaded
            .zip(start_sample)
            .and_then(|(l, b)| per_client_kib(l.private_bytes, b.private_bytes, connected));
        let show = |x: Option<f64>| x.map_or_else(|| "n/a".to_owned(), |v| format!("{v:.2}"));
        println!(
            "delta per connected client vs baseline: working set {} KiB, private {} KiB (vs round start: {} / {} KiB)",
            show(ws_kib),
            show(priv_kib),
            show(ws_kib_prev),
            show(priv_kib_prev)
        );

        rounds.push(json!({
            "requested": n,
            "connected": connected,
            "failed": failed,
            "still_connecting": pending,
            "first_error": first_error,
            "connect_wait_ms": r2(ms(took)),
            "streams_ended_early": ended_early,
            "round_start": sample_json(start_sample),
            "loaded": sample_json(loaded),
            "after_close": sample_json(after),
            "ws_bytes": loaded.map(|s| s.working_set),
            "private_bytes": loaded.map(|s| s.private_bytes),
            "delta_ws_kib_per_client": opt_f64(ws_kib),
            "delta_private_kib_per_client": opt_f64(priv_kib),
            "delta_ws_kib_per_client_vs_round_start": opt_f64(ws_kib_prev),
            "delta_private_kib_per_client_vs_round_start": opt_f64(priv_kib_prev),
            "probe_http_status": probe.as_ref().map(|p| p.status),
            "probe_receivers_reported": probe.as_ref().and_then(|p| p.receivers),
            "received_count": probe.as_ref().map(|p| p.received),
            "deliver_to_all_ms": opt_f64(probe.as_ref().and_then(|p| p.deliver_ms)),
            "probe_post_ms": probe.as_ref().map(|p| r2(p.post_ms)),
        }));
    }

    Ok(json!({
        "cmd": "sse-rss",
        "target": t.header_json(),
        "path": a.path,
        "settle_secs": a.settle_secs,
        "connect_concurrency": a.connect_concurrency,
        "baseline": sample_json(baseline),
        "rounds": rounds,
    }))
}

// ---------------------------------------------------------------------------------------------
// fanout
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct EmitStats {
    ok: u64,
    errors: u64,
    reconnects: u64,
    first_error: Option<String>,
    first_at: Option<Instant>,
    last_at: Option<Instant>,
}

async fn run_emitter(
    addr: SocketAddr,
    path: &str,
    conn: HttpConn,
    rate: u64,
    total: u64,
) -> EmitStats {
    let mut st = EmitStats::default();
    let pad = "x".repeat(64);
    let mut ticker = tokio::time::interval(Duration::from_nanos(1_000_000_000 / rate.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut slot = Some(conn);
    for seq in 0..total {
        ticker.tick().await;
        if slot.is_none() {
            match HttpConn::connect(addr).await {
                Ok(c) => {
                    st.reconnects += 1;
                    slot = Some(c);
                }
                Err(e) => {
                    st.errors += 1;
                    st.first_error.get_or_insert(e);
                    continue;
                }
            }
        }
        let Some(c) = slot.as_mut() else { continue };
        let t = unix_micros();
        let body = format!(r#"{{"event":"bench","data":{{"seq":{seq},"t":{t},"pad":"{pad}"}}}}"#);
        let now = Instant::now();
        st.first_at.get_or_insert(now);
        match post_emit(c, path, body).await {
            Ok((202, _)) => {
                st.ok += 1;
                st.last_at = Some(Instant::now());
            }
            Ok((status, _)) => {
                st.errors += 1;
                st.first_error
                    .get_or_insert(format!("emit returned HTTP {status}"));
            }
            Err(e) => {
                st.errors += 1;
                st.first_error.get_or_insert(e);
                slot = None;
            }
        }
    }
    st
}

async fn cmd_fanout(a: FanoutArgs) -> Res<Value> {
    if a.rate == 0 {
        return Err("--rate must be greater than 0".to_owned());
    }
    check_path(&a.path)?;
    check_path(&a.emit_path)?;
    let mut t = Target::start(&a.srv).await?;
    let mut me = ProcSampler::new(std::process::id());

    eprintln!("opening {} clients on {} ...", a.clients, a.path);
    let group = SseGroup::open(
        a.clients,
        t.addr,
        &a.path,
        true,
        a.connect_concurrency,
        Duration::from_secs(10),
    );
    let (connected, failed, took) = group.wait_ready(secs(a.connect_timeout_secs)).await;
    let first_error = group.shared.first_error();
    println!(
        "clients: connected {connected}/{} in {:.2} s, failed {failed}",
        a.clients,
        took.as_secs_f64()
    );
    if let Some(e) = &first_error {
        println!("first connect error: {e}");
    }
    if connected == 0 {
        return Err("no client could connect".to_owned());
    }
    sleep(secs(a.settle_secs)).await;

    // Phase A: no emits, only keep-alive traffic.
    let a0 = t.sample();
    let a_start = Instant::now();
    sleep(secs(a.baseline_secs)).await;
    let a1 = t.sample();
    let a_secs = a_start.elapsed().as_secs_f64();
    let base_cpu = cpu_delta(a0, a1);
    let base_rate = base_cpu.map(|c| c as f64 / a_secs);
    match (base_cpu, base_rate) {
        (Some(c), Some(r)) => {
            println!("phase A (no emits): server CPU {c} ms over {a_secs:.2} s = {r:.2} ms/s");
        }
        _ => println!("phase A (no emits): server CPU not measured"),
    }

    // Phase B: emit at a fixed rate, then drain.
    let total = a.rate * a.duration_secs;
    let emit_conn = HttpConn::connect(t.addr).await?;
    let delivered0 = group.shared.events.load(Ordering::Relaxed);
    let connected_b = group.shared.connected.load(Ordering::Relaxed);
    let b0 = t.sample();
    let me0 = me.sample();
    let b_start = Instant::now();
    let stats = run_emitter(t.addr, &a.emit_path, emit_conn, a.rate, total).await;
    sleep(secs(a.drain_secs)).await;
    let b_secs = b_start.elapsed().as_secs_f64();
    let b1 = t.sample();
    let me1 = me.sample();
    let delivered = group
        .shared
        .events
        .load(Ordering::Relaxed)
        .saturating_sub(delivered0);
    let ended_early = group.shared.ended_early.load(Ordering::Relaxed);

    let outs = group.close(Duration::from_secs(20)).await;
    let mut merged = new_hist();
    for o in &outs {
        if let Some(h) = &o.hist {
            let _ = merged.add(h);
        }
    }

    let emit_window = match (stats.first_at, stats.last_at) {
        (Some(f), Some(l)) if l > f => l.duration_since(f).as_secs_f64(),
        _ => 0.0,
    };
    let expected = stats.ok * connected_b;
    let per_s = (emit_window > 0.0).then(|| delivered as f64 / emit_window);
    let per_s_total = delivered as f64 / b_secs;
    let ratio = (expected > 0).then(|| delivered as f64 / expected as f64);
    let cpu_b = cpu_delta(b0, b1);
    let cpu_b_rate = cpu_b.map(|c| c as f64 / b_secs);
    let cpu_us_per = cpu_b
        .filter(|_| delivered > 0)
        .map(|c| c as f64 * 1000.0 / delivered as f64);
    let cpu_us_per_net = cpu_b
        .zip(base_rate)
        .filter(|_| delivered > 0)
        .map(|(c, r)| (c as f64 - r * b_secs).max(0.0) * 1000.0 / delivered as f64);
    let client_cpu = cpu_delta(me0, me1);

    println!(
        "phase B: emitted {} ok, {} errors (planned {total}) over {emit_window:.2} s, phase length incl. drain {b_secs:.2} s",
        stats.ok, stats.errors
    );
    if let Some(e) = &stats.first_error {
        println!("first emit error: {e}");
    }
    println!(
        "deliveries: expected {expected} (emitted x {connected_b} clients), delivered {delivered}{}; streams ended early: {ended_early}",
        ratio.map_or_else(String::new, |r| format!(" ({:.3}%)", r * 100.0))
    );
    match per_s {
        Some(p) => println!(
            "delivered per second over the emit window: {p:.0} (over the whole phase incl. drain: {per_s_total:.0})"
        ),
        None => println!("delivered per second: not computable (emit window is empty)"),
    }
    match (cpu_b, cpu_b_rate) {
        (Some(c), Some(r)) => {
            println!("server CPU in phase B: {c} ms = {r:.2} ms/s");
            if let Some(u) = cpu_us_per {
                println!(
                    "server CPU per delivered event: {u:.3} us (net of idle baseline: {:.3} us)",
                    cpu_us_per_net.unwrap_or(f64::NAN)
                );
            }
        }
        _ => println!("server CPU in phase B: not measured"),
    }
    match client_cpu {
        Some(c) => println!("measure process CPU in phase B: {c} ms"),
        None => println!("measure process CPU: not measured"),
    }
    print_hist("delivery latency", &merged);
    if merged.len() != delivered {
        println!(
            "note: {} of {delivered} delivered events carried a parseable \"t\" field",
            merged.len()
        );
    }

    Ok(json!({
        "cmd": "fanout",
        "target": t.header_json(),
        "path": a.path,
        "clients_requested": a.clients,
        "clients_connected": connected,
        "clients_failed": failed,
        "clients_connected_at_phase_b": connected_b,
        "first_connect_error": first_error,
        "streams_ended_early": ended_early,
        "rate_per_s": a.rate,
        "duration_secs": a.duration_secs,
        "planned_emits": total,
        "emitted": stats.ok,
        "emit_errors": stats.errors,
        "emit_reconnects": stats.reconnects,
        "emit_first_error": stats.first_error,
        "emit_window_s": r3(emit_window),
        "phase_b_s": r3(b_secs),
        "expected_deliveries": expected,
        "delivered": delivered,
        "delivery_ratio": ratio.map(r3),
        "delivered_per_s": opt_f64(per_s),
        "delivered_per_s_incl_drain": r2(per_s_total),
        "server_cpu_ms": cpu_b,
        "server_cpu_ms_per_s": opt_f64(cpu_b_rate),
        "server_cpu_us_per_delivered": cpu_us_per.map(r3),
        "server_cpu_us_per_delivered_net_of_idle": cpu_us_per_net.map(r3),
        "baseline_secs": r3(a_secs),
        "baseline_cpu_ms": base_cpu,
        "baseline_cpu_ms_per_s": opt_f64(base_rate),
        "latency_samples": merged.len(),
        "latency": hist_json(&merged),
        "measure_cpu_ms": client_cpu,
        "server_cpu_samples": {
            "phase_a_start": sample_json(a0),
            "phase_a_end": sample_json(a1),
            "phase_b_start": sample_json(b0),
            "phase_b_end": sample_json(b1),
        },
    }))
}

// ---------------------------------------------------------------------------------------------
// http-load
// ---------------------------------------------------------------------------------------------

const PH_WARMUP: u8 = 0;
const PH_MEASURE: u8 = 1;
const PH_STOP: u8 = 2;

struct LoadOut {
    hist: Histogram<u64>,
    requests: u64,
    errors: u64,
    non_200: u64,
    body_bytes: u64,
    reconnects: u64,
    last_encoding: Option<HeaderValue>,
    first_error: Option<String>,
}

impl LoadOut {
    fn new() -> Self {
        Self {
            hist: new_hist(),
            requests: 0,
            errors: 0,
            non_200: 0,
            body_bytes: 0,
            reconnects: 0,
            last_encoding: None,
            first_error: None,
        }
    }

    fn note_error(&mut self, e: String) {
        self.errors += 1;
        self.first_error.get_or_insert(e);
    }
}

/// One keep-alive connection sending requests back to back. A request is recorded only if it
/// started and finished inside the measured window.
async fn load_worker(
    addr: SocketAddr,
    path: Arc<str>,
    accept_encoding: Option<Arc<str>>,
    phase: Arc<AtomicU8>,
    sem: Arc<Semaphore>,
) -> LoadOut {
    let mut out = LoadOut::new();
    let mut conn: Option<HttpConn> = None;
    let mut fresh = false;
    loop {
        let ph0 = phase.load(Ordering::Relaxed);
        if ph0 == PH_STOP {
            break;
        }
        if conn.is_none() {
            match connect_retry(addr, &sem).await {
                Ok(c) => {
                    conn = Some(c);
                    fresh = true;
                }
                Err(e) => {
                    if ph0 == PH_MEASURE {
                        out.note_error(e);
                    }
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
            }
        }
        let Some(c) = conn.as_mut() else { continue };
        if let Err(e) = c.ready().await {
            // The server closed the connection between requests: reconnect. A connection that
            // is not usable right after connecting counts as an error and backs off.
            conn = None;
            if fresh {
                if ph0 == PH_MEASURE {
                    out.note_error(e);
                }
                sleep(Duration::from_millis(10)).await;
            } else {
                out.reconnects += 1;
            }
            continue;
        }
        fresh = false;
        let Ok(req) = get_request(&path, accept_encoding.as_deref(), None) else {
            out.note_error("cannot build request".to_owned());
            break;
        };
        let t0 = Instant::now();
        let res = c.fetch(req).await;
        let dt = t0.elapsed();
        let measured = ph0 == PH_MEASURE && phase.load(Ordering::Relaxed) == PH_MEASURE;
        match res {
            Ok(f) => {
                if measured {
                    out.requests += 1;
                    if f.status != 200 {
                        out.non_200 += 1;
                    }
                    out.body_bytes += f.body_len;
                    out.last_encoding = f.encoding;
                    let _ = out
                        .hist
                        .record(u64::try_from(dt.as_micros()).unwrap_or(u64::MAX));
                }
            }
            Err(e) => {
                conn = None;
                if measured {
                    out.note_error(e);
                }
            }
        }
    }
    out
}

async fn cmd_http_load(a: HttpLoadArgs) -> Res<Value> {
    if a.connections == 0 {
        return Err("--connections must be greater than 0".to_owned());
    }
    // Validate the request once (e.g. an invalid header value) before starting anything.
    get_request(&a.path, a.accept_encoding.as_deref(), None)?;
    let mut t = Target::start(&a.srv).await?;
    let mut me = ProcSampler::new(std::process::id());

    let phase = Arc::new(AtomicU8::new(PH_WARMUP));
    let path: Arc<str> = Arc::from(a.path.as_str());
    let ae: Option<Arc<str>> = a.accept_encoding.as_deref().map(Arc::from);
    let sem = Arc::new(Semaphore::new(256));
    let handles: Vec<JoinHandle<LoadOut>> = (0..a.connections)
        .map(|_| {
            tokio::spawn(load_worker(
                t.addr,
                Arc::clone(&path),
                ae.clone(),
                Arc::clone(&phase),
                Arc::clone(&sem),
            ))
        })
        .collect();

    sleep(secs(a.warmup_secs)).await;
    phase.store(PH_MEASURE, Ordering::SeqCst);
    let s0 = t.sample();
    let me0 = me.sample();
    let start = Instant::now();
    sleep(secs(a.duration_secs)).await;
    let end = Instant::now();
    phase.store(PH_STOP, Ordering::SeqCst);
    let s1 = t.sample();
    let me1 = me.sample();
    let window = end.duration_since(start).as_secs_f64();

    let mut hist = new_hist();
    let (mut requests, mut errors, mut non_200) = (0u64, 0u64, 0u64);
    let (mut body_bytes, mut reconnects) = (0u64, 0u64);
    let mut encoding: Option<HeaderValue> = None;
    let mut first_error: Option<String> = None;
    let mut finished = 0usize;
    for h in handles {
        if let Ok(Ok(o)) = timeout(Duration::from_secs(15), h).await {
            finished += 1;
            let _ = hist.add(&o.hist);
            requests += o.requests;
            errors += o.errors;
            non_200 += o.non_200;
            body_bytes += o.body_bytes;
            reconnects += o.reconnects;
            if o.last_encoding.is_some() {
                encoding = o.last_encoding;
            }
            if first_error.is_none() {
                first_error = o.first_error;
            }
        }
    }
    let encoding = encoding.and_then(|v| v.to_str().ok().map(str::to_owned));
    let rps = requests as f64 / window;
    let mean_body = (requests > 0).then(|| body_bytes as f64 / requests as f64);
    let cpu = cpu_delta(s0, s1);
    let cpu_us_per_req = cpu
        .filter(|_| requests > 0)
        .map(|c| c as f64 * 1000.0 / requests as f64);
    let client_cpu = cpu_delta(me0, me1);

    println!(
        "http-load GET {} with {} connections, accept-encoding {}: window {window:.2} s",
        a.path,
        a.connections,
        a.accept_encoding.as_deref().unwrap_or("(none)")
    );
    println!(
        "requests {requests}, errors {errors}, non-200 {non_200}, reconnects {reconnects}, workers finished {finished}/{}",
        a.connections
    );
    if let Some(e) = &first_error {
        println!("first error: {e}");
    }
    println!("throughput: {rps:.0} requests/s");
    print_hist("latency", &hist);
    println!(
        "mean body bytes: {}; content-encoding of last response: {}",
        mean_body.map_or_else(|| "n/a".to_owned(), |m| format!("{m:.1}")),
        encoding.as_deref().unwrap_or("(none)")
    );
    match cpu {
        Some(c) => println!(
            "server CPU in window: {c} ms = {:.2} ms/s{}",
            c as f64 / window,
            cpu_us_per_req.map_or_else(String::new, |u| format!(", {u:.3} us per request"))
        ),
        None => println!("server CPU: not measured"),
    }
    match client_cpu {
        Some(c) => println!("measure process CPU in window: {c} ms"),
        None => println!("measure process CPU: not measured"),
    }

    Ok(json!({
        "cmd": "http-load",
        "target": t.header_json(),
        "path": a.path,
        "connections": a.connections,
        "accept_encoding": a.accept_encoding,
        "warmup_secs": a.warmup_secs,
        "window_s": r3(window),
        "requests": requests,
        "errors": errors,
        "non_200": non_200,
        "reconnects": reconnects,
        "first_error": first_error,
        "requests_per_s": r2(rps),
        "latency": hist_json(&hist),
        "mean_body_bytes": opt_f64(mean_body),
        "content_encoding": encoding,
        "server_cpu_ms": cpu,
        "server_cpu_ms_per_s": opt_f64(cpu.map(|c| c as f64 / window)),
        "server_cpu_us_per_request": cpu_us_per_req.map(r3),
        "measure_cpu_ms": client_cpu,
        "server_cpu_samples": {"window_start": sample_json(s0), "window_end": sample_json(s1)},
    }))
}

// ---------------------------------------------------------------------------------------------
// bundle and binsize
// ---------------------------------------------------------------------------------------------

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let ft = e.file_type()?;
        if ft.is_dir() {
            collect_files(&p, out)?;
        } else if ft.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

fn gzip_len(data: &[u8]) -> Res<u64> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).map_err(ctx("gzip"))?;
    let out = enc.finish().map_err(ctx("gzip"))?;
    Ok(out.len() as u64)
}

fn brotli_len(data: &[u8]) -> Res<u64> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 65536, 11, 22);
        w.write_all(data).map_err(ctx("brotli"))?;
    }
    Ok(out.len() as u64)
}

fn pct(part: u64, whole: u64) -> String {
    if whole == 0 {
        "-".to_owned()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

fn ratio(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| r3(part as f64 / whole as f64))
}

#[derive(Default, Clone, Copy)]
struct Agg {
    count: u64,
    raw: u64,
    gz: u64,
    br: u64,
}

impl Agg {
    fn add(&mut self, raw: u64, gz: u64, br: u64) {
        self.count += 1;
        self.raw += raw;
        self.gz += gz;
        self.br += br;
    }

    fn json(&self) -> Value {
        json!({
            "count": self.count,
            "raw_bytes": self.raw,
            "gzip_bytes": self.gz,
            "br_bytes": self.br,
            "gzip_ratio": ratio(self.gz, self.raw),
            "br_ratio": ratio(self.br, self.raw),
        })
    }
}

fn cmd_bundle(a: &BundleArgs) -> Res<Value> {
    let mut files = Vec::new();
    collect_files(&a.dir, &mut files)
        .map_err(|e| format!("cannot read {}: {e}", a.dir.display()))?;
    if files.is_empty() {
        return Err(format!("no files below {}", a.dir.display()));
    }
    let mut total = Agg::default();
    let mut by_ext: BTreeMap<String, Agg> = BTreeMap::new();

    println!("Bundle: {}", a.dir.display());
    println!();
    println!("| file | raw B | gzip B | br B | gzip | br |");
    println!("|---|---:|---:|---:|---:|---:|");
    for p in &files {
        let data = std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let raw = data.len() as u64;
        let gz = gzip_len(&data)?;
        let br = brotli_len(&data)?;
        let rel = p
            .strip_prefix(&a.dir)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/");
        let ext = p.extension().map_or_else(
            || "(none)".to_owned(),
            |e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()),
        );
        println!(
            "| {rel} | {raw} | {gz} | {br} | {} | {} |",
            pct(gz, raw),
            pct(br, raw)
        );
        total.add(raw, gz, br);
        by_ext.entry(ext).or_default().add(raw, gz, br);
    }

    println!();
    println!("| extension | files | raw B | gzip B | br B | gzip | br |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for (ext, g) in &by_ext {
        println!(
            "| {ext} | {} | {} | {} | {} | {} | {} |",
            g.count,
            g.raw,
            g.gz,
            g.br,
            pct(g.gz, g.raw),
            pct(g.br, g.raw)
        );
    }
    println!(
        "| total | {} | {} | {} | {} | {} | {} |",
        total.count,
        total.raw,
        total.gz,
        total.br,
        pct(total.gz, total.raw),
        pct(total.br, total.raw)
    );
    println!();
    println!("gzip: flate2 level 9 (Compression::best); brotli: quality 11, lgwin 22.");

    let ext_json: serde_json::Map<String, Value> =
        by_ext.iter().map(|(k, v)| (k.clone(), v.json())).collect();
    Ok(json!({
        "cmd": "bundle",
        "dir": a.dir.to_string_lossy(),
        "totals": total.json(),
        "by_extension": ext_json,
    }))
}

fn cmd_binsize(a: &BinsizeArgs) -> Res<Value> {
    println!("| file | bytes | KiB |");
    println!("|---|---:|---:|");
    let mut rows = Vec::new();
    let mut missing = Vec::new();
    for p in &a.files {
        match std::fs::metadata(p) {
            Ok(m) => {
                let bytes = m.len();
                println!("| {} | {bytes} | {:.2} |", p.display(), bytes as f64 / KIB);
                rows.push(
                    json!({"path": p.to_string_lossy(), "bytes": bytes, "kib": r2(bytes as f64 / KIB)}),
                );
            }
            Err(e) => {
                println!("| {} | error: {e} | |", p.display());
                missing.push(format!("{}: {e}", p.display()));
            }
        }
    }
    if rows.is_empty() {
        return Err(missing.join("; "));
    }
    Ok(json!({"cmd": "binsize", "files": rows, "errors": missing}))
}

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------

async fn dispatch(cmd: Cmd) -> Res<Value> {
    match cmd {
        Cmd::ColdStart(a) => cmd_cold_start(a).await,
        Cmd::IdleRss(a) => cmd_idle_rss(a).await,
        Cmd::SseRss(a) => cmd_sse_rss(a).await,
        Cmd::Fanout(a) => cmd_fanout(a).await,
        Cmd::HttpLoad(a) => cmd_http_load(a).await,
        Cmd::Bundle(a) => cmd_bundle(&a),
        Cmd::Binsize(a) => cmd_binsize(&a),
    }
}

fn main() -> ExitCode {
    install_panic_cleanup();
    let cli = Cli::parse();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = cli.threads {
        builder.worker_threads(n.max(1));
    }
    let rt = match builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot build the tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = rt.block_on(async {
        tokio::select! {
            r = dispatch(cli.cmd) => r,
            _ = tokio::signal::ctrl_c() => {
                kill_all_children();
                Err("interrupted".to_owned())
            }
        }
    });
    rt.shutdown_background();
    kill_all_children();
    match result {
        Ok(v) => {
            println!("RESULT {v}");
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsed view of a frame for assertions: (is_event, is_shutdown, event, data).
    type Seen = (bool, bool, Option<String>, Option<String>);

    fn collect(chunks: &[&[u8]]) -> Vec<Seen> {
        let mut p = SseParser::default();
        let mut out = Vec::new();
        for c in chunks {
            p.push(c, |f| {
                out.push((
                    f.is_event(),
                    f.is_shutdown(),
                    f.event.map(|e| String::from_utf8_lossy(e).into_owned()),
                    f.data.map(|e| String::from_utf8_lossy(e).into_owned()),
                ));
            });
        }
        out
    }

    const STREAM: &[u8] = b"retry: 3000\n: connected\n\nid: 7\nevent: bench\ndata: {\"seq\":1,\"t\":1700000000123456}\n\n: keep-alive\n\nevent: shutdown\ndata: {}\n\n";

    #[test]
    fn splits_whole_stream() {
        let frames = collect(&[STREAM]);
        assert_eq!(frames.len(), 4);
        // retry + comment frame has no data line
        assert!(!frames[0].0);
        // normal event
        assert_eq!(frames[1].2.as_deref(), Some("bench"));
        assert!(frames[1].0 && !frames[1].1);
        assert_eq!(
            extract_t(frames[1].3.as_deref().unwrap().as_bytes()),
            Some(1_700_000_000_123_456)
        );
        // keep-alive comment is not an event
        assert!(!frames[2].0);
        // shutdown
        assert!(frames[3].1);
    }

    #[test]
    fn same_result_for_every_split_point() {
        let whole = collect(&[STREAM]);
        for cut in 0..=STREAM.len() {
            let (a, b) = STREAM.split_at(cut);
            assert_eq!(collect(&[a, b]), whole, "cut at {cut}");
        }
    }

    #[test]
    fn same_result_byte_by_byte() {
        let whole = collect(&[STREAM]);
        let chunks: Vec<&[u8]> = STREAM.chunks(1).collect();
        assert_eq!(collect(&chunks), whole);
    }

    #[test]
    fn handles_crlf_terminators() {
        let frames = collect(&[b"event: bench\r\ndata: {\"t\":5}\r\n\r\n: ping\r\n\r\n"]);
        assert_eq!(frames.len(), 2);
        assert!(frames[0].0);
        assert_eq!(frames[0].2.as_deref(), Some("bench"));
        assert_eq!(frames[0].3.as_deref(), Some("{\"t\":5}"));
        assert!(!frames[1].0);
    }

    #[test]
    fn data_before_event_and_no_space_after_colon() {
        let frames = collect(&[b"data:{\"t\": 42}\nevent:bench\n\n"]);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].0);
        assert_eq!(frames[0].2.as_deref(), Some("bench"));
        assert_eq!(
            extract_t(frames[0].3.as_deref().unwrap().as_bytes()),
            Some(42)
        );
    }

    #[test]
    fn incomplete_frame_is_held_back() {
        let mut p = SseParser::default();
        let mut n = 0;
        p.push(b"data: x\n", |_| n += 1);
        assert_eq!(n, 0);
        p.push(b"\n", |_| n += 1);
        assert_eq!(n, 1);
        assert!(p.buf.is_empty());
    }

    #[test]
    fn frame_end_positions() {
        assert_eq!(find_frame_end(b"a\n\nb"), Some((1, 3)));
        assert_eq!(find_frame_end(b"a\r\n\r\nb"), Some((2, 5)));
        assert_eq!(find_frame_end(b"a\nb\n"), None);
        assert_eq!(find_frame_end(b"a\r\n\r"), None);
        assert_eq!(find_frame_end(b""), None);
    }

    #[test]
    fn extracts_t_in_various_positions() {
        assert_eq!(extract_t(br#"{"seq":1,"t":123,"pad":"xx"}"#), Some(123));
        assert_eq!(extract_t(br#"{"t":9}"#), Some(9));
        assert_eq!(extract_t(br#"{"probe":true,"t": 77}"#), Some(77));
        assert_eq!(extract_t(br#"{"start":5}"#), None);
        assert_eq!(extract_t(br#"{"t":"abc"}"#), None);
        assert_eq!(extract_t(b""), None);
        assert_eq!(extract_t(br#"{"t":99999999999999999999999}"#), None);
    }

    #[test]
    fn median_min_max() {
        assert_eq!(stats3(&[3.0, 1.0, 2.0]), Some((2.0, 1.0, 3.0)));
        assert_eq!(stats3(&[4.0, 1.0, 2.0, 3.0]), Some((2.5, 1.0, 4.0)));
        assert_eq!(stats3(&[5.0]), Some((5.0, 5.0, 5.0)));
        assert_eq!(stats3(&[]), None);
    }

    #[test]
    fn rounding_helpers() {
        assert!((r2(1.234_9) - 1.23).abs() < 1e-9);
        assert!((r2(1.235_1) - 1.24).abs() < 1e-9);
        assert!((r3(1.234_56) - 1.235).abs() < 1e-9);
    }

    #[test]
    fn per_client_delta_is_signed() {
        assert_eq!(per_client_kib(2048, 0, 2), Some(1.0));
        assert_eq!(per_client_kib(0, 2048, 2), Some(-1.0));
        assert_eq!(per_client_kib(1, 0, 0), None);
    }

    #[test]
    fn compression_sizes_are_plausible() {
        let data = vec![b'a'; 10_000];
        let gz = gzip_len(&data).unwrap();
        let br = brotli_len(&data).unwrap();
        assert!(gz > 0 && gz < 200, "gzip {gz}");
        assert!(br > 0 && br < 100, "brotli {br}");
    }
}
