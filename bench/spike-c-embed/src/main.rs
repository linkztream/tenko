//! Spike C server: the SPA embedded in the binary and served by the API process, with
//! live updates over SSE.
//!
//! Routes:
//! - `GET /api/health`
//! - `GET /api/events` (SSE, pre-encoded frames, shared keep-alive)
//! - `GET /api/events/axum` (SSE through axum's `Sse`, for comparison)
//! - `POST /api/events/emit` (test hook)
//! - everything else: the UI (embedded, or `--ui-dir` from disk), with SPA fallback.
#![forbid(unsafe_code)]

mod assets;
mod events;
mod mime;
mod web;

use std::future::{Future, IntoFuture};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::serve::ListenerExt;
use clap::Parser;
use tokio::net::{TcpListener, TcpSocket};

use crate::assets::AssetTable;
use crate::events::Hub;

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Spike C: embedded SPA and SSE server")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Serve the UI from this directory instead of the embedded assets (development).
    #[arg(long, value_name = "PATH")]
    ui_dir: Option<PathBuf>,
    /// Tokio worker threads (default: number of logical CPUs).
    #[arg(long)]
    workers: Option<usize>,
    /// Seconds between SSE keep-alive comments.
    #[arg(long, default_value_t = 15)]
    keepalive_secs: u64,
    /// Events a subscriber may fall behind before it is reset.
    #[arg(long, default_value_t = 1024)]
    channel_capacity: usize,
    /// Events kept for `Last-Event-ID` replay.
    #[arg(long, default_value_t = 256)]
    ring: usize,
    /// Seconds to wait for open connections after ctrl-c before exiting anyway.
    #[arg(long, default_value_t = 10)]
    shutdown_grace_secs: u64,
    /// Coalesce events published within this many milliseconds into one write per client
    /// (0 = send every event immediately).
    #[arg(long, default_value_t = 0)]
    coalesce_ms: u64,
}

const HEALTH: &str = concat!(
    "{\"status\":\"ok\",\"version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\"}"
);

async fn health() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
        ],
        HEALTH,
    )
}

async fn api_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [(CONTENT_TYPE, "application/json")],
        "{\"error\":\"not_found\"}",
    )
}

/// Where the UI comes from.
enum Ui {
    Embedded(Arc<AssetTable>),
    Dir(PathBuf),
}

impl Ui {
    fn describe(&self) -> String {
        match self {
            Ui::Embedded(t) => {
                let s = t.stats();
                format!(
                    "embedded {} ({} files, {} bytes, {} br, {} gzip, runtime compression: {})",
                    t.backend,
                    s.files,
                    s.identity_bytes,
                    s.br_files,
                    s.gzip_files,
                    cfg!(feature = "runtime-compression")
                )
            }
            Ui::Dir(d) => format!("directory {}", d.display()),
        }
    }
}

fn app(hub: Arc<Hub>, ui: &Ui) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/events", get(events::events_raw))
        .route("/events/axum", get(events::events_axum))
        .route("/events/emit", post(events::emit))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(hub);
    let ui_router = match ui {
        Ui::Embedded(table) => Router::new()
            .fallback(web::serve_embedded)
            .with_state(Arc::clone(table)),
        Ui::Dir(dir) => web::dir_router(dir),
    };
    let app = Router::new().nest("/api", api).fallback_service(ui_router);
    // The default predicate skips text/event-stream, images and bodies under 32 bytes.
    #[cfg(feature = "runtime-compression")]
    let app = app.layer(tower_http::compression::CompressionLayer::new());
    app.layer(axum::middleware::map_response(web::security_headers))
}

fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // SO_REUSEADDR has port-stealing semantics on Windows; only set it elsewhere.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    // A deep backlog absorbs reconnect storms (every SSE client reconnecting at once).
    socket.listen(4096)
}

/// Serves until `signal` resolves, then shuts down gracefully: SSE streams are ended
/// through the hub, idle keep-alive connections are closed, and in-flight requests may
/// finish within `grace`.
async fn serve(
    listener: TcpListener,
    app: Router,
    hub: Arc<Hub>,
    signal: impl Future<Output = ()> + Send + 'static,
    grace: Duration,
) -> io::Result<()> {
    let started = Arc::new(tokio::sync::Notify::new());
    let on_signal = Arc::clone(&started);
    let listener = listener.tap_io(|tcp| {
        // SSE frames are small writes; Nagle plus delayed ACK would hold them back.
        let _ = tcp.set_nodelay(true);
    });
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        signal.await;
        hub.shutdown();
        on_signal.notify_one();
    });
    tokio::select! {
        result = server.into_future() => result,
        () = async { started.notified().await; tokio::time::sleep(grace).await } => {
            eprintln!("graceful shutdown did not finish within {grace:?}; exiting");
            Ok(())
        }
    }
}

async fn run(args: Args) -> io::Result<()> {
    let t0 = Instant::now();
    let ui = match &args.ui_dir {
        Some(dir) => {
            if !dir.join("index.html").is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{}/index.html not found", dir.display()),
                ));
            }
            Ui::Dir(dir.clone())
        }
        None => Ui::Embedded(Arc::new(AssetTable::embedded())),
    };
    let hub = Hub::with_coalescing(args.channel_capacity, args.ring, args.coalesce_ms > 0);
    hub.spawn_keepalive(Duration::from_secs(args.keepalive_secs.max(1)));
    if args.coalesce_ms > 0 {
        hub.spawn_flusher(Duration::from_millis(args.coalesce_ms));
    }
    let router = app(Arc::clone(&hub), &ui);
    let listener = bind(args.listen)?;
    println!(
        "listening on {} (ui: {}, init: {:.2} ms)",
        listener.local_addr()?,
        ui.describe(),
        t0.elapsed().as_secs_f64() * 1e3
    );
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("ctrl-c received, shutting down");
    };
    serve(
        listener,
        router,
        hub,
        ctrl_c,
        Duration::from_secs(args.shutdown_grace_secs),
    )
    .await
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = args.workers {
        builder.worker_threads(n.max(1));
    }
    let runtime = match builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run(args));
    runtime.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end tests against a real listener with a raw HTTP/1.1 client.
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    struct Server {
        addr: SocketAddr,
        stop: Option<oneshot::Sender<()>>,
        task: JoinHandle<io::Result<()>>,
        table: Arc<AssetTable>,
    }

    async fn start() -> Server {
        start_with(None, false).await
    }

    async fn start_with(ui_dir: Option<PathBuf>, coalesce: bool) -> Server {
        let table = Arc::new(AssetTable::embedded());
        let hub = Hub::with_coalescing(64, 16, coalesce);
        if coalesce {
            hub.spawn_flusher(Duration::from_millis(20));
        }
        let ui = match ui_dir {
            Some(dir) => Ui::Dir(dir),
            None => Ui::Embedded(Arc::clone(&table)),
        };
        let router = app(Arc::clone(&hub), &ui);
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(
            listener,
            router,
            hub,
            async move {
                let _ = rx.await;
            },
            Duration::from_secs(5),
        ));
        Server {
            addr,
            stop: Some(tx),
            task,
            table,
        }
    }

    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    fn parse_head(raw: &[u8]) -> (u16, Vec<(String, String)>, usize) {
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("end of headers")
            + 4;
        let head = std::str::from_utf8(&raw[..end]).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.trim().to_owned(), v.trim().to_owned())
            })
            .collect();
        (status, headers, end)
    }

    async fn request(
        addr: SocketAddr,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        req.push_str("\r\n");
        req.push_str(body);
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        let (status, headers, end) = parse_head(&raw);
        Reply {
            status,
            headers,
            body: raw[end..].to_vec(),
        }
    }

    /// Opens an SSE stream and returns the socket after the response head.
    async fn open_sse(addr: SocketAddr, path: &str, last_id: Option<u64>) -> (TcpStream, Vec<u8>) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nAccept: text/event-stream\r\n");
        if let Some(id) = last_id {
            req.push_str(&format!("Last-Event-ID: {id}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        read_until(&mut s, &mut buf, b"connected").await;
        let (status, headers, _) = parse_head(&buf);
        assert_eq!(status, 200);
        assert!(
            headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/event-stream")
        );
        (s, buf)
    }

    async fn read_until(s: &mut TcpStream, buf: &mut Vec<u8>, needle: &[u8]) {
        timeout(Duration::from_secs(5), async {
            while !buf.windows(needle.len()).any(|w| w == needle) {
                let mut chunk = [0u8; 4096];
                let n = s.read(&mut chunk).await.unwrap();
                assert!(
                    n > 0,
                    "stream closed before {:?}",
                    String::from_utf8_lossy(needle)
                );
                buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("timed out waiting for SSE data");
    }

    fn js_asset(table: &AssetTable) -> String {
        table
            .keys()
            .find(|k| k.starts_with("assets/") && k.ends_with(".js"))
            .expect("a hashed JS asset in ui/dist")
            .to_owned()
    }

    #[tokio::test]
    async fn static_rules() {
        let srv = start().await;
        let a = srv.addr;

        let r = request(a, "GET", "/", &[], "").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(r.header("cache-control"), Some("no-cache"));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
        assert!(
            r.header("content-security-policy")
                .unwrap()
                .contains("default-src 'self'")
        );
        assert!(r.header("content-encoding").is_none());
        assert!(String::from_utf8_lossy(&r.body).contains("<div id=\"root\">"));
        let etag = r.header("etag").unwrap().to_owned();

        let r = request(a, "GET", "/", &[("If-None-Match", &etag)], "").await;
        assert_eq!(r.status, 304);
        assert!(r.body.is_empty());

        let r = request(
            a,
            "GET",
            "/",
            &[("Accept-Encoding", "gzip, deflate, br")],
            "",
        )
        .await;
        assert_eq!(r.status, 200);
        if cfg!(feature = "precompressed") {
            assert_eq!(r.header("content-encoding"), Some("br"));
            assert_eq!(r.header("vary"), Some("accept-encoding"));
            let br_etag = r.header("etag").unwrap().to_owned();
            assert_ne!(br_etag, etag);
            let r = request(a, "GET", "/", &[("If-None-Match", &br_etag)], "").await;
            assert_eq!(r.status, 304);
        }

        let js = js_asset(&srv.table);
        let r = request(
            a,
            "GET",
            &format!("/{js}"),
            &[("Accept-Encoding", "gzip")],
            "",
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(
            r.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        if cfg!(feature = "precompressed") {
            assert_eq!(r.header("content-encoding"), Some("gzip"));
        }

        let r = request(a, "HEAD", &format!("/{js}"), &[], "").await;
        assert_eq!(r.status, 200);
        assert!(r.body.is_empty());
        assert_eq!(
            r.header("content-length").unwrap(),
            srv.table.get(&js).unwrap().identity.len().to_string()
        );

        // SPA fallback for client routes, including ones that look like file names.
        for path in ["/ipam", "/dns/zones/example.com", "/ipam/192.0.2.0/24"] {
            let r = request(a, "GET", path, &[], "").await;
            assert_eq!(r.status, 200, "{path}");
            assert_eq!(
                r.header("content-type"),
                Some("text/html; charset=utf-8"),
                "{path}"
            );
        }
        // No fallback (and no listing) under /assets.
        for path in ["/assets/missing-abc123.js", "/assets/", "/assets"] {
            let r = request(a, "GET", path, &[], "").await;
            assert_eq!(r.status, 404, "{path}");
        }
        // The API never falls back to the UI.
        let r = request(a, "GET", "/api/nope", &[], "").await;
        assert_eq!(r.status, 404);
        assert_eq!(r.header("content-type"), Some("application/json"));

        let r = request(a, "POST", "/", &[], "").await;
        assert_eq!(r.status, 405);
        assert_eq!(r.header("allow"), Some("GET, HEAD"));

        let r = request(a, "GET", "/api/health", &[], "").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, HEALTH.as_bytes());

        let _ = srv.stop.unwrap().send(());
        timeout(Duration::from_secs(5), srv.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn ui_dir_mode() {
        let srv = start_with(Some(PathBuf::from("../../ui/dist")), false).await;
        let a = srv.addr;
        let js = js_asset(&srv.table);
        for (path, status, html) in [
            ("/", 200, true),
            ("/dns/zones/example.com", 200, true),
            (&*format!("/{js}"), 200, false),
            ("/assets/missing-abc123.js", 404, false),
            ("/assets/", 404, false),
            ("/../Cargo.toml", 200, true),
        ] {
            let r = request(a, "GET", path, &[], "").await;
            assert_eq!(r.status, status, "{path}");
            assert_eq!(r.header("cache-control"), Some("no-cache"), "{path}");
            assert_eq!(
                r.header("x-content-type-options"),
                Some("nosniff"),
                "{path}"
            );
            if html {
                assert!(
                    r.header("content-type").unwrap().starts_with("text/html"),
                    "{path}"
                );
            }
        }
        let _ = srv.stop.unwrap().send(());
        timeout(Duration::from_secs(5), srv.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    async fn sse_roundtrip(path: &str, coalesce: bool) {
        let mut srv = start_with(None, coalesce).await;
        let a = srv.addr;
        let (mut s1, mut buf1) = open_sse(a, path, None).await;

        let r = request(
            a,
            "POST",
            "/api/events/emit",
            &[],
            r#"{"event":"lease.updated","data":{"ip":"192.0.2.10"}}"#,
        )
        .await;
        assert_eq!(r.status, 202);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let id = v["id"].as_u64().unwrap();
        assert_eq!(v["receivers"], 1);
        read_until(&mut s1, &mut buf1, b"192.0.2.10").await;
        let text = String::from_utf8_lossy(&buf1).into_owned();
        assert!(text.contains(&format!("id: {id}\n")), "{text}");
        assert!(text.contains("event: lease.updated\n"), "{text}");
        assert!(text.contains("data: {\"ip\":\"192.0.2.10\"}\n"), "{text}");

        // A second event, then a client that saw only the first one reconnects.
        let r = request(
            a,
            "POST",
            "/api/events/emit",
            &[],
            r#"{"event":"lease.updated","data":{"ip":"192.0.2.11"}}"#,
        )
        .await;
        assert_eq!(r.status, 202);
        let (mut s2, mut buf2) = open_sse(a, path, Some(id)).await;
        read_until(&mut s2, &mut buf2, b"192.0.2.11").await;
        assert!(
            !String::from_utf8_lossy(&buf2).contains("192.0.2.10"),
            "replay must start after Last-Event-ID"
        );

        // An id the server cannot replay yields a reset.
        let (mut s3, mut buf3) = open_sse(a, path, Some(1)).await;
        read_until(&mut s3, &mut buf3, b"reset").await;

        // Graceful shutdown ends every stream with a shutdown event and closes it.
        let _ = srv.stop.take().unwrap().send(());
        for (s, buf) in [
            (&mut s1, &mut buf1),
            (&mut s2, &mut buf2),
            (&mut s3, &mut buf3),
        ] {
            read_until(s, buf, b"event: shutdown").await;
            let mut rest = Vec::new();
            timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
                .await
                .expect("stream closes")
                .unwrap();
        }
        timeout(Duration::from_secs(5), srv.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn sse_raw() {
        sse_roundtrip("/api/events", false).await;
    }

    #[tokio::test]
    async fn sse_axum() {
        sse_roundtrip("/api/events/axum", false).await;
    }

    #[tokio::test]
    async fn sse_raw_coalesced() {
        sse_roundtrip("/api/events", true).await;
    }

    #[tokio::test]
    async fn sse_axum_coalesced() {
        sse_roundtrip("/api/events/axum", true).await;
    }
}
