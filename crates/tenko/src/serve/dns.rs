//! The `dns` role in the controller's process (plan section 2.10, ADR 0004, WP4.3).
//!
//! The start step `dns` runs after the API is up, when the node runs the role and the DNS
//! module is on:
//!
//! 1. The engine's metric families join the process registry.
//! 2. The role's derived index joins the store (`tenko_dns::store_feed`), which builds the
//!    first image of the `dns` tables from a local read; the catalog (index, views,
//!    forwarding rules) is built from it, aside from the async threads.
//! 3. The query log writer starts when `[dns.log] enabled`, and the plain forwarder
//!    (P2-Q16) with the upstreams of `[dns] forwarders`.
//! 4. The server binds every listen address for UDP and TCP and starts its workers: only now
//!    does the node answer, from a complete index.
//! 5. The writer of the catalog follows the feed: deltas in revision order, a reset after a
//!    snapshot install, each swapped in whole.
//!
//! A node without the role, or with the module off, starts nothing here. The role stops
//! first when the process stops: the listeners close, the queries in hand are answered, the
//! writer and the forwarder end and the query log is flushed, before the store closes.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tenko_core::{Role, metrics::Registry};
use tenko_dns::{
    authoritative::{Authoritative, Settings},
    catalog,
    cookie::CookieMode,
    forward::{ForwardSettings, PlainForwarder, PlainUpstream},
    log::QueryLogSink,
    querylog::{LogSettings, LogWriter},
    respond::ForwardSink,
    server::{Hooks, Server, ServerConfig},
    status::{DnsNode, LocalNode},
    store_feed,
    transport::{SocketMode, tcp::TcpSettings, udp::UdpSettings},
};
use tenko_store::Store;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::StartError;
use crate::config::{DnsCookies, DnsSection, DnsSocketMode, DnsUpstreamTransport, Resolved};

/// How long the role may take to stop its tasks.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this node runs the `dns` role: the role is listed and the DNS module is on.
pub(crate) fn runs(resolved: &Resolved, modules: tenko_api::modules::ModuleSet) -> bool {
    resolved.roles.contains(Role::Dns) && modules.contains(crate::modules::Module::Dns)
}

/// The running role.
pub(crate) struct DnsRole {
    node: Arc<LocalNode>,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    log: Option<LogWriter>,
    announce: String,
}

impl std::fmt::Debug for DnsRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsRole")
            .field("announce", &self.announce)
            .finish_non_exhaustive()
    }
}

/// What the start step needs.
pub(crate) struct Parts<'a> {
    pub(crate) resolved: &'a Resolved,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) metrics: &'a Registry,
}

fn error(code: &str, message: impl Into<String>) -> StartError {
    StartError::new("dns", code, message)
}

/// The engine's settings from `[dns]`.
fn server_config(section: &DnsSection, listen: Vec<SocketAddr>) -> ServerConfig {
    ServerConfig {
        listen,
        udp: UdpSettings {
            workers: section.worker_count(),
            mode: match section.udp.socket {
                DnsSocketMode::Auto => SocketMode::platform_default(),
                DnsSocketMode::Reuseport => SocketMode::ReusePort,
                DnsSocketMode::Shared => SocketMode::Shared,
            },
            recv_buffer: section.udp.recv_buffer,
            send_buffer: section.udp.send_buffer,
        },
        tcp: Some(TcpSettings {
            max_connections: section.tcp.max_connections,
            per_client: section.tcp.per_client,
            idle: Duration::from_secs(section.tcp.idle_secs),
        }),
        metrics: true,
        cookies: match section.cookies {
            DnsCookies::On => CookieMode::On,
            DnsCookies::Required => CookieMode::Required,
            DnsCookies::Off => CookieMode::Off,
        },
        edns_udp_size: section.edns.udp_size,
    }
}

fn upstreams(section: &DnsSection) -> Vec<PlainUpstream> {
    section
        .forwarders
        .iter()
        .map(|upstream| match upstream.transport {
            DnsUpstreamTransport::Udp => PlainUpstream::udp(upstream.socket_addr()),
            DnsUpstreamTransport::Tcp => PlainUpstream::tcp(upstream.socket_addr()),
        })
        .collect()
}

/// Logs the limit of a wildcard listen address (no `IP_PKTINFO`, `docs/dns.md` section 12).
fn note_wildcard(listen: &[SocketAddr]) {
    if listen.iter().any(|address| address.ip().is_unspecified()) {
        tracing::info!(
            "the dns role listens on a wildcard address: on a host with more than one address \
             on a network, an answer may leave from another address than the client asked; \
             list each address in [dns] listen in that case"
        );
    }
}

/// The query log writer, when `[dns.log] enabled`.
fn start_log(section: &DnsSection, resolved: &Resolved) -> Result<Option<LogWriter>, StartError> {
    if !section.log.enabled {
        return Ok(None);
    }
    let settings = LogSettings {
        dir: section.log_dir(&resolved.data_dir),
        days: section.log.days,
        size_mb: section.log.size_mb,
        sample: section.log.sample,
        pseudonymise: section.log.pseudonymise,
    };
    let dir = settings.dir.clone();
    LogWriter::start(settings).map(Some).map_err(|io| {
        error(
            "start.dns.log",
            format!("the query log directory {}: {io}", dir.display()),
        )
    })
}

/// The ready line and the step's summary.
fn describe(
    handle: &catalog::CatalogHandle,
    server: &Server,
    forwarder: &PlainForwarder,
    log: Option<&LogWriter>,
) -> (String, String) {
    let catalog = handle.load();
    let stats = catalog.index().stats();
    let revision = catalog.revision();
    let udp = server
        .udp_addresses()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let workers = server.config().udp.workers;
    let mode = server.config().udp.mode.as_str();
    let forwarding = if forwarder.upstreams().is_empty() {
        "no forwarder (names outside the zones are refused)".to_owned()
    } else {
        format!("forwarding to {} upstream(s)", forwarder.upstreams().len())
    };
    let logging = log.map_or_else(
        || "query log off".to_owned(),
        |writer| format!("query log in {}", writer.dir().display()),
    );
    let announce = format!(
        "dns role answering on {udp} (UDP and TCP), {} zone(s) at revision {revision}, \
         {forwarding}",
        stats.zones
    );
    let summary = format!(
        "{} zone(s), {} RRset(s) at revision {revision}, index bases {:.1} MiB; listening on \
         {udp} (UDP and TCP), {workers} UDP worker(s) per address ({mode}); {forwarding}; \
         {logging}",
        stats.zones,
        stats.base_rrsets,
        mib(stats.base_bytes)
    );
    (announce, summary)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "a size for the log, to a tenth of a MiB"
)]
fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Starts the role; see the module documentation for the order.
///
/// # Errors
///
/// `start.dns.feed` when the store cannot be read, `start.dns.log` when the query log
/// directory cannot be created, `start.dns.bind` when a listen address cannot be bound.
pub(crate) async fn start(parts: Parts<'_>) -> Result<(DnsRole, String), StartError> {
    let Parts {
        resolved,
        store,
        metrics,
    } = parts;
    let section = &resolved.config.dns;
    let listen = section
        .listen_addrs()
        .map_err(|problem| error("config.invalid", problem.to_string()))?;
    note_wildcard(&listen);
    tenko_dns::metrics::register(metrics);
    let mut feed = tokio::task::spawn_blocking(move || store_feed::register(store))
        .await
        .map_err(|join| error("start.dns.panic", join.to_string()))?
        .map_err(|store| error("start.dns.feed", store.to_string()))?;
    let progress = feed.progress();
    let handle = catalog::initial(&mut feed)
        .await
        .map_err(|feed| error("start.dns.feed", feed.to_string()))?;
    let stop = CancellationToken::new();
    let log = start_log(section, resolved)?;
    let sink: Option<Arc<dyn QueryLogSink>> = log
        .as_ref()
        .map(|writer| writer.sink() as Arc<dyn QueryLogSink>);
    let upstreams = upstreams(section);
    let default_forwarder = !upstreams.is_empty();
    let (forwarder, forward_task) = PlainForwarder::start(
        ForwardSettings {
            upstreams,
            timeout: Duration::from_millis(section.forward_timeout_ms),
            retries: section.forward_retries,
            udp_size: section.edns.udp_size,
            metrics: true,
        },
        handle.clone(),
        sink.clone(),
        stop.child_token(),
    );
    let resolver = Authoritative::new(handle.clone()).with_settings(Settings {
        recursion_available: default_forwarder,
        default_forwarder,
        ..Settings::default()
    });
    let config = server_config(section, listen);
    let hooks = Hooks {
        log: sink,
        forward: Some(Arc::clone(&forwarder) as Arc<dyn ForwardSink>),
        cookies: None,
    };
    let server = match Server::start(config, handle.clone(), resolver, hooks).await {
        Ok(server) => server,
        Err(io) => {
            stop.cancel();
            let _ = forward_task.await;
            if let Some(log) = log {
                let _ = tokio::task::spawn_blocking(move || log.stop()).await;
            }
            return Err(error(
                "start.dns.bind",
                format!(
                    "the dns role cannot listen on {}: {io}; port 53 needs \
                     CAP_NET_BIND_SERVICE on Linux (deploy/README.md), and another DNS server \
                     may hold the port",
                    section.listen.join(", ")
                ),
            ));
        }
    };
    let follow_stop = stop.clone();
    let follow_handle = handle.clone();
    let follower = tokio::spawn(async move {
        if let Err(error) = catalog::follow(feed, follow_handle, follow_stop).await {
            tracing::error!(%error, "the dns role stopped following the store; it keeps serving the rows it holds");
        }
    });
    let (announce, summary) = describe(&handle, &server, &forwarder, log.as_ref());
    let node = Arc::new(LocalNode::new(
        resolved.node_id,
        server,
        progress,
        Some(forwarder),
        log.as_ref()
            .map(|writer| (writer.sink(), writer.dir().to_path_buf())),
    ));
    Ok((
        DnsRole {
            node,
            stop,
            tasks: vec![follower, forward_task],
            log,
            announce,
        },
        summary,
    ))
}

impl DnsRole {
    /// The role as the API reaches it.
    pub(crate) fn node(&self) -> Arc<dyn DnsNode> {
        Arc::clone(&self.node) as Arc<dyn DnsNode>
    }

    /// The line `tenko serve` prints when it is ready.
    pub(crate) fn announce(&self) -> &str {
        &self.announce
    }

    /// Stops answering, then the writer, the forwarder and the query log.
    pub(crate) async fn stop(self) {
        let Self {
            node,
            stop,
            tasks,
            log,
            ..
        } = self;
        if let Some(server) = node.take_server() {
            server.stop().await;
        }
        stop.cancel();
        for mut task in tasks {
            if tokio::time::timeout(STOP_TIMEOUT, &mut task).await.is_err() {
                task.abort();
            }
        }
        if let Some(log) = log {
            let _ = tokio::task::spawn_blocking(move || log.stop()).await;
        }
    }
}
