//! The server of the `dns` role: the sockets, the workers, the catalog swap and the cookie
//! secret in one value with a start and a graceful stop (the role start step of WP4.3 calls
//! them).
//!
//! [`Server::start`] binds every listen address for UDP and TCP before it starts anything,
//! so a port in use fails the start and leaves nothing running; then it starts the UDP
//! workers, the TCP accept loops and the daily rotation of the cookie secret.
//! [`Server::stop`] stops accepting, lets the UDP workers finish the query in hand (they
//! see the stop within [`udp::STOP_POLL`]), closes the TCP connections after their current
//! query, and waits for all of it.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

use crate::{
    authoritative::Authoritative,
    catalog::CatalogHandle,
    cookie::{CookieMode, CookieSecret},
    log::QueryLogSink,
    resolver::Resolver,
    respond::{ForwardSink, Responder},
    transport::{
        WorkerLayout, WorkerSlot,
        tcp::{self, Limits, TcpSettings},
        udp::{self, UdpSettings},
    },
};

/// How often the cookie secret is replaced (RFC 9018 suggests monthly at most; a node
/// rotates daily and keeps the previous secret valid).
pub const COOKIE_ROTATION: Duration = Duration::from_secs(24 * 60 * 60);

/// How long [`Server::stop`] waits for open TCP connections to close.
const DRAIN: Duration = Duration::from_secs(2);

/// The settings of a server; the `[dns]` keys of the configuration (WP4.3) map onto them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// The addresses to listen on, for UDP and TCP (`listen`).
    pub listen: Vec<SocketAddr>,
    /// The UDP workers (`workers`) and their sockets.
    pub udp: UdpSettings,
    /// The TCP limits (`tcp.max_connections`, `tcp.per_client`, `tcp.idle_secs`); `None`
    /// serves UDP only.
    pub tcp: Option<TcpSettings>,
    /// Count queries and their latency (OPS-21; switched off only to measure its cost).
    pub metrics: bool,
    /// How cookies are used.
    pub cookies: CookieMode,
    /// The EDNS UDP size (`edns.udp_size`): the largest UDP answer and the size advertised,
    /// 512 to 4096, 1232 by default (DNS flag day 2020).
    pub edns_udp_size: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec![
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
            ],
            udp: UdpSettings::default(),
            tcp: Some(TcpSettings::default()),
            metrics: true,
            cookies: CookieMode::On,
            edns_udp_size: crate::wire::SERVER_UDP_PAYLOAD,
        }
    }
}

/// What a server is given besides its settings.
#[derive(Default, Clone)]
pub struct Hooks {
    /// The query log; none when it is off.
    pub log: Option<Arc<dyn QueryLogSink>>,
    /// The forwarder's intake; without one, queries the resolver forwards get SERVFAIL.
    pub forward: Option<Arc<dyn ForwardSink>>,
    /// The cookie secret; a random one when absent.
    pub cookies: Option<CookieSecret>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field("log", &self.log.is_some())
            .field("forward", &self.forward.is_some())
            .field("cookies", &self.cookies.is_some())
            .finish()
    }
}

/// A running DNS server.
#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    catalog: CatalogHandle,
    cookies: CookieSecret,
    stop_flag: Arc<AtomicBool>,
    cancel: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    slots: Vec<WorkerSlot>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    udp: Vec<SocketAddr>,
    tcp: Vec<SocketAddr>,
    limits: Arc<Limits>,
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_string())
}

impl Server {
    /// Starts the authoritative resolver on `catalog`.
    ///
    /// # Errors
    ///
    /// As [`Server::start`].
    pub async fn start_authoritative(
        config: ServerConfig,
        catalog: CatalogHandle,
        hooks: Hooks,
    ) -> io::Result<Self> {
        let resolver = Authoritative::new(catalog.clone());
        Self::start(config, catalog, resolver, hooks).await
    }

    /// Binds every listener and starts the workers. Must run inside a tokio runtime (the
    /// TCP side and the cookie rotation are tasks of it).
    ///
    /// # Errors
    ///
    /// An address that cannot be bound, no listen address, no worker, or a failing random
    /// generator for the cookie secret; nothing keeps running then.
    pub async fn start<R: Resolver + 'static>(
        config: ServerConfig,
        catalog: CatalogHandle,
        resolver: R,
        hooks: Hooks,
    ) -> io::Result<Self> {
        if config.listen.is_empty() {
            return Err(invalid("no listen address"));
        }
        if config.udp.workers == 0 {
            return Err(invalid("at least one worker"));
        }
        let cookies = match hooks.cookies {
            Some(cookies) => cookies,
            None => CookieSecret::random()
                .map_err(|_| io::Error::other("the random generator failed"))?,
        };
        let mut responder = Responder::new(resolver, cookies.clone())
            .with_cookie_mode(config.cookies)
            .with_udp_size(config.edns_udp_size)
            .with_metrics(config.metrics);
        if let Some(log) = hooks.log {
            responder = responder.with_log(log);
        }
        if let Some(forward) = hooks.forward {
            responder = responder.with_forwarder(forward);
        }
        let responder = Arc::new(responder);
        // Bind everything first: a failure leaves nothing running.
        let mut bound = Vec::with_capacity(config.listen.len());
        let mut listeners = Vec::new();
        for address in &config.listen {
            let udp = udp::bind(*address, &config.udp)?;
            if config.tcp.is_some() {
                listeners.push(tcp::bind(udp.local)?);
            }
            bound.push(udp);
        }
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let limits = Arc::new(Limits::default());
        let mut server = Self {
            udp: bound.iter().map(|bound| bound.local).collect(),
            tcp: listeners
                .iter()
                .filter_map(|listener| listener.local_addr().ok())
                .collect(),
            config,
            catalog,
            cookies,
            stop_flag,
            cancel,
            threads: Vec::new(),
            slots: Vec::new(),
            tasks: Vec::new(),
            limits,
        };
        for socket_set in &bound {
            match udp::spawn(
                socket_set,
                &server.config.udp,
                &responder,
                &server.stop_flag,
                server.slots.len(),
            ) {
                Ok(workers) => {
                    for (thread, slot) in workers {
                        server.threads.push(thread);
                        server.slots.push(slot);
                    }
                }
                Err(error) => {
                    server.stop().await;
                    return Err(error);
                }
            }
        }
        if let Some(settings) = server.config.tcp {
            for listener in listeners {
                server.tasks.push(tokio::spawn(tcp::serve(
                    listener,
                    Arc::clone(&responder),
                    Arc::clone(&server.limits),
                    settings,
                    server.cancel.clone(),
                )));
            }
        }
        server.tasks.push(tokio::spawn(rotate_cookies(
            server.cookies.clone(),
            server.cancel.clone(),
        )));
        Ok(server)
    }

    /// The UDP addresses bound (with the ports the system chose for port 0).
    pub fn udp_addresses(&self) -> &[SocketAddr] {
        &self.udp
    }

    /// The TCP addresses bound.
    pub fn tcp_addresses(&self) -> &[SocketAddr] {
        &self.tcp
    }

    /// The catalog swap the server answers from: the role's writer stores into it.
    pub fn catalog(&self) -> &CatalogHandle {
        &self.catalog
    }

    /// The node's cookie secret.
    pub fn cookies(&self) -> &CookieSecret {
        &self.cookies
    }

    /// The settings it runs with.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The workers, their sockets and counters, and the TCP connections (ADR 0009).
    pub fn layout(&self) -> WorkerLayout {
        WorkerLayout {
            mode: self.config.udp.mode,
            workers_per_address: self.config.udp.workers,
            udp: self
                .slots
                .iter()
                .enumerate()
                .map(|(index, slot)| slot.view(index))
                .collect(),
            tcp: self.tcp.clone(),
            tcp_open: self.limits.open(),
            tcp_refused: self.limits.refused(),
        }
    }

    /// Stops accepting, finishes the queries in hand and waits for every worker.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        self.stop_flag.store(true, Ordering::Relaxed);
        let threads = std::mem::take(&mut self.threads);
        let _ = tokio::task::spawn_blocking(move || {
            for thread in threads {
                let _ = thread.join();
            }
        })
        .await;
        for task in std::mem::take(&mut self.tasks) {
            let _ = task.await;
        }
        let deadline = Instant::now() + DRAIN;
        while self.limits.open() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // A server dropped without stop still lets its workers end.
        self.cancel.cancel();
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

async fn rotate_cookies(cookies: CookieSecret, stop: CancellationToken) {
    let mut ticks = tokio::time::interval(COOKIE_ROTATION);
    ticks.tick().await;
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticks.tick() => {
                // A failing generator keeps the old secret until the next day.
                let _ = cookies.rotate();
            }
        }
    }
}
