//! The `dns` role in the controller's process (plan section 2.10, ADR 0004, WP4.3).
//!
//! The start step `dns` runs after the API is up, when the node runs the role and the DNS
//! module is on:
//!
//! 1. The engine's metric families join the process registry.
//! 2. The role's derived index joins the store (`tenko_dns::store_feed`), which builds the
//!    first image of the `dns` tables from a local read; the catalog (index, views,
//!    forwarding rules) is built from it, aside from the async threads.
//! 3. The query log writer starts when `[dns.log] enabled` (or, unset, the security
//!    profile: TGL-15) says so; the policy of RPZ zones and block lists (WP5.2) reads the
//!    catalog, and the rate limiter takes `[dns.limits]` under the profile in force
//!    (TGL-11); the forwarder (WP5.1) starts with
//!    the default upstreams of `[dns] forwarders`, the cache of `[dns.cache]` sized for the
//!    profile in force, and the recursion policy: the profile's default and the prefixes
//!    IPAM knows, which a follower keeps current from the store. The forwarder's answers
//!    pass the policy on their way to the client (`tenko_dns::policy::answer`).
//! 4. The server binds every listen address for UDP and TCP, and the DoT and DoH addresses
//!    of `[dns.tls]` with the certificate of the API's TLS mode or one of their own, and
//!    starts its workers: only now does the node answer, from a complete index.
//! 5. The writer of the catalog follows the feed: deltas in revision order, a reset after a
//!    snapshot install, each swapped in whole.
//!
//! A node without the role, or with the module off, starts nothing here. The role stops
//! first when the process stops: the listeners close, the queries in hand are answered, the
//! writer and the forwarder end and the query log is flushed, before the store closes.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::StreamExt as _;
use rustls::server::ResolvesServerCert;
use tenko_auth::{model::SETTINGS, settings::Profile};
use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService, TrustedProxies};
use tenko_core::{Role, dns::ForwardTransport, metrics::Registry};
use tenko_dns::{
    authoritative::{Authoritative, Settings},
    cache::CacheSettings,
    catalog,
    cookie::CookieMode,
    forward::{ForwardSettings, Forwarder, RecursionDefault, RecursionPolicy},
    log::QueryLogSink,
    policy::{Policy, PolicyEngine, answer::PolicySink},
    pool::UpstreamSpec,
    querylog::{ClientField, LogFormat, LogSettings, LogWriter},
    rate::{
        RateLimiter,
        limiter::{ClientLimit, LimitSettings, Limiter, RrlSettings},
    },
    respond::ForwardSink,
    server::{Hooks, Server, ServerConfig},
    status::{DnsNode, LocalNode},
    store_feed,
    tls::{Termination, TlsListen},
    transport::{SocketMode, tcp::TcpSettings, udp::UdpSettings},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::StartError;
use crate::config::{
    DnsCookies, DnsLogClient, DnsLogFormat, DnsSection, DnsSocketMode, DnsUpstreamTransport,
    Resolved,
};

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
    /// The file watcher of a certificate of DoT and DoH's own; aborted at the stop.
    watchers: Vec<JoinHandle<()>>,
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
    /// The API's TLS service: its certificate is DoT and DoH's unless they have their own.
    pub(crate) api_tls: TlsService,
    /// The protocol policy of the API (TLS 1.3 only under the Hardened profile).
    pub(crate) tls_policy: TlsPolicy,
    // WP6.1: zone transfers.
    /// The zone service and the secondary service the transfer path reads and notifies.
    pub(crate) transfers: Option<Transfers>,
}

// WP6.1: zone transfers out, NOTIFY in and the leader services of transfers.
/// What the transfer path reads and tells: the zone service, the secondary service, and
/// where NOTIFY out learns the revision the role serves.
#[derive(Clone)]
pub(crate) struct Transfers {
    zones: Arc<tenko_dns::zone::ZoneService>,
    secondaries: tenko_dns::zone::secondary::SecondaryService,
    served: tenko_dns::xfr::notify::ServedRevision,
}

impl Transfers {
    /// The secondary service, for the API.
    pub(crate) fn secondaries(&self) -> &tenko_dns::zone::secondary::SecondaryService {
        &self.secondaries
    }
}

/// Registers the leader services `dns.transfer` and `dns.notify` and returns what the API
/// and the role reach.
pub(crate) fn transfer_services(
    zones: &Arc<tenko_dns::zone::ZoneService>,
    section: &DnsSection,
    leaders: &super::leader::LeaderRegistry,
) -> Transfers {
    use tenko_dns::{xfr::notify, zone::secondary};
    let upstream_ca = section.upstream_ca.as_ref().and_then(|path| {
        std::fs::read(path)
            .map_err(|io| {
                tracing::warn!(path = %path.display(), %io, "dns.upstream_ca cannot be read; XoT primaries are checked against the system roots");
            })
            .ok()
    });
    let keys = Arc::new(secondary::KeyLoader::new(Arc::clone(zones)));
    let service = secondary::SecondaryService::new(
        Arc::clone(zones),
        Arc::clone(&keys),
        secondary::SecondarySettings {
            upstream_ca,
            ..secondary::SecondarySettings::default()
        },
    );
    leaders.register(Arc::new(service.clone()));
    let served = notify::ServedRevision::default();
    leaders.register(Arc::new(notify::NotifyService::new(
        Arc::clone(zones),
        keys,
        served.clone(),
        notify::NotifySettings::default(),
    )));
    Transfers {
        zones: Arc::clone(zones),
        secondaries: service,
        served,
    }
}

// WP6.2: the directory is shared with the update path.
/// The transfer path, the task that keeps its directory current, and the directory.
type TransferPath = (
    Arc<dyn tenko_dns::xfr::TransferSink>,
    JoinHandle<()>,
    Arc<tenko_dns::xfr::Directory>,
);

/// The transfer path of the role's listeners: the directory of zones and keys kept current
/// from the store, the index for AXFR, the journal for IXFR, NOTIFY to the secondary
/// service; and the task that keeps the directory current.
fn transfer_path(
    transfers: Option<&Transfers>,
    handle: &catalog::CatalogHandle,
    store: &Arc<dyn Store>,
    stop: CancellationToken,
) -> Option<TransferPath> {
    use tenko_dns::xfr::{self, out::XfrOut};
    let Transfers {
        zones,
        secondaries,
        served,
    } = transfers?;
    served.set(handle.clone());
    let directory = Arc::new(xfr::Directory::default());
    let task = tokio::spawn(Arc::clone(&directory).follow(Arc::clone(zones), stop));
    let path = XfrOut::new(
        handle.clone(),
        Arc::clone(&directory),
        Arc::new(xfr::StoreJournal::new(Arc::clone(store))),
        Arc::new(xfr::StoreAudit::new(Arc::clone(store))),
        Some(Arc::new(secondaries.clone()) as Arc<dyn xfr::NotifyHandler>),
    );
    Some((
        Arc::new(path) as Arc<dyn xfr::TransferSink>,
        task,
        directory,
    ))
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
        tls: None,
    }
}

/// The DoT and DoH side of the role, when `[dns.tls]` turns either on.
struct Encrypted {
    listen: TlsListen,
    certificates: Option<Arc<dyn ResolvesServerCert>>,
    watchers: Vec<JoinHandle<()>>,
    describe: String,
}

/// The listeners and the certificate of `[dns.tls]`: behind a proxy none; a certificate
/// of their own, loaded now and watched like the imported files of mode b; else the API's,
/// which follows its renewal or reload.
fn encrypted(
    resolved: &Resolved,
    listen: &[SocketAddr],
    api_tls: &TlsService,
    policy: TlsPolicy,
) -> Result<Option<Encrypted>, StartError> {
    let section = &resolved.config.dns.tls;
    if !section.enabled() {
        return Ok(None);
    }
    let (dot, doh) = section
        .addresses(listen)
        .map_err(|problem| error("config.invalid", problem.to_string()))?;
    let mut watchers = Vec::new();
    let (termination, certificates, source) = if section.behind_proxy {
        let trusted = TrustedProxies::parse(&resolved.config.tls.trusted_proxies)
            .map_err(|problem| error("config.invalid", problem.to_string()))?;
        (
            Termination::Proxy {
                trusted: trusted.networks().to_vec(),
                proxy_protocol: section.proxy_protocol,
            },
            None,
            if section.proxy_protocol {
                "TLS ends in the reverse proxy (PROXY protocol)".to_owned()
            } else {
                "TLS ends in the reverse proxy".to_owned()
            },
        )
    } else {
        let termination = Termination::Tls {
            tls13_only: policy.tls13_only,
        };
        if let (Some(cert_path), Some(key_path)) = (&section.certificate, &section.key) {
            let mode = TlsMode::Imported {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
            };
            let service = TlsService::new(mode.clone(), policy)
                .and_then(|service| service.set_mode(mode).map(|()| service))
                .map_err(|problem| {
                    error(
                        "start.dns.tls",
                        format!("the certificate of dns.tls.certificate: {problem}"),
                    )
                })?;
            watchers.push(service.spawn_watcher(Duration::from_secs(
                resolved.config.tls.watch_interval_secs.max(1),
            )));
            let own: Arc<dyn ResolvesServerCert> = service.resolver();
            (
                termination,
                Some(own),
                format!("certificate {}", cert_path.display()),
            )
        } else if api_tls.status().mode.terminates_tls() {
            let api: Arc<dyn ResolvesServerCert> = api_tls.resolver();
            (
                termination,
                Some(api),
                format!("the API's certificate ({})", api_tls.status().mode.name()),
            )
        } else {
            return Err(error(
                "start.dns.tls",
                "the API serves no certificate (its TLS ends in a reverse proxy), so DoT and \
                 DoH have none either; set dns.tls.certificate and dns.tls.key, or \
                 dns.tls.behind_proxy = true",
            ));
        }
    };
    let join = |addrs: &[SocketAddr]| {
        addrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut parts = Vec::new();
    if !dot.is_empty() {
        parts.push(format!("DoT on {}", join(&dot)));
    }
    if !doh.is_empty() {
        parts.push(format!("DoH on {}", join(&doh)));
    }
    let describe = format!("{} with {source}", parts.join(", "));
    Ok(Some(Encrypted {
        listen: TlsListen {
            dot,
            doh,
            termination,
            max_connections: section.max_connections,
            per_client: section.per_client,
            idle: Duration::from_secs(section.idle_secs),
            handshake_timeout: Duration::from_secs(section.handshake_timeout_secs),
            doh_streams: section.doh_streams,
        },
        certificates,
        watchers,
        describe,
    }))
}

fn upstreams(section: &DnsSection) -> Vec<UpstreamSpec> {
    section
        .forwarders
        .iter()
        .map(|upstream| UpstreamSpec {
            address: upstream.socket_addr(),
            transport: match upstream.transport {
                DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => ForwardTransport::Plain,
                DnsUpstreamTransport::Dot => ForwardTransport::Dot,
                DnsUpstreamTransport::Doh => ForwardTransport::Doh,
            },
            tcp_only: upstream.transport == DnsUpstreamTransport::Tcp,
            tls_name: upstream.tls_name.clone(),
            path: upstream.path.clone(),
        })
        .collect()
}

/// Who may recurse in a view without a recursion access list, by profile (TGL-22).
fn recursion_default(profile: Profile) -> RecursionDefault {
    match profile {
        Profile::Hardened => RecursionDefault::Nobody,
        Profile::Lab => RecursionDefault::Anyone,
        _ => RecursionDefault::KnownPrefixes,
    }
}

// WP6.2: the profile of the update policy (TGL-09).
/// The update policy's profile for the installation's profile.
fn update_profile_of(profile: Profile) -> tenko_dns::update::policy::UpdateProfile {
    use tenko_dns::update::policy::UpdateProfile;
    match profile {
        Profile::Home => UpdateProfile::Home,
        Profile::Standard => UpdateProfile::Standard,
        Profile::Hardened => UpdateProfile::Hardened,
        Profile::Lab => UpdateProfile::Lab,
    }
}

/// The settings of the forwarder from `[dns]` under `profile`.
fn forward_settings(
    section: &DnsSection,
    profile: Profile,
    upstream_ca: Option<Vec<u8>>,
) -> ForwardSettings {
    let cache = &section.cache;
    ForwardSettings {
        upstreams: upstreams(section),
        timeout: Duration::from_millis(section.forward_timeout_ms),
        retries: section.forward_retries,
        udp_size: section.edns.udp_size,
        metrics: true,
        cache: cache.enabled.then(|| CacheSettings {
            entries: cache.entries_for(profile),
            max_bytes: cache.max_bytes_for(profile),
            stale: Duration::from_secs(cache.stale_secs),
            max_ttl: cache.max_ttl_secs,
            negative_ttl: cache.negative_ttl_secs,
            prefetch: cache.prefetch,
        }),
        stale_budget: Duration::from_millis(cache.stale_answer_ms),
        upstream_ca,
        // WP10.1: set by `recursion_settings` at the start.
        recursion: None,
        // WP10.2: set at the start too.
        validation: None,
    }
}

// WP10.1: the recursive resolver's settings from `[dns.recursion]` under the profile.
/// The engine's settings of `[dns.recursion]` under `profile`, `None` when recursion is
/// off; a hints file that cannot be read stops the start.
fn recursion_settings(
    section: &DnsSection,
    profile: Profile,
) -> Result<Option<tenko_dns::recurse::EngineSettings>, StartError> {
    use tenko_dns::recursion::{
        InfraBounds, Minimisation, Outbound, RecursionSettings, WorkBudget,
    };
    let keys = &section.recursion;
    if !keys.enabled_for(profile) {
        return Ok(None);
    }
    if let Some(path) = &keys.hints {
        tenko_dns::recurse::hints::Hints::from_file(path)
            .map_err(|hints| error("config.invalid", format!("dns.recursion.hints: {hints}")))?;
    }
    let cuts = keys.infra_entries_for(profile);
    let defaults = RecursionSettings::default();
    let recursion = RecursionSettings {
        enabled: true,
        // WP10.2: TGL-12.
        validate: keys.validate_for(profile),
        outbound: match keys.outbound {
            crate::config::RecursionOutbound::Auto => Outbound::Auto,
            crate::config::RecursionOutbound::V4 => Outbound::V4,
            crate::config::RecursionOutbound::V6 => Outbound::V6,
            crate::config::RecursionOutbound::Both => Outbound::Both,
        },
        timeout: Duration::from_millis(keys.timeout_ms),
        budget: WorkBudget {
            queries: u16::try_from(keys.budget_queries).unwrap_or(u16::MAX),
            restarts: u8::try_from(keys.budget_restarts).unwrap_or(u8::MAX),
            depth: u8::try_from(keys.budget_depth).unwrap_or(u8::MAX),
            wall: Duration::from_millis(keys.budget_ms),
            ..WorkBudget::DEFAULT
        },
        infra: InfraBounds {
            cuts,
            servers: cuts.saturating_mul(2),
            ttl: Duration::from_secs(u64::from(keys.infra_ttl_secs)),
        },
        minimisation: match keys.qname_minimisation {
            crate::config::QnameMinimisation::Relaxed => Minimisation::Relaxed,
            crate::config::QnameMinimisation::Strict => Minimisation::Strict,
            crate::config::QnameMinimisation::Off => Minimisation::Off,
        },
        aggressive_nsec: keys.aggressive_nsec,
        denial_entries: keys.denial_entries_for(profile),
        failure_max: Duration::from_secs(u64::from(keys.failure_cache_max_secs)),
        signalling: keys.trust_anchor_signalling_for(profile),
        key_sentinel: keys.key_sentinel,
        fresh_port: keys.fresh_port_per_query,
        ..defaults
    };
    Ok(Some(tenko_dns::recurse::EngineSettings {
        recursion,
        hints: keys.hints.clone(),
        local_zones_except: keys
            .local_zones_except
            .iter()
            .filter_map(|name| tenko_core::dns::DnsName::new(name).ok())
            .collect(),
        metrics: true,
    }))
}
// WP10.1: end.

/// The CA file of `[dns] upstream_ca`, read at start.
fn upstream_ca(section: &DnsSection) -> Result<Option<Vec<u8>>, StartError> {
    section
        .upstream_ca
        .as_ref()
        .map(|path| {
            std::fs::read(path).map_err(|io| {
                error(
                    "config.invalid",
                    format!("dns.upstream_ca {}: {io}", path.display()),
                )
            })
        })
        .transpose()
}

/// The profile in force and the prefixes IPAM knows, read from the store.
async fn recursion_inputs(
    store: &dyn Store,
    bootstrap: Profile,
) -> Result<(Profile, Vec<ipnet::IpNet>), tenko_store::StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let profile = view
        .get_typed(&SETTINGS, &())?
        .map_or(bootstrap, |(settings, _)| settings.profile);
    let prefixes = view
        .scan_typed(
            &tenko_ipam::tables::PREFIXES,
            KeyRange::all(),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, prefix, _)| prefix.cidr)
        .collect();
    Ok((profile, prefixes))
}

/// Keeps the recursion policy current: the profile (it changes at setup) and the prefixes
/// IPAM knows, read again after every change of either table, until `stop`.
async fn follow_recursion(
    store: Arc<dyn Store>,
    bootstrap: Profile,
    policy: Arc<RecursionPolicy>,
    // WP6.2: the profile of the update policy.
    update_profile: Arc<tenko_dns::update::policy::ProfileCell>,
    stop: CancellationToken,
) {
    let filter = || {
        WatchFilter::tables([
            SETTINGS.name().clone(),
            tenko_ipam::tables::PREFIXES.name().clone(),
        ])
    };
    let mut stream = store.watch(None, filter()).ok();
    loop {
        let alive = tokio::select! {
            () = stop.cancelled() => return,
            alive = async {
                if let Some(stream) = &mut stream {
                    matches!(stream.next().await, Some(Ok(_)))
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    false
                }
            } => alive,
        };
        if !alive {
            stream = store.watch(None, filter()).ok();
        }
        match recursion_inputs(store.as_ref(), bootstrap).await {
            Ok((profile, prefixes)) => {
                policy.set_default(recursion_default(profile));
                update_profile.set(update_profile_of(profile));
                policy.set_prefixes(prefixes);
            }
            Err(error) => {
                tracing::warn!(%error, "the recursion policy could not be read from the store");
            }
        }
    }
}

/// The limiter of `[dns.limits]` under `profile`; the clients the recursion policy knows
/// are exempt with `exempt_known`.
fn limiter(
    section: &DnsSection,
    profile: Profile,
    recursion: &Arc<RecursionPolicy>,
) -> Result<(Limiter, String), StartError> {
    let limits = &section.limits;
    let effective = limits.effective(profile);
    let exempt = limits
        .exempt_prefixes()
        .map_err(|problem| error("config.invalid", problem.to_string()))?;
    let rrl = effective.rrl.then_some(RrlSettings {
        responses_per_second: effective.responses_per_second,
        errors_per_second: effective.errors_per_second,
        window_secs: limits.window_secs,
        slip: limits.slip,
        ipv4_prefix: limits.ipv4_prefix,
        ipv6_prefix: limits.ipv6_prefix,
    });
    let client = (effective.client_qps > 0).then_some(ClientLimit {
        queries_per_second: effective.client_qps,
        burst: effective.client_burst,
    });
    let describe = match (&rrl, &client) {
        (None, None) => "no rate limiting".to_owned(),
        (rrl, client) => {
            let mut parts = Vec::new();
            if let Some(rrl) = rrl {
                parts.push(format!(
                    "RRL {}/{} per second, slip {}",
                    rrl.responses_per_second, rrl.errors_per_second, rrl.slip
                ));
            }
            if let Some(client) = client {
                parts.push(format!(
                    "{} queries per second per client",
                    client.queries_per_second
                ));
            }
            parts.join(", ")
        }
    };
    let mut limiter = Limiter::new(LimitSettings {
        rrl,
        client,
        exempt,
        table: limits.table,
    });
    if limits.exempt_known {
        let recursion = Arc::clone(recursion);
        limiter = limiter.with_known_exempt(Arc::new(move |client: std::net::IpAddr| {
            client.is_loopback() || recursion.known(client)
        }));
    }
    Ok((limiter, describe))
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

/// The security profile the query log's defaults follow (TGL-15): the stored profile
/// after setup, else the bootstrap profile of the file.
async fn log_profile(resolved: &Resolved, store: &dyn Store) -> Profile {
    let stored = match store.read(ReadConsistency::Local).await {
        Ok(view) => view
            .get_typed(&SETTINGS, &())
            .ok()
            .flatten()
            .map(|(settings, _)| settings.profile),
        Err(_) => None,
    };
    stored.unwrap_or(resolved.config.profile.name)
}

/// The query log writer, when `[dns.log]` or the profile turns it on.
fn start_log(
    section: &DnsSection,
    resolved: &Resolved,
    profile: Profile,
) -> Result<Option<LogWriter>, StartError> {
    let effective = section.log.effective(profile);
    if !effective.enabled {
        return Ok(None);
    }
    let settings = LogSettings {
        dir: section.log_dir(&resolved.data_dir),
        format: match section.log.format {
            DnsLogFormat::Jsonl => LogFormat::Jsonl,
            DnsLogFormat::Dnstap => LogFormat::Dnstap,
        },
        days: effective.days,
        size_mb: section.log.size_mb,
        sample: section.log.sample,
        client: match (section.log.client, section.log.pseudonymise) {
            (DnsLogClient::Hidden, _) => ClientField::Hidden,
            (DnsLogClient::Logged, true) => ClientField::Pseudonym,
            (DnsLogClient::Logged, false) => ClientField::Address,
        },
        identity: format!("node-{}", resolved.node_id),
        version: env!("CARGO_PKG_VERSION").to_owned(),
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
    forwarder: &Forwarder,
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
    let rules = catalog.forward_rules().count() + catalog.stub_zones().count();
    let upstreams = if forwarder.upstreams().is_empty() {
        format!("{rules} forwarding rule(s) and stub zone(s), no default forwarder")
    } else {
        format!(
            "forwarding to {} default upstream(s) and {rules} rule(s) and stub zone(s)",
            forwarder.upstreams().len()
        )
    };
    let cache = forwarder.cache().map_or_else(
        || "no cache".to_owned(),
        |cache| format!("cache of {} entries", cache.settings().entries),
    );
    let forwarding = format!("{upstreams}, {cache}");
    let logging = log.map_or_else(
        || "query log off".to_owned(),
        |writer| {
            let figures = writer.sink().figures();
            format!(
                "query log in {} ({}, client {}, {} day(s){})",
                writer.dir().display(),
                figures.format.as_str(),
                figures.client.as_str(),
                figures.days,
                if figures.stopped {
                    ", stopped by dns.log.stop"
                } else {
                    ""
                }
            )
        },
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

/// The policy's part of the summary: RPZ zones and lists in force.
fn policy_line(handle: &catalog::CatalogHandle) -> String {
    let catalog = handle.load();
    let policy = catalog.policy();
    format!(
        "{} RPZ zone(s), {} block list(s) and {} allow list(s) in force",
        policy.zones().len(),
        policy.blocks().len(),
        policy.allows().len()
    )
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
#[allow(
    clippy::too_many_lines,
    reason = "the start steps in their order, each a few lines"
)]
pub(crate) async fn start(parts: Parts<'_>) -> Result<(DnsRole, String), StartError> {
    let Parts {
        resolved,
        store,
        metrics,
        api_tls,
        tls_policy,
        transfers,
    } = parts;
    let section = &resolved.config.dns;
    let listen = section
        .listen_addrs()
        .map_err(|problem| error("config.invalid", problem.to_string()))?;
    note_wildcard(&listen);
    // Before anything starts: a certificate that does not load stops the start here.
    let encrypted = encrypted(resolved, &listen, &api_tls, tls_policy)?;
    if encrypted.is_some() {
        tenko_dns::tls::register(metrics);
    }
    tenko_dns::metrics::register(metrics);
    tenko_dns::querylog::register_metrics(metrics);
    metrics.register(&tenko_dns::policy::counters::BLOCKED_FAMILY);
    tenko_dns::rate::limiter::register_metrics(metrics);
    tenko_dns::xfr::register_metrics(metrics);
    // WP6.2: the update families.
    tenko_dns::update::register_metrics(metrics);
    // WP10.1: the recursive resolver's families, when it runs.
    if section.recursion.enabled.unwrap_or(true) {
        tenko_dns::metrics::register_recursion(metrics);
    }
    let log_profile = log_profile(resolved, store.as_ref()).await;
    let feed_store = Arc::clone(&store);
    let mut feed = tokio::task::spawn_blocking(move || store_feed::register(feed_store))
        .await
        .map_err(|join| error("start.dns.panic", join.to_string()))?
        .map_err(|store| error("start.dns.feed", store.to_string()))?;
    let progress = feed.progress();
    let handle = catalog::initial(&mut feed)
        .await
        .map_err(|feed| error("start.dns.feed", feed.to_string()))?;
    let stop = CancellationToken::new();
    let upstream_ca = upstream_ca(section)?;
    let bootstrap = resolved.config.profile.name;
    let (profile, prefixes) = recursion_inputs(store.as_ref(), bootstrap)
        .await
        .map_err(|store| error("start.dns.feed", store.to_string()))?;
    let log = start_log(section, resolved, log_profile)?;
    let log_sink: Option<Arc<dyn QueryLogSink>> = log
        .as_ref()
        .map(|writer| writer.sink() as Arc<dyn QueryLogSink>);
    let recursion = Arc::new(RecursionPolicy::new(recursion_default(profile)));
    // WP6.2: the profile the update policy follows, kept current with the recursion's.
    let update_profile = Arc::new(tenko_dns::update::policy::ProfileCell::new(
        update_profile_of(profile),
    ));
    recursion.set_prefixes(prefixes);
    // WP10.1: the recursive resolver beside the forwarder, its flushes audited.
    let mut settings = forward_settings(section, profile, upstream_ca);
    settings.recursion = recursion_settings(section, profile)?;
    // WP10.2: the validator (TGL-12) with the profile's bound on key sets, and the
    // resolver the leader's trust anchor service asks in process, with the Lab hold-down.
    if section.recursion.validate_for(profile) {
        settings.validation = Some(tenko_dns::forward::ValidationSettings {
            key_sets: section.recursion.infra_entries_for(profile),
            ..tenko_dns::forward::ValidationSettings::default()
        });
    }
    let (forwarder, forward_task) = Forwarder::start(
        settings,
        handle.clone(),
        log_sink.clone(),
        Arc::clone(&recursion),
        stop.child_token(),
    );
    forwarder.set_audit(Arc::new(tenko_dns::xfr::StoreAudit::new(Arc::clone(
        &store,
    ))));
    if let Some(engine) = forwarder.engine() {
        let caps = forwarder
            .validator()
            .map_or(tenko_dns::recursion::ValidationCaps::DEFAULT, |validator| {
                validator.caps()
            });
        super::leader::ANCHOR_WIRING.set_resolver(
            Arc::new(tenko_dns::anchors::NodeResolver::new(
                Arc::clone(engine),
                Arc::clone(forwarder.anchors()) as Arc<dyn tenko_dns::recursion::TrustAnchors>,
                caps,
            )),
            section.recursion.rfc5011_hold_down_secs,
        );
    }
    // WP10.2: end.
    // WP10.1: end.
    let (limiter, limits_line) = limiter(section, profile, &recursion)?;
    let recursion_task = tokio::spawn(follow_recursion(
        Arc::clone(&store),
        bootstrap,
        recursion,
        Arc::clone(&update_profile),
        stop.child_token(),
    ));
    // The policy decides on every name outside the zones and on every forwarded answer.
    let policy: Arc<dyn PolicyEngine> = Arc::new(Policy);
    let rate: Arc<dyn RateLimiter> = Arc::new(limiter);
    let sink = PolicySink::new(
        Arc::clone(&forwarder) as Arc<dyn ForwardSink>,
        handle.clone(),
        Arc::clone(&policy),
        tokio::runtime::Handle::current(),
    );
    // Every name outside the zones goes to the forwarder, which refuses it when no rule,
    // stub zone or default upstream covers it, or the client may not recurse.
    let resolver = Authoritative::new(handle.clone())
        .with_settings(Settings {
            recursion_available: true,
            default_forwarder: true,
            ..Settings::default()
        })
        .with_policy(policy)
        .with_rate_limiter(rate);
    let mut config = server_config(section, listen);
    let mut certificates = None;
    let mut watchers = Vec::new();
    let mut listening = section.listen.join(", ");
    let mut encrypted_line = None;
    if let Some(encrypted) = encrypted {
        listening = format!("{listening} ({})", encrypted.describe);
        config.tls = Some(encrypted.listen);
        certificates = encrypted.certificates;
        watchers = encrypted.watchers;
        encrypted_line = Some(encrypted.describe);
    }
    let transfer_path = transfer_path(transfers.as_ref(), &handle, &store, stop.child_token());
    // WP6.2: the update path, with the zone service, the keys of the transfer path's
    // directory and the policy under the profile in force (TGL-09).
    let update_path =
        transfer_path
            .as_ref()
            .zip(transfers.as_ref())
            .map(|((_, _, directory), transfers)| {
                Arc::new(tenko_dns::update::UpdatePath::new(
                    handle.clone(),
                    Arc::clone(directory),
                    Arc::clone(&transfers.zones),
                    Arc::clone(&update_profile),
                    Arc::new(tenko_dns::xfr::StoreAudit::new(Arc::clone(&store))),
                    stop.child_token(),
                )) as Arc<dyn tenko_dns::update::UpdateSink>
            });
    let hooks = Hooks {
        log: log_sink,
        forward: Some(Arc::new(sink) as Arc<dyn ForwardSink>),
        cookies: None,
        certificates,
        transfers: transfer_path.as_ref().map(|(path, _, _)| Arc::clone(path)),
        updates: update_path,
    };
    let server = match Server::start(config, handle.clone(), resolver, hooks).await {
        Ok(server) => server,
        Err(io) => {
            stop.cancel();
            for watcher in &watchers {
                watcher.abort();
            }
            let _ = forward_task.await;
            let _ = recursion_task.await;
            if let Some(log) = log {
                let _ = tokio::task::spawn_blocking(move || log.stop()).await;
            }
            return Err(error(
                "start.dns.bind",
                format!(
                    "the dns role cannot listen on {listening}: {io}; ports below 1024 (53, \
                     853, 443) need CAP_NET_BIND_SERVICE on Linux (deploy/README.md), and \
                     another server may hold the port"
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
    let (mut announce, mut summary) = describe(&handle, &server, &forwarder, log.as_ref());
    summary = format!("{summary}; {limits_line}; {}", policy_line(&handle));
    if let Some(line) = encrypted_line {
        announce = format!("{announce}; {line}");
        summary = format!("{summary}; {line}");
    }
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
            tasks: [follower, forward_task, recursion_task]
                .into_iter()
                .chain(transfer_path.map(|(_, task, _)| task))
                .collect(),
            log,
            watchers,
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
            watchers,
            ..
        } = self;
        if let Some(server) = node.take_server() {
            server.stop().await;
        }
        for watcher in watchers {
            watcher.abort();
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

// WP6.3: the DNSSEC signer.

/// Starts the DNSSEC signer on the controllers (ADR 0018): the leader-only service
/// `dns.signer`, whose timer re-signs zones before their signatures expire, and the step
/// handlers of the rollover job `dns.dnssec.rollover`.
pub(crate) fn start_signer(
    zones: &Arc<tenko_dns::zone::ZoneService>,
    vault: &Arc<tenko_vault::StoreVault>,
    engine: &mut tenko_jobs::JobEngine,
    leaders: &super::leader::LeaderRegistry,
) {
    let signer = tenko_dns::dnssec::Signer::new(
        Arc::clone(zones),
        Arc::clone(vault) as Arc<dyn tenko_vault::Vault>,
        tenko_dns::dnssec::SignerConfig::default(),
    );
    for handler in tenko_dns::dnssec::rollover::step_handlers(&signer) {
        engine.register(handler);
    }
    leaders.register(signer.leader_service());
}
