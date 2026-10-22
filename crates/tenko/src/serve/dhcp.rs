//! The `dhcp` role in the controller's process (plan sections 2.5 and 2.10, ADR 0004,
//! WP7.5).
//!
//! The start step `dhcp` runs after the `dns` step, when the node runs the role and the
//! DHCP module is on (`tenko_dhcp::role` says what each part does):
//!
//! 1. The role's metric families join the process registry under the contracts' names.
//! 2. The in-process feed joins the store; the configuration image and the lease table are
//!    built from its first image, aside from the async threads.
//! 3. The committer of the lease store starts on the replicated store, with the refusal
//!    gate of P3-Q14 in front of it.
//! 4. The listeners of `[dhcp] listen` bind and the workers start: only now does the node
//!    answer, from complete tables. A snapshot install later resets both tables at once.
//! 5. The leader services `dhcp.expiry` (bindings that ran out, over the role's table) and
//!    `dhcp.history.purge` (the retention of P3-Q13) are registered; on one controller they
//!    run at once.
//! 6. A follower keeps the profile current: the history retention and whether conflict
//!    detection is expected (TGL-16, the health row `dhcp.probe.missing`).
//!
//! The role stops first with the `dns` role when the process stops: the listeners close,
//! the workers end, the follower and the committer stop, before the store closes. A module
//! change stops the process with status 12, as for every role.

use std::{sync::Arc, time::Duration};

use futures::StreamExt as _;
use tenko_auth::{model::SETTINGS, settings::Profile};
use tenko_core::{NodeId, Role, metrics::Registry};
use tenko_dhcp::{
    lease::{
        CommitSettings, ExpiryService, ExpirySettings, HistoryProfile, HistoryRetention,
        PurgeService, PurgeSettings,
    },
    role::{self as dhcp_role, LocalNode, RoleSettings},
    server::{Listen, ServerConfig},
    v4::engine::{EngineSettings, ListenMode},
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{StartError, leader::LeaderRegistry};
use crate::config::{DhcpListenMode, DhcpSection, Resolved};

/// Whether this node runs the `dhcp` role: the role is listed and the DHCP module is on.
pub(crate) fn runs(resolved: &Resolved, modules: tenko_api::modules::ModuleSet) -> bool {
    resolved.roles.contains(Role::Dhcp) && modules.contains(crate::modules::Module::Dhcp)
}

/// The running role.
pub(crate) struct DhcpRole {
    role: dhcp_role::Role,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    announce: String,
}

impl std::fmt::Debug for DhcpRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpRole")
            .field("announce", &self.announce)
            .finish_non_exhaustive()
    }
}

/// What the start step needs.
pub(crate) struct Parts<'a> {
    pub(crate) resolved: &'a Resolved,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) metrics: &'a Registry,
    pub(crate) leaders: &'a LeaderRegistry,
    // WP8.3: the zone service the DDNS worker writes through; none without the DNS module.
    pub(crate) zones: Option<Arc<tenko_dns::zone::ZoneService>>,
}

fn error(code: &str, message: impl Into<String>) -> StartError {
    StartError::new("dhcp", code, message)
}

/// The history retention's profile for the installation's profile.
fn history_profile(profile: Profile) -> HistoryProfile {
    match profile {
        Profile::Home => HistoryProfile::Home,
        Profile::Standard => HistoryProfile::Standard,
        Profile::Hardened => HistoryProfile::Hardened,
        Profile::Lab => HistoryProfile::Lab,
    }
}

/// Whether the profile expects conflict detection and warns without a probe (TGL-16).
fn probe_expected(profile: Profile) -> bool {
    profile == Profile::Hardened
}

// WP8.3: the DDNS worker with the profile's defaults of P3-Q6, read from the system
// settings at every batch, and the retries of `[dhcp.ddns]`.
fn ddns_service(
    store: &Arc<dyn Store>,
    zones: Arc<tenko_dns::zone::ZoneService>,
    bootstrap: Profile,
    section: &DhcpSection,
) -> Arc<tenko_dhcp::ddns::DdnsService> {
    use tenko_dhcp::ddns::DdnsProfile;
    let profile: tenko_dhcp::ddns::ProfileSource = Arc::new(move |view| {
        let profile = view
            .get_typed(&SETTINGS, &())
            .ok()
            .flatten()
            .map_or(bootstrap, |(settings, _)| settings.profile);
        match profile {
            Profile::Home => DdnsProfile::HOME,
            Profile::Standard => DdnsProfile::STANDARD,
            Profile::Hardened => DdnsProfile::HARDENED,
            Profile::Lab => DdnsProfile::LAB,
        }
    });
    Arc::new(tenko_dhcp::ddns::DdnsService::new(
        Arc::clone(store),
        zones,
        profile,
        tenko_dhcp::ddns::DdnsSettings {
            retries: section.ddns.retries,
            backoff: Duration::from_millis(section.ddns.backoff_ms),
            ..tenko_dhcp::ddns::DdnsSettings::default()
        },
    ))
}

/// The listeners and the engine's settings from `[dhcp]`.
pub(crate) fn server_config(section: &DhcpSection, node: NodeId) -> ServerConfig {
    ServerConfig {
        listen: section
            .listen
            .iter()
            .map(|listen| Listen {
                address: section.socket_addr(listen),
                mode: match listen.mode {
                    DhcpListenMode::Relay => ListenMode::Relay,
                    DhcpListenMode::Direct => ListenMode::Direct,
                },
                interface: listen.interface.clone(),
            })
            .collect(),
        workers: section.worker_count(),
        engine: EngineSettings {
            offer_secs: section.offer_secs,
            decline_hold_secs: section.decline.hold_secs,
            relay_port: section.relay_port,
            client_port: section.client_port,
        },
        node,
        // WP8.4: the ProxyDHCP listeners of `[dhcp] proxy`.
        proxy: section
            .proxy
            .iter()
            .map(|address| std::net::SocketAddrV4::new(*address, section.proxy_port))
            .collect(),
        ..ServerConfig::default()
    }
}

/// The profile in force: the stored one after setup, else the bootstrap profile.
async fn profile_of(store: &dyn Store, bootstrap: Profile) -> Profile {
    match store.read(ReadConsistency::Local).await {
        Ok(view) => view
            .get_typed(&SETTINGS, &())
            .ok()
            .flatten()
            .map_or(bootstrap, |(settings, _)| settings.profile),
        Err(_) => bootstrap,
    }
}

/// Keeps the retention's profile and the probe expectation current until `stop`.
async fn follow_profile(
    store: Arc<dyn Store>,
    bootstrap: Profile,
    retention: Arc<HistoryRetention>,
    node: Arc<LocalNode>,
    stop: CancellationToken,
) {
    let filter = || WatchFilter::tables([SETTINGS.name().clone()]);
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
        let profile = profile_of(store.as_ref(), bootstrap).await;
        retention.set_profile(history_profile(profile));
        node.set_probe_expected(probe_expected(profile));
    }
}

/// The ready line and the step's summary.
fn describe(node: &LocalNode, section: &DhcpSection) -> (String, String) {
    use tenko_dhcp::role::DhcpNode as _;
    let status = node.status();
    let leases: usize = status.leases.iter().map(|(_, count)| count).sum();
    let listening = if status.listeners.is_empty() {
        "no listener ([dhcp] listen is empty)".to_owned()
    } else {
        status
            .listeners
            .iter()
            .map(|listener| {
                let mode = match listener.mode {
                    ListenMode::Relay => "relay".to_owned(),
                    ListenMode::Direct => match (&listener.interface, listener.link_layer) {
                        (Some(interface), true) => {
                            format!("direct on {interface}, link-layer replies")
                        }
                        (Some(interface), false) => {
                            format!("direct on {interface}, broadcast replies")
                        }
                        (None, _) => "direct, broadcast replies".to_owned(),
                    },
                };
                format!("{} ({mode})", listener.address)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let announce = format!(
        "dhcp role answering on {listening}, {} scope(s) at revision {}, {leases} lease row(s)",
        status.scopes, status.revision
    );
    let summary = format!(
        "{} scope(s) at revision {}, {leases} lease row(s); listening on {listening}, {} \
         worker(s) per listener; offers held {} s, declined addresses {} s",
        status.scopes,
        status.revision,
        section.worker_count(),
        section.offer_secs,
        section.decline.hold_secs
    );
    (announce, summary)
}

/// Starts the role; see the module documentation for the order.
///
/// # Errors
///
/// `start.dhcp.feed` when the store cannot be read, `start.dhcp.bind` when a listener
/// cannot be bound.
#[allow(
    clippy::too_many_lines,
    reason = "the start steps in their order, each a few lines"
)]
pub(crate) async fn start(parts: Parts<'_>) -> Result<(DhcpRole, String), StartError> {
    let Parts {
        resolved,
        store,
        metrics,
        leaders,
        // WP8.3: the zone service of the DDNS worker.
        zones,
    } = parts;
    let section = &resolved.config.dhcp;
    dhcp_role::metrics::register(metrics);
    let bootstrap = resolved.config.profile.name;
    let profile = profile_of(store.as_ref(), bootstrap).await;
    // WP8.5: conflict detection (plan section 2.7, TGL-16): the in-process probe when the
    // probe role runs, else none, said once per start (the health row `dhcp.probe.missing`
    // follows the profile below).
    let mut server = server_config(section, resolved.node_id);
    server.conflict = tenko_dhcp::conflict::ConflictSettings {
        probe: tenko_dhcp::conflict::scan::choose(resolved.roles.contains(Role::Probe)),
        profile_default: profile != Profile::Lab,
        cap: Duration::from_millis(section.probe.timeout_ms),
        cache: Duration::from_secs(section.probe.cache_secs),
        pending: section.probe.pending,
        decline_limit: section.decline.limit,
        decline_window: Duration::from_secs(section.decline.window_secs),
        ..tenko_dhcp::conflict::ConflictSettings::default()
    };
    // End of the WP8.5 block.
    let settings = RoleSettings {
        server,
        commit: CommitSettings::default(),
        probe: resolved.roles.contains(Role::Probe),
        probe_expected: probe_expected(profile),
    };
    // WP8.1: the lease batch carries the IPAM facts of the source `dhcp:<node>` (plan
    // section 2.8), from the hook over the stored facts; its outcomes are counted.
    metrics.register(&tenko_dhcp::lease::observe::LEASE_FACTS);
    let hook = tenko_dhcp::lease::observe::IpamObservations::register(
        store.as_ref(),
        resolved.node_id,
        tenko_ipam::observe::ObserveConfig::default(),
    )
    .map_err(|problem| error("start.dhcp.feed", problem.to_string()))?;
    let node_id = resolved.node_id;
    let role = dhcp_role::Role::start_observed(Arc::clone(&store), node_id, settings, hook)
        .await
        .map_err(|problem| match problem {
            dhcp_role::StartError::Feed(detail) => error("start.dhcp.feed", detail),
            dhcp_role::StartError::Bind(io) => error(
                "start.dhcp.bind",
                format!(
                    "the dhcp role cannot listen on {}: {io}; port 67 needs \
                     CAP_NET_BIND_SERVICE on Linux, direct mode also CAP_NET_RAW \
                     (deploy/systemd/dhcp-direct.conf), the address must be one of this \
                     host's, and another DHCP server may hold the port",
                    section
                        .listen
                        .iter()
                        .map(|listen| section.socket_addr(listen).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
        })?;
    let node = role.node();
    dhcp_role::metrics::install(Arc::clone(&node));
    leaders.register(Arc::new(
        ExpiryService::new(
            Arc::clone(&store),
            resolved.node_id,
            ExpirySettings::default(),
        )
        .with_table(node.leases().clone()),
    ));
    let retention = Arc::new(HistoryRetention::new(
        history_profile(profile),
        section.history.days,
    ));
    leaders.register(Arc::new(PurgeService::new(
        Arc::clone(&store),
        Arc::clone(&retention),
        PurgeSettings::default(),
    )));
    // WP8.3: the DDNS worker `dhcp.ddns` (ADR 0020): it follows the lease rows and writes
    // the names through the zone service; the profile's defaults of P3-Q6 are read from
    // the system settings at every batch. Without the DNS module there is no DDNS.
    if let Some(zones) = zones {
        leaders.register(ddns_service(&store, zones, bootstrap, section));
    } else {
        tracing::info!("DDNS from DHCP needs the DNS module; the dhcp role writes no names");
    }
    let stop = CancellationToken::new();
    let follower = tokio::spawn(follow_profile(
        Arc::clone(&store),
        bootstrap,
        retention,
        Arc::clone(&node),
        stop.child_token(),
    ));
    let (announce, summary) = describe(&node, section);
    if section.listen.is_empty() {
        tracing::warn!(
            "the dhcp role runs without a listener: set [dhcp] listen in tenko.toml to answer \
             DHCP requests"
        );
    }
    Ok((
        DhcpRole {
            role,
            stop,
            tasks: vec![follower],
            announce,
        },
        summary,
    ))
}

impl DhcpRole {
    /// The role as the API reaches it.
    pub(crate) fn node(&self) -> Arc<dyn tenko_dhcp::role::DhcpNode> {
        self.role.node() as Arc<dyn tenko_dhcp::role::DhcpNode>
    }

    /// The line `tenko serve` prints when it is ready.
    pub(crate) fn announce(&self) -> &str {
        &self.announce
    }

    /// Stops answering, then the follower and the committer.
    pub(crate) async fn stop(self) {
        let Self {
            role, stop, tasks, ..
        } = self;
        dhcp_role::metrics::clear();
        stop.cancel();
        role.stop().await;
        for mut task in tasks {
            if tokio::time::timeout(Duration::from_secs(10), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DhcpListen, DhcpSection};

    #[test]
    fn the_section_becomes_the_server_settings() {
        let section = DhcpSection {
            listen: vec![
                DhcpListen {
                    address: "192.0.2.10".parse().expect("address"),
                    mode: DhcpListenMode::Relay,
                    interface: None,
                },
                DhcpListen {
                    address: "198.51.100.1".parse().expect("address"),
                    mode: DhcpListenMode::Direct,
                    interface: Some("eth1".to_owned()),
                },
            ],
            port: 6767,
            workers: 3,
            relay_port: 6868,
            ..DhcpSection::default()
        };
        let config = server_config(&section, NodeId(4));
        assert_eq!(config.listen.len(), 2);
        assert_eq!(
            config.listen[0].address,
            "192.0.2.10:6767".parse().expect("address")
        );
        assert_eq!(config.listen[1].mode, ListenMode::Direct);
        assert_eq!(config.listen[1].interface.as_deref(), Some("eth1"));
        assert_eq!(config.workers, 3);
        assert_eq!(config.engine.relay_port, 6868);
        assert_eq!(config.engine.client_port, 68);
        assert_eq!(config.engine.offer_secs, 10);
        assert_eq!(config.node, NodeId(4));
    }

    #[test]
    fn hardened_expects_a_probe_and_the_history_follows_the_profile() {
        assert!(probe_expected(Profile::Hardened));
        assert!(!probe_expected(Profile::Home));
        assert_eq!(history_profile(Profile::Lab).default_days(), 7);
        assert_eq!(history_profile(Profile::Home).default_days(), 30);
    }
}
