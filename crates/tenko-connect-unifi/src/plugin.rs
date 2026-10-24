//! The plugin's services: the health check, the inventory and the network controller.
//!
//! Every call starts from nothing: it reads the settings and secrets of its context, builds
//! the HTTP client with the instance's TLS mode, detects the deployment when it is `auto`,
//! logs in (classic API) or presents the key (Integration API), does its work and logs out.

use std::{net::IpAddr, time::Instant};

use tenko_connect::{
    CallContext, Connector, ConnectorError, Cursor, Health, HealthReport, InventoryBatch,
    InventorySource, L2Change, L2Plan, L2Receipt, NetworkController, TopologySnapshot, WriteMode,
};
use tenko_core::Timestamp;

use crate::{
    classic::Session,
    detect::{self, Detected},
    http::Http,
    integration,
    model::{self, Local, Read},
    settings::{self, Config, Credentials},
    write,
};

/// The UniFi plugin.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unifi;

/// The setup of one call.
struct Call {
    config: Config,
    http: Http,
    detected: Detected,
    credentials: Credentials,
}

impl Call {
    async fn open(ctx: &CallContext) -> Result<Self, ConnectorError> {
        let config = settings::config(ctx)?;
        let credentials = settings::credentials(ctx)?;
        let http = Http::new(&config)?;
        if config.insecure() {
            log(
                "WARN",
                ctx,
                "this instance talks to the controller without a certificate check or without encryption",
            );
        }
        let detected = detect::detect(&http, config.deployment).await?;
        Ok(Self {
            config,
            http,
            detected,
            credentials,
        })
    }

    async fn login(&self) -> Result<Session, ConnectorError> {
        match &self.credentials {
            Credentials::Account { username, password } => {
                Session::login(
                    &self.http,
                    self.detected.paths,
                    &self.config.site,
                    username,
                    password,
                )
                .await
            }
            Credentials::ApiKey(_) => Err(ConnectorError::Unsupported),
        }
    }

    fn key(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::ApiKey(key) => Some(key.as_str()),
            Credentials::Account { .. } => None,
        }
    }
}

fn log(level: &str, ctx: &CallContext, message: &str) {
    eprintln!("{level} [{}] {message}", ctx.request_id);
}

/// Runs `work` in a logged-in session and logs out afterwards, whatever the outcome.
macro_rules! in_session {
    ($call:expr, |$session:ident| $work:expr) => {{
        let mut $session = $call.login().await?;
        let outcome = $work;
        $session.logout().await;
        outcome
    }};
}

async fn read_classic(session: &mut Session) -> Result<Read, ConnectorError> {
    Ok(Read {
        devices: session.devices().await?,
        clients: session.clients().await?,
        networks: session.networks().await?,
        wlans: session.wlans().await?,
        profiles: session.profiles().await?,
    })
}

/// The controller's addresses and the addresses Tenko reaches it from.
async fn local_view(config: &Config) -> Local {
    let port = config.base.port_or_known_default().unwrap_or(443);
    let host = config
        .base
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let connect = config.tls.connect_address.as_deref().and_then(|text| {
        text.trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok()
    });
    let controller: Vec<IpAddr> = match (connect, host.parse::<IpAddr>()) {
        (Some(ip), _) | (None, Ok(ip)) => vec![ip],
        (None, Err(_)) if !host.is_empty() => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
            .unwrap_or_default(),
        (None, Err(_)) => Vec::new(),
    };
    let mut tenko: Vec<IpAddr> = controller
        .iter()
        .filter_map(|ip| {
            let any: IpAddr = if ip.is_ipv4() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                IpAddr::from([0u16; 8])
            };
            // Connecting a UDP socket sends nothing; it only picks the local address.
            let socket = std::net::UdpSocket::bind((any, 0)).ok()?;
            socket.connect((*ip, port)).ok()?;
            socket.local_addr().ok().map(|addr| addr.ip())
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    tenko.sort();
    tenko.dedup();
    Local { controller, tenko }
}

#[async_trait::async_trait]
impl Connector for Unifi {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        let started = Instant::now();
        let config = settings::config(ctx)?;
        if config.fingerprint_missing() {
            // Show the operator the certificate to pin; nothing else can be checked yet.
            let mut probe = config.clone();
            probe.tls.mode = tenko_connect::sdk::http::TlsMode::Insecure;
            let seen = match Http::new(&probe) {
                Ok(http) => http.web().presented_fingerprint().await,
                Err(_) => None,
            };
            return Ok(HealthReport {
                health: Health::Degraded,
                checked_at: Timestamp::now(),
                latency_ms: None,
                remote_version: None,
                detail: Some(match seen {
                    Some(seen) => format!(
                        "set `tls_fingerprint` to the SHA-256 fingerprint the controller presents: {seen}"
                    ),
                    None => {
                        "set `tls_fingerprint`; the controller presented no certificate".to_owned()
                    }
                }),
            });
        }
        let call = Call::open(ctx).await?;
        let mut notes = vec![format!(
            "{}, {} API, site `{}`",
            call.detected.paths.describe(),
            if call.credentials.is_account() {
                "classic"
            } else {
                "Integration"
            },
            call.config.site
        )];
        let version = if let Some(key) = call.key() {
            let api = integration::Api::new(&call.http, call.detected.paths, key);
            api.site(&call.config.site).await?;
            notes.push("read-only: devices, uplinks, clients without ports or SSIDs, and from Network 10 the networks with their VLANs; writes need the local account".to_owned());
            api.version().await.ok().flatten()
        } else {
            in_session!(call, |session| {
                let sites = session.sites().await;
                let version = session.version().await;
                match sites {
                    Ok(sites) if !sites.iter().any(|s| s == &call.config.site) => {
                        Err(ConnectorError::invalid_settings(format!(
                            "the account sees no site `{}`",
                            call.config.site
                        )))
                    }
                    Ok(_) => Ok(version.ok().flatten()),
                    Err(error) => Err(error),
                }
            })?
        }
        .or_else(|| call.detected.version.clone());
        let insecure = call.config.insecure();
        notes.extend(call.http.web().notes());
        if insecure
            && call.config.base.scheme() == "https"
            && let Some(seen) = call.http.web().presented_fingerprint().await
        {
            notes.push(format!(
                "the controller presents the certificate with SHA-256 fingerprint {seen}; pin it with tls = fingerprint"
            ));
        }
        Ok(HealthReport {
            health: if insecure {
                Health::Degraded
            } else {
                Health::Healthy
            },
            checked_at: Timestamp::now(),
            latency_ms: u64::try_from(started.elapsed().as_millis()).ok(),
            remote_version: version,
            detail: Some(notes.join("; ")),
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for Unifi {
    async fn poll(
        &self,
        ctx: &CallContext,
        _cursor: Option<Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        let call = Call::open(ctx).await?;
        let hosts = if let Some(key) = call.key() {
            let api = integration::Api::new(&call.http, call.detected.paths, key);
            let site = api.site(&call.config.site).await?;
            integration::inventory(&api.read(&site).await?)
        } else {
            let read = in_session!(call, |session| read_classic(&mut session).await)?;
            model::inventory(&read)
        };
        Ok(InventoryBatch::complete(Timestamp::now(), hosts))
    }
}

#[async_trait::async_trait]
impl NetworkController for Unifi {
    async fn topology(&self, ctx: &CallContext) -> Result<TopologySnapshot, ConnectorError> {
        let call = Call::open(ctx).await?;
        if let Some(key) = call.key() {
            let api = integration::Api::new(&call.http, call.detected.paths, key);
            let site = api.site(&call.config.site).await?;
            let read = api.read(&site).await?;
            let local = local_view(&call.config).await;
            return Ok(integration::topology(&read, &local, Timestamp::now()));
        }
        let read = in_session!(call, |session| read_classic(&mut session).await)?;
        let local = local_view(&call.config).await;
        Ok(model::topology(&read, &local, Timestamp::now()))
    }

    async fn plan(&self, ctx: &CallContext, change: &L2Change) -> Result<L2Plan, ConnectorError> {
        let call = Call::open(ctx).await?;
        in_session!(call, |session| write::plan(&mut session, change).await)
    }

    async fn apply(
        &self,
        ctx: &CallContext,
        plan: &L2Plan,
        mode: WriteMode,
    ) -> Result<L2Receipt, ConnectorError> {
        let call = Call::open(ctx).await?;
        let receipt = in_session!(call, |session| write::apply(&mut session, plan, mode).await)?;
        if mode == WriteMode::Apply && !receipt.plan.diff.is_empty() {
            log(
                "INFO",
                ctx,
                &format!(
                    "applied a {} change; read-back {}",
                    change_kind(&plan.change),
                    if receipt.verified {
                        "matches"
                    } else {
                        "DIFFERS"
                    }
                ),
            );
        }
        Ok(receipt)
    }

    async fn revert(&self, ctx: &CallContext, receipt: &L2Receipt) -> Result<(), ConnectorError> {
        let call = Call::open(ctx).await?;
        in_session!(call, |session| write::revert(&mut session, receipt).await)?;
        log(
            "INFO",
            ctx,
            &format!("reverted a {} change", change_kind(&receipt.plan.change)),
        );
        Ok(())
    }
}

fn change_kind(change: &L2Change) -> &'static str {
    match change {
        L2Change::EnsureNetwork { .. } => "network",
        L2Change::SetPortProfile { .. } => "port profile",
        L2Change::SetClientVlan { .. } => "client VLAN",
        L2Change::ClearClientVlan { .. } => "client VLAN removal",
        L2Change::RemoveNetwork { .. } => "network removal",
    }
}
