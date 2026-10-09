//! The TLS step of `tenko serve`: the mode of OPS-22, the internal CA's server certificate
//! with its renewal task (mode a), the file watcher (mode b) and the trusted proxies
//! (mode c).

use std::{sync::Arc, time::Duration};

use futures::StreamExt as _;
use tenko_auth::{
    model::{INSTALLATION, SETTINGS},
    settings::Profile,
};
use tenko_cluster::ca::{
    CaPolicy, DEFAULT_WATCH_INTERVAL, InternalCa, ServerIdentity, TlsMode, TlsPolicy, TlsService,
    TrustedProxies,
};
use tenko_core::{RequestCtx, principal::SystemComponent};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tenko_vault::StoreVault;
use tokio::{sync::watch, task::JoinHandle, time::MissedTickBehavior};

use super::StartError;
use crate::config::{Resolved, TlsSpec};

/// What the TLS step produced.
pub(super) struct TlsSetup {
    /// The TLS layer of the listener.
    pub service: TlsService,
    /// Its protocol policy.
    pub policy: TlsPolicy,
    /// Plain HTTP from any source (Lab only).
    pub lab_plain_http: bool,
    /// The profile in force: the stored one after setup, else the bootstrap one.
    pub profile: Profile,
    /// Whether clients reach the listener over HTTPS (directly or through the proxy).
    pub https: bool,
    /// One line for the start log.
    pub summary: String,
    /// Background tasks that end when the stop signal is set (renewal).
    pub tasks: Vec<JoinHandle<()>>,
    /// Background tasks that are aborted at shutdown (the file and expiry watcher).
    pub watchers: Vec<JoinHandle<()>>,
}

/// Brings up the TLS layer.
pub(super) async fn start(
    resolved: &Resolved,
    store: &Arc<dyn Store>,
    vault: &Arc<StoreVault>,
    stop: &watch::Receiver<bool>,
) -> Result<TlsSetup, StartError> {
    let profile = effective_profile(resolved, store.as_ref()).await?;
    let policy = TlsPolicy {
        tls13_only: resolved.config.tls.tls13_only || profile == Profile::Hardened,
    };
    let base = TlsSetup {
        service: TlsService::new(TlsMode::InternalCa, policy)
            .map_err(|error| StartError::coded("tls", &error))?,
        policy,
        lab_plain_http: false,
        profile,
        https: true,
        summary: String::new(),
        tasks: Vec::new(),
        watchers: Vec::new(),
    };
    match &resolved.tls {
        TlsSpec::InternalCa { .. } => internal_ca(base, resolved, store, vault, stop).await,
        TlsSpec::Imported {
            cert_path,
            key_path,
        } => imported(
            base,
            TlsMode::Imported {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
            },
            watch_interval(resolved),
        ),
        TlsSpec::ReverseProxy {
            trusted_proxies,
            proxy_protocol,
            public_host,
        } => {
            let summary = format!(
                "TLS terminates in a reverse proxy for {public_host}; trusted proxies: {}{}",
                trusted_proxies
                    .networks()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                if *proxy_protocol {
                    " (PROXY protocol)"
                } else {
                    ""
                }
            );
            let mode = TlsMode::ReverseProxy {
                trusted_proxies: trusted_proxies.clone(),
                proxy_protocol: *proxy_protocol,
                public_host: public_host.clone(),
            };
            switch(&base.service, mode)?;
            Ok(TlsSetup { summary, ..base })
        }
        TlsSpec::Plain => {
            if profile != Profile::Lab {
                return Err(StartError::new(
                    "tls",
                    "start.tls.plain_not_allowed",
                    format!(
                        "tls.mode = \"plain\" is allowed under the Lab profile only (TGL-08),                          and the stored profile is `{}`; choose another tls.mode",
                        profile.as_str()
                    ),
                ));
            }
            let public_host = resolved
                .config
                .tls
                .host_name
                .clone()
                .unwrap_or_else(|| "localhost".to_owned());
            let mode = TlsMode::ReverseProxy {
                trusted_proxies: TrustedProxies::default(),
                proxy_protocol: false,
                public_host,
            };
            switch(&base.service, mode)?;
            Ok(TlsSetup {
                lab_plain_http: true,
                https: false,
                summary: "PLAIN HTTP from every source (Lab profile, TGL-08)".to_owned(),
                ..base
            })
        }
    }
}

fn switch(service: &TlsService, mode: TlsMode) -> Result<(), StartError> {
    service
        .set_mode(mode)
        .map_err(|error| StartError::coded("tls", &error))
}

fn watch_interval(resolved: &Resolved) -> Duration {
    Duration::from_secs(resolved.config.tls.watch_interval_secs)
        .max(Duration::from_millis(1))
        .min(DEFAULT_WATCH_INTERVAL * 720)
}

/// Mode a: the internal CA, its server certificate, the CA root file and the renewal task.
async fn internal_ca(
    base: TlsSetup,
    resolved: &Resolved,
    store: &Arc<dyn Store>,
    vault: &Arc<StoreVault>,
    stop: &watch::Receiver<bool>,
) -> Result<TlsSetup, StartError> {
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = InternalCa::load_or_init(store.as_ref(), vault.as_ref(), &ctx, CaPolicy::default())
        .await
        .map_err(|error| StartError::coded("tls", &error))?;
    let root = resolved.layout().ca_root();
    write_root(&root, &ca.root_pem())?;
    let identity = identity(resolved, store.as_ref()).await?;
    let material = ca
        .server_material(store.as_ref(), vault.as_ref(), &ctx, &identity)
        .await
        .map_err(|error| StartError::coded("tls", &error))?;
    let not_after = material.info().not_after;
    base.service.install(material);
    let summary = format!(
        "internal CA, certificate for {} until {not_after}; CA root at {}",
        identity.host_name,
        root.display()
    );
    let renewal = tokio::spawn(renew(
        Renewal {
            ca,
            store: Arc::clone(store),
            vault: Arc::clone(vault),
            service: base.service.clone(),
            resolved: resolved.clone(),
            interval: Duration::from_secs(
                resolved.config.tls.renew_check_hours.saturating_mul(3_600),
            ),
        },
        stop.clone(),
    ));
    let watcher = base.service.spawn_watcher(watch_interval(resolved));
    Ok(TlsSetup {
        summary,
        tasks: vec![renewal],
        watchers: vec![watcher],
        ..base
    })
}

/// Mode b: the imported files, loaded now (a failure stops the start) and watched.
fn imported(base: TlsSetup, mode: TlsMode, interval: Duration) -> Result<TlsSetup, StartError> {
    switch(&base.service, mode)?;
    let summary = match &base.service.status().certificate {
        Some(info) => format!(
            "imported certificate {} until {}, watched every {} s",
            info.subject,
            info.not_after,
            interval.as_secs()
        ),
        None => "imported certificate".to_owned(),
    };
    let watcher = base.service.spawn_watcher(interval);
    Ok(TlsSetup {
        summary,
        watchers: vec![watcher],
        ..base
    })
}

/// The stored profile after setup, else the bootstrap profile of the file.
async fn effective_profile(resolved: &Resolved, store: &dyn Store) -> Result<Profile, StartError> {
    let view = store
        .read(ReadConsistency::Local)
        .await
        .map_err(|error| StartError::coded("tls", &error))?;
    let stored = view
        .get_typed(&SETTINGS, &())
        .map_err(|error| StartError::coded("tls", &error))?
        .map(|(settings, _)| settings.profile);
    let bootstrap = resolved.config.profile.name;
    match stored {
        Some(profile) => {
            if profile != bootstrap {
                tracing::info!(
                    stored = profile.as_str(),
                    file = bootstrap.as_str(),
                    "the stored security profile applies; profile.name of the configuration file \
                     is used before first-run setup only"
                );
            }
            Ok(profile)
        }
        None => Ok(bootstrap),
    }
}

/// The names of the server certificate: the host name from setup (or the configured one
/// before setup), the configured host name as an extra name, and the configured extras.
async fn identity(resolved: &Resolved, store: &dyn Store) -> Result<ServerIdentity, StartError> {
    let TlsSpec::InternalCa {
        host_name,
        alt_names,
        addresses,
    } = &resolved.tls
    else {
        return Err(StartError::new(
            "tls",
            "start.tls.mode",
            "the internal CA serves mode a only",
        ));
    };
    let view = store
        .read(ReadConsistency::Local)
        .await
        .map_err(|error| StartError::coded("tls", &error))?;
    let installed = view
        .get_typed(&INSTALLATION, &())
        .map_err(|error| StartError::coded("tls", &error))?
        .map(|(installation, _)| installation.host_name);
    let primary = installed.unwrap_or_else(|| host_name.clone());
    let mut identity = ServerIdentity::new(primary.clone());
    if *host_name != primary {
        identity = identity.with_name(host_name.clone());
    }
    for name in alt_names {
        if *name != primary && *name != *host_name {
            identity = identity.with_name(name.clone());
        }
    }
    for address in addresses {
        identity = identity.with_address(*address);
    }
    Ok(identity)
}

/// Writes the public CA root for admin clients (`tenko --ca-file`, browsers).
fn write_root(path: &std::path::Path, pem: &str) -> Result<(), StartError> {
    let io = |error: std::io::Error| {
        StartError::new(
            "tls",
            "start.tls.ca_root",
            format!("cannot write the CA root to {}: {error}", path.display()),
        )
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    if std::fs::read_to_string(path).is_ok_and(|current| current == pem) {
        return Ok(());
    }
    std::fs::write(path, pem).map_err(io)
}

/// What the renewal task needs.
struct Renewal {
    ca: InternalCa,
    store: Arc<dyn Store>,
    vault: Arc<StoreVault>,
    service: TlsService,
    resolved: Resolved,
    interval: Duration,
}

/// Mode a: checks the server certificate every `interval` (daily by default) and whenever
/// the installation record changes (the host name of first-run setup), and installs a new
/// one when the stored certificate is due for renewal or no longer matches the names.
async fn renew(renewal: Renewal, mut stop: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(renewal.interval.max(Duration::from_secs(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    let filter = || WatchFilter::tables([INSTALLATION.name().clone()]);
    let mut changes = renewal.store.watch(None, filter()).ok();
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticker.tick() => {}
            change = next_change(&mut changes) => {
                if change.is_none() {
                    // The stream ended or lagged: subscribe again; the ticker still runs.
                    changes = renewal.store.watch(None, filter()).ok();
                    continue;
                }
            }
        }
        if *stop.borrow() {
            return;
        }
        refresh(&renewal).await;
    }
}

/// The next change of the installation table; pending forever without a stream.
async fn next_change(changes: &mut Option<tenko_store::ChangeStream>) -> Option<()> {
    match changes {
        Some(stream) => match stream.next().await {
            Some(Ok(_)) => Some(()),
            Some(Err(_)) | None => None,
        },
        None => std::future::pending().await,
    }
}

async fn refresh(renewal: &Renewal) {
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let identity = match identity(&renewal.resolved, renewal.store.as_ref()).await {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(%error, "server certificate check skipped");
            return;
        }
    };
    match renewal
        .ca
        .server_material(
            renewal.store.as_ref(),
            renewal.vault.as_ref(),
            &ctx,
            &identity,
        )
        .await
    {
        Ok(material) => {
            let current = renewal
                .service
                .status()
                .certificate
                .as_ref()
                .map(|info| info.sha256.clone());
            if current.as_deref() != Some(material.info().sha256.as_str()) {
                tracing::info!(
                    host = %identity.host_name,
                    not_after = %material.info().not_after,
                    "installed a new server certificate from the internal CA"
                );
                renewal.service.install(material);
            }
        }
        Err(error) => {
            tracing::error!(%error, "the server certificate could not be renewed");
        }
    }
}
