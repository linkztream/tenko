//! The TLS service: the active mode, hot-swappable material and a watch channel for the
//! API listener (WP1.7) and the health view.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use aws_lc_rs::digest;
use rustls::ServerConfig;
use tenko_core::Timestamp;
use tokio::{sync::watch, time::MissedTickBehavior};
use zeroize::Zeroizing;

use super::{
    CertSource, ExpiryState, TlsError, TlsMaterial, TlsMode, TlsPolicy, TlsResolver, TlsStatus, tls,
};

/// Default interval at which imported files are checked for changes.
pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Shortest interval the watcher accepts; `tokio::time::interval` panics on zero.
const MIN_WATCH_INTERVAL: Duration = Duration::from_millis(1);

/// The TLS layer of the API listener. Cheap to clone; clones share state.
///
/// - [`server_config`](TlsService::server_config) is built once over a swapping resolver,
///   so modes a and b reload without restarting the listener.
/// - [`watch`](TlsService::watch) publishes a [`TlsStatus`] on every change of mode,
///   certificate or error; WP1.7 restarts its listener when the mode switches between
///   terminating TLS and reverse-proxy operation.
/// - Mode a: install the internal CA's material with
///   [`install`](TlsService::install) at start and after every renewal.
/// - Mode b: [`set_mode`](TlsService::set_mode) loads the files; the task from
///   [`spawn_watcher`](TlsService::spawn_watcher) reloads them when they change, and a
///   failed reload keeps the previous certificate while reporting the error.
#[derive(Debug, Clone)]
pub struct TlsService {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    resolver: Arc<TlsResolver>,
    config: Arc<ServerConfig>,
    status: watch::Sender<Arc<TlsStatus>>,
    /// Fingerprint of the imported files last loaded (mode b). The lock also serializes
    /// every change of mode and material (`set_mode`, `install`, `reload`), so a reload
    /// that is parsing files cannot install material after the mode has moved on.
    files: Mutex<Option<FileState>>,
}

/// What was last loaded successfully from the imported files.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileState {
    cert_path: PathBuf,
    key_path: PathBuf,
    digest: Vec<u8>,
}

impl TlsService {
    /// A service in `mode` with no material yet.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the policy.
    pub fn new(mode: TlsMode, policy: TlsPolicy) -> Result<Self, TlsError> {
        let resolver = Arc::new(TlsResolver::default());
        let config = tls::server_config(Arc::clone(&resolver) as _, policy)?;
        let (status, _) = watch::channel(Arc::new(TlsStatus {
            mode,
            certificate: None,
            last_error: None,
            loaded_at: None,
            revision: 0,
        }));
        Ok(Self {
            inner: Arc::new(Inner {
                resolver,
                config,
                status,
                files: Mutex::new(None),
            }),
        })
    }

    /// The server configuration for the listener (modes a and b). It follows every
    /// install and reload; without material, handshakes fail.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.inner.config)
    }

    /// The resolver behind [`server_config`](TlsService::server_config), for a listener
    /// that builds its own configuration.
    pub fn resolver(&self) -> Arc<TlsResolver> {
        Arc::clone(&self.inner.resolver)
    }

    /// Subscribes to status changes.
    pub fn watch(&self) -> watch::Receiver<Arc<TlsStatus>> {
        self.inner.status.subscribe()
    }

    /// The current status.
    pub fn status(&self) -> Arc<TlsStatus> {
        Arc::clone(&self.inner.status.borrow())
    }

    /// Switches the mode (settings change). Mode b loads its files now; mode c removes the
    /// material; mode a keeps whatever is installed until [`install`](TlsService::install).
    ///
    /// # Errors
    ///
    /// The load error of mode b; the mode still switches and the error is published.
    pub fn set_mode(&self, mode: TlsMode) -> Result<(), TlsError> {
        let mut files = self.lock_files();
        match mode {
            TlsMode::Imported { .. } => {
                self.update(|status| status.mode = mode);
                self.reload_locked(&mut files).map(drop)
            }
            TlsMode::ReverseProxy { .. } => {
                self.inner.resolver.set(None);
                *files = None;
                self.update(|status| {
                    status.mode = mode;
                    status.certificate = None;
                    status.loaded_at = None;
                    status.last_error = None;
                });
                Ok(())
            }
            TlsMode::InternalCa => {
                // The material stays; an error of the imported files no longer applies.
                *files = None;
                self.update(|status| {
                    status.mode = mode;
                    status.last_error = None;
                });
                Ok(())
            }
        }
    }

    /// Installs material (mode a after issue or renewal, or an upload).
    pub fn install(&self, material: TlsMaterial) {
        let mut files = self.lock_files();
        let info = material.info().clone();
        self.inner.resolver.set(Some(material));
        // The served material no longer comes from the files, so a later switch to mode b
        // (or the next poll in it) must read them again.
        *files = None;
        self.update(|status| {
            status.certificate = Some(info);
            status.loaded_at = Some(Timestamp::now());
            status.last_error = None;
        });
    }

    /// Re-reads the files of mode b now; returns whether new material was installed.
    /// Unchanged files are not parsed again. On failure the previous material keeps
    /// serving and the error is published.
    ///
    /// # Errors
    ///
    /// [`TlsError::NoLocalTls`] outside mode b, or the load error.
    pub fn reload(&self) -> Result<bool, TlsError> {
        let mut files = self.lock_files();
        self.reload_locked(&mut files)
    }

    /// Spawns a task that calls [`reload`](TlsService::reload) every `interval` while the
    /// mode is b. Needs a Tokio runtime; abort the handle to stop it.
    ///
    /// The task also logs a warning once whenever the served certificate (in any mode)
    /// moves into the warning, critical or expired state of its validity.
    pub fn spawn_watcher(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval.max(MIN_WATCH_INTERVAL));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut reported = None;
            loop {
                ticker.tick().await;
                if matches!(service.status().mode, TlsMode::Imported { .. }) {
                    // File reads and the certificate parse may block (network shares), so
                    // they run off the async workers. The lock lives inside the closure
                    // and is never held across an await.
                    let worker = service.clone();
                    match tokio::task::spawn_blocking(move || worker.reload()).await {
                        // A failed reload is already published and logged by `reload`.
                        Ok(_) => {}
                        Err(error) if error.is_cancelled() => break,
                        Err(error) => tracing::error!(%error, "TLS certificate reload panicked"),
                    }
                }
                service.report_expiry(&mut reported);
            }
        })
    }

    fn lock_files(&self) -> MutexGuard<'_, Option<FileState>> {
        self.inner
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `reload` with the `files` lock held by the caller.
    fn reload_locked(&self, files: &mut Option<FileState>) -> Result<bool, TlsError> {
        let TlsMode::Imported {
            cert_path,
            key_path,
        } = self.status().mode.clone()
        else {
            return Err(TlsError::NoLocalTls);
        };
        self.try_reload(&cert_path, &key_path, files)
            .inspect_err(|error| self.publish_failure(error, &cert_path, &key_path))
    }

    fn try_reload(
        &self,
        cert_path: &Path,
        key_path: &Path,
        files: &mut Option<FileState>,
    ) -> Result<bool, TlsError> {
        let cert = read_file(cert_path)?;
        let key = Zeroizing::new(read_file(key_path)?);
        let state = FileState {
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
            digest: fingerprint(&cert, &key),
        };
        if files.as_ref() == Some(&state) {
            // Back to the files that are being served (a failed edit was reverted): the
            // earlier failure no longer applies.
            if self.status().last_error.is_some() {
                self.update(|status| status.last_error = None);
            }
            return Ok(false);
        }
        let material = TlsMaterial::from_pem(
            &cert,
            &key,
            CertSource::Imported {
                cert_path: state.cert_path.clone(),
                key_path: state.key_path.clone(),
            },
        )?;
        let info = material.info().clone();
        self.inner.resolver.set(Some(material));
        *files = Some(state);
        tracing::info!(
            subject = %info.subject,
            serial = %info.serial,
            sha256 = %info.sha256,
            not_after = %info.not_after,
            cert_path = %cert_path.display(),
            "imported TLS certificate loaded"
        );
        self.update(|status| {
            status.certificate = Some(info);
            status.loaded_at = Some(Timestamp::now());
            status.last_error = None;
        });
        Ok(true)
    }

    /// Publishes a failed reload; a failure with the same text as the published one is
    /// neither logged nor counted again.
    fn publish_failure(&self, error: &TlsError, cert_path: &Path, key_path: &Path) {
        let text = error.to_string();
        if self.status().last_error.as_deref() == Some(text.as_str()) {
            return;
        }
        if self.inner.resolver.has_material() {
            tracing::warn!(
                error = %text,
                cert_path = %cert_path.display(),
                key_path = %key_path.display(),
                "reloading the imported TLS certificate failed; the previous certificate keeps serving"
            );
        } else {
            tracing::warn!(
                error = %text,
                cert_path = %cert_path.display(),
                key_path = %key_path.display(),
                "loading the imported TLS certificate failed; there is no certificate to serve"
            );
        }
        self.update(|status| status.last_error = Some(text));
    }

    /// Logs when the served certificate moved into a state that needs attention.
    /// `reported` remembers the certificate and state last looked at.
    fn report_expiry(&self, reported: &mut Option<(String, ExpiryState)>) {
        let status = self.status();
        let Some(info) = status.certificate.as_ref() else {
            *reported = None;
            return;
        };
        let expiry = info.expiry(Timestamp::now());
        let seen = (info.sha256.clone(), expiry.state);
        if reported.as_ref() == Some(&seen) {
            return;
        }
        match expiry.state {
            ExpiryState::Warning | ExpiryState::Critical => tracing::warn!(
                subject = %info.subject,
                days_left = expiry.days_left,
                state = ?expiry.state,
                not_after = %expiry.not_after,
                "the TLS certificate expires soon"
            ),
            ExpiryState::Expired => tracing::warn!(
                subject = %info.subject,
                days_left = expiry.days_left,
                state = ?expiry.state,
                not_after = %expiry.not_after,
                "the TLS certificate has expired"
            ),
            ExpiryState::Valid | ExpiryState::NotYetValid => {}
        }
        *reported = Some(seen);
    }

    /// Changes the status and publishes it with a bumped revision, unless nothing changed.
    fn update(&self, change: impl FnOnce(&mut TlsStatus)) {
        self.inner.status.send_if_modified(|status| {
            let mut next = TlsStatus::clone(status);
            change(&mut next);
            if next == **status {
                return false;
            }
            next.revision = status.revision + 1;
            *status = Arc::new(next);
            true
        });
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|error| TlsError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

/// SHA-256 over the certificate file, a separator (a zero byte and the certificate's
/// length, so the split between the two files is unambiguous) and the key file.
fn fingerprint(cert: &[u8], key: &[u8]) -> Vec<u8> {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(cert);
    context.update(&[0]);
    context.update(&u64::try_from(cert.len()).unwrap_or(u64::MAX).to_be_bytes());
    context.update(key);
    context.finish().as_ref().to_vec()
}
