//! Tests of the TLS service: loading imported certificates, hot reload by hand and by the
//! watcher task, the three modes, expiry reporting and real in-memory TLS handshakes
//! against the service's server configuration.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use aws_lc_rs::digest;
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConnection,
    pki_types::{CertificateDer, ServerName},
};
use tenko_cluster::ca::{
    CertSource, ExpiryState, TlsError, TlsMaterial, TlsMode, TlsPolicy, TlsService, TlsStatus,
    TrustedProxies,
};
use tenko_core::Timestamp;
use time::OffsetDateTime;
use tracing::{
    Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

const HOST: &str = "tenko.example";
const WAIT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

/// A self-signed certificate for [`HOST`] with its key.
struct Identity {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

impl Identity {
    /// Valid since yesterday for 90 days.
    fn new() -> Self {
        Self::valid_between(days_from_now(-1), days_from_now(90))
    }

    /// Valid since 30 days ago, until `days` from now (negative: already expired).
    fn expiring_in(days: i64) -> Self {
        Self::valid_between(days_from_now(-30), days_from_now(days))
    }

    fn valid_between(not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        let mut params = CertificateParams::new(vec![HOST.to_owned()]).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, HOST.to_owned());
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self-signed certificate");
        Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    fn sha256(&self) -> String {
        hex(digest::digest(&digest::SHA256, &self.der).as_ref())
    }

    fn material(&self) -> TlsMaterial {
        TlsMaterial::from_pem(
            self.cert_pem.as_bytes(),
            self.key_pem.as_bytes(),
            CertSource::Inline,
        )
        .expect("material")
    }
}

fn days_from_now(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::days(days)
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a string");
        out
    })
}

/// A unique directory below the system temp directory, removed on drop.
struct TestDir {
    root: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "tenko-tls-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create the test directory");
        Self { root }
    }

    fn cert_path(&self) -> PathBuf {
        self.root.join("server.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.root.join("server.key")
    }

    fn mode(&self) -> TlsMode {
        TlsMode::Imported {
            cert_path: self.cert_path(),
            key_path: self.key_path(),
        }
    }

    /// Writes both files in place.
    fn write(&self, identity: &Identity) {
        fs::write(self.cert_path(), &identity.cert_pem).expect("write the certificate");
        fs::write(self.key_path(), &identity.key_pem).expect("write the key");
    }

    /// Replaces both files the way deployment tools do: write beside, rename over.
    fn replace(&self, identity: &Identity) {
        for (path, content) in [
            (self.cert_path(), &identity.cert_pem),
            (self.key_path(), &identity.key_pem),
        ] {
            let mut name = path.file_name().expect("file name").to_owned();
            name.push(".new");
            let staging = path.with_file_name(name);
            fs::write(&staging, content).expect("write the staging file");
            fs::rename(&staging, &path).expect("rename over the live file");
        }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn service(mode: TlsMode) -> TlsService {
    TlsService::new(mode, TlsPolicy::default()).expect("service")
}

/// An imported-mode service that has loaded `identity` from a fresh directory.
fn loaded(identity: &Identity) -> (TestDir, TlsService) {
    let dir = TestDir::new();
    dir.write(identity);
    let service = service(dir.mode());
    service.set_mode(dir.mode()).expect("initial load");
    (dir, service)
}

fn served_leaf(service: &TlsService) -> CertificateDer<'static> {
    service
        .resolver()
        .current()
        .expect("material is installed")
        .cert[0]
        .clone()
}

fn reverse_proxy() -> TlsMode {
    TlsMode::ReverseProxy {
        trusted_proxies: TrustedProxies::parse(["10.0.0.0/8"]).expect("proxies"),
        proxy_protocol: false,
        public_host: HOST.to_owned(),
    }
}

/// Waits until the receiver sees a status with `predicate` true.
async fn wait_for_status(
    receiver: &mut tokio::sync::watch::Receiver<Arc<TlsStatus>>,
    predicate: impl Fn(&TlsStatus) -> bool,
) {
    tokio::time::timeout(WAIT, async {
        loop {
            let current = Arc::clone(&receiver.borrow_and_update());
            if predicate(&current) {
                return;
            }
            receiver.changed().await.expect("the service is alive");
        }
    })
    .await
    .expect("the status reached the expected state in time");
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the condition became true in time");
}

async fn stop(handle: tokio::task::JoinHandle<()>) {
    handle.abort();
    let result = tokio::time::timeout(WAIT, handle)
        .await
        .expect("the watcher stops when aborted");
    assert!(result.expect_err("an aborted task").is_cancelled());
}

// ---------------------------------------------------------------------------------------
// Loading and reloading
// ---------------------------------------------------------------------------------------

#[test]
fn set_mode_imported_loads_the_files() {
    let identity = Identity::new();
    let dir = TestDir::new();
    dir.write(&identity);
    let service = service(TlsMode::InternalCa);
    assert!(!service.resolver().has_material());

    service.set_mode(dir.mode()).expect("load");

    let status = service.status();
    assert_eq!(status.mode, dir.mode());
    let info = status.certificate.as_ref().expect("certificate in status");
    assert_eq!(info.sha256, identity.sha256());
    assert_eq!(info.subject, format!("CN={HOST}"));
    assert_eq!(info.dns_names, [HOST]);
    assert!(status.loaded_at.is_some());
    assert!(status.last_error.is_none());
    assert!(status.revision > 0);
    assert!(service.resolver().current().is_some());
    assert_eq!(served_leaf(&service), identity.der);
}

#[tokio::test]
async fn watch_receiver_sees_the_load() {
    let identity = Identity::new();
    let dir = TestDir::new();
    dir.write(&identity);
    let service = service(dir.mode());
    let mut receiver = service.watch();
    let before = receiver.borrow_and_update().revision;

    service.set_mode(dir.mode()).expect("load");

    tokio::time::timeout(WAIT, receiver.changed())
        .await
        .expect("a notification arrives")
        .expect("the service is alive");
    let status = Arc::clone(&receiver.borrow_and_update());
    assert!(status.revision > before);
    assert_eq!(
        status.certificate.as_ref().map(|info| info.sha256.clone()),
        Some(identity.sha256())
    );
}

#[test]
fn reload_serves_replaced_files() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    let revision = service.status().revision;
    let second = Identity::new();
    assert_ne!(first.der, second.der);

    dir.write(&second);

    assert_eq!(service.reload(), Ok(true));
    assert_eq!(served_leaf(&service), second.der);
    let status = service.status();
    assert_eq!(
        status.certificate.as_ref().map(|info| info.sha256.clone()),
        Some(second.sha256())
    );
    assert!(status.revision > revision);
    assert!(status.last_error.is_none());
}

#[test]
fn a_replacement_is_pending_while_the_service_does_not_accept_it() {
    let first = Identity::new();
    let dir = TestDir::new();
    dir.write(&first);
    let tls = service(dir.mode());
    tls.set_accept_replacement(false);
    // The start loads the files whatever the setting says.
    tls.set_mode(dir.mode()).expect("initial load");
    assert_eq!(served_leaf(&tls), first.der);
    assert_eq!(tls.status().chain_len, 1);
    assert!(tls.status().pending.is_none());

    let second = Identity::new();
    dir.write(&second);

    assert_eq!(tls.reload(), Ok(false));
    assert_eq!(
        served_leaf(&tls),
        first.der,
        "the old certificate keeps serving"
    );
    let status = tls.status();
    assert!(!status.accept_replacement);
    let pending = status
        .pending
        .as_ref()
        .expect("the new certificate is pending");
    assert_eq!(pending.certificate.sha256, second.sha256());
    assert_eq!(pending.chain_len, 1);
    assert!(status.last_error.is_none());
    assert_eq!(
        status.certificate.as_ref().map(|info| info.sha256.clone()),
        Some(first.sha256())
    );

    // The same files again change nothing, not even the revision.
    let revision = status.revision;
    assert_eq!(tls.reload(), Ok(false));
    assert_eq!(tls.status().revision, revision);

    // A restart loads what is on disk and the pending state is gone.
    let restarted = service(dir.mode());
    restarted.set_accept_replacement(false);
    restarted.set_mode(dir.mode()).expect("load at start");
    assert_eq!(served_leaf(&restarted), second.der);
    assert!(restarted.status().pending.is_none());
}

#[test]
fn restoring_the_served_files_clears_the_pending_state() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    service.set_accept_replacement(false);
    dir.write(&Identity::new());
    assert_eq!(service.reload(), Ok(false));
    assert!(service.status().pending.is_some());

    dir.write(&first);

    assert_eq!(service.reload(), Ok(false));
    assert!(service.status().pending.is_none());
}

#[test]
fn accepting_again_installs_the_pending_files_at_the_next_poll() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    service.set_accept_replacement(false);
    let second = Identity::new();
    dir.write(&second);
    assert_eq!(service.reload(), Ok(false));

    service.set_accept_replacement(true);

    assert_eq!(service.reload(), Ok(true));
    assert_eq!(served_leaf(&service), second.der);
    assert!(service.status().pending.is_none());
}

#[test]
fn a_broken_replacement_is_an_error_not_a_pending_certificate() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    service.set_accept_replacement(false);
    fs::write(dir.cert_path(), "not a certificate").expect("write");

    assert!(service.reload().is_err());

    let status = service.status();
    assert!(status.pending.is_none());
    assert!(status.last_error.is_some());
    assert_eq!(served_leaf(&service), first.der);
}

#[test]
fn reload_of_unchanged_files_returns_false_and_publishes_nothing() {
    let identity = Identity::new();
    let (_dir, service) = loaded(&identity);
    let before = service.status();

    assert_eq!(service.reload(), Ok(false));
    assert_eq!(service.reload(), Ok(false));

    let after = service.status();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.loaded_at, before.loaded_at);
    assert_eq!(served_leaf(&service), identity.der);
}

#[test]
fn garbage_key_keeps_the_previous_certificate_and_publishes_the_error() {
    let identity = Identity::new();
    let (dir, service) = loaded(&identity);

    fs::write(dir.key_path(), "this is not a key").expect("write garbage");
    let error = service.reload().expect_err("garbage key");

    assert!(matches!(error, TlsError::NoPrivateKey { .. }), "{error:?}");
    assert_eq!(served_leaf(&service), identity.der);
    let status = service.status();
    assert_eq!(status.last_error, Some(error.to_string()));
    assert_eq!(
        status.certificate.as_ref().map(|info| info.sha256.clone()),
        Some(identity.sha256())
    );

    // The same failure again changes nothing that is published.
    assert_eq!(service.reload(), Err(error.clone()));
    assert_eq!(service.status().revision, status.revision);

    // A different failure is a change.
    fs::remove_file(dir.key_path()).expect("remove the key");
    let missing = service.reload().expect_err("missing key");
    assert!(matches!(missing, TlsError::Io { .. }), "{missing:?}");
    let after = service.status();
    assert_eq!(after.last_error, Some(missing.to_string()));
    assert_eq!(after.revision, status.revision + 1);
    assert_eq!(served_leaf(&service), identity.der);
}

#[test]
fn certificate_that_is_not_pem_is_reported() {
    let identity = Identity::new();
    let (dir, service) = loaded(&identity);

    fs::write(dir.cert_path(), "garbage").expect("write garbage");

    assert_eq!(service.reload(), Err(TlsError::NoCertificate));
    assert_eq!(served_leaf(&service), identity.der);
}

#[test]
fn mismatched_certificate_and_key_is_a_key_mismatch_until_the_key_follows() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    let second = Identity::new();

    // The new certificate is visible while the old key still is.
    fs::write(dir.cert_path(), &second.cert_pem).expect("write the certificate");
    assert_eq!(service.reload(), Err(TlsError::KeyMismatch));
    assert_eq!(served_leaf(&service), first.der);
    assert_eq!(
        service.status().last_error,
        Some(TlsError::KeyMismatch.to_string())
    );

    // The key arrives; the next poll succeeds and the error is gone.
    fs::write(dir.key_path(), &second.key_pem).expect("write the key");
    assert_eq!(service.reload(), Ok(true));
    assert_eq!(served_leaf(&service), second.der);
    assert!(service.status().last_error.is_none());
}

#[test]
fn fixing_the_files_clears_the_error() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    fs::write(dir.key_path(), "broken").expect("write garbage");
    service.reload().expect_err("broken");
    assert!(service.status().last_error.is_some());

    let second = Identity::new();
    dir.write(&second);

    assert_eq!(service.reload(), Ok(true));
    assert!(service.status().last_error.is_none());
    assert_eq!(served_leaf(&service), second.der);
}

#[test]
fn reverting_to_the_loaded_files_clears_the_error_without_a_reload() {
    let identity = Identity::new();
    let (dir, service) = loaded(&identity);
    fs::write(dir.key_path(), "broken").expect("write garbage");
    service.reload().expect_err("broken");
    let failed = service.status();
    assert!(failed.last_error.is_some());

    fs::write(dir.key_path(), &identity.key_pem).expect("restore the key");

    assert_eq!(service.reload(), Ok(false));
    let status = service.status();
    assert!(status.last_error.is_none());
    assert!(status.revision > failed.revision);
    assert_eq!(status.loaded_at, failed.loaded_at);
    assert_eq!(served_leaf(&service), identity.der);
}

#[test]
fn failing_first_load_reports_the_error_and_serves_nothing() {
    let dir = TestDir::new();
    let service = service(dir.mode());

    let error = service.set_mode(dir.mode()).expect_err("no files");

    assert!(matches!(error, TlsError::Io { .. }), "{error:?}");
    assert!(!service.resolver().has_material());
    let status = service.status();
    assert_eq!(status.last_error, Some(error.to_string()));
    assert!(status.certificate.is_none());
    assert_eq!(status.mode, dir.mode());

    // Once the files exist, the next reload serves them.
    let identity = Identity::new();
    dir.write(&identity);
    assert_eq!(service.reload(), Ok(true));
    assert_eq!(served_leaf(&service), identity.der);
    assert!(service.status().last_error.is_none());
}

// ---------------------------------------------------------------------------------------
// Modes and install
// ---------------------------------------------------------------------------------------

#[test]
fn reverse_proxy_removes_the_material_and_the_certificate() {
    let identity = Identity::new();
    let (dir, service) = loaded(&identity);
    let proxy = reverse_proxy();

    service.set_mode(proxy.clone()).expect("switch");

    assert!(!service.resolver().has_material());
    assert!(service.resolver().current().is_none());
    let status = service.status();
    assert_eq!(status.mode, proxy);
    assert!(status.certificate.is_none());
    assert!(status.loaded_at.is_none());
    assert!(status.last_error.is_none());
    assert_eq!(service.reload(), Err(TlsError::NoLocalTls));

    // Back to imported files: they are read again even though they did not change.
    service.set_mode(dir.mode()).expect("switch back");
    assert_eq!(served_leaf(&service), identity.der);
    assert!(service.status().certificate.is_some());
}

#[test]
fn reload_outside_the_imported_mode_is_no_local_tls() {
    let service = service(TlsMode::InternalCa);
    assert_eq!(service.reload(), Err(TlsError::NoLocalTls));

    service.install(Identity::new().material());
    assert_eq!(service.reload(), Err(TlsError::NoLocalTls));

    service.set_mode(reverse_proxy()).expect("switch");
    assert_eq!(service.reload(), Err(TlsError::NoLocalTls));
}

#[test]
fn internal_ca_mode_keeps_the_material_until_install() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    fs::write(dir.key_path(), "broken").expect("write garbage");
    service.reload().expect_err("broken");

    service.set_mode(TlsMode::InternalCa).expect("switch");

    assert_eq!(served_leaf(&service), first.der);
    let status = service.status();
    assert_eq!(status.mode, TlsMode::InternalCa);
    assert!(status.certificate.is_some());
    assert!(
        status.last_error.is_none(),
        "the file error no longer applies"
    );
    assert_eq!(service.reload(), Err(TlsError::NoLocalTls));

    let issued = Identity::new();
    service.install(issued.material());
    assert_eq!(served_leaf(&service), issued.der);
}

#[test]
fn install_publishes_the_material_in_internal_ca_mode() {
    let service = service(TlsMode::InternalCa);
    let mut receiver = service.watch();
    receiver.mark_unchanged();
    let identity = Identity::new();

    service.install(identity.material());

    assert!(receiver.has_changed().expect("the service is alive"));
    assert!(service.resolver().has_material());
    assert_eq!(served_leaf(&service), identity.der);
    let status = service.status();
    assert_eq!(status.mode, TlsMode::InternalCa);
    assert_eq!(
        status.certificate.as_ref().map(|info| info.sha256.clone()),
        Some(identity.sha256())
    );
    assert!(status.loaded_at.is_some());
    assert!(status.last_error.is_none());
    assert_eq!(status.revision, 1);

    // A renewal replaces it.
    let renewed = Identity::new();
    service.install(renewed.material());
    assert_eq!(served_leaf(&service), renewed.der);
    assert_eq!(service.status().revision, 2);
}

#[test]
fn install_forgets_the_loaded_files_so_they_are_read_again() {
    let from_files = Identity::new();
    let (dir, service) = loaded(&from_files);
    assert_eq!(service.reload(), Ok(false));

    let uploaded = Identity::new();
    service.install(uploaded.material());
    assert_eq!(served_leaf(&service), uploaded.der);

    // The files did not change, but they are not what is served any more.
    assert_eq!(service.reload(), Ok(true));
    assert_eq!(served_leaf(&service), from_files.der);

    // The same holds when the mode is switched away and back.
    service.install(uploaded.material());
    service.set_mode(TlsMode::InternalCa).expect("switch");
    service.set_mode(dir.mode()).expect("switch back");
    assert_eq!(served_leaf(&service), from_files.der);
}

// ---------------------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn watcher_picks_up_replaced_files() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    let mut receiver = service.watch();
    let handle = service.spawn_watcher(Duration::from_millis(50));

    // Quiet while nothing changes.
    let revision = service.status().revision;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(service.status().revision, revision);

    // The two renames can be seen half done (new certificate, old key); the watcher
    // reports that and recovers on a later poll.
    let second = Identity::new();
    dir.replace(&second);
    let sha = second.sha256();
    tokio::time::timeout(WAIT, async {
        loop {
            let current = Arc::clone(&receiver.borrow_and_update());
            if current
                .certificate
                .as_ref()
                .is_some_and(|info| info.sha256 == sha)
            {
                return;
            }
            receiver.changed().await.expect("the service is alive");
        }
    })
    .await
    .expect("the watcher served the replaced certificate");

    assert_eq!(served_leaf(&service), second.der);
    assert!(service.status().last_error.is_none());
    stop(handle).await;
}

#[tokio::test]
async fn watcher_reports_a_broken_file_and_recovers() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    let mut receiver = service.watch();
    let handle = service.spawn_watcher(Duration::from_millis(20));

    fs::write(dir.key_path(), "broken").expect("write garbage");
    wait_for_status(&mut receiver, |status| status.last_error.is_some()).await;
    assert_eq!(served_leaf(&service), first.der);

    let second = Identity::new();
    dir.replace(&second);
    wait_for_status(&mut receiver, |status| {
        status.last_error.is_none()
            && status
                .certificate
                .as_ref()
                .is_some_and(|info| info.sha256 == second.sha256())
    })
    .await;
    assert_eq!(served_leaf(&service), second.der);
    stop(handle).await;
}

#[tokio::test]
async fn watcher_leaves_other_modes_alone_and_stops_when_aborted() {
    let service = service(TlsMode::InternalCa);
    service.install(Identity::new().material());

    let handle = service.spawn_watcher(Duration::from_millis(20));
    // Starting the watcher publishes its interval, once.
    let revision = service.status().revision;
    assert_eq!(
        service.status().watch_interval,
        Some(Duration::from_millis(20))
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!handle.is_finished());
    assert_eq!(service.status().revision, revision);

    stop(handle).await;
}

#[tokio::test]
async fn watcher_accepts_a_zero_interval() {
    let service = service(TlsMode::InternalCa);
    let handle = service.spawn_watcher(Duration::ZERO);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!handle.is_finished());
    stop(handle).await;
}

// ---------------------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------------------

fn expiry_after_loading(identity: &Identity) -> (ExpiryState, i64) {
    let (_dir, service) = loaded(identity);
    let expiry = service
        .status()
        .expiry(Timestamp::from(OffsetDateTime::now_utc()))
        .expect("a certificate is served");
    (expiry.state, expiry.days_left)
}

#[test]
fn expiry_is_reported_through_the_status() {
    let (state, days) = expiry_after_loading(&Identity::expiring_in(90));
    assert_eq!(state, ExpiryState::Valid);
    assert!((89..=90).contains(&days), "{days}");

    let (state, days) = expiry_after_loading(&Identity::expiring_in(10));
    assert_eq!(state, ExpiryState::Warning);
    assert!((9..=10).contains(&days), "{days}");

    let (state, days) = expiry_after_loading(&Identity::expiring_in(3));
    assert_eq!(state, ExpiryState::Critical);
    assert!((2..=3).contains(&days), "{days}");

    let (state, days) = expiry_after_loading(&Identity::expiring_in(-1));
    assert_eq!(state, ExpiryState::Expired);
    assert!(days < 0, "{days}");
}

#[test]
fn status_without_material_has_no_expiry() {
    let service = service(TlsMode::InternalCa);
    assert!(
        service
            .status()
            .expiry(Timestamp::from(OffsetDateTime::now_utc()))
            .is_none()
    );
}

/// Collects the fields of every event with a `days_left` field.
#[derive(Clone, Default)]
struct ExpiryLog {
    events: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}

impl ExpiryLog {
    fn len(&self) -> usize {
        self.events.lock().expect("log lock").len()
    }

    fn event(&self, index: usize) -> BTreeMap<String, String> {
        self.events.lock().expect("log lock")[index].clone()
    }
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl Subscriber for ExpiryLog {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        if *event.metadata().level() == Level::WARN && fields.0.contains_key("days_left") {
            self.events.lock().expect("log lock").push(fields.0);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn watcher_warns_once_per_expiry_state_change() {
    let log = ExpiryLog::default();
    // The watcher task runs on this thread (current-thread runtime), so this subscriber
    // sees what it logs.
    let _guard = tracing::subscriber::set_default(log.clone());

    let (dir, service) = loaded(&Identity::expiring_in(10));
    let mut receiver = service.watch();
    let handle = service.spawn_watcher(Duration::from_millis(20));

    // Warning: logged on the first look, not on the ticks after it.
    wait_until(|| log.len() >= 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(log.len(), 1);
    let warning = log.event(0);
    assert_eq!(warning["state"], "Warning");
    assert_eq!(warning["subject"], format!("CN={HOST}"));
    assert!(
        ["9", "10"].contains(&warning["days_left"].as_str()),
        "{warning:?}"
    );

    // A replacement that is critical logs again.
    let critical = Identity::expiring_in(3);
    dir.replace(&critical);
    wait_until(|| log.len() >= 2).await;
    assert_eq!(log.event(1)["state"], "Critical");

    // A healthy one does not.
    let healthy = Identity::new();
    dir.replace(&healthy);
    wait_for_status(&mut receiver, |status| {
        status
            .certificate
            .as_ref()
            .is_some_and(|info| info.sha256 == healthy.sha256())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(log.len(), 2);

    // An expired one does.
    let expired = Identity::expiring_in(-1);
    dir.replace(&expired);
    wait_until(|| log.len() >= 3).await;
    let event = log.event(2);
    assert_eq!(event["state"], "Expired");
    assert!(event["days_left"].starts_with('-'), "{event:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(log.len(), 3);

    stop(handle).await;
}

// ---------------------------------------------------------------------------------------
// Real handshakes
// ---------------------------------------------------------------------------------------

fn client_config(
    trusted: &CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted.clone()).expect("trust anchor");
    Arc::new(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_protocol_versions(versions)
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// Moves everything `from` wants to send into `to`.
fn pump(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).expect("writing to memory");
    }
    let mut input = wire.as_slice();
    while !input.is_empty() {
        let read = to.read_tls(&mut input).expect("reading from memory");
        to.process_new_packets()?;
        if read == 0 {
            break;
        }
    }
    Ok(())
}

/// Runs a handshake between a client trusting `trusted` and a server on the service's
/// configuration. Returns the finished client side.
fn handshake(
    service: &TlsService,
    trusted: &CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Connection, rustls::Error> {
    let name = ServerName::try_from(HOST).expect("server name");
    let mut client = Connection::from(
        ClientConnection::new(client_config(trusted, versions), name).expect("client connection"),
    );
    let mut server = Connection::from(
        ServerConnection::new(service.server_config()).expect("server connection"),
    );
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(client);
        }
        pump(&mut client, &mut server)?;
        pump(&mut server, &mut client)?;
    }
    panic!("the handshake did not finish");
}

fn presented_leaf(client: &Connection) -> CertificateDer<'static> {
    client.peer_certificates().expect("the server sent a chain")[0].clone()
}

#[test]
fn handshake_presents_the_imported_certificate_and_follows_a_reload() {
    let first = Identity::new();
    let (dir, service) = loaded(&first);
    let all_versions = rustls::ALL_VERSIONS;

    let client = handshake(&service, &first.der, all_versions).expect("first handshake");
    assert_eq!(presented_leaf(&client), first.der);
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    let second = Identity::new();
    dir.write(&second);
    assert_eq!(service.reload(), Ok(true));

    // The same server configuration now presents the new certificate.
    let client = handshake(&service, &second.der, all_versions).expect("second handshake");
    assert_eq!(presented_leaf(&client), second.der);

    // A client that only trusts the old certificate is refused.
    assert!(handshake(&service, &first.der, all_versions).is_err());
}

#[test]
fn a_failed_reload_does_not_disturb_handshakes() {
    let identity = Identity::new();
    let (dir, service) = loaded(&identity);
    fs::write(dir.key_path(), "broken").expect("write garbage");
    service.reload().expect_err("broken");

    let client = handshake(&service, &identity.der, rustls::ALL_VERSIONS).expect("handshake");
    assert_eq!(presented_leaf(&client), identity.der);
}

#[test]
fn handshake_fails_without_material() {
    let service = service(TlsMode::InternalCa);
    let identity = Identity::new();
    assert!(handshake(&service, &identity.der, rustls::ALL_VERSIONS).is_err());

    // And again after the material is removed.
    service.install(identity.material());
    assert!(handshake(&service, &identity.der, rustls::ALL_VERSIONS).is_ok());
    service.set_mode(reverse_proxy()).expect("switch");
    assert!(handshake(&service, &identity.der, rustls::ALL_VERSIONS).is_err());
}

#[test]
fn tls13_only_policy_refuses_a_tls12_client() {
    let identity = Identity::new();
    let dir = TestDir::new();
    dir.write(&identity);
    let tls12 = &[&rustls::version::TLS12];

    // Without the policy a TLS 1.2 client is served.
    let open = service(dir.mode());
    open.set_mode(dir.mode()).expect("load");
    let client = handshake(&open, &identity.der, tls12).expect("TLS 1.2 handshake");
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );

    // With it, only TLS 1.3 works.
    let hardened = TlsService::new(dir.mode(), TlsPolicy { tls13_only: true }).expect("service");
    hardened.set_mode(dir.mode()).expect("load");
    assert!(handshake(&hardened, &identity.der, tls12).is_err());
    let client =
        handshake(&hardened, &identity.der, &[&rustls::version::TLS13]).expect("TLS 1.3 handshake");
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}
