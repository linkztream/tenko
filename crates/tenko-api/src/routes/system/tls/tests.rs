use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axum::Router;
use rcgen::{CertificateParams, DnType, KeyPair};
use serde_json::{Value, json};
use tenko_auth::{settings::Profile, testing::TestEnv};
use tenko_cluster::ca::{
    CertSource, TlsMaterial, TlsMode as ServiceMode, TlsPolicy, TlsService, TrustedProxies,
};

use super::*;
use crate::routes::auth::testkit::{Credential::*, Harness};

const HOST: &str = "ddi.example.test";

/// A self-signed certificate for `HOST` with its key, valid for `days` from now.
struct Identity {
    cert_pem: String,
    key_pem: String,
}

impl Identity {
    fn new(days: i64) -> Self {
        let mut params = CertificateParams::new(vec![HOST.to_owned(), "192.0.2.10".to_owned()])
            .expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, HOST.to_owned());
        let day = Duration::from_secs(86_400);
        let now = tenko_core::Timestamp::now().0;
        params.not_before = now - day;
        params.not_after = now + day * u32::try_from(days).expect("days");
        let key = KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("certificate");
        Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
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

/// A directory below the system temp directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tenko-api-tls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("directory");
        Self(path)
    }

    fn mode(&self) -> ServiceMode {
        ServiceMode::Imported {
            cert_path: self.0.join("fullchain.pem"),
            key_path: self.0.join("privkey.pem"),
        }
    }

    fn write(&self, identity: &Identity) {
        fs::write(self.0.join("fullchain.pem"), &identity.cert_pem).expect("certificate");
        fs::write(self.0.join("privkey.pem"), &identity.key_pem).expect("key");
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The API over an installation whose listener serves `tls`, with `ca_root` as the internal
/// CA root source of the server binary when given.
async fn installation(
    tls: Option<&TlsService>,
    lab_plain_http: bool,
    ca_root: Option<CaRootSource>,
) -> (Harness, String) {
    let env = TestEnv::new().await;
    env.clock.set(tenko_core::Timestamp::now());
    let admin = env
        .setup(Profile::Home)
        .await
        .expect("setup succeeds")
        .secret
        .expose()
        .to_owned();
    let tls = tls.cloned();
    let harness = Harness::wired(env, move |state| {
        if let Some(tls) = tls {
            state.platform.listener.store(Some(Arc::new(ListenerInfo {
                tls,
                policy: TlsPolicy::default(),
                lab_plain_http,
                hsts: true,
                ui_from_directory: false,
            })));
        }
        let router: Router = crate::api(state).0;
        match ca_root {
            Some(source) => router.layer(Extension(Arc::new(source))),
            None => router,
        }
    });
    (harness, admin)
}

async fn tls_of(harness: &Harness, admin: &str) -> Value {
    let reply = harness
        .call("GET", "/system/tls", Cookie(admin), None)
        .await;
    reply.assert_status(200);
    reply.body
}

async fn warnings_of(harness: &Harness, admin: &str) -> Vec<String> {
    let reply = harness
        .call("GET", "/system/status", Cookie(admin), None)
        .await;
    reply.assert_status(200);
    reply.body["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .map(|warning| warning["code"].as_str().expect("code").to_owned())
        .collect()
}

#[tokio::test]
async fn an_imported_certificate_is_described_with_its_files_and_never_the_key() {
    let dir = Dir::new();
    let identity = Identity::new(90);
    dir.write(&identity);
    let tls = TlsService::new(dir.mode(), TlsPolicy::default()).expect("service");
    tls.set_mode(dir.mode()).expect("load");
    let watcher = tls.spawn_watcher(Duration::from_secs(5));
    let (harness, admin) = installation(Some(&tls), false, None).await;

    let body = tls_of(&harness, &admin).await;

    assert_eq!(body["mode"], "imported");
    assert_eq!(body["min_version"], "1.2");
    assert_eq!(body["hsts"], true);
    let certificate = &body["certificate"];
    assert_eq!(certificate["subject"], format!("CN={HOST}"));
    assert_eq!(certificate["dns_names"], json!([HOST]));
    assert_eq!(certificate["ip_addresses"], json!(["192.0.2.10"]));
    assert_eq!(certificate["chain_len"], 1);
    assert_eq!(certificate["state"], "valid");
    assert!(certificate["days_left"].as_i64().expect("days") >= 89);
    assert_eq!(
        certificate["sha256"].as_str().expect("fingerprint").len(),
        64
    );
    assert!(body["loaded_at"].is_string());
    assert!(body["pending"].is_null());
    let imported = &body["imported"];
    assert_eq!(imported["watch_interval_secs"], 5);
    assert_eq!(imported["accept_external_replacement"], true);
    assert!(
        imported["cert_path"]
            .as_str()
            .expect("path")
            .ends_with("fullchain.pem")
    );
    assert!(
        imported["key_path"]
            .as_str()
            .expect("path")
            .ends_with("privkey.pem")
    );
    assert!(body["internal_ca"].is_null() && body["reverse_proxy"].is_null());
    let text = body.to_string();
    assert!(!text.contains("PRIVATE KEY"));
    let key_body: String = identity
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    assert!(!text.contains(&key_body));
    assert!(
        !warnings_of(&harness, &admin)
            .await
            .contains(&"sys.tls.certificate_pending".to_owned())
    );
    watcher.abort();
}

#[tokio::test]
async fn a_certificate_that_is_not_accepted_is_pending_and_raises_the_warning() {
    let dir = Dir::new();
    dir.write(&Identity::new(10));
    let tls = TlsService::new(dir.mode(), TlsPolicy::default()).expect("service");
    tls.set_accept_replacement(false);
    tls.set_mode(dir.mode()).expect("load");
    let (harness, admin) = installation(Some(&tls), false, None).await;
    let first = tls_of(&harness, &admin).await;
    assert_eq!(first["certificate"]["state"], "warning");
    let served = first["certificate"]["sha256"].clone();

    dir.write(&Identity::new(90));
    assert_eq!(tls.reload(), Ok(false));

    let body = tls_of(&harness, &admin).await;
    assert_eq!(body["imported"]["accept_external_replacement"], false);
    assert_eq!(
        body["certificate"]["sha256"], served,
        "the old one keeps serving"
    );
    let pending = &body["pending"];
    assert_eq!(pending["certificate"]["state"], "valid");
    assert_ne!(pending["certificate"]["sha256"], served);
    assert_eq!(pending["certificate"]["chain_len"], 1);
    assert!(pending["detected_at"].is_string());
    let warnings = warnings_of(&harness, &admin).await;
    assert!(
        warnings.contains(&"sys.tls.certificate_pending".to_owned()),
        "{warnings:?}"
    );
    assert!(
        warnings.contains(&"sys.tls.certificate_expiry".to_owned()),
        "{warnings:?}"
    );
}

#[tokio::test]
async fn the_internal_ca_mode_names_the_root_and_where_to_download_it() {
    let ca = Identity::new(3_650);
    let leaf = Identity::new(60);
    let tls = TlsService::new(ServiceMode::InternalCa, TlsPolicy::default()).expect("service");
    tls.install(leaf.material());
    let source = CaRootSource::new(tls.clone(), ca.cert_pem.clone(), "ab".repeat(32));
    let (harness, admin) = installation(Some(&tls), false, Some(source)).await;

    let body = tls_of(&harness, &admin).await;

    assert_eq!(body["mode"], "internal_ca");
    let ca_root = &body["internal_ca"];
    assert_eq!(ca_root["root_subject"], format!("CN={HOST}"));
    assert!(ca_root["root_not_after"].is_string());
    assert_eq!(ca_root["download_path"], "/api/v1/system/ca-root");
    assert_eq!(
        ca_root["root_sha256"].as_str().expect("fingerprint").len(),
        64
    );
    assert!(body["imported"].is_null() && body["reverse_proxy"].is_null());
    assert_eq!(body["certificate"]["state"], "valid");
}

#[tokio::test]
async fn a_reverse_proxy_names_its_proxies_and_the_public_host() {
    let mode = ServiceMode::ReverseProxy {
        trusted_proxies: TrustedProxies::parse(["198.51.100.0/24"]).expect("proxies"),
        proxy_protocol: true,
        public_host: HOST.to_owned(),
    };
    let tls = TlsService::new(mode.clone(), TlsPolicy::default()).expect("service");
    let (harness, admin) = installation(Some(&tls), false, None).await;

    let body = tls_of(&harness, &admin).await;

    assert_eq!(body["mode"], "reverse_proxy");
    assert!(body["certificate"].is_null() && body["min_version"].is_null());
    let proxy = &body["reverse_proxy"];
    assert_eq!(proxy["trusted_proxies"], json!(["198.51.100.0/24"]));
    assert_eq!(proxy["proxy_protocol"], true);
    assert_eq!(proxy["public_host"], HOST);
}

#[tokio::test]
async fn plain_http_has_no_certificate_and_no_proxy_details() {
    let mode = ServiceMode::ReverseProxy {
        trusted_proxies: TrustedProxies::default(),
        proxy_protocol: false,
        public_host: "localhost".to_owned(),
    };
    let tls = TlsService::new(mode, TlsPolicy::default()).expect("service");
    let (harness, admin) = installation(Some(&tls), true, None).await;

    let body = tls_of(&harness, &admin).await;

    assert_eq!(body["mode"], "plain");
    assert_eq!(body["hsts"], false);
    assert!(body["certificate"].is_null() && body["reverse_proxy"].is_null());
}

#[tokio::test]
async fn the_route_needs_a_sign_in_and_a_running_listener() {
    let tls = TlsService::new(ServiceMode::InternalCa, TlsPolicy::default()).expect("service");
    let (harness, _) = installation(Some(&tls), false, None).await;
    harness
        .call("GET", "/system/tls", Anonymous, None)
        .await
        .assert_problem(401, "auth.unauthenticated");

    let (without_listener, admin) = installation(None, false, None).await;
    without_listener
        .call("GET", "/system/tls", Cookie(&admin), None)
        .await
        .assert_problem(503, codes::NOT_READY);
}
