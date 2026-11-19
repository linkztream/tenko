//! The integration CA of ADR 0035 against the in-memory store and vault: one root created
//! once with a key of its own purpose, integration certificates that carry only the account,
//! whatever the request asks for, the identity reader's refusals, and the separation from the
//! internal CA: neither root's verifier accepts the other root's certificates.

use std::{sync::Arc, time::Duration as StdDuration};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
    string::Ia5String,
};
use rustls::{
    CertificateError, Error as TlsErr, RootCertStore,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, UnixTime},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};
use tenko_cluster::{
    ca::{
        CaError, CaPolicy, CertInfo, INTEGRATION_CA_CREATE, INTEGRATION_CA_KEY_PURPOSE,
        IntegrationCa, IntegrationIdentity, InternalCa, MAX_INTEGRATION_VALIDITY_DAYS,
        ServerIdentity, node_uri, role_uri, service_account_uri, tables,
    },
    mtls::verify_controller,
};
use tenko_core::{
    NodeId, RequestCtx, Role, SystemComponent, Timestamp, UserId, secret::SecretClass,
};
use tenko_store::{ReadConsistency, ReadViewExt, Store, mem::MemStore};
use tenko_vault::{MemVault, Vault};
use time::{Duration, OffsetDateTime};

struct Env {
    store: Arc<MemStore>,
    vault: MemVault,
}

impl Env {
    fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let vault = MemVault::with_store(store.clone());
        Self { store, vault }
    }

    async fn integration(&self) -> IntegrationCa {
        IntegrationCa::load_or_init(&*self.store, &self.vault, &ctx())
            .await
            .expect("integration CA")
    }

    async fn internal(&self) -> InternalCa {
        InternalCa::load_or_init(&*self.store, &self.vault, &ctx(), CaPolicy::default())
            .await
            .expect("internal CA")
    }
}

fn t0() -> Timestamp {
    Timestamp(OffsetDateTime::from_unix_timestamp(1_790_000_000).expect("timestamp"))
}

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster).at(t0())
}

fn unix(ts: Timestamp) -> UnixTime {
    let seconds = u64::try_from(ts.0.unix_timestamp()).expect("positive");
    UnixTime::since_unix_epoch(StdDuration::from_secs(seconds))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn roots_of(root: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).expect("trust anchor");
    roots
}

fn client_verifier(root: &CertificateDer<'static>) -> Arc<dyn ClientCertVerifier> {
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots_of(root)), provider())
        .build()
        .expect("client verifier")
}

fn is_unknown_issuer(error: &TlsErr) -> bool {
    matches!(
        error,
        TlsErr::InvalidCertificate(CertificateError::UnknownIssuer)
    )
}

fn csr(params: &CertificateParams) -> Vec<u8> {
    let key = KeyPair::generate().expect("key");
    params.serialize_request(&key).expect("csr").der().to_vec()
}

fn plain_csr() -> Vec<u8> {
    csr(&CertificateParams::default())
}

fn not_an_integration(case: &str, result: Result<IntegrationIdentity, CaError>) -> String {
    match result {
        Err(CaError::NotAnIntegration { reason }) => reason,
        other => panic!("{case}: expected a refusal, got {other:?}"),
    }
}

fn uri(text: String) -> SanType {
    SanType::URI(Ia5String::try_from(text).expect("uri"))
}

/// A change to an otherwise well-formed integration certificate of the given account.
type Shape = fn(&mut CertificateParams, UserId);

/// The shapes the identity reader must refuse.
fn refused_shapes() -> [(&'static str, Shape); 13] {
    [
        ("a CA", |p, _| {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }),
        ("server authentication", |p, _| {
            p.extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }),
        ("any purpose", |p, _| {
            p.extended_key_usages.push(ExtendedKeyUsagePurpose::Any);
        }),
        ("no extended key usage", |p, _| {
            p.extended_key_usages.clear();
        }),
        ("server authentication only", |p, _| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }),
        ("no name", |p, _| p.subject_alt_names.clear()),
        ("two accounts", |p, _| {
            p.subject_alt_names
                .push(uri(service_account_uri(UserId::generate())));
        }),
        ("a node name beside the account", |p, _| {
            p.subject_alt_names.push(uri(node_uri(NodeId(1))));
        }),
        ("a role beside the account", |p, _| {
            p.subject_alt_names.push(uri(role_uri(Role::Controller)));
        }),
        ("a DNS name beside the account", |p, _| {
            p.subject_alt_names.push(SanType::DnsName(
                Ia5String::try_from("tenko.example.test").expect("name"),
            ));
        }),
        ("a node instead of an account", |p, _| {
            p.subject_alt_names = vec![uri(node_uri(NodeId(1)))];
        }),
        ("an account id that is no identifier", |p, _| {
            p.subject_alt_names = vec![uri("urn:tenko:service-account:admin".to_owned())];
        }),
        ("an account id in a second spelling", |p, account| {
            p.subject_alt_names = vec![uri(format!(
                "urn:tenko:service-account:{}",
                account.uuid().simple()
            ))];
        }),
    ]
}

#[tokio::test]
async fn the_root_is_created_once_with_a_key_of_its_own_purpose() {
    let env = Env::new();
    let first = env.integration().await;
    let again = env.integration().await;
    assert_eq!(first.root_der(), again.root_der());
    assert!(first.root_info().is_ca);
    assert!(
        first
            .root_info()
            .subject
            .contains("Tenko DDI integration CA")
    );

    let internal = env.internal().await;
    assert_ne!(internal.root_der(), first.root_der());

    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (record, _) = view
        .get_typed(&tables::INTEGRATION_CA, &())
        .expect("read")
        .expect("the record exists");
    assert_eq!(record.cert_pem, first.root_pem());
    let meta = env
        .vault
        .meta(record.key)
        .await
        .expect("meta")
        .expect("the key exists");
    assert_eq!(meta.class, SecretClass::System);
    assert_eq!(meta.purpose, INTEGRATION_CA_KEY_PURPOSE);
    assert_ne!(record.key, internal.record().key);
    assert_eq!(
        INTEGRATION_CA_CREATE.as_str(),
        "cluster.integration_ca.create"
    );

    let loaded = IntegrationCa::load(&*env.store, &env.vault, &ctx())
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(loaded.root_der(), first.root_der());
    let empty = Env::new();
    assert!(
        IntegrationCa::load(&*empty.store, &empty.vault, &ctx())
            .await
            .expect("load")
            .is_none()
    );
}

#[tokio::test]
async fn a_certificate_names_the_account_and_nothing_the_request_asks_for() {
    let env = Env::new();
    let ca = env.integration().await;
    let account = UserId::generate();

    let mut greedy = CertificateParams::default();
    greedy.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    greedy.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    greedy.subject_alt_names = vec![
        SanType::URI(Ia5String::try_from(node_uri(NodeId(1))).expect("uri")),
        SanType::URI(Ia5String::try_from(role_uri(Role::Controller)).expect("uri")),
        SanType::URI(Ia5String::try_from(service_account_uri(UserId::generate())).expect("uri")),
        SanType::DnsName(Ia5String::try_from("tenko.example.test").expect("name")),
    ];
    let issued = ca.issue(account, &csr(&greedy), t0(), 30).expect("issue");

    let info = CertInfo::from_der(&issued.cert).expect("parse");
    assert!(!info.is_ca);
    assert_eq!(info.uris, [service_account_uri(account)]);
    assert!(info.dns_names.is_empty() && info.ip_addresses.is_empty());
    assert_eq!(info.subject, "CN=tenko-integration");
    assert_eq!(info.issuer, ca.root_info().subject);
    assert_eq!(info.not_before.0, t0().0 - Duration::hours(1));
    assert_eq!(info.not_after.0, t0().0 + Duration::days(30));

    assert_eq!(issued.identity.account, account);
    assert_eq!(issued.identity.serial, info.serial);
    assert_eq!(issued.identity.sha256, info.sha256);
    assert_eq!(issued.identity.key_sha256.len(), 64);
    assert_eq!(
        IntegrationIdentity::from_der(&issued.cert).expect("read back"),
        issued.identity
    );
    assert!(
        issued
            .chain_pem()
            .starts_with("-----BEGIN CERTIFICATE-----\n")
    );

    // The same key in a second request gives the same key digest.
    let key = KeyPair::generate().expect("key");
    let once = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let twice = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let a = ca.issue(account, once.der(), t0(), 7).expect("issue");
    let b = ca.issue(account, twice.der(), t0(), 7).expect("issue");
    assert_eq!(a.identity.key_sha256, b.identity.key_sha256);
    assert_ne!(a.identity.serial, b.identity.serial);
    assert_ne!(a.identity.key_sha256, issued.identity.key_sha256);
}

#[tokio::test]
async fn requests_and_lifetimes_outside_the_rules_are_refused() {
    let env = Env::new();
    let ca = env.integration().await;
    let account = UserId::generate();

    for days in [0, MAX_INTEGRATION_VALIDITY_DAYS + 1, u32::MAX] {
        assert!(
            matches!(
                ca.issue(account, &plain_csr(), t0(), days),
                Err(CaError::Generation { .. })
            ),
            "{days} days"
        );
    }
    assert!(
        ca.issue(account, &plain_csr(), t0(), MAX_INTEGRATION_VALIDITY_DAYS)
            .is_ok()
    );

    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("key");
    let p384 = CertificateParams::default()
        .serialize_request(&p384)
        .expect("csr");
    let ed25519 = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let ed25519 = CertificateParams::default()
        .serialize_request(&ed25519)
        .expect("csr");
    let mut broken = plain_csr();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;
    let mut trailing = plain_csr();
    trailing.push(0);
    for (name, request) in [
        ("P-384", p384.der().to_vec()),
        ("Ed25519", ed25519.der().to_vec()),
        ("a broken signature", broken),
        ("trailing data", trailing),
        ("not a request", b"not a request".to_vec()),
        ("empty", Vec::new()),
    ] {
        assert!(
            matches!(
                ca.issue(account, &request, t0(), 30),
                Err(CaError::InvalidCsr { .. })
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_identity_reader_refuses_every_other_certificate() {
    let env = Env::new();
    let internal = env.internal().await;
    let integration = env.integration().await;

    let node = internal
        .issue_node_cert_with_key(NodeId(5), t0())
        .expect("node");
    let reason = not_an_integration("a node", IntegrationIdentity::from_der(&node.chain[0]));
    assert!(reason.contains("client authentication"), "{reason}");
    let server = internal
        .issue_server_cert(&ServerIdentity::new("tenko.example.test"), t0())
        .expect("server");
    not_an_integration("a server", IntegrationIdentity::from_der(&server.chain[0]));
    not_an_integration(
        "the root",
        IntegrationIdentity::from_der(integration.root_der()),
    );
    not_an_integration(
        "garbage",
        IntegrationIdentity::from_der(b"not a certificate"),
    );

    let account = UserId::generate();
    let shaped = |configure: &dyn Fn(&mut CertificateParams)| {
        let mut params = CertificateParams::default();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(service_account_uri(account)).expect("uri"),
        )];
        configure(&mut params);
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("self-signed").der().clone()
    };

    // The form of an issued certificate is read (the reader leaves the chain to the
    // verifier).
    let good = shaped(&|_| {});
    assert_eq!(
        IntegrationIdentity::from_der(&good).expect("read").account,
        account
    );
    let mut trailing = good.to_vec();
    trailing.push(0);
    not_an_integration("trailing data", IntegrationIdentity::from_der(&trailing));

    for (name, configure) in refused_shapes() {
        let der = shaped(&|params: &mut CertificateParams| configure(params, account));
        not_an_integration(name, IntegrationIdentity::from_der(&der));
    }
}

#[tokio::test]
async fn neither_root_accepts_the_other_roots_certificates() {
    let env = Env::new();
    let internal = env.internal().await;
    let integration = env.integration().await;
    let now = unix(t0());

    let issued = integration
        .issue(UserId::generate(), &plain_csr(), t0(), 30)
        .expect("issue");
    client_verifier(integration.root_der())
        .verify_client_cert(&issued.cert, &[], now)
        .expect("the integration listener's chain check accepts it");

    // The cluster port's chain check and a node's check of its controller trust only the
    // internal root.
    let error = client_verifier(internal.root_der())
        .verify_client_cert(&issued.cert, &[], now)
        .expect_err("the cluster port refuses it");
    assert!(is_unknown_issuer(&error), "{error:?}");
    let algorithms = provider().signature_verification_algorithms;
    let error = verify_controller(
        &roots_of(internal.root_der()),
        &issued.cert,
        &[],
        now,
        &algorithms,
    )
    .expect_err("a node refuses it as a controller");
    // The purpose check comes before the issuer: it is not a server certificate either.
    assert!(matches!(error, TlsErr::InvalidCertificate(_)), "{error:?}");

    // The integration listener's chain check refuses node and server certificates.
    let node = internal
        .issue_node_cert_with_key(NodeId(5), t0())
        .expect("node");
    let error = client_verifier(integration.root_der())
        .verify_client_cert(&node.chain[0], &[], now)
        .expect_err("the integration listener refuses a node");
    assert!(is_unknown_issuer(&error), "{error:?}");
}
