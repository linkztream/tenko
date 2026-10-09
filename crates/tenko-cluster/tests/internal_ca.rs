//! The internal CA against the in-memory store and vault: persistence of the root and the
//! server certificate, the system-secret keys, validation of the issued chains by rustls,
//! full in-memory TLS handshakes, renewal and the absence of private keys in the store.

use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration as StdDuration,
};

use rcgen::{CertificateParams, KeyPair};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig,
    ServerConnection,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject,
    },
    server::WebPkiClientVerifier,
};
use tenko_cluster::ca::{
    CA_CREATE, CA_KEY_PURPOSE, CaError, CaPolicy, CertInfo, ExpiryState, InternalCa,
    SERVER_CERT_ISSUE, ServerCertRecord, ServerIdentity, TLS_KEY_PURPOSE, TlsMaterial, TlsPolicy,
    TlsResolver, node_id_of, node_uri, tables,
};
use tenko_core::{NodeId, RequestCtx, SystemComponent, Timestamp, secret::SecretClass};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt, Store, TableName, WriteBatch, mem::MemStore,
    tables as store_tables,
};
use tenko_vault::{MemVault, SecretBytes, Vault, VaultError};
use time::{Duration, OffsetDateTime};

const HOST: &str = "tenko.example.net";
const ALT: &str = "ddi.lan";
const ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// A store with a vault over it.
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

    async fn init(&self, ctx: &RequestCtx) -> InternalCa {
        InternalCa::init(&*self.store, &self.vault, ctx, CaPolicy::default())
            .await
            .expect("init")
    }

    async fn load(&self, ctx: &RequestCtx) -> Result<Option<InternalCa>, CaError> {
        InternalCa::load(&*self.store, &self.vault, ctx, CaPolicy::default()).await
    }

    async fn material(
        &self,
        ca: &InternalCa,
        ctx: &RequestCtx,
        identity: &ServerIdentity,
    ) -> Result<TlsMaterial, CaError> {
        ca.server_material(&*self.store, &self.vault, ctx, identity)
            .await
    }

    async fn server_record(&self) -> Option<ServerCertRecord> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(&tables::SERVER_CERT, &())
            .expect("read")
            .map(|(record, _)| record)
    }

    /// The audit actions of the CA (the vault audits its own secret writes as well).
    async fn audit_actions(&self) -> Vec<String> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&store_tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record.draft.action.as_str().to_owned())
            .filter(|action| action.starts_with("cluster."))
            .collect()
    }
}

fn t0() -> Timestamp {
    Timestamp(OffsetDateTime::from_unix_timestamp(1_790_000_000).expect("timestamp"))
}

fn after(ts: Timestamp, days: i64) -> Timestamp {
    Timestamp(ts.0 + Duration::days(days))
}

fn ctx_at(ts: Timestamp) -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster).at(ts)
}

fn identity() -> ServerIdentity {
    ServerIdentity::new(HOST)
        .with_name(ALT)
        .with_address(IpAddr::V4(ADDRESS_V4))
        .with_address(IpAddr::V6(ADDRESS_V6))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn roots_of(root: &CertificateDer<'static>) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).expect("trust anchor");
    Arc::new(roots)
}

fn unix(ts: Timestamp) -> UnixTime {
    let seconds = u64::try_from(ts.0.unix_timestamp()).expect("positive");
    UnixTime::since_unix_epoch(StdDuration::from_secs(seconds))
}

fn server_name(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).expect("server name")
}

fn server_verifier(root: &CertificateDer<'static>) -> Arc<WebPkiServerVerifier> {
    WebPkiServerVerifier::builder_with_provider(roots_of(root), provider())
        .build()
        .expect("server verifier")
}

fn verify_server(
    root: &CertificateDer<'static>,
    leaf: &CertificateDer<'static>,
    name: &str,
    at: Timestamp,
) -> Result<(), rustls::Error> {
    server_verifier(root)
        .verify_server_cert(leaf, &[], &server_name(name), &[], unix(at))
        .map(|_| ())
}

fn pkcs8_key(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))
}

fn client_connection(
    root: &CertificateDer<'static>,
    name: &str,
    auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Connection {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots_of(root));
    let mut config = match auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client auth"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    ClientConnection::new(Arc::new(config), server_name(name))
        .expect("client")
        .into()
}

fn server_connection(material: &TlsMaterial, policy: TlsPolicy) -> Connection {
    let config = material.server_config(policy).expect("server config");
    ServerConnection::new(config).expect("server").into()
}

fn mutual_server_connection(material: &TlsMaterial, root: &CertificateDer<'static>) -> Connection {
    let verifier = WebPkiClientVerifier::builder_with_provider(roots_of(root), provider())
        .build()
        .expect("client verifier");
    let resolver = TlsResolver::default();
    resolver.set(Some(material.clone()));
    let mut config: ServerConfig = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec()];
    ServerConnection::new(Arc::new(config))
        .expect("server")
        .into()
}

/// Moves what `from` has to say into `to`.
fn shuttle(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).expect("write to memory");
    }
    let mut input = wire.as_slice();
    while !input.is_empty() {
        let read = to.read_tls(&mut input).expect("read from memory");
        to.process_new_packets()?;
        if read == 0 {
            break;
        }
    }
    Ok(())
}

/// Runs the handshake until neither side is handshaking.
fn handshake(client: &mut Connection, server: &mut Connection) -> Result<(), rustls::Error> {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        shuttle(client, server)?;
        shuttle(server, client)?;
    }
    panic!("the handshake does not finish");
}

fn is_name_error(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    )
}

fn is_unknown_issuer(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    )
}

#[tokio::test]
async fn init_then_load_gives_the_same_root() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    assert!(env.load(&ctx).await.expect("load").is_none());

    let created = env.init(&ctx).await;
    let loaded = env.load(&ctx).await.expect("load").expect("the CA exists");
    assert_eq!(created.root_der(), loaded.root_der());
    assert_eq!(created.root_pem(), loaded.root_pem());
    assert_eq!(created.root_info(), loaded.root_info());
    assert_eq!(created.record(), loaded.record());
    assert_eq!(created.record().created_at, t0());
    assert_eq!(env.audit_actions().await, [CA_CREATE.as_str()]);
}

#[tokio::test]
async fn a_second_init_is_already_initialized() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let first = env.init(&ctx).await;
    let again = InternalCa::init(&*env.store, &env.vault, &ctx, CaPolicy::default()).await;
    assert!(matches!(again, Err(CaError::AlreadyInitialized)));

    let loaded = env.load(&ctx).await.expect("load").expect("the CA exists");
    assert_eq!(first.root_der(), loaded.root_der());
    assert_eq!(env.audit_actions().await.len(), 1);
}

#[tokio::test]
async fn load_or_init_creates_the_root_once() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let policy = CaPolicy::default();
    let first = InternalCa::load_or_init(&*env.store, &env.vault, &ctx, policy)
        .await
        .expect("create");
    let second = InternalCa::load_or_init(&*env.store, &env.vault, &ctx, policy)
        .await
        .expect("load");
    assert_eq!(first.root_der(), second.root_der());

    let other = Env::new();
    let (a, b) = tokio::join!(
        InternalCa::load_or_init(&*other.store, &other.vault, &ctx, policy),
        InternalCa::load_or_init(&*other.store, &other.vault, &ctx, policy),
    );
    let (a, b) = (a.expect("first racer"), b.expect("second racer"));
    assert_eq!(a.root_der(), b.root_der());
    assert_eq!(other.audit_actions().await.len(), 1);
}

#[tokio::test]
async fn root_pem_parses_and_describes_the_root() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let pem = ca.root_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    let parsed = CertificateDer::from_pem_slice(pem.as_bytes()).expect("PEM");
    assert_eq!(&parsed, ca.root_der());

    let info = ca.root_info();
    assert!(info.is_ca);
    assert!(info.subject.contains("O=Tenko DDI"), "{}", info.subject);
    assert!(
        info.subject.contains("CN=Tenko DDI local CA "),
        "{}",
        info.subject
    );
    assert_eq!(info.subject, info.issuer);
    assert_eq!(info.not_before.0, t0().0 - Duration::hours(1));
    assert_eq!(info.not_after, after(t0(), 3650));
    assert_eq!(info, &CertInfo::from_der(&parsed).expect("info"));
    let _anchors = roots_of(&parsed);
}

#[tokio::test]
async fn the_ca_key_is_a_system_secret() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let key = ca.record().key;

    let meta = env
        .vault
        .meta(key)
        .await
        .expect("meta")
        .expect("the key exists");
    assert_eq!(meta.id, key.secret);
    assert_eq!(meta.class, SecretClass::System);
    assert_eq!(meta.purpose, CA_KEY_PURPOSE);
    assert_eq!(meta.purpose.as_str(), "cluster.ca_key");

    let refused = env.vault.reveal(&ctx, key).await;
    assert!(matches!(refused, Err(VaultError::NotRevealable { .. })));
    let value = env.vault.get_system(&ctx, key).await.expect("system use");
    assert!(!value.is_empty());
}

#[tokio::test]
async fn load_rejects_a_key_that_does_not_match_the_root() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let other = KeyPair::generate().expect("key");
    env.vault
        .replace(
            &ctx,
            ca.record().key,
            SecretBytes::from_slice(other.serialized_der()),
        )
        .await
        .expect("replace");
    let loaded = env.load(&ctx).await;
    assert!(matches!(loaded, Err(CaError::Corrupt { .. })), "{loaded:?}");
}

#[tokio::test]
async fn rustls_accepts_the_server_certificate_for_its_names() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let issued = ca.issue_server_cert(&identity(), t0()).expect("server");
    let leaf = &issued.chain[0];
    for name in [HOST, ALT, "192.0.2.10", "2001:db8::1"] {
        verify_server(ca.root_der(), leaf, name, t0()).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    assert_eq!(issued.info.dns_names, [HOST, ALT]);
    assert_eq!(
        issued.info.ip_addresses,
        [IpAddr::V4(ADDRESS_V4), IpAddr::V6(ADDRESS_V6)]
    );
    assert_eq!(issued.info.not_after, after(t0(), 397));
    assert_eq!(issued.chain_pem().matches("BEGIN CERTIFICATE").count(), 1);
}

#[tokio::test]
async fn rustls_rejects_wrong_names_other_roots_and_other_times() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let issued = ca.issue_server_cert(&identity(), t0()).expect("server");
    let leaf = &issued.chain[0];

    for name in ["other.example.net", "tenko", "192.0.2.11", "2001:db8::2"] {
        let error = verify_server(ca.root_der(), leaf, name, t0()).expect_err(name);
        assert!(is_name_error(&error), "{name}: {error:?}");
    }

    let stranger = Env::new();
    let other_ca = stranger.init(&ctx).await;
    let error = verify_server(other_ca.root_der(), leaf, HOST, t0()).expect_err("other root");
    assert!(is_unknown_issuer(&error), "{error:?}");

    let late = after(t0(), 400);
    let error = verify_server(ca.root_der(), leaf, HOST, late).expect_err("expired");
    assert!(matches!(
        error,
        rustls::Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. }
        )
    ));
    let early = Timestamp(t0().0 - Duration::days(1));
    let error = verify_server(ca.root_der(), leaf, HOST, early).expect_err("not yet valid");
    assert!(matches!(
        error,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
        )
    ));
    // The one hour of clock skew is covered.
    verify_server(
        ca.root_der(),
        leaf,
        HOST,
        Timestamp(t0().0 - Duration::minutes(30)),
    )
    .expect("within the skew allowance");
}

#[tokio::test]
async fn a_full_tls_handshake_negotiates_h2() {
    let env = Env::new();
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = env.init(&ctx).await;
    let material = env
        .material(&ca, &ctx, &identity())
        .await
        .expect("material");

    for policy in [TlsPolicy::default(), TlsPolicy { tls13_only: true }] {
        for name in [HOST, ALT, "192.0.2.10"] {
            let mut client = client_connection(ca.root_der(), name, None);
            let mut server = server_connection(&material, policy);
            handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
            assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
            let seen = client.peer_certificates().expect("server certificate");
            assert_eq!(seen[0], material.chain()[0]);
            if policy.tls13_only {
                assert_eq!(
                    client.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
            }

            client.writer().write_all(b"ping").expect("write");
            shuttle(&mut client, &mut server).expect("deliver");
            let mut received = [0u8; 4];
            server.reader().read_exact(&mut received).expect("read");
            assert_eq!(&received, b"ping");
        }
    }
}

#[tokio::test]
async fn a_handshake_fails_for_the_wrong_name_and_the_wrong_root() {
    let env = Env::new();
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = env.init(&ctx).await;
    let material = env
        .material(&ca, &ctx, &identity())
        .await
        .expect("material");

    let mut client = client_connection(ca.root_der(), "other.example.net", None);
    let mut server = server_connection(&material, TlsPolicy::default());
    let error = handshake(&mut client, &mut server).expect_err("wrong name");
    assert!(is_name_error(&error), "{error:?}");

    let stranger = Env::new();
    let other_ca = stranger.init(&ctx).await;
    let mut client = client_connection(other_ca.root_der(), HOST, None);
    let mut server = server_connection(&material, TlsPolicy::default());
    let error = handshake(&mut client, &mut server).expect_err("wrong root");
    assert!(is_unknown_issuer(&error), "{error:?}");
}

#[tokio::test]
async fn node_certificates_verify_as_client_certificates() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let verifier = WebPkiClientVerifier::builder_with_provider(roots_of(ca.root_der()), provider())
        .build()
        .expect("client verifier");

    let with_key = ca.issue_node_cert_with_key(NodeId(5), t0()).expect("node");
    verifier
        .verify_client_cert(&with_key.chain[0], &[], unix(t0()))
        .expect("a node certificate is a client certificate");
    assert_eq!(node_id_of(&with_key.chain[0]), Some(NodeId(5)));
    assert_eq!(with_key.info.uris, [node_uri(NodeId(5))]);

    let key = KeyPair::generate().expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let from_csr = ca
        .issue_node_cert(NodeId(8), csr.der(), t0())
        .expect("node");
    verifier
        .verify_client_cert(&from_csr.chain[0], &[], unix(t0()))
        .expect("a node certificate for a request");
    assert_eq!(node_id_of(&from_csr.chain[0]), Some(NodeId(8)));
    assert_eq!(from_csr.node, NodeId(8));
    assert_eq!(from_csr.info.not_after, after(t0(), 365));

    let server = ca.issue_server_cert(&identity(), t0()).expect("server");
    assert!(
        verifier
            .verify_client_cert(&server.chain[0], &[], unix(t0()))
            .is_err()
    );
    assert!(
        verifier
            .verify_client_cert(&with_key.chain[0], &[], unix(after(t0(), 400)))
            .is_err()
    );

    let stranger = Env::new().init(&ctx).await;
    let foreign = stranger
        .issue_node_cert_with_key(NodeId(5), t0())
        .expect("node");
    let error = verifier
        .verify_client_cert(&foreign.chain[0], &[], unix(t0()))
        .expect_err("a node of another cluster");
    assert!(is_unknown_issuer(&error), "{error:?}");

    let garbage = ca.issue_node_cert(NodeId(9), b"not a request", t0());
    assert!(matches!(garbage, Err(CaError::InvalidCsr { .. })));
}

#[tokio::test]
async fn mutual_tls_between_a_server_and_a_node() {
    let env = Env::new();
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let ca = env.init(&ctx).await;
    let material = env
        .material(&ca, &ctx, &identity())
        .await
        .expect("material");

    let node = ca
        .issue_node_cert_with_key(NodeId(5), ctx.now)
        .expect("node");
    let auth = (node.chain.clone(), pkcs8_key(node.key.expose()));
    let mut client = client_connection(ca.root_der(), HOST, Some(auth));
    let mut server = mutual_server_connection(&material, ca.root_der());
    handshake(&mut client, &mut server).expect("mutual handshake");
    let peer = server.peer_certificates().expect("client certificate");
    assert_eq!(peer[0], node.chain[0]);
    assert_eq!(node_id_of(&peer[0]), Some(NodeId(5)));

    // A node enrolled with its own key through a request.
    let key = KeyPair::generate().expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let enrolled = ca
        .issue_node_cert(NodeId(6), csr.der(), ctx.now)
        .expect("node");
    let auth = (enrolled.chain.clone(), pkcs8_key(key.serialized_der()));
    let mut client = client_connection(ca.root_der(), HOST, Some(auth));
    let mut server = mutual_server_connection(&material, ca.root_der());
    handshake(&mut client, &mut server).expect("mutual handshake");
    let peer = server.peer_certificates().expect("client certificate");
    assert_eq!(node_id_of(&peer[0]), Some(NodeId(6)));

    // A client without a certificate is refused.
    let mut anonymous = client_connection(ca.root_der(), HOST, None);
    let mut server = mutual_server_connection(&material, ca.root_der());
    assert!(handshake(&mut anonymous, &mut server).is_err());
}

#[tokio::test]
async fn server_material_issues_once_and_reuses_the_certificate() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    assert!(env.server_record().await.is_none());

    let first = env.material(&ca, &ctx, &identity()).await.expect("first");
    let record = env.server_record().await.expect("stored");
    let again = env
        .material(&ca, &ctx_at(after(t0(), 10)), &identity())
        .await
        .expect("second");
    assert_eq!(first.info().sha256, again.info().sha256);
    assert_eq!(first.chain(), again.chain());
    assert_eq!(env.server_record().await.expect("stored"), record);
    assert_eq!(record.identity, identity());
    assert_eq!(record.issued_at, t0());
    let stored_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(record.chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("stored chain");
    assert_eq!(stored_chain, first.chain());

    let actions = env.audit_actions().await;
    assert_eq!(actions, [CA_CREATE.as_str(), SERVER_CERT_ISSUE.as_str()]);

    let meta = env
        .vault
        .meta(record.key)
        .await
        .expect("meta")
        .expect("the key exists");
    assert_eq!(meta.class, SecretClass::System);
    assert_eq!(meta.purpose, TLS_KEY_PURPOSE);
    let refused = env.vault.reveal(&ctx, record.key).await;
    assert!(matches!(refused, Err(VaultError::NotRevealable { .. })));

    // After a restart the stored certificate is still the one served.
    let loaded = env.load(&ctx).await.expect("load").expect("exists");
    let restarted = env
        .material(&loaded, &ctx_at(after(t0(), 20)), &identity())
        .await
        .expect("third");
    assert_eq!(restarted.info().sha256, first.info().sha256);
    verify_server(ca.root_der(), &restarted.chain()[0], HOST, after(t0(), 20)).expect("valid");
}

#[tokio::test]
async fn server_material_reissues_when_the_identity_changes() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let first = env.material(&ca, &ctx, &identity()).await.expect("first");
    let old = env.server_record().await.expect("stored");

    let renamed = ServerIdentity::new("renamed.example.net").with_address(IpAddr::V4(ADDRESS_V4));
    let later = ctx_at(after(t0(), 1));
    let second = env.material(&ca, &later, &renamed).await.expect("second");
    assert_ne!(first.info().sha256, second.info().sha256);
    assert_eq!(second.info().dns_names, ["renamed.example.net"]);
    verify_server(
        ca.root_der(),
        &second.chain()[0],
        "renamed.example.net",
        after(t0(), 1),
    )
    .expect("valid for the new name");
    assert!(verify_server(ca.root_der(), &second.chain()[0], HOST, after(t0(), 1)).is_err());

    let new = env.server_record().await.expect("stored");
    assert_eq!(new.identity, renamed);
    assert_eq!(new.issued_at, after(t0(), 1));
    assert_ne!(new.key, old.key);
    assert!(
        env.vault.meta(old.key).await.expect("meta").is_none(),
        "the old key is deleted"
    );
    assert!(matches!(
        env.vault.get_system(&ctx, old.key).await,
        Err(VaultError::NotFound { .. })
    ));
    let meta = env
        .vault
        .meta(new.key)
        .await
        .expect("meta")
        .expect("the new key exists");
    assert_eq!(meta.purpose, TLS_KEY_PURPOSE);
    assert_eq!(meta.class, SecretClass::System);

    // Asking for the same identity again keeps the new certificate.
    let same = env
        .material(&ca, &ctx_at(after(t0(), 2)), &renamed)
        .await
        .expect("third");
    assert_eq!(same.info().sha256, second.info().sha256);
    let tls_keys = env
        .vault
        .list()
        .await
        .expect("list")
        .into_iter()
        .filter(|meta| meta.purpose == TLS_KEY_PURPOSE)
        .count();
    assert_eq!(tls_keys, 1);
    assert_eq!(
        env.audit_actions()
            .await
            .iter()
            .filter(|a| *a == SERVER_CERT_ISSUE.as_str())
            .count(),
        2
    );
}

#[tokio::test]
async fn server_material_renews_within_thirty_days_of_expiry() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let first = env.material(&ca, &ctx, &identity()).await.expect("first");
    let old = env.server_record().await.expect("stored");
    assert_eq!(first.info().not_after, after(t0(), 397));

    // 31 days left: kept. 29 days left: renewed.
    let early = env
        .material(&ca, &ctx_at(after(t0(), 366)), &identity())
        .await
        .expect("kept");
    assert_eq!(early.info().sha256, first.info().sha256);
    assert!(env.vault.meta(old.key).await.expect("meta").is_some());

    let soon = after(t0(), 370);
    let renewed = env
        .material(&ca, &ctx_at(soon), &identity())
        .await
        .expect("renewed");
    assert_ne!(renewed.info().sha256, first.info().sha256);
    assert_eq!(renewed.info().not_before.0, soon.0 - Duration::hours(1));
    assert_eq!(renewed.info().not_after, after(soon, 397));
    verify_server(ca.root_der(), &renewed.chain()[0], HOST, soon).expect("valid after renewal");
    assert!(
        env.vault.meta(old.key).await.expect("meta").is_none(),
        "the old key is deleted"
    );

    let record = env.server_record().await.expect("stored");
    assert_eq!(record.issued_at, soon);
    assert_eq!(record.identity, identity());
    assert_ne!(record.key, old.key);
    let again = env
        .material(&ca, &ctx_at(after(soon, 1)), &identity())
        .await
        .expect("kept");
    assert_eq!(again.info().sha256, renewed.info().sha256);

    // An expired certificate is replaced too.
    let expired = after(soon, 400);
    let last = env
        .material(&ca, &ctx_at(expired), &identity())
        .await
        .expect("replaced");
    assert_ne!(last.info().sha256, renewed.info().sha256);
    assert_eq!(last.info().expiry(expired).state, ExpiryState::Valid);
}

#[tokio::test]
async fn an_invalid_identity_changes_nothing() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let first = env.material(&ca, &ctx, &identity()).await.expect("first");
    let record = env.server_record().await.expect("stored");
    let actions = env.audit_actions().await;

    for bad in [
        ServerIdentity::new("*.example.net"),
        ServerIdentity::new("10.0.0.1"),
        ServerIdentity::new(HOST).with_name("bad_name.example.net"),
        ServerIdentity::new(""),
    ] {
        let result = env.material(&ca, &ctx_at(after(t0(), 1)), &bad).await;
        assert!(
            matches!(result, Err(CaError::InvalidName { .. })),
            "{bad:?}"
        );
    }
    assert_eq!(env.server_record().await.expect("stored"), record);
    assert_eq!(env.audit_actions().await, actions);
    assert!(env.vault.meta(record.key).await.expect("meta").is_some());
    let kept = env
        .material(&ca, &ctx_at(after(t0(), 2)), &identity())
        .await
        .expect("kept");
    assert_eq!(kept.info().sha256, first.info().sha256);
}

#[tokio::test]
async fn expiry_reporting_follows_the_thresholds() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let info = ca
        .issue_server_cert(&identity(), t0())
        .expect("server")
        .info;
    let end = info.not_after;
    let before_end = |d: Duration| Timestamp(end.0 - d);

    let cases = [
        (before_end(Duration::days(397)), ExpiryState::Valid, 397),
        (before_end(Duration::days(31)), ExpiryState::Valid, 31),
        (before_end(Duration::days(30)), ExpiryState::Valid, 30),
        (
            before_end(Duration::days(30) - Duration::seconds(1)),
            ExpiryState::Warning,
            29,
        ),
        (before_end(Duration::days(29)), ExpiryState::Warning, 29),
        (before_end(Duration::days(7)), ExpiryState::Warning, 7),
        (
            before_end(Duration::days(7) - Duration::seconds(1)),
            ExpiryState::Critical,
            6,
        ),
        (before_end(Duration::days(1)), ExpiryState::Critical, 1),
        (before_end(Duration::seconds(1)), ExpiryState::Critical, 0),
        (end, ExpiryState::Expired, 0),
        (
            Timestamp(end.0 + Duration::days(1)),
            ExpiryState::Expired,
            -1,
        ),
        (
            Timestamp(info.not_before.0 - Duration::seconds(1)),
            ExpiryState::NotYetValid,
            397,
        ),
    ];
    for (now, state, days) in cases {
        let expiry = info.expiry(now);
        assert_eq!(expiry.state, state, "{now:?}");
        assert_eq!(expiry.days_left, days, "{now:?}");
        assert_eq!(expiry.not_after, end);
    }

    let renewal = |now| ca.needs_renewal(&info, now);
    assert!(!renewal(before_end(Duration::days(30))));
    assert!(renewal(before_end(
        Duration::days(30) - Duration::seconds(1)
    )));
    assert!(renewal(end));
    assert!(!renewal(t0()));
}

/// The windows of a PKCS#8 key that must never appear in a store table: the whole encoding,
/// a window from its middle and the 32-byte private scalar.
fn needles(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    let middle = pkcs8.len() / 2;
    let scalar = pkcs8
        .windows(2)
        .position(|window| window == [0x04, 0x20])
        .expect("the private scalar follows an OCTET STRING header")
        + 2;
    vec![
        pkcs8.to_vec(),
        pkcs8[middle - 8..middle + 8].to_vec(),
        pkcs8[scalar..scalar + 32].to_vec(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every key and value of every table the journal ever mentions, plus the audit log.
async fn dump_store(store: &MemStore) -> Vec<(TableName, Vec<u8>)> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let journal = view
        .scan_typed(&store_tables::JOURNAL, KeyRange::all(), usize::MAX, false)
        .expect("journal");
    let mut names = BTreeSet::new();
    names.insert(store_tables::AUDIT.name().clone());
    names.insert(store_tables::JOURNAL.name().clone());
    for (_, change_set, _) in journal {
        names.extend(change_set.changes.into_iter().map(|change| change.table));
    }
    let mut rows = Vec::new();
    for name in names {
        for (key, value) in view
            .scan(&name, KeyRange::all(), usize::MAX, false)
            .expect("scan")
        {
            rows.push((name.clone(), key.to_vec()));
            rows.push((name.clone(), value.value.to_vec()));
        }
    }
    rows
}

#[tokio::test]
async fn no_store_table_contains_a_private_key() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let mut keys: Vec<SecretBytes> = Vec::new();
    keys.push(
        env.vault
            .get_system(&ctx, ca.record().key)
            .await
            .expect("CA key"),
    );

    // Issue, rename, renew; remember every TLS key before it is deleted.
    env.material(&ca, &ctx, &identity()).await.expect("first");
    let record = env.server_record().await.expect("stored");
    keys.push(
        env.vault
            .get_system(&ctx, record.key)
            .await
            .expect("TLS key"),
    );
    let renamed = ServerIdentity::new("renamed.example.net");
    env.material(&ca, &ctx_at(after(t0(), 1)), &renamed)
        .await
        .expect("second");
    let record = env.server_record().await.expect("stored");
    keys.push(
        env.vault
            .get_system(&ctx, record.key)
            .await
            .expect("TLS key"),
    );
    env.material(&ca, &ctx_at(after(t0(), 400)), &renamed)
        .await
        .expect("third");
    let record = env.server_record().await.expect("stored");
    keys.push(
        env.vault
            .get_system(&ctx, record.key)
            .await
            .expect("TLS key"),
    );

    // Keys that are generated for callers and never stored.
    keys.push(ca.issue_server_cert(&identity(), t0()).expect("server").key);
    keys.push(
        ca.issue_node_cert_with_key(NodeId(1), t0())
            .expect("node")
            .key,
    );
    assert_eq!(
        keys.iter()
            .map(|key| key.expose().to_vec())
            .collect::<BTreeSet<_>>()
            .len(),
        keys.len(),
        "every key is distinct"
    );

    let rows = dump_store(&env.store).await;
    let tables: BTreeSet<&str> = rows.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "cluster.ca",
        "cluster.server_cert",
        "sys.audit",
        "sys.journal",
    ] {
        assert!(
            tables.contains(expected),
            "{expected} is scanned: {tables:?}"
        );
    }
    assert!(
        tables.iter().any(|name| name.starts_with("vault.")),
        "{tables:?}"
    );

    // The scan sees what it is meant to see: the public root certificate is stored.
    let root_pem = ca.root_pem();
    assert!(
        rows.iter()
            .any(|(name, bytes)| name.as_str() == "cluster.ca"
                && contains(bytes, root_pem.as_bytes()))
    );

    for key in &keys {
        for needle in needles(key.expose()) {
            for (name, bytes) in &rows {
                assert!(!contains(bytes, &needle), "private key material in {name}");
            }
        }
    }
}

#[tokio::test]
async fn the_key_scan_detects_a_key_stored_in_the_clear() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let key = KeyPair::generate().expect("key");
    let mut batch = WriteBatch::for_request(&ctx);
    batch.put(
        TableName::from_static("cluster.leak"),
        b"key".to_vec(),
        key.serialized_der().to_vec(),
    );
    env.store.propose(batch).await.expect("write");

    let rows = dump_store(&env.store).await;
    let found = needles(key.serialized_der()).iter().all(|needle| {
        rows.iter()
            .any(|(name, bytes)| name.as_str() == "cluster.leak" && contains(bytes, needle))
    });
    assert!(found, "the scan must see a key written in the clear");
}

#[tokio::test]
async fn server_material_recovers_from_a_lost_key() {
    let env = Env::new();
    let ctx = ctx_at(t0());
    let ca = env.init(&ctx).await;
    let first = env.material(&ca, &ctx, &identity()).await.expect("first");
    let old = env.server_record().await.expect("stored");
    env.vault.delete(&ctx, old.key).await.expect("delete");

    let second = env
        .material(&ca, &ctx_at(after(t0(), 1)), &identity())
        .await
        .expect("a lost key is replaced, not fatal");
    assert_ne!(first.info().sha256, second.info().sha256);
    let new = env.server_record().await.expect("stored");
    assert_ne!(new.key, old.key);
    assert!(env.vault.meta(new.key).await.expect("meta").is_some());
}
