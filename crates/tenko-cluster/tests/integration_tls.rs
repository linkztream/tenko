//! The TLS of the integration listener (ADR 0035, decision 3) in memory: a recorded
//! integration certificate completes the handshake, everything else does not; TLS 1.2 only
//! when allowed; no resumption; the certificate request names only the integration root.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use rcgen::{CertificateParams, KeyPair};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Connection, HandshakeKind, ProtocolVersion,
    RootCertStore, ServerConnection, SignatureScheme,
    client::{ClientSessionMemoryCache, ResolvesClientCert, Resumption},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    sign::CertifiedKey,
};
use tenko_cluster::{
    ca::{CaPolicy, IntegrationCa, IntegrationIdentity, InternalCa, ServerIdentity, TlsResolver},
    client_tls::{CertificateGate, integration_server_config},
};
use tenko_core::{NodeId, RequestCtx, SystemComponent, Timestamp, UserId};
use tenko_store::mem::MemStore;
use tenko_vault::MemVault;

const HOST: &str = "tenko.example.test";

/// Admits what it is told to.
struct Gate(AtomicBool);

impl CertificateGate for Gate {
    fn admits(&self, _: &IntegrationIdentity, _: Timestamp) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

struct Env {
    internal: InternalCa,
    integration: IntegrationCa,
    resolver: Arc<TlsResolver>,
    gate: Arc<Gate>,
}

impl Env {
    async fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let vault = MemVault::with_store(store.clone());
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let internal = InternalCa::load_or_init(&*store, &vault, &ctx, CaPolicy::default())
            .await
            .expect("internal CA");
        let integration = IntegrationCa::load_or_init(&*store, &vault, &ctx)
            .await
            .expect("integration CA");
        let resolver = Arc::new(TlsResolver::default());
        let server = internal
            .issue_server_cert(&ServerIdentity::new(HOST), ctx.now)
            .expect("server certificate");
        resolver.set(Some(server.material().expect("material")));
        Self {
            internal,
            integration,
            resolver,
            gate: Arc::new(Gate(AtomicBool::new(true))),
        }
    }

    /// An integration certificate and its key.
    fn client(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let issued = self
            .integration
            .issue(UserId::generate(), csr.der(), Timestamp::now(), 30)
            .expect("issue");
        (vec![issued.cert], pkcs8(&key))
    }

    fn server(&self, allow_tls12: bool) -> Connection {
        let config = integration_server_config(
            self.integration.root_der(),
            self.resolver.clone(),
            self.gate.clone(),
            allow_tls12,
        )
        .expect("config");
        ServerConnection::new(config).expect("server").into()
    }

    fn client_config(
        &self,
        auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> ClientConfig {
        let builder = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .expect("versions")
            .with_root_certificates(roots_of(self.internal.root_der()));
        let mut config = match auth {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key).expect("auth"),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }
}

fn pkcs8(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn roots_of(root: &CertificateDer<'static>) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).expect("anchor");
    Arc::new(roots)
}

fn connect(config: ClientConfig) -> Connection {
    ClientConnection::new(Arc::new(config), ServerName::try_from(HOST).expect("name"))
        .expect("client")
        .into()
}

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

/// Runs the handshake; the error is the server's when it refuses.
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

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

#[tokio::test]
async fn a_recorded_integration_certificate_completes_the_handshake() {
    let env = Env::new().await;
    let mut client = connect(env.client_config(Some(env.client()), TLS13));
    let mut server = env.server(false);
    handshake(&mut client, &mut server).expect("handshake");
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
    let Connection::Server(server) = &server else {
        unreachable!()
    };
    let presented = server.peer_certificates().expect("a client certificate");
    IntegrationIdentity::from_der(&presented[0]).expect("an integration certificate");
}

#[tokio::test]
async fn the_gate_no_certificate_and_a_node_certificate_are_refused() {
    let env = Env::new().await;
    env.gate.0.store(false, Ordering::SeqCst);
    let mut client = connect(env.client_config(Some(env.client()), TLS13));
    let error = handshake(&mut client, &mut env.server(false)).expect_err("not admitted");
    assert_eq!(
        error,
        rustls::Error::InvalidCertificate(CertificateError::Revoked)
    );
    env.gate.0.store(true, Ordering::SeqCst);

    let mut client = connect(env.client_config(None, TLS13));
    let error = handshake(&mut client, &mut env.server(false)).expect_err("no certificate");
    assert!(
        matches!(error, rustls::Error::NoCertificatesPresented),
        "{error:?}"
    );

    let node = env
        .internal
        .issue_node_cert_with_key(NodeId(3), Timestamp::now())
        .expect("node");
    let node_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(node.key.expose().to_vec()));
    let mut client = connect(env.client_config(Some((node.chain, node_key)), TLS13));
    let error = handshake(&mut client, &mut env.server(false)).expect_err("a node");
    assert_eq!(
        error,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
}

#[tokio::test]
async fn tls_1_2_only_when_allowed_and_never_resumed() {
    let env = Env::new().await;
    let mut client = connect(env.client_config(Some(env.client()), TLS12));
    let error = handshake(&mut client, &mut env.server(false)).expect_err("TLS 1.2 is off");
    assert!(
        matches!(error, rustls::Error::PeerIncompatible(_)),
        "TLS 1.2 is refused by default: {error:?}"
    );

    let mut config = env.client_config(Some(env.client()), TLS12);
    config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(8)));
    let config = Arc::new(config);
    for _ in 0..2 {
        let mut client: Connection = ClientConnection::new(
            Arc::clone(&config),
            ServerName::try_from(HOST).expect("name"),
        )
        .expect("client")
        .into();
        let mut server = env.server(true);
        handshake(&mut client, &mut server).expect("TLS 1.2 when allowed");
        assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }

    let mut config = env.client_config(Some(env.client()), TLS13);
    config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(8)));
    let config = Arc::new(config);
    for _ in 0..2 {
        let mut client: Connection = ClientConnection::new(
            Arc::clone(&config),
            ServerName::try_from(HOST).expect("name"),
        )
        .expect("client")
        .into();
        let mut server = env.server(false);
        handshake(&mut client, &mut server).expect("TLS 1.3");
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }
}

/// The transport's client resumes no TLS session, even from a server that hands out
/// tickets, so every connection runs the certificate checks; the same configuration with a
/// session cache does resume.
#[tokio::test]
async fn the_cluster_client_resumes_no_tls_session() {
    let env = Env::new().await;
    let issued = env
        .internal
        .issue_node_cert_with_key_for(
            NodeId(2),
            [tenko_core::Role::Controller].into_iter().collect(),
            Timestamp::now(),
        )
        .expect("controller certificate");
    let resolver = Arc::new(TlsResolver::default());
    resolver.set(Some(
        tenko_cluster::ca::TlsMaterial::from_der(
            issued.chain.clone(),
            &issued.key,
            tenko_cluster::ca::CertSource::Inline,
        )
        .expect("material"),
    ));
    let mut server = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(TLS13)
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server.alpn_protocols = vec![b"h2".to_vec()];
    let server = Arc::new(server);
    let config =
        tenko_cluster::mtls::client_config(env.internal.root_der(), issued.chain, &issued.key)
            .expect("client config");
    let mut caching = ClientConfig::clone(&*config);
    caching.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(8)));
    for (config, second) in [
        (config, HandshakeKind::Full),
        (Arc::new(caching), HandshakeKind::Resumed),
    ] {
        let mut kinds = Vec::new();
        for _ in 0..2 {
            let mut client: Connection = ClientConnection::new(
                Arc::clone(&config),
                ServerName::try_from(HOST).expect("name"),
            )
            .expect("client")
            .into();
            let mut connection: Connection = ServerConnection::new(Arc::clone(&server))
                .expect("server")
                .into();
            handshake(&mut client, &mut connection).expect("handshake");
            // The tickets follow the handshake.
            shuttle(&mut connection, &mut client).expect("tickets");
            kinds.push(connection.handshake_kind());
        }
        assert_eq!(kinds, [Some(HandshakeKind::Full), Some(second)]);
    }
}

/// Records the certificate authorities the server names, and presents nothing.
#[derive(Debug, Default)]
struct Hints(Mutex<Vec<Vec<u8>>>);

impl ResolvesClientCert for Hints {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        _: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        *self.0.lock().expect("lock") = root_hint_subjects
            .iter()
            .map(|subject| subject.to_vec())
            .collect();
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn the_certificate_request_names_only_the_integration_root() {
    let env = Env::new().await;
    let hints = Arc::new(Hints::default());
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(TLS13)
        .expect("versions")
        .with_root_certificates(roots_of(env.internal.root_der()))
        .with_client_cert_resolver(hints.clone());
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client = connect(config);
    let _ = handshake(&mut client, &mut env.server(false));
    let hints = hints.0.lock().expect("lock").clone();
    assert_eq!(hints.len(), 1, "one authority");
    let subject = env.integration.root_info().subject.clone();
    let common_name = subject.rsplit("CN=").next().expect("a common name");
    assert!(
        hints[0]
            .windows(common_name.len())
            .any(|window| window == common_name.as_bytes()),
        "the hint names {common_name}"
    );
}
