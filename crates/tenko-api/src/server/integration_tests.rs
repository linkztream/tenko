//! The integration listener over real sockets: when it opens, what its router answers, and
//! when it closes a connection (ADR 0035, decision 3).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::{
    ClientConfig, HandshakeKind, RootCertStore, SupportedProtocolVersion,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject},
};
use tenko_auth::{
    client_cert::{
        ClientCerts, EnrollInput, Issuer as _, NewCode, enrollment_proof,
        model::{CLIENT_CERTS, CertState, ClientCertRecord, IntegrationPolicy},
    },
    encoding::hex_decode,
    model::{SETTINGS, USERS, UserKind, UserRecord},
    settings::Profile,
};
use tenko_cluster::ca::{
    CaPolicy, InternalCa, ServerIdentity, TlsResolver, generate_csr, integration_request_key,
};
use tenko_core::{
    RequestCtx, SystemComponent, Timestamp, UserId,
    auth::Credentials,
    testing::{free_port, wait_until_async},
};
use tenko_store::{MemStore, Store, WriteBatch};
use tenko_vault::{MemVault, Vault};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::{IntegrationListener, MAX_PER_SOURCE, supervise};
use crate::{
    middleware::HttpConfig,
    problem::codes,
    routes::integrations::CaIssuer,
    server::forwarded::{ConnInfo, IntegrationClient},
    state::AppState,
    ui::UiSource,
};

const HOST: &str = "localhost";
const LABEL: &str = "lab-host";

/// A controller's integration listener on a loopback port, with its records.
struct Lab {
    store: Arc<dyn Store>,
    certs: Arc<ClientCerts>,
    issuer: Arc<CaIssuer>,
    internal: Arc<InternalCa>,
    account: UserId,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Which router the listener serves.
enum Serves {
    /// The integration router of the server, with its middleware.
    App,
    /// One route whose answer never ends, to see a connection closed in the middle of it.
    Stream,
}

impl Lab {
    async fn new(serves: Serves) -> Self {
        let mem = Arc::new(MemStore::default());
        let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(mem.clone()));
        let store: Arc<dyn Store> = mem;
        let ctx = RequestCtx::system(SystemComponent::Api);
        let internal = Arc::new(
            InternalCa::load_or_init(&*store, vault.as_ref(), &ctx, CaPolicy::default())
                .await
                .expect("CA"),
        );
        let mut user = UserRecord::new(
            "backup".to_owned(),
            "Backup job".to_owned(),
            Vec::new(),
            ctx.now,
        );
        user.kind = UserKind::Service;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.put_typed(&USERS, &user.id, &user).expect("user");
        batch
            .put_typed(&SETTINGS, &(), &Profile::Home.defaults())
            .expect("settings");
        store.propose(batch).await.expect("stored");
        let issuer = Arc::new(CaIssuer::new(
            Arc::clone(&store),
            Arc::clone(&vault),
            Arc::clone(&internal),
        ));
        let certs = Arc::new(ClientCerts::new(
            Arc::clone(&store),
            vault,
            Arc::clone(&issuer) as _,
        ));
        let resolver = Arc::new(TlsResolver::default());
        let server_cert = internal
            .issue_server_cert(&ServerIdentity::new(HOST), ctx.now)
            .expect("server certificate");
        resolver.set(Some(server_cert.material().expect("material")));
        let router = match serves {
            Serves::App => {
                let state = AppState::new(Arc::clone(&store));
                let mut extensions = axum::http::Extensions::new();
                extensions.insert(Arc::clone(&certs));
                let (_, layers) = super::super::build_app(
                    state.clone(),
                    &HttpConfig::default(),
                    &UiSource::Embedded,
                    extensions.clone(),
                )
                .expect("app");
                super::super::integration_app(state, &layers, extensions)
            }
            Serves::Stream => axum::Router::new().route(
                "/stream",
                axum::routing::get(|| async {
                    let ticks = futures::stream::unfold((), |()| async {
                        tokio::task::yield_now().await;
                        Some((
                            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"tick\n")),
                            (),
                        ))
                    });
                    axum::body::Body::from_stream(ticks)
                }),
            ),
        };
        let port = free_port().release();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(supervise(
            IntegrationListener {
                listen: vec![addr],
                on_demand: true,
                certs: Arc::clone(&certs),
                issuer: Arc::clone(&issuer),
                resolver: resolver as _,
            },
            router,
            Arc::clone(&store),
            Duration::from_secs(30),
            stopped,
        ));
        Self {
            store,
            certs,
            issuer,
            internal,
            account: user.id,
            addr,
            stop,
            task,
        }
    }

    async fn load(&self) {
        self.certs
            .index()
            .load(self.store.as_ref())
            .await
            .expect("load");
    }

    /// Enrolls a host and answers its chain and key; the index is loaded afterwards.
    async fn enroll(&self) -> Client {
        let ctx = RequestCtx::system(SystemComponent::Api);
        let created = self
            .certs
            .create_code(
                &ctx,
                UserId::generate(),
                &NewCode {
                    account: self.account,
                    lifetime_secs: None,
                    source: None,
                },
            )
            .await
            .expect("code");
        let parts: Vec<&str> = created.code.split('.').collect();
        let code = parts[1].parse().expect("code id");
        let secret = hex_decode(parts[3]).expect("secret");
        let (key, csr) = generate_csr().expect("csr");
        let spki = integration_request_key(&csr).expect("key");
        let pem = self
            .certs
            .enroll(
                &ctx,
                EnrollInput {
                    code,
                    proof: enrollment_proof(&secret, code, self.account, LABEL, &spki),
                    csr,
                    label: LABEL.to_owned(),
                    source: None,
                },
            )
            .await
            .expect("enrolled");
        self.load().await;
        Client::new(&pem, key.expose())
    }

    /// A successor of `client`'s certificate, pending, valid from now.
    async fn successor(&self, client: &Client) -> Client {
        let ctx = RequestCtx::system(SystemComponent::Api);
        let (key, csr) = generate_csr().expect("csr");
        let issued = self
            .issuer
            .issue(&ctx, self.account, &csr, 30)
            .await
            .expect("issued");
        let current = self.record(&client.serial).await;
        let mut batch = WriteBatch::for_request(&ctx);
        batch
            .put_typed(
                &CLIENT_CERTS,
                &issued.serial,
                &ClientCertRecord {
                    serial: issued.serial.clone(),
                    key_sha256: issued.key_sha256.clone(),
                    not_before: issued.not_before,
                    not_after: issued.not_after,
                    issued_at: ctx.now,
                    state: CertState::Pending,
                    ..current
                },
            )
            .expect("record");
        self.store.propose(batch).await.expect("stored");
        self.load().await;
        Client::new(&issued.pem, key.expose())
    }

    async fn record(&self, serial: &str) -> ClientCertRecord {
        self.certs
            .list(None)
            .await
            .expect("list")
            .into_iter()
            .find(|record| record.serial == serial)
            .expect("recorded")
    }

    async fn allow_tls12(&self) {
        let mut settings = Profile::Home.defaults();
        settings.integrations = Some(IntegrationPolicy {
            allow_tls12: true,
            ..IntegrationPolicy::of(Profile::Home)
        });
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Api));
        batch
            .put_typed(&SETTINGS, &(), &settings)
            .expect("settings");
        self.store.propose(batch).await.expect("stored");
        self.load().await;
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.internal.root_der().clone()).expect("root");
        Arc::new(roots)
    }

    /// A client configuration over `versions`, with `client`'s certificate when given.
    fn config(
        &self,
        client: Option<&Client>,
        versions: &[&'static SupportedProtocolVersion],
    ) -> Arc<ClientConfig> {
        let builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(self.roots());
        let mut config = match client {
            Some(client) => builder
                .with_client_auth_cert(client.chain.clone(), client.key.clone_key())
                .expect("client auth"),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    async fn connect(&self, config: Arc<ClientConfig>) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(self.addr).await?;
        TlsConnector::from(config)
            .connect(ServerName::try_from(HOST).expect("name"), tcp)
            .await
    }

    async fn open(&self, client: &Client) -> TlsStream<TcpStream> {
        self.connect(self.config(Some(client), &[&rustls::version::TLS13]))
            .await
            .expect("handshake")
    }

    async fn shut(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// A host's certificate chain and key.
struct Client {
    serial: String,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Client {
    fn new(pem: &str, pkcs8: &[u8]) -> Self {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("chain");
        let serial = tenko_cluster::ca::IntegrationIdentity::from_der(&chain[0])
            .expect("identity")
            .serial;
        Self {
            serial,
            chain,
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
        }
    }
}

/// Sends `GET path` and answers the status and the body, keeping the connection open.
async fn get(stream: &mut TlsStream<TcpStream>, path: &str) -> (u16, String) {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
        .await
        .expect("request");
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.expect("head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("text");
    let status = head[9..12].parse().expect("status");
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.expect("body");
    (status, String::from_utf8(body).expect("text"))
}

/// Whether the server has closed the connection: a read ends or fails. It waits for that,
/// and gives up (answering false) only at the shared limit.
async fn closed(stream: &mut TlsStream<TcpStream>) -> bool {
    let mut buffer = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buffer)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

/// How far ahead the boundaries of the boundary test lie: long enough that the change which
/// sets them is handled first, so that the time and not the change ends the answer.
const MARGIN: Duration = Duration::from_secs(3);

/// Whether the streaming answer still delivers: a read answers data.
async fn still_open(stream: &mut TlsStream<TcpStream>) -> bool {
    let mut buffer = [0u8; 64];
    matches!(stream.read(&mut buffer).await, Ok(read) if read > 0)
}

async fn reachable(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

#[tokio::test]
async fn it_opens_after_the_first_load_and_on_demand() {
    let lab = Lab::new(Serves::App).await;
    // Not loaded: nothing could pass, so nothing listens.
    assert!(!reachable(lab.addr).await);
    lab.load().await;
    assert!(
        !reachable(lab.addr).await,
        "no code waits and no certificate is in use"
    );
    let _client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    lab.shut().await;
}

#[tokio::test]
async fn it_serves_the_api_gate_and_nothing_else() {
    let lab = Lab::new(Serves::App).await;
    let client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    // Without a client certificate there is no HTTP at all.
    let mut refused = lab
        .connect(lab.config(None, &[&rustls::version::TLS13]))
        .await;
    if let Ok(stream) = refused.as_mut() {
        // TLS 1.3 reports the refusal of the client's certificate at the first read.
        assert!(closed(stream).await);
    }
    let mut stream = lab.open(&client).await;
    // An authenticated route needs a token of the certificate's account.
    let (status, body) = get(&mut stream, "/api/v1/system/status").await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("integration.token.required"), "{body}");
    // No UI, no static file, no unknown path: problem details.
    for path in [
        "/",
        "/index.html",
        "/assets/app.js",
        "/api/v1/no-such-route",
    ] {
        let (status, body) = get(&mut stream, path).await;
        assert_eq!(status, 404, "{path}: {body}");
        assert!(body.contains(codes::ROUTE_NOT_FOUND), "{path}: {body}");
    }
    lab.shut().await;
}

#[tokio::test]
async fn a_revocation_closes_an_open_answer() {
    let lab = Lab::new(Serves::Stream).await;
    let client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let mut stream = lab.open(&client).await;
    stream
        .write_all(format!("GET /stream HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
        .await
        .expect("request");
    let mut first = [0u8; 64];
    let read = stream.read(&mut first).await.expect("the answer streams");
    assert!(read > 0);
    lab.certs
        .revoke(
            &RequestCtx::system(SystemComponent::Api),
            &client.serial,
            "test",
        )
        .await
        .expect("revoked");
    lab.load().await;
    assert!(closed(&mut stream).await, "the answer was cut off");
    lab.shut().await;
}

#[tokio::test]
async fn an_answer_ends_at_the_bound_of_unread_records_and_at_the_end_of_the_overlap() {
    let lab = Lab::new(Serves::Stream).await;
    let client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let start = |mut stream: TlsStream<TcpStream>| async move {
        stream
            .write_all(format!("GET /stream HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
            .await
            .expect("request");
        let mut first = [0u8; 64];
        assert!(stream.read(&mut first).await.expect("streams") > 0);
        stream
    };

    // Records that could not be read for almost the whole bound: the answer ends when the
    // bound is reached, without any further change of the records.
    let mut stream = start(lab.open(&client).await).await;
    let almost = tenko_auth::client_cert::STALE_LIMIT.saturating_sub(MARGIN);
    lab.certs
        .index()
        .mark_stale(Timestamp(Timestamp::now().0 - almost));
    assert!(
        still_open(&mut stream).await,
        "the change itself ends nothing"
    );
    assert!(closed(&mut stream).await, "closed at the bound");
    lab.load().await;

    // A replaced certificate whose overlap ends in a moment.
    let successor = lab.successor(&client).await;
    let mut stream = start(lab.open(&client).await).await;
    let overlap_almost_over =
        Timestamp(Timestamp::now().0 - tenko_auth::client_cert::OVERLAP + MARGIN);
    lab.certs
        .note_presented(
            &RequestCtx::system(SystemComponent::Api).at(overlap_almost_over),
            &successor.serial,
        )
        .await
        .expect("presented");
    lab.load().await;
    assert!(still_open(&mut stream).await, "the overlap still runs");
    assert!(
        closed(&mut stream).await,
        "closed at the end of the overlap"
    );
    lab.shut().await;
}

#[tokio::test]
async fn a_handshake_that_does_not_finish_is_dropped() {
    let lab = Lab::new(Serves::App).await;
    let _client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let mut silent = TcpStream::connect(lab.addr).await.expect("connect");
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(30), silent.read(&mut buffer))
        .await
        .expect("dropped within the handshake timeout");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    lab.shut().await;
}

#[tokio::test]
async fn one_source_holds_at_most_its_share_before_any_handshake() {
    let lab = Lab::new(Serves::App).await;
    let _client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let mut held = Vec::new();
    for _ in 0..MAX_PER_SOURCE {
        held.push(
            TcpStream::connect(lab.addr)
                .await
                .expect("within the share"),
        );
    }
    // One more from the same source is accepted by the kernel and dropped at once.
    let mut extra = TcpStream::connect(lab.addr).await.expect("connect");
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(30), extra.read(&mut buffer))
        .await
        .expect("dropped");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    // The ones within the share are still waiting for their handshake.
    let mut probe = [0u8; 1];
    assert!(matches!(
        held[0].try_read(&mut probe),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    lab.shut().await;
}

#[tokio::test]
async fn tls_1_2_only_when_allowed_and_never_resumed() {
    let lab = Lab::new(Serves::App).await;
    let client = lab.enroll().await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let tls12 = lab.config(Some(&client), &[&rustls::version::TLS12]);
    match lab.connect(Arc::clone(&tls12)).await {
        Err(_) => {}
        Ok(mut stream) => assert!(closed(&mut stream).await, "TLS 1.2 refused by default"),
    }
    lab.allow_tls12().await;
    for config in [tls12, lab.config(Some(&client), &[&rustls::version::TLS13])] {
        for attempt in 0..2 {
            let mut stream = lab.connect(Arc::clone(&config)).await.expect("handshake");
            let (status, _) = get(&mut stream, "/api/v1/system/status").await;
            assert_eq!(status, 401);
            assert_eq!(
                stream.get_ref().1.handshake_kind(),
                Some(HandshakeKind::Full),
                "attempt {attempt}: no ticket and no session id is honored"
            );
        }
    }
    lab.shut().await;
}

#[tokio::test]
async fn the_first_presentation_of_a_successor_is_recorded() {
    let lab = Lab::new(Serves::App).await;
    let client = lab.enroll().await;
    let successor = lab.successor(&client).await;
    wait_until_async("the listener opened", || reachable(lab.addr)).await;
    let mut stream = lab.open(&successor).await;
    // The renewal route needs no token: the request passes the gate and is recorded,
    // whatever the handler answers to an empty body.
    stream
        .write_all(
            format!(
                "POST /api/v1/integrations/certificate/renew HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("request");
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).await.expect("an answer");
    assert_eq!(
        lab.record(&successor.serial).await.state,
        CertState::Current
    );
    assert_eq!(lab.record(&client.serial).await.state, CertState::Replaced);
    lab.shut().await;
}

#[tokio::test]
async fn a_token_travels_with_a_lineage_only_from_a_recorded_certificate_of_its_account() {
    let lab = Lab::new(Serves::App).await;
    let client = lab.enroll().await;
    let lineage = lab.record(&client.serial).await.lineage;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer tnkb_abc".parse().expect("header"),
    );
    let extensions = |account: UserId, certs: &Arc<ClientCerts>| {
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(ConnInfo {
            peer: "192.0.2.10:40000".parse().expect("peer"),
            tls: true,
            mode: Arc::new(tenko_cluster::ca::TlsMode::InternalCa),
            trusted: false,
            proxy: None,
            client: Some(Arc::new(IntegrationClient {
                serial: client.serial.clone(),
                account,
            })),
        });
        extensions.insert(Arc::clone(certs));
        extensions
    };
    assert_eq!(
        crate::extract::credentials_of(&headers, &extensions(lab.account, &lab.certs), true),
        Credentials::CertifiedBearer {
            token: "tnkb_abc".to_owned(),
            lineage
        }
    );
    // The record names another account: the token travels without a lineage.
    assert_eq!(
        crate::extract::credentials_of(&headers, &extensions(UserId::generate(), &lab.certs), true),
        Credentials::Bearer("tnkb_abc".to_owned())
    );
    // An index that has not loaded knows no record.
    let unloaded = Arc::new(ClientCerts::new(
        Arc::clone(&lab.store),
        Arc::new(MemVault::default()),
        Arc::clone(&lab.issuer) as _,
    ));
    assert_eq!(
        crate::extract::credentials_of(&headers, &extensions(lab.account, &unloaded), true),
        Credentials::Bearer("tnkb_abc".to_owned())
    );
    // Without an integration certificate (the API listener) a bearer token is a bearer token.
    let mut plain = axum::http::Extensions::new();
    plain.insert(Arc::clone(&lab.certs));
    assert_eq!(
        crate::extract::credentials_of(&headers, &plain, true),
        Credentials::Bearer("tnkb_abc".to_owned())
    );
    lab.shut().await;
}
