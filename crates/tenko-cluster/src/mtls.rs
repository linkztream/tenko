//! Mutual TLS of the node transport (OPS-04).
//!
//! mTLS between nodes is structural: no profile turns it off. Both sides speak TLS 1.3
//! only, offer ALPN `h2`, and trust exactly one root: the installation's internal CA. Names
//! play no part; a certificate identifies its node by the URI subject alternative name
//! `urn:tenko:node:<id>` and carries its roles as `urn:tenko:role:<role>`.
//!
//! - **Controller (server).** [`server_config`] requires a client certificate that chains
//!   to the CA root, has client authentication in its extended key usage, names a node,
//!   and whose serial is not in the [`RevocationSet`]. A revoked certificate fails the
//!   handshake with the alert `certificate_revoked`, except a controller's: it passes,
//!   and its connection is marked ([`KillSwitch::is_marked_revoked`]) and gets nothing
//!   but the exchange of generation records, so that two histories always learn of each
//!   other whatever either side revoked.
//! - **Node (client).** [`client_config`] presents the node certificate and accepts a
//!   server certificate only when it chains to the CA root the node received at enrollment
//!   (a controller of another installation is refused) and carries the role `controller`.
//!   Sessions are never resumed: every connection makes a full handshake.
//!
//! The controller tracks every accepted connection with a [`KillSwitch`] per node, so a
//! revocation can close the connections of that node at once ([`NodeStream`]).

use std::{
    collections::HashSet,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use crate::{
    ca::{CertInfo, CertSource, TlsMaterial, node_id_of, roles_in},
    error::ClusterError,
};
use arc_swap::ArcSwap;
use futures::task::AtomicWaker;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsErr,
    RootCertStore, ServerConfig, SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        ParsedCertificate, ResolvesServerCert, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};
use tenko_core::{NodeId, Role, RoleSet, Timestamp};
use tenko_vault::SecretBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The ALPN protocol of the node transport.
pub const ALPN_H2: &[u8] = b"h2";

/// The crypto provider of the node transport: aws-lc-rs, as everywhere in Tenko.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Who is on the other end of a connection: what its certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The node.
    pub node: NodeId,
    /// Its roles.
    pub roles: RoleSet,
    /// The serial number of its certificate, lower-case hex.
    pub serial: String,
    /// SHA-256 of its certificate, lower-case hex.
    pub sha256: String,
    /// When its certificate expires.
    pub not_after: Timestamp,
}

impl PeerIdentity {
    /// Reads a node certificate.
    ///
    /// # Errors
    ///
    /// `cluster.tls.not_a_node` when the certificate names no node, or a parse error.
    pub fn from_der(der: &[u8]) -> Result<Self, ClusterError> {
        let info = CertInfo::from_der(der)?;
        let node = node_id_of(der).ok_or_else(|| {
            ClusterError::new(
                "cluster.tls.not_a_node",
                403,
                "the certificate does not name a Tenko node",
            )
        })?;
        Ok(Self {
            node,
            roles: roles_in(&info.uris),
            serial: info.serial,
            sha256: info.sha256,
            not_after: info.not_after,
        })
    }
}

/// The serials of revoked certificates, checked at every handshake on the cluster port (and
/// the revoked nodes, `RevocationSet<NodeId>`). A view of the store replaces it while local
/// revocations add to it: [`RevocationSet::generation`] counts the additions, so that a
/// replacement from a view read before an addition keeps that addition.
#[derive(Debug)]
pub struct RevocationSet<T = String> {
    state: ArcSwap<(u64, HashSet<T>)>,
}

impl<T> Default for RevocationSet<T> {
    fn default() -> Self {
        Self {
            state: ArcSwap::from_pointee((0, HashSet::new())),
        }
    }
}

impl RevocationSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T: Eq + std::hash::Hash + Clone> RevocationSet<T> {
    /// Whether the entry (a serial in lower-case hex) is revoked.
    pub fn is_revoked<Q>(&self, entry: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ?Sized,
    {
        self.state.load().1.contains(entry)
    }

    /// The additions so far: read it before the view that [`RevocationSet::replace`] takes.
    pub fn generation(&self) -> u64 {
        self.state.load().0
    }

    /// Replaces the set with what a view of the store holds, read when the set was at
    /// `generation`. After an addition since then, the view's entries join the set instead,
    /// until a replacement from a newer view: an entry kept a little longer stays refused.
    pub fn replace(&self, generation: u64, entries: impl IntoIterator<Item = T>) {
        let entries: HashSet<T> = entries.into_iter().collect();
        self.state.rcu(|state| {
            let (now, current) = &**state;
            if *now == generation {
                (*now, entries.clone())
            } else {
                (*now, entries.union(current).cloned().collect())
            }
        });
    }

    /// Adds entries, by compare and swap: a replacement that lands meanwhile keeps them.
    pub fn insert(&self, entries: impl IntoIterator<Item = T>) {
        let entries: Vec<T> = entries.into_iter().collect();
        self.state.rcu(|state| {
            let (now, current) = &**state;
            let mut next = HashSet::clone(current);
            next.extend(entries.iter().cloned());
            (now + 1, next)
        });
    }

    /// How many entries are revoked.
    pub fn len(&self) -> usize {
        self.state.load().1.len()
    }

    /// Whether nothing is revoked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn roots(ca_root: &CertificateDer<'static>) -> Result<Arc<RootCertStore>, ClusterError> {
    let mut store = RootCertStore::empty();
    store.add(ca_root.clone()).map_err(|error| {
        ClusterError::new(
            "cluster.tls.invalid_root",
            500,
            format!("the CA root cannot be used as a trust anchor: {error}"),
        )
    })?;
    Ok(Arc::new(store))
}

/// The client certificate check of the cluster port: the web PKI checks against the CA
/// root, then a node identity and the revocation set.
struct NodeClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    revoked: Arc<RevocationSet>,
}

impl fmt::Debug for NodeClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeClientVerifier")
            .field("revoked", &self.revoked.len())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for NodeClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsErr> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let peer = PeerIdentity::from_der(end_entity).map_err(|_| {
            TlsErr::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        // A revoked controller passes, marked, to the exchange of generation records only.
        if self.revoked.is_revoked(&peer.serial)
            && !peer.roles.contains(tenko_core::Role::Controller)
        {
            tracing::warn!(node = %peer.node, serial = %peer.serial, "refused a revoked node certificate");
            return Err(TlsErr::InvalidCertificate(CertificateError::Revoked));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsErr> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsErr> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The server certificate check of a client of the cluster port: the certificate chains to
/// the CA root of the node's enrollment, names a node and belongs to a controller.
struct ControllerVerifier {
    roots: Arc<RootCertStore>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for ControllerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerVerifier").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for ControllerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsErr> {
        verify_controller(
            &self.roots,
            end_entity,
            intermediates,
            now,
            &self.algorithms,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsErr> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsErr> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Checks a controller's certificate: it chains to one of `roots` at `time`, names a node and
/// carries the role `controller`. Shared by a node's check of its controller and by the
/// check of a signed generation record (`crate::generation`).
///
/// # Errors
///
/// The TLS error of the chain, or `ApplicationVerificationFailure` for a certificate that
/// names no node or is not a controller's.
pub fn verify_controller(
    roots: &RootCertStore,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    time: UnixTime,
    algorithms: &WebPkiSupportedAlgorithms,
) -> Result<PeerIdentity, TlsErr> {
    let cert = ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
        &cert,
        roots,
        intermediates,
        time,
        algorithms.all,
    )?;
    let peer = PeerIdentity::from_der(end_entity).map_err(|_| {
        TlsErr::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
    })?;
    if !peer.roles.contains(Role::Controller) {
        return Err(TlsErr::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ));
    }
    Ok(peer)
}

fn config_error(error: &impl fmt::Display) -> ClusterError {
    ClusterError::new(
        "cluster.tls.config",
        500,
        format!("the TLS configuration of the cluster port failed: {error}"),
    )
}

/// The TLS configuration of the controller's cluster port: TLS 1.3, ALPN `h2`, the
/// controller certificate from `resolver`, and mandatory node certificates of the CA
/// `ca_root` that are not in `revoked` (a controller's revoked certificate passes, marked:
/// [`KillSwitch::is_marked_revoked`]).
///
/// # Errors
///
/// `cluster.tls.invalid_root` or `cluster.tls.config`.
pub fn server_config(
    ca_root: &CertificateDer<'static>,
    resolver: Arc<dyn ResolvesServerCert>,
    revoked: Arc<RevocationSet>,
) -> Result<Arc<ServerConfig>, ClusterError> {
    let provider = provider();
    let inner = WebPkiClientVerifier::builder_with_provider(roots(ca_root)?, Arc::clone(&provider))
        .build()
        .map_err(|error| config_error(&error))?;
    let verifier = Arc::new(NodeClientVerifier { inner, revoked });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| config_error(&error))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    // Every connection runs the client-certificate verifier: no tickets, nothing stored.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// The TLS configuration of a node: TLS 1.3, ALPN `h2`, the node certificate `chain` with
/// its PKCS#8 `key`, and trust in the CA `ca_root` for controllers only.
///
/// # Errors
///
/// `cluster.tls.invalid_root`, `cluster.tls.config`, or `cluster.tls.key` when the key
/// does not fit the certificate.
pub fn client_config(
    ca_root: &CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: &SecretBytes,
) -> Result<Arc<ClientConfig>, ClusterError> {
    let provider = provider();
    let verifier = Arc::new(ControllerVerifier {
        roots: roots(ca_root)?,
        algorithms: provider.signature_verification_algorithms,
    });
    let material = TlsMaterial::from_der(chain, key, CertSource::Inline).map_err(|error| {
        ClusterError::new(
            "cluster.tls.key",
            500,
            format!("the node key does not fit its certificate: {error}"),
        )
    })?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| config_error(&error))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(NodeCertResolver(material.certified_key())));
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    // A resumed session skips the certificate checks: every connection runs them.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Presents the node certificate to every controller.
#[derive(Debug)]
struct NodeCertResolver(Arc<CertifiedKey>);

impl ResolvesClientCert for NodeCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The name a node sends as SNI for an endpoint host: the host when it is a valid DNS name
/// or address, else the unspecified address (no SNI; the controller ignores names).
pub fn server_name(host: &str) -> ServerName<'static> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(host.to_owned()).unwrap_or(ServerName::IpAddress(
        std::net::IpAddr::from([0u8, 0, 0, 0]).into(),
    ))
}

/// Closes the connections of one node: once killed, every read and write of its
/// [`NodeStream`]s fails, which ends the HTTP/2 connection and its calls.
#[derive(Debug, Default)]
pub struct KillSwitch {
    killed: AtomicBool,
    marked: std::sync::OnceLock<std::time::Instant>,
    waker: AtomicWaker,
}

impl KillSwitch {
    /// A live switch.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Kills the connection.
    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    /// Whether the connection was killed.
    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    /// Marks a connection accepted with a revoked certificate (a controller's, which the
    /// handshake lets through): it gets nothing but the exchange of generation records, and
    /// every other call is refused with its code.
    pub fn mark_revoked(&self) {
        self.mark_revoked_at(std::time::Instant::now());
    }

    pub(crate) fn mark_revoked_at(&self, at: std::time::Instant) {
        let _ = self.marked.set(at);
    }

    /// Whether the connection was accepted with a revoked certificate.
    pub fn is_marked_revoked(&self) -> bool {
        self.marked.get().is_some()
    }

    /// When the connection was marked revoked, if it was.
    pub(crate) fn marked_at(&self) -> Option<std::time::Instant> {
        self.marked.get().copied()
    }
}

/// What the gRPC services learn about the connection a call arrived on (the
/// `ConnectInfo` of [`NodeStream`]).
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The certificate's node.
    pub identity: PeerIdentity,
    /// The TCP peer.
    pub remote: Option<SocketAddr>,
    /// The local address the connection arrived on (the cluster port as the peer reached
    /// it).
    pub local: Option<SocketAddr>,
    /// The connection's kill switch, marked when the certificate is revoked
    /// ([`KillSwitch::is_marked_revoked`]).
    pub kill: Arc<KillSwitch>,
}

/// A TLS connection of a node on the cluster port that a revocation can close.
#[derive(Debug)]
pub struct NodeStream<S> {
    inner: S,
    peer: PeerInfo,
}

impl<S> NodeStream<S> {
    /// Wraps an established TLS stream.
    pub fn new(inner: S, peer: PeerInfo) -> Self {
        Self { inner, peer }
    }

    /// The peer.
    pub fn peer(&self) -> &PeerInfo {
        &self.peer
    }
}

fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the node was revoked; the connection is closed",
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for NodeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.peer.kill.waker.register(cx.waker());
        if self.peer.kill.is_killed() {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NodeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.peer.kill.waker.register(cx.waker());
        if self.peer.kill.is_killed() {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.peer.kill.is_killed() {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Send + 'static> tonic::transport::server::Connected for NodeStream<S> {
    type ConnectInfo = PeerInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replacement by the revocation watcher that lands while a local revocation adds to
    /// the set stays beside the addition. The replacement runs while the addition reads its
    /// entries, between the load and the store of a plain load, clone and store; it shows
    /// that the set is read after the entries, not the compare and swap itself.
    #[test]
    fn an_addition_keeps_a_replacement_made_meanwhile() {
        let set = RevocationSet::new();
        set.replace(set.generation(), ["old".to_owned()]);
        set.insert(std::iter::once_with(|| {
            set.replace(set.generation(), ["old".to_owned(), "watched".to_owned()]);
            "local".to_owned()
        }));
        for serial in ["old", "watched", "local"] {
            assert!(set.is_revoked(serial), "{serial}");
        }
    }

    /// A replacement from a view read before a local revocation (the hourly reload, or the
    /// watcher) keeps that revocation beside the view's entries; one from a view read after
    /// it replaces the set.
    #[test]
    fn a_view_read_before_an_addition_keeps_it() {
        let set = RevocationSet::<NodeId>::default();
        let before = set.generation();
        set.insert([NodeId(7)]);
        set.replace(before, [NodeId(8)]);
        assert!(set.is_revoked(&NodeId(7)) && set.is_revoked(&NodeId(8)));
        set.replace(set.generation(), [NodeId(8)]);
        assert!(!set.is_revoked(&NodeId(7)) && set.is_revoked(&NodeId(8)));
    }
}
