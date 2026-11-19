//! The TLS of the integration listener (ADR 0035, decision 3).
//!
//! - A client certificate is mandatory and must chain to the integration root, the only
//!   trust anchor; the certificate request names only that root. Then the certificate must
//!   have the form of an integration certificate ([`IntegrationIdentity`]) and its record must
//!   let it pass ([`CertificateGate`]): a valid signature is necessary, never sufficient.
//! - TLS 1.3, and TLS 1.2 only when the caller allows it (the third part of TGL-47). TLS 1.2
//!   is limited to the suites of the provider (ECDHE with AES-GCM or ChaCha20-Poly1305) and
//!   requires the Extended Master Secret (RFC 7627); rustls has no renegotiation.
//! - No session tickets, no session IDs, no session cache: every connection runs the full
//!   handshake, and the verifier runs at every connection.

use std::{fmt, sync::Arc, time::Duration};

use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsErr, RootCertStore,
    ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use tenko_core::Timestamp;

use crate::{ca::IntegrationIdentity, error::ClusterError, mtls::provider};

/// Whether the record of an integration certificate lets it through the handshake.
pub trait CertificateGate: Send + Sync {
    /// `true` when the certificate passes at `now` for at least one route.
    fn admits(&self, identity: &IntegrationIdentity, now: Timestamp) -> bool;
}

/// The client certificate check of the integration listener.
struct IntegrationClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    gate: Arc<dyn CertificateGate>,
}

impl fmt::Debug for IntegrationClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrationClientVerifier")
            .finish_non_exhaustive()
    }
}

fn timestamp(now: UnixTime) -> Option<Timestamp> {
    let seconds = i64::try_from(now.as_secs()).ok()?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .map(Timestamp)
}

impl ClientCertVerifier for IntegrationClientVerifier {
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
        let identity = IntegrationIdentity::from_der(end_entity).map_err(|_| {
            TlsErr::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        match timestamp(now) {
            Some(now) if self.gate.admits(&identity, now) => Ok(verified),
            _ => {
                tracing::debug!(serial = %identity.serial, account = %identity.account, "refused an integration certificate its record does not admit");
                Err(TlsErr::InvalidCertificate(CertificateError::Revoked))
            }
        }
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

/// The handshake limit of the integration listener (ADR 0035, decision 3).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The TLS configuration of the integration listener: the server certificate from
/// `resolver`, a mandatory client certificate of the integration root `root` that `gate`
/// admits, TLS 1.3 and with `allow_tls12` also TLS 1.2, ALPN `h2` and `http/1.1`.
///
/// # Errors
///
/// `cluster.tls.invalid_root` or `cluster.tls.config`.
pub fn integration_server_config(
    root: &CertificateDer<'static>,
    resolver: Arc<dyn ResolvesServerCert>,
    gate: Arc<dyn CertificateGate>,
    allow_tls12: bool,
) -> Result<Arc<ServerConfig>, ClusterError> {
    let config_error = |error: &dyn fmt::Display| {
        ClusterError::new(
            "cluster.tls.config",
            500,
            format!("the integration listener's TLS cannot be set up: {error}"),
        )
    };
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).map_err(|error| {
        ClusterError::new(
            "cluster.tls.invalid_root",
            500,
            format!("the integration root cannot be used as a trust anchor: {error}"),
        )
    })?;
    let provider = provider();
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|error| config_error(&error))?;
    let versions: &[&'static rustls::SupportedProtocolVersion] = if allow_tls12 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|error| config_error(&error))?
        .with_client_cert_verifier(Arc::new(IntegrationClientVerifier { inner, gate }))
        .with_cert_resolver(resolver);
    config.require_ems = true;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
