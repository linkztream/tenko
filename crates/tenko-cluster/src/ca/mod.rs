//! The internal certificate authority and the TLS model of the API and UI listener
//! (OPS-22, TGL-08, Q5).
//!
//! - [`InternalCa`]: an ECDSA P-256 root made with `rcgen`, its key a system secret in the
//!   vault; server certificates for the configured host name and addresses with renewal
//!   before expiry ([`InternalCa::server_material`]); the root as PEM for installation on
//!   admin clients; node certificates carrying `urn:tenko:node:<id>` for Slice 2
//!   enrolment.
//! - [`TlsMode`]: (a) internal CA, (b) imported certificate and key with hot reload, (c)
//!   termination in a reverse proxy with [`TrustedProxies`].
//! - [`TlsMaterial`]: a chain and key loaded for rustls, with [`CertInfo`] and
//!   [`Expiry`] for the health view; [`TlsService`] serves it through a swapping resolver
//!   and publishes [`TlsStatus`] changes on a watch channel.
//!
//! WP1.7 builds its listener from [`TlsService::server_config`] in modes a and b, and in
//! mode c accepts connections and forwarded headers only from
//! [`TrustedProxies::is_trusted`] peers.

mod authority;
mod certs;
mod error;
mod proxy;
mod reload;
mod tls;

pub use authority::pem as pem_block;
pub use authority::{
    CA_CREATE, CA_KEY_PURPOSE, CaPolicy, CaRecord, InternalCa, IssuedCert, NodeCert,
    SERVER_CERT_ISSUE, ServerCertRecord, ServerIdentity, TLS_KEY_PURPOSE, tables,
};
pub use certs::{generate_csr, node_id_of, node_uri, role_uri, roles_in, roles_of};
pub use error::{CaError, TlsError};
pub use proxy::TrustedProxies;
pub use reload::{DEFAULT_WATCH_INTERVAL, TlsService};
pub use tls::{
    CertInfo, CertSource, EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS, Expiry, ExpiryState,
    TlsMaterial, TlsMode, TlsPolicy, TlsResolver, TlsStatus, server_config,
};
