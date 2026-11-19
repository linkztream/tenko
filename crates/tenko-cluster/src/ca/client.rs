//! The integration CA (ADR 0035): a second ECDSA P-256 root, its key a vault system secret
//! of its own purpose, that signs integration certificates and nothing else. The existing
//! root never signs an integration certificate and this one never signs a server or node
//! certificate: each root has its own type with its own issuing method. The cluster port and
//! a node's check of a controller trust only the existing root, so an integration
//! certificate fails chain building there before Tenko reads it.
//!
//! An integration certificate names one service account in the URI subject alternative
//! name `urn:tenko:service-account:<id>`, has client authentication as its only extended key
//! usage and is no CA. [`IntegrationIdentity::from_der`] reads one and refuses anything else,
//! so that the separation holds even if trust anchors were mixed up.

use std::fmt;

use rustls::pki_types::CertificateDer;
use tenko_core::{RequestCtx, Timestamp, UserId, audit::AuditAction};
use tenko_store::Store;
use tenko_vault::{SecretPurpose, Vault};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

use super::{
    CaError, CertInfo,
    authority::{CaRecord, LoadedRoot, RootSlot, pem, tables},
    certs::{self, SERVICE_ACCOUNT_URI_PREFIX, Signer},
    tls::hex,
};

/// Vault purpose of the integration CA's root key.
pub const INTEGRATION_CA_KEY_PURPOSE: SecretPurpose =
    SecretPurpose::from_static("cluster.integration_ca_key");
/// Audit action: the integration CA's root was created.
pub const INTEGRATION_CA_CREATE: AuditAction =
    AuditAction::from_static("cluster.integration_ca.create");
/// The longest lifetime of an integration certificate (the Lab value of TGL-47).
pub const MAX_INTEGRATION_VALIDITY_DAYS: u32 = 365;
/// The lifetime of the integration root, as the internal CA's.
const ROOT_VALIDITY_DAYS: u32 = 3650;

const INTEGRATION_ROOT: RootSlot = RootSlot {
    table: tables::INTEGRATION_CA,
    purpose: INTEGRATION_CA_KEY_PURPOSE,
    created: INTEGRATION_CA_CREATE,
    name: "Tenko DDI integration CA",
};

/// The integration CA.
pub struct IntegrationCa {
    record: CaRecord,
    root: CertificateDer<'static>,
    root_info: CertInfo,
    signer: Signer,
}

impl fmt::Debug for IntegrationCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrationCa")
            .field("root", &self.root_info)
            .finish_non_exhaustive()
    }
}

impl IntegrationCa {
    /// Loads the integration CA, or `None` before the first enrollment code created it.
    ///
    /// # Errors
    ///
    /// [`CaError::Corrupt`] when the stored key does not match the root, or a vault or
    /// store error.
    pub async fn load(
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
    ) -> Result<Option<Self>, CaError> {
        Ok(INTEGRATION_ROOT
            .load(store, vault, ctx)
            .await?
            .map(Self::from))
    }

    /// Loads the integration CA, creating it on first use (audit
    /// `cluster.integration_ca.create`); two controllers that create it at the same moment
    /// end with one root.
    ///
    /// # Errors
    ///
    /// As [`load`](IntegrationCa::load), or a generation error.
    pub async fn load_or_init(
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
    ) -> Result<Self, CaError> {
        Ok(INTEGRATION_ROOT
            .load_or_init(store, vault, ctx, ROOT_VALIDITY_DAYS)
            .await?
            .into())
    }

    /// The root, DER: the only trust anchor of the integration listener.
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root
    }

    /// The root as PEM.
    pub fn root_pem(&self) -> String {
        self.record.cert_pem.clone()
    }

    /// What the root says.
    pub fn root_info(&self) -> &CertInfo {
        &self.root_info
    }

    /// Issues an integration certificate for `account` over the key of a PKCS#10 request,
    /// valid for `validity_days` (TGL-47). The request's self-signature must verify over an
    /// ECDSA P-256 key; its names, extensions and attributes are ignored.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidCsr`], or [`CaError::Generation`] for a lifetime outside
    /// 1 to [`MAX_INTEGRATION_VALIDITY_DAYS`] days.
    pub fn issue(
        &self,
        account: UserId,
        csr_der: &[u8],
        now: Timestamp,
        validity_days: u32,
    ) -> Result<IntegrationCert, CaError> {
        if !(1..=MAX_INTEGRATION_VALIDITY_DAYS).contains(&validity_days) {
            return Err(CaError::Generation {
                reason: format!(
                    "an integration certificate lasts 1 to {MAX_INTEGRATION_VALIDITY_DAYS} days, not {validity_days}"
                ),
            });
        }
        let cert = certs::issue_integration_from_csr(
            &self.signer,
            account,
            csr_der,
            now.0,
            validity_days,
        )?;
        let identity = IntegrationIdentity::from_der(&cert)?;
        Ok(IntegrationCert { cert, identity })
    }
}

impl From<LoadedRoot> for IntegrationCa {
    fn from(root: LoadedRoot) -> Self {
        Self {
            record: root.record,
            root: root.root,
            root_info: root.root_info,
            signer: root.signer,
        }
    }
}

/// An issued integration certificate; the integrator keeps the key.
#[derive(Debug, Clone)]
pub struct IntegrationCert {
    /// The certificate, DER (the root is not part of the answer).
    pub cert: CertificateDer<'static>,
    /// What it says.
    pub identity: IntegrationIdentity,
}

impl IntegrationCert {
    /// The certificate as PEM, the answer of an enrollment or a renewal.
    pub fn chain_pem(&self) -> String {
        pem("CERTIFICATE", &self.cert)
    }
}

/// What an integration certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationIdentity {
    /// The service account it names.
    pub account: UserId,
    /// Its serial number, lower-case hex.
    pub serial: String,
    /// SHA-256 of the certificate, lower-case hex.
    pub sha256: String,
    /// SHA-256 of its `SubjectPublicKeyInfo`, lower-case hex: the key a token is bound to, and
    /// what `openssl pkey -pubout -outform DER | openssl dgst -sha256` prints for the key.
    pub key_sha256: String,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
}

impl IntegrationIdentity {
    /// Reads an integration certificate and checks its form: exactly one subject alternative
    /// name, the URI `urn:tenko:service-account:<id>`; client authentication and no other
    /// extended key usage; not a CA. The signature is not checked here: the integration
    /// listener's verifier has checked the chain before it calls this.
    ///
    /// # Errors
    ///
    /// [`CaError::NotAnIntegration`].
    pub fn from_der(der: &[u8]) -> Result<Self, CaError> {
        let refuse = |reason: &str| CaError::NotAnIntegration {
            reason: reason.to_owned(),
        };
        let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|_| refuse("it cannot be parsed"))?;
        if !rest.is_empty() {
            return Err(refuse("trailing data after the certificate"));
        }
        if cert.is_ca() {
            return Err(refuse("it is a CA certificate"));
        }
        let usage = cert
            .extended_key_usage()
            .map_err(|_| refuse("its extended key usage cannot be parsed"))?
            .ok_or_else(|| refuse("it has no extended key usage"))?
            .value;
        if !usage.client_auth
            || usage.any
            || usage.server_auth
            || usage.code_signing
            || usage.email_protection
            || usage.time_stamping
            || usage.ocsp_signing
            || !usage.other.is_empty()
        {
            return Err(refuse(
                "its only extended key usage is not client authentication",
            ));
        }
        let names = cert
            .subject_alternative_name()
            .map_err(|_| refuse("its subject alternative name cannot be parsed"))?
            .ok_or_else(|| refuse("it names no service account"))?
            .value;
        let [GeneralName::URI(uri)] = names.general_names.as_slice() else {
            return Err(refuse(
                "it does not name exactly one service account and nothing else",
            ));
        };
        let account = uri
            .strip_prefix(SERVICE_ACCOUNT_URI_PREFIX)
            .and_then(|id| {
                id.parse::<UserId>()
                    .ok()
                    .filter(|account| account.to_string() == id)
            })
            .ok_or_else(|| refuse("it names no service account"))?;
        let info = CertInfo::from_der(der).map_err(|_| refuse("it cannot be parsed"))?;
        Ok(Self {
            account,
            serial: info.serial,
            sha256: info.sha256,
            key_sha256: hex(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                cert.public_key().raw,
            )
            .as_ref()),
            not_before: info.not_before,
            not_after: info.not_after,
        })
    }
}

/// The entry point of the fuzz target `integration_identity` (not part of the API).
#[doc(hidden)]
pub mod fuzzing {
    /// The identity reader of the integration listener over arbitrary DER.
    pub fn identity(data: &[u8]) {
        if let Ok(identity) = super::IntegrationIdentity::from_der(data) {
            assert_eq!(identity.key_sha256.len(), 64);
            assert_eq!(identity.sha256.len(), 64);
        }
    }
}
