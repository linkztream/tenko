//! Integration client certificates (ADR 0035; IAM-22, IAM-25): the records, the enrollment
//! codes, enrollment with the HMAC proof, revocation, and the in-memory index the
//! integration listener asks at every handshake and request.
//!
//! The certificate authority lives in `tenko-cluster`, which this crate does not depend on:
//! the server binary hands it in as an [`Issuer`]. The records are an allow-list: a
//! certificate passes only while its serial has a record in an accepting state
//! ([`CertIndex::accept`]).
//!
//! The authorization of a route and the fresh sign-in an enrollment code needs are checked by
//! the route; this service checks everything about the account, the code and the key.

mod enroll;
mod follow;
pub mod model;
mod renew;
pub(crate) mod revoke;

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use tenko_core::{
    Coded, RequestCtx, Timestamp, UserId,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, WriteBatch};
use tenko_vault::{SecretPurpose, Vault, VaultError};

pub use enroll::{CreatedCode, EnrollInput, NewCode, enrollment_proof};
pub use follow::{Acceptance, CertIndex, OVERLAP};
pub use renew::{RENEW_INTERVAL, Renewal, alarm_after, renew_after};

use crate::{model::SETTINGS, settings::Profile};
use model::IntegrationPolicy;

/// The prefix of an enrollment code's text: `tnki.<code id>.<account id>.<secret>.<fingerprint>`.
pub const CODE_PREFIX: &str = "tnki";
/// The label at the start of the message an enrollment's HMAC covers.
pub const PROOF_LABEL: &str = "tenko-integration-enroll-v1";
/// The shortest and longest lifetime of an enrollment code, in seconds.
pub const CODE_LIFETIME_SECS: std::ops::RangeInclusive<u64> = 60..=3600;
/// How many lineages a service account may hold at once.
pub const MAX_LINEAGES: usize = 8;
/// How long used, withdrawn and expired codes stay listed, in seconds.
pub const CODE_KEPT_SECS: i64 = 7 * 86_400;

/// Vault purpose of an enrollment code's secret.
pub const CODE_SECRET_PURPOSE: SecretPurpose = SecretPurpose::from_static("auth.integration_code");

/// The audit actions of integration certificates.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// An enrollment code was created.
    pub const CODE_CREATE: AuditAction = AuditAction::from_static("auth.client_cert.code_create");
    /// An enrollment code was withdrawn, by an administrator or because it came over plain
    /// HTTP.
    pub const CODE_WITHDRAW: AuditAction =
        AuditAction::from_static("auth.client_cert.code_withdraw");
    /// A certificate was issued at enrollment, or an enrollment was refused.
    pub const ISSUE: AuditAction = AuditAction::from_static("auth.client_cert.issue");
    /// A lineage was revoked.
    pub const REVOKE: AuditAction = AuditAction::from_static("auth.client_cert.revoke");
    /// A certificate was renewed.
    pub const RENEW: AuditAction = AuditAction::from_static("auth.client_cert.renew");
    /// A renewed certificate was first presented and replaced its predecessor.
    pub const PRESENT: AuditAction = AuditAction::from_static("auth.client_cert.present");
    /// The tokens bound to a lineage that lapsed were removed.
    pub const LAPSE: AuditAction = AuditAction::from_static("auth.client_cert.lapse");
}

/// What the integration CA answers for an issued certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The certificate, PEM.
    pub pem: String,
    /// Its serial, lower-case hex.
    pub serial: String,
    /// SHA-256 of its key's `SubjectPublicKeyInfo`, lower-case hex.
    pub key_sha256: String,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
}

/// The integration CA, as the server binary provides it.
#[async_trait]
pub trait Issuer: Send + Sync {
    /// The canonical `SubjectPublicKeyInfo` of a request whose self-signature verifies over
    /// an ECDSA P-256 key.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::InvalidRequest`].
    fn request_key(&self, csr: &[u8]) -> Result<Vec<u8>, ClientCertError>;

    /// Creates the integration root when it does not exist yet.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::Issuing`].
    async fn ensure_root(&self, ctx: &RequestCtx) -> Result<(), ClientCertError>;

    /// Issues a certificate for `account` over the key of `csr`, valid for `days`.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::InvalidRequest`] or [`ClientCertError::Issuing`].
    async fn issue(
        &self,
        ctx: &RequestCtx,
        account: UserId,
        csr: &[u8],
        days: u32,
    ) -> Result<Issued, ClientCertError>;

    /// SHA-256 of the internal root (the root of the integration listener's server
    /// certificate), lower-case hex: the fingerprint an enrollment code carries.
    fn server_root_sha256(&self) -> String;

    /// The internal root, PEM.
    fn server_root_pem(&self) -> String;
}

/// The errors of integration certificates.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientCertError {
    /// No such code, a wrong proof, or a withdrawn code.
    #[error("the enrollment code or its proof is not valid")]
    CodeInvalid,
    /// The code was used.
    #[error("the enrollment code was used")]
    CodeUsed,
    /// The code expired.
    #[error("the enrollment code expired")]
    CodeExpired,
    /// The enrollment came from outside the code's network.
    #[error("the enrollment code may not be used from this address")]
    CodeSource,
    /// The code arrived over plain HTTP, or through a proxy that did not state the scheme.
    #[error("an enrollment must use HTTPS; {0}")]
    Transport(&'static str),
    /// A code lifetime outside [`CODE_LIFETIME_SECS`].
    #[error("an enrollment code lives 60 to 3600 seconds")]
    Lifetime,
    /// The account is not a service account, is disabled, or its tokens ended since.
    #[error("the account cannot hold integration certificates")]
    Account,
    /// The key was enrolled before.
    #[error("this key was enrolled before; make a new key")]
    KeyUsed,
    /// The account holds [`MAX_LINEAGES`] lineages.
    #[error("the service account holds {MAX_LINEAGES} certificate lineages already")]
    Lineages,
    /// The label is empty, too long or not printable.
    #[error("the label must be 1 to 64 printable characters")]
    Label,
    /// The certificate request is not usable.
    #[error("the certificate request is not usable: {reason}")]
    InvalidRequest {
        /// Why.
        reason: String,
    },
    /// No such certificate, code or account.
    #[error("no such {0}")]
    NotFound(&'static str),
    /// The integration CA failed.
    #[error("the integration CA failed: {reason}")]
    Issuing {
        /// Why.
        reason: String,
    },
    /// The connection's certificate does not pass.
    #[error("this certificate is no longer accepted")]
    Certificate,
    /// A renewal from a certificate its lineage already replaced; the lineage is revoked.
    #[error("this certificate was already replaced; its lineage is revoked")]
    Reuse,
    /// A renewal within [`RENEW_INTERVAL`] of the last one.
    #[error("the lineage renewed within the last hour")]
    TooSoon,
    /// Another write came first; nothing was written.
    #[error("another change came first; try again")]
    Conflict,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl From<tenko_core::codec::CodecError> for ClientCertError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::Store(StoreError::from(error))
    }
}

impl Coded for ClientCertError {
    fn code(&self) -> &'static str {
        match self {
            Self::CodeInvalid => "integration.code.invalid",
            Self::CodeUsed => "integration.code.used",
            Self::CodeExpired => "integration.code.expired",
            Self::CodeSource => "integration.code.source",
            Self::Transport(_) => "integration.enroll.transport",
            Self::Lifetime => "integration.code.lifetime",
            Self::Account => "integration.account",
            Self::KeyUsed => "integration.key.used",
            Self::Lineages => "integration.lineages",
            Self::Label => "integration.label",
            Self::InvalidRequest { .. } => "integration.request.invalid",
            Self::NotFound(_) => "integration.not_found",
            Self::Issuing { .. } => "integration.issuing",
            Self::Conflict => "integration.conflict",
            Self::Certificate => "integration.certificate.refused",
            Self::Reuse => "integration.renew.reuse",
            Self::TooSoon => "integration.renew.too_soon",
            Self::Store(error) => error.code(),
            Self::Vault(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::CodeInvalid | Self::CodeUsed | Self::CodeExpired | Self::Certificate => 401,
            Self::CodeSource | Self::Transport(_) | Self::Account | Self::Reuse => 403,
            Self::NotFound(_) => 404,
            Self::KeyUsed | Self::Lineages | Self::Conflict | Self::TooSoon => 409,
            Self::Lifetime | Self::Label | Self::InvalidRequest { .. } => 422,
            Self::Issuing { .. } => 500,
            Self::Store(error) => error.http_status(),
            Self::Vault(error) => error.http_status(),
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::NotFound(kind) => [("kind", (*kind).to_owned())].into(),
            Self::Store(error) => error.params(),
            Self::Vault(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }
}

/// Integration certificates: the service behind `/integrations/*`.
pub struct ClientCerts {
    store: Arc<dyn Store>,
    vault: Arc<dyn Vault>,
    issuer: Arc<dyn Issuer>,
    index: Arc<CertIndex>,
}

impl std::fmt::Debug for ClientCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCerts").finish_non_exhaustive()
    }
}

impl ClientCerts {
    /// The service over the store, the vault and the integration CA.
    pub fn new(store: Arc<dyn Store>, vault: Arc<dyn Vault>, issuer: Arc<dyn Issuer>) -> Self {
        Self {
            store,
            vault,
            issuer,
            index: Arc::new(CertIndex::default()),
        }
    }

    /// The internal root, PEM: what an integrator pins for the integration listener.
    pub fn server_root_pem(&self) -> String {
        self.issuer.server_root_pem()
    }

    /// The index the integration listener asks.
    pub fn index(&self) -> &Arc<CertIndex> {
        &self.index
    }

    /// The profile's TGL-47 values; Standard when no settings are stored.
    fn policy(view: &dyn ReadView) -> Result<IntegrationPolicy, ClientCertError> {
        Ok(view.get_typed(&SETTINGS, &())?.map_or_else(
            || IntegrationPolicy::of(Profile::Standard),
            |(settings, _)| settings.integrations(),
        ))
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, ClientCertError> {
        Ok(self.store.read(ReadConsistency::Local).await?)
    }

    /// Writes `batch`; a failed precondition is [`ClientCertError::Conflict`].
    async fn commit(&self, batch: WriteBatch) -> Result<(), ClientCertError> {
        match self.store.propose(batch).await {
            Ok(_) => Ok(()),
            Err(StoreError::PreconditionFailed(_)) => Err(ClientCertError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    /// Writes an audit record of a refusal on its own.
    async fn audit_refusal(&self, ctx: &RequestCtx, draft: AuditDraft) {
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(draft.with_source_ip(ctx.source_ip));
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(code = %error.code(), "the audit record of a refused enrollment was not written");
        }
    }
}

fn audit(action: AuditAction, account: UserId, ctx: &RequestCtx) -> AuditDraft {
    AuditDraft::success(action, vec![tenko_core::ObjectRef::from(account)])
        .with_source_ip(ctx.source_ip)
}
