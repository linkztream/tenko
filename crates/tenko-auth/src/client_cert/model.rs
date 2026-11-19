//! The stored form of integration certificates and enrollment codes (ADR 0035).
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `auth.client_certs` | serial, lower-case hex | [`ClientCertRecord`] |
//! | `auth.client_cert_keys` | SHA-256 of the key, lower-case hex | [`KeyRecord`]: a key enrolls once |
//! | `auth.integration_codes` | code id | [`EnrollmentCode`] |
//!
//! The tables are new, so a build that does not know them refuses every integration
//! certificate instead of reading one wrongly.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{Timestamp, UserId, secret::SecretRef, table::TableDef};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::settings::Profile;

/// Integration certificates by serial.
pub const CLIENT_CERTS: TableDef<String, ClientCertRecord> = TableDef::new("auth.client_certs");
/// Every key ever enrolled, by its digest.
pub const CLIENT_CERT_KEYS: TableDef<String, KeyRecord> = TableDef::new("auth.client_cert_keys");
/// Enrollment codes by id.
pub const ENROLLMENT_CODES: TableDef<Uuid, EnrollmentCode> =
    TableDef::new("auth.integration_codes");

/// Where a certificate stands in its lineage (ADR 0035, decisions 6 and 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertState {
    /// Issued by a renewal and not presented yet; its predecessor is still current.
    Pending,
    /// The lineage's certificate in use.
    Current,
    /// Its successor has been presented; it passes for every route until the overlap ends,
    /// then for the renewal route only, where a renewal from it is reuse.
    Replaced,
    /// Replaced by another renewal before anybody presented it (a lost answer).
    Withdrawn,
    /// Revoked with its lineage.
    Revoked,
}

/// An integration certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClientCertRecord {
    /// The serial, lower-case hex.
    pub serial: String,
    /// The service account it names.
    pub account: UserId,
    /// The account's `tokens_generation` when it was issued: a certificate issued under a
    /// lower value than the account's no longer passes.
    pub generation: u64,
    /// The lineage: the first certificate and every renewal of it share this id.
    pub lineage: Uuid,
    /// The integrator's label of the host, from the enrollment.
    pub label: String,
    /// SHA-256 of its key's `SubjectPublicKeyInfo`, lower-case hex.
    pub key_sha256: String,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// Where it stands in its lineage.
    pub state: CertState,
    /// When it was first presented on the integration listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_at: Option<Timestamp>,
    /// When it left the state `current` or `pending`: replaced, withdrawn or revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<Timestamp>,
    /// Why it was revoked or withdrawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A key that was enrolled: it never enrolls again, for any account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// The account it was enrolled for.
    pub account: UserId,
    /// Its lineage.
    pub lineage: Uuid,
}

/// Where an enrollment code stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CodeState {
    /// Waiting for its enrollment.
    Pending,
    /// Used for the certificate with this serial.
    Used {
        /// The certificate's serial.
        serial: String,
    },
    /// Withdrawn by an administrator, or because it arrived over plain HTTP.
    Withdrawn,
}

/// A single-use enrollment code. Its secret is a system secret of the vault while the code
/// can be used: the controller needs it to check the enrollment's HMAC, and deletes it when
/// the code is used or withdrawn, or once it has expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentCode {
    /// The code id.
    pub id: Uuid,
    /// The service account it enrolls.
    pub account: UserId,
    /// The account's `tokens_generation` when it was created: an end of the account's
    /// access since then ends the code too.
    pub generation: u64,
    /// The administrator who created it.
    pub created_by: UserId,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it expires.
    pub expires_at: Timestamp,
    /// The only network it may be used from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<IpNet>,
    /// The secret, while the code can be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,
    /// Where it stands.
    pub state: CodeState,
}

/// An enrollment code as the API lists it: never its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnrollmentCodeView {
    /// The code id.
    pub id: Uuid,
    /// The service account it enrolls.
    pub account: UserId,
    /// The administrator who created it.
    pub created_by: UserId,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it expires.
    pub expires_at: Timestamp,
    /// The only network it may be used from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub source: Option<IpNet>,
    /// Where it stands.
    pub state: CodeState,
    /// Whether it expired unused.
    pub expired: bool,
}

impl EnrollmentCode {
    /// The listed form at `now`.
    pub fn view(&self, now: Timestamp) -> EnrollmentCodeView {
        EnrollmentCodeView {
            id: self.id,
            account: self.account,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            source: self.source,
            state: self.state.clone(),
            expired: self.state == CodeState::Pending && now.0 >= self.expires_at.0,
        }
    }
}

/// TGL-47, the integration client certificates (SECURITY-PROFILES.md): the certificate
/// lifetime, whether service-account tokens must be bound, and whether the integration
/// listener accepts TLS 1.2. [`IntegrationPolicy::of`] gives a profile's values; a stored
/// override is `SecuritySettings::integrations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntegrationPolicy {
    /// The lifetime of an integration certificate, in days.
    pub lifetime_days: u32,
    /// Every token an administrator creates for a service account must be bound.
    pub require_binding: bool,
    /// The integration listener accepts TLS 1.2 (never under Hardened).
    pub allow_tls12: bool,
}

impl IntegrationPolicy {
    /// The longest certificate lifetime the setting takes, in days (the Lab value).
    pub const MAX_LIFETIME_DAYS: u32 = 365;

    /// The values of a profile.
    pub const fn of(profile: Profile) -> Self {
        let (lifetime_days, require_binding) = match profile {
            Profile::Home => (90, false),
            Profile::Standard => (30, false),
            Profile::Hardened => (7, true),
            Profile::Lab => (365, false),
        };
        Self {
            lifetime_days,
            require_binding,
            allow_tls12: false,
        }
    }
}
