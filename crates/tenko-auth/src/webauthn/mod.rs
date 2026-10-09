//! The WebAuthn relying party (ADR 0010): registration and authentication ceremonies,
//! discoverable credentials, ES256, `EdDSA` and RS256, attestation `none` and `packed`.
//!
//! The verifier is stateless: the service issues a challenge, keeps it with the ceremony
//! state, and hands both to [`RelyingParty::finish_registration`] or
//! [`RelyingParty::finish_assertion`]. All cryptography is `aws-lc-rs`.
//!
//! Registration (WebAuthn Level 3, section 7.1) checks, in order: credential type and
//! id, client data type, challenge, origin, `crossOrigin` and `topOrigin`, the attestation
//! object, the RP ID hash, user presence, user verification when required, the backup
//! flags, the attested credential id and public key (ES256, `EdDSA`, RS256 only), the
//! attestation statement and, for accounts that need a hardware key, the attestation kind
//! and the backup-eligible flag.
//!
//! Authentication (section 7.2) checks the credential id, the client data as above, the
//! RP ID hash, user presence, user verification when required, the backup flags against
//! the stored ones, the signature over `authenticatorData || SHA-256(clientDataJSON)` and
//! the signature counter.

mod attestation;
mod authdata;
mod cose;
mod der;
mod error;
mod types;

use ciborium::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::Timestamp;
use utoipa::ToSchema;

pub use attestation::{AttestationKind, TrustAnchor};
pub use authdata::{AuthenticatorData, Flags, MAX_CREDENTIAL_ID_LEN};
pub use cose::CoseKey;
pub use error::WebAuthnError;
pub use types::{
    ALG_EDDSA, ALG_ES256, ALG_RS256, AssertionResponse, AttestationResponse,
    AuthenticationResponse, AuthenticatorSelection, ClientData, CreationOptions,
    CredentialDescriptor, CredentialParameter, RegistrationResponse, RequestOptions, RpEntity,
    UserEntity, UserVerification,
};

use crate::encoding::{base64url_decode, base64url_encode};

/// Default ceremony timeout: five minutes.
pub const DEFAULT_TIMEOUT_MS: u32 = 300_000;

/// Configuration of the relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpConfig {
    /// The RP ID: the installation's host name (`localhost` in development).
    pub rp_id: String,
    /// The name the browser shows.
    pub rp_name: String,
    /// The origins the UI is served from, for example `https://tenko.example.test`. An
    /// entry ending in `:*` (`https://tenko.example.test:*`) matches the scheme and host on
    /// any port, or without one.
    pub origins: Vec<String>,
    /// DER root certificates that attestation chains may end at. Empty: certificate
    /// attestation is verified but not anchored.
    pub trust_anchors: Vec<Vec<u8>>,
    /// Ceremony timeout in milliseconds.
    pub timeout_ms: u32,
}

impl RpConfig {
    /// A configuration for `rp_id` served from `https://<rp_id>` on any port.
    pub fn for_host(rp_id: &str) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            rp_name: "Tenko DDI".to_owned(),
            origins: vec![format!("https://{rp_id}:*")],
            trust_anchors: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Requirements of a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationPolicy {
    /// Whether user verification is required.
    pub user_verification: UserVerification,
    /// The account accepts only attested, non-backup-eligible security keys (break-glass,
    /// IAM-09). The options then ask for `direct` attestation and a cross-platform
    /// authenticator.
    pub hardware_key_required: bool,
}

impl Default for RegistrationPolicy {
    fn default() -> Self {
        Self {
            user_verification: UserVerification::Required,
            hardware_key_required: false,
        }
    }
}

/// Requirements of an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionPolicy {
    /// Whether user verification is required.
    pub user_verification: UserVerification,
    /// The account accepts only hardware keys: a backup-eligible assertion is refused.
    pub hardware_key_required: bool,
}

impl Default for AssertionPolicy {
    fn default() -> Self {
        Self {
            user_verification: UserVerification::Required,
            hardware_key_required: false,
        }
    }
}

/// A verified new credential, ready to be stored.
#[allow(clippy::struct_excessive_bools)] // The WebAuthn flags are independent booleans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The COSE public key as the authenticator encoded it.
    pub public_key: Vec<u8>,
    /// The COSE algorithm.
    pub alg: i64,
    /// The signature counter at registration.
    pub sign_count: u32,
    /// The authenticator model.
    pub aaguid: [u8; 16],
    /// Whether the user was verified during registration.
    pub user_verified: bool,
    /// Whether the credential may be synced (a passkey provider's credential).
    pub backup_eligible: bool,
    /// Whether the credential is currently backed up.
    pub backup_state: bool,
    /// What the attestation proved.
    pub attestation: AttestationKind,
    /// Transports reported by the client.
    pub transports: Vec<String>,
    /// Whether the credential counts as a hardware security key (ADR 0010, decision 4).
    pub hardware_key: bool,
}

/// What the relying party needs of a stored credential to verify an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredKey<'a> {
    /// The credential id.
    pub credential_id: &'a [u8],
    /// The COSE public key.
    pub public_key: &'a [u8],
    /// The last signature counter seen.
    pub sign_count: u32,
    /// The backup-eligible flag recorded at registration.
    pub backup_eligible: bool,
}

/// A verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The new signature counter to store.
    pub sign_count: u32,
    /// Whether the user was verified.
    pub user_verified: bool,
    /// Whether the credential is currently backed up.
    pub backup_state: bool,
    /// The user handle the authenticator returned, if any.
    pub user_handle: Option<Vec<u8>>,
}

/// A summary of a credential for listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialFlags {
    /// Whether the credential may be synced.
    pub backup_eligible: bool,
    /// Whether the credential was backed up at its last use.
    pub backup_state: bool,
}

/// The relying party.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    config: RpConfig,
    rp_id_hash: [u8; 32],
    anchors: Vec<TrustAnchor>,
}

impl RelyingParty {
    /// Creates a relying party.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::Malformed`] for an empty RP ID or origin list, or
    /// [`WebAuthnError::AttestationInvalid`] for a trust anchor that is not a certificate.
    pub fn new(config: RpConfig) -> Result<Self, WebAuthnError> {
        if config.rp_id.is_empty() || config.origins.is_empty() {
            return Err(WebAuthnError::Malformed("relying-party configuration"));
        }
        let anchors = config
            .trust_anchors
            .iter()
            .map(|der| TrustAnchor::from_der(der.clone()))
            .collect::<Result<_, _>>()?;
        let rp_id_hash = Sha256::digest(config.rp_id.as_bytes()).into();
        Ok(Self {
            config,
            rp_id_hash,
            anchors,
        })
    }

    /// The RP ID.
    pub fn rp_id(&self) -> &str {
        &self.config.rp_id
    }

    /// The configuration.
    pub fn config(&self) -> &RpConfig {
        &self.config
    }

    /// Whether attestation trust anchors are configured.
    pub fn has_trust_anchors(&self) -> bool {
        !self.anchors.is_empty()
    }

    /// Options for a registration ceremony. `user_handle` is the account's 16-byte user
    /// handle; `exclude` lists the account's existing credentials.
    pub fn creation_options(
        &self,
        user_handle: &[u8],
        user_name: &str,
        display_name: &str,
        challenge: &[u8],
        exclude: Vec<CredentialDescriptor>,
        policy: &RegistrationPolicy,
    ) -> CreationOptions {
        let hardware = policy.hardware_key_required;
        CreationOptions {
            rp: RpEntity {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            user: UserEntity {
                id: base64url_encode(user_handle),
                name: user_name.to_owned(),
                display_name: display_name.to_owned(),
            },
            challenge: base64url_encode(challenge),
            pub_key_cred_params: [ALG_ES256, ALG_EDDSA, ALG_RS256]
                .into_iter()
                .map(|alg| CredentialParameter {
                    type_: "public-key".to_owned(),
                    alg,
                })
                .collect(),
            timeout: self.config.timeout_ms,
            exclude_credentials: exclude,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: hardware.then(|| "cross-platform".to_owned()),
                resident_key: "required".to_owned(),
                require_resident_key: true,
                user_verification: policy.user_verification.as_str().to_owned(),
            },
            attestation: if hardware { "direct" } else { "none" }.to_owned(),
            hints: if hardware {
                vec!["security-key".to_owned()]
            } else {
                Vec::new()
            },
        }
    }

    /// Options for an authentication ceremony. An empty `allow` list asks for a
    /// discoverable credential.
    pub fn request_options(
        &self,
        challenge: &[u8],
        allow: Vec<CredentialDescriptor>,
        policy: &AssertionPolicy,
    ) -> RequestOptions {
        RequestOptions {
            challenge: base64url_encode(challenge),
            timeout: self.config.timeout_ms,
            rp_id: self.config.rp_id.clone(),
            allow_credentials: allow,
            user_verification: policy.user_verification.as_str().to_owned(),
            hints: if policy.hardware_key_required {
                vec!["security-key".to_owned()]
            } else {
                Vec::new()
            },
        }
    }

    /// Verifies a registration response against the issued challenge.
    ///
    /// # Errors
    ///
    /// The [`WebAuthnError`] of the first failed check.
    pub fn finish_registration(
        &self,
        response: &RegistrationResponse,
        challenge: &[u8],
        policy: &RegistrationPolicy,
        now: Timestamp,
    ) -> Result<RegisteredCredential, WebAuthnError> {
        let raw_id = credential_id(&response.type_, &response.id, &response.raw_id)?;
        let client_data_json = decode(&response.response.client_data_json, "clientDataJSON")?;
        self.check_client_data(&client_data_json, "webauthn.create", challenge)?;
        let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();

        let object = decode(&response.response.attestation_object, "attestationObject")?;
        let (format, statement, auth_data_raw) = parse_attestation_object(&object)?;
        let auth_data = AuthenticatorData::parse(&auth_data_raw)?;
        self.check_flags(&auth_data, policy.user_verification)?;
        let attested = auth_data
            .attested
            .as_ref()
            .ok_or(WebAuthnError::Malformed("attested credential data"))?;
        if attested.credential_id != raw_id {
            return Err(WebAuthnError::CredentialMismatch);
        }

        let attestation = attestation::verify(
            &attestation::Statement {
                format: &format,
                body: &statement,
                auth_data: &auth_data_raw,
                client_data_hash: &client_data_hash,
                credential_key: &attested.public_key,
                aaguid: &attested.aaguid,
            },
            &self.anchors,
            now.0.unix_timestamp(),
        )?;
        let backup_eligible = auth_data.flags.backup_eligible();
        let hardware_key = matches!(
            attestation,
            AttestationKind::Certificate { anchored, .. } if anchored || self.anchors.is_empty()
        ) && !backup_eligible;
        if policy.hardware_key_required {
            match &attestation {
                AttestationKind::Certificate {
                    anchored: false, ..
                } if !self.anchors.is_empty() => {
                    return Err(WebAuthnError::AttestationUntrusted);
                }
                AttestationKind::Certificate { .. } => {}
                AttestationKind::None | AttestationKind::SelfAttestation => {
                    return Err(WebAuthnError::AttestationRequired);
                }
            }
            if backup_eligible {
                return Err(WebAuthnError::BackupEligibleRefused);
            }
        }

        Ok(RegisteredCredential {
            credential_id: raw_id,
            public_key: attested.public_key_cbor.clone(),
            alg: attested.public_key.alg(),
            sign_count: auth_data.sign_count,
            aaguid: attested.aaguid,
            user_verified: auth_data.flags.user_verified(),
            backup_eligible,
            backup_state: auth_data.flags.backup_state(),
            attestation,
            transports: response.response.transports.clone(),
            hardware_key,
        })
    }

    /// Verifies an assertion with a stored credential. The caller looked the credential
    /// up by [`assertion_credential_id`] and checks the returned user handle against the
    /// account.
    ///
    /// # Errors
    ///
    /// The [`WebAuthnError`] of the first failed check.
    pub fn finish_assertion(
        &self,
        response: &AuthenticationResponse,
        challenge: &[u8],
        stored: &StoredKey<'_>,
        policy: &AssertionPolicy,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        let raw_id = credential_id(&response.type_, &response.id, &response.raw_id)?;
        if raw_id != stored.credential_id {
            return Err(WebAuthnError::CredentialMismatch);
        }
        let client_data_json = decode(&response.response.client_data_json, "clientDataJSON")?;
        self.check_client_data(&client_data_json, "webauthn.get", challenge)?;
        let auth_data_raw = decode(&response.response.authenticator_data, "authenticatorData")?;
        let auth_data = AuthenticatorData::parse(&auth_data_raw)?;
        if auth_data.attested.is_some() {
            return Err(WebAuthnError::Malformed("attested data in an assertion"));
        }
        self.check_flags(&auth_data, policy.user_verification)?;
        if auth_data.flags.backup_eligible() != stored.backup_eligible {
            return Err(WebAuthnError::BackupFlagsInvalid);
        }
        if policy.hardware_key_required && auth_data.flags.backup_eligible() {
            return Err(WebAuthnError::BackupEligibleRefused);
        }

        let key = CoseKey::parse(stored.public_key)?;
        let signature = decode(&response.response.signature, "signature")?;
        let mut signed = auth_data_raw;
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        key.verify(&signed, &signature)?;

        if (auth_data.sign_count != 0 || stored.sign_count != 0)
            && auth_data.sign_count <= stored.sign_count
        {
            return Err(WebAuthnError::CounterRegression);
        }
        let user_handle = response
            .response
            .user_handle
            .as_deref()
            .filter(|handle| !handle.is_empty())
            .map(|handle| decode(handle, "userHandle"))
            .transpose()?;
        Ok(VerifiedAssertion {
            sign_count: auth_data.sign_count,
            user_verified: auth_data.flags.user_verified(),
            backup_state: auth_data.flags.backup_state(),
            user_handle,
        })
    }

    fn check_client_data(
        &self,
        json: &[u8],
        ceremony: &str,
        challenge: &[u8],
    ) -> Result<(), WebAuthnError> {
        let client_data: ClientData =
            serde_json::from_slice(json).map_err(|_| WebAuthnError::Malformed("clientDataJSON"))?;
        if client_data.type_ != ceremony {
            return Err(WebAuthnError::WrongCeremony);
        }
        let presented = base64url_decode(&client_data.challenge)
            .map_err(|_| WebAuthnError::Malformed("challenge"))?;
        if aws_lc_rs::constant_time::verify_slices_are_equal(&presented, challenge).is_err() {
            return Err(WebAuthnError::ChallengeMismatch);
        }
        if !self
            .config
            .origins
            .iter()
            .any(|allowed| origin_matches(allowed, &client_data.origin))
        {
            return Err(WebAuthnError::OriginMismatch(truncate(&client_data.origin)));
        }
        if client_data.cross_origin == Some(true) || client_data.top_origin.is_some() {
            return Err(WebAuthnError::CrossOrigin);
        }
        Ok(())
    }

    fn check_flags(
        &self,
        auth_data: &AuthenticatorData,
        user_verification: UserVerification,
    ) -> Result<(), WebAuthnError> {
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            &auth_data.rp_id_hash,
            &self.rp_id_hash,
        )
        .is_err()
        {
            return Err(WebAuthnError::RpIdMismatch);
        }
        if !auth_data.flags.user_present() {
            return Err(WebAuthnError::UserPresenceMissing);
        }
        if user_verification == UserVerification::Required && !auth_data.flags.user_verified() {
            return Err(WebAuthnError::UserVerificationMissing);
        }
        if auth_data.flags.backup_state() && !auth_data.flags.backup_eligible() {
            return Err(WebAuthnError::BackupFlagsInvalid);
        }
        Ok(())
    }
}

/// The credential id of an assertion, for looking up the stored credential.
///
/// # Errors
///
/// [`WebAuthnError::Malformed`] if the id does not decode or `id` and `rawId` differ.
pub fn assertion_credential_id(
    response: &AuthenticationResponse,
) -> Result<Vec<u8>, WebAuthnError> {
    credential_id(&response.type_, &response.id, &response.raw_id)
}

fn credential_id(type_: &str, id: &str, raw_id: &str) -> Result<Vec<u8>, WebAuthnError> {
    if type_ != "public-key" {
        return Err(WebAuthnError::Malformed("credential type"));
    }
    let decoded = decode(raw_id, "rawId")?;
    if decode(id, "id")? != decoded || decoded.is_empty() || decoded.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(WebAuthnError::Malformed("credential id"));
    }
    Ok(decoded)
}

/// Whether a client origin matches an allowed origin (exact, or any port for `:*`).
fn origin_matches(allowed: &str, origin: &str) -> bool {
    match allowed.strip_suffix(":*") {
        None => allowed == origin,
        Some(base) => origin.strip_prefix(base).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
        }),
    }
}

fn decode(text: &str, what: &'static str) -> Result<Vec<u8>, WebAuthnError> {
    base64url_decode(text).map_err(|_| WebAuthnError::Malformed(what))
}

fn truncate(text: &str) -> String {
    text.chars().take(128).collect()
}

fn parse_attestation_object(bytes: &[u8]) -> Result<(String, Value, Vec<u8>), WebAuthnError> {
    const MALFORMED: WebAuthnError = WebAuthnError::Malformed("attestationObject");
    let mut reader = bytes;
    let value: Value = ciborium::de::from_reader(&mut reader).map_err(|_| MALFORMED)?;
    if !reader.is_empty() {
        return Err(MALFORMED);
    }
    let Value::Map(entries) = value else {
        return Err(MALFORMED);
    };
    let mut format = None;
    let mut statement = None;
    let mut auth_data = None;
    for (key, value) in entries {
        match (key.as_text(), value) {
            (Some("fmt"), Value::Text(text)) if format.is_none() => format = Some(text),
            (Some("attStmt"), value @ Value::Map(_)) if statement.is_none() => {
                statement = Some(value);
            }
            (Some("authData"), Value::Bytes(bytes)) if auth_data.is_none() => {
                auth_data = Some(bytes);
            }
            // Members of other specifications are ignored; a known member with the wrong
            // type or twice is not.
            (Some(name), _) if !matches!(name, "fmt" | "attStmt" | "authData") => {}
            _ => return Err(MALFORMED),
        }
    }
    match (format, statement, auth_data) {
        (Some(format), Some(statement), Some(auth_data)) => Ok((format, statement, auth_data)),
        _ => Err(MALFORMED),
    }
}

#[cfg(test)]
mod tests {
    use super::origin_matches;

    #[test]
    fn origins_match_exactly_or_on_any_port() {
        assert!(origin_matches("https://a.test", "https://a.test"));
        assert!(!origin_matches("https://a.test", "https://a.test:8443"));
        assert!(origin_matches("https://a.test:*", "https://a.test"));
        assert!(origin_matches("https://a.test:*", "https://a.test:8443"));
        assert!(!origin_matches(
            "https://a.test:*",
            "https://a.test.evil:8443"
        ));
        assert!(!origin_matches("https://a.test:*", "https://a.testx"));
        assert!(!origin_matches("https://a.test:*", "http://a.test"));
        assert!(!origin_matches("https://a.test:*", "https://a.test:"));
        assert!(!origin_matches("https://a.test:*", "https://a.test:84/x"));
    }
}
