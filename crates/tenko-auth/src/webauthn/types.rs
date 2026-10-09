//! Wire types of the ceremonies, in the JSON shapes of WebAuthn Level 3
//! (`PublicKeyCredentialCreationOptionsJSON`, `PublicKeyCredentialRequestOptionsJSON`,
//! `RegistrationResponseJSON` and `AuthenticationResponseJSON`). Binary members are
//! unpadded base64url strings, as `PublicKeyCredential.parseCreationOptionsFromJSON()` and
//! `toJSON()` expect in the browser.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// COSE algorithm identifier of ES256 (ECDSA P-256 with SHA-256).
pub const ALG_ES256: i64 = -7;
/// COSE algorithm identifier of `EdDSA` (Ed25519).
pub const ALG_EDDSA: i64 = -8;
/// COSE algorithm identifier of RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
pub const ALG_RS256: i64 = -257;

/// The relying party as shown by the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RpEntity {
    /// The RP ID: the host name of the installation.
    pub id: String,
    /// A human-readable name.
    pub name: String,
}

/// The account a credential is created for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    /// The user handle: the 16 bytes of the user's UUID, base64url.
    pub id: String,
    /// The user name.
    pub name: String,
    /// The display name.
    pub display_name: String,
}

/// An acceptable credential algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialParameter {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The COSE algorithm identifier.
    pub alg: i64,
}

/// A credential reference in `excludeCredentials` or `allowCredentials`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialDescriptor {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The credential id, base64url.
    pub id: String,
    /// Transport hints reported at registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

impl CredentialDescriptor {
    /// A descriptor for a credential id.
    pub fn new(id: &[u8], transports: Vec<String>) -> Self {
        Self {
            type_: "public-key".to_owned(),
            id: crate::encoding::base64url_encode(id),
            transports,
        }
    }
}

/// How strongly the relying party asks for user verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserVerification {
    /// The ceremony fails without user verification.
    Required,
    /// User verification is asked for but not enforced.
    Preferred,
    /// User verification is not asked for.
    Discouraged,
}

impl UserVerification {
    /// The value of the WebAuthn enumeration.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
}

/// Authenticator selection criteria of a registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    /// `platform` or `cross-platform`; absent for any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Always `required`: Tenko creates discoverable credentials.
    pub resident_key: String,
    /// Always `true` (Level 1 clients).
    pub require_resident_key: bool,
    /// `required`, `preferred` or `discouraged`.
    pub user_verification: String,
}

/// Options of a registration ceremony, passed to
/// `PublicKeyCredential.parseCreationOptionsFromJSON()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreationOptions {
    /// The relying party.
    pub rp: RpEntity,
    /// The account.
    pub user: UserEntity,
    /// The challenge, base64url.
    pub challenge: String,
    /// Acceptable algorithms, preferred first.
    pub pub_key_cred_params: Vec<CredentialParameter>,
    /// Ceremony timeout in milliseconds.
    pub timeout: u32,
    /// Credentials the account already has.
    #[serde(default)]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    /// Authenticator selection.
    pub authenticator_selection: AuthenticatorSelection,
    /// `none` or `direct`.
    pub attestation: String,
    /// Client hints such as `security-key`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

/// Options of an authentication ceremony, passed to
/// `PublicKeyCredential.parseRequestOptionsFromJSON()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    /// The challenge, base64url.
    pub challenge: String,
    /// Ceremony timeout in milliseconds.
    pub timeout: u32,
    /// The RP ID.
    pub rp_id: String,
    /// Allowed credentials; empty for a discoverable login.
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    /// `required`, `preferred` or `discouraged`.
    pub user_verification: String,
    /// Client hints such as `security-key`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

/// The `response` member of a registration (`AuthenticatorAttestationResponseJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    /// `clientDataJSON`, base64url.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// The CBOR attestation object, base64url.
    pub attestation_object: String,
    /// Transports reported by the client.
    #[serde(default)]
    pub transports: Vec<String>,
}

/// A registration result from the browser (`RegistrationResponseJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    /// The credential id, base64url.
    pub id: String,
    /// The credential id again, base64url.
    pub raw_id: String,
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The attestation response.
    pub response: AttestationResponse,
    /// `platform` or `cross-platform`, when the client reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results; ignored.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub client_extension_results: serde_json::Value,
}

/// The `response` member of an assertion (`AuthenticatorAssertionResponseJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    /// `clientDataJSON`, base64url.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// The authenticator data, base64url.
    pub authenticator_data: String,
    /// The signature, base64url.
    pub signature: String,
    /// The user handle, base64url; present for discoverable credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// An authentication result from the browser (`AuthenticationResponseJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    /// The credential id, base64url.
    pub id: String,
    /// The credential id again, base64url.
    pub raw_id: String,
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The assertion response.
    pub response: AssertionResponse,
    /// `platform` or `cross-platform`, when the client reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results; ignored.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub client_extension_results: serde_json::Value,
}

/// The client data of a ceremony (`CollectedClientData`), as parsed from
/// `clientDataJSON`. Unknown members are ignored, as the specification requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    /// `webauthn.create` or `webauthn.get`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The challenge, base64url.
    pub challenge: String,
    /// The origin of the calling page.
    pub origin: String,
    /// Whether the call came from a cross-origin iframe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
    /// The top-level origin when the call came from an iframe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_origin: Option<String>,
}
