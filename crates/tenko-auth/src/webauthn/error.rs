//! Errors of the WebAuthn ceremonies (`auth.webauthn.*`).

use std::collections::BTreeMap;

use tenko_core::Coded;

/// Why a registration or an assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebAuthnError {
    /// A field does not decode or has an impossible shape.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// `clientDataJSON.type` is not the expected ceremony type.
    #[error("client data has the wrong ceremony type")]
    WrongCeremony,
    /// The challenge in the client data is not the one issued.
    #[error("the challenge does not match")]
    ChallengeMismatch,
    /// The origin is not one of the configured origins.
    #[error("origin `{0}` is not allowed")]
    OriginMismatch(String),
    /// The ceremony ran in a cross-origin iframe (`crossOrigin` or `topOrigin`).
    #[error("cross-origin ceremonies are not allowed")]
    CrossOrigin,
    /// The RP ID hash of the authenticator data does not match.
    #[error("the RP ID hash does not match")]
    RpIdMismatch,
    /// The user-present flag is not set.
    #[error("user presence was not confirmed")]
    UserPresenceMissing,
    /// The user-verified flag is not set although user verification is required.
    #[error("user verification is required")]
    UserVerificationMissing,
    /// BS is set without BE, or BE changed since registration.
    #[error("inconsistent backup flags")]
    BackupFlagsInvalid,
    /// The credential algorithm is not ES256, `EdDSA` or RS256.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(i64),
    /// The attestation format is not `none` or `packed`.
    #[error("unsupported attestation format `{0}`")]
    UnsupportedAttestation(String),
    /// The attestation statement does not verify.
    #[error("invalid attestation: {0}")]
    AttestationInvalid(&'static str),
    /// The account needs an attested hardware key, and the credential has no verified
    /// `packed` certificate attestation.
    #[error("an attested hardware security key is required")]
    AttestationRequired,
    /// The attestation certificate does not chain to a configured trust anchor.
    #[error("the attestation does not chain to a trusted root")]
    AttestationUntrusted,
    /// The account refuses backup-eligible (synced) credentials (IAM-09).
    #[error("a synced passkey is not accepted for this account")]
    BackupEligibleRefused,
    /// The signature does not verify.
    #[error("the signature does not verify")]
    SignatureInvalid,
    /// The signature counter did not increase: the authenticator may be cloned.
    #[error("the signature counter did not increase")]
    CounterRegression,
    /// The credential or the user handle does not match the expected account.
    #[error("the credential does not belong to the expected account")]
    CredentialMismatch,
    /// The credential is already registered.
    #[error("the credential is already registered")]
    CredentialExists,
}

impl Coded for WebAuthnError {
    fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "auth.webauthn.malformed",
            Self::WrongCeremony => "auth.webauthn.wrong_ceremony",
            Self::ChallengeMismatch => "auth.webauthn.challenge_mismatch",
            Self::OriginMismatch(_) => "auth.webauthn.origin_mismatch",
            Self::CrossOrigin => "auth.webauthn.cross_origin",
            Self::RpIdMismatch => "auth.webauthn.rp_id_mismatch",
            Self::UserPresenceMissing => "auth.webauthn.user_presence",
            Self::UserVerificationMissing => "auth.webauthn.user_verification",
            Self::BackupFlagsInvalid => "auth.webauthn.backup_flags",
            Self::UnsupportedAlgorithm(_) => "auth.webauthn.unsupported_algorithm",
            Self::UnsupportedAttestation(_) => "auth.webauthn.unsupported_attestation",
            Self::AttestationInvalid(_) => "auth.webauthn.attestation_invalid",
            Self::AttestationRequired => "auth.webauthn.attestation_required",
            Self::AttestationUntrusted => "auth.webauthn.attestation_untrusted",
            Self::BackupEligibleRefused => "auth.webauthn.backup_eligible_refused",
            Self::SignatureInvalid => "auth.webauthn.signature_invalid",
            Self::CounterRegression => "auth.webauthn.counter_regression",
            Self::CredentialMismatch => "auth.webauthn.credential_mismatch",
            Self::CredentialExists => "auth.webauthn.credential_exists",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::CredentialExists => 409,
            Self::AttestationRequired
            | Self::AttestationUntrusted
            | Self::BackupEligibleRefused => 403,
            _ => 400,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::Malformed(what) => BTreeMap::from([("what", (*what).to_owned())]),
            Self::OriginMismatch(origin) => BTreeMap::from([("origin", origin.clone())]),
            Self::UnsupportedAlgorithm(alg) => BTreeMap::from([("alg", alg.to_string())]),
            Self::UnsupportedAttestation(format) => BTreeMap::from([("format", format.clone())]),
            Self::AttestationInvalid(reason) => BTreeMap::from([("reason", (*reason).to_owned())]),
            _ => BTreeMap::new(),
        }
    }
}
