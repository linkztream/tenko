//! Attestation statement verification: formats `none` and `packed` (WebAuthn Level 3,
//! sections 8.2 and 8.7). Every other format is refused.

use ciborium::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use utoipa::ToSchema;

use super::{
    WebAuthnError,
    cose::CoseKey,
    der::{Certificate, PublicKey, oid},
    types::{ALG_EDDSA, ALG_ES256, ALG_RS256},
};

/// What the attestation of a credential proved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttestationKind {
    /// No attestation (`none`).
    None,
    /// `packed` self attestation: signed with the credential key itself.
    SelfAttestation,
    /// `packed` attestation with a certificate chain (`x5c`).
    Certificate {
        /// Whether the chain ends at a configured trust anchor.
        anchored: bool,
        /// SHA-256 of the attestation certificate, hexadecimal.
        certificate_sha256: String,
        /// The common name of the attestation certificate.
        subject: String,
    },
}

/// A configured attestation trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    der: Vec<u8>,
    subject: Vec<u8>,
    public_key: PublicKey,
    not_before: i64,
    not_after: i64,
}

impl TrustAnchor {
    /// Parses a DER root certificate.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::AttestationInvalid`] if it is not a certificate.
    pub fn from_der(der: Vec<u8>) -> Result<Self, WebAuthnError> {
        let certificate = Certificate::parse(&der)?;
        let subject = certificate.subject.to_vec();
        let public_key = certificate.public_key.clone();
        let (not_before, not_after) = (certificate.not_before, certificate.not_after);
        Ok(Self {
            der,
            subject,
            public_key,
            not_before,
            not_after,
        })
    }

    /// Whether the anchor is or issued `last`, the top of an attestation chain.
    fn vouches_for(&self, last: &Certificate<'_>, now_unix: i64) -> bool {
        self.der == last.raw
            || (self.subject == last.issuer
                && self.not_before <= now_unix
                && now_unix <= self.not_after
                && last.verify_issued_by(&self.public_key).is_ok())
    }
}

/// The inputs of attestation verification.
pub(super) struct Statement<'a> {
    pub format: &'a str,
    pub body: &'a Value,
    pub auth_data: &'a [u8],
    pub client_data_hash: &'a [u8; 32],
    pub credential_key: &'a CoseKey,
    pub aaguid: &'a [u8; 16],
}

/// Verifies an attestation statement.
pub(super) fn verify(
    input: &Statement<'_>,
    anchors: &[TrustAnchor],
    now_unix: i64,
) -> Result<AttestationKind, WebAuthnError> {
    match input.format {
        "none" => match input.body {
            Value::Map(entries) if entries.is_empty() => Ok(AttestationKind::None),
            _ => Err(WebAuthnError::AttestationInvalid("`none` with a statement")),
        },
        "packed" => verify_packed(input, anchors, now_unix),
        other => Err(WebAuthnError::UnsupportedAttestation(other.to_owned())),
    }
}

fn verify_packed(
    input: &Statement<'_>,
    anchors: &[TrustAnchor],
    now_unix: i64,
) -> Result<AttestationKind, WebAuthnError> {
    let Value::Map(entries) = input.body else {
        return Err(WebAuthnError::AttestationInvalid("statement is not a map"));
    };
    let mut alg = None;
    let mut sig = None;
    let mut x5c = None;
    for (key, value) in entries {
        match (key.as_text(), value) {
            (Some("alg"), Value::Integer(value)) if alg.is_none() => {
                alg =
                    Some(i64::try_from(i128::from(*value)).map_err(|_| {
                        WebAuthnError::AttestationInvalid("algorithm out of range")
                    })?);
            }
            (Some("sig"), Value::Bytes(bytes)) if sig.is_none() => sig = Some(bytes),
            (Some("x5c"), Value::Array(items)) if x5c.is_none() => x5c = Some(items),
            (Some("ecdaaKeyId"), _) => {
                return Err(WebAuthnError::UnsupportedAttestation(
                    "packed-ecdaa".to_owned(),
                ));
            }
            _ => {
                return Err(WebAuthnError::AttestationInvalid(
                    "unexpected statement member",
                ));
            }
        }
    }
    let alg = alg.ok_or(WebAuthnError::AttestationInvalid("missing alg"))?;
    let sig = sig.ok_or(WebAuthnError::AttestationInvalid("missing sig"))?;
    let mut signed = Vec::with_capacity(input.auth_data.len() + 32);
    signed.extend_from_slice(input.auth_data);
    signed.extend_from_slice(input.client_data_hash);

    let Some(chain) = x5c else {
        // Self attestation: the credential key signs, with its own algorithm.
        if alg != input.credential_key.alg() {
            return Err(WebAuthnError::AttestationInvalid(
                "self attestation algorithm differs from the credential",
            ));
        }
        input
            .credential_key
            .verify(&signed, sig)
            .map_err(|_| WebAuthnError::AttestationInvalid("self attestation signature"))?;
        return Ok(AttestationKind::SelfAttestation);
    };

    let ders: Vec<&[u8]> = chain
        .iter()
        .map(|item| match item {
            Value::Bytes(bytes) => Ok(bytes.as_slice()),
            _ => Err(WebAuthnError::AttestationInvalid(
                "x5c item is not a certificate",
            )),
        })
        .collect::<Result<_, _>>()?;
    if ders.is_empty() || ders.len() > 8 {
        return Err(WebAuthnError::AttestationInvalid("x5c length"));
    }
    let certificates: Vec<Certificate<'_>> = ders
        .iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<_, _>>()?;
    let leaf = &certificates[0];
    check_leaf_requirements(leaf, input.aaguid)?;
    verify_with_certificate_key(leaf, alg, &signed, sig)?;
    for (index, certificate) in certificates.iter().enumerate() {
        if !certificate.valid_at(now_unix) {
            return Err(WebAuthnError::AttestationInvalid(
                "certificate outside its validity",
            ));
        }
        if let Some(issuer) = certificates.get(index + 1) {
            if certificate.issuer != issuer.subject || issuer.is_ca()? != Some(true) {
                return Err(WebAuthnError::AttestationInvalid(
                    "broken certificate chain",
                ));
            }
            certificate.verify_issued_by(&issuer.public_key)?;
        }
    }
    let last = certificates.last().unwrap_or(leaf);
    let anchored = anchors
        .iter()
        .any(|anchor| anchor.vouches_for(last, now_unix));
    let certificate_sha256 = crate::encoding::hex_encode(&Sha256::digest(leaf.raw));
    Ok(AttestationKind::Certificate {
        anchored,
        certificate_sha256,
        subject: leaf
            .subject_attribute(oid::COMMON_NAME)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// The requirements of section 8.2.1 on a `packed` attestation certificate.
fn check_leaf_requirements(leaf: &Certificate<'_>, aaguid: &[u8; 16]) -> Result<(), WebAuthnError> {
    let fail = WebAuthnError::AttestationInvalid;
    if leaf.version != 2 {
        return Err(fail("attestation certificate is not X.509 v3"));
    }
    if leaf.subject_attribute(oid::ORGANIZATIONAL_UNIT) != Some("Authenticator Attestation") {
        return Err(fail("attestation certificate subject OU"));
    }
    let has = |oid: &[u8]| {
        leaf.subject_attribute(oid)
            .is_some_and(|value| !value.is_empty())
    };
    if !has(oid::COUNTRY) || !has(oid::ORGANIZATION) || !has(oid::COMMON_NAME) {
        return Err(fail("attestation certificate subject"));
    }
    if leaf.is_ca()? == Some(true) {
        return Err(fail("attestation certificate is a CA"));
    }
    if let Some(certified) = leaf.aaguid()?
        && &certified != aaguid
    {
        return Err(fail("AAGUID differs from the certificate"));
    }
    Ok(())
}

fn verify_with_certificate_key(
    leaf: &Certificate<'_>,
    alg: i64,
    message: &[u8],
    sig: &[u8],
) -> Result<(), WebAuthnError> {
    use aws_lc_rs::signature::{self, UnparsedPublicKey};
    let refused = WebAuthnError::AttestationInvalid("attestation signature");
    let (algorithm, key): (&'static dyn signature::VerificationAlgorithm, &[u8]) =
        match (alg, &leaf.public_key) {
            (ALG_ES256, PublicKey::P256(point)) => (&signature::ECDSA_P256_SHA256_ASN1, point),
            (ALG_RS256, PublicKey::Rsa(key)) => (&signature::RSA_PKCS1_2048_8192_SHA256, key),
            (ALG_EDDSA, PublicKey::Ed25519(key)) => (&signature::ED25519, key),
            (ALG_ES256 | ALG_RS256 | ALG_EDDSA, _) => {
                return Err(WebAuthnError::AttestationInvalid(
                    "algorithm does not match the certificate key",
                ));
            }
            (other, _) => return Err(WebAuthnError::UnsupportedAlgorithm(other)),
        };
    UnparsedPublicKey::new(algorithm, key)
        .verify(message, sig)
        .map_err(|_| refused)
}
