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
        other => Err(WebAuthnError::UnsupportedAttestation(format_name(other))),
    }
}

/// The longest attestation format name an error repeats: the registered formats are at
/// most 17 characters long.
pub(super) const MAX_FORMAT_NAME: usize = 32;

/// A format name as an error may repeat it: at most [`MAX_FORMAT_NAME`] characters, each
/// a visible ASCII character or `?`, so the answer never grows with what the client sent.
pub(super) fn format_name(format: &str) -> String {
    format
        .chars()
        .take(MAX_FORMAT_NAME)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
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
    check_chain_constraints(&certificates)?;
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

/// The constraints of the chain that need no signature: no certificate marks an
/// extension critical that the reader does not understand, and every issuer may sign
/// certificates (key usage `keyCertSign` when it states a key usage) and allows the
/// authorities below it (`pathLenConstraint`). Self-issued certificates are not part of
/// an attestation chain, so every issuer below an authority counts.
pub(super) fn check_chain_constraints(
    certificates: &[Certificate<'_>],
) -> Result<(), WebAuthnError> {
    for (index, certificate) in certificates.iter().enumerate() {
        certificate.check_critical_extensions()?;
        if index == 0 {
            continue;
        }
        if !certificate.may_sign_certificates()? {
            return Err(WebAuthnError::AttestationInvalid(
                "an issuer's key usage does not allow signing certificates",
            ));
        }
        // The authorities between this one and the leaf.
        let below = u32::try_from(index - 1).unwrap_or(u32::MAX);
        if certificate.path_len()?.is_some_and(|limit| below > limit) {
            return Err(WebAuthnError::AttestationInvalid(
                "the chain is longer than an issuer allows",
            ));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, KeyUsagePurpose,
    };

    use super::*;

    /// A self-signed certificate made with `params`; the constraints read no signature.
    fn der(params: &CertificateParams) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        params
            .self_signed(&key)
            .expect("certificate")
            .der()
            .to_vec()
    }

    fn params(ca: Option<BasicConstraints>, usages: Vec<KeyUsagePurpose>) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = ca.map_or(IsCa::NoCa, IsCa::Ca);
        params.key_usages = usages;
        params
    }

    fn check(ders: &[Vec<u8>]) -> Result<(), WebAuthnError> {
        let certificates: Vec<Certificate<'_>> = ders
            .iter()
            .map(|der| Certificate::parse(der).expect("parses"))
            .collect();
        check_chain_constraints(&certificates)
    }

    #[test]
    fn an_unknown_critical_extension_is_refused() {
        let mut leaf = params(None, Vec::new());
        let mut extension =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99_999, 1], vec![0x05, 0x00]);
        extension.set_criticality(true);
        leaf.custom_extensions = vec![extension];
        assert_eq!(
            check(&[der(&leaf)]),
            Err(WebAuthnError::AttestationInvalid(
                "unknown critical extension"
            ))
        );
        // The same extension, not critical, is ignored.
        let mut plain = params(None, Vec::new());
        plain.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 99_999, 1],
            vec![0x05, 0x00],
        )];
        assert_eq!(check(&[der(&plain)]), Ok(()));
        // Critical basic constraints and key usage are understood.
        let ca = params(
            Some(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign],
        );
        assert_eq!(check(&[der(&params(None, Vec::new())), der(&ca)]), Ok(()));
    }

    #[test]
    fn an_issuer_must_be_allowed_to_sign_certificates() {
        let leaf = der(&params(None, Vec::new()));
        let signs_only = params(
            Some(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::DigitalSignature],
        );
        assert_eq!(
            check(&[leaf.clone(), der(&signs_only)]),
            Err(WebAuthnError::AttestationInvalid(
                "an issuer's key usage does not allow signing certificates"
            ))
        );
        // Without a key usage nothing is restricted.
        let no_usage = params(Some(BasicConstraints::Unconstrained), Vec::new());
        assert_eq!(check(&[leaf, der(&no_usage)]), Ok(()));
    }

    #[test]
    fn an_issuer_limits_the_authorities_below_it() {
        let leaf = der(&params(None, Vec::new()));
        let usage = vec![KeyUsagePurpose::KeyCertSign];
        let intermediate = der(&params(
            Some(BasicConstraints::Constrained(0)),
            usage.clone(),
        ));
        let root_zero = der(&params(
            Some(BasicConstraints::Constrained(0)),
            usage.clone(),
        ));
        let root_one = der(&params(Some(BasicConstraints::Constrained(1)), usage));
        // An issuer with path length 0 may issue the leaf directly.
        assert_eq!(check(&[leaf.clone(), intermediate.clone()]), Ok(()));
        // One authority below a root that allows none is refused.
        assert_eq!(
            check(&[leaf.clone(), intermediate.clone(), root_zero]),
            Err(WebAuthnError::AttestationInvalid(
                "the chain is longer than an issuer allows"
            ))
        );
        assert_eq!(check(&[leaf, intermediate, root_one]), Ok(()));
    }

    #[test]
    fn the_path_length_and_the_key_usage_are_read() {
        let usage = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let constrained = der(&params(Some(BasicConstraints::Constrained(3)), usage));
        let certificate = Certificate::parse(&constrained).expect("parses");
        assert_eq!(certificate.path_len(), Ok(Some(3)));
        assert_eq!(certificate.may_sign_certificates(), Ok(true));
        let unconstrained = der(&params(
            Some(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::DigitalSignature],
        ));
        let certificate = Certificate::parse(&unconstrained).expect("parses");
        assert_eq!(certificate.path_len(), Ok(None));
        assert_eq!(certificate.may_sign_certificates(), Ok(false));
        let leaf = der(&params(None, Vec::new()));
        assert_eq!(
            Certificate::parse(&leaf).expect("parses").path_len(),
            Ok(None)
        );
    }

    #[test]
    fn a_format_name_in_an_error_is_bounded() {
        let long = "x".repeat(10_000);
        assert_eq!(format_name(&long).len(), MAX_FORMAT_NAME);
        assert_eq!(format_name("tpm\n\u{1b}[31m"), "tpm??[31m");
        assert_eq!(format_name("android-safetynet"), "android-safetynet");
        let Err(WebAuthnError::UnsupportedAttestation(echoed)) = verify(
            &Statement {
                format: &long,
                body: &Value::Map(Vec::new()),
                auth_data: &[],
                client_data_hash: &[0; 32],
                credential_key: &crate::webauthn::cose::CoseKey::parse(&es256_key()).expect("key"),
                aaguid: &[0; 16],
            },
            &[],
            0,
        ) else {
            panic!("refused");
        };
        assert_eq!(echoed.len(), MAX_FORMAT_NAME);
    }

    /// A COSE ES256 key with the generator point of P-256.
    fn es256_key() -> Vec<u8> {
        let x = crate::encoding::hex_decode(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
        .expect("hex");
        let y = crate::encoding::hex_decode(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .expect("hex");
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(x)),
            (Value::Integer((-3).into()), Value::Bytes(y)),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).expect("cbor");
        out
    }
}
