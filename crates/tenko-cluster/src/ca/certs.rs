//! Certificate generation with `rcgen` (ECDSA P-256, aws-lc-rs backend).
//!
//! Keys are generated here, kept in zeroizing buffers and handed on as [`SecretBytes`];
//! nothing in this module stores anything. The root is self-signed with a path length of
//! zero, so it can sign leaf certificates only. Leaf certificates carry an authority key
//! identifier, a random 16-byte serial number and a validity that starts one hour before
//! `now` to tolerate clock skew between nodes and clients.

use std::{collections::HashSet, net::IpAddr};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm, SigningKey, SubjectPublicKeyInfo, string::Ia5String,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tenko_core::{NodeId, Role, RoleSet};
use tenko_vault::SecretBytes;
use time::{Duration, OffsetDateTime, UtcOffset};
use x509_parser::{
    certification_request::X509CertificationRequest, parse_x509_certificate, prelude::FromDer,
};
use zeroize::Zeroizing;

use super::{CaError, ServerIdentity};

/// Organisation in the subject of the root.
const ORGANISATION: &str = "Tenko DDI";
/// Tolerated clock skew: certificates are valid from this long before issuance.
const CLOCK_SKEW: Duration = Duration::hours(1);
/// Longest common name X.520 allows (`ub-common-name`).
const MAX_COMMON_NAME: usize = 64;
/// Common name of a server certificate whose host name is too long for a common name; the
/// names themselves are in the subject alternative name.
const LONG_NAME_COMMON_NAME: &str = "Tenko DDI server";
/// Longest DNS name in octets (RFC 1035, without the root label).
const MAX_DNS_NAME: usize = 253;
/// Longest DNS label in octets.
const MAX_DNS_LABEL: usize = 63;
/// Length of a serial number in octets.
const SERIAL_LEN: usize = 16;

/// A freshly generated root: certificate and PKCS#8 private key.
pub(crate) struct RootKeyPair {
    /// The self-signed root certificate.
    pub cert_der: CertificateDer<'static>,
    /// The root key, PKCS#8 DER.
    pub key_pkcs8: SecretBytes,
}

/// Generates a self-signed ECDSA P-256 root.
///
/// The root is a CA with a path length of zero (key usage `keyCertSign`, `cRLSign` and
/// `digitalSignature`), valid from one hour before `now` for `validity_days` days after it.
pub(crate) fn generate_root(
    common_name: &str,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<RootKeyPair, CaError> {
    if common_name.is_empty() || common_name.len() > MAX_COMMON_NAME {
        return Err(CaError::InvalidName {
            name: common_name.to_owned(),
            reason: format!("a common name has 1 to {MAX_COMMON_NAME} octets"),
        });
    }
    let key = generate_key()?;
    let (not_before, not_after) = validity(now, validity_days)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name(common_name, Some(ORGANISATION));
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.serial_number = Some(random_serial()?);
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.self_signed(&*key)?;
    Ok(RootKeyPair {
        cert_der: cert.der().clone(),
        key_pkcs8: pkcs8_of(&key),
    })
}

/// The root key pair as an `rcgen` signing key whose buffers are zeroized on drop.
struct CaKey(Zeroizing<KeyPair>);

impl PublicKeyData for CaKey {
    fn der_bytes(&self) -> &[u8] {
        self.0.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl SigningKey for CaKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.0.sign(msg)
    }
}

/// Signs certificates with the root key.
pub(crate) struct Signer {
    issuer: Issuer<'static, CaKey>,
}

impl Signer {
    /// Loads the root and its key; fails when the key does not belong to the root.
    ///
    /// The issuer name and key identifier are taken from the root certificate itself, so
    /// issued certificates chain to the stored root byte for byte.
    pub(crate) fn new(
        root_der: &CertificateDer<'_>,
        key_pkcs8: &SecretBytes,
    ) -> Result<Self, CaError> {
        let corrupt = |reason: &str| CaError::Corrupt {
            reason: reason.to_owned(),
        };
        let key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(key_pkcs8.expose()))
            .map_err(|_| corrupt("the CA key is not a valid PKCS#8 private key"))?;
        let key = Zeroizing::new(key);
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(corrupt("the CA key is not an ECDSA P-256 key"));
        }
        let (rest, root) = parse_x509_certificate(root_der)
            .map_err(|_| corrupt("the root certificate cannot be parsed"))?;
        if !rest.is_empty() {
            return Err(corrupt("trailing data after the root certificate"));
        }
        if root.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err(corrupt("the CA key does not match the root certificate"));
        }
        if !root.is_ca() {
            return Err(corrupt("the root certificate is not a CA certificate"));
        }
        match root.key_usage() {
            Ok(Some(usage)) if !usage.value.key_cert_sign() => {
                return Err(corrupt("the root certificate may not sign certificates"));
            }
            Ok(_) => {}
            Err(_) => return Err(corrupt("the root key usage cannot be parsed")),
        }
        let issuer = Issuer::from_ca_cert_der(root_der, CaKey(key))?;
        Ok(Self { issuer })
    }
}

/// Issues a server certificate with a fresh P-256 key.
///
/// The common name is the host name; the subject alternative name lists the host name, every
/// alternative name and every address. Names are checked first.
pub(crate) fn issue_server(
    signer: &Signer,
    identity: &ServerIdentity,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<(CertificateDer<'static>, SecretBytes), CaError> {
    let names = server_names(identity)?;
    let mut params = leaf_params(now, validity_days)?;
    let common_name = if identity.host_name.len() <= MAX_COMMON_NAME {
        identity.host_name.as_str()
    } else {
        LONG_NAME_COMMON_NAME
    };
    params.distinguished_name = distinguished_name(common_name, None);
    params.subject_alt_names = names;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = generate_key()?;
    let cert = sign_leaf(signer, &params, &*key)?;
    Ok((cert, pkcs8_of(&key)))
}

/// Issues a node certificate for the public key of a CSR.
///
/// The request must be a well-formed PKCS#10 request whose self-signature verifies, over an
/// ECDSA P-256 key (proof that the requester holds the private key). Only that public key is
/// used: names, extensions and attributes in the request are ignored, so a request cannot
/// ask for a CA certificate or another identity.
pub(crate) fn issue_node_from_csr(
    signer: &Signer,
    node: NodeId,
    csr_der: &[u8],
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<CertificateDer<'static>, CaError> {
    let public_key = csr_public_key(csr_der)?;
    let params = node_params(node, now, validity_days)?;
    sign_leaf(signer, &params, &public_key)
}

/// Issues a node certificate with a fresh P-256 key.
pub(crate) fn issue_node(
    signer: &Signer,
    node: NodeId,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<(CertificateDer<'static>, SecretBytes), CaError> {
    let params = node_params(node, now, validity_days)?;
    let key = generate_key()?;
    let cert = sign_leaf(signer, &params, &*key)?;
    Ok((cert, pkcs8_of(&key)))
}

/// Issues a node certificate for the public key of a CSR, with the node's roles as
/// `urn:tenko:role:<role>` URIs next to `urn:tenko:node:<id>` (enrolment, WP2.2). The
/// request is checked as in [`issue_node_from_csr`].
pub(crate) fn issue_node_with_roles_from_csr(
    signer: &Signer,
    node: NodeId,
    roles: RoleSet,
    csr_der: &[u8],
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<CertificateDer<'static>, CaError> {
    let public_key = csr_public_key(csr_der)?;
    let params = node_role_params(node, roles, now, validity_days)?;
    sign_leaf(signer, &params, &public_key)
}

/// Issues a node certificate with roles and a fresh P-256 key (the controller's own
/// certificate on the cluster port).
pub(crate) fn issue_node_with_roles(
    signer: &Signer,
    node: NodeId,
    roles: RoleSet,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<(CertificateDer<'static>, SecretBytes), CaError> {
    let params = node_role_params(node, roles, now, validity_days)?;
    let key = generate_key()?;
    let cert = sign_leaf(signer, &params, &*key)?;
    Ok((cert, pkcs8_of(&key)))
}

/// A fresh ECDSA P-256 key and a PKCS#10 request over it, DER, for enrolment and renewal
/// on the node. The request names nothing: the CA takes only the key.
///
/// # Errors
///
/// [`CaError::Generation`] when the key or the request cannot be made.
pub fn generate_csr() -> Result<(SecretBytes, Vec<u8>), CaError> {
    let key = generate_key()?;
    let csr = CertificateParams::default().serialize_request(&*key)?;
    Ok((pkcs8_of(&key), csr.der().to_vec()))
}

/// The URI subject alternative name of a role in a node certificate:
/// `urn:tenko:role:<role>`.
pub fn role_uri(role: Role) -> String {
    format!("urn:tenko:role:{role}")
}

/// The roles in a node certificate's URI subject alternative names; empty for a
/// certificate without roles or one that cannot be parsed.
pub fn roles_of(cert_der: &[u8]) -> RoleSet {
    let Ok(info) = super::CertInfo::from_der(cert_der) else {
        return RoleSet::EMPTY;
    };
    roles_in(&info.uris)
}

/// The roles among certificate URIs.
pub fn roles_in(uris: &[String]) -> RoleSet {
    uris.iter()
        .filter_map(|uri| uri.strip_prefix("urn:tenko:role:")?.parse::<Role>().ok())
        .collect()
}

/// The URI subject alternative name of a node certificate: `urn:tenko:node:<id>`.
pub fn node_uri(node: NodeId) -> String {
    format!("urn:tenko:node:{node}")
}

/// The node identifier in a node certificate's URI subject alternative name.
pub fn node_id_of(cert_der: &[u8]) -> Option<NodeId> {
    let info = super::CertInfo::from_der(cert_der).ok()?;
    info.uris.iter().find_map(|uri| {
        uri.strip_prefix("urn:tenko:node:")?
            .parse()
            .ok()
            .map(NodeId)
    })
}

/// A fresh ECDSA P-256 key pair whose serialized private key is zeroized on drop.
fn generate_key() -> Result<Zeroizing<KeyPair>, CaError> {
    Ok(Zeroizing::new(KeyPair::generate_for(
        &PKCS_ECDSA_P256_SHA256,
    )?))
}

/// The PKCS#8 encoding of a key as a secret.
fn pkcs8_of(key: &KeyPair) -> SecretBytes {
    SecretBytes::from_slice(key.serialized_der())
}

/// A random positive serial number of exactly [`SERIAL_LEN`] octets (126 random bits).
fn random_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; SERIAL_LEN];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| CaError::Generation {
        reason: "random number generator failed".to_owned(),
    })?;
    // Clear the sign bit and set the next one: positive, and no leading zero octet.
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

/// `not_before` (one hour before `now`) and `not_after` (`validity_days` after it).
fn validity(
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<(OffsetDateTime, OffsetDateTime), CaError> {
    let now = now.to_offset(UtcOffset::UTC);
    let out_of_range = || CaError::Generation {
        reason: "the certificate validity is outside the supported date range".to_owned(),
    };
    let not_before = now.checked_sub(CLOCK_SKEW).ok_or_else(out_of_range)?;
    let not_after = now
        .checked_add(Duration::days(i64::from(validity_days)))
        .ok_or_else(out_of_range)?;
    Ok((not_before, not_after))
}

fn distinguished_name(common_name: &str, organisation: Option<&str>) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    if let Some(organisation) = organisation {
        name.push(DnType::OrganizationName, organisation);
    }
    name.push(DnType::CommonName, common_name);
    name
}

/// The parameters every leaf certificate shares: not a CA, `digitalSignature`, authority key
/// identifier, random serial and the validity window.
fn leaf_params(now: OffsetDateTime, validity_days: u32) -> Result<CertificateParams, CaError> {
    let (not_before, not_after) = validity(now, validity_days)?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(random_serial()?);
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn node_params(
    node: NodeId,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<CertificateParams, CaError> {
    let mut params = leaf_params(now, validity_days)?;
    params.distinguished_name = distinguished_name(&format!("tenko node {node}"), None);
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(node_uri(node))?)];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    Ok(params)
}

/// [`node_params`] with one `urn:tenko:role:<role>` URI per role.
fn node_role_params(
    node: NodeId,
    roles: RoleSet,
    now: OffsetDateTime,
    validity_days: u32,
) -> Result<CertificateParams, CaError> {
    let mut params = node_params(node, now, validity_days)?;
    for role in roles.roles() {
        params
            .subject_alt_names
            .push(SanType::URI(Ia5String::try_from(role_uri(role))?));
    }
    Ok(params)
}

fn sign_leaf(
    signer: &Signer,
    params: &CertificateParams,
    subject: &impl PublicKeyData,
) -> Result<CertificateDer<'static>, CaError> {
    Ok(params.signed_by(subject, &signer.issuer)?.der().clone())
}

/// The public key of a CSR whose self-signature verifies.
///
/// `rcgen` offers `CertificateSigningRequestParams::from_der`, which verifies the signature
/// too but also rejects requests carrying extensions it does not know. A node certificate
/// takes nothing from the request but the key, so the request is read with `x509-parser`
/// directly and its extensions are left alone.
pub(crate) fn csr_public_key(csr_der: &[u8]) -> Result<SubjectPublicKeyInfo, CaError> {
    let invalid = |reason: String| CaError::InvalidCsr { reason };
    let (rest, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("it cannot be parsed: {e}")))?;
    if !rest.is_empty() {
        return Err(invalid("trailing data after the request".to_owned()));
    }
    csr.verify_signature()
        .map_err(|e| invalid(format!("the signature does not verify: {e}")))?;
    let key = SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
        .map_err(|e| invalid(format!("unsupported public key: {e}")))?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(invalid(
            "the public key is not an ECDSA P-256 key".to_owned(),
        ));
    }
    Ok(key)
}

/// Validates the names of a server identity and returns them as subject alternative names:
/// the host name, the alternative names and the addresses, without duplicates.
fn server_names(identity: &ServerIdentity) -> Result<Vec<SanType>, CaError> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for name in std::iter::once(&identity.host_name).chain(&identity.alt_names) {
        validate_dns_name(name)?;
        if seen.insert(name.to_ascii_lowercase()) {
            names.push(SanType::DnsName(Ia5String::try_from(name.as_str())?));
        }
    }
    let mut addresses = HashSet::new();
    for address in &identity.addresses {
        validate_address(*address)?;
        if addresses.insert(*address) {
            names.push(SanType::IpAddress(*address));
        }
    }
    Ok(names)
}

fn validate_address(address: IpAddr) -> Result<(), CaError> {
    let reason = if address.is_unspecified() {
        "the unspecified address cannot identify a host"
    } else if address.is_multicast() {
        "a multicast address cannot identify a host"
    } else {
        return Ok(());
    };
    Err(CaError::InvalidName {
        name: address.to_string(),
        reason: reason.to_owned(),
    })
}

/// Checks a DNS name for a certificate: 1 to 253 octets in labels of 1 to 63 letters, digits
/// and hyphens that neither start nor end with a hyphen. A single label such as `localhost`
/// is a name. Wildcards, IP literals and a trailing dot are refused, and so is a numeric top
/// label (RFC 3696, section 2), which would be mistaken for an address.
fn validate_dns_name(name: &str) -> Result<(), CaError> {
    let invalid = |reason: &str| CaError::InvalidName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    if name.is_empty() {
        return Err(invalid("the name is empty"));
    }
    if name.len() > MAX_DNS_NAME {
        return Err(invalid("the name is longer than 253 octets"));
    }
    if name.parse::<IpAddr>().is_ok() {
        return Err(invalid("an IP address is not a DNS name"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(invalid("the name has an empty label"));
        }
        if label.len() > MAX_DNS_LABEL {
            return Err(invalid("a label is longer than 63 octets"));
        }
        if label.contains('*') {
            return Err(invalid("wildcard names are not issued"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid(
                "labels contain only ASCII letters, digits and hyphens",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("a label starts or ends with a hyphen"));
        }
    }
    let top = name.rsplit('.').next().unwrap_or(name);
    if top.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("the last label is numeric"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rcgen::{CustomExtension, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};
    use tenko_core::Timestamp;
    use x509_parser::{
        certificate::X509Certificate,
        extensions::ParsedExtension,
        oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    };

    use super::*;
    use crate::ca::{CertInfo, ExpiryState};

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_790_000_000).expect("timestamp")
    }

    fn fixture() -> (RootKeyPair, Signer) {
        let root = generate_root("Tenko DDI test CA", now(), 3650).expect("root");
        let signer = Signer::new(&root.cert_der, &root.key_pkcs8).expect("signer");
        (root, signer)
    }

    fn identity() -> ServerIdentity {
        ServerIdentity::new("tenko.example.net")
            .with_name("ddi")
            .with_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
            .with_address(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    }

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        let (rest, cert) = parse_x509_certificate(der).expect("certificate");
        assert_eq!(rest.len(), 0, "trailing data after the certificate");
        cert
    }

    fn error<T>(result: Result<T, CaError>) -> CaError {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    fn public_key_of(pkcs8: &SecretBytes) -> Vec<u8> {
        let key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8.expose())).expect("key");
        key.public_key_raw().to_vec()
    }

    fn subject_key_id(cert: &X509Certificate<'_>) -> Vec<u8> {
        cert.iter_extensions()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
            .expect("subject key identifier")
    }

    fn authority_key_id(cert: &X509Certificate<'_>) -> Vec<u8> {
        cert.iter_extensions()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            })
            .expect("authority key identifier")
    }

    fn csr_for(key: &KeyPair, tweak: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
        let mut params = CertificateParams::default();
        tweak(&mut params);
        params.serialize_request(key).expect("csr").der().to_vec()
    }

    fn error_reason(error: &CaError) -> &str {
        match error {
            CaError::InvalidCsr { reason }
            | CaError::Corrupt { reason }
            | CaError::Generation { reason } => reason,
            other => panic!("unexpected error {other}"),
        }
    }

    #[test]
    fn signer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Signer>();
    }

    #[test]
    fn root_is_a_p256_ca_with_path_length_zero() {
        let (root, _) = fixture();
        let cert = parse(&root.cert_der);
        let constraints = cert.basic_constraints().expect("valid").expect("present");
        assert!(constraints.critical);
        assert!(constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, Some(0));
        let usage = cert.key_usage().expect("valid").expect("present").value;
        assert!(usage.key_cert_sign() && usage.crl_sign() && usage.digital_signature());
        assert!(!usage.key_encipherment() && !usage.key_agreement());
        let key = cert.public_key();
        assert_eq!(key.algorithm.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
        let curve = key.algorithm.parameters.as_ref().expect("curve");
        assert_eq!(curve.as_oid().expect("curve oid"), OID_EC_P256);
        assert_eq!(
            key.subject_public_key.data.as_ref(),
            public_key_of(&root.key_pkcs8)
        );
        cert.verify_signature(None).expect("self-signed");
        assert_eq!(cert.subject(), cert.issuer());
        let common_name = cert.subject().iter_common_name().next().expect("CN");
        assert_eq!(common_name.as_str().expect("text"), "Tenko DDI test CA");
        let organisation = cert.subject().iter_organization().next().expect("O");
        assert_eq!(organisation.as_str().expect("text"), "Tenko DDI");
    }

    #[test]
    fn root_validity_starts_an_hour_early() {
        let (root, _) = fixture();
        let info = CertInfo::from_der(&root.cert_der).expect("info");
        assert!(info.is_ca);
        assert_eq!(info.not_before.0, now() - Duration::hours(1));
        assert_eq!(info.not_after.0, now() + Duration::days(3650));
        assert_eq!(info.expiry(Timestamp(now())).state, ExpiryState::Valid);
    }

    #[test]
    fn serial_numbers_are_random_positive_and_sixteen_octets() {
        let (first, signer) = fixture();
        let (second, _) = fixture();
        let a = CertInfo::from_der(&first.cert_der).expect("info").serial;
        let b = CertInfo::from_der(&second.cert_der).expect("info").serial;
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        let (one, _) = issue_node(&signer, NodeId(1), now(), 365).expect("node");
        let (two, _) = issue_node(&signer, NodeId(1), now(), 365).expect("node");
        assert_ne!(
            CertInfo::from_der(&one).expect("info").serial,
            CertInfo::from_der(&two).expect("info").serial
        );
        for der in [first.cert_der.as_ref(), one.as_ref(), two.as_ref()] {
            let cert = parse(der);
            let serial = cert.raw_serial();
            assert_eq!(serial.len(), SERIAL_LEN);
            assert!(serial[0] & 0x80 == 0 && serial[0] != 0);
        }
    }

    #[test]
    fn root_keys_differ_between_roots() {
        let (first, _) = fixture();
        let (second, _) = fixture();
        assert_ne!(first.key_pkcs8, second.key_pkcs8);
        assert_ne!(
            public_key_of(&first.key_pkcs8),
            public_key_of(&second.key_pkcs8)
        );
    }

    #[test]
    fn root_refuses_an_unusable_common_name() {
        assert!(matches!(
            error(generate_root("", now(), 1)),
            CaError::InvalidName { .. }
        ));
        assert!(matches!(
            error(generate_root(&"x".repeat(65), now(), 1)),
            CaError::InvalidName { .. }
        ));
    }

    #[test]
    fn server_certificate_carries_the_names_and_the_validity() {
        let (root, signer) = fixture();
        let (der, key) = issue_server(&signer, &identity(), now(), 397).expect("server");
        let info = CertInfo::from_der(&der).expect("info");
        assert_eq!(info.dns_names, ["tenko.example.net", "ddi"]);
        assert_eq!(
            info.ip_addresses,
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ]
        );
        assert_eq!(info.uris.len(), 0);
        assert!(!info.is_ca);
        assert_eq!(info.subject, "CN=tenko.example.net");
        assert_eq!(
            info.issuer,
            CertInfo::from_der(&root.cert_der).expect("root").subject
        );
        assert_eq!(info.not_before.0, now() - Duration::hours(1));
        assert_eq!(info.not_after.0, now() + Duration::days(397));
        let expiry = info.expiry(Timestamp(now()));
        assert_eq!(expiry.days_left, 397);
        assert_eq!(expiry.state, ExpiryState::Valid);

        let cert = parse(&der);
        let constraints = cert.basic_constraints().expect("valid").expect("present");
        assert!(!constraints.value.ca);
        let usage = cert.key_usage().expect("valid").expect("present").value;
        assert!(usage.digital_signature() && !usage.key_cert_sign());
        let eku = cert
            .extended_key_usage()
            .expect("valid")
            .expect("present")
            .value;
        assert!(eku.server_auth && !eku.client_auth);
        assert_eq!(
            public_key_of(&key),
            cert.public_key().subject_public_key.data.as_ref()
        );

        let root_cert = parse(&root.cert_der);
        cert.verify_signature(Some(root_cert.public_key()))
            .expect("signed by the root");
        assert_eq!(cert.issuer().as_raw(), root_cert.subject().as_raw());
        assert_eq!(authority_key_id(&cert), subject_key_id(&root_cert));
    }

    #[test]
    fn server_keys_are_fresh_per_certificate() {
        let (_, signer) = fixture();
        let (_, first) = issue_server(&signer, &identity(), now(), 397).expect("first");
        let (_, second) = issue_server(&signer, &identity(), now(), 397).expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn single_label_and_mixed_case_names_are_accepted() {
        let (_, signer) = fixture();
        let long_label = "a".repeat(63);
        let long_name = format!("{long_label}.{long_label}.{long_label}.{}", "b".repeat(61));
        assert_eq!(long_name.len(), 253);
        for name in [
            "localhost",
            "Tenko-1.Example.NET",
            "a",
            "xn--mnchen-3ya.de",
            "host.lan",
            "3com.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            let identity = ServerIdentity::new(name);
            let (der, _) = issue_server(&signer, &identity, now(), 30)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let info = CertInfo::from_der(&der).expect("info");
            assert_eq!(info.dns_names, [name]);
        }
    }

    #[test]
    fn invalid_names_are_rejected() {
        let (_, signer) = fixture();
        let too_long_label = "a".repeat(64);
        let too_long_name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(62));
        assert_eq!(too_long_name.len(), 254);
        let invalid = [
            "",
            ".",
            "example..com",
            "example.com.",
            ".example.com",
            "-example.com",
            "example-.com",
            "exa-.mple.com",
            "exa mple.com",
            "exa_mple.com",
            "*.example.com",
            "*",
            "m\u{fc}nchen.de",
            "example.com/path",
            "user@example.com",
            "10.0.0.1",
            "192.0.2.1",
            "2001:db8::1",
            "[2001:db8::1]",
            "::1",
            "1.2.3",
            "1234",
            "host.123",
            too_long_label.as_str(),
            too_long_name.as_str(),
        ];
        for name in invalid {
            let as_host = issue_server(&signer, &ServerIdentity::new(name), now(), 30);
            assert!(
                matches!(error(as_host), CaError::InvalidName { name: ref n, .. } if n == name),
                "host name {name:?}"
            );
            let as_alt = issue_server(
                &signer,
                &ServerIdentity::new("ok.example.net").with_name(name),
                now(),
                30,
            );
            assert!(
                matches!(error(as_alt), CaError::InvalidName { name: ref n, .. } if n == name),
                "alternative name {name:?}"
            );
        }
    }

    #[test]
    fn unspecified_and_multicast_addresses_are_rejected() {
        let (_, signer) = fixture();
        for address in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            let identity = ServerIdentity::new("tenko.example.net").with_address(address);
            assert!(
                matches!(
                    error(issue_server(&signer, &identity, now(), 30)),
                    CaError::InvalidName { .. }
                ),
                "{address}"
            );
        }
        let loopback = ServerIdentity::new("localhost")
            .with_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_address(IpAddr::V6(Ipv6Addr::LOCALHOST));
        issue_server(&signer, &loopback, now(), 30).expect("loopback addresses");
    }

    #[test]
    fn duplicate_names_appear_once() {
        let (_, signer) = fixture();
        let identity = ServerIdentity::new("tenko.example.net")
            .with_name("TENKO.example.net")
            .with_name("ddi")
            .with_name("ddi")
            .with_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let (der, _) = issue_server(&signer, &identity, now(), 30).expect("server");
        let info = CertInfo::from_der(&der).expect("info");
        assert_eq!(info.dns_names, ["tenko.example.net", "ddi"]);
        assert_eq!(info.ip_addresses, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn long_host_names_get_a_generic_common_name() {
        let (_, signer) = fixture();
        let host = format!("{}.{}.example.net", "a".repeat(40), "b".repeat(40));
        assert!(host.len() > MAX_COMMON_NAME);
        let (der, _) =
            issue_server(&signer, &ServerIdentity::new(host.as_str()), now(), 30).expect("server");
        let info = CertInfo::from_der(&der).expect("info");
        assert_eq!(info.subject, "CN=Tenko DDI server");
        assert_eq!(info.dns_names, [host]);
    }

    #[test]
    fn a_validity_beyond_the_date_range_fails() {
        let (_, signer) = fixture();
        let identity = ServerIdentity::new("tenko.example.net");
        for days in [u32::MAX, 3_000_000] {
            assert!(
                matches!(
                    error(issue_server(&signer, &identity, now(), days)),
                    CaError::Generation { .. }
                ),
                "{days} days"
            );
        }
        assert!(matches!(
            error(generate_root("Tenko DDI test CA", now(), u32::MAX)),
            CaError::Generation { .. }
        ));
    }

    #[test]
    fn issuance_does_not_depend_on_the_offset_of_now() {
        let (_, signer) = fixture();
        let shifted = now().to_offset(UtcOffset::from_hms(5, 30, 0).expect("offset"));
        let (der, _) =
            issue_server(&signer, &ServerIdentity::new("localhost"), shifted, 10).expect("server");
        let info = CertInfo::from_der(&der).expect("info");
        assert_eq!(info.not_before.0, now() - Duration::hours(1));
        assert_eq!(info.not_after.0, now() + Duration::days(10));
    }

    #[test]
    fn node_uri_round_trips_with_node_id_of() {
        let (root, signer) = fixture();
        for node in [NodeId(0), NodeId(7), NodeId(u64::MAX)] {
            let (der, key) = issue_node(&signer, node, now(), 365).expect("node");
            assert_eq!(node_id_of(&der), Some(node));
            let info = CertInfo::from_der(&der).expect("info");
            assert_eq!(info.uris, [node_uri(node)]);
            assert_eq!(info.uris, [format!("urn:tenko:node:{}", node.0)]);
            assert!(info.dns_names.is_empty() && info.ip_addresses.is_empty());
            assert!(!info.is_ca);
            assert_eq!(info.subject, format!("CN=tenko node {}", node.0));
            assert_eq!(info.not_after.0, now() + Duration::days(365));

            let cert = parse(&der);
            let eku = cert
                .extended_key_usage()
                .expect("valid")
                .expect("present")
                .value;
            assert!(eku.server_auth && eku.client_auth);
            let usage = cert.key_usage().expect("valid").expect("present").value;
            assert!(usage.digital_signature() && !usage.key_cert_sign());
            assert_eq!(
                public_key_of(&key),
                cert.public_key().subject_public_key.data.as_ref()
            );
            let root_cert = parse(&root.cert_der);
            cert.verify_signature(Some(root_cert.public_key()))
                .expect("signed by the root");
            assert_eq!(authority_key_id(&cert), subject_key_id(&root_cert));
        }
    }

    #[test]
    fn node_id_of_ignores_other_certificates() {
        let (root, signer) = fixture();
        let (server, _) = issue_server(&signer, &identity(), now(), 30).expect("server");
        assert_eq!(node_id_of(&server), None);
        assert_eq!(node_id_of(&root.cert_der), None);
        assert_eq!(node_id_of(b"not a certificate"), None);
    }

    #[test]
    fn csr_path_keeps_the_public_key_of_the_request() {
        let (root, signer) = fixture();
        let key = KeyPair::generate().expect("key");
        let csr = csr_for(&key, |params| {
            params.distinguished_name = distinguished_name("evil", Some("Evil Inc"));
            params.subject_alt_names = vec![
                SanType::DnsName(Ia5String::try_from("evil.example").expect("name")),
                SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 66))),
            ];
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                vec![0x05, 0x00],
            )];
        });
        let der = issue_node_from_csr(&signer, NodeId(9), &csr, now(), 365).expect("node");
        let cert = parse(&der);
        assert_eq!(
            cert.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
        let info = CertInfo::from_der(&der).expect("info");
        assert_eq!(info.uris, ["urn:tenko:node:9"]);
        assert_eq!(node_id_of(&der), Some(NodeId(9)));
        assert!(info.dns_names.is_empty() && info.ip_addresses.is_empty());
        assert!(!info.is_ca);
        assert_eq!(info.subject, "CN=tenko node 9");
        let usage = cert.key_usage().expect("valid").expect("present").value;
        assert!(usage.digital_signature() && !usage.key_cert_sign() && !usage.crl_sign());
        let eku = cert
            .extended_key_usage()
            .expect("valid")
            .expect("present")
            .value;
        assert!(eku.server_auth && eku.client_auth && !eku.code_signing);
        assert!(
            cert.iter_extensions()
                .all(|ext| ext.oid.to_id_string() != "1.3.6.1.4.1.99999.1")
        );
        let root_cert = parse(&root.cert_der);
        cert.verify_signature(Some(root_cert.public_key()))
            .expect("signed by the root");
    }

    #[test]
    fn csr_without_extensions_is_accepted() {
        let (_, signer) = fixture();
        let key = KeyPair::generate().expect("key");
        let csr = csr_for(&key, |_| {});
        let der = issue_node_from_csr(&signer, NodeId(3), &csr, now(), 30).expect("node");
        assert_eq!(node_id_of(&der), Some(NodeId(3)));
    }

    #[test]
    fn tampered_requests_are_rejected() {
        let (_, signer) = fixture();
        let key = KeyPair::generate().expect("key");
        let csr = csr_for(&key, |params| {
            params.distinguished_name = distinguished_name("evil", None);
        });
        let issue = |bytes: &[u8]| issue_node_from_csr(&signer, NodeId(1), bytes, now(), 30);
        issue(&csr).expect("the untouched request is accepted");

        // The signature is the last element.
        let mut bad_signature = csr.clone();
        *bad_signature.last_mut().expect("byte") ^= 0x01;
        let rejected = error(issue(&bad_signature));
        assert!(matches!(rejected, CaError::InvalidCsr { .. }));
        assert!(error_reason(&rejected).contains("signature"), "{rejected}");

        // A signed field changed: the subject.
        let at = csr.windows(4).position(|w| w == b"evil").expect("subject");
        let mut bad_subject = csr.clone();
        bad_subject[at + 3] = b'o';
        let rejected = error(issue(&bad_subject));
        assert!(matches!(rejected, CaError::InvalidCsr { .. }));
        assert!(error_reason(&rejected).contains("signature"), "{rejected}");

        // A signed field changed: the public key.
        let point = key.public_key_raw();
        let at = csr
            .windows(point.len())
            .position(|w| w == point)
            .expect("public key");
        let mut bad_key = csr.clone();
        bad_key[at + 40] ^= 0x01;
        assert!(matches!(error(issue(&bad_key)), CaError::InvalidCsr { .. }));

        // Not a request at all, truncated, or followed by more data.
        let mut trailing = csr.clone();
        trailing.push(0);
        assert!(matches!(
            error(issue(&trailing)),
            CaError::InvalidCsr { .. }
        ));
        assert!(matches!(
            error(issue(&csr[..csr.len() - 5])),
            CaError::InvalidCsr { .. }
        ));
        for junk in [
            &b""[..],
            b"\x30\x00",
            b"-----BEGIN CERTIFICATE REQUEST-----",
        ] {
            assert!(matches!(error(issue(junk)), CaError::InvalidCsr { .. }));
        }
    }

    #[test]
    fn a_certificate_is_not_a_request() {
        let (root, signer) = fixture();
        let result = issue_node_from_csr(&signer, NodeId(1), &root.cert_der, now(), 30);
        assert!(matches!(error(result), CaError::InvalidCsr { .. }));
    }

    #[test]
    fn requests_over_other_key_types_are_rejected() {
        let (_, signer) = fixture();
        for alg in [&PKCS_ED25519, &PKCS_ECDSA_P384_SHA384] {
            let key = KeyPair::generate_for(alg).expect("key");
            let csr = csr_for(&key, |_| {});
            let rejected = error(issue_node_from_csr(&signer, NodeId(1), &csr, now(), 30));
            assert!(matches!(rejected, CaError::InvalidCsr { .. }), "{rejected}");
            assert!(error_reason(&rejected).contains("P-256"), "{rejected}");
        }
    }

    #[test]
    fn signer_rejects_a_key_of_another_root() {
        let (first, _) = fixture();
        let (second, _) = fixture();
        let rejected = error(Signer::new(&first.cert_der, &second.key_pkcs8));
        assert!(matches!(rejected, CaError::Corrupt { .. }), "{rejected}");
        assert!(
            error_reason(&rejected).contains("does not match"),
            "{rejected}"
        );
        Signer::new(&first.cert_der, &first.key_pkcs8).expect("its own key");
    }

    #[test]
    fn signer_rejects_unusable_inputs() {
        let (root, signer) = fixture();
        let junk = SecretBytes::from_slice(b"not a key");
        assert!(matches!(
            error(Signer::new(&root.cert_der, &junk)),
            CaError::Corrupt { .. }
        ));
        let garbage = CertificateDer::from(b"not a certificate".to_vec());
        assert!(matches!(
            error(Signer::new(&garbage, &root.key_pkcs8)),
            CaError::Corrupt { .. }
        ));
        let mut trailing = root.cert_der.to_vec();
        trailing.push(0);
        assert!(matches!(
            error(Signer::new(
                &CertificateDer::from(trailing),
                &root.key_pkcs8
            )),
            CaError::Corrupt { .. }
        ));

        // A matching key over a certificate that is not a CA.
        let (leaf, key) = issue_server(&signer, &identity(), now(), 30).expect("leaf");
        let rejected = error(Signer::new(&leaf, &key));
        assert!(error_reason(&rejected).contains("not a CA"), "{rejected}");

        // A key of another type.
        let ed25519 = KeyPair::generate_for(&PKCS_ED25519).expect("key");
        let ed25519 = SecretBytes::from_slice(ed25519.serialized_der());
        let rejected = error(Signer::new(&root.cert_der, &ed25519));
        assert!(error_reason(&rejected).contains("P-256"), "{rejected}");
    }

    #[test]
    fn a_reloaded_signer_issues_the_same_chain() {
        let (root, first) = fixture();
        let reloaded = Signer::new(&root.cert_der, &root.key_pkcs8).expect("reloaded");
        let root_cert = parse(&root.cert_der);
        for signer in [&first, &reloaded] {
            let (der, _) = issue_server(signer, &identity(), now(), 30).expect("server");
            let cert = parse(&der);
            cert.verify_signature(Some(root_cert.public_key()))
                .expect("signed by the root");
            assert_eq!(cert.issuer().as_raw(), root_cert.subject().as_raw());
            assert_eq!(authority_key_id(&cert), subject_key_id(&root_cert));
        }
    }
}
