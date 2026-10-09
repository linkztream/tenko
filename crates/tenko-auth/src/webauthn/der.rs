//! A minimal DER reader for the X.509 attestation certificates of `packed` attestation
//! (WebAuthn Level 3, section 8.2.1).
//!
//! It reads exactly what the verifier needs: the signed part, the version, issuer and
//! subject (raw, plus the subject attributes C, O, OU and CN), the validity period, the
//! subject public key, the extensions and the signature. Anything outside definite-length
//! DER with single-byte tags is refused.

use aws_lc_rs::signature::{self, UnparsedPublicKey};

use super::WebAuthnError;

/// DER tags used here.
mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const VERSION: u8 = 0xa0;
    pub const EXTENSIONS: u8 = 0xa3;
}

/// Object identifiers (DER content bytes).
pub mod oid {
    /// id-ecPublicKey (1.2.840.10045.2.1).
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1 (1.2.840.10045.3.1.7).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1 (1.3.132.0.34).
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// rsaEncryption (1.2.840.113549.1.1.1).
    pub const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// id-Ed25519 (1.3.101.112).
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    /// ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384 (1.2.840.10045.4.3.3).
    pub const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    pub const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// basicConstraints (2.5.29.19).
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4).
    pub const FIDO_AAGUID: &[u8] = &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
    ];
    /// countryName (2.5.4.6).
    pub const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
    /// organizationName (2.5.4.10).
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    /// organizationalUnitName (2.5.4.11).
    pub const ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
    /// commonName (2.5.4.3).
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
}

const MALFORMED: WebAuthnError = WebAuthnError::AttestationInvalid("malformed certificate");

/// One DER element.
#[derive(Debug, Clone, Copy)]
struct Element<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

/// Reads DER elements one after the other.
#[derive(Debug, Clone, Copy)]
struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.first().copied()
    }

    fn read(&mut self) -> Result<Element<'a>, WebAuthnError> {
        let input = self.input;
        let (&tag, rest) = input.split_first().ok_or(MALFORMED)?;
        // High tag numbers (0x1f) are not used in certificates.
        if tag & 0x1f == 0x1f {
            return Err(MALFORMED);
        }
        let (&first, mut rest) = rest.split_first().ok_or(MALFORMED)?;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            // 0x80 is the indefinite form (BER only); more than four bytes is absurd here.
            if count == 0 || count > 4 || rest.len() < count {
                return Err(MALFORMED);
            }
            let (bytes, after) = rest.split_at(count);
            rest = after;
            if bytes[0] == 0 {
                return Err(MALFORMED);
            }
            let length = bytes
                .iter()
                .fold(0_usize, |acc, &byte| (acc << 8) | usize::from(byte));
            if length < 0x80 {
                return Err(MALFORMED);
            }
            length
        };
        if rest.len() < length {
            return Err(MALFORMED);
        }
        let header = input.len() - rest.len();
        let (content, after) = rest.split_at(length);
        self.input = after;
        Ok(Element {
            tag,
            content,
            raw: &input[..header + length],
        })
    }

    fn expect(&mut self, tag: u8) -> Result<Element<'a>, WebAuthnError> {
        let element = self.read()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(MALFORMED)
        }
    }

    fn finish(&self) -> Result<(), WebAuthnError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(MALFORMED)
        }
    }
}

/// A subject public key the verifier can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An uncompressed P-256 point.
    P256(Vec<u8>),
    /// An uncompressed P-384 point (trust chains only).
    P384(Vec<u8>),
    /// A PKCS #1 `RSAPublicKey`.
    Rsa(Vec<u8>),
    /// An Ed25519 key.
    Ed25519(Vec<u8>),
    /// Any other key type.
    Other,
}

/// The signature algorithm of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ecdsa-with-SHA256.
    EcdsaSha256,
    /// ecdsa-with-SHA384.
    EcdsaSha384,
    /// sha256WithRSAEncryption.
    RsaSha256,
    /// Ed25519.
    Ed25519,
    /// Any other algorithm.
    Other,
}

/// One certificate extension.
#[derive(Debug, Clone, Copy)]
pub struct Extension<'a> {
    /// The extension OID (content bytes).
    pub oid: &'a [u8],
    /// The critical flag.
    pub critical: bool,
    /// The content of `extnValue`.
    pub value: &'a [u8],
}

/// A parsed X.509 certificate, borrowing from its DER encoding.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    /// The whole certificate.
    pub raw: &'a [u8],
    /// The signed part (`tbsCertificate`, with its header).
    pub tbs: &'a [u8],
    /// The version number as encoded (2 for X.509 v3).
    pub version: u8,
    /// The issuer name, encoded.
    pub issuer: &'a [u8],
    /// The subject name, encoded.
    pub subject: &'a [u8],
    /// Subject attributes as (OID, value) pairs, in order.
    pub subject_attributes: Vec<(&'a [u8], String)>,
    /// Start of validity, seconds since the Unix epoch.
    pub not_before: i64,
    /// End of validity, seconds since the Unix epoch.
    pub not_after: i64,
    /// The subject public key.
    pub public_key: PublicKey,
    /// The extensions.
    pub extensions: Vec<Extension<'a>>,
    /// The signature algorithm of the issuer.
    pub signature_algorithm: SignatureAlgorithm,
    /// The signature bits.
    pub signature: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Parses a DER certificate.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::AttestationInvalid`] for anything that is not a well-formed
    /// certificate.
    pub fn parse(der: &'a [u8]) -> Result<Self, WebAuthnError> {
        let mut outer = Reader::new(der);
        let certificate = outer.expect(tag::SEQUENCE)?;
        outer.finish()?;
        let mut parts = Reader::new(certificate.content);
        let tbs = parts.expect(tag::SEQUENCE)?;
        let outer_algorithm = parts.expect(tag::SEQUENCE)?;
        let signature = parts.expect(tag::BIT_STRING)?;
        parts.finish()?;

        let mut fields = Reader::new(tbs.content);
        let version = if fields.peek_tag() == Some(tag::VERSION) {
            let explicit = fields.read()?;
            let mut inner = Reader::new(explicit.content);
            let number = inner.expect(tag::INTEGER)?;
            inner.finish()?;
            match number.content {
                [value] if *value <= 2 => *value,
                _ => return Err(MALFORMED),
            }
        } else {
            0
        };
        let _serial = fields.expect(tag::INTEGER)?;
        let inner_algorithm = fields.expect(tag::SEQUENCE)?;
        if inner_algorithm.raw != outer_algorithm.raw {
            return Err(MALFORMED);
        }
        let issuer = fields.expect(tag::SEQUENCE)?;
        let validity = fields.expect(tag::SEQUENCE)?;
        let subject = fields.expect(tag::SEQUENCE)?;
        let spki = fields.expect(tag::SEQUENCE)?;
        let mut extensions = Vec::new();
        while !fields.is_empty() {
            let element = fields.read()?;
            if element.tag == tag::EXTENSIONS {
                extensions = parse_extensions(element.content)?;
            }
        }

        let mut times = Reader::new(validity.content);
        let not_before = parse_time(times.read()?)?;
        let not_after = parse_time(times.read()?)?;
        times.finish()?;

        Ok(Self {
            raw: certificate.raw,
            tbs: tbs.raw,
            version,
            issuer: issuer.raw,
            subject: subject.raw,
            subject_attributes: parse_name(subject.content)?,
            not_before,
            not_after,
            public_key: parse_spki(spki.content)?,
            extensions,
            signature_algorithm: parse_signature_algorithm(outer_algorithm.content)?,
            signature: bit_string(signature.content)?,
        })
    }

    /// The value of the first subject attribute with the OID.
    pub fn subject_attribute(&self, oid: &[u8]) -> Option<&str> {
        self.subject_attributes
            .iter()
            .find(|(attribute, _)| *attribute == oid)
            .map(|(_, value)| value.as_str())
    }

    /// The extension with the OID.
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension<'a>> {
        self.extensions
            .iter()
            .find(|extension| extension.oid == oid)
    }

    /// The `cA` component of basic constraints; `None` without the extension.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::AttestationInvalid`] if the extension is malformed.
    pub fn is_ca(&self) -> Result<Option<bool>, WebAuthnError> {
        let Some(extension) = self.extension(oid::BASIC_CONSTRAINTS) else {
            return Ok(None);
        };
        let mut outer = Reader::new(extension.value);
        let constraints = outer.expect(tag::SEQUENCE)?;
        outer.finish()?;
        let mut inner = Reader::new(constraints.content);
        if inner.peek_tag() == Some(tag::BOOLEAN) {
            let flag = inner.read()?;
            return match flag.content {
                [0x00] => Ok(Some(false)),
                [0xff] => Ok(Some(true)),
                _ => Err(MALFORMED),
            };
        }
        Ok(Some(false))
    }

    /// The 16 bytes of the FIDO AAGUID extension, if present.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::AttestationInvalid`] if the extension is malformed or critical.
    pub fn aaguid(&self) -> Result<Option<[u8; 16]>, WebAuthnError> {
        let Some(extension) = self.extension(oid::FIDO_AAGUID) else {
            return Ok(None);
        };
        if extension.critical {
            return Err(WebAuthnError::AttestationInvalid(
                "critical AAGUID extension",
            ));
        }
        let mut reader = Reader::new(extension.value);
        let octets = reader.expect(tag::OCTET_STRING)?;
        reader.finish()?;
        octets.content.try_into().map(Some).map_err(|_| MALFORMED)
    }

    /// Whether `unix_seconds` lies inside the validity period.
    pub fn valid_at(&self, unix_seconds: i64) -> bool {
        self.not_before <= unix_seconds && unix_seconds <= self.not_after
    }

    /// Verifies this certificate's signature with the issuer's public key.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::AttestationInvalid`] if the algorithm is unsupported or the
    /// signature does not verify.
    pub fn verify_issued_by(&self, issuer: &PublicKey) -> Result<(), WebAuthnError> {
        let refused = WebAuthnError::AttestationInvalid("certificate signature");
        let algorithm: &'static dyn signature::VerificationAlgorithm =
            match (self.signature_algorithm, issuer) {
                (SignatureAlgorithm::EcdsaSha256, PublicKey::P256(_)) => {
                    &signature::ECDSA_P256_SHA256_ASN1
                }
                (SignatureAlgorithm::EcdsaSha384, PublicKey::P384(_)) => {
                    &signature::ECDSA_P384_SHA384_ASN1
                }
                (SignatureAlgorithm::RsaSha256, PublicKey::Rsa(_)) => {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                }
                (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(_)) => &signature::ED25519,
                _ => return Err(refused),
            };
        let key = match issuer {
            PublicKey::P256(bytes)
            | PublicKey::P384(bytes)
            | PublicKey::Rsa(bytes)
            | PublicKey::Ed25519(bytes) => bytes,
            PublicKey::Other => return Err(refused),
        };
        UnparsedPublicKey::new(algorithm, key)
            .verify(self.tbs, self.signature)
            .map_err(|_| refused)
    }
}

fn parse_extensions(content: &[u8]) -> Result<Vec<Extension<'_>>, WebAuthnError> {
    let mut outer = Reader::new(content);
    let list = outer.expect(tag::SEQUENCE)?;
    outer.finish()?;
    let mut reader = Reader::new(list.content);
    let mut extensions = Vec::new();
    while !reader.is_empty() {
        let extension = reader.expect(tag::SEQUENCE)?;
        let mut fields = Reader::new(extension.content);
        let oid = fields.expect(tag::OID)?.content;
        let critical = if fields.peek_tag() == Some(tag::BOOLEAN) {
            match fields.read()?.content {
                [0xff] => true,
                [0x00] => false,
                _ => return Err(MALFORMED),
            }
        } else {
            false
        };
        let value = fields.expect(tag::OCTET_STRING)?.content;
        fields.finish()?;
        if extensions
            .iter()
            .any(|known: &Extension<'_>| known.oid == oid)
        {
            return Err(MALFORMED);
        }
        extensions.push(Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(extensions)
}

fn parse_name(content: &[u8]) -> Result<Vec<(&[u8], String)>, WebAuthnError> {
    let mut sets = Reader::new(content);
    let mut attributes = Vec::new();
    while !sets.is_empty() {
        let set = sets.expect(tag::SET)?;
        let mut pairs = Reader::new(set.content);
        while !pairs.is_empty() {
            let pair = pairs.expect(tag::SEQUENCE)?;
            let mut fields = Reader::new(pair.content);
            let oid = fields.expect(tag::OID)?.content;
            let value = fields.read()?;
            fields.finish()?;
            // PrintableString, UTF8String, IA5String and similar string types.
            let text = String::from_utf8(value.content.to_vec()).map_err(|_| MALFORMED)?;
            attributes.push((oid, text));
        }
    }
    Ok(attributes)
}

fn parse_spki(content: &[u8]) -> Result<PublicKey, WebAuthnError> {
    let mut fields = Reader::new(content);
    let algorithm = fields.expect(tag::SEQUENCE)?;
    let key = bit_string(fields.expect(tag::BIT_STRING)?.content)?;
    fields.finish()?;
    let mut parts = Reader::new(algorithm.content);
    let oid = parts.expect(tag::OID)?.content;
    let parameter = if parts.is_empty() {
        None
    } else {
        Some(parts.read()?)
    };
    Ok(match oid {
        oid::EC_PUBLIC_KEY => match parameter {
            Some(curve) if curve.tag == tag::OID && curve.content == oid::P256 => {
                PublicKey::P256(key.to_vec())
            }
            Some(curve) if curve.tag == tag::OID && curve.content == oid::P384 => {
                PublicKey::P384(key.to_vec())
            }
            _ => PublicKey::Other,
        },
        oid::RSA => PublicKey::Rsa(key.to_vec()),
        oid::ED25519 => PublicKey::Ed25519(key.to_vec()),
        _ => PublicKey::Other,
    })
}

fn parse_signature_algorithm(content: &[u8]) -> Result<SignatureAlgorithm, WebAuthnError> {
    let mut parts = Reader::new(content);
    let oid = parts.expect(tag::OID)?.content;
    Ok(match oid {
        oid::ECDSA_SHA256 => SignatureAlgorithm::EcdsaSha256,
        oid::ECDSA_SHA384 => SignatureAlgorithm::EcdsaSha384,
        oid::RSA_SHA256 => SignatureAlgorithm::RsaSha256,
        oid::ED25519 => SignatureAlgorithm::Ed25519,
        _ => SignatureAlgorithm::Other,
    })
}

/// The bits of a BIT STRING without unused bits.
fn bit_string(content: &[u8]) -> Result<&[u8], WebAuthnError> {
    match content.split_first() {
        Some((0, bits)) => Ok(bits),
        _ => Err(MALFORMED),
    }
}

/// `UTCTime` or `GeneralizedTime` in the `Z` form, as seconds since the Unix epoch.
fn parse_time(element: Element<'_>) -> Result<i64, WebAuthnError> {
    let text = std::str::from_utf8(element.content).map_err(|_| MALFORMED)?;
    let digits = text.strip_suffix('Z').ok_or(MALFORMED)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MALFORMED);
    }
    let number = |range: std::ops::Range<usize>| -> Result<i32, WebAuthnError> {
        digits
            .get(range)
            .and_then(|part| part.parse().ok())
            .ok_or(MALFORMED)
    };
    let (year, rest) = match (element.tag, digits.len()) {
        (tag::UTC_TIME, 12) => {
            let short = number(0..2)?;
            (
                if short < 50 {
                    2000 + short
                } else {
                    1900 + short
                },
                2,
            )
        }
        (tag::GENERALIZED_TIME, 14) => (number(0..4)?, 4),
        _ => return Err(MALFORMED),
    };
    let month = u8::try_from(number(rest..rest + 2)?).map_err(|_| MALFORMED)?;
    let month = time::Month::try_from(month).map_err(|_| MALFORMED)?;
    let day = u8::try_from(number(rest + 2..rest + 4)?).map_err(|_| MALFORMED)?;
    let hour = u8::try_from(number(rest + 4..rest + 6)?).map_err(|_| MALFORMED)?;
    let minute = u8::try_from(number(rest + 6..rest + 8)?).map_err(|_| MALFORMED)?;
    let second = u8::try_from(number(rest + 8..rest + 10)?).map_err(|_| MALFORMED)?;
    let date = time::Date::from_calendar_date(year, month, day).map_err(|_| MALFORMED)?;
    let time = time::Time::from_hms(hour, minute, second).map_err(|_| MALFORMED)?;
    Ok(time::PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_decode;

    /// The attestation root certificate of the WebAuthn Level 3 test vectors (section 16.1).
    const W3C_ROOT: &str = "30820207308201ada003020102021100ed7f905d8bd0b414d1784913170a90b6300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a3062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d030107034200043269300e5ff7b699015f70cf80a8763bf705bc2e2af0c1b39cff718b7c35880ca30f319078d91b03389a006fdfc8a1dcd84edfa07d30aa13474a248a0dab5baaa3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e0416041445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d04030203480030450220483063b6bb08dcc83da33a02c11d2f42203176893554d138c614a36908724cc8022100f5ef2c912d4500b3e2f5b591d0622491e9f220dfd1f9734ec484bb7e90887663";

    #[test]
    fn parses_the_w3c_attestation_root() {
        let der = hex_decode(W3C_ROOT).expect("hex");
        let certificate = Certificate::parse(&der).expect("certificate");
        assert_eq!(certificate.version, 2);
        assert_eq!(
            certificate.subject_attribute(oid::COMMON_NAME),
            Some("WebAuthn test vectors")
        );
        assert_eq!(
            certificate.subject_attribute(oid::ORGANIZATIONAL_UNIT),
            Some("Authenticator Attestation CA")
        );
        assert_eq!(certificate.subject_attribute(oid::COUNTRY), Some("AA"));
        assert_eq!(certificate.issuer, certificate.subject);
        assert!(matches!(certificate.public_key, PublicKey::P256(ref point) if point.len() == 65));
        assert_eq!(certificate.is_ca().expect("constraints"), Some(true));
        assert_eq!(certificate.aaguid().expect("aaguid"), None);
        // 2024-01-01T00:00:00Z to 3024-01-01T00:00:00Z.
        assert_eq!(certificate.not_before, 1_704_067_200);
        assert!(certificate.valid_at(1_791_547_200));
        assert!(!certificate.valid_at(1_704_067_199));
        // Self-signed.
        certificate
            .verify_issued_by(&certificate.public_key)
            .expect("self-signature");
    }

    #[test]
    fn refuses_truncated_and_trailing_input() {
        let der = hex_decode(W3C_ROOT).expect("hex");
        assert!(Certificate::parse(&der[..der.len() - 1]).is_err());
        let mut longer = der.clone();
        longer.push(0);
        assert!(Certificate::parse(&longer).is_err());
        assert!(Certificate::parse(&[]).is_err());
        assert!(Certificate::parse(&[0x30, 0x80, 0x00, 0x00]).is_err());
    }

    #[test]
    fn a_flipped_signature_bit_fails() {
        let mut der = hex_decode(W3C_ROOT).expect("hex");
        let last = der.len() - 1;
        der[last] ^= 0x01;
        let certificate = Certificate::parse(&der).expect("still parses");
        assert!(
            certificate
                .verify_issued_by(&certificate.public_key)
                .is_err()
        );
    }

    #[test]
    fn utc_time_uses_the_two_digit_window() {
        let element = |tag, text: &'static str| Element {
            tag,
            content: text.as_bytes(),
            raw: text.as_bytes(),
        };
        assert_eq!(
            parse_time(element(tag::UTC_TIME, "491231235959Z")).expect("time"),
            2_524_607_999
        );
        assert_eq!(
            parse_time(element(tag::UTC_TIME, "500101000000Z")).expect("time"),
            -631_152_000
        );
        assert!(parse_time(element(tag::UTC_TIME, "500101000000")).is_err());
        assert!(parse_time(element(tag::GENERALIZED_TIME, "20261301000000Z")).is_err());
    }
}
