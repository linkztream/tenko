//! A software WebAuthn authenticator for tests.
//!
//! [`SoftAuthenticator`] plays the part of the browser and the security key: it takes the
//! creation and request options a [`RelyingParty`](crate::webauthn::RelyingParty) issued
//! and answers with the JSON responses a real client would send back (WebAuthn Level 3,
//! sections 5.1 and 5.2). Everything is real: the keys are created with `aws-lc-rs`, the
//! signatures verify, the authenticator data and the CBOR attestation object follow the
//! specification byte for byte, and `packed` attestation with a certificate carries an
//! X.509 v3 leaf that satisfies section 8.2.1, issued by a root CA that tests can
//! configure as a trust anchor ([`SoftAuthenticator::attestation_root_der`]).
//!
//! [`Tweaks`] bends a single ceremony out of shape (wrong challenge, foreign origin,
//! cleared flags, forced counter, a flipped signature bit) so that every check of the
//! verifier can be exercised with a negative test. `Tweaks::default()` changes nothing.
//!
//! The signature counter is kept per credential: a registration reports 0 and every
//! assertion adds 1 (1, 2, 3, ...) while counting is enabled; with
//! [`SoftAuthenticator::counter`] set to `false` it stays 0 for good.

use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::KeySize,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
        RSA_PKCS1_SHA256, RsaKeyPair,
    },
};
use ciborium::Value;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    encoding::{base64url_decode, base64url_encode},
    random,
    webauthn::{
        ALG_EDDSA, ALG_ES256, ALG_RS256, AssertionResponse, AttestationResponse,
        AuthenticationResponse, CreationOptions, Flags, RegistrationResponse, RequestOptions,
    },
};

/// The key algorithm of the credentials a [`SoftAuthenticator`] creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftKeyAlg {
    /// ECDSA over P-256 with SHA-256 (COSE -7).
    Es256,
    /// `EdDSA` over Ed25519 (COSE -8).
    Ed25519,
    /// RSASSA-PKCS1-v1_5 with SHA-256, 2048-bit keys (COSE -257).
    Rs256,
}

impl SoftKeyAlg {
    /// The COSE algorithm identifier.
    const fn cose_id(self) -> i64 {
        match self {
            Self::Es256 => ALG_ES256,
            Self::Ed25519 => ALG_EDDSA,
            Self::Rs256 => ALG_RS256,
        }
    }
}

/// The attestation a [`SoftAuthenticator`] gives at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftAttestation {
    /// Format `none`: an empty statement.
    None,
    /// Format `packed` with self attestation: signed with the credential key.
    PackedSelf,
    /// Format `packed` with an `x5c` certificate: signed with a separate P-256 attestation
    /// key whose leaf certificate was issued by the shared attestation root.
    PackedCertificate,
}

/// Per-ceremony tweaks for negative tests. `Tweaks::default()` changes nothing.
#[derive(Debug, Clone, Default)]
pub struct Tweaks {
    /// Replaces the `type` of the client data (`webauthn.create` or `webauthn.get`).
    pub ceremony_type: Option<String>,
    /// Replaces the origin the client data reports.
    pub origin: Option<String>,
    /// Replaces the challenge in the client data with these raw bytes.
    pub challenge: Option<Vec<u8>>,
    /// Replaces `crossOrigin` of the client data (default `false`).
    pub cross_origin: Option<bool>,
    /// Adds `topOrigin` to the client data (absent by default).
    pub top_origin: Option<String>,
    /// Hashes this RP ID into the authenticator data instead of the ceremony's RP ID.
    pub rp_id: Option<String>,
    /// Flag bits set in the flags byte after the normal flags are computed.
    pub set_flags: u8,
    /// Flag bits cleared in the flags byte after `set_flags` was applied.
    pub clear_flags: u8,
    /// Forces the signature counter in the authenticator data. The authenticator's own
    /// counter still advances as usual.
    pub sign_count: Option<u32>,
    /// Flips a bit of the assertion signature, or of the attestation signature of a
    /// `packed` registration. Format `none` has no signature to corrupt.
    pub corrupt_signature: bool,
}

/// A software WebAuthn authenticator.
///
/// One instance models one device: it has a random AAGUID, creates a fresh credential per
/// registration and remembers each credential's RP ID, user handle and key. It sets the
/// user-present flag always, the user-verified flag unless
/// [`user_verifying`](Self::user_verifying) turned it off, and the backup flags as
/// configured with [`backup`](Self::backup) (both off by default).
#[derive(Debug)]
pub struct SoftAuthenticator {
    alg: SoftKeyAlg,
    attestation: SoftAttestation,
    aaguid: [u8; 16],
    /// The UV, BE and BS bits every authenticator data carries.
    flags: u8,
    counter_enabled: bool,
    attestation_signer: Option<AttestationSigner>,
    credentials: Vec<Credential>,
}

/// A credential the authenticator holds.
#[derive(Debug)]
struct Credential {
    id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    key: CredentialKey,
    sign_count: u32,
}

impl SoftAuthenticator {
    /// A new authenticator that creates `alg` credentials and attests as `attestation`.
    /// It has a random AAGUID, verifies the user, is not backup eligible and counts
    /// signatures.
    ///
    /// # Panics
    ///
    /// If the system random source or key generation fails, which does not happen on a
    /// working system.
    pub fn new(alg: SoftKeyAlg, attestation: SoftAttestation) -> Self {
        let aaguid = random::array::<16>().expect("the system random source works");
        let attestation_signer = (attestation == SoftAttestation::PackedCertificate)
            .then(|| AttestationSigner::new(&aaguid));
        Self {
            alg,
            attestation,
            aaguid,
            flags: Flags::USER_VERIFIED,
            counter_enabled: true,
            attestation_signer,
            credentials: Vec::new(),
        }
    }

    /// Sets the backup-eligible (BE) and backup-state (BS) flags of every authenticator
    /// data. BS without BE is invalid and is what negative tests ask for.
    #[must_use]
    pub fn backup(mut self, eligible: bool, state: bool) -> Self {
        self.flags = with_flag(self.flags, Flags::BACKUP_ELIGIBLE, eligible);
        self.flags = with_flag(self.flags, Flags::BACKUP_STATE, state);
        self
    }

    /// Whether the authenticator verifies the user (sets the UV flag). On by default.
    #[must_use]
    pub fn user_verifying(mut self, verifies: bool) -> Self {
        self.flags = with_flag(self.flags, Flags::USER_VERIFIED, verifies);
        self
    }

    /// Whether the authenticator counts signatures. Enabled: the first assertion of a
    /// credential reports 1 and each further one adds 1 (a registration reports 0).
    /// Disabled: the counter is 0 for good.
    #[must_use]
    pub fn counter(mut self, enabled: bool) -> Self {
        self.counter_enabled = enabled;
        self
    }

    /// The AAGUID of this authenticator model, random per instance.
    pub fn aaguid(&self) -> [u8; 16] {
        self.aaguid
    }

    /// The DER of the attestation root CA that signs the leaf certificates of
    /// [`SoftAttestation::PackedCertificate`]. It is generated once per process, so every
    /// instance shares it and a test can configure it as a trust anchor.
    ///
    /// # Panics
    ///
    /// If key generation fails the first time, which does not happen on a working system.
    pub fn attestation_root_der() -> Vec<u8> {
        attestation_root().certificate.clone()
    }

    /// The id of the most recently registered credential, if any.
    pub fn last_credential_id(&self) -> Option<Vec<u8>> {
        self.credentials
            .last()
            .map(|credential| credential.id.clone())
    }

    /// Answers a registration ceremony: creates a credential for `options.user` at
    /// `options.rp` and returns the `RegistrationResponseJSON` a browser on `origin` would
    /// send. The attestation format is the authenticator's own: the conveyance preference
    /// of the options is not applied, so a test decides what the relying party receives.
    ///
    /// # Panics
    ///
    /// If `options` do not accept the authenticator's algorithm, `options.user.id` is not
    /// base64url, or the system random source or a cryptographic primitive fails.
    pub fn register(&mut self, options: &CreationOptions, origin: &str) -> RegistrationResponse {
        self.register_with(options, origin, &Tweaks::default())
    }

    /// As [`register`](Self::register), bent by `tweaks`.
    ///
    /// # Panics
    ///
    /// As [`register`](Self::register).
    pub fn register_with(
        &mut self,
        options: &CreationOptions,
        origin: &str,
        tweaks: &Tweaks,
    ) -> RegistrationResponse {
        let cose_alg = self.alg.cose_id();
        assert!(
            options
                .pub_key_cred_params
                .iter()
                .any(|parameter| parameter.alg == cose_alg),
            "the creation options do not accept algorithm {cose_alg}"
        );
        let user_handle =
            base64url_decode(&options.user.id).expect("user.id of the options is base64url");
        let key = CredentialKey::generate(self.alg);
        let credential_id = random::array::<32>()
            .expect("the system random source works")
            .to_vec();

        let attested =
            attested_credential_data(&self.aaguid, &credential_id, &key.cose_public_key());
        let auth_data = authenticator_data(
            tweaks.rp_id.as_deref().unwrap_or(&options.rp.id),
            self.flags_byte(Flags::ATTESTED, tweaks),
            tweaks.sign_count.unwrap_or(0),
            &attested,
        );
        let client_data_json =
            client_data_json("webauthn.create", &options.challenge, origin, tweaks);
        let client_data_hash = Sha256::digest(&client_data_json);
        let (format, statement) =
            self.attestation_statement(&key, &auth_data, &client_data_hash, tweaks);
        let attestation_object = cbor(&Value::Map(vec![
            (text("fmt"), text(format)),
            (text("attStmt"), statement),
            (text("authData"), Value::Bytes(auth_data)),
        ]));

        let encoded_id = base64url_encode(&credential_id);
        let cross_platform = self.attestation == SoftAttestation::PackedCertificate;
        let response = RegistrationResponse {
            id: encoded_id.clone(),
            raw_id: encoded_id,
            type_: "public-key".to_owned(),
            response: AttestationResponse {
                client_data_json: base64url_encode(&client_data_json),
                attestation_object: base64url_encode(&attestation_object),
                transports: vec![transport(cross_platform).to_owned()],
            },
            authenticator_attachment: Some(attachment(cross_platform).to_owned()),
            client_extension_results: serde_json::json!({}),
        };
        self.credentials.push(Credential {
            id: credential_id,
            rp_id: options.rp.id.clone(),
            user_handle,
            key,
            sign_count: 0,
        });
        response
    }

    /// Answers an authentication ceremony and returns the `AuthenticationResponseJSON` a
    /// browser on `origin` would send. It uses the first credential of
    /// `options.allow_credentials` it knows for `options.rp_id`; for an empty list it uses
    /// the most recently registered credential for `options.rp_id` (a discoverable
    /// credential). The response always carries the user handle.
    ///
    /// # Panics
    ///
    /// If no credential matches, or a cryptographic primitive fails.
    pub fn assert(&mut self, options: &RequestOptions, origin: &str) -> AuthenticationResponse {
        self.assert_with(options, origin, &Tweaks::default())
    }

    /// As [`assert`](Self::assert), bent by `tweaks`.
    ///
    /// # Panics
    ///
    /// As [`assert`](Self::assert).
    pub fn assert_with(
        &mut self,
        options: &RequestOptions,
        origin: &str,
        tweaks: &Tweaks,
    ) -> AuthenticationResponse {
        let index = self.select_credential(options);
        let flags = self.flags_byte(0, tweaks);
        let counter_enabled = self.counter_enabled;
        let credential = &mut self.credentials[index];
        if counter_enabled {
            credential.sign_count = credential.sign_count.saturating_add(1);
        }

        let auth_data = authenticator_data(
            tweaks.rp_id.as_deref().unwrap_or(&options.rp_id),
            flags,
            tweaks.sign_count.unwrap_or(credential.sign_count),
            &[],
        );
        let client_data_json = client_data_json("webauthn.get", &options.challenge, origin, tweaks);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let mut signature = credential.key.sign(&signed);
        if tweaks.corrupt_signature {
            flip_bit(&mut signature);
        }

        let encoded_id = base64url_encode(&credential.id);
        let cross_platform = self.attestation == SoftAttestation::PackedCertificate;
        AuthenticationResponse {
            id: encoded_id.clone(),
            raw_id: encoded_id,
            type_: "public-key".to_owned(),
            response: AssertionResponse {
                client_data_json: base64url_encode(&client_data_json),
                authenticator_data: base64url_encode(&auth_data),
                signature: base64url_encode(&signature),
                user_handle: Some(base64url_encode(&credential.user_handle)),
            },
            authenticator_attachment: Some(attachment(cross_platform).to_owned()),
            client_extension_results: serde_json::json!({}),
        }
    }

    /// The flags byte: UP, the configured UV, BE and BS bits and `extra`, then the
    /// tweaks.
    fn flags_byte(&self, extra: u8, tweaks: &Tweaks) -> u8 {
        (Flags::USER_PRESENT | self.flags | extra | tweaks.set_flags) & !tweaks.clear_flags
    }

    /// The index of the credential an assertion uses.
    fn select_credential(&self, options: &RequestOptions) -> usize {
        if options.allow_credentials.is_empty() {
            return self
                .credentials
                .iter()
                .rposition(|credential| credential.rp_id == options.rp_id)
                .unwrap_or_else(|| {
                    panic!("no discoverable credential for RP ID `{}`", options.rp_id)
                });
        }
        options
            .allow_credentials
            .iter()
            .filter_map(|descriptor| base64url_decode(&descriptor.id).ok())
            .find_map(|id| {
                self.credentials
                    .iter()
                    .position(|credential| credential.id == id && credential.rp_id == options.rp_id)
            })
            .unwrap_or_else(|| {
                panic!(
                    "none of the allowed credentials is known for RP ID `{}`",
                    options.rp_id
                )
            })
    }

    /// The attestation format and statement of a registration.
    fn attestation_statement(
        &self,
        key: &CredentialKey,
        auth_data: &[u8],
        client_data_hash: &[u8],
        tweaks: &Tweaks,
    ) -> (&'static str, Value) {
        let mut message = auth_data.to_vec();
        message.extend_from_slice(client_data_hash);
        let finish = |mut signature: Vec<u8>| {
            if tweaks.corrupt_signature {
                flip_bit(&mut signature);
            }
            Value::Bytes(signature)
        };
        match self.attestation {
            SoftAttestation::None => ("none", Value::Map(Vec::new())),
            SoftAttestation::PackedSelf => (
                "packed",
                Value::Map(vec![
                    (text("alg"), int(key.cose_alg())),
                    (text("sig"), finish(key.sign(&message))),
                ]),
            ),
            SoftAttestation::PackedCertificate => {
                let signer = self
                    .attestation_signer
                    .as_ref()
                    .expect("certificate attestation has an attestation key");
                (
                    "packed",
                    Value::Map(vec![
                        (text("alg"), int(ALG_ES256)),
                        (text("sig"), finish(signer.sign(&message))),
                        (
                            text("x5c"),
                            Value::Array(vec![Value::Bytes(signer.certificate.clone())]),
                        ),
                    ]),
                )
            }
        }
    }
}

/// `flags` with `flag` set or cleared.
const fn with_flag(flags: u8, flag: u8, on: bool) -> u8 {
    if on { flags | flag } else { flags & !flag }
}

/// The transport a registration reports.
const fn transport(cross_platform: bool) -> &'static str {
    if cross_platform { "usb" } else { "internal" }
}

/// The authenticator attachment a response reports.
const fn attachment(cross_platform: bool) -> &'static str {
    if cross_platform {
        "cross-platform"
    } else {
        "platform"
    }
}

/// Flips the lowest bit of the last byte: the encoding stays well formed, the signature
/// no longer verifies.
fn flip_bit(signature: &mut [u8]) {
    if let Some(last) = signature.last_mut() {
        *last ^= 0x01;
    }
}

/// The `CollectedClientData` JSON of a ceremony, in the member order browsers use.
fn client_data_json(
    default_type: &str,
    default_challenge: &str,
    origin: &str,
    tweaks: &Tweaks,
) -> Vec<u8> {
    #[derive(Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        type_: &'a str,
        challenge: &'a str,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
        #[serde(rename = "topOrigin", skip_serializing_if = "Option::is_none")]
        top_origin: Option<&'a str>,
    }

    let challenge = tweaks.challenge.as_deref().map(base64url_encode);
    serde_json::to_vec(&ClientData {
        type_: tweaks.ceremony_type.as_deref().unwrap_or(default_type),
        challenge: challenge.as_deref().unwrap_or(default_challenge),
        origin: tweaks.origin.as_deref().unwrap_or(origin),
        cross_origin: tweaks.cross_origin.unwrap_or(false),
        top_origin: tweaks.top_origin.as_deref(),
    })
    .expect("client data serialises")
}

/// Authenticator data (WebAuthn Level 3, section 6.1): RP ID hash, flags, counter and,
/// for registrations, the attested credential data.
fn authenticator_data(rp_id: &str, flags: u8, counter: u32, attested: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + attested.len());
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(attested);
    out
}

/// Attested credential data (section 6.5.1): AAGUID, id length, id and COSE key.
fn attested_credential_data(aaguid: &[u8; 16], credential_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
    let length = u16::try_from(credential_id.len()).expect("a credential id fits in 16 bits");
    let length = length.to_be_bytes();
    let parts: [&[u8]; 4] = [aaguid, &length, credential_id, cose_key];
    parts.concat()
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// CBOR encoding of a value.
fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encodes into memory");
    out
}

/// A COSE key (RFC 9052) as a CBOR map with integer labels, in the order of the CTAP2
/// canonical form.
fn cose_key(entries: Vec<(i64, Value)>) -> Vec<u8> {
    cbor(&Value::Map(
        entries
            .into_iter()
            .map(|(label, value)| (int(label), value))
            .collect(),
    ))
}

/// The private key of a credential.
#[derive(Debug)]
enum CredentialKey {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rs256(&'static RsaKeyPair),
}

impl CredentialKey {
    fn generate(alg: SoftKeyAlg) -> Self {
        match alg {
            SoftKeyAlg::Es256 => Self::Es256(
                EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
                    .expect("P-256 key generation"),
            ),
            SoftKeyAlg::Ed25519 => {
                Self::Ed25519(Ed25519KeyPair::generate().expect("Ed25519 key generation"))
            }
            SoftKeyAlg::Rs256 => Self::Rs256(pooled_rsa_key()),
        }
    }

    fn cose_alg(&self) -> i64 {
        match self {
            Self::Es256(_) => ALG_ES256,
            Self::Ed25519(_) => ALG_EDDSA,
            Self::Rs256(_) => ALG_RS256,
        }
    }

    /// The CBOR encoding of the COSE public key.
    fn cose_public_key(&self) -> Vec<u8> {
        match self {
            Self::Es256(pair) => {
                let point = pair.public_key().as_ref();
                let (x_coordinate, y_coordinate) = point[1..].split_at(32);
                cose_key(vec![
                    (1, int(2)),
                    (3, int(ALG_ES256)),
                    (-1, int(1)),
                    (-2, bytes(x_coordinate)),
                    (-3, bytes(y_coordinate)),
                ])
            }
            Self::Ed25519(pair) => cose_key(vec![
                (1, int(1)),
                (3, int(ALG_EDDSA)),
                (-1, int(6)),
                (-2, bytes(pair.public_key().as_ref())),
            ]),
            Self::Rs256(pair) => {
                let (modulus, exponent) = rsa_components(pair);
                cose_key(vec![
                    (1, int(3)),
                    (3, int(ALG_RS256)),
                    (-1, bytes(&modulus)),
                    (-2, bytes(&exponent)),
                ])
            }
        }
    }

    /// Signs as the credential algorithm does: ASN.1 DER for ECDSA, raw for Ed25519 and
    /// PKCS #1 v1.5 with SHA-256 for RSA.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256(pair) => pair
                .sign(&SystemRandom::new(), message)
                .expect("ECDSA signing")
                .as_ref()
                .to_vec(),
            Self::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
            Self::Rs256(pair) => {
                let mut signature = vec![0_u8; pair.public_modulus_len()];
                pair.sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .expect("RSA signing");
                signature
            }
        }
    }
}

/// An RSA-2048 key from a small process-wide pool. Generating a key takes a noticeable
/// moment, so credentials take turns on four keys that are generated on first use.
fn pooled_rsa_key() -> &'static RsaKeyPair {
    const POOL: usize = 4;
    static KEYS: [OnceLock<RsaKeyPair>; POOL] = [const { OnceLock::new() }; POOL];
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let slot = NEXT.fetch_add(1, Ordering::Relaxed) % POOL;
    KEYS[slot].get_or_init(|| RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA key generation"))
}

/// The modulus and public exponent of an RSA key, big-endian without leading zeros.
fn rsa_components(pair: &RsaKeyPair) -> (Vec<u8>, Vec<u8>) {
    let (_, public_key, _) = der::parse(pair.public_key().as_ref()).expect("RSAPublicKey");
    let (_, modulus, rest) = der::parse(public_key).expect("RSAPublicKey modulus");
    let (_, exponent, _) = der::parse(rest).expect("RSAPublicKey exponent");
    (
        der::unsigned(modulus).to_vec(),
        der::unsigned(exponent).to_vec(),
    )
}

// --- X.509 -------------------------------------------------------------------------------

/// Object identifiers (DER content bytes).
mod oid {
    /// id-ecPublicKey (1.2.840.10045.2.1).
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1 (1.2.840.10045.3.1.7).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// keyUsage (2.5.29.15).
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
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

/// A small DER writer: just what the attestation certificates need.
mod der {
    const BOOLEAN: u8 = 0x01;
    const INTEGER: u8 = 0x02;
    const BIT_STRING: u8 = 0x03;
    const OCTET_STRING: u8 = 0x04;
    const OID: u8 = 0x06;
    const UTF8_STRING: u8 = 0x0c;
    const PRINTABLE_STRING: u8 = 0x13;
    const UTC_TIME: u8 = 0x17;
    const GENERALIZED_TIME: u8 = 0x18;
    const SEQUENCE: u8 = 0x30;
    const SET: u8 = 0x31;
    /// Class bits of an explicit, context-specific, constructed tag: `[number]`.
    const EXPLICIT: u8 = 0xa0;

    /// One tag-length-value element. Lengths below 128 use the short form, longer ones
    /// the long form with the fewest length octets.
    pub fn element(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(content.len() + 6);
        out.push(tag);
        push_length(&mut out, content.len());
        out.extend_from_slice(content);
        out
    }

    fn push_length(out: &mut Vec<u8>, length: usize) {
        if let Ok(short) = u8::try_from(length)
            && short < 0x80
        {
            out.push(short);
            return;
        }
        let octets = length.to_be_bytes();
        let first = octets
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(octets.len() - 1);
        let significant = &octets[first..];
        out.push(0x80 | u8::try_from(significant.len()).expect("a length has at most 8 octets"));
        out.extend_from_slice(significant);
    }

    /// A SEQUENCE of already encoded elements.
    pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        element(SEQUENCE, &parts.concat())
    }

    /// A SET of already encoded elements.
    pub fn set(parts: &[&[u8]]) -> Vec<u8> {
        element(SET, &parts.concat())
    }

    /// A non-negative INTEGER from big-endian bytes: leading zeros are dropped, one is
    /// added when the high bit would make the value negative.
    pub fn integer(unsigned_be: &[u8]) -> Vec<u8> {
        let magnitude = unsigned(unsigned_be);
        let mut content = Vec::with_capacity(magnitude.len() + 1);
        if magnitude.first().is_none_or(|octet| octet & 0x80 != 0) {
            content.push(0);
        }
        content.extend_from_slice(magnitude);
        element(INTEGER, &content)
    }

    /// `bytes` without leading zeros (a single zero stays empty).
    pub fn unsigned(bytes: &[u8]) -> &[u8] {
        let zeros = bytes.iter().take_while(|octet| **octet == 0).count();
        &bytes[zeros..]
    }

    /// A BIT STRING of whole octets.
    pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
        bit_string_with_unused(0, bytes)
    }

    /// A BIT STRING whose last octet has `unused` unused bits.
    pub fn bit_string_with_unused(unused: u8, bytes: &[u8]) -> Vec<u8> {
        let mut content = Vec::with_capacity(bytes.len() + 1);
        content.push(unused);
        content.extend_from_slice(bytes);
        element(BIT_STRING, &content)
    }

    /// An OCTET STRING.
    pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
        element(OCTET_STRING, bytes)
    }

    /// An OBJECT IDENTIFIER from its content octets.
    pub fn oid(content: &[u8]) -> Vec<u8> {
        element(OID, content)
    }

    /// A BOOLEAN.
    pub fn boolean(value: bool) -> Vec<u8> {
        element(BOOLEAN, &[if value { 0xff } else { 0x00 }])
    }

    /// A `UTF8String`.
    pub fn utf8_string(text: &str) -> Vec<u8> {
        element(UTF8_STRING, text.as_bytes())
    }

    /// A `PrintableString`.
    pub fn printable_string(text: &str) -> Vec<u8> {
        element(PRINTABLE_STRING, text.as_bytes())
    }

    /// An X.509 time (UTC): `UTCTime` before 2050, `GeneralizedTime` from 2050.
    pub fn time(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Vec<u8> {
        if year < 2050 {
            let text = format!(
                "{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z",
                year % 100
            );
            element(UTC_TIME, text.as_bytes())
        } else {
            let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
            element(GENERALIZED_TIME, text.as_bytes())
        }
    }

    /// An explicit context tag `[number]` around an encoded element.
    pub fn explicit(number: u8, content: &[u8]) -> Vec<u8> {
        element(EXPLICIT | number, content)
    }

    /// Splits one element off the front of `input`: its tag, its content and the rest.
    pub fn parse(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let (octets, rest) = rest.split_at(count);
            (
                octets
                    .iter()
                    .fold(0_usize, |acc, octet| (acc << 8) | usize::from(*octet)),
                rest,
            )
        };
        if rest.len() < length {
            return None;
        }
        let (content, after) = rest.split_at(length);
        Some((tag, content, after))
    }
}

/// The shared attestation root CA of the process.
#[derive(Debug)]
struct AttestationRoot {
    key: EcdsaKeyPair,
    /// The encoded subject (and issuer) name.
    name: Vec<u8>,
    certificate: Vec<u8>,
}

fn attestation_root() -> &'static AttestationRoot {
    static ROOT: OnceLock<AttestationRoot> = OnceLock::new();
    ROOT.get_or_init(|| {
        let key =
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("P-256 key generation");
        let name = der::sequence(&[
            &relative_name(oid::COUNTRY, &der::printable_string("SE")),
            &relative_name(oid::ORGANIZATION, &der::utf8_string("Tenko Test")),
            &relative_name(
                oid::COMMON_NAME,
                &der::utf8_string("Tenko Soft Authenticator Root CA"),
            ),
        ]);
        let extensions = [
            extension(
                oid::BASIC_CONSTRAINTS,
                true,
                &der::sequence(&[&der::boolean(true)]),
            ),
            // keyCertSign and cRLSign.
            extension(
                oid::KEY_USAGE,
                true,
                &der::bit_string_with_unused(1, &[0x06]),
            ),
        ];
        let serial = random::array::<16>().expect("the system random source works");
        // The issuer is the subject: the root is self-signed, and the leaf certificates
        // reuse these very bytes as their issuer.
        let certificate = certificate(
            &TbsCertificate {
                serial: &serial,
                issuer: &name,
                subject: &name,
                public_key: key.public_key().as_ref(),
                extensions: &extensions,
            },
            &key,
        );
        AttestationRoot {
            key,
            name,
            certificate,
        }
    })
}

/// The attestation key of one authenticator and its leaf certificate.
#[derive(Debug)]
struct AttestationSigner {
    key: EcdsaKeyPair,
    certificate: Vec<u8>,
}

impl AttestationSigner {
    /// A fresh P-256 attestation key with a leaf certificate for `aaguid`, issued by the
    /// shared root.
    fn new(aaguid: &[u8; 16]) -> Self {
        let root = attestation_root();
        let key =
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("P-256 key generation");
        let subject = der::sequence(&[
            &relative_name(oid::COUNTRY, &der::printable_string("SE")),
            &relative_name(oid::ORGANIZATION, &der::utf8_string("Tenko Test")),
            &relative_name(
                oid::ORGANIZATIONAL_UNIT,
                &der::utf8_string("Authenticator Attestation"),
            ),
            &relative_name(
                oid::COMMON_NAME,
                &der::utf8_string("Tenko Soft Authenticator"),
            ),
        ]);
        let extensions = [
            // cA is FALSE, the default, so the DER encoding leaves it out.
            extension(oid::BASIC_CONSTRAINTS, true, &der::sequence(&[])),
            // id-fido-gen-ce-aaguid, non-critical: an OCTET STRING inside the extnValue.
            extension(oid::FIDO_AAGUID, false, &der::octet_string(aaguid)),
        ];
        let serial = random::array::<16>().expect("the system random source works");
        let certificate = certificate(
            &TbsCertificate {
                serial: &serial,
                issuer: &root.name,
                subject: &subject,
                public_key: key.public_key().as_ref(),
                extensions: &extensions,
            },
            &root.key,
        );
        Self { key, certificate }
    }

    /// An ASN.1 DER ECDSA signature, as `packed` attestation with ES256 carries.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key
            .sign(&SystemRandom::new(), message)
            .expect("ECDSA signing")
            .as_ref()
            .to_vec()
    }
}

/// The fields of a `tbsCertificate` that differ between the certificates built here.
struct TbsCertificate<'a> {
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    /// An uncompressed P-256 point.
    public_key: &'a [u8],
    extensions: &'a [Vec<u8>],
}

/// A relative distinguished name with one attribute: `SET { SEQUENCE { type, value } }`.
fn relative_name(attribute: &[u8], value: &[u8]) -> Vec<u8> {
    der::set(&[&der::sequence(&[&der::oid(attribute), value])])
}

/// One extension: `SEQUENCE { extnID, critical (when true), extnValue }`.
fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let id = der::oid(id);
    let value = der::octet_string(value);
    if critical {
        der::sequence(&[&id, &der::boolean(true), &value])
    } else {
        der::sequence(&[&id, &value])
    }
}

/// An X.509 v3 certificate valid from 2024-01-01 to 2099-12-31, signed with
/// ecdsa-with-SHA256 by `issuer_key`.
fn certificate(tbs: &TbsCertificate<'_>, issuer_key: &EcdsaKeyPair) -> Vec<u8> {
    let algorithm = der::sequence(&[&der::oid(oid::ECDSA_SHA256)]);
    let validity = der::sequence(&[
        &der::time(2024, 1, 1, 0, 0, 0),
        &der::time(2099, 12, 31, 23, 59, 59),
    ]);
    let public_key_info = der::sequence(&[
        &der::sequence(&[&der::oid(oid::EC_PUBLIC_KEY), &der::oid(oid::P256)]),
        &der::bit_string(tbs.public_key),
    ]);
    let extensions = der::explicit(3, &der::sequence(&[&tbs.extensions.concat()]));
    let body = der::sequence(&[
        &der::explicit(0, &der::integer(&[2])),
        &der::integer(tbs.serial),
        &algorithm,
        tbs.issuer,
        &validity,
        tbs.subject,
        &public_key_info,
        &extensions,
    ]);
    let signature = issuer_key
        .sign(&SystemRandom::new(), &body)
        .expect("ECDSA signing");
    der::sequence(&[&body, &algorithm, &der::bit_string(signature.as_ref())])
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

    use super::*;

    #[test]
    fn lengths_use_the_short_and_the_long_form() {
        assert_eq!(der::element(0x04, &[]), [0x04, 0x00]);
        assert_eq!(der::element(0x04, &[7; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(der::element(0x04, &[7; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(der::element(0x04, &[7; 0xff])[..3], [0x04, 0x81, 0xff]);
        assert_eq!(
            der::element(0x04, &[7; 0x100])[..4],
            [0x04, 0x82, 0x01, 0x00]
        );
        assert_eq!(
            der::element(0x04, &vec![7; 0x1_0000])[..5],
            [0x04, 0x83, 0x01, 0x00, 0x00]
        );
        for length in [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234, 0x1_0000] {
            let encoded = der::element(0x04, &vec![9; length]);
            let (tag, content, rest) = der::parse(&encoded).expect("parses");
            assert_eq!((tag, content.len(), rest.len()), (0x04, length, 0));
        }
    }

    #[test]
    fn integers_are_minimal_and_non_negative() {
        assert_eq!(der::integer(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(der::integer(&[0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(der::integer(&[0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(der::integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(
            der::integer(&[0, 0, 0x80, 0x01]),
            [0x02, 0x03, 0x00, 0x80, 0x01]
        );
        assert_eq!(
            der::integer(&[0x01, 0x00, 0x01]),
            [0x02, 0x03, 0x01, 0x00, 0x01]
        );
    }

    #[test]
    fn primitives_encode_as_expected() {
        assert_eq!(der::bit_string(&[0xab]), [0x03, 0x02, 0x00, 0xab]);
        assert_eq!(
            der::bit_string_with_unused(1, &[0x06]),
            [0x03, 0x02, 0x01, 0x06]
        );
        assert_eq!(der::boolean(true), [0x01, 0x01, 0xff]);
        assert_eq!(der::boolean(false), [0x01, 0x01, 0x00]);
        assert_eq!(
            der::oid(&[0x55, 0x04, 0x03]),
            [0x06, 0x03, 0x55, 0x04, 0x03]
        );
        assert_eq!(der::sequence(&[]), [0x30, 0x00]);
        assert_eq!(
            der::explicit(0, &[0x02, 0x01, 0x02]),
            [0xa0, 0x03, 0x02, 0x01, 0x02]
        );
        assert_eq!(der::utf8_string("ab"), [0x0c, 0x02, b'a', b'b']);
        assert_eq!(der::printable_string("SE"), [0x13, 0x02, b'S', b'E']);
    }

    #[test]
    fn times_switch_to_generalized_time_in_2050() {
        assert_eq!(der::time(2024, 1, 1, 0, 0, 0)[..2], [0x17, 0x0d]);
        assert_eq!(&der::time(2024, 1, 1, 0, 0, 0)[2..], b"240101000000Z");
        assert_eq!(&der::time(2049, 12, 31, 23, 59, 59)[2..], b"491231235959Z");
        assert_eq!(der::time(2050, 1, 1, 0, 0, 0)[..2], [0x18, 0x0f]);
        assert_eq!(
            &der::time(2099, 12, 31, 23, 59, 59)[2..],
            b"20991231235959Z"
        );
    }

    /// Splits a certificate into its three parts: `tbsCertificate` (with header), the
    /// signature algorithm and the signature bits.
    fn split_certificate(der_bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let (tag, body, rest) = der::parse(der_bytes).expect("certificate");
        assert_eq!(
            (tag, rest.len()),
            (0x30, 0),
            "one SEQUENCE and nothing after it"
        );
        let (tbs_tag, tbs_content, after) = der::parse(body).expect("tbsCertificate");
        assert_eq!(tbs_tag, 0x30);
        let tbs = &body[..body.len() - after.len()];
        assert!(tbs.len() > tbs_content.len());
        let (algorithm_tag, algorithm, after) = der::parse(after).expect("algorithm");
        assert_eq!(algorithm_tag, 0x30);
        let (signature_tag, signature, after) = der::parse(after).expect("signature");
        assert_eq!((signature_tag, signature[0], after.len()), (0x03, 0, 0));
        (tbs, algorithm, &signature[1..])
    }

    /// The encoded `index`-th field of a `tbsCertificate` with an explicit version: 0
    /// version, 1 serial, 2 algorithm, 3 issuer, 4 validity, 5 subject, 6 key, 7
    /// extensions.
    fn tbs_field(tbs: &[u8], index: usize) -> &[u8] {
        let (_, mut rest, _) = der::parse(tbs).expect("tbs");
        for _ in 0..index {
            rest = der::parse(rest).expect("field").2;
        }
        let (_, _, after) = der::parse(rest).expect("field");
        &rest[..rest.len() - after.len()]
    }

    #[test]
    fn the_root_is_self_signed_and_stable() {
        let root = SoftAuthenticator::attestation_root_der();
        assert_eq!(root, SoftAuthenticator::attestation_root_der());
        let (tbs, algorithm, signature) = split_certificate(&root);
        assert_eq!(algorithm, der::oid(oid::ECDSA_SHA256));
        let key = attestation_root().key.public_key().as_ref().to_vec();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(tbs, signature)
            .expect("the root signs itself");
        // The issuer (field 3) equals the subject (field 5).
        assert_eq!(tbs_field(tbs, 3), tbs_field(tbs, 5));
        assert_eq!(tbs_field(tbs, 3), attestation_root().name);
    }

    #[test]
    fn the_leaf_is_issued_by_the_root_and_names_the_aaguid() {
        let authenticator =
            SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate);
        let leaf = &authenticator
            .attestation_signer
            .as_ref()
            .expect("signer")
            .certificate;
        let (tbs, _, signature) = split_certificate(leaf);
        let root_key = attestation_root().key.public_key().as_ref().to_vec();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, root_key)
            .verify(tbs, signature)
            .expect("the root issued the leaf");
        // The issuer bytes are the root's subject bytes, character for character.
        assert_eq!(tbs_field(tbs, 3), attestation_root().name);
        // The AAGUID extension holds the AAGUID as OCTET STRING inside the extnValue.
        let wrapped = der::octet_string(&der::octet_string(&authenticator.aaguid()));
        assert!(
            leaf.windows(wrapped.len())
                .any(|window| window == wrapped.as_slice())
        );
    }

    #[test]
    fn rsa_components_have_no_leading_zero() {
        let (modulus, exponent) = rsa_components(pooled_rsa_key());
        assert_eq!(modulus.len(), 256);
        assert_ne!(modulus[0], 0);
        assert_eq!(exponent, [0x01, 0x00, 0x01]);
    }
}
