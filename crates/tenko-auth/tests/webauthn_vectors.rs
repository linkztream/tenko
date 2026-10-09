//! The WebAuthn Level 3 test vectors (W3C Recommendation, section 16) against the relying
//! party of ADR 0010: every supported combination registers and authenticates, every
//! unsupported one is refused with the expected error.

use std::collections::BTreeMap;

use tenko_auth::{
    clock::{Clock, MockClock},
    encoding::{base64url_encode, hex_decode},
    webauthn::{
        ALG_EDDSA, ALG_ES256, ALG_RS256, AssertionPolicy, AssertionResponse, AttestationKind,
        AttestationResponse, AuthenticationResponse, RegisteredCredential, RegistrationPolicy,
        RegistrationResponse, RelyingParty, RpConfig, StoredKey, UserVerification, WebAuthnError,
    },
};

const VECTORS: &str = include_str!("fixtures/webauthn/w3c-webauthn-l3-vectors.txt");

/// Section number to (`phase.name` to bytes).
fn vectors() -> BTreeMap<String, BTreeMap<String, Vec<u8>>> {
    let mut sections = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let number = rest.split(']').next().expect("section header");
            current = Some(number.to_owned());
            sections.insert(number.to_owned(), BTreeMap::new());
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("name = hex");
        let section = current.as_ref().expect("value inside a section");
        sections
            .get_mut(section)
            .expect("section")
            .insert(name.to_owned(), hex_decode(value).expect("hex"));
    }
    sections
}

fn relying_party(anchored: bool) -> RelyingParty {
    let root = vectors()["16.1"]["root.attestation_ca_cert"].clone();
    RelyingParty::new(RpConfig {
        rp_id: "example.org".to_owned(),
        rp_name: "Example".to_owned(),
        origins: vec!["https://example.org".to_owned()],
        trust_anchors: if anchored { vec![root] } else { Vec::new() },
        timeout_ms: 60_000,
    })
    .expect("relying party")
}

/// The vectors draw their UV flags at random, so the conformance runs do not require UV.
const LENIENT: RegistrationPolicy = RegistrationPolicy {
    user_verification: UserVerification::Discouraged,
    hardware_key_required: false,
};
const LENIENT_ASSERTION: AssertionPolicy = AssertionPolicy {
    user_verification: UserVerification::Discouraged,
    hardware_key_required: false,
};

fn registration(values: &BTreeMap<String, Vec<u8>>) -> RegistrationResponse {
    let id = base64url_encode(&values["registration.credential_id"]);
    RegistrationResponse {
        id: id.clone(),
        raw_id: id,
        type_: "public-key".to_owned(),
        response: AttestationResponse {
            client_data_json: base64url_encode(&values["registration.clientDataJSON"]),
            attestation_object: base64url_encode(&values["registration.attestationObject"]),
            transports: Vec::new(),
        },
        authenticator_attachment: None,
        client_extension_results: serde_json::Value::Null,
    }
}

fn assertion(values: &BTreeMap<String, Vec<u8>>) -> AuthenticationResponse {
    let id = base64url_encode(&values["registration.credential_id"]);
    AuthenticationResponse {
        id: id.clone(),
        raw_id: id,
        type_: "public-key".to_owned(),
        response: AssertionResponse {
            client_data_json: base64url_encode(&values["authentication.clientDataJSON"]),
            authenticator_data: base64url_encode(&values["authentication.authenticatorData"]),
            signature: base64url_encode(&values["authentication.signature"]),
            user_handle: None,
        },
        authenticator_attachment: None,
        client_extension_results: serde_json::Value::Null,
    }
}

fn register(
    rp: &RelyingParty,
    section: &str,
    policy: RegistrationPolicy,
) -> Result<RegisteredCredential, WebAuthnError> {
    let all = vectors();
    let values = &all[section];
    rp.finish_registration(
        &registration(values),
        &values["registration.challenge"],
        &policy,
        MockClock::fixed().now(),
    )
}

fn authenticate(rp: &RelyingParty, section: &str, credential: &RegisteredCredential) {
    let all = vectors();
    let values = &all[section];
    let verified = rp
        .finish_assertion(
            &assertion(values),
            &values["authentication.challenge"],
            &StoredKey {
                credential_id: &credential.credential_id,
                public_key: &credential.public_key,
                sign_count: credential.sign_count,
                backup_eligible: credential.backup_eligible,
            },
            &LENIENT_ASSERTION,
        )
        .unwrap_or_else(|error| panic!("{section}: assertion refused: {error}"));
    assert_eq!(verified.user_handle, None, "{section}");
}

#[test]
fn supported_vectors_register_and_authenticate() {
    let rp = relying_party(true);
    for (section, alg, kind) in [
        ("16.2", ALG_ES256, "none"),
        ("16.3", ALG_ES256, "self"),
        ("16.6", ALG_ES256, "none"),
        ("16.7", ALG_ES256, "certificate"),
        ("16.10", ALG_RS256, "certificate"),
        ("16.11", ALG_EDDSA, "certificate"),
    ] {
        let credential = register(&rp, section, LENIENT)
            .unwrap_or_else(|error| panic!("{section}: registration refused: {error}"));
        assert_eq!(credential.alg, alg, "{section}");
        assert_eq!(
            credential.credential_id,
            vectors()[section]["registration.credential_id"],
            "{section}"
        );
        assert_eq!(
            credential.aaguid.to_vec(),
            vectors()[section]["registration.aaguid"],
            "{section}"
        );
        match (kind, &credential.attestation) {
            ("none", AttestationKind::None) | ("self", AttestationKind::SelfAttestation) => {}
            ("certificate", AttestationKind::Certificate { anchored, .. }) => {
                assert!(anchored, "{section}: chains to the W3C test root");
                assert_eq!(
                    credential.hardware_key, !credential.backup_eligible,
                    "{section}"
                );
            }
            (expected, actual) => panic!("{section}: expected {expected}, got {actual:?}"),
        }
        authenticate(&rp, section, &credential);
    }
}

#[test]
fn the_long_credential_id_vector_round_trips() {
    let rp = relying_party(false);
    let credential = register(&rp, "16.6", LENIENT).expect("registration");
    assert!(credential.credential_id.len() > 32);
}

#[test]
fn certificate_attestation_without_the_anchor_is_unanchored() {
    let rp = relying_party(false);
    let credential = register(&rp, "16.7", LENIENT).expect("registration");
    assert!(matches!(
        credential.attestation,
        AttestationKind::Certificate {
            anchored: false,
            ..
        }
    ));
    // Without configured anchors the verified certificate still counts, unless BE is set.
    assert_eq!(credential.hardware_key, !credential.backup_eligible);
}

#[test]
fn cross_origin_vectors_are_refused() {
    let rp = relying_party(true);
    for section in ["16.4", "16.5"] {
        assert_eq!(
            register(&rp, section, LENIENT).expect_err(section),
            WebAuthnError::CrossOrigin,
            "{section}"
        );
    }
}

#[test]
fn unsupported_algorithms_are_refused() {
    let rp = relying_party(true);
    assert_eq!(
        register(&rp, "16.8", LENIENT),
        Err(WebAuthnError::UnsupportedAlgorithm(-35))
    );
    assert_eq!(
        register(&rp, "16.9", LENIENT),
        Err(WebAuthnError::UnsupportedAlgorithm(-36))
    );
    // Ed448 (the fully specified identifier -53).
    assert_eq!(
        register(&rp, "16.12", LENIENT),
        Err(WebAuthnError::UnsupportedAlgorithm(-53))
    );
}

#[test]
fn unsupported_attestation_formats_are_refused() {
    let rp = relying_party(true);
    for (section, format) in [
        ("16.13", "tpm"),
        ("16.14", "android-key"),
        ("16.15", "apple"),
        ("16.16", "fido-u2f"),
    ] {
        assert_eq!(
            register(&rp, section, LENIENT),
            Err(WebAuthnError::UnsupportedAttestation(format.to_owned())),
            "{section}"
        );
    }
}

#[test]
fn hardware_key_policy_needs_certificate_attestation() {
    let rp = relying_party(true);
    let strict = RegistrationPolicy {
        user_verification: UserVerification::Discouraged,
        hardware_key_required: true,
    };
    assert_eq!(
        register(&rp, "16.2", strict),
        Err(WebAuthnError::AttestationRequired)
    );
    assert_eq!(
        register(&rp, "16.3", strict),
        Err(WebAuthnError::AttestationRequired)
    );
    // 16.7 is certificate-attested; whether it passes depends on its BE flag.
    let lenient = register(&rp, "16.7", LENIENT).expect("registration");
    let strict_result = register(&rp, "16.7", strict);
    if lenient.backup_eligible {
        assert_eq!(strict_result, Err(WebAuthnError::BackupEligibleRefused));
    } else {
        assert!(strict_result.expect("hardware key").hardware_key);
    }
}

#[test]
fn required_user_verification_follows_the_uv_flag() {
    let rp = relying_party(true);
    let required = RegistrationPolicy {
        user_verification: UserVerification::Required,
        hardware_key_required: false,
    };
    for section in ["16.2", "16.3", "16.7", "16.10", "16.11"] {
        let lenient = register(&rp, section, LENIENT).expect("registration");
        let result = register(&rp, section, required);
        if lenient.user_verified {
            assert!(result.is_ok(), "{section}");
        } else {
            assert_eq!(
                result,
                Err(WebAuthnError::UserVerificationMissing),
                "{section}"
            );
        }
    }
}

#[test]
fn a_wrong_challenge_or_origin_is_refused() {
    let rp = relying_party(true);
    let all = vectors();
    let values = &all["16.2"];
    let now = MockClock::fixed().now();
    assert_eq!(
        rp.finish_registration(&registration(values), &[0; 32], &LENIENT, now),
        Err(WebAuthnError::ChallengeMismatch)
    );
    let other = RelyingParty::new(RpConfig {
        origins: vec!["https://other.example.org".to_owned()],
        ..RpConfig::for_host("example.org")
    })
    .expect("rp");
    assert_eq!(
        other.finish_registration(
            &registration(values),
            &values["registration.challenge"],
            &LENIENT,
            now
        ),
        Err(WebAuthnError::OriginMismatch(
            "https://example.org".to_owned()
        ))
    );
}
