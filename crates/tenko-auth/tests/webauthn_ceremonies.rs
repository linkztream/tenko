//! End-to-end WebAuthn ceremonies: the software authenticator against the relying party of
//! ADR 0010. Every algorithm and attestation format registers and authenticates, the
//! hardware-key rules hold, and every check of the verifier refuses what it should with
//! the exact error.

use ciborium::Value;
use sha2::{Digest as _, Sha256};
use tenko_auth::{
    clock::{Clock as _, MockClock},
    encoding::{base64url_decode, base64url_encode, hex_decode, hex_encode},
    testing::authenticator::{SoftAttestation, SoftAuthenticator, SoftKeyAlg, Tweaks},
    webauthn::{
        ALG_EDDSA, ALG_ES256, ALG_RS256, AssertionPolicy, AttestationKind, AuthenticationResponse,
        CoseKey, CredentialDescriptor, Flags, RegisteredCredential, RegistrationPolicy,
        RegistrationResponse, RelyingParty, RequestOptions, RpConfig, StoredKey, TrustAnchor,
        UserVerification, VerifiedAssertion, WebAuthnError, assertion_credential_id,
    },
};
use tenko_core::Timestamp;

const RP_HOST: &str = "tenko.example.test";
const ORIGIN: &str = "https://tenko.example.test";
const USER_ID: &[u8; 16] = b"tenko-user-00001";
const REGISTRATION_CHALLENGE: [u8; 32] = [0xa5; 32];
const AUTHENTICATION_CHALLENGE: [u8; 32] = [0x5a; 32];
const ALGORITHMS: [SoftKeyAlg; 3] = [SoftKeyAlg::Es256, SoftKeyAlg::Ed25519, SoftKeyAlg::Rs256];
const ATTESTATIONS: [SoftAttestation; 3] = [
    SoftAttestation::None,
    SoftAttestation::PackedSelf,
    SoftAttestation::PackedCertificate,
];

/// The attestation root of the WebAuthn Level 3 test vectors (section 16.1), DER.
const W3C_ROOT: &str = "30820207308201ada003020102021100ed7f905d8bd0b414d1784913170a90b6300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a3062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d030107034200043269300e5ff7b699015f70cf80a8763bf705bc2e2af0c1b39cff718b7c35880ca30f319078d91b03389a006fdfc8a1dcd84edfa07d30aa13474a248a0dab5baaa3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e0416041445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d04030203480030450220483063b6bb08dcc83da33a02c11d2f42203176893554d138c614a36908724cc8022100f5ef2c912d4500b3e2f5b591d0622491e9f220dfd1f9734ec484bb7e90887663";

// --- Helpers -----------------------------------------------------------------------------

fn now() -> Timestamp {
    MockClock::fixed().now()
}

fn relying_party(anchors: Vec<Vec<u8>>) -> RelyingParty {
    let mut config = RpConfig::for_host(RP_HOST);
    config.trust_anchors = anchors;
    RelyingParty::new(config).expect("relying party")
}

fn soft_root() -> Vec<u8> {
    SoftAuthenticator::attestation_root_der()
}

fn w3c_root() -> Vec<u8> {
    hex_decode(W3C_ROOT).expect("the W3C root is hexadecimal")
}

fn hardware_registration() -> RegistrationPolicy {
    RegistrationPolicy {
        hardware_key_required: true,
        ..RegistrationPolicy::default()
    }
}

fn hardware_assertion() -> AssertionPolicy {
    AssertionPolicy {
        hardware_key_required: true,
        ..AssertionPolicy::default()
    }
}

fn cose_id(alg: SoftKeyAlg) -> i64 {
    match alg {
        SoftKeyAlg::Es256 => ALG_ES256,
        SoftKeyAlg::Ed25519 => ALG_EDDSA,
        SoftKeyAlg::Rs256 => ALG_RS256,
    }
}

fn registration_response(
    rp: &RelyingParty,
    authenticator: &mut SoftAuthenticator,
    user: &[u8],
    origin: &str,
    tweaks: &Tweaks,
    policy: RegistrationPolicy,
) -> RegistrationResponse {
    let options = rp.creation_options(
        user,
        "alice",
        "Alice Example",
        &REGISTRATION_CHALLENGE,
        Vec::new(),
        &policy,
    );
    authenticator.register_with(&options, origin, tweaks)
}

fn finish_registration(
    rp: &RelyingParty,
    response: &RegistrationResponse,
    policy: RegistrationPolicy,
) -> Result<RegisteredCredential, WebAuthnError> {
    rp.finish_registration(response, &REGISTRATION_CHALLENGE, &policy, now())
}

/// An honest registration of `user`.
fn register_user(
    rp: &RelyingParty,
    authenticator: &mut SoftAuthenticator,
    user: &[u8],
    policy: RegistrationPolicy,
) -> Result<RegisteredCredential, WebAuthnError> {
    let response =
        registration_response(rp, authenticator, user, ORIGIN, &Tweaks::default(), policy);
    finish_registration(rp, &response, policy)
}

/// An honest registration of the standard user.
fn register(
    rp: &RelyingParty,
    authenticator: &mut SoftAuthenticator,
    policy: RegistrationPolicy,
) -> Result<RegisteredCredential, WebAuthnError> {
    register_user(rp, authenticator, USER_ID, policy)
}

fn request_options(
    rp: &RelyingParty,
    allow: Vec<CredentialDescriptor>,
    policy: AssertionPolicy,
) -> RequestOptions {
    rp.request_options(&AUTHENTICATION_CHALLENGE, allow, &policy)
}

fn allow(credential_id: &[u8]) -> Vec<CredentialDescriptor> {
    vec![CredentialDescriptor::new(credential_id, Vec::new())]
}

/// What a service stores of a credential, and updates after a login.
struct Account {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    sign_count: u32,
    backup_eligible: bool,
}

impl Account {
    fn new(credential: &RegisteredCredential) -> Self {
        Self {
            credential_id: credential.credential_id.clone(),
            public_key: credential.public_key.clone(),
            sign_count: credential.sign_count,
            backup_eligible: credential.backup_eligible,
        }
    }

    fn stored(&self) -> StoredKey<'_> {
        StoredKey {
            credential_id: &self.credential_id,
            public_key: &self.public_key,
            sign_count: self.sign_count,
            backup_eligible: self.backup_eligible,
        }
    }
}

/// A relying party, an authenticator and the account its first credential created.
struct Fixture {
    rp: RelyingParty,
    authenticator: SoftAuthenticator,
    account: Account,
}

impl Fixture {
    fn new(mut authenticator: SoftAuthenticator) -> Self {
        let rp = relying_party(Vec::new());
        let credential = register(&rp, &mut authenticator, RegistrationPolicy::default())
            .expect("an honest registration succeeds");
        let account = Account::new(&credential);
        Self {
            rp,
            authenticator,
            account,
        }
    }

    /// ES256 without attestation, the plainest passkey.
    fn plain() -> Self {
        Self::new(SoftAuthenticator::new(
            SoftKeyAlg::Es256,
            SoftAttestation::None,
        ))
    }

    fn response(
        &mut self,
        origin: &str,
        tweaks: &Tweaks,
        policy: AssertionPolicy,
    ) -> AuthenticationResponse {
        let options = request_options(&self.rp, allow(&self.account.credential_id), policy);
        self.authenticator.assert_with(&options, origin, tweaks)
    }

    /// Verifies `response`; on success the stored counter moves on, as a service does.
    fn verify(
        &mut self,
        response: &AuthenticationResponse,
        policy: AssertionPolicy,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        let verified = self.rp.finish_assertion(
            response,
            &AUTHENTICATION_CHALLENGE,
            &self.account.stored(),
            &policy,
        )?;
        self.account.sign_count = verified.sign_count;
        Ok(verified)
    }

    fn login_with(
        &mut self,
        origin: &str,
        tweaks: &Tweaks,
        policy: AssertionPolicy,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        let response = self.response(origin, tweaks, policy);
        self.verify(&response, policy)
    }

    fn login(&mut self, tweaks: &Tweaks) -> Result<VerifiedAssertion, WebAuthnError> {
        self.login_with(ORIGIN, tweaks, AssertionPolicy::default())
    }
}

/// The error of a registration of the plain authenticator bent by `tweaks`.
fn registration_error(tweaks: &Tweaks) -> WebAuthnError {
    registration_error_with(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None),
        ORIGIN,
        tweaks,
        RegistrationPolicy::default(),
    )
}

fn registration_error_with(
    mut authenticator: SoftAuthenticator,
    origin: &str,
    tweaks: &Tweaks,
    policy: RegistrationPolicy,
) -> WebAuthnError {
    let rp = relying_party(Vec::new());
    let response = registration_response(&rp, &mut authenticator, USER_ID, origin, tweaks, policy);
    finish_registration(&rp, &response, policy).expect_err("the registration must be refused")
}

/// The error of a login of the plain authenticator bent by `tweaks`.
fn assertion_error(tweaks: &Tweaks) -> WebAuthnError {
    Fixture::plain()
        .login(tweaks)
        .expect_err("the assertion must be refused")
}

/// The members of a CBOR map by text key.
fn member<'a>(map: &'a [(Value, Value)], name: &str) -> &'a Value {
    let Some((_, value)) = map.iter().find(|(key, _)| key.as_text() == Some(name)) else {
        panic!("the map has no `{name}`");
    };
    value
}

fn attestation_object(response: &RegistrationResponse) -> Vec<(Value, Value)> {
    let bytes = base64url_decode(&response.response.attestation_object).expect("base64url");
    let value: Value = ciborium::de::from_reader(bytes.as_slice()).expect("CBOR");
    value.into_map().expect("the attestation object is a map")
}

fn bytes_of(value: &Value) -> &[u8] {
    value.as_bytes().expect("a byte string")
}

fn integer_of(value: &Value) -> i64 {
    let integer = value.as_integer().expect("an integer");
    i64::try_from(i128::from(integer)).expect("a small integer")
}

fn text_of(encoded: &str) -> String {
    String::from_utf8(base64url_decode(encoded).expect("base64url")).expect("UTF-8")
}

// --- Registration then assertion, for every algorithm and attestation --------------------

fn registration_then_assertion(alg: SoftKeyAlg, attestation: SoftAttestation) {
    let rp = relying_party(Vec::new());
    let mut authenticator = SoftAuthenticator::new(alg, attestation);
    let credential =
        register(&rp, &mut authenticator, RegistrationPolicy::default()).expect("registration");

    assert_eq!(credential.alg, cose_id(alg));
    assert_eq!(credential.aaguid, authenticator.aaguid());
    assert_eq!(
        Some(credential.credential_id.clone()),
        authenticator.last_credential_id()
    );
    assert_eq!(credential.credential_id.len(), 32);
    assert!(credential.user_verified);
    assert!(!credential.backup_eligible);
    assert!(!credential.backup_state);
    assert_eq!(credential.sign_count, 0);
    assert_eq!(
        CoseKey::parse(&credential.public_key)
            .expect("COSE key")
            .alg(),
        cose_id(alg)
    );
    match attestation {
        SoftAttestation::None => assert_eq!(credential.attestation, AttestationKind::None),
        SoftAttestation::PackedSelf => {
            assert_eq!(credential.attestation, AttestationKind::SelfAttestation);
        }
        SoftAttestation::PackedCertificate => assert!(matches!(
            &credential.attestation,
            AttestationKind::Certificate { anchored: false, subject, .. }
                if subject == "Tenko Soft Authenticator"
        )),
    }
    assert_eq!(
        credential.hardware_key,
        attestation == SoftAttestation::PackedCertificate
    );

    // The stored key verifies later assertions, and the stored counter moves up.
    let mut account = Account::new(&credential);
    for expected in 1..=3_u32 {
        let options = request_options(
            &rp,
            allow(&account.credential_id),
            AssertionPolicy::default(),
        );
        let response = authenticator.assert(&options, ORIGIN);
        assert_eq!(
            assertion_credential_id(&response).expect("credential id"),
            account.credential_id
        );
        let verified = rp
            .finish_assertion(
                &response,
                &AUTHENTICATION_CHALLENGE,
                &account.stored(),
                &AssertionPolicy::default(),
            )
            .expect("assertion");
        assert_eq!(verified.sign_count, expected);
        assert!(verified.user_verified);
        assert!(!verified.backup_state);
        assert_eq!(verified.user_handle.as_deref(), Some(&USER_ID[..]));
        account.sign_count = verified.sign_count;
    }
}

macro_rules! ceremony_tests {
    ($($name:ident: $alg:expr, $attestation:expr;)*) => {
        $(
            #[test]
            fn $name() {
                registration_then_assertion($alg, $attestation);
            }
        )*
    };
}

ceremony_tests! {
    es256_with_no_attestation: SoftKeyAlg::Es256, SoftAttestation::None;
    es256_with_packed_self_attestation: SoftKeyAlg::Es256, SoftAttestation::PackedSelf;
    es256_with_packed_certificate_attestation: SoftKeyAlg::Es256, SoftAttestation::PackedCertificate;
    ed25519_with_no_attestation: SoftKeyAlg::Ed25519, SoftAttestation::None;
    ed25519_with_packed_self_attestation: SoftKeyAlg::Ed25519, SoftAttestation::PackedSelf;
    ed25519_with_packed_certificate_attestation: SoftKeyAlg::Ed25519, SoftAttestation::PackedCertificate;
    rs256_with_no_attestation: SoftKeyAlg::Rs256, SoftAttestation::None;
    rs256_with_packed_self_attestation: SoftKeyAlg::Rs256, SoftAttestation::PackedSelf;
    rs256_with_packed_certificate_attestation: SoftKeyAlg::Rs256, SoftAttestation::PackedCertificate;
}

#[test]
fn a_new_registration_creates_a_new_credential() {
    let rp = relying_party(Vec::new());
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let first = register(&rp, &mut authenticator, RegistrationPolicy::default()).expect("first");
    let second = register(&rp, &mut authenticator, RegistrationPolicy::default()).expect("second");
    assert_ne!(first.credential_id, second.credential_id);
    assert_ne!(first.public_key, second.public_key);
    assert_eq!(
        Some(second.credential_id),
        authenticator.last_credential_id()
    );
}

#[test]
fn sign_counts_are_stored_and_increase() {
    let mut fixture = Fixture::plain();
    assert_eq!(fixture.account.sign_count, 0);
    for expected in 1..=5_u32 {
        let verified = fixture.login(&Tweaks::default()).expect("login");
        assert_eq!(verified.sign_count, expected);
        assert_eq!(fixture.account.sign_count, expected);
    }
}

#[test]
fn a_disabled_counter_stays_at_zero_and_passes() {
    let mut fixture = Fixture::new(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).counter(false),
    );
    assert_eq!(fixture.account.sign_count, 0);
    for _ in 0..3 {
        let verified = fixture
            .login(&Tweaks::default())
            .expect("counters 0 and 0 pass");
        assert_eq!(verified.sign_count, 0);
    }
}

#[test]
fn every_instance_has_its_own_aaguid_and_shares_the_root() {
    let first = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate);
    let second = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate);
    assert_ne!(first.aaguid(), second.aaguid());
    assert_eq!(
        SoftAuthenticator::attestation_root_der(),
        SoftAuthenticator::attestation_root_der()
    );
    TrustAnchor::from_der(soft_root()).expect("the soft root is a certificate");
    assert!(first.last_credential_id().is_none());
}

// --- Discoverable login ------------------------------------------------------------------

#[test]
fn discoverable_login_returns_the_user_handle() {
    for alg in ALGORITHMS {
        let rp = relying_party(Vec::new());
        let mut authenticator = SoftAuthenticator::new(alg, SoftAttestation::None);
        let credential =
            register(&rp, &mut authenticator, RegistrationPolicy::default()).expect("registration");

        let options = request_options(&rp, Vec::new(), AssertionPolicy::default());
        assert_eq!(
            options.allow_credentials,
            Vec::<CredentialDescriptor>::new()
        );
        let response = authenticator.assert(&options, ORIGIN);
        assert_eq!(
            response.response.user_handle.as_deref(),
            Some(base64url_encode(USER_ID).as_str())
        );
        // The service finds the credential by id, then verifies and checks the handle.
        let id = assertion_credential_id(&response).expect("credential id");
        assert_eq!(id, credential.credential_id);
        let account = Account::new(&credential);
        let verified = rp
            .finish_assertion(
                &response,
                &AUTHENTICATION_CHALLENGE,
                &account.stored(),
                &AssertionPolicy::default(),
            )
            .expect("assertion");
        assert_eq!(verified.user_handle.as_deref(), Some(&USER_ID[..]));
    }
}

#[test]
fn discoverable_login_uses_the_latest_credential_and_the_allow_list_selects() {
    let rp = relying_party(Vec::new());
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Ed25519, SoftAttestation::None);
    let first = register_user(
        &rp,
        &mut authenticator,
        &[1; 16],
        RegistrationPolicy::default(),
    )
    .expect("first user");
    let second = register_user(
        &rp,
        &mut authenticator,
        &[2; 16],
        RegistrationPolicy::default(),
    )
    .expect("second user");

    let discoverable = authenticator.assert(
        &request_options(&rp, Vec::new(), AssertionPolicy::default()),
        ORIGIN,
    );
    assert_eq!(
        assertion_credential_id(&discoverable).expect("id"),
        second.credential_id
    );
    let verified = rp
        .finish_assertion(
            &discoverable,
            &AUTHENTICATION_CHALLENGE,
            &Account::new(&second).stored(),
            &AssertionPolicy::default(),
        )
        .expect("assertion");
    assert_eq!(verified.user_handle, Some(vec![2; 16]));

    // The first credential is selected by the allow list, an unknown id is skipped.
    let mut allowed = allow(&[9; 32]);
    allowed.extend(allow(&first.credential_id));
    let selected = authenticator.assert(
        &request_options(&rp, allowed, AssertionPolicy::default()),
        ORIGIN,
    );
    assert_eq!(
        assertion_credential_id(&selected).expect("id"),
        first.credential_id
    );
    let verified = rp
        .finish_assertion(
            &selected,
            &AUTHENTICATION_CHALLENGE,
            &Account::new(&first).stored(),
            &AssertionPolicy::default(),
        )
        .expect("assertion");
    assert_eq!(verified.user_handle, Some(vec![1; 16]));
}

// --- Wire format of the software authenticator -------------------------------------------

#[test]
fn registration_responses_follow_the_wire_format() {
    for alg in ALGORITHMS {
        for attestation in ATTESTATIONS {
            check_registration_wire_format(alg, attestation);
        }
    }
}

fn check_registration_wire_format(alg: SoftKeyAlg, attestation: SoftAttestation) {
    let rp = relying_party(Vec::new());
    let mut authenticator = SoftAuthenticator::new(alg, attestation);
    let policy = RegistrationPolicy::default();
    let options = rp.creation_options(
        USER_ID,
        "alice",
        "Alice",
        &REGISTRATION_CHALLENGE,
        vec![],
        &policy,
    );
    let response = authenticator.register(&options, ORIGIN);

    assert_eq!(response.type_, "public-key");
    assert_eq!(response.id, response.raw_id);
    assert_eq!(
        text_of(&response.response.client_data_json),
        format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
            options.challenge
        )
    );

    let object = attestation_object(&response);
    assert_eq!(object.len(), 3);
    let auth_data = bytes_of(member(&object, "authData"));
    assert_eq!(auth_data[..32], Sha256::digest(RP_HOST.as_bytes())[..]);
    assert_eq!(
        auth_data[32],
        Flags::USER_PRESENT | Flags::USER_VERIFIED | Flags::ATTESTED
    );
    assert_eq!(auth_data[33..37], [0, 0, 0, 0]);
    assert_eq!(auth_data[37..53], authenticator.aaguid());
    assert_eq!(auth_data[53..55], [0, 32]);
    let credential_id = base64url_decode(&response.id).expect("id");
    assert_eq!(auth_data[55..87], credential_id[..]);
    check_cose_key(alg, &auth_data[87..]);

    let statement = member(&object, "attStmt")
        .as_map()
        .expect("attStmt is a map");
    let format = member(&object, "fmt").as_text().expect("fmt is text");
    match attestation {
        SoftAttestation::None => {
            assert_eq!(format, "none");
            assert_eq!(statement.len(), 0);
        }
        SoftAttestation::PackedSelf => {
            assert_eq!(format, "packed");
            assert_eq!(statement.len(), 2);
            assert_eq!(integer_of(member(statement, "alg")), cose_id(alg));
            assert_ne!(bytes_of(member(statement, "sig")).len(), 0);
        }
        SoftAttestation::PackedCertificate => {
            assert_eq!(format, "packed");
            assert_eq!(statement.len(), 3);
            assert_eq!(integer_of(member(statement, "alg")), ALG_ES256);
            assert_ne!(bytes_of(member(statement, "sig")).len(), 0);
            let chain = member(statement, "x5c")
                .as_array()
                .expect("x5c is an array");
            assert_eq!(chain.len(), 1);
            assert_eq!(bytes_of(&chain[0])[0], 0x30);
        }
    }
}

/// The COSE key in `encoded`: integer labels in canonical order, the right members.
fn check_cose_key(alg: SoftKeyAlg, encoded: &[u8]) {
    let mut reader = encoded;
    let value: Value = ciborium::de::from_reader(&mut reader).expect("COSE key");
    assert!(reader.is_empty(), "nothing follows the COSE key");
    let entries = value.into_map().expect("a map");
    let labels: Vec<i64> = entries.iter().map(|(label, _)| integer_of(label)).collect();
    let value_of = |label: i64| {
        &entries
            .iter()
            .find(|(key, _)| integer_of(key) == label)
            .expect("label")
            .1
    };
    match alg {
        SoftKeyAlg::Es256 => {
            assert_eq!(labels, [1, 3, -1, -2, -3]);
            assert_eq!(integer_of(value_of(1)), 2);
            assert_eq!(integer_of(value_of(3)), ALG_ES256);
            assert_eq!(integer_of(value_of(-1)), 1);
            assert_eq!(bytes_of(value_of(-2)).len(), 32);
            assert_eq!(bytes_of(value_of(-3)).len(), 32);
        }
        SoftKeyAlg::Ed25519 => {
            assert_eq!(labels, [1, 3, -1, -2]);
            assert_eq!(integer_of(value_of(1)), 1);
            assert_eq!(integer_of(value_of(3)), ALG_EDDSA);
            assert_eq!(integer_of(value_of(-1)), 6);
            assert_eq!(bytes_of(value_of(-2)).len(), 32);
        }
        SoftKeyAlg::Rs256 => {
            assert_eq!(labels, [1, 3, -1, -2]);
            assert_eq!(integer_of(value_of(1)), 3);
            assert_eq!(integer_of(value_of(3)), ALG_RS256);
            assert_eq!(bytes_of(value_of(-1)).len(), 256);
            assert_ne!(bytes_of(value_of(-1))[0], 0);
            assert_eq!(bytes_of(value_of(-2)), [0x01, 0x00, 0x01]);
        }
    }
}

#[test]
fn assertion_responses_follow_the_wire_format() {
    for alg in ALGORITHMS {
        let mut fixture = Fixture::new(SoftAuthenticator::new(alg, SoftAttestation::None));
        let response = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());
        assert_eq!(response.type_, "public-key");
        assert_eq!(response.id, response.raw_id);
        assert_eq!(
            text_of(&response.response.client_data_json),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
                base64url_encode(&AUTHENTICATION_CHALLENGE)
            )
        );
        let auth_data = base64url_decode(&response.response.authenticator_data).expect("base64url");
        assert_eq!(
            auth_data.len(),
            37,
            "no attested credential data in an assertion"
        );
        assert_eq!(auth_data[..32], Sha256::digest(RP_HOST.as_bytes())[..]);
        assert_eq!(auth_data[32], Flags::USER_PRESENT | Flags::USER_VERIFIED);
        assert_eq!(auth_data[33..37], [0, 0, 0, 1]);
        assert!(response.response.user_handle.is_some());
    }
}

#[test]
fn tweaks_change_only_what_they_name() {
    let mut fixture = Fixture::plain();
    let tweaks = Tweaks {
        ceremony_type: Some("webauthn.create".to_owned()),
        origin: Some("https://other.example.test".to_owned()),
        challenge: Some(vec![1, 2, 3]),
        cross_origin: Some(true),
        top_origin: Some(ORIGIN.to_owned()),
        ..Tweaks::default()
    };
    let response = fixture.response(ORIGIN, &tweaks, AssertionPolicy::default());
    assert_eq!(
        text_of(&response.response.client_data_json),
        concat!(
            r#"{"type":"webauthn.create","challenge":"AQID","#,
            r#""origin":"https://other.example.test","crossOrigin":true,"#,
            r#""topOrigin":"https://tenko.example.test"}"#
        )
    );
    // The flags byte: set bits first, then cleared bits.
    let tweaks = Tweaks {
        set_flags: Flags::BACKUP_ELIGIBLE | Flags::BACKUP_STATE,
        clear_flags: Flags::USER_VERIFIED | Flags::BACKUP_STATE,
        sign_count: Some(0x0102_0304),
        ..Tweaks::default()
    };
    let response = fixture.response(ORIGIN, &tweaks, AssertionPolicy::default());
    let auth_data = base64url_decode(&response.response.authenticator_data).expect("base64url");
    assert_eq!(auth_data[32], Flags::USER_PRESENT | Flags::BACKUP_ELIGIBLE);
    assert_eq!(auth_data[33..37], [1, 2, 3, 4]);
}

// --- Strength of a credential ------------------------------------------------------------

fn certificate_authenticator() -> SoftAuthenticator {
    SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate)
}

#[test]
fn a_certificate_without_backup_is_a_hardware_key_without_trust_anchors() {
    let rp = relying_party(Vec::new());
    let credential = register(
        &rp,
        &mut certificate_authenticator(),
        RegistrationPolicy::default(),
    )
    .expect("registration");
    assert!(credential.hardware_key);
    assert!(matches!(
        credential.attestation,
        AttestationKind::Certificate {
            anchored: false,
            ..
        }
    ));
}

#[test]
fn a_certificate_chaining_to_the_soft_root_is_anchored() {
    let rp = relying_party(vec![soft_root()]);
    let mut authenticator = certificate_authenticator();
    let policy = RegistrationPolicy::default();
    let response = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );
    let credential = finish_registration(&rp, &response, policy).expect("registration");
    assert!(credential.hardware_key);

    let object = attestation_object(&response);
    let statement = member(&object, "attStmt").as_map().expect("attStmt");
    let leaf = bytes_of(&member(statement, "x5c").as_array().expect("x5c")[0]).to_vec();
    let AttestationKind::Certificate {
        anchored,
        certificate_sha256,
        subject,
    } = &credential.attestation
    else {
        panic!(
            "expected certificate attestation, got {:?}",
            credential.attestation
        );
    };
    assert!(*anchored);
    assert_eq!(subject, "Tenko Soft Authenticator");
    assert_eq!(*certificate_sha256, hex_encode(&Sha256::digest(&leaf)));

    // The same account passes the hardware-key policy on top.
    let mut again = certificate_authenticator();
    let verified = register(&rp, &mut again, hardware_registration()).expect("hardware key");
    assert!(verified.hardware_key);
}

#[test]
fn the_w3c_root_does_not_anchor_a_soft_certificate() {
    let rp = relying_party(vec![w3c_root()]);
    let credential = register(
        &rp,
        &mut certificate_authenticator(),
        RegistrationPolicy::default(),
    )
    .expect("registration");
    assert!(matches!(
        credential.attestation,
        AttestationKind::Certificate {
            anchored: false,
            ..
        }
    ));
    assert!(!credential.hardware_key);

    let refused = register(
        &rp,
        &mut certificate_authenticator(),
        hardware_registration(),
    )
    .expect_err("an untrusted attestation is refused");
    assert_eq!(refused, WebAuthnError::AttestationUntrusted);
}

#[test]
fn the_soft_root_anchors_next_to_other_roots() {
    let rp = relying_party(vec![w3c_root(), soft_root()]);
    let credential = register(
        &rp,
        &mut certificate_authenticator(),
        hardware_registration(),
    )
    .expect("registration");
    assert!(credential.hardware_key);
    assert!(matches!(
        credential.attestation,
        AttestationKind::Certificate { anchored: true, .. }
    ));
}

#[test]
fn a_backup_eligible_credential_is_not_a_hardware_key() {
    for (eligible, state) in [(true, false), (true, true)] {
        for anchors in [Vec::new(), vec![soft_root()]] {
            let rp = relying_party(anchors);
            let mut authenticator = certificate_authenticator().backup(eligible, state);
            let credential = register(&rp, &mut authenticator, RegistrationPolicy::default())
                .expect("registration");
            assert!(!credential.hardware_key);
            assert!(credential.backup_eligible);
            assert_eq!(credential.backup_state, state);
        }
    }
}

#[test]
fn a_synced_passkey_is_refused_for_a_hardware_key_account() {
    for state in [false, true] {
        let rp = relying_party(vec![soft_root()]);
        let mut authenticator = certificate_authenticator().backup(true, state);
        let refused = register(&rp, &mut authenticator, hardware_registration())
            .expect_err("a synced passkey is refused");
        assert_eq!(refused, WebAuthnError::BackupEligibleRefused);
    }
}

#[test]
fn a_backup_eligible_assertion_is_refused_for_a_hardware_key_account() {
    // Registered under the ordinary policy, so the stored credential is backup eligible.
    let mut fixture = Fixture::new(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate)
            .backup(true, true),
    );
    assert!(fixture.account.backup_eligible);
    let refused = fixture
        .login_with(ORIGIN, &Tweaks::default(), hardware_assertion())
        .expect_err("the assertion carries BE");
    assert_eq!(refused, WebAuthnError::BackupEligibleRefused);
    // The ordinary policy accepts the same authenticator.
    let verified = fixture.login(&Tweaks::default()).expect("ordinary login");
    assert!(verified.backup_state);

    // A real hardware key passes the hardware policy.
    let mut key = Fixture::new(certificate_authenticator());
    key.login_with(ORIGIN, &Tweaks::default(), hardware_assertion())
        .expect("hardware key login");
}

#[test]
fn a_hardware_key_account_needs_certificate_attestation() {
    for alg in ALGORITHMS {
        for attestation in [SoftAttestation::None, SoftAttestation::PackedSelf] {
            let rp = relying_party(vec![soft_root()]);
            let mut authenticator = SoftAuthenticator::new(alg, attestation);
            let refused = register(&rp, &mut authenticator, hardware_registration())
                .expect_err("only certificate attestation counts");
            assert_eq!(
                refused,
                WebAuthnError::AttestationRequired,
                "{alg:?} {attestation:?}"
            );
        }
    }
}

#[test]
fn creation_and_request_options_follow_the_policy() {
    let rp = relying_party(Vec::new());
    let ordinary = RegistrationPolicy::default();
    let options = rp.creation_options(
        USER_ID,
        "alice",
        "Alice",
        &REGISTRATION_CHALLENGE,
        vec![],
        &ordinary,
    );
    assert_eq!(options.attestation, "none");
    assert_eq!(options.authenticator_selection.resident_key, "required");
    assert!(options.authenticator_selection.require_resident_key);
    assert_eq!(
        options.authenticator_selection.authenticator_attachment,
        None
    );
    assert_eq!(options.hints, Vec::<String>::new());

    let hardware = hardware_registration();
    let options = rp.creation_options(
        USER_ID,
        "alice",
        "Alice",
        &REGISTRATION_CHALLENGE,
        vec![],
        &hardware,
    );
    assert_eq!(options.attestation, "direct");
    assert_eq!(
        options
            .authenticator_selection
            .authenticator_attachment
            .as_deref(),
        Some("cross-platform")
    );
    assert_eq!(options.hints, ["security-key"]);
    assert_eq!(options.user.id, base64url_encode(USER_ID));

    assert_eq!(
        request_options(&rp, Vec::new(), AssertionPolicy::default()).hints,
        Vec::<String>::new()
    );
    assert_eq!(
        request_options(&rp, Vec::new(), hardware_assertion()).hints,
        ["security-key"]
    );
}

#[test]
fn the_attestation_certificate_is_only_valid_in_its_validity_period() {
    let rp = relying_party(vec![soft_root()]);
    let policy = RegistrationPolicy::default();
    let at = |unix: i128| Timestamp::from_unix_nanos(unix * 1_000_000_000).expect("timestamp");
    let register_at = |unix: i128| {
        let mut authenticator = certificate_authenticator();
        let response = registration_response(
            &rp,
            &mut authenticator,
            USER_ID,
            ORIGIN,
            &Tweaks::default(),
            policy,
        );
        rp.finish_registration(&response, &REGISTRATION_CHALLENGE, &policy, at(unix))
    };
    // 2024-01-01T00:00:00Z to 2099-12-31T23:59:59Z, both ends included.
    assert!(register_at(1_704_067_200).is_ok());
    assert!(register_at(4_102_444_799).is_ok());
    for unix in [1_704_067_199, 4_102_444_800] {
        let refused = register_at(unix).expect_err("outside the validity period");
        assert!(
            matches!(refused, WebAuthnError::AttestationInvalid(_)),
            "{refused:?}"
        );
    }
}

// --- One negative test per check ---------------------------------------------------------

#[test]
fn a_wrong_ceremony_type_is_refused() {
    let tweaks = Tweaks {
        ceremony_type: Some("webauthn.get".to_owned()),
        ..Tweaks::default()
    };
    assert_eq!(registration_error(&tweaks), WebAuthnError::WrongCeremony);
    let tweaks = Tweaks {
        ceremony_type: Some("webauthn.create".to_owned()),
        ..Tweaks::default()
    };
    assert_eq!(assertion_error(&tweaks), WebAuthnError::WrongCeremony);
}

#[test]
fn a_wrong_challenge_is_refused() {
    for challenge in [
        vec![0; 32],
        vec![0xa5; 31],
        vec![0xa5; 33],
        REGISTRATION_CHALLENGE[..16].to_vec(),
    ] {
        let tweaks = Tweaks {
            challenge: Some(challenge),
            ..Tweaks::default()
        };
        assert_eq!(
            registration_error(&tweaks),
            WebAuthnError::ChallengeMismatch
        );
        assert_eq!(assertion_error(&tweaks), WebAuthnError::ChallengeMismatch);
    }
    // The challenge of the other ceremony is no better.
    let tweaks = Tweaks {
        challenge: Some(REGISTRATION_CHALLENGE.to_vec()),
        ..Tweaks::default()
    };
    assert_eq!(assertion_error(&tweaks), WebAuthnError::ChallengeMismatch);
}

#[test]
fn a_foreign_origin_is_refused() {
    for origin in [
        "https://evil.example.test",
        "http://tenko.example.test",
        // `RpConfig::for_host` accepts the host on any port (`https://host:*`), but not a
        // longer host name or another scheme.
        "https://tenko.example.test.evil.test",
        "https://tenko.example.test:8443x",
        "https://example.test",
        "",
    ] {
        let expected = WebAuthnError::OriginMismatch(origin.to_owned());
        // Through the origin of the page, and through the client data tweak.
        let refused = registration_error_with(
            SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None),
            origin,
            &Tweaks::default(),
            RegistrationPolicy::default(),
        );
        assert_eq!(refused, expected);
        let tweaks = Tweaks {
            origin: Some(origin.to_owned()),
            ..Tweaks::default()
        };
        assert_eq!(registration_error(&tweaks), expected);
        assert_eq!(assertion_error(&tweaks), expected);
        let refused = Fixture::plain()
            .login_with(origin, &Tweaks::default(), AssertionPolicy::default())
            .expect_err("the origin is foreign");
        assert_eq!(refused, expected);
    }
}

#[test]
fn cross_origin_ceremonies_are_refused() {
    let cross_origin = Tweaks {
        cross_origin: Some(true),
        ..Tweaks::default()
    };
    let top_origin = Tweaks {
        top_origin: Some(ORIGIN.to_owned()),
        ..Tweaks::default()
    };
    let both = Tweaks {
        cross_origin: Some(true),
        top_origin: Some("https://evil.example.test".to_owned()),
        ..Tweaks::default()
    };
    for tweaks in [cross_origin, top_origin, both] {
        assert_eq!(registration_error(&tweaks), WebAuthnError::CrossOrigin);
        assert_eq!(assertion_error(&tweaks), WebAuthnError::CrossOrigin);
    }
    // An explicit `crossOrigin: false` is the normal case.
    let explicit = Tweaks {
        cross_origin: Some(false),
        ..Tweaks::default()
    };
    Fixture::plain()
        .login(&explicit)
        .expect("crossOrigin false is fine");
}

#[test]
fn the_rp_id_hash_of_another_rp_is_refused() {
    for rp_id in [
        "evil.example.test",
        "example.test",
        "tenko.example.test.",
        "TENKO.EXAMPLE.TEST",
    ] {
        let tweaks = Tweaks {
            rp_id: Some(rp_id.to_owned()),
            ..Tweaks::default()
        };
        assert_eq!(
            registration_error(&tweaks),
            WebAuthnError::RpIdMismatch,
            "{rp_id}"
        );
        assert_eq!(
            assertion_error(&tweaks),
            WebAuthnError::RpIdMismatch,
            "{rp_id}"
        );
    }
}

#[test]
fn missing_user_presence_is_refused() {
    let tweaks = Tweaks {
        clear_flags: Flags::USER_PRESENT,
        ..Tweaks::default()
    };
    assert_eq!(
        registration_error(&tweaks),
        WebAuthnError::UserPresenceMissing
    );
    assert_eq!(assertion_error(&tweaks), WebAuthnError::UserPresenceMissing);
}

#[test]
fn missing_user_verification_is_refused_only_when_required() {
    let unverified =
        || SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).user_verifying(false);
    // Registration.
    let refused = registration_error_with(
        unverified(),
        ORIGIN,
        &Tweaks::default(),
        RegistrationPolicy::default(),
    );
    assert_eq!(refused, WebAuthnError::UserVerificationMissing);
    for user_verification in [UserVerification::Preferred, UserVerification::Discouraged] {
        let policy = RegistrationPolicy {
            user_verification,
            ..RegistrationPolicy::default()
        };
        let rp = relying_party(Vec::new());
        let credential = register(&rp, &mut unverified(), policy).expect("UV is not enforced");
        assert!(!credential.user_verified);
    }

    // Assertion: the credential exists, the later assertions lack UV.
    let rp = relying_party(Vec::new());
    let mut authenticator = unverified();
    let policy = RegistrationPolicy {
        user_verification: UserVerification::Preferred,
        ..RegistrationPolicy::default()
    };
    let credential = register(&rp, &mut authenticator, policy).expect("registration");
    let mut fixture = Fixture {
        rp,
        authenticator,
        account: Account::new(&credential),
    };
    let refused = fixture
        .login(&Tweaks::default())
        .expect_err("the default policy requires user verification");
    assert_eq!(refused, WebAuthnError::UserVerificationMissing);
    for user_verification in [UserVerification::Preferred, UserVerification::Discouraged] {
        let policy = AssertionPolicy {
            user_verification,
            ..AssertionPolicy::default()
        };
        let verified = fixture
            .login_with(ORIGIN, &Tweaks::default(), policy)
            .expect("UV is not enforced");
        assert!(!verified.user_verified);
    }
    // A flag cleared by tweak behaves the same.
    let tweaks = Tweaks {
        clear_flags: Flags::USER_VERIFIED,
        ..Tweaks::default()
    };
    assert_eq!(
        registration_error(&tweaks),
        WebAuthnError::UserVerificationMissing
    );
    assert_eq!(
        assertion_error(&tweaks),
        WebAuthnError::UserVerificationMissing
    );
}

#[test]
fn backup_state_without_backup_eligibility_is_refused() {
    let refused = registration_error_with(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).backup(false, true),
        ORIGIN,
        &Tweaks::default(),
        RegistrationPolicy::default(),
    );
    assert_eq!(refused, WebAuthnError::BackupFlagsInvalid);

    let mut fixture = Fixture::plain();
    let tweaks = Tweaks {
        set_flags: Flags::BACKUP_STATE,
        ..Tweaks::default()
    };
    assert_eq!(
        fixture.login(&tweaks).expect_err("BS without BE"),
        WebAuthnError::BackupFlagsInvalid
    );
    // The same on a backup-eligible credential that loses BE but keeps BS.
    let mut synced = Fixture::new(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).backup(true, true),
    );
    let tweaks = Tweaks {
        clear_flags: Flags::BACKUP_ELIGIBLE,
        ..Tweaks::default()
    };
    assert_eq!(
        synced.login(&tweaks).expect_err("BS without BE"),
        WebAuthnError::BackupFlagsInvalid
    );
}

#[test]
fn a_changed_backup_eligibility_is_refused_at_assertion() {
    // Registered without BE, asserted with BE.
    let mut plain = Fixture::plain();
    let tweaks = Tweaks {
        set_flags: Flags::BACKUP_ELIGIBLE,
        ..Tweaks::default()
    };
    assert_eq!(
        plain.login(&tweaks).expect_err("BE appeared"),
        WebAuthnError::BackupFlagsInvalid
    );

    // Registered with BE (not backed up yet), asserted without BE.
    let mut eligible = Fixture::new(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).backup(true, false),
    );
    assert!(eligible.account.backup_eligible);
    let tweaks = Tweaks {
        clear_flags: Flags::BACKUP_ELIGIBLE,
        ..Tweaks::default()
    };
    assert_eq!(
        eligible.login(&tweaks).expect_err("BE vanished"),
        WebAuthnError::BackupFlagsInvalid
    );

    // BS may change freely while BE stays: the credential got synced in the meantime.
    let tweaks = Tweaks {
        set_flags: Flags::BACKUP_STATE,
        ..Tweaks::default()
    };
    let verified = eligible.login(&tweaks).expect("BS changes are allowed");
    assert!(verified.backup_state);
}

#[test]
fn a_corrupted_assertion_signature_is_refused() {
    for alg in ALGORITHMS {
        let mut fixture = Fixture::new(SoftAuthenticator::new(alg, SoftAttestation::None));
        let tweaks = Tweaks {
            corrupt_signature: true,
            ..Tweaks::default()
        };
        assert_eq!(
            fixture.login(&tweaks).expect_err("the signature is wrong"),
            WebAuthnError::SignatureInvalid,
            "{alg:?}"
        );
        // The counter did not move, and an honest assertion still works.
        assert_eq!(fixture.account.sign_count, 0);
        fixture.login(&Tweaks::default()).expect("honest assertion");
    }
}

#[test]
fn a_signature_over_other_data_is_refused() {
    // The signature of one assertion does not cover the authenticator data of another.
    let mut fixture = Fixture::plain();
    let mut response = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());
    let other = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());
    assert_ne!(response.response.signature, other.response.signature);
    response.response.signature = other.response.signature;
    assert_eq!(
        fixture
            .verify(&response, AssertionPolicy::default())
            .expect_err("mixed response"),
        WebAuthnError::SignatureInvalid
    );
}

#[test]
fn the_signature_counter_must_increase() {
    let mut fixture = Fixture::plain();
    fixture.login(&Tweaks::default()).expect("first login");
    let verified = fixture.login(&Tweaks::default()).expect("second login");
    assert_eq!(verified.sign_count, 2);

    for forced in [2, 1, 0] {
        let tweaks = Tweaks {
            sign_count: Some(forced),
            ..Tweaks::default()
        };
        assert_eq!(
            fixture
                .login(&tweaks)
                .expect_err("the counter did not increase"),
            WebAuthnError::CounterRegression,
            "forced {forced}"
        );
        assert_eq!(
            fixture.account.sign_count, 2,
            "a refused assertion changes nothing"
        );
    }
    // A counter may skip values.
    let tweaks = Tweaks {
        sign_count: Some(40),
        ..Tweaks::default()
    };
    assert_eq!(
        fixture.login(&tweaks).expect("skipping is fine").sign_count,
        40
    );
    assert_eq!(fixture.account.sign_count, 40);
}

#[test]
fn counters_of_zero_and_zero_pass() {
    let mut fixture = Fixture::new(
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).counter(false),
    );
    let tweaks = Tweaks {
        sign_count: Some(0),
        ..Tweaks::default()
    };
    for _ in 0..2 {
        assert_eq!(fixture.login(&tweaks).expect("0 and 0 pass").sign_count, 0);
    }
    // Once the stored counter is non-zero, going back to zero is a regression.
    fixture.account.sign_count = 3;
    assert_eq!(
        fixture.login(&tweaks).expect_err("back to zero"),
        WebAuthnError::CounterRegression
    );
}

#[test]
fn mismatching_credential_ids_are_refused() {
    let mut fixture = Fixture::plain();
    let good = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());

    // `id` and `rawId` differ.
    let mut mismatched = good.clone();
    mismatched.id = base64url_encode(&[7; 32]);
    assert!(matches!(
        assertion_credential_id(&mismatched),
        Err(WebAuthnError::Malformed(_))
    ));
    let refused = fixture
        .verify(&mismatched, AssertionPolicy::default())
        .expect_err("id differs");
    assert!(
        matches!(refused, WebAuthnError::Malformed(_)),
        "{refused:?}"
    );

    // The credential type is not `public-key`.
    let mut wrong_type = good.clone();
    wrong_type.type_ = "password".to_owned();
    let refused = fixture
        .verify(&wrong_type, AssertionPolicy::default())
        .expect_err("type");
    assert!(
        matches!(refused, WebAuthnError::Malformed(_)),
        "{refused:?}"
    );

    // The response belongs to another stored credential.
    let other = Fixture::plain();
    let refused = fixture
        .rp
        .finish_assertion(
            &good,
            &AUTHENTICATION_CHALLENGE,
            &other.account.stored(),
            &AssertionPolicy::default(),
        )
        .expect_err("another credential is stored");
    assert_eq!(refused, WebAuthnError::CredentialMismatch);

    // The honest response still verifies.
    fixture
        .verify(&good, AssertionPolicy::default())
        .expect("honest response");
}

#[test]
fn registration_credential_ids_must_agree() {
    let rp = relying_party(Vec::new());
    let policy = RegistrationPolicy::default();
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let good = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );

    // `id` and `rawId` differ.
    let mut mismatched = good.clone();
    mismatched.id = base64url_encode(&[7; 32]);
    let refused = finish_registration(&rp, &mismatched, policy).expect_err("id differs");
    assert!(
        matches!(refused, WebAuthnError::Malformed(_)),
        "{refused:?}"
    );

    // `id` and `rawId` agree but are not the credential id in the attested data.
    let mut foreign = good.clone();
    foreign.id = base64url_encode(&[7; 32]);
    foreign.raw_id = foreign.id.clone();
    assert_eq!(
        finish_registration(&rp, &foreign, policy).expect_err("another id"),
        WebAuthnError::CredentialMismatch
    );

    // The credential type is not `public-key`.
    let mut wrong_type = good.clone();
    wrong_type.type_ = "password".to_owned();
    let refused = finish_registration(&rp, &wrong_type, policy).expect_err("type");
    assert!(
        matches!(refused, WebAuthnError::Malformed(_)),
        "{refused:?}"
    );

    finish_registration(&rp, &good, policy).expect("honest response");
}

#[test]
fn a_corrupted_attestation_signature_is_refused() {
    let tweaks = Tweaks {
        corrupt_signature: true,
        ..Tweaks::default()
    };
    for alg in ALGORITHMS {
        let refused = registration_error_with(
            SoftAuthenticator::new(alg, SoftAttestation::PackedSelf),
            ORIGIN,
            &tweaks,
            RegistrationPolicy::default(),
        );
        assert!(
            matches!(refused, WebAuthnError::AttestationInvalid(_)),
            "{alg:?}: {refused:?}"
        );
    }
    // The signature of the attestation key, with and without a trust anchor.
    for anchors in [Vec::new(), vec![soft_root()]] {
        let rp = relying_party(anchors);
        let policy = RegistrationPolicy::default();
        let mut authenticator = certificate_authenticator();
        let response =
            registration_response(&rp, &mut authenticator, USER_ID, ORIGIN, &tweaks, policy);
        let refused = finish_registration(&rp, &response, policy).expect_err("corrupted");
        assert!(
            matches!(refused, WebAuthnError::AttestationInvalid(_)),
            "{refused:?}"
        );
    }
}

#[test]
fn the_attestation_signature_covers_the_client_data() {
    // Extra members keep the client data well formed but change its hash, so the
    // statement no longer matches.
    let rp = relying_party(Vec::new());
    let policy = RegistrationPolicy::default();
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedSelf);
    let mut response = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );
    let client_data = text_of(&response.response.client_data_json)
        .replace("\"crossOrigin\":false", "\"crossOrigin\":false,\"extra\":1");
    response.response.client_data_json = base64url_encode(client_data.as_bytes());
    let refused = finish_registration(&rp, &response, policy).expect_err("different client data");
    assert!(
        matches!(refused, WebAuthnError::AttestationInvalid(_)),
        "{refused:?}"
    );
}

#[test]
fn tampered_base64_is_refused() {
    let rp = relying_party(Vec::new());
    let policy = RegistrationPolicy::default();
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let good = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );
    for tampered in ["not base64!", "AAAA+/==", "a", "AB=C", "\u{e9}\u{e9}"] {
        let edits: [fn(&mut RegistrationResponse, &str); 4] = [
            |r, t| r.id = t.to_owned(),
            |r, t| r.raw_id = t.to_owned(),
            |r, t| r.response.client_data_json = t.to_owned(),
            |r, t| r.response.attestation_object = t.to_owned(),
        ];
        for edit in edits {
            let mut response = good.clone();
            edit(&mut response, tampered);
            let refused = finish_registration(&rp, &response, policy).expect_err("tampered");
            assert!(
                matches!(refused, WebAuthnError::Malformed(_)),
                "{tampered:?}: {refused:?}"
            );
        }
    }

    let mut fixture = Fixture::plain();
    let good = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());
    for tampered in ["not base64!", "AAAA+/==", "a", "AB=C", "\u{e9}\u{e9}"] {
        let edits: [fn(&mut AuthenticationResponse, &str); 6] = [
            |r, t| r.id = t.to_owned(),
            |r, t| r.raw_id = t.to_owned(),
            |r, t| r.response.client_data_json = t.to_owned(),
            |r, t| r.response.authenticator_data = t.to_owned(),
            |r, t| r.response.signature = t.to_owned(),
            |r, t| r.response.user_handle = Some(t.to_owned()),
        ];
        for edit in edits {
            let mut response = good.clone();
            edit(&mut response, tampered);
            let refused = fixture
                .verify(&response, AssertionPolicy::default())
                .expect_err("tampered");
            assert!(
                matches!(refused, WebAuthnError::Malformed(_)),
                "{tampered:?}: {refused:?}"
            );
        }
    }
    // Nothing above consumed the honest response.
    fixture
        .verify(&good, AssertionPolicy::default())
        .expect("honest response");
}

// --- Malformed attestation objects and statements ----------------------------------------

/// `response` with its attestation object edited by `edit`.
fn with_attestation_object(
    response: &RegistrationResponse,
    edit: impl FnOnce(&mut Vec<(Value, Value)>),
) -> RegistrationResponse {
    let mut object = attestation_object(response);
    edit(&mut object);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(object), &mut bytes).expect("CBOR encodes");
    let mut edited = response.clone();
    edited.response.attestation_object = base64url_encode(&bytes);
    edited
}

fn set_member(object: &mut [(Value, Value)], name: &str, value: Value) {
    let entry = object
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap_or_else(|| panic!("the object has no `{name}`"));
    entry.1 = value;
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn integer(value: i64) -> Value {
    Value::Integer(value.into())
}

#[test]
fn malformed_attestation_statements_are_refused() {
    let rp = relying_party(Vec::new());
    let policy = RegistrationPolicy::default();
    let honest = |attestation| {
        let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, attestation);
        registration_response(
            &rp,
            &mut authenticator,
            USER_ID,
            ORIGIN,
            &Tweaks::default(),
            policy,
        )
    };
    let refused = |response: &RegistrationResponse| {
        finish_registration(&rp, response, policy).expect_err("the registration must be refused")
    };
    let invalid = |error: WebAuthnError| matches!(error, WebAuthnError::AttestationInvalid(_));

    // A format the verifier does not implement.
    let none = honest(SoftAttestation::None);
    let tpm = with_attestation_object(&none, |object| set_member(object, "fmt", text("tpm")));
    assert_eq!(
        refused(&tpm),
        WebAuthnError::UnsupportedAttestation("tpm".to_owned())
    );
    // `none` carries no statement.
    let statement = Value::Map(vec![(text("alg"), integer(-7))]);
    let none_with_statement =
        with_attestation_object(&none, |object| set_member(object, "attStmt", statement));
    assert!(invalid(refused(&none_with_statement)));

    // Self attestation names the credential algorithm.
    let packed = honest(SoftAttestation::PackedSelf);
    let wrong_alg = with_attestation_object(&packed, |object| {
        let statement = Value::Map(vec![
            (text("alg"), integer(-8)),
            (text("sig"), Value::Bytes(vec![0; 64])),
        ]);
        set_member(object, "attStmt", statement);
    });
    assert!(invalid(refused(&wrong_alg)));
    // ECDAA is not supported, and unknown members are not allowed.
    let ecdaa = with_attestation_object(&packed, |object| {
        let statement = Value::Map(vec![
            (text("alg"), integer(-7)),
            (text("ecdaaKeyId"), Value::Bytes(vec![1])),
        ]);
        set_member(object, "attStmt", statement);
    });
    assert_eq!(
        refused(&ecdaa),
        WebAuthnError::UnsupportedAttestation("packed-ecdaa".to_owned())
    );
    let unknown_member = with_attestation_object(&packed, |object| {
        let statement = Value::Map(vec![
            (text("alg"), integer(-7)),
            (text("sig"), Value::Bytes(vec![0; 8])),
            (text("extra"), Value::Bytes(vec![1])),
        ]);
        set_member(object, "attStmt", statement);
    });
    assert!(invalid(refused(&unknown_member)));
}

#[test]
fn malformed_certificate_chains_are_refused() {
    let rp = relying_party(vec![soft_root()]);
    let policy = RegistrationPolicy::default();
    let mut authenticator = certificate_authenticator();
    let honest = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );
    let with_chain = |chain: &Value| {
        with_attestation_object(&honest, |object| {
            let mut statement = member(object, "attStmt").as_map().expect("map").clone();
            for entry in &mut statement {
                if entry.0.as_text() == Some("x5c") {
                    entry.1 = chain.clone();
                }
            }
            set_member(object, "attStmt", Value::Map(statement));
        })
    };
    let leaf = {
        let object = attestation_object(&honest);
        let statement = member(&object, "attStmt").as_map().expect("map");
        member(statement, "x5c").as_array().expect("array")[0].clone()
    };
    let chains = [
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Bytes(vec![0x30, 0x00])]),
        Value::Array(vec![text("certificate")]),
        Value::Array(vec![Value::Bytes(bytes_of(&leaf)[..40].to_vec())]),
        Value::Array(vec![leaf.clone(); 9]),
        // The leaf twice: the second certificate is not a CA that issued the first.
        Value::Array(vec![leaf.clone(), leaf]),
    ];
    for chain in chains {
        let refused = finish_registration(&rp, &with_chain(&chain), policy)
            .expect_err("a broken chain is refused");
        assert!(
            matches!(refused, WebAuthnError::AttestationInvalid(_)),
            "{chain:?}: {refused:?}"
        );
    }
    finish_registration(&rp, &honest, policy).expect("the honest chain");
}

#[test]
fn malformed_attestation_objects_are_refused() {
    let rp = relying_party(Vec::new());
    let policy = RegistrationPolicy::default();
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let honest = registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &Tweaks::default(),
        policy,
    );
    let malformed = |response: &RegistrationResponse| {
        let refused = finish_registration(&rp, response, policy).expect_err("malformed");
        assert!(
            matches!(refused, WebAuthnError::Malformed(_)),
            "{refused:?}"
        );
    };

    // A missing, mistyped or doubled member.
    for name in ["fmt", "attStmt", "authData"] {
        malformed(&with_attestation_object(&honest, |object| {
            object.retain(|(key, _)| key.as_text() != Some(name));
        }));
        malformed(&with_attestation_object(&honest, |object| {
            set_member(object, name, integer(1));
        }));
        malformed(&with_attestation_object(&honest, |object| {
            let copy = object
                .iter()
                .find(|(key, _)| key.as_text() == Some(name))
                .cloned();
            object.extend(copy);
        }));
    }
    // Not a map, trailing bytes and garbage.
    let mut array = Vec::new();
    ciborium::ser::into_writer(&Value::Array(Vec::new()), &mut array).expect("CBOR encodes");
    let mut trailing = base64url_decode(&honest.response.attestation_object).expect("base64url");
    trailing.push(0);
    for bytes in [array, trailing, vec![0xff; 12], Vec::new()] {
        let mut response = honest.clone();
        response.response.attestation_object = base64url_encode(&bytes);
        malformed(&response);
    }
    // The attested-credential-data flag must agree with the data that follows.
    let cleared = Tweaks {
        clear_flags: Flags::ATTESTED,
        ..Tweaks::default()
    };
    malformed(&registration_response(
        &rp,
        &mut authenticator,
        USER_ID,
        ORIGIN,
        &cleared,
        policy,
    ));
    // Truncated authenticator data.
    malformed(&with_attestation_object(&honest, |object| {
        set_member(object, "authData", Value::Bytes(vec![0; 36]));
    }));
}

#[test]
fn an_assertion_with_attested_credential_data_is_refused() {
    let tweaks = Tweaks {
        set_flags: Flags::ATTESTED,
        ..Tweaks::default()
    };
    assert!(matches!(
        assertion_error(&tweaks),
        WebAuthnError::Malformed(_)
    ));
    // Truncated authenticator data.
    let mut fixture = Fixture::plain();
    let mut response = fixture.response(ORIGIN, &Tweaks::default(), AssertionPolicy::default());
    let data = base64url_decode(&response.response.authenticator_data).expect("base64url");
    response.response.authenticator_data = base64url_encode(&data[..36]);
    let refused = fixture
        .verify(&response, AssertionPolicy::default())
        .expect_err("truncated");
    assert!(
        matches!(refused, WebAuthnError::Malformed(_)),
        "{refused:?}"
    );
}
