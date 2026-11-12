#![no_main]
//! What a sign-in reads from a client that is not signed in yet (`tenko_auth`): the
//! `clientDataJSON` of a passkey ceremony, the credential id of an assertion, the ceremony id
//! the browser hands back, a TOTP code, a recovery code, the shape check of a session cookie,
//! and the hand-written base64url, base32 and hexadecimal decoders all of them use.
//!
//! The input is one control octet and text. The control octet picks the ceremony of the
//! client data (bit 0: `webauthn.get`, else `webauthn.create`), the time of the TOTP check
//! (bits 1 to 4, in steps) and whether a step was used before (bit 5).
//!
//! It checks that client data passes only with the ceremony's type, the expected challenge,
//! an allowed origin and no cross-origin claim; that a credential id is 1 to 1,023 octets and
//! both of its encodings agree; that a TOTP code passes only for a step within the drift
//! window, after the last used one, whose code it is; that a recovery code matches only the
//! code it normalizes to; that a decoder's output encodes to text that decodes to it again;
//! and that the codes the product makes pass its own checks.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use tenko_auth::{
    challenge::{Ceremonies, CeremonyKey},
    encoding::{
        base32_decode, base32_encode, base64url_decode, base64url_encode, hex_decode, hex_encode,
    },
    recovery::{self, GeneratedRecoveryCodes},
    secret::looks_like_session_secret,
    totp::{self, TotpParams},
    webauthn::{
        AuthenticationResponse, ClientData, MAX_CREDENTIAL_ID_LEN, RelyingParty, RpConfig,
        assertion_credential_id, fuzzing,
    },
};
use tenko_core::Timestamp;

/// The challenge of the ceremony under test.
const CHALLENGE: [u8; 32] = [
    0x5e, 0x00, 0x53, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
];
/// The allowed origins: one exact, one on any port.
const ORIGINS: [&str; 2] = ["https://ddi.example.test", "http://localhost:*"];
/// The secret of RFC 6238 appendix B (SHA-1).
const TOTP_SECRET: &[u8] = b"12345678901234567890";
/// 2026-01-01T00:00:00Z.
const NOW: u64 = 1_767_225_600;

static RELYING_PARTY: LazyLock<RelyingParty> = LazyLock::new(|| {
    let mut config = RpConfig::for_host("ddi.example.test");
    config.origins = ORIGINS.iter().map(|origin| (*origin).to_owned()).collect();
    RelyingParty::new(config).expect("a relying party")
});
static RECOVERY: LazyLock<GeneratedRecoveryCodes> =
    LazyLock::new(|| recovery::generate().expect("recovery codes"));
static CEREMONIES: LazyLock<Ceremonies> =
    LazyLock::new(|| Ceremonies::with_key(16, CeremonyKey::from_cluster_key(&[0x5e; 32])));

fn origin_allowed(origin: &str) -> bool {
    origin == ORIGINS[0]
        || origin.strip_prefix("http://localhost").is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
        })
}

fn decoders(text: &str, raw: &[u8]) {
    if let Ok(bytes) = base64url_decode(text) {
        assert_eq!(base64url_decode(&base64url_encode(&bytes)), Ok(bytes));
    }
    if let Ok(bytes) = base32_decode(text) {
        assert_eq!(base32_decode(&base32_encode(&bytes)), Ok(bytes));
    }
    if let Ok(bytes) = hex_decode(text) {
        assert_eq!(hex_decode(&hex_encode(&bytes)), Ok(bytes));
    }
    assert_eq!(base64url_decode(&base64url_encode(raw)).as_deref(), Ok(raw));
    assert_eq!(base32_decode(&base32_encode(raw)).as_deref(), Ok(raw));
    assert_eq!(hex_decode(&hex_encode(raw)).as_deref(), Ok(raw));
}

fn client_data(json: &[u8], ceremony: &str) {
    if fuzzing::client_data(&RELYING_PARTY, json, ceremony, &CHALLENGE).is_err() {
        return;
    }
    // Read as the product reads it (an object or, as serde reads a struct, an array).
    let data: ClientData = serde_json::from_slice(json).expect("accepted client data reads");
    assert_eq!(data.type_, ceremony);
    assert_eq!(
        base64url_decode(&data.challenge).as_deref(),
        Ok(&CHALLENGE[..])
    );
    assert!(origin_allowed(&data.origin));
    assert_ne!(data.cross_origin, Some(true));
    assert_eq!(data.top_origin, None);
}

fn credential_id(json: &[u8]) {
    let Ok(response) = serde_json::from_slice::<AuthenticationResponse>(json) else {
        return;
    };
    if let Ok(id) = assertion_credential_id(&response) {
        assert!(!id.is_empty() && id.len() <= MAX_CREDENTIAL_ID_LEN);
        assert_eq!(response.type_, "public-key");
        assert_eq!(base64url_decode(&response.raw_id).as_deref(), Ok(&id[..]));
        assert_eq!(base64url_decode(&response.id).as_deref(), Ok(&id[..]));
    }
}

fn totp_code(code: &str, control: u8) {
    let params = TotpParams::default();
    let now = NOW + u64::from((control >> 1) & 0x0f) * params.period;
    let now_step = totp::step_at(&params, now);
    let last_used = (control & 0x20 != 0).then(|| now_step - 1);
    if let Some(step) = totp::verify(TOTP_SECRET, &params, code, now, last_used) {
        assert!(step + params.skew >= now_step && step <= now_step + params.skew);
        assert!(last_used.is_none_or(|used| step > used));
        let presented: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            totp::code_at(TOTP_SECRET, &params, step * params.period).as_str(),
            presented
        );
    }
    // The code of the current step passes.
    let current = totp::code_at(TOTP_SECRET, &params, now);
    assert!(totp::verify(TOTP_SECRET, &params, &current, now, last_used).is_some());
}

fn recovery_code(input: &str) {
    let normalized = recovery::normalize(input);
    assert_eq!(*recovery::normalize(&normalized), *normalized);
    if let Some(index) = recovery::find(input, &RECOVERY.stored) {
        assert_eq!(*recovery::normalize(&RECOVERY.display[index]), *normalized);
    }
    assert_eq!(
        recovery::find(&RECOVERY.display[0], &RECOVERY.stored),
        Some(0)
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let ceremony = if control & 1 == 0 {
        "webauthn.create"
    } else {
        "webauthn.get"
    };
    client_data(rest, ceremony);
    credential_id(rest);
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    decoders(text, rest);
    totp_code(text, control);
    recovery_code(text);
    if looks_like_session_secret(text) {
        assert_eq!(text.len(), 43);
        assert_eq!(base64url_decode(text).map(|bytes| bytes.len()), Ok(32));
    }
    let now = Timestamp::from_unix_nanos(i128::from(NOW) * 1_000_000_000).expect("a time");
    let _ = CEREMONIES.take(text, now);
});
