#![no_main]

//! The authenticator data of a WebAuthn registration or assertion (ADR 0010): the fixed
//! header, the attested credential data with its COSE key and the extensions. When a key
//! parses, it also checks a signature over the input, as an assertion does.

use libfuzzer_sys::fuzz_target;
use tenko_auth::webauthn::{AuthenticatorData, CoseKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = AuthenticatorData::parse(data)
        && let Some(attested) = &parsed.attested
    {
        let reparsed = CoseKey::parse(&attested.public_key_cbor);
        assert_eq!(reparsed.as_ref().ok(), Some(&attested.public_key));
        let _ = attested.public_key.verify(data, &attested.credential_id);
    }
});
