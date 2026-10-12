#![no_main]

//! The attestation object of a WebAuthn registration (ADR 0010): the CBOR object, its
//! authenticator data and the `none` and `packed` statements with their certificate
//! chains. The first 32 bytes of the input are the SHA-256 of the client data the
//! statement signs, the rest is the object.

use libfuzzer_sys::fuzz_target;
use tenko_auth::webauthn::fuzzing;

fuzz_target!(|data: &[u8]| {
    let Some((hash, object)) = data.split_first_chunk::<32>() else {
        return;
    };
    let _ = fuzzing::attestation_object(object, hash);
});
