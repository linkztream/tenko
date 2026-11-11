#![no_main]

//! The X.509 certificates of a `packed` attestation chain as the verifier reads them before
//! any signature: each certificate parsed, then the constraints of the chain (critical
//! extensions, the key usage and the path length of the issuers). The input is a run of DER
//! certificates, at most eight.

use libfuzzer_sys::fuzz_target;
use tenko_auth::webauthn::fuzzing;

fuzz_target!(|data: &[u8]| {
    let _ = fuzzing::certificate_chain(data);
});
