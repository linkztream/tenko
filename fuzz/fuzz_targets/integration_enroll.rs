#![no_main]

//! What the integration enrollment reads from a client that holds no certificate yet
//! (`tenko_api::fuzzing::integration_enroll`): the `Content-Type`, the code id and the proof
//! headers, and the body, then the canonical key of the PKCS#10 request in it. The input is
//! header lines `name: value`, an octet `0xff`, and the body.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tenko_api::fuzzing::integration_enroll(data);
});
