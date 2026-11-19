#![no_main]

//! The identity an integration certificate states, as the integration listener reads it after
//! the chain check: one URI `urn:tenko:service-account:<id>`, client authentication only, not
//! a CA. Any DER is read or refused; a certificate that is read yields its serial and the
//! SHA-256 of the certificate and of its key.

use libfuzzer_sys::fuzz_target;
use tenko_cluster::ca::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::identity(data);
});
