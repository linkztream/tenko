#![no_main]

use libfuzzer_sys::fuzz_target;

// An AP-REQ through the acceptor: as it is (first octet even), or built from the plaintexts
// of a ticket and an authenticator encrypted under the lab keys (first octet odd), so that
// the checks after the ciphers are reached.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::ap_req(data);
});
