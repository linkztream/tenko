#![no_main]

use libfuzzer_sys::fuzz_target;

// The first octet chooses the Kerberos, GSS-API or SPNEGO structure; the rest is decoded as
// it, and a value that decodes must encode to octets that decode to the same value.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::der(data);
});
