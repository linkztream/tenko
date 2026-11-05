#![no_main]

use libfuzzer_sys::fuzz_target;

// An RFC 4121 MIC token (the first 28 octets) over the rest, verified both ways under a
// fixed context key; a token signed over the rest verifies with its sequence number and is
// refused in the other direction and with any octet changed.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::mic(data);
});
