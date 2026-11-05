#![no_main]

use libfuzzer_sys::fuzz_target;

// A PAC: the buffers, the logon information's NDR and the client information, read
// without the signature and verified with the lab key.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::pac(data);
});
