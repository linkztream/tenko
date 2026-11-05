#![no_main]

use libfuzzer_sys::fuzz_target;

// The tokens of a SPNEGO or raw Kerberos negotiation (legs separated by 0xff 0xfe) through
// the acceptor, which holds the Samba lab key and the recorded time.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::spnego(data);
});
