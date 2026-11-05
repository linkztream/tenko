#![no_main]

use libfuzzer_sys::fuzz_target;

// An uploaded keytab file: kept entries are AES with keys of the right length, every other
// entry is listed as refused, and the counts stay bounded.
fuzz_target!(|data: &[u8]| {
    tenko_krb::fuzzing::keytab(data);
});
