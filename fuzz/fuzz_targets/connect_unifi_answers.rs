//! Fuzzes the UniFi connector's readers of controller answers and its topology and
//! inventory mapping.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tenko_connect_unifi::fuzzing::answers(data);
});
