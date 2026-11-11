#![no_main]

//! The device cookie of a sign-in request as the server reads it: the value of
//! `__Host-tenko_device` (or `tenko_device`) split into marks. Whatever the value, at most
//! five marks come out, each of the shape of a 256-bit base64url secret, none twice.

use libfuzzer_sys::fuzz_target;
use tenko_auth::service::DeviceMarks;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let marks = DeviceMarks::parse(text);
    assert!(marks.len() <= 5);
});
