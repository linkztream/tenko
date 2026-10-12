#![no_main]

//! The multipart parser of `POST /imports` (WP1.5): the boundary read from the
//! `Content-Type` header and the file parts split out of the body. The input is the header
//! value, a line feed and the body. Every file part must lie inside the body.

use libfuzzer_sys::fuzz_target;
use tenko_api::routes::import::{boundary_from_content_type, parse_multipart};

fuzz_target!(|data: &[u8]| {
    let (header, body) = match data.iter().position(|&byte| byte == b'\n') {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &[][..]),
    };
    let Some(boundary) = boundary_from_content_type(&String::from_utf8_lossy(header)) else {
        return;
    };
    if let Ok(files) = parse_multipart(body, &boundary) {
        let range = body.as_ptr_range();
        for file in files {
            let part = file.bytes.as_ptr_range();
            assert!(range.start <= part.start && part.end <= range.end);
        }
    }
});
