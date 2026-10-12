#![no_main]

// The JSON lines of the audit export (`tenko audit verify --file`): every line of the
// input is read as a record, checkpoint or test line, with the check of the canonical
// CBOR against the hash. None may panic on any input.

use libfuzzer_sys::fuzz_target;
use tenko_auth::audit_export::format::json::parse_line;

fuzz_target!(|data: &[u8]| {
    for line in data.split(|&byte| byte == b'\n') {
        if let Ok(text) = std::str::from_utf8(line) {
            let _ = parse_line(text);
        }
    }
});
