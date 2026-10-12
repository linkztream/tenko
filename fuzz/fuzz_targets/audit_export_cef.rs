#![no_main]

// The CEF line of the audit export: the parser on any text, and the round trip of
// attacker-chosen text through the renderer (the principal of a test message and the sink
// name), whose extension values must come back byte for byte, line breaks included.

use libfuzzer_sys::fuzz_target;
use tenko_auth::audit_export::format::{Event, Origin, TestMessage, cef};
use tenko_core::Timestamp;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = cef::parse(text);
    }
    let text = String::from_utf8_lossy(data).into_owned();
    let origin = Origin {
        hostname: "ctl1.example.test".to_owned(),
        version: "0.0.1".to_owned(),
        sink: text.clone(),
    };
    let test = TestMessage {
        at: Timestamp::UNIX_EPOCH,
        by: text.clone(),
    };
    let line = cef::render(&origin, &Event::Test(&test));
    let parsed = cef::parse(&line).expect("a rendered line parses");
    assert_eq!(parsed.get("suser"), Some(text.as_str()));
    assert_eq!(parsed.get("cs5"), Some(text.as_str()));
});
