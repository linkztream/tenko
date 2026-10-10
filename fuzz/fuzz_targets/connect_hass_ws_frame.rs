//! Fuzzes the WebSocket frame decoder and message assembler of the Home Assistant connector.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_connect_hass::ws::{Assembler, decode_frame};

/// The size cap of both the decoder and the assembler: small, so the fuzzer reaches it.
const LIMIT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let mut assembler = Assembler::new(LIMIT);
    let mut rest = data;
    while let Ok(Some((frame, consumed))) = decode_frame(rest, LIMIT) {
        // A frame is at least two bytes and never longer than the input; a decoder that
        // breaks either would loop forever or slice out of range.
        assert!(consumed >= 2 && consumed <= rest.len());
        if assembler.push(frame).is_err() {
            return;
        }
        rest = &rest[consumed..];
    }
});
