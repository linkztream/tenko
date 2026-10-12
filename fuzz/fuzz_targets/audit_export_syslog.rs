#![no_main]

// The syslog side of the audit export: the octet-counting decoder (RFC 6587) fed in two
// chunks, the strict RFC 5424 parser on every frame and on the whole input. None may
// panic, and the decoder's buffer stays bounded by the frame limit.

use libfuzzer_sys::fuzz_target;
use tenko_auth::audit_export::format::syslog::{FrameDecoder, parse};

const MAX_FRAME: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let _ = parse(data);
    let split = data.first().map_or(0, |&byte| usize::from(byte) % (data.len() + 1));
    let (head, tail) = data.split_at(split);
    let mut decoder = FrameDecoder::new(MAX_FRAME);
    for chunk in [head, tail] {
        decoder.push(chunk);
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => {
                    let _ = parse(&frame);
                }
                Ok(None) | Err(_) => break,
            }
        }
        assert!(decoder.buffered() <= data.len());
    }
});
