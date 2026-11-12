//! What several fuzz targets share: the split of an input into datagrams, and the time and
//! addresses of the worlds the engine targets build.

use tenko_core::Timestamp;

/// The datagrams of an input: each behind a two-octet big-endian length, the last one cut
/// short when the input ends inside it; at most `max`.
pub fn datagrams(mut rest: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while out.len() < max && rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let body = &rest[2..];
        let take = len.min(body.len());
        out.push(&body[..take]);
        rest = &body[take..];
    }
    out
}

/// The time an engine target's world starts at.
///
/// # Panics
///
/// Never: the text is a valid time.
pub fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("a time")
}

/// The MAC address of client `k`, from the documentation block of RFC 7042.
pub fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}
