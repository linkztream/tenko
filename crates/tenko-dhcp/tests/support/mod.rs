//! Shared helpers of the integration tests: the fixture loader, the re-encoding of a parsed
//! message through the builder, and a small deterministic random generator.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::path::Path;

use tenko_dhcp::v4::{Message, MessageBuilder, code};

/// The well-formed fixtures: every one parses, walks without an error and re-encodes to
/// the same octets.
pub const WELL_FORMED: [&str; 9] = [
    "windows-discover",
    "linux-discover-duid",
    "relayed-request",
    "inform",
    "pxe-discover",
    "ack-fqdn-search",
    "offer-overload",
    "ack-split-routes",
    "rfc3397-search-split",
];

/// The malformed fixtures.
pub const MALFORMED: [&str; 5] = [
    "malformed-short",
    "malformed-cookie",
    "malformed-truncated",
    "malformed-overload",
    "malformed-file-truncated",
];

/// The octets of `fixtures/<name>.hex`: hex pairs, `vv*N` for N octets of `vv`, `#` starts
/// a comment.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(format!("{name}.hex"));
    let text = std::fs::read_to_string(&path).expect("the fixture exists");
    let mut out = Vec::new();
    for line in text.lines() {
        let data = line.split('#').next().unwrap_or_default();
        for token in data.split_whitespace() {
            let (octet, count) = token.split_once('*').map_or((token, 1), |(octet, count)| {
                (octet, count.parse().expect("a repeat count"))
            });
            let octet = u8::from_str_radix(octet, 16).expect("a hex octet");
            out.extend(std::iter::repeat_n(octet, count));
        }
    }
    out
}

/// Writes `message` again through the builder, field by field and instance by instance,
/// into `out` and returns the length: the octets must come out unchanged.
pub fn rebuild(message: &Message<'_>, out: &mut [u8]) -> usize {
    let mut builder = MessageBuilder::new(out, message.len()).expect("a buffer");
    builder
        .op(message.op())
        .htype(message.htype())
        .hlen(message.hlen())
        .hops(message.hops())
        .xid(message.xid())
        .secs(message.secs())
        .flags(message.flags())
        .ciaddr(message.ciaddr())
        .yiaddr(message.yiaddr())
        .siaddr(message.siaddr())
        .giaddr(message.giaddr());
    builder.chaddr(message.chaddr_field()).expect("chaddr");
    if let Some(name) = message.server_name().expect("overload") {
        builder.sname(name).expect("sname");
    }
    if let Some(name) = message.boot_file().expect("overload") {
        builder.file(name).expect("file");
    }
    if message.overload().expect("overload") != 0 {
        builder.allow_overload().expect("room for option 52");
    }
    for option in message.options() {
        let option = option.expect("a well-formed option");
        if option.code != code::OVERLOAD {
            builder.option(option.code, option.data).expect("room");
        }
    }
    builder.pad_to(message.len()).expect("padding");
    builder.finish().expect("finish")
}

/// xorshift64*, enough for test inputs.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value below `bound` (above 0).
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound).expect("bound")).expect("index")
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64().to_be_bytes()[0]
    }
}
