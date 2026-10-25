#![no_main]

//! The Router Advertisement parser of the probe (RFC 4861 section 4.2, WP9.2): the ICMPv6
//! messages a raw socket hands over from any host on the link, so they are fuzzed like
//! network input. `RouterAdvert::parse` on arbitrary octets, then on success every option,
//! prefix and flag accessor, and the Router Solicitation builder.
//!
//! Nothing may panic. The invariants kept: a message that parses is at least 16 octets, of
//! type 134 and code 0; the options yielded are those of an independent walk of the octets
//! (same count, same types, same values, classified by the length each type needs) and lie
//! inside the message; a prefix has no host bits and a length of at most 128; the M and O
//! flags are bits 7 and 6 of the flags octet; and the walk is the same each time.

use libfuzzer_sys::fuzz_target;
use tenko_scan::ra::{NdOption, ROUTER_ADVERTISEMENT, RouterAdvert, router_solicitation};

/// The octets of `inner` lie inside `outer`.
fn is_inside(outer: &[u8], inner: &[u8]) -> bool {
    let start = outer.as_ptr() as usize;
    let at = inner.as_ptr() as usize;
    at >= start && at + inner.len() <= start + outer.len()
}

fuzz_target!(|data: &[u8]| {
    // The solicitation builder takes the first six octets as a link-layer address.
    let mac = data
        .get(..6)
        .map(|octets| <[u8; 6]>::try_from(octets).expect("six octets"));
    let mut out = [0xa5u8; 16];
    let len = router_solicitation(mac, &mut out);
    assert_eq!(len, if mac.is_some() { 16 } else { 8 });
    assert_eq!(out[0], 133);

    let Ok(ra) = RouterAdvert::parse(data) else {
        return;
    };
    assert!(data.len() >= 16);
    assert_eq!(data[0], ROUTER_ADVERTISEMENT);
    assert_eq!(data[1], 0);
    assert_eq!(ra.flags, data[5]);
    assert_eq!(ra.managed(), ra.flags & 0x80 != 0);
    assert_eq!(ra.other(), ra.flags & 0x40 != 0);
    let _ = (
        ra.cur_hop_limit,
        ra.router_lifetime,
        ra.reachable_ms,
        ra.retrans_ms,
    );

    // The options read again from the octets, independently: type, then length in units of
    // eight octets, then the value. `parse` has checked that this walk ends on the last
    // octet, so a short or zero length cannot occur here.
    let mut at = 16;
    let mut walked = Vec::new();
    while at < data.len() {
        let len = usize::from(data[at + 1]) * 8;
        assert!(len >= 8 && at + len <= data.len());
        walked.push((data[at], &data[at + 2..at + len]));
        at += len;
    }
    assert_eq!(at, data.len());

    let options: Vec<_> = ra.options().collect();
    assert_eq!(options.len(), walked.len());
    let mut prefixes = 0usize;
    let mut first_link_layer = None;
    for (option, (kind, value)) in options.iter().zip(&walked) {
        match *option {
            NdOption::SourceLinkLayer(address) => {
                assert_eq!(*kind, 1);
                assert_eq!(address, *value);
                assert!(is_inside(data, address));
                assert_eq!(address.len() % 8, 6);
                first_link_layer.get_or_insert(address);
            }
            NdOption::Mtu(_) => {
                assert_eq!(*kind, 5);
                assert!(value.len() >= 6);
            }
            NdOption::Prefix(info) => {
                assert_eq!(*kind, 3);
                assert!(value.len() >= 30);
                assert!(info.prefix.prefix_len() <= 128);
                assert_eq!(info.prefix, info.prefix.trunc());
                prefixes += 1;
            }
            NdOption::Rdnss { addrs, .. } => {
                assert_eq!(*kind, 25);
                assert!(value.len() >= 6);
                assert!(is_inside(data, addrs));
                assert_eq!(addrs.len() % 16, 0);
                // What follows the lifetime, cut to whole addresses.
                assert!(addrs.len() <= value.len() - 6);
                assert!(value.len() - 6 - addrs.len() < 16);
            }
            NdOption::Other {
                kind: other,
                data: rest,
            } => {
                assert_eq!(other, *kind);
                assert_eq!(rest, *value);
                assert!(is_inside(data, rest));
                // Only an option too short for its fields, or of another type, is "other".
                assert!(match other {
                    5 | 25 => rest.len() < 6,
                    3 => rest.len() < 30,
                    1 => false,
                    _ => true,
                });
            }
        }
    }
    assert_eq!(ra.prefixes().count(), prefixes);
    assert_eq!(ra.source_link_layer(), first_link_layer);
    assert!(ra.options().eq(ra.options()));
    let _ = format!("{ra:?}");
});
