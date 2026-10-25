//! The Router Advertisement parser (RFC 4861 section 4.2) against advertisements as radvd and
//! a typical home router send them, the malformed ones a hostile host on the link could send,
//! and loops over truncations and single-octet changes that must never panic. The messages
//! are hex files under `tests/fixtures/ra`, one message per file, with `#` comment lines that
//! say what each field is; every field read here is checked against that annotation. Nothing
//! here touches a network.

use std::net::Ipv6Addr;
use std::path::PathBuf;

use ipnet::Ipv6Net;
use tenko_scan::ra::{
    ALL_ROUTERS, ND_HOP_LIMIT, NdOption, PrefixInfo, ROUTER_ADVERTISEMENT, ROUTER_SOLICITATION,
    RaError, RouterAdvert, router_solicitation,
};

/// The advertisements: every one parses.
const ADVERTISEMENTS: &[&str] = &[
    "ra_flags_off.hex",
    "ra_managed.hex",
    "ra_other_only.hex",
    "ra_rdnss_slla_mtu.hex",
    "ra_lifetime_zero.hex",
    "ra_two_prefixes.hex",
];

/// The malformed messages and the solicitation, with the error each one gives.
const REFUSED: &[(&str, RaError)] = &[
    ("bad_truncated_fixed.hex", RaError::Short),
    ("bad_option_length_zero.hex", RaError::BadOption),
    ("bad_option_past_end.hex", RaError::BadOption),
    ("bad_code.hex", RaError::Code(1)),
    ("router_solicitation.hex", RaError::NotAdvert(133)),
];

/// Reads a fixture: hex bytes separated by white space, `#` starts a comment.
fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", "ra", name]
        .iter()
        .collect();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut bytes = Vec::new();
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or("");
        for token in content.split_whitespace() {
            let byte = u8::from_str_radix(token, 16)
                .unwrap_or_else(|_| panic!("{name}: {token:?} is not a hex byte"));
            bytes.push(byte);
        }
    }
    bytes
}

fn parsed(bytes: &[u8]) -> RouterAdvert<'_> {
    RouterAdvert::parse(bytes).unwrap_or_else(|error| panic!("an advertisement: {error}"))
}

fn net(text: &str) -> Ipv6Net {
    text.parse().expect("a network")
}

fn ip(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

fn prefix(
    text: &str,
    on_link: bool,
    autonomous: bool,
    valid: u32,
    preferred: u32,
) -> NdOption<'static> {
    NdOption::Prefix(PrefixInfo {
        prefix: net(text),
        on_link,
        autonomous,
        valid,
        preferred,
    })
}

/// The documentation MAC 00:00:5e:00:53:`last`.
fn mac(last: u8) -> [u8; 6] {
    [0, 0, 0x5e, 0, 0x53, last]
}

/// The octets of `inner` lie inside `outer`.
fn is_inside(outer: &[u8], inner: &[u8]) -> bool {
    let start = outer.as_ptr() as usize;
    let at = inner.as_ptr() as usize;
    at >= start && at + inner.len() <= start + outer.len()
}

/// Everything a parsed advertisement offers, walked the way a consumer would, and checked
/// against an independent walk of the octets. The same checks as the body of the fuzz target
/// `scan_ra` (which cannot run here), so that its assertions are proven on every message of
/// these tests. Returns the number of options.
fn walk(data: &[u8], ra: &RouterAdvert<'_>) -> usize {
    assert!(data.len() >= 16);
    assert_eq!(data[0], ROUTER_ADVERTISEMENT);
    assert_eq!(data[1], 0);
    assert_eq!(ra.flags, data[5]);
    assert_eq!(ra.managed(), ra.flags & 0x80 != 0);
    assert_eq!(ra.other(), ra.flags & 0x40 != 0);
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
    options.len()
}

// ---- recorded advertisements -------------------------------------------------------------

#[test]
fn a_home_router_with_m_and_o_off_reads_its_prefix_and_link_layer_address() {
    let bytes = fixture("ra_flags_off.hex");
    assert_eq!(bytes.len(), 64);
    assert_eq!(bytes[0], ROUTER_ADVERTISEMENT);
    let ra = parsed(&bytes);
    assert_eq!(ra.cur_hop_limit, 64);
    assert_eq!(ra.flags, 0x00);
    assert!(!ra.managed());
    assert!(!ra.other());
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.reachable_ms, 0);
    assert_eq!(ra.retrans_ms, 0);
    assert_eq!(ra.source_link_layer(), Some(&mac(1)[..]));
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![
            NdOption::SourceLinkLayer(&mac(1)),
            NdOption::Mtu(1500),
            prefix("2001:db8:100::/64", true, true, 86_400, 14_400),
        ]
    );
    assert_eq!(
        ra.prefixes().collect::<Vec<_>>(),
        vec![PrefixInfo {
            prefix: net("2001:db8:100::/64"),
            on_link: true,
            autonomous: true,
            valid: 86_400,
            preferred: 14_400,
        }]
    );
}

#[test]
fn the_m_flag_alone_is_managed_and_not_other() {
    let bytes = fixture("ra_managed.hex");
    let ra = parsed(&bytes);
    assert_eq!(ra.cur_hop_limit, 64);
    assert_eq!(ra.flags, 0x80);
    assert!(ra.managed());
    assert!(!ra.other());
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.source_link_layer(), Some(&mac(2)[..]));
    // The prefix has L but not A: hosts form no address in it by SLAAC.
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![
            NdOption::SourceLinkLayer(&mac(2)),
            prefix("2001:db8:200::/64", true, false, 2_592_000, 604_800),
        ]
    );
}

#[test]
fn the_o_flag_alone_is_other_and_not_managed() {
    let bytes = fixture("ra_other_only.hex");
    let ra = parsed(&bytes);
    assert_eq!(ra.flags, 0x40);
    assert!(!ra.managed());
    assert!(ra.other());
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.source_link_layer(), Some(&mac(3)[..]));
    assert_eq!(
        ra.prefixes().map(|info| info.prefix).collect::<Vec<_>>(),
        vec![net("2001:db8:100::/64")]
    );
}

#[test]
fn rdnss_and_the_search_list_come_with_the_other_options() {
    let bytes = fixture("ra_rdnss_slla_mtu.hex");
    assert_eq!(bytes.len(), 128);
    let ra = parsed(&bytes);
    assert_eq!(ra.cur_hop_limit, 64);
    // 0x48: O on, M off, router preference high. The preference bits are not M or O.
    assert_eq!(ra.flags, 0x48);
    assert!(!ra.managed());
    assert!(ra.other());
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.reachable_ms, 30_000);
    assert_eq!(ra.retrans_ms, 1_000);

    let mut servers = ip("2001:db8:100::53").octets().to_vec();
    servers.extend(ip("2001:db8:100::54").octets());
    // The DNS search list is kept as "other" with the octets after the type and length:
    // reserved, lifetime, the name in wire format, and the padding.
    let mut search = vec![0, 0, 0, 0, 0x04, 0xb0];
    search.extend(b"\x07example\x03net\x00");
    search.extend([0, 0, 0]);
    assert_eq!(search.len(), 22);

    let options: Vec<_> = ra.options().collect();
    assert_eq!(
        options,
        vec![
            NdOption::SourceLinkLayer(&mac(4)),
            NdOption::Mtu(1480),
            prefix("2001:db8:100::/64", true, true, 86_400, 14_400),
            NdOption::Rdnss {
                lifetime: 1200,
                addrs: &servers,
            },
            NdOption::Other {
                kind: 31,
                data: &search,
            },
        ]
    );
    // The addresses of the RDNSS option read as 16 octets each.
    let NdOption::Rdnss { addrs, .. } = options[3] else {
        panic!("an RDNSS option");
    };
    let read: Vec<Ipv6Addr> = addrs
        .as_chunks::<16>()
        .0
        .iter()
        .map(|chunk| Ipv6Addr::from(*chunk))
        .collect();
    assert_eq!(read, vec![ip("2001:db8:100::53"), ip("2001:db8:100::54")]);
}

#[test]
fn a_router_lifetime_of_zero_is_read_as_zero_with_both_flags() {
    let bytes = fixture("ra_lifetime_zero.hex");
    let ra = parsed(&bytes);
    assert_eq!(ra.cur_hop_limit, 0);
    assert_eq!(ra.flags, 0xc0);
    assert!(ra.managed() && ra.other());
    assert_eq!(ra.router_lifetime, 0);
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![
            prefix("2001:db8:100::/64", true, true, 0, 0),
            NdOption::SourceLinkLayer(&mac(5)),
        ]
    );
    // The prefix option comes before the link-layer address and is still found.
    assert_eq!(ra.source_link_layer(), Some(&mac(5)[..]));
}

#[test]
fn two_prefixes_come_in_the_order_they_were_sent() {
    let bytes = fixture("ra_two_prefixes.hex");
    let ra = parsed(&bytes);
    assert_eq!(ra.flags, 0xc0);
    assert!(ra.managed() && ra.other());
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(
        ra.prefixes().collect::<Vec<_>>(),
        vec![
            PrefixInfo {
                prefix: net("2001:db8:100::/64"),
                on_link: true,
                autonomous: true,
                valid: 86_400,
                preferred: 14_400,
            },
            PrefixInfo {
                prefix: net("2001:db8:300::/64"),
                on_link: true,
                autonomous: false,
                valid: 604_800,
                preferred: 86_400,
            },
        ]
    );
    assert_eq!(ra.options().count(), 3);
    assert_eq!(ra.source_link_layer(), Some(&mac(6)[..]));
}

#[test]
fn every_advertisement_walks_and_the_walk_is_repeatable() {
    for name in ADVERTISEMENTS {
        let bytes = fixture(name);
        let ra = parsed(&bytes);
        assert!(walk(&bytes, &ra) >= 1, "{name}: options");
        // The view is `Copy` and the iterators restart where the message starts.
        let again = ra;
        assert_eq!(
            ra.options().collect::<Vec<_>>(),
            again.options().collect::<Vec<_>>(),
            "{name}"
        );
    }
}

// ---- refused messages --------------------------------------------------------------------

#[test]
fn malformed_messages_give_their_error() {
    for (name, error) in REFUSED {
        let bytes = fixture(name);
        assert_eq!(RouterAdvert::parse(&bytes), Err(*error), "{name}");
        assert!(!error.to_string().is_empty(), "{name}: a message");
    }
}

#[test]
fn an_empty_message_and_a_lone_type_octet_are_short() {
    assert_eq!(RouterAdvert::parse(&[]), Err(RaError::Short));
    assert_eq!(RouterAdvert::parse(&[134]), Err(RaError::Short));
}

#[test]
fn the_type_is_checked_before_the_code() {
    // A neighbour advertisement (136) with code 1 is not an advertisement of routers.
    let mut bytes = fixture("ra_flags_off.hex");
    bytes[0] = 136;
    bytes[1] = 1;
    assert_eq!(RouterAdvert::parse(&bytes), Err(RaError::NotAdvert(136)));
}

#[test]
fn a_lone_trailing_octet_is_a_bad_option() {
    let mut bytes = fixture("ra_flags_off.hex");
    bytes.push(0);
    assert_eq!(RouterAdvert::parse(&bytes), Err(RaError::BadOption));
    // Seven octets of padding are no option either.
    bytes.extend([0; 6]);
    assert_eq!(RouterAdvert::parse(&bytes), Err(RaError::BadOption));
}

#[test]
fn an_advertisement_with_no_options_is_valid() {
    let bytes = fixture("ra_flags_off.hex");
    let ra = parsed(&bytes[..16]);
    assert_eq!(ra.options().count(), 0);
    assert_eq!(ra.prefixes().count(), 0);
    assert_eq!(ra.source_link_layer(), None);
    assert_eq!(ra.router_lifetime, 1800);
}

#[test]
fn only_the_first_two_flag_bits_are_m_and_o() {
    let mut bytes = fixture("ra_flags_off.hex");
    for (flags, managed, other) in [
        (0x00, false, false),
        (0x80, true, false),
        (0x40, false, true),
        (0xc0, true, true),
        // H (0x20), the preference (0x18) and the reserved bits (0x07) are neither.
        (0x3f, false, false),
        (0xbf, true, false),
    ] {
        bytes[5] = flags;
        let ra = parsed(&bytes);
        assert_eq!((ra.managed(), ra.other()), (managed, other), "{flags:#x}");
        assert_eq!(ra.flags, flags);
    }
}

// ---- options that are too short for their fields, and prefix edge cases -------------------

/// The fixed part of an advertisement with `options` after it.
fn with_options(options: &[u8]) -> Vec<u8> {
    let mut bytes = fixture("ra_flags_off.hex")[..16].to_vec();
    bytes.extend_from_slice(options);
    bytes
}

#[test]
fn an_option_too_short_for_its_fields_is_kept_as_other() {
    // Prefix information of 1 unit (8 octets) instead of 4 parses as an option but reads as
    // "other"; an MTU option of 1 unit has all its fields.
    let mut options = vec![3, 1, 64, 0xc0, 0, 0, 0, 0];
    options.extend([5, 1, 0, 0, 0, 0, 5, 0xdc]);
    let bytes = with_options(&options);
    let ra = parsed(&bytes);
    let read: Vec<_> = ra.options().collect();
    assert_eq!(
        read,
        vec![
            NdOption::Other {
                kind: 3,
                data: &options[2..8],
            },
            NdOption::Mtu(1500),
        ]
    );
    assert_eq!(ra.prefixes().count(), 0);

    // A prefix of 2 units (16 octets) does not hold the 30 octets of its fields either.
    let bytes = with_options(&[3, 2, 64, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let ra = parsed(&bytes);
    assert_eq!(ra.prefixes().count(), 0);
    assert!(matches!(
        ra.options().next(),
        Some(NdOption::Other { kind: 3, .. })
    ));
}

#[test]
fn an_rdnss_option_keeps_whole_addresses_only() {
    // 1 unit: no address. 2 units: 8 octets after the lifetime, not a whole address. 4 units:
    // one address and 8 octets that are not one.
    let one = with_options(&[25, 1, 0, 0, 0, 0, 0x04, 0xb0]);
    let ra = parsed(&one);
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![NdOption::Rdnss {
            lifetime: 1200,
            addrs: &[],
        }]
    );

    let mut two = vec![25, 2, 0, 0, 0, 0, 0x04, 0xb0];
    two.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    let bytes = with_options(&two);
    let ra = parsed(&bytes);
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![NdOption::Rdnss {
            lifetime: 1200,
            addrs: &[],
        }]
    );

    let mut three = vec![25, 4, 0, 0, 0, 0, 0x04, 0xb0];
    three.extend(ip("2001:db8:100::53").octets());
    three.extend([0xff; 8]);
    let bytes = with_options(&three);
    let ra = parsed(&bytes);
    assert_eq!(
        ra.options().collect::<Vec<_>>(),
        vec![NdOption::Rdnss {
            lifetime: 1200,
            addrs: &ip("2001:db8:100::53").octets(),
        }]
    );
}

#[test]
fn a_prefix_loses_the_bits_beyond_its_length() {
    // 2001:db8:300::5 with a length of 64 reads as 2001:db8:300::/64, and a /60 keeps the
    // top 60 bits of 2001:db8:3ff:ffff::, which are 2001:db8:3ff:fff0::.
    let mut option = vec![3, 4, 64, 0xc0];
    option.extend(86_400u32.to_be_bytes());
    option.extend(14_400u32.to_be_bytes());
    option.extend([0; 4]);
    option.extend(ip("2001:db8:300::5").octets());
    let bytes = with_options(&option);
    let ra = parsed(&bytes);
    assert_eq!(
        ra.prefixes().map(|info| info.prefix).collect::<Vec<_>>(),
        vec![net("2001:db8:300::/64")]
    );

    option[2] = 60;
    option[16..32].copy_from_slice(&ip("2001:db8:3ff:ffff::").octets());
    let bytes = with_options(&option);
    let ra = parsed(&bytes);
    assert_eq!(
        ra.prefixes().map(|info| info.prefix).collect::<Vec<_>>(),
        vec![net("2001:db8:3ff:fff0::/60")]
    );
}

#[test]
fn a_prefix_length_past_128_does_not_make_an_invalid_prefix() {
    let mut option = vec![3, 4, 200, 0xc0];
    option.extend([0; 8]);
    option.extend([0; 4]);
    option.extend(ip("2001:db8:100::1").octets());
    let bytes = with_options(&option);
    let ra = parsed(&bytes);
    for info in ra.prefixes() {
        assert!(info.prefix.prefix_len() <= 128);
    }
}

#[test]
fn the_reserved_prefix_flag_bits_are_neither_l_nor_a() {
    let mut option = vec![3, 4, 64, 0x3f];
    option.extend([0; 12]);
    option.extend(ip("2001:db8:100::").octets());
    let bytes = with_options(&option);
    let ra = parsed(&bytes);
    let info = ra.prefixes().next().expect("a prefix");
    assert!(!info.on_link && !info.autonomous);
}

#[test]
fn an_option_of_the_largest_length_fits_or_is_refused_without_a_panic() {
    // 255 units is 2040 octets; the area here is shorter, so it runs past the end.
    let bytes = with_options(&[1, 255, 0, 0, 0, 0, 0, 0]);
    assert_eq!(RouterAdvert::parse(&bytes), Err(RaError::BadOption));
    // The same length with all of its octets present is one option.
    let mut full = vec![200, 255];
    full.resize(2040, 0xaa);
    let bytes = with_options(&full);
    let ra = parsed(&bytes);
    let mut options = ra.options();
    let Some(NdOption::Other { kind: 200, data }) = options.next() else {
        panic!("an unknown option");
    };
    assert_eq!(data.len(), 2038);
    assert!(options.next().is_none());
}

// ---- hostile input -----------------------------------------------------------------------

#[test]
fn no_truncation_of_any_fixture_panics_and_a_cut_inside_an_option_is_refused() {
    for name in ADVERTISEMENTS
        .iter()
        .copied()
        .chain(REFUSED.iter().map(|(name, _)| *name))
    {
        let bytes = fixture(name);
        for cut in 0..=bytes.len() {
            let result = RouterAdvert::parse(&bytes[..cut]);
            if let Ok(ra) = result {
                walk(&bytes[..cut], &ra);
            }
        }
    }
    // For a valid advertisement the cut decides: shorter than the fixed part is `Short`, in
    // the middle of an option `BadOption`, and on an option boundary an advertisement with
    // fewer options.
    for name in ADVERTISEMENTS {
        let bytes = fixture(name);
        let full = parsed(&bytes).options().count();
        let mut boundaries = vec![16];
        let mut at = 16;
        while at < bytes.len() {
            at += usize::from(bytes[at + 1]) * 8;
            boundaries.push(at);
        }
        assert_eq!(boundaries.last(), Some(&bytes.len()), "{name}");
        for cut in 0..=bytes.len() {
            let result = RouterAdvert::parse(&bytes[..cut]);
            if cut < 16 {
                assert_eq!(result, Err(RaError::Short), "{name} cut at {cut}");
            } else if let Some(index) = boundaries.iter().position(|&b| b == cut) {
                let ra = result.unwrap_or_else(|error| panic!("{name} cut at {cut}: {error}"));
                assert_eq!(ra.options().count(), index, "{name} cut at {cut}");
                assert!(ra.options().count() <= full);
            } else {
                assert_eq!(result, Err(RaError::BadOption), "{name} cut at {cut}");
            }
        }
    }
}

#[test]
fn no_single_octet_change_of_any_fixture_panics() {
    let mut parsed_ok = 0usize;
    for name in ADVERTISEMENTS
        .iter()
        .copied()
        .chain(REFUSED.iter().map(|(name, _)| *name))
    {
        let original = fixture(name);
        let mut bytes = original.clone();
        for at in 0..original.len() {
            for value in 0..=255u8 {
                bytes[at] = value;
                if let Ok(ra) = RouterAdvert::parse(&bytes) {
                    walk(&bytes, &ra);
                    parsed_ok += 1;
                }
            }
            bytes[at] = original[at];
        }
    }
    assert!(parsed_ok > 0);
}

#[test]
fn the_flags_octet_decides_m_and_o_bit_by_bit() {
    // The flags octet is octet 5: a flip of bit 7 or 6 changes M or O and nothing else.
    let original = fixture("ra_two_prefixes.hex");
    for bit in 0..8 {
        let mut bytes = original.clone();
        bytes[5] ^= 1 << bit;
        let ra = parsed(&bytes);
        assert_eq!(ra.flags, original[5] ^ (1 << bit));
        assert_eq!(ra.managed(), ra.flags & 0x80 != 0);
        assert_eq!(ra.other(), ra.flags & 0x40 != 0);
        assert_eq!(ra.options().count(), 3);
    }
}

#[test]
fn a_long_run_of_one_unit_options_is_walked_in_linear_time() {
    // 1,000 options of one unit each: the largest message a link could carry is shorter, but
    // the walk must not depend on how many there are.
    let mut options = Vec::new();
    for _ in 0..1_000 {
        options.extend([200, 1, 1, 2, 3, 4, 5, 6]);
    }
    let bytes = with_options(&options);
    let ra = parsed(&bytes);
    assert_eq!(ra.options().count(), 1_000);
    assert_eq!(ra.prefixes().count(), 0);
    assert_eq!(ra.source_link_layer(), None);
}

// ---- the solicitation --------------------------------------------------------------------

#[test]
fn the_solicitation_with_an_address_is_the_recorded_message() {
    let mut out = [0xffu8; 16];
    let len = router_solicitation(Some(mac(1)), &mut out);
    assert_eq!(len, 16);
    assert_eq!(out[..len], fixture("router_solicitation.hex")[..]);
    assert_eq!(out[0], ROUTER_SOLICITATION);
    // The checksum is zero: the kernel fills it on a raw ICMPv6 socket.
    assert_eq!(out[2..4], [0, 0]);
}

#[test]
fn the_solicitation_without_an_address_is_eight_octets_of_zeros_after_the_type() {
    let mut out = [0xffu8; 16];
    let len = router_solicitation(None, &mut out);
    assert_eq!(len, 8);
    // The buffer is cleared whole, so nothing of an earlier message stays behind.
    assert_eq!(out, {
        let mut expected = [0u8; 16];
        expected[0] = 133;
        expected
    });
}

#[test]
fn the_solicitation_is_not_an_advertisement_and_carries_its_option() {
    let mut out = [0u8; 16];
    for mac in [None, Some(mac(1)), Some([0xff; 6])] {
        let len = router_solicitation(mac, &mut out);
        // Eight octets are shorter than an advertisement's fixed part and read as short.
        let expected = if len < 16 {
            RaError::Short
        } else {
            RaError::NotAdvert(ROUTER_SOLICITATION)
        };
        assert_eq!(RouterAdvert::parse(&out[..len]), Err(expected));
        if let Some(mac) = mac {
            // Option 1, length 1 unit, then the six octets.
            assert_eq!(out[8..10], [1, 1]);
            assert_eq!(out[10..16], mac);
        }
    }
}

#[test]
fn the_constants_are_those_of_the_rfc() {
    assert_eq!(ROUTER_SOLICITATION, 133);
    assert_eq!(ROUTER_ADVERTISEMENT, 134);
    assert_eq!(ALL_ROUTERS, ip("ff02::2"));
    assert_eq!(ND_HOP_LIMIT, 255);
}

// ---- the fuzz seeds ----------------------------------------------------------------------

#[test]
fn the_fuzz_seeds_are_the_fixtures() {
    let seeds: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "fuzz",
        "seeds",
        "scan_ra",
    ]
    .iter()
    .collect();
    let pairs = [
        ("ra_flags_off.hex", "ra-flags-off"),
        ("ra_managed.hex", "ra-managed"),
        ("ra_other_only.hex", "ra-other-only"),
        ("ra_rdnss_slla_mtu.hex", "ra-rdnss-slla-mtu"),
        ("ra_lifetime_zero.hex", "ra-lifetime-zero"),
        ("ra_two_prefixes.hex", "ra-two-prefixes"),
        ("bad_truncated_fixed.hex", "malformed-truncated-fixed"),
        ("bad_option_length_zero.hex", "malformed-option-length-zero"),
        ("bad_option_past_end.hex", "malformed-option-past-end"),
        ("bad_code.hex", "malformed-code"),
        ("router_solicitation.hex", "router-solicitation"),
    ];
    for (name, seed) in pairs {
        let bytes =
            std::fs::read(seeds.join(seed)).unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        assert_eq!(bytes, fixture(name), "{seed} is {name}");
    }
    let count = std::fs::read_dir(&seeds)
        .expect("the seed directory")
        .count();
    assert_eq!(count, pairs.len(), "a seed without a fixture");
}
