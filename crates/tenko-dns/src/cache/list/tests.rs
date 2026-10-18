use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, RecordData, Rtype, ViewId};

use super::*;
use crate::cache::{Cache, CacheKey, CacheSettings};

const A: u16 = 1;
const CNAME: u16 = 5;
const SOA: u16 = 6;
const MX: u16 = 15;

fn wire_name(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

fn key(view: Option<ViewId>, qname: &str, qtype: u16) -> CacheKey {
    CacheKey::new(view, &wire_name(qname), qtype, 1, false, false)
}

/// An upstream answer: the question, then `(type, TTL, data)` records owned by a pointer to
/// the question, `answers` of them in the answer section and the rest in the authority one.
fn upstream(
    qname: &str,
    qtype: u16,
    rcode: u8,
    records: &[(u16, u32, Vec<u8>)],
    answers: u16,
) -> Vec<u8> {
    let mut out = vec![0x42, 0x42, 0x81, 0x80 | rcode, 0, 1];
    out.extend_from_slice(&answers.to_be_bytes());
    let authority = u16::try_from(records.len()).expect("count") - answers;
    out.extend_from_slice(&authority.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&wire_name(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for (rtype, ttl, data) in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).expect("len").to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn a(qname: &str, last: u8, ttl: u32) -> Vec<u8> {
    upstream(qname, A, 0, &[(A, ttl, vec![192, 0, 2, last])], 1)
}

fn cache() -> Cache {
    Cache::new(CacheSettings {
        entries: 10_000,
        stale: Duration::from_secs(600),
        ..CacheSettings::default()
    })
}

fn names(page: &CachePage) -> Vec<String> {
    page.entries
        .iter()
        .map(|entry| format!("{} {}", entry.name, entry.rtype))
        .collect()
}

#[test]
fn pages_come_in_canonical_order_with_a_cursor() {
    let cache = cache();
    let now = Instant::now();
    for name in [
        "z.example.test",
        "example.test",
        "b.example.test",
        "www.example.net",
        "a.b.example.test",
        "a.example.test",
    ] {
        assert!(cache.insert(&key(None, name, A), &a(name, 1, 300), now, None));
    }
    let k = key(None, "a.example.test", MX);
    let mx = upstream(
        "a.example.test",
        MX,
        0,
        &[(MX, 300, b"\x00\x0a\x02mx\xc0\x0e".to_vec())],
        1,
    );
    assert!(cache.insert(&k, &mx, now, None));

    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = cache.list(ViewFilter::All, None, 3, cursor.as_ref(), now);
        assert!(page.entries.len() <= 3);
        seen.extend(names(&page));
        pages += 1;
        match page.next {
            Some(next) => {
                let text = next.encode();
                cursor = Some(ListCursor::parse(&text).expect("the cursor parses back"));
                assert_eq!(cursor.as_ref(), Some(&next));
            }
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(
        seen,
        [
            "www.example.net A",
            "example.test A",
            "a.example.test A",
            "a.example.test MX",
            "b.example.test A",
            "a.b.example.test A",
            "z.example.test A",
        ]
    );
}

#[test]
fn a_suffix_and_a_view_narrow_the_listing() {
    let cache = cache();
    let now = Instant::now();
    let view = ViewId::generate();
    for (view, name) in [
        (None, "www.example.test"),
        (Some(view), "www.example.test"),
        (None, "badexample.test"),
        (None, "other.test"),
    ] {
        assert!(cache.insert(&key(view, name, A), &a(name, 1, 300), now, None));
    }
    let suffix = wire_name("example.test");
    let page = cache.list(ViewFilter::All, Some(&suffix), 10, None, now);
    assert_eq!(names(&page), ["www.example.test A", "www.example.test A"]);
    assert_eq!(page.entries[0].view, None, "no view sorts first");
    assert_eq!(page.entries[1].view, Some(view));
    assert!(page.next.is_none());

    let only = cache.list(ViewFilter::View(view), None, 10, None, now);
    assert_eq!(names(&only), ["www.example.test A"]);
    let default = cache.list(ViewFilter::Default, None, 10, None, now);
    assert_eq!(default.entries.len(), 3);
    assert!(default.entries.iter().all(|entry| entry.view.is_none()));
    assert_eq!(ViewFilter::parse("default"), Some(ViewFilter::Default));
    assert_eq!(
        ViewFilter::parse(&view.to_string()),
        Some(ViewFilter::View(view))
    );
    assert_eq!(ViewFilter::parse("lan"), None);
}

#[test]
fn an_entry_shows_its_ttl_left_hits_records_and_stale_state() {
    let cache = cache();
    let now = Instant::now();
    // www.example.test CNAME cdn.example.test (compressed), cdn A 192.0.2.7.
    let chain = upstream(
        "www.example.test",
        A,
        0,
        &[
            (CNAME, 300, b"\x03cdn\xc0\x10".to_vec()),
            (A, 120, vec![192, 0, 2, 7]),
        ],
        2,
    );
    let k = key(None, "www.example.test", A);
    assert!(cache.insert(&k, &chain, now, None));
    let mut soa = wire_name("ns1.example.test");
    soa.extend_from_slice(&wire_name("hostmaster.example.test"));
    for value in [1u32, 3600, 900, 1_209_600, 60] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    let missing = upstream("missing.example.test", A, 3, &[(SOA, 300, soa)], 0);
    assert!(cache.insert(&key(None, "missing.example.test", A), &missing, now, None));

    let asked = {
        let mut out = Vec::new();
        crate::wire::write_query(&mut out, 7, "www.example.test", A, None);
        out
    };
    let client = crate::cache::Client {
        message: &asked,
        question_end: crate::wire::questions_end(&asked, 1).expect("question"),
        id: 7,
        rd: true,
        cd: false,
        edns: None,
        max_len: 512,
    };
    let mut out = Vec::with_capacity(512);
    let later = now + Duration::from_secs(20);
    cache.answer(&k, later, &client, &mut out);
    cache.answer(&k, later, &client, &mut out);

    let page = cache.list(ViewFilter::All, None, 10, None, later);
    assert_eq!(
        names(&page),
        ["missing.example.test A", "www.example.test A"]
    );
    let negative = &page.entries[0];
    assert_eq!((negative.rcode, negative.ttl, negative.hits), (3, 40, 0));
    assert_eq!(negative.records, []);
    assert!(!negative.stale);
    let positive = &page.entries[1];
    assert_eq!((positive.rcode, positive.ttl, positive.hits), (0, 100, 2));
    assert_eq!(positive.rtype, Rtype::A);
    assert_eq!(positive.class, 1);
    assert!(!positive.dnssec_ok && !positive.checking_disabled);
    assert_eq!(
        positive.records,
        [
            RecordData::Cname {
                target: DnsName::new("cdn.example.test").expect("name"),
            },
            RecordData::A {
                address: Ipv4Addr::new(192, 0, 2, 7),
            },
        ]
    );

    // Past its TTL the entry is stale with no time left; past the stale window it is gone.
    let stale = cache.list(
        ViewFilter::All,
        None,
        10,
        None,
        now + Duration::from_secs(200),
    );
    assert_eq!(
        names(&stale),
        ["missing.example.test A", "www.example.test A"]
    );
    assert!(
        stale
            .entries
            .iter()
            .all(|entry| entry.stale && entry.ttl == 0)
    );
    let gone = cache.list(
        ViewFilter::All,
        None,
        10,
        None,
        now + Duration::from_secs(900),
    );
    assert_eq!(gone, CachePage::default());
}

#[test]
fn the_limit_is_bounded_and_a_bad_cursor_does_not_parse() {
    let cache = cache();
    let now = Instant::now();
    for n in 0..30u8 {
        let name = format!("h{n}.example.test");
        assert!(cache.insert(&key(None, &name, A), &a(&name, n, 300), now, None));
    }
    let one = cache.list(ViewFilter::All, None, 0, None, now);
    assert_eq!(one.entries.len(), 1, "a limit of 0 lists one");
    assert!(one.next.is_some());
    let all = cache.list(ViewFilter::All, None, 5_000, None, now);
    assert_eq!(all.entries.len(), 30);
    assert!(all.next.is_none());
    assert_eq!((MAX_LIST, DEFAULT_LIST), (1_000, 200));

    for bad in ["", "0", "zz", "02", "0000010001000003777777", "01ab"] {
        assert!(ListCursor::parse(bad).is_none(), "{bad:?}");
    }
    // Upper case labels are not a key the cache makes.
    let upper = ListCursor(key(None, "www.example.test", A))
        .encode()
        .replace("777777", "575757");
    assert!(ListCursor::parse(&upper).is_none());
}
