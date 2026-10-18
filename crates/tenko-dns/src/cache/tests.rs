use std::time::{Duration, Instant};

use tenko_core::dns::{ForwardRuleId, ViewId};

use super::*;

const A: u16 = 1;
const SOA: u16 = 6;
const AAAA: u16 = 28;

fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in text.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).expect("label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A record: its owner as a pointer to the question, type, TTL and data.
struct Rec {
    rtype: u16,
    ttl: u32,
    data: Vec<u8>,
}

fn a(last: u8, ttl: u32) -> Rec {
    Rec {
        rtype: A,
        ttl,
        data: vec![192, 0, 2, last],
    }
}

fn soa(ttl: u32, minimum: u32) -> Rec {
    let mut data = wire_name("ns1.example.test");
    data.extend_from_slice(&wire_name("hostmaster.example.test"));
    for value in [1u32, 3600, 900, 1_209_600, minimum] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    Rec {
        rtype: SOA,
        ttl,
        data,
    }
}

/// An upstream answer to `qname`/`qtype` with `rcode`, the answer and authority records,
/// and an OPT record at the end when `opt`.
fn upstream(
    qname: &str,
    qtype: u16,
    rcode: u8,
    answer: &[Rec],
    authority: &[Rec],
    opt: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x4242u16.to_be_bytes());
    out.push(0x81);
    out.push(0x80 | rcode);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(answer.len()).expect("count").to_be_bytes());
    out.extend_from_slice(&u16::try_from(authority.len()).expect("count").to_be_bytes());
    out.extend_from_slice(&u16::from(opt).to_be_bytes());
    out.extend_from_slice(&wire_name(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for record in answer.iter().chain(authority) {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(record.data.len()).expect("len").to_be_bytes());
        out.extend_from_slice(&record.data);
    }
    if opt {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&4096u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0x80, 0]);
        out.extend_from_slice(&[0, 0]);
    }
    out
}

/// A client's query in the case it typed.
fn query(qname: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, 0x1234, qname, qtype, edns);
    out
}

fn client(message: &[u8], edns: Option<ClientEdns>, max_len: usize) -> Client<'_> {
    Client {
        message,
        question_end: wire::questions_end(message, 1).expect("question"),
        id: 0x1234,
        rd: true,
        cd: false,
        edns,
        max_len,
    }
}

fn key(qname: &str, qtype: u16) -> CacheKey {
    CacheKey::new(None, &wire_name(qname), qtype, 1, false, false)
}

fn ttls(message: &[u8]) -> Vec<u32> {
    let header = wire::parse_header(message).expect("header");
    let mut pos = wire::questions_end(message, 1).expect("question");
    let mut out = Vec::new();
    let total = header.ancount + header.nscount + header.arcount;
    for _ in 0..total {
        let record = wire::read_record(message, pos).expect("record");
        if record.rtype != TYPE_OPT {
            out.push(record.ttl);
        }
        pos = record.end();
    }
    out
}

fn small(entries: usize) -> Cache {
    Cache::new(CacheSettings {
        entries,
        ..CacheSettings::default()
    })
}

#[test]
fn a_key_reads_back_its_parts() {
    let view = ViewId::generate();
    let name = wire_name("www.example.test");
    let key = CacheKey::new(Some(view), &name, AAAA, 1, true, true);
    assert_eq!(key.qname(), &name[..]);
    assert_eq!((key.qtype(), key.qclass()), (AAAA, 1));
    assert!(key.dnssec_ok() && key.cd());
    assert_eq!(key.view(), Some(view));
    let plain = CacheKey::new(None, &name, A, 1, false, false);
    assert_eq!(plain.view(), None);
    assert_eq!(CacheKey::from_bytes(plain.as_bytes()).qname(), &name[..]);
    assert_ne!(plain.as_bytes(), key.as_bytes());
}

#[test]
fn a_hit_answers_with_the_client_id_case_and_lowered_ttls() {
    let cache = small(100);
    let now = Instant::now();
    let message = upstream("www.example.test", A, 0, &[a(1, 300)], &[], false);
    assert!(cache.insert(&key("www.example.test", A), &message, now, None));
    assert_eq!(cache.len(), 1);
    let asked = query("WWW.Example.TEST", A, None);
    let mut out = Vec::with_capacity(MAX_MESSAGE);
    let hit = cache.answer(
        &key("www.example.test", A),
        now + Duration::from_secs(10),
        &client(&asked, None, 512),
        &mut out,
    );
    assert_eq!(hit, Hit::Fresh { rcode: 0 });
    let header = wire::parse_header(&out).expect("header");
    assert_eq!(header.id, 0x1234);
    assert!(header.qr && header.ra && header.rd);
    assert!(!header.aa && !header.ad && !header.tc);
    assert_eq!((header.ancount, header.arcount), (1, 0));
    let end = wire::questions_end(&out, 1).expect("question");
    assert_eq!(
        &out[HEADER_LEN..end],
        &asked[HEADER_LEN..end],
        "the client's case"
    );
    assert_eq!(ttls(&out), vec![290]);
}

const MAX_MESSAGE: usize = 65_535;

#[test]
fn an_expired_entry_answers_stale_with_ttl_30_within_the_window() {
    let cache = Cache::new(CacheSettings {
        entries: 100,
        stale: Duration::from_secs(600),
        ..CacheSettings::default()
    });
    let now = Instant::now();
    let message = upstream("www.example.test", A, 0, &[a(1, 300)], &[], false);
    let key = key("www.example.test", A);
    assert!(cache.insert(&key, &message, now, None));
    let asked = query("www.example.test", A, None);
    let mut out = Vec::new();
    let later = now + Duration::from_secs(301);
    assert_eq!(
        cache.answer(&key, later, &client(&asked, None, 512), &mut out),
        Hit::Expired
    );
    assert!(cache.has_stale(&key, later));
    assert_eq!(
        cache.answer_stale(&key, later, &client(&asked, None, 512), &mut out),
        Some(0)
    );
    assert_eq!(ttls(&out), vec![STALE_TTL]);
    // A fresh entry answers through the stale path with its real TTL.
    assert_eq!(
        cache.answer_stale(
            &key,
            now + Duration::from_secs(100),
            &client(&asked, None, 512),
            &mut out
        ),
        Some(0)
    );
    assert_eq!(ttls(&out), vec![200]);
    let gone = now + Duration::from_secs(300 + 600);
    assert!(!cache.has_stale(&key, gone));
    assert_eq!(
        cache.answer_stale(&key, gone, &client(&asked, None, 512), &mut out),
        None
    );
    assert_eq!(cache.purge(gone), 1);
    assert!(cache.is_empty());
}

#[test]
fn negative_answers_live_for_the_soa_minimum() {
    let cache = small(100);
    let now = Instant::now();
    let nx = upstream("nohost.example.test", A, 3, &[], &[soa(3600, 60)], false);
    let nx_key = key("nohost.example.test", A);
    assert!(cache.insert(&nx_key, &nx, now, None));
    let asked = query("nohost.example.test", A, None);
    let mut out = Vec::new();
    assert_eq!(
        cache.answer(
            &nx_key,
            now + Duration::from_secs(59),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Fresh { rcode: 3 }
    );
    assert_eq!(
        ttls(&out),
        vec![1],
        "the SOA's TTL is cut to the remaining lifetime"
    );
    assert_eq!(
        cache.answer(
            &nx_key,
            now + Duration::from_secs(61),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Expired
    );
    // NODATA: NOERROR without answers, with an SOA whose TTL is the smaller.
    let nodata = upstream("www.example.test", AAAA, 0, &[], &[soa(30, 600)], false);
    let nodata_key = key("www.example.test", AAAA);
    assert!(cache.insert(&nodata_key, &nodata, now, None));
    let asked = query("www.example.test", AAAA, None);
    assert_eq!(
        cache.answer(
            &nodata_key,
            now + Duration::from_secs(29),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Fresh { rcode: 0 }
    );
    assert_eq!(
        cache.answer(
            &nodata_key,
            now + Duration::from_secs(31),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Expired
    );
}

#[test]
fn what_is_not_cached() {
    let cache = small(100);
    let now = Instant::now();
    let k = key("www.example.test", A);
    // A negative answer without an SOA (RFC 2308 section 5).
    assert!(!cache.insert(
        &k,
        &upstream("www.example.test", A, 3, &[], &[], false),
        now,
        None
    ));
    // SERVFAIL and REFUSED.
    assert!(!cache.insert(
        &k,
        &upstream("www.example.test", A, 2, &[], &[], false),
        now,
        None
    ));
    assert!(!cache.insert(
        &k,
        &upstream("www.example.test", A, 5, &[], &[], false),
        now,
        None
    ));
    // A truncated answer.
    let mut truncated = upstream("www.example.test", A, 0, &[a(1, 300)], &[], false);
    truncated[2] |= 0x02;
    assert!(!cache.insert(&k, &truncated, now, None));
    // TTL 0.
    assert!(!cache.insert(
        &k,
        &upstream("www.example.test", A, 0, &[a(1, 0)], &[], false),
        now,
        None
    ));
    // A query, not an answer.
    assert!(!cache.insert(&k, &query("www.example.test", A, None), now, None));
    assert!(cache.is_empty());
    // A zero negative TTL keeps no negative entries.
    let no_negative = Cache::new(CacheSettings {
        negative_ttl: 0,
        ..CacheSettings::default()
    });
    assert!(!no_negative.insert(
        &k,
        &upstream("www.example.test", A, 3, &[], &[soa(300, 300)], false),
        now,
        None
    ));
}

#[test]
fn lifetimes_are_capped() {
    let cache = Cache::new(CacheSettings {
        entries: 100,
        max_ttl: 600,
        negative_ttl: 20,
        ..CacheSettings::default()
    });
    let now = Instant::now();
    let long = upstream("www.example.test", A, 0, &[a(1, 100_000)], &[], false);
    let k = key("www.example.test", A);
    assert!(cache.insert(&k, &long, now, None));
    let asked = query("www.example.test", A, None);
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, None, 512), &mut out);
    assert_eq!(ttls(&out), vec![600]);
    assert_eq!(
        cache.answer(
            &k,
            now + Duration::from_secs(601),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Expired
    );
    let nx = upstream("nohost.example.test", A, 3, &[], &[soa(3600, 3600)], false);
    let nx_key = key("nohost.example.test", A);
    assert!(cache.insert(&nx_key, &nx, now, None));
    let asked = query("nohost.example.test", A, None);
    assert_eq!(
        cache.answer(
            &nx_key,
            now + Duration::from_secs(21),
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Expired
    );
}

#[test]
fn the_upstream_opt_is_replaced_by_this_nodes_with_the_cookie() {
    let cache = small(100);
    let now = Instant::now();
    let message = upstream("www.example.test", A, 0, &[a(1, 300)], &[], true);
    let k = key("www.example.test", A);
    assert!(cache.insert(&k, &message, now, None));
    let asked = query("www.example.test", A, Some(1232));
    let cookie = [7u8; 24];
    let edns = ClientEdns {
        udp_size: 1232,
        dnssec_ok: true,
        cookie: Some(cookie),
    };
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, Some(edns), 1232), &mut out);
    let header = wire::parse_header(&out).expect("header");
    assert_eq!((header.ancount, header.arcount), (1, 1));
    let mut pos = wire::questions_end(&out, 1).expect("question");
    pos = wire::read_record(&out, pos).expect("answer").end();
    let opt = wire::read_record(&out, pos).expect("opt");
    assert_eq!((opt.rtype, opt.class), (TYPE_OPT, 1232));
    assert_eq!(opt.ttl & 0x8000, 0x8000, "DO echoed");
    let data = opt.data(&out);
    assert_eq!(&data[..4], &[0, 10, 0, 24]);
    assert_eq!(&data[4..], &cookie);
    assert_eq!(opt.end(), out.len());
    // Without EDNS from the client: no OPT record at all.
    let plain = query("www.example.test", A, None);
    cache.answer(&k, now, &client(&plain, None, 512), &mut out);
    assert_eq!(wire::parse_header(&out).expect("header").arcount, 0);
}

#[test]
fn an_answer_over_the_clients_limit_is_cut_with_tc() {
    let cache = small(100);
    let now = Instant::now();
    let records: Vec<Rec> = (1..=40).map(|last| a(last, 300)).collect();
    let message = upstream("www.example.test", A, 0, &records, &[], false);
    let k = key("www.example.test", A);
    assert!(cache.insert(&k, &message, now, None));
    let asked = query("www.example.test", A, None);
    let mut out = Vec::new();
    assert_eq!(
        cache.answer(&k, now, &client(&asked, None, 512), &mut out),
        Hit::Fresh { rcode: 0 }
    );
    let header = wire::parse_header(&out).expect("header");
    assert!(header.tc);
    assert_eq!((header.ancount, header.nscount, header.arcount), (0, 0, 0));
    assert_eq!(out.len(), wire::questions_end(&asked, 1).expect("question"));
    cache.answer(&k, now, &client(&asked, None, MAX_MESSAGE), &mut out);
    assert_eq!(wire::parse_header(&out).expect("header").ancount, 40);
}

#[test]
fn the_entry_bound_holds_and_the_least_recently_used_goes_first() {
    let cache = small(2);
    let now = Instant::now();
    let asked = query("a.example.test", A, None);
    let mut out = Vec::new();
    for name in ["a.example.test", "b.example.test"] {
        assert!(cache.insert(
            &key(name, A),
            &upstream(name, A, 0, &[a(1, 300)], &[], false),
            now,
            None
        ));
    }
    assert_eq!(
        cache.answer(
            &key("a.example.test", A),
            now,
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Fresh { rcode: 0 }
    );
    let name = "c.example.test";
    assert!(cache.insert(
        &key(name, A),
        &upstream(name, A, 0, &[a(1, 300)], &[], false),
        now,
        None
    ));
    assert_eq!(cache.len(), 2);
    assert!(cache.has_stale(&key("a.example.test", A), now));
    assert!(
        !cache.has_stale(&key("b.example.test", A), now),
        "b was least recently used"
    );

    for entries in [300, 10_000] {
        let cache = small(entries);
        for index in 0..entries * 3 {
            let name = format!("host-{index}.example.test");
            cache.insert(
                &key(&name, A),
                &upstream(&name, A, 0, &[a(1, 300)], &[], false),
                now,
                None,
            );
        }
        let stats = cache.stats();
        assert!(
            cache.len() <= entries,
            "{} entries held of {entries}",
            cache.len()
        );
        assert!(stats.max_entries <= entries);
        assert!(
            cache.len() >= entries * 9 / 10,
            "the shards are used evenly"
        );
        assert_eq!(stats.entries, cache.len());
    }
}

#[test]
fn the_byte_bound_holds() {
    let cache = Cache::new(CacheSettings {
        entries: 100_000,
        max_bytes: 64 * 1024,
        ..CacheSettings::default()
    });
    let now = Instant::now();
    for index in 0..5_000 {
        let name = format!("host-{index}.example.test");
        cache.insert(
            &key(&name, A),
            &upstream(&name, A, 0, &[a(1, 300)], &[], false),
            now,
            None,
        );
    }
    let stats = cache.stats();
    assert!(stats.bytes <= 64 * 1024, "{} octets", stats.bytes);
    assert!(stats.entries > 50);
}

#[test]
fn views_and_the_do_bit_keep_entries_apart() {
    let cache = small(100);
    let now = Instant::now();
    let name = wire_name("www.example.test");
    let view = ViewId::generate();
    let message = upstream("www.example.test", A, 0, &[a(1, 300)], &[], false);
    assert!(cache.insert(
        &CacheKey::new(Some(view), &name, A, 1, false, false),
        &message,
        now,
        None
    ));
    let asked = query("www.example.test", A, None);
    let mut out = Vec::new();
    for other in [
        CacheKey::new(None, &name, A, 1, false, false),
        CacheKey::new(Some(ViewId::generate()), &name, A, 1, false, false),
        CacheKey::new(Some(view), &name, A, 1, true, false),
        CacheKey::new(Some(view), &name, A, 1, false, true),
    ] {
        assert_eq!(
            cache.answer(&other, now, &client(&asked, None, 512), &mut out),
            Hit::Miss
        );
    }
    assert_eq!(
        cache.answer(
            &CacheKey::new(Some(view), &name, A, 1, false, false),
            now,
            &client(&asked, None, 512),
            &mut out
        ),
        Hit::Fresh { rcode: 0 }
    );
}

#[test]
fn a_popular_entry_near_its_end_is_queued_for_prefetch_once() {
    let cache = small(100);
    let now = Instant::now();
    let rule = ForwardRuleId::generate();
    let k = key("www.example.test", A);
    let message = upstream("www.example.test", A, 0, &[a(1, 100)], &[], false);
    assert!(cache.insert(&k, &message, now, Some(rule)));
    let asked = query("www.example.test", A, None);
    let mut out = Vec::new();
    cache.answer(
        &k,
        now + Duration::from_secs(50),
        &client(&asked, None, 512),
        &mut out,
    );
    assert!(
        cache.take_prefetch().is_empty(),
        "half its lifetime is left"
    );
    cache.answer(
        &k,
        now + Duration::from_secs(95),
        &client(&asked, None, 512),
        &mut out,
    );
    cache.answer(
        &k,
        now + Duration::from_secs(96),
        &client(&asked, None, 512),
        &mut out,
    );
    let queued = cache.take_prefetch();
    assert_eq!(queued.len(), 1, "queued once");
    assert_eq!(queued[0].0.qname(), k.qname());
    assert_eq!(queued[0].1, Some(rule));
    cache.answer(
        &k,
        now + Duration::from_secs(97),
        &client(&asked, None, 512),
        &mut out,
    );
    assert!(cache.take_prefetch().is_empty());
    cache.prefetch_failed(&k);
    cache.answer(
        &k,
        now + Duration::from_secs(98),
        &client(&asked, None, 512),
        &mut out,
    );
    assert_eq!(
        cache.take_prefetch().len(),
        1,
        "queued again after a failed prefetch"
    );
    // A short TTL is not prefetched.
    let short = key("short.example.test", A);
    let asked = query("short.example.test", A, None);
    cache.insert(
        &short,
        &upstream("short.example.test", A, 0, &[a(1, 5)], &[], false),
        now,
        None,
    );
    cache.answer(
        &short,
        now + Duration::from_secs(4),
        &client(&asked, None, 512),
        &mut out,
    );
    assert!(cache.take_prefetch().is_empty());
    // Without prefetch nothing is queued.
    let off = Cache::new(CacheSettings {
        prefetch: false,
        ..CacheSettings::default()
    });
    off.insert(&k, &message, now, None);
    let asked = query("www.example.test", A, None);
    off.answer(
        &k,
        now + Duration::from_secs(95),
        &client(&asked, None, 512),
        &mut out,
    );
    assert!(off.take_prefetch().is_empty());
}

#[test]
fn a_flush_removes_everything_or_a_suffix() {
    let cache = small(100);
    let now = Instant::now();
    for name in ["www.example.test", "api.example.test", "www.example.net"] {
        assert!(cache.insert(
            &key(name, A),
            &upstream(name, A, 0, &[a(1, 300)], &[], false),
            now,
            None
        ));
    }
    assert_eq!(cache.flush(Some(&wire_name("example.test"))).entries, 2);
    assert_eq!(cache.len(), 1);
    assert!(cache.has_stale(&key("www.example.net", A), now));
    assert_eq!(cache.flush(None).entries, 1);
    assert!(cache.is_empty());
    assert_eq!(cache.stats().bytes, 0);
}

#[test]
fn relay_gives_the_client_its_id_case_and_this_nodes_opt() {
    let message = upstream("WwW.eXample.TeSt", A, 0, &[a(1, 300)], &[], true);
    let asked = query("www.EXAMPLE.test", A, Some(1232));
    let edns = ClientEdns {
        udp_size: 1232,
        dnssec_ok: false,
        cookie: None,
    };
    let mut out = Vec::new();
    assert_eq!(
        relay(&message, &client(&asked, Some(edns), 1232), &mut out),
        Some(0)
    );
    let header = wire::parse_header(&out).expect("header");
    assert_eq!(header.id, 0x1234);
    assert!(header.ra && !header.ad && !header.aa);
    assert_eq!((header.ancount, header.arcount), (1, 1));
    let end = wire::questions_end(&out, 1).expect("question");
    assert_eq!(&out[HEADER_LEN..end], &asked[HEADER_LEN..end]);
    assert_eq!(ttls(&out), vec![300]);
    let mut pos = end;
    pos = wire::read_record(&out, pos).expect("answer").end();
    let opt = wire::read_record(&out, pos).expect("opt");
    assert_eq!((opt.rtype, opt.class, opt.rdlen), (TYPE_OPT, 1232, 0));
    // A question of another length is not this client's.
    let other = query("other.example.test", A, None);
    assert_eq!(relay(&message, &client(&other, None, 512), &mut out), None);
}
