//! The transfer client against a primary on loopback that answers as the test says.

use std::time::Duration;

use tenko_core::dns::{Rdata, RecordData};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
use crate::xfr::message::{MessageWriter, TYPE_SOA, read_request};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn soa(serial: u32) -> Rdata {
    Rdata::from_data(&RecordData::Soa {
        mname: name("ns1.example.test"),
        rname: name("hostmaster.example.test"),
        serial,
        refresh: 3600,
        retry: 600,
        expire: 86_400,
        minimum: 60,
    })
}

fn txt(text: &str) -> Rdata {
    Rdata::from_data(&RecordData::txt(text))
}

/// What the fake primary sends after the opening SOA.
#[derive(Clone, Copy)]
enum Feed {
    /// One in-zone and one out-of-zone record, then the closing SOA.
    Mixed,
    /// Messages of large TXT records without end, as fast as they go.
    Endless,
    /// One record every 100 ms without end: never idle, never done.
    Trickle,
    /// The SOA with this serial alone, as the whole answer.
    SoaOnly(u32),
}

/// A primary on loopback that answers one AXFR of `example.test` with `feed`.
async fn primary(feed: Feed) -> Primary {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let len = usize::from(stream.read_u16().await.expect("length"));
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await.expect("request");
        let request = read_request(&message).expect("a request");
        let apex = name("example.test").to_wire();
        let mut writer = MessageWriter::new(&message, &request, 16 * 1024);
        let mut send = async |writer: &mut MessageWriter| {
            let out = writer.take();
            let mut framed = u16::try_from(out.len())
                .expect("size")
                .to_be_bytes()
                .to_vec();
            framed.extend_from_slice(&out);
            stream.write_all(&framed).await.is_ok()
        };
        let opening = match feed {
            Feed::SoaOnly(serial) => serial,
            _ => 5,
        };
        writer.push(&apex, TYPE_SOA, 60, soa(opening).as_bytes());
        let big = txt(&"x".repeat(200));
        match feed {
            Feed::Mixed => {
                writer.push(&name("www.example.test").to_wire(), 16, 60, big.as_bytes());
                writer.push(&name("www.example.net").to_wire(), 16, 60, big.as_bytes());
                writer.push(&apex, TYPE_SOA, 60, soa(5).as_bytes());
                let _ = send(&mut writer).await;
            }
            Feed::Endless => {
                for index in 0u64.. {
                    let owner = name(&format!("h{index}.example.test")).to_wire();
                    if !writer.push(&owner, 16, 60, big.as_bytes()) && !send(&mut writer).await {
                        return;
                    }
                }
            }
            Feed::SoaOnly(_) => {
                let _ = send(&mut writer).await;
            }
            Feed::Trickle => loop {
                if !send(&mut writer).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                writer.push(&name("www.example.test").to_wire(), 16, 60, big.as_bytes());
            },
        }
    });
    Primary {
        address,
        key: None,
        tls: None,
    }
}

#[tokio::test]
async fn records_outside_the_zone_are_dropped_as_they_arrive() {
    let primary = primary(Feed::Mixed).await;
    let fetched = fetch(&primary, &name("example.test"), None, Limits::default())
        .await
        .expect("a transfer");
    let Fetched::Full { records, .. } = fetched else {
        panic!("a full transfer");
    };
    let owners: Vec<String> = records.iter().map(|r| r.name.to_string()).collect();
    assert_eq!(owners, ["example.test", "www.example.test"]);
}

/// A primary cannot make the client hold more than the byte limit.
#[tokio::test]
async fn a_transfer_larger_than_the_byte_limit_fails() {
    let primary = primary(Feed::Endless).await;
    let limits = Limits {
        max_bytes: 256 * 1024,
        ..Limits::default()
    };
    let error = fetch(&primary, &name("example.test"), None, limits)
        .await
        .expect_err("over the limit");
    assert_eq!(error.code, codes::TRANSFER_FAILED);
    assert!(error.detail.contains("octets"), "{}", error.detail);
}

/// A primary that keeps sending just often enough never trips the idle limit, but the
/// deadline of the whole refresh ends it and frees the slot.
#[tokio::test]
async fn a_transfer_longer_than_the_deadline_fails() {
    let primary = primary(Feed::Trickle).await;
    let limits = Limits {
        idle: Duration::from_secs(5),
        deadline: Duration::from_millis(700),
        ..Limits::default()
    };
    let started = std::time::Instant::now();
    let error = fetch(&primary, &name("example.test"), None, limits)
        .await
        .expect_err("past the deadline");
    assert!(
        error.detail.contains("longer than the limit"),
        "{}",
        error.detail
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

fn held(serial: u32) -> Held {
    Held {
        serial,
        ttl: 60,
        rdata: soa(serial).as_bytes().to_vec(),
    }
}

/// RFC 1982: an IXFR answered with an older SOA alone is not "current": the copy is kept
/// and the state names the older serial. The same serial is current.
#[tokio::test]
async fn an_ixfr_answered_with_an_older_soa_is_not_current() {
    let older = primary(Feed::SoaOnly(3)).await;
    let error = fetch(
        &older,
        &name("example.test"),
        Some(&held(5)),
        Limits::default(),
    )
    .await
    .expect_err("older");
    assert_eq!(error.code, OLDER_SERIAL);
    let same = primary(Feed::SoaOnly(5)).await;
    let fetched = fetch(
        &same,
        &name("example.test"),
        Some(&held(5)),
        Limits::default(),
    )
    .await
    .expect("current");
    assert_eq!(fetched, Fetched::Current { serial: 5 });
}
