//! The dnstap output of the query log, checked with readers that share no code with the
//! writer: a Frame Streams reader written here, a protobuf decoder derived by `prost` from
//! the field layout of `dnstap.proto`, and `hickory-proto` for the DNS messages.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use hickory_proto::op::{Message as DnsMessage, MessageType};
use prost::Message as _;
use tenko_core::dns::{DnsName, QueryTransport};
use tenko_dns::{
    log::{QueryLogEntry, QueryLogSink},
    querylog::{self, ClientField, LogFilter, LogFormat, LogSettings, LogWriter},
};

/// `dnstap.proto`'s `Dnstap`, the fields Tenko writes.
#[derive(Clone, PartialEq, prost::Message)]
struct Dnstap {
    #[prost(bytes = "vec", optional, tag = "1")]
    identity: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    version: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    extra: Option<Vec<u8>>,
    #[prost(message, optional, tag = "14")]
    message: Option<Message>,
    #[prost(int32, required, tag = "15")]
    kind: i32,
}

/// `dnstap.proto`'s `Message`.
#[derive(Clone, PartialEq, prost::Message)]
#[allow(clippy::struct_field_names, reason = "the field names of dnstap.proto")]
struct Message {
    #[prost(int32, required, tag = "1")]
    kind: i32,
    #[prost(int32, optional, tag = "2")]
    socket_family: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    socket_protocol: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    query_address: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    response_address: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "6")]
    query_port: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    response_port: Option<u32>,
    #[prost(uint64, optional, tag = "8")]
    query_time_sec: Option<u64>,
    #[prost(fixed32, optional, tag = "9")]
    query_time_nsec: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "10")]
    query_message: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    query_zone: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "12")]
    response_time_sec: Option<u64>,
    #[prost(fixed32, optional, tag = "13")]
    response_time_nsec: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "14")]
    response_message: Option<Vec<u8>>,
}

const CLIENT_QUERY: i32 = 5;
const CLIENT_RESPONSE: i32 = 6;

/// A Frame Streams file: the content type of its START frame, its data frames, and
/// whether it ends with a STOP frame.
struct Stream {
    content_type: Vec<u8>,
    frames: Vec<Vec<u8>>,
    stopped: bool,
}

fn be32(bytes: &[u8], at: usize) -> usize {
    usize::try_from(u32::from_be_bytes(
        bytes[at..at + 4].try_into().expect("four octets"),
    ))
    .expect("a length")
}

fn read_stream(bytes: &[u8]) -> Stream {
    assert_eq!(be32(bytes, 0), 0, "the file starts with a control frame");
    let length = be32(bytes, 4);
    let control = &bytes[8..8 + length];
    assert_eq!(be32(control, 0), 2, "START");
    assert_eq!(be32(control, 4), 1, "a content type field");
    let type_length = be32(control, 8);
    let content_type = control[12..12 + type_length].to_vec();
    assert_eq!(12 + type_length, control.len());
    let mut at = 8 + length;
    let mut frames = Vec::new();
    let mut stopped = false;
    while at < bytes.len() {
        let length = be32(bytes, at);
        if length == 0 {
            let control_length = be32(bytes, at + 4);
            assert_eq!(control_length, 4);
            assert_eq!(be32(bytes, at + 8), 3, "STOP");
            stopped = true;
            at += 12;
            assert_eq!(at, bytes.len(), "nothing follows STOP");
            break;
        }
        frames.push(bytes[at + 4..at + 4 + length].to_vec());
        at += 4 + length;
    }
    Stream {
        content_type,
        frames,
        stopped,
    }
}

struct Query {
    qname: &'static str,
    qtype: u16,
    rcode: u16,
    client: IpAddr,
    transport: QueryTransport,
    cached: bool,
}

const AT: u64 = 1_792_000_000_123_456;

const QUERIES: [Query; 3] = [
    Query {
        qname: "www.example.test",
        qtype: 1,
        rcode: 0,
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        transport: QueryTransport::Udp,
        cached: false,
    },
    Query {
        qname: "missing.example.test",
        qtype: 28,
        rcode: 3,
        client: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
        transport: QueryTransport::Tcp,
        cached: false,
    },
    Query {
        qname: "old.example.test",
        qtype: 16,
        rcode: 16,
        client: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
        transport: QueryTransport::Dot,
        cached: true,
    },
];

fn write(dir: &Path, client: ClientField) -> Vec<u8> {
    let writer = LogWriter::start(LogSettings {
        format: LogFormat::Dnstap,
        client,
        identity: "node-7".to_owned(),
        version: "0.0.1".to_owned(),
        ..LogSettings::new(dir)
    })
    .expect("writer");
    let sink = writer.sink();
    for (n, query) in QUERIES.iter().enumerate() {
        let qname = DnsName::new(query.qname).expect("name").to_wire();
        sink.record(&QueryLogEntry {
            at_micros: AT + n as u64,
            client: query.client,
            transport: query.transport,
            qname: &qname,
            qtype: query.qtype,
            rcode: query.rcode,
            view: None,
            blocked: None,
            cached: query.cached,
            duration_micros: 250,
        });
    }
    writer.stop();
    let mut names: Vec<_> = fs::read_dir(dir)
        .expect("directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .filter(|name| name.ends_with(".dnstap"))
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    fs::read(dir.join(names.remove(0))).expect("segment")
}

#[test]
fn the_dnstap_segment_decodes_with_independent_readers() {
    let dir = TempDir::new();
    let bytes = write(dir.path(), ClientField::Address);
    let stream = read_stream(&bytes);
    assert_eq!(stream.content_type, b"protobuf:dnstap.Dnstap");
    assert!(stream.stopped, "a closed segment ends with STOP");
    assert_eq!(stream.frames.len(), 2 * QUERIES.len());
    for (n, pair) in stream.frames.chunks(2).enumerate() {
        let expected = &QUERIES[n];
        let offset = u32::try_from(n).expect("small");
        let query = Dnstap::decode(pair[0].as_slice()).expect("protobuf");
        let response = Dnstap::decode(pair[1].as_slice()).expect("protobuf");
        for tap in [&query, &response] {
            assert_eq!(tap.kind, 1, "MESSAGE");
            assert_eq!(tap.identity.as_deref(), Some(&b"node-7"[..]));
            assert_eq!(tap.version.as_deref(), Some(&b"0.0.1"[..]));
            let extra = String::from_utf8(tap.extra.clone().expect("extra")).expect("text");
            assert!(extra.starts_with("tenko;client=address"), "{extra}");
            assert_eq!(extra.ends_with(";cached"), expected.cached, "{extra}");
            let message = tap.message.as_ref().expect("message");
            let (family, octets) = match expected.client {
                IpAddr::V4(v4) => (1, v4.octets().to_vec()),
                IpAddr::V6(v6) => (2, v6.octets().to_vec()),
            };
            assert_eq!(message.socket_family, Some(family));
            assert_eq!(message.query_address.as_deref(), Some(octets.as_slice()));
            let protocol = match expected.transport {
                QueryTransport::Udp => 1,
                QueryTransport::Tcp => 2,
                QueryTransport::Dot => 3,
                QueryTransport::Doh => 4,
            };
            assert_eq!(message.socket_protocol, Some(protocol));
            assert_eq!(message.query_time_sec, Some(1_792_000_000));
            assert_eq!(message.query_time_nsec, Some((123_456 + offset) * 1_000));
        }
        let asked = query.message.expect("message");
        assert_eq!(asked.kind, CLIENT_QUERY);
        assert_eq!(asked.response_message, None);
        let wire = DnsMessage::from_vec(&asked.query_message.expect("query message"))
            .expect("a DNS query");
        assert_eq!(wire.metadata.message_type, MessageType::Query);
        assert_eq!(wire.queries.len(), 1);
        assert_eq!(
            wire.queries[0].name().to_ascii(),
            format!("{}.", expected.qname)
        );
        assert_eq!(u16::from(wire.queries[0].query_type()), expected.qtype);

        let answered = response.message.expect("message");
        assert_eq!(answered.kind, CLIENT_RESPONSE);
        assert_eq!(answered.response_time_sec, Some(1_792_000_000));
        assert_eq!(
            answered.response_time_nsec,
            Some((123_456 + offset + 250) * 1_000)
        );
        let wire = DnsMessage::from_vec(&answered.response_message.expect("response message"))
            .expect("a DNS response");
        assert_eq!(wire.metadata.message_type, MessageType::Response);
        assert_eq!(u16::from(wire.metadata.response_code), expected.rcode);
        assert_eq!(
            wire.queries[0].name().to_ascii(),
            format!("{}.", expected.qname)
        );
    }

    let page = querylog::read(dir.path(), None, 10, &LogFilter::default()).expect("page");
    assert_eq!(page.lines.len(), 3);
    assert_eq!(page.lines[0].qname, "old.example.test");
    assert_eq!(page.lines[0].rcode, 16);
    assert!(page.lines[0].cached);
    assert_eq!(page.lines[0].transport, QueryTransport::Dot);
    assert_eq!(page.lines[1].client.as_deref(), Some("2001:db8::10"));
    assert_eq!(page.lines[2].duration_micros, 250);
}

#[test]
fn pseudonymised_and_hidden_clients_never_reach_the_file() {
    let dir = TempDir::new();
    let bytes = write(dir.path(), ClientField::Pseudonym);
    for frame in read_stream(&bytes).frames {
        let tap = Dnstap::decode(frame.as_slice()).expect("protobuf");
        let message = tap.message.expect("message");
        let address = message.query_address.expect("a pseudonymised address");
        assert!(address.len() == 4 || address.len() == 16);
        for query in &QUERIES {
            let octets = match query.client {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            assert_ne!(address, octets);
        }
        assert!(
            String::from_utf8(tap.extra.expect("extra"))
                .expect("text")
                .starts_with("tenko;client=pseudonym")
        );
    }
    let lines = querylog::read(dir.path(), None, 10, &LogFilter::default())
        .expect("page")
        .lines;
    assert!(lines.iter().all(|line| {
        line.client
            .as_deref()
            .is_some_and(|client| client.starts_with("p:"))
    }));
    let by_address = LogFilter {
        client: Some("2001:db8::10".to_owned()),
        ..LogFilter::default()
    };
    let found = querylog::read(dir.path(), None, 10, &by_address).expect("page");
    assert_eq!(found.lines.len(), 1);
    assert_eq!(found.lines[0].qname, "missing.example.test");

    let hidden = TempDir::new();
    let bytes = write(hidden.path(), ClientField::Hidden);
    for frame in read_stream(&bytes).frames {
        let tap = Dnstap::decode(frame.as_slice()).expect("protobuf");
        assert_eq!(tap.message.expect("message").query_address, None);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tenko-dnstap-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&path).expect("directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
