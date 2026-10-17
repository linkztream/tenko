//! Queries for the tests and a small decoder of answers: names as the server wrote them
//! (case kept, pointers followed), the names inside NS, CNAME, PTR, DNAME, MX and SRV data,
//! and the OPT record with its options. Every answer is also read by `hickory-proto`, an
//! independent decoder, so a malformed message fails the test.

use tenko_dns::wire::{self, RawHeader};

/// A query to build.
#[derive(Debug, Clone)]
pub struct Query {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
    pub rd: bool,
    pub opcode: u8,
    pub edns: Option<Edns>,
}

/// The OPT record of a query.
#[derive(Debug, Clone)]
pub struct Edns {
    pub size: u16,
    pub dnssec_ok: bool,
    pub version: u8,
    pub cookie: Option<Vec<u8>>,
    pub other: Vec<(u16, Vec<u8>)>,
}

/// A query for `name` and `qtype` with EDNS (1232), no RD.
pub fn query(name: &str, qtype: u16) -> Query {
    Query {
        name: name.to_string(),
        qtype,
        class: 1,
        rd: false,
        opcode: 0,
        edns: Some(Edns {
            size: 1232,
            dnssec_ok: false,
            version: 0,
            cookie: None,
            other: Vec::new(),
        }),
    }
}

impl Query {
    #[must_use]
    pub fn rd(mut self) -> Self {
        self.rd = true;
        self
    }

    #[must_use]
    pub fn no_edns(mut self) -> Self {
        self.edns = None;
        self
    }

    fn edns_mut(&mut self) -> &mut Edns {
        self.edns.get_or_insert(Edns {
            size: 1232,
            dnssec_ok: false,
            version: 0,
            cookie: None,
            other: Vec::new(),
        })
    }

    #[must_use]
    pub fn dnssec(mut self) -> Self {
        self.edns_mut().dnssec_ok = true;
        self
    }

    #[must_use]
    pub fn size(mut self, size: u16) -> Self {
        self.edns_mut().size = size;
        self
    }

    #[must_use]
    pub fn version(mut self, version: u8) -> Self {
        self.edns_mut().version = version;
        self
    }

    #[must_use]
    pub fn cookie(mut self, cookie: &[u8]) -> Self {
        self.edns_mut().cookie = Some(cookie.to_vec());
        self
    }

    #[must_use]
    pub fn option(mut self, code: u16, value: &[u8]) -> Self {
        self.edns_mut().other.push((code, value.to_vec()));
        self
    }

    #[must_use]
    pub fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }

    #[must_use]
    pub fn opcode(mut self, opcode: u8) -> Self {
        self.opcode = opcode;
        self
    }

    /// The query's octets with message id `id`.
    pub fn bytes(&self, id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.push((self.opcode << 3) | u8::from(self.rd));
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(self.edns.is_some())]);
        for label in self.name.split('.').filter(|label| !label.is_empty()) {
            out.push(u8::try_from(label.len()).expect("label"));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        if let Some(edns) = &self.edns {
            let mut options = Vec::new();
            if let Some(cookie) = &edns.cookie {
                options.extend_from_slice(&10u16.to_be_bytes());
                options.extend_from_slice(&u16::try_from(cookie.len()).expect("len").to_be_bytes());
                options.extend_from_slice(cookie);
            }
            for (code, value) in &edns.other {
                options.extend_from_slice(&code.to_be_bytes());
                options.extend_from_slice(&u16::try_from(value.len()).expect("len").to_be_bytes());
                options.extend_from_slice(value);
            }
            out.push(0);
            out.extend_from_slice(&41u16.to_be_bytes());
            out.extend_from_slice(&edns.size.to_be_bytes());
            out.push(0);
            out.push(edns.version);
            out.push(if edns.dnssec_ok { 0x80 } else { 0 });
            out.push(0);
            out.extend_from_slice(&u16::try_from(options.len()).expect("len").to_be_bytes());
            out.extend_from_slice(&options);
        }
        out
    }
}

/// One record of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rec {
    /// The owner as written, case kept, without the final dot.
    pub owner: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    /// The data as written (names inside may be compressed).
    pub rdata: Vec<u8>,
    /// The name inside NS, CNAME, PTR, DNAME, MX and SRV data, decompressed.
    pub target: Option<String>,
}

/// The OPT record of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub udp_size: u16,
    pub dnssec_ok: bool,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Opt {
    pub fn option(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(candidate, _)| *candidate == code)
            .map(|(_, value)| &value[..])
    }

    /// The extended error's info code (RFC 8914).
    pub fn ede(&self) -> Option<u16> {
        self.option(15)
            .map(|value| u16::from_be_bytes([value[0], value[1]]))
    }
}

/// A decoded answer.
#[derive(Debug, Clone)]
pub struct Answer {
    pub header: RawHeader,
    /// The full RCODE: the header's four bits and OPT's eight.
    pub rcode: u16,
    pub question: String,
    pub answers: Vec<Rec>,
    pub authority: Vec<Rec>,
    /// Without the OPT record.
    pub additional: Vec<Rec>,
    pub opt: Option<Opt>,
}

impl Answer {
    pub fn ede(&self) -> Option<u16> {
        self.opt.as_ref().and_then(Opt::ede)
    }
}

/// The name at `pos` as written (case kept), and the position after it where it started.
pub fn name_at(message: &[u8], pos: usize) -> (String, usize) {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = pos;
    let mut end = None;
    for _ in 0..256 {
        let len = message[cursor];
        if len == 0 {
            return (labels.join("."), end.unwrap_or(cursor + 1));
        }
        if len >= 0xc0 {
            end.get_or_insert(cursor + 2);
            cursor = usize::from(u16::from_be_bytes([len & 0x3f, message[cursor + 1]]));
            continue;
        }
        let len = usize::from(len);
        labels.push(String::from_utf8_lossy(&message[cursor + 1..cursor + 1 + len]).into_owned());
        cursor += 1 + len;
    }
    panic!("a name with a pointer loop");
}

fn target(message: &[u8], rtype: u16, rdata: usize) -> Option<String> {
    match rtype {
        2 | 5 | 12 | 39 => Some(name_at(message, rdata).0),
        15 => Some(name_at(message, rdata + 2).0),
        33 => Some(name_at(message, rdata + 6).0),
        _ => None,
    }
}

/// Decodes an answer; panics when it does not parse here or in `hickory-proto`.
pub fn decode(message: &[u8]) -> Answer {
    hickory_proto::op::Message::from_vec(message).expect("an independent decoder reads the answer");
    let header = wire::parse_header(message).expect("header");
    assert!(header.qr, "a response");
    let mut pos = wire::HEADER_LEN;
    let mut question = String::new();
    if header.qdcount == 1 {
        let (name, end) = name_at(message, pos);
        question = name;
        pos = end + 4;
    }
    let mut sections: [Vec<Rec>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut opt = None;
    let mut rcode = u16::from(header.rcode);
    let counts = [header.ancount, header.nscount, header.arcount];
    for (section, count) in counts.iter().enumerate() {
        for _ in 0..*count {
            let record = wire::read_record(message, pos).expect("record");
            pos = record.end();
            if record.rtype == 41 {
                rcode |= u16::try_from(record.ttl >> 24).expect("byte") << 4;
                opt = Some(Opt {
                    udp_size: record.class,
                    dnssec_ok: record.ttl & 0x8000 != 0,
                    options: wire::options(record.data(message))
                        .map(|(code, value)| (code, value.to_vec()))
                        .collect(),
                });
                continue;
            }
            sections[section].push(Rec {
                owner: name_at(message, record.start).0,
                rtype: record.rtype,
                class: record.class,
                ttl: record.ttl,
                rdata: record.data(message).to_vec(),
                target: target(message, record.rtype, record.rdata),
            });
        }
    }
    assert_eq!(pos, message.len(), "no octets after the last record");
    let [answers, authority, additional] = sections;
    Answer {
        header,
        rcode,
        question,
        answers,
        authority,
        additional,
        opt,
    }
}
