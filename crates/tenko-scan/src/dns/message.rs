//! A small DNS message layer: queries out, responses in.
//!
//! Everything here is a pure function over bytes. Parsing and building go through the
//! `domain` crate; this module only bounds and cleans what comes out of it, because the
//! input is whatever a host on the network chose to send.
//!
//! Bounds for untrusted input:
//!
//! * a message over [`MAX_MESSAGE_LEN`] bytes is refused;
//! * at most [`MAX_RECORDS`] records and [`MAX_QUESTIONS`] questions are read, the rest is
//!   ignored;
//! * names, TXT strings and HINFO strings are converted lossily to UTF-8, lose control
//!   characters and invisible direction marks, and are cut to [`MAX_TEXT_CHARS`] characters;
//! * a record whose data does not parse is skipped, and so is every record of another class
//!   than IN (the mDNS cache-flush bit in the class is split off first);
//! * a header that does not parse is an error.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use domain::base::iana::Class;
use domain::base::message::Section as WireSection;
use domain::base::name::{NameBuilder, ParsedName};
use domain::base::{Message, MessageBuilder, Name, ParsedRecord, Rtype};
use domain::rdata::{A, Aaaa, Hinfo, Ptr, Srv, Txt};

/// The largest message that is parsed. Larger datagrams are refused.
pub const MAX_MESSAGE_LEN: usize = 9_000;
/// The most records read from one message, over all sections.
pub const MAX_RECORDS: usize = 256;
/// The most questions read from one message.
pub const MAX_QUESTIONS: usize = 32;
/// The longest name or text kept, in characters.
pub const MAX_TEXT_CHARS: usize = 255;
/// The most strings kept from one TXT record.
const MAX_TXT_STRINGS: usize = 64;

/// The top bit of a class: the cache-flush bit in answers, the unicast-response bit in
/// questions (RFC 6762, sections 5.4 and 10.2).
const CLASS_TOP_BIT: u16 = 0x8000;

/// The type of a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Pointer, used for reverse lookups and service browsing.
    Ptr,
    /// Service location.
    Srv,
    /// Text strings.
    Txt,
    /// Every record type.
    Any,
}

impl QueryType {
    fn rtype(self) -> Rtype {
        match self {
            QueryType::A => Rtype::A,
            QueryType::Aaaa => Rtype::AAAA,
            QueryType::Ptr => Rtype::PTR,
            QueryType::Srv => Rtype::SRV,
            QueryType::Txt => Rtype::TXT,
            QueryType::Any => Rtype::ANY,
        }
    }
}

/// Header bits and flags of a query.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryOptions {
    /// The message identifier. mDNS multicast queries use 0.
    pub id: u16,
    /// Ask a resolver to resolve recursively (the RD bit).
    pub recursion_desired: bool,
    /// Ask for a unicast answer to a multicast query: sets the QU bit, the top bit of the
    /// question class (RFC 6762, section 5.4).
    pub unicast_response: bool,
}

/// A DNS message that cannot be built or parsed. The detail is English and never repeats the
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError(String);

impl DnsError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    /// What is wrong with the message.
    pub fn detail(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsError {}

/// The section of a message a record was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// The answer section.
    Answer,
    /// The authority section.
    Authority,
    /// The additional section.
    Additional,
}

/// The data of a record, for the types the scanner reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// A pointer to a name (lower case, no trailing dot).
    Ptr(String),
    /// A service location.
    Srv {
        /// Lower numbers are tried first.
        priority: u16,
        /// Relative weight among equal priorities.
        weight: u16,
        /// The port of the service.
        port: u16,
        /// The host that provides the service (lower case, no trailing dot).
        target: String,
    },
    /// The strings of a TXT record.
    Txt(Vec<String>),
    /// A host information record.
    Hinfo {
        /// The CPU field.
        cpu: String,
        /// The operating system field.
        os: String,
    },
    /// A record of another type: the numeric type.
    Other(u16),
}

/// One resource record of class IN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The section of the message the record is in.
    pub section: Section,
    /// The owner name, lower case, without a trailing dot.
    pub name: String,
    /// Time to live in seconds.
    pub ttl: u32,
    /// mDNS: the top bit of the class was set (RFC 6762, section 10.2).
    pub cache_flush: bool,
    /// The data.
    pub data: RecordData,
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The message identifier.
    pub id: u16,
    /// The QR bit: the message is a response, not a query.
    pub is_response: bool,
    /// The TC bit: the message was truncated.
    pub truncated: bool,
    /// The response code of the header (4 bits).
    pub rcode: u8,
    /// The questions: the name (lower case, no trailing dot) and the numeric type.
    pub questions: Vec<(String, u16)>,
    /// The records of class IN that parsed, in message order.
    pub records: Vec<Record>,
}

/// Builds a query with one question of class IN.
///
/// The name is given in text form with or without a trailing dot. Labels are taken as they
/// are, without escape sequences; empty labels, control characters, labels over 63 bytes and
/// names over 253 bytes are refused.
///
/// # Errors
///
/// Returns an error for a name that is not a valid DNS name.
pub fn build_query(
    name: &str,
    qtype: QueryType,
    options: QueryOptions,
) -> Result<Vec<u8>, DnsError> {
    let qname = query_name(name)?;
    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(options.id);
    header.set_rd(options.recursion_desired);
    let class = if options.unicast_response {
        Class::from_int(Class::IN.to_int() | CLASS_TOP_BIT)
    } else {
        Class::IN
    };
    let mut questions = builder.question();
    questions
        .push((qname, qtype.rtype(), class))
        .map_err(|error| DnsError::new(format!("the question does not fit: {error}")))?;
    Ok(questions.finish())
}

fn query_name(name: &str) -> Result<Name<Vec<u8>>, DnsError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(DnsError::new("the query name is empty"));
    }
    if trimmed.len() > 253 {
        return Err(DnsError::new("the query name is longer than 253 bytes"));
    }
    let mut builder = NameBuilder::new_vec();
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::new("the query name has an empty label"));
        }
        if label.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(DnsError::new("the query name has a control character"));
        }
        builder
            .append_label(label.as_bytes())
            .map_err(|_| DnsError::new("a label of the query name is longer than 63 bytes"))?;
    }
    builder
        .into_name()
        .map_err(|_| DnsError::new("the query name is too long"))
}

/// The reverse lookup name of an address, without a trailing dot: `4.3.2.192.in-addr.arpa`
/// for IPv4 and the lower-case nibble form under `ip6.arpa` for IPv6. An IPv4-mapped IPv6
/// address uses the IPv4 form.
pub fn reverse_name(ip: IpAddr) -> String {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(73);
            for byte in v6.octets().iter().rev() {
                push_nibble(&mut out, byte & 0x0f);
                out.push('.');
                push_nibble(&mut out, byte >> 4);
                out.push('.');
            }
            out.push_str("ip6.arpa");
            out
        }
    }
}

fn push_nibble(out: &mut String, nibble: u8) {
    out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
}

/// The address a reverse lookup name stands for: the inverse of [`reverse_name`]. Accepts a
/// trailing dot and any letter case. Returns `None` for a name that is not a complete
/// `in-addr.arpa` or `ip6.arpa` name.
pub fn reverse_address(name: &str) -> Option<IpAddr> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.len() > 80 {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if let Some(prefix) = lower.strip_suffix(".in-addr.arpa") {
        let mut octets = [0u8; 4];
        let mut count = 0;
        for label in prefix.split('.') {
            if count == 4 || label.is_empty() || label.len() > 3 {
                return None;
            }
            if !label.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            octets[3 - count] = label.parse().ok()?;
            count += 1;
        }
        return (count == 4).then(|| IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if let Some(prefix) = lower.strip_suffix(".ip6.arpa") {
        let mut octets = [0u8; 16];
        let mut count = 0;
        for label in prefix.split('.') {
            if count == 32 {
                return None;
            }
            let mut chars = label.chars();
            let digit = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            let nibble = u8::try_from(digit.to_digit(16)?).ok()?;
            let index = 15 - count / 2;
            if count % 2 == 0 {
                octets[index] |= nibble;
            } else {
                octets[index] |= nibble << 4;
            }
            count += 1;
        }
        return (count == 32).then(|| IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

/// Parses a DNS message, for a response or for a query alike.
///
/// Unparsable records are skipped; see the module documentation for the bounds.
///
/// # Errors
///
/// Returns an error for a message over [`MAX_MESSAGE_LEN`] bytes and for one that is shorter
/// than the 12 byte header.
pub fn parse_response(bytes: &[u8]) -> Result<Response, DnsError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(DnsError::new(format!(
            "the message has {} bytes, more than the limit of {MAX_MESSAGE_LEN}",
            bytes.len()
        )));
    }
    let message = Message::from_slice(bytes)
        .map_err(|_| DnsError::new("the message is shorter than the 12 byte header"))?;
    let header = message.header();

    let mut questions = Vec::new();
    for question in message.question().take(MAX_QUESTIONS) {
        let Ok(question) = question else { break };
        questions.push((render_name(question.qname()), question.qtype().to_int()));
    }

    let mut records = Vec::new();
    for item in message.iter().take(MAX_RECORDS) {
        let Ok((record, section)) = item else { break };
        if let Some(record) = convert_record(&record, section) {
            records.push(record);
        }
    }

    Ok(Response {
        id: header.id(),
        is_response: header.qr(),
        truncated: header.tc(),
        rcode: header.rcode().to_int(),
        questions,
        records,
    })
}

fn convert_record(record: &ParsedRecord<'_, [u8]>, section: WireSection) -> Option<Record> {
    let class = record.class().to_int();
    if class & !CLASS_TOP_BIT != Class::IN.to_int() {
        return None;
    }
    Some(Record {
        section: match section {
            WireSection::Answer => Section::Answer,
            WireSection::Authority => Section::Authority,
            WireSection::Additional => Section::Additional,
        },
        name: render_name(&record.owner()),
        ttl: record.ttl().as_secs(),
        cache_flush: class & CLASS_TOP_BIT != 0,
        data: convert_data(record)?,
    })
}

fn convert_data(record: &ParsedRecord<'_, [u8]>) -> Option<RecordData> {
    match record.rtype() {
        Rtype::A => {
            let parsed = record.to_record::<A>().ok()??;
            Some(RecordData::A(parsed.data().addr()))
        }
        Rtype::AAAA => {
            let parsed = record.to_record::<Aaaa>().ok()??;
            Some(RecordData::Aaaa(parsed.data().addr()))
        }
        Rtype::PTR => {
            let parsed = record.to_record::<Ptr<ParsedName<&[u8]>>>().ok()??;
            Some(RecordData::Ptr(render_name(parsed.data().ptrdname())))
        }
        Rtype::SRV => {
            let parsed = record.to_record::<Srv<ParsedName<&[u8]>>>().ok()??;
            let srv = parsed.data();
            Some(RecordData::Srv {
                priority: srv.priority(),
                weight: srv.weight(),
                port: srv.port(),
                target: render_name(srv.target()),
            })
        }
        Rtype::TXT => {
            let parsed = record.to_record::<Txt<&[u8]>>().ok()??;
            let strings = parsed
                .data()
                .iter()
                .take(MAX_TXT_STRINGS)
                .map(clean_text)
                .collect();
            Some(RecordData::Txt(strings))
        }
        Rtype::HINFO => {
            let parsed = record.to_record::<Hinfo<&[u8]>>().ok()??;
            let hinfo = parsed.data();
            Some(RecordData::Hinfo {
                cpu: clean_text(hinfo.cpu().as_slice()),
                os: clean_text(hinfo.os().as_slice()),
            })
        }
        other => Some(RecordData::Other(other.to_int())),
    }
}

/// A name as lower-case text without a trailing dot.
fn render_name(name: &ParsedName<&[u8]>) -> String {
    let mut out = String::new();
    for label in name {
        let text = clean_text(label.as_ref());
        if text.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&text);
        if out.len() > MAX_TEXT_CHARS * 4 {
            break;
        }
    }
    out.make_ascii_lowercase();
    if let Some((cut, _)) = out.char_indices().nth(MAX_TEXT_CHARS) {
        out.truncate(cut);
    }
    out
}

/// Bytes as text: lossy UTF-8, without control characters and invisible direction marks, cut
/// to [`MAX_TEXT_CHARS`] characters.
fn clean_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !is_unsafe_char(*c))
        .take(MAX_TEXT_CHARS)
        .collect()
}

fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// The targets of the PTR records in the answer section whose owner is the reverse name of
/// `ip`, without duplicates and in message order.
pub fn ptr_names(response: &Response, ip: IpAddr) -> Vec<String> {
    let owner = reverse_name(ip);
    let mut names: Vec<String> = Vec::new();
    for record in &response.records {
        if record.section != Section::Answer || record.name != owner {
            continue;
        }
        if let RecordData::Ptr(target) = &record.data
            && !target.is_empty()
            && !names.contains(target)
        {
            names.push(target.clone());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ptr_query_bytes_with_recursion_desired() {
        let bytes = build_query(
            "40.2.0.192.in-addr.arpa",
            QueryType::Ptr,
            QueryOptions {
                id: 0x1234,
                recursion_desired: true,
                unicast_response: false,
            },
        )
        .unwrap();
        let expected: Vec<u8> = [
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[2, b'4', b'0', 1, b'2', 1, b'0', 3, b'1', b'9', b'2'],
            &[7, b'i', b'n', b'-', b'a', b'd', b'd', b'r'],
            &[4, b'a', b'r', b'p', b'a', 0],
            &[0, 12, 0, 1],
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn unicast_response_sets_the_top_class_bit() {
        let bytes = build_query(
            "_services._dns-sd._udp.local.",
            QueryType::Ptr,
            QueryOptions {
                unicast_response: true,
                ..QueryOptions::default()
            },
        )
        .unwrap();
        assert_eq!(&bytes[bytes.len() - 4..], &[0x00, 0x0c, 0x80, 0x01]);
        assert_eq!(&bytes[..4], &[0, 0, 0, 0], "id 0 and no flags");
        let parsed = parse_response(&bytes).unwrap();
        assert!(!parsed.is_response);
        assert_eq!(
            parsed.questions,
            vec![("_services._dns-sd._udp.local".to_string(), 12)]
        );
    }

    #[test]
    fn query_types_map_to_their_numbers() {
        let cases = [
            (QueryType::A, 1),
            (QueryType::Aaaa, 28),
            (QueryType::Ptr, 12),
            (QueryType::Srv, 33),
            (QueryType::Txt, 16),
            (QueryType::Any, 255),
        ];
        for (qtype, number) in cases {
            let bytes = build_query("host.local", qtype, QueryOptions::default()).unwrap();
            let parsed = parse_response(&bytes).unwrap();
            assert_eq!(parsed.questions, vec![("host.local".to_string(), number)]);
        }
    }

    #[test]
    fn trailing_dot_is_optional() {
        let with = build_query("a.example.net.", QueryType::A, QueryOptions::default());
        let without = build_query("a.example.net", QueryType::A, QueryOptions::default());
        assert_eq!(with.unwrap(), without.unwrap());
    }

    #[test]
    fn invalid_names_are_refused() {
        let options = QueryOptions::default();
        let long_label = "a".repeat(64);
        let long_name = vec!["a".repeat(50); 6].join(".");
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a\u{0}b.local",
            "a\nb.local",
            &long_label,
            &long_name,
        ] {
            assert!(
                build_query(bad, QueryType::A, options).is_err(),
                "{bad:?} must be refused"
            );
        }
        let longest_label = "a".repeat(63);
        assert!(build_query(&longest_label, QueryType::A, options).is_ok());
    }

    #[test]
    fn labels_may_hold_spaces_and_utf8() {
        let bytes = build_query(
            "Office Printer._ipp._tcp.local",
            QueryType::Srv,
            QueryOptions::default(),
        )
        .unwrap();
        let parsed = parse_response(&bytes).unwrap();
        assert_eq!(parsed.questions[0].0, "office printer._ipp._tcp.local");
    }

    #[test]
    fn error_display_is_the_detail() {
        let error = build_query("", QueryType::A, QueryOptions::default()).unwrap_err();
        assert_eq!(error.to_string(), error.detail());
        assert_ne!(error.detail(), "");
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_ne!(boxed.to_string(), "");
    }

    #[test]
    fn reverse_name_for_ipv4() {
        assert_eq!(reverse_name(v4(192, 0, 2, 40)), "40.2.0.192.in-addr.arpa");
        assert_eq!(
            reverse_name(v4(198, 51, 100, 7)),
            "7.100.51.198.in-addr.arpa"
        );
    }

    #[test]
    fn reverse_name_for_ipv6_uses_lower_case_nibbles() {
        let ip: IpAddr = "2001:db8::4a".parse().unwrap();
        assert_eq!(
            reverse_name(ip),
            "a.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn reverse_name_for_a_mapped_address_is_the_ipv4_form() {
        let ip: IpAddr = "::ffff:192.0.2.40".parse().unwrap();
        assert_eq!(reverse_name(ip), "40.2.0.192.in-addr.arpa");
    }

    #[test]
    fn reverse_address_inverts_reverse_name() {
        for text in [
            "192.0.2.40",
            "198.51.100.7",
            "0.0.0.0",
            "255.255.255.255",
            "2001:db8::50",
            "2001:db8:ffff::1",
            "::1",
        ] {
            let ip: IpAddr = text.parse().unwrap();
            assert_eq!(reverse_address(&reverse_name(ip)), Some(ip), "{text}");
            assert_eq!(
                reverse_address(&format!("{}.", reverse_name(ip).to_uppercase())),
                Some(ip),
                "{text} with a trailing dot and capitals"
            );
        }
    }

    #[test]
    fn reverse_address_refuses_other_names() {
        for bad in [
            "",
            "printer.local",
            "in-addr.arpa",
            "2.0.192.in-addr.arpa",
            "1.40.2.0.192.in-addr.arpa",
            "256.2.0.192.in-addr.arpa",
            "+1.2.0.192.in-addr.arpa",
            "a.2.0.192.in-addr.arpa",
            "0.2.0.192.in-addr.arpa.example.net",
            "ip6.arpa",
            "0.ip6.arpa",
            "g.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "00.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "0.a.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ] {
            assert_eq!(reverse_address(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn short_and_oversized_messages_are_errors() {
        assert!(parse_response(&[]).is_err());
        assert!(parse_response(&[0; 11]).is_err());
        assert!(parse_response(&[0; 12]).is_ok());
        assert!(parse_response(&vec![0; MAX_MESSAGE_LEN]).is_ok());
        let error = parse_response(&vec![0; MAX_MESSAGE_LEN + 1]).unwrap_err();
        assert!(error.detail().contains("9001"));
    }

    #[test]
    fn text_is_cleaned_and_cut() {
        assert_eq!(clean_text(b"a\x00b\x1b[31mc\x7fd"), "ab[31mcd");
        assert_eq!(clean_text("tab\tnew\nline".as_bytes()), "tabnewline");
        assert_eq!(clean_text("\u{202e}evil\u{200b}".as_bytes()), "evil");
        assert_eq!(clean_text(&[b'o', 0xff, b'k']), "o\u{fffd}k");
        let long = vec![b'x'; 300];
        assert_eq!(clean_text(&long).chars().count(), MAX_TEXT_CHARS);
        assert_eq!(clean_text("Café Printer".as_bytes()), "Café Printer");
    }

    #[test]
    fn ptr_names_reads_only_answers_of_the_reverse_owner() {
        let ip = v4(192, 0, 2, 40);
        let ptr = |section, name: &str, target: &str| Record {
            section,
            name: name.to_string(),
            ttl: 120,
            cache_flush: false,
            data: RecordData::Ptr(target.to_string()),
        };
        let response = Response {
            id: 0,
            is_response: true,
            truncated: false,
            rcode: 0,
            questions: Vec::new(),
            records: vec![
                ptr(Section::Answer, "40.2.0.192.in-addr.arpa", "printer.local"),
                ptr(Section::Answer, "41.2.0.192.in-addr.arpa", "other.local"),
                ptr(
                    Section::Additional,
                    "40.2.0.192.in-addr.arpa",
                    "extra.local",
                ),
                ptr(Section::Answer, "40.2.0.192.in-addr.arpa", "printer.local"),
                ptr(Section::Answer, "40.2.0.192.in-addr.arpa", "alias.local"),
            ],
        };
        assert_eq!(
            ptr_names(&response, ip),
            vec!["printer.local".to_string(), "alias.local".to_string()]
        );
        assert_eq!(
            ptr_names(&response, v4(192, 0, 2, 99)),
            Vec::<String>::new()
        );
    }
}
