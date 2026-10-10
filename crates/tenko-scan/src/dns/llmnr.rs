//! Link-local multicast name resolution (RFC 4795): what an answer says about the host that
//! sent it.
//!
//! An LLMNR responder only answers for its own names, so the answer to an A or AAAA query names
//! the host and the answer to a PTR query for a reverse name gives the name of that address.
//! There are no services and no operating system hints. Queries are ignored, and so are
//! messages with a non-zero response code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::NameFindings;
use super::collect::Collector;
use super::message::{RecordData, Response, Section, reverse_address};

/// The UDP and TCP port of LLMNR.
pub const LLMNR_PORT: u16 = 5355;
/// The IPv4 multicast group of LLMNR (224.0.0.252).
pub const LLMNR_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
/// The IPv6 multicast group of LLMNR (`ff02::1:3`).
pub const LLMNR_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3);

/// What the answers of a response say. `source` is the address the datagram came from; it is
/// part of the result when the response has at least one answer. Names are kept as given,
/// lower case: a single label like `fileserver` or a full name.
pub fn interpret(source: IpAddr, response: &Response) -> NameFindings {
    if !response.is_response || response.rcode != 0 {
        return NameFindings::default();
    }
    let mut answers = response
        .records
        .iter()
        .filter(|record| record.section == Section::Answer)
        .peekable();
    if answers.peek().is_none() {
        return NameFindings::default();
    }
    let mut collector = Collector::new();
    collector.admit_source(source);
    for record in answers {
        match &record.data {
            RecordData::A(addr) => collector.set_name(IpAddr::V4(*addr), &record.name),
            RecordData::Aaaa(addr) => collector.set_name(IpAddr::V6(*addr), &record.name),
            RecordData::Ptr(target) => {
                if let Some(ip) = reverse_address(&record.name) {
                    collector.set_name(ip, target);
                }
            }
            _ => {}
        }
    }
    collector.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::Record;
    use std::collections::BTreeSet;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rec(section: Section, name: &str, data: RecordData) -> Record {
        Record {
            section,
            name: name.to_string(),
            ttl: 30,
            cache_flush: false,
            data,
        }
    }

    fn response(records: Vec<Record>) -> Response {
        Response {
            id: 1,
            is_response: true,
            truncated: false,
            rcode: 0,
            questions: Vec::new(),
            records,
        }
    }

    const SOURCE: &str = "192.0.2.51";

    #[test]
    fn answers_name_the_hosts() {
        let found = interpret(
            ip(SOURCE),
            &response(vec![
                rec(
                    Section::Answer,
                    "fileserver",
                    RecordData::A("192.0.2.50".parse().unwrap()),
                ),
                rec(
                    Section::Answer,
                    "fileserver",
                    RecordData::Aaaa("2001:db8::50".parse().unwrap()),
                ),
                rec(
                    Section::Answer,
                    "50.2.0.192.in-addr.arpa",
                    RecordData::Ptr("fileserver".to_string()),
                ),
            ]),
        );
        assert_eq!(
            found.addresses,
            BTreeSet::from([ip(SOURCE), ip("192.0.2.50"), ip("2001:db8::50")])
        );
        assert_eq!(found.names[&ip("192.0.2.50")], "fileserver");
        assert_eq!(found.names[&ip("2001:db8::50")], "fileserver");
        assert!(found.services.is_empty());
        assert!(found.os.is_empty());
    }

    #[test]
    fn the_source_needs_an_answer() {
        let additional_only = response(vec![rec(
            Section::Additional,
            "fileserver",
            RecordData::A("192.0.2.50".parse().unwrap()),
        )]);
        assert!(interpret(ip(SOURCE), &additional_only).is_empty());
        assert!(interpret(ip(SOURCE), &response(Vec::new())).is_empty());
        let other_type = response(vec![rec(Section::Answer, "x", RecordData::Other(47))]);
        let found = interpret(ip(SOURCE), &other_type);
        assert_eq!(found.addresses, BTreeSet::from([ip(SOURCE)]));
        assert!(found.names.is_empty());
    }

    #[test]
    fn queries_and_error_responses_are_ignored() {
        let records = vec![rec(
            Section::Answer,
            "fileserver",
            RecordData::A("192.0.2.50".parse().unwrap()),
        )];
        let mut query = response(records.clone());
        query.is_response = false;
        assert!(interpret(ip(SOURCE), &query).is_empty());
        let mut failed = response(records);
        failed.rcode = 3;
        assert!(interpret(ip(SOURCE), &failed).is_empty());
    }

    #[test]
    fn unusable_addresses_are_skipped_and_the_first_name_wins() {
        let found = interpret(
            ip(SOURCE),
            &response(vec![
                rec(
                    Section::Answer,
                    "loop",
                    RecordData::A("127.0.0.1".parse().unwrap()),
                ),
                rec(
                    Section::Answer,
                    "one",
                    RecordData::A("192.0.2.52".parse().unwrap()),
                ),
                rec(
                    Section::Answer,
                    "two",
                    RecordData::A("192.0.2.52".parse().unwrap()),
                ),
            ]),
        );
        assert_eq!(
            found.addresses,
            BTreeSet::from([ip(SOURCE), ip("192.0.2.52")])
        );
        assert_eq!(found.names[&ip("192.0.2.52")], "one");
    }

    #[test]
    fn the_multicast_constants_are_the_registered_groups() {
        assert_eq!(LLMNR_V4.to_string(), "224.0.0.252");
        assert_eq!(LLMNR_V6.to_string(), "ff02::1:3");
        assert_eq!(LLMNR_PORT, 5355);
        assert!(LLMNR_V4.is_multicast() && LLMNR_V6.is_multicast());
    }
}
