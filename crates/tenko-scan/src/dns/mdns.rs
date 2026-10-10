//! Multicast DNS (RFC 6762) and DNS-based service discovery (RFC 6763): what an answer says
//! about the host that sent it.
//!
//! [`interpret`] reads names and addresses from A and AAAA records, TCP service ports from SRV
//! records, and operating system hints from HINFO records and from the TXT records of
//! `_device-info._tcp` and `_esphomelib._tcp` instances. mDNS has no authentication: every
//! finding is a claim of the sender, and the confidence values say how specific the hint is,
//! not how far it can be trusted.
//!
//! Queries are ignored, and so are messages with a non-zero response code (RFC 6762,
//! section 18.11).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::NameFindings;
use super::collect::Collector;
use super::message::{RecordData, Response, Section, reverse_address};

/// The UDP port of mDNS.
pub const MDNS_PORT: u16 = 5353;
/// The IPv4 multicast group of mDNS (224.0.0.251).
pub const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The IPv6 multicast group of mDNS (`ff02::fb`).
pub const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// The name that lists the service types a host offers (RFC 6763, section 9).
pub const SERVICES_QUERY: &str = "_services._dns-sd._udp.local";

/// The most service types [`service_types`] returns.
const MAX_SERVICE_TYPES: usize = 64;

/// The confidence of an operating system name from a HINFO record that is recognised.
const HINFO_KNOWN: u8 = 60;
/// The confidence of a HINFO text that is passed on as it is.
const HINFO_RAW: u8 = 40;

/// The service of an instance name like `Office Printer._ipp._tcp.local`.
struct Service<'a> {
    /// The service label, `_ipp`.
    label: &'a str,
    /// The protocol label, `_tcp` or `_udp`.
    proto: &'a str,
}

/// Finds the `_service._proto` pair in an instance or service name. The last pair counts, so
/// an instance name that looks like a service does not change the result.
fn service_of(name: &str) -> Option<Service<'_>> {
    let labels: Vec<&str> = name.split('.').collect();
    let index = labels
        .windows(2)
        .rposition(|pair| pair[0].starts_with('_') && matches!(pair[1], "_tcp" | "_udp"))?;
    Some(Service {
        label: labels[index],
        proto: labels[index + 1],
    })
}

/// What a response says about the hosts behind it. `source` is the address the datagram came
/// from.
///
/// Rules, in short: A and AAAA owners are the names of their addresses; PTR records under
/// `in-addr.arpa` and `ip6.arpa` name the address they encode; the SRV records of `_x._tcp`
/// services give ports to the addresses their target resolves to; HINFO and TXT records give
/// operating system hints. `source` is part of the result when the response has any record.
pub fn interpret(source: IpAddr, response: &Response) -> NameFindings {
    if !response.is_response || response.rcode != 0 || response.records.is_empty() {
        return NameFindings::default();
    }
    let mut collector = Collector::new();
    collector.admit_source(source);

    let hosts = collect_hosts(&mut collector, response);
    for record in &response.records {
        if let RecordData::Ptr(target) = &record.data
            && let Some(ip) = reverse_address(&record.name)
        {
            collector.set_name(ip, target);
        }
    }

    let lookup = Lookup {
        source,
        hosts: &hosts,
    };
    apply_services(&mut collector, &lookup, response);
    apply_hinfo(&mut collector, &lookup, response);
    apply_txt(&mut collector, &lookup, response);
    collector.finish()
}

/// Host names with their addresses, from the A and AAAA records of all sections. Also gives
/// each address its name.
fn collect_hosts<'a>(
    collector: &mut Collector,
    response: &'a Response,
) -> BTreeMap<&'a str, BTreeSet<IpAddr>> {
    let mut hosts: BTreeMap<&str, BTreeSet<IpAddr>> = BTreeMap::new();
    for record in &response.records {
        let ip = match &record.data {
            RecordData::A(addr) => IpAddr::V4(*addr),
            RecordData::Aaaa(addr) => IpAddr::V6(*addr),
            _ => continue,
        };
        if collector.admit(ip) {
            collector.set_name(ip, &record.name);
            hosts.entry(record.name.as_str()).or_default().insert(ip);
        }
    }
    hosts
}

/// How a host name in a record turns into addresses.
struct Lookup<'a> {
    source: IpAddr,
    hosts: &'a BTreeMap<&'a str, BTreeSet<IpAddr>>,
}

impl Lookup<'_> {
    /// The addresses of an SRV target: its A and AAAA records in the message, or the source
    /// when the source is known by that name.
    fn target(&self, collector: &Collector, target: &str) -> Vec<IpAddr> {
        match self.hosts.get(target) {
            Some(addresses) if !addresses.is_empty() => addresses.iter().copied().collect(),
            _ if collector.name_of(self.source) == Some(target) => vec![self.source],
            _ => Vec::new(),
        }
    }

    /// The addresses an owner name stands for: its A and AAAA records, or the source.
    fn owner(&self, owner: &str) -> Vec<IpAddr> {
        match self.hosts.get(owner) {
            Some(addresses) if !addresses.is_empty() => addresses.iter().copied().collect(),
            _ => vec![self.source],
        }
    }

    /// The addresses of the host behind a service instance: the targets of its SRV records,
    /// or the source when the message does not say.
    fn instance(&self, collector: &Collector, response: &Response, instance: &str) -> Vec<IpAddr> {
        let mut found = Vec::new();
        for record in &response.records {
            if record.name != instance {
                continue;
            }
            if let RecordData::Srv { target, .. } = &record.data {
                for ip in self.target(collector, target) {
                    if !found.contains(&ip) {
                        found.push(ip);
                    }
                }
            }
        }
        if found.is_empty() {
            found.push(self.source);
        }
        found
    }
}

/// TCP ports from the SRV records of `_x._tcp` services.
///
/// `_workstation._tcp` is skipped: Avahi announces it on port 9 as a marker for the host, and
/// nothing listens there.
fn apply_services(collector: &mut Collector, lookup: &Lookup<'_>, response: &Response) {
    for record in &response.records {
        let RecordData::Srv { port, target, .. } = &record.data else {
            continue;
        };
        let Some(service) = service_of(&record.name) else {
            continue;
        };
        if *port == 0 || service.proto != "_tcp" || service.label == "_workstation" {
            continue;
        }
        for ip in lookup.target(collector, target) {
            collector.add_port(ip, *port);
        }
    }
}

/// Operating system guesses from HINFO records.
fn apply_hinfo(collector: &mut Collector, lookup: &Lookup<'_>, response: &Response) {
    for record in &response.records {
        let RecordData::Hinfo { os, .. } = &record.data else {
            continue;
        };
        let Some((name, confidence)) = hinfo_os(os) else {
            continue;
        };
        for ip in lookup.owner(&record.name) {
            collector.set_os(ip, &name, confidence);
        }
    }
}

fn hinfo_os(os: &str) -> Option<(String, u8)> {
    let text = os.trim();
    if text.is_empty() {
        return None;
    }
    let upper = text.to_ascii_uppercase();
    let known = if upper.starts_with("LINUX") {
        Some("Linux")
    } else if upper.starts_with("WIN") {
        Some("Windows")
    } else if upper.starts_with("MACOS")
        || upper.starts_with("MAC OS X")
        || upper.starts_with("DARWIN")
    {
        Some("macOS")
    } else if upper.starts_with("FREEBSD") {
        Some("FreeBSD")
    } else {
        None
    };
    Some(match known {
        Some(name) => (name.to_string(), HINFO_KNOWN),
        None => (text.to_string(), HINFO_RAW),
    })
}

/// Operating system hints from the TXT records of `_device-info._tcp` and `_esphomelib._tcp`
/// instances. They go to the host behind the instance.
fn apply_txt(collector: &mut Collector, lookup: &Lookup<'_>, response: &Response) {
    for record in &response.records {
        let RecordData::Txt(strings) = &record.data else {
            continue;
        };
        let Some(service) = service_of(&record.name) else {
            continue;
        };
        if service.proto != "_tcp" {
            continue;
        }
        let hints = match service.label {
            "_device-info" => device_info_hints(strings),
            "_esphomelib" => esphome_hints(strings),
            _ => continue,
        };
        if hints.is_empty() {
            continue;
        }
        for ip in lookup.instance(collector, response, &record.name) {
            for (name, confidence) in &hints {
                collector.set_os(ip, name, *confidence);
            }
        }
    }
}

/// `key=value` pairs of a TXT record. Keys are case-insensitive (RFC 6763, section 6.4).
fn pairs(strings: &[String]) -> impl Iterator<Item = (&str, &str)> {
    strings.iter().filter_map(|text| text.split_once('='))
}

fn device_info_hints(strings: &[String]) -> Vec<(&'static str, u8)> {
    let mut hints = Vec::new();
    for (key, value) in pairs(strings) {
        if key.eq_ignore_ascii_case("model") {
            if value.starts_with("Mac") || value.starts_with("iMac") {
                hints.push(("macOS", 60));
            } else if value.starts_with("iPhone") {
                hints.push(("iOS", 60));
            } else if value.starts_with("iPad") {
                hints.push(("iPadOS", 60));
            } else if value.starts_with("AppleTV") {
                hints.push(("tvOS", 50));
            }
        } else if key.eq_ignore_ascii_case("osxvers")
            && !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
        {
            hints.push(("macOS", 70));
        }
    }
    hints
}

fn esphome_hints(strings: &[String]) -> Vec<(&'static str, u8)> {
    let announced = pairs(strings)
        .any(|(key, value)| key.eq_ignore_ascii_case("platform") && !value.is_empty());
    if announced {
        vec![("ESPHome", 60)]
    } else {
        Vec::new()
    }
}

/// The service types listed in the answers to a `_services._dns-sd._udp.local` query, for
/// example `_ipp._tcp.local`, without duplicates and in message order, at most 64.
pub fn service_types(response: &Response) -> Vec<String> {
    let mut types: Vec<String> = Vec::new();
    if !response.is_response || response.rcode != 0 {
        return types;
    }
    for record in &response.records {
        if record.section != Section::Answer || record.name != SERVICES_QUERY {
            continue;
        }
        if let RecordData::Ptr(target) = &record.data
            && !target.is_empty()
            && !types.contains(target)
        {
            types.push(target.clone());
            if types.len() >= MAX_SERVICE_TYPES {
                break;
            }
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::Record;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rec(name: &str, data: RecordData) -> Record {
        Record {
            section: Section::Answer,
            name: name.to_string(),
            ttl: 120,
            cache_flush: true,
            data,
        }
    }

    fn a(name: &str, address: &str) -> Record {
        let data = match ip(address) {
            IpAddr::V4(v4) => RecordData::A(v4),
            IpAddr::V6(v6) => RecordData::Aaaa(v6),
        };
        rec(name, data)
    }

    fn srv(name: &str, port: u16, target: &str) -> Record {
        rec(
            name,
            RecordData::Srv {
                priority: 0,
                weight: 0,
                port,
                target: target.to_string(),
            },
        )
    }

    fn txt(name: &str, strings: &[&str]) -> Record {
        rec(
            name,
            RecordData::Txt(strings.iter().map(ToString::to_string).collect()),
        )
    }

    fn hinfo(name: &str, os: &str) -> Record {
        rec(
            name,
            RecordData::Hinfo {
                cpu: "CPU".to_string(),
                os: os.to_string(),
            },
        )
    }

    fn ptr(name: &str, target: &str) -> Record {
        rec(name, RecordData::Ptr(target.to_string()))
    }

    fn response(records: Vec<Record>) -> Response {
        Response {
            id: 0,
            is_response: true,
            truncated: false,
            rcode: 0,
            questions: Vec::new(),
            records,
        }
    }

    const SOURCE: &str = "192.0.2.10";

    fn findings(records: Vec<Record>) -> NameFindings {
        interpret(ip(SOURCE), &response(records))
    }

    fn os_of(findings: &NameFindings, address: &str) -> Option<(String, u8)> {
        findings.os.get(&ip(address)).cloned()
    }

    #[test]
    fn queries_error_responses_and_empty_messages_are_ignored() {
        let records = vec![a("host.local", "192.0.2.11")];
        let mut query = response(records.clone());
        query.is_response = false;
        assert!(interpret(ip(SOURCE), &query).is_empty());
        let mut failed = response(records);
        failed.rcode = 3;
        assert!(interpret(ip(SOURCE), &failed).is_empty());
        assert!(findings(Vec::new()).is_empty());
    }

    #[test]
    fn the_source_is_part_of_any_message_with_a_record() {
        let found = findings(vec![rec("host.local", RecordData::Other(47))]);
        assert_eq!(found.addresses, BTreeSet::from([ip(SOURCE)]));
        assert!(found.names.is_empty());
    }

    #[test]
    fn a_loopback_source_is_kept_but_a_multicast_source_is_not() {
        let records = vec![rec("host.local", RecordData::Other(47))];
        let found = interpret(ip("127.0.0.1"), &response(records.clone()));
        assert_eq!(found.addresses, BTreeSet::from([ip("127.0.0.1")]));
        assert!(interpret(ip("224.0.0.251"), &response(records.clone())).is_empty());
        assert!(interpret(ip("0.0.0.0"), &response(records)).is_empty());
    }

    #[test]
    fn unusable_addresses_in_records_are_skipped() {
        let found = findings(vec![
            a("loop.local", "127.0.0.1"),
            a("loop6.local", "::1"),
            a("group.local", "224.0.0.251"),
            a("group6.local", "ff02::fb"),
            a("any.local", "0.0.0.0"),
            a("any6.local", "::"),
            a("broadcast.local", "255.255.255.255"),
            a("good.local", "192.0.2.12"),
        ]);
        assert_eq!(
            found.addresses,
            BTreeSet::from([ip(SOURCE), ip("192.0.2.12")])
        );
        assert_eq!(found.names.len(), 1);
        assert_eq!(found.names[&ip("192.0.2.12")], "good.local");
    }

    #[test]
    fn the_first_name_wins_but_arpa_names_give_way() {
        let found = findings(vec![
            a("one.local", "192.0.2.12"),
            a("two.local", "192.0.2.12"),
            a("odd.in-addr.arpa", "192.0.2.13"),
            a("real.example.net", "192.0.2.13"),
            a("kept.local", "192.0.2.14"),
            a("odd.in-addr.arpa", "192.0.2.14"),
        ]);
        assert_eq!(found.names[&ip("192.0.2.12")], "one.local");
        assert_eq!(found.names[&ip("192.0.2.13")], "real.example.net");
        assert_eq!(found.names[&ip("192.0.2.14")], "kept.local");
    }

    #[test]
    fn reverse_pointers_name_the_address_they_encode() {
        let found = findings(vec![
            ptr("40.2.0.192.in-addr.arpa", "printer.local"),
            ptr(
                "1.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                "printer6.local",
            ),
            ptr("1.0.0.127.in-addr.arpa", "loop.local"),
            ptr("not-a-reverse-name.local", "ignored.local"),
            ptr("2.0.192.in-addr.arpa", "short.local"),
        ]);
        assert_eq!(found.names[&ip("192.0.2.40")], "printer.local");
        assert_eq!(found.names[&ip("2001:db8::41")], "printer6.local");
        assert_eq!(found.names.len(), 2);
        assert!(found.addresses.contains(&ip("192.0.2.40")));
        assert!(found.addresses.contains(&ip("2001:db8::41")));
        assert_eq!(found.addresses.len(), 3, "the two addresses and the source");
    }

    #[test]
    fn a_reverse_pointer_name_does_not_replace_a_host_name() {
        let found = findings(vec![
            a("printer.local", "192.0.2.40"),
            ptr("40.2.0.192.in-addr.arpa", "other.local"),
        ]);
        assert_eq!(found.names[&ip("192.0.2.40")], "printer.local");
    }

    #[test]
    fn tcp_services_give_ports_to_the_addresses_of_their_target() {
        let found = findings(vec![
            srv("web._http._tcp.local", 80, "host.local"),
            srv("web._https._tcp.local", 443, "host.local"),
            a("host.local", "192.0.2.20"),
            a("host.local", "2001:db8::20"),
        ]);
        let ports = BTreeSet::from([80, 443]);
        assert_eq!(found.services[&ip("192.0.2.20")], ports);
        assert_eq!(found.services[&ip("2001:db8::20")], ports);
        assert!(!found.services.contains_key(&ip(SOURCE)));
    }

    #[test]
    fn udp_services_port_zero_and_workstation_markers_are_not_services() {
        let found = findings(vec![
            srv("x._sleep-proxy._udp.local", 61000, "host.local"),
            srv("y._device-info._tcp.local", 0, "host.local"),
            srv(
                "host [00:00:5e:00:53:20]._workstation._tcp.local",
                9,
                "host.local",
            ),
            srv("z._ssh._tcp.local", 22, "host.local"),
            a("host.local", "192.0.2.20"),
        ]);
        assert_eq!(
            found.services,
            BTreeMap::from([(ip("192.0.2.20"), BTreeSet::from([22]))])
        );
    }

    #[test]
    fn an_srv_target_without_an_address_uses_the_source_when_it_is_known_by_that_name() {
        let src_reverse = "10.2.0.192.in-addr.arpa";
        let found = findings(vec![
            ptr(src_reverse, "me.local"),
            srv("a._ssh._tcp.local", 22, "me.local"),
            srv("b._ssh._tcp.local", 2222, "elsewhere.local"),
        ]);
        assert_eq!(
            found.services,
            BTreeMap::from([(ip(SOURCE), BTreeSet::from([22]))])
        );
        // Without a name for the source nothing is attributed.
        let found = findings(vec![srv("a._ssh._tcp.local", 22, "me.local")]);
        assert!(found.services.is_empty());
    }

    #[test]
    fn the_service_pair_is_found_from_the_end_of_the_name() {
        let service = |name| service_of(name).map(|s| (s.label, s.proto));
        assert_eq!(service("_ipp._tcp.local"), Some(("_ipp", "_tcp")));
        assert_eq!(
            service("office printer._ipp._tcp.local"),
            Some(("_ipp", "_tcp"))
        );
        assert_eq!(service("a._x._udp.local"), Some(("_x", "_udp")));
        assert_eq!(
            service("_evil._tcp.fake._real._tcp.local"),
            Some(("_real", "_tcp"))
        );
        assert_eq!(service("a._x._tcp.example.net"), Some(("_x", "_tcp")));
        assert_eq!(service("printer.local"), None);
        assert_eq!(service("_tcp.local"), None);
        assert_eq!(service("_x._sctp.local"), None);
        assert_eq!(service(""), None);
    }

    #[test]
    fn hinfo_text_maps_to_an_operating_system() {
        let cases = [
            ("LINUX", "Linux", 60),
            ("linux", "Linux", 60),
            ("Linux 6.8", "Linux", 60),
            ("WINDOWS", "Windows", 60),
            ("WIN32", "Windows", 60),
            ("MACOS", "macOS", 60),
            ("Mac OS X 10.4", "macOS", 60),
            ("DARWIN", "macOS", 60),
            ("FREEBSD", "FreeBSD", 60),
            ("  Example RTOS 2  ", "Example RTOS 2", 40),
            ("VxWorks", "VxWorks", 40),
        ];
        for (text, name, confidence) in cases {
            assert_eq!(
                hinfo_os(text),
                Some((name.to_string(), confidence)),
                "{text:?}"
            );
        }
        assert_eq!(hinfo_os(""), None);
        assert_eq!(hinfo_os("   "), None);
    }

    #[test]
    fn hinfo_goes_to_the_address_of_its_owner_or_else_to_the_source() {
        let found = findings(vec![
            a("pc.local", "192.0.2.30"),
            hinfo("pc.local", "WINDOWS"),
            hinfo("unknown.local", "LINUX"),
        ]);
        assert_eq!(
            os_of(&found, "192.0.2.30"),
            Some(("Windows".to_string(), 60))
        );
        assert_eq!(os_of(&found, SOURCE), Some(("Linux".to_string(), 60)));
    }

    #[test]
    fn device_info_models_map_to_apple_platforms() {
        let cases = [
            ("model=MacStudio1,1", Some(("macOS", 60))),
            ("model=MacBookPro18,3", Some(("macOS", 60))),
            ("model=Macmini9,1", Some(("macOS", 60))),
            ("model=iMac21,1", Some(("macOS", 60))),
            ("Model=iMac21,1", Some(("macOS", 60))),
            ("model=iPhone14,2", Some(("iOS", 60))),
            ("model=iPad13,1", Some(("iPadOS", 60))),
            ("model=AppleTV6,2", Some(("tvOS", 50))),
            ("model=AudioAccessory5,1", None),
            ("model=RackStation", None),
            ("osxvers=24", Some(("macOS", 70))),
            ("osxvers=", None),
            ("osxvers=24b", None),
            ("osxvers", None),
            ("modelx=Mac1", None),
        ];
        for (text, expected) in cases {
            let found = findings(vec![txt("d._device-info._tcp.local", &[text])]);
            let expected = expected.map(|(name, conf)| (name.to_string(), conf));
            assert_eq!(os_of(&found, SOURCE), expected, "{text}");
        }
    }

    #[test]
    fn the_highest_confidence_inside_a_message_wins() {
        let found = findings(vec![
            txt(
                "d._device-info._tcp.local",
                &["model=MacStudio1,1", "osxvers=24"],
            ),
            hinfo("other.local", "DARWIN"),
        ]);
        assert_eq!(os_of(&found, SOURCE), Some(("macOS".to_string(), 70)));
        // On a tie the first guess stays.
        let found = findings(vec![hinfo("x.local", "LINUX"), hinfo("y.local", "FREEBSD")]);
        assert_eq!(os_of(&found, SOURCE), Some(("Linux".to_string(), 60)));
    }

    #[test]
    fn device_info_only_counts_for_the_tcp_service() {
        let found = findings(vec![
            txt("d._device-info._udp.local", &["model=Mac1"]),
            txt("web._http._tcp.local", &["model=Mac1", "platform=ESP32"]),
        ]);
        assert!(found.os.is_empty());
    }

    #[test]
    fn instance_hints_follow_the_srv_target_when_it_is_in_the_message() {
        let found = findings(vec![
            srv("n._esphomelib._tcp.local", 6053, "node.local"),
            a("node.local", "192.0.2.31"),
            txt("n._esphomelib._tcp.local", &["platform=ESP8266"]),
        ]);
        assert_eq!(
            os_of(&found, "192.0.2.31"),
            Some(("ESPHome".to_string(), 60))
        );
        assert_eq!(os_of(&found, SOURCE), None);
        assert_eq!(found.services[&ip("192.0.2.31")], BTreeSet::from([6053]));
    }

    #[test]
    fn esphome_needs_a_platform() {
        for (strings, expected) in [
            (vec!["platform=ESP32"], true),
            (vec!["version=1", "PLATFORM=RP2040"], true),
            (vec!["platform="], false),
            (vec!["board=esp32dev"], false),
            (vec![], false),
        ] {
            let found = findings(vec![txt("n._esphomelib._tcp.local", &strings)]);
            assert_eq!(os_of(&found, SOURCE).is_some(), expected, "{strings:?}");
        }
    }

    #[test]
    fn one_message_contributes_at_most_256_addresses() {
        let records: Vec<Record> = (0..300u16)
            .map(|index| {
                a(
                    &format!("h{index}.local"),
                    &format!("198.51.{}.{}", index / 200, index % 200 + 1),
                )
            })
            .collect();
        let found = findings(records);
        assert_eq!(found.addresses.len(), 256);
        assert!(found.addresses.contains(&ip(SOURCE)));
        assert!(found.names.keys().all(|key| found.addresses.contains(key)));
    }

    #[test]
    fn ports_per_address_are_bounded() {
        let mut records = vec![a("host.local", "192.0.2.20")];
        for port in 1..=100u16 {
            records.push(srv(&format!("s{port}._x._tcp.local"), port, "host.local"));
        }
        let found = findings(records);
        assert_eq!(found.services[&ip("192.0.2.20")].len(), 64);
    }

    #[test]
    fn service_types_are_deduplicated_and_come_from_answers_only() {
        let mut extra = ptr(SERVICES_QUERY, "_extra._tcp.local");
        extra.section = Section::Additional;
        let records = vec![
            ptr(SERVICES_QUERY, "_ipp._tcp.local"),
            ptr(SERVICES_QUERY, "_ssh._tcp.local"),
            ptr(SERVICES_QUERY, "_ipp._tcp.local"),
            ptr("_other._tcp.local", "x._other._tcp.local"),
            ptr(SERVICES_QUERY, ""),
            extra,
            a(SERVICES_QUERY, "192.0.2.5"),
        ];
        assert_eq!(
            service_types(&response(records.clone())),
            vec!["_ipp._tcp.local".to_string(), "_ssh._tcp.local".to_string()]
        );
        let mut query = response(records);
        query.is_response = false;
        assert_eq!(service_types(&query), Vec::<String>::new());
    }

    #[test]
    fn service_types_are_bounded() {
        let records = (0..100)
            .map(|index| ptr(SERVICES_QUERY, &format!("_s{index}._tcp.local")))
            .collect();
        assert_eq!(service_types(&response(records)).len(), 64);
    }

    #[test]
    fn the_multicast_constants_are_the_registered_groups() {
        assert_eq!(MDNS_V4.to_string(), "224.0.0.251");
        assert_eq!(MDNS_V6.to_string(), "ff02::fb");
        assert_eq!(MDNS_PORT, 5353);
        assert!(MDNS_V4.is_multicast() && MDNS_V6.is_multicast());
    }
}
