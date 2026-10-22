//! One response policy zone compiled for the query path (DNS-21,
//! draft-vixie-dnsop-dns-rpz).
//!
//! The owner names of an RPZ zone, relative to its apex, are triggers:
//!
//! | Owner | Trigger |
//! |---|---|
//! | `name`, `*.name` | QNAME: the query name (or a CNAME target in the answer) is `name`, or below it |
//! | `<len>.<address reversed>.rpz-ip` | Response IP: an A or AAAA record of the answer is in the prefix |
//! | `name.rpz-nsdname`, `*.name.rpz-nsdname` | NSDNAME: a name server of the answer is `name`, or below it |
//! | `<len>.<address reversed>.rpz-nsip` | NSIP: an address of a name server of the answer is in the prefix |
//! | `<len>.<address reversed>.rpz-client-ip` | Client IP: the client's address is in the prefix |
//!
//! An IPv4 prefix is written with its octets reversed (`24.0.2.0.192.rpz-ip` is
//! 192.0.2.0/24); an IPv6 prefix with its 16-bit groups reversed and `zz` for the run of
//! zero groups (`48.zz.db8.2001.rpz-ip` is `2001:db8::/48`). The records at a trigger are its
//! action: `CNAME .` is NXDOMAIN, `CNAME *.` NODATA, `CNAME rpz-passthru.` PASSTHRU (no
//! rewrite), `CNAME rpz-drop.` DROP (no answer), `CNAME rpz-tcp-only.` an empty truncated
//! answer over UDP; any other records are local data, answered in place of the real answer.
//!
//! An exact QNAME trigger wins over a wildcard, a closer wildcard over one further up, and
//! a longer prefix over a shorter one. A trigger that does not parse is skipped and counted
//! in [`RpzZone::skipped`].

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tenko_core::dns::{RrSet, Rtype, Zone, ZoneId};

use crate::name;

/// A record of local data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord {
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The record data in wire form.
    pub rdata: Box<[u8]>,
}

/// What a trigger does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpzAction {
    /// NXDOMAIN.
    Nxdomain,
    /// NOERROR without data.
    Nodata,
    /// No rewrite, by this zone or any after it.
    Passthru,
    /// No answer.
    Drop,
    /// Over UDP an empty answer with TC set; over TCP the real answer.
    TcpOnly,
    /// These records instead of the real answer.
    Local(Box<[LocalRecord]>),
}

/// Exact names and wildcards, each with its action.
#[derive(Debug, Clone, Default)]
pub struct NameTriggers {
    exact: HashMap<Box<[u8]>, RpzAction>,
    /// Keyed by the name below the `*`.
    wild: HashMap<Box<[u8]>, RpzAction>,
}

impl NameTriggers {
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wild.is_empty()
    }

    fn len(&self) -> usize {
        self.exact.len() + self.wild.len()
    }

    /// The action for a lowercase wire name: an exact trigger, else the closest wildcard.
    pub fn find(&self, wire: &[u8]) -> Option<&RpzAction> {
        if self.is_empty() {
            return None;
        }
        if let Some(action) = self.exact.get(wire) {
            return Some(action);
        }
        if self.wild.is_empty() {
            return None;
        }
        let labels = name::label_count(wire);
        (1..=labels).find_map(|skip| self.wild.get(name::suffix(wire, skip)))
    }
}

/// Address prefixes, each with its action; the longest prefix wins.
#[derive(Debug, Clone, Default)]
pub struct PrefixTriggers {
    /// Per prefix length, longest first: the masked addresses (IPv4 in the low 32 bits).
    v4: Vec<(u8, HashMap<u128, RpzAction>)>,
    v6: Vec<(u8, HashMap<u128, RpzAction>)>,
}

fn mask(bits: u128, len: u8, width: u8) -> u128 {
    if len == 0 {
        return 0;
    }
    let keep = u32::from(width - len);
    let full = if width == 32 {
        u128::from(u32::MAX)
    } else {
        u128::MAX
    };
    (bits >> keep << keep) & full
}

impl PrefixTriggers {
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn len(&self) -> usize {
        self.v4
            .iter()
            .chain(&self.v6)
            .map(|(_, map)| map.len())
            .sum()
    }

    fn insert(&mut self, address: IpAddr, len: u8, action: RpzAction) {
        let (table, bits, width) = match address {
            IpAddr::V4(v4) => (&mut self.v4, u128::from(v4.to_bits()), 32),
            IpAddr::V6(v6) => (&mut self.v6, v6.to_bits(), 128),
        };
        let key = mask(bits, len, width);
        if let Some((_, map)) = table.iter_mut().find(|(at, _)| *at == len) {
            map.entry(key).or_insert(action);
        } else {
            table.push((len, HashMap::from([(key, action)])));
            table.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        }
    }

    /// The action of the longest prefix that holds `address`.
    pub fn find(&self, address: IpAddr) -> Option<&RpzAction> {
        if self.is_empty() {
            return None;
        }
        let (table, bits, width) = match address.to_canonical() {
            IpAddr::V4(v4) => (&self.v4, u128::from(v4.to_bits()), 32),
            IpAddr::V6(v6) => (&self.v6, v6.to_bits(), 128),
        };
        table
            .iter()
            .find_map(|(len, map)| map.get(&mask(bits, *len, width)))
    }
}

/// One RPZ zone ready for the query path.
#[derive(Debug, Clone)]
pub struct RpzZone {
    /// The zone.
    pub id: ZoneId,
    /// Its name, the label of its counters.
    pub name: Box<str>,
    /// QNAME triggers.
    pub qname: NameTriggers,
    /// NSDNAME triggers.
    pub nsdname: NameTriggers,
    /// Response IP triggers.
    pub ip: PrefixTriggers,
    /// NSIP triggers.
    pub nsip: PrefixTriggers,
    /// Client IP triggers.
    pub client: PrefixTriggers,
    /// Owners that are no valid trigger.
    pub skipped: usize,
}

const NXDOMAIN_TARGET: &[u8] = &[0];
const NODATA_TARGET: &[u8] = b"\x01*\x00";
const PASSTHRU_TARGET: &[u8] = b"\x0crpz-passthru\x00";
const DROP_TARGET: &[u8] = b"\x08rpz-drop\x00";
const TCP_ONLY_TARGET: &[u8] = b"\x0crpz-tcp-only\x00";

/// The action of the RRsets at one owner.
fn action_of(sets: &[&RrSet]) -> Option<RpzAction> {
    if let Some(cname) = sets.iter().find(|set| set.rtype == Rtype::CNAME) {
        let target = cname.rdata.first()?.as_bytes();
        let lower = target.to_ascii_lowercase();
        return Some(match lower.as_slice() {
            NXDOMAIN_TARGET => RpzAction::Nxdomain,
            NODATA_TARGET => RpzAction::Nodata,
            PASSTHRU_TARGET => RpzAction::Passthru,
            DROP_TARGET => RpzAction::Drop,
            TCP_ONLY_TARGET => RpzAction::TcpOnly,
            _ => RpzAction::Local(
                vec![LocalRecord {
                    rtype: Rtype::CNAME,
                    ttl: cname.ttl,
                    rdata: target.into(),
                }]
                .into_boxed_slice(),
            ),
        });
    }
    let records: Vec<LocalRecord> = sets
        .iter()
        .filter(|set| !matches!(set.rtype.0, 46 | 47 | 50 | 2 | 6))
        .flat_map(|set| {
            set.rdata.iter().map(|rdata| LocalRecord {
                rtype: set.rtype,
                ttl: set.ttl,
                rdata: rdata.as_bytes().into(),
            })
        })
        .collect();
    (!records.is_empty()).then(|| RpzAction::Local(records.into_boxed_slice()))
}

/// The prefix of an `rpz-ip`, `rpz-nsip` or `rpz-client-ip` owner: its labels (leftmost
/// first) before that label.
fn prefix_of(labels: &[&str]) -> Option<(IpAddr, u8)> {
    let (len, rest) = labels.split_first()?;
    let len: u8 = len.parse().ok()?;
    if rest.len() == 4 && rest.iter().all(|label| label.parse::<u8>().is_ok()) {
        if len > 32 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (at, label) in rest.iter().rev().enumerate() {
            octets[at] = label.parse().ok()?;
        }
        return Some((IpAddr::V4(Ipv4Addr::from(octets)), len));
    }
    if len > 128 || rest.is_empty() || rest.len() > 8 {
        return None;
    }
    // Reversed groups, `zz` for the zero run.
    let groups: Vec<&str> = rest.iter().rev().copied().collect();
    let mut out = [0u16; 8];
    let zz = groups.iter().position(|group| *group == "zz");
    let parse = |group: &str| u16::from_str_radix(group, 16).ok();
    match zz {
        None if groups.len() == 8 => {
            for (at, group) in groups.iter().enumerate() {
                out[at] = parse(group)?;
            }
        }
        Some(at) if groups.iter().filter(|group| **group == "zz").count() == 1 => {
            let (head, tail) = (&groups[..at], &groups[at + 1..]);
            if head.len() + tail.len() > 7 {
                return None;
            }
            for (index, group) in head.iter().enumerate() {
                out[index] = parse(group)?;
            }
            for (index, group) in tail.iter().enumerate() {
                out[8 - tail.len() + index] = parse(group)?;
            }
        }
        _ => return None,
    }
    Some((IpAddr::V6(Ipv6Addr::from(out)), len))
}

impl RpzZone {
    /// Compiles a zone from its RRsets (those of its default scope).
    pub fn compile<'a>(zone: &Zone, rrsets: impl IntoIterator<Item = &'a RrSet>) -> Self {
        let apex = zone.name.to_wire();
        let mut owners: HashMap<Vec<u8>, Vec<&RrSet>> = HashMap::new();
        for set in rrsets {
            let owner = set.name.to_wire();
            if owner == apex || !name::is_within(&owner, &apex) {
                continue;
            }
            owners.entry(owner).or_default().push(set);
        }
        let mut compiled = Self {
            id: zone.id,
            name: zone.name.as_str().into(),
            qname: NameTriggers::default(),
            nsdname: NameTriggers::default(),
            ip: PrefixTriggers::default(),
            nsip: PrefixTriggers::default(),
            client: PrefixTriggers::default(),
            skipped: 0,
        };
        let apex_labels = name::label_count(&apex);
        for (owner, sets) in owners {
            let Some(action) = action_of(&sets) else {
                compiled.skipped += 1;
                continue;
            };
            let labels: Vec<&[u8]> = name::Labels::new(&owner).collect();
            let relative = &labels[..labels.len() - apex_labels];
            let texts: Vec<String> = relative
                .iter()
                .map(|label| String::from_utf8_lossy(label).to_ascii_lowercase())
                .collect();
            let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
            let (kind, rest) = match texts.split_last() {
                Some((&"rpz-ip", rest)) => ("ip", rest),
                Some((&"rpz-nsip", rest)) => ("nsip", rest),
                Some((&"rpz-client-ip", rest)) => ("client", rest),
                Some((&"rpz-nsdname", rest)) => ("nsdname", rest),
                _ => ("qname", &texts[..]),
            };
            let ok = match kind {
                "ip" | "nsip" | "client" => match prefix_of(rest) {
                    Some((address, len)) => {
                        let table = match kind {
                            "ip" => &mut compiled.ip,
                            "nsip" => &mut compiled.nsip,
                            _ => &mut compiled.client,
                        };
                        table.insert(address, len, action);
                        true
                    }
                    None => false,
                },
                _ => {
                    let table = if kind == "qname" {
                        &mut compiled.qname
                    } else {
                        &mut compiled.nsdname
                    };
                    insert_name(table, rest, action)
                }
            };
            if !ok {
                compiled.skipped += 1;
            }
        }
        compiled
    }

    /// Triggers in the zone.
    pub fn triggers(&self) -> usize {
        self.qname.len() + self.nsdname.len() + self.ip.len() + self.nsip.len() + self.client.len()
    }

    /// Whether the zone has triggers that look at the answer (IP, NSDNAME, NSIP).
    pub fn has_answer_triggers(&self) -> bool {
        !self.ip.is_empty() || !self.nsip.is_empty() || !self.nsdname.is_empty()
    }

    // WP10.1: the triggers on the delegation (E41).
    /// Whether the zone has NSDNAME or NSIP triggers: the recursive resolver then puts the
    /// delegation it followed into its answers (its NS records in the authority section,
    /// their addresses in the additional section), where [`crate::policy::Policy`] matches
    /// them as it matches a forwarded answer's.
    pub fn has_ns_triggers(&self) -> bool {
        !self.nsip.is_empty() || !self.nsdname.is_empty()
    }
    // WP10.1: end.
}

/// Inserts a name trigger from its labels (leftmost first); `false` for none.
fn insert_name(table: &mut NameTriggers, labels: &[&str], action: RpzAction) -> bool {
    let (wild, labels) = match labels.split_first() {
        Some((&"*", rest)) => (true, rest),
        _ => (false, labels),
    };
    if labels.is_empty() && !wild {
        return false;
    }
    let mut wire = Vec::with_capacity(64);
    for label in labels {
        let Ok(len) = u8::try_from(label.len()) else {
            return false;
        };
        wire.push(len);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    let map = if wild {
        &mut table.wild
    } else {
        &mut table.exact
    };
    map.entry(wire.into_boxed_slice()).or_insert(action);
    true
}
