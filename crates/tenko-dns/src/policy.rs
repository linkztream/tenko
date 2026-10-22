//! Response policy (DNS-21, DNS-23): RPZ zones and block lists, applied after the
//! authoritative lookup and before the forwarder. Every blocked answer carries the
//! extended error of RFC 8914 (`Blocked`, info code 15; `Filtered`, 17).
//!
//! The policy is part of the serving catalog ([`PolicyData`], built from the rows of one
//! revision); the [`PolicyEngine`] decides with it, in two phases:
//!
//! 1. **The query** ([`PolicyEngine::check`], from the resolver, for every name outside the
//!    zones), in this order: a client in the `exempt` prefixes of an enabled allow list is
//!    never blocked; a name on an allow list (at or below a listed name) is never blocked;
//!    then the RPZ zones in the view's order (the RPZ zones its scope map names, in that
//!    order, then the others by name; the implicit default view takes them by name), each
//!    with its client-IP triggers, then its QNAME triggers; the first zone with a match
//!    decides, and PASSTHRU ends the policy for the query; then the enabled block lists by
//!    name, each skipped for the clients it exempts, answered with the list's action.
//! 2. **The answer** ([`PolicyEngine::check_answer`], on the forwarded answer, from the
//!    cache or the upstream, through [`answer::PolicySink`]): when the query passed, the
//!    RPZ zones in the same order look at the CNAME targets of the answer (QNAME
//!    triggers), its A and AAAA records (IP triggers), the NS records of the answer or the
//!    authority section (NSDNAME) and the addresses of those name servers in the additional
//!    section (NSIP); then the block lists look at the CNAME targets, so a tracker behind a
//!    CNAME is blocked as well. A target on an allow list is not blocked by name.
//!
//! A blocked query answers per its action: NXDOMAIN, NODATA, the redirect address of a
//! list, an RPZ zone's local data, nothing (DROP), or over UDP an empty truncated answer
//! (TCP-only); each with the extended error `Blocked` and counted per list and zone
//! ([`counters`]). [`NoPolicy`] passes every query.
//!
//! While the block lists are paused ([`pause`]) no block list blocks a name; the allow
//! lists, the exemptions and the RPZ zones apply as before.

pub mod answer;
pub mod counters;
pub mod data;
// dns-visibility: the pause of the block lists.
pub mod pause;
pub mod rpz;

use std::net::IpAddr;

use tenko_core::dns::{BlockAction, BlockListId, QueryTransport, Rtype, ViewId, ZoneId};

pub use data::PolicyData;
use data::{ActiveList, ActiveZone};
use rpz::{LocalRecord, RpzAction};

use crate::{catalog::Catalog, name::NameBuf, wire};

/// The extended DNS error info code of a blocked answer (RFC 8914).
pub const EDE_BLOCKED: u16 = 15;

/// The extended DNS error info code of a filtered answer (RFC 8914).
pub const EDE_FILTERED: u16 = 17;

/// What the policy is asked about.
#[derive(Debug, Clone, Copy)]
pub struct PolicyQuery<'a> {
    /// The view that matched.
    pub view: Option<ViewId>,
    /// The client.
    pub client: IpAddr,
    /// The query name, lowercase wire form.
    pub qname: &'a [u8],
    /// The query type.
    pub qtype: Rtype,
    /// The transport.
    pub transport: QueryTransport,
}

/// What blocked a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A block list.
    List(BlockListId),
    /// An RPZ zone.
    Zone(ZoneId),
}

/// The answer of a blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// NXDOMAIN.
    Nxdomain,
    /// NOERROR without data.
    Nodata,
    /// No answer.
    Drop,
    /// An empty answer with TC set (over UDP).
    TcpOnly,
    /// An address record of this address for the matching type, else NODATA.
    Redirect(IpAddr),
    /// These records (their types as asked, or a CNAME), else NODATA.
    Local(&'a [LocalRecord]),
}

/// A blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit<'a> {
    /// The list or zone.
    pub source: Source,
    /// Its name.
    pub name: &'a str,
    /// The answer.
    pub action: Action<'a>,
    slot: u16,
}

impl<'a> Hit<'a> {
    /// A hit counted under `other` (for engines of tests and tools).
    pub fn new(source: Source, name: &'a str, action: Action<'a>) -> Self {
        Self {
            source,
            name,
            action,
            slot: 0,
        }
    }

    /// Counts the hit on its list's or zone's counter.
    pub fn count(&self) {
        counters::count(self.slot);
    }
}

/// What the policy says about a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Nothing matched: answer as usual (the answer is looked at again).
    Pass,
    /// Never blocked: an exempt client, an allowed name, PASSTHRU.
    Allowed,
    /// Blocked.
    Block(Hit<'a>),
}

/// The policy of response policy zones and block lists.
pub trait PolicyEngine: Send + Sync {
    /// The verdict for a query, from the catalog's policy. Reads memory only and allocates
    /// nothing; a block is counted.
    fn check<'a>(&self, catalog: &'a Catalog, query: &PolicyQuery<'_>) -> Verdict<'a>;

    /// The verdict for the answer `message` to a query that passed. Reads memory only and
    /// allocates nothing; a block is counted.
    fn check_answer<'a>(
        &self,
        catalog: &'a Catalog,
        query: &PolicyQuery<'_>,
        message: &[u8],
    ) -> Verdict<'a>;
}

/// The policy that passes everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPolicy;

impl PolicyEngine for NoPolicy {
    fn check<'a>(&self, _catalog: &'a Catalog, _query: &PolicyQuery<'_>) -> Verdict<'a> {
        Verdict::Pass
    }

    fn check_answer<'a>(
        &self,
        _catalog: &'a Catalog,
        _query: &PolicyQuery<'_>,
        _message: &[u8],
    ) -> Verdict<'a> {
        Verdict::Pass
    }
}

/// The policy of the catalog: RPZ zones, block and allow lists, exemptions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy;

impl PolicyEngine for Policy {
    fn check<'a>(&self, catalog: &'a Catalog, query: &PolicyQuery<'_>) -> Verdict<'a> {
        let verdict = eval_query(catalog, query);
        if let Verdict::Block(hit) = &verdict {
            hit.count();
        }
        verdict
    }

    fn check_answer<'a>(
        &self,
        catalog: &'a Catalog,
        query: &PolicyQuery<'_>,
        message: &[u8],
    ) -> Verdict<'a> {
        let verdict = match eval_query(catalog, query) {
            Verdict::Pass => eval_answer(catalog, query, message),
            other => other,
        };
        if let Verdict::Block(hit) = &verdict {
            hit.count();
        }
        verdict
    }
}

fn list_action(action: &BlockAction) -> Action<'_> {
    match action {
        BlockAction::Nxdomain => Action::Nxdomain,
        BlockAction::Nodata => Action::Nodata,
        BlockAction::Redirect { address } => Action::Redirect(*address),
    }
}

/// The verdict of an RPZ action of `zone`.
fn zone_verdict<'a>(
    zone: &'a ActiveZone,
    action: &'a RpzAction,
    transport: QueryTransport,
) -> Verdict<'a> {
    let action = match action {
        RpzAction::Passthru => return Verdict::Allowed,
        RpzAction::TcpOnly if transport != QueryTransport::Udp => return Verdict::Allowed,
        RpzAction::TcpOnly => Action::TcpOnly,
        RpzAction::Nxdomain => Action::Nxdomain,
        RpzAction::Nodata => Action::Nodata,
        RpzAction::Drop => Action::Drop,
        RpzAction::Local(records) => Action::Local(records),
    };
    Verdict::Block(Hit {
        source: Source::Zone(zone.zone.id),
        name: &zone.zone.name,
        action,
        slot: zone.slot,
    })
}

fn list_hit(list: &ActiveList) -> Verdict<'_> {
    Verdict::Block(Hit {
        source: Source::List(list.id),
        name: &list.name,
        action: list_action(&list.action),
        slot: list.slot,
    })
}

/// Calls `each` on the RPZ zones in the view's order until it returns a verdict.
fn in_order<'a>(
    catalog: &'a Catalog,
    view: Option<ViewId>,
    mut each: impl FnMut(&'a ActiveZone) -> Option<Verdict<'a>>,
) -> Option<Verdict<'a>> {
    let policy = catalog.policy();
    let named = view
        .and_then(|id| catalog.view(id))
        .map(|view| &view.scope_map[..]);
    let named = named.unwrap_or(&[]);
    for (at, entry) in named.iter().enumerate() {
        if named[..at].iter().any(|earlier| earlier.zone == entry.zone) {
            continue;
        }
        if let Some(zone) = policy.zone(entry.zone)
            && let Some(verdict) = each(zone)
        {
            return Some(verdict);
        }
    }
    for zone in policy.zones() {
        if named.iter().any(|entry| entry.zone == zone.zone.id) {
            continue;
        }
        if let Some(verdict) = each(zone) {
            return Some(verdict);
        }
    }
    None
}

/// Whether the allow lists allow a name.
fn allowed(catalog: &Catalog, wire: &[u8]) -> bool {
    catalog
        .policy()
        .allows()
        .iter()
        .any(|list| list.matcher.matches(wire))
}

/// The block list that blocks a name for `client`; none while the lists are paused.
fn blocked<'a>(catalog: &'a Catalog, client: IpAddr, wire: &[u8]) -> Option<Verdict<'a>> {
    if pause::active() {
        return None;
    }
    catalog
        .policy()
        .blocks()
        .iter()
        .find(|list| !list.exempts(client) && list.matcher.matches(wire))
        .map(list_hit)
}

fn eval_query<'a>(catalog: &'a Catalog, query: &PolicyQuery<'_>) -> Verdict<'a> {
    let policy = catalog.policy();
    if policy.is_empty() {
        return Verdict::Pass;
    }
    let client = query.client.to_canonical();
    if policy
        .exempt_all()
        .iter()
        .any(|prefix| prefix.contains(&client))
    {
        return Verdict::Allowed;
    }
    if allowed(catalog, query.qname) {
        return Verdict::Allowed;
    }
    let transport = query.transport;
    if let Some(verdict) = in_order(catalog, query.view, |zone| {
        zone.zone
            .client
            .find(client)
            .or_else(|| zone.zone.qname.find(query.qname))
            .map(|action| zone_verdict(zone, action, transport))
    }) {
        return verdict;
    }
    blocked(catalog, client, query.qname).unwrap_or(Verdict::Pass)
}

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// The sections of an answer as positions: where the answer, authority and additional
/// records start and how many each holds.
#[derive(Debug, Clone, Copy)]
struct Sections {
    answer: (usize, u16),
    authority: (usize, u16),
    additional: (usize, u16),
}

fn sections(message: &[u8]) -> Option<Sections> {
    let header = wire::parse_header(message)?;
    let mut pos = wire::questions_end(message, header.qdcount)?;
    let mut skip = |count: u16| -> Option<usize> {
        let start = pos;
        for _ in 0..count {
            pos = wire::read_record(message, pos)?.end();
        }
        Some(start)
    };
    let answer = skip(header.ancount)?;
    let authority = skip(header.nscount)?;
    let additional = skip(header.arcount)?;
    Some(Sections {
        answer: (answer, header.ancount),
        authority: (authority, header.nscount),
        additional: (additional, header.arcount),
    })
}

/// Calls `each` on the records of a section until it returns something.
fn records<T>(
    message: &[u8],
    (start, count): (usize, u16),
    mut each: impl FnMut(wire::RawRecord) -> Option<T>,
) -> Option<T> {
    let mut pos = start;
    for _ in 0..count {
        let record = wire::read_record(message, pos)?;
        pos = record.end();
        if let Some(found) = each(record) {
            return Some(found);
        }
    }
    None
}

fn address_of(record: &wire::RawRecord, message: &[u8]) -> Option<IpAddr> {
    let data = record.data(message);
    match (record.rtype, data.len()) {
        (TYPE_A, 4) => Some(IpAddr::from([data[0], data[1], data[2], data[3]])),
        (TYPE_AAAA, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

fn eval_answer<'a>(catalog: &'a Catalog, query: &PolicyQuery<'_>, message: &[u8]) -> Verdict<'a> {
    let policy = catalog.policy();
    if !policy.inspects_answers() {
        return Verdict::Pass;
    }
    let Some(sections) = sections(message) else {
        return Verdict::Pass;
    };
    let client = query.client.to_canonical();
    let transport = query.transport;
    let mut target = NameBuf::root();
    // The CNAME targets of the answer, each read into `target`.
    let cname_target = |record: &wire::RawRecord, target: &mut NameBuf| -> bool {
        record.rtype == TYPE_CNAME && wire::read_name(message, record.rdata, target).is_some()
    };
    let ns_section = if query.qtype == Rtype::NS {
        sections.answer
    } else {
        sections.authority
    };
    let has_ns = records(message, ns_section, |record| {
        (record.rtype == TYPE_NS).then_some(())
    })
    .is_some();
    let zone_verdict_of = |zone: &'a ActiveZone, target: &mut NameBuf| -> Option<Verdict<'a>> {
        let rpz = &zone.zone;
        let action = records(message, sections.answer, |record| {
            if cname_target(&record, target) && !allowed(catalog, target.as_wire()) {
                rpz.qname.find(target.as_wire())
            } else {
                None
            }
        })
        .or_else(|| {
            records(message, sections.answer, |record| {
                address_of(&record, message).and_then(|address| rpz.ip.find(address))
            })
        })
        .or_else(|| {
            records(message, ns_section, |record| {
                (record.rtype == TYPE_NS
                    && wire::read_name(message, record.rdata, target).is_some())
                .then(|| rpz.nsdname.find(target.as_wire()))
                .flatten()
            })
        })
        .or_else(|| {
            has_ns
                .then(|| {
                    records(message, sections.additional, |record| {
                        address_of(&record, message).and_then(|address| rpz.nsip.find(address))
                    })
                })
                .flatten()
        })?;
        Some(zone_verdict(zone, action, transport))
    };
    if let Some(verdict) = in_order(catalog, query.view, |zone| {
        zone_verdict_of(zone, &mut target)
    }) {
        return verdict;
    }
    if policy.blocks().is_empty() {
        return Verdict::Pass;
    }
    records(message, sections.answer, |record| {
        if cname_target(&record, &mut target) && !allowed(catalog, target.as_wire()) {
            blocked(catalog, client, target.as_wire())
        } else {
            None
        }
    })
    .unwrap_or(Verdict::Pass)
}
