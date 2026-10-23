//! One exchange with one authoritative server ([`Authority`], recursion plan section 2.1)
//! and its test oracle [`MemAuthority`], scripted from zone data so that the engine is
//! tested without sockets.
//!
//! An [`Authority`] owns the defences of DNS-08 and the fallback ladder of one exchange:
//! a random id, 0x20 over the question (the exact case checked on the answer), a fresh
//! source port when asked, EDNS with [`AUTHORITY_UDP_SIZE`] octets and DO, the client
//! cookie and the server cookie it knows (RFC 7873, RFC 9018); TCP when the UDP answer is
//! truncated (RFC 7766); one retry without EDNS when the server answers FORMERR or NOTIMP
//! to it (RFC 6891 section 6.2.2, never on a timeout); one retry with the new server
//! cookie on BADCOOKIE. What it learnt goes back in the [`Exchange`], and the engine
//! writes it into the infrastructure cache.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, RecordData, Rtype};

use crate::tree::canonical_cmp;

/// The one EDNS UDP size of queries to authorities (DNS flag day 2020): no step to 4,096
/// or 512.
pub const AUTHORITY_UDP_SIZE: u16 = 1_232;

/// The transport an exchange ended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityTransport {
    /// UDP.
    Udp,
    /// TCP (asked for, or after a truncated UDP answer).
    Tcp,
}

impl AuthorityTransport {
    /// The `transport` label of `tenko_dns_authority_queries_total`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthorityTransport::Udp => "udp",
            AuthorityTransport::Tcp => "tcp",
        }
    }
}

/// A server cookie (RFC 7873 section 4: 8 to 32 octets), kept per server address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerCookie {
    len: u8,
    bytes: [u8; 32],
}

impl std::fmt::Debug for ServerCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCookie")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl ServerCookie {
    /// A server cookie of 8 to 32 octets.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if !(8..=32).contains(&bytes.len()) {
            return None;
        }
        let mut cookie = Self {
            len: u8::try_from(bytes.len()).ok()?,
            bytes: [0; 32],
        };
        cookie.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(cookie)
    }

    /// The octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// What one exchange asks one server.
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of one query, each from the infrastructure cache"
)]
pub struct AuthorityQuery<'a> {
    /// The server's address and port.
    pub server: SocketAddr,
    /// The name, uncompressed wire form, any case (the implementation applies 0x20).
    pub qname: &'a [u8],
    /// The type.
    pub qtype: u16,
    /// The class.
    pub qclass: u16,
    /// Ask with EDNS (and DO); `false` for a server the infrastructure cache knows as
    /// EDNS-less.
    pub edns: bool,
    /// Ask over TCP from the start (a server that truncates everything, or one flooded
    /// with unwanted answers).
    pub tcp: bool,
    /// Randomise the case of the question (`false` after the server's 0x20 strikes).
    pub mix_case: bool,
    /// The client cookie for this server (8 octets from the node's secret over the
    /// server's address).
    pub client_cookie: Option<[u8; 8]>,
    /// The server cookie the infrastructure cache holds for it.
    pub server_cookie: Option<ServerCookie>,
    /// Bind a fresh source port for this exchange (`[dns.recursion] fresh_port_per_query`).
    pub fresh_port: bool,
    /// The answer must be in before this.
    pub deadline: Instant,
}

/// What an exchange learnt about the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    /// The transport of the answer.
    pub transport: AuthorityTransport,
    /// The answer came to a query with EDNS (`false` after the FORMERR fallback).
    pub edns: bool,
    /// The UDP answer was truncated and TCP followed.
    pub truncated: bool,
    /// The round-trip time of the answer that came.
    pub rtt: Duration,
    /// The server cookie of the answer, when it sent one.
    pub server_cookie: Option<ServerCookie>,
}

/// Why an exchange gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// No answer before the deadline.
    #[error("the authority did not answer in time")]
    Timeout,
    /// The server could not be reached (no route, refused connection, no such family).
    #[error("the authority could not be reached: {0}")]
    Unreachable(&'static str),
    /// The answer does not match the query (id, question, 0x20 case) or does not parse.
    #[error("the authority's answer is malformed: {0}")]
    Malformed(&'static str),
    /// BADCOOKIE again after the retry with the new cookie.
    #[error("the authority refused the cookie")]
    BadCookie,
}

impl AuthorityError {
    /// The `outcome` label of `tenko_dns_authority_queries_total`.
    pub const fn outcome(self) -> &'static str {
        match self {
            AuthorityError::Timeout => "timeout",
            AuthorityError::Unreachable(_) => "unreachable",
            AuthorityError::Malformed(_) => "malformed",
            AuthorityError::BadCookie => "badcookie",
        }
    }
}

/// One exchange with one authoritative server; see the module documentation.
pub trait Authority: Send + Sync {
    /// Asks `query` and writes the answer into `answer` (replaced): the server's message,
    /// its OPT record included.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] for a timeout, an unreachable server, a malformed answer or a
    /// cookie refused twice.
    fn exchange<'a>(
        &'a self,
        query: &'a AuthorityQuery<'a>,
        answer: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<Exchange, AuthorityError>> + Send + 'a;
}

// ---------------------------------------------------------------------------------------
// The scripted oracle

/// A zone one scripted server serves: its apex and its records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemZone {
    /// The apex.
    pub apex: DnsName,
    /// The records: owner, TTL and data.
    pub records: Vec<(DnsName, u32, RecordData)>,
}

impl MemZone {
    /// An empty zone at `apex`.
    pub fn new(apex: DnsName) -> Self {
        Self {
            apex,
            records: Vec::new(),
        }
    }

    /// Adds a record.
    #[must_use]
    pub fn record(mut self, owner: DnsName, ttl: u32, data: RecordData) -> Self {
        self.records.push((owner, ttl, data));
        self
    }

    fn at<'a>(
        &'a self,
        owner: &'a DnsName,
    ) -> impl Iterator<Item = &'a (DnsName, u32, RecordData)> {
        self.records
            .iter()
            .filter(move |(name, _, _)| name == owner)
    }

    fn has(&self, owner: &DnsName, rtype: Rtype) -> bool {
        self.at(owner).any(|(_, _, data)| data.rtype() == rtype)
    }

    /// Whether `name` exists: it owns records or is an empty non-terminal above one.
    fn exists(&self, name: &DnsName) -> bool {
        self.records
            .iter()
            .any(|(owner, _, _)| owner.is_subdomain_of(name))
    }
}

/// The ways a scripted server misbehaves (the lab's `quirk` server, recursion plan
/// section 2.12, as an oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent misbehaviours, each a case of E36"
)]
pub struct Quirks {
    /// Never answers: every exchange times out.
    pub silent: bool,
    /// Answers FORMERR to a query with EDNS; the exchange falls back once without.
    pub formerr_on_edns: bool,
    /// Breaks 0x20 (answers in lower case): an exchange that mixed the case fails as
    /// malformed.
    pub case_broken: bool,
    /// Truncates every UDP answer; the exchange follows over TCP.
    pub truncate_udp: bool,
    /// Answers REFUSED to everything (a lame server).
    pub refuse: bool,
    /// Answers SERVFAIL to everything.
    pub servfail: bool,
    /// The server cookie it answers with.
    pub cookie: Option<ServerCookie>,
    /// The round-trip time it reports.
    pub rtt: Duration,
}

/// One scripted server: the zones it serves and how it misbehaves.
#[derive(Debug, Clone, Default)]
pub struct MemServer {
    /// The zones.
    pub zones: Vec<MemZone>,
    /// The misbehaviours.
    pub quirks: Quirks,
}

/// A query a scripted server saw, the witness of the minimisation and denial checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The server.
    pub server: IpAddr,
    /// The name asked, lower case.
    pub qname: DnsName,
    /// The type asked.
    pub qtype: u16,
    /// Over which transport.
    pub transport: AuthorityTransport,
    /// With EDNS.
    pub edns: bool,
}

/// The test oracle of [`Authority`]: servers by address, each answering from its zones as
/// an authoritative server does (RFC 1034 section 4.3.2): referrals with the NS set, the
/// DS set and glue below a cut, answers with AA, CNAMEs, wildcards, NODATA and NXDOMAIN
/// with the SOA, and the RRSIG and NSEC records for a query with EDNS (DO). Every query is
/// logged ([`MemAuthority::asked`]). A server it does not know is unreachable.
#[derive(Debug, Default)]
pub struct MemAuthority {
    servers: Mutex<HashMap<IpAddr, MemServer>>,
    log: Mutex<Vec<Asked>>,
}

const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

impl MemAuthority {
    /// No server.
    pub fn new() -> Self {
        Self::default()
    }

    /// `server` serves `zone` as well.
    #[must_use]
    pub fn serve(self, server: IpAddr, zone: MemZone) -> Self {
        self.servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(server)
            .or_default()
            .zones
            .push(zone);
        self
    }

    /// `server` misbehaves so.
    #[must_use]
    pub fn quirks(self, server: IpAddr, quirks: Quirks) -> Self {
        self.servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(server)
            .or_default()
            .quirks = quirks;
        self
    }

    /// Every query seen, in order.
    pub fn asked(&self) -> Vec<Asked> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The queries `server` saw.
    pub fn asked_of(&self, server: IpAddr) -> usize {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|asked| asked.server == server)
            .count()
    }

    /// Forgets the log.
    pub fn clear_log(&self) {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn note(
        &self,
        server: IpAddr,
        qname: &DnsName,
        qtype: u16,
        transport: AuthorityTransport,
        edns: bool,
    ) {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Asked {
                server,
                qname: qname.clone(),
                qtype,
                transport,
                edns,
            });
    }

    /// The exchange, synchronously.
    fn answer(
        &self,
        query: &AuthorityQuery<'_>,
        out: &mut Vec<u8>,
    ) -> Result<Exchange, AuthorityError> {
        let server = query.server.ip();
        let Some(state) = self
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&server)
            .cloned()
        else {
            return Err(AuthorityError::Unreachable("no such server"));
        };
        let quirks = state.quirks;
        let (qname, _) =
            DnsName::from_wire(query.qname).map_err(|_| AuthorityError::Malformed("question"))?;
        let mut transport = if query.tcp {
            AuthorityTransport::Tcp
        } else {
            AuthorityTransport::Udp
        };
        let mut edns = query.edns;
        self.note(server, &qname, query.qtype, transport, edns);
        if quirks.silent {
            return Err(AuthorityError::Timeout);
        }
        let mixed = query.mix_case && query.qname.iter().any(u8::is_ascii_uppercase);
        if quirks.case_broken && mixed {
            return Err(AuthorityError::Malformed("0x20"));
        }
        if quirks.formerr_on_edns && edns {
            edns = false;
            self.note(server, &qname, query.qtype, transport, edns);
        }
        let mut truncated = false;
        if quirks.truncate_udp && transport == AuthorityTransport::Udp {
            truncated = true;
            transport = AuthorityTransport::Tcp;
            self.note(server, &qname, query.qtype, transport, edns);
        }
        let rcode = if quirks.refuse {
            Some(5)
        } else if quirks.servfail {
            Some(2)
        } else {
            None
        };
        let built = match rcode {
            Some(rcode) => Built::empty(rcode, false),
            None => build(&state.zones, &qname, query.qtype, edns),
        };
        let size = if edns { AUTHORITY_UDP_SIZE } else { 512 };
        built.encode(query, edns, out);
        if transport == AuthorityTransport::Udp && out.len() > usize::from(size) {
            // The real exchange gets TC and asks again over TCP.
            truncated = true;
            transport = AuthorityTransport::Tcp;
            self.note(server, &qname, query.qtype, transport, edns);
        }
        Ok(Exchange {
            transport,
            edns,
            truncated,
            rtt: quirks.rtt,
            server_cookie: quirks.cookie.filter(|_| edns),
        })
    }
}

impl Authority for MemAuthority {
    fn exchange<'a>(
        &'a self,
        query: &'a AuthorityQuery<'a>,
        answer: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<Exchange, AuthorityError>> + Send + 'a {
        let result = self.answer(query, answer);
        std::future::ready(result)
    }
}

/// An answer before encoding: the RCODE, AA and the three sections.
struct Built {
    rcode: u8,
    aa: bool,
    sections: [Vec<(DnsName, u32, RecordData)>; 3],
}

impl Built {
    fn empty(rcode: u8, aa: bool) -> Self {
        Self {
            rcode,
            aa,
            sections: [Vec::new(), Vec::new(), Vec::new()],
        }
    }

    fn encode(&self, query: &AuthorityQuery<'_>, edns: bool, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&[0, 0, 0x80 | if self.aa { 0x04 } else { 0 }, self.rcode]);
        out.extend_from_slice(&1u16.to_be_bytes());
        for (index, section) in self.sections.iter().enumerate() {
            let count = section.len() + usize::from(index == 2 && edns);
            out.extend_from_slice(&u16::try_from(count).unwrap_or(u16::MAX).to_be_bytes());
        }
        out.extend_from_slice(query.qname);
        out.extend_from_slice(&query.qtype.to_be_bytes());
        out.extend_from_slice(&query.qclass.to_be_bytes());
        let mut data = Vec::new();
        for (owner, ttl, record) in self.sections.iter().flatten() {
            owner.write_wire(out);
            out.extend_from_slice(&record.rtype().0.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            data.clear();
            record.write_wire(&mut data);
            out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(&data);
        }
        if edns {
            out.push(0);
            out.extend_from_slice(&41u16.to_be_bytes());
            out.extend_from_slice(&AUTHORITY_UDP_SIZE.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
        }
    }
}

/// The records at `owner` of `rtype`, and with DO their RRSIGs.
fn rrset(
    zone: &MemZone,
    owner: &DnsName,
    rtype: Rtype,
    dnssec: bool,
    as_owner: &DnsName,
) -> Vec<(DnsName, u32, RecordData)> {
    let mut out: Vec<(DnsName, u32, RecordData)> = zone
        .at(owner)
        .filter(|(_, _, data)| {
            data.rtype() == rtype || (rtype.0 == TYPE_ANY && data.rtype() != Rtype::RRSIG)
        })
        .map(|(_, ttl, data)| (as_owner.clone(), *ttl, data.clone()))
        .collect();
    if dnssec && !out.is_empty() {
        out.extend(
            zone.at(owner)
                .filter(|(_, _, data)| {
                    matches!(data, RecordData::Rrsig { type_covered, .. } if *type_covered == rtype || rtype.0 == TYPE_ANY)
                })
                .map(|(_, ttl, data)| (as_owner.clone(), *ttl, data.clone())),
        );
    }
    out
}

/// The NSEC records of `zone` that cover or match `name`, with their RRSIGs.
fn nsec_for(zone: &MemZone, name: &DnsName) -> Vec<(DnsName, u32, RecordData)> {
    let wire = name.to_wire();
    let mut out = Vec::new();
    for (owner, _, data) in &zone.records {
        let RecordData::Nsec { next, .. } = data else {
            continue;
        };
        let (owner_wire, next_wire) = (owner.to_wire(), next.to_wire());
        let after_owner = canonical_cmp(&owner_wire, &wire).is_le();
        let before_next = canonical_cmp(&wire, &next_wire).is_lt() || next == &zone.apex;
        if after_owner && before_next {
            out.extend(rrset(zone, owner, Rtype::NSEC, true, owner));
        }
    }
    out
}

/// The answer of a server with `zones` to `qname`/`qtype`.
#[allow(clippy::too_many_lines, reason = "one answer with its denial records")]
fn build(zones: &[MemZone], qname: &DnsName, qtype: u16, dnssec: bool) -> Built {
    let Some(zone) = zones
        .iter()
        .filter(|zone| qname.is_subdomain_of(&zone.apex))
        .max_by_key(|zone| zone.apex.label_count())
    else {
        return Built::empty(5, false);
    };
    let rtype = Rtype(qtype);
    // A cut between the apex and the name, the highest first; DS at a cut is the parent's.
    let mut below: Vec<DnsName> = Vec::new();
    let mut name = qname.clone();
    while name != zone.apex {
        below.push(name.clone());
        match name.parent() {
            Some(parent) => name = parent,
            None => break,
        }
    }
    for cut in below.iter().rev() {
        if zone.has(cut, Rtype::NS) && !(cut == qname && rtype == Rtype::DS) {
            let mut built = Built::empty(0, false);
            built.sections[1] = rrset(zone, cut, Rtype::NS, false, cut);
            if dnssec {
                built.sections[1].extend(rrset(zone, cut, Rtype::DS, true, cut));
            }
            let hosts: Vec<DnsName> = built.sections[1]
                .iter()
                .filter_map(|(_, _, data)| match data {
                    RecordData::Ns { host } => Some(host.clone()),
                    _ => None,
                })
                .collect();
            for host in hosts {
                for other in zones {
                    for glue in [Rtype::A, Rtype::AAAA] {
                        built.sections[2].extend(rrset(other, &host, glue, false, &host));
                    }
                }
            }
            return built;
        }
    }
    let soa = |built: &mut Built| {
        built.sections[1] = rrset(zone, &zone.apex, Rtype::SOA, dnssec, &zone.apex);
    };
    let mut built = Built::empty(0, true);
    let answer = rrset(zone, qname, rtype, dnssec, qname);
    if !answer.is_empty() {
        built.sections[0] = answer;
        return built;
    }
    let cname = rrset(zone, qname, Rtype::CNAME, dnssec, qname);
    if !cname.is_empty() && rtype != Rtype::CNAME {
        built.sections[0] = cname;
        return built;
    }
    if zone.exists(qname) {
        soa(&mut built);
        if dnssec {
            let matching = rrset(zone, qname, Rtype::NSEC, true, qname);
            if matching.is_empty() {
                // WP10.2: an empty non-terminal has no NSEC of its own; the covering
                // record (whose next name lies below it) is the proof, as an authoritative
                // server answers.
                built.sections[1].extend(nsec_for(zone, qname));
            } else {
                built.sections[1].extend(matching);
            }
        }
        return built;
    }
    // The closest encloser and its wildcard.
    let mut encloser = qname.parent();
    while let Some(candidate) = encloser.clone() {
        if zone.exists(&candidate) || candidate == zone.apex {
            break;
        }
        encloser = candidate.parent();
    }
    let wildcard = encloser.and_then(|encloser| encloser.child("*").ok());
    if let Some(wildcard) = &wildcard
        && zone.exists(wildcard)
    {
        let answer = rrset(zone, wildcard, rtype, dnssec, qname);
        if answer.is_empty() {
            soa(&mut built);
        } else {
            built.sections[0] = answer;
        }
        if dnssec {
            built.sections[1].extend(nsec_for(zone, qname));
        }
        return built;
    }
    built.rcode = 3;
    soa(&mut built);
    if dnssec {
        built.sections[1].extend(nsec_for(zone, qname));
        // WP10.2: the name error's proof also denies the wildcard at the closest encloser
        // (RFC 4035 section 3.1.3.2), as an authoritative server answers.
        if let Some(wildcard) = &wildcard {
            for record in nsec_for(zone, wildcard) {
                if !built.sections[1].contains(&record) {
                    built.sections[1].push(record);
                }
            }
        }
    }
    built
}
