//! The authoritative resolver (WP4.1): the [`Resolver`] of the `dns` role in Slice 4.
//!
//! The order of one query (plan sections 2.2 and 2.3):
//!
//! 1. The header: an opcode other than QUERY is NOTIMP; a signed query is NOTAUTH until the
//!    TSIG keys reach the engine (WP6.2); a class other than IN is REFUSED; the meta types
//!    OPT, TKEY and TSIG are FORMERR, AXFR and IXFR are REFUSED (transfers are WP6.1),
//!    MAILA and MAILB NOTIMP.
//! 2. The rate limiter admits the query ([`RateLimiter::admit_query`]).
//! 3. The view: the first view of the catalog whose rules all match, else the implicit
//!    default view; its weights pick a scope per zone, stable per client.
//! 4. The index: the zone of the longest apex, then the answer, a CNAME chain followed
//!    inside the index (at most [`MAX_CHAIN`] steps, DNAMEs included, a loop stops the
//!    chain), a referral at a zone cut, or a negative answer.
//! 5. Outside the zones: the policy ([`PolicyEngine::check`]: allow lists and exemptions,
//!    the RPZ zones, the block lists) may block the name with its action and the extended
//!    error "Blocked", or drop the query; then a forwarding rule by longest suffix or the
//!    default forwarder when the client asked for recursion ([`Resolution::Forward`]), else
//!    REFUSED with the extended error "Not Authoritative".
//! 6. The rate limiter decides on the response ([`RateLimiter::admit_response`], keyed by
//!    the client's prefix, the response kind and its name: the query name for answers and
//!    NODATA, the zone for NXDOMAIN and referrals): send it, slip it (an empty answer with
//!    TC) or drop it.
//!
//! The answer sections follow minimal responses: a positive answer carries no NS in the
//! authority section; the additional section carries the addresses of the targets of MX,
//! SRV and NS answers that the index holds, and the glue of a referral, the in-domain glue
//! required (RFC 9471). A negative answer carries the SOA of the zone with the TTL of RFC
//! 2308 (the smaller of the SOA's TTL and its MINIMUM). A query for ANY gets one RRset (RFC
//! 8482). AA is set for answers from a zone and clear for a referral; RA says whether a
//! forwarder is configured. EDNS, cookies and the OPT record are the responder's
//! ([`crate::respond`]), which calls this resolver for everything else.
//!
//! Nothing here allocates: the catalog is read through its swap, names synthesized from a
//! DNAME live in fixed buffers, and every record goes into the caller's [`AnswerBuf`].

use std::{net::IpAddr, sync::Arc};

use tenko_core::dns::{QueryTransport, Rdata, Rtype, ViewId, ZoneKind};

use crate::{
    catalog::{Catalog, CatalogHandle, CompiledView, ViewQuery, ViewScopes},
    codec::{AnswerBuf, Owner, Section},
    index::{Chain, Index, Lookup, MAX_CHAIN, RrSetView, ZoneView},
    name::{self, MAX_NAME_LEN, NameBuf},
    policy::{Action, EDE_BLOCKED, Hit, NoPolicy, PolicyEngine, PolicyQuery, Verdict},
    rate::{RateDecision, RateLimiter, ResponseKey, ResponseKind, Unlimited},
    resolver::{QueryContext, Resolution, Resolver},
    tree::ZoneIndex,
};

/// The RCODEs the engine answers with (RFC 1035, RFC 2136, RFC 6891, RFC 7873).
pub mod rcode {
    /// No error.
    pub const NOERROR: u16 = 0;
    /// Format error.
    pub const FORMERR: u16 = 1;
    /// Server failure.
    pub const SERVFAIL: u16 = 2;
    /// Non-existent domain.
    pub const NXDOMAIN: u16 = 3;
    /// Not implemented.
    pub const NOTIMP: u16 = 4;
    /// Refused.
    pub const REFUSED: u16 = 5;
    /// A name that should not exist does (a DNAME result too long, RFC 6672).
    pub const YXDOMAIN: u16 = 6;
    /// Not authorized (a signed query whose key the server does not know).
    pub const NOTAUTH: u16 = 9;
    /// Bad EDNS version.
    pub const BADVERS: u16 = 16;
    /// Bad or missing server cookie.
    pub const BADCOOKIE: u16 = 23;
}

/// Extended DNS error "Prohibited" (RFC 8914): a zone transfer is not served here.
pub const EDE_PROHIBITED: u16 = 18;

/// Extended DNS error "Not Authoritative" (RFC 8914): a name outside the zones.
pub const EDE_NOT_AUTHORITATIVE: u16 = 20;

/// Extended DNS error "Not Supported" (RFC 8914).
pub const EDE_NOT_SUPPORTED: u16 = 21;

/// The meta types the resolver refuses or does not implement.
const TYPE_TKEY: u16 = 249;
const TYPE_TSIG: u16 = 250;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;
const TYPE_MAILB: u16 = 253;
const TYPE_MAILA: u16 = 254;
const TYPE_OPT: u16 = 41;

/// The settings of the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Set RA: a forwarder answers names outside the zones.
    pub recursion_available: bool,
    /// Names outside the zones that no forwarding rule covers go to the forwarder of the
    /// configuration (WP4.3) when the client asked for recursion.
    pub default_forwarder: bool,
    /// The TTL of an answer synthesized by a block list's redirect.
    pub redirect_ttl: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            recursion_available: false,
            default_forwarder: false,
            redirect_ttl: 60,
        }
    }
}

/// The authoritative resolver on the serving catalog.
pub struct Authoritative {
    catalog: CatalogHandle,
    policy: Arc<dyn PolicyEngine>,
    rate: Arc<dyn RateLimiter>,
    settings: Settings,
}

impl std::fmt::Debug for Authoritative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authoritative")
            .field("revision", &self.catalog.revision())
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Authoritative {
    /// A resolver on `catalog` with no policy, no rate limit and the default settings.
    pub fn new(catalog: CatalogHandle) -> Self {
        Self {
            catalog,
            policy: Arc::new(NoPolicy),
            rate: Arc::new(Unlimited),
            settings: Settings::default(),
        }
    }

    /// The same resolver with a policy engine.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<dyn PolicyEngine>) -> Self {
        self.policy = policy;
        self
    }

    /// The same resolver with a rate limiter.
    #[must_use]
    pub fn with_rate_limiter(mut self, rate: Arc<dyn RateLimiter>) -> Self {
        self.rate = rate;
        self
    }

    /// The same resolver with other settings.
    #[must_use]
    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// The catalog it answers from.
    pub fn catalog(&self) -> &CatalogHandle {
        &self.catalog
    }

    /// The answer of a blocked name, into `answer`.
    fn blocked(&self, hit: &Hit<'_>, qtype: Rtype, answer: &mut AnswerBuf) {
        match hit.action {
            Action::Nxdomain => answer.rcode = rcode::NXDOMAIN,
            Action::Nodata | Action::Drop => {}
            Action::TcpOnly => answer.truncated = true,
            Action::Redirect(address) => {
                let (v4, v6);
                let (rtype, octets): (Rtype, &[u8]) = match address {
                    IpAddr::V4(address) => {
                        v4 = address.octets();
                        (Rtype::A, &v4)
                    }
                    IpAddr::V6(address) => {
                        v6 = address.octets();
                        (Rtype::AAAA, &v6)
                    }
                };
                if qtype == rtype || qtype == Rtype::ANY {
                    let _ = answer.push(
                        Section::Answer,
                        Owner::Qname,
                        rtype.0,
                        self.settings.redirect_ttl,
                        octets,
                    );
                }
            }
            Action::Local(records) => {
                let cname = records.iter().find(|record| record.rtype == Rtype::CNAME);
                for record in cname.into_iter().chain(records.iter().filter(|record| {
                    cname.is_none() && (record.rtype == qtype || qtype == Rtype::ANY)
                })) {
                    if answer
                        .push(
                            Section::Answer,
                            Owner::Qname,
                            record.rtype.0,
                            record.ttl,
                            &record.rdata,
                        )
                        .is_err()
                    {
                        answer.truncated = true;
                        break;
                    }
                }
            }
        }
        let _ = answer.set_extended_error(EDE_BLOCKED, "");
    }

    /// Names outside the zones: the policy, then the forwarder, else REFUSED.
    fn outside(
        &self,
        catalog: &Catalog,
        query: &QueryContext<'_>,
        view: Option<ViewId>,
        answer: &mut AnswerBuf,
    ) -> Option<Resolution> {
        let request = query.request;
        let qname = request.qname.as_wire();
        let qtype = Rtype(request.qtype);
        let check = PolicyQuery {
            view,
            client: query.client.ip(),
            qname,
            qtype,
            transport: query.transport,
        };
        if let Verdict::Block(hit) = self.policy.check(catalog, &check) {
            if hit.action == Action::Drop {
                return Some(Resolution::Drop);
            }
            self.blocked(&hit, qtype, answer);
            return None;
        }
        if request.rd {
            if let Some(rule) = catalog.forwarders().find(qname, view) {
                return Some(Resolution::Forward {
                    view,
                    rule: Some(rule),
                });
            }
            if self.settings.default_forwarder {
                return Some(Resolution::Forward { view, rule: None });
            }
        }
        answer.rcode = rcode::REFUSED;
        let _ = answer.set_extended_error(EDE_NOT_AUTHORITATIVE, "");
        None
    }
}

/// The early answer to a query the lookup does not handle: class, meta types.
fn early(qclass: u16, qtype: u16, answer: &mut AnswerBuf) -> bool {
    let (code, ede) = match (qclass, qtype) {
        (_, TYPE_OPT | TYPE_TKEY | TYPE_TSIG) => (rcode::FORMERR, None),
        (1, TYPE_AXFR | TYPE_IXFR) => (rcode::REFUSED, Some(EDE_PROHIBITED)),
        (1, TYPE_MAILA | TYPE_MAILB) => (rcode::NOTIMP, Some(EDE_NOT_SUPPORTED)),
        (1, _) => return false,
        _ => (rcode::REFUSED, Some(EDE_NOT_AUTHORITATIVE)),
    };
    answer.rcode = code;
    if let Some(ede) = ede {
        let _ = answer.set_extended_error(ede, "");
    }
    true
}

impl Resolver for Authoritative {
    fn resolve(&self, query: &QueryContext<'_>, answer: &mut AnswerBuf) -> Resolution {
        let request = query.request;
        answer.recursion_available = self.settings.recursion_available;
        if request.opcode != 0 {
            answer.rcode = rcode::NOTIMP;
            return Resolution::Answered { view: None };
        }
        if request.tsig.is_some() {
            answer.rcode = rcode::NOTAUTH;
            return Resolution::Answered { view: None };
        }
        let client = query.client.ip();
        if !self.rate.admit_query(client, query.now) {
            return Resolution::Drop;
        }
        if early(request.qclass, request.qtype, answer) {
            return Resolution::Answered { view: None };
        }
        let catalog = self.catalog.load();
        let qname = request.qname.as_wire();
        let qtype = Rtype(request.qtype);
        let view = catalog.views().select(&ViewQuery {
            client,
            local: query.local.ip(),
            transport: query.transport,
            qtype,
            minute_of_day: query.minute_of_day,
            qname,
        });
        let view_id = view.map(CompiledView::id);
        let scopes = ViewScopes::new(view, client);
        let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
        let (kind, zone) = match walk(catalog.index(), &scopes, qname, qtype, dnssec_ok, answer) {
            Walk::Done { kind, apex } => (kind, apex),
            Walk::Outside => {
                if let Some(resolution) = self.outside(&catalog, query, view_id, answer) {
                    return resolution;
                }
                // A refusal is an error; a policy answer (NXDOMAIN included) counts as
                // an answer of the name.
                let kind = if answer.rcode == rcode::REFUSED {
                    ResponseKind::Error
                } else {
                    ResponseKind::Answer
                };
                (kind, &[0u8][..])
            }
        };
        let key = ResponseKey {
            kind,
            name: match kind {
                ResponseKind::Answer | ResponseKind::NoData => qname,
                ResponseKind::NxDomain | ResponseKind::Referral => zone,
                ResponseKind::Error => &[0],
            },
            qtype: request.qtype,
            udp: query.transport == QueryTransport::Udp,
        };
        match self.rate.admit_response(client, &key, query.now) {
            RateDecision::Send => {}
            RateDecision::Slip => {
                let recursion = answer.recursion_available;
                answer.clear();
                answer.recursion_available = recursion;
                answer.truncated = true;
            }
            RateDecision::Drop => return Resolution::Drop,
        }
        Resolution::Answered { view: view_id }
    }
}

/// Where a name being answered comes from.
#[derive(Debug, Clone, Copy)]
enum At<'a> {
    /// The question name, its case kept.
    Qname,
    /// A name inside the index (a CNAME target).
    Index(&'a [u8]),
    /// The name synthesized from a DNAME, in the walk's buffer.
    Synth,
}

/// The end of a walk through the index.
enum Walk<'a> {
    /// The question's name is outside the served zones.
    Outside,
    /// The answer is written.
    Done { kind: ResponseKind, apex: &'a [u8] },
}

fn owner<'b>(at: At<'b>, synth: &'b NameBuf) -> Owner<'b> {
    match at {
        At::Qname => Owner::Qname,
        At::Index(name) => Owner::Name(name),
        At::Synth => Owner::Name(synth.as_wire()),
    }
}

/// Pushes every record of an RRset; `false` when the buffer is full (an answer or
/// authority record that does not fit truncates the answer).
fn push_set(
    answer: &mut AnswerBuf,
    section: Section,
    owner: Owner<'_>,
    set: &RrSetView<'_>,
    ttl: u32,
) -> bool {
    for rdata in set.rdata {
        if answer
            .push(section, owner, set.rtype.0, ttl, rdata.as_bytes())
            .is_err()
        {
            if section != Section::Additional {
                answer.truncated = true;
            }
            return false;
        }
    }
    true
}

/// The A and AAAA RRsets of `target` that the index holds, into the additional section.
fn push_addresses(
    index: &ZoneIndex,
    scopes: &ViewScopes<'_>,
    target: &[u8],
    answer: &mut AnswerBuf,
) -> bool {
    for set in index.addresses(scopes, target).into_iter().flatten() {
        if !push_set(
            answer,
            Section::Additional,
            Owner::Name(target),
            &set,
            set.ttl,
        ) {
            return false;
        }
    }
    true
}

/// The name inside the record data of an MX, SRV or NS record.
fn target_of(rtype: Rtype, rdata: &[u8]) -> Option<&[u8]> {
    match rtype {
        Rtype::NS => Some(rdata),
        Rtype::MX => rdata.get(2..),
        Rtype::SRV => rdata.get(6..),
        _ => None,
    }
}

/// The addresses of the targets of an MX, SRV or NS answer, each target once.
fn push_target_addresses(
    index: &ZoneIndex,
    scopes: &ViewScopes<'_>,
    set: &RrSetView<'_>,
    answer: &mut AnswerBuf,
) {
    for (position, rdata) in set.rdata.iter().enumerate() {
        let Some(target) = target_of(set.rtype, rdata.as_bytes()) else {
            return;
        };
        let seen = set.rdata[..position]
            .iter()
            .any(|earlier| target_of(set.rtype, earlier.as_bytes()) == Some(target));
        if !seen && !push_addresses(index, scopes, target, answer) {
            return;
        }
    }
}

/// The SOA of a negative answer, with the TTL of RFC 2308, section 5; the SOA and the TTL
/// when it was written.
fn push_negative_soa<'a>(
    answer: &mut AnswerBuf,
    soa: Option<RrSetView<'a>>,
) -> Option<(RrSetView<'a>, u32)> {
    let soa = soa?;
    let minimum = soa
        .rdata
        .first()
        .map(Rdata::as_bytes)
        .and_then(|data| data.len().checked_sub(4).map(|at| &data[at..]))
        .map_or(soa.ttl, |tail| {
            u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]])
        });
    let ttl = soa.ttl.min(minimum);
    push_set(
        answer,
        Section::Authority,
        Owner::Name(soa.owner),
        &soa,
        ttl,
    )
    .then_some((soa, ttl))
}

/// A referral: the NS RRset of the cut (and for DNSSEC clients its signed DS, or the proof
/// that it has none, after the proofs of the walk), the in-domain glue as required
/// additional records, then the other glue inside the parent zone.
#[allow(clippy::too_many_arguments, reason = "the parts of one referral")]
fn push_referral<'a>(
    index: &'a ZoneIndex,
    scopes: &ViewScopes<'_>,
    zone: &ZoneView<'a>,
    ns: &RrSetView<'a>,
    ds: Option<RrSetView<'a>>,
    dnssec_ok: bool,
    proofs: &mut Proofs<'a>,
    answer: &mut AnswerBuf,
) {
    if !push_set(
        answer,
        Section::Authority,
        Owner::Name(ns.owner),
        ns,
        ns.ttl,
    ) {
        return;
    }
    if dnssec_ok {
        // WP6.3: the signed DS, or the proof that the cut has none.
        match ds {
            Some(ds) => {
                if !push_set(
                    answer,
                    Section::Authority,
                    Owner::Name(ds.owner),
                    &ds,
                    ds.ttl,
                ) || !push_rrsigs(
                    index,
                    zone,
                    answer,
                    Section::Authority,
                    Owner::Name(ds.owner),
                    &ds,
                    ds.ttl,
                ) {
                    return;
                }
            }
            None => proofs.push(*zone, ProofKind::NoDs, ns.owner, &[]),
        }
        if !proofs.write(index, answer) {
            return;
        }
    }
    for required in [true, false] {
        for rdata in ns.rdata {
            let target = rdata.as_bytes();
            let in_domain = name::is_within(target, ns.owner);
            if in_domain == required
                && (in_domain || name::is_within(target, zone.apex))
                && !push_addresses(index, scopes, target, answer)
            {
                return;
            }
        }
        if required {
            answer.require_additional();
        }
    }
}

/// The name a DNAME makes of `current`: its labels below the DNAME owner, then the target.
/// `None` when the result is longer than 255 octets (YXDOMAIN, RFC 6672).
fn dname_target(
    current: &[u8],
    dname_owner: &[u8],
    target: &[u8],
    out: &mut NameBuf,
) -> Option<()> {
    let keep = current.len().checked_sub(dname_owner.len())?;
    if keep + target.len() > MAX_NAME_LEN {
        return None;
    }
    let mut buf = [0u8; MAX_NAME_LEN];
    buf[..keep].copy_from_slice(&current[..keep]);
    buf[keep..keep + target.len()].copy_from_slice(target);
    *out = NameBuf::from_wire(&buf[..keep + target.len()]).ok()?;
    Some(())
}

fn served(kind: ZoneKind) -> bool {
    matches!(kind, ZoneKind::Primary | ZoneKind::Secondary)
}

#[allow(
    clippy::too_many_lines,
    reason = "one walk with one arm per kind of lookup reads better whole"
)]
/// Answers from the index: the chain of CNAMEs and DNAMEs from the question name, then the
/// answer, the referral or the negative answer at its end. With `dnssec_ok` the RRsets
/// carry their RRSIGs and the authority section the NSEC or NSEC3 proofs (WP6.3).
fn walk<'a>(
    index: &'a ZoneIndex,
    scopes: &ViewScopes<'_>,
    qname: &[u8],
    qtype: Rtype,
    dnssec_ok: bool,
    answer: &mut AnswerBuf,
) -> Walk<'a> {
    let mut at = At::Qname;
    let mut synth = NameBuf::root();
    let mut hops = 0;
    let mut apex: &'a [u8] = &[0];
    // WP6.3: the proofs gathered on the way, written once the answer section is complete.
    let mut proofs = Proofs::default();
    loop {
        let name = match at {
            At::Qname => qname,
            At::Index(name) => name,
            At::Synth => synth.as_wire(),
        };
        let mut chain = Chain::default();
        let lookup = index.resolve(scopes, name, qtype, &mut chain);
        if hops == 0 {
            let zone = chain
                .steps()
                .next()
                .map(|(zone, _, _)| zone)
                .or_else(|| zone_of(&lookup));
            match zone {
                Some(zone) if served(zone.kind) => apex = zone.apex,
                // WP6.1: a secondary zone without its copy (before the first transfer, or
                // expired) answers SERVFAIL for its names.
                None if matches!(lookup, Lookup::NotAuthoritative)
                    && matches!(index.enclosing_zone(name), Some((_, ZoneKind::Secondary))) =>
                {
                    answer.rcode = rcode::SERVFAIL;
                    return done(ResponseKind::Error, &[0]);
                }
                _ => return Walk::Outside,
            }
            answer.authoritative = true;
        }
        let mut current = at;
        for (zone, cname, wildcard) in chain.steps() {
            if !push_set(
                answer,
                Section::Answer,
                owner(current, &synth),
                &cname,
                cname.ttl,
            ) {
                return done(ResponseKind::Answer, apex);
            }
            if dnssec_ok {
                if !push_rrsigs(
                    index,
                    &zone,
                    answer,
                    Section::Answer,
                    owner(current, &synth),
                    &cname,
                    cname.ttl,
                ) {
                    return done(ResponseKind::Answer, apex);
                }
                if let Some(wildcard) = wildcard {
                    proofs.push(
                        zone,
                        ProofKind::Wildcard,
                        at_name(current, qname, &synth),
                        wildcard,
                    );
                }
            }
            let Some(target) = cname.rdata.first() else {
                return done(ResponseKind::Answer, apex);
            };
            current = At::Index(target.as_bytes());
            hops += 1;
        }
        if chain.exhausted || hops > MAX_CHAIN {
            proofs.write(index, answer);
            return done(ResponseKind::Answer, apex);
        }
        let current_name = at_name(current, qname, &synth);
        match lookup {
            Lookup::NotAuthoritative | Lookup::Cname { .. } => {
                proofs.write(index, answer);
                return done(ResponseKind::Answer, apex);
            }
            Lookup::Answer {
                zone,
                rrset,
                wildcard,
            } => {
                if push_set(
                    answer,
                    Section::Answer,
                    owner(current, &synth),
                    &rrset,
                    rrset.ttl,
                ) && (!dnssec_ok
                    || push_rrsigs(
                        index,
                        &zone,
                        answer,
                        Section::Answer,
                        owner(current, &synth),
                        &rrset,
                        rrset.ttl,
                    ))
                {
                    if dnssec_ok && let Some(wildcard) = wildcard {
                        proofs.push(zone, ProofKind::Wildcard, current_name, wildcard);
                    }
                    if proofs.write(index, answer) {
                        push_target_addresses(index, scopes, &rrset, answer);
                    }
                }
                return done(ResponseKind::Answer, apex);
            }
            Lookup::NoData {
                zone,
                soa,
                wildcard,
            } => {
                let negative = push_negative_soa(answer, soa);
                if dnssec_ok {
                    if let Some((soa, ttl)) = negative
                        && !push_rrsigs(
                            index,
                            &zone,
                            answer,
                            Section::Authority,
                            Owner::Name(soa.owner),
                            &soa,
                            ttl,
                        )
                    {
                        return done(ResponseKind::NoData, apex);
                    }
                    match wildcard {
                        Some(wildcard) => {
                            proofs.push(zone, ProofKind::WildcardNoData, current_name, wildcard);
                        }
                        None => proofs.push(zone, ProofKind::NoData, current_name, &[]),
                    }
                    proofs.write(index, answer);
                }
                return done(ResponseKind::NoData, apex);
            }
            Lookup::NxDomain {
                zone,
                soa,
                closest_encloser,
            } => {
                answer.rcode = rcode::NXDOMAIN;
                let negative = push_negative_soa(answer, soa);
                if dnssec_ok {
                    if let Some((soa, ttl)) = negative
                        && !push_rrsigs(
                            index,
                            &zone,
                            answer,
                            Section::Authority,
                            Owner::Name(soa.owner),
                            &soa,
                            ttl,
                        )
                    {
                        return done(ResponseKind::NxDomain, apex);
                    }
                    proofs.push(zone, ProofKind::NxDomain, current_name, closest_encloser);
                    proofs.write(index, answer);
                }
                return done(ResponseKind::NxDomain, apex);
            }
            Lookup::Delegation { zone, ns, ds } => {
                if hops == 0 {
                    answer.authoritative = false;
                }
                push_referral(
                    index,
                    scopes,
                    &zone,
                    &ns,
                    ds,
                    dnssec_ok,
                    &mut proofs,
                    answer,
                );
                return done(ResponseKind::Referral, apex);
            }
            Lookup::Dname { zone, dname } => {
                let Some(target) = dname.rdata.first() else {
                    return done(ResponseKind::Answer, apex);
                };
                if !push_set(
                    answer,
                    Section::Answer,
                    Owner::Name(dname.owner),
                    &dname,
                    dname.ttl,
                ) || (dnssec_ok
                    && !push_rrsigs(
                        index,
                        &zone,
                        answer,
                        Section::Answer,
                        Owner::Name(dname.owner),
                        &dname,
                        dname.ttl,
                    ))
                {
                    return done(ResponseKind::Answer, apex);
                }
                let mut next = NameBuf::root();
                if dname_target(current_name, dname.owner, target.as_bytes(), &mut next).is_none() {
                    answer.rcode = rcode::YXDOMAIN;
                    return done(ResponseKind::Answer, apex);
                }
                // The CNAME synthesized from the DNAME, with the DNAME's TTL.
                if answer
                    .push(
                        Section::Answer,
                        owner(current, &synth),
                        Rtype::CNAME.0,
                        dname.ttl,
                        next.as_wire(),
                    )
                    .is_err()
                {
                    answer.truncated = true;
                    return done(ResponseKind::Answer, apex);
                }
                hops += 1;
                if hops > MAX_CHAIN {
                    proofs.write(index, answer);
                    return done(ResponseKind::Answer, apex);
                }
                synth = next;
                at = At::Synth;
            }
        }
    }
}

/// The wire name of a point of the walk.
fn at_name<'b>(at: At<'b>, qname: &'b [u8], synth: &'b NameBuf) -> &'b [u8] {
    match at {
        At::Qname => qname,
        At::Index(name) => name,
        At::Synth => synth.as_wire(),
    }
}

fn done(kind: ResponseKind, apex: &[u8]) -> Walk<'_> {
    Walk::Done { kind, apex }
}

fn zone_of<'a>(lookup: &Lookup<'a>) -> Option<ZoneView<'a>> {
    match *lookup {
        Lookup::NotAuthoritative => None,
        Lookup::Answer { zone, .. }
        | Lookup::Cname { zone, .. }
        | Lookup::Dname { zone, .. }
        | Lookup::Delegation { zone, .. }
        | Lookup::NoData { zone, .. }
        | Lookup::NxDomain { zone, .. } => Some(zone),
    }
}

// ---------------------------------------------------------------------------------------
// WP6.3: the DNSSEC records of answers to clients that set DO (RFC 4035, section 3.1;
// RFC 5155, section 7.2). Nothing changes without DO; the AD bit is never set here; the
// records go through the same buffer and truncation rules as the rest, and nothing
// allocates: names are hashed and composed in fixed buffers.

/// The RRSIGs at `index_owner` that cover the RRset `set`, with `ttl`, under `owner`.
/// `false` when the buffer is full (an answer or authority record that does not fit
/// truncates the answer).
fn push_rrsigs(
    index: &ZoneIndex,
    zone: &ZoneView<'_>,
    answer: &mut AnswerBuf,
    section: Section,
    owner: Owner<'_>,
    set: &RrSetView<'_>,
    ttl: u32,
) -> bool {
    let Some(sigs) = index.rrset_at(zone, set.owner, Rtype::RRSIG) else {
        return true;
    };
    for rdata in sigs.rdata {
        let bytes = rdata.as_bytes();
        if bytes.len() < 2 || u16::from_be_bytes([bytes[0], bytes[1]]) != set.rtype.0 {
            continue;
        }
        if answer
            .push(section, owner, Rtype::RRSIG.0, ttl, bytes)
            .is_err()
        {
            if section != Section::Additional {
                answer.truncated = true;
            }
            return false;
        }
    }
    true
}

/// A denial RRset (NSEC or NSEC3) and its RRSIGs in the authority section.
fn push_denial(
    index: &ZoneIndex,
    zone: &ZoneView<'_>,
    set: &RrSetView<'_>,
    answer: &mut AnswerBuf,
) -> bool {
    push_set(
        answer,
        Section::Authority,
        Owner::Name(set.owner),
        set,
        set.ttl,
    ) && push_rrsigs(
        index,
        zone,
        answer,
        Section::Authority,
        Owner::Name(set.owner),
        set,
        set.ttl,
    )
}

/// What a proof shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    /// An answer synthesized from the wildcard: the name itself does not exist.
    Wildcard,
    /// The name exists (or is an empty non-terminal) without the type.
    NoData,
    /// The name matched the wildcard, which lacks the type.
    WildcardNoData,
    /// The name does not exist, nor does the wildcard at its closest encloser.
    NxDomain,
    /// The delegation at the name has no DS.
    NoDs,
}

/// One proof to write: the zone, what it shows, the name (copied, it may be a name of the
/// walk's buffer) and the wildcard owner or the closest encloser from the index.
#[derive(Debug, Clone)]
struct Proof<'a> {
    zone: ZoneView<'a>,
    kind: ProofKind,
    name: NameBuf,
    other: &'a [u8],
}

/// The proofs of one answer, at most one per step of the walk.
#[derive(Debug, Default)]
struct Proofs<'a> {
    items: [Option<Proof<'a>>; MAX_CHAIN + 2],
    len: usize,
}

/// A hashed owner name: the base32hex label of the NSEC3 hash and the apex.
struct Hashed {
    buf: [u8; MAX_NAME_LEN],
    len: usize,
}

impl Hashed {
    fn as_wire(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// The NSEC3 parameters of a zone from its NSEC3PARAM: the iterations and the salt.
fn nsec3_params<'a>(index: &'a ZoneIndex, zone: &ZoneView<'_>) -> Option<(u16, &'a [u8])> {
    let param = index.rrset_at(zone, zone.apex, Rtype::NSEC3PARAM)?;
    let data = param.rdata.first()?.as_bytes();
    let iterations = u16::from_be_bytes([*data.get(2)?, *data.get(3)?]);
    let salt_len = usize::from(*data.get(4)?);
    Some((iterations, data.get(5..5 + salt_len)?))
}

/// The hashed owner of `name` in the zone at `apex`.
fn hashed(name: &[u8], apex: &[u8], params: (u16, &[u8])) -> Option<Hashed> {
    let hash = crate::dnssec::chain::nsec3_hash(name, params.1, params.0);
    let label = crate::dnssec::chain::base32hex(&hash);
    let len = 1 + label.len() + apex.len();
    if len > MAX_NAME_LEN {
        return None;
    }
    let mut buf = [0u8; MAX_NAME_LEN];
    buf[0] = u8::try_from(label.len()).ok()?;
    buf[1..=label.len()].copy_from_slice(&label);
    buf[1 + label.len()..len].copy_from_slice(apex);
    Some(Hashed { buf, len })
}

impl<'a> Proofs<'a> {
    fn push(&mut self, zone: ZoneView<'a>, kind: ProofKind, name: &[u8], other: &'a [u8]) {
        if self.len == self.items.len() {
            return;
        }
        let Ok(name) = NameBuf::from_wire(name) else {
            return;
        };
        self.items[self.len] = Some(Proof {
            zone,
            kind,
            name,
            other,
        });
        self.len += 1;
    }

    /// Writes every proof into the authority section; `false` when the buffer is full.
    fn write(&self, index: &'a ZoneIndex, answer: &mut AnswerBuf) -> bool {
        // The denial records already written, by owner, so a record that proves two
        // things goes in once.
        let mut written: [&[u8]; 3 * (MAX_CHAIN + 2)] = [&[]; 3 * (MAX_CHAIN + 2)];
        let mut count = 0;
        for proof in self.items[..self.len].iter().flatten() {
            let mut sets: [Option<RrSetView<'a>>; 3] = [None; 3];
            match nsec3_params(index, &proof.zone) {
                Some(params) => nsec3_proof(index, proof, params, &mut sets),
                None => nsec_proof(index, proof, &mut sets),
            }
            for set in sets.iter().flatten() {
                if written[..count].contains(&set.owner) {
                    continue;
                }
                if !push_denial(index, &proof.zone, set, answer) {
                    return false;
                }
                if count < written.len() {
                    written[count] = set.owner;
                    count += 1;
                }
            }
        }
        true
    }
}

/// The NSEC records of a proof (RFC 4035, section 3.1.3).
fn nsec_proof<'a>(index: &'a ZoneIndex, proof: &Proof<'a>, sets: &mut [Option<RrSetView<'a>>; 3]) {
    let zone = &proof.zone;
    let name = proof.name.as_wire();
    match proof.kind {
        // The NSEC at or before the name: the one at the name for NODATA, the one that
        // covers an empty non-terminal or a name that does not exist.
        ProofKind::NoData | ProofKind::Wildcard => sets[0] = index.covering_nsec(zone, name),
        ProofKind::WildcardNoData => {
            sets[0] = index.covering_nsec(zone, name);
            sets[1] = index.rrset_at(zone, proof.other, Rtype::NSEC);
        }
        ProofKind::NxDomain => {
            sets[0] = index.covering_nsec(zone, name);
            let mut buf = [0u8; MAX_NAME_LEN];
            if let Some(wildcard) = wildcard_name(proof.other, &mut buf) {
                sets[1] = index.covering_nsec(zone, wildcard);
            }
        }
        ProofKind::NoDs => sets[0] = index.rrset_at(zone, name, Rtype::NSEC),
    }
}

/// The NSEC3 records of a proof (RFC 5155, section 7.2): the closest encloser's, the one
/// covering the next closer name, and the wildcard's.
fn nsec3_proof<'a>(
    index: &'a ZoneIndex,
    proof: &Proof<'a>,
    params: (u16, &[u8]),
    sets: &mut [Option<RrSetView<'a>>; 3],
) {
    let zone = &proof.zone;
    let name = proof.name.as_wire();
    let cover = |target: &[u8]| {
        hashed(target, zone.apex, params)
            .and_then(|hashed| index.covering_nsec3(zone, hashed.as_wire()))
    };
    match proof.kind {
        ProofKind::NoData | ProofKind::NoDs => sets[0] = cover(name),
        ProofKind::Wildcard => {
            // The closest encloser is the wildcard's parent; the next closer name is one
            // label longer than it.
            let encloser = name::suffix(proof.other, 1);
            sets[0] = cover(next_closer(name, encloser));
        }
        ProofKind::WildcardNoData => {
            let encloser = name::suffix(proof.other, 1);
            sets[0] = cover(encloser);
            sets[1] = cover(next_closer(name, encloser));
            sets[2] = cover(proof.other);
        }
        ProofKind::NxDomain => {
            let encloser = proof.other;
            sets[0] = cover(encloser);
            sets[1] = cover(next_closer(name, encloser));
            let mut buf = [0u8; MAX_NAME_LEN];
            if let Some(wildcard) = wildcard_name(encloser, &mut buf) {
                sets[2] = cover(wildcard);
            }
        }
    }
}

/// The ancestor of `name` one label below `encloser`.
fn next_closer<'b>(name: &'b [u8], encloser: &[u8]) -> &'b [u8] {
    let skip = name::label_count(name)
        .saturating_sub(name::label_count(encloser))
        .saturating_sub(1);
    name::suffix(name, skip)
}

/// `*.` and `encloser` in `buf`.
fn wildcard_name<'b>(encloser: &[u8], buf: &'b mut [u8; MAX_NAME_LEN]) -> Option<&'b [u8]> {
    let len = encloser.len() + 2;
    if len > MAX_NAME_LEN {
        return None;
    }
    buf[0] = 1;
    buf[1] = b'*';
    buf[2..len].copy_from_slice(encloser);
    Some(&buf[..len])
}
