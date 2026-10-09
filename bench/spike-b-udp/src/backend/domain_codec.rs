//! Parse and build with `domain` (NLnet Labs).
//!
//! Parsing is zero-copy: `Message<&[u8]>` and `ParsedName<&[u8]>` borrow the
//! packet. Building writes into the caller's reused `Vec<u8>` through a
//! `StaticCompressor` (name compression with a fixed-size table, no heap).

use domain::base::iana::{Class, Opcode, OptRcode, Rcode};
use domain::base::message_builder::{
    AnswerBuilder, AuthorityBuilder, MessageBuilder, StaticCompressor,
};
use domain::base::name::ParsedName;
use domain::base::{Message, Name, Question, Serial, Ttl};
use domain::rdata::{A, Soa};

use super::{Codec, CodecError, EdnsInfo, QueryMeta};
use crate::wire::{APEX, OPT_LEN, SERVER_EDNS_UDP};
use crate::zone::{NameKey, Outcome, SOA, TTL};

type Target = StaticCompressor<Vec<u8>>;

/// A parsed query: the message header view plus its sole question.
pub struct DomainQuery<'a> {
    pub question: Question<ParsedName<&'a [u8]>>,
    pub opcode: Opcode,
}

pub struct DomainCodec {
    apex: Name<Vec<u8>>,
    soa: Soa<Name<Vec<u8>>>,
}

fn name(s: &str) -> Name<Vec<u8>> {
    Name::vec_from_str(s).expect("valid static name")
}

fn err<E>(what: &'static str) -> impl FnOnce(E) -> CodecError {
    move |_| CodecError(what)
}

impl DomainCodec {
    /// Starts a response: header and the question. Returns the builder positioned at the answer section.
    fn start(
        &self,
        target: Target,
        query: &DomainQuery<'_>,
        meta: &QueryMeta,
        outcome: Outcome,
        limit: usize,
    ) -> Result<AnswerBuilder<Target>, CodecError> {
        let mut msg = MessageBuilder::from_target(target).map_err(err("header"))?;
        msg.set_push_limit(limit);
        let h = msg.header_mut();
        h.set_id(meta.id);
        h.set_qr(true);
        h.set_opcode(query.opcode);
        h.set_rd(meta.rd);
        h.set_aa(matches!(
            outcome,
            Outcome::Answer(_) | Outcome::NoData | Outcome::NxDomain | Outcome::ApexSoa
        ));
        // Low four bits; BADVERS is completed through the OPT record.
        h.set_rcode(Rcode::masked_from_int((outcome.rcode() & 0x0f) as u8));
        let mut q = msg.question();
        q.push(query.question)
            .map_err(err("question does not fit"))?;
        Ok(q.answer())
    }

    /// Pushes the records for `outcome` and moves on to the authority section.
    /// Returns false if they did not fit. (Going back from a later section to
    /// an earlier one rewinds the later one, so the builder only moves forward.)
    fn push_records(
        &self,
        mut ans: AnswerBuilder<Target>,
        query: &DomainQuery<'_>,
        outcome: Outcome,
    ) -> (AuthorityBuilder<Target>, bool) {
        let mut ok = match outcome {
            Outcome::Answer(ip) => ans
                .push((
                    query.question.qname(),
                    Class::IN,
                    Ttl::from_secs(TTL),
                    A::new(ip),
                ))
                .is_ok(),
            Outcome::ApexSoa => ans
                .push((&self.apex, Class::IN, Ttl::from_secs(TTL), &self.soa))
                .is_ok(),
            _ => true,
        };
        let mut auth = ans.authority();
        if ok && matches!(outcome, Outcome::NoData | Outcome::NxDomain) {
            ok = auth
                .push((
                    &self.apex,
                    Class::IN,
                    Ttl::from_secs(SOA.minimum),
                    &self.soa,
                ))
                .is_ok();
        }
        (auth, ok)
    }
}

impl Codec for DomainCodec {
    const NAME: &'static str = "domain";
    type Query<'a> = DomainQuery<'a>;

    fn new() -> Self {
        let soa = Soa::new(
            name(SOA.mname),
            name(SOA.rname),
            Serial(SOA.serial),
            Ttl::from_secs(SOA.refresh),
            Ttl::from_secs(SOA.retry),
            Ttl::from_secs(SOA.expire),
            Ttl::from_secs(SOA.minimum),
        );
        Self {
            apex: name(APEX),
            soa,
        }
    }

    #[inline]
    fn parse<'a>(
        &self,
        req: &'a [u8],
        key: &mut NameKey,
    ) -> Result<(DomainQuery<'a>, QueryMeta), CodecError> {
        let msg = Message::from_octets(req).map_err(err("short message"))?;
        let header = msg.header();
        let question = msg.sole_question().map_err(err("question"))?;
        for label in question.qname().iter() {
            key.push_label(label.as_slice());
        }
        let edns = if msg.header_counts().arcount() > 0 {
            msg.opt().map(|opt| EdnsInfo {
                udp_size: opt.udp_payload_size(),
                version: opt.version(),
                dnssec_ok: opt.dnssec_ok(),
            })
        } else {
            None
        };
        let meta = QueryMeta {
            id: header.id(),
            opcode: header.opcode().to_int(),
            rd: header.rd(),
            qtype: question.qtype().to_int(),
            qclass: question.qclass().to_int(),
            edns,
        };
        Ok((
            DomainQuery {
                question,
                opcode: header.opcode(),
            },
            meta,
        ))
    }

    #[inline]
    fn build(
        &self,
        query: &DomainQuery<'_>,
        meta: &QueryMeta,
        outcome: Outcome,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        let opt_reserve = if meta.edns.is_some() { OPT_LEN } else { 0 };
        // The builder rejects a push that makes the message reach the limit,
        // hence the + 1.
        let limit = max_len.saturating_sub(opt_reserve) + 1;
        let ans = self.start(
            StaticCompressor::new(std::mem::take(out)),
            query,
            meta,
            outcome,
            limit,
        )?;
        let (auth, fits) = self.push_records(ans, query, outcome);
        let mut add = if fits {
            auth.additional()
        } else {
            // Truncate: restart with header and question only, TC=1.
            let target = auth.finish();
            let mut ans = self.start(target, query, meta, outcome, limit)?;
            ans.header_mut().set_tc(true);
            ans.additional()
        };
        add.clear_push_limit();
        if meta.edns.is_some() {
            add.opt(|opt| {
                opt.set_udp_payload_size(SERVER_EDNS_UDP);
                if outcome == Outcome::BadVers {
                    opt.set_rcode(OptRcode::BADVERS);
                }
                Ok(())
            })
            .map_err(err("opt"))?;
        }
        *out = add.finish().into_target();
        Ok(())
    }
}
