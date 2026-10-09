//! Parse and build with `hickory-proto`.
//!
//! Uses the crate's lower-level API instead of decoding a whole `Message`:
//! `Header::read` + `Query::read` + `Record::read` for the additional section
//! (the OPT record), and `emit_message_parts` with borrowed records into the
//! caller's reused `Vec<u8>` (the same approach `hickory-server` takes for
//! responses). Name compression is on (the crate default).

use hickory_proto::op::{Edns, Header, Metadata, Query, ResponseCode, emit_message_parts};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};

use super::{Codec, CodecError, EdnsInfo, QueryMeta};
use crate::wire::{APEX, SERVER_EDNS_UDP};
use crate::zone::{NameKey, Outcome, SOA, TTL};

/// A parsed query: header metadata and the sole question.
pub struct HickoryQuery {
    pub metadata: Metadata,
    pub query: Query,
}

pub struct HickoryCodec {
    /// Apex SOA for the answer section (TTL = zone TTL).
    soa_answer: Record,
    /// Apex SOA for the authority section of negative answers (TTL = SOA minimum).
    soa_negative: Record,
}

fn name(s: &str) -> Name {
    let mut n = Name::from_ascii(s).expect("valid static name");
    n.set_fqdn(true);
    n
}

fn err<E>(what: &'static str) -> impl FnOnce(E) -> CodecError {
    move |_| CodecError(what)
}

impl HickoryCodec {
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        query: &HickoryQuery,
        metadata: &Metadata,
        answer: Option<&Record>,
        authority: Option<&Record>,
        edns: Option<&Edns>,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<Header, CodecError> {
        out.clear();
        let mut enc = BinEncoder::new(out);
        enc.set_max_size(u16::try_from(max_len).unwrap_or(u16::MAX));
        emit_message_parts(
            metadata,
            &mut std::iter::once(&query.query),
            &mut answer.into_iter(),
            &mut authority.into_iter(),
            &mut std::iter::empty::<&Record>(),
            edns,
            None,
            &mut enc,
        )
        .map_err(err("emit"))
    }
}

impl Codec for HickoryCodec {
    const NAME: &'static str = "hickory";
    type Query<'a> = HickoryQuery;

    fn new() -> Self {
        let apex = name(APEX);
        let soa = SOA::new(
            name(SOA.mname),
            name(SOA.rname),
            SOA.serial,
            SOA.refresh as i32,
            SOA.retry as i32,
            SOA.expire as i32,
            SOA.minimum,
        );
        Self {
            soa_answer: Record::from_rdata(apex.clone(), TTL, RData::SOA(soa.clone())),
            soa_negative: Record::from_rdata(apex, SOA.minimum, RData::SOA(soa)),
        }
    }

    #[inline]
    fn parse(
        &self,
        req: &[u8],
        key: &mut NameKey,
    ) -> Result<(HickoryQuery, QueryMeta), CodecError> {
        let mut d = BinDecoder::new(req);
        let header = Header::read(&mut d).map_err(err("header"))?;
        if header.counts.queries != 1 {
            return Err(CodecError("qdcount != 1"));
        }
        let query = Query::read(&mut d).map_err(err("question"))?;
        for label in query.name().iter() {
            key.push_label(label);
        }
        let mut edns = None;
        let records = u32::from(header.counts.answers) + u32::from(header.counts.authorities);
        let additionals = u32::from(header.counts.additionals);
        if additionals > 0 {
            for _ in 0..records {
                Record::read(&mut d).map_err(err("record"))?;
            }
            for _ in 0..additionals {
                let rec = Record::read(&mut d).map_err(err("additional"))?;
                if rec.record_type() == RecordType::OPT {
                    if edns.is_some() {
                        return Err(CodecError("duplicate OPT"));
                    }
                    let e = Edns::from(&rec);
                    edns = Some(EdnsInfo {
                        udp_size: e.max_payload(),
                        version: e.version(),
                        dnssec_ok: e.flags().dnssec_ok,
                    });
                }
            }
        }
        let m = &header.metadata;
        let meta = QueryMeta {
            id: m.id,
            opcode: u8::from(m.op_code),
            rd: m.recursion_desired,
            qtype: u16::from(query.query_type()),
            qclass: u16::from(query.query_class()),
            edns,
        };
        Ok((
            HickoryQuery {
                metadata: header.metadata,
                query,
            },
            meta,
        ))
    }

    #[inline]
    fn build(
        &self,
        query: &HickoryQuery,
        meta: &QueryMeta,
        outcome: Outcome,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        let mut metadata = Metadata::response_from_request(&query.metadata);
        metadata.authoritative = matches!(
            outcome,
            Outcome::Answer(_) | Outcome::NoData | Outcome::NxDomain | Outcome::ApexSoa
        );
        let rcode = outcome.rcode();
        metadata.response_code = ResponseCode::from((rcode >> 4) as u8, (rcode & 0x0f) as u8);

        let a_record;
        let (answer, authority) = match outcome {
            Outcome::Answer(ip) => {
                a_record = Record::from_rdata(query.query.name().clone(), TTL, RData::A(A(ip)));
                (Some(&a_record), None)
            }
            Outcome::ApexSoa => (Some(&self.soa_answer), None),
            Outcome::NoData | Outcome::NxDomain => (None, Some(&self.soa_negative)),
            Outcome::Refused | Outcome::NotImp | Outcome::BadVers => (None, None),
        };
        let edns = meta.edns.map(|_| {
            let mut e = Edns::new();
            e.set_max_payload(SERVER_EDNS_UDP);
            e.set_version(0);
            e
        });
        let header = self.emit(
            query,
            &metadata,
            answer,
            authority,
            edns.as_ref(),
            max_len,
            out,
        )?;
        if header.metadata.truncation {
            // Something did not fit: header, question and OPT only, TC=1.
            metadata.truncation = true;
            self.emit(query, &metadata, None, None, edns.as_ref(), max_len, out)?;
        }
        Ok(())
    }
}
