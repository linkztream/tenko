//! The policy on forwarded answers: [`PolicySink`] wraps the forwarder's
//! [`ForwardSink`] and looks at every answer before it reaches the client
//! ([`PolicyEngine::check_answer`]); a blocked answer is rewritten in place
//! ([`rewrite`]) with the action of its list or zone and the extended error `Blocked`.
//!
//! - A cache hit is looked at on the query path, in the output buffer the cache wrote,
//!   without an allocation. A hit whose action is DROP goes on to the forwarder instead,
//!   so that it is dropped like an upstream answer.
//! - A query that goes upstream gets a reply path of the sink's own; a task on the
//!   runtime takes the forwarder's answer from it, looks at it, and writes it (or its
//!   rewrite, or nothing) to the client's path. When the catalog's policy looks at no
//!   answer (no list, no RPZ zone) the query is handed over unchanged.
//!
//! The forwarder logs and counts a forwarded query before the sink rewrites it, so the
//! query log shows the upstream's RCODE for an answer the policy rewrote.

use std::{net::IpAddr, sync::Arc};

use tenko_core::dns::{QueryTransport, Rtype, ViewId};
use tokio::sync::mpsc;

use super::{Action, EDE_BLOCKED, Hit, PolicyEngine, PolicyQuery, Verdict};
use crate::{
    authoritative::rcode,
    catalog::CatalogHandle,
    name::NameBuf,
    respond::{ForwardQuery, ForwardSink, Intake, IntakeQuery, ReplyPath},
    wire::{self, HEADER_LEN, OPTION_EXTENDED_ERROR, TYPE_OPT},
};

/// The longest rewritten answer; local data beyond it is cut and the answer truncated.
const REWRITE_MAX: usize = 4096;

/// The TTL of a redirect address.
pub const REDIRECT_TTL: u32 = 60;

/// A fixed buffer the rewrite writes into.
struct Out {
    buf: [u8; REWRITE_MAX],
    len: usize,
}

impl Out {
    fn push(&mut self, bytes: &[u8]) -> bool {
        let Some(slot) = self.buf.get_mut(self.len..self.len + bytes.len()) else {
            return false;
        };
        slot.copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }
}

/// One record owned by the question name (a compression pointer to offset 12).
fn push_record(out: &mut Out, rtype: u16, ttl: u32, rdata: &[u8]) -> bool {
    let Ok(rdlen) = u16::try_from(rdata.len()) else {
        return false;
    };
    let start = out.len;
    let ok = out.push(&[0xc0, 0x0c])
        && out.push(&rtype.to_be_bytes())
        && out.push(&1u16.to_be_bytes())
        && out.push(&ttl.to_be_bytes())
        && out.push(&rdlen.to_be_bytes())
        && out.push(rdata);
    if !ok {
        out.len = start;
    }
    ok
}

/// Rewrites the answer `message` for a blocked query into `out` (cleared first): the
/// header and question of the answer, the records of the action and the answer's OPT
/// record with the extended error `Blocked`. Returns the new RCODE, or `None` when the
/// action is DROP or the message does not parse (nothing is sent). Allocates nothing when
/// `out` holds 4,096 octets; `message` and `out` may hold the same octets.
pub fn rewrite(message: &[u8], hit: &Hit<'_>, qtype: Rtype, out: &mut Vec<u8>) -> Option<u16> {
    let (written, code) = rewrite_into(message, hit, qtype)?;
    out.clear();
    out.extend_from_slice(&written.buf[..written.len]);
    Some(code)
}

#[allow(
    clippy::too_many_lines,
    reason = "one answer from header to OPT record reads better whole"
)]
fn rewrite_into(message: &[u8], hit: &Hit<'_>, qtype: Rtype) -> Option<(Out, u16)> {
    if hit.action == Action::Drop {
        return None;
    }
    let header = wire::parse_header(message)?;
    let question_end = wire::questions_end(message, header.qdcount)?;
    // The OPT record of the answer, if any.
    let mut pos = question_end;
    let mut opt = None;
    for _ in 0..u32::from(header.ancount) + u32::from(header.nscount) + u32::from(header.arcount) {
        let record = wire::read_record(message, pos)?;
        if record.rtype == TYPE_OPT {
            opt = Some(record);
        }
        pos = record.end();
    }
    let mut w = Out {
        buf: [0; REWRITE_MAX],
        len: 0,
    };
    let code = if hit.action == Action::Nxdomain {
        rcode::NXDOMAIN
    } else {
        rcode::NOERROR
    };
    let truncated = hit.action == Action::TcpOnly;
    w.push(&message[..2]);
    w.push(&[
        0x80 | (header.opcode << 3) | (u8::from(truncated) << 1) | u8::from(header.rd),
        (u8::from(header.ra) << 7)
            | (u8::from(header.cd) << 4)
            | (u8::try_from(code & 0x0f).ok()?),
    ]);
    w.push(&header.qdcount.to_be_bytes());
    w.push(&[0, 0, 0, 0, 0, 0]);
    if !w.push(&message[HEADER_LEN..question_end]) {
        return None;
    }
    let mut answers: u16 = 0;
    let mut cut = false;
    let mut add = |w: &mut Out, rtype: u16, ttl: u32, rdata: &[u8]| {
        if push_record(w, rtype, ttl, rdata) {
            answers += 1;
        } else {
            cut = true;
        }
    };
    match hit.action {
        Action::Redirect(address) => {
            let (rtype, v4, v6);
            let octets: &[u8] = match address {
                IpAddr::V4(address) => {
                    v4 = address.octets();
                    rtype = Rtype::A;
                    &v4
                }
                IpAddr::V6(address) => {
                    v6 = address.octets();
                    rtype = Rtype::AAAA;
                    &v6
                }
            };
            if qtype == rtype || qtype == Rtype::ANY {
                add(&mut w, rtype.0, REDIRECT_TTL, octets);
            }
        }
        Action::Local(records) => {
            let cname = records.iter().find(|record| record.rtype == Rtype::CNAME);
            for record in
                cname.into_iter().chain(records.iter().filter(|record| {
                    cname.is_none() && (record.rtype == qtype || qtype == Rtype::ANY)
                }))
            {
                add(&mut w, record.rtype.0, record.ttl, &record.rdata);
            }
        }
        _ => {}
    }
    let mut additional: u16 = 0;
    if let Some(opt) = opt {
        // The OPT record: owner root, type, the class and TTL of the answer's, its options
        // and the extended error.
        let options = opt.data(message);
        let rdlen = u16::try_from(options.len() + 6).ok()?;
        let ok = w.push(&[0])
            && w.push(&TYPE_OPT.to_be_bytes())
            && w.push(&opt.class.to_be_bytes())
            && w.push(&opt.ttl.to_be_bytes())
            && w.push(&rdlen.to_be_bytes())
            && w.push(options)
            && w.push(&OPTION_EXTENDED_ERROR.to_be_bytes())
            && w.push(&2u16.to_be_bytes())
            && w.push(&EDE_BLOCKED.to_be_bytes());
        if ok {
            additional = 1;
        }
    }
    w.buf[6..8].copy_from_slice(&answers.to_be_bytes());
    w.buf[10..12].copy_from_slice(&additional.to_be_bytes());
    if cut {
        w.buf[2] |= 0x02;
    }
    Some((w, code))
}

/// The question of a message: its name and type.
fn question(message: &[u8], name: &mut NameBuf) -> Option<Rtype> {
    let end = wire::read_name(message, HEADER_LEN, name)?;
    let qtype = message.get(end..end + 2)?;
    Some(Rtype(u16::from_be_bytes([qtype[0], qtype[1]])))
}

/// The forwarder's sink with the policy on its answers.
pub struct PolicySink {
    inner: Arc<dyn ForwardSink>,
    catalog: CatalogHandle,
    policy: Arc<dyn PolicyEngine>,
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for PolicySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicySink").finish_non_exhaustive()
    }
}

impl PolicySink {
    /// The sink over `inner`, deciding with `policy` on the catalog of `catalog`; the
    /// answers of upstream queries are looked at on `runtime`.
    pub fn new(
        inner: Arc<dyn ForwardSink>,
        catalog: CatalogHandle,
        policy: Arc<dyn PolicyEngine>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            inner,
            catalog,
            policy,
            runtime,
        }
    }
}

/// Looks at one forwarded answer and returns what to send: the answer, its rewrite or
/// nothing.
fn filter(
    policy: &dyn PolicyEngine,
    catalog: &CatalogHandle,
    client: IpAddr,
    view: Option<ViewId>,
    transport: QueryTransport,
    mut message: Vec<u8>,
) -> Option<Vec<u8>> {
    let mut name = NameBuf::root();
    let Some(qtype) = question(&message, &mut name) else {
        return Some(message);
    };
    let catalog = catalog.load();
    let query = PolicyQuery {
        view,
        client,
        qname: name.as_wire(),
        qtype,
        transport,
    };
    match policy.check_answer(&catalog, &query, &message) {
        Verdict::Block(hit) => {
            let (written, _) = rewrite_into(&message, &hit, qtype)?;
            message.clear();
            message.extend_from_slice(&written.buf[..written.len]);
            Some(message)
        }
        Verdict::Pass | Verdict::Allowed => Some(message),
    }
}

impl ForwardSink for PolicySink {
    fn submit(&self, mut query: ForwardQuery) {
        if !self.catalog.load().policy().inspects_answers() {
            self.inner.submit(query);
            return;
        }
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(1);
        let reply = std::mem::replace(&mut query.reply, ReplyPath::Tcp(sender));
        let (client, view, transport) = (query.client, query.view, query.transport);
        let policy = Arc::clone(&self.policy);
        let catalog = self.catalog.clone();
        self.runtime.spawn(async move {
            let Some(message) = receiver.recv().await else {
                return;
            };
            let Some(message) = filter(
                policy.as_ref(),
                &catalog,
                client.ip(),
                view,
                transport,
                message,
            ) else {
                return;
            };
            match reply {
                ReplyPath::Udp(socket) => {
                    let _ = socket.send_to(&message, client);
                }
                ReplyPath::Tcp(sender) => {
                    let _ = sender.send(message).await;
                }
            }
        });
        self.inner.submit(query);
    }

    fn intake(&self, query: &IntakeQuery<'_>, out: &mut Vec<u8>) -> Intake {
        let intake = self.inner.intake(query, out);
        // WP10.3: a synthesised wildcard answer carries addresses as well.
        let (Intake::Answered { .. } | Intake::Synthesised { .. }) = intake else {
            return intake;
        };
        let catalog = self.catalog.load();
        if !catalog.policy().inspects_answers() {
            return intake;
        }
        let request = query.request;
        let check = PolicyQuery {
            view: query.view,
            client: query.client.ip(),
            qname: request.qname.as_wire(),
            qtype: Rtype(request.qtype),
            transport: query.transport,
        };
        let Verdict::Block(hit) = self.policy.check_answer(&catalog, &check, out) else {
            return intake;
        };
        if hit.action == Action::Drop {
            return Intake::Forward;
        }
        let Some((written, rcode)) = rewrite_into(out, &hit, Rtype(request.qtype)) else {
            return intake;
        };
        out.clear();
        out.extend_from_slice(&written.buf[..written.len]);
        Intake::Answered {
            rcode,
            validation: None,
        }
    }
}
