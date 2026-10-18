//! The transfer client (RFC 5936, RFC 1995, RFC 9103): one transfer of a zone from one
//! primary.
//!
//! With a copy held, the client asks for IXFR with the copy's SOA: a single SOA at or
//! before the copy's serial means the copy is current; a delta comes back as its steps; a
//! zone in AXFR form replaces the copy. A primary that refuses IXFR (NOTIMP, FORMERR) or
//! answers an IXFR with a newer single SOA is asked for AXFR on a new connection. Without
//! a copy the client asks for AXFR at once. The request is signed with the primary's key
//! when it has one, and every answer must then verify in the MAC chain (RFC 8945 section
//! 5.3.1) and end on a signed message. With `xot` the connection is TLS to the primary's
//! port (853 unless set) with ALPN `dot`, the name of `tls_name` (else the address)
//! checked in its certificate against the system roots or `[dns] upstream_ca`.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::ClientConfig;
use tenko_core::dns::{DnsName, Rtype, codes};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::{
    MetricKind, Outcome, count, count_bytes,
    message::{self, OPCODE_QUERY, Record, TYPE_AXFR, TYPE_IXFR, read_answer, write_request},
    out::{serial_ge, unix_now},
};
use crate::{
    tsig::{Signer, TsigKey, Verifier},
    wire::MAX_MESSAGE_LEN,
};

/// A primary as the client reaches it.
#[derive(Debug, Clone)]
pub struct Primary {
    /// The address and port.
    pub address: SocketAddr,
    /// The TSIG key of the transfer.
    pub key: Option<Arc<TsigKey>>,
    /// TLS (XoT): the client configuration and the name in the certificate.
    pub tls: Option<(Arc<ClientConfig>, String)>,
}

/// The time limits of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// To connect (and finish the TLS handshake).
    pub connect: Duration,
    /// Between two messages.
    pub idle: Duration,
    /// Records of one transfer at most.
    pub max_records: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(30),
            max_records: 10_000_000,
        }
    }
}

/// The copy the client holds: the SOA's TTL and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The serial.
    pub serial: u32,
    /// The SOA's TTL.
    pub ttl: u32,
    /// The SOA's data.
    pub rdata: Vec<u8>,
}

/// One step of an incremental transfer: the records removed and added, each starting with
/// its SOA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The old SOA, then the records removed.
    pub removed: Vec<Record>,
    /// The new SOA, then the records added.
    pub added: Vec<Record>,
}

/// What a transfer brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The copy is current.
    Current {
        /// The primary's serial.
        serial: u32,
    },
    /// The whole zone (AXFR form): the SOA first, then every other record.
    Full {
        /// The records, SOA first.
        records: Vec<Record>,
        /// The octets received.
        bytes: usize,
    },
    /// The steps from the held serial to the new one.
    Delta {
        /// The steps in order.
        steps: Vec<Step>,
        /// The new SOA.
        soa: Record,
        /// The octets received.
        bytes: usize,
    },
}

impl Fetched {
    /// The serial the transfer ends at.
    pub fn serial(&self) -> Option<u32> {
        match self {
            Fetched::Current { serial } => Some(*serial),
            Fetched::Full { records, .. } => records.first().and_then(record_serial),
            Fetched::Delta { soa, .. } => record_serial(soa),
        }
    }
}

/// Why a transfer failed: the stable code (`dns.transfer.failed`, `dns.transfer.tsig`,
/// `dns.transfer.refused`) and a detail in English.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct FetchError {
    /// The code.
    pub code: &'static str,
    /// What happened.
    pub detail: String,
}

impl FetchError {
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            code: codes::TRANSFER_FAILED,
            detail: detail.into(),
        }
    }

    fn tsig(detail: impl Into<String>) -> Self {
        Self {
            code: codes::TRANSFER_TSIG,
            detail: detail.into(),
        }
    }

    fn refused(detail: impl Into<String>) -> Self {
        Self {
            code: codes::TRANSFER_REFUSED,
            detail: detail.into(),
        }
    }
}

fn record_serial(record: &Record) -> Option<u32> {
    (record.rtype == Rtype::SOA)
        .then(|| message::soa_serial(record.rdata.as_bytes()))
        .flatten()
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn connect(primary: &Primary, limits: Limits) -> Result<Box<dyn Io>, FetchError> {
    let tcp = tokio::time::timeout(limits.connect, TcpStream::connect(primary.address))
        .await
        .map_err(|_| FetchError::failed(format!("no connection to {} in time", primary.address)))?
        .map_err(|error| {
            FetchError::failed(format!("connecting to {}: {error}", primary.address))
        })?;
    let _ = tcp.set_nodelay(true);
    let Some((config, name)) = &primary.tls else {
        return Ok(Box::new(tcp));
    };
    let server = crate::upstream::server_name(name).map_err(FetchError::failed)?;
    let tls = tokio::time::timeout(
        limits.connect,
        tokio_rustls::TlsConnector::from(Arc::clone(config)).connect(server, tcp),
    )
    .await
    .map_err(|_| FetchError::failed("the TLS handshake took too long"))?
    .map_err(|error| FetchError::failed(format!("TLS with {}: {error}", primary.address)))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"dot") {
        return Err(FetchError::failed(
            "the primary did not agree to ALPN dot (RFC 9103)",
        ));
    }
    Ok(Box::new(tls))
}

/// The state of an answer being read.
enum Parse {
    /// Nothing read yet.
    Start,
    /// The first SOA read; the second record decides.
    First(Record),
    /// The zone in AXFR form, until the SOA comes again.
    Full { serial: u32, records: Vec<Record> },
    /// The steps of an IXFR: in the removals of the last step, or its additions.
    Delta {
        new: Record,
        steps: Vec<Step>,
        adding: bool,
    },
}

/// Runs one request on a fresh connection and reads the answer to its end.
#[allow(
    clippy::too_many_lines,
    reason = "one exchange from the request to the last record"
)]
async fn exchange(
    primary: &Primary,
    apex: &DnsName,
    qtype: u16,
    held: Option<&Held>,
    limits: Limits,
) -> Result<Fetched, FetchError> {
    let mut stream = connect(primary, limits).await?;
    let id = random_id();
    let mut request = Vec::with_capacity(512);
    let soa = held
        .filter(|_| qtype == TYPE_IXFR)
        .map(|held| (held.ttl, held.rdata.as_slice()));
    write_request(&mut request, id, OPCODE_QUERY, &apex.to_wire(), qtype, soa);
    let mut verifier = None;
    if let Some(key) = &primary.key {
        let mut signer = Signer::request(Arc::clone(key));
        if !signer.sign(&mut request, unix_now(), 0, &[], MAX_MESSAGE_LEN) {
            return Err(FetchError::failed("the request could not be signed"));
        }
        let mac = signer.last_mac().unwrap_or_default();
        verifier = Some(Verifier::new(Arc::clone(key), mac));
    }
    let mut framed = Vec::with_capacity(request.len() + 2);
    framed.extend_from_slice(&u16::try_from(request.len()).unwrap_or(0).to_be_bytes());
    framed.extend_from_slice(&request);
    stream
        .write_all(&framed)
        .await
        .map_err(|error| FetchError::failed(format!("sending the request: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| FetchError::failed(format!("sending the request: {error}")))?;
    let mut buf = vec![0u8; MAX_MESSAGE_LEN];
    let mut state = Parse::Start;
    let mut bytes = 0usize;
    let mut total = 0usize;
    loop {
        let len = tokio::time::timeout(limits.idle, stream.read_u16())
            .await
            .map_err(|_| FetchError::failed("the primary stopped sending"))?
            .map_err(|error| FetchError::failed(format!("the transfer ended early: {error}")))?;
        let len = usize::from(len);
        tokio::time::timeout(limits.idle, stream.read_exact(&mut buf[..len]))
            .await
            .map_err(|_| FetchError::failed("the primary stopped sending"))?
            .map_err(|error| FetchError::failed(format!("the transfer ended early: {error}")))?;
        let message = &buf[..len];
        bytes += len + 2;
        if let Some(verifier) = &mut verifier {
            verifier
                .verify(message, unix_now())
                .map_err(|error| FetchError::tsig(format!("from {}: {error}", primary.address)))?;
        }
        let answer = read_answer(message)
            .map_err(|error| FetchError::failed(format!("from {}: {error}", primary.address)))?;
        if answer.id != id {
            return Err(FetchError::failed("an answer with another id"));
        }
        match answer.rcode {
            0 => {}
            4 | 1 if qtype == TYPE_IXFR => {
                return Err(FetchError {
                    code: "ixfr.unsupported",
                    detail: format!("the primary answered IXFR with RCODE {}", answer.rcode),
                });
            }
            5 | 9 => {
                return Err(FetchError::refused(format!(
                    "{} refused the transfer (RCODE {})",
                    primary.address, answer.rcode
                )));
            }
            other => {
                return Err(FetchError::failed(format!(
                    "{} answered with RCODE {other}",
                    primary.address
                )));
            }
        }
        total += answer.answers.len();
        if total > limits.max_records {
            return Err(FetchError::failed(
                "the zone is larger than the transfer limit",
            ));
        }
        let mut records = answer.answers.into_iter();
        let mut done = None;
        for record in records.by_ref() {
            if record.name != *apex && matches!(state, Parse::Start) {
                return Err(FetchError::failed(
                    "the answer does not start with the zone's SOA",
                ));
            }
            state = match state {
                Parse::Start => {
                    if record.rtype != Rtype::SOA || record.name != *apex {
                        return Err(FetchError::failed(
                            "the answer does not start with the zone's SOA",
                        ));
                    }
                    Parse::First(record)
                }
                Parse::First(first) => {
                    let first_serial = record_serial(&first).unwrap_or_default();
                    let incremental = qtype == TYPE_IXFR
                        && record.rtype == Rtype::SOA
                        && record.name == *apex
                        && held.is_some_and(|held| record_serial(&record) == Some(held.serial));
                    if incremental {
                        Parse::Delta {
                            new: first,
                            steps: vec![Step {
                                removed: vec![record],
                                added: Vec::new(),
                            }],
                            adding: false,
                        }
                    } else if record.rtype == Rtype::SOA
                        && record.name == *apex
                        && record_serial(&record) == Some(first_serial)
                    {
                        // An empty zone: SOA, SOA.
                        done = Some(Fetched::Full {
                            records: vec![first],
                            bytes,
                        });
                        Parse::Start
                    } else {
                        Parse::Full {
                            serial: first_serial,
                            records: vec![first, record],
                        }
                    }
                }
                Parse::Full {
                    serial,
                    mut records,
                } => {
                    if record.rtype == Rtype::SOA && record.name == *apex {
                        if record_serial(&record) != Some(serial) {
                            return Err(FetchError::failed(
                                "the closing SOA differs from the first",
                            ));
                        }
                        done = Some(Fetched::Full {
                            records: std::mem::take(&mut records),
                            bytes,
                        });
                        Parse::Start
                    } else {
                        records.push(record);
                        Parse::Full { serial, records }
                    }
                }
                Parse::Delta {
                    new,
                    mut steps,
                    adding,
                } => {
                    let is_soa = record.rtype == Rtype::SOA && record.name == *apex;
                    let new_serial = record_serial(&new);
                    match (is_soa, adding) {
                        (true, true) if record_serial(&record) == new_serial => {
                            done = Some(Fetched::Delta {
                                steps: std::mem::take(&mut steps),
                                soa: new.clone(),
                                bytes,
                            });
                            Parse::Start
                        }
                        (true, true) => {
                            steps.push(Step {
                                removed: vec![record],
                                added: Vec::new(),
                            });
                            Parse::Delta {
                                new,
                                steps,
                                adding: false,
                            }
                        }
                        (true, false) => {
                            if let Some(step) = steps.last_mut() {
                                step.added.push(record);
                            }
                            Parse::Delta {
                                new,
                                steps,
                                adding: true,
                            }
                        }
                        (false, adding) => {
                            if let Some(step) = steps.last_mut() {
                                if adding {
                                    step.added.push(record);
                                } else {
                                    step.removed.push(record);
                                }
                            }
                            Parse::Delta { new, steps, adding }
                        }
                    }
                }
            };
            if done.is_some() {
                break;
            }
        }
        if let Some(fetched) = done {
            if records.next().is_some() {
                return Err(FetchError::failed("records after the closing SOA"));
            }
            if let Some(verifier) = &verifier
                && !verifier.complete()
            {
                return Err(FetchError::tsig(
                    "the last message of the transfer is not signed",
                ));
            }
            return Ok(match fetched {
                Fetched::Full { records, .. } => Fetched::Full { records, bytes },
                Fetched::Delta { steps, soa, .. } => Fetched::Delta { steps, soa, bytes },
                current @ Fetched::Current { .. } => current,
            });
        }
        // A single SOA as the whole answer to an IXFR.
        if let Parse::First(first) = &state
            && qtype == TYPE_IXFR
        {
            let serial = record_serial(first).unwrap_or_default();
            if held.is_some_and(|held| serial_ge(held.serial, serial)) {
                if let Some(verifier) = &verifier
                    && !verifier.complete()
                {
                    return Err(FetchError::tsig("the answer is not signed"));
                }
                return Ok(Fetched::Current { serial });
            }
            return Err(FetchError {
                code: "ixfr.unsupported",
                detail: "the primary answered IXFR with a newer SOA only".to_owned(),
            });
        }
    }
}

fn random_id() -> u16 {
    let mut bytes = [0u8; 2];
    let _ = aws_lc_rs::rand::fill(&mut bytes);
    u16::from_be_bytes(bytes)
}

/// One transfer of `apex` from `primary`: IXFR from `held` when there is a copy (with the
/// AXFR fallback), else AXFR.
///
/// # Errors
///
/// [`FetchError`] with the stable code of the failure.
pub async fn fetch(
    primary: &Primary,
    apex: &DnsName,
    held: Option<&Held>,
    limits: Limits,
) -> Result<Fetched, FetchError> {
    if held.is_some() {
        match exchange(primary, apex, TYPE_IXFR, held, limits).await {
            Ok(fetched) => {
                let outcome = if matches!(fetched, Fetched::Current { .. }) {
                    Outcome::Current
                } else {
                    Outcome::Ok
                };
                count(MetricKind::IxfrIn, outcome);
                if let Fetched::Full { bytes, .. } | Fetched::Delta { bytes, .. } = &fetched {
                    count_bytes(true, *bytes);
                }
                return Ok(fetched);
            }
            Err(error) if error.code == "ixfr.unsupported" => {
                tracing::debug!(%apex, detail = %error.detail, "IXFR not available; asking for AXFR");
            }
            Err(error) => {
                count(
                    MetricKind::IxfrIn,
                    if error.code == codes::TRANSFER_FAILED {
                        Outcome::Failed
                    } else {
                        Outcome::Refused
                    },
                );
                return Err(error);
            }
        }
    }
    match exchange(primary, apex, TYPE_AXFR, None, limits).await {
        Ok(fetched) => {
            count(MetricKind::AxfrIn, Outcome::Ok);
            if let Fetched::Full { bytes, .. } = &fetched {
                count_bytes(true, *bytes);
            }
            Ok(fetched)
        }
        Err(error) => {
            count(
                MetricKind::AxfrIn,
                if error.code == codes::TRANSFER_FAILED {
                    Outcome::Failed
                } else {
                    Outcome::Refused
                },
            );
            Err(if error.code == "ixfr.unsupported" {
                FetchError::failed(error.detail)
            } else {
                error
            })
        }
    }
}
