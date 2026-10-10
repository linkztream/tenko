//! Probe batches: what a probe hands to its buffer and the controller hands to the
//! reconciler.
//!
//! A probe does not know the controller's VRF ids, so a [`ProbeBatch`] carries sightings
//! without a VRF; the controller assigns one ([`ProbeBatch::into_observations`]): the VRF
//! the batch names, else the VRF of the node's enrolment token, else the default VRF. The
//! source of every observation is `probe:<node>:<method>`, so a complete batch of one
//! method expires only what that method of that node reported before.
//!
//! On the wire a batch is an `IngestRequest` of `tenko.cluster.v1`; [`ProbeBatch::encode`]
//! and [`ProbeBatch::decode`] convert, and the buffer keeps the encoded form.

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use prost::Message;
use serde::{Deserialize, Serialize};
use tenko_core::{
    MacAddr, NodeId, ObservationId, Timestamp, VrfId,
    observe::{Endpoint, LinkKind, Observation, ObservationSource, Observed, ProbeMethod},
};

use crate::{error::ClusterError, proto::v1};

/// Most sightings in one batch.
pub const MAX_SIGHTINGS: usize = 250_000;

/// One batch of a probe: one method, one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeBatch {
    /// How the probe saw what the batch reports.
    pub method: ProbeMethod,
    /// The VRF of the addresses; `None` lets the controller choose.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// Whether the batch is the probe's whole picture for this method.
    #[serde(default)]
    pub complete: bool,
    /// When the probe finished collecting the batch.
    pub collected_at: Timestamp,
    /// What the probe saw.
    pub sightings: Vec<Sighting>,
}

/// One thing a probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sighting {
    /// When.
    pub observed_at: Timestamp,
    /// Seconds it stays current without a refresh; `None` lets the controller decide.
    #[serde(default)]
    pub ttl_secs: Option<u32>,
    /// What.
    pub subject: SightingSubject,
}

/// What a probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SightingSubject {
    /// An address in use.
    Address {
        /// The address.
        ip: IpAddr,
        /// The MAC address behind it, when the method shows one.
        #[serde(default)]
        mac: Option<MacAddr>,
    },
    /// Open TCP ports of an address.
    Services {
        /// The address.
        ip: IpAddr,
        /// The open ports.
        open_tcp: Vec<u16>,
        /// The open ports that answered a TLS handshake.
        #[serde(default)]
        tls_tcp: Vec<u16>,
    },
    /// An operating system guess.
    Os {
        /// The address.
        ip: IpAddr,
        /// The guess, such as `Linux 6.x`.
        guess: String,
        /// Confidence in percent.
        confidence: u8,
    },
    /// A link between two devices.
    Link {
        /// One end.
        a: Endpoint,
        /// The other end.
        b: Endpoint,
        /// How it was learned.
        kind: LinkKind,
    },
    /// Where a client is attached.
    Attachment {
        /// The client.
        mac: MacAddr,
        /// The switch.
        device: String,
        /// The switch port.
        #[serde(default)]
        port: Option<String>,
        /// The VLAN.
        #[serde(default)]
        vlan: Option<u16>,
    },
    /// A name found for an address; not a sighting of the address.
    Name {
        /// The address.
        ip: IpAddr,
        /// The name.
        name: String,
    },
    /// The vendor of a MAC address.
    Vendor {
        /// The MAC address.
        mac: MacAddr,
        /// The vendor.
        vendor: String,
    },
}

/// What one ingest did, as the reconciler counts it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestCounts {
    /// Facts seen for the first time.
    pub new: u32,
    /// Facts whose attributes changed.
    pub changed: u32,
    /// Facts whose last sighting was refreshed.
    pub refreshed: u32,
    /// Facts reported again without a write.
    pub unchanged: u32,
    /// Facts expired because a complete batch no longer reports them.
    pub gone: u32,
    /// Sightings refused as malformed.
    pub skipped: u32,
}

/// Where a controller hands the probes' batches: the reconciler's ingest, wired by the
/// server binary.
#[async_trait]
pub trait ProbeSink: Send + Sync {
    /// Ingests one batch of `node`. `vrf` is the VRF the batch's addresses belong to,
    /// already chosen by the controller.
    ///
    /// # Errors
    ///
    /// The ingest's coded error; the node keeps the batch and sends it again.
    async fn ingest(
        &self,
        node: NodeId,
        vrf: Option<VrfId>,
        batch: ProbeBatch,
    ) -> Result<IngestCounts, ClusterError>;
}

/// A sink that keeps nothing (the IPAM module is off); it counts every sighting as
/// skipped.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardProbes;

#[async_trait]
impl ProbeSink for DiscardProbes {
    async fn ingest(
        &self,
        _node: NodeId,
        _vrf: Option<VrfId>,
        batch: ProbeBatch,
    ) -> Result<IngestCounts, ClusterError> {
        Ok(IngestCounts {
            skipped: u32::try_from(batch.sightings.len()).unwrap_or(u32::MAX),
            ..IngestCounts::default()
        })
    }
}

fn invalid(detail: impl Into<String>) -> ClusterError {
    ClusterError::new("cluster.probe.invalid_batch", 400, detail)
}

fn method_to_proto(method: ProbeMethod) -> v1::ProbeMethod {
    match method {
        ProbeMethod::Arp => v1::ProbeMethod::Arp,
        ProbeMethod::Nd => v1::ProbeMethod::Nd,
        ProbeMethod::Mdns => v1::ProbeMethod::Mdns,
        ProbeMethod::Lldp => v1::ProbeMethod::Lldp,
        ProbeMethod::Icmp => v1::ProbeMethod::Icmp,
        ProbeMethod::TcpSyn => v1::ProbeMethod::TcpSyn,
        ProbeMethod::OsFingerprint => v1::ProbeMethod::OsFingerprint,
        ProbeMethod::Snmp => v1::ProbeMethod::Snmp,
        ProbeMethod::TcpConnect => v1::ProbeMethod::TcpConnect,
        ProbeMethod::ReverseDns => v1::ProbeMethod::ReverseDns,
        ProbeMethod::Llmnr => v1::ProbeMethod::Llmnr,
        ProbeMethod::ArpSweep => v1::ProbeMethod::ArpSweep,
    }
}

fn method_from_proto(value: i32) -> Result<ProbeMethod, ClusterError> {
    Ok(match v1::ProbeMethod::try_from(value) {
        Ok(v1::ProbeMethod::Arp) => ProbeMethod::Arp,
        Ok(v1::ProbeMethod::Nd) => ProbeMethod::Nd,
        Ok(v1::ProbeMethod::Mdns) => ProbeMethod::Mdns,
        Ok(v1::ProbeMethod::Lldp) => ProbeMethod::Lldp,
        Ok(v1::ProbeMethod::Icmp) => ProbeMethod::Icmp,
        Ok(v1::ProbeMethod::TcpSyn) => ProbeMethod::TcpSyn,
        Ok(v1::ProbeMethod::OsFingerprint) => ProbeMethod::OsFingerprint,
        Ok(v1::ProbeMethod::Snmp) => ProbeMethod::Snmp,
        Ok(v1::ProbeMethod::TcpConnect) => ProbeMethod::TcpConnect,
        Ok(v1::ProbeMethod::ReverseDns) => ProbeMethod::ReverseDns,
        Ok(v1::ProbeMethod::Llmnr) => ProbeMethod::Llmnr,
        Ok(v1::ProbeMethod::ArpSweep) => ProbeMethod::ArpSweep,
        Ok(v1::ProbeMethod::Unspecified) | Err(_) => {
            return Err(invalid("the batch names no probe method it knows"));
        }
    })
}

fn kind_to_proto(kind: LinkKind) -> v1::LinkKind {
    match kind {
        LinkKind::Lldp => v1::LinkKind::Lldp,
        LinkKind::Uplink => v1::LinkKind::Uplink,
        LinkKind::Wired => v1::LinkKind::Wired,
        LinkKind::Wireless => v1::LinkKind::Wireless,
    }
}

fn kind_from_proto(value: i32) -> Option<LinkKind> {
    match v1::LinkKind::try_from(value) {
        Ok(v1::LinkKind::Lldp) => Some(LinkKind::Lldp),
        Ok(v1::LinkKind::Uplink) => Some(LinkKind::Uplink),
        Ok(v1::LinkKind::Wired) => Some(LinkKind::Wired),
        Ok(v1::LinkKind::Wireless) => Some(LinkKind::Wireless),
        Ok(v1::LinkKind::Unspecified) | Err(_) => None,
    }
}

/// A timestamp as protobuf.
pub fn timestamp_to_proto(at: Timestamp) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: at.0.unix_timestamp(),
        nanos: i32::try_from(at.0.nanosecond()).unwrap_or(0),
    }
}

/// A protobuf timestamp; `None` when it is out of range.
pub fn timestamp_from_proto(at: &prost_types::Timestamp) -> Option<Timestamp> {
    let nanos = i128::from(at.seconds) * 1_000_000_000 + i128::from(at.nanos);
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .map(Timestamp)
}

fn end_to_proto(end: &Endpoint) -> v1::LinkEnd {
    v1::LinkEnd {
        device: end.device.clone(),
        port: end.port.clone(),
    }
}

fn end_from_proto(end: Option<v1::LinkEnd>) -> Option<Endpoint> {
    let end = end?;
    (!end.device.is_empty()).then_some(Endpoint {
        device: end.device,
        port: end.port,
    })
}

impl Sighting {
    fn to_proto(&self) -> v1::Sighting {
        use v1::sighting::Subject;
        let subject = match &self.subject {
            SightingSubject::Address { ip, mac } => Subject::Address(v1::AddressSighting {
                ip: ip.to_string(),
                mac: mac.map(|mac| mac.to_string()),
            }),
            SightingSubject::Services {
                ip,
                open_tcp,
                tls_tcp,
            } => Subject::Services(v1::ServicesSighting {
                ip: ip.to_string(),
                open_tcp: open_tcp.iter().copied().map(u32::from).collect(),
                tls_tcp: tls_tcp.iter().copied().map(u32::from).collect(),
            }),
            SightingSubject::Os {
                ip,
                guess,
                confidence,
            } => Subject::Os(v1::OsSighting {
                ip: ip.to_string(),
                guess: guess.clone(),
                confidence: u32::from(*confidence),
            }),
            SightingSubject::Link { a, b, kind } => Subject::Link(v1::LinkSighting {
                a: Some(end_to_proto(a)),
                b: Some(end_to_proto(b)),
                kind: kind_to_proto(*kind).into(),
            }),
            SightingSubject::Attachment {
                mac,
                device,
                port,
                vlan,
            } => Subject::Attachment(v1::AttachmentSighting {
                mac: mac.to_string(),
                device: device.clone(),
                port: port.clone(),
                vlan: vlan.map(u32::from),
            }),
            SightingSubject::Name { ip, name } => Subject::Name(v1::NameSighting {
                ip: ip.to_string(),
                name: name.clone(),
            }),
            SightingSubject::Vendor { mac, vendor } => Subject::Vendor(v1::VendorSighting {
                mac: mac.to_string(),
                vendor: vendor.clone(),
            }),
        };
        v1::Sighting {
            observed_at: Some(timestamp_to_proto(self.observed_at)),
            ttl_secs: self.ttl_secs.unwrap_or(0),
            subject: Some(subject),
        }
    }

    /// The sighting of a protobuf message; `None` when it is malformed (counted as
    /// skipped).
    fn from_proto(message: v1::Sighting) -> Option<Self> {
        use v1::sighting::Subject;
        let ip = |text: &str| text.parse::<IpAddr>().ok();
        let ports = |values: Vec<u32>| {
            values
                .into_iter()
                .map(u16::try_from)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        };
        let subject = match message.subject? {
            Subject::Address(address) => SightingSubject::Address {
                ip: ip(&address.ip)?,
                mac: match address.mac {
                    Some(text) => Some(text.parse().ok()?),
                    None => None,
                },
            },
            Subject::Services(services) => SightingSubject::Services {
                ip: ip(&services.ip)?,
                open_tcp: ports(services.open_tcp)?,
                tls_tcp: ports(services.tls_tcp)?,
            },
            Subject::Os(os) => SightingSubject::Os {
                ip: ip(&os.ip)?,
                guess: os.guess,
                confidence: u8::try_from(os.confidence.min(100)).ok()?,
            },
            Subject::Link(link) => SightingSubject::Link {
                a: end_from_proto(link.a)?,
                b: end_from_proto(link.b)?,
                kind: kind_from_proto(link.kind)?,
            },
            Subject::Attachment(attachment) => SightingSubject::Attachment {
                mac: attachment.mac.parse().ok()?,
                device: attachment.device,
                port: attachment.port,
                vlan: match attachment.vlan {
                    Some(vlan) => Some(u16::try_from(vlan).ok()?),
                    None => None,
                },
            },
            Subject::Name(name) => {
                let text = name.name.trim();
                if text.is_empty() {
                    return None;
                }
                SightingSubject::Name {
                    ip: ip(&name.ip)?,
                    name: text.to_owned(),
                }
            }
            Subject::Vendor(vendor) => {
                let text = vendor.vendor.trim();
                if text.is_empty() {
                    return None;
                }
                SightingSubject::Vendor {
                    mac: vendor.mac.parse().ok()?,
                    vendor: text.to_owned(),
                }
            }
        };
        Some(Self {
            observed_at: timestamp_from_proto(&message.observed_at?)?,
            ttl_secs: (message.ttl_secs > 0).then_some(message.ttl_secs),
            subject,
        })
    }
}

impl ProbeBatch {
    /// The batch as an `IngestRequest` with an empty epoch and sequence 0 (the buffer's
    /// form; the sender fills both).
    pub fn to_request(&self) -> v1::IngestRequest {
        v1::IngestRequest {
            epoch: String::new(),
            sequence: 0,
            method: method_to_proto(self.method).into(),
            vrf: self.vrf.map(|vrf| vrf.to_string()),
            complete: self.complete,
            collected_at: Some(timestamp_to_proto(self.collected_at)),
            sightings: self.sightings.iter().map(Sighting::to_proto).collect(),
        }
    }

    /// The batch as protobuf bytes, the payload the buffer keeps.
    pub fn encode(&self) -> Vec<u8> {
        self.to_request().encode_to_vec()
    }

    /// The batch of a request and the number of malformed sightings left out.
    ///
    /// # Errors
    ///
    /// `cluster.probe.invalid_batch` (400) when the method, the VRF or the collection time
    /// is missing or malformed, or the batch has more than [`MAX_SIGHTINGS`] sightings.
    pub fn from_request(request: v1::IngestRequest) -> Result<(Self, u32), ClusterError> {
        let method = method_from_proto(request.method)?;
        let vrf = match request.vrf.as_deref().filter(|text| !text.is_empty()) {
            Some(text) => Some(
                text.parse::<VrfId>()
                    .map_err(|_| invalid(format!("`{text}` is not a VRF id")))?,
            ),
            None => None,
        };
        let collected_at = request
            .collected_at
            .as_ref()
            .and_then(timestamp_from_proto)
            .ok_or_else(|| invalid("the batch has no collection time"))?;
        if request.sightings.len() > MAX_SIGHTINGS {
            return Err(invalid(format!(
                "the batch has {} sightings; at most {MAX_SIGHTINGS} fit in one batch",
                request.sightings.len()
            )));
        }
        let total = request.sightings.len();
        let sightings: Vec<Sighting> = request
            .sightings
            .into_iter()
            .filter_map(Sighting::from_proto)
            .collect();
        let skipped = u32::try_from(total - sightings.len()).unwrap_or(u32::MAX);
        Ok((
            Self {
                method,
                vrf,
                complete: request.complete,
                collected_at,
                sightings,
            },
            skipped,
        ))
    }

    /// Decodes buffer bytes.
    ///
    /// # Errors
    ///
    /// `cluster.probe.invalid_batch` when the bytes are not a batch.
    pub fn decode(bytes: &[u8]) -> Result<(Self, u32), ClusterError> {
        let request = v1::IngestRequest::decode(bytes)
            .map_err(|error| invalid(format!("the batch does not decode: {error}")))?;
        Self::from_request(request)
    }

    /// The observation source of this batch from `node`.
    pub fn source(&self, node: NodeId) -> ObservationSource {
        ObservationSource::Probe {
            node,
            method: self.method,
        }
    }

    /// The observations for the reconciler: one per sighting, from source
    /// `probe:<node>:<method>`, addresses in `vrf`.
    pub fn into_observations(
        self,
        node: NodeId,
        vrf: VrfId,
        received_at: Timestamp,
    ) -> (ObservationSource, Vec<Observation>) {
        let source = self.source(node);
        let observations = self
            .sightings
            .into_iter()
            .map(|sighting| {
                let expires_at = sighting.ttl_secs.and_then(|ttl| {
                    sighting
                        .observed_at
                        .checked_add(Duration::from_secs(u64::from(ttl)))
                });
                let subject = match sighting.subject {
                    SightingSubject::Address { ip, mac } => Observed::Address { vrf, ip, mac },
                    SightingSubject::Services {
                        ip,
                        open_tcp,
                        tls_tcp,
                    } => Observed::Services {
                        ip,
                        open_tcp,
                        tls_tcp,
                    },
                    SightingSubject::Name { ip, name } => Observed::Name { ip, name },
                    SightingSubject::Vendor { mac, vendor } => Observed::Vendor { mac, vendor },
                    SightingSubject::Os {
                        ip,
                        guess,
                        confidence,
                    } => Observed::Os {
                        ip,
                        guess,
                        confidence,
                    },
                    SightingSubject::Link { a, b, kind } => Observed::Link { a, b, kind },
                    SightingSubject::Attachment {
                        mac,
                        device,
                        port,
                        vlan,
                    } => Observed::Attachment {
                        mac,
                        device,
                        port,
                        ssid: None,
                        vlan,
                    },
                };
                Observation {
                    id: ObservationId::generate(),
                    source: source.clone(),
                    subject,
                    observed_at: sighting.observed_at,
                    received_at,
                    expires_at,
                }
            })
            .collect();
        (source, observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn batch() -> ProbeBatch {
        ProbeBatch {
            method: ProbeMethod::Arp,
            vrf: None,
            complete: true,
            collected_at: at("2026-10-10T08:00:05Z"),
            sightings: vec![
                Sighting {
                    observed_at: at("2026-10-10T08:00:01Z"),
                    ttl_secs: Some(600),
                    subject: SightingSubject::Address {
                        ip: "192.0.2.10".parse().expect("ip"),
                        mac: Some("00:00:5e:00:53:10".parse().expect("mac")),
                    },
                },
                Sighting {
                    observed_at: at("2026-10-10T08:00:02Z"),
                    ttl_secs: None,
                    subject: SightingSubject::Address {
                        ip: "2001:db8::10".parse().expect("ip"),
                        mac: None,
                    },
                },
                Sighting {
                    observed_at: at("2026-10-10T08:00:03Z"),
                    ttl_secs: None,
                    subject: SightingSubject::Services {
                        ip: "192.0.2.10".parse().expect("ip"),
                        open_tcp: vec![22, 443],
                        tls_tcp: vec![443],
                    },
                },
                Sighting {
                    observed_at: at("2026-10-10T08:00:03Z"),
                    ttl_secs: Some(3600),
                    subject: SightingSubject::Name {
                        ip: "192.0.2.10".parse().expect("ip"),
                        name: "printer.example.net".to_owned(),
                    },
                },
                Sighting {
                    observed_at: at("2026-10-10T08:00:03Z"),
                    ttl_secs: None,
                    subject: SightingSubject::Vendor {
                        mac: "00:00:5e:00:53:10".parse().expect("mac"),
                        vendor: "ICANN, IANA Department".to_owned(),
                    },
                },
                Sighting {
                    observed_at: at("2026-10-10T08:00:04Z"),
                    ttl_secs: None,
                    subject: SightingSubject::Link {
                        a: Endpoint {
                            device: "switch-a.example.net".to_owned(),
                            port: Some("1".to_owned()),
                        },
                        b: Endpoint {
                            device: "ap-b.example.net".to_owned(),
                            port: None,
                        },
                        kind: LinkKind::Lldp,
                    },
                },
            ],
        }
    }

    #[test]
    fn batches_round_trip_through_protobuf() {
        let original = batch();
        let (back, skipped) = ProbeBatch::decode(&original.encode()).expect("decode");
        assert_eq!(skipped, 0);
        assert_eq!(back, original);
    }

    #[test]
    fn malformed_sightings_are_skipped_and_counted() {
        let mut request = batch().to_request();
        request.sightings.push(v1::Sighting {
            observed_at: Some(timestamp_to_proto(at("2026-10-10T08:00:00Z"))),
            ttl_secs: 0,
            subject: Some(v1::sighting::Subject::Address(v1::AddressSighting {
                ip: "not an address".to_owned(),
                mac: None,
            })),
        });
        let (back, skipped) = ProbeBatch::from_request(request).expect("batch");
        assert_eq!(skipped, 1);
        assert_eq!(back.sightings.len(), 6);
    }

    #[test]
    fn every_probe_method_crosses_the_wire() {
        for method in [
            ProbeMethod::Arp,
            ProbeMethod::Nd,
            ProbeMethod::Mdns,
            ProbeMethod::Lldp,
            ProbeMethod::Icmp,
            ProbeMethod::TcpSyn,
            ProbeMethod::OsFingerprint,
            ProbeMethod::Snmp,
            ProbeMethod::TcpConnect,
            ProbeMethod::ReverseDns,
            ProbeMethod::Llmnr,
            ProbeMethod::ArpSweep,
        ] {
            let wire: i32 = method_to_proto(method).into();
            assert_eq!(method_from_proto(wire).expect("method"), method);
        }
    }

    #[test]
    fn blank_names_and_vendors_are_skipped() {
        let mut request = batch().to_request();
        request.sightings.push(v1::Sighting {
            observed_at: Some(timestamp_to_proto(at("2026-10-10T08:00:00Z"))),
            ttl_secs: 0,
            subject: Some(v1::sighting::Subject::Name(v1::NameSighting {
                ip: "192.0.2.11".to_owned(),
                name: "  ".to_owned(),
            })),
        });
        request.sightings.push(v1::Sighting {
            observed_at: Some(timestamp_to_proto(at("2026-10-10T08:00:00Z"))),
            ttl_secs: 0,
            subject: Some(v1::sighting::Subject::Vendor(v1::VendorSighting {
                mac: "00:00:5e:00:53:11".to_owned(),
                vendor: String::new(),
            })),
        });
        let (_, skipped) = ProbeBatch::from_request(request).expect("batch");
        assert_eq!(skipped, 2);
    }

    #[test]
    fn a_batch_without_method_or_time_is_refused() {
        let mut request = batch().to_request();
        request.method = 0;
        let error = ProbeBatch::from_request(request).expect_err("no method");
        assert_eq!(error.code(), "cluster.probe.invalid_batch");
        let mut request = batch().to_request();
        request.collected_at = None;
        assert!(ProbeBatch::from_request(request).is_err());
        let mut request = batch().to_request();
        request.vrf = Some("not a uuid".to_owned());
        assert!(ProbeBatch::from_request(request).is_err());
    }

    #[test]
    fn observations_carry_the_probe_source_and_the_vrf() {
        let vrf = VrfId::generate();
        let received = at("2026-10-10T08:00:06Z");
        let (source, observations) = batch().into_observations(NodeId(1001), vrf, received);
        assert_eq!(
            source,
            ObservationSource::Probe {
                node: NodeId(1001),
                method: ProbeMethod::Arp
            }
        );
        assert_eq!(observations.len(), 6);
        assert!(observations.iter().all(|o| o.source == source));
        match &observations[0].subject {
            Observed::Address { vrf: got, .. } => assert_eq!(*got, vrf),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(observations[0].expires_at, Some(at("2026-10-10T08:10:01Z")));
        assert_eq!(observations[1].expires_at, None);
        assert!(observations.iter().all(|o| o.received_at == received));
    }

    #[test]
    fn batches_read_from_json() {
        let json = r#"{
            "method": "arp",
            "complete": false,
            "collected_at": "2026-10-10T08:00:05Z",
            "sightings": [
                {"observed_at": "2026-10-10T08:00:01Z",
                 "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}}
            ]
        }"#;
        let batch: ProbeBatch = serde_json::from_str(json).expect("json");
        assert_eq!(batch.sightings.len(), 1);
        assert!(!batch.complete);
    }
}
