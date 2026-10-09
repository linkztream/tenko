//! The records of the observation layer: facts per source and subject, the batches that
//! feed them, and the last sighting of intent objects.

use std::{collections::BTreeSet, fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ConnectorId, MacAddr, ObservationId, Timestamp, VrfId,
    observe::{Endpoint, LinkKind, Observation, ObservationSource, Observed},
};
use utoipa::ToSchema;

/// The canonical text of a source, the first part of every fact key:
/// `inventory:<connector>`, `network_controller:<connector>`, `probe:<node>:<method>`,
/// `dns:<zone>` or `dhcp:<node>`.
pub fn source_key(source: &ObservationSource) -> String {
    match source {
        ObservationSource::Inventory { connector } => format!("inventory:{connector}"),
        ObservationSource::NetworkController { connector } => {
            format!("network_controller:{connector}")
        }
        ObservationSource::Probe { node, method } => {
            let method = serde_json::to_value(method)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            format!("probe:{node}:{method}")
        }
        ObservationSource::DnsRecord { zone } => format!("dns:{zone}"),
        ObservationSource::DhcpLease { node } => format!("dhcp:{node}"),
    }
}

/// The connector behind a source, if it is a connector.
pub fn source_connector(source: &ObservationSource) -> Option<ConnectorId> {
    match source {
        ObservationSource::Inventory { connector }
        | ObservationSource::NetworkController { connector } => Some(*connector),
        _ => None,
    }
}

/// What a fact is about, within its source: the source's own identity of the thing it
/// reports. Two reports of one source about one subject are the same fact, refreshed.
///
/// Adjacently tagged (`{"type": "address", "data": {...}}`) because variants carry IP
/// addresses (see the encoding rules in `tenko_core::codec`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum FactSubject {
    /// A host of an inventory source, by the source's own identifier (CONN-02).
    Host {
        /// The source's identifier (VM id, entity id).
        external_id: String,
    },
    /// An address in use in a VRF (probe sightings, later DHCP leases).
    Address {
        /// The VRF of the observing source.
        vrf: VrfId,
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
    },
    /// Where a client is attached (network controller).
    Attachment {
        /// The client.
        mac: MacAddr,
    },
    /// The open ports of an address (SCAN-08).
    Services {
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
    },
    /// The operating system guess of an address (SCAN-08).
    Os {
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
    },
    /// A link between two devices (topology, IPAM-20).
    Link {
        /// One end.
        a: Endpoint,
        /// The other end.
        b: Endpoint,
        /// How the link was learned.
        kind: LinkKind,
    },
}

impl FactSubject {
    /// The subject of an observation.
    pub fn of(observed: &Observed) -> Self {
        match observed {
            Observed::Host(host) => FactSubject::Host {
                external_id: host.external_id.clone(),
            },
            Observed::Address { vrf, ip, .. } => FactSubject::Address { vrf: *vrf, ip: *ip },
            Observed::Attachment { mac, .. } => FactSubject::Attachment { mac: *mac },
            Observed::Services { ip, .. } => FactSubject::Services { ip: *ip },
            Observed::Os { ip, .. } => FactSubject::Os { ip: *ip },
            Observed::Link { a, b, kind } => {
                // A link is the same fact whichever end the source names first.
                let (a, b) = if (&a.device, &a.port) <= (&b.device, &b.port) {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                FactSubject::Link { a, b, kind: *kind }
            }
        }
    }

    /// The type name (`host`, `address`, `attachment`, `services`, `os`, `link`).
    pub const fn type_name(&self) -> &'static str {
        match self {
            FactSubject::Host { .. } => "host",
            FactSubject::Address { .. } => "address",
            FactSubject::Attachment { .. } => "attachment",
            FactSubject::Services { .. } => "services",
            FactSubject::Os { .. } => "os",
            FactSubject::Link { .. } => "link",
        }
    }

    /// The canonical text of the subject, the second part of the fact key:
    /// `host:<external id>`, `address:<vrf>/<ip>`, `attachment:<mac>`, `services:<ip>`,
    /// `os:<ip>` or `link:<device>|<port>|<device>|<port>|<kind>`.
    pub fn key(&self) -> String {
        match self {
            FactSubject::Host { external_id } => format!("host:{external_id}"),
            FactSubject::Address { vrf, ip } => format!("address:{vrf}/{ip}"),
            FactSubject::Attachment { mac } => format!("attachment:{mac}"),
            FactSubject::Services { ip } => format!("services:{ip}"),
            FactSubject::Os { ip } => format!("os:{ip}"),
            FactSubject::Link { a, b, kind } => {
                let kind = serde_json::to_value(kind)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                format!(
                    "link:{}|{}|{}|{}|{kind}",
                    a.device,
                    a.port.as_deref().unwrap_or_default(),
                    b.device,
                    b.port.as_deref().unwrap_or_default()
                )
            }
        }
    }
}

impl fmt::Display for FactSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

/// One source's knowledge of one subject: the latest report as the source gave it, with
/// first and last sighting. Facts of different sources are never merged; the view across
/// sources is computed when read ([`super::view`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObservedFact {
    /// The source.
    pub source: ObservationSource,
    /// The canonical text of the source ([`source_key`]).
    pub source_key: String,
    /// The subject.
    pub subject: FactSubject,
    /// The canonical text of the subject ([`FactSubject::key`]).
    pub subject_key: String,
    /// The latest report, with every attribute the source gave (name, MAC and IP
    /// addresses, OS, platform, hypervisor node, tags, attachment, ports).
    pub observed: Observed,
    /// The observation that last changed the fact (or first reported it).
    pub observation: ObservationId,
    /// When the source first reported the subject (its time).
    pub first_seen: Timestamp,
    /// When the source last reported the subject (its time).
    pub last_seen: Timestamp,
    /// When the fact was last written.
    pub received_at: Timestamp,
    /// When the fact stops counting as current without a refresh; set to the receive time
    /// when a complete batch of the source no longer reports the subject.
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
    /// Reports of the subject, counted at most once per refresh interval (the adoption
    /// constraint "after N sightings").
    #[serde(default)]
    pub sightings: u32,
    /// The source's time of the last counted sighting.
    #[serde(default)]
    pub counted_at: Option<Timestamp>,
    /// Store revision of the fact (filled when read).
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: tenko_core::Revision,
}

impl ObservedFact {
    /// Whether the fact counts as current at `now`: not expired.
    pub fn is_current(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|expires| expires > now)
    }

    /// The MAC addresses the fact names.
    pub fn macs(&self) -> Vec<MacAddr> {
        observed_macs(&self.observed)
    }

    /// The IP addresses the fact names.
    pub fn ips(&self) -> Vec<IpAddr> {
        observed_ips(&self.observed)
    }

    /// The name the source gives the subject, if any.
    pub fn name(&self) -> Option<&str> {
        observed_name(&self.observed)
    }

    /// The VRF the source reported, if it reports one (probe addresses).
    pub fn vrf(&self) -> Option<VrfId> {
        match &self.observed {
            Observed::Address { vrf, .. } => Some(*vrf),
            _ => None,
        }
    }
}

/// The MAC addresses an observation names, sorted and without duplicates.
pub fn observed_macs(observed: &Observed) -> Vec<MacAddr> {
    let set: BTreeSet<MacAddr> = match observed {
        Observed::Host(host) => host.macs.iter().copied().collect(),
        Observed::Address { mac, .. } => mac.iter().copied().collect(),
        Observed::Attachment { mac, .. } => BTreeSet::from([*mac]),
        Observed::Services { .. } | Observed::Os { .. } | Observed::Link { .. } => BTreeSet::new(),
    };
    set.into_iter().collect()
}

/// The IP addresses an observation names, sorted and without duplicates.
pub fn observed_ips(observed: &Observed) -> Vec<IpAddr> {
    let set: BTreeSet<IpAddr> = match observed {
        Observed::Host(host) => host.ips.iter().copied().collect(),
        Observed::Address { ip, .. } | Observed::Services { ip, .. } | Observed::Os { ip, .. } => {
            BTreeSet::from([*ip])
        }
        Observed::Attachment { .. } | Observed::Link { .. } => BTreeSet::new(),
    };
    set.into_iter().collect()
}

/// The name an observation gives its subject, if any (inventory hosts).
pub fn observed_name(observed: &Observed) -> Option<&str> {
    match observed {
        Observed::Host(host) => host
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty()),
        _ => None,
    }
}

/// Observations of one run of one source, as the connector host or a probe hands them
/// over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestBatch {
    /// The source the batch covers. Observations of other sources in the batch are
    /// ingested too, but only this source's facts are expired by a complete batch.
    pub source: ObservationSource,
    /// The observations.
    pub observations: Vec<Observation>,
    /// Whether the batch is the source's whole picture: its facts absent from the batch
    /// are gone (they expire at once).
    pub complete: bool,
    /// When the batch was received.
    pub received_at: Timestamp,
}

/// What one ingest wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IngestReport {
    /// Facts seen for the first time.
    pub new: u32,
    /// Facts whose attributes changed.
    pub changed: u32,
    /// Facts whose last sighting was refreshed (the refresh interval passed, or the fact
    /// had expired).
    pub refreshed: u32,
    /// Facts reported again without a write (unchanged, refreshed recently).
    pub unchanged: u32,
    /// Facts expired because a complete batch no longer reports them.
    pub gone: u32,
    /// Observations refused (malformed, such as an empty external id).
    pub skipped: u32,
    /// The revision that committed the write; `None` when nothing was written.
    #[serde(default)]
    #[schema(value_type = Option<u64>)]
    pub revision: Option<tenko_core::Revision>,
}

impl IngestReport {
    /// Whether anything was written.
    pub fn wrote(&self) -> bool {
        self.revision.is_some()
    }
}

/// When an intent object (an address or an interface) was last matched by a current
/// observation; written by the reconciler at most once per refresh interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntentSighting {
    /// The latest matching sighting (the source's time).
    pub at: Timestamp,
    /// The source of that sighting.
    pub source: String,
    /// The observation behind it.
    pub observation: ObservationId,
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        NodeId,
        codec::{from_cbor, to_cbor},
        observe::{ObservedHost, ProbeMethod},
    };

    use super::*;

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("mac")
    }

    #[test]
    fn source_keys_are_canonical() {
        let connector = ConnectorId::generate();
        assert_eq!(
            source_key(&ObservationSource::Inventory { connector }),
            format!("inventory:{connector}")
        );
        assert_eq!(
            source_key(&ObservationSource::Probe {
                node: NodeId(3),
                method: ProbeMethod::TcpSyn
            }),
            "probe:3:tcp_syn"
        );
        assert_eq!(
            source_connector(&ObservationSource::NetworkController { connector }),
            Some(connector)
        );
    }

    #[test]
    fn links_are_one_fact_in_either_direction() {
        let a = Endpoint {
            device: "switch-a".to_owned(),
            port: Some("1".to_owned()),
        };
        let b = Endpoint {
            device: "ap-b".to_owned(),
            port: None,
        };
        let one = FactSubject::of(&Observed::Link {
            a: a.clone(),
            b: b.clone(),
            kind: LinkKind::Lldp,
        });
        let other = FactSubject::of(&Observed::Link {
            a: b,
            b: a,
            kind: LinkKind::Lldp,
        });
        assert_eq!(one, other);
        assert_eq!(one.key(), "link:ap-b||switch-a|1|lldp");
    }

    #[test]
    fn hosts_name_their_macs_ips_and_name() {
        let observed = Observed::Host(ObservedHost {
            external_id: "qemu/101".to_owned(),
            name: Some(" web01 ".to_owned()),
            macs: vec![mac("00:00:5e:00:53:02"), mac("00:00:5e:00:53:01")],
            ips: vec!["192.0.2.10".parse().expect("ip")],
            ..ObservedHost::default()
        });
        assert_eq!(
            observed_macs(&observed),
            vec![mac("00:00:5e:00:53:01"), mac("00:00:5e:00:53:02")]
        );
        assert_eq!(observed_name(&observed), Some("web01"));
        assert_eq!(FactSubject::of(&observed).key(), "host:qemu/101");
    }

    #[test]
    fn facts_round_trip_in_cbor_and_json() {
        let vrf = VrfId::generate();
        let fact = ObservedFact {
            source: ObservationSource::Probe {
                node: NodeId(1),
                method: ProbeMethod::Arp,
            },
            source_key: "probe:1:arp".to_owned(),
            subject: FactSubject::Address {
                vrf,
                ip: "2001:db8::10".parse().expect("ip"),
            },
            subject_key: format!("address:{vrf}/2001:db8::10"),
            observed: Observed::Address {
                vrf,
                ip: "2001:db8::10".parse().expect("ip"),
                mac: Some(mac("00:00:5e:00:53:10")),
            },
            observation: ObservationId::generate(),
            first_seen: "2026-10-10T08:00:00Z".parse().expect("time"),
            last_seen: "2026-10-10T09:00:00Z".parse().expect("time"),
            received_at: "2026-10-10T09:00:01Z".parse().expect("time"),
            expires_at: None,
            sightings: 4,
            counted_at: None,
            revision: tenko_core::Revision::ZERO,
        };
        let back: ObservedFact = from_cbor(&to_cbor(&fact).expect("cbor")).expect("cbor");
        assert_eq!(back, fact);
        let json = serde_json::to_value(&fact).expect("json");
        assert_eq!(json["subject"]["type"], "address");
        assert_eq!(json["subject"]["data"]["ip"], "2001:db8::10");
        assert_eq!(
            serde_json::from_value::<ObservedFact>(json).expect("json"),
            fact
        );
        assert!(fact.is_current("2026-10-10T09:00:01Z".parse().expect("time")));
        assert_eq!(fact.vrf(), Some(vrf));
    }
}
