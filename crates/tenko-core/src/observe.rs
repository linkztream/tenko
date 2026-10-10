//! Observations and proposals (plan section 2.3, IPAM-12, IPAM-15).
//!
//! Observations are what discovery, connectors and later the DNS and DHCP engines see.
//! They live in `ipam.obs.*` tables and never overwrite intent; observations without
//! intent become [`Proposal`]s for a human (or an explicit auto-adopt rule) to decide.
//! Ingest writes changes only, and "last seen" is refreshed at most every 15 minutes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    id::{ConnectorId, NodeId, ObservationId, PrefixId, ProposalId, VrfId},
    ipam::{AssignmentMode, Stamp},
    net::{Fqdn, HostName, MacAddr},
    object::ObjectRef,
    timestamp::Timestamp,
};

/// One thing seen by one source at one time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Observation {
    /// Identifier.
    pub id: ObservationId,
    /// Who saw it.
    pub source: ObservationSource,
    /// What was seen.
    pub subject: Observed,
    /// When the source saw it.
    pub observed_at: Timestamp,
    /// When Tenko received it.
    pub received_at: Timestamp,
    /// When it stops being valid without a refresh.
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
}

/// The source of an observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObservationSource {
    /// A discovery probe (SCAN-02, SCAN-04, SCAN-05).
    Probe {
        /// The probe node.
        node: NodeId,
        /// How it saw the subject.
        method: ProbeMethod,
    },
    /// An inventory connector (CONN-02).
    Inventory {
        /// The connector.
        connector: ConnectorId,
    },
    /// A network controller connector (CONN-05).
    NetworkController {
        /// The connector.
        connector: ConnectorId,
    },
    /// A DNS record (Phase 2).
    DnsRecord {
        /// The zone.
        zone: Fqdn,
    },
    /// A DHCP lease (Phase 3).
    DhcpLease {
        /// The DHCP node.
        node: NodeId,
    },
}

/// How a probe saw its subject.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    /// IPv4 neighbours from the probe host's ARP table.
    Arp,
    /// IPv6 neighbours from the probe host's neighbour discovery table.
    Nd,
    /// Multicast DNS.
    Mdns,
    /// LLDP.
    Lldp,
    /// ICMP echo.
    Icmp,
    /// TCP SYN scan (raw sockets).
    TcpSyn,
    /// OS fingerprinting.
    OsFingerprint,
    /// SNMP polling.
    Snmp,
    /// TCP connect scan through the operating system.
    TcpConnect,
    /// Reverse DNS lookups of discovered addresses.
    ReverseDns,
    /// Link-local multicast name resolution.
    Llmnr,
    /// An active ARP sweep (raw sockets).
    ArpSweep,
}

/// What was observed.
///
/// Adjacently tagged (`{"type": "address", "data": {...}}`) because variants carry IP
/// addresses; see the encoding rules in [`crate::codec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Observed {
    /// An address in use, with the MAC behind it when known.
    Address {
        /// The VRF the observing source belongs to.
        vrf: VrfId,
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
        /// The MAC address.
        #[serde(default)]
        mac: Option<MacAddr>,
    },
    /// A host from an inventory source.
    Host(ObservedHost),
    /// Open TCP ports (SCAN-08).
    Services {
        /// The address scanned.
        #[schema(value_type = String)]
        ip: IpAddr,
        /// Open ports.
        open_tcp: Vec<u16>,
        /// The open ports that answered a TLS handshake.
        #[serde(default)]
        tls_tcp: Vec<u16>,
    },
    /// An operating system guess (SCAN-08).
    Os {
        /// The address scanned.
        #[schema(value_type = String)]
        ip: IpAddr,
        /// Free-text guess, such as `Linux 6.x`.
        guess: String,
        /// Confidence in percent.
        confidence: u8,
    },
    /// Where a client is attached (switch port or wireless network).
    Attachment {
        /// The client.
        mac: MacAddr,
        /// The switch or access point, as the controller names it.
        device: String,
        /// The switch port.
        #[serde(default)]
        port: Option<String>,
        /// The wireless network.
        #[serde(default)]
        ssid: Option<String>,
        /// The VLAN the client is in.
        #[serde(default)]
        vlan: Option<u16>,
    },
    /// A link between two devices (IPAM-20 topology edges).
    Link {
        /// One end.
        a: Endpoint,
        /// The other end.
        b: Endpoint,
        /// How the link was learned.
        kind: LinkKind,
    },
    /// A name a source found for an address (reverse DNS, mDNS, LLMNR, SNMP). A name is
    /// not a sighting of the address.
    Name {
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
        /// The name, such as `printer.example.net`.
        name: String,
    },
    /// The organisation a MAC address is registered to (its OUI), or the manufacturer a
    /// device reports.
    Vendor {
        /// The MAC address.
        mac: MacAddr,
        /// The vendor name.
        vendor: String,
    },
}

/// A host as an inventory source reports it (CONN-02).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObservedHost {
    /// The source's own identifier (VM id, entity id), stable across polls.
    pub external_id: String,
    /// Name as the source shows it.
    #[serde(default)]
    pub name: Option<String>,
    /// MAC addresses.
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// IP addresses.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub ips: Vec<IpAddr>,
    /// Operating system.
    #[serde(default)]
    pub os: Option<String>,
    /// Platform, such as `qemu`, `lxc` or `esphome`.
    #[serde(default)]
    pub platform: Option<String>,
    /// The parent host's `external_id` (the hypervisor node of a VM).
    #[serde(default)]
    pub parent: Option<String>,
    /// Tags from the source.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// One end of a link.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Endpoint {
    /// The device, as the source names it.
    pub device: String,
    /// The port.
    #[serde(default)]
    pub port: Option<String>,
}

/// How a link was learned.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// LLDP neighbour.
    Lldp,
    /// Uplink reported by a network controller.
    Uplink,
    /// Wired client attachment.
    Wired,
    /// Wireless client attachment.
    Wireless,
}

/// A suggestion derived from observations, waiting for a decision (IPAM-15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Proposal {
    /// Identifier.
    pub id: ProposalId,
    /// What kind of suggestion.
    pub kind: ProposalKind,
    /// The observations behind it.
    pub evidence: Vec<ObservationId>,
    /// The intent that approving would create or change.
    pub suggestion: SuggestedIntent,
    /// Decision state.
    pub state: ProposalState,
}

/// Kinds of proposals.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// An unknown device (for example an unknown MAC in a lease or scan).
    DiscoveredHost,
    /// A DNS record without a host.
    OrphanedRecord,
    /// Observation contradicts intent (IPAM-23).
    Conflict,
}

/// The intent a proposal suggests. Fields that are `None` are left as they are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SuggestedIntent {
    /// The existing object the proposal concerns, if any.
    #[serde(default)]
    pub target: Option<ObjectRef>,
    /// Host name.
    #[serde(default)]
    pub name: Option<HostName>,
    /// Assignment mode.
    #[serde(default)]
    pub mode: Option<AssignmentMode>,
    /// VRF.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// Prefix.
    #[serde(default)]
    pub prefix: Option<PrefixId>,
    /// Address.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// MAC address.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// DNS name.
    #[serde(default)]
    pub dns_name: Option<Fqdn>,
}

/// Decision state of a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProposalState {
    /// Waiting for a decision.
    Open,
    /// Approved by a person.
    Approved(Stamp),
    /// Rejected by a person.
    Rejected(Stamp),
    /// Adopted by an explicit rule.
    AutoAdopted {
        /// The rule that adopted it.
        rule: ObjectRef,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{from_cbor, to_cbor},
        principal::{Principal, SystemComponent},
    };

    #[test]
    fn observations_round_trip() {
        let observation = Observation {
            id: ObservationId::generate(),
            source: ObservationSource::Probe {
                node: NodeId(2),
                method: ProbeMethod::Arp,
            },
            subject: Observed::Address {
                vrf: VrfId::generate(),
                ip: "192.0.2.44".parse().expect("ip"),
                mac: Some("00:00:5e:00:53:44".parse().expect("mac")),
            },
            observed_at: "2026-10-09T12:00:00Z".parse().expect("time"),
            received_at: "2026-10-09T12:00:01Z".parse().expect("time"),
            expires_at: None,
        };
        let json = serde_json::to_value(&observation).expect("json");
        assert_eq!(json["source"]["type"], "probe");
        assert_eq!(json["subject"]["type"], "address");
        assert_eq!(json["subject"]["data"]["ip"], "192.0.2.44");
        assert_eq!(
            serde_json::from_value::<Observation>(json).expect("json"),
            observation
        );
        let back: Observation = from_cbor(&to_cbor(&observation).expect("cbor")).expect("cbor");
        assert_eq!(back, observation);
    }

    #[test]
    fn host_and_link_observations_round_trip() {
        for subject in [
            Observed::Host(ObservedHost {
                external_id: "qemu/101".to_owned(),
                name: Some("web01".to_owned()),
                ips: vec!["2001:db8::10".parse().expect("ip")],
                ..ObservedHost::default()
            }),
            Observed::Link {
                a: Endpoint {
                    device: "switch-a".to_owned(),
                    port: Some("1".to_owned()),
                },
                b: Endpoint {
                    device: "ap-b".to_owned(),
                    port: None,
                },
                kind: LinkKind::Lldp,
            },
            Observed::Services {
                ip: "192.0.2.10".parse().expect("ip"),
                open_tcp: vec![22, 443],
                tls_tcp: vec![443],
            },
            Observed::Name {
                ip: "192.0.2.10".parse().expect("ip"),
                name: "printer.example.net".to_owned(),
            },
            Observed::Vendor {
                mac: "00:00:5e:00:53:10".parse().expect("mac"),
                vendor: "ICANN, IANA Department".to_owned(),
            },
        ] {
            let back: Observed = from_cbor(&to_cbor(&subject).expect("cbor")).expect("cbor");
            assert_eq!(back, subject);
            let json = serde_json::to_string(&subject).expect("json");
            assert_eq!(
                serde_json::from_str::<Observed>(&json).expect("json"),
                subject
            );
        }
    }

    #[test]
    fn services_without_tls_ports_read_as_empty() {
        let json = r#"{"type": "services", "data": {"ip": "192.0.2.10", "open_tcp": [22]}}"#;
        let Observed::Services { tls_tcp, .. } = serde_json::from_str(json).expect("json") else {
            panic!("not services");
        };
        assert_eq!(tls_tcp, Vec::<u16>::new());
        assert_eq!(
            serde_json::to_value(ProbeMethod::ReverseDns).expect("json"),
            "reverse_dns"
        );
    }

    #[test]
    fn proposal_states_round_trip() {
        let stamp = Stamp::new(
            "2026-10-09T12:00:00Z".parse().expect("time"),
            Principal::system(SystemComponent::Reconciler),
        );
        for state in [
            ProposalState::Open,
            ProposalState::Approved(stamp.clone()),
            ProposalState::Rejected(stamp),
        ] {
            let json = serde_json::to_string(&state).expect("json");
            assert_eq!(
                serde_json::from_str::<ProposalState>(&json).expect("json"),
                state
            );
            let back: ProposalState = from_cbor(&to_cbor(&state).expect("cbor")).expect("cbor");
            assert_eq!(back, state);
        }
    }
}
