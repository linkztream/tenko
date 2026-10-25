//! Shared helpers of the reconciler and proposal tests: an IPAM service over a fresh
//! in-memory store with a reconciler, synthetic connector observations and readers of the
//! proposal table. Data lives in the documentation ranges.

#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use tenko_core::{
    ConnectorId, MacAddr, NodeId, ObservationId, Timestamp, VrfId,
    observe::{NetworkDhcp, Observation, ObservationSource, Observed, ObservedHost, ProbeMethod},
};
use tenko_ipam::{
    IpamService, PlanOptions,
    observe::{IngestBatch, IngestReport},
    proposals::{
        self, Decision, IntentProposal, IntentProposalKind, IntentProposalState, ProposalQuery,
    },
    reconcile::{ReconcileReport, Reconciler, ReconcilerConfig},
};
use tenko_store::{MemStore, ReadConsistency, Store};

/// A time of the test day, `HH:MM` on 2026-10-10.
pub fn at(clock: &str) -> Timestamp {
    format!("2026-10-10T{clock}:00Z").parse().expect("time")
}

/// A time `days` after `base`.
pub fn days_after(base: Timestamp, days: u64) -> Timestamp {
    base.checked_add(Duration::from_secs(days * 24 * 3600))
        .expect("time")
}

/// Parses a MAC address.
pub fn mac(text: &str) -> MacAddr {
    text.parse().expect("mac")
}

/// A reconciler over a fresh store and IPAM service (inline jobs in place).
pub struct World {
    pub store: Arc<dyn Store>,
    pub service: Arc<IpamService>,
    pub reconciler: Arc<Reconciler>,
    pub connector: ConnectorId,
}

impl World {
    pub fn new() -> Self {
        Self::with_config(ReconcilerConfig::default())
    }

    pub fn with_config(config: ReconcilerConfig) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
        Self::over(store, service, config)
    }

    pub fn over(
        store: Arc<dyn Store>,
        service: Arc<IpamService>,
        config: ReconcilerConfig,
    ) -> Self {
        let reconciler = Reconciler::new(Arc::clone(&service), config).expect("reconciler");
        Self {
            store,
            service,
            reconciler,
            connector: ConnectorId::generate(),
        }
    }

    /// One complete inventory poll of this world's connector at `when`.
    pub async fn poll(&self, hosts: Vec<ObservedHost>, when: Timestamp) -> IngestReport {
        let source = ObservationSource::Inventory {
            connector: self.connector,
        };
        let observations = hosts
            .into_iter()
            .map(|host| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Host(host),
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        self.reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: true,
                received_at: when,
            })
            .await
            .expect("ingest")
    }

    /// Probe sightings (ARP) of `(ip, mac)` pairs in `vrf` at `when`, from probe node 7.
    pub async fn probe(&self, vrf: VrfId, pairs: &[(&str, Option<&str>)], when: Timestamp) {
        let source = ObservationSource::Probe {
            node: NodeId(7),
            method: ProbeMethod::Arp,
        };
        let observations = pairs
            .iter()
            .map(|(ip, address_mac)| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Address {
                    vrf,
                    ip: ip.parse().expect("ip"),
                    mac: address_mac.map(mac),
                },
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        self.reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: false,
                received_at: when,
            })
            .await
            .expect("probe ingest");
    }

    /// Names that probe node 7 found for addresses (reverse DNS) at `when`: `(ip, name)`.
    pub async fn names(&self, names: &[(&str, &str)], when: Timestamp) {
        let source = ObservationSource::Probe {
            node: NodeId(7),
            method: ProbeMethod::ReverseDns,
        };
        let observations = names
            .iter()
            .map(|(ip, name)| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Name {
                    ip: ip.parse().expect("ip"),
                    name: (*name).to_owned(),
                    placeholder: false,
                },
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(3600)),
            })
            .collect();
        self.reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: false,
                received_at: when,
            })
            .await
            .expect("name ingest");
    }

    /// One complete topology read of this world's connector as a network controller at
    /// `when`, reporting the networks `(reference, name, VLAN id, subnet)`.
    pub async fn networks(
        &self,
        networks: &[(&str, &str, Option<u16>, Option<&str>)],
        when: Timestamp,
    ) -> IngestReport {
        let source = ObservationSource::NetworkController {
            connector: self.connector,
        };
        let observations = networks
            .iter()
            .map(|(reference, name, vlan, subnet)| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Network {
                    controller: (*reference).to_owned(),
                    name: (*name).to_owned(),
                    subnet: subnet.map(|text| text.parse().expect("subnet")),
                    vlan: *vlan,
                    dhcp: NetworkDhcp::Disabled,
                    management: false,
                },
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        self.reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: true,
                received_at: when,
            })
            .await
            .expect("network ingest")
    }

    /// Rejects a proposal as a person.
    pub async fn reject(&self, proposal: &IntentProposal) -> Decision {
        proposals::reject(
            &self.service,
            proposal.id,
            Some("not ours".to_owned()),
            &crate::common::person(),
            None,
        )
        .await
        .expect("reject")
    }

    pub async fn reconcile(&self, when: Timestamp) -> ReconcileReport {
        self.reconciler.reconcile(when).await.expect("reconcile")
    }

    /// Proposals in `state` (every state when `None`), oldest first.
    pub async fn proposals(&self, state: Option<IntentProposalState>) -> Vec<IntentProposal> {
        let view = self
            .store
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view");
        proposals::query::list(
            view.as_ref(),
            &ProposalQuery {
                states: state.into_iter().collect(),
                sort: vec!["created".to_owned()],
                limit: Some(1_000),
                ..ProposalQuery::default()
            },
        )
        .expect("list")
        .items
    }

    /// The open proposals of one kind.
    pub async fn open(&self, kind: IntentProposalKind) -> Vec<IntentProposal> {
        self.proposals(Some(IntentProposalState::Open))
            .await
            .into_iter()
            .filter(|proposal| proposal.kind == kind)
            .collect()
    }

    /// Approves a proposal as a person.
    pub async fn approve(&self, proposal: &IntentProposal) -> Decision {
        proposals::approve(
            &self.service,
            proposal.id,
            &crate::common::person(),
            &PlanOptions::default(),
            false,
            None,
        )
        .await
        .expect("approve")
    }

    /// The default VRF (created with the first prefix).
    pub async fn default_vrf(&self) -> VrfId {
        let view = self.service.view(None).await.expect("view");
        tenko_ipam::query::list::<tenko_core::ipam::Vrf>(
            view.as_ref(),
            &tenko_ipam::query::ListQuery::default(),
        )
        .expect("vrfs")
        .items
        .into_iter()
        .find(|vrf| vrf.name == "default")
        .expect("default VRF")
        .id
    }
}

/// An inventory host with one MAC address and addresses.
pub fn vm(id: &str, name: Option<&str>, host_mac: Option<&str>, ips: &[&str]) -> ObservedHost {
    ObservedHost {
        external_id: id.to_owned(),
        name: name.map(str::to_owned),
        name_placeholder: false,
        macs: host_mac.map(mac).into_iter().collect(),
        ips: ips.iter().map(|ip| ip.parse().expect("ip")).collect(),
        os: Some("Linux 6.x".to_owned()),
        platform: Some("qemu".to_owned()),
        parent: Some("pve1".to_owned()),
        tags: Vec::new(),
        power: None,
    }
}
