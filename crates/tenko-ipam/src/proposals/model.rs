//! The records of proposals and adoption policies, and their tables.

use std::{collections::BTreeMap, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    MacAddr, ObjectRef, ObservationId, PrefixId, ProposalId, Revision, Timestamp, VrfId,
    audit::Digest,
    ipam::{AssignmentMode, Stamp},
    observe::ObservationSource,
    table::TableDef,
};
use utoipa::ToSchema;

use crate::command::IpamCommand;

/// What a proposal is about.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IntentProposalKind {
    /// An observed MAC or address that no host or address of intent knows, inside a
    /// known network (IPAM-15).
    DiscoveredHost,
    /// Intent that no source has seen for longer than the orphan age.
    OrphanedIntent,
    /// A host seen on an address other than its intent.
    AddressMismatch,
    /// Observations that contradict each other or the intent: two devices on one
    /// address, one device in two networks, an address held by another device (IPAM-23).
    Conflict,
    /// An address seen outside every known network: a prefix is suggested.
    OutsidePrefixes,
}

impl IntentProposalKind {
    /// Every kind.
    pub const ALL: [IntentProposalKind; 5] = [
        IntentProposalKind::DiscoveredHost,
        IntentProposalKind::OrphanedIntent,
        IntentProposalKind::AddressMismatch,
        IntentProposalKind::Conflict,
        IntentProposalKind::OutsidePrefixes,
    ];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentProposalKind::DiscoveredHost => "discovered_host",
            IntentProposalKind::OrphanedIntent => "orphaned_intent",
            IntentProposalKind::AddressMismatch => "address_mismatch",
            IntentProposalKind::Conflict => "conflict",
            IntentProposalKind::OutsidePrefixes => "outside_prefixes",
        }
    }
}

/// How urgent a proposal is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProposalSeverity {
    /// Good to know: a new device, an unused address.
    Info,
    /// Needs attention: a device off its intent, an address outside every network.
    Warning,
    /// Breaks something: two devices on one address.
    Critical,
}

/// The decision state of a proposal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IntentProposalState {
    /// Waiting for a decision.
    Open,
    /// Approved by a person or adopted by a policy; its commands were applied.
    Accepted,
    /// Rejected by a person; the same evidence does not open it again.
    Rejected,
    /// The observation behind it no longer holds (the device is gone, the intent caught
    /// up, the object was locked or deleted).
    Expired,
    /// Replaced by a newer proposal about the same subject with other evidence or
    /// commands.
    Superseded,
}

impl IntentProposalState {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentProposalState::Open => "open",
            IntentProposalState::Accepted => "accepted",
            IntentProposalState::Rejected => "rejected",
            IntentProposalState::Expired => "expired",
            IntentProposalState::Superseded => "superseded",
        }
    }
}

/// What a proposal concerns: the observed identity and the intent objects involved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProposalSubject {
    /// The MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// The network (outside-prefix proposals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub cidr: Option<IpNet>,
    /// The VRF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfId>,
    /// The most specific prefix of the address, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<PrefixId>,
    /// The name a source gives the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The intent objects involved (hosts, interfaces, addresses).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectRef>,
}

/// One observation behind a proposal, as it was when the proposal was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProposalEvidence {
    /// The source.
    pub source: ObservationSource,
    /// The canonical text of the source.
    pub source_key: String,
    /// The canonical text of the fact's subject.
    pub subject_key: String,
    /// The observation that last changed the fact.
    pub observation: ObservationId,
    /// The MAC address the fact pairs with the address, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The IP address, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// The name the source gives, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// First sighting by this source.
    pub first_seen: Timestamp,
    /// Last sighting by this source.
    pub last_seen: Timestamp,
    /// Counted sightings by this source.
    #[serde(default)]
    pub sightings: u32,
}

/// A suggestion of the reconciler: evidence, the commands that would resolve it, and the
/// decision (IPAM-15). Stored in `ipam.proposals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntentProposal {
    /// Identifier.
    pub id: ProposalId,
    /// The kind.
    pub kind: IntentProposalKind,
    /// The rule that produced it, a stable code such as
    /// `ipam.reconcile.discovered_mac`; the UI translates it with [`Self::params`].
    pub rule: String,
    /// The subject key: kind and subject, unique among open proposals
    /// (`discovered_host/mac:00:00:5e:00:53:01`).
    pub key: String,
    /// The subject.
    pub subject: ProposalSubject,
    /// How urgent it is.
    pub severity: ProposalSeverity,
    /// The decision state.
    pub state: IntentProposalState,
    /// English one-line summary.
    pub summary: String,
    /// Named parameters of the summary, for translation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// The observations behind it.
    pub evidence: Vec<ProposalEvidence>,
    /// The commands an approval applies (empty for conflicts, which a person resolves).
    #[serde(default)]
    pub commands: Vec<IpamCommand>,
    /// SHA-256 over the canonical CBOR of the kind, the subject key, the evidence
    /// identities (sources, subjects, paired addresses) and the commands: equal evidence,
    /// equal fingerprint. A rejection is remembered by it.
    pub fingerprint: Digest,
    /// When it was opened.
    pub created: Timestamp,
    /// When it last changed.
    pub updated: Timestamp,
    /// Who decided and when: the approving person, `system:reconciler` for an adoption,
    /// an expiry or a supersession.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided: Option<Stamp>,
    /// The rejection reason, or why it expired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The prefix whose adoption policy adopted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted_by: Option<PrefixId>,
    /// The objects its commands created or changed, once accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ObjectRef>,
    /// The proposal that replaced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<ProposalId>,
    /// The error code of the last failed adoption; the policy does not try again until
    /// the proposal is replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adoption_error: Option<String>,
    /// Store revision (filled when read; `ETag` and `If-Match` of the decisions).
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

impl IntentProposal {
    /// Whether it waits for a decision.
    pub fn is_open(&self) -> bool {
        self.state == IntentProposalState::Open
    }

    /// The latest sighting among the evidence.
    pub fn last_seen(&self) -> Option<Timestamp> {
        self.evidence
            .iter()
            .map(|evidence| evidence.last_seen)
            .max()
    }

    /// The most sightings of one source among the evidence.
    pub fn sightings(&self) -> u32 {
        self.evidence
            .iter()
            .map(|evidence| evidence.sightings)
            .max()
            .unwrap_or_default()
    }
}

/// A remembered rejection: the same subject with the same evidence stays closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Rejection {
    /// The fingerprint of the rejected proposal.
    pub fingerprint: Digest,
    /// The rejected proposal.
    pub proposal: ProposalId,
    /// Who rejected it and when.
    pub stamp: Stamp,
    /// The reason given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What a prefix's policy adopts without a person (IPAM-15 "auto-adopt in network Z").
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionMode {
    /// Nothing: every proposal waits for a person.
    #[default]
    Manual,
    /// Discovered hosts with a MAC address.
    AdoptHosts,
    /// Discovered hosts with or without a MAC address, and the address changes of
    /// `dynamic` hosts (where IPAM only observes).
    AdoptAll,
}

/// The adoption policy of a prefix, inherited by the prefixes inside it that have none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AdoptionPolicy {
    /// What is adopted.
    pub mode: AdoptionMode,
    /// Only addresses inside a DHCP pool of the prefix.
    #[serde(default)]
    pub only_dhcp_pools: bool,
    /// Only devices whose vendor matches one entry: an OUI prefix of the MAC address
    /// (`00:00:5e`, `00-00-5E`) or text the source reports as the vendor (compared
    /// without case). Empty: any vendor. At most 32 entries of 1 to 64 characters.
    #[serde(default)]
    pub vendors: Vec<String>,
    /// Only after this many counted sightings by one source (1 to 1,000; 1 by default).
    #[serde(default = "one")]
    pub min_sightings: u32,
    /// The assignment mode of adopted hosts; `dynamic` by default (IPAM only observes).
    #[serde(default = "dynamic")]
    pub host_mode: AssignmentMode,
}

fn one() -> u32 {
    1
}

fn dynamic() -> AssignmentMode {
    AssignmentMode::Dynamic
}

impl Default for AdoptionPolicy {
    fn default() -> Self {
        Self {
            mode: AdoptionMode::Manual,
            only_dhcp_pools: false,
            vendors: Vec::new(),
            min_sightings: 1,
            host_mode: AssignmentMode::Dynamic,
        }
    }
}

/// The stored policy of one prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoredPolicy {
    /// The prefix.
    pub prefix: PrefixId,
    /// The policy.
    pub policy: AdoptionPolicy,
    /// Who set it and when.
    pub updated: Stamp,
    /// Store revision (filled when read).
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// Proposals by id.
pub static PROPOSALS: TableDef<ProposalId, IntentProposal> = TableDef::new("ipam.proposals");
/// The open proposal of each subject key.
pub static OPEN_KEYS: TableDef<String, ProposalId> = TableDef::new("ipam.proposal_keys");
/// Remembered rejections by subject key.
pub static REJECTIONS: TableDef<String, Rejection> = TableDef::new("ipam.proposal_rejections");
/// Adoption policies by prefix.
pub static ADOPTION: TableDef<PrefixId, StoredPolicy> = TableDef::new("ipam.adoption");

/// Stable codes of the proposal and reconciler area.
pub mod codes {
    /// The proposal does not exist (404). Params: `id`.
    pub const NOT_FOUND: &str = "ipam.proposal.not_found";
    /// The proposal is not open (409). Params: `id`, `state`.
    pub const NOT_OPEN: &str = "ipam.proposal.not_open";
    /// The proposal has no commands to apply; reject it once resolved (409).
    pub const NOTHING_TO_APPLY: &str = "ipam.proposal.nothing_to_apply";
    /// `If-Match` does not match the proposal (412). Params: `expected`, `actual`.
    pub const REVISION_MISMATCH: &str = "ipam.proposal.revision_mismatch";
    /// The adoption policy is invalid (400). Params: `field`.
    pub const POLICY_INVALID: &str = "ipam.adoption.invalid";
    /// The reconciler does not run on this server (503).
    pub const RECONCILER_UNAVAILABLE: &str = "ipam.reconciler.unavailable";
}

/// Audit actions of the area.
pub mod actions {
    /// A proposal was opened.
    pub const OPEN: &str = "ipam.proposal.open";
    /// A proposal was replaced by a newer one.
    pub const SUPERSEDE: &str = "ipam.proposal.supersede";
    /// A proposal expired.
    pub const EXPIRE: &str = "ipam.proposal.expire";
    /// A person approved a proposal.
    pub const APPROVE: &str = "ipam.proposal.approve";
    /// A person rejected a proposal.
    pub const REJECT: &str = "ipam.proposal.reject";
    /// A policy adopted a proposal.
    pub const ADOPT: &str = "ipam.proposal.adopt";
    /// An adoption failed.
    pub const ADOPT_FAILED: &str = "ipam.proposal.adopt_failed";
    /// An adoption policy was set.
    pub const POLICY_SET: &str = "ipam.adoption.set";
    /// An adoption policy was removed (the prefix inherits again).
    pub const POLICY_CLEAR: &str = "ipam.adoption.clear";
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        ConnectorId, Principal, SystemComponent,
        codec::{from_cbor, to_cbor},
    };

    use super::*;
    use crate::command::{HostInput, InterfaceInput};

    #[test]
    fn proposals_round_trip_in_cbor_and_json() {
        let at: Timestamp = "2026-10-10T08:00:00Z".parse().expect("time");
        let proposal = IntentProposal {
            id: ProposalId::generate(),
            kind: IntentProposalKind::DiscoveredHost,
            rule: "ipam.reconcile.discovered_mac".to_owned(),
            key: "discovered_host/mac:00:00:5e:00:53:01".to_owned(),
            subject: ProposalSubject {
                mac: Some("00:00:5e:00:53:01".parse().expect("mac")),
                ip: Some("192.0.2.10".parse().expect("ip")),
                ..ProposalSubject::default()
            },
            severity: ProposalSeverity::Info,
            state: IntentProposalState::Open,
            summary: "new device".to_owned(),
            params: BTreeMap::from([("ip".to_owned(), "192.0.2.10".to_owned())]),
            evidence: vec![ProposalEvidence {
                source: ObservationSource::Inventory {
                    connector: ConnectorId::generate(),
                },
                source_key: "inventory:x".to_owned(),
                subject_key: "host:101".to_owned(),
                observation: ObservationId::generate(),
                mac: None,
                ip: Some("2001:db8::10".parse().expect("ip")),
                name: Some("web01".to_owned()),
                first_seen: at,
                last_seen: at,
                sightings: 2,
            }],
            commands: vec![IpamCommand::CreateHost(HostInput {
                id: None,
                tenant: None,
                name: "web01".parse().expect("name"),
                mode: Some(AssignmentMode::Dynamic),
                lock: None,
                site: None,
                interfaces: vec![InterfaceInput {
                    id: None,
                    host: None,
                    name: "eth0".to_owned(),
                    mac: Some("00:00:5e:00:53:01".parse().expect("mac")),
                    duid: None,
                    client_id: None,
                    tags: std::collections::BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }],
                tags: std::collections::BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            })],
            fingerprint: Digest([7; 32]),
            created: at,
            updated: at,
            decided: Some(Stamp::new(
                at,
                Principal::system(SystemComponent::Reconciler),
            )),
            reason: None,
            adopted_by: None,
            results: Vec::new(),
            superseded_by: None,
            adoption_error: None,
            revision: Revision::ZERO,
        };
        let back: IntentProposal = from_cbor(&to_cbor(&proposal).expect("cbor")).expect("cbor");
        assert_eq!(back, proposal);
        let json = serde_json::to_value(&proposal).expect("json");
        assert_eq!(json["kind"], "discovered_host");
        assert_eq!(json["state"], "open");
        assert_eq!(json["commands"][0]["op"], "create_host");
        assert_eq!(
            serde_json::from_value::<IntentProposal>(json).expect("json"),
            proposal
        );
        assert_eq!(proposal.sightings(), 2);
    }

    #[test]
    fn policies_default_and_round_trip() {
        let policy: AdoptionPolicy =
            serde_json::from_str(r#"{"mode": "adopt_hosts"}"#).expect("json");
        assert_eq!(policy.min_sightings, 1);
        assert_eq!(policy.host_mode, AssignmentMode::Dynamic);
        assert!(serde_json::from_str::<AdoptionPolicy>(r#"{"mode": "manual", "x": 1}"#).is_err());
        let back: AdoptionPolicy = from_cbor(&to_cbor(&policy).expect("cbor")).expect("cbor");
        assert_eq!(back, policy);
    }
}
