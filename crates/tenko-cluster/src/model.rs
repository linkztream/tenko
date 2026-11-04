//! The records of the node registry (store tables in the `cluster` namespace) and the
//! views and requests of its API.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `cluster.nodes` | node id | [`NodeRecord`] |
//! | `cluster.node_names` | lower-case name | node id |
//! | `cluster.node_seq` | `()` | the last node id handed out |
//! | `cluster.enrolments` (spelling: stored key) | token id | [`EnrollmentRecord`] |
//! | `cluster.revocations` | certificate serial (hex) | [`Revocation`] |
//! | `cluster.controller_certs` | node id | [`ControllerCertRecord`] |
//! | `cluster.members` | node id | [`MemberRecord`]: a controller of the Raft group and its cluster port |
//! | `cluster.kek_transfers` | enrollment token id | [`KekTransferRecord`]: the one key transfer a join token allows |
//! | `cluster.connections` | node id | [`ConnectionRecord`]: the controller a node is connected to |
//!
//! Heartbeats are kept in memory; `last_seen` is written at connect, at disconnect and at
//! most every [`LAST_SEEN_INTERVAL_SECS`] seconds in between, so a quiet cluster does not
//! write on every beat.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, Role, RoleSet, Timestamp, UserId, VrfId, secret::SecretRef, table::TableDef,
};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{token::TokenDigest, version::VersionMismatch};

/// Seconds between two writes of a connected node's `last_seen`.
pub const LAST_SEEN_INTERVAL_SECS: u64 = 300;

/// The store tables of the node registry.
pub mod tables {
    use super::{
        ConnectionRecord, ControllerCertRecord, EnrollmentRecord, KekTransferRecord, MemberRecord,
        NodeRecord, Revocation, TableDef, Uuid,
    };

    /// Enrolled nodes by id.
    pub const NODES: TableDef<u64, NodeRecord> = TableDef::new("cluster.nodes");
    /// Node names (lower case) to node ids; names are unique.
    pub const NODE_NAMES: TableDef<String, u64> = TableDef::new("cluster.node_names");
    /// The last node id handed out (ids are never reused).
    pub const NODE_SEQ: TableDef<(), u64> = TableDef::new("cluster.node_seq");
    /// Enrollment tokens by id (only a digest of the secret).
    pub const ENROLLMENTS: TableDef<Uuid, EnrollmentRecord> = TableDef::new("cluster.enrolments"); // spelling: stored key
    /// Revoked certificates by serial (lower-case hex), until they expire.
    pub const REVOCATIONS: TableDef<String, Revocation> = TableDef::new("cluster.revocations");
    /// The cluster-port certificate of each controller.
    pub const CONTROLLER_CERTS: TableDef<u64, ControllerCertRecord> =
        TableDef::new("cluster.controller_certs");
    /// The controllers of the Raft group by node id, with the cluster port their peers
    /// dial. Peers resolve endpoints here, not from the Raft membership.
    pub const MEMBERS: TableDef<u64, MemberRecord> = TableDef::new("cluster.members");
    /// Key transfers to joining controllers by the id of the enrollment token they used.
    pub const KEK_TRANSFERS: TableDef<Uuid, KekTransferRecord> =
        TableDef::new("cluster.kek_transfers");
    /// The controller each connected node is connected to, written when the node connects
    /// and disconnects, so every controller shows the same connected view.
    pub const CONNECTIONS: TableDef<u64, ConnectionRecord> = TableDef::new("cluster.connections");
}

/// The first id handed to an enrolled node. Controllers take theirs from `[node] id`
/// (1 and up); enrolled nodes start here so the two never meet.
pub const FIRST_ENROLLED_NODE_ID: u64 = 1001;

/// A certificate issued to a node, as the registry remembers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertificateRef {
    /// Serial number, lower-case hex.
    pub serial: String,
    /// SHA-256 of the certificate, lower-case hex.
    pub sha256: String,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
}

/// The protocol state of a node: what it offered and what was agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProtocolState {
    /// The majors the node offered in its last handshake.
    #[serde(default)]
    pub offered: Vec<u32>,
    /// The major agreed in the last successful handshake.
    #[serde(default)]
    pub agreed: Option<u32>,
    /// The last refused handshake, until a later one succeeds.
    #[serde(default)]
    pub mismatch: Option<MismatchRecord>,
}

/// A refused handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MismatchRecord {
    /// The majors on both sides.
    #[serde(flatten)]
    pub majors: VersionMismatch,
    /// When it happened.
    pub at: Timestamp,
    /// The software version the node reported.
    pub version: String,
}

/// An enrolled node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// The node id, also in its certificate (`urn:tenko:node:<id>`).
    pub id: NodeId,
    /// A unique name.
    pub name: String,
    /// Its roles, also in its certificate.
    pub roles: Vec<Role>,
    /// The address the node gave at enrollment, else the address it enrolled from.
    pub address: Option<String>,
    /// The VRF of its observations when a batch names none.
    pub vrf: Option<VrfId>,
    /// The newest certificate.
    pub certificate: CertificateRef,
    /// Serials of every certificate issued to the node that has not expired, newest last;
    /// all of them are revoked with the node.
    pub serials: Vec<CertificateRef>,
    /// When the node enrolled.
    pub enrolled_at: Timestamp,
    /// The token it enrolled with.
    #[serde(alias = "enrolment")] // spelling: alias permanently (stored node records carry it)
    pub enrollment: Uuid,
    /// The user who created that token.
    pub enrolled_by: Option<UserId>,
    /// When the certificate was last renewed.
    pub renewed_at: Option<Timestamp>,
    /// When the controller last heard from the node (written at most every five minutes).
    pub last_seen: Option<Timestamp>,
    /// The software version the node reported last.
    pub version: Option<String>,
    /// Protocol negotiation.
    #[serde(default)]
    pub protocol: ProtocolState,
}

impl NodeRecord {
    /// The roles as a set.
    pub fn role_set(&self) -> RoleSet {
        self.roles.iter().copied().collect()
    }

    /// Whether a certificate serial belongs to the node and has not expired at `now`.
    pub fn holds(&self, serial: &str, now: Timestamp) -> bool {
        self.serials
            .iter()
            .any(|cert| cert.serial == serial && cert.not_after > now)
    }
}

/// An enrollment token as the controller stores it: never the secret, only its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// The token id (the middle part of the token text).
    pub id: Uuid,
    /// SHA-256 over the id and the secret.
    pub digest: TokenDigest,
    /// The name the node gets; the node chooses one when absent.
    pub name: Option<String>,
    /// The roles the node may take.
    pub roles: Vec<Role>,
    /// The VRF of the node's observations.
    pub vrf: Option<VrfId>,
    /// Who created it.
    pub created_by: Option<UserId>,
    /// When.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
    /// Set once a node enrolled with it.
    pub used: Option<TokenUse>,
}

/// The enrollment a token was used for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TokenUse {
    /// The node that enrolled.
    pub node: NodeId,
    /// When.
    pub at: Timestamp,
}

/// The state of an enrollment token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    /// Waiting for a node.
    Pending,
    /// A node enrolled with it.
    Used,
    /// It expired unused.
    Expired,
}

impl EnrollmentRecord {
    /// The state at `now`.
    pub fn state(&self, now: Timestamp) -> EnrollmentState {
        if self.used.is_some() {
            EnrollmentState::Used
        } else if now >= self.expires_at {
            EnrollmentState::Expired
        } else {
            EnrollmentState::Pending
        }
    }
}

/// A revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Revocation {
    /// The node it was issued to.
    pub node: NodeId,
    /// When it was revoked.
    pub revoked_at: Timestamp,
    /// When it expires; the entry is removed after that.
    pub not_after: Timestamp,
}

/// The certificate a controller presents on the cluster port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerCertRecord {
    /// The chain, PEM, leaf first.
    pub chain_pem: String,
    /// The key (a system secret of the vault, PKCS#8).
    pub key: SecretRef,
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// A controller of the Raft group. Written when it joins (by the leader) and when the
/// first controller registers itself at the first join; removed with the member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The node id, also its Raft id.
    pub node: NodeId,
    /// Its cluster port as `host:port`.
    pub address: String,
    /// The software version it reported.
    pub version: String,
    /// The data format its binary knows.
    pub data_format: u32,
    /// When it joined.
    pub joined_at: Timestamp,
    /// The protocol majors its binary speaks with nodes (OPS-08); empty in records written
    /// before members reported them.
    #[serde(default)]
    pub protocol_majors: Vec<u32>,
    /// The wire version of its Raft messages (`openraft-0.9/cbor-1`); absent in records
    /// written before members reported it.
    #[serde(default)]
    pub raft_wire: Option<String>,
    /// The data formats its binary can open, oldest first (it migrates every older one to
    /// the newest); empty in records written before members reported them.
    #[serde(default)]
    pub formats: Vec<u32>,
}

impl MemberRecord {
    /// The data formats the member's binary knows: the reported list, else every format up
    /// to [`MemberRecord::data_format`].
    pub fn known_formats(&self) -> Vec<u32> {
        if self.formats.is_empty() {
            (1..=self.data_format).collect()
        } else {
            self.formats.clone()
        }
    }
}

/// The controller a node is connected to (written at connect, removed at disconnect by the
/// same controller).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// The controller that holds the connection.
    pub controller: NodeId,
    /// When the heartbeat stream opened.
    pub since: Timestamp,
    /// The node's address as that controller sees it.
    pub peer: Option<SocketAddr>,
    /// The software version the node reported.
    pub version: String,
    /// The agreed protocol major.
    pub major: u32,
}

/// The key transfer a joining controller received with its enrollment token (single use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KekTransferRecord {
    /// The joining controller.
    pub node: NodeId,
    /// When.
    pub at: Timestamp,
    /// The ids of the transferred generations (never the material).
    pub generations: Vec<String>,
}

// ---------------------------------------------------------------------------------------
// API views and requests.

/// A node as `GET /nodes` shows it: the stored record and the live connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeView {
    /// The node id.
    #[schema(value_type = u64)]
    pub id: NodeId,
    /// Its name.
    pub name: String,
    /// Its roles: `probe`, `dns`, `dhcp`.
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
    /// The address the node gave at enrollment, else the address it enrolled from.
    pub address: Option<String>,
    /// The VRF of its observations when a batch names none.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub vrf: Option<VrfId>,
    /// The newest certificate.
    pub certificate: CertificateRef,
    /// When the node enrolled.
    pub enrolled_at: Timestamp,
    /// The user who created the enrollment token.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub enrolled_by: Option<UserId>,
    /// When the certificate was last renewed.
    pub renewed_at: Option<Timestamp>,
    /// When the controller last heard from the node.
    pub last_seen: Option<Timestamp>,
    /// The software version the node reported last.
    pub version: Option<String>,
    /// Protocol negotiation, with the last refused handshake.
    pub protocol: ProtocolState,
    /// Whether the node is connected to a controller of the cluster now (this one or
    /// another; `connection.controller` names it).
    pub connected: bool,
    /// The live connection, while there is one.
    pub connection: Option<ConnectionView>,
    /// Store revision of the record (the `ETag`).
    #[schema(value_type = u64)]
    pub revision: tenko_core::Revision,
}

impl NodeView {
    /// The view of a record with its live connection.
    pub fn new(
        record: NodeRecord,
        revision: tenko_core::Revision,
        connection: Option<ConnectionView>,
    ) -> Self {
        let last_seen = match (&connection, record.last_seen) {
            (Some(live), Some(stored)) => Some(live.last_beat.unwrap_or(live.since).max(stored)),
            (Some(live), None) => Some(live.last_beat.unwrap_or(live.since)),
            (None, stored) => stored,
        };
        let version = connection
            .as_ref()
            .map(|live| live.version.clone())
            .filter(|version| !version.is_empty())
            .or(record.version);
        Self {
            id: record.id,
            name: record.name,
            roles: record.roles,
            address: record.address,
            vrf: record.vrf,
            certificate: record.certificate,
            enrolled_at: record.enrolled_at,
            enrolled_by: record.enrolled_by,
            renewed_at: record.renewed_at,
            last_seen,
            version,
            protocol: record.protocol,
            connected: connection.is_some(),
            connection,
            revision,
        }
    }
}

/// A live connection of a node to this controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ConnectionView {
    /// When the heartbeat stream opened.
    pub since: Timestamp,
    /// The node's address as this controller sees it.
    #[schema(value_type = Option<String>)]
    pub peer: Option<SocketAddr>,
    /// The agreed protocol major.
    pub major: u32,
    /// The software version the node reports.
    pub version: String,
    /// The last heartbeat.
    pub last_beat: Option<Timestamp>,
    /// Observation batches waiting in the node's buffer.
    pub buffered_batches: u64,
    /// Their size in bytes.
    pub buffered_bytes: u64,
    /// Batches the node dropped since it started because its buffer was full.
    pub dropped_batches: u64,
    /// When the node's certificate expires, as the node reports it.
    pub certificate_not_after: Option<Timestamp>,
    /// The controller the node is connected to; heartbeat figures are known only to that
    /// controller.
    #[serde(default)]
    #[schema(value_type = Option<u64>)]
    pub controller: Option<NodeId>,
}

/// An enrollment token as `GET /nodes/enrollments` shows it (never the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnrollmentView {
    /// The token id.
    #[schema(value_type = String, format = Uuid)]
    pub id: Uuid,
    /// The name the node gets; the node chooses one when absent.
    pub name: Option<String>,
    /// The roles the node may take.
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
    /// The VRF of the node's observations.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub vrf: Option<VrfId>,
    /// Who created it.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub created_by: Option<UserId>,
    /// When.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
    /// `pending`, `used` or `expired`.
    pub state: EnrollmentState,
    /// The enrollment it was used for.
    pub used: Option<TokenUse>,
    /// Store revision of the record.
    #[schema(value_type = u64)]
    pub revision: tenko_core::Revision,
}

impl EnrollmentView {
    /// The view of a record at `now`.
    pub fn new(record: EnrollmentRecord, revision: tenko_core::Revision, now: Timestamp) -> Self {
        let state = record.state(now);
        Self {
            id: record.id,
            name: record.name,
            roles: record.roles,
            vrf: record.vrf,
            created_by: record.created_by,
            created_at: record.created_at,
            expires_at: record.expires_at,
            state,
            used: record.used,
            revision,
        }
    }
}

/// Body of `POST /nodes/enrollments`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewEnrollment {
    /// The roles the node may take (`probe`, `dns`, `dhcp`); default `probe`.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
    /// The name the node gets; without it the node chooses one (its host name).
    #[serde(default)]
    pub name: Option<String>,
    /// The VRF of the node's observations; default the default VRF.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub vrf: Option<VrfId>,
    /// Seconds until the token expires: 60 to 604,800 (seven days); default 3,600.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// Answer of `POST /nodes/enrollments`: the token, shown once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreatedEnrollment {
    /// The stored token.
    pub enrollment: EnrollmentView,
    /// The token text. It is shown only in this answer and cannot be read again.
    pub token: String,
    /// The SHA-256 fingerprint of the internal CA root, for `--ca-fingerprint`.
    pub ca_fingerprint: String,
    /// The command to run on the node, with the token and the fingerprint filled in.
    pub command: String,
}

/// Body of `POST /nodes/enroll`: a node presents its token and its certificate request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// The enrollment token.
    pub token: String,
    /// A PKCS#10 certificate signing request over an ECDSA P-256 key, PEM.
    pub csr: String,
    /// The node's name; the token's name wins when it has one.
    #[serde(default)]
    pub name: Option<String>,
    /// The roles the node runs; default the token's roles. Each must be allowed by the
    /// token.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
    /// The node's address as the controller should show it; default the address the
    /// request came from.
    #[serde(default)]
    pub address: Option<String>,
    /// The node's software version.
    #[serde(default)]
    pub version: String,
    /// The protocol majors the node implements.
    #[serde(default)]
    pub majors: Vec<u32>,
}

/// Answer of `POST /nodes/enroll`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnrollResponse {
    /// The node as registered.
    pub node: NodeView,
    /// The node certificate, PEM, leaf first.
    pub certificate: String,
    /// The root of the internal CA, PEM: the node trusts only it on the cluster port.
    pub ca_root: String,
    /// `host:port` endpoints of the cluster port; empty: the host the node enrolled through
    /// with `cluster_port`.
    pub endpoints: Vec<String>,
    /// The cluster port of the controller the node enrolled with.
    pub cluster_port: Option<u16>,
    /// Seconds between two heartbeats.
    pub heartbeat_secs: u32,
    /// The protocol majors the controller implements.
    pub majors: Vec<u32>,
}

/// Cluster health for `GET /system/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClusterHealth {
    /// The addresses the cluster port listens on; empty while it is off.
    pub listening: Vec<String>,
    /// The protocol majors this controller implements.
    pub majors: Vec<u32>,
    /// Enrolled nodes.
    pub nodes: u64,
    /// Nodes connected to this controller now.
    pub connected: u64,
    /// Software versions of the connected nodes and how many run each.
    pub versions: BTreeMap<String, u64>,
    /// Nodes whose last handshake was refused for want of a common protocol major.
    pub mismatched: Vec<NodeMismatch>,
}

/// A node whose last handshake was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeMismatch {
    /// The node.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// Its name.
    pub name: String,
    /// What was refused.
    pub mismatch: MismatchRecord,
}

/// Parses a node address given at enrollment: an IP address or a host name, at most 253
/// characters, without spaces or control characters.
pub fn valid_address(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && text.len() <= 253
        && (text.parse::<IpAddr>().is_ok()
            || text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    #[test]
    fn enrollment_state_follows_use_and_time() {
        let mut record = EnrollmentRecord {
            id: Uuid::nil(),
            digest: crate::token::EnrollmentToken::from_parts(Uuid::nil(), [7; 32]).digest(),
            name: None,
            roles: vec![Role::Probe],
            vrf: None,
            created_by: None,
            created_at: at("2026-10-10T08:00:00Z"),
            expires_at: at("2026-10-10T09:00:00Z"),
            used: None,
        };
        assert_eq!(
            record.state(at("2026-10-10T08:30:00Z")),
            EnrollmentState::Pending
        );
        assert_eq!(
            record.state(at("2026-10-10T09:00:00Z")),
            EnrollmentState::Expired
        );
        record.used = Some(TokenUse {
            node: NodeId(1001),
            at: at("2026-10-10T08:31:00Z"),
        });
        assert_eq!(
            record.state(at("2026-10-10T10:00:00Z")),
            EnrollmentState::Used
        );
    }

    #[test]
    fn a_node_record_stored_by_0_0_11_still_reads() {
        let certificate = CertificateRef {
            serial: "0a".to_owned(),
            sha256: "00".repeat(32),
            not_before: at("2026-10-10T08:00:00Z"),
            not_after: at("2026-11-10T08:00:00Z"),
        };
        let record = NodeRecord {
            id: NodeId(1001),
            name: "probe-dmz".to_owned(),
            roles: vec![Role::Probe],
            address: Some("192.0.2.20".to_owned()),
            vrf: None,
            certificate: certificate.clone(),
            serials: vec![certificate],
            enrolled_at: at("2026-10-10T08:00:00Z"),
            enrollment: Uuid::from_u128(7),
            enrolled_by: None,
            renewed_at: None,
            last_seen: None,
            version: Some("0.0.11".to_owned()),
            protocol: ProtocolState::default(),
        };
        let new = tables::NODES.encode(&record).expect("cbor").to_vec();
        // The bytes 0.0.11 wrote: the same map with the CBOR text key of the old name.
        let new_key = cbor_text("enrollment");
        let old_key = cbor_text("enrolment"); // spelling: alias permanently
        let at_key = new
            .windows(new_key.len())
            .position(|window| window == new_key)
            .expect("the key");
        let mut old = new[..at_key].to_vec();
        old.extend_from_slice(&old_key);
        old.extend_from_slice(&new[at_key + new_key.len()..]);
        assert_eq!(
            tables::NODES.decode(&old).expect("an old record decodes"),
            record
        );
    }

    /// A short CBOR text string: the header byte (major type 3, length below 24) and the bytes.
    fn cbor_text(text: &str) -> Vec<u8> {
        let length = u8::try_from(text.len()).expect("short");
        assert!(length < 24);
        let mut out = vec![0x60 | length];
        out.extend_from_slice(text.as_bytes());
        out
    }

    #[test]
    fn addresses_are_names_or_ip_addresses() {
        assert!(valid_address("192.0.2.20"));
        assert!(valid_address("2001:db8::20"));
        assert!(valid_address("probe-dmz.example.net"));
        assert!(!valid_address(""));
        assert!(!valid_address("probe dmz"));
        assert!(!valid_address(&"a".repeat(254)));
    }
}
