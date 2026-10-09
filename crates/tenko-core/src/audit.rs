//! Audit records and the hash chain (plan section 2.5, IAM-18, NEVER-02).
//!
//! A write batch carries [`AuditDraft`]s. The store turns them into [`AuditRecord`]s at
//! apply time, in the same atomic step as the change: it assigns the gap-free
//! [`AuditSeq`], links each record to its predecessor and seals it with SHA-256 over the
//! canonical CBOR of every other field. The chain is therefore identical on every replica
//! and verifiable offline ([`ChainVerifier`], `tenko audit verify`).
//!
//! Denied and failed actions (failed logins, refused guardrails) are audited too: a batch
//! with drafts and no mutations.
//!
//! Hash input rules: the hashed fields are those of [`AuditRecord`] except `hash`. A field
//! added later must be optional with `#[serde(default, skip_serializing_if = "…")]`, so
//! that records written before it existed still verify. Replicas that do not know a new
//! field would compute a different hash, so such a change also needs a protocol version
//! gate (OPS-08) and goes through the lead builder.

use std::{borrow::Cow, collections::BTreeMap, fmt, net::IpAddr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::{PartialSchema, ToSchema, openapi::RefOr, openapi::schema::Schema};

use crate::{
    codec::cbor::{CodecError, canonical_sha256},
    error::Coded,
    id::{AuditSeq, RequestId, Revision},
    object::ObjectRef,
    principal::Principal,
    serde_util::{deserialize_bytes_or_hex, serialize_bytes_or_hex, string_schema, to_hex},
    timestamp::Timestamp,
};

crate::namespaced_name! {
    /// What was done, namespaced by owning area: `auth.login.password`,
    /// `ipam.prefix.create`, `jobs.cancel`, `sys.setup.complete`.
    AuditAction, "audit action"
}

/// A SHA-256 digest: 32 bytes in CBOR, lowercase hexadecimal in JSON.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The all-zero digest: `prev` of the first record.
    pub const ZERO: Digest = Digest([0; 32]);
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", to_hex(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes_or_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes_or_hex(deserializer, "SHA-256 digest")?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("a SHA-256 digest has 32 bytes"))?;
        Ok(Self(array))
    }
}

impl PartialSchema for Digest {
    fn schema() -> RefOr<Schema> {
        string_schema("SHA-256 digest as 64 lowercase hexadecimal characters")
    }
}

impl ToSchema for Digest {}

/// The outcome of an audited action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The action took effect.
    Success,
    /// Authorization refused the action.
    Denied,
    /// The action failed with an error code.
    Failed {
        /// The stable error code.
        #[schema(value_type = String)]
        code: Cow<'static, str>,
    },
}

impl AuditOutcome {
    /// A failure with the code of a coded error.
    pub fn failed(error: &(impl Coded + ?Sized)) -> Self {
        AuditOutcome::Failed {
            code: Cow::Borrowed(error.code()),
        }
    }
}

/// One changed field: a diff line or a toggle change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FieldChange {
    /// The object, when the draft names several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectRef>,
    /// The field or toggle, for example `status` or `TGL-02`.
    pub field: String,
    /// The value before, rendered as text; `None` when the field was absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// The value after, rendered as text; `None` when the field was removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// Details of an audited action: field changes and free-form context. Never contains
/// secrets (a changed secret is recorded as a change without values).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditDetails {
    /// Changed fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<FieldChange>,
    /// Context such as the attempted user name of a failed login.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

/// An audit entry as the proposer writes it into a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditDraft {
    /// What was done.
    pub action: AuditAction,
    /// The objects concerned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectRef>,
    /// The outcome.
    pub outcome: AuditOutcome,
    /// The client address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub source_ip: Option<IpAddr>,
    /// Diff and context.
    #[serde(default)]
    pub details: AuditDetails,
}

impl AuditDraft {
    /// A successful action on the given objects.
    pub fn success(action: AuditAction, objects: Vec<ObjectRef>) -> Self {
        Self {
            action,
            objects,
            outcome: AuditOutcome::Success,
            source_ip: None,
            details: AuditDetails::default(),
        }
    }

    /// A denied action.
    pub fn denied(action: AuditAction, objects: Vec<ObjectRef>) -> Self {
        Self {
            outcome: AuditOutcome::Denied,
            ..Self::success(action, objects)
        }
    }

    /// A failed action.
    pub fn failed(action: AuditAction, objects: Vec<ObjectRef>, error: &dyn Coded) -> Self {
        Self {
            outcome: AuditOutcome::failed(error),
            ..Self::success(action, objects)
        }
    }

    /// Sets the client address.
    #[must_use]
    pub fn with_source_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.source_ip = ip;
        self
    }

    /// Adds a field change.
    #[must_use]
    pub fn with_change(mut self, change: FieldChange) -> Self {
        self.details.changes.push(change);
        self
    }

    /// Adds a context entry.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.context.insert(key.into(), value.into());
        self
    }
}

/// A sealed audit record, stored in `sys.audit` under its sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditRecord {
    /// Position in the chain, gap-free from 1.
    pub seq: AuditSeq,
    /// The store revision that committed the record with its change.
    pub revision: Revision,
    /// The proposer's time of the batch.
    pub at: Timestamp,
    /// Who acted.
    pub principal: Principal,
    /// The request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestId>,
    /// The audited action.
    pub draft: AuditDraft,
    /// Hash of the previous record ([`Digest::ZERO`] for the first).
    pub prev: Digest,
    /// SHA-256 over the canonical CBOR of every field above.
    pub hash: Digest,
}

/// The hashed part of a record: every field except `hash`, with the same names.
#[derive(Serialize)]
struct Unsealed<'a> {
    seq: AuditSeq,
    revision: Revision,
    at: Timestamp,
    principal: &'a Principal,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<RequestId>,
    draft: &'a AuditDraft,
    prev: Digest,
}

impl AuditRecord {
    /// Builds and seals a record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the record cannot be encoded.
    pub fn seal(
        seq: AuditSeq,
        revision: Revision,
        at: Timestamp,
        principal: Principal,
        request: Option<RequestId>,
        draft: AuditDraft,
        prev: Digest,
    ) -> Result<Self, CodecError> {
        let mut record = Self {
            seq,
            revision,
            at,
            principal,
            request,
            draft,
            prev,
            hash: Digest::ZERO,
        };
        record.hash = record.compute_hash()?;
        Ok(record)
    }

    /// Recomputes the hash from the other fields.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the record cannot be encoded.
    pub fn compute_hash(&self) -> Result<Digest, CodecError> {
        canonical_sha256(&Unsealed {
            seq: self.seq,
            revision: self.revision,
            at: self.at,
            principal: &self.principal,
            request: self.request,
            draft: &self.draft,
            prev: self.prev,
        })
        .map(Digest)
    }
}

/// The verified end of a chain: the last sequence number and its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct ChainHead {
    /// Last verified sequence number ([`AuditSeq::NONE`] before the first record).
    pub seq: AuditSeq,
    /// Its hash ([`Digest::ZERO`] before the first record).
    pub hash: Digest,
}

/// The chain does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// A sequence number is missing or out of order.
    #[error("audit chain gap: expected record {expected}, found {found}")]
    Gap {
        /// The expected sequence number.
        expected: AuditSeq,
        /// The sequence number found.
        found: AuditSeq,
    },
    /// A record does not link to its predecessor.
    #[error("audit record {seq} does not link to its predecessor")]
    BrokenLink {
        /// The record.
        seq: AuditSeq,
    },
    /// A record's hash does not match its content.
    #[error("audit record {seq} has been altered")]
    BadHash {
        /// The record.
        seq: AuditSeq,
    },
    /// A record could not be encoded for hashing.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

impl Coded for ChainError {
    fn code(&self) -> &'static str {
        match self {
            ChainError::Gap { .. } => "sys.audit.gap",
            ChainError::BrokenLink { .. } => "sys.audit.broken_link",
            ChainError::BadHash { .. } => "sys.audit.bad_hash",
            ChainError::Codec(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        500
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            ChainError::Gap { expected, found } => BTreeMap::from([
                ("expected", expected.to_string()),
                ("found", found.to_string()),
            ]),
            ChainError::BrokenLink { seq } | ChainError::BadHash { seq } => {
                BTreeMap::from([("seq", seq.to_string())])
            }
            ChainError::Codec(_) => BTreeMap::new(),
        }
    }
}

/// Verifies records in sequence order, from the start of the chain or from a trusted head.
#[derive(Debug, Clone, Default)]
pub struct ChainVerifier {
    head: ChainHead,
}

impl ChainVerifier {
    /// A verifier for a chain starting at record 1.
    pub fn new() -> Self {
        Self::default()
    }

    /// A verifier that continues after a trusted head (for example the last exported
    /// record).
    pub fn resume(head: ChainHead) -> Self {
        Self { head }
    }

    /// Verifies the next record.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] on a gap, a broken link or an altered record.
    pub fn push(&mut self, record: &AuditRecord) -> Result<(), ChainError> {
        let expected = self.head.seq.next();
        if record.seq != expected {
            return Err(ChainError::Gap {
                expected,
                found: record.seq,
            });
        }
        if record.prev != self.head.hash {
            return Err(ChainError::BrokenLink { seq: record.seq });
        }
        if record.compute_hash()? != record.hash {
            return Err(ChainError::BadHash { seq: record.seq });
        }
        self.head = ChainHead {
            seq: record.seq,
            hash: record.hash,
        };
        Ok(())
    }

    /// The last verified position.
    pub fn head(&self) -> ChainHead {
        self.head
    }
}

/// Verifies a whole chain from record 1 and returns its head.
///
/// # Errors
///
/// Returns [`ChainError`] at the first record that does not verify.
pub fn verify_chain<'a>(
    records: impl IntoIterator<Item = &'a AuditRecord>,
) -> Result<ChainHead, ChainError> {
    let mut verifier = ChainVerifier::new();
    for record in records {
        verifier.push(record)?;
    }
    Ok(verifier.head())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{from_cbor, to_canonical_cbor, to_cbor},
        id::HostId,
        principal::SystemComponent,
    };

    const CREATE: AuditAction = AuditAction::from_static("ipam.host.create");

    fn chain(len: u64) -> Vec<AuditRecord> {
        let mut prev = Digest::ZERO;
        (1..=len)
            .map(|seq| {
                let draft = AuditDraft::success(CREATE, vec![HostId::generate().into()])
                    .with_source_ip(Some("203.0.113.5".parse().expect("ip")))
                    .with_change(FieldChange {
                        object: None,
                        field: "name".to_owned(),
                        old: None,
                        new: Some(format!("host{seq}")),
                    });
                let record = AuditRecord::seal(
                    AuditSeq(seq),
                    Revision(seq * 2),
                    "2026-10-09T12:00:00Z".parse().expect("time"),
                    Principal::system(SystemComponent::Ipam),
                    Some(RequestId::generate()),
                    draft,
                    prev,
                )
                .expect("seal");
                prev = record.hash;
                record
            })
            .collect()
    }

    #[test]
    fn sealed_chain_verifies() {
        let records = chain(5);
        let head = verify_chain(&records).expect("verifies");
        assert_eq!(head.seq, AuditSeq(5));
        assert_eq!(head.hash, records[4].hash);
    }

    #[test]
    fn tampering_is_detected() {
        let mut records = chain(3);
        records[1]
            .draft
            .details
            .context
            .insert("x".to_owned(), "y".to_owned());
        assert_eq!(
            verify_chain(&records),
            Err(ChainError::BadHash { seq: AuditSeq(2) })
        );

        let mut records = chain(3);
        records.remove(1);
        assert!(matches!(
            verify_chain(&records),
            Err(ChainError::Gap { .. })
        ));

        let mut records = chain(3);
        let resealed = AuditRecord::seal(
            records[1].seq,
            records[1].revision,
            records[1].at,
            records[1].principal.clone(),
            records[1].request,
            records[1].draft.clone(),
            Digest([7; 32]),
        )
        .expect("seal");
        records[1] = resealed;
        assert_eq!(
            verify_chain(&records),
            Err(ChainError::BrokenLink { seq: AuditSeq(2) })
        );
    }

    #[test]
    fn records_survive_json_and_cbor_and_still_verify() {
        let records = chain(2);
        let json = serde_json::to_string(&records).expect("json");
        let from_json: Vec<AuditRecord> = serde_json::from_str(&json).expect("json");
        assert_eq!(from_json, records);
        verify_chain(&from_json).expect("verifies after JSON");
        let cbor = to_cbor(&records).expect("cbor");
        let from_cbor_records: Vec<AuditRecord> = from_cbor(&cbor).expect("cbor");
        verify_chain(&from_cbor_records).expect("verifies after CBOR");
        let value = serde_json::to_value(&records[0]).expect("json");
        assert_eq!(value["hash"].as_str().map(str::len), Some(64));
    }

    #[test]
    fn verification_resumes_from_a_head() {
        let records = chain(4);
        let head = verify_chain(&records[..2]).expect("verifies");
        let mut verifier = ChainVerifier::resume(head);
        for record in &records[2..] {
            verifier.push(record).expect("verifies");
        }
        assert_eq!(verifier.head().seq, AuditSeq(4));
    }

    #[test]
    fn equal_drafts_hash_identically() {
        let a = AuditDraft::success(CREATE, vec![])
            .with_context("b", "2")
            .with_context("a", "1");
        let b = AuditDraft::success(CREATE, vec![])
            .with_context("a", "1")
            .with_context("b", "2");
        assert_eq!(
            to_canonical_cbor(&a).expect("cbor"),
            to_canonical_cbor(&b).expect("cbor")
        );
    }

    #[test]
    fn chain_errors_are_coded() {
        let error = ChainError::Gap {
            expected: AuditSeq(2),
            found: AuditSeq(3),
        };
        assert_eq!(error.code(), "sys.audit.gap");
        assert_eq!(error.params()["found"], "3");
    }
}
