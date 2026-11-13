//! The generation of a controller cluster's history (OPS-03, OPS-26; the cluster recovery
//! plan, sections 3.1 and 3.6).
//!
//! Every installation starts at generation 0, which has no record. A forced step on a
//! survivor (`tenko cluster recover --force`) starts a new history: a [`GenerationRecord`]
//! numbered one above the highest generation the copy has seen, naming its parent (the hash
//! of the record of the history whose data the copy holds; none for generation 0), the
//! forced controller, the fork point and the voters it supersedes. The forced controller
//! signs the record with its cluster-port key and carries its certificate chain, so any
//! holder of the installation's CA can check it without trusting whoever passes it on.
//!
//! # What a receiver does with an offered record
//!
//! A record offered by a peer reaches no decision unchecked: [`Lineage::admit`] is the only
//! way from offered bytes to a [`Relation`], and [`Signed`] has no public constructor for a
//! record that came from outside. The offer is a lineage, the records of the sender's
//! history from older to newer (at most [`MAX_LINEAGE`]), so a controller several
//! generations behind can link the newest record to its own. Every record must verify
//! (chain to the CA at the record's time, a controller's certificate naming the forced
//! node, the signature over [`SIGNING_CONTEXT`] and the body), carry a time not after the
//! receiver's clock plus [`MAX_CLOCK_SKEW`], and be signed by a certificate the receiver's
//! store does not revoke. Then:
//!
//! - **Known** ([`Relation::Known`]): every record is in the receiver's own lineage, or the
//!   newest one is older than the receiver's own. Nothing to do; the other side learns of
//!   this history from the receiver.
//! - **Descendant**: the offer links to the receiver's own record (the first new record's
//!   parent is it) with a higher number, signed by a voter of the receiver's history that
//!   is neither superseded nor revoked there and holds the certificate that signed. The
//!   receiver's history was superseded: it fences itself.
//! - **Sibling**: the first new record shares the receiver's parent, is not older, and is
//!   signed by a voter of that parent history: a competing forced history. Both stop
//!   writing; an operator chooses, and [`suggested_winner`] names the same one everywhere.
//! - **Unplaced**: anything else that is not older than the receiver's own: a parent the
//!   receiver does not know, a lineage longer than an offer carries, a descendant signed by
//!   a certificate the receiver's store does not know. The receiver stops writing too and
//!   shows the records to an operator, never ignores them: a history it cannot place may
//!   be one that superseded it.
//!
//! A record signed by a revoked certificate, by a controller superseded in the receiver's
//! store (except as a sibling), or by a node that was not a voter, is refused and fences
//! nothing.
//!
//! # Byte layouts
//!
//! - The body ([`GenerationBody`]) is canonical CBOR (`tenko_core::codec::to_canonical_cbor`)
//!   and is read exactly: a body whose bytes are not the canonical form of what they decode
//!   to is refused. The record's hash is the SHA-256 of the body bytes; the signature is
//!   ECDSA P-256 with SHA-256 (ASN.1 DER) over [`SIGNING_CONTEXT`] followed by the body, so
//!   no other message signed with the same key can pass for a record. The algorithm belongs
//!   to the layout: another key type is a new layout.
//! - Every layout, present and future, keeps the keys `layout`, `number`, `parent`, `forced`
//!   and `at` with their meaning ([`Header`]): a receiver of an older version can then place
//!   a record of a newer layout and stop writing, although it cannot read the rest.
//! - The record is CBOR of [`GenerationRecord`]: the body bytes, the signature and the
//!   signer's certificate chain (DER, leaf first), read exactly as well. The store row
//!   [`GENERATION`] holds every record of the store's history by number; the metadata entry
//!   [`RECORD_METADATA`] carries a lineage (a CBOR array of records, oldest first).
//! - The wire claim ([`Claim`], metadata entry [`GENERATION_METADATA`]) is
//!   `<number>:<first 16 bytes of the hash in lower-case hex>`; a call without it claims
//!   generation 0.
//! - A controller that stopped writing keeps the records that stopped it in
//!   `<data_dir>/node/` ([`FenceFile`]) and reads them before its Raft core starts.
//!
//! The golden tests below pin every layout and one signed record byte for byte.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
    time::Duration,
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
    },
};
use rustls::pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    NodeId, Revision, Role, Timestamp,
    audit::{ChainHead, Digest},
    codec::{from_cbor, to_canonical_cbor, to_cbor},
    serde_util::{HexBytes, to_hex},
    table::TableDef,
};
use tenko_store::{FenceReason, KeyRange, ReadView, ReadViewExt as _};
use tenko_vault::SecretBytes;

use crate::{
    error::ClusterError,
    identity::{NODE_DIR, files_error, write_private},
    model::tables,
    mtls::PeerIdentity,
};

/// The layout version of [`GenerationBody`] this build writes and reads in full.
pub const LAYOUT: u8 = 1;

/// What the signature covers before the body: a fixed context, so that a signature the
/// same key makes for any other purpose never verifies as a generation record.
pub const SIGNING_CONTEXT: &[u8] = b"tenko generation record v1\0";

/// The largest encoded record: a body of a few hundred bytes, a signature and a leaf
/// certificate fit several times over.
pub const MAX_RECORD_BYTES: usize = 8 * 1024;

/// The most records an offered lineage carries; a receiver further behind cannot link the
/// newest and stops writing ([`Relation::Unplaced`]).
pub const MAX_LINEAGE: usize = 8;

/// The largest encoded lineage (a binary metadata entry of about 22 KiB in base64).
pub const MAX_LINEAGE_BYTES: usize = 16 * 1024;

/// How far a record's time may be ahead of the receiver's clock.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Bytes of the hash a [`Claim`] carries: enough to tell two signed records apart.
pub const CLAIM_HASH_BYTES: usize = 16;

/// Metadata entry of every `Raft` and `Cluster` call and answer: the sender's [`Claim`].
pub const GENERATION_METADATA: &str = "tenko-generation";

/// Binary metadata entry with a lineage of records ([`encode_lineage`]): on a refusal by
/// the newer side, and on the calls a newer side makes to a controller it knows is behind.
pub const RECORD_METADATA: &str = "tenko-generation-record-bin";

/// The generation records of the history this store holds, by number; empty at
/// generation 0. The highest one is the store's own record.
pub const GENERATION: TableDef<u64, GenerationRecord> = TableDef::new("cluster.generation");

/// The marks of the controllers a forced step superseded, by node id. Their member records
/// stay; a controller of the current history refuses every call of a node marked here
/// (section 3.9), whatever generation it claims.
pub const SUPERSEDED: TableDef<u64, SupersededMark> = TableDef::new("cluster.superseded");

/// The file under `<data_dir>/node/` that keeps a controller fenced across restarts.
pub const FENCE_FILE: &str = "generation-fence";

/// Error codes of the generations and the recovery.
pub mod codes {
    use tenko_store::FenceReason;

    /// A call or a write refused because the controller's history was superseded, or because
    /// the caller's history differs from the callee's.
    pub const SUPERSEDED: &str = FenceReason::Superseded.code();
    /// A competing forced history was seen: this controller stopped writing until an
    /// operator chooses.
    pub const CONFLICT: &str = FenceReason::Conflict.code();
    /// The first start after a forced step found the old cluster alive and did not take
    /// office.
    pub const MAJORITY_ALIVE: &str = FenceReason::MajorityAlive.code();
    /// `--force` on a copy behind a given fingerprint.
    pub const NOT_FRESHEST: &str = "cluster.recover.not_freshest";
    /// `--force` while a known member runs a binary without generations.
    pub const MIXED: &str = "cluster.recover.mixed";
    /// `--force` on a copy that is already the only voter.
    pub const NOT_NEEDED: &str = "cluster.recover.not_needed";
    /// The typed confirmation did not match.
    pub const CONFIRM: &str = "cluster.recover.confirm";
    /// `--undo` after the first start took office, or without a forced step to undo.
    pub const UNDO_REFUSED: &str = "cluster.recover.undo_refused";
    /// A forced step was interrupted: the server does not start until it is finished or
    /// undone.
    pub const INTERRUPTED: &str = "cluster.recover.interrupted";
    /// The command needs a stopped controller.
    pub const IN_USE: &str = "cluster.recover.in_use";
    /// A generation record that does not verify, or that this receiver may not act on.
    pub const RECORD_INVALID: &str = "cluster.recover.record_invalid";
    /// Warning: a superseded controller has not received the record yet.
    pub const SUPERSEDED_UNREACHED: &str = "cluster.recover.superseded_unreached";
    /// Warning: a superseded controller is neither rejoined nor removed.
    pub const SUPERSEDED_PENDING: &str = "cluster.recover.superseded_pending";
}

/// Audit actions of the recovery.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A forced step created a new generation (written in the step's own batch).
    pub const FORCE: AuditAction = AuditAction::from_static("cluster.recover.force");
}

/// Where the superseded history ends and the new one starts: the forced copy's last log id,
/// its revision and its audit head once its whole log was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkPoint {
    /// The term of the last log id.
    pub term: u64,
    /// The node of the last log id's leader.
    pub leader: u64,
    /// The index of the last log id.
    pub index: u64,
    /// The store revision after the whole log.
    pub revision: Revision,
    /// The head of the audit chain after the whole log.
    pub audit: ChainHead,
}

impl ForkPoint {
    /// Raft's order of log ids: term first, then index. Only meaningful inside one history.
    pub fn log_order(&self, other: &Self) -> Ordering {
        (self.term, self.index).cmp(&(other.term, other.index))
    }
}

/// What a generation record says (layout 1). Its canonical CBOR is what is hashed and,
/// after [`SIGNING_CONTEXT`], signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationBody {
    /// [`LAYOUT`].
    pub layout: u8,
    /// The generation: one above the highest the forced copy had seen; never 0.
    pub number: u64,
    /// The hash of the record of the history whose data the copy holds; `None` for
    /// generation 0.
    pub parent: Option<Digest>,
    /// The forced controller, which signed the record.
    pub forced: NodeId,
    /// Where the new history starts.
    pub fork: ForkPoint,
    /// The voters of the parent history that this one supersedes (the forced one not
    /// among them).
    pub superseded: Vec<NodeId>,
    /// When the record was made.
    pub at: Timestamp,
    /// 16 random bytes, so that two forced steps never make one body.
    pub nonce: HexBytes,
}

impl GenerationBody {
    /// The canonical bytes that are hashed.
    ///
    /// # Errors
    ///
    /// A codec error.
    pub fn canonical(&self) -> Result<Vec<u8>, ClusterError> {
        Ok(to_canonical_cbor(self)?)
    }
}

/// The part of a body every layout keeps with the same meaning: enough to verify the record
/// and to place it among histories, read tolerantly from a layout this build does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Header {
    /// The layout of the whole body.
    pub layout: u8,
    /// The generation.
    pub number: u64,
    /// The parent record's hash.
    pub parent: Option<Digest>,
    /// The forced controller.
    pub forced: NodeId,
    /// When the record was made.
    pub at: Timestamp,
}

/// A signed generation record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRecord {
    /// The canonical CBOR of the body.
    pub body: HexBytes,
    /// ECDSA P-256 SHA-256 (ASN.1 DER) over [`SIGNING_CONTEXT`] and `body` with the forced
    /// controller's key.
    pub signature: HexBytes,
    /// The forced controller's certificate chain, DER, leaf first.
    pub chain: Vec<HexBytes>,
}

impl std::fmt::Debug for GenerationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationRecord")
            .field("hash", &self.hash())
            .finish_non_exhaustive()
    }
}

fn invalid(detail: impl Into<String>) -> ClusterError {
    ClusterError::new(codes::RECORD_INVALID, 403, detail)
}

/// Decodes CBOR whose bytes must be exactly the encoding of what they decode to: no
/// trailing bytes, no second form of the same value.
fn exact<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    canonical: bool,
    what: &str,
) -> Result<T, ClusterError> {
    let value: T = from_cbor(bytes)
        .map_err(|error| invalid(format!("the {what} does not decode: {error}")))?;
    let again = if canonical {
        to_canonical_cbor(&value)?
    } else {
        to_cbor(&value)?.to_vec()
    };
    if again != bytes {
        return Err(invalid(format!(
            "the {what} is not in its exact encoding (trailing or non-canonical bytes)"
        )));
    }
    Ok(value)
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    [SIGNING_CONTEXT, body].concat()
}

impl GenerationRecord {
    /// Signs `body` with the PKCS#8 key of `chain`'s leaf.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` when the key is not an ECDSA P-256 key or the chain
    /// is empty; a codec error.
    pub fn sign(
        body: &GenerationBody,
        chain: &[CertificateDer<'_>],
        key: &SecretBytes,
    ) -> Result<Self, ClusterError> {
        if chain.is_empty() {
            return Err(invalid(
                "a generation record needs the signer's certificate",
            ));
        }
        let bytes = body.canonical()?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key.expose())
            .map_err(|error| invalid(format!("the controller key cannot sign: {error}")))?;
        let signature = pair
            .sign(&SystemRandom::new(), &signed_message(&bytes))
            .map_err(|error| invalid(format!("signing failed: {error}")))?;
        Ok(Self {
            body: HexBytes(bytes),
            signature: HexBytes(signature.as_ref().to_vec()),
            chain: chain.iter().map(|cert| HexBytes(cert.to_vec())).collect(),
        })
    }

    /// The record's hash: SHA-256 of its body bytes.
    pub fn hash(&self) -> Digest {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &self.body.0);
        let mut out = [0; 32];
        out.copy_from_slice(digest.as_ref());
        Digest(out)
    }

    /// The part of the body every layout keeps, read tolerantly.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid`.
    pub fn header(&self) -> Result<Header, ClusterError> {
        from_cbor(&self.body.0).map_err(|error| {
            invalid(format!(
                "the generation record's header does not decode: {error}"
            ))
        })
    }

    /// The body of layout [`LAYOUT`], read exactly; `None` for a later layout.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` for a body of this layout that is not exactly its
    /// canonical encoding, or that breaks a rule of the layout (number 0, a nonce that is
    /// not 16 bytes, the forced controller among the superseded ones).
    pub fn body(&self) -> Result<Option<GenerationBody>, ClusterError> {
        if self.header()?.layout != LAYOUT {
            return Ok(None);
        }
        let body: GenerationBody = exact(&self.body.0, true, "generation record's body")?;
        if body.number == 0 || body.nonce.0.len() != 16 || body.superseded.contains(&body.forced) {
            return Err(invalid(
                "the generation record breaks a rule of its layout (number 0, nonce length, or \
                 the forced controller among the superseded ones)",
            ));
        }
        Ok(Some(body))
    }

    /// The record's CBOR.
    ///
    /// # Errors
    ///
    /// A codec error.
    pub fn encode(&self) -> Result<Vec<u8>, ClusterError> {
        Ok(to_cbor(self)?.to_vec())
    }

    /// Reads a record of at most [`MAX_RECORD_BYTES`], exactly.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("the generation record is too large"));
        }
        exact(bytes, false, "generation record")
    }

    /// Checks the chain against `ca_root` at the record's own time (a returning controller
    /// may meet a record whose signer renewed its certificate since; how far that time may
    /// lie is bounded by [`Lineage::admit`]), the leaf as the forced controller's, and the
    /// signature.
    fn verify(&self, ca_root: &CertificateDer<'_>) -> Result<Signed, ClusterError> {
        let header = self.header()?;
        if header.number == 0 {
            return Err(invalid("a generation record is never numbered 0"));
        }
        let body = self.body()?;
        let (leaf, intermediates) = self
            .chain
            .split_first()
            .ok_or_else(|| invalid("the generation record carries no certificate"))?;
        let leaf = CertificateDer::from(leaf.0.as_slice());
        let intermediates: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|cert| CertificateDer::from(cert.0.as_slice()))
            .collect();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca_root.clone().into_owned())
            .map_err(|error| invalid(format!("the CA root is unusable: {error}")))?;
        let seconds = u64::try_from(header.at.0.unix_timestamp())
            .map_err(|_| invalid("the generation record's time is before 1970"))?;
        let signer = crate::mtls::verify_controller(
            &roots,
            &leaf,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
            &crate::mtls::provider().signature_verification_algorithms,
        )
        .map_err(|error| invalid(format!("the signer's certificate does not verify: {error}")))?;
        if signer.node != header.forced {
            return Err(invalid(
                "the generation record is not signed by the forced controller's certificate",
            ));
        }
        let point = public_key(&leaf)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(&signed_message(&self.body.0), &self.signature.0)
            .map_err(|_| invalid("the generation record's signature does not verify"))?;
        Ok(Signed {
            hash: self.hash(),
            header,
            body,
            signer,
            record: self.clone(),
        })
    }
}

fn public_key(leaf: &[u8]) -> Result<Vec<u8>, ClusterError> {
    use x509_parser::prelude::FromDer as _;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf)
        .map_err(|error| invalid(format!("the signer's certificate: {error}")))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

/// Encodes a lineage for [`RECORD_METADATA`]: the records, oldest first.
///
/// # Errors
///
/// A codec error.
pub fn encode_lineage(records: &[GenerationRecord]) -> Result<Vec<u8>, ClusterError> {
    Ok(to_cbor(records)?.to_vec())
}

/// Reads a lineage of [`RECORD_METADATA`], exactly, with at most [`MAX_LINEAGE`] records
/// and [`MAX_LINEAGE_BYTES`].
///
/// # Errors
///
/// `cluster.recover.record_invalid`.
pub fn decode_lineage(bytes: &[u8]) -> Result<Vec<GenerationRecord>, ClusterError> {
    if bytes.len() > MAX_LINEAGE_BYTES {
        return Err(invalid("the offered lineage is too large"));
    }
    let records: Vec<GenerationRecord> = exact(bytes, false, "offered lineage")?;
    if records.is_empty() || records.len() > MAX_LINEAGE {
        return Err(invalid(format!(
            "an offered lineage holds 1 to {MAX_LINEAGE} records"
        )));
    }
    Ok(records)
}

/// A record whose signature and chain verified, or one this controller keeps itself.
/// Fields are private: a record from outside becomes one only through [`Lineage::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    hash: Digest,
    header: Header,
    body: Option<GenerationBody>,
    signer: PeerIdentity,
    record: GenerationRecord,
}

impl Signed {
    /// A record this controller wrote or admitted itself (its store's rows, its fence
    /// file), read without checking the signature again.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` when the body or the certificate does not decode.
    pub fn kept(record: &GenerationRecord) -> Result<Self, ClusterError> {
        let leaf = record
            .chain
            .first()
            .ok_or_else(|| invalid("the generation record carries no certificate"))?;
        Ok(Self {
            hash: record.hash(),
            header: record.header()?,
            body: record.body()?,
            signer: PeerIdentity::from_der(&leaf.0)
                .map_err(|_| invalid("the signer's certificate names no node"))?,
            record: record.clone(),
        })
    }

    /// The record's hash.
    pub fn hash(&self) -> Digest {
        self.hash
    }

    /// The generation.
    pub fn number(&self) -> u64 {
        self.header.number
    }

    /// The parent record's hash.
    pub fn parent(&self) -> Option<Digest> {
        self.header.parent
    }

    /// The forced controller.
    pub fn forced(&self) -> NodeId {
        self.header.forced
    }

    /// When the record was made.
    pub fn at(&self) -> Timestamp {
        self.header.at
    }

    /// The whole body, when its layout is this build's.
    pub fn body(&self) -> Option<&GenerationBody> {
        self.body.as_ref()
    }

    /// The certificate that signed.
    pub fn signer(&self) -> &PeerIdentity {
        &self.signer
    }

    /// The record.
    pub fn record(&self) -> &GenerationRecord {
        &self.record
    }

    /// The claim of this history on the wire.
    pub fn claim(&self) -> Claim {
        Claim::of(self.number(), &self.hash)
    }
}

/// How an offered lineage stands to the history a receiver holds ([`Lineage::admit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Nothing new: every record is the receiver's own, or the newest is older than the
    /// receiver's own.
    Known,
    /// It supersedes the receiver's history: the receiver fences itself.
    Descendant,
    /// A competing forced history from the receiver's parent: both stop writing.
    Sibling,
    /// A newer or equal history the receiver cannot place: it stops writing too.
    Unplaced,
}

impl Relation {
    /// What the receiver does: the fence it raises, or nothing.
    pub fn fence(self) -> Option<FenceReason> {
        match self {
            Self::Known => None,
            Self::Descendant => Some(FenceReason::Superseded),
            Self::Sibling | Self::Unplaced => Some(FenceReason::Conflict),
        }
    }
}

/// The outcome of an admitted offer.
#[derive(Debug, Clone)]
pub struct Admission {
    /// How it stands.
    pub relation: Relation,
    /// Its records that the receiver's lineage does not hold, oldest first; the last is
    /// the newest record offered.
    pub new: Vec<Signed>,
}

/// What the receiver's store says about the signers: the voters of its history, the
/// controllers it marks superseded, the revoked certificates and nodes, and the
/// certificates each node record holds.
#[derive(Debug, Clone)]
pub struct Standing {
    voters: BTreeSet<NodeId>,
    superseded: BTreeSet<NodeId>,
    revoked_serials: BTreeSet<String>,
    revoked_nodes: BTreeSet<NodeId>,
    serials: BTreeMap<NodeId, BTreeSet<String>>,
    now: Timestamp,
}

impl Default for Standing {
    /// A store that knows no controller, at the current time: every signer lacks standing.
    fn default() -> Self {
        Self {
            voters: BTreeSet::new(),
            superseded: BTreeSet::new(),
            revoked_serials: BTreeSet::new(),
            revoked_nodes: BTreeSet::new(),
            serials: BTreeMap::new(),
            now: Timestamp::now(),
        }
    }
}

impl Standing {
    /// The standing in `view`, with `voters` the voters of the receiver's membership and
    /// `now` its clock.
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn read(
        view: &dyn ReadView,
        voters: BTreeSet<NodeId>,
        now: Timestamp,
    ) -> Result<Self, ClusterError> {
        let mut standing = Self {
            voters,
            now,
            ..Self::default()
        };
        for (node, _, _) in view.scan_typed(&SUPERSEDED, KeyRange::all(), usize::MAX, false)? {
            standing.superseded.insert(NodeId(node));
        }
        for (serial, revocation, _) in
            view.scan_typed(&tables::REVOCATIONS, KeyRange::all(), usize::MAX, false)?
        {
            standing.revoked_serials.insert(serial);
            standing.revoked_nodes.insert(revocation.node);
        }
        for (node, record, _) in
            view.scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)?
        {
            if record.roles.contains(&Role::Controller) {
                standing.serials.insert(
                    NodeId(node),
                    record.serials.into_iter().map(|cert| cert.serial).collect(),
                );
            }
        }
        Ok(standing)
    }

    fn revoked(&self, signer: &PeerIdentity) -> bool {
        self.revoked_serials.contains(&signer.serial) || self.revoked_nodes.contains(&signer.node)
    }

    fn holds(&self, signer: &PeerIdentity) -> bool {
        self.serials
            .get(&signer.node)
            .is_some_and(|serials| serials.contains(&signer.serial))
    }
}

fn refused(signer: NodeId, why: &str) -> ClusterError {
    invalid(format!(
        "a generation record signed by controller {signer} was refused: {why}"
    ))
    .with_param("node", signer.to_string())
}

/// The records of the history a store holds, oldest first; empty at generation 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lineage {
    records: Vec<Signed>,
}

impl Lineage {
    /// The lineage of `view` ([`GENERATION`]).
    ///
    /// # Errors
    ///
    /// A store error, or a stored record that does not read.
    pub fn read(view: &dyn ReadView) -> Result<Self, ClusterError> {
        let records = view
            .scan_typed(&GENERATION, KeyRange::all(), usize::MAX, false)?
            .iter()
            .map(|(_, record, _)| Signed::kept(record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { records })
    }

    /// A lineage of records this controller keeps itself, in any order.
    ///
    /// # Errors
    ///
    /// A record that does not read.
    pub fn kept(records: &[GenerationRecord]) -> Result<Self, ClusterError> {
        let mut records = records
            .iter()
            .map(Signed::kept)
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(Signed::number);
        Ok(Self { records })
    }

    /// The records, oldest first.
    pub fn records(&self) -> &[Signed] {
        &self.records
    }

    /// The store's own record: the newest; `None` at generation 0.
    pub fn tip(&self) -> Option<&Signed> {
        self.records.last()
    }

    /// The claim of this history.
    pub fn claim(&self) -> Claim {
        self.tip().map_or(Claim::ZERO, Signed::claim)
    }

    /// The generation of this history.
    pub fn number(&self) -> u64 {
        self.tip().map_or(0, Signed::number)
    }

    /// The newest records that fit an offer ([`MAX_LINEAGE`], [`MAX_LINEAGE_BYTES`]),
    /// oldest first.
    pub fn offer(&self) -> Vec<GenerationRecord> {
        let mut offer = Vec::new();
        let mut bytes = 16;
        for signed in self.records.iter().rev().take(MAX_LINEAGE) {
            let size = signed
                .record
                .encode()
                .map_or(usize::MAX, |encoded| encoded.len());
            if bytes + size > MAX_LINEAGE_BYTES {
                break;
            }
            bytes += size;
            offer.push(signed.record.clone());
        }
        offer.reverse();
        offer
    }

    /// Checks an offered lineage against this one and the receiver's `standing` (see the
    /// module documentation for the rules).
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` for an offer that does not verify, is not one
    /// lineage, lies in the future, or is signed by a controller this receiver may not take
    /// a record from; the offer then changes nothing.
    pub fn admit(
        &self,
        offered: &[GenerationRecord],
        ca_root: &CertificateDer<'_>,
        standing: &Standing,
    ) -> Result<Admission, ClusterError> {
        if offered.is_empty() || offered.len() > MAX_LINEAGE {
            return Err(invalid(format!(
                "an offered lineage holds 1 to {MAX_LINEAGE} records"
            )));
        }
        let latest = standing
            .now
            .checked_add(MAX_CLOCK_SKEW)
            .unwrap_or(standing.now);
        let mut checked = Vec::with_capacity(offered.len());
        for record in offered {
            let signed = record.verify(ca_root)?;
            if signed.at() > latest {
                return Err(invalid("a generation record carries a time in the future"));
            }
            if standing.revoked(&signed.signer) {
                return Err(refused(signed.forced(), "its certificate is revoked"));
            }
            checked.push(signed);
        }
        checked.sort_by_key(Signed::number);
        for pair in checked.windows(2) {
            if pair[1].parent() != Some(pair[0].hash)
                || pair[1].number() <= pair[0].number()
                || pair[1].at() < pair[0].at()
            {
                return Err(invalid("the offered records are not one lineage"));
            }
        }
        let known: BTreeSet<Digest> = self.records.iter().map(|own| own.hash).collect();
        let new: Vec<Signed> = checked
            .into_iter()
            .filter(|signed| !known.contains(&signed.hash))
            .collect();
        let (Some(first), Some(newest)) = (new.first(), new.last()) else {
            return Ok(Admission {
                relation: Relation::Known,
                new,
            });
        };
        let own = self.tip();
        let own_hash = own.map(|own| own.hash);
        let own_number = self.number();
        if newest.number() < own_number {
            return Ok(Admission {
                relation: Relation::Known,
                new,
            });
        }
        let signer = first.signer();
        let relation = if first.parent() == own_hash && first.number() > own_number {
            if !standing.voters.contains(&signer.node) {
                return Err(refused(signer.node, "it is not a voter of this history"));
            }
            if standing.superseded.contains(&signer.node) {
                return Err(refused(signer.node, "it is superseded in this history"));
            }
            if own.is_some_and(|own| first.at() < own.at()) {
                return Err(refused(signer.node, "its record is older than its parent"));
            }
            if standing.holds(signer) {
                Relation::Descendant
            } else {
                // A voter in good standing whose certificate this store does not know: a
                // renewal this copy missed, or a certificate minted elsewhere. Neither is
                // ignored; an operator decides.
                Relation::Unplaced
            }
        } else if let Some(own) = own.filter(|own| first.parent() == own.parent()) {
            let parent_voters = own.body().map(|body| {
                body.superseded
                    .iter()
                    .copied()
                    .chain([own.forced()])
                    .collect::<BTreeSet<_>>()
            });
            if parent_voters.is_some_and(|voters| !voters.contains(&signer.node)) {
                return Err(refused(
                    signer.node,
                    "it was not a voter of the parent history",
                ));
            }
            Relation::Sibling
        } else {
            if standing.superseded.contains(&signer.node) {
                return Err(refused(signer.node, "it is superseded in this history"));
            }
            Relation::Unplaced
        };
        Ok(Admission { relation, new })
    }
}

/// The order of competing histories, the same on every member and transitive: the higher
/// number; then the parent (none first, then the lower hash); then, within one parent, the
/// fresher fork point; then the lower node id of the forced controller; then the lower hash.
/// `Ordering::Less` when `a` is the suggested winner. A record of a later layout has no
/// readable fork point and ranks as the oldest one at its place.
pub fn suggested_winner(a: &Signed, b: &Signed) -> Ordering {
    let fork = |signed: &Signed| {
        signed
            .body()
            .map_or((0, 0), |body| (body.fork.term, body.fork.index))
    };
    b.number()
        .cmp(&a.number())
        .then_with(|| a.parent().cmp(&b.parent()))
        .then_with(|| fork(b).cmp(&fork(a)))
        .then_with(|| a.forced().0.cmp(&b.forced().0))
        .then_with(|| a.hash.cmp(&b.hash))
}

/// A history as a call names it: its number and the first [`CLAIM_HASH_BYTES`] of its
/// record's hash. Generation 0 is the claim of a call without the metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Claim {
    /// The generation.
    pub number: u64,
    /// The hash prefix; zero at generation 0.
    pub hash: [u8; CLAIM_HASH_BYTES],
}

impl Claim {
    /// The claim of generation 0.
    pub const ZERO: Self = Self {
        number: 0,
        hash: [0; CLAIM_HASH_BYTES],
    };

    /// The claim of a record numbered `number` with hash `hash`.
    pub fn of(number: u64, hash: &Digest) -> Self {
        let mut prefix = [0; CLAIM_HASH_BYTES];
        prefix.copy_from_slice(&hash.0[..CLAIM_HASH_BYTES]);
        Self {
            number,
            hash: prefix,
        }
    }

    /// The metadata value, `None` for generation 0 (the entry is left out).
    pub fn render(&self) -> Option<String> {
        (*self != Self::ZERO).then(|| format!("{}:{}", self.number, to_hex(&self.hash)))
    }

    /// Reads a metadata value in the one form [`Claim::render`] writes; `None` otherwise.
    pub fn parse(text: &str) -> Option<Self> {
        let (number, hash) = text.split_once(':')?;
        let digits = !number.is_empty()
            && !number.starts_with('0')
            && number.bytes().all(|byte| byte.is_ascii_digit());
        let lower_hex = hash.len() == CLAIM_HASH_BYTES * 2
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !digits || !lower_hex {
            return None;
        }
        let mut out = [0; CLAIM_HASH_BYTES];
        for (index, pair) in hash.as_bytes().chunks(2).enumerate() {
            out[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self {
            number: number.parse().ok()?,
            hash: out,
        })
    }
}

/// The fence a controller keeps under `<data_dir>/node/` ([`FENCE_FILE`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceFile {
    /// Why: [`FenceReason::Superseded`] for a descendant, [`FenceReason::Conflict`] for a
    /// history that competes or that this controller could not place.
    pub kind: FenceReason,
    /// The records that stopped it, oldest first.
    pub records: Vec<GenerationRecord>,
    /// When.
    pub at: Timestamp,
}

impl FenceFile {
    /// The fence of `data_dir`, if any; read tolerantly.
    ///
    /// # Errors
    ///
    /// `cluster.node.files` when the file exists but cannot be read or decoded: a start
    /// must not go on unfenced over a fence it cannot read.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, ClusterError> {
        let path = data_dir.join(NODE_DIR).join(FENCE_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(files_error(&path, &error)),
        };
        from_cbor(&bytes)
            .map(Some)
            .map_err(|error| files_error(&path, &error))
    }

    /// Writes the fence: private to the service account, replaced atomically and durable
    /// before this returns.
    ///
    /// # Errors
    ///
    /// `cluster.node.files`.
    pub fn save(&self, data_dir: &Path) -> Result<(), ClusterError> {
        let dir = data_dir.join(NODE_DIR);
        crate::identity::create_private_dir(&dir)?;
        write_private(&dir.join(FENCE_FILE), &to_cbor(self)?)
    }
}

/// What the store records about a member that a forced step superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededMark {
    /// The generation that superseded it.
    pub generation: u64,
    /// That generation's record hash.
    pub record: Digest,
    /// Whether it may rejoin by itself when it holds nothing of its own after the fork
    /// (`--rejoin`, CR-Q1).
    #[serde(default)]
    pub rejoin: bool,
}

#[cfg(test)]
mod tests;
