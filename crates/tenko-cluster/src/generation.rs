//! The generation of a controller cluster's history (OPS-03, OPS-26; the cluster recovery
//! plan, sections 3.1 and 3.6).
//!
//! Every installation starts at generation 0, which has no record. A forced step on a
//! survivor (`tenko cluster recover --force`) starts a new history: a [`GenerationRecord`]
//! numbered one above the highest generation the copy has seen, naming its parent (the hash
//! of the record of the history whose data the copy holds; none for generation 0), the
//! forced controller, the fork point and the voters it supersedes. The forced controller
//! signs the record's body with its cluster-port key and carries its certificate chain, so
//! any holder of the installation's CA can check it without trusting whoever passes it on.
//!
//! Two histories never merge: a controller that learns of a record whose parent is its own
//! history (a **descendant**, [`Relation::Descendant`]) fences itself; two records with the
//! same parent (**siblings**) both stop writing until an operator chooses, and
//! [`suggested_winner`] names the same one on every member.
//!
//! # Byte layouts
//!
//! - The body ([`GenerationBody`]) is canonical CBOR (`tenko_core::codec::to_canonical_cbor`),
//!   and the record's hash is the SHA-256 of exactly those bytes; the signature covers them.
//!   A body is decoded tolerantly (unknown fields are ignored), since the hash and the
//!   signature already bind every byte of it.
//! - The record is CBOR of [`GenerationRecord`]: the body bytes, the signature (ECDSA P-256
//!   with SHA-256, ASN.1 DER) and the signer's certificate chain (DER, leaf first). It is
//!   the value of the store row [`GENERATION`] and of the metadata entry
//!   [`RECORD_METADATA`].
//! - The wire claim ([`Claim`], metadata entry [`GENERATION_METADATA`]) is
//!   `<number>:<first 16 bytes of the hash in hex>`; a call without it claims generation 0.
//! - A controller that learned of a newer or competing history keeps the record in
//!   `<data_dir>/node/` ([`FenceFile`]) and reads it before its Raft core starts.
//!
//! The golden tests below pin every layout.

use std::{cmp::Ordering, fs, io, path::Path, time::Duration};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
    },
};
use rustls::{
    pki_types::{CertificateDer, UnixTime},
    server::ParsedCertificate,
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, Revision, Role, Timestamp,
    audit::{ChainHead, Digest},
    codec::{from_cbor, to_canonical_cbor, to_cbor},
    serde_util::{HexBytes, from_hex, to_hex},
    table::TableDef,
};
use tenko_store::FenceReason;
use tenko_vault::SecretBytes;

use crate::{
    error::ClusterError,
    identity::{NODE_DIR, write_private},
    mtls::PeerIdentity,
};

/// The layout version of [`GenerationBody`] this build writes and reads.
pub const LAYOUT: u8 = 1;

/// The largest encoded record accepted from the network or a file: a body of a few hundred
/// bytes, a signature and a chain of two certificates fit many times over.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Bytes of the hash a [`Claim`] carries: enough to tell two signed records apart.
pub const CLAIM_HASH_BYTES: usize = 16;

/// Metadata entry of every `Raft` and `Cluster` call and answer: the sender's [`Claim`].
pub const GENERATION_METADATA: &str = "tenko-generation";

/// Binary metadata entry with a whole [`GenerationRecord`]: on a refusal by the newer side,
/// and on the calls a newer side makes to a controller it knows is behind.
pub const RECORD_METADATA: &str = "tenko-generation-record-bin";

/// The generation record of the history this store holds; absent at generation 0.
pub const GENERATION: TableDef<(), GenerationRecord> = TableDef::new("cluster.generation");

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
    /// A node refuses the configuration of a controller of an older generation.
    pub const NODE_CONFIG_SUPERSEDED: &str = "node.config.superseded";
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

/// What a generation record says. Its canonical CBOR is what is signed and hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationBody {
    /// [`LAYOUT`].
    pub layout: u8,
    /// The generation: one above the highest the forced copy had seen.
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
    /// The canonical bytes that are signed and hashed.
    ///
    /// # Errors
    ///
    /// A codec error.
    pub fn canonical(&self) -> Result<Vec<u8>, ClusterError> {
        Ok(to_canonical_cbor(self)?)
    }
}

/// A signed generation record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRecord {
    /// The canonical CBOR of the [`GenerationBody`].
    pub body: HexBytes,
    /// ECDSA P-256 SHA-256 (ASN.1 DER) over `body` with the forced controller's key.
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
            .sign(&SystemRandom::new(), &bytes)
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

    /// The body, read tolerantly; a layout this build does not know is refused.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid`.
    pub fn body(&self) -> Result<GenerationBody, ClusterError> {
        let body: GenerationBody = from_cbor(&self.body.0)
            .map_err(|error| invalid(format!("the generation record does not decode: {error}")))?;
        if body.layout != LAYOUT {
            return Err(invalid(format!(
                "the generation record has layout {}, this build reads {LAYOUT}",
                body.layout
            )));
        }
        Ok(body)
    }

    /// The record's CBOR.
    ///
    /// # Errors
    ///
    /// A codec error.
    pub fn encode(&self) -> Result<Vec<u8>, ClusterError> {
        Ok(to_cbor(self)?.to_vec())
    }

    /// Reads a record of at most [`MAX_RECORD_BYTES`].
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("the generation record is too large"));
        }
        from_cbor(bytes)
            .map_err(|error| invalid(format!("the generation record does not decode: {error}")))
    }

    /// Checks the signature and the chain against `ca_root` at the record's own time (a
    /// returning controller may meet a record whose signer renewed its certificate since)
    /// and that the leaf is a controller's. Who the signer may be is the receiver's
    /// question ([`Relation`] and its store), not this one's.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid`.
    pub fn verify(&self, ca_root: &CertificateDer<'_>) -> Result<Signed, ClusterError> {
        let body = self.body()?;
        let leaf = self
            .chain
            .first()
            .ok_or_else(|| invalid("the generation record carries no certificate"))?;
        let leaf = CertificateDer::from(leaf.0.as_slice());
        let intermediates: Vec<CertificateDer<'_>> = self.chain[1..]
            .iter()
            .map(|cert| CertificateDer::from(cert.0.as_slice()))
            .collect();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca_root.clone().into_owned())
            .map_err(|error| invalid(format!("the CA root is unusable: {error}")))?;
        let parsed = ParsedCertificate::try_from(&leaf)
            .map_err(|error| invalid(format!("the signer's certificate: {error}")))?;
        let seconds = u64::try_from(body.at.0.unix_timestamp())
            .map_err(|_| invalid("the generation record's time is before 1970"))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
            crate::mtls::provider()
                .signature_verification_algorithms
                .all,
        )
        .map_err(|error| invalid(format!("the signer's certificate does not verify: {error}")))?;
        let signer = PeerIdentity::from_der(&leaf)
            .map_err(|_| invalid("the signer's certificate names no node"))?;
        if !signer.roles.contains(Role::Controller) || signer.node != body.forced {
            return Err(invalid(
                "the generation record is not signed by the forced controller's certificate",
            ));
        }
        let point = public_key(&leaf)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(&self.body.0, &self.signature.0)
            .map_err(|_| invalid("the generation record's signature does not verify"))?;
        Ok(Signed {
            hash: self.hash(),
            body,
            signer,
            record: self.clone(),
        })
    }
}

impl GenerationRecord {
    /// The record as [`Signed`] without checking the signature: for a record this
    /// controller holds itself (its store's row, its fence file), which was checked before
    /// it was kept.
    ///
    /// # Errors
    ///
    /// `cluster.recover.record_invalid` when the body or the certificate does not decode.
    pub fn trusted(&self) -> Result<Signed, ClusterError> {
        let leaf = self
            .chain
            .first()
            .ok_or_else(|| invalid("the generation record carries no certificate"))?;
        Ok(Signed {
            hash: self.hash(),
            body: self.body()?,
            signer: PeerIdentity::from_der(&leaf.0)
                .map_err(|_| invalid("the signer's certificate names no node"))?,
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

/// A record whose signature and chain verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The record's hash.
    pub hash: Digest,
    /// Its body.
    pub body: GenerationBody,
    /// The certificate that signed it.
    pub signer: PeerIdentity,
    /// The record itself.
    pub record: GenerationRecord,
}

impl Signed {
    /// The claim of this history on the wire.
    pub fn claim(&self) -> Claim {
        Claim::of(self.body.number, &self.hash)
    }
}

/// How a record stands to the history a receiver holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// It is the receiver's own record.
    Same,
    /// Its parent is the receiver's history: the receiver was superseded.
    Descendant,
    /// It shares the receiver's parent and is not older: a competing forced history.
    Sibling,
    /// Anything else (an older record, or one of a history the receiver cannot place).
    Unrelated,
}

/// How `other` stands to `own` (the record of the receiver's history; `None` at generation
/// 0). Log ids are never compared here: they belong to one history (plan section 3.1).
pub fn relation(own: Option<&Signed>, other: &Signed) -> Relation {
    let own_hash = own.map(|own| own.hash);
    if own_hash == Some(other.hash) {
        return Relation::Same;
    }
    if other.body.parent == own_hash {
        return Relation::Descendant;
    }
    match own {
        Some(own)
            if other.body.parent == own.body.parent && other.body.number >= own.body.number =>
        {
            Relation::Sibling
        }
        _ => Relation::Unrelated,
    }
}

/// The record two sibling histories should keep, the same on every member: the higher
/// number; at equal numbers and the same parent the fresher fork point; then the lower
/// node id; then the lower hash. Returns the order with the suggested winner first
/// (`Ordering::Less` when `a` wins).
pub fn suggested_winner(a: &Signed, b: &Signed) -> Ordering {
    b.body
        .number
        .cmp(&a.body.number)
        .then_with(|| {
            if a.body.parent == b.body.parent {
                b.body.fork.log_order(&a.body.fork)
            } else {
                Ordering::Equal
            }
        })
        .then_with(|| a.body.forced.0.cmp(&b.body.forced.0))
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

    /// Reads a metadata value; `None` when it is malformed.
    pub fn parse(text: &str) -> Option<Self> {
        let (number, hash) = text.split_once(':')?;
        let number = number.parse().ok()?;
        if hash.len() != CLAIM_HASH_BYTES * 2 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let hash = from_hex(hash)?.try_into().ok()?;
        Some(Self { number, hash })
    }
}

/// The fence a controller keeps under `<data_dir>/node/` ([`FENCE_FILE`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceFile {
    /// Why: [`FenceReason::Superseded`] for a descendant record, [`FenceReason::Conflict`]
    /// for a sibling.
    pub kind: FenceReason,
    /// The record that fenced it.
    pub record: GenerationRecord,
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

    /// Writes the fence (private to the service account, replaced atomically).
    ///
    /// # Errors
    ///
    /// `cluster.node.files`.
    pub fn save(&self, data_dir: &Path) -> Result<(), ClusterError> {
        let dir = data_dir.join(NODE_DIR);
        crate::identity::create_private_dir(&dir)?;
        let part = dir.join(format!("{FENCE_FILE}.part"));
        write_private(&part, &to_cbor(self)?)?;
        let path = dir.join(FENCE_FILE);
        fs::rename(&part, &path).map_err(|error| files_error(&path, &error))
    }
}

fn files_error(path: &Path, error: &impl std::fmt::Display) -> ClusterError {
    ClusterError::new(
        "cluster.node.files",
        500,
        format!("{}: {error}", path.display()),
    )
    .with_param("path", path.display().to_string())
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
mod tests {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    fn body(number: u64, parent: Option<Digest>, forced: u64) -> GenerationBody {
        GenerationBody {
            layout: LAYOUT,
            number,
            parent,
            forced: NodeId(forced),
            fork: ForkPoint {
                term: 7,
                leader: 1,
                index: 88530,
                revision: Revision(88412),
                audit: ChainHead::default(),
            },
            superseded: vec![NodeId(1), NodeId(3)],
            at: Timestamp::from_unix_nanos(1_789_000_000_000_000_000).expect("time"),
            nonce: HexBytes(vec![7; 16]),
        }
    }

    #[test]
    fn the_body_layout_is_pinned() {
        let bytes = body(1, None, 2).canonical().expect("cbor");
        // The canonical CBOR of the body above: a map of eight fields in the canonical
        // key order; a change here is a change of the signed contract.
        assert_eq!(
            to_hex(&bytes),
            concat!(
                "a862617474323032362d30392d31305430303a32363a34305a64666f726ba5647465726d",
                "07656175646974a263736571006468617368582000000000000000000000000000000000",
                "0000000000000000000000000000000065696e6465781a000159d2666c65616465720168",
                "7265766973696f6e1a0001595c656e6f6e63655007070707070707070707070707070707",
                "66666f7263656402666c61796f757401666e756d6265720166706172656e74f66a737570",
                "65727365646564820103",
            )
        );
    }

    #[test]
    fn a_claim_round_trips_and_generation_zero_is_absent() {
        let hash = Digest([0xab; 32]);
        let claim = Claim::of(4, &hash);
        let text = claim.render().expect("a claim");
        assert_eq!(text, format!("4:{}", "ab".repeat(16)));
        assert!(text.len() < 64);
        assert_eq!(Claim::parse(&text), Some(claim));
        assert_eq!(Claim::ZERO.render(), None);
        for bad in ["", "4", "x:ab", "4:abc", &format!("4:{}", "ab".repeat(17))] {
            assert_eq!(Claim::parse(bad), None, "{bad}");
        }
    }

    struct Ca {
        root: CertificateDer<'static>,
        issuer: rcgen::Issuer<'static, KeyPair>,
    }

    fn ca() -> Ca {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&key).expect("root");
        Ca {
            root: root.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn leaf(ca: &Ca, node: u64, role: &str) -> (Vec<CertificateDer<'static>>, SecretBytes) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![
            rcgen::SanType::URI(format!("urn:tenko:node:{node}").try_into().expect("uri")),
            rcgen::SanType::URI(format!("urn:tenko:role:{role}").try_into().expect("uri")),
        ];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let cert = params.signed_by(&key, &ca.issuer).expect("leaf");
        (
            vec![cert.der().clone()],
            SecretBytes::from_slice(&key.serialize_der()),
        )
    }

    #[test]
    fn a_signed_record_verifies_and_round_trips() {
        let ca = ca();
        let (chain, key) = leaf(&ca, 2, "controller");
        let record = GenerationRecord::sign(&body(1, None, 2), &chain, &key).expect("sign");
        let decoded = GenerationRecord::decode(&record.encode().expect("cbor")).expect("decode");
        assert_eq!(decoded, record);
        let signed = decoded.verify(&ca.root).expect("verify");
        assert_eq!(signed.body, body(1, None, 2));
        assert_eq!(signed.signer.node, NodeId(2));
        assert_eq!(signed.hash, record.hash());
    }

    /// The refusal of a record, with its code and the reason in its detail.
    #[track_caller]
    fn refused<T: std::fmt::Debug>(result: Result<T, ClusterError>, why: &str) {
        let error = result.expect_err(why);
        assert_eq!(error.code(), codes::RECORD_INVALID);
        assert!(error.detail().contains(why), "{}", error.detail());
    }

    #[test]
    fn a_forged_record_does_not_verify() {
        let ca = ca();
        let (chain, key) = leaf(&ca, 2, "controller");
        let good = GenerationRecord::sign(&body(1, None, 2), &chain, &key).expect("sign");

        // The body changed after signing.
        let mut changed = good.clone();
        changed.body = HexBytes(body(9, None, 2).canonical().expect("cbor"));
        refused(changed.verify(&ca.root), "signature does not verify");
        // Signed by a certificate of another CA.
        let other = super::tests::ca();
        refused(good.verify(&other.root), "certificate does not verify");
        // Signed by a certificate that is not a controller's.
        let (probe_chain, probe_key) = leaf(&ca, 2, "probe");
        let probe =
            GenerationRecord::sign(&body(1, None, 2), &probe_chain, &probe_key).expect("sign");
        refused(
            probe.verify(&ca.root),
            "not signed by the forced controller",
        );
        // Signed by another controller than the one the body names.
        let (chain3, key3) = leaf(&ca, 3, "controller");
        let other_signer = GenerationRecord::sign(&body(1, None, 2), &chain3, &key3).expect("sign");
        refused(
            other_signer.verify(&ca.root),
            "not signed by the forced controller",
        );
        // Garbage and oversized input.
        refused(GenerationRecord::decode(&[0xff; 8]), "does not decode");
        refused(
            GenerationRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]),
            "too large",
        );
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the tests build bodies inline"
    )]
    fn signed(ca: &Ca, body: GenerationBody) -> Signed {
        let (chain, key) = leaf(ca, body.forced.0, "controller");
        GenerationRecord::sign(&body, &chain, &key)
            .expect("sign")
            .verify(&ca.root)
            .expect("verify")
    }

    #[test]
    fn relations_follow_the_parent() {
        let ca = ca();
        let first = signed(&ca, body(1, None, 2));
        assert_eq!(relation(None, &first), Relation::Descendant);
        assert_eq!(relation(Some(&first), &first), Relation::Same);
        let child = signed(&ca, body(2, Some(first.hash), 3));
        assert_eq!(relation(Some(&first), &child), Relation::Descendant);
        let twin = signed(&ca, body(1, None, 3));
        assert_eq!(relation(Some(&first), &twin), Relation::Sibling);
        let later_twin = signed(&ca, body(2, None, 3));
        assert_eq!(relation(Some(&first), &later_twin), Relation::Sibling);
        assert_eq!(relation(Some(&child), &first), Relation::Unrelated);
        assert_eq!(relation(Some(&later_twin), &first), Relation::Unrelated);
    }

    #[test]
    fn the_suggested_winner_is_one_total_order() {
        let ca = ca();
        let a = signed(&ca, body(1, None, 2));
        let mut fresher = body(1, None, 3);
        fresher.fork.index += 1;
        let b = signed(&ca, fresher);
        let higher = signed(&ca, body(2, None, 5));
        assert_eq!(suggested_winner(&higher, &a), Ordering::Less);
        assert_eq!(suggested_winner(&b, &a), Ordering::Less);
        assert_eq!(suggested_winner(&a, &b), Ordering::Greater);
        // Equal number and fork: the lower node id, then the lower hash; never equal.
        let c = signed(&ca, body(1, None, 2));
        let mut other_nonce = body(1, None, 2);
        other_nonce.nonce = HexBytes(vec![8; 16]);
        let d = signed(&ca, other_nonce);
        let order = suggested_winner(&c, &d);
        assert_ne!(order, Ordering::Equal);
        assert_eq!(suggested_winner(&d, &c), order.reverse());
        assert_eq!(order, c.hash.cmp(&d.hash));
    }

    #[test]
    fn the_fence_file_round_trips_and_an_unknown_kind_is_strict() {
        let ca = ca();
        let dir = tenko_core::testing::TempDir::new("generation-fence");
        assert_eq!(FenceFile::load(dir.path()).expect("load"), None);
        let fence = FenceFile {
            kind: FenceReason::Superseded,
            record: signed(&ca, body(1, None, 2)).record,
            at: Timestamp::now(),
        };
        fence.save(dir.path()).expect("save");
        assert_eq!(FenceFile::load(dir.path()).expect("load"), Some(fence));
        let unknown: FenceReason = from_cbor(&to_cbor("later_kind").expect("cbor")).expect("kind");
        assert_eq!(unknown.code(), codes::SUPERSEDED);
        fs::write(dir.path().join(NODE_DIR).join(FENCE_FILE), b"\xff").expect("write");
        let error = FenceFile::load(dir.path()).expect_err("an unreadable fence");
        assert_eq!(error.code(), "cluster.node.files");
        assert!(error.detail().contains(FENCE_FILE), "{}", error.detail());
    }

    #[test]
    fn the_superseded_mark_layout_is_pinned() {
        let mark = SupersededMark {
            generation: 1,
            record: Digest([1; 32]),
            rejoin: true,
        };
        let bytes = to_cbor(&mark).expect("cbor");
        assert_eq!(
            to_hex(&bytes),
            format!(
                "a36a67656e65726174696f6e01667265636f72645820{}6672656a6f696ef5",
                "01".repeat(32)
            )
        );
        assert_eq!(from_cbor::<SupersededMark>(&bytes).expect("decode"), mark);
    }

    #[test]
    fn the_record_and_fence_layouts_are_pinned() {
        let record = GenerationRecord {
            body: HexBytes(vec![0xa0]),
            signature: HexBytes(vec![9; 4]),
            chain: vec![HexBytes(vec![1, 2])],
        };
        assert_eq!(
            to_hex(&record.encode().expect("cbor")),
            "a364626f647941a0697369676e6174757265440909090965636861696e81420102"
        );
        let fence = FenceFile {
            kind: FenceReason::Conflict,
            record,
            at: Timestamp::from_unix_nanos(1_789_000_000_000_000_000).expect("time"),
        };
        assert_eq!(
            to_hex(&to_cbor(&fence).expect("cbor")),
            concat!(
                "a3646b696e6468636f6e666c696374667265636f7264a364626f647941a0697369676e",
                "6174757265440909090965636861696e8142010262617474323032362d30392d313054",
                "30303a32363a34305a",
            )
        );
    }
}
