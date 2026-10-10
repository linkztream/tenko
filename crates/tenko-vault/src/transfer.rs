//! The sealed transfer of KEK generations between the controllers of one installation
//! (S3-Q5, ADR 0014, R22).
//!
//! An installation has one set of KEK generations. A controller that joins receives every
//! generation from a member over the cluster port (mutual TLS 1.3), sealed to a one-time
//! X25519 key that only the joiner holds, and then seals each generation with its own
//! provider ([`KekConfig::import`](crate::KekConfig::import)), keeping the identifiers so
//! that every envelope unwraps on every controller. A member that missed a generation (it
//! was stopped during an online rotation) fetches it the same way.
//!
//! # Construction
//!
//! The construction follows HPKE in base mode (RFC 9180) with DHKEM(X25519),
//! HKDF-SHA-256 and AES-256-GCM, all from `aws-lc-rs`, in a fixed, self-describing frame:
//!
//! ```text
//! recipient:  TransferKey::generate()              -> sk_R, pk_R (sent in the request)
//! sender:     sk_E, enc = X25519 key pair           (fresh for every transfer)
//!             dh   = X25519(sk_E, pk_R)             (refused when all zero)
//!             prk  = HKDF-Extract(salt = "tenko-kek-transfer/1", dh)
//!             key  = HKDF-Expand(prk, "tenko-kek-transfer/1 key\0" | enc | pk_R
//!                                     | context length u32 | context, 32)
//!             aad  = header | pk_R | context length u32 | context
//!             sealed = header | AES-256-GCM(key, nonce, payload, aad) | tag
//!
//! header  = "TKXF" | version u8 = 1 | enc (32) | nonce (12)
//! payload = "TKXP" | version u8 = 1 | count u8 (1..=64)
//!           | count × (id length u8 (1..=64) | id (ASCII) | key (32))
//! ```
//!
//! The generations are listed oldest first with the sender's active generation last. The
//! `context` (built by [`join_context`] or [`fetch_context`]) binds the transfer to the
//! joining node and its enrolment token, or to the fetching member, so a transfer recorded
//! for one purpose does not open for another. The sender's ephemeral key is dropped after
//! sealing and the recipient's [`TransferKey`] is consumed by [`TransferKey::open`]: a
//! sealed transfer opens once, on one host.
//!
//! The material never appears in a log line, an error, an audit record or the store: the
//! audit record [`TRANSFER_AUDIT`] names the generation identifiers only. The cluster
//! service that answers `Cluster.TransferKek` (WP3.1a) checks the caller's certificate and
//! enrolment, refuses a second transfer for the same join token, and writes that audit
//! record.

use std::fmt;

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    hkdf,
    rand::SystemRandom,
};
use tenko_core::{NodeId, audit::AuditAction};
use zeroize::Zeroizing;

use crate::{
    VaultError,
    error::TransferFailure,
    kek::{DataKey, KekRing, MAX_KEK_ID_LEN, valid_kek_id},
};

/// The format of a sealed transfer, carried beside it (`TransferKekResponse.format`).
pub const FORMAT: &str = "tenko-kek-transfer/x25519-hkdf-sha256-aes256gcm/1";

/// The audit action of a transfer: the record names the generation identifiers, the
/// recipient node and the enrolment, never the material.
pub const TRANSFER_AUDIT: AuditAction = AuditAction::from_static("vault.kek.transfer");

/// Length of an X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The most generations one transfer carries.
pub const MAX_GENERATIONS: usize = 64;

/// The largest sealed transfer a recipient accepts, in bytes.
pub const MAX_SEALED_LEN: usize =
    HEADER_LEN + PAYLOAD_HEADER_LEN + MAX_GENERATIONS * (1 + MAX_KEK_ID_LEN + DataKey::LEN) + 16;

const SEALED_MAGIC: &[u8; 4] = b"TKXF";
const PAYLOAD_MAGIC: &[u8; 4] = b"TKXP";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + PUBLIC_KEY_LEN + NONCE_LEN;
const PAYLOAD_HEADER_LEN: usize = 4 + 1 + 1;
const TAG_LEN: usize = 16;
const SALT: &[u8] = b"tenko-kek-transfer/1";
const KEY_LABEL: &[u8] = b"tenko-kek-transfer/1 key\0";
const JOIN_CONTEXT: &[u8] = b"tenko-kek-transfer/1\0";
const FETCH_CONTEXT: &[u8] = b"tenko-kek-fetch/1\0";

/// The context of a join: `"tenko-kek-transfer/1\0"`, the joining node's id (u64,
/// big-endian) and the 16 bytes of the join token's UUID. Both sides build it from what
/// the enrolment recorded.
pub fn join_context(node: NodeId, token: [u8; 16]) -> Vec<u8> {
    let mut context = Vec::with_capacity(JOIN_CONTEXT.len() + 8 + 16);
    context.extend_from_slice(JOIN_CONTEXT);
    context.extend_from_slice(&node.0.to_be_bytes());
    context.extend_from_slice(&token);
    context
}

/// The context of a member fetching the generations it lacks (start step 3, an online
/// rotation): `"tenko-kek-fetch/1\0"` and the member's node id (u64, big-endian).
pub fn fetch_context(node: NodeId) -> Vec<u8> {
    let mut context = Vec::with_capacity(FETCH_CONTEXT.len() + 8);
    context.extend_from_slice(FETCH_CONTEXT);
    context.extend_from_slice(&node.0.to_be_bytes());
    context
}

/// One KEK generation in transit. `Debug` shows the identifier only; the material is
/// zeroized on drop.
#[derive(Clone)]
pub struct TransferredKek {
    /// The KEK identifier, as envelopes name it.
    pub id: String,
    /// The 256-bit key.
    pub material: Zeroizing<[u8; DataKey::LEN]>,
}

impl fmt::Debug for TransferredKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferredKek")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A sealed transfer as the sender answers it; maps one to one onto
/// `TransferKekResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKeks {
    /// [`FORMAT`].
    pub format: &'static str,
    /// The sealed frame (see the module documentation).
    pub sealed: Vec<u8>,
    /// The identifiers of the generations inside, oldest first, the active one last.
    pub generation_ids: Vec<String>,
}

/// A recipient's one-time X25519 key pair. It is never stored; [`open`](TransferKey::open)
/// consumes it, and the private key is freed (and cleared by `aws-lc`) on drop.
pub struct TransferKey {
    private: EphemeralPrivateKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl fmt::Debug for TransferKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferKey").finish_non_exhaustive()
    }
}

impl TransferKey {
    /// A fresh key pair.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] if the random number generator fails.
    pub fn generate() -> Result<Self, VaultError> {
        let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
            .map_err(|_| crypto("transfer key generation"))?;
        let public = public_bytes(&private)?;
        Ok(Self { private, public })
    }

    /// The public key, sent as `TransferKekRequest.ephemeral_public_key`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Opens what [`seal_ring`] produced for this key with the same `context`. Returns the
    /// generations oldest first, the sender's active one last.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transfer`] with [`TransferFailure::Format`] for another format or
    /// version, [`TransferFailure::Malformed`] for a frame or payload that does not parse,
    /// and [`TransferFailure::Integrity`] when it was sealed to another key, under another
    /// context, or altered.
    pub fn open(
        self,
        format: &str,
        sealed: &[u8],
        context: &[u8],
    ) -> Result<Vec<TransferredKek>, VaultError> {
        if format != FORMAT {
            return Err(VaultError::transfer(TransferFailure::Format));
        }
        let frame = Frame::parse(sealed)?;
        let peer = UnparsedPublicKey::new(&X25519, frame.enc);
        let key = agreement::agree_ephemeral(
            self.private,
            peer,
            VaultError::transfer(TransferFailure::Integrity),
            |dh| derive(dh, frame.enc, &self.public, context),
        )?;
        let aad = aad(frame.header, &self.public, context);
        let mut buffer = Zeroizing::new(frame.ciphertext.to_vec());
        let plain_len = key
            .open_in_place(
                Nonce::assume_unique_for_key(frame.nonce),
                Aad::from(aad),
                buffer.as_mut_slice(),
            )
            .map_err(|_| VaultError::transfer(TransferFailure::Integrity))?
            .len();
        decode_payload(&buffer[..plain_len])
    }
}

/// Seals every generation of `ring` to `recipient` (a 32-byte X25519 public key): the
/// generations other than the active one in the ring's order (oldest first, then a
/// generation received for an online rotation that is not active yet), then the active
/// one. `context` goes into the key derivation and the AEAD additional data.
///
/// # Errors
///
/// [`VaultError::Transfer`] with [`TransferFailure::PublicKey`] for a key that is not a
/// usable X25519 public key, [`TransferFailure::NotExportable`] when a generation cannot
/// leave its provider, [`TransferFailure::Malformed`] for an identifier the format cannot
/// carry or more than [`MAX_GENERATIONS`]; [`VaultError::Crypto`] if a primitive fails.
pub fn seal_ring(
    ring: &KekRing,
    recipient: &[u8],
    context: &[u8],
) -> Result<SealedKeks, VaultError> {
    let recipient: [u8; PUBLIC_KEY_LEN] = recipient
        .try_into()
        .map_err(|_| VaultError::transfer(TransferFailure::PublicKey))?;
    let active = ring.active();
    let mut generations = Vec::new();
    for kek in ring
        .generations()
        .filter(|kek| kek.id() != active.id())
        .chain(std::iter::once(active))
    {
        let material = kek
            .export_material()
            .ok_or_else(|| VaultError::transfer(TransferFailure::NotExportable))?;
        generations.push(TransferredKek {
            id: kek.id().to_owned(),
            material,
        });
    }
    seal_generations(&generations, &recipient, context)
}

/// Seals `generations` (oldest first, the active one last) to `recipient`.
fn seal_generations(
    generations: &[TransferredKek],
    recipient: &[u8; PUBLIC_KEY_LEN],
    context: &[u8],
) -> Result<SealedKeks, VaultError> {
    let payload = encode_payload(generations)?;
    let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
        .map_err(|_| crypto("transfer key generation"))?;
    let enc = public_bytes(&private)?;
    let peer = UnparsedPublicKey::new(&X25519, recipient);
    let key = agreement::agree_ephemeral(
        private,
        peer,
        VaultError::transfer(TransferFailure::PublicKey),
        |dh| derive(dh, &enc, recipient, context),
    )?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| crypto("random nonce"))?;
    let mut sealed = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    sealed.extend_from_slice(SEALED_MAGIC);
    sealed.push(VERSION);
    sealed.extend_from_slice(&enc);
    sealed.extend_from_slice(&nonce);
    let aad = aad(&sealed, recipient, context);
    let mut body = Zeroizing::new(Vec::with_capacity(payload.len() + TAG_LEN));
    body.extend_from_slice(&payload);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut *body,
    )
    .map_err(|_| crypto("seal key transfer"))?;
    sealed.extend_from_slice(&body);
    Ok(SealedKeks {
        format: FORMAT,
        sealed,
        generation_ids: generations.iter().map(|kek| kek.id.clone()).collect(),
    })
}

/// The parts of a sealed frame.
struct Frame<'a> {
    header: &'a [u8],
    enc: &'a [u8; PUBLIC_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

impl<'a> Frame<'a> {
    fn parse(sealed: &'a [u8]) -> Result<Self, VaultError> {
        let malformed = || VaultError::transfer(TransferFailure::Malformed);
        if sealed.len() > MAX_SEALED_LEN {
            return Err(malformed());
        }
        let (header, ciphertext) = sealed.split_at_checked(HEADER_LEN).ok_or_else(malformed)?;
        let rest = header
            .strip_prefix(SEALED_MAGIC.as_slice())
            .ok_or_else(malformed)?;
        let (&version, rest) = rest.split_first().ok_or_else(malformed)?;
        if version != VERSION {
            return Err(VaultError::transfer(TransferFailure::Format));
        }
        let (enc, rest) = rest
            .split_first_chunk::<PUBLIC_KEY_LEN>()
            .ok_or_else(malformed)?;
        let nonce: [u8; NONCE_LEN] = rest.try_into().map_err(|_| malformed())?;
        // The smallest payload is one generation with a one-byte identifier.
        if ciphertext.len() < PAYLOAD_HEADER_LEN + 1 + 1 + DataKey::LEN + TAG_LEN {
            return Err(malformed());
        }
        Ok(Self {
            header,
            enc,
            nonce,
            ciphertext,
        })
    }
}

/// Checks the frame of a sealed transfer without opening it: magic, version and lengths.
/// For the fuzz target and for callers that want to refuse junk before any key agreement.
///
/// # Errors
///
/// As [`TransferKey::open`] for a frame that does not parse.
pub fn check_frame(sealed: &[u8]) -> Result<(), VaultError> {
    Frame::parse(sealed).map(drop)
}

fn derive(
    dh: &[u8],
    enc: &[u8; PUBLIC_KEY_LEN],
    recipient: &[u8; PUBLIC_KEY_LEN],
    context: &[u8],
) -> Result<LessSafeKey, VaultError> {
    if dh.iter().all(|byte| *byte == 0) {
        return Err(VaultError::transfer(TransferFailure::PublicKey));
    }
    let context_len = context_len(context)?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(dh);
    let info: [&[u8]; 5] = [KEY_LABEL, enc, recipient, &context_len, context];
    let mut key = Zeroizing::new([0u8; 32]);
    prk.expand(&info, &AES_256_GCM)
        .and_then(|okm| okm.fill(key.as_mut()))
        .map_err(|_| crypto("transfer key derivation"))?;
    UnboundKey::new(&AES_256_GCM, key.as_ref())
        .map(LessSafeKey::new)
        .map_err(|_| crypto("transfer key setup"))
}

fn context_len(context: &[u8]) -> Result<[u8; 4], VaultError> {
    u32::try_from(context.len())
        .map(u32::to_be_bytes)
        .map_err(|_| VaultError::transfer(TransferFailure::Malformed))
}

fn aad(header: &[u8], recipient: &[u8; PUBLIC_KEY_LEN], context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + PUBLIC_KEY_LEN + 4 + context.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(recipient);
    aad.extend_from_slice(
        &u32::try_from(context.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(context);
    aad
}

fn public_bytes(private: &EphemeralPrivateKey) -> Result<[u8; PUBLIC_KEY_LEN], VaultError> {
    let public = private
        .compute_public_key()
        .map_err(|_| crypto("transfer public key"))?;
    public
        .as_ref()
        .try_into()
        .map_err(|_| crypto("transfer public key"))
}

fn crypto(operation: &'static str) -> VaultError {
    VaultError::Crypto { operation }
}

fn encode_payload(generations: &[TransferredKek]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let malformed = || VaultError::transfer(TransferFailure::Malformed);
    if generations.is_empty() || generations.len() > MAX_GENERATIONS {
        return Err(malformed());
    }
    let count = u8::try_from(generations.len()).map_err(|_| malformed())?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        PAYLOAD_HEADER_LEN + generations.len() * (1 + MAX_KEK_ID_LEN + DataKey::LEN),
    ));
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.push(VERSION);
    out.push(count);
    for (index, kek) in generations.iter().enumerate() {
        if !valid_kek_id(&kek.id) || generations[..index].iter().any(|seen| seen.id == kek.id) {
            return Err(malformed());
        }
        out.push(u8::try_from(kek.id.len()).map_err(|_| malformed())?);
        out.extend_from_slice(kek.id.as_bytes());
        out.extend_from_slice(kek.material.as_ref());
    }
    Ok(out)
}

/// Decodes the payload of an opened transfer.
fn decode_payload(bytes: &[u8]) -> Result<Vec<TransferredKek>, VaultError> {
    let malformed = || VaultError::transfer(TransferFailure::Malformed);
    let rest = bytes
        .strip_prefix(PAYLOAD_MAGIC.as_slice())
        .ok_or_else(malformed)?;
    let (&version, rest) = rest.split_first().ok_or_else(malformed)?;
    if version != VERSION {
        return Err(VaultError::transfer(TransferFailure::Format));
    }
    let (&count, mut rest) = rest.split_first().ok_or_else(malformed)?;
    let count = usize::from(count);
    if count == 0 || count > MAX_GENERATIONS {
        return Err(malformed());
    }
    let mut generations: Vec<TransferredKek> = Vec::with_capacity(count);
    for _ in 0..count {
        let (&len, tail) = rest.split_first().ok_or_else(malformed)?;
        let (id, tail) = tail
            .split_at_checked(usize::from(len))
            .ok_or_else(malformed)?;
        let id = std::str::from_utf8(id).map_err(|_| malformed())?;
        if !valid_kek_id(id) || generations.iter().any(|seen| seen.id == id) {
            return Err(malformed());
        }
        let (key, tail) = tail
            .split_first_chunk::<{ DataKey::LEN }>()
            .ok_or_else(malformed)?;
        generations.push(TransferredKek {
            id: id.to_owned(),
            material: Zeroizing::new(*key),
        });
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok(generations)
}

/// Entry points for the fuzz target `kek_transfer` (not part of the API).
#[doc(hidden)]
pub mod fuzzing {
    use super::{TransferredKek, VaultError, decode_payload};

    /// Decodes an opened payload.
    ///
    /// # Errors
    ///
    /// As the recipient's decoding.
    pub fn decode(bytes: &[u8]) -> Result<Vec<TransferredKek>, VaultError> {
        decode_payload(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::kek::{KekProvider, MemKek};

    fn kek(id: &str, byte: u8) -> Arc<dyn KekProvider> {
        Arc::new(MemKek::from_bytes(id, &Zeroizing::new([byte; 32])))
    }

    fn ring() -> KekRing {
        KekRing::new(kek("dpapi-2-0000beef", 2))
            .with_retired(kek("dpapi-1-0000cafe", 1))
            .with_newer(kek("dpapi-3-0000f00d", 3))
    }

    #[test]
    fn a_transfer_round_trips_with_the_active_generation_last() {
        let recipient = TransferKey::generate().expect("key");
        let context = join_context(NodeId(1001), [7; 16]);
        let sealed = seal_ring(&ring(), &recipient.public_key(), &context).expect("seal");
        assert_eq!(sealed.format, FORMAT);
        assert_eq!(
            sealed.generation_ids,
            ["dpapi-1-0000cafe", "dpapi-3-0000f00d", "dpapi-2-0000beef"]
        );
        let opened = recipient
            .open(sealed.format, &sealed.sealed, &context)
            .expect("open");
        let ids: Vec<&str> = opened.iter().map(|kek| kek.id.as_str()).collect();
        assert_eq!(ids, sealed.generation_ids);
        assert_eq!(opened[0].material.as_ref(), &[1; 32]);
        assert_eq!(opened[2].material.as_ref(), &[2; 32]);
        for byte in 1..=3u8 {
            assert!(
                !sealed.sealed.windows(32).any(|w| w == [byte; 32]),
                "the material shows in the sealed frame"
            );
        }
        assert!(!format!("{opened:?}").contains("material: ["));
    }

    #[test]
    fn another_key_context_or_format_does_not_open() {
        let recipient = TransferKey::generate().expect("key");
        let public = recipient.public_key();
        let context = fetch_context(NodeId(1002));
        let sealed = seal_ring(&ring(), &public, &context).expect("seal");
        let other = TransferKey::generate().expect("key");
        let integrity = VaultError::transfer(TransferFailure::Integrity);
        assert_eq!(
            other
                .open(FORMAT, &sealed.sealed, &context)
                .expect_err("key"),
            integrity
        );
        let wrong_context = TransferKey::generate().expect("key");
        let sealed_for = seal_ring(&ring(), &wrong_context.public_key(), &context).expect("seal");
        assert_eq!(
            wrong_context
                .open(FORMAT, &sealed_for.sealed, &fetch_context(NodeId(1003)))
                .expect_err("context"),
            integrity
        );
        assert_eq!(
            recipient
                .open("tenko-kek-transfer/other/1", &sealed.sealed, &context)
                .expect_err("format"),
            VaultError::transfer(TransferFailure::Format)
        );
    }

    #[test]
    fn every_altered_byte_is_refused() {
        let context = join_context(NodeId(1001), [1; 16]);
        let probe = TransferKey::generate().expect("key");
        let sealed = seal_ring(&ring(), &probe.public_key(), &context).expect("seal");
        drop(probe);
        for at in [
            0,
            4,
            5,
            20,
            HEADER_LEN - 1,
            HEADER_LEN,
            sealed.sealed.len() - 1,
        ] {
            let mut altered = sealed.sealed.clone();
            altered[at] ^= 0x01;
            // A fresh key would not open the original either; the point is that nothing
            // panics and every alteration is refused.
            let key = TransferKey::generate().expect("key");
            assert!(key.open(FORMAT, &altered, &context).is_err());
        }
        let recipient = TransferKey::generate().expect("key");
        let sealed = seal_ring(&ring(), &recipient.public_key(), &context).expect("seal");
        let mut altered = sealed.sealed.clone();
        let last = altered.len() - 1;
        altered[last] ^= 0x80;
        assert_eq!(
            recipient.open(FORMAT, &altered, &context).expect_err("tag"),
            VaultError::transfer(TransferFailure::Integrity)
        );
    }

    #[test]
    fn bad_public_keys_and_frames_are_refused() {
        let context = fetch_context(NodeId(5));
        assert_eq!(
            seal_ring(&ring(), &[9; 31], &context).expect_err("short"),
            VaultError::transfer(TransferFailure::PublicKey)
        );
        // The all-zero point gives an all-zero shared secret.
        assert!(seal_ring(&ring(), &[0; 32], &context).is_err());
        assert!(check_frame(b"").is_err());
        assert!(check_frame(b"TKXF").is_err());
        let mut frame = vec![0u8; HEADER_LEN + 60];
        frame[..4].copy_from_slice(SEALED_MAGIC);
        frame[4] = 2;
        assert_eq!(
            check_frame(&frame).expect_err("version"),
            VaultError::transfer(TransferFailure::Format)
        );
        frame[4] = VERSION;
        assert!(check_frame(&frame).is_ok());
        assert!(check_frame(&vec![0u8; MAX_SEALED_LEN + 1]).is_err());
    }

    #[test]
    fn payloads_decode_strictly() {
        let generations = vec![
            TransferredKek {
                id: "a".to_owned(),
                material: Zeroizing::new([1; 32]),
            },
            TransferredKek {
                id: "b-2".to_owned(),
                material: Zeroizing::new([2; 32]),
            },
        ];
        let encoded = encode_payload(&generations).expect("encode");
        let decoded = decode_payload(&encoded).expect("decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].id, "b-2");
        assert!(decode_payload(&encoded[..encoded.len() - 1]).is_err());
        let mut longer = encoded.to_vec();
        longer.push(0);
        assert!(decode_payload(&longer).is_err());
        let duplicate = vec![generations[0].clone(), generations[0].clone()];
        assert!(encode_payload(&duplicate).is_err());
        assert!(encode_payload(&[]).is_err());
        let bad_id = vec![TransferredKek {
            id: "a/b".to_owned(),
            material: Zeroizing::new([0; 32]),
        }];
        assert!(encode_payload(&bad_id).is_err());
        let mut zero_count = encoded.to_vec();
        zero_count[5] = 0;
        assert!(decode_payload(&zero_count).is_err());
    }

    #[test]
    fn a_provider_without_material_cannot_be_transferred() {
        #[derive(Debug)]
        struct Sealed;
        impl KekProvider for Sealed {
            fn id(&self) -> &'static str {
                "hsm-1"
            }
            fn protection(&self) -> crate::KekProtection {
                crate::KekProtection::Memory
            }
            fn wrap(&self, _: &DataKey, _: &[u8]) -> Result<Vec<u8>, VaultError> {
                Err(crypto("wrap"))
            }
            fn unwrap(&self, _: &[u8], _: &[u8]) -> Result<DataKey, VaultError> {
                Err(crypto("unwrap"))
            }
        }
        let recipient = TransferKey::generate().expect("key");
        assert_eq!(
            seal_ring(
                &KekRing::new(Arc::new(Sealed)),
                &recipient.public_key(),
                b"context"
            )
            .expect_err("not exportable"),
            VaultError::transfer(TransferFailure::NotExportable)
        );
    }
}
