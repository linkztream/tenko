//! Pending ceremonies between their start and finish requests: second-factor challenges,
//! WebAuthn ceremonies and TOTP enrolments.
//!
//! # Sealed challenge ids
//!
//! A ceremony is not stored anywhere. [`Ceremonies::open`] seals the pending state into the
//! opaque challenge id itself: `base64url(version || nonce || ciphertext_and_tag)`, AES-256-GCM
//! under a [`CeremonyKey`], with the CBOR of the state (the expiry, a random single-use key
//! and the [`Pending`] itself, TOTP seed included) as plaintext. Any controller that holds the
//! same key opens the id, so a ceremony started on one controller finishes on another behind
//! a load balancer without sticky sessions. Nothing is written to the store when a ceremony
//! starts: an unauthenticated client can start a WebAuthn login at will, and that must not
//! reach the replicated log. An id that does not open (unknown key, damaged, truncated,
//! another version, expired) is [`AuthError::ChallengeInvalid`], never anything more
//! specific, because the id comes from a client that is not authenticated.
//!
//! # The key
//!
//! [`CeremonyKey::from_cluster_key`] derives the key from the installation's cluster key
//! (HKDF-SHA-256), so every controller derives the same one. [`CeremonyKey::random`] makes a
//! key that only this process knows: [`Ceremonies::new`] uses it, which is the single
//! controller case, where a restart cancels open ceremonies and the user starts again.
//! [`Ceremonies::set_key`] replaces the key at run time; ids sealed under the old key stop
//! opening.
//!
//! # Single use
//!
//! On one controller, [`Ceremonies::take`] remembers every ceremony it handed out (until the
//! ceremony expires, bounded by the capacity) and refuses a replay. Across controllers the
//! use is recorded in the replicated store table [`USED_CHALLENGES`]: the finishing handler
//! calls [`Ceremonies::take_staged`] with a read view, which refuses a ceremony whose row is
//! already there, and stages the returned [`StagedUse`] into the write batch that completes
//! the ceremony (the session, the credential, the enrolment). The ceremony is consumed
//! exactly when that batch commits; a replay on another controller is refused by the row, or
//! by the version precondition of the batch when both race. [`purge_used`] removes the rows
//! of expired ceremonies; the leader runs it hourly as a leader-only service.
//!
//! A wrong second-factor code is the one case that keeps a ceremony open:
//! [`Ceremonies::put_back`] stores the pending state with its attempt counter on this
//! controller only, under the id as given, so the same id works once more here. Another
//! controller opens the id with the counter it was sealed with.
//!
//! # Clocks
//!
//! A ceremony expires by the clock of the controller that finishes it, against the expiry
//! sealed into the id by the controller that started it. Clock skew between controllers
//! therefore shortens or lengthens the five minutes of [`CEREMONY_TTL`] by the skew.

use std::{
    collections::HashMap,
    fmt,
    sync::{Mutex, MutexGuard, PoisonError, RwLock},
    time::Duration,
};

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf,
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    AuthStrength, Principal, SessionId, SystemComponent, Timestamp, UserId, table::TableDef,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, WriteBatch,
};
use zeroize::Zeroizing;

use crate::{
    encoding::{base64url_decode, base64url_encode},
    error::AuthError,
    random,
};

/// How long a ceremony stays open.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Wrong second-factor codes accepted per challenge before it is dropped.
pub const MAX_CODE_ATTEMPTS: u32 = 5;

/// The store table of used ceremonies, by ceremony key (see [`StagedUse`]).
pub const USED_CHALLENGES: TableDef<String, UsedChallenge> = TableDef::new("auth.used_challenges");

/// HKDF-SHA-256 salt of the subkeys of the cluster key.
const CLUSTER_KEY_SALT: &[u8] = b"tenko cluster key v1";
/// HKDF info of the ceremony sealing key.
const CEREMONY_KEY_INFO: &[u8] = b"ceremony sealing";
/// Additional authenticated data of a sealed challenge id.
const SEAL_AAD: &[u8] = b"tenko ceremony v1";
/// The first byte of a sealed challenge id.
const SEAL_VERSION: u8 = 1;
/// The longest challenge id (in characters) that is even tried: ids come from clients that
/// are not authenticated.
const MAX_ID_LEN: usize = 4096;
/// Size of the single-use key in a sealed ceremony (random bytes).
const CEREMONY_KEY_LEN: usize = 16;
/// Rows read per page by [`purge_used`].
const PURGE_PAGE: usize = 1_000;

/// What a pending ceremony remembers.
#[derive(Clone)]
pub enum Pending {
    /// The password was correct; a second factor is required.
    SecondFactor {
        /// The user.
        user: UserId,
        /// The strength of the first factor (PIN or password).
        first: AuthStrength,
        /// Wrong codes so far.
        attempts: u32,
    },
    /// A WebAuthn login.
    WebAuthnLogin {
        /// The challenge.
        challenge: [u8; 32],
        /// The expected user, when the login named one or continues a password login.
        user: Option<UserId>,
        /// Whether the allow list was empty (a discoverable login needs the user handle).
        discoverable: bool,
        /// Whether the login continues a password login (the passkey is a second factor).
        continuation: bool,
    },
    /// A WebAuthn registration for a signed-in user.
    WebAuthnRegister {
        /// The challenge.
        challenge: [u8; 32],
        /// The user.
        user: UserId,
        /// The session that started it.
        session: SessionId,
        /// The label for the new credential.
        label: String,
        /// Whether a hardware security key with attestation was requested.
        hardware_key: bool,
    },
    /// A TOTP enrolment: the new seed until the user proves it with a code.
    TotpEnrolment {
        /// The user.
        user: UserId,
        /// The session that started it.
        session: SessionId,
        /// The seed. Zeroized on drop.
        secret: Zeroizing<Vec<u8>>,
    },
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::SecondFactor { .. } => "SecondFactor",
            Self::WebAuthnLogin { .. } => "WebAuthnLogin",
            Self::WebAuthnRegister { .. } => "WebAuthnRegister",
            Self::TotpEnrolment { .. } => "TotpEnrolment",
        };
        write!(f, "Pending::{kind}(<redacted>)")
    }
}

/// The key that seals ceremonies into challenge ids: 32 bytes for AES-256-GCM, zeroized on
/// drop.
#[derive(Clone)]
pub struct CeremonyKey(Zeroizing<[u8; 32]>);

/// The output length of the HKDF expansion of [`CeremonyKey`].
struct KeyLen;

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        32
    }
}

impl CeremonyKey {
    /// The ceremony key of an installation: HKDF-SHA-256 over the cluster key, with salt
    /// `tenko cluster key v1` and info `ceremony sealing`. Every controller derives the same
    /// key from the same cluster key.
    ///
    /// # Panics
    ///
    /// Never: HKDF-SHA-256 yields up to 8,160 bytes.
    pub fn from_cluster_key(cluster_key: &[u8; 32]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, CLUSTER_KEY_SALT).extract(cluster_key);
        let mut key = Zeroizing::new([0_u8; 32]);
        prk.expand(&[CEREMONY_KEY_INFO], KeyLen)
            .and_then(|okm| okm.fill(&mut key[..]))
            .expect("HKDF-SHA-256 yields 32 bytes");
        Self(key)
    }

    /// A key that only this process knows.
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] if the random source fails.
    pub fn random() -> Result<Self, AuthError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        random::fill(&mut key[..])?;
        Ok(Self(key))
    }

    fn cipher(&self) -> Result<LessSafeKey, AuthError> {
        UnboundKey::new(&AES_256_GCM, &self.0[..])
            .map(LessSafeKey::new)
            .map_err(|_| AuthError::internal("ceremony key setup failed"))
    }

    /// Seals a ceremony into a challenge id.
    fn seal(&self, sealed: &Sealed) -> Result<String, AuthError> {
        // Room for the CBOR, the tag and a little more, so the plaintext (it holds the TOTP
        // seed) is not moved to a bigger allocation that is then left behind unzeroized.
        let capacity = 256 + AES_256_GCM.tag_len() + sealed.pending.size_hint();
        let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
        ciborium::into_writer(sealed, &mut *buffer)
            .map_err(|_| AuthError::internal("ceremony encoding failed"))?;
        let nonce = random::array::<NONCE_LEN>()?;
        self.cipher()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(SEAL_AAD),
                &mut *buffer,
            )
            .map_err(|_| AuthError::internal("ceremony sealing failed"))?;
        let mut id = Vec::with_capacity(1 + NONCE_LEN + buffer.len());
        id.push(SEAL_VERSION);
        id.extend_from_slice(&nonce);
        id.extend_from_slice(&buffer);
        let id = base64url_encode(&id);
        if id.len() > MAX_ID_LEN {
            return Err(AuthError::internal("ceremony too large"));
        }
        Ok(id)
    }

    /// Opens a challenge id. Every failure is [`AuthError::ChallengeInvalid`]; expiry is the
    /// caller's check.
    fn unseal(&self, id: &str) -> Result<Sealed, AuthError> {
        if id.len() > MAX_ID_LEN {
            return Err(AuthError::ChallengeInvalid);
        }
        let bytes = base64url_decode(id).map_err(|_| AuthError::ChallengeInvalid)?;
        let Some((&version, rest)) = bytes.split_first() else {
            return Err(AuthError::ChallengeInvalid);
        };
        if version != SEAL_VERSION {
            return Err(AuthError::ChallengeInvalid);
        }
        let (nonce, ciphertext) = rest
            .split_at_checked(NONCE_LEN)
            .ok_or(AuthError::ChallengeInvalid)?;
        let nonce =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| AuthError::ChallengeInvalid)?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let plain_len = self
            .cipher()?
            .open_in_place(nonce, Aad::from(SEAL_AAD), &mut buffer[..])
            .map_err(|_| AuthError::ChallengeInvalid)?
            .len();
        buffer.truncate(plain_len);
        ciborium::from_reader(&buffer[..]).map_err(|_| AuthError::ChallengeInvalid)
    }
}

impl fmt::Debug for CeremonyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CeremonyKey(<redacted>)")
    }
}

/// What a challenge id carries under the seal.
#[derive(Serialize, Deserialize)]
struct Sealed {
    /// The single-use key of the ceremony (random, base64url).
    ceremony: String,
    /// When the ceremony ends, by the clock of the controller that opened it.
    expires_at: Timestamp,
    pending: SealedPending,
}

/// A serde mirror of [`Pending`]; the public type keeps its shape. Byte strings are CBOR
/// byte strings, and the TOTP seed stays in a zeroizing buffer.
#[derive(Serialize, Deserialize)]
enum SealedPending {
    SecondFactor {
        user: UserId,
        first: AuthStrength,
        attempts: u32,
    },
    WebAuthnLogin {
        #[serde(with = "challenge_bytes")]
        challenge: [u8; 32],
        user: Option<UserId>,
        discoverable: bool,
        continuation: bool,
    },
    WebAuthnRegister {
        #[serde(with = "challenge_bytes")]
        challenge: [u8; 32],
        user: UserId,
        session: SessionId,
        label: String,
        hardware_key: bool,
    },
    TotpEnrolment {
        user: UserId,
        session: SessionId,
        #[serde(with = "secret_bytes")]
        secret: Zeroizing<Vec<u8>>,
    },
}

impl SealedPending {
    /// A rough size of the encoded form beyond the fixed part.
    fn size_hint(&self) -> usize {
        match self {
            Self::SecondFactor { .. } | Self::WebAuthnLogin { .. } => 0,
            Self::WebAuthnRegister { label, .. } => label.len(),
            Self::TotpEnrolment { secret, .. } => secret.len(),
        }
    }
}

impl From<Pending> for SealedPending {
    fn from(pending: Pending) -> Self {
        match pending {
            Pending::SecondFactor {
                user,
                first,
                attempts,
            } => Self::SecondFactor {
                user,
                first,
                attempts,
            },
            Pending::WebAuthnLogin {
                challenge,
                user,
                discoverable,
                continuation,
            } => Self::WebAuthnLogin {
                challenge,
                user,
                discoverable,
                continuation,
            },
            Pending::WebAuthnRegister {
                challenge,
                user,
                session,
                label,
                hardware_key,
            } => Self::WebAuthnRegister {
                challenge,
                user,
                session,
                label,
                hardware_key,
            },
            Pending::TotpEnrolment {
                user,
                session,
                secret,
            } => Self::TotpEnrolment {
                user,
                session,
                secret,
            },
        }
    }
}

impl From<SealedPending> for Pending {
    fn from(sealed: SealedPending) -> Self {
        match sealed {
            SealedPending::SecondFactor {
                user,
                first,
                attempts,
            } => Self::SecondFactor {
                user,
                first,
                attempts,
            },
            SealedPending::WebAuthnLogin {
                challenge,
                user,
                discoverable,
                continuation,
            } => Self::WebAuthnLogin {
                challenge,
                user,
                discoverable,
                continuation,
            },
            SealedPending::WebAuthnRegister {
                challenge,
                user,
                session,
                label,
                hardware_key,
            } => Self::WebAuthnRegister {
                challenge,
                user,
                session,
                label,
                hardware_key,
            },
            SealedPending::TotpEnrolment {
                user,
                session,
                secret,
            } => Self::TotpEnrolment {
                user,
                session,
                secret,
            },
        }
    }
}

/// CBOR byte strings for the 32-byte WebAuthn challenges.
mod challenge_bytes {
    use serde::{Deserializer, Serializer, de::Visitor};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        struct Bytes32;

        impl Visitor<'_> for Bytes32 {
            type Value = [u8; 32];

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("32 bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<[u8; 32], E> {
                value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))
            }
        }

        deserializer.deserialize_bytes(Bytes32)
    }
}

/// CBOR byte strings for the TOTP seed, which stays in a zeroizing buffer.
mod secret_bytes {
    use serde::{Deserializer, Serializer, de::Visitor};
    use zeroize::Zeroizing;

    pub(super) fn serialize<S: Serializer>(
        value: &Zeroizing<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        struct Secret;

        impl Visitor<'_> for Secret {
            type Value = Zeroizing<Vec<u8>>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(Zeroizing::new(value.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(Zeroizing::new(value))
            }
        }

        deserializer.deserialize_bytes(Secret)
    }
}

/// The value of a row of [`USED_CHALLENGES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsedChallenge {
    /// When the row may be purged: when the ceremony expires, so the id cannot be used again
    /// whether or not the row is there.
    pub expires_at: Timestamp,
}

/// The use of one ceremony, to be staged into the write batch that completes it; see
/// [`Ceremonies::take_staged`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUse {
    ceremony: String,
    expires_at: Timestamp,
}

impl StagedUse {
    /// The single-use key of the ceremony (the key of the row).
    pub fn ceremony(&self) -> &str {
        &self.ceremony
    }

    /// When the ceremony ends and the row may be purged.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Adds the use to `batch`: a precondition that no row of the ceremony exists yet, and
    /// the row. A second batch that stages the same ceremony fails with
    /// [`StoreError::PreconditionFailed`] when it commits; that is the single use across
    /// controllers.
    ///
    /// # Errors
    ///
    /// [`StoreError::Codec`] if the row cannot be encoded.
    pub fn stage(&self, batch: &mut WriteBatch) -> Result<(), StoreError> {
        batch.expect_typed(&USED_CHALLENGES, &self.ceremony, None);
        batch.put_typed(
            &USED_CHALLENGES,
            &self.ceremony,
            &UsedChallenge {
                expires_at: self.expires_at,
            },
        )?;
        Ok(())
    }
}

/// What this controller remembers about the ceremonies it has handled.
#[derive(Default)]
struct Local {
    /// Ceremonies taken on this controller, by single-use key, with their expiry.
    consumed: HashMap<String, Timestamp>,
    /// What [`Ceremonies::put_back`] stored, by challenge id as given, with its expiry.
    overrides: HashMap<String, (Pending, Timestamp)>,
}

/// Inserts into a map that holds at most `capacity` entries: expired entries go first, then
/// the entry that expires first.
fn insert_bounded<V>(
    map: &mut HashMap<String, V>,
    capacity: usize,
    now: Timestamp,
    key: String,
    value: V,
    expiry: impl Fn(&V) -> Timestamp,
) {
    if !map.contains_key(&key) && map.len() >= capacity {
        map.retain(|_, entry| expiry(entry) > now);
        while map.len() >= capacity {
            let Some(first) = map
                .iter()
                .min_by_key(|(_, entry)| expiry(entry))
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            map.remove(&first);
        }
    }
    map.insert(key, value);
}

/// The pending ceremonies of this controller: the key that seals them into challenge ids and
/// the bounded memory of what this controller has already handed out.
pub struct Ceremonies {
    key: RwLock<CeremonyKey>,
    local: Mutex<Local>,
    capacity: usize,
}

impl fmt::Debug for Ceremonies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ceremonies")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Ceremonies {
    /// Ceremonies sealed under a random key of this process, remembering at most `capacity`
    /// taken ceremonies (and as many put-back ones) at a time. Ids of this instance open
    /// nowhere else; see [`with_key`](Self::with_key) for the cluster.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random source fails, which leaves no way to key the
    /// seals.
    pub fn new(capacity: usize) -> Self {
        Self::with_key(
            capacity,
            CeremonyKey::random().expect("the operating system's random source works"),
        )
    }

    /// Ceremonies sealed under `key`, remembering at most `capacity` taken ceremonies (and as
    /// many put-back ones) at a time.
    pub fn with_key(capacity: usize, key: CeremonyKey) -> Self {
        Self {
            key: RwLock::new(key),
            local: Mutex::new(Local::default()),
            capacity: capacity.max(1),
        }
    }

    /// Replaces the key. Ids sealed under the old key stop opening: ceremonies that were
    /// open at that moment end and the user starts again.
    pub fn set_key(&self, key: CeremonyKey) {
        *self.key.write().unwrap_or_else(PoisonError::into_inner) = key;
    }

    fn lock(&self) -> MutexGuard<'_, Local> {
        self.local.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn unseal(&self, id: &str) -> Result<Sealed, AuthError> {
        self.key
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .unseal(id)
    }

    /// Opens a ceremony and returns its id: the pending state sealed under the key, valid
    /// for [`CEREMONY_TTL`] from `now`. Writes nothing, here or in the store.
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] if the random source fails or the state cannot be encoded.
    pub fn open(&self, pending: Pending, now: Timestamp) -> Result<String, AuthError> {
        let ceremony = base64url_encode(&random::array::<CEREMONY_KEY_LEN>()?);
        let sealed = Sealed {
            ceremony,
            expires_at: now.checked_add(CEREMONY_TTL).unwrap_or(now),
            pending: SealedPending::from(pending),
        };
        self.key
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .seal(&sealed)
    }

    /// Takes the pending state a [`put_back`](Self::put_back) left for `id`, if it is still
    /// open. The ceremony stays consumed.
    fn take_override(&self, id: &str, now: Timestamp) -> Option<Pending> {
        let (pending, expires_at) = self.lock().overrides.remove(id)?;
        (expires_at > now).then_some(pending)
    }

    /// Marks an opened ceremony as taken on this controller.
    fn consume(&self, sealed: Sealed, now: Timestamp) -> Result<Pending, AuthError> {
        let Sealed {
            ceremony,
            expires_at,
            pending,
        } = sealed;
        if expires_at <= now {
            return Err(AuthError::ChallengeInvalid);
        }
        let mut local = self.lock();
        if local.consumed.contains_key(&ceremony) {
            return Err(AuthError::ChallengeInvalid);
        }
        insert_bounded(
            &mut local.consumed,
            self.capacity,
            now,
            ceremony,
            expires_at,
            |expires_at| *expires_at,
        );
        Ok(pending.into())
    }

    /// Takes a ceremony out (one use on this controller). A replay against this controller
    /// fails; across controllers use [`take_staged`](Self::take_staged), which also checks
    /// the store.
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`] if the id does not open (another key, damaged,
    /// unknown version), the ceremony has expired, or this controller took it already.
    pub fn take(&self, id: &str, now: Timestamp) -> Result<Pending, AuthError> {
        if let Some(pending) = self.take_override(id, now) {
            return Ok(pending);
        }
        let sealed = self.unseal(id)?;
        self.consume(sealed, now)
    }

    /// Takes a ceremony out for a handler that finishes it with a store write. As
    /// [`take`](Self::take), and it refuses a ceremony whose row in [`USED_CHALLENGES`]
    /// `view` already holds.
    ///
    /// The finishing handler stages the returned [`StagedUse`] into the write batch that
    /// completes the ceremony (the session, the credential, the enrolment), so the
    /// ceremony is consumed exactly when that batch commits. A replay on another controller
    /// is refused by the row, or by the precondition of its batch when both race; a
    /// ceremony whose finish fails before it commits (a wrong code, an error) is not
    /// consumed in the store.
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`] as for [`take`](Self::take), or because the row
    /// exists; [`AuthError::Store`] if the read fails.
    pub fn take_staged(
        &self,
        id: &str,
        now: Timestamp,
        view: &dyn ReadView,
    ) -> Result<(Pending, StagedUse), AuthError> {
        let sealed = self.unseal(id)?;
        let staged = StagedUse {
            ceremony: sealed.ceremony.clone(),
            expires_at: sealed.expires_at,
        };
        if view
            .get_typed(&USED_CHALLENGES, &staged.ceremony)?
            .is_some()
        {
            return Err(AuthError::ChallengeInvalid);
        }
        if let Some(pending) = self.take_override(id, now) {
            return Ok((pending, staged));
        }
        let pending = self.consume(sealed, now)?;
        Ok((pending, staged))
    }

    /// Puts a ceremony back under its id after a wrong code, open for another
    /// [`CEREMONY_TTL`] on this controller; [`MAX_CODE_ATTEMPTS`] bounds how often that
    /// happens. The next [`take`](Self::take) of the id returns `pending`, with the attempt
    /// counter it carries. Another controller does not know it and opens the id as it was
    /// sealed.
    pub fn put_back(&self, id: String, pending: Pending, now: Timestamp) {
        let expires_at = now.checked_add(CEREMONY_TTL).unwrap_or(now);
        let mut local = self.lock();
        insert_bounded(
            &mut local.overrides,
            self.capacity,
            now,
            id,
            (pending, expires_at),
            |(_, expires_at)| *expires_at,
        );
    }

    /// The number of entries this controller remembers: the ceremonies it has taken plus the
    /// ones put back. Open ceremonies are not counted; they live in their ids.
    pub fn len(&self) -> usize {
        let local = self.lock();
        local.consumed.len() + local.overrides.len()
    }

    /// Whether this controller remembers no taken or put-back ceremony.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Deletes the rows of [`USED_CHALLENGES`] whose ceremonies have expired (`expires_at <=
/// now`), at most [`PURGE_PAGE`] rows per batch so a backlog stays far below the batch size
/// limit; returns how many. The leader runs it hourly as a leader-only service,
/// with the leader epoch of its term as `fence` (`tenko_store::fence`), so a deposed
/// leader's purge fails instead of racing the new leader's. Nothing is proposed when no row
/// is due.
///
/// # Errors
///
/// The store's errors, the precondition failure of a fenced batch among them.
pub async fn purge_used(
    store: &dyn Store,
    now: Timestamp,
    fence: Option<u64>,
) -> Result<usize, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let mut expired = Vec::new();
    let mut range = KeyRange::all();
    loop {
        let page = view.scan_typed(&USED_CHALLENGES, range, PURGE_PAGE, false)?;
        let last = if page.len() == PURGE_PAGE {
            page.last().map(|(key, _, _)| USED_CHALLENGES.key(key))
        } else {
            None
        };
        expired.extend(
            page.into_iter()
                .filter(|(_, row, _)| row.expires_at <= now)
                .map(|(key, _, revision)| (key, revision)),
        );
        match last {
            Some(last) => range = KeyRange::all().after(last),
            None => break,
        }
    }
    for chunk in expired.chunks(PURGE_PAGE) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        if let Some(epoch) = fence {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        for (key, revision) in chunk {
            batch
                .expect_typed(&USED_CHALLENGES, key, Some(*revision))
                .delete_typed(&USED_CHALLENGES, key);
        }
        store.propose(batch).await?;
    }
    Ok(expired.len())
}

#[cfg(test)]
mod tests {
    use tenko_core::cluster::LEADER_EPOCH;
    use tenko_store::{Committed, MemStore};

    use super::*;
    use crate::clock::{Clock, MockClock};

    fn second_factor() -> Pending {
        Pending::SecondFactor {
            user: UserId::generate(),
            first: AuthStrength::Password,
            attempts: 0,
        }
    }

    fn webauthn_login() -> Pending {
        Pending::WebAuthnLogin {
            challenge: [0xa5; 32],
            user: Some(UserId::generate()),
            discoverable: true,
            continuation: false,
        }
    }

    fn totp_enrolment(seed: &[u8]) -> Pending {
        Pending::TotpEnrolment {
            user: UserId::generate(),
            session: SessionId::generate(),
            secret: Zeroizing::new(seed.to_vec()),
        }
    }

    fn cluster_key(byte: u8) -> CeremonyKey {
        CeremonyKey::from_cluster_key(&[byte; 32])
    }

    /// A controller whose key derives from the cluster key made of `byte`.
    fn controller(byte: u8) -> Ceremonies {
        Ceremonies::with_key(10, cluster_key(byte))
    }

    /// The raw bytes of an id, for tampering.
    fn decode(id: &str) -> Vec<u8> {
        base64url_decode(id).expect("a sealed id is base64url")
    }

    fn refused(ceremonies: &Ceremonies, id: &str, now: Timestamp) -> bool {
        matches!(ceremonies.take(id, now), Err(AuthError::ChallengeInvalid))
    }

    #[test]
    fn ceremonies_are_single_use_and_expire() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(10);
        let id = ceremonies.open(second_factor(), clock.now()).expect("open");
        assert!(ceremonies.take(&id, clock.now()).is_ok());
        assert!(matches!(
            ceremonies.take(&id, clock.now()),
            Err(AuthError::ChallengeInvalid)
        ));
        let id = ceremonies.open(second_factor(), clock.now()).expect("open");
        clock.advance(CEREMONY_TTL);
        assert!(ceremonies.take(&id, clock.now()).is_err());
    }

    #[test]
    fn capacity_is_bounded() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(3);
        for _ in 0..10 {
            let id = ceremonies.open(second_factor(), clock.now()).expect("open");
            ceremonies.take(&id, clock.now()).expect("take");
            clock.advance(Duration::from_secs(1));
        }
        assert_eq!(ceremonies.len(), 3, "taken ceremonies are bounded");
        for index in 0..10 {
            ceremonies.put_back(format!("id {index}"), second_factor(), clock.now());
            clock.advance(Duration::from_secs(1));
        }
        assert_eq!(ceremonies.len(), 6, "put-back ceremonies are bounded too");
    }

    #[test]
    fn opening_writes_nothing_locally() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(3);
        for _ in 0..20 {
            ceremonies.open(second_factor(), clock.now()).expect("open");
        }
        assert!(ceremonies.is_empty());
        assert_eq!(ceremonies.len(), 0);
    }

    #[test]
    fn expired_entries_make_room_before_live_ones() {
        let clock = MockClock::fixed();
        let ceremonies = Ceremonies::new(2);
        let old = ceremonies.open(second_factor(), clock.now()).expect("open");
        ceremonies.take(&old, clock.now()).expect("take");
        clock.advance(Duration::from_secs(100));
        let live = ceremonies.open(second_factor(), clock.now()).expect("open");
        ceremonies.take(&live, clock.now()).expect("take");
        clock.advance(Duration::from_secs(200));
        // `old` has expired and makes room; `live` stays and is still refused.
        let newer = ceremonies.open(second_factor(), clock.now()).expect("open");
        ceremonies.take(&newer, clock.now()).expect("take");
        assert_eq!(ceremonies.len(), 2);
        assert!(refused(&ceremonies, &live, clock.now()));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let pending = Pending::TotpEnrolment {
            user: UserId::generate(),
            session: SessionId::generate(),
            secret: Zeroizing::new(vec![1, 2, 3]),
        };
        assert_eq!(format!("{pending:?}"), "Pending::TotpEnrolment(<redacted>)");
        assert_eq!(
            format!("{:?}", webauthn_login()),
            "Pending::WebAuthnLogin(<redacted>)"
        );

        let key = CeremonyKey::from_cluster_key(&[0x42; 32]);
        assert_eq!(format!("{key:?}"), "CeremonyKey(<redacted>)");
        assert_eq!(
            format!("{:?}", CeremonyKey::random().expect("random")),
            "CeremonyKey(<redacted>)"
        );
        let shown = format!("{:?}", Ceremonies::with_key(4, key));
        assert!(shown.starts_with("Ceremonies"), "{shown}");
        assert!(!shown.to_lowercase().contains("key"), "{shown}");
    }

    #[test]
    fn the_cluster_key_derivation_is_pinned() {
        // HKDF-SHA-256, salt "tenko cluster key v1", info "ceremony sealing", over the bytes
        // 0..32 (computed independently): every controller and every release derives this.
        let cluster: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).expect("below 32"));
        let key = CeremonyKey::from_cluster_key(&cluster);
        assert_eq!(
            crate::encoding::hex_encode(&key.0[..]),
            "929c094837f294b3334c1a2a24313b84061397c762e804b00e70e22c15e9bcf7"
        );
        let other = CeremonyKey::from_cluster_key(&[1; 32]);
        assert_ne!(other.0[..], key.0[..]);
        assert_eq!(
            CeremonyKey::from_cluster_key(&cluster).0[..],
            key.0[..],
            "deterministic"
        );
        let random = CeremonyKey::random().expect("random");
        assert_ne!(random.0[..], CeremonyKey::random().expect("random").0[..]);
    }

    #[test]
    fn ids_have_the_documented_shape_and_hide_the_state() {
        let clock = MockClock::fixed();
        let ceremonies = controller(1);
        let seed = b"correct horse battery";
        let pending = totp_enrolment(seed);
        let id = ceremonies.open(pending.clone(), clock.now()).expect("open");
        let bytes = decode(&id);
        assert_eq!(bytes[0], 1, "version");
        assert!(bytes.len() > 1 + NONCE_LEN + AES_256_GCM.tag_len());
        assert!(
            !bytes.windows(seed.len()).any(|window| window == seed),
            "the seed is not in the id in the clear"
        );
        // The same state seals differently every time (fresh ceremony key and nonce).
        let again = ceremonies.open(pending, clock.now()).expect("open");
        assert_ne!(id, again);
        assert_ne!(decode(&id)[1..=NONCE_LEN], decode(&again)[1..=NONCE_LEN]);
    }

    #[test]
    fn a_ceremony_opened_on_one_controller_finishes_on_another() {
        let clock = MockClock::fixed();
        let a = controller(7);
        let b = controller(7);
        let user = UserId::generate();
        let session = SessionId::generate();

        let id = a
            .open(
                Pending::WebAuthnLogin {
                    challenge: [9; 32],
                    user: Some(user),
                    discoverable: true,
                    continuation: true,
                },
                clock.now(),
            )
            .expect("open");
        let Pending::WebAuthnLogin {
            challenge,
            user: found,
            discoverable,
            continuation,
        } = b
            .take(&id, clock.now())
            .expect("take on another controller")
        else {
            panic!("a WebAuthn login");
        };
        assert_eq!(challenge, [9; 32]);
        assert_eq!(found, Some(user));
        assert!(discoverable && continuation);

        let seed = vec![0, 1, 2, 3, 250, 251, 252, 253, 254, 255];
        let id = a
            .open(
                Pending::TotpEnrolment {
                    user,
                    session,
                    secret: Zeroizing::new(seed.clone()),
                },
                clock.now(),
            )
            .expect("open");
        let Pending::TotpEnrolment {
            user: found,
            session: found_session,
            secret,
        } = b
            .take(&id, clock.now())
            .expect("take on another controller")
        else {
            panic!("a TOTP enrolment");
        };
        assert_eq!((found, found_session), (user, session));
        assert_eq!(&secret[..], &seed[..]);

        let id = a
            .open(
                Pending::WebAuthnRegister {
                    challenge: [3; 32],
                    user,
                    session,
                    label: "Laptop \u{1f511}".to_owned(),
                    hardware_key: true,
                },
                clock.now(),
            )
            .expect("open");
        let Pending::WebAuthnRegister {
            challenge,
            label,
            hardware_key,
            ..
        } = b
            .take(&id, clock.now())
            .expect("take on another controller")
        else {
            panic!("a WebAuthn registration");
        };
        assert_eq!(challenge, [3; 32]);
        assert_eq!(label, "Laptop \u{1f511}");
        assert!(hardware_key);

        let id = a.open(second_factor(), clock.now()).expect("open");
        let Pending::SecondFactor {
            first, attempts, ..
        } = b
            .take(&id, clock.now())
            .expect("take on another controller")
        else {
            panic!("a second factor");
        };
        assert_eq!((first, attempts), (AuthStrength::Password, 0));
    }

    #[test]
    fn ids_that_do_not_open_are_refused() {
        let clock = MockClock::fixed();
        let now = clock.now();
        let a = controller(7);
        let id = a.open(webauthn_login(), now).expect("open");

        // Another key.
        assert!(refused(&controller(8), &id, now));
        assert!(refused(
            &Ceremonies::with_key(10, CeremonyKey::random().expect("random")),
            &id,
            now
        ));
        // Nothing, and things that are not base64url.
        for bad in ["", "A", "=", "!!!!", "not base64 at all", "\u{e9}\u{e9}"] {
            assert!(refused(&a, bad, now), "{bad:?}");
        }
        // A string past the length limit.
        assert!(refused(&a, &"A".repeat(MAX_ID_LEN + 4), now));

        let bytes = decode(&id);
        // Truncated, at every length.
        for len in 0..bytes.len() {
            assert!(
                refused(&a, &base64url_encode(&bytes[..len]), now),
                "truncated to {len}"
            );
        }
        // Extended.
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(refused(&a, &base64url_encode(&longer), now));
        // A flipped bit in every byte: version, nonce, ciphertext and tag.
        for index in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[index] ^= 0x01;
            assert!(
                refused(&a, &base64url_encode(&damaged), now),
                "byte {index}"
            );
        }
        // Another version.
        for version in [0, 2, 255] {
            let mut other = bytes.clone();
            other[0] = version;
            assert!(
                refused(&a, &base64url_encode(&other), now),
                "version {version}"
            );
        }
        // A changed character of the text itself.
        let mut text = id.clone().into_bytes();
        text[10] = if text[10] == b'A' { b'B' } else { b'A' };
        assert!(refused(
            &a,
            &String::from_utf8(text).expect("ASCII stays ASCII"),
            now
        ));
        // The undamaged id still opens, once.
        assert!(a.take(&id, now).is_ok());
        assert!(refused(&a, &id, now));
    }

    #[test]
    fn ceremonies_expire_at_the_ttl() {
        let clock = MockClock::fixed();
        let a = controller(7);
        let b = controller(7);
        let start = clock.now();
        let id = a.open(second_factor(), start).expect("open");
        // One tick before the end, another controller still opens it.
        clock.advance(Duration::from_millis(299_999));
        assert!(b.take(&id, clock.now()).is_ok());

        let id = a.open(second_factor(), start).expect("open");
        clock.set(start.checked_add(CEREMONY_TTL).expect("in range"));
        assert!(refused(&b, &id, clock.now()));
        clock.advance(Duration::from_secs(3_600));
        assert!(refused(&a, &id, clock.now()));
    }

    #[test]
    fn a_replay_on_the_same_controller_is_refused() {
        let clock = MockClock::fixed();
        let a = controller(7);
        let id = a.open(webauthn_login(), clock.now()).expect("open");
        assert!(a.take(&id, clock.now()).is_ok());
        assert_eq!(a.len(), 1);
        for _ in 0..3 {
            assert!(refused(&a, &id, clock.now()));
        }
        // Another controller, which has not seen it, opens it (the store is what stops that).
        assert!(controller(7).take(&id, clock.now()).is_ok());
    }

    #[test]
    fn a_wrong_code_keeps_the_attempts_and_the_same_id_works_once_more() {
        let clock = MockClock::fixed();
        let a = controller(7);
        let user = UserId::generate();
        let id = a
            .open(
                Pending::SecondFactor {
                    user,
                    first: AuthStrength::Password,
                    attempts: 0,
                },
                clock.now(),
            )
            .expect("open");
        let Pending::SecondFactor { attempts, .. } = a.take(&id, clock.now()).expect("take") else {
            panic!("a second factor");
        };
        assert_eq!(attempts, 0);

        // The handler sees a wrong code and puts the challenge back with one more attempt.
        clock.advance(Duration::from_secs(60));
        a.put_back(
            id.clone(),
            Pending::SecondFactor {
                user,
                first: AuthStrength::Password,
                attempts: attempts + 1,
            },
            clock.now(),
        );
        let Pending::SecondFactor {
            user: found,
            attempts,
            ..
        } = a.take(&id, clock.now()).expect("the id works once more")
        else {
            panic!("a second factor");
        };
        assert_eq!((found, attempts), (user, 1));
        // And once only, unless put back again.
        assert!(refused(&a, &id, clock.now()));

        // A put-back ceremony is open for another TTL, from the moment it was put back, but
        // not longer.
        a.put_back(id.clone(), second_factor(), clock.now());
        clock.advance(CEREMONY_TTL);
        assert!(refused(&a, &id, clock.now()));
    }

    #[test]
    fn replacing_the_key_ends_the_ceremonies_of_the_old_one() {
        let clock = MockClock::fixed();
        let a = controller(7);
        let before = a.open(second_factor(), clock.now()).expect("open");
        a.set_key(cluster_key(8));
        assert!(refused(&a, &before, clock.now()));
        let after = a.open(second_factor(), clock.now()).expect("open");
        assert!(refused(&controller(7), &after, clock.now()));
        assert!(controller(8).take(&after, clock.now()).is_ok());
        // The old key still opens the old id elsewhere; only this instance moved on.
        assert!(controller(7).take(&before, clock.now()).is_ok());
    }

    /// Commits a batch that stages `staged`, as a finishing handler does.
    async fn finish(
        store: &MemStore,
        staged: &StagedUse,
        now: Timestamp,
    ) -> Result<Committed, StoreError> {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        staged.stage(&mut batch)?;
        store.propose(batch).await
    }

    async fn used_row(store: &MemStore, ceremony: &str) -> Option<UsedChallenge> {
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .get_typed(&USED_CHALLENGES, &ceremony.to_owned())
            .expect("read")
            .map(|(row, _)| row)
    }

    #[tokio::test]
    async fn the_store_makes_a_ceremony_single_use_across_controllers() {
        let clock = MockClock::fixed();
        let store = MemStore::default();
        let a = controller(7);
        let b = controller(7);
        let id = a.open(totp_enrolment(b"seed"), clock.now()).expect("open");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        let (pending, staged) = a
            .take_staged(&id, clock.now(), view.as_ref())
            .expect("controller A takes it");
        assert!(matches!(pending, Pending::TotpEnrolment { .. }));
        assert_eq!(
            staged.expires_at(),
            clock.now().checked_add(CEREMONY_TTL).expect("in range")
        );
        assert_eq!(staged.ceremony().len(), 22, "16 random bytes, base64url");
        assert!(
            used_row(&store, staged.ceremony()).await.is_none(),
            "nothing is written before the finishing batch commits"
        );

        finish(&store, &staged, clock.now()).await.expect("commit");
        let row = used_row(&store, staged.ceremony())
            .await
            .expect("the row is there");
        assert_eq!(row.expires_at, staged.expires_at());

        // Controller B, with a fresh view, is refused: the row is there.
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(matches!(
            b.take_staged(&id, clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
        // So is A, which also remembers it locally.
        assert!(matches!(
            a.take_staged(&id, clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
        // A refused take leaves nothing behind on B: it did not consume anything.
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn two_controllers_that_race_cannot_both_commit() {
        let clock = MockClock::fixed();
        let store = MemStore::default();
        let a = controller(7);
        let b = controller(7);
        let id = a.open(webauthn_login(), clock.now()).expect("open");

        // Both read before either commits, so both are let through.
        let view_a = store.read(ReadConsistency::Local).await.expect("view");
        let view_b = store.read(ReadConsistency::Local).await.expect("view");
        let (_, staged_a) = a
            .take_staged(&id, clock.now(), view_a.as_ref())
            .expect("A takes it");
        let (_, staged_b) = b
            .take_staged(&id, clock.now(), view_b.as_ref())
            .expect("B takes it");
        assert_eq!(staged_a, staged_b);

        finish(&store, &staged_a, clock.now())
            .await
            .expect("the first batch commits");
        let error = finish(&store, &staged_b, clock.now())
            .await
            .expect_err("the second batch is refused");
        assert!(
            matches!(error, StoreError::PreconditionFailed(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_put_back_ceremony_can_still_be_staged() {
        let clock = MockClock::fixed();
        let store = MemStore::default();
        let a = controller(7);
        let user = UserId::generate();
        let id = a.open(second_factor(), clock.now()).expect("open");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        let (_, first) = a
            .take_staged(&id, clock.now(), view.as_ref())
            .expect("take");
        a.put_back(
            id.clone(),
            Pending::SecondFactor {
                user,
                first: AuthStrength::Password,
                attempts: 1,
            },
            clock.now(),
        );
        let (pending, second) = a
            .take_staged(&id, clock.now(), view.as_ref())
            .expect("take again");
        assert!(matches!(
            pending,
            Pending::SecondFactor {
                attempts: 1,
                user: found,
                ..
            } if found == user
        ));
        assert_eq!(first, second, "the same ceremony");
        finish(&store, &second, clock.now()).await.expect("commit");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        a.put_back(id.clone(), second_factor(), clock.now());
        assert!(
            matches!(
                a.take_staged(&id, clock.now(), view.as_ref()),
                Err(AuthError::ChallengeInvalid)
            ),
            "the row wins over a put-back"
        );
    }

    #[tokio::test]
    async fn staged_ids_still_need_to_open_and_be_fresh() {
        let clock = MockClock::fixed();
        let store = MemStore::default();
        let a = controller(7);
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(matches!(
            a.take_staged("", clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
        let id = controller(8)
            .open(second_factor(), clock.now())
            .expect("open");
        assert!(matches!(
            a.take_staged(&id, clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
        let id = a.open(second_factor(), clock.now()).expect("open");
        clock.advance(CEREMONY_TTL);
        assert!(matches!(
            a.take_staged(&id, clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
    }

    async fn put_used(store: &MemStore, name: &str, expires_at: Timestamp) {
        let mut batch = WriteBatch::new(
            Principal::system(SystemComponent::Auth),
            Timestamp::UNIX_EPOCH,
        );
        batch
            .put_typed(
                &USED_CHALLENGES,
                &name.to_owned(),
                &UsedChallenge { expires_at },
            )
            .expect("encode");
        store.propose(batch).await.expect("commit");
    }

    async fn used_names(store: &MemStore) -> Vec<String> {
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .scan_typed(&USED_CHALLENGES, KeyRange::all(), 100_000, false)
            .expect("scan")
            .into_iter()
            .map(|(name, _, _)| name)
            .collect()
    }

    #[tokio::test]
    async fn the_purge_removes_expired_rows_only() {
        let clock = MockClock::fixed();
        let now = clock.now();
        let next_second = now.checked_add(Duration::from_secs(1)).expect("in range");
        let next_hour = now
            .checked_add(Duration::from_secs(3_600))
            .expect("in range");
        let store = MemStore::default();
        put_used(&store, "expired", Timestamp::UNIX_EPOCH).await;
        put_used(&store, "due", now).await;
        put_used(&store, "next second", next_second).await;
        put_used(&store, "next hour", next_hour).await;

        assert_eq!(purge_used(&store, now, None).await.expect("purge"), 2);
        assert_eq!(used_names(&store).await, ["next hour", "next second"]);

        let revision = store.status().revision;
        assert_eq!(purge_used(&store, now, None).await.expect("purge"), 0);
        assert_eq!(
            store.status().revision,
            revision,
            "nothing is proposed when nothing is due"
        );

        assert_eq!(
            purge_used(&store, next_second, Some(0))
                .await
                .expect("purge"),
            1,
            "a row is due at its expiry"
        );
        assert_eq!(used_names(&store).await, ["next hour"]);
    }

    #[tokio::test]
    async fn the_purge_pages_through_every_row() {
        const ROWS: u32 = 2_300;
        let clock = MockClock::fixed();
        let now = clock.now();
        let later = now.checked_add(Duration::from_secs(60)).expect("in range");
        let store = MemStore::default();
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        for index in 0..ROWS {
            let expires_at = if index.is_multiple_of(7) { later } else { now };
            batch
                .put_typed(
                    &USED_CHALLENGES,
                    &format!("row {index:05}"),
                    &UsedChallenge { expires_at },
                )
                .expect("encode");
        }
        store.propose(batch).await.expect("commit");
        let live = (0..ROWS).filter(|index| index.is_multiple_of(7)).count();

        assert_eq!(
            purge_used(&store, now, None).await.expect("purge"),
            usize::try_from(ROWS).expect("small") - live
        );
        assert_eq!(used_names(&store).await.len(), live);
    }

    #[tokio::test]
    async fn a_fenced_purge_needs_the_current_epoch() {
        let clock = MockClock::fixed();
        let now = clock.now();
        let store = MemStore::default();
        put_used(&store, "one", Timestamp::UNIX_EPOCH).await;
        put_used(&store, "two", Timestamp::UNIX_EPOCH).await;
        assert_eq!(
            store
                .read(ReadConsistency::Local)
                .await
                .expect("view")
                .counter(&LEADER_EPOCH)
                .expect("counter"),
            0
        );

        let error = purge_used(&store, now, Some(5))
            .await
            .expect_err("a deposed leader cannot purge");
        assert!(
            matches!(error, StoreError::PreconditionFailed(_)),
            "{error}"
        );
        assert_eq!(used_names(&store).await, ["one", "two"], "nothing deleted");

        assert_eq!(purge_used(&store, now, Some(0)).await.expect("purge"), 2);
        assert_eq!(used_names(&store).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_purged_row_is_not_a_replay_window() {
        let clock = MockClock::fixed();
        let store = MemStore::default();
        let a = controller(7);
        let b = controller(7);
        let id = a.open(second_factor(), clock.now()).expect("open");
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let (_, staged) = a
            .take_staged(&id, clock.now(), view.as_ref())
            .expect("take");
        finish(&store, &staged, clock.now()).await.expect("commit");

        // Before the expiry the purge keeps the row, so the replay stays refused.
        assert_eq!(
            purge_used(&store, clock.now(), None).await.expect("purge"),
            0
        );
        // At the expiry the row is due, and the id is dead by itself.
        clock.advance(CEREMONY_TTL);
        assert_eq!(
            purge_used(&store, clock.now(), None).await.expect("purge"),
            1
        );
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(matches!(
            b.take_staged(&id, clock.now(), view.as_ref()),
            Err(AuthError::ChallengeInvalid)
        ));
    }
}
