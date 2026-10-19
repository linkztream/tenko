//! The keys of a signed zone (P2-Q4, OPS-07): the metadata in `dns.sign_state`, the
//! private key as a system secret of the vault with the purpose `dns.dnssec` (the role
//! purpose `dnssec` of node sync, as TSIG secrets are `dns.tsig` in the vault and `tsig`
//! in node sync).
//!
//! A zone has a KSK and a ZSK, or one CSK when its policy says so. A key's state decides
//! what it does ([`KeySet`]):
//!
//! | State | In the DNSKEY set | Signs the DNSKEY, CDS and CDNSKEY sets | Signs the rest | In CDS and CDNSKEY, and the DS shown |
//! |---|---|---|---|---|
//! | `generated` | no | no | no | no |
//! | `published` | yes | a KSK or CSK does (a KSK rollover) | no | a KSK or CSK is |
//! | `active` | yes | a KSK or CSK does | a ZSK or CSK does | a KSK or CSK is |
//! | `retired` | yes | no | no | no |
//! | `removed` | no | no | no | no |
//!
//! The private key never leaves the vault except in a backup, which carries the vault's
//! envelopes (encrypted under the KEK) like every other table of the store; the signer
//! decrypts it for its own use and holds it in memory only while it leads.

use tenko_core::{
    ObjectRef, RequestCtx, Timestamp,
    dns::{
        DnsKeyId, DnsName, DnssecAlgorithm, DnssecKeyMeta, KeyRole, KeyState, Rdata, RecordData,
        Rtype, SignState, ZoneId,
    },
    ipam::Stamp,
    secret::SecretClass,
    serde_util::HexBytes,
};
use tenko_store::WriteBatch;
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault, VaultError};

use super::crypto::{self, CryptoError, KeyPair};

/// The vault purpose of DNSSEC private keys.
pub const VAULT_PURPOSE: &str = "dns.dnssec";

/// A key with its private part loaded.
#[derive(Debug)]
pub struct LoadedKey {
    /// The metadata.
    pub meta: DnssecKeyMeta,
    /// The private key.
    pub pair: KeyPair,
    /// The public key as the DNSKEY carries it.
    pub public_key: Vec<u8>,
}

impl LoadedKey {
    /// A key from its metadata and its private key.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the private key does not load or does not match the public key.
    pub fn load(meta: DnssecKeyMeta, der: &[u8]) -> Result<Self, CryptoError> {
        let pair = KeyPair::from_pkcs8(meta.algorithm, der)?;
        let public_key = pair.public_key();
        if public_key != meta.public_key.0 {
            return Err(CryptoError("the private key does not match the DNSKEY"));
        }
        Ok(Self {
            meta,
            pair,
            public_key,
        })
    }

    /// The DNSKEY record data.
    pub fn dnskey(&self) -> Rdata {
        Rdata::from_data(&crypto::dnskey(
            self.meta.role,
            self.meta.algorithm,
            &self.public_key,
        ))
    }
}

/// Whether a key in `state` stands in the DNSKEY set.
pub fn published(state: KeyState) -> bool {
    matches!(
        state,
        KeyState::Published | KeyState::Active | KeyState::Retired
    )
}

/// Whether a key of `role` is a key-signing key (KSK or CSK).
pub fn signs_keys(role: KeyRole) -> bool {
    matches!(role, KeyRole::Ksk | KeyRole::Csk)
}

/// Whether a key of `role` signs the zone data (ZSK or CSK).
pub fn signs_data(role: KeyRole) -> bool {
    matches!(role, KeyRole::Zsk | KeyRole::Csk)
}

/// Whether the parent should hold the DS of this key: a KSK or CSK, published or active.
pub fn in_parent(meta: &DnssecKeyMeta) -> bool {
    signs_keys(meta.role) && matches!(meta.state, KeyState::Published | KeyState::Active)
}

/// Whether `rtype` is signed by the key-signing keys.
pub fn key_set_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY)
}

/// The loaded keys of a zone and what each signs.
#[derive(Debug, Default)]
pub struct KeySet {
    /// Every key with a private part loaded, in the order of the state.
    pub keys: Vec<LoadedKey>,
}

impl KeySet {
    /// The keys that sign an RRset of `rtype`.
    pub fn signers(&self, rtype: Rtype) -> impl Iterator<Item = &LoadedKey> {
        let keys = key_set_type(rtype);
        self.keys.iter().filter(move |key| {
            if keys {
                signs_keys(key.meta.role)
                    && matches!(key.meta.state, KeyState::Published | KeyState::Active)
            } else {
                signs_data(key.meta.role) && key.meta.state == KeyState::Active
            }
        })
    }

    /// Whether the set can sign a zone: a key for the DNSKEY set and one for the data.
    pub fn complete(&self) -> bool {
        self.signers(Rtype::DNSKEY).next().is_some() && self.signers(Rtype::SOA).next().is_some()
    }

    /// The DNSKEY records of the published keys.
    pub fn dnskeys(&self) -> Vec<Rdata> {
        self.keys
            .iter()
            .filter(|key| published(key.meta.state))
            .map(LoadedKey::dnskey)
            .collect()
    }

    /// The CDNSKEY records (RFC 7344): the DNSKEY of each key the parent should hold.
    pub fn cdnskeys(&self) -> Vec<Rdata> {
        self.keys
            .iter()
            .filter(|key| in_parent(&key.meta))
            .map(LoadedKey::dnskey)
            .collect()
    }

    /// The CDS records (RFC 7344): the SHA-256 DS of each key the parent should hold.
    pub fn cds(&self, apex: &DnsName) -> Vec<Rdata> {
        self.keys
            .iter()
            .filter(|key| in_parent(&key.meta))
            .map(|key| {
                Rdata::from_data(&crypto::ds(
                    apex,
                    key.meta.role,
                    key.meta.algorithm,
                    &key.public_key,
                ))
            })
            .collect()
    }
}

/// The DS records of the keys of `state` the parent should hold, as typed data.
pub fn ds_records(apex: &DnsName, state: &SignState) -> Vec<RecordData> {
    state
        .keys
        .iter()
        .filter(|meta| in_parent(meta))
        .map(|meta| crypto::ds(apex, meta.role, meta.algorithm, &meta.public_key.0))
        .collect()
}

/// A new key staged into `batch`: generated, its private key a vault secret of the
/// purpose `dns.dnssec` owned by the key, its tag different from the zone's other keys.
///
/// # Errors
///
/// [`KeyError`] when the key cannot be made or the vault refuses it.
#[allow(clippy::too_many_arguments, reason = "the parts of one key")]
pub fn stage_new_key(
    vault: &dyn Vault,
    batch: &mut WriteBatch,
    cx: &RequestCtx,
    zone: ZoneId,
    apex: &DnsName,
    role: KeyRole,
    algorithm: DnssecAlgorithm,
    state: KeyState,
    taken: &[u16],
) -> Result<DnssecKeyMeta, KeyError> {
    for _ in 0..16 {
        let (pair, der) = KeyPair::generate(algorithm)?;
        let public_key = pair.public_key();
        let tag = crypto::key_tag(&crypto::dnskey_wire(role, algorithm, &public_key));
        if taken.contains(&tag) {
            continue;
        }
        let id = DnsKeyId::generate();
        let spec = SecretSpec::new(SecretPurpose::from_static(VAULT_PURPOSE))
            .owned_by(ObjectRef::from(id))
            .labelled(format!("{apex} {} {tag}", role_name(role)));
        let secret = vault.stage_put(
            batch,
            cx,
            SecretClass::System,
            spec,
            &SecretBytes::new(der.to_vec()),
        )?;
        let now = cx.now;
        let active = state == KeyState::Active;
        return Ok(DnssecKeyMeta {
            id,
            zone,
            role,
            algorithm,
            key_tag: tag,
            public_key: HexBytes(public_key),
            secret,
            state,
            created: Stamp::new(now, cx.principal.clone()),
            published: published(state).then_some(now),
            activated: active.then_some(now),
            retired: None,
        });
    }
    Err(KeyError::Crypto(CryptoError(
        "no key with a free key tag could be generated",
    )))
}

/// Moves a key to `state` at `now`, setting the timestamp of the state.
pub fn set_state(meta: &mut DnssecKeyMeta, state: KeyState, now: Timestamp) {
    meta.state = state;
    match state {
        KeyState::Published => {
            meta.published.get_or_insert(now);
        }
        KeyState::Active => {
            meta.published.get_or_insert(now);
            meta.activated = Some(now);
            meta.retired = None;
        }
        KeyState::Retired => {
            meta.retired = Some(now);
        }
        KeyState::Generated | KeyState::Removed => {}
    }
}

/// The stable name of a role.
pub fn role_name(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Ksk => "ksk",
        KeyRole::Zsk => "zsk",
        KeyRole::Csk => "csk",
    }
}

/// The stable name of a state.
pub fn state_name(state: KeyState) -> &'static str {
    match state {
        KeyState::Generated => "generated",
        KeyState::Published => "published",
        KeyState::Active => "active",
        KeyState::Retired => "retired",
        KeyState::Removed => "removed",
    }
}

/// A key could not be made or stored.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The library failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// Loads the private keys of `state` that the signer uses (every key but the generated
/// and removed ones).
///
/// # Errors
///
/// A description naming the key that does not load.
pub async fn load(vault: &dyn Vault, cx: &RequestCtx, state: &SignState) -> Result<KeySet, String> {
    let mut keys = Vec::new();
    for meta in &state.keys {
        if matches!(meta.state, KeyState::Generated | KeyState::Removed) {
            continue;
        }
        let secret = vault.get_system(cx, meta.secret).await.map_err(|error| {
            format!(
                "the private key of {} {} is not in the vault: {error}",
                role_name(meta.role),
                meta.key_tag
            )
        })?;
        let key = LoadedKey::load(meta.clone(), secret.expose()).map_err(|error| {
            format!(
                "the private key of {} {} does not load: {error}",
                role_name(meta.role),
                meta.key_tag
            )
        })?;
        keys.push(key);
    }
    Ok(KeySet { keys })
}
