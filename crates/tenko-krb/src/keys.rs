//! The keys of the service account (identity plan section 3.2): per key version the
//! principal and its realm, the key version number, the encryption type and the key
//! octets, with the version's place in the rotation (current, previous, pending). This is
//! what the vault secret of purpose `dns.krb` holds and what the acceptor selects from.
//!
//! The acceptor picks keys by the ticket's `etype` and `kvno` (decision 12 of the spike):
//! a ticket that names a key version is tried only under that version, an encryption type
//! other than AES is refused before any key is looked at, and a key version Tenko does not
//! hold is reported as such (`dns.gss.kvno_unknown`, section 3.10).

use tenko_core::dns::{EncryptionType, KeyVersionState, PrincipalName};

use crate::cipher::{self, CipherError, Key};

/// The most entries a key set holds: two principals (the account and an SPN as a keytab
/// may name it) times two types times three versions leaves room to spare.
pub const MAX_KEY_ENTRIES: usize = 64;

/// One key of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// The principal the key belongs to, with its realm (`TENKO-DNS$@CORP.EXAMPLE.TEST`,
    /// or an SPN of the account as a keytab names it).
    pub principal: PrincipalName,
    /// The key version number the KDC puts in tickets.
    pub kvno: u32,
    /// Where the version stands in the rotation.
    pub state: KeyVersionState,
    /// The key, with its encryption type.
    pub key: Key,
}

impl KeyEntry {
    /// The encryption type.
    pub const fn etype(&self) -> EncryptionType {
        self.key.etype()
    }
}

/// Why no key was found for a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// The ticket is encrypted with a type other than AES (`dns.gss.weak_etype`).
    #[error("the ticket's encryption type {0} is not accepted")]
    UnsupportedEnctype(i32),
    /// The ticket names a key version Tenko does not hold (`dns.gss.kvno_unknown`).
    #[error("key version {0} is not held")]
    KvnoUnknown(u32),
    /// The version is held, or no version is named, but not for this type.
    #[error("no key of type {etype} for key version {kvno:?}")]
    EnctypeNotHeld {
        /// The ticket's encryption type.
        etype: i32,
        /// The ticket's key version, if it named one.
        kvno: Option<u32>,
    },
}

/// Why a key set was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeySetError {
    /// More than [`MAX_KEY_ENTRIES`] entries.
    #[error("a key set holds at most {MAX_KEY_ENTRIES} keys")]
    TooMany,
    /// Two entries for the same principal, version and type with different keys.
    #[error("two different keys for {principal} version {kvno} type {etype}")]
    Conflict {
        /// The principal.
        principal: String,
        /// The version.
        kvno: u32,
        /// The type.
        etype: i32,
    },
    /// A key could not be derived.
    #[error(transparent)]
    Cipher(#[from] CipherError),
}

/// The keys of one account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    entries: Vec<KeyEntry>,
}

impl KeySet {
    /// A key set from its entries; exact duplicates are kept once.
    ///
    /// # Errors
    ///
    /// [`KeySetError::TooMany`] or [`KeySetError::Conflict`].
    pub fn new(entries: Vec<KeyEntry>) -> Result<Self, KeySetError> {
        let mut set = Self::default();
        for entry in entries {
            set.insert(entry)?;
        }
        Ok(set)
    }

    /// Adds an entry; an exact duplicate is ignored.
    ///
    /// # Errors
    ///
    /// [`KeySetError::TooMany`] or [`KeySetError::Conflict`].
    pub fn insert(&mut self, entry: KeyEntry) -> Result<(), KeySetError> {
        if let Some(existing) = self.entries.iter().find(|e| {
            e.principal == entry.principal && e.kvno == entry.kvno && e.etype() == entry.etype()
        }) {
            if existing.key == entry.key {
                return Ok(());
            }
            return Err(KeySetError::Conflict {
                principal: entry.principal.to_string(),
                kvno: entry.kvno,
                etype: entry.etype().number(),
            });
        }
        if self.entries.len() == MAX_KEY_ENTRIES {
            return Err(KeySetError::TooMany);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// The keys of one version derived from a password (adopt and rotation, section 3.1),
    /// for each of `etypes`.
    ///
    /// # Errors
    ///
    /// [`KeySetError::Cipher`] when the iteration count is refused.
    pub fn from_password(
        principal: &PrincipalName,
        kvno: u32,
        state: KeyVersionState,
        password: &[u8],
        salt: &str,
        iterations: u32,
        etypes: &[EncryptionType],
    ) -> Result<Self, KeySetError> {
        let mut set = Self::default();
        for etype in etypes {
            set.insert(KeyEntry {
                principal: principal.clone(),
                kvno,
                state,
                key: cipher::string_to_key(*etype, password, salt.as_bytes(), iterations)?,
            })?;
        }
        Ok(set)
    }

    /// The entries.
    pub fn entries(&self) -> &[KeyEntry] {
        &self.entries
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The key versions held, ascending.
    pub fn kvnos(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.entries.iter().map(|e| e.kvno).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The keys a ticket of `etype` and `kvno` may be encrypted under, to be tried in this
    /// order (different keys only). With a version, only that version; without one, the
    /// current version first, then the pending one, then the previous ones.
    ///
    /// # Errors
    ///
    /// [`SelectError::UnsupportedEnctype`] for a type other than AES,
    /// [`SelectError::KvnoUnknown`] for a version not held, and
    /// [`SelectError::EnctypeNotHeld`] when no key of the type matches.
    pub fn select(&self, etype: i32, kvno: Option<u32>) -> Result<Vec<&Key>, SelectError> {
        let wanted = cipher::enctype(etype).map_err(|_| SelectError::UnsupportedEnctype(etype))?;
        if let Some(kvno) = kvno
            && !self.entries.iter().any(|e| e.kvno == kvno)
        {
            return Err(SelectError::KvnoUnknown(kvno));
        }
        let rank = |state: KeyVersionState| match state {
            KeyVersionState::Current => 0,
            KeyVersionState::Pending => 1,
            KeyVersionState::Previous => 2,
        };
        let mut matching: Vec<&KeyEntry> = self
            .entries
            .iter()
            .filter(|e| e.etype() == wanted && kvno.is_none_or(|k| e.kvno == k))
            .collect();
        matching.sort_by_key(|e| (rank(e.state), std::cmp::Reverse(e.kvno)));
        let mut keys: Vec<&Key> = Vec::new();
        for entry in matching {
            if !keys.iter().any(|k| **k == entry.key) {
                keys.push(&entry.key);
            }
        }
        if keys.is_empty() {
            return Err(SelectError::EnctypeNotHeld { etype, kvno });
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::dns::Realm;

    use super::*;

    fn principal(text: &str) -> PrincipalName {
        PrincipalName::parse(text).expect("principal")
    }

    fn entry(kvno: u32, state: KeyVersionState, etype: EncryptionType, seed: u8) -> KeyEntry {
        KeyEntry {
            principal: principal("TENKO-DNS$@CORP.EXAMPLE.TEST"),
            kvno,
            state,
            key: Key::new(etype, &vec![seed; cipher::key_len(etype)]).expect("key"),
        }
    }

    const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha1;
    const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha1;

    /// DNS-28: keys are selected by the ticket's type and version.
    #[test]
    fn dns_28_keys_are_selected_by_etype_and_kvno() {
        let set = KeySet::new(vec![
            entry(2, KeyVersionState::Previous, AES256, 2),
            entry(2, KeyVersionState::Previous, AES128, 3),
            entry(3, KeyVersionState::Current, AES256, 4),
            entry(3, KeyVersionState::Current, AES128, 5),
            entry(4, KeyVersionState::Pending, AES256, 6),
        ])
        .expect("set");
        assert_eq!(set.kvnos(), [2, 3, 4]);
        let first = |etype, kvno| set.select(etype, kvno).map(|k| k[0].as_bytes()[0]);
        assert_eq!(first(18, Some(2)), Ok(2));
        assert_eq!(first(17, Some(2)), Ok(3));
        assert_eq!(first(18, Some(3)), Ok(4));
        assert_eq!(first(18, Some(4)), Ok(6));
        assert_eq!(first(18, Some(5)), Err(SelectError::KvnoUnknown(5)));
        assert_eq!(
            first(17, Some(4)),
            Err(SelectError::EnctypeNotHeld {
                etype: 17,
                kvno: Some(4)
            })
        );
        assert_eq!(first(23, Some(3)), Err(SelectError::UnsupportedEnctype(23)));
        // Without a version: current, then pending, then previous.
        let order: Vec<u8> = set
            .select(18, None)
            .expect("keys")
            .iter()
            .map(|k| k.as_bytes()[0])
            .collect();
        assert_eq!(order, [4, 6, 2]);
        assert!(KeySet::default().select(18, None).is_err());
    }

    #[test]
    fn duplicates_and_conflicts() {
        let mut set = KeySet::default();
        set.insert(entry(3, KeyVersionState::Current, AES256, 1))
            .expect("first");
        set.insert(entry(3, KeyVersionState::Current, AES256, 1))
            .expect("same again");
        assert_eq!(set.entries().len(), 1);
        assert!(matches!(
            set.insert(entry(3, KeyVersionState::Current, AES256, 2)),
            Err(KeySetError::Conflict {
                kvno: 3,
                etype: 18,
                ..
            })
        ));
        let mut full = KeySet::default();
        for kvno in 0..u32::try_from(MAX_KEY_ENTRIES).expect("small") {
            full.insert(entry(kvno, KeyVersionState::Previous, AES128, 7))
                .expect("room");
        }
        assert_eq!(
            full.insert(entry(999, KeyVersionState::Current, AES128, 7)),
            Err(KeySetError::TooMany)
        );
    }

    #[test]
    fn keys_from_a_password_with_the_computer_salt() {
        // The keys ktutil derived for the same password and salt
        // (tests/fixtures/keytabs/computer-tenko-dns.klist, version 3).
        let account = principal("TENKO-DNS$@CORP.EXAMPLE.TEST");
        assert_eq!(
            account.realm(),
            &Realm::new("CORP.EXAMPLE.TEST").expect("realm")
        );
        let set = KeySet::from_password(
            &account,
            3,
            KeyVersionState::Pending,
            b"Lab-Machine-Pass-1-3",
            "CORP.EXAMPLE.TESThosttenko-dns.corp.example.test",
            cipher::DEFAULT_ITERATIONS,
            &[AES256, AES128],
        )
        .expect("keys");
        let hex = |k: &Key| crate::fixtures::hex_string(k.as_bytes());
        assert_eq!(
            hex(set.select(18, Some(3)).expect("aes256")[0]),
            "33bf225e01dee5621f2214cca36b25befed000908a0dfbee73a2da37acf9b997"
        );
        assert_eq!(
            hex(set.select(17, Some(3)).expect("aes128")[0]),
            "be2115f40aae7c4e4418aae54bee2a7f"
        );
    }
}
