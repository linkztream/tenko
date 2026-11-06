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

use zeroize::Zeroizing;

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
    /// The stored form of a key set is not one [`KeySet::encode`] wrote: the field that
    /// failed and its offset. Never the octets.
    #[error("the stored key set is malformed at offset {offset}: {field}")]
    Stored {
        /// The offset in the stored octets.
        offset: usize,
        /// The field that failed.
        field: &'static str,
    },
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

    /// The entries in one state, as a key set of their own (the pending keys a recovery
    /// tries alone, the current keys a rotation authenticates with).
    #[must_use]
    pub fn in_state(&self, state: KeyVersionState) -> KeySet {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|e| e.state == state)
                .cloned()
                .collect(),
        }
    }

    /// The set with every entry of `kvno` moved to `state` (`kvno` itself unchanged).
    #[must_use]
    pub fn with_state(mut self, kvno: u32, state: KeyVersionState) -> KeySet {
        for entry in &mut self.entries {
            if entry.kvno == kvno {
                entry.state = state;
            }
        }
        self
    }

    /// The set with every entry in `state` dropped.
    #[must_use]
    pub fn without_state(mut self, state: KeyVersionState) -> KeySet {
        self.entries.retain(|e| e.state != state);
        self
    }

    /// The set without the version `kvno`.
    #[must_use]
    pub fn without_kvno(mut self, kvno: u32) -> KeySet {
        self.entries.retain(|e| e.kvno != kvno);
        self
    }

    /// The set with every entry of the version `from` renumbered to `to` (a pending
    /// version whose number the KDC told only after the change); `None` when another
    /// version holds `to` already, so that no key is ever lost to a renumbering.
    #[must_use]
    pub fn renumbered(mut self, from: u32, to: u32) -> Option<KeySet> {
        if from == to {
            return Some(self);
        }
        if self.entries.iter().any(|e| e.kvno == to) {
            return None;
        }
        for entry in &mut self.entries {
            if entry.kvno == from {
                entry.kvno = to;
            }
        }
        Some(self)
    }

    /// The stored form of the set: the value of the vault secret of purpose `dns.krb`
    /// (identity plan section 3.2). Written into zeroizing memory.
    ///
    /// ```text
    /// set     = magic:"TKS" version:u8(1) count:u16 count*entry
    /// entry   = state:u8 kvno:u32 etype:u8 principal:u16-data key:u8-data
    /// state   = 0 current | 1 previous | 2 pending
    /// etype   = 17 aes128-cts-hmac-sha1-96 | 18 aes256-cts-hmac-sha1-96
    /// principal = the RFC 1964 string form of the principal with its realm, UTF-8
    /// ```
    ///
    /// All numbers are big-endian. The format is Tenko's own: it holds exactly the fields
    /// of [`KeyEntry`], it is read by [`KeySet::decode`] with every length checked, and it
    /// never passes the key octets through a general serializer's buffers.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        // The exact length first: a buffer that grew would leave copies of key octets in
        // the memory it gave back.
        let len = 6 + self
            .entries
            .iter()
            .map(|e| 1 + 4 + 1 + 2 + e.principal.to_string().len() + 1 + e.key.as_bytes().len())
            .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&STORED_MAGIC);
        // At most MAX_KEY_ENTRIES (64) entries: the count fits.
        let count = u16::try_from(self.entries.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            out.push(match entry.state {
                KeyVersionState::Current => 0,
                KeyVersionState::Previous => 1,
                KeyVersionState::Pending => 2,
            });
            out.extend_from_slice(&entry.kvno.to_be_bytes());
            // 17 or 18.
            out.push(u8::try_from(entry.etype().number()).unwrap_or(0));
            let principal = entry.principal.to_string();
            // A principal is at most MAX_PRINCIPAL_LEN (1,024) octets.
            let len = u16::try_from(principal.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(principal.as_bytes());
            let key = entry.key.as_bytes();
            // 16 or 32 octets.
            out.push(u8::try_from(key.len()).unwrap_or(0));
            out.extend_from_slice(key);
        }
        out
    }

    /// Reads the stored form [`KeySet::encode`] wrote.
    ///
    /// # Errors
    ///
    /// [`KeySetError::Stored`] naming the field and its offset; [`KeySetError::TooMany`]
    /// or [`KeySetError::Conflict`] when the entries break the rules of a set.
    pub fn decode(bytes: &[u8]) -> Result<KeySet, KeySetError> {
        let mut r = Stored { bytes, at: 0 };
        if r.take(4, "magic")? != STORED_MAGIC {
            return Err(stored_error(0, "magic"));
        }
        let count = usize::from(r.u16("count")?);
        if count > MAX_KEY_ENTRIES {
            return Err(KeySetError::TooMany);
        }
        let mut set = KeySet::default();
        for _ in 0..count {
            let at = r.at;
            let state = match r.u8("state")? {
                0 => KeyVersionState::Current,
                1 => KeyVersionState::Previous,
                2 => KeyVersionState::Pending,
                _ => return Err(stored_error(at, "state")),
            };
            let kvno = r.u32("kvno")?;
            let at = r.at;
            let etype = EncryptionType::from_number(i32::from(r.u8("etype")?))
                .ok_or_else(|| stored_error(at, "etype"))?;
            let at = r.at;
            let len = usize::from(r.u16("principal")?);
            let principal = std::str::from_utf8(r.take(len, "principal")?)
                .ok()
                .and_then(|text| PrincipalName::parse(text).ok())
                .ok_or_else(|| stored_error(at, "principal"))?;
            let at = r.at;
            let len = usize::from(r.u8("key")?);
            let key = Key::new(etype, r.take(len, "key")?).map_err(|_| stored_error(at, "key"))?;
            set.insert(KeyEntry {
                principal,
                kvno,
                state,
                key,
            })?;
        }
        if r.at != bytes.len() {
            return Err(stored_error(r.at, "trailing octets"));
        }
        Ok(set)
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

/// The first octets of the stored form of a key set: `TKS` and the format version 1.
pub const STORED_MAGIC: [u8; 4] = [b'T', b'K', b'S', 1];

/// The error of a stored key set at `offset`.
fn stored_error(offset: usize, field: &'static str) -> KeySetError {
    KeySetError::Stored { offset, field }
}

/// A bounds-checked reader of the stored form.
struct Stored<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Stored<'a> {
    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], KeySetError> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(KeySetError::Stored {
                offset: self.at,
                field,
            })?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, KeySetError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, KeySetError> {
        let b = self.take(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, KeySetError> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
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

    /// IAM-16: the stored form of a key set reads back as the same set, octet for octet,
    /// with every state, both types and a principal that needs escapes.
    #[test]
    fn iam_16_the_stored_key_set_round_trips() {
        let mut set = KeySet::new(vec![
            entry(2, KeyVersionState::Previous, AES256, 2),
            entry(3, KeyVersionState::Current, AES256, 4),
            entry(3, KeyVersionState::Current, AES128, 5),
            entry(4, KeyVersionState::Pending, AES256, 6),
        ])
        .expect("set");
        set.insert(KeyEntry {
            principal: principal(r"DNS/a\/b.corp.example.test@CORP.EXAMPLE.TEST"),
            kvno: u32::MAX,
            state: KeyVersionState::Current,
            key: Key::new(AES128, &[9; 16]).expect("key"),
        })
        .expect("escaped");
        let stored = set.encode();
        assert_eq!(stored.capacity(), stored.len(), "written without growing");
        assert_eq!(&stored[..4], &STORED_MAGIC);
        let back = KeySet::decode(&stored).expect("decode");
        assert_eq!(back, set);
        assert_eq!(&*back.encode(), &*stored);
        // The empty set is stored too (an account whose adopt has not finished).
        let empty = KeySet::default().encode();
        assert_eq!(KeySet::decode(&empty).expect("empty"), KeySet::default());
    }

    /// IAM-16: every truncation and every corrupted field of the stored form is refused
    /// with the field named and no key octet in the error text.
    #[test]
    fn iam_16_a_malformed_stored_key_set_is_refused() {
        let set = KeySet::new(vec![
            entry(3, KeyVersionState::Current, AES256, 0xaa),
            entry(4, KeyVersionState::Pending, AES128, 0xbb),
        ])
        .expect("set");
        let stored = set.encode();
        for len in 0..stored.len() {
            let error = KeySet::decode(&stored[..len]).expect_err("truncated");
            assert!(
                matches!(error, KeySetError::Stored { .. }),
                "{len}: {error}"
            );
            let text = error.to_string();
            assert!(!text.contains("aa") && !text.contains("bb"), "{text}");
        }
        let mut longer = stored.to_vec();
        longer.push(0);
        assert!(matches!(
            KeySet::decode(&longer),
            Err(KeySetError::Stored {
                field: "trailing octets",
                ..
            })
        ));
        let field = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = stored.to_vec();
            mutate(&mut bytes);
            match KeySet::decode(&bytes) {
                Err(KeySetError::Stored { field, .. }) => field,
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(field(&|b| b[0] = b'X'), "magic");
        assert_eq!(field(&|b| b[3] = 2), "magic");
        // The first entry starts at 6: state, kvno (4), etype, principal length (2).
        assert_eq!(field(&|b| b[6] = 3), "state");
        assert_eq!(field(&|b| b[11] = 23), "etype");
        assert_eq!(field(&|b| b[14] = 0xff), "principal");
        // The key length of the first entry follows its principal.
        let principal_len = usize::from(u16::from_be_bytes([stored[12], stored[13]]));
        let key_at = 14 + principal_len;
        assert_eq!(field(&|b| b[key_at] = 16), "key");
        // More entries than a set holds, and two different keys for one version.
        let mut many = STORED_MAGIC.to_vec();
        many.extend_from_slice(&65_u16.to_be_bytes());
        assert_eq!(KeySet::decode(&many), Err(KeySetError::TooMany));
        let mut twice = STORED_MAGIC.to_vec();
        twice.extend_from_slice(&2_u16.to_be_bytes());
        let one = entry(3, KeyVersionState::Current, AES256, 1);
        let other = entry(3, KeyVersionState::Current, AES256, 2);
        for e in [one, other] {
            let single = KeySet::new(vec![e]).expect("one").encode();
            twice.extend_from_slice(&single[6..]);
        }
        assert!(matches!(
            KeySet::decode(&twice),
            Err(KeySetError::Conflict { kvno: 3, .. })
        ));
        // Arbitrary octets after the magic never panic.
        let mut seed = 0x9e37_79b9_u32;
        for _ in 0..2_000 {
            let mut bytes = STORED_MAGIC.to_vec();
            for _ in 0..(seed % 200) {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                bytes.push((seed >> 24) as u8);
            }
            let _ = KeySet::decode(&bytes);
        }
    }

    /// DNS-28: the moves of a rotation: the pending keys alone, renumbered to the version
    /// the KDC told, made current; the old current made previous; the old previous gone.
    #[test]
    fn dns_28_the_states_of_a_rotation() {
        let set = KeySet::new(vec![
            entry(2, KeyVersionState::Previous, AES256, 2),
            entry(3, KeyVersionState::Current, AES256, 4),
            entry(4, KeyVersionState::Pending, AES256, 6),
        ])
        .expect("set");
        assert_eq!(set.in_state(KeyVersionState::Pending).kvnos(), [4]);
        let rotated = set
            .without_state(KeyVersionState::Previous)
            .with_state(3, KeyVersionState::Previous)
            .renumbered(4, 7)
            .expect("free")
            .with_state(7, KeyVersionState::Current);
        assert_eq!(rotated.kvnos(), [3, 7]);
        assert_eq!(rotated.in_state(KeyVersionState::Current).kvnos(), [7]);
        assert_eq!(rotated.in_state(KeyVersionState::Previous).kvnos(), [3]);
        assert!(rotated.in_state(KeyVersionState::Pending).is_empty());
        // Renumbering onto a version that is held is refused: no key is lost to it.
        let clash = KeySet::new(vec![
            entry(3, KeyVersionState::Current, AES256, 4),
            entry(4, KeyVersionState::Pending, AES256, 6),
        ])
        .expect("set");
        assert_eq!(clash.clone().renumbered(4, 3), None);
        assert_eq!(clash.clone().renumbered(4, 4), Some(clash.clone()));
        assert_eq!(clash.without_kvno(3).kvnos(), [4]);
    }
}
