//! The import parser of the MIT keytab format, version 2 (`0x0502`), as `ktpass`,
//! `msktutil` and MIT's `ktutil` write it (identity plan section 3.1, keytab import).
//! Tenko keeps the AES entries in the vault and never writes a keytab file; the caller
//! hands the octets of an uploaded file to [`parse`] and drops them afterwards.
//!
//! The format, all numbers big-endian:
//!
//! ```text
//! file    = 0x05 0x02 *record
//! record  = size:i32 (size > 0: an entry of size octets; size < 0: a hole of -size octets;
//!           size = 0: the end)
//! entry   = count:u16 realm:data count*component:data name_type:u32 timestamp:u32
//!           kvno8:u8 enctype:u16 key:data [kvno32:u32] [more octets, ignored]
//! data    = length:u16 octets
//! ```
//!
//! Version 1 (`0x0501`) is recognized and refused: it writes numbers in the writer's own
//! byte order and counts the realm as a component, and no current tool writes it. The
//! 32-bit key version, when present and not zero, replaces the 8-bit one.
//!
//! Every count and length is checked against the octets that are there before it is
//! used; the file, the number of entries and the number of components are bounded. An
//! entry of another encryption type than AES (RC4, DES, 3DES) is not an error: it is
//! listed in [`Keytab::refused`] so that the operator is told, and never kept.

use tenko_core::dns::{KeyVersionState, PrincipalName, Realm};

use crate::{
    cipher::{self, CipherError, Key},
    der::MAX_NAME_COMPONENTS,
    keys::{KeyEntry, KeySet, KeySetError},
};

/// The largest keytab accepted.
pub const MAX_KEYTAB_LEN: usize = 1 << 20;
/// The most records (entries and holes) read.
pub const MAX_KEYTAB_RECORDS: usize = 1024;

/// The version octets of format 2.
pub const VERSION_2: [u8; 2] = [0x05, 0x02];
/// The version octets of format 1.
pub const VERSION_1: [u8; 2] = [0x05, 0x01];

/// What was wrong with a keytab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeytabErrorKind {
    /// Larger than [`MAX_KEYTAB_LEN`].
    TooLarge,
    /// Format version 1, which stores numbers in the writer's byte order.
    Version1,
    /// Not a keytab: the first octets are not `0x05 0x02`.
    NotAKeytab,
    /// The input ends inside a record.
    Truncated(&'static str),
    /// More than [`MAX_KEYTAB_RECORDS`] records.
    TooManyRecords,
    /// No component, or more than the codec reads.
    ComponentCount,
    /// A realm or component that is not UTF-8 or not a valid name.
    BadPrincipal,
    /// No entry at all.
    Empty,
}

impl std::fmt::Display for KeytabErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "the file is larger than {MAX_KEYTAB_LEN} octets"),
            Self::Version1 => f.write_str(
                "keytab format version 1 (0x0501) stores its numbers in the byte order of the \
                 machine that wrote it and is not read; export the keys again with ktpass, \
                 msktutil or ktutil, which write version 2",
            ),
            Self::NotAKeytab => f.write_str("not a keytab: the file does not start with 0x0502"),
            Self::Truncated(field) => write!(f, "the file ends inside the {field}"),
            Self::TooManyRecords => {
                write!(f, "more than {MAX_KEYTAB_RECORDS} entries")
            }
            Self::ComponentCount => write!(
                f,
                "a principal with no component or more than {MAX_NAME_COMPONENTS}"
            ),
            Self::BadPrincipal => f.write_str("a principal that is not a valid name"),
            Self::Empty => f.write_str("the keytab holds no entry"),
        }
    }
}

/// A refused keytab: what was wrong and the offset of the record (or of the field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("keytab at offset {offset}: {kind}")]
pub struct KeytabError {
    /// The offset in the file.
    pub offset: usize,
    /// What was wrong.
    pub kind: KeytabErrorKind,
}

/// One AES entry of a keytab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeytabEntry {
    /// The principal with its realm.
    pub principal: PrincipalName,
    /// The name type the file records.
    pub name_type: u32,
    /// When the entry was written (Unix seconds).
    pub timestamp: u32,
    /// The key version number.
    pub kvno: u32,
    /// The key.
    pub key: Key,
}

/// An entry that was read and not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedEntry {
    /// The principal with its realm.
    pub principal: PrincipalName,
    /// The key version number.
    pub kvno: u32,
    /// The encryption type number.
    pub enctype: i32,
    /// Why: [`CipherError::UnsupportedEnctype`] for RC4, DES and 3DES (ADR 0026 point 3),
    /// [`CipherError::KeyLength`] for an AES key of the wrong length.
    pub reason: CipherError,
}

/// A parsed keytab.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keytab {
    /// The AES entries, in file order.
    pub entries: Vec<KeytabEntry>,
    /// The entries of other types, never kept.
    pub refused: Vec<RefusedEntry>,
}

impl Keytab {
    /// The principals of the AES entries, without repeats, in file order.
    pub fn principals(&self) -> Vec<&PrincipalName> {
        let mut out: Vec<&PrincipalName> = Vec::new();
        for entry in &self.entries {
            if !out.contains(&&entry.principal) {
                out.push(&entry.principal);
            }
        }
        out
    }

    /// The key set of the entries `keep` selects, all in the state `state` (an import is
    /// current; the version the KDC issues is learned by the self-test).
    ///
    /// # Errors
    ///
    /// [`KeySetError`] when two entries disagree or there are too many.
    pub fn key_set(
        &self,
        keep: impl Fn(&KeytabEntry) -> bool,
        state: KeyVersionState,
    ) -> Result<KeySet, KeySetError> {
        KeySet::new(
            self.entries
                .iter()
                .filter(|entry| keep(entry))
                .map(|entry| KeyEntry {
                    principal: entry.principal.clone(),
                    kvno: entry.kvno,
                    state,
                    key: entry.key.clone(),
                })
                .collect(),
        )
    }
}

/// A cursor over one record.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    fn error(&self, kind: KeytabErrorKind) -> KeytabError {
        KeytabError {
            offset: self.base + self.pos,
            kind,
        }
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], KeytabError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| self.error(KeytabErrorKind::Truncated(field)))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, KeytabError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, KeytabError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, KeytabError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn data(&mut self, field: &'static str) -> Result<&'a [u8], KeytabError> {
        let len = usize::from(self.u16(field)?);
        self.take(len, field)
    }

    fn text(&mut self, field: &'static str) -> Result<String, KeytabError> {
        let at = self.pos;
        let bytes = self.data(field)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| KeytabError {
                offset: self.base + at,
                kind: KeytabErrorKind::BadPrincipal,
            })
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// Parses a keytab.
///
/// # Errors
///
/// A [`KeytabError`] with the offset and the reason; an entry of a type other than AES
/// is not an error but is listed in [`Keytab::refused`].
pub fn parse(bytes: &[u8]) -> Result<Keytab, KeytabError> {
    let at = |offset, kind| KeytabError { offset, kind };
    if bytes.len() > MAX_KEYTAB_LEN {
        return Err(at(0, KeytabErrorKind::TooLarge));
    }
    match bytes.get(..2) {
        Some(v) if v == VERSION_2 => {}
        Some(v) if v == VERSION_1 => return Err(at(0, KeytabErrorKind::Version1)),
        _ => return Err(at(0, KeytabErrorKind::NotAKeytab)),
    }
    let mut keytab = Keytab::default();
    let mut pos = 2;
    let mut records = 0;
    let mut seen_entry = false;
    while pos < bytes.len() {
        if records == MAX_KEYTAB_RECORDS {
            return Err(at(pos, KeytabErrorKind::TooManyRecords));
        }
        records += 1;
        let size_octets: [u8; 4] = bytes
            .get(pos..pos + 4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| at(pos, KeytabErrorKind::Truncated("record size")))?;
        let size = i32::from_be_bytes(size_octets);
        pos += 4;
        if size == 0 {
            break;
        }
        let len = usize::try_from(size.unsigned_abs())
            .map_err(|_| at(pos, KeytabErrorKind::Truncated("record")))?;
        let record = bytes
            .get(pos..)
            .and_then(|rest| rest.get(..len))
            .ok_or_else(|| at(pos, KeytabErrorKind::Truncated("record")))?;
        if size > 0 {
            parse_entry(record, pos, &mut keytab)?;
            seen_entry = true;
        }
        pos += len;
    }
    if !seen_entry {
        return Err(at(pos, KeytabErrorKind::Empty));
    }
    Ok(keytab)
}

fn parse_entry(record: &[u8], base: usize, keytab: &mut Keytab) -> Result<(), KeytabError> {
    let mut c = Cursor {
        data: record,
        pos: 0,
        base,
    };
    let count = usize::from(c.u16("component count")?);
    if count == 0 || count > MAX_NAME_COMPONENTS {
        return Err(c.error(KeytabErrorKind::ComponentCount));
    }
    let realm_at = c.pos;
    let realm = c.text("realm")?;
    let mut components = Vec::new();
    for _ in 0..count {
        components.push(c.text("component")?);
    }
    let name_type = c.u32("name type")?;
    let timestamp = c.u32("timestamp")?;
    let kvno8 = c.u8("key version")?;
    let enctype = i32::from(c.u16("encryption type")?);
    let key_octets = c.data("key")?;
    let mut kvno = u32::from(kvno8);
    if c.remaining() >= 4 {
        let kvno32 = c.u32("32-bit key version")?;
        if kvno32 != 0 {
            kvno = kvno32;
        }
    }
    let bad_principal = KeytabError {
        offset: base + realm_at,
        kind: KeytabErrorKind::BadPrincipal,
    };
    let realm = Realm::new(&realm).map_err(|_| bad_principal)?;
    let principal = PrincipalName::new(components, realm).map_err(|_| bad_principal)?;
    match cipher::enctype(enctype).and_then(|etype| Key::new(etype, key_octets)) {
        Ok(key) => keytab.entries.push(KeytabEntry {
            principal,
            name_type,
            timestamp,
            kvno,
            key,
        }),
        Err(reason) => keytab.refused.push(RefusedEntry {
            principal,
            kvno,
            enctype,
            reason,
        }),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
