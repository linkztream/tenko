//! The canonical order of names (RFC 4034 section 6.1) as plain byte order, and the small
//! readers of names and type bitmaps the lookup needs, all without allocating.
//!
//! An order key writes the labels of a name from the rightmost to the leftmost, each octet
//! in lower case followed by a terminator of two zero octets; a zero octet inside a label is
//! written as `0x00 0x01`, so that a label sorts before every longer label it begins and
//! byte order equals the canonical order.

use crate::name;

/// The longest order key: every octet of a 255-octet name escaped and a terminator per
/// label.
pub const ORDER_MAX: usize = 2 * 255 + 2 * 128;

/// The longest wire name.
pub const NAME_MAX: usize = 255;

/// An order key on the stack.
pub struct OrderKey {
    buf: [u8; ORDER_MAX],
    len: usize,
}

impl OrderKey {
    /// The order key of the uncompressed wire name `name`; `None` when it does not parse.
    pub fn of(name: &[u8]) -> Option<Self> {
        let mut starts = [0u8; 128];
        let mut count = 0usize;
        let mut pos = 0usize;
        loop {
            let len = usize::from(*name.get(pos)?);
            if len == 0 {
                break;
            }
            if len > 63 || count == starts.len() || pos + 1 + len > name.len() {
                return None;
            }
            starts[count] = u8::try_from(pos).ok()?;
            count += 1;
            pos += 1 + len;
        }
        let mut key = Self {
            buf: [0; ORDER_MAX],
            len: 0,
        };
        for index in (0..count).rev() {
            let start = usize::from(starts[index]);
            let len = usize::from(name[start]);
            for &octet in &name[start + 1..start + 1 + len] {
                match octet.to_ascii_lowercase() {
                    0 => key.push(&[0, 1]),
                    octet => key.push(&[octet]),
                }
            }
            key.push(&[0, 0]);
        }
        Some(key)
    }

    fn push(&mut self, octets: &[u8]) {
        let end = (self.len + octets.len()).min(ORDER_MAX);
        let take = end - self.len;
        self.buf[self.len..end].copy_from_slice(&octets[..take]);
        self.len = end;
    }

    /// The key's octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// The number of rightmost labels `a` and `b` share (both lowercase wire form).
pub fn common_labels(a: &[u8], b: &[u8]) -> usize {
    let (la, lb) = (name::label_count(a), name::label_count(b));
    let mut shared = la.min(lb);
    while shared > 0 && name::suffix(a, la - shared) != name::suffix(b, lb - shared) {
        shared -= 1;
    }
    shared
}

/// The wildcard `*.<name>` written into `buf`; `None` when it would be longer than a name.
pub fn wildcard_of<'a>(name: &[u8], buf: &'a mut [u8; NAME_MAX]) -> Option<&'a [u8]> {
    let len = name.len() + 2;
    if len > NAME_MAX {
        return None;
    }
    buf[0] = 1;
    buf[1] = b'*';
    buf[2..len].copy_from_slice(name);
    Some(&buf[..len])
}

/// Whether the type bitmap of an NSEC or NSEC3 record (RFC 4034 section 4.1.2) holds
/// `rtype`.
pub fn has_type(bitmap: &[u8], rtype: u16) -> bool {
    let [window, low] = rtype.to_be_bytes();
    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let (block, len) = (bitmap[pos], usize::from(bitmap[pos + 1]));
        let bits = bitmap.get(pos + 2..pos + 2 + len).unwrap_or_default();
        if block == window {
            let byte = usize::from(low / 8);
            return bits
                .get(byte)
                .is_some_and(|octet| octet & (0x80 >> (low % 8)) != 0);
        }
        pos += 2 + len;
    }
    false
}

/// Whether the record at the owner whose bitmap is `bitmap` is a delegation (NS without
/// SOA): the parent's denial record proves nothing below it.
pub fn is_delegation(bitmap: &[u8]) -> bool {
    has_type(bitmap, TYPE_NS) && !has_type(bitmap, TYPE_SOA)
}

/// NS.
pub const TYPE_NS: u16 = 2;
/// CNAME.
pub const TYPE_CNAME: u16 = 5;
/// SOA.
pub const TYPE_SOA: u16 = 6;
/// DNAME.
pub const TYPE_DNAME: u16 = 39;
