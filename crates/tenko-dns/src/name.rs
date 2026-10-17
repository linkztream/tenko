//! [`NameBuf`]: a DNS name in lowercase, uncompressed wire form in a fixed buffer.
//!
//! The query path never allocates (ADR 0009), so the query name lives in a buffer of 255
//! octets on the stack or in the worker's scratch. The wire form makes the parents of a
//! name sub-slices of it: `www.example.test` is `\x03www\x07example\x04test\x00`, and its
//! parent `example.test` is the slice after the first label. The index looks up the
//! closest encloser by walking these suffixes.

use std::fmt;

use tenko_core::dns::DnsName;

/// The longest name in wire form (RFC 1035).
pub const MAX_NAME_LEN: usize = 255;

/// Why a name could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The name would be longer than 255 octets.
    #[error("the name is longer than 255 octets")]
    TooLong,
    /// A label is empty or longer than 63 octets.
    #[error("a label is empty or longer than 63 octets")]
    BadLabel,
}

/// A DNS name in lowercase, uncompressed wire form, the root label included.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NameBuf {
    buf: [u8; MAX_NAME_LEN],
    len: usize,
    labels: usize,
}

impl Default for NameBuf {
    fn default() -> Self {
        Self::root()
    }
}

impl NameBuf {
    /// The root name.
    pub const fn root() -> Self {
        Self {
            buf: [0; MAX_NAME_LEN],
            len: 1,
            labels: 0,
        }
    }

    /// Makes this the root name again.
    pub fn clear(&mut self) {
        self.buf[0] = 0;
        self.len = 1;
        self.labels = 0;
    }

    /// Appends a label below the labels pushed so far (left to right: `www`, then
    /// `example`, then `test`), lowercased.
    ///
    /// # Errors
    ///
    /// [`NameError`] for an empty or long label, or a name over 255 octets.
    pub fn push_label(&mut self, label: &[u8]) -> Result<(), NameError> {
        if label.is_empty() || label.len() > 63 {
            return Err(NameError::BadLabel);
        }
        // The root octet moves to the end.
        let start = self.len - 1;
        if start + 1 + label.len() + 1 > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        // A label is at most 63 octets (checked above).
        self.buf[start] = u8::try_from(label.len()).unwrap_or(63);
        for (dst, src) in self.buf[start + 1..start + 1 + label.len()]
            .iter_mut()
            .zip(label)
        {
            *dst = src.to_ascii_lowercase();
        }
        self.len = start + 1 + label.len() + 1;
        self.buf[self.len - 1] = 0;
        self.labels += 1;
        Ok(())
    }

    /// The name from uncompressed wire bytes (which must end with the root label).
    ///
    /// # Errors
    ///
    /// [`NameError`] for malformed input.
    pub fn from_wire(wire: &[u8]) -> Result<Self, NameError> {
        let mut name = Self::root();
        let mut pos = 0;
        loop {
            let Some(&len) = wire.get(pos) else {
                return Err(NameError::BadLabel);
            };
            if len == 0 {
                return Ok(name);
            }
            let len = usize::from(len);
            let label = wire
                .get(pos + 1..pos + 1 + len)
                .ok_or(NameError::BadLabel)?;
            name.push_label(label)?;
            pos += 1 + len;
        }
    }

    /// The name of a model name.
    pub fn from_dns_name(name: &DnsName) -> Self {
        let mut out = Self::root();
        for label in name.labels() {
            // A `DnsName` is always a valid wire name.
            let _ = out.push_label(label.as_bytes());
        }
        out
    }

    /// The model name, if the labels are in its character set. Allocates; not for the
    /// query path.
    pub fn to_dns_name(&self) -> Option<DnsName> {
        DnsName::from_wire(self.as_wire())
            .ok()
            .map(|(name, _)| name)
    }

    /// The wire form.
    pub fn as_wire(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The number of labels, the root not counted.
    pub fn label_count(&self) -> usize {
        self.labels
    }

    /// Whether this is the root.
    pub fn is_root(&self) -> bool {
        self.labels == 0
    }

    /// The wire form without the `skip` leftmost labels; the root for `skip` at or above
    /// the label count.
    pub fn suffix(&self, skip: usize) -> &[u8] {
        suffix(self.as_wire(), skip)
    }

    /// The labels, leftmost first.
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            wire: self.as_wire(),
        }
    }
}

/// The wire form `wire` without its `skip` leftmost labels.
pub fn suffix(wire: &[u8], skip: usize) -> &[u8] {
    let mut pos = 0;
    for _ in 0..skip {
        match wire.get(pos) {
            Some(&len) if len != 0 => pos += 1 + usize::from(len),
            _ => break,
        }
    }
    wire.get(pos..).unwrap_or(&[0])
}

/// The number of labels of a wire name, the root not counted.
pub fn label_count(wire: &[u8]) -> usize {
    Labels { wire }.count()
}

/// The labels of a wire name, leftmost first.
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    wire: &'a [u8],
}

impl<'a> Labels<'a> {
    /// The labels of an uncompressed wire name.
    pub fn new(wire: &'a [u8]) -> Self {
        Self { wire }
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.wire.first()?);
        if len == 0 {
            return None;
        }
        let label = self.wire.get(1..1 + len)?;
        self.wire = &self.wire[1 + len..];
        Some(label)
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameBuf({self})")
    }
}

impl fmt::Display for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for (index, label) in self.labels().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            for &byte in label {
                if byte.is_ascii_graphic() && byte != b'.' && byte != b'\\' {
                    write!(f, "{}", char::from(byte))?;
                } else {
                    write!(f, "\\{byte:03}")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_build_lowercase_and_expose_their_suffixes() {
        let mut name = NameBuf::root();
        for label in [&b"WWW"[..], b"Example", b"TEST"] {
            name.push_label(label).expect("label");
        }
        assert_eq!(name.as_wire(), b"\x03www\x07example\x04test\x00");
        assert_eq!(name.label_count(), 3);
        assert_eq!(name.suffix(1), b"\x07example\x04test\x00");
        assert_eq!(name.suffix(3), b"\x00");
        assert_eq!(name.suffix(9), b"\x00");
        assert_eq!(name.to_string(), "www.example.test");
        assert_eq!(label_count(name.suffix(1)), 2);
        let model = DnsName::new("www.example.test").expect("name");
        assert_eq!(NameBuf::from_dns_name(&model), name);
        assert_eq!(name.to_dns_name(), Some(model));
        assert_eq!(NameBuf::from_wire(name.as_wire()), Ok(name.clone()));
        name.clear();
        assert!(name.is_root());
        assert_eq!(name.to_string(), ".");
    }

    #[test]
    fn limits_hold() {
        let mut name = NameBuf::root();
        assert_eq!(name.push_label(b""), Err(NameError::BadLabel));
        assert_eq!(name.push_label(&[b'a'; 64]), Err(NameError::BadLabel));
        for _ in 0..3 {
            name.push_label(&[b'a'; 63]).expect("label");
        }
        // 3 * 64 + 1 = 193 octets; one more 63-octet label would make 257.
        assert_eq!(name.push_label(&[b'a'; 63]), Err(NameError::TooLong));
        name.push_label(&[b'a'; 61]).expect("fits exactly");
        assert_eq!(name.as_wire().len(), MAX_NAME_LEN);
        assert!(NameBuf::from_wire(b"\x03ab").is_err());
        let mut odd = NameBuf::root();
        odd.push_label(b"a.b").expect("a dot inside a label");
        assert_eq!(odd.to_string(), "a\\046b");
    }
}
