//! Domain names in DHCP options: the uncompressed wire form of option 81 (RFC 4702,
//! section 2.3.1), the compressed list of option 119 (RFC 3397, with the compression of
//! RFC 1035, section 4.1.4) and the deprecated ASCII form of option 81.

use std::fmt;

use super::{DecodeError, EncodeError, code};

/// The longest name in wire form, the root label included (RFC 1035, section 2.3.4).
pub const MAX_WIRE_LEN: usize = 255;

/// The longest label.
const MAX_LABEL_LEN: usize = 63;

/// A domain name in uncompressed wire form, held inline (no allocation): length-prefixed
/// labels, and the zero-length root label when the name is absolute. A relative name is a
/// partial name of option 81 that the server completes, or an empty one.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireName {
    buf: [u8; MAX_WIRE_LEN],
    len: u8,
    absolute: bool,
}

impl Default for WireName {
    fn default() -> Self {
        Self {
            buf: [0; MAX_WIRE_LEN],
            len: 0,
            absolute: false,
        }
    }
}

impl WireName {
    /// A name from uncompressed wire form: labels up to a zero-length label (absolute) or
    /// up to the end of `data` (relative, the partial names of RFC 4702). `None` for a
    /// compression pointer, a label that runs past the end, octets after the root label or
    /// a name above 255 octets.
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        let mut name = Self::default();
        let mut pos = 0;
        while let Some(&len) = data.get(pos) {
            if len == 0 {
                name.push_root()?;
                return (pos + 1 == data.len()).then_some(name);
            }
            let label = data.get(pos + 1..pos + 1 + usize::from(len))?;
            name.push_label(label)?;
            pos += 1 + usize::from(len);
        }
        Some(name)
    }

    /// A name from dotted text: absolute with a trailing dot, relative without, the root
    /// for `.`, empty for an empty text. `None` for an empty label, a label above 63
    /// octets or a name above 255 octets. Escapes are not read: every octet but the dot is
    /// a label octet.
    pub fn from_text(text: &[u8]) -> Option<Self> {
        let mut name = Self::default();
        if text == b"." {
            name.push_root()?;
            return Some(name);
        }
        let (labels, absolute) = match text.strip_suffix(b".") {
            Some(labels) => (labels, true),
            None => (text, false),
        };
        if !labels.is_empty() {
            for label in labels.split(|&b| b == b'.') {
                name.push_label(label)?;
            }
        }
        if absolute {
            name.push_root()?;
        }
        Some(name)
    }

    /// A name from dotted text; see [`WireName::from_text`].
    pub fn from_str_text(text: &str) -> Option<Self> {
        Self::from_text(text.as_bytes())
    }

    fn push_label(&mut self, label: &[u8]) -> Option<()> {
        let len = usize::from(self.len);
        // Keep room for the root label.
        if label.is_empty() || label.len() > MAX_LABEL_LEN || len + 1 + label.len() >= MAX_WIRE_LEN
        {
            return None;
        }
        self.buf[len] = u8::try_from(label.len()).ok()?;
        self.buf[len + 1..len + 1 + label.len()].copy_from_slice(label);
        self.len = u8::try_from(len + 1 + label.len()).ok()?;
        Some(())
    }

    fn push_root(&mut self) -> Option<()> {
        let len = usize::from(self.len);
        if self.absolute || len >= MAX_WIRE_LEN {
            return None;
        }
        self.buf[len] = 0;
        self.len = u8::try_from(len + 1).ok()?;
        self.absolute = true;
        Some(())
    }

    /// The wire form, with the root label when the name is absolute.
    pub fn as_wire(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Whether the name ends with the root label (a fully qualified name).
    pub fn is_absolute(&self) -> bool {
        self.absolute
    }

    /// Whether the name has no label (the root counts as empty).
    pub fn is_empty(&self) -> bool {
        self.labels().next().is_none()
    }

    /// The labels, without the root.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let mut rest = self.as_wire();
        std::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            if len == 0 {
                return None;
            }
            let label = &tail[..usize::from(len)];
            rest = &tail[usize::from(len)..];
            Some(label)
        })
    }
}

/// The dotted text without a trailing dot (the root alone is `.`); `.` and `\` inside a
/// label are escaped with `\`, other octets outside printable ASCII as `\DDD`.
impl fmt::Display for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for label in self.labels() {
            if !first {
                f.write_str(".")?;
            }
            first = false;
            for &octet in label {
                match octet {
                    b'.' | b'\\' => write!(f, "\\{}", char::from(octet))?,
                    0x21..=0x7e => write!(f, "{}", char::from(octet))?,
                    _ => write!(f, "\\{octet:03}")?,
                }
            }
        }
        if first && self.absolute {
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dot = if self.absolute && !self.is_empty() {
            "."
        } else {
            ""
        };
        write!(f, "WireName({self}{dot})")
    }
}

/// Option 119, the domain search list (RFC 3397): absolute names, compressed against the
/// names before them in the same option. A long list is split over several instances;
/// read it from the concatenation ([`super::Message::option_data`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSearch<'a> {
    data: &'a [u8],
}

impl<'a> DomainSearch<'a> {
    /// The list in `data`; every name is decoded once.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadLength`] for an empty value, [`DecodeError::BadValue`] for a name
    /// that does not decode: a label that runs past the end, a pointer that does not point
    /// before the name it is in, a name above 255 octets.
    pub fn parse(data: &'a [u8]) -> Result<Self, DecodeError> {
        const CODE: u8 = code::DOMAIN_SEARCH;
        if data.is_empty() {
            return Err(DecodeError::BadLength { code: CODE, len: 0 });
        }
        let mut pos = 0;
        while pos < data.len() {
            let (_, next) = decode_at(data, pos).ok_or(DecodeError::BadValue { code: CODE })?;
            pos = next;
        }
        Ok(Self { data })
    }

    /// The names in order.
    pub fn iter(&self) -> impl Iterator<Item = WireName> + 'a {
        let data = self.data;
        let mut pos = 0;
        std::iter::from_fn(move || {
            if pos >= data.len() {
                return None;
            }
            let (name, next) = decode_at(data, pos)?;
            pos = next;
            Some(name)
        })
    }

    /// The value as it is on the wire.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// Decodes the compressed name at `start` and returns it with the position after it. A
/// pointer must point before the start of the name, and every later pointer before the
/// one followed last, so the walk always ends.
fn decode_at(data: &[u8], start: usize) -> Option<(WireName, usize)> {
    let mut name = WireName::default();
    let mut pos = start;
    let mut limit = start;
    let mut next = None;
    loop {
        let len = *data.get(pos)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                name.push_root()?;
                return Some((name, next.unwrap_or(pos + 1)));
            }
            0x00 => {
                let label = data.get(pos + 1..pos + 1 + usize::from(len))?;
                name.push_label(label)?;
                pos += 1 + usize::from(len);
            }
            0xc0 => {
                let low = *data.get(pos + 1)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= limit {
                    return None;
                }
                next.get_or_insert(pos + 2);
                limit = target;
                pos = target;
            }
            _ => return None,
        }
    }
}

/// Whether the name at `pos` in `out` (written by [`encode_domain_search`], so well
/// formed) is the uncompressed `suffix`.
fn same_name(out: &[u8], mut pos: usize, mut suffix: &[u8]) -> bool {
    for _ in 0..MAX_WIRE_LEN {
        let Some(&len) = out.get(pos) else {
            return false;
        };
        if len & 0xc0 == 0xc0 {
            let Some(&low) = out.get(pos + 1) else {
                return false;
            };
            pos = (usize::from(len & 0x3f) << 8) | usize::from(low);
            continue;
        }
        if suffix.first() != Some(&len) {
            return false;
        }
        if len == 0 {
            return true;
        }
        let n = usize::from(len);
        if out.get(pos + 1..pos + 1 + n) != suffix.get(1..1 + n) {
            return false;
        }
        pos += 1 + n;
        suffix = &suffix[1 + n..];
    }
    false
}

/// Writes `names` as the value of option 119 into `out` and returns its length. Every
/// name is compressed against the names before it (RFC 3397, section 2): its longest
/// suffix that was written already becomes a pointer.
///
/// # Errors
///
/// [`EncodeError::BadValue`] for an empty list or a relative name,
/// [`EncodeError::NoRoom`] when `out` is too small.
pub fn encode_domain_search(names: &[WireName], out: &mut [u8]) -> Result<usize, EncodeError> {
    const CODE: u8 = code::DOMAIN_SEARCH;
    if names.is_empty() {
        return Err(EncodeError::BadValue { code: CODE });
    }
    // Where the written labels start: the pointer targets.
    let mut starts = [0u16; 256];
    let mut count = 0;
    let mut len = 0;
    for name in names {
        if !name.is_absolute() {
            return Err(EncodeError::BadValue { code: CODE });
        }
        let wire = name.as_wire();
        let mut cut = 0;
        let mut pointer = None;
        while wire[cut] != 0 {
            pointer = starts[..count]
                .iter()
                .copied()
                .find(|&start| same_name(&out[..len], usize::from(start), &wire[cut..]));
            if pointer.is_some() {
                break;
            }
            cut += 1 + usize::from(wire[cut]);
        }
        let need = cut + if pointer.is_some() { 2 } else { 1 };
        let target = out
            .get_mut(len..len + need)
            .ok_or(EncodeError::NoRoom { code: CODE })?;
        target[..cut].copy_from_slice(&wire[..cut]);
        let mut label = 0;
        while label < cut {
            if let Ok(start) = u16::try_from(len + label)
                && start < 0x4000
                && count < starts.len()
            {
                starts[count] = start;
                count += 1;
            }
            label += 1 + usize::from(wire[label]);
        }
        match pointer {
            Some(start) => target[cut..].copy_from_slice(&(0xc000 | start).to_be_bytes()),
            None => target[cut] = 0,
        }
        len += need;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> WireName {
        WireName::from_str_text(text).expect("a name")
    }

    #[test]
    fn text_and_wire_forms_agree() {
        let absolute = name("host.example.test.");
        assert!(absolute.is_absolute());
        assert_eq!(absolute.as_wire(), b"\x04host\x07example\x04test\x00");
        assert_eq!(absolute.to_string(), "host.example.test");
        assert_eq!(WireName::from_wire(absolute.as_wire()), Some(absolute));
        let partial = name("host");
        assert!(!partial.is_absolute());
        assert_eq!(partial.as_wire(), b"\x04host");
        assert_eq!(WireName::from_wire(b"\x04host"), Some(partial));
        assert_eq!(name(".").as_wire(), b"\x00");
        assert_eq!(name(".").to_string(), ".");
        assert!(name("").is_empty());
        assert_eq!(WireName::from_text(b"a..b"), None);
        assert_eq!(WireName::from_text(b".a"), None);
        assert_eq!(WireName::from_wire(b"\x00\x00"), None);
        assert_eq!(WireName::from_wire(b"\xc0\x00"), None);
    }

    #[test]
    fn display_escapes() {
        let odd = WireName::from_wire(b"\x03a.b\x02\\\x01\x00").expect("wire");
        assert_eq!(odd.to_string(), "a\\.b.\\\\\\001");
    }

    #[test]
    fn length_limits() {
        let label = "a".repeat(63);
        assert!(WireName::from_str_text(&label).is_some());
        assert!(WireName::from_str_text(&"a".repeat(64)).is_none());
        // Four labels of 63 octets are 256 octets of wire form with the root.
        let long = [label.as_str(); 4].join(".");
        assert!(WireName::from_str_text(&long).is_none());
        let longest = format!("{}.{}", [label.as_str(); 3].join("."), "a".repeat(61));
        let longest = WireName::from_str_text(&format!("{longest}.")).expect("255 octets");
        assert_eq!(longest.as_wire().len(), MAX_WIRE_LEN);
    }

    #[test]
    fn compression_round_trip() {
        let names = [
            name("eng.example.test."),
            name("marketing.example.test."),
            name("example.test."),
            name("other.test."),
        ];
        let mut out = [0; 128];
        let len = encode_domain_search(&names, &mut out).expect("encode");
        assert_eq!(
            &out[..len],
            b"\x03eng\x07example\x04test\x00\x09marketing\xc0\x04\xc0\x04\x05other\xc0\x0c"
        );
        let list = DomainSearch::parse(&out[..len]).expect("decode");
        assert!(list.iter().eq(names));
    }

    #[test]
    fn pointer_loops_are_refused() {
        assert!(DomainSearch::parse(b"\xc0\x00").is_err());
        assert!(DomainSearch::parse(b"\x01a\xc0\x00").is_err());
        assert!(DomainSearch::parse(b"\x01a\x00\xc0\x03").is_err());
        assert!(DomainSearch::parse(b"\x01a\x00\x01b\xc0\x00").is_ok());
        assert!(DomainSearch::parse(b"\x40").is_err());
    }
}
