//! The IANA trust anchor file (RFC 7958 section 2): a `TrustAnchor` element with its
//! `id` and `source`, a `Zone`, and one `KeyDigest` per key with `validFrom`,
//! `validUntil`, `KeyTag`, `Algorithm`, `DigestType`, `Digest` and, since 2024, the
//! `PublicKey` and `Flags`. Read with a small scanner of this one format (the file
//! carries no entities, namespaces or CDATA): it drives the check of the shipped file
//! against the generated table and the fuzz target `dns_trust_anchor_xml`.

/// One `KeyDigest` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDigest {
    /// The `id` attribute.
    pub id: String,
    /// The `validFrom` attribute, as written.
    pub valid_from: String,
    /// The `validUntil` attribute, as written; `None` when absent.
    pub valid_until: Option<String>,
    /// The key tag.
    pub key_tag: u16,
    /// The algorithm.
    pub algorithm: u8,
    /// The digest type.
    pub digest_type: u8,
    /// The digest octets.
    pub digest: Vec<u8>,
    /// The public key octets, when the element carries them.
    pub public_key: Option<Vec<u8>>,
    /// The DNSKEY flags, when the element carries them.
    pub flags: Option<u16>,
}

impl KeyDigest {
    /// The DS record's data of the digest.
    pub fn ds_rdata(&self) -> Vec<u8> {
        let mut out = self.key_tag.to_be_bytes().to_vec();
        out.push(self.algorithm);
        out.push(self.digest_type);
        out.extend_from_slice(&self.digest);
        out
    }
}

/// The file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorFile {
    /// The `id` attribute of `TrustAnchor`.
    pub id: String,
    /// The `source` attribute.
    pub source: String,
    /// The zone, `.` for the root.
    pub zone: String,
    /// The key digests in file order.
    pub digests: Vec<KeyDigest>,
}

/// Why the text is not a trust anchor file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct XmlError(pub &'static str);

/// The most key digests a file may hold.
pub const MAX_DIGESTS: usize = 64;

/// A scanner over the text.
/// An opening tag: its name and its attributes.
type Open<'a> = (&'a str, Vec<(&'a str, &'a str)>);

struct Scanner<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn skip_space(&mut self) {
        while let Some(rest) = self.text.get(self.pos..)
            && let Some(first) = rest.chars().next()
            && first.is_whitespace()
        {
            self.pos += first.len_utf8();
        }
    }

    /// Skips the XML declaration and comments.
    fn skip_prolog(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_space();
            let rest = &self.text[self.pos..];
            if let Some(after) = rest.strip_prefix("<?") {
                let end = after
                    .find("?>")
                    .ok_or(XmlError("an unterminated declaration"))?;
                self.pos += 2 + end + 2;
            } else if let Some(after) = rest.strip_prefix("<!--") {
                let end = after
                    .find("-->")
                    .ok_or(XmlError("an unterminated comment"))?;
                self.pos += 4 + end + 3;
            } else {
                return Ok(());
            }
        }
    }

    /// Reads an opening tag `<name attr="v" ...>`; returns the name and the attributes.
    fn open(&mut self) -> Result<Open<'a>, XmlError> {
        self.skip_prolog()?;
        let rest = &self.text[self.pos..];
        let rest = rest
            .strip_prefix('<')
            .ok_or(XmlError("an element was expected"))?;
        let end = rest.find('>').ok_or(XmlError("an unterminated tag"))?;
        let inside = &rest[..end];
        if inside.ends_with('/') || inside.starts_with('/') {
            return Err(XmlError("an element with content was expected"));
        }
        let name_end = inside
            .find(|c: char| c.is_whitespace())
            .unwrap_or(inside.len());
        let name = &inside[..name_end];
        if name.is_empty() {
            return Err(XmlError("an element has a name"));
        }
        let mut attributes = Vec::new();
        let mut attrs = inside[name_end..].trim();
        while !attrs.is_empty() {
            let eq = attrs
                .find('=')
                .ok_or(XmlError("an attribute has a value"))?;
            let key = attrs[..eq].trim();
            let value_part = attrs[eq + 1..].trim_start();
            let quote = value_part
                .chars()
                .next()
                .filter(|c| *c == '"' || *c == '\'')
                .ok_or(XmlError("an attribute value is quoted"))?;
            let value_end = value_part[1..]
                .find(quote)
                .ok_or(XmlError("an unterminated attribute value"))?;
            let value = &value_part[1..=value_end];
            attributes.push((key, value));
            attrs = value_part[1 + value_end + 1..].trim_start();
        }
        self.pos += 1 + end + 1;
        Ok((name, attributes))
    }

    /// Whether the next thing is the closing tag of `name`; consumes it when it is.
    fn close(&mut self, name: &str) -> Result<bool, XmlError> {
        self.skip_prolog()?;
        let rest = &self.text[self.pos..];
        let Some(after) = rest.strip_prefix("</") else {
            return Ok(false);
        };
        let end = after
            .find('>')
            .ok_or(XmlError("an unterminated closing tag"))?;
        if after[..end].trim() != name {
            return Err(XmlError("a closing tag does not match"));
        }
        self.pos += 2 + end + 1;
        Ok(true)
    }

    /// Reads the text up to the next tag.
    fn text(&mut self) -> &'a str {
        let rest = &self.text[self.pos..];
        let end = rest.find('<').unwrap_or(rest.len());
        self.pos += end;
        rest[..end].trim()
    }

    /// Reads `<name>text</name>`.
    fn simple(&mut self, name: &'a str) -> Result<&'a str, XmlError> {
        let text = self.text();
        if !self.close(name)? {
            return Err(XmlError("a simple element holds text only"));
        }
        Ok(text)
    }
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn attribute<'a>(attributes: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

/// Reads one `KeyDigest` after its opening tag.
fn key_digest(
    scanner: &mut Scanner<'_>,
    attributes: &[(&str, &str)],
) -> Result<KeyDigest, XmlError> {
    let mut digest = KeyDigest {
        id: attribute(attributes, "id")
            .ok_or(XmlError("a KeyDigest has an id"))?
            .to_owned(),
        valid_from: attribute(attributes, "validFrom")
            .ok_or(XmlError("a KeyDigest has validFrom"))?
            .to_owned(),
        valid_until: attribute(attributes, "validUntil").map(str::to_owned),
        key_tag: 0,
        algorithm: 0,
        digest_type: 0,
        digest: Vec::new(),
        public_key: None,
        flags: None,
    };
    let (mut tag, mut algorithm, mut digest_type, mut digest_hex) = (None, None, None, None);
    loop {
        if scanner.close("KeyDigest")? {
            break;
        }
        let (name, _) = scanner.open()?;
        let text = scanner.simple(name)?;
        match name {
            "KeyTag" => {
                tag = Some(
                    text.parse()
                        .map_err(|_| XmlError("the KeyTag is a number"))?,
                );
            }
            "Algorithm" => {
                algorithm = Some(
                    text.parse()
                        .map_err(|_| XmlError("the Algorithm is a number"))?,
                );
            }
            "DigestType" => {
                digest_type = Some(
                    text.parse()
                        .map_err(|_| XmlError("the DigestType is a number"))?,
                );
            }
            "Digest" => digest_hex = Some(hex(text).ok_or(XmlError("the Digest is hexadecimal"))?),
            "PublicKey" => {
                digest.public_key =
                    Some(super::base64::decode(text).ok_or(XmlError("the PublicKey is base64"))?);
            }
            "Flags" => {
                digest.flags = Some(
                    text.parse()
                        .map_err(|_| XmlError("the Flags are a number"))?,
                );
            }
            _ => return Err(XmlError("an unknown element in a KeyDigest")),
        }
    }
    digest.key_tag = tag.ok_or(XmlError("a KeyDigest has a KeyTag"))?;
    digest.algorithm = algorithm.ok_or(XmlError("a KeyDigest has an Algorithm"))?;
    digest.digest_type = digest_type.ok_or(XmlError("a KeyDigest has a DigestType"))?;
    digest.digest = digest_hex.ok_or(XmlError("a KeyDigest has a Digest"))?;
    Ok(digest)
}

/// Reads a trust anchor file.
///
/// # Errors
///
/// [`XmlError`] naming what is wrong.
pub fn parse(text: &str) -> Result<AnchorFile, XmlError> {
    if text.len() > 1 << 20 {
        return Err(XmlError("the file is too large"));
    }
    let mut scanner = Scanner { text, pos: 0 };
    let (root, attributes) = scanner.open()?;
    if root != "TrustAnchor" {
        return Err(XmlError("the root element is TrustAnchor"));
    }
    let mut file = AnchorFile {
        id: attribute(&attributes, "id")
            .ok_or(XmlError("the TrustAnchor has an id"))?
            .to_owned(),
        source: attribute(&attributes, "source")
            .unwrap_or_default()
            .to_owned(),
        zone: String::new(),
        digests: Vec::new(),
    };
    let mut zone = None;
    loop {
        if scanner.close("TrustAnchor")? {
            break;
        }
        let (name, attributes) = scanner.open()?;
        match name {
            "Zone" => zone = Some(scanner.simple("Zone")?.to_owned()),
            "KeyDigest" => {
                if file.digests.len() >= MAX_DIGESTS {
                    return Err(XmlError("too many key digests"));
                }
                file.digests.push(key_digest(&mut scanner, &attributes)?);
            }
            _ => return Err(XmlError("an unknown element in the TrustAnchor")),
        }
    }
    file.zone = zone.ok_or(XmlError("the TrustAnchor names its Zone"))?;
    scanner.skip_prolog()?;
    if scanner.pos != text.len() {
        return Err(XmlError("text after the TrustAnchor"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::shipped;

    #[test]
    fn the_shipped_file_reads_as_the_generated_table() {
        let file = parse(shipped::ROOT_ANCHORS_XML).expect("the shipped file");
        assert_eq!(file.id, shipped::ROOT_ANCHORS_ID);
        assert_eq!(file.zone, ".");
        assert_eq!(file.digests.len(), shipped::ROOT_ANCHORS.len());
        for (digest, shipped) in file.digests.iter().zip(shipped::ROOT_ANCHORS) {
            assert_eq!(digest.id, shipped.id);
            assert_eq!(digest.key_tag, shipped.key_tag);
            assert_eq!(digest.algorithm, shipped.algorithm);
            assert_eq!(digest.digest_type, shipped.digest_type);
            assert_eq!(digest.digest, shipped.digest);
            assert_eq!(digest.valid_from, shipped.valid_from);
            assert_eq!(digest.valid_until.as_deref(), shipped.valid_until);
        }
        // The public keys the file carries hash to their digests.
        let root = tenko_core::dns::DnsName::root().to_wire();
        for digest in file
            .digests
            .iter()
            .filter(|digest| digest.public_key.is_some())
        {
            let mut dnskey = digest.flags.unwrap_or(257).to_be_bytes().to_vec();
            dnskey.push(3);
            dnskey.push(digest.algorithm);
            dnskey.extend_from_slice(digest.public_key.as_deref().unwrap_or_default());
            assert!(crate::dnssec::crypto::ds_matches(
                &root,
                &dnskey,
                &digest.ds_rdata()
            ));
        }
    }

    #[test]
    fn broken_files_are_refused() {
        for text in [
            "",
            "<Zone>.</Zone>",
            "<TrustAnchor id=\"x\"><Zone>.</Zone>",
            "<TrustAnchor id=\"x\"><Zone>.</Zone><KeyDigest id=\"k\" validFrom=\"t\"><KeyTag>x</KeyTag></KeyDigest></TrustAnchor>",
            "<TrustAnchor id=\"x\"><Zone>.</Zone><Other/></TrustAnchor>",
            "<TrustAnchor id=\"x\"><Zone>.</Zone></TrustAnchor>trailing",
            "<TrustAnchor id=x><Zone>.</Zone></TrustAnchor>",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        let minimal = "<?xml version=\"1.0\"?><!-- a comment --><TrustAnchor id=\"x\"><Zone>example.test</Zone></TrustAnchor>";
        let file = parse(minimal).expect("minimal");
        assert_eq!(file.zone, "example.test");
        assert_eq!(file.digests, vec![]);
    }
}
