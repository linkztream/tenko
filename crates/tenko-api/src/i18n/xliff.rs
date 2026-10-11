//! The XLIFF 2.0 subset of language packs, read with `quick-xml`.
//!
//! The format is the one of the built-in files in `ui/i18n/` (see
//! `ui/scripts/i18n/compile.mjs`, which reads them at build time):
//!
//! - UTF-8, no DOCTYPE (so no entity definitions); the predefined entities and numeric
//!   character references are decoded; line endings are normalized to LF first.
//! - Root `<xliff version="2.0" srcLang="en" trgLang="<tag>">` in the XLIFF 2.0 namespace with
//!   exactly one `<file>`. Its `<mda:metadata>` may hold a meta group of category
//!   `language-pack` with the entries `displayName`, `author`, `version` and
//!   `sourceLanguage`.
//! - `<group>` elements nest freely; a `<unit id="area.some.key">` has exactly one `<segment>`
//!   with one `<source>` and at most one `<target>`. Notes and elements of other namespaces
//!   are ignored.
//! - `<source>` and `<target>` hold text only: an inline element (`<pc>`, `<ph>`, `<mrk>`,
//!   anything) makes the unit unusable. A translation that needs markup-like text writes it
//!   escaped (`&lt;b&gt;`) and the UI shows it as text.
//! - The text of an element is its character data and CDATA sections. When the text contains
//!   a line break, the white space (space, tab, line feed) before the first and after the last
//!   character of the raw text is dropped, which removes the indentation of pretty printing;
//!   character references and CDATA content at the edges stay.
//!
//! Problems of the document as a whole are errors ([`XliffError`]); problems of one unit are
//! recorded on the unit and leave the others readable.

use quick_xml::{
    XmlVersion,
    encoding::Decoder,
    events::{BytesDecl, BytesStart, Event},
    name::ResolveResult,
    reader::NsReader,
};

/// The XLIFF 2.0 namespace.
pub const XLIFF_NS: &str = "urn:oasis:names:tc:xliff:document:2.0";
/// The XLIFF 2.0 metadata module namespace.
pub const METADATA_NS: &str = "urn:oasis:names:tc:xliff:metadata:2.0";
/// The category of the meta group with the pack's metadata.
pub const META_CATEGORY: &str = "language-pack";

/// The deepest element nesting of a document.
pub const MAX_DEPTH: usize = 32;
/// The most units of a document.
pub const MAX_UNITS: usize = 20_000;

/// A problem of the document as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XliffError {
    /// The stable code (`i18n.pack.*`).
    pub code: &'static str,
    /// English explanation.
    pub message: String,
    /// The 1-based line, when the problem has a place.
    pub line: Option<u32>,
}

impl XliffError {
    fn new(code: &'static str, message: impl Into<String>, line: Option<u32>) -> Self {
        Self {
            code,
            message: message.into(),
            line,
        }
    }
}

impl std::fmt::Display for XliffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "{} (line {line})", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for XliffError {}

/// The metadata of a pack; empty strings for absent entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// The language's name in itself.
    pub display_name: String,
    /// Who made the pack.
    pub author: String,
    /// The pack's own version.
    pub version: String,
    /// The language the pack translates from.
    pub source_language: String,
}

/// One `<unit>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The `id` attribute: the message key.
    pub id: String,
    /// The 1-based line of the `<unit>` tag.
    pub line: u32,
    /// The `<source>` text.
    pub source: Option<String>,
    /// The `<target>` text.
    pub target: Option<String>,
    /// The first note of category `description`: what the message is for.
    pub description: Option<String>,
    /// Why the unit cannot be used: a code and an English explanation.
    pub problem: Option<(&'static str, String)>,
}

/// A read document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// `srcLang`.
    pub src_lang: String,
    /// `trgLang`, when present.
    pub trg_lang: Option<String>,
    /// The `language-pack` metadata.
    pub metadata: Metadata,
    /// Whether the document carries a `language-pack` meta group at all.
    pub has_metadata: bool,
    /// The units in document order.
    pub units: Vec<Unit>,
}

/// A namespace as the reader resolved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ns {
    Xliff,
    Metadata,
    Other,
}

#[derive(Debug)]
struct Element {
    ns: Ns,
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
    line: u32,
}

#[derive(Debug)]
enum Node {
    Element(Element),
    /// Character data; the reader reports references separately, so it holds none.
    Text(String),
    /// A decoded entity or character reference.
    Reference(String),
    CData(String),
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn children<'a>(&'a self, ns: Ns, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter_map(move |node| match node {
            Node::Element(el) if el.ns == ns && el.name == name => Some(el),
            _ => None,
        })
    }
}

/// Byte offsets of line starts, for line numbers.
struct Lines(Vec<usize>);

impl Lines {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Self(starts)
    }

    fn line(&self, offset: u64) -> u32 {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let index = self.0.partition_point(|&start| start <= offset);
        u32::try_from(index.max(1)).unwrap_or(u32::MAX)
    }
}

fn namespace(resolved: &ResolveResult<'_>) -> Ns {
    match resolved {
        ResolveResult::Bound(ns) if ns.as_ref() == XLIFF_NS.as_bytes() => Ns::Xliff,
        ResolveResult::Bound(ns) if ns.as_ref() == METADATA_NS.as_bytes() => Ns::Metadata,
        _ => Ns::Other,
    }
}

fn utf8(bytes: &[u8]) -> Result<String, XliffError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| XliffError::new("i18n.pack.xml", "the document is not UTF-8", None))
}

/// Whether a code point may appear in an XML 1.0 document.
fn is_xml_char(c: u32) -> bool {
    matches!(c, 0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x1_0000..=0x10_ffff)
}

fn reference(name: &str, line: u32) -> Result<String, XliffError> {
    let bad = || {
        XliffError::new(
            "i18n.pack.xml",
            format!(
                "the reference &{name}; is not allowed: only the predefined entities and character references are"
            ),
            Some(line),
        )
    };
    let text = match name {
        "amp" => "&".to_owned(),
        "lt" => "<".to_owned(),
        "gt" => ">".to_owned(),
        "quot" => "\"".to_owned(),
        "apos" => "'".to_owned(),
        _ => {
            let code = if let Some(hex) = name.strip_prefix("#x") {
                u32::from_str_radix(hex, 16).map_err(|_| bad())?
            } else if let Some(dec) = name.strip_prefix('#') {
                dec.parse::<u32>().map_err(|_| bad())?
            } else {
                return Err(bad());
            };
            if !is_xml_char(code) {
                return Err(bad());
            }
            char::from_u32(code).ok_or_else(bad)?.to_string()
        }
    };
    Ok(text)
}

fn start_element(
    start: &BytesStart<'_>,
    ns: Ns,
    line: u32,
    decoder: Decoder,
) -> Result<Element, XliffError> {
    let name = utf8(start.local_name().as_ref())?;
    let mut attrs = Vec::new();
    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|error| {
            XliffError::new(
                "i18n.pack.xml",
                format!("the document is not well formed: {error}"),
                Some(line),
            )
        })?;
        let key = utf8(attr.key.as_ref())?;
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|error| {
                XliffError::new(
                    "i18n.pack.xml",
                    format!("the attribute {key} is not well formed: {error}"),
                    Some(line),
                )
            })?;
        attrs.push((key, value.into_owned()));
    }
    Ok(Element {
        ns,
        name,
        attrs,
        children: Vec::new(),
        line,
    })
}

/// The tree under construction: the open elements and, once closed, the root.
struct TreeBuilder {
    stack: Vec<Element>,
    root: Option<Element>,
}

impl TreeBuilder {
    fn xml_error(message: &str, line: u32) -> XliffError {
        XliffError::new("i18n.pack.xml", message, Some(line))
    }

    /// Adds a finished element to its parent, or makes it the root.
    fn close(&mut self, element: Element) {
        match self.stack.last_mut() {
            Some(parent) => parent.children.push(Node::Element(element)),
            None => self.root = Some(element),
        }
    }

    fn open(&mut self, element: Element, line: u32) -> Result<(), XliffError> {
        if self.root.is_some() {
            return Err(Self::xml_error(
                "the document has more than one root element",
                line,
            ));
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(XliffError::new(
                "i18n.pack.xml",
                format!("elements are nested deeper than {MAX_DEPTH}"),
                Some(line),
            ));
        }
        self.stack.push(element);
        Ok(())
    }

    /// Adds character data, a reference or a CDATA section to the open element. White space
    /// outside the root is allowed, anything else is not.
    fn text(&mut self, node: Node, line: u32) -> Result<(), XliffError> {
        match self.stack.last_mut() {
            Some(parent) => {
                parent.children.push(node);
                Ok(())
            }
            None if matches!(&node, Node::Text(text) if text.trim().is_empty()) => Ok(()),
            None => Err(Self::xml_error("text outside the root element", line)),
        }
    }
}

/// Checks the encoding of the XML declaration: a pack is UTF-8.
fn check_declaration(decl: &BytesDecl<'_>, line: u32) -> Result<(), XliffError> {
    if let Some(encoding) = decl.encoding() {
        let encoding = encoding.map_err(|error| {
            XliffError::new(
                "i18n.pack.xml",
                format!("the XML declaration is not well formed: {error}"),
                Some(line),
            )
        })?;
        let encoding = String::from_utf8_lossy(&encoding).to_ascii_lowercase();
        if encoding != "utf-8" && encoding != "utf8" {
            return Err(XliffError::new(
                "i18n.pack.xml",
                format!("the XML declaration says encoding {encoding}, a pack must be UTF-8"),
                Some(line),
            ));
        }
    }
    Ok(())
}

/// Parses the XML of a document into a small tree.
fn parse_tree(text: &str) -> Result<Element, XliffError> {
    let lines = Lines::new(text);
    let mut reader = NsReader::from_str(text);
    {
        let config = reader.config_mut();
        config.check_end_names = true;
        config.check_comments = true;
        config.allow_dangling_amp = false;
        config.allow_unmatched_ends = false;
        config.expand_empty_elements = false;
        config.trim_text_start = false;
        config.trim_text_end = false;
    }
    let mut tree = TreeBuilder {
        stack: Vec::new(),
        root: None,
    };
    loop {
        let line = lines.line(reader.buffer_position());
        let decoder = reader.decoder();
        let (resolved, event) = reader.read_resolved_event().map_err(|error| {
            XliffError::new(
                "i18n.pack.xml",
                format!("the document is not well formed: {error}"),
                Some(line),
            )
        })?;
        let ns = namespace(&resolved);
        match event {
            Event::Decl(decl) => check_declaration(&decl, line)?,
            Event::DocType(_) => {
                return Err(TreeBuilder::xml_error(
                    "DOCTYPE declarations are not allowed",
                    line,
                ));
            }
            Event::Start(start) => tree.open(start_element(&start, ns, line, decoder)?, line)?,
            Event::Empty(start) => {
                tree.open(start_element(&start, ns, line, decoder)?, line)?;
                if let Some(element) = tree.stack.pop() {
                    tree.close(element);
                }
            }
            Event::End(_) => {
                let element = tree
                    .stack
                    .pop()
                    .ok_or_else(|| TreeBuilder::xml_error("an end tag has no start tag", line))?;
                tree.close(element);
            }
            Event::Text(text) => tree.text(Node::Text(utf8(&text.into_inner())?), line)?,
            Event::GeneralRef(name) => {
                let name = utf8(&name.into_inner())?;
                tree.text(Node::Reference(reference(&name, line)?), line)?;
            }
            Event::CData(data) => tree.text(Node::CData(utf8(&data.into_inner())?), line)?,
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if !tree.stack.is_empty() {
        return Err(XliffError::new(
            "i18n.pack.xml",
            "the document ends inside an element",
            None,
        ));
    }
    tree.root
        .ok_or_else(|| XliffError::new("i18n.pack.xml", "the document has no root element", None))
}

/// The text of an element by the text rule of the module documentation.
fn element_text(element: &Element) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Text,
        Reference,
        CData,
    }
    let mut pieces: Vec<(Kind, &str)> = Vec::new();
    for node in &element.children {
        match node {
            Node::Text(text) => pieces.push((Kind::Text, text)),
            Node::Reference(text) => pieces.push((Kind::Reference, text)),
            Node::CData(text) => pieces.push((Kind::CData, text)),
            Node::Element(_) => {}
        }
    }
    let multiline = pieces
        .iter()
        .any(|(kind, text)| *kind != Kind::Reference && text.contains('\n'));
    let mut texts: Vec<String> = pieces.iter().map(|(_, text)| (*text).to_owned()).collect();
    if multiline {
        let is_ws = |c: char| matches!(c, ' ' | '\t' | '\n');
        // Leading white space of the raw text: character data up to the first reference or
        // CDATA section.
        for (i, (kind, _)) in pieces.iter().enumerate() {
            if *kind != Kind::Text {
                break;
            }
            let trimmed = texts[i].trim_start_matches(is_ws).to_owned();
            let all = trimmed.is_empty();
            texts[i] = trimmed;
            if !all {
                break;
            }
        }
        for (i, (kind, _)) in pieces.iter().enumerate().rev() {
            if *kind != Kind::Text {
                break;
            }
            let trimmed = texts[i].trim_end_matches(is_ws).to_owned();
            let all = trimmed.is_empty();
            texts[i] = trimmed;
            if !all {
                break;
            }
        }
    }
    texts.concat()
}

fn read_metadata(file: &Element) -> (Metadata, bool) {
    let mut metadata = Metadata::default();
    let mut found = false;
    for group in file
        .children(Ns::Metadata, "metadata")
        .flat_map(|m| m.children(Ns::Metadata, "metaGroup"))
        .filter(|g| g.attr("category") == Some(META_CATEGORY))
    {
        found = true;
        for meta in group.children(Ns::Metadata, "meta") {
            let value = element_text(meta).trim().to_owned();
            let slot = match meta.attr("type") {
                Some("displayName") => &mut metadata.display_name,
                Some("author") => &mut metadata.author,
                Some("version") => &mut metadata.version,
                Some("sourceLanguage") => &mut metadata.source_language,
                _ => continue,
            };
            if slot.is_empty() {
                *slot = value;
            }
        }
    }
    (metadata, found)
}

fn read_unit(element: &Element) -> Unit {
    let mut unit = Unit {
        id: element.attr("id").unwrap_or_default().to_owned(),
        line: element.line,
        source: None,
        target: None,
        description: element
            .children(Ns::Xliff, "notes")
            .flat_map(|notes| notes.children(Ns::Xliff, "note"))
            .find(|note| note.attr("category") == Some("description"))
            .map(element_text),
        problem: None,
    };
    let segments: Vec<&Element> = element.children(Ns::Xliff, "segment").collect();
    if element.children(Ns::Xliff, "ignorable").next().is_some() {
        unit.problem = Some((
            "i18n.pack.structure",
            "<ignorable> is not supported, a unit has exactly one <segment>".to_owned(),
        ));
        return unit;
    }
    let segment = match segments.as_slice() {
        [segment] => *segment,
        [] => {
            unit.problem = Some((
                "i18n.pack.structure",
                "the unit has no <segment>".to_owned(),
            ));
            return unit;
        }
        _ => {
            unit.problem = Some((
                "i18n.pack.structure",
                format!(
                    "the unit has {} <segment> elements, exactly one is allowed",
                    segments.len()
                ),
            ));
            return unit;
        }
    };
    for name in ["source", "target"] {
        let found: Vec<&Element> = segment.children(Ns::Xliff, name).collect();
        if found.len() > 1 {
            unit.problem = Some((
                "i18n.pack.structure",
                format!(
                    "the segment has {} <{name}> elements, at most one is allowed",
                    found.len()
                ),
            ));
            return unit;
        }
        let Some(el) = found.first() else { continue };
        if let Some(inline) = el.children.iter().find_map(|node| match node {
            Node::Element(inline) => Some(inline),
            _ => None,
        }) {
            unit.problem = Some((
                "i18n.pack.markup",
                format!(
                    "<{name}> contains the element <{}>; inline markup is not supported, write it as text",
                    inline.name
                ),
            ));
            return unit;
        }
        let text = element_text(el);
        if name == "source" {
            unit.source = Some(text);
        } else {
            unit.target = Some(text);
        }
    }
    if unit.source.is_none() {
        unit.problem = Some((
            "i18n.pack.structure",
            "the segment has no <source>".to_owned(),
        ));
    }
    unit
}

fn collect_units(parent: &Element, out: &mut Vec<Unit>) -> Result<(), XliffError> {
    for node in &parent.children {
        let Node::Element(element) = node else {
            continue;
        };
        if element.ns != Ns::Xliff {
            continue;
        }
        match element.name.as_str() {
            "unit" => {
                if out.len() >= MAX_UNITS {
                    return Err(XliffError::new(
                        "i18n.pack.too_many_units",
                        format!("the pack has more than {MAX_UNITS} units"),
                        Some(element.line),
                    ));
                }
                out.push(read_unit(element));
            }
            "group" => collect_units(element, out)?,
            _ => {}
        }
    }
    Ok(())
}

/// Reads a document. `bytes` may start with a UTF-8 byte order mark.
///
/// # Errors
///
/// [`XliffError`] when the bytes are not well-formed UTF-8 XML, or the document is not an
/// XLIFF 2.0 document with one `<file>`, or it has too many units.
pub fn read(bytes: &[u8]) -> Result<Document, XliffError> {
    let bytes = bytes
        .strip_prefix(b"\xef\xbb\xbf".as_slice())
        .unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|error| {
        XliffError::new(
            "i18n.pack.xml",
            format!("the document is not UTF-8 (byte {})", error.valid_up_to()),
            None,
        )
    })?;
    // XML 1.0 section 2.11: every line break is a single line feed.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    if let Some((offset, c)) = text
        .char_indices()
        .find(|&(_, c)| !is_xml_char(u32::from(c)))
    {
        return Err(XliffError::new(
            "i18n.pack.xml",
            format!("the character U+{:04X} is not allowed in XML", u32::from(c)),
            Some(Lines::new(&text).line(u64::try_from(offset).unwrap_or(u64::MAX))),
        ));
    }
    let root = parse_tree(&text)?;
    if root.ns != Ns::Xliff || root.name != "xliff" {
        return Err(XliffError::new(
            "i18n.pack.root",
            format!("the root element must be <xliff> in the namespace {XLIFF_NS}"),
            Some(root.line),
        ));
    }
    match root.attr("version") {
        Some("2.0") => {}
        Some(other) => {
            return Err(XliffError::new(
                "i18n.pack.version",
                format!("the XLIFF version must be 2.0, found {other}"),
                Some(root.line),
            ));
        }
        None => {
            return Err(XliffError::new(
                "i18n.pack.version",
                "the version attribute is missing, it must be 2.0",
                Some(root.line),
            ));
        }
    }
    let src_lang = root
        .attr("srcLang")
        .ok_or_else(|| {
            XliffError::new(
                "i18n.pack.src_lang",
                "the srcLang attribute is missing",
                Some(root.line),
            )
        })?
        .to_owned();
    let trg_lang = root.attr("trgLang").map(str::to_owned);
    let files: Vec<&Element> = root.children(Ns::Xliff, "file").collect();
    let [file] = files.as_slice() else {
        return Err(XliffError::new(
            "i18n.pack.structure",
            format!("expected exactly one <file> element, found {}", files.len()),
            Some(root.line),
        ));
    };
    let (metadata, has_metadata) = read_metadata(file);
    let mut units = Vec::new();
    collect_units(file, &mut units)?;
    Ok(Document {
        src_lang,
        trg_lang,
        metadata,
        has_metadata,
        units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<xliff xmlns="{XLIFF_NS}" xmlns:mda="{METADATA_NS}" version="2.0" srcLang="en" trgLang="fr">
  <file id="ui">
    <mda:metadata>
      <mda:metaGroup category="language-pack">
        <mda:meta type="displayName">Français</mda:meta>
        <mda:meta type="author">Example translators</mda:meta>
        <mda:meta type="version">1.0</mda:meta>
        <mda:meta type="sourceLanguage">en</mda:meta>
      </mda:metaGroup>
    </mda:metadata>
    {body}
  </file>
</xliff>
"#
        )
    }

    fn read_ok(text: &str) -> Document {
        read(text.as_bytes()).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn reads_metadata_groups_and_units() {
        let document = read_ok(&doc(r#"<group id="common">
      <unit id="common.action.cancel">
        <notes><note category="description">A button.</note></notes>
        <segment><source>Cancel</source><target>Annuler</target></segment>
      </unit>
      <group id="nested"><unit id="common.greeting"><segment><source>Signed in as {name}</source></segment></unit></group>
    </group>"#));
        assert_eq!(document.src_lang, "en");
        assert_eq!(document.trg_lang.as_deref(), Some("fr"));
        assert!(document.has_metadata);
        assert_eq!(document.metadata.display_name, "Français");
        assert_eq!(document.metadata.author, "Example translators");
        assert_eq!(document.metadata.version, "1.0");
        assert_eq!(document.metadata.source_language, "en");
        assert_eq!(document.units.len(), 2);
        assert_eq!(document.units[0].id, "common.action.cancel");
        assert_eq!(document.units[0].target.as_deref(), Some("Annuler"));
        assert_eq!(document.units[1].target, None);
        assert_eq!(
            document.units[1].source.as_deref(),
            Some("Signed in as {name}")
        );
        assert!(document.units[0].line > 1);
    }

    #[test]
    fn text_follows_the_compiler_rule() {
        let document = read_ok(&doc(
            "<unit id=\"a.b\"><segment><source>\n      Two\n      lines  \n    </source>\
             <target>\n  &#32;kept&#32;\n  </target></segment></unit>\
             <unit id=\"a.c\"><segment><source>  edge  </source><target><![CDATA[\n x ]]>&lt;b&gt; &amp;amp;</target></segment></unit>\r\n",
        ));
        assert_eq!(
            document.units[0].source.as_deref(),
            Some("Two\n      lines")
        );
        assert_eq!(document.units[0].target.as_deref(), Some(" kept "));
        assert_eq!(document.units[1].source.as_deref(), Some("  edge  "));
        assert_eq!(document.units[1].target.as_deref(), Some("\n x <b> &amp;"));
    }

    #[test]
    fn inline_markup_and_bad_structure_spoil_only_their_unit() {
        let document = read_ok(&doc(
            r#"<unit id="a.markup"><segment><source>Hi</source><target>Hi <pc id="1">there</pc></target></segment></unit>
      <unit id="a.two"><segment><source>A</source></segment><segment><source>B</source></segment></unit>
      <unit id="a.none"/>
      <unit id="a.ok"><segment><source>Fine</source><target>Bien</target></segment></unit>"#,
        ));
        let problems: Vec<_> = document
            .units
            .iter()
            .map(|u| u.problem.as_ref().map(|p| p.0))
            .collect();
        assert_eq!(
            problems,
            [
                Some("i18n.pack.markup"),
                Some("i18n.pack.structure"),
                Some("i18n.pack.structure"),
                None
            ]
        );
    }

    #[test]
    fn documents_that_are_not_packs_are_refused() {
        let cases: [(&str, &str); 9] = [
            ("<xliff", "i18n.pack.xml"),
            ("<a/><b/>", "i18n.pack.xml"),
            (
                "<!DOCTYPE x [<!ENTITY e \"boom\">]><x>&e;</x>",
                "i18n.pack.xml",
            ),
            ("<x>&e;</x>", "i18n.pack.xml"),
            ("<x>a & b</x>", "i18n.pack.xml"),
            (
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><x/>",
                "i18n.pack.xml",
            ),
            ("<xliff version=\"2.0\" srcLang=\"en\"/>", "i18n.pack.root"),
            (
                &format!("<xliff xmlns=\"{XLIFF_NS}\" version=\"1.2\" srcLang=\"en\"/>"),
                "i18n.pack.version",
            ),
            (
                &format!(
                    "<xliff xmlns=\"{XLIFF_NS}\" version=\"2.0\" srcLang=\"en\"><file/><file/></xliff>"
                ),
                "i18n.pack.structure",
            ),
        ];
        for (text, code) in cases {
            let error = read(text.as_bytes()).expect_err(text);
            assert_eq!(error.code, code, "{text}: {error}");
        }
        assert_eq!(
            read(b"\xff\xfe").expect_err("not utf-8").code,
            "i18n.pack.xml"
        );
        assert_eq!(
            read("<x>\u{1}</x>".as_bytes()).expect_err("control").code,
            "i18n.pack.xml"
        );
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert!(
            read(deep.as_bytes())
                .expect_err("deep")
                .message
                .contains("nested")
        );
    }

    #[test]
    fn a_byte_order_mark_and_crlf_are_accepted() {
        let text = format!(
            "\u{feff}{}",
            doc("<unit id=\"a.b\"><segment><source>x\ny</source></segment></unit>")
                .replace('\n', "\r\n")
        );
        let document = read_ok(&text);
        assert_eq!(document.units[0].source.as_deref(), Some("x\ny"));
    }
}
