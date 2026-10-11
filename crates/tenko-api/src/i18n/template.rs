//! The template of a language: the running key set as an XLIFF 2.0 pack.
//!
//! Every unit carries the English `<source>` and its translator note; the `<target>` is the
//! language's current message where it has one, and absent where it has none, so a
//! translator sees what is missing and the template re-imports with the language's true
//! completeness. The template of the source language itself has the English text as target
//! and re-imports at 100 percent. Units are grouped by the first part of their key, as in the
//! built-in files. Text is escaped so that the reader of [`super::xliff`] returns it
//! unchanged, white space at the edges of a text with line breaks included.

use std::{collections::BTreeMap, fmt::Write as _};

use super::{
    validate::KeySet,
    xliff::{META_CATEGORY, METADATA_NS, Metadata, XLIFF_NS},
};

/// Escapes text for element content.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    if !text.contains('\n') {
        return out;
    }
    // The reader drops white space at the edges of a text with line breaks: write it as
    // character references, which it keeps.
    let reference = |c: char| match c {
        ' ' => Some("&#32;"),
        '\t' => Some("&#9;"),
        '\n' => Some("&#10;"),
        _ => None,
    };
    let leading = out.chars().take_while(|&c| reference(c).is_some()).count();
    let trailing = out
        .chars()
        .rev()
        .take_while(|&c| reference(c).is_some())
        .count();
    let chars: Vec<char> = out.chars().collect();
    if leading == chars.len() {
        return chars.iter().filter_map(|&c| reference(c)).collect();
    }
    let mut edged = String::with_capacity(out.len() + 8 * (leading + trailing));
    for (i, &c) in chars.iter().enumerate() {
        match reference(c) {
            Some(r) if i < leading || i >= chars.len() - trailing => edged.push_str(r),
            _ => edged.push(c),
        }
    }
    edged
}

/// Escapes text for an attribute value in double quotes.
fn escape_attr(text: &str) -> String {
    escape(text).replace('"', "&quot;").replace('\n', "&#10;")
}

/// Renders the template of `tag`: `targets` are the language's messages by key (`None` for
/// the source language, whose targets are the English texts), `metadata` its pack metadata.
pub fn render(
    keys: &KeySet,
    tag: &str,
    metadata: &Metadata,
    targets: Option<&BTreeMap<String, String>>,
) -> String {
    let mut out = String::with_capacity(keys.len() * 200);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<xliff xmlns=\"{XLIFF_NS}\" xmlns:mda=\"{METADATA_NS}\" version=\"2.0\" srcLang=\"{}\" trgLang=\"{}\">",
        escape_attr(&keys.language),
        escape_attr(tag)
    );
    out.push_str("  <file id=\"ui\">\n    <mda:metadata>\n");
    let _ = writeln!(out, "      <mda:metaGroup category=\"{META_CATEGORY}\">");
    let display_name = if metadata.display_name.is_empty() {
        tag
    } else {
        metadata.display_name.as_str()
    };
    for (kind, value) in [
        ("displayName", display_name),
        ("author", metadata.author.as_str()),
        ("version", metadata.version.as_str()),
        ("sourceLanguage", keys.language.as_str()),
    ] {
        let _ = writeln!(
            out,
            "        <mda:meta type=\"{kind}\">{}</mda:meta>",
            escape(value)
        );
    }
    out.push_str("      </mda:metaGroup>\n    </mda:metadata>\n");
    let mut group: Option<&str> = None;
    for (key, message) in &keys.messages {
        let area = key.split('.').next().unwrap_or_default();
        if group != Some(area) {
            if group.is_some() {
                out.push_str("    </group>\n");
            }
            let _ = writeln!(out, "    <group id=\"{}\">", escape_attr(area));
            group = Some(area);
        }
        let _ = writeln!(out, "      <unit id=\"{}\">", escape_attr(key));
        if let Some(description) = &message.description {
            let _ = writeln!(
                out,
                "        <notes><note category=\"description\">{}</note></notes>",
                escape(description)
            );
        }
        out.push_str("        <segment>\n");
        let _ = writeln!(out, "          <source>{}</source>", escape(&message.text));
        let target = match targets {
            None => Some(message.text.as_str()),
            Some(targets) => targets.get(key).map(String::as_str),
        };
        if let Some(target) = target {
            let _ = writeln!(out, "          <target>{}</target>", escape(target));
        }
        out.push_str("        </segment>\n      </unit>\n");
    }
    if group.is_some() {
        out.push_str("    </group>\n");
    }
    out.push_str("  </file>\n</xliff>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{validate::validate, xliff};

    fn keys() -> KeySet {
        let text = format!(
            "<xliff xmlns=\"{XLIFF_NS}\" version=\"2.0\" srcLang=\"en\"><file id=\"ui\">\
             <unit id=\"a.one\"><notes><note category=\"description\">A &lt;note&gt;</note></notes><segment><source>One &amp; {{n, number}}</source></segment></unit>\
             <unit id=\"a.two\"><segment><source>&#32;edge\nlines&#10;</source></segment></unit>\
             <unit id=\"b.three\"><segment><source>{{n, plural, one {{# x}} other {{# xs}}}}</source></segment></unit>\
             </file></xliff>"
        );
        KeySet::from_source_documents(&[text.as_bytes()]).expect("keys")
    }

    #[test]
    fn edges_survive_the_reader() {
        for text in ["plain", " a\nb ", "\n\n", "x\n", "\tx\n y\t", "<b>&</b>\n"] {
            let document = format!(
                "<xliff xmlns=\"{XLIFF_NS}\" version=\"2.0\" srcLang=\"en\"><file id=\"f\"><unit id=\"a.b\"><segment><source>{}</source></segment></unit></file></xliff>",
                escape(text)
            );
            let read = xliff::read(document.as_bytes()).expect("read");
            assert_eq!(read.units[0].source.as_deref(), Some(text));
        }
    }

    #[test]
    fn the_source_template_reimports_at_100_percent() {
        let keys = keys();
        assert_eq!(keys.messages["a.two"].text, " edge\nlines\n");
        let metadata = Metadata {
            display_name: "English".to_owned(),
            author: "Tenko".to_owned(),
            version: "1".to_owned(),
            source_language: "en".to_owned(),
        };
        let template = render(&keys, "en", &metadata, None);
        assert!(template.contains("<group id=\"a\">") && template.contains("<group id=\"b\">"));
        assert!(template.contains("A &lt;note&gt;"));
        let pack = validate(template.as_bytes(), &keys).expect("valid");
        assert_eq!(pack.report.percent, 100);
        assert_eq!(pack.report.stale.len() + pack.report.problems.len(), 0);
        assert_eq!(pack.messages["a.two"], " edge\nlines\n");
    }

    #[test]
    fn a_language_template_has_the_targets_it_knows() {
        let keys = keys();
        let targets = BTreeMap::from([("a.one".to_owned(), "Un & {n, number}".to_owned())]);
        let template = render(&keys, "fr", &Metadata::default(), Some(&targets));
        assert!(template.contains("<mda:meta type=\"displayName\">fr</mda:meta>"));
        let pack = validate(template.as_bytes(), &keys).expect("valid");
        assert_eq!(pack.report.translated, 1);
        assert_eq!(pack.report.missing, ["a.two", "b.three"]);
        assert_eq!(pack.messages["a.one"], "Un & {n, number}");
    }
}
