//! The validation of an uploaded pack against the key set of the running UI.
//!
//! [`KeySet`] is the English source of every message the running UI uses, read from the
//! source documents the UI build emits (`dist/i18n/en.xlf`). [`validate`] reads a pack and
//! answers either a [`Refusal`] (the document is not a usable pack at all) or a [`Validated`]
//! pack: its tag, metadata, the messages it may contribute and a [`Report`] with the
//! completeness, the keys that are missing, unknown or translated from an older English
//! text, and the problems of single units, which are left out.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{
    MAX_PACK_BYTES,
    icu::{self, ArgKind},
    tag,
    xliff::{self, Metadata},
};

/// The longest display name of a pack, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// One message of the source language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMessage {
    /// The English ICU text.
    pub text: String,
    /// The arguments the text uses.
    pub args: BTreeMap<String, ArgKind>,
    /// The note for translators.
    pub description: Option<String>,
}

/// The messages of the running UI in the source language.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    /// The source language (`en`).
    pub language: String,
    /// The metadata of the source document.
    pub metadata: Metadata,
    /// The messages by key.
    pub messages: BTreeMap<String, SourceMessage>,
}

/// Whether a unit id is a message key: a lower-case dotted path such as `area.some.key`.
pub fn is_key(key: &str) -> bool {
    let mut parts = key.split('.');
    let first_ok = parts.next().is_some_and(|first| {
        first.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && first
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    });
    let mut rest = 0;
    let rest_ok = parts.all(|part| {
        rest += 1;
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    });
    first_ok && rest_ok && rest > 0
}

impl KeySet {
    /// The key set of source documents: a main document and its fragments, merged in order
    /// (the first definition of a key wins), as the UI build merges `en.xlf` and `en.d/`.
    ///
    /// # Errors
    ///
    /// The first document that cannot be read or is not in the source language, or the
    /// first source message that is not valid ICU.
    pub fn from_source_documents(documents: &[&[u8]]) -> Result<Self, String> {
        let mut keys = KeySet::default();
        for (index, bytes) in documents.iter().enumerate() {
            let document = xliff::read(bytes).map_err(|error| error.to_string())?;
            if index == 0 {
                keys.language.clone_from(&document.src_lang);
                keys.metadata = document.metadata.clone();
            } else if document.src_lang != keys.language {
                return Err(format!(
                    "a source document is in {}, not {}",
                    document.src_lang, keys.language
                ));
            }
            for unit in document.units {
                if unit.problem.is_some()
                    || !is_key(&unit.id)
                    || keys.messages.contains_key(&unit.id)
                {
                    continue;
                }
                let Some(text) = unit.source else { continue };
                let info = icu::check(&text).map_err(|error| format!("{}: {error}", unit.id))?;
                keys.messages.insert(
                    unit.id,
                    SourceMessage {
                        text,
                        args: info.args,
                        description: unit.description,
                    },
                );
            }
        }
        Ok(keys)
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the key set has no keys (a build without the embedded UI).
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// How bad a problem is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = PackSeverity)]
pub enum Severity {
    /// The pack, or the unit, is not used.
    Error,
    /// Worth fixing; the pack works.
    Warning,
}

/// A problem found in a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = PackProblem)]
pub struct Problem {
    /// Error or warning.
    pub severity: Severity,
    /// The stable code, for example `i18n.pack.icu`.
    pub code: String,
    /// The unit, when the problem belongs to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The 1-based line in the document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// English explanation.
    pub detail: String,
}

impl Problem {
    fn error(code: &str, key: Option<&str>, line: Option<u32>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: code.to_owned(),
            key: key.map(str::to_owned),
            line,
            detail: detail.into(),
        }
    }

    fn warning(code: &str, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.to_owned(),
            key: None,
            line: None,
            detail: detail.into(),
        }
    }
}

/// The validation report of a pack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = PackReport)]
pub struct Report {
    /// The BCP 47 tag (`trgLang`).
    pub tag: String,
    /// The language's name in itself.
    pub display_name: String,
    /// Who made the pack.
    pub author: String,
    /// The pack's own version.
    pub version: String,
    /// The keys of the running UI.
    pub total: u32,
    /// The keys the pack translates usably.
    pub translated: u32,
    /// `translated` in percent of `total`, rounded down (100 when the UI has no keys).
    pub percent: u32,
    /// Keys of the running UI the pack does not translate; they show in English.
    pub missing: Vec<String>,
    /// Units whose key the running UI does not have; they are not used.
    pub extra: Vec<String>,
    /// Units translated from an English text that has changed since; they are used.
    pub stale: Vec<String>,
    /// Errors of single units (left out) and warnings.
    pub problems: Vec<Problem>,
}

/// A pack that can be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    /// The tag.
    pub tag: String,
    /// The metadata.
    pub metadata: Metadata,
    /// The usable translations by key (ICU text).
    pub messages: BTreeMap<String, String>,
    /// The report.
    pub report: Report,
}

/// Why a document is not a usable pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The stable code of the first problem (`i18n.pack.*`).
    pub code: &'static str,
    /// The tag, when the document names one.
    pub tag: Option<String>,
    /// Every problem found, errors first.
    pub problems: Vec<Problem>,
}

impl Refusal {
    fn one(
        code: &'static str,
        tag: Option<String>,
        line: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            tag,
            problems: vec![Problem::error(code, None, line, detail)],
        }
    }
}

/// Bidirectional formatting characters that open an embedding, override or isolate, and
/// the character that closes each.
fn bidi_opener(c: char) -> Option<char> {
    match c {
        '\u{202a}' | '\u{202b}' | '\u{202d}' | '\u{202e}' => Some('\u{202c}'),
        '\u{2066}'..='\u{2068}' => Some('\u{2069}'),
        _ => None,
    }
}

/// Checks the characters of a translation: no control characters except tab and line feed,
/// and every bidirectional embedding, override and isolate closed in order.
fn check_characters(text: &str) -> Result<(), (&'static str, String)> {
    let mut open: Vec<char> = Vec::new();
    for c in text.chars() {
        let code = u32::from(c);
        if (code < 0x20 && c != '\t' && c != '\n')
            || (0x7f..=0x9f).contains(&code)
            || (0xfff9..=0xfffb).contains(&code)
        {
            return Err((
                "i18n.pack.control",
                format!("the text contains the control character U+{code:04X}"),
            ));
        }
        if let Some(closer) = bidi_opener(c) {
            if open.len() >= 16 {
                return Err((
                    "i18n.pack.bidi",
                    "bidirectional formatting is nested too deeply".to_owned(),
                ));
            }
            open.push(closer);
        } else if (c == '\u{202c}' || c == '\u{2069}') && open.pop() != Some(c) {
            return Err((
                "i18n.pack.bidi",
                format!("U+{code:04X} closes no open bidirectional formatting"),
            ));
        }
    }
    if open.is_empty() {
        Ok(())
    } else {
        Err((
            "i18n.pack.bidi",
            "bidirectional formatting (an embedding, override or isolate) is not closed".to_owned(),
        ))
    }
}

/// Validates a pack against the key set.
///
/// # Errors
///
/// [`Refusal`] when the document is over [`MAX_PACK_BYTES`], is not a well-formed XLIFF 2.0
/// document, does not translate from the source language, names no valid target language,
/// has no display name, or translates no key of the running UI.
pub fn validate(bytes: &[u8], keys: &KeySet) -> Result<Validated, Refusal> {
    if bytes.len() > MAX_PACK_BYTES {
        return Err(Refusal::one(
            "i18n.pack.too_large",
            None,
            None,
            format!(
                "the pack has {} bytes, the limit is {MAX_PACK_BYTES}",
                bytes.len()
            ),
        ));
    }
    let document = xliff::read(bytes)
        .map_err(|error| Refusal::one(error.code, None, error.line, error.message))?;
    let tag = check_document(&document, keys)?;
    let metadata = document.metadata.clone();
    let mut report = Report {
        tag: tag.clone(),
        display_name: metadata.display_name.trim().to_owned(),
        author: metadata.author.clone(),
        version: metadata.version.clone(),
        ..Report::default()
    };
    if metadata.author.is_empty() || metadata.version.is_empty() {
        report.problems.push(Problem::warning(
            "i18n.pack.metadata",
            "the pack has no author or no version in its metadata",
        ));
    }
    let messages = check_units(&document.units, keys, &mut report);
    if messages.is_empty() {
        let mut problems = vec![Problem::error(
            "i18n.pack.empty",
            None,
            None,
            "the pack translates no message of the running user interface",
        )];
        problems.extend(
            report
                .problems
                .into_iter()
                .filter(|p| p.severity == Severity::Error),
        );
        return Err(Refusal {
            code: "i18n.pack.empty",
            tag: Some(tag),
            problems,
        });
    }
    report.missing = keys
        .messages
        .keys()
        .filter(|key| !messages.contains_key(*key))
        .cloned()
        .collect();
    report.total = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    report.translated = u32::try_from(messages.len()).unwrap_or(u32::MAX);
    report.percent = if report.total == 0 {
        100
    } else {
        u32::try_from(u64::from(report.translated) * 100 / u64::from(report.total)).unwrap_or(100)
    };
    report
        .problems
        .sort_by_key(|p| p.severity == Severity::Warning);
    Ok(Validated {
        tag,
        metadata,
        messages,
        report,
    })
}

/// The checks of the document as a whole; the answer is the tag.
fn check_document(document: &xliff::Document, keys: &KeySet) -> Result<String, Refusal> {
    let mut problems: Vec<Problem> = Vec::new();
    let mut first_code: Option<&'static str> = None;
    let mut refuse = |code: &'static str, detail: String| {
        first_code.get_or_insert(code);
        problems.push(Problem::error(code, None, None, detail));
    };
    if document.src_lang != keys.language {
        refuse(
            "i18n.pack.src_lang",
            format!(
                "srcLang is {}, a pack translates from {}",
                document.src_lang, keys.language
            ),
        );
    }
    match &document.trg_lang {
        None => refuse(
            "i18n.pack.trg_lang",
            "the trgLang attribute is missing: it names the language of the pack".to_owned(),
        ),
        Some(tag) => {
            if let Err(reason) = tag::check(tag) {
                refuse(
                    "i18n.pack.tag",
                    format!("trgLang {tag:?} is not a valid language tag: {reason}"),
                );
            }
        }
    }
    let metadata = &document.metadata;
    let name = metadata.display_name.trim();
    if name.is_empty() {
        refuse(
            "i18n.pack.metadata",
            "the pack has no displayName (mda:meta type=\"displayName\" in a mda:metaGroup \
             category=\"language-pack\")"
                .to_owned(),
        );
    } else if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        refuse(
            "i18n.pack.metadata",
            format!(
                "the displayName has more than {MAX_NAME_CHARS} characters or control characters"
            ),
        );
    }
    if !metadata.source_language.is_empty() && metadata.source_language != document.src_lang {
        refuse(
            "i18n.pack.metadata",
            format!(
                "the metadata sourceLanguage {} differs from srcLang {}",
                metadata.source_language, document.src_lang
            ),
        );
    }
    match first_code {
        Some(code) => Err(Refusal {
            code,
            tag: document.trg_lang.clone(),
            problems,
        }),
        None => Ok(document.trg_lang.clone().unwrap_or_default()),
    }
}

/// The checks of the units: the usable translations by key; the problems, the stale and the
/// extra keys go into the report.
fn check_units(
    units: &[xliff::Unit],
    keys: &KeySet,
    report: &mut Report,
) -> BTreeMap<String, String> {
    let mut messages: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut extra: BTreeSet<String> = BTreeSet::new();
    for unit in units {
        let key = unit.id.as_str();
        let line = Some(unit.line);
        let refused = if key.is_empty() {
            Some(("i18n.pack.structure", "a <unit> has no id".to_owned()))
        } else if !seen.insert(key) {
            Some((
                "i18n.pack.duplicate",
                "the unit id appears more than once; the first one is used".to_owned(),
            ))
        } else if !is_key(key) {
            Some((
                "i18n.pack.key",
                "the unit id is not a message key (a lower-case dotted path such as area.some.key)"
                    .to_owned(),
            ))
        } else {
            unit.problem.clone()
        };
        if let Some((code, detail)) = refused {
            let key = (!key.is_empty()).then_some(key);
            report
                .problems
                .push(Problem::error(code, key, line, detail));
            continue;
        }
        let Some(source) = keys.messages.get(key) else {
            extra.insert(key.to_owned());
            continue;
        };
        let Some(target) = unit
            .target
            .as_deref()
            .filter(|t| !t.is_empty() || source.text.is_empty())
        else {
            continue;
        };
        if unit.source.as_deref() != Some(source.text.as_str()) {
            report.stale.push(key.to_owned());
        }
        match check_target(target, source) {
            Ok(()) => {
                messages.insert(key.to_owned(), target.to_owned());
            }
            Err((code, detail)) => {
                report
                    .problems
                    .push(Problem::error(code, Some(key), line, detail));
            }
        }
    }
    report.extra = extra.into_iter().collect();
    messages
}

/// Checks one translation against its English source.
fn check_target(target: &str, source: &SourceMessage) -> Result<(), (&'static str, String)> {
    check_characters(target)?;
    let info = icu::check(target).map_err(|error| {
        (
            "i18n.pack.icu",
            format!("the target is not a valid ICU message: {error}"),
        )
    })?;
    let unknown: Vec<&str> = info
        .args
        .keys()
        .filter(|arg| !source.args.contains_key(*arg))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err((
            "i18n.pack.argument",
            format!(
                "the target uses the argument {}, which the English text does not have",
                unknown.join(", ")
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::xliff::{METADATA_NS, XLIFF_NS};

    fn source() -> KeySet {
        let text = format!(
            r#"<xliff xmlns="{XLIFF_NS}" xmlns:mda="{METADATA_NS}" version="2.0" srcLang="en"><file id="ui">
<mda:metadata><mda:metaGroup category="language-pack"><mda:meta type="displayName">English</mda:meta></mda:metaGroup></mda:metadata>
<unit id="a.cancel"><segment><source>Cancel</source></segment></unit>
<unit id="a.greeting"><segment><source>Signed in as {{name}}</source></segment></unit>
<unit id="a.count"><segment><source>{{count, plural, one {{# item}} other {{# items}}}}</source></segment></unit>
<unit id="a.close"><segment><source>Close</source></segment></unit>
</file></xliff>"#
        );
        KeySet::from_source_documents(&[text.as_bytes()]).expect("key set")
    }

    fn pack(trg: &str, units: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<xliff xmlns="{XLIFF_NS}" xmlns:mda="{METADATA_NS}" version="2.0" srcLang="en" trgLang="{trg}"><file id="ui">
<mda:metadata><mda:metaGroup category="language-pack">
<mda:meta type="displayName">Français</mda:meta><mda:meta type="author">Example</mda:meta><mda:meta type="version">1</mda:meta>
</mda:metaGroup></mda:metadata>
{units}
</file></xliff>"#
        )
    }

    fn unit(key: &str, source: &str, target: &str) -> String {
        format!(
            r#"<unit id="{key}"><segment><source>{source}</source><target>{target}</target></segment></unit>"#
        )
    }

    #[test]
    fn keys_are_lower_case_dotted_paths() {
        for good in ["a.b", "common.action.cancel", "x1.y_2.z3"] {
            assert!(is_key(good), "{good}");
        }
        for bad in ["a", "A.b", "a..b", ".a", "a.", "1a.b", "a.B", "a-b.c"] {
            assert!(!is_key(bad), "{bad}");
        }
    }

    #[test]
    fn a_partial_pack_reports_its_completeness() {
        let keys = source();
        let text = pack(
            "fr",
            &[
                unit("a.cancel", "Cancel", "Annuler"),
                unit(
                    "a.greeting",
                    "Signed in as {name}",
                    "Connecté en tant que {name}",
                ),
                unit(
                    "a.count",
                    "old text",
                    "{count, plural, one {# élément} other {# éléments}}",
                ),
                unit("a.unknown", "Gone", "Parti"),
            ]
            .concat(),
        );
        let pack = validate(text.as_bytes(), &keys).expect("valid");
        assert_eq!(pack.tag, "fr");
        assert_eq!(pack.report.total, 4);
        assert_eq!(pack.report.translated, 3);
        assert_eq!(pack.report.percent, 75);
        assert_eq!(pack.report.missing, ["a.close"]);
        assert_eq!(pack.report.extra, ["a.unknown"]);
        assert_eq!(pack.report.stale, ["a.count"]);
        assert_eq!(pack.report.display_name, "Français");
        assert!(
            pack.report.problems.is_empty(),
            "{:?}",
            pack.report.problems
        );
        assert_eq!(pack.messages.len(), 3);
        assert_eq!(pack.messages["a.cancel"], "Annuler");
    }

    #[test]
    fn bad_units_are_left_out_with_a_problem() {
        let keys = source();
        let units = [
            unit("a.cancel", "Cancel", "&lt;b&gt;Annuler&lt;/b&gt;"),
            unit("a.greeting", "Signed in as {name}", "Bonjour {nom}"),
            unit("a.count", "x", "{count, plural, one {# élément}}"),
            unit("a.close", "Close", "\u{202e}Fermer"),
            unit("a.cancel", "Cancel", "Encore"),
            r#"<unit id="Bad.Key"><segment><source>x</source><target>y</target></segment></unit>"#.to_owned(),
            r#"<unit id="a.close"><segment><source>Close</source><target>Fe<ph id="1"/>rmer</target></segment></unit>"#.to_owned(),
        ]
        .concat();
        let pack = validate(pack("fr", &units).as_bytes(), &keys).expect("valid");
        // Markup-like text is text.
        assert_eq!(pack.messages["a.cancel"], "<b>Annuler</b>");
        assert_eq!(pack.messages.len(), 1);
        let codes: Vec<(&str, Option<&str>)> = pack
            .report
            .problems
            .iter()
            .map(|p| (p.code.as_str(), p.key.as_deref()))
            .collect();
        assert_eq!(
            codes,
            [
                ("i18n.pack.argument", Some("a.greeting")),
                ("i18n.pack.icu", Some("a.count")),
                ("i18n.pack.bidi", Some("a.close")),
                ("i18n.pack.duplicate", Some("a.cancel")),
                ("i18n.pack.key", Some("Bad.Key")),
                ("i18n.pack.duplicate", Some("a.close")),
            ]
        );
        assert!(
            pack.report
                .problems
                .iter()
                .all(|p| p.severity == Severity::Error && p.line.is_some())
        );
    }

    #[test]
    fn balanced_bidi_formatting_is_accepted() {
        let keys = source();
        let target = "\u{202e}Fermer\u{202c} \u{2067}x\u{2069}";
        let pack = validate(
            pack("ar-XB", &unit("a.close", "Close", target)).as_bytes(),
            &keys,
        )
        .expect("valid");
        assert_eq!(pack.messages["a.close"], target);
        assert_eq!(pack.tag, "ar-XB");
    }

    #[test]
    fn documents_that_are_not_usable_packs_are_refused() {
        let keys = source();
        let ok = unit("a.cancel", "Cancel", "Annuler");
        let cases: Vec<(String, &str)> = vec![
            ("<xliff/>".to_owned(), "i18n.pack.root"),
            (
                pack("fr", &ok).replace(" trgLang=\"fr\"", ""),
                "i18n.pack.trg_lang",
            ),
            (pack("FR", &ok), "i18n.pack.tag"),
            (pack("english", &ok), "i18n.pack.tag"),
            (
                pack("fr", &ok).replace("srcLang=\"en\"", "srcLang=\"sv\""),
                "i18n.pack.src_lang",
            ),
            (
                pack("fr", &ok).replace("Français", ""),
                "i18n.pack.metadata",
            ),
            (pack("fr", &unit("a.unknown", "x", "y")), "i18n.pack.empty"),
            (
                format!("{}{}", pack("fr", &ok), " ".repeat(MAX_PACK_BYTES)),
                "i18n.pack.too_large",
            ),
        ];
        for (text, code) in cases {
            let refusal = validate(text.as_bytes(), &keys).expect_err(code);
            assert_eq!(refusal.code, code, "{:?}", refusal.problems);
            assert_ne!(refusal.problems.len(), 0);
        }
    }

    #[test]
    fn a_pack_without_author_or_version_gets_a_warning() {
        let keys = source();
        let text = pack("fr", &unit("a.cancel", "Cancel", "Annuler"))
            .replace("<mda:meta type=\"author\">Example</mda:meta>", "");
        let pack = validate(text.as_bytes(), &keys).expect("valid");
        assert_eq!(pack.report.problems.len(), 1);
        assert_eq!(pack.report.problems[0].severity, Severity::Warning);
    }
}
