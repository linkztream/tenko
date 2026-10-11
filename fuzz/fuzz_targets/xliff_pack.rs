#![no_main]
//! The language-pack parser of the API (API-21): the XLIFF 2.0 reader, the validation of a
//! pack against a key set, the ICU message checker and the language tags. None may panic on
//! any input; what a valid pack returns must agree with the key set, and the template
//! renderer must write it back so that the reader returns the same messages.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use tenko_api::i18n::{
    MAX_PACK_BYTES, icu, tag, template,
    validate::{KeySet, Validated, validate},
    xliff,
};

/// The English source document of the key set: the shapes of message a pack translates.
const SOURCE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0" xmlns:mda="urn:oasis:names:tc:xliff:metadata:2.0" version="2.0" srcLang="en">
  <file id="ui">
    <mda:metadata>
      <mda:metaGroup category="language-pack">
        <mda:meta type="displayName">English</mda:meta>
      </mda:metaGroup>
    </mda:metadata>
    <unit id="common.cancel"><segment><source>Cancel</source></segment></unit>
    <unit id="common.greeting"><segment><source>Signed in as {name}</source></segment></unit>
    <unit id="common.count"><segment><source>{count, plural, one {# item} other {# items}}</source></segment></unit>
    <unit id="common.kind"><segment><source>{kind, select, lease {DHCP lease} record {DNS record} other {Entry}}</source></segment></unit>
    <unit id="common.apostrophe"><segment><source>Don''t save {name}''s '{'draft'}' twice</source></segment></unit>
    <unit id="help.text">
      <notes><note category="description">Two lines of help text.</note></notes>
      <segment><source>First line of the help.
Second line of the help.</source></segment>
    </unit>
  </file>
</xliff>"#;

/// The key set of the running UI, built once.
static KEYS: LazyLock<KeySet> = LazyLock::new(|| {
    KeySet::from_source_documents(&[SOURCE.as_bytes()])
        .expect("the inline source document is a valid key set")
});

/// The invariants of a pack that passed the validation.
fn check_validated(pack: &Validated) {
    assert_eq!(
        pack.report.translated as usize,
        pack.messages.len(),
        "translated does not count the messages"
    );
    assert!(pack.report.percent <= 100, "percent is over 100");
    for (key, message) in &pack.messages {
        assert!(
            KEYS.messages.contains_key(key),
            "a message has a key the key set lacks"
        );
        assert!(icu::check(message).is_ok(), "a message is not valid ICU");
    }
    // The renderer escapes text so that the reader returns it unchanged.
    let rendered = template::render(&KEYS, &pack.tag, &pack.metadata, Some(&pack.messages));
    let again = validate(rendered.as_bytes(), &KEYS)
        .expect("the rendered template of a valid pack is a valid pack");
    assert_eq!(
        again.messages, pack.messages,
        "the rendered template changed the messages"
    );
}

/// The canonical case of a tag is a fixed point and passes the check.
fn check_tag(text: &str) {
    if let Ok(canonical) = tag::canonical(text) {
        assert_eq!(
            tag::canonical(&canonical),
            Ok(canonical.clone()),
            "the canonical case of a tag is not stable"
        );
        assert!(
            tag::check(&canonical).is_ok(),
            "a canonical tag fails the check"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // The size check is covered by unit tests; keep the inputs that are about to reach it out.
    if data.len() > MAX_PACK_BYTES + 1024 {
        return;
    }
    if let Ok(document) = xliff::read(data)
        && let Some(trg_lang) = &document.trg_lang
    {
        check_tag(trg_lang);
    }
    let validated = validate(data, &KEYS);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = icu::check(text);
        check_tag(text);
    }
    if let Ok(pack) = &validated {
        check_validated(pack);
    }
});
