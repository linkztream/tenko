//! Language packs held in the replicated store (API-21, owner decision S3-Q8).
//!
//! The UI ships English and Swedish built in ([`BUILT_IN_LANGUAGES`]); an administrator
//! uploads further packs, previews them and activates them, and the store replicates the
//! choice to every controller. The table [`PACKS`] holds one small record per language tag
//! with its state; the pack content (the XLIFF document, its compiled messages and the
//! validation report) lives in tables of its own, so that readers of the active language
//! set, such as the authorization index that checks a user's language, never decode it.
//!
//! The record carries only what the language check needs; the language-pack package
//! (WP3.7) adds fields with `#[serde(default)]`.

use serde::{Deserialize, Serialize};

use crate::table::TableDef;

/// The languages compiled into the UI. They are always active: an uploaded pack of the
/// same tag overrides the built-in messages and can be reverted, but a built-in language
/// cannot be removed.
pub const BUILT_IN_LANGUAGES: [&str; 2] = ["en", "sv"];

/// Language packs by BCP 47 tag.
pub const PACKS: TableDef<String, PackRecord> = TableDef::new("i18n.packs");

/// The life cycle of an uploaded pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackState {
    /// Uploaded and validated; not offered to anyone.
    Uploaded,
    /// Shown to the administrator who previews it, in that session only.
    Previewed,
    /// Offered to every user and accepted as a user or installation language.
    Active,
}

/// One language pack (table [`PACKS`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRecord {
    /// The BCP 47 tag, equal to the key.
    pub tag: String,
    /// Where the pack is in its life cycle.
    pub state: PackState,
    /// The language's name in itself, from the pack's metadata.
    #[serde(default)]
    pub display_name: String,
}

impl PackRecord {
    /// Whether users may choose the language.
    pub fn is_active(&self) -> bool {
        self.state == PackState::Active
    }
}

/// Whether `tag` has the shape of a BCP 47 language tag as packs use it: a primary
/// language subtag of two or three lower-case letters, then optional subtags of one to
/// eight letters or digits separated by `-` (`fr`, `pt-BR`, `zh-Hant`, `sr-Latn-RS`). The
/// pack package checks the full grammar when a pack is uploaded.
pub fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let primary_ok = subtags.next().is_some_and(|primary| {
        (2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_lowercase())
    });
    primary_ok
        && subtags.all(|subtag| {
            (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_cbor, to_cbor};

    #[test]
    fn tags_are_checked_for_their_shape() {
        for tag in ["en", "sv", "fr", "pt-BR", "zh-Hant", "sr-Latn-RS", "fil"] {
            assert!(is_language_tag(tag), "{tag}");
        }
        for tag in [
            "",
            "e",
            "EN",
            "english",
            "en-",
            "-en",
            "en_US",
            "en-toolongsubtag",
            "e1",
        ] {
            assert!(!is_language_tag(tag), "{tag}");
        }
        assert!(BUILT_IN_LANGUAGES.iter().all(|tag| is_language_tag(tag)));
    }

    /// A record as an older writer stored it, without the optional fields.
    #[derive(Serialize)]
    struct Minimal {
        tag: &'static str,
        state: PackState,
    }

    #[test]
    fn records_round_trip_and_tolerate_missing_fields() {
        let record = PackRecord {
            tag: "fr".to_owned(),
            state: PackState::Active,
            display_name: "Français".to_owned(),
        };
        let back: PackRecord = from_cbor(&to_cbor(&record).expect("cbor")).expect("cbor");
        assert_eq!(back, record);
        assert!(back.is_active());

        let minimal: PackRecord = from_cbor(
            &to_cbor(&Minimal {
                tag: "de",
                state: PackState::Uploaded,
            })
            .expect("cbor"),
        )
        .expect("a record without the optional fields");
        assert_eq!(minimal.display_name, "");
        assert!(!minimal.is_active());
        assert_eq!(PACKS.name().as_str(), "i18n.packs");
    }
}
