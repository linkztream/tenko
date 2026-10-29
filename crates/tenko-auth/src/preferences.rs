//! Personal preferences of a person: the saved layout of each table of the web UI (UI-Q4 of
//! the UI plan, API-08).
//!
//! A preference is one small JSON document under a key, stored per user in
//! `auth.preferences` ([`crate::model::PREFERENCES`]) and replicated with the rest of the
//! store. The only kind of key today is `table:<id>`, the layout of the table `<id>` of the
//! UI: the columns it hides, their order, their widths and the sort. The server checks the
//! shape and the size of the document and nothing else: the column ids are the UI's, and the
//! UI validates them against the table's known columns before it applies a layout. The
//! document is opaque to the server beyond this schema; it is never interpolated into HTML,
//! SQL or a log line.
//!
//! | Bound | Value |
//! |---|---|
//! | Keys per user | [`MAX_KEYS`] (64) |
//! | Document size, as the canonical JSON the server stores | [`MAX_DOCUMENT_BYTES`] (16 KiB) |
//! | Key | `table:` and 1 to 64 of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter or digit |
//! | Column id | 1 to 64 of `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`, `:` |
//! | Columns in `order`, `hidden` and `widths` | at most [`MAX_COLUMNS`] (128) each, no repeats |
//! | Width | [`MIN_WIDTH`] to [`MAX_WIDTH`] pixels (16 to 1,200) |

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;
use utoipa::ToSchema;

use crate::AuthError;

/// The most keys one person may store.
pub const MAX_KEYS: usize = 64;

/// The largest document, in bytes of the canonical JSON the server stores.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

/// The most columns a layout names in each of its lists.
pub const MAX_COLUMNS: usize = 128;

/// The longest table or column id, in characters.
pub const MAX_ID_LEN: usize = 64;

/// The narrowest width a layout may store, in pixels.
pub const MIN_WIDTH: u16 = 16;

/// The widest width a layout may store, in pixels (the UI's own limit).
pub const MAX_WIDTH: u16 = 1_200;

/// The version of the table layout document this server reads and writes.
pub const TABLE_LAYOUT_VERSION: u32 = 1;

/// The prefix of the key of a table layout.
pub const TABLE_PREFIX: &str = "table:";

/// The sort of a table: one column, ascending or descending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LayoutSort {
    /// The column (or the server's sort field) the table sorts on.
    pub column: String,
    /// Whether the sort is descending.
    #[serde(default)]
    pub desc: bool,
}

/// The saved layout of one table of the web UI (`table:<id>`), version 1.
///
/// Unknown fields are refused. An absent list means the table's default for it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "version": 1,
    "order": ["ip", "dns_name", "mode", "mac"],
    "hidden": ["mac"],
    "widths": {"ip": 140, "dns_name": 220},
    "sort": {"column": "ip", "desc": false}
}))]
pub struct TableLayout {
    /// The version of the document; this server knows version 1.
    pub version: u32,
    /// The column ids in the person's order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    /// The column ids the person hid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<Vec<String>>,
    /// The widths the person set, in pixels, by column id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widths: Option<BTreeMap<String, u16>>,
    /// The sort the person chose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<LayoutSort>,
}

/// One stored preference in an answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Preference {
    /// The key, `table:<id>`.
    pub key: String,
    /// The document as it was stored.
    #[schema(value_type = TableLayout)]
    pub value: serde_json::Value,
    /// When it was last written.
    pub updated_at: Timestamp,
}

/// A preference as the store holds it: the canonical JSON of the validated document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPreference {
    /// The document, as canonical JSON.
    pub document: String,
    /// When it was last written.
    pub updated_at: Timestamp,
}

impl StoredPreference {
    /// The answer for `key`. A document that no longer parses as JSON (it cannot happen
    /// through this server) is answered as `null`, so one bad row never hides the others.
    pub fn to_preference(&self, key: String) -> Preference {
        Preference {
            key,
            value: serde_json::from_str(&self.document).unwrap_or(serde_json::Value::Null),
            updated_at: self.updated_at,
        }
    }
}

fn invalid(field: &'static str, reason: impl Into<std::borrow::Cow<'static, str>>) -> AuthError {
    AuthError::invalid(field, reason)
}

/// Checks a key: `table:` and a table id of 1 to 64 lowercase letters, digits, `.`, `_` and
/// `-` that starts with a letter or a digit.
///
/// # Errors
///
/// [`AuthError::Invalid`] on the field `key`.
pub fn check_key(key: &str) -> Result<(), AuthError> {
    let Some(id) = key.strip_prefix(TABLE_PREFIX) else {
        return Err(invalid("key", "a preference key is `table:<id>`"));
    };
    let first_ok = id
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if !first_ok || !rest_ok || id.len() > MAX_ID_LEN {
        return Err(invalid(
            "key",
            "a table id is 1 to 64 of a-z, 0-9, `.`, `_` and `-`, starting with a letter or digit",
        ));
    }
    Ok(())
}

fn check_column(field: &'static str, id: &str) -> Result<(), AuthError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if ok {
        Ok(())
    } else {
        Err(invalid(
            field,
            "a column id is 1 to 64 of A-Z, a-z, 0-9, `.`, `_`, `-` and `:`",
        ))
    }
}

fn check_list(field: &'static str, list: &[String]) -> Result<(), AuthError> {
    if list.len() > MAX_COLUMNS {
        return Err(invalid(field, "a layout names at most 128 columns"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in list {
        check_column(field, id)?;
        if !seen.insert(id.as_str()) {
            return Err(invalid(field, "a column is named twice"));
        }
    }
    Ok(())
}

impl TableLayout {
    /// Checks the document against the schema and returns its canonical JSON, the form the
    /// store keeps.
    ///
    /// # Errors
    ///
    /// [`AuthError::Invalid`] for a field outside the schema, or
    /// [`AuthError::PreferenceTooLarge`] for a document over [`MAX_DOCUMENT_BYTES`].
    pub fn validate(&self) -> Result<String, AuthError> {
        if self.version != TABLE_LAYOUT_VERSION {
            return Err(invalid(
                "version",
                "this server knows version 1 of a table layout",
            ));
        }
        if let Some(order) = &self.order {
            check_list("order", order)?;
        }
        if let Some(hidden) = &self.hidden {
            check_list("hidden", hidden)?;
        }
        if let Some(widths) = &self.widths {
            if widths.len() > MAX_COLUMNS {
                return Err(invalid("widths", "a layout names at most 128 columns"));
            }
            for (id, width) in widths {
                check_column("widths", id)?;
                if !(MIN_WIDTH..=MAX_WIDTH).contains(width) {
                    return Err(invalid("widths", "a width is 16 to 1200 pixels"));
                }
            }
        }
        if let Some(sort) = &self.sort {
            check_column("sort", &sort.column)?;
        }
        let document = serde_json::to_string(self)
            .map_err(|_| AuthError::internal("a table layout does not serialize"))?;
        if document.len() > MAX_DOCUMENT_BYTES {
            return Err(AuthError::PreferenceTooLarge {
                max_bytes: MAX_DOCUMENT_BYTES,
            });
        }
        Ok(document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> TableLayout {
        TableLayout {
            version: 1,
            order: Some(vec!["ip".into(), "dns_name".into()]),
            hidden: Some(vec!["mac".into()]),
            widths: Some(BTreeMap::from([("ip".into(), 140)])),
            sort: Some(LayoutSort {
                column: "ip".into(),
                desc: true,
            }),
        }
    }

    #[test]
    fn keys_name_a_table() {
        for good in [
            "table:addresses",
            "table:dhcp-leases",
            "table:a",
            "table:prefix.children_2",
        ] {
            check_key(good).unwrap_or_else(|error| panic!("{good}: {error}"));
        }
        let long = format!("table:{}", "a".repeat(65));
        for bad in [
            "addresses",
            "table:",
            "table:-x",
            "table:Addresses",
            "table:a b",
            "table:a/b",
            "theme:dark",
            long.as_str(),
        ] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
        check_key(&format!("table:{}", "a".repeat(64))).expect("64 characters");
    }

    #[test]
    fn a_valid_layout_is_stored_as_canonical_json() {
        let document = layout().validate().expect("valid");
        assert_eq!(
            document,
            r#"{"version":1,"order":["ip","dns_name"],"hidden":["mac"],"widths":{"ip":140},"sort":{"column":"ip","desc":true}}"#
        );
        let minimal = TableLayout {
            version: 1,
            ..TableLayout::default()
        };
        assert_eq!(minimal.validate().expect("valid"), r#"{"version":1}"#);
    }

    #[test]
    fn unknown_fields_and_versions_are_refused() {
        assert!(
            serde_json::from_str::<TableLayout>(r#"{"version":1,"script":"x"}"#).is_err(),
            "an unknown field"
        );
        assert!(
            serde_json::from_str::<TableLayout>(r#"{"version":1,"sort":{"column":"ip","x":1}}"#)
                .is_err(),
            "an unknown field of the sort"
        );
        assert!(
            serde_json::from_str::<TableLayout>(r#"{"order":[]}"#).is_err(),
            "no version"
        );
        let mut next = layout();
        next.version = 2;
        assert!(matches!(
            next.validate(),
            Err(AuthError::Invalid {
                field: "version",
                ..
            })
        ));
    }

    #[test]
    fn column_ids_widths_and_counts_are_bounded() {
        let mut bad = layout();
        bad.order = Some(vec!["<script>".into()]);
        assert!(matches!(
            bad.validate(),
            Err(AuthError::Invalid { field: "order", .. })
        ));
        let mut bad = layout();
        bad.hidden = Some(vec!["mac".into(), "mac".into()]);
        assert!(matches!(
            bad.validate(),
            Err(AuthError::Invalid {
                field: "hidden",
                ..
            })
        ));
        let mut bad = layout();
        bad.widths = Some(BTreeMap::from([("ip".into(), 1201)]));
        assert!(matches!(
            bad.validate(),
            Err(AuthError::Invalid {
                field: "widths",
                ..
            })
        ));
        let mut bad = layout();
        bad.widths = Some(BTreeMap::from([("ip".into(), 15)]));
        assert!(bad.validate().is_err());
        let mut bad = layout();
        bad.order = Some((0..129).map(|i| format!("c{i}")).collect());
        assert!(bad.validate().is_err(), "129 columns");
        let mut bad = layout();
        bad.sort = Some(LayoutSort {
            column: String::new(),
            desc: false,
        });
        assert!(matches!(
            bad.validate(),
            Err(AuthError::Invalid { field: "sort", .. })
        ));
    }

    #[test]
    fn a_document_over_16_kib_is_refused() {
        // 128 ids of 64 characters in two lists: about 17 KiB of JSON.
        let ids: Vec<String> = (0..128).map(|i| format!("{i:0>64}")).collect();
        let big = TableLayout {
            version: 1,
            order: Some(ids.clone()),
            hidden: Some(ids),
            ..TableLayout::default()
        };
        assert!(matches!(
            big.validate(),
            Err(AuthError::PreferenceTooLarge { max_bytes: 16_384 })
        ));
    }
}
