//! Custom-field validation for the IPAM domain (IPAM-08).
//!
//! A custom field is declared once by a [`CustomFieldDef`] and then carried as a
//! [`CustomValue`] in the `custom` map of any object of the kinds the definition applies to.
//! This module holds every rule that is not already expressed by the types of `tenko-core`:
//!
//! - [`validate_values`] checks the values of one object against the definitions and reports
//!   every problem, sorted by key, so a client can fix a request in one round trip.
//! - [`validate_definition`] checks a definition before it is stored, and
//!   [`check_kind_change`] checks an edit of a stored definition while values may exist.
//! - [`value_to_text`] and [`parse_value`] convert between values and plain text for diffs,
//!   search filters and the CSV import.
//!
//! Value rules by kind:
//!
//! | Kind | Rule |
//! |------|------|
//! | Text | at most 1024 characters, no control characters except line feed and tab |
//! | Integer, Boolean | none beyond the type |
//! | Date | `YYYY-MM-DD` with ASCII digits only and a real calendar date |
//! | Url | at most 2048 characters, no whitespace or control characters, `scheme:rest` with a scheme of `[a-zA-Z][a-zA-Z0-9+.-]*` and a non-empty `rest`; for `http`, `https`, `ftp`, `ssh` and `rdp`, `rest` must start with `//` followed by a non-empty host |
//! | Select | exactly one of the options of the definition |
//!
//! Every problem carries a stable code (the constants of this module) for clients and an
//! English message for logs and the `detail` of problem documents. Messages quote at most a
//! short prefix of the offending value.

use std::{collections::BTreeMap, error::Error, fmt, mem};

use tenko_core::{
    ObjectKind,
    ipam::{CustomFieldDef, CustomKind, CustomValue, FieldKey},
};

/// Error code: a value was given for a key that has no definition.
pub const UNKNOWN: &str = "ipam.custom_field.unknown";
/// Error code: the definition does not apply to the kind of the object.
pub const NOT_APPLICABLE: &str = "ipam.custom_field.not_applicable";
/// Error code: the value variant differs from the kind of the definition.
pub const TYPE_MISMATCH: &str = "ipam.custom_field.type_mismatch";
/// Error code: the value has the right type but breaks a rule of that type.
pub const INVALID: &str = "ipam.custom_field.invalid";
/// Error code: a required field has no value.
pub const REQUIRED: &str = "ipam.custom_field.required";
/// Error code: a definition breaks the rules for definitions.
pub const INVALID_DEFINITION: &str = "ipam.custom_field.invalid_definition";
/// Error code: the kind of a definition may not change this way.
pub const INCOMPATIBLE_CHANGE: &str = "ipam.custom_field.incompatible_change";

/// The object kinds a custom field may apply to (the nine IPAM kinds).
pub const APPLICABLE_KINDS: [ObjectKind; 9] = [
    ObjectKind::Tenant,
    ObjectKind::Vrf,
    ObjectKind::Site,
    ObjectKind::Vlan,
    ObjectKind::Prefix,
    ObjectKind::Range,
    ObjectKind::Address,
    ObjectKind::Host,
    ObjectKind::Interface,
];

/// Longest text value, in characters.
const MAX_TEXT_CHARS: usize = 1024;
/// Longest URL value, in characters.
const MAX_URL_CHARS: usize = 2048;
/// Longest select option, in characters.
const MAX_OPTION_CHARS: usize = 128;
/// Characters of a value quoted in a message before it is cut off.
const PREVIEW_CHARS: usize = 48;
/// URL schemes whose `rest` must start with `//` and a host.
const AUTHORITY_SCHEMES: [&str; 5] = ["http", "https", "ftp", "ssh", "rdp"];

/// One problem with a custom field definition or value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomFieldProblem {
    /// The field key as given (may be invalid or unknown).
    pub key: String,
    /// Stable error code, one of the constants of this module.
    pub code: &'static str,
    /// English explanation for logs and the `detail` of problem documents.
    pub message: String,
}

impl CustomFieldProblem {
    fn new(key: &str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CustomFieldProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CustomFieldProblem {}

/// Validates the custom values of one object of `kind` against the definitions.
///
/// Every problem is reported, not only the first, sorted by key. A key without a definition is
/// [`UNKNOWN`]; a definition whose `applies_to` lacks `kind` is [`NOT_APPLICABLE`]; a value of
/// another variant than the definition kind is [`TYPE_MISMATCH`]; a value that breaks the rules
/// of its kind (see the module documentation) is [`INVALID`]; and every required definition that
/// applies to `kind` and has no value is [`REQUIRED`].
pub fn validate_values(
    kind: ObjectKind,
    values: &BTreeMap<FieldKey, CustomValue>,
    defs: &BTreeMap<FieldKey, CustomFieldDef>,
) -> Vec<CustomFieldProblem> {
    let mut problems = Vec::new();
    for (key, value) in values {
        let Some(def) = defs.get(key) else {
            problems.push(CustomFieldProblem::new(
                key.as_str(),
                UNKNOWN,
                format!("no custom field {key} is defined"),
            ));
            continue;
        };
        if !def.applies_to.contains(&kind) {
            problems.push(CustomFieldProblem::new(
                key.as_str(),
                NOT_APPLICABLE,
                format!("custom field {key} does not apply to {}", kind.as_str()),
            ));
            continue;
        }
        problems.extend(check_value(key, &def.kind, value));
    }
    for (key, def) in defs {
        if def.required && def.applies_to.contains(&kind) && !values.contains_key(key) {
            problems.push(CustomFieldProblem::new(
                key.as_str(),
                REQUIRED,
                format!("custom field {key} is required for {}", kind.as_str()),
            ));
        }
    }
    // Each key yields at most one problem, so a stable sort by key is a total order.
    problems.sort_by(|a, b| a.key.cmp(&b.key));
    problems
}

/// Validates a definition.
///
/// `applies_to` must be non-empty, without duplicates and limited to [`APPLICABLE_KINDS`]. The
/// options of a select must be non-empty and unique, each 1 to 128 characters long, without
/// control characters and without surrounding whitespace. Every problem is reported, all with
/// the code [`INVALID_DEFINITION`].
pub fn validate_definition(def: &CustomFieldDef) -> Vec<CustomFieldProblem> {
    let key = def.key.as_str();
    let broken = |message: String| CustomFieldProblem::new(key, INVALID_DEFINITION, message);
    let mut problems = Vec::new();

    if def.applies_to.is_empty() {
        problems.push(broken(
            "applies_to must name at least one object kind".to_owned(),
        ));
    }
    for (index, kind) in def.applies_to.iter().enumerate() {
        if !APPLICABLE_KINDS.contains(kind) {
            problems.push(broken(format!(
                "a custom field cannot apply to {}",
                kind.as_str()
            )));
        }
        let first_time = !def.applies_to[..index].contains(kind);
        let again_later = def.applies_to[index + 1..].contains(kind);
        if first_time && again_later {
            problems.push(broken(format!(
                "applies_to lists {} more than once",
                kind.as_str()
            )));
        }
    }

    if let CustomKind::Select { options } = &def.kind {
        if options.is_empty() {
            problems.push(broken("a select needs at least one option".to_owned()));
        }
        for (index, option) in options.iter().enumerate() {
            if let Some(message) = option_problem(option) {
                problems.push(broken(message));
            }
            let first_time = !options[..index].contains(option);
            let again_later = options[index + 1..].contains(option);
            if first_time && again_later {
                problems.push(broken(format!(
                    "option {} is listed more than once",
                    preview(option)
                )));
            }
        }
    }
    problems
}

/// Whether a definition may change from the `old` to the `new` kind while values may exist.
///
/// The same kind is always allowed, except that a select may only gain options, never lose
/// one. Any other change of kind is refused.
///
/// # Errors
///
/// Returns a problem with the code [`INCOMPATIBLE_CHANGE`] if the change would invalidate
/// values that may exist.
pub fn check_kind_change(
    key: &FieldKey,
    old: &CustomKind,
    new: &CustomKind,
) -> Result<(), CustomFieldProblem> {
    let refuse = |message: String| {
        Err(CustomFieldProblem::new(
            key.as_str(),
            INCOMPATIBLE_CHANGE,
            message,
        ))
    };
    match (old, new) {
        (CustomKind::Select { options: before }, CustomKind::Select { options: after }) => {
            let removed: Vec<String> = before
                .iter()
                .filter(|option| !after.contains(option))
                .map(|option| preview(option))
                .collect();
            if removed.is_empty() {
                Ok(())
            } else {
                refuse(format!(
                    "custom field {key} cannot lose select options: {}",
                    removed.join(", ")
                ))
            }
        }
        _ if mem::discriminant(old) == mem::discriminant(new) => Ok(()),
        _ => refuse(format!(
            "custom field {key} cannot change from {} to {}",
            kind_name(old),
            kind_name(new)
        )),
    }
}

/// Renders a value as plain text for diffs, search and CSV.
///
/// Text, date, URL and select values are returned as they are, integers in decimal and
/// booleans as `true` or `false`.
pub fn value_to_text(value: &CustomValue) -> String {
    match value {
        CustomValue::Text(text)
        | CustomValue::Date(text)
        | CustomValue::Url(text)
        | CustomValue::Select(text) => text.clone(),
        CustomValue::Integer(number) => number.to_string(),
        CustomValue::Boolean(flag) => flag.to_string(),
    }
}

/// Parses text into a value of `kind`, trimming surrounding whitespace.
///
/// Used by search filters and the CSV import. An integer is an optional sign and digits. A
/// boolean is `true`, `false`, `yes`, `no`, `1`, `0` or the Swedish `ja` and `nej`, in any
/// letter case. Text, date and URL follow the rules of [`validate_values`]. A select is matched
/// case-insensitively (an exact match wins) and returned with the spelling of the definition.
///
/// # Errors
///
/// Returns a problem with the code [`INVALID`] and the given `key` if the text is not a valid
/// value of `kind`.
pub fn parse_value(
    key: &FieldKey,
    kind: &CustomKind,
    text: &str,
) -> Result<CustomValue, CustomFieldProblem> {
    parse_trimmed(kind, text.trim())
        .map_err(|message| CustomFieldProblem::new(key.as_str(), INVALID, message))
}

/// Parses already trimmed text; the error is the message of the problem.
fn parse_trimmed(kind: &CustomKind, text: &str) -> Result<CustomValue, String> {
    match kind {
        CustomKind::Text => accept(text_problem(text), CustomValue::Text(text.to_owned())),
        CustomKind::Integer => text
            .parse::<i64>()
            .map(CustomValue::Integer)
            .map_err(|_| format!("{} is not a 64-bit integer", preview(text))),
        CustomKind::Boolean => match text.to_lowercase().as_str() {
            "true" | "yes" | "1" | "ja" => Ok(CustomValue::Boolean(true)),
            "false" | "no" | "0" | "nej" => Ok(CustomValue::Boolean(false)),
            _ => Err(format!(
                "{} is not a boolean (true, false, yes, no, 1, 0, ja or nej)",
                preview(text)
            )),
        },
        CustomKind::Date => accept(date_problem(text), CustomValue::Date(text.to_owned())),
        CustomKind::Url => accept(url_problem(text), CustomValue::Url(text.to_owned())),
        CustomKind::Select { options } => {
            let lowered = text.to_lowercase();
            options
                .iter()
                .find(|option| option.as_str() == text)
                .or_else(|| {
                    options
                        .iter()
                        .find(|option| option.to_lowercase() == lowered)
                })
                .map(|option| CustomValue::Select(option.clone()))
                .ok_or_else(|| {
                    format!(
                        "{} is not one of the {} allowed options",
                        preview(text),
                        options.len()
                    )
                })
        }
    }
}

/// `value` if there is no problem, else the problem as an error.
fn accept(problem: Option<String>, value: CustomValue) -> Result<CustomValue, String> {
    match problem {
        None => Ok(value),
        Some(message) => Err(message),
    }
}

/// Checks one value against the kind of its definition.
fn check_value(
    key: &FieldKey,
    kind: &CustomKind,
    value: &CustomValue,
) -> Option<CustomFieldProblem> {
    let message = match (value, kind) {
        (CustomValue::Text(text), CustomKind::Text) => text_problem(text),
        (CustomValue::Date(date), CustomKind::Date) => date_problem(date),
        (CustomValue::Url(url), CustomKind::Url) => url_problem(url),
        (CustomValue::Select(choice), CustomKind::Select { options }) => {
            select_problem(choice, options)
        }
        (CustomValue::Integer(_), CustomKind::Integer)
        | (CustomValue::Boolean(_), CustomKind::Boolean) => None,
        _ => {
            return Some(CustomFieldProblem::new(
                key.as_str(),
                TYPE_MISMATCH,
                format!(
                    "custom field {key} holds {} values, not {}",
                    kind_name(kind),
                    value_name(value)
                ),
            ));
        }
    };
    message.map(|message| CustomFieldProblem::new(key.as_str(), INVALID, message))
}

/// The problem with a text value, if any.
fn text_problem(text: &str) -> Option<String> {
    let length = text.chars().count();
    if length > MAX_TEXT_CHARS {
        return Some(format!(
            "text has {length} characters, the limit is {MAX_TEXT_CHARS}"
        ));
    }
    text.chars()
        .find(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        .map(|c| format!("text contains the control character U+{:04X}", u32::from(c)))
}

/// The problem with a date value, if any.
fn date_problem(text: &str) -> Option<String> {
    let shaped = text.len() == 10
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        });
    if !shaped {
        return Some(format!("{} is not of the form YYYY-MM-DD", preview(text)));
    }
    // The shape is checked above because the calendar check of `matches` also accepts signs.
    if CustomValue::Date(text.to_owned()).matches(&CustomKind::Date) {
        None
    } else {
        Some(format!("{} is not a real calendar date", preview(text)))
    }
}

/// The problem with a URL value, if any.
fn url_problem(text: &str) -> Option<String> {
    let length = text.chars().count();
    if length > MAX_URL_CHARS {
        return Some(format!(
            "URL has {length} characters, the limit is {MAX_URL_CHARS}"
        ));
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("URL must not contain whitespace or control characters".to_owned());
    }
    let Some((scheme, rest)) = text.split_once(':') else {
        return Some(format!(
            "{} is not a URL: it has no scheme before a colon",
            preview(text)
        ));
    };
    if !is_scheme(scheme) {
        return Some(format!(
            "{} is not a URL: {} is not a valid scheme",
            preview(text),
            preview(scheme)
        ));
    }
    if rest.is_empty() {
        return Some(format!(
            "{} is not a URL: nothing follows the scheme",
            preview(text)
        ));
    }
    let needs_host = AUTHORITY_SCHEMES
        .iter()
        .any(|known| scheme.eq_ignore_ascii_case(known));
    if needs_host && !rest.strip_prefix("//").is_some_and(has_host) {
        return Some(format!(
            "a {} URL must continue with // and a host name",
            scheme.to_ascii_lowercase()
        ));
    }
    None
}

/// Whether `text` is a URL scheme: `[a-zA-Z][a-zA-Z0-9+.-]*`.
fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// Whether the text after `//` starts with a non-empty host (user information and port are
/// allowed around it, and an IPv6 literal must be in brackets).
fn has_host(after_slashes: &str) -> bool {
    let authority = after_slashes
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    if let Some(literal) = host_port.strip_prefix('[') {
        literal.find(']').is_some_and(|end| end > 0)
    } else {
        host_port
            .split(':')
            .next()
            .is_some_and(|host| !host.is_empty())
    }
}

/// The problem with a select choice, if any.
fn select_problem(choice: &str, options: &[String]) -> Option<String> {
    if options.iter().any(|option| option == choice) {
        None
    } else {
        Some(format!(
            "{} is not one of the {} allowed options",
            preview(choice),
            options.len()
        ))
    }
}

/// The problem with one select option of a definition, if any.
fn option_problem(option: &str) -> Option<String> {
    let length = option.chars().count();
    if length == 0 {
        Some("a select option must not be empty".to_owned())
    } else if length > MAX_OPTION_CHARS {
        Some(format!(
            "select option {} has {length} characters, the limit is {MAX_OPTION_CHARS}",
            preview(option)
        ))
    } else if option.chars().any(char::is_control) {
        Some(format!(
            "select option {} contains a control character",
            preview(option)
        ))
    } else if option.trim() != option {
        Some(format!(
            "select option {} has leading or trailing whitespace",
            preview(option)
        ))
    } else {
        None
    }
}

/// The stable name of a kind, as in the API.
fn kind_name(kind: &CustomKind) -> &'static str {
    match kind {
        CustomKind::Text => "text",
        CustomKind::Integer => "integer",
        CustomKind::Boolean => "boolean",
        CustomKind::Date => "date",
        CustomKind::Url => "url",
        CustomKind::Select { .. } => "select",
    }
}

/// The stable name of the kind a value belongs to.
fn value_name(value: &CustomValue) -> &'static str {
    match value {
        CustomValue::Text(_) => "text",
        CustomValue::Integer(_) => "integer",
        CustomValue::Boolean(_) => "boolean",
        CustomValue::Date(_) => "date",
        CustomValue::Url(_) => "url",
        CustomValue::Select(_) => "select",
    }
}

/// Quotes a value for a message, cut off after a few characters.
fn preview(text: &str) -> String {
    let mut shown: String = text.chars().take(PREVIEW_CHARS).collect();
    if text.chars().nth(PREVIEW_CHARS).is_some() {
        shown.push_str("...");
    }
    format!("{shown:?}")
}

#[cfg(test)]
mod tests {
    use tenko_core::CustomFieldId;

    use super::*;

    fn key(text: &str) -> FieldKey {
        FieldKey::new(text).expect("key")
    }

    fn def(
        name: &str,
        kind: CustomKind,
        applies_to: &[ObjectKind],
        required: bool,
    ) -> CustomFieldDef {
        CustomFieldDef {
            id: CustomFieldId::generate(),
            key: key(name),
            kind,
            applies_to: applies_to.to_vec(),
            required,
        }
    }

    fn defs(list: Vec<CustomFieldDef>) -> BTreeMap<FieldKey, CustomFieldDef> {
        list.into_iter().map(|d| (d.key.clone(), d)).collect()
    }

    fn select(options: &[&str]) -> CustomKind {
        CustomKind::Select {
            options: options.iter().map(|o| (*o).to_owned()).collect(),
        }
    }

    fn text(value: &str) -> CustomValue {
        CustomValue::Text(value.to_owned())
    }

    /// Validates one value for a prefix against a single definition of `kind`.
    fn check(kind: CustomKind, value: CustomValue) -> Vec<CustomFieldProblem> {
        let definitions = defs(vec![def("rack_unit", kind, &[ObjectKind::Prefix], false)]);
        let values = BTreeMap::from([(key("rack_unit"), value)]);
        validate_values(ObjectKind::Prefix, &values, &definitions)
    }

    fn codes(problems: &[CustomFieldProblem]) -> Vec<(&str, &'static str)> {
        problems.iter().map(|p| (p.key.as_str(), p.code)).collect()
    }

    fn broken_definition(name: &str, kind: CustomKind, applies_to: &[ObjectKind]) -> Vec<String> {
        let problems = validate_definition(&def(name, kind, applies_to, false));
        assert!(problems.iter().all(|p| p.code == INVALID_DEFINITION));
        assert!(problems.iter().all(|p| p.key == name));
        problems.into_iter().map(|p| p.message).collect()
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(UNKNOWN, "ipam.custom_field.unknown");
        assert_eq!(NOT_APPLICABLE, "ipam.custom_field.not_applicable");
        assert_eq!(TYPE_MISMATCH, "ipam.custom_field.type_mismatch");
        assert_eq!(INVALID, "ipam.custom_field.invalid");
        assert_eq!(REQUIRED, "ipam.custom_field.required");
        assert_eq!(INVALID_DEFINITION, "ipam.custom_field.invalid_definition");
        assert_eq!(INCOMPATIBLE_CHANGE, "ipam.custom_field.incompatible_change");
    }

    #[test]
    fn applicable_kinds_are_the_nine_ipam_kinds() {
        let names: Vec<&str> = APPLICABLE_KINDS.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "tenant",
                "vrf",
                "site",
                "vlan",
                "prefix",
                "range",
                "address",
                "host",
                "interface"
            ]
        );
        assert!(!APPLICABLE_KINDS.contains(&ObjectKind::User));
        assert!(!APPLICABLE_KINDS.contains(&ObjectKind::CustomField));
    }

    #[test]
    fn valid_values_of_every_kind_pass() {
        let definitions = defs(vec![
            def("owner", CustomKind::Text, &APPLICABLE_KINDS, false),
            def("rack_unit", CustomKind::Integer, &APPLICABLE_KINDS, false),
            def("monitored", CustomKind::Boolean, &APPLICABLE_KINDS, false),
            def("installed", CustomKind::Date, &APPLICABLE_KINDS, false),
            def("wiki", CustomKind::Url, &APPLICABLE_KINDS, false),
            def(
                "tier",
                select(&["gold", "silver"]),
                &APPLICABLE_KINDS,
                false,
            ),
        ]);
        let values = BTreeMap::from([
            (key("owner"), text("network team")),
            (key("rack_unit"), CustomValue::Integer(-42)),
            (key("monitored"), CustomValue::Boolean(false)),
            (key("installed"), CustomValue::Date("2026-02-28".to_owned())),
            (
                key("wiki"),
                CustomValue::Url("https://wiki.example.test/net".to_owned()),
            ),
            (key("tier"), CustomValue::Select("silver".to_owned())),
        ]);
        for kind in APPLICABLE_KINDS {
            assert_eq!(validate_values(kind, &values, &definitions), []);
        }
        assert_eq!(
            validate_values(ObjectKind::Host, &BTreeMap::new(), &definitions),
            []
        );
    }

    #[test]
    fn key_without_definition_is_unknown() {
        let values = BTreeMap::from([(key("owner"), text("network team"))]);
        let problems = validate_values(ObjectKind::Site, &values, &BTreeMap::new());
        assert_eq!(codes(&problems), [("owner", UNKNOWN)]);
        assert!(problems[0].message.contains("owner"));
    }

    #[test]
    fn definition_for_other_kinds_is_not_applicable() {
        let definitions = defs(vec![def(
            "owner",
            CustomKind::Text,
            &[ObjectKind::Host],
            true,
        )]);
        let values = BTreeMap::from([(key("owner"), text("network team"))]);
        let problems = validate_values(ObjectKind::Vlan, &values, &definitions);
        // The required field is not reported on top: it does not apply to a VLAN.
        assert_eq!(codes(&problems), [("owner", NOT_APPLICABLE)]);
        assert!(problems[0].message.contains("vlan"));
        assert_eq!(validate_values(ObjectKind::Host, &values, &definitions), []);
    }

    #[test]
    fn variant_mismatch_is_a_type_mismatch() {
        let kinds = [
            CustomKind::Text,
            CustomKind::Integer,
            CustomKind::Boolean,
            CustomKind::Date,
            CustomKind::Url,
            select(&["gold"]),
        ];
        let values = [
            text("x"),
            CustomValue::Integer(1),
            CustomValue::Boolean(true),
            CustomValue::Date("2026-02-28".to_owned()),
            CustomValue::Url("https://wiki.example.test/".to_owned()),
            CustomValue::Select("gold".to_owned()),
        ];
        for (i, kind) in kinds.iter().enumerate() {
            for (j, value) in values.iter().enumerate() {
                let problems = check(kind.clone(), value.clone());
                if i == j {
                    assert_eq!(problems, [], "{kind:?}");
                } else {
                    assert_eq!(
                        codes(&problems),
                        [("rack_unit", TYPE_MISMATCH)],
                        "{kind:?} {value:?}"
                    );
                }
            }
        }
        let message = &check(CustomKind::Integer, text("12"))[0].message;
        assert!(
            message.contains("integer") && message.contains("text"),
            "{message}"
        );
    }

    #[test]
    fn text_length_is_counted_in_characters() {
        assert_eq!(check(CustomKind::Text, text(&"a".repeat(1024))), []);
        assert_eq!(check(CustomKind::Text, text(&"\u{e5}".repeat(1024))), []);
        assert_eq!(check(CustomKind::Text, text("")), []);
        let problems = check(CustomKind::Text, text(&"a".repeat(1025)));
        assert_eq!(codes(&problems), [("rack_unit", INVALID)]);
        assert!(problems[0].message.contains("1025"));
        // A long value is not echoed back in full.
        assert!(problems[0].message.len() < 200);
        let problems = check(CustomKind::Text, text(&"\u{e5}".repeat(1025)));
        assert_eq!(codes(&problems), [("rack_unit", INVALID)]);
    }

    #[test]
    fn text_allows_line_feed_and_tab_only() {
        assert_eq!(check(CustomKind::Text, text("line one\nline two\tend")), []);
        for bad in [
            "a\rb",
            "a\0b",
            "a\u{7}b",
            "a\u{1b}[0m",
            "a\u{85}b",
            "a\u{7f}b",
        ] {
            let problems = check(CustomKind::Text, text(bad));
            assert_eq!(codes(&problems), [("rack_unit", INVALID)], "{bad:?}");
        }
    }

    #[test]
    fn date_must_be_a_real_calendar_date_in_iso_form() {
        for good in ["2026-02-28", "2028-02-29", "2026-12-31", "0001-01-01"] {
            assert_eq!(
                check(CustomKind::Date, CustomValue::Date(good.to_owned())),
                [],
                "{good}"
            );
        }
        for bad in [
            "",
            "2026-02-30",
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "2026-1-5",
            "26-01-05",
            "2026/01/05",
            "20260105",
            "2026-01-05 ",
            "2026-01-05T10:00:00Z",
            "+026-01-05",
            "2026-+1-05",
            "2026-01-+5",
            "2026-01-0\u{663}",
        ] {
            let problems = check(CustomKind::Date, CustomValue::Date(bad.to_owned()));
            assert_eq!(codes(&problems), [("rack_unit", INVALID)], "{bad:?}");
        }
    }

    #[test]
    fn url_accepts_generic_and_hierarchical_forms() {
        for good in [
            "https://wiki.example.test/net",
            "HTTPS://Wiki.Example.test",
            "http://198.51.100.7:8080/path?x=1#top",
            "https://[2001:db8::1]:8443/",
            "ftp://files.example.test/pub",
            "ssh://admin@host.example.test",
            "rdp://203.0.113.9",
            "https://user:secret@host.example.test/",
            "mailto:noc@example.test",
            "tel:+4600000000",
            "urn:example:net",
            "git+ssh://host.example.test/repo.git",
            "file:///srv/docs/net.txt",
            "localhost:8080/path",
        ] {
            assert_eq!(
                check(CustomKind::Url, CustomValue::Url(good.to_owned())),
                [],
                "{good}"
            );
        }
        let longest = format!("https://wiki.example.test/{}", "a".repeat(2048 - 26));
        assert_eq!(longest.chars().count(), 2048);
        assert_eq!(check(CustomKind::Url, CustomValue::Url(longest)), []);
    }

    #[test]
    fn url_rejects_malformed_values() {
        let too_long = format!("https://wiki.example.test/{}", "a".repeat(2048 - 25));
        assert_eq!(too_long.chars().count(), 2049);
        let mut bad: Vec<String> = [
            "",
            "wiki.example.test/net",
            "://wiki.example.test",
            "1http://wiki.example.test",
            "ht tp://wiki.example.test",
            "ht_tp://wiki.example.test",
            "mailto:",
            "https://wiki.example.test/a b",
            "https://wiki.example.test/\tx",
            "https://wiki.example.test/\nx",
            "https://wiki.example.test/\u{7}",
            "https://wiki.example.test/\u{a0}",
            "https:wiki.example.test",
            "https:/wiki.example.test",
            "https://",
            "https:///path",
            "https://?query",
            "https://#frag",
            "https://:8443/",
            "https://user@/",
            "https://[]/",
            "https://[2001:db8::1/",
            "http:",
            "ftp:/files",
            "ssh:host.example.test",
            "RDP:203.0.113.9",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        bad.push(too_long);
        for url in bad {
            let problems = check(CustomKind::Url, CustomValue::Url(url.clone()));
            assert_eq!(codes(&problems), [("rack_unit", INVALID)], "{url:?}");
        }
    }

    #[test]
    fn select_needs_an_exact_option() {
        let kind = select(&["gold", "Silver"]);
        assert_eq!(
            check(kind.clone(), CustomValue::Select("gold".to_owned())),
            []
        );
        assert_eq!(
            check(kind.clone(), CustomValue::Select("Silver".to_owned())),
            []
        );
        for bad in ["silver", "GOLD", "gold ", "bronze", ""] {
            let problems = check(kind.clone(), CustomValue::Select(bad.to_owned()));
            assert_eq!(codes(&problems), [("rack_unit", INVALID)], "{bad:?}");
        }
    }

    #[test]
    fn required_fields_without_value_are_reported() {
        let definitions = defs(vec![
            def(
                "owner",
                CustomKind::Text,
                &[ObjectKind::Prefix, ObjectKind::Host],
                true,
            ),
            def("rack_unit", CustomKind::Integer, &[ObjectKind::Host], true),
            def("note", CustomKind::Text, &[ObjectKind::Prefix], false),
        ]);
        let none = BTreeMap::new();
        let problems = validate_values(ObjectKind::Prefix, &none, &definitions);
        assert_eq!(codes(&problems), [("owner", REQUIRED)]);
        assert!(problems[0].message.contains("prefix"));
        let problems = validate_values(ObjectKind::Host, &none, &definitions);
        assert_eq!(
            codes(&problems),
            [("owner", REQUIRED), ("rack_unit", REQUIRED)]
        );
        assert_eq!(validate_values(ObjectKind::Tenant, &none, &definitions), []);
        let values = BTreeMap::from([(key("owner"), text("network team"))]);
        assert_eq!(
            validate_values(ObjectKind::Prefix, &values, &definitions),
            []
        );
        // An empty text still counts as a value.
        let values = BTreeMap::from([(key("owner"), text(""))]);
        assert_eq!(
            validate_values(ObjectKind::Prefix, &values, &definitions),
            []
        );
    }

    #[test]
    fn every_problem_is_reported_sorted_by_key() {
        let definitions = defs(vec![
            def("owner", CustomKind::Text, &[ObjectKind::Prefix], false),
            def(
                "rack_unit",
                CustomKind::Integer,
                &[ObjectKind::Prefix],
                false,
            ),
            def("installed", CustomKind::Date, &[ObjectKind::Prefix], false),
            def("zone", CustomKind::Text, &[ObjectKind::Prefix], true),
            def("budget", CustomKind::Text, &[ObjectKind::Host], false),
            def(
                "aaa_required",
                CustomKind::Boolean,
                &[ObjectKind::Prefix],
                true,
            ),
        ]);
        let values = BTreeMap::from([
            (key("owner"), text("a\u{0}b")),
            (key("rack_unit"), text("12")),
            (key("installed"), CustomValue::Date("2026-02-30".to_owned())),
            (key("budget"), text("none")),
            (key("mystery"), CustomValue::Boolean(true)),
        ]);
        let problems = validate_values(ObjectKind::Prefix, &values, &definitions);
        assert_eq!(
            codes(&problems),
            [
                ("aaa_required", REQUIRED),
                ("budget", NOT_APPLICABLE),
                ("installed", INVALID),
                ("mystery", UNKNOWN),
                ("owner", INVALID),
                ("rack_unit", TYPE_MISMATCH),
                ("zone", REQUIRED),
            ]
        );
    }

    #[test]
    fn valid_definition_passes() {
        let definition = def("tier", select(&["gold", "silver"]), &APPLICABLE_KINDS, true);
        assert_eq!(validate_definition(&definition), []);
        let definition = def("owner", CustomKind::Text, &[ObjectKind::Interface], false);
        assert_eq!(validate_definition(&definition), []);
    }

    #[test]
    fn applies_to_is_checked() {
        let empty = broken_definition("owner", CustomKind::Text, &[]);
        assert_eq!(empty.len(), 1);
        assert!(empty[0].contains("applies_to"));

        let duplicate = broken_definition(
            "owner",
            CustomKind::Text,
            &[
                ObjectKind::Host,
                ObjectKind::Site,
                ObjectKind::Host,
                ObjectKind::Host,
            ],
        );
        assert_eq!(duplicate.len(), 1);
        assert!(duplicate[0].contains("host"));

        let foreign = broken_definition(
            "owner",
            CustomKind::Text,
            &[ObjectKind::Host, ObjectKind::User, ObjectKind::Job],
        );
        assert_eq!(foreign.len(), 2);
        assert!(foreign[0].contains("user") && foreign[1].contains("job"));
    }

    #[test]
    fn select_options_are_checked() {
        assert_eq!(
            broken_definition("tier", select(&[]), &[ObjectKind::Host]).len(),
            1
        );
        let kinds = [ObjectKind::Host];
        for (option, word) in [
            ("", "empty"),
            ("gold\n", "control"),
            ("go\u{0}ld", "control"),
            (" gold", "whitespace"),
            ("gold ", "whitespace"),
            (" ", "whitespace"),
        ] {
            let messages = broken_definition("tier", select(&[option]), &kinds);
            assert_eq!(messages.len(), 1, "{option:?}");
            assert!(messages[0].contains(word), "{option:?}: {}", messages[0]);
        }
        let boundary = "a".repeat(128);
        assert_eq!(
            validate_definition(&def("tier", select(&[&boundary]), &kinds, false)),
            []
        );
        let wide = "\u{e5}".repeat(128);
        assert_eq!(
            validate_definition(&def("tier", select(&[&wide]), &kinds, false)),
            []
        );
        let messages = broken_definition("tier", select(&[&"a".repeat(129)]), &kinds);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("129"));
        // Options are unique by exact spelling.
        let messages =
            broken_definition("tier", select(&["gold", "silver", "gold", "gold"]), &kinds);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("gold"));
        assert_eq!(
            validate_definition(&def("tier", select(&["gold", "Gold"]), &kinds, false)),
            []
        );
    }

    #[test]
    fn all_definition_problems_are_reported_together() {
        let messages = broken_definition("tier", select(&["", "a", "a"]), &[ObjectKind::Job]);
        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn same_kind_is_always_allowed() {
        let name = key("rack_unit");
        for kind in [
            CustomKind::Text,
            CustomKind::Integer,
            CustomKind::Boolean,
            CustomKind::Date,
            CustomKind::Url,
            select(&["gold", "silver"]),
        ] {
            assert_eq!(check_kind_change(&name, &kind, &kind), Ok(()));
        }
    }

    #[test]
    fn select_may_gain_options_but_not_lose_them() {
        let name = key("tier");
        let old = select(&["gold", "silver"]);
        assert_eq!(
            check_kind_change(&name, &old, &select(&["silver", "gold", "bronze"])),
            Ok(())
        );
        assert_eq!(
            check_kind_change(&name, &old, &select(&["gold", "silver", "gold"])),
            Ok(())
        );
        let problem = check_kind_change(&name, &old, &select(&["gold"])).expect_err("lost option");
        assert_eq!(problem.code, INCOMPATIBLE_CHANGE);
        assert_eq!(problem.key, "tier");
        assert!(problem.message.contains("silver") && !problem.message.contains("gold"));
        let problem = check_kind_change(&name, &old, &select(&[])).expect_err("lost options");
        assert!(problem.message.contains("gold") && problem.message.contains("silver"));
        // Spelling counts: a renamed option is a removed option.
        assert!(check_kind_change(&name, &old, &select(&["Gold", "silver"])).is_err());
    }

    #[test]
    fn any_other_kind_change_is_refused() {
        let name = key("rack_unit");
        let kinds = [
            CustomKind::Text,
            CustomKind::Integer,
            CustomKind::Boolean,
            CustomKind::Date,
            CustomKind::Url,
            select(&["gold"]),
        ];
        for (i, old) in kinds.iter().enumerate() {
            for (j, new) in kinds.iter().enumerate() {
                let result = check_kind_change(&name, old, new);
                if i == j {
                    assert_eq!(result, Ok(()));
                } else {
                    let problem = result.expect_err("kind change");
                    assert_eq!(problem.code, INCOMPATIBLE_CHANGE);
                    assert_eq!(problem.key, "rack_unit");
                }
            }
        }
        let problem = check_kind_change(&name, &CustomKind::Text, &CustomKind::Integer)
            .expect_err("text to integer");
        assert!(problem.message.contains("text") && problem.message.contains("integer"));
    }

    #[test]
    fn values_render_as_plain_text() {
        assert_eq!(value_to_text(&text("network team")), "network team");
        assert_eq!(value_to_text(&CustomValue::Integer(-42)), "-42");
        assert_eq!(
            value_to_text(&CustomValue::Integer(i64::MAX)),
            "9223372036854775807"
        );
        assert_eq!(value_to_text(&CustomValue::Boolean(true)), "true");
        assert_eq!(value_to_text(&CustomValue::Boolean(false)), "false");
        assert_eq!(
            value_to_text(&CustomValue::Date("2026-02-28".to_owned())),
            "2026-02-28"
        );
        let url = "https://wiki.example.test/net";
        assert_eq!(value_to_text(&CustomValue::Url(url.to_owned())), url);
        assert_eq!(
            value_to_text(&CustomValue::Select("gold".to_owned())),
            "gold"
        );
    }

    #[test]
    fn parse_text_and_url_trim_and_validate() {
        let name = key("owner");
        assert_eq!(
            parse_value(&name, &CustomKind::Text, "  network team \n"),
            Ok(text("network team"))
        );
        assert_eq!(parse_value(&name, &CustomKind::Text, "   "), Ok(text("")));
        let problem = parse_value(&name, &CustomKind::Text, &"a".repeat(1025)).expect_err("long");
        assert_eq!((problem.key.as_str(), problem.code), ("owner", INVALID));
        assert!(parse_value(&name, &CustomKind::Text, "a\u{7}b").is_err());

        let url = parse_value(&name, &CustomKind::Url, " https://wiki.example.test/net ");
        assert_eq!(
            url,
            Ok(CustomValue::Url("https://wiki.example.test/net".to_owned()))
        );
        assert!(parse_value(&name, &CustomKind::Url, "wiki.example.test").is_err());
        assert!(parse_value(&name, &CustomKind::Url, "https://").is_err());
        assert!(parse_value(&name, &CustomKind::Url, "https://wiki.example.test/a b").is_err());
    }

    #[test]
    fn parse_integer_takes_a_sign_and_digits() {
        let name = key("rack_unit");
        for (input, expected) in [
            ("42", 42),
            ("+42", 42),
            ("-42", -42),
            ("  7  ", 7),
            ("007", 7),
            ("-0", 0),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
        ] {
            assert_eq!(
                parse_value(&name, &CustomKind::Integer, input),
                Ok(CustomValue::Integer(expected)),
                "{input:?}"
            );
        }
        for bad in [
            "",
            "+",
            "-",
            "4 2",
            "4.2",
            "1e3",
            "0x10",
            "1_000",
            "12a",
            "9223372036854775808",
            "--1",
            "\u{663}",
        ] {
            let problem = parse_value(&name, &CustomKind::Integer, bad).expect_err(bad);
            assert_eq!(
                (problem.key.as_str(), problem.code),
                ("rack_unit", INVALID),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_boolean_accepts_english_and_swedish_words() {
        let name = key("monitored");
        for word in [
            "true", "TRUE", "True", "yes", "Yes", "1", "ja", "JA", " ja ",
        ] {
            assert_eq!(
                parse_value(&name, &CustomKind::Boolean, word),
                Ok(CustomValue::Boolean(true)),
                "{word:?}"
            );
        }
        for word in ["false", "False", "NO", "no", "0", "nej", "Nej", "\tNEJ\n"] {
            assert_eq!(
                parse_value(&name, &CustomKind::Boolean, word),
                Ok(CustomValue::Boolean(false)),
                "{word:?}"
            );
        }
        for bad in ["", "y", "n", "2", "on", "tru", "yes please", "-1"] {
            let problem = parse_value(&name, &CustomKind::Boolean, bad).expect_err(bad);
            assert_eq!(
                (problem.key.as_str(), problem.code),
                ("monitored", INVALID),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_date_validates_the_calendar() {
        let name = key("installed");
        assert_eq!(
            parse_value(&name, &CustomKind::Date, " 2028-02-29 "),
            Ok(CustomValue::Date("2028-02-29".to_owned()))
        );
        for bad in [
            "",
            "2026-02-29",
            "2026-2-3",
            "+026-01-05",
            "2026-+1-05",
            "tomorrow",
            "2026-01-05T00:00",
        ] {
            let problem = parse_value(&name, &CustomKind::Date, bad).expect_err(bad);
            assert_eq!(
                (problem.key.as_str(), problem.code),
                ("installed", INVALID),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_select_matches_case_insensitively_with_definition_spelling() {
        let name = key("tier");
        let kind = select(&["Gold", "silver", "Bronze Plus"]);
        for (input, expected) in [
            ("Gold", "Gold"),
            ("gold", "Gold"),
            ("GOLD", "Gold"),
            ("  silver  ", "silver"),
            ("SILVER", "silver"),
            ("bronze plus", "Bronze Plus"),
        ] {
            assert_eq!(
                parse_value(&name, &kind, input),
                Ok(CustomValue::Select(expected.to_owned())),
                "{input:?}"
            );
        }
        for bad in ["", "platinum", "gol", "bronze  plus"] {
            let problem = parse_value(&name, &kind, bad).expect_err(bad);
            assert_eq!(
                (problem.key.as_str(), problem.code),
                ("tier", INVALID),
                "{bad:?}"
            );
        }
        // With options that differ only in case, an exact match wins.
        let kind = select(&["gold", "Gold"]);
        assert_eq!(
            parse_value(&name, &kind, "Gold"),
            Ok(CustomValue::Select("Gold".to_owned()))
        );
        assert_eq!(
            parse_value(&name, &kind, "gold"),
            Ok(CustomValue::Select("gold".to_owned()))
        );
        assert_eq!(
            parse_value(&name, &kind, "GOLD"),
            Ok(CustomValue::Select("gold".to_owned()))
        );
    }

    #[test]
    fn parsed_values_pass_validation_and_round_trip_to_text() {
        let name = key("rack_unit");
        let cases = [
            (CustomKind::Text, "network team"),
            (CustomKind::Integer, "-12"),
            (CustomKind::Boolean, "false"),
            (CustomKind::Date, "2026-10-09"),
            (CustomKind::Url, "https://wiki.example.test/net"),
            (select(&["gold", "silver"]), "silver"),
        ];
        for (kind, input) in cases {
            let value = parse_value(&name, &kind, input).expect("parse");
            assert_eq!(value_to_text(&value), input);
            assert_eq!(check(kind, value), []);
        }
    }

    #[test]
    fn problem_displays_its_message_and_is_an_error() {
        let problem = check_kind_change(&key("tier"), &CustomKind::Text, &CustomKind::Date)
            .expect_err("kind change");
        assert_eq!(problem.to_string(), problem.message);
        let error: &dyn Error = &problem;
        assert!(error.source().is_none());
        assert_eq!(problem.clone(), problem);
    }

    #[test]
    fn messages_quote_only_a_short_prefix_of_a_value() {
        let long = format!("{}-{}", "x".repeat(300), "end");
        let problem = parse_value(&key("installed"), &CustomKind::Date, &long).expect_err("date");
        assert!(problem.message.len() < 200, "{}", problem.message);
        assert!(!problem.message.contains("end"));
        assert!(problem.message.contains("..."));
        let problem =
            parse_value(&key("installed"), &CustomKind::Date, "no\u{1b}[0m").expect_err("date");
        assert!(!problem.message.contains('\u{1b}'), "{:?}", problem.message);
    }
}
