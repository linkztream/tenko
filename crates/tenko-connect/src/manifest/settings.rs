//! The settings schema of a manifest: the supported JSON Schema subset and the validation
//! of instance settings against it.

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use regex::Regex;
use serde_json::{Map, Value};

use super::ManifestProblem;

/// Where the settings schema sits in a manifest.
const ROOT: &str = "/settings";
/// The only dialect a settings schema may name.
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
/// Most settings a plugin declares.
const MAX_SETTINGS: usize = 64;
/// Longest `title`, in characters.
const MAX_TITLE_CHARS: usize = 200;
/// Longest `description`, in characters.
const MAX_DESCRIPTION_CHARS: usize = 1_000;
/// Longest `pattern`, in characters.
const MAX_PATTERN_CHARS: usize = 1_000;
/// Characters of a name or value quoted in a message.
const MAX_QUOTED_CHARS: usize = 100;
/// Values listed in a "must be one of" message.
const MAX_LISTED_VALUES: usize = 10;

/// The keywords of the root of a settings schema.
const ROOT_KEYWORDS: [&str; 7] = [
    "$schema",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
];

/// Names, or name endings after `_`, that mark a setting as holding a secret.
const SECRET_NAMES: [&str; 7] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
];

/// The `format` values a form knows.
const FORMATS: [&str; 4] = ["uri", "hostname", "ipv4", "ipv6"];

const CODE_TYPE: &str = "connect.settings.type";
const CODE_UNKNOWN: &str = "connect.settings.unknown";
const CODE_REQUIRED: &str = "connect.settings.required";
const CODE_ENUM: &str = "connect.settings.enum";
const CODE_LENGTH: &str = "connect.settings.length";
const CODE_PATTERN: &str = "connect.settings.pattern";
const CODE_FORMAT: &str = "connect.settings.format";
const CODE_RANGE: &str = "connect.settings.range";
const CODE_ITEMS: &str = "connect.settings.items";
const CODE_UNIQUE: &str = "connect.settings.unique";

/// One problem of instance settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsProblem {
    /// JSON pointer of the offending member, for example `/url`; empty for the document.
    pub path: String,
    /// The stable code, for example `connect.settings.required`.
    pub code: &'static str,
    /// What is wrong, in English.
    pub message: String,
}

impl SettingsProblem {
    fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for SettingsProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// The type of a setting, as a schema names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
}

impl Kind {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "string" => Some(Self::String),
            "integer" => Some(Self::Integer),
            "number" => Some(Self::Number),
            "boolean" => Some(Self::Boolean),
            "array" => Some(Self::Array),
            _ => None,
        }
    }

    /// The type a schema object names, when it is a known one.
    fn of(schema: &Value) -> Option<Self> {
        schema
            .get("type")
            .and_then(Value::as_str)
            .and_then(Self::parse)
    }

    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Array => "array",
        }
    }

    /// The keywords of this type beyond the common ones.
    fn keywords(self) -> &'static [&'static str] {
        match self {
            Self::String => &["enum", "minLength", "maxLength", "pattern", "format"],
            Self::Integer => &["enum", "minimum", "maximum"],
            Self::Number => &["minimum", "maximum"],
            Self::Boolean => &[],
            Self::Array => &["items", "minItems", "maxItems", "uniqueItems"],
        }
    }
}

/// Where a typed schema sits: as a setting or as the `items` of an array setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Property,
    Item,
}

// ---------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------

/// `text` in backticks, cut at 100 characters, control characters replaced, for messages.
pub(super) fn quote(text: &str) -> String {
    let mut shown = String::from('`');
    for (index, c) in text.chars().enumerate() {
        if index == MAX_QUOTED_CHARS {
            shown.push_str("...");
            break;
        }
        shown.push(if c.is_control() { '?' } else { c });
    }
    shown.push('`');
    shown
}

/// Lowercase ASCII letters, digits and `_`, starting with a letter, at most 64 characters:
/// the shape of setting names and secret purposes.
pub(super) fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A host name by RFC 1123: dot-separated labels of 1 to 63 ASCII letters, digits and `-`
/// without a leading or trailing `-`, at most 253 characters, one optional trailing dot.
pub(super) fn is_hostname(text: &str) -> bool {
    let name = text.strip_suffix('.').unwrap_or(text);
    !name.is_empty() && name.len() <= 253 && name.split('.').all(is_label)
}

fn is_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A scheme, a `:` and a non-empty rest, without whitespace or control characters.
fn is_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        && !rest.is_empty()
        && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether a setting name denotes a secret: one of the secret names, alone or after `_`.
fn holds_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|secret| {
        lower == *secret
            || lower
                .strip_suffix(secret)
                .is_some_and(|rest| rest.ends_with('_'))
    })
}

/// An integer value that fits `i64` or `u64`.
fn as_integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

/// `1 character`, `3 characters`.
fn plural(count: u64, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// `path/segment` with the segment escaped as a JSON pointer token.
fn child(path: &str, segment: &str) -> String {
    format!("{path}/{}", segment.replace('~', "~0").replace('/', "~1"))
}

fn push(problems: &mut Vec<ManifestProblem>, path: impl Into<String>, message: impl Into<String>) {
    problems.push(ManifestProblem::new(path, message));
}

// ---------------------------------------------------------------------------------------
// The settings schema
// ---------------------------------------------------------------------------------------

/// Checks that a settings schema stays within the supported subset. Problem paths start
/// with `/settings`.
pub fn validate_settings_schema(schema: &serde_json::Value) -> Vec<ManifestProblem> {
    let mut problems = Vec::new();
    let Some(root) = schema.as_object() else {
        push(
            &mut problems,
            ROOT,
            "the settings schema must be a JSON object",
        );
        return problems;
    };
    if root.get("type").and_then(Value::as_str) != Some("object") {
        push(
            &mut problems,
            child(ROOT, "type"),
            "the settings schema must have `\"type\": \"object\"`",
        );
    }
    if let Some(dialect) = root.get("$schema")
        && dialect.as_str() != Some(SCHEMA_DIALECT)
    {
        push(
            &mut problems,
            child(ROOT, "$schema"),
            format!("`$schema` must be `{SCHEMA_DIALECT}`"),
        );
    }
    check_text(root, "title", MAX_TITLE_CHARS, ROOT, &mut problems);
    check_text(
        root,
        "description",
        MAX_DESCRIPTION_CHARS,
        ROOT,
        &mut problems,
    );
    check_properties(root, &mut problems);
    check_required(root, &mut problems);
    if let Some(additional) = root.get("additionalProperties")
        && *additional != Value::Bool(false)
    {
        push(
            &mut problems,
            child(ROOT, "additionalProperties"),
            "`additionalProperties` can only be `false`: unknown settings are always refused",
        );
    }
    for key in root
        .keys()
        .filter(|key| !ROOT_KEYWORDS.contains(&key.as_str()))
    {
        push(
            &mut problems,
            child(ROOT, key),
            format!(
                "{} is not a supported keyword of the settings schema",
                quote(key)
            ),
        );
    }
    problems
}

/// A `title` or `description`: a string of at most `max_chars` characters.
fn check_text(
    schema: &Map<String, Value>,
    key: &str,
    max_chars: usize,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    let Some(value) = schema.get(key) else {
        return;
    };
    match value.as_str() {
        Some(text) if text.chars().count() <= max_chars => {}
        Some(_) => push(
            problems,
            child(path, key),
            format!("`{key}` is longer than {max_chars} characters"),
        ),
        None => push(
            problems,
            child(path, key),
            format!("`{key}` must be a string"),
        ),
    }
}

fn check_properties(root: &Map<String, Value>, problems: &mut Vec<ManifestProblem>) {
    let Some(value) = root.get("properties") else {
        return;
    };
    let path = child(ROOT, "properties");
    let Some(properties) = value.as_object() else {
        push(problems, path, "`properties` must be an object");
        return;
    };
    if properties.len() > MAX_SETTINGS {
        push(
            problems,
            &path,
            format!(
                "a plugin has at most {MAX_SETTINGS} settings, found {}",
                properties.len()
            ),
        );
    }
    for (name, schema) in properties {
        check_property(name, schema, &path, problems);
    }
}

fn check_property(name: &str, schema: &Value, parent: &str, problems: &mut Vec<ManifestProblem>) {
    let path = child(parent, name);
    if !is_identifier(name) {
        push(
            problems,
            &path,
            format!(
                "{} is not a setting name: lowercase letters, digits and `_`, starting with a \
                 letter, at most 64 characters",
                quote(name)
            ),
        );
    }
    if holds_secret(name) {
        push(
            problems,
            &path,
            format!(
                "{} holds a secret: secrets are declared in `secrets` and injected per call, \
                 never stored in settings",
                quote(name)
            ),
        );
    }
    check_typed_schema(schema, &path, Level::Property, problems);
}

fn check_required(root: &Map<String, Value>, problems: &mut Vec<ManifestProblem>) {
    let Some(value) = root.get("required") else {
        return;
    };
    let path = child(ROOT, "required");
    let Some(names) = value.as_array() else {
        push(
            problems,
            path,
            "`required` must be an array of setting names",
        );
        return;
    };
    let declared = root.get("properties").and_then(Value::as_object);
    let mut seen = HashSet::new();
    for (index, item) in names.iter().enumerate() {
        let item_path = format!("{path}/{index}");
        let Some(name) = item.as_str() else {
            push(problems, item_path, "a required name must be a string");
            continue;
        };
        if !seen.insert(name) {
            push(
                problems,
                item_path,
                format!("{} is listed twice", quote(name)),
            );
        } else if !declared.is_some_and(|properties| properties.contains_key(name)) {
            push(
                problems,
                item_path,
                format!("{} is not a declared setting", quote(name)),
            );
        }
    }
}

/// A setting (or the `items` of an array setting): an object with a known `type` and only
/// the keywords of that type.
fn check_typed_schema(
    value: &Value,
    path: &str,
    level: Level,
    problems: &mut Vec<ManifestProblem>,
) {
    let Some(schema) = value.as_object() else {
        let what = match level {
            Level::Property => "the schema of a setting",
            Level::Item => "`items`",
        };
        push(problems, path, format!("{what} must be an object"));
        return;
    };
    let before = problems.len();
    let kind = Kind::of(value)
        .filter(|kind| level == Level::Property || matches!(kind, Kind::String | Kind::Integer));
    if kind.is_none() {
        let message = match level {
            Level::Property => {
                "a setting needs a `type` of `string`, `integer`, `number`, `boolean` or `array`"
            }
            Level::Item => "`items` needs a `type` of `string` or `integer`",
        };
        push(problems, child(path, "type"), message);
    }
    check_text(schema, "title", MAX_TITLE_CHARS, path, problems);
    check_text(schema, "description", MAX_DESCRIPTION_CHARS, path, problems);
    if level == Level::Property
        && let Some(examples) = schema.get("examples")
        && !examples.is_array()
    {
        push(
            problems,
            child(path, "examples"),
            "`examples` must be an array",
        );
    }
    let Some(kind) = kind else {
        return;
    };
    check_unknown_keywords(schema, kind, level, path, problems);
    match kind {
        Kind::String => check_string_keywords(schema, path, problems),
        Kind::Integer => check_integer_keywords(schema, path, problems),
        Kind::Number => check_number_keywords(schema, path, problems),
        Kind::Boolean => {}
        Kind::Array => check_array_keywords(schema, path, problems),
    }
    if level == Level::Property
        && problems.len() == before
        && let Some(default) = schema.get("default")
    {
        check_default(value, default, path, problems);
    }
}

fn check_unknown_keywords(
    schema: &Map<String, Value>,
    kind: Kind,
    level: Level,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    for key in schema.keys() {
        let known = matches!(key.as_str(), "type" | "title" | "description")
            || (level == Level::Property && matches!(key.as_str(), "default" | "examples"))
            || kind.keywords().contains(&key.as_str());
        if !known {
            push(
                problems,
                child(path, key),
                format!(
                    "{} is not a supported keyword for type `{}`",
                    quote(key),
                    kind.name()
                ),
            );
        }
    }
}

/// A bound keyword: absent, or a value `parse` accepts; otherwise a problem.
fn check_bound<T>(
    schema: &Map<String, Value>,
    key: &str,
    path: &str,
    parse: fn(&Value) -> Option<T>,
    noun: &str,
    problems: &mut Vec<ManifestProblem>,
) -> Option<T> {
    let parsed = parse(schema.get(key)?);
    if parsed.is_none() {
        push(
            problems,
            child(path, key),
            format!("`{key}` must be {noun}"),
        );
    }
    parsed
}

/// A non-negative integer keyword (`minLength`, `maxItems`, ...).
fn check_count(
    schema: &Map<String, Value>,
    key: &str,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) -> Option<u64> {
    check_bound(
        schema,
        key,
        path,
        Value::as_u64,
        "a non-negative integer",
        problems,
    )
}

/// The lower bound must not exceed the upper one.
fn check_order<T: PartialOrd>(
    low: Option<T>,
    high: Option<T>,
    keys: (&str, &str),
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    if let (Some(low), Some(high)) = (low, high)
        && low > high
    {
        push(
            problems,
            child(path, keys.0),
            format!("`{}` must not be larger than `{}`", keys.0, keys.1),
        );
    }
}

/// `enum`: a non-empty array of unique strings, or of unique integers.
fn check_enum(
    schema: &Map<String, Value>,
    kind: Kind,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    let Some(value) = schema.get("enum") else {
        return;
    };
    let enum_path = child(path, "enum");
    let Some(values) = value.as_array().filter(|values| !values.is_empty()) else {
        push(problems, enum_path, "`enum` must be a non-empty array");
        return;
    };
    let mut seen = HashSet::new();
    for (index, item) in values.iter().enumerate() {
        let item_path = format!("{enum_path}/{index}");
        let valid = match kind {
            Kind::String => item.is_string(),
            _ => as_integer(item).is_some(),
        };
        if !valid {
            let noun = if kind == Kind::String {
                "a string"
            } else {
                "an integer"
            };
            push(problems, item_path, format!("an enum value must be {noun}"));
        } else if !seen.insert(item.to_string()) {
            push(
                problems,
                item_path,
                format!("{} is listed twice", describe(item)),
            );
        }
    }
}

fn check_string_keywords(
    schema: &Map<String, Value>,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    check_enum(schema, Kind::String, path, problems);
    let min = check_count(schema, "minLength", path, problems);
    let max = check_count(schema, "maxLength", path, problems);
    check_order(min, max, ("minLength", "maxLength"), path, problems);
    check_pattern(schema, path, problems);
    if let Some(format) = schema.get("format")
        && !format.as_str().is_some_and(|name| FORMATS.contains(&name))
    {
        push(
            problems,
            child(path, "format"),
            "`format` must be one of `uri`, `hostname`, `ipv4` and `ipv6`",
        );
    }
}

fn check_pattern(schema: &Map<String, Value>, path: &str, problems: &mut Vec<ManifestProblem>) {
    let Some(value) = schema.get("pattern") else {
        return;
    };
    let pattern_path = child(path, "pattern");
    let Some(pattern) = value.as_str() else {
        push(problems, pattern_path, "`pattern` must be a string");
        return;
    };
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        push(
            problems,
            pattern_path,
            format!("`pattern` is longer than {MAX_PATTERN_CHARS} characters"),
        );
    } else if let Err(error) = Regex::new(pattern) {
        push(
            problems,
            pattern_path,
            format!(
                "`pattern` is not a valid regular expression: {}",
                regex_reason(&error)
            ),
        );
    }
}

/// The last line of a regex error, which names the reason without the source excerpt.
fn regex_reason(error: &regex::Error) -> String {
    let text = error.to_string();
    let last = text.lines().next_back().unwrap_or_default().trim();
    last.strip_prefix("error: ").unwrap_or(last).to_owned()
}

fn check_integer_keywords(
    schema: &Map<String, Value>,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    check_enum(schema, Kind::Integer, path, problems);
    let min = check_bound(schema, "minimum", path, as_integer, "an integer", problems);
    let max = check_bound(schema, "maximum", path, as_integer, "an integer", problems);
    check_order(min, max, ("minimum", "maximum"), path, problems);
}

fn check_number_keywords(
    schema: &Map<String, Value>,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    let min = check_bound(schema, "minimum", path, Value::as_f64, "a number", problems);
    let max = check_bound(schema, "maximum", path, Value::as_f64, "a number", problems);
    check_order(min, max, ("minimum", "maximum"), path, problems);
}

fn check_array_keywords(
    schema: &Map<String, Value>,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    match schema.get("items") {
        None => push(
            problems,
            child(path, "items"),
            "an array setting needs `items`: a schema of type `string` or `integer`",
        ),
        Some(items) => check_typed_schema(items, &child(path, "items"), Level::Item, problems),
    }
    let min = check_count(schema, "minItems", path, problems);
    let max = check_count(schema, "maxItems", path, problems);
    check_order(min, max, ("minItems", "maxItems"), path, problems);
    if let Some(unique) = schema.get("uniqueItems")
        && !unique.is_boolean()
    {
        push(
            problems,
            child(path, "uniqueItems"),
            "`uniqueItems` must be a boolean",
        );
    }
}

/// A `default` must satisfy the schema it belongs to.
fn check_default(schema: &Value, default: &Value, path: &str, problems: &mut Vec<ManifestProblem>) {
    let mut found = Vec::new();
    check_value(schema, default, "", &mut found);
    for problem in found {
        push(
            problems,
            format!("{path}/default{}", problem.path),
            format!("the default is not valid: {}", problem.message),
        );
    }
}

// ---------------------------------------------------------------------------------------
// Instance settings
// ---------------------------------------------------------------------------------------

/// Validates settings against a schema and returns them with defaults filled in.
///
/// The schema is expected to have passed [`validate_settings_schema`]; on any other schema
/// unknown keywords, unknown types and malformed values of known keywords are ignored
/// rather than reported, and nothing panics.
pub(crate) fn validate_settings(
    schema: &serde_json::Value,
    settings: &serde_json::Value,
) -> Result<serde_json::Value, Vec<SettingsProblem>> {
    let Some(document) = settings.as_object() else {
        return Err(vec![SettingsProblem::new(
            "",
            CODE_TYPE,
            "the settings must be a JSON object",
        )]);
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    let mut merged = document.clone();
    for (name, property) in properties.into_iter().flatten() {
        if !merged.contains_key(name)
            && let Some(default) = property.get("default")
        {
            merged.insert(name.clone(), default.clone());
        }
    }
    let mut problems = Vec::new();
    for (name, value) in &merged {
        let path = child("", name);
        match properties.and_then(|properties| properties.get(name)) {
            Some(property) => check_value(property, value, &path, &mut problems),
            None => problems.push(SettingsProblem::new(
                path,
                CODE_UNKNOWN,
                "this setting is not declared by the plugin",
            )),
        }
    }
    let required = schema.get("required").and_then(Value::as_array);
    for name in required.into_iter().flatten().filter_map(Value::as_str) {
        if !merged.contains_key(name) {
            problems.push(SettingsProblem::new(
                child("", name),
                CODE_REQUIRED,
                "a value is required",
            ));
        }
    }
    if problems.is_empty() {
        Ok(Value::Object(merged))
    } else {
        Err(problems)
    }
}

/// One value against the schema of its setting (or of an array item). A schema without a
/// known `type` accepts everything.
fn check_value(schema: &Value, value: &Value, path: &str, out: &mut Vec<SettingsProblem>) {
    let Some(kind) = Kind::of(schema) else {
        return;
    };
    match kind {
        Kind::String => check_string_value(schema, value, path, out),
        Kind::Integer => check_integer_value(schema, value, path, out),
        Kind::Number => check_number_value(schema, value, path, out),
        Kind::Boolean => {
            if !value.is_boolean() {
                out.push(wrong_type(path, "a boolean"));
            }
        }
        Kind::Array => check_array_value(schema, value, path, out),
    }
}

fn wrong_type(path: &str, expected: &str) -> SettingsProblem {
    SettingsProblem::new(path, CODE_TYPE, format!("must be {expected}"))
}

/// A value for a message: strings quoted, other values as JSON.
fn describe(value: &Value) -> String {
    value.as_str().map_or_else(|| value.to_string(), quote)
}

/// The `enum` of a schema, when it is a non-empty array.
fn enum_values(schema: &Value) -> Option<&[Value]> {
    schema
        .get("enum")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .map(Vec::as_slice)
}

fn not_in_enum(path: &str, allowed: &[Value]) -> SettingsProblem {
    let mut listed: Vec<String> = allowed
        .iter()
        .take(MAX_LISTED_VALUES)
        .map(describe)
        .collect();
    if allowed.len() > MAX_LISTED_VALUES {
        listed.push("...".to_owned());
    }
    SettingsProblem::new(
        path,
        CODE_ENUM,
        format!("must be one of {}", listed.join(", ")),
    )
}

fn check_string_value(schema: &Value, value: &Value, path: &str, out: &mut Vec<SettingsProblem>) {
    let Some(text) = value.as_str() else {
        out.push(wrong_type(path, "a string"));
        return;
    };
    if let Some(allowed) = enum_values(schema)
        && !allowed.iter().any(|item| item.as_str() == Some(text))
    {
        out.push(not_in_enum(path, allowed));
    }
    check_length(schema, text, path, out);
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
        && let Ok(regex) = Regex::new(pattern)
        && !regex.is_match(text)
    {
        out.push(SettingsProblem::new(
            path,
            CODE_PATTERN,
            format!("must match the pattern {}", quote(pattern)),
        ));
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str)
        && let Some(expected) = format_violation(format, text)
    {
        out.push(SettingsProblem::new(path, CODE_FORMAT, expected));
    }
}

/// What the text should be, when it does not have the format.
fn format_violation(format: &str, text: &str) -> Option<&'static str> {
    let (valid, expected) = match format {
        "uri" => (is_uri(text), "must be a URI such as `https://host/path`"),
        "hostname" => (is_hostname(text), "must be a host name"),
        "ipv4" => (text.parse::<Ipv4Addr>().is_ok(), "must be an IPv4 address"),
        "ipv6" => (text.parse::<Ipv6Addr>().is_ok(), "must be an IPv6 address"),
        _ => return None,
    };
    (!valid).then_some(expected)
}

/// `minLength` and `maxLength`, counted in characters.
fn check_length(schema: &Value, text: &str, path: &str, out: &mut Vec<SettingsProblem>) {
    let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
        && length < min
    {
        out.push(SettingsProblem::new(
            path,
            CODE_LENGTH,
            format!("must have at least {}", plural(min, "character")),
        ));
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
        && length > max
    {
        out.push(SettingsProblem::new(
            path,
            CODE_LENGTH,
            format!("must have at most {}", plural(max, "character")),
        ));
    }
}

fn check_integer_value(schema: &Value, value: &Value, path: &str, out: &mut Vec<SettingsProblem>) {
    let Some(number) = as_integer(value) else {
        out.push(wrong_type(path, "an integer"));
        return;
    };
    if let Some(allowed) = enum_values(schema)
        && !allowed
            .iter()
            .filter_map(as_integer)
            .any(|item| item == number)
    {
        out.push(not_in_enum(path, allowed));
    }
    if let Some(min) = schema.get("minimum").and_then(as_integer)
        && number < min
    {
        out.push(SettingsProblem::new(
            path,
            CODE_RANGE,
            format!("must be at least {min}"),
        ));
    }
    if let Some(max) = schema.get("maximum").and_then(as_integer)
        && number > max
    {
        out.push(SettingsProblem::new(
            path,
            CODE_RANGE,
            format!("must be at most {max}"),
        ));
    }
}

fn check_number_value(schema: &Value, value: &Value, path: &str, out: &mut Vec<SettingsProblem>) {
    let Some(number) = value.as_f64() else {
        out.push(wrong_type(path, "a number"));
        return;
    };
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
        && number < min
    {
        out.push(SettingsProblem::new(
            path,
            CODE_RANGE,
            format!("must be at least {min}"),
        ));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
        && number > max
    {
        out.push(SettingsProblem::new(
            path,
            CODE_RANGE,
            format!("must be at most {max}"),
        ));
    }
}

fn check_array_value(schema: &Value, value: &Value, path: &str, out: &mut Vec<SettingsProblem>) {
    let Some(items) = value.as_array() else {
        out.push(wrong_type(path, "an array"));
        return;
    };
    let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
        && count < min
    {
        out.push(SettingsProblem::new(
            path,
            CODE_ITEMS,
            format!("must have at least {}", plural(min, "item")),
        ));
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
        && count > max
    {
        out.push(SettingsProblem::new(
            path,
            CODE_ITEMS,
            format!("must have at most {}", plural(max, "item")),
        ));
    }
    if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
        let mut seen = HashSet::new();
        for (index, item) in items.iter().enumerate() {
            if !seen.insert(item.to_string()) {
                out.push(SettingsProblem::new(
                    format!("{path}/{index}"),
                    CODE_UNIQUE,
                    "duplicates an earlier item",
                ));
            }
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            check_value(item_schema, item, &format!("{path}/{index}"), out);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    /// A schema with a single setting `p`.
    fn one(property: &Value) -> Value {
        json!({ "type": "object", "properties": { "p": property } })
    }

    /// The paths of the schema problems, in order.
    fn schema_paths(schema: &Value) -> Vec<String> {
        validate_settings_schema(schema)
            .into_iter()
            .map(|problem| problem.path)
            .collect()
    }

    #[track_caller]
    fn assert_schema_ok(schema: &Value) {
        let problems = validate_settings_schema(schema);
        assert!(problems.is_empty(), "unexpected problems: {problems:#?}");
    }

    /// The schema has a problem at `path` whose message contains `fragment`.
    #[track_caller]
    fn assert_schema_problem(schema: &Value, path: &str, fragment: &str) {
        let problems = validate_settings_schema(schema);
        assert!(
            problems
                .iter()
                .any(|problem| problem.path == path && problem.message.contains(fragment)),
            "no problem at {path} containing {fragment:?} in {problems:#?}"
        );
    }

    /// The only problem of the schema is at `path` and contains `fragment`.
    #[track_caller]
    fn assert_single_schema_problem(schema: &Value, path: &str, fragment: &str) {
        assert_schema_problem(schema, path, fragment);
        let problems = validate_settings_schema(schema);
        assert_eq!(problems.len(), 1, "more than one problem: {problems:#?}");
    }

    /// The `(path, code)` pairs of the problems of validating `settings`, sorted.
    fn failures(schema: &Value, settings: &Value) -> Vec<(String, &'static str)> {
        let mut found: Vec<_> = validate_settings(schema, settings)
            .expect_err("the settings should be refused")
            .into_iter()
            .map(|problem| (problem.path, problem.code))
            .collect();
        found.sort();
        found
    }

    #[track_caller]
    fn assert_fails(schema: &Value, settings: &Value, path: &str, code: &str) {
        let found = failures(schema, settings);
        assert!(
            found
                .iter()
                .any(|(found_path, found_code)| found_path == path && *found_code == code),
            "expected {code} at {path:?}, found {found:?}"
        );
    }

    #[track_caller]
    fn assert_accepts(schema: &Value, settings: &Value) {
        if let Err(problems) = validate_settings(schema, settings) {
            panic!("unexpected problems: {problems:#?}");
        }
    }

    /// The settings schema of a network controller.
    fn controller_schema() -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "title": "Network controller",
            "properties": {
                "address": {
                    "type": "string",
                    "format": "uri",
                    "title": "Address",
                    "examples": ["https://unifi.example.net:8443"]
                },
                "site": {
                    "type": "string",
                    "default": "default",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": "^[A-Za-z0-9_-]+$"
                },
                "verify_tls": { "type": "boolean", "default": true },
                "poll_interval": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": 3600,
                    "default": 300
                },
                "tags": {
                    "type": "array",
                    "items": { "type": "string", "maxLength": 32 },
                    "uniqueItems": true,
                    "maxItems": 8
                }
            },
            "required": ["address"],
            "additionalProperties": false
        })
    }

    // -----------------------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------------------

    #[test]
    fn hostnames_follow_rfc_1123_labels() {
        for valid in [
            "a",
            "host",
            "unifi.example.net",
            "example.com.",
            "a-b.example.org",
            "192.0.2.10",
            "1a.test",
        ] {
            assert!(is_hostname(valid), "{valid} should be a host name");
        }
        let long_label = "a".repeat(64);
        let longest = format!("{}a", "a.".repeat(126));
        assert_eq!(longest.len(), 253);
        assert!(is_hostname(&longest));
        assert!(is_hostname(&format!("{longest}.")));
        let too_long = format!("{longest}.a");
        for invalid in [
            "",
            ".",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            ".example.com",
            "a_b.example.com",
            "a b.example.com",
            "exämple.com",
            "2001:db8::1",
            long_label.as_str(),
            too_long.as_str(),
        ] {
            assert!(!is_hostname(invalid), "{invalid} should not be a host name");
        }
        assert!(is_hostname(&"a".repeat(63)));
    }

    #[test]
    fn uris_need_a_scheme_and_a_rest_without_whitespace() {
        for valid in [
            "https://unifi.example.net:8443",
            "http://192.0.2.10/path?q=1",
            "ssh:host",
            "a+b.c-d:x",
        ] {
            assert!(is_uri(valid), "{valid} should be a URI");
        }
        for invalid in [
            "",
            "unifi.example.net",
            "https:",
            ":rest",
            "1http://x",
            "ht tp://x",
            "https://exa mple.com",
            "https://x\n",
            "https://x\u{0}",
            "h_ttp://x",
        ] {
            assert!(!is_uri(invalid), "{invalid:?} should not be a URI");
        }
    }

    #[test]
    fn identifiers_are_lowercase_with_digits_and_underscores() {
        let longest = "a".repeat(64);
        let too_long = "a".repeat(65);
        for valid in ["a", "url", "poll_interval", "a1_b2", longest.as_str()] {
            assert!(is_identifier(valid), "{valid} should be an identifier");
        }
        for invalid in ["", "Url", "1a", "_a", "a-b", "a b", "ä", too_long.as_str()] {
            assert!(!is_identifier(invalid), "{invalid} should not be one");
        }
    }

    #[test]
    fn secret_names_are_recognized_alone_or_after_an_underscore() {
        for secret in [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "db_password",
            "unifi_api_key",
            "admin_token",
            "client_secret",
            "Password",
        ] {
            assert!(holds_secret(secret), "{secret} should be a secret name");
        }
        for other in [
            "passwordless",
            "token_ttl",
            "tokens",
            "keyboard",
            "secretary",
            "mypassword",
            "url",
            "key",
        ] {
            assert!(!holds_secret(other), "{other} should be allowed");
        }
    }

    #[test]
    fn quote_cuts_long_text_and_hides_control_characters() {
        assert_eq!(quote("abc"), "`abc`");
        assert_eq!(quote("a\nb"), "`a?b`");
        let shown = quote(&"x".repeat(300));
        assert_eq!(shown.chars().count(), 100 + 3 + 2);
        assert!(shown.ends_with("...`"));
    }

    #[test]
    fn problem_display_prefixes_the_path() {
        let problem = SettingsProblem::new("/url", CODE_REQUIRED, "a value is required");
        assert_eq!(problem.to_string(), "/url: a value is required");
        let document = SettingsProblem::new("", CODE_TYPE, "the settings must be a JSON object");
        assert_eq!(document.to_string(), "the settings must be a JSON object");
    }

    // -----------------------------------------------------------------------------------
    // Schema: root
    // -----------------------------------------------------------------------------------

    #[test]
    fn empty_schemas_are_valid() {
        assert_schema_ok(&super::super::empty_settings_schema());
        assert_schema_ok(&json!({ "type": "object" }));
    }

    #[test]
    fn controller_schema_is_valid() {
        assert_schema_ok(&controller_schema());
    }

    #[test]
    fn schema_must_be_an_object() {
        for schema in [json!(null), json!([]), json!("object"), json!(3)] {
            assert_single_schema_problem(&schema, "/settings", "must be a JSON object");
        }
    }

    #[test]
    fn root_type_must_be_object() {
        assert_single_schema_problem(&json!({}), "/settings/type", "\"type\": \"object\"");
        assert_single_schema_problem(
            &json!({ "type": "string" }),
            "/settings/type",
            "\"type\": \"object\"",
        );
        assert_single_schema_problem(
            &json!({ "type": ["object"] }),
            "/settings/type",
            "\"type\": \"object\"",
        );
    }

    #[test]
    fn root_dialect_is_2020_12_only() {
        assert_schema_ok(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        }));
        assert_single_schema_problem(
            &json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object"
            }),
            "/settings/$schema",
            "draft/2020-12",
        );
        assert_single_schema_problem(
            &json!({ "$schema": 7, "type": "object" }),
            "/settings/$schema",
            "draft/2020-12",
        );
    }

    #[test]
    fn root_unknown_keywords_are_named() {
        let schema = json!({ "type": "object", "$id": "x", "definitions": {}, "if": {} });
        assert_schema_problem(&schema, "/settings/$id", "`$id` is not a supported keyword");
        assert_schema_problem(&schema, "/settings/definitions", "`definitions`");
        assert_schema_problem(&schema, "/settings/if", "`if`");
        assert_eq!(validate_settings_schema(&schema).len(), 3);
    }

    #[test]
    fn additional_properties_can_only_be_false() {
        assert_schema_ok(&json!({ "type": "object", "additionalProperties": false }));
        for value in [json!(true), json!({}), json!(null), json!("no")] {
            assert_single_schema_problem(
                &json!({ "type": "object", "additionalProperties": value }),
                "/settings/additionalProperties",
                "can only be `false`",
            );
        }
    }

    #[test]
    fn root_title_and_description_have_limits() {
        assert_schema_ok(&json!({
            "type": "object",
            "title": "t".repeat(200),
            "description": "d".repeat(1000)
        }));
        assert_schema_problem(
            &json!({ "type": "object", "title": "t".repeat(201) }),
            "/settings/title",
            "longer than 200",
        );
        assert_schema_problem(
            &json!({ "type": "object", "description": "d".repeat(1001) }),
            "/settings/description",
            "longer than 1000",
        );
        assert_schema_problem(
            &json!({ "type": "object", "title": 5 }),
            "/settings/title",
            "must be a string",
        );
    }

    // -----------------------------------------------------------------------------------
    // Schema: properties
    // -----------------------------------------------------------------------------------

    #[test]
    fn properties_must_be_an_object() {
        for value in [json!([]), json!(null), json!("p")] {
            assert_single_schema_problem(
                &json!({ "type": "object", "properties": value }),
                "/settings/properties",
                "must be an object",
            );
        }
    }

    #[test]
    fn at_most_64_settings() {
        let mut properties = Map::new();
        for index in 0..64 {
            properties.insert(format!("s{index}"), json!({ "type": "boolean" }));
        }
        let mut schema = json!({ "type": "object", "properties": properties });
        assert_schema_ok(&schema);
        schema["properties"]["s64"] = json!({ "type": "boolean" });
        assert_single_schema_problem(&schema, "/settings/properties", "at most 64 settings");
    }

    #[test]
    fn setting_names_have_a_fixed_shape() {
        for name in ["Url", "1a", "a-b", "a b", "ä"] {
            let schema = json!({ "type": "object", "properties": { name: { "type": "string" } } });
            assert_single_schema_problem(
                &schema,
                &format!("/settings/properties/{name}"),
                "is not a setting name",
            );
        }
        let long = "a".repeat(65);
        let schema =
            json!({ "type": "object", "properties": { long.as_str(): { "type": "string" } } });
        assert_single_schema_problem(
            &schema,
            &format!("/settings/properties/{long}"),
            "at most 64 characters",
        );
        let longest = "a".repeat(64);
        assert_schema_ok(
            &json!({ "type": "object", "properties": { longest.as_str(): { "type": "string" } } }),
        );
    }

    #[test]
    fn setting_names_are_escaped_in_problem_paths() {
        let schema = json!({ "type": "object", "properties": { "a/b~c": { "type": "string" } } });
        assert_single_schema_problem(
            &schema,
            "/settings/properties/a~1b~0c",
            "is not a setting name",
        );
    }

    #[test]
    fn secrets_never_live_in_settings() {
        for name in [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "db_password",
            "unifi_api_key",
        ] {
            let schema = json!({ "type": "object", "properties": { name: { "type": "string" } } });
            assert_single_schema_problem(
                &schema,
                &format!("/settings/properties/{name}"),
                "secrets are declared in `secrets` and injected per call, never stored in settings",
            );
        }
        for name in ["passwordless", "token_ttl", "keyboard"] {
            let schema = json!({ "type": "object", "properties": { name: { "type": "string" } } });
            assert_schema_ok(&schema);
        }
    }

    #[test]
    fn a_setting_is_an_object_with_a_known_type() {
        assert_single_schema_problem(
            &one(&json!("string")),
            "/settings/properties/p",
            "must be an object",
        );
        for property in [
            json!({}),
            json!({ "type": "object" }),
            json!({ "type": "null" }),
            json!({ "type": ["string", "null"] }),
            json!({ "type": 5 }),
        ] {
            assert_single_schema_problem(
                &one(&property),
                "/settings/properties/p/type",
                "needs a `type` of `string`, `integer`, `number`, `boolean` or `array`",
            );
        }
    }

    #[test]
    fn unknown_keywords_are_named() {
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "const": "x" })),
            "/settings/properties/p/const",
            "`const` is not a supported keyword for type `string`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "boolean", "enum": [true] })),
            "/settings/properties/p/enum",
            "type `boolean`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "minLength": 1 })),
            "/settings/properties/p/minLength",
            "type `integer`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "number", "enum": [1] })),
            "/settings/properties/p/enum",
            "type `number`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "items": {} })),
            "/settings/properties/p/items",
            "type `string`",
        );
    }

    #[test]
    fn common_keywords_have_limits() {
        assert_schema_ok(&one(&json!({
            "type": "string",
            "title": "t".repeat(200),
            "description": "d".repeat(1000),
            "default": "x",
            "examples": ["a", "b"]
        })));
        assert_schema_problem(
            &one(&json!({ "type": "string", "title": "t".repeat(201) })),
            "/settings/properties/p/title",
            "longer than 200",
        );
        assert_schema_problem(
            &one(&json!({ "type": "string", "description": "d".repeat(1001) })),
            "/settings/properties/p/description",
            "longer than 1000",
        );
        assert_schema_problem(
            &one(&json!({ "type": "string", "title": ["x"] })),
            "/settings/properties/p/title",
            "must be a string",
        );
        assert_schema_problem(
            &one(&json!({ "type": "string", "examples": "x" })),
            "/settings/properties/p/examples",
            "must be an array",
        );
    }

    #[test]
    fn title_limits_count_characters_not_bytes() {
        assert_schema_ok(&one(&json!({ "type": "string", "title": "ä".repeat(200) })));
    }

    // -----------------------------------------------------------------------------------
    // Schema: string
    // -----------------------------------------------------------------------------------

    #[test]
    fn string_enum_is_a_non_empty_array_of_unique_strings() {
        assert_schema_ok(&one(&json!({ "type": "string", "enum": ["a", "b"] })));
        for value in [json!([]), json!("a"), json!({})] {
            assert_single_schema_problem(
                &one(&json!({ "type": "string", "enum": value })),
                "/settings/properties/p/enum",
                "non-empty array",
            );
        }
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "enum": ["a", 1] })),
            "/settings/properties/p/enum/1",
            "must be a string",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "enum": ["a", "b", "a"] })),
            "/settings/properties/p/enum/2",
            "`a` is listed twice",
        );
    }

    #[test]
    fn length_bounds_are_non_negative_integers_in_order() {
        assert_schema_ok(&one(
            &json!({ "type": "string", "minLength": 0, "maxLength": 5 }),
        ));
        assert_schema_ok(&one(
            &json!({ "type": "string", "minLength": 5, "maxLength": 5 }),
        ));
        for value in [json!(-1), json!(1.5), json!("1"), json!(null)] {
            assert_single_schema_problem(
                &one(&json!({ "type": "string", "minLength": value })),
                "/settings/properties/p/minLength",
                "non-negative integer",
            );
            assert_single_schema_problem(
                &one(&json!({ "type": "string", "maxLength": value })),
                "/settings/properties/p/maxLength",
                "non-negative integer",
            );
        }
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "minLength": 6, "maxLength": 5 })),
            "/settings/properties/p/minLength",
            "must not be larger than `maxLength`",
        );
    }

    #[test]
    fn pattern_must_compile_and_stay_short() {
        assert_schema_ok(&one(&json!({ "type": "string", "pattern": "^[a-z]+$" })));
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "pattern": "(" })),
            "/settings/properties/p/pattern",
            "not a valid regular expression",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "pattern": 5 })),
            "/settings/properties/p/pattern",
            "must be a string",
        );
        assert_schema_ok(&one(
            &json!({ "type": "string", "pattern": "a".repeat(1000) }),
        ));
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "pattern": "a".repeat(1001) })),
            "/settings/properties/p/pattern",
            "longer than 1000",
        );
    }

    #[test]
    fn pattern_error_names_the_reason_in_one_line() {
        let problems = validate_settings_schema(&one(&json!({ "type": "string", "pattern": "(" })));
        let message = &problems[0].message;
        assert!(message.contains("unclosed group"), "{message}");
        assert!(!message.contains('\n'), "{message}");
    }

    #[test]
    fn format_is_one_of_four() {
        for format in ["uri", "hostname", "ipv4", "ipv6"] {
            assert_schema_ok(&one(&json!({ "type": "string", "format": format })));
        }
        for format in [json!("email"), json!("date-time"), json!(4), json!(null)] {
            assert_single_schema_problem(
                &one(&json!({ "type": "string", "format": format })),
                "/settings/properties/p/format",
                "one of `uri`, `hostname`, `ipv4` and `ipv6`",
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // Schema: integer, number, boolean
    // -----------------------------------------------------------------------------------

    #[test]
    fn integer_bounds_are_integers_in_order() {
        assert_schema_ok(&one(
            &json!({ "type": "integer", "minimum": -5, "maximum": 10 }),
        ));
        assert_schema_ok(&one(
            &json!({ "type": "integer", "minimum": 0, "maximum": u64::MAX }),
        ));
        for value in [json!(1.5), json!("1"), json!(null)] {
            assert_single_schema_problem(
                &one(&json!({ "type": "integer", "minimum": value })),
                "/settings/properties/p/minimum",
                "must be an integer",
            );
            assert_single_schema_problem(
                &one(&json!({ "type": "integer", "maximum": value })),
                "/settings/properties/p/maximum",
                "must be an integer",
            );
        }
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "minimum": 11, "maximum": 10 })),
            "/settings/properties/p/minimum",
            "must not be larger than `maximum`",
        );
    }

    #[test]
    fn integer_enum_is_unique_integers() {
        assert_schema_ok(&one(&json!({ "type": "integer", "enum": [1, 2, 3] })));
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "enum": [1, 2, 1] })),
            "/settings/properties/p/enum/2",
            "1 is listed twice",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "enum": [1, 2.5] })),
            "/settings/properties/p/enum/1",
            "must be an integer",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "enum": ["1"] })),
            "/settings/properties/p/enum/0",
            "must be an integer",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "enum": [] })),
            "/settings/properties/p/enum",
            "non-empty array",
        );
    }

    #[test]
    fn number_bounds_are_numbers_in_order() {
        assert_schema_ok(&one(
            &json!({ "type": "number", "minimum": -0.5, "maximum": 2.5 }),
        ));
        assert_schema_ok(&one(
            &json!({ "type": "number", "minimum": 1, "maximum": 1 }),
        ));
        assert_single_schema_problem(
            &one(&json!({ "type": "number", "minimum": "1" })),
            "/settings/properties/p/minimum",
            "must be a number",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "number", "maximum": null })),
            "/settings/properties/p/maximum",
            "must be a number",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "number", "minimum": 2.5, "maximum": 2.4 })),
            "/settings/properties/p/minimum",
            "must not be larger than `maximum`",
        );
    }

    #[test]
    fn boolean_takes_no_other_keywords() {
        assert_schema_ok(&one(
            &json!({ "type": "boolean", "title": "On", "default": false }),
        ));
        assert_single_schema_problem(
            &one(&json!({ "type": "boolean", "minimum": 0 })),
            "/settings/properties/p/minimum",
            "type `boolean`",
        );
    }

    // -----------------------------------------------------------------------------------
    // Schema: array
    // -----------------------------------------------------------------------------------

    #[test]
    fn array_needs_items_of_string_or_integer() {
        assert_schema_ok(&one(
            &json!({ "type": "array", "items": { "type": "string" } }),
        ));
        assert_schema_ok(&one(
            &json!({ "type": "array", "items": { "type": "integer", "minimum": 1 } }),
        ));
        assert_single_schema_problem(
            &one(&json!({ "type": "array" })),
            "/settings/properties/p/items",
            "needs `items`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": "string" })),
            "/settings/properties/p/items",
            "must be an object",
        );
        for item_type in ["array", "number", "boolean", "object"] {
            assert_single_schema_problem(
                &one(&json!({ "type": "array", "items": { "type": item_type } })),
                "/settings/properties/p/items/type",
                "`string` or `integer`",
            );
        }
    }

    #[test]
    fn items_use_the_keywords_of_their_type() {
        assert_schema_ok(&one(&json!({
            "type": "array",
            "items": {
                "type": "string",
                "title": "Host",
                "minLength": 1,
                "maxLength": 253,
                "pattern": "^[a-z.]+$",
                "format": "hostname",
                "enum": ["a.test", "b.test"]
            }
        })));
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string", "minimum": 1 } })),
            "/settings/properties/p/items/minimum",
            "type `string`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string", "default": "x" } })),
            "/settings/properties/p/items/default",
            "not a supported keyword",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string", "pattern": "(" } })),
            "/settings/properties/p/items/pattern",
            "regular expression",
        );
        assert_single_schema_problem(
            &one(
                &json!({ "type": "array", "items": { "type": "integer", "minimum": 5, "maximum": 1 } }),
            ),
            "/settings/properties/p/items/minimum",
            "must not be larger",
        );
    }

    #[test]
    fn item_count_bounds_are_ordered_integers() {
        assert_schema_ok(&one(&json!({
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1,
            "maxItems": 3,
            "uniqueItems": true
        })));
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string" }, "minItems": -1 })),
            "/settings/properties/p/minItems",
            "non-negative integer",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string" }, "maxItems": 1.5 })),
            "/settings/properties/p/maxItems",
            "non-negative integer",
        );
        assert_single_schema_problem(
            &one(&json!({
                "type": "array", "items": { "type": "string" }, "minItems": 4, "maxItems": 3
            })),
            "/settings/properties/p/minItems",
            "must not be larger than `maxItems`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "string" }, "uniqueItems": "yes" })),
            "/settings/properties/p/uniqueItems",
            "must be a boolean",
        );
    }

    // -----------------------------------------------------------------------------------
    // Schema: defaults and required
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_default_must_satisfy_its_schema() {
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "minimum": 60, "default": 30 })),
            "/settings/properties/p/default",
            "the default is not valid: must be at least 60",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "enum": ["a", "b"], "default": "c" })),
            "/settings/properties/p/default",
            "must be one of `a`, `b`",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "default": 5 })),
            "/settings/properties/p/default",
            "must be a string",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "boolean", "default": "true" })),
            "/settings/properties/p/default",
            "must be a boolean",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "string", "format": "uri", "default": "not a uri" })),
            "/settings/properties/p/default",
            "must be a URI",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "default": 1.5 })),
            "/settings/properties/p/default",
            "must be an integer",
        );
    }

    #[test]
    fn a_default_is_checked_inside_arrays() {
        assert_schema_ok(&one(&json!({
            "type": "array",
            "items": { "type": "string" },
            "uniqueItems": true,
            "default": ["a", "b"]
        })));
        assert_single_schema_problem(
            &one(&json!({
                "type": "array", "items": { "type": "string" }, "uniqueItems": true,
                "default": ["a", "a"]
            })),
            "/settings/properties/p/default/1",
            "duplicates an earlier item",
        );
        assert_single_schema_problem(
            &one(&json!({ "type": "array", "items": { "type": "integer" }, "default": [1, "2"] })),
            "/settings/properties/p/default/1",
            "must be an integer",
        );
    }

    #[test]
    fn a_default_is_not_checked_when_the_schema_has_other_problems() {
        assert_single_schema_problem(
            &one(&json!({ "type": "integer", "minimum": "x", "default": "y" })),
            "/settings/properties/p/minimum",
            "must be an integer",
        );
    }

    #[test]
    fn required_names_declared_settings_once() {
        let mut schema = controller_schema();
        schema["required"] = json!(["address", "site"]);
        assert_schema_ok(&schema);
        schema["required"] = json!("address");
        assert_single_schema_problem(&schema, "/settings/required", "array of setting names");
        schema["required"] = json!(["address", 5]);
        assert_single_schema_problem(&schema, "/settings/required/1", "must be a string");
        schema["required"] = json!(["address", "address"]);
        assert_single_schema_problem(&schema, "/settings/required/1", "`address` is listed twice");
        schema["required"] = json!(["address", "nope"]);
        assert_single_schema_problem(
            &schema,
            "/settings/required/1",
            "`nope` is not a declared setting",
        );
    }

    #[test]
    fn required_without_properties_names_undeclared_settings() {
        assert_single_schema_problem(
            &json!({ "type": "object", "required": ["a"] }),
            "/settings/required/0",
            "not a declared setting",
        );
    }

    #[test]
    fn several_schema_problems_are_collected_together() {
        let schema = json!({
            "type": "object",
            "$id": "x",
            "properties": {
                "Bad": { "type": "string" },
                "api_key": { "type": "string" },
                "n": { "type": "integer", "minimum": 5, "maximum": 1, "format": "uri" },
                "tags": { "type": "array" }
            },
            "required": ["gone"]
        });
        let mut paths = schema_paths(&schema);
        paths.sort();
        assert_eq!(
            paths,
            [
                "/settings/$id",
                "/settings/properties/Bad",
                "/settings/properties/api_key",
                "/settings/properties/n/format",
                "/settings/properties/n/minimum",
                "/settings/properties/tags/items",
                "/settings/required/0",
            ]
        );
    }

    // -----------------------------------------------------------------------------------
    // Instances: documents, unknown members, required, defaults
    // -----------------------------------------------------------------------------------

    #[test]
    fn the_document_must_be_an_object() {
        let schema = controller_schema();
        for settings in [json!(null), json!([]), json!("x"), json!(1)] {
            let problems = validate_settings(&schema, &settings).expect_err("refused");
            assert_eq!(problems.len(), 1);
            assert_eq!(problems[0].path, "");
            assert_eq!(problems[0].code, "connect.settings.type");
        }
    }

    #[test]
    fn defaults_are_filled_in_for_absent_settings() {
        let schema = controller_schema();
        let settings = json!({ "address": "https://unifi.example.net:8443" });
        let result = validate_settings(&schema, &settings).expect("valid");
        assert_eq!(
            result,
            json!({
                "address": "https://unifi.example.net:8443",
                "site": "default",
                "verify_tls": true,
                "poll_interval": 300
            })
        );
    }

    #[test]
    fn given_values_win_over_defaults() {
        let schema = controller_schema();
        let settings = json!({
            "address": "https://unifi.example.net:8443",
            "site": "lab",
            "verify_tls": false,
            "poll_interval": 3600,
            "tags": ["core", "lab"]
        });
        let result = validate_settings(&schema, &settings).expect("valid");
        assert_eq!(result, settings);
    }

    #[test]
    fn settings_without_defaults_stay_absent() {
        let schema = one(&json!({ "type": "string" }));
        assert_eq!(
            validate_settings(&schema, &json!({})).expect("valid"),
            json!({})
        );
    }

    #[test]
    fn unknown_members_are_refused() {
        let schema = controller_schema();
        let settings = json!({ "address": "https://unifi.example.net", "extra": 1 });
        assert_eq!(
            failures(&schema, &settings),
            [("/extra".to_owned(), "connect.settings.unknown")]
        );
        let problems = validate_settings(&schema, &settings).expect_err("refused");
        assert_eq!(
            problems[0].message,
            "this setting is not declared by the plugin"
        );
    }

    #[test]
    fn unknown_member_paths_are_escaped() {
        let schema = json!({ "type": "object", "properties": {} });
        assert_fails(
            &schema,
            &json!({ "a/b": 1 }),
            "/a~1b",
            "connect.settings.unknown",
        );
    }

    #[test]
    fn a_schema_without_properties_declares_no_settings() {
        assert_accepts(&json!({ "type": "object" }), &json!({}));
        assert_fails(
            &json!({ "type": "object" }),
            &json!({ "x": 1 }),
            "/x",
            "connect.settings.unknown",
        );
    }

    #[test]
    fn required_settings_must_be_present() {
        let schema = controller_schema();
        assert_eq!(
            failures(&schema, &json!({})),
            [("/address".to_owned(), "connect.settings.required")]
        );
        assert_accepts(&schema, &json!({ "address": "https://unifi.example.net" }));
    }

    #[test]
    fn a_default_satisfies_required() {
        let schema = json!({
            "type": "object",
            "properties": { "site": { "type": "string", "default": "default" } },
            "required": ["site"]
        });
        let result = validate_settings(&schema, &json!({})).expect("valid");
        assert_eq!(result, json!({ "site": "default" }));
    }

    #[test]
    fn null_is_a_value_not_an_absence() {
        let schema = controller_schema();
        let settings = json!({ "address": "https://unifi.example.net", "site": null });
        assert_fails(&schema, &settings, "/site", "connect.settings.type");
    }

    // -----------------------------------------------------------------------------------
    // Instances: types
    // -----------------------------------------------------------------------------------

    #[test]
    fn values_must_have_the_declared_type() {
        let cases = [
            ("string", json!(5)),
            ("string", json!(null)),
            ("integer", json!("5")),
            ("integer", json!(true)),
            ("number", json!("5")),
            ("boolean", json!("true")),
            ("boolean", json!(1)),
            ("array", json!("a")),
            ("array", json!({})),
        ];
        for (kind, value) in cases {
            let property = if kind == "array" {
                json!({ "type": "array", "items": { "type": "string" } })
            } else {
                json!({ "type": kind })
            };
            assert_fails(
                &one(&property),
                &json!({ "p": value }),
                "/p",
                "connect.settings.type",
            );
        }
    }

    #[test]
    fn matching_types_are_accepted() {
        let schema = json!({
            "type": "object",
            "properties": {
                "s": { "type": "string" },
                "i": { "type": "integer" },
                "n": { "type": "number" },
                "b": { "type": "boolean" },
                "a": { "type": "array", "items": { "type": "string" } }
            }
        });
        assert_accepts(
            &schema,
            &json!({ "s": "x", "i": -3, "n": 1.5, "b": false, "a": ["x"] }),
        );
    }

    #[test]
    fn integers_have_no_fraction() {
        let schema = one(&json!({ "type": "integer" }));
        assert_accepts(&schema, &json!({ "p": 0 }));
        assert_accepts(&schema, &json!({ "p": i64::MIN }));
        assert_accepts(&schema, &json!({ "p": u64::MAX }));
        for text in ["1.5", "5.0", "1e3", "1.0e0"] {
            let settings: Value =
                serde_json::from_str(&format!("{{\"p\": {text}}}")).expect("json");
            assert_fails(&schema, &settings, "/p", "connect.settings.type");
        }
    }

    #[test]
    fn numbers_accept_integers_and_fractions() {
        let schema = one(&json!({ "type": "number" }));
        assert_accepts(&schema, &json!({ "p": 3 }));
        assert_accepts(&schema, &json!({ "p": -0.25 }));
        assert_accepts(&schema, &json!({ "p": u64::MAX }));
        assert_fails(&schema, &json!({ "p": "3" }), "/p", "connect.settings.type");
    }

    // -----------------------------------------------------------------------------------
    // Instances: constraints
    // -----------------------------------------------------------------------------------

    #[test]
    fn enums_list_the_allowed_values() {
        let schema = one(&json!({ "type": "string", "enum": ["a", "b"] }));
        assert_accepts(&schema, &json!({ "p": "a" }));
        assert_fails(&schema, &json!({ "p": "c" }), "/p", "connect.settings.enum");
        let problems = validate_settings(&schema, &json!({ "p": "c" })).expect_err("refused");
        assert_eq!(problems[0].message, "must be one of `a`, `b`");

        let numbers = one(&json!({ "type": "integer", "enum": [1, 2, 3] }));
        assert_accepts(&numbers, &json!({ "p": 2 }));
        assert_fails(&numbers, &json!({ "p": 4 }), "/p", "connect.settings.enum");
        let problems = validate_settings(&numbers, &json!({ "p": 4 })).expect_err("refused");
        assert_eq!(problems[0].message, "must be one of 1, 2, 3");
    }

    #[test]
    fn long_enums_are_abbreviated_in_the_message() {
        let values: Vec<String> = (0..30).map(|index| format!("v{index}")).collect();
        let schema = one(&json!({ "type": "string", "enum": values }));
        let problems = validate_settings(&schema, &json!({ "p": "x" })).expect_err("refused");
        assert!(
            problems[0].message.ends_with("`v9`, ..."),
            "{}",
            problems[0].message
        );
    }

    #[test]
    fn lengths_count_characters_not_bytes() {
        let schema = one(&json!({ "type": "string", "minLength": 2, "maxLength": 4 }));
        assert_accepts(&schema, &json!({ "p": "ab" }));
        assert_accepts(&schema, &json!({ "p": "ääää" }));
        assert_accepts(&schema, &json!({ "p": "日本語" }));
        assert_fails(
            &schema,
            &json!({ "p": "a" }),
            "/p",
            "connect.settings.length",
        );
        assert_fails(
            &schema,
            &json!({ "p": "äääää" }),
            "/p",
            "connect.settings.length",
        );
        let problems = validate_settings(&schema, &json!({ "p": "a" })).expect_err("refused");
        assert_eq!(problems[0].message, "must have at least 2 characters");
        let problems = validate_settings(&schema, &json!({ "p": "abcde" })).expect_err("refused");
        assert_eq!(problems[0].message, "must have at most 4 characters");
        let single = one(&json!({ "type": "string", "minLength": 1 }));
        let problems = validate_settings(&single, &json!({ "p": "" })).expect_err("refused");
        assert_eq!(problems[0].message, "must have at least 1 character");
    }

    #[test]
    fn patterns_are_searched_not_anchored() {
        let schema = one(&json!({ "type": "string", "pattern": "[0-9]{2}" }));
        assert_accepts(&schema, &json!({ "p": "abc42def" }));
        assert_fails(
            &schema,
            &json!({ "p": "abc4def" }),
            "/p",
            "connect.settings.pattern",
        );
        let anchored = one(&json!({ "type": "string", "pattern": "^[a-z]+$" }));
        assert_accepts(&anchored, &json!({ "p": "abc" }));
        assert_fails(
            &anchored,
            &json!({ "p": "abc1" }),
            "/p",
            "connect.settings.pattern",
        );
        let problems = validate_settings(&anchored, &json!({ "p": "1" })).expect_err("refused");
        assert_eq!(problems[0].message, "must match the pattern `^[a-z]+$`");
    }

    #[test]
    fn formats_are_checked() {
        let cases = [
            ("uri", "https://unifi.example.net:8443", "unifi.example.net"),
            ("hostname", "unifi.example.net", "unifi_example.net"),
            ("ipv4", "192.0.2.10", "192.0.2.256"),
            ("ipv6", "2001:db8::10", "2001:db8::g"),
        ];
        for (format, valid, invalid) in cases {
            let schema = one(&json!({ "type": "string", "format": format }));
            assert_accepts(&schema, &json!({ "p": valid }));
            assert_fails(
                &schema,
                &json!({ "p": invalid }),
                "/p",
                "connect.settings.format",
            );
        }
        let ipv4 = one(&json!({ "type": "string", "format": "ipv4" }));
        assert_fails(
            &ipv4,
            &json!({ "p": "2001:db8::1" }),
            "/p",
            "connect.settings.format",
        );
        let ipv6 = one(&json!({ "type": "string", "format": "ipv6" }));
        assert_fails(
            &ipv6,
            &json!({ "p": "192.0.2.1" }),
            "/p",
            "connect.settings.format",
        );
    }

    #[test]
    fn integer_ranges_are_inclusive() {
        let schema = one(&json!({ "type": "integer", "minimum": 60, "maximum": 3600 }));
        assert_accepts(&schema, &json!({ "p": 60 }));
        assert_accepts(&schema, &json!({ "p": 3600 }));
        assert_fails(&schema, &json!({ "p": 59 }), "/p", "connect.settings.range");
        assert_fails(
            &schema,
            &json!({ "p": 3601 }),
            "/p",
            "connect.settings.range",
        );
        let problems = validate_settings(&schema, &json!({ "p": 59 })).expect_err("refused");
        assert_eq!(problems[0].message, "must be at least 60");
        let problems = validate_settings(&schema, &json!({ "p": 3601 })).expect_err("refused");
        assert_eq!(problems[0].message, "must be at most 3600");
    }

    #[test]
    fn number_ranges_are_inclusive() {
        let schema = one(&json!({ "type": "number", "minimum": 0.5, "maximum": 2 }));
        assert_accepts(&schema, &json!({ "p": 0.5 }));
        assert_accepts(&schema, &json!({ "p": 2 }));
        assert_fails(
            &schema,
            &json!({ "p": 0.4 }),
            "/p",
            "connect.settings.range",
        );
        assert_fails(
            &schema,
            &json!({ "p": 2.1 }),
            "/p",
            "connect.settings.range",
        );
    }

    #[test]
    fn arrays_check_count_uniqueness_and_items() {
        let schema = one(&json!({
            "type": "array",
            "items": { "type": "string", "maxLength": 3 },
            "minItems": 1,
            "maxItems": 3,
            "uniqueItems": true
        }));
        assert_accepts(&schema, &json!({ "p": ["a", "b"] }));
        assert_fails(&schema, &json!({ "p": [] }), "/p", "connect.settings.items");
        assert_fails(
            &schema,
            &json!({ "p": ["a", "b", "c", "d"] }),
            "/p",
            "connect.settings.items",
        );
        assert_fails(
            &schema,
            &json!({ "p": ["a", "b", "a"] }),
            "/p/2",
            "connect.settings.unique",
        );
        assert_fails(
            &schema,
            &json!({ "p": ["a", 5] }),
            "/p/1",
            "connect.settings.type",
        );
        assert_fails(
            &schema,
            &json!({ "p": ["a", "abcd"] }),
            "/p/1",
            "connect.settings.length",
        );
        let problems = validate_settings(&schema, &json!({ "p": [] })).expect_err("refused");
        assert_eq!(problems[0].message, "must have at least 1 item");
    }

    #[test]
    fn duplicates_are_allowed_without_unique_items() {
        let schema = one(&json!({ "type": "array", "items": { "type": "integer" } }));
        assert_accepts(&schema, &json!({ "p": [1, 1, 2] }));
        assert_fails(
            &schema,
            &json!({ "p": [1, 2.5] }),
            "/p/1",
            "connect.settings.type",
        );
    }

    #[test]
    fn several_instance_problems_are_collected_together() {
        let schema = controller_schema();
        let settings = json!({
            "site": "",
            "verify_tls": "yes",
            "poll_interval": 5,
            "tags": ["a", "a"],
            "extra": true
        });
        assert_eq!(
            failures(&schema, &settings),
            [
                ("/address".to_owned(), "connect.settings.required"),
                ("/extra".to_owned(), "connect.settings.unknown"),
                ("/poll_interval".to_owned(), "connect.settings.range"),
                ("/site".to_owned(), "connect.settings.length"),
                ("/site".to_owned(), "connect.settings.pattern"),
                ("/tags/1".to_owned(), "connect.settings.unique"),
                ("/verify_tls".to_owned(), "connect.settings.type"),
            ]
        );
    }

    #[test]
    fn the_controller_example_is_accepted() {
        let schema = controller_schema();
        let settings = json!({
            "address": "https://unifi.example.net:8443",
            "site": "default",
            "poll_interval": 600
        });
        let result = validate_settings(&schema, &settings).expect("valid");
        assert_eq!(result["verify_tls"], json!(true));
        assert_eq!(result["poll_interval"], json!(600));
    }

    // -----------------------------------------------------------------------------------
    // Instances: invalid schemas
    // -----------------------------------------------------------------------------------

    #[test]
    fn invalid_schemas_never_panic_and_unknown_things_pass() {
        let schemas = [
            json!(null),
            json!([]),
            json!("object"),
            json!({}),
            json!({ "properties": [] }),
            json!({ "properties": { "p": null } }),
            json!({ "properties": { "p": { "type": "object" } } }),
            json!({ "properties": { "p": { "type": 5 } } }),
            json!({ "properties": { "p": { "type": "string", "pattern": "(" } } }),
            json!({ "properties": { "p": { "type": "string", "enum": [] } } }),
            json!({ "properties": { "p": { "type": "string", "enum": [1, null] } } }),
            json!({ "properties": { "p": { "type": "string", "minLength": "x", "maxLength": -1 } } }),
            json!({ "properties": { "p": { "type": "string", "format": "email" } } }),
            json!({ "properties": { "p": { "type": "integer", "minimum": "a", "enum": ["x"] } } }),
            json!({ "properties": { "p": { "type": "array" } } }),
            json!({ "properties": { "p": { "type": "array", "items": 5 } } }),
            json!({ "properties": { "p": { "type": "array", "items": { "type": "array" } } } }),
            json!({ "properties": { "p": { "type": "array", "minItems": "x", "uniqueItems": 3 } } }),
            json!({ "required": "p" }),
            json!({ "required": [1, null, "q"] }),
        ];
        let documents = [
            json!({}),
            json!({ "p": null }),
            json!({ "p": "x" }),
            json!({ "p": 3 }),
            json!({ "p": [1, "a", null, [2]] }),
            json!({ "p": {} }),
            json!([]),
        ];
        for schema in &schemas {
            for document in &documents {
                // Only the absence of a panic matters here.
                let _ = validate_settings(schema, document);
            }
        }
        // Unknown types and keywords pass.
        let lenient = json!({ "properties": { "p": { "type": "object" } } });
        assert_accepts(&lenient, &json!({ "p": { "any": "thing" } }));
        let odd =
            json!({ "properties": { "p": { "type": "string", "pattern": "(", "enum": [] } } });
        assert_accepts(&odd, &json!({ "p": "x" }));
    }

    #[test]
    fn invalid_schemas_never_panic_in_schema_validation() {
        let schemas = [
            json!(null),
            json!({ "type": "object", "properties": { "p": null, "q": [] } }),
            json!({ "type": "object", "properties": { "p": { "type": "array", "items": { "items": {} } } } }),
            json!({ "type": "object", "required": [[], {}, null] }),
            json!({ "type": "object", "properties": { "p": { "type": "string", "enum": [null, [], {}] } } }),
        ];
        for schema in &schemas {
            let first = validate_settings_schema(schema).into_iter().next();
            assert!(first.is_some(), "no problem found in {schema}");
        }
    }
}
