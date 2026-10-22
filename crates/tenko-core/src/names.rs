//! Namespaced names and request keys.
//!
//! Store tables, counters, error codes, audit actions, SSE topics, step and job kinds and UI
//! message keys are namespaced by owning area, and only the owner adds names in its
//! namespace, so parallel work packages cannot collide (plan section 2.1).
//!
//! A namespaced name is lowercase ASCII (`a-z`, `0-9`, `_`, `-`) in dot-separated segments,
//! at most 128 bytes, and its first segment is one of [`NAMESPACES`]: `ipam.prefixes`,
//! `auth.login.password`, `sys.journal`.

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    codec::key::{KeyCodec, encode_key},
    error::InvalidValue,
};

/// The namespaces and their owners.
///
/// | Namespace | Owner |
/// |---|---|
/// | `auth` | authentication, users, sessions, settings (WP1.2) |
/// | `backup` | backups: settings, schedule and history (WP3.4b) |
/// | `cluster` | enrolment, mTLS, internal CA (WP1.3, WP2.2); controller membership (WP3.1a) |
/// | `connect` | connectors (WP2.5, WP2.6) |
/// | `dhcp` | the DHCP module: scopes, pools, options, classes, policies, filters, leases (Phase 3, WP7.0) |
/// | `dns` | the DNS module: zones, records, views, forwarders, keys, lists (Phase 2, WP4.0) |
/// | `i18n` | language packs held in the store (WP3.7) |
/// | `import` | import and export (WP1.5) |
/// | `ipam` | the IPAM domain (WP1.4) |
/// | `jobs` | the job engine (WP1.6) |
/// | `scan` | discovery probes (WP2.3) |
/// | `sys` | store, API platform and shared codes (WP1.0, WP1.1, WP1.7) |
/// | `vault` | the vault (WP1.3) |
// WP7.0: `dhcp` added for Phase 3.
pub const NAMESPACES: [&str; 13] = [
    "auth", "backup", "cluster", "connect", "dhcp", "dns", "i18n", "import", "ipam", "jobs",
    "scan", "sys", "vault",
];

/// Maximum length of a namespaced name in bytes.
pub const MAX_NAME_LEN: usize = 128;

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Checks the namespaced-name rules. Usable in constant expressions.
pub const fn is_valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
        return false;
    }
    // Characters, and no empty segment.
    let mut first_dot = 0;
    let mut i = 0;
    let mut previous_dot = true;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            if previous_dot {
                return false;
            }
            if first_dot == 0 {
                first_dot = i;
            }
            previous_dot = true;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' {
            previous_dot = false;
        } else {
            return false;
        }
        i += 1;
    }
    if previous_dot || first_dot == 0 {
        return false;
    }
    // Known namespace.
    let (namespace, _) = bytes.split_at(first_dot);
    let mut n = 0;
    while n < NAMESPACES.len() {
        if bytes_eq(namespace, NAMESPACES[n].as_bytes()) {
            return true;
        }
        n += 1;
    }
    false
}

/// Defines a namespaced name type: a validated `Cow<'static, str>` newtype with a
/// `const fn from_static` (which fails compilation in a `const` item when the name is
/// invalid), a fallible `new`, `Display`, serde as a string and an OpenAPI string schema.
#[macro_export]
macro_rules! namespaced_name {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(::std::borrow::Cow<'static, str>);

        impl $name {
            /// Creates the name from a literal.
            ///
            /// # Panics
            ///
            /// Panics if the name breaks the namespaced-name rules; in a `const` item this is
            /// a compile-time error.
            pub const fn from_static(name: &'static str) -> Self {
                assert!(
                    $crate::names::is_valid_name(name),
                    concat!("invalid ", $what)
                );
                Self(::std::borrow::Cow::Borrowed(name))
            }

            /// Creates the name from runtime input.
            ///
            /// # Errors
            ///
            /// Returns `tenko_core::error::InvalidValue` if the name breaks the
            /// namespaced-name rules.
            pub fn new(
                name: impl ::core::convert::Into<::std::borrow::Cow<'static, str>>,
            ) -> ::core::result::Result<Self, $crate::error::InvalidValue> {
                let name = name.into();
                if $crate::names::is_valid_name(&name) {
                    Ok(Self(name))
                } else {
                    Err($crate::error::InvalidValue::new(
                        $what,
                        &name,
                        "not a namespaced name (lowercase segments, known namespace)",
                    ))
                }
            }

            /// The name as a string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The owning namespace (the first segment).
            pub fn namespace(&self) -> &str {
                self.0.split('.').next().unwrap_or_default()
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.as_str())
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::core::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::error::InvalidValue;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::new(s.to_owned())
            }
        }

        impl $crate::__private::serde::Serialize for $name {
            fn serialize<S: $crate::__private::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let text = <::std::string::String as $crate::__private::serde::Deserialize>
                    ::deserialize(deserializer)?;
                Self::new(text).map_err(<D::Error as $crate::__private::serde::de::Error>::custom)
            }
        }

        impl $crate::__private::utoipa::PartialSchema for $name {
            fn schema() -> $crate::__private::utoipa::openapi::RefOr<
                $crate::__private::utoipa::openapi::schema::Schema,
            > {
                $crate::serde_util::string_schema(concat!("Namespaced ", $what))
            }
        }

        impl $crate::__private::utoipa::ToSchema for $name {}

        impl $crate::codec::key::KeyCodec for $name {
            fn encode_key(&self, out: &mut ::std::vec::Vec<u8>) {
                $crate::codec::key::encode_str(self.as_str(), out);
            }
            fn decode_key(
                input: &mut &[u8],
            ) -> ::core::result::Result<Self, $crate::codec::key::KeyError> {
                let text = <::std::string::String as $crate::codec::key::KeyCodec>::decode_key(input)?;
                Self::new(text).map_err(|_| $crate::codec::key::KeyError::Invalid($what))
            }
        }
    };
}

namespaced_name! {
    /// Name of a store table, such as `ipam.prefixes` or `sys.journal`.
    ///
    /// Tables whose last segment is `secrets` or ends in `_secrets` are secret-bearing: the
    /// store accepts only vault envelopes as their values (NEVER-01), see
    /// [`TableName::is_secret_bearing`] and [`crate::secret::VaultEnvelope`].
    TableName, "table name"
}

impl TableName {
    /// Whether values of this table must be vault envelopes.
    pub fn is_secret_bearing(&self) -> bool {
        let last = self.as_str().rsplit('.').next().unwrap_or_default();
        last == "secrets" || last.ends_with("_secrets")
    }
}

namespaced_name! {
    /// Key of a translatable UI message, such as `ipam.move.reconfigure_device`. Job titles,
    /// manual task instructions and step previews carry message keys, never English text.
    MessageKey, "message key"
}

/// Name of a store counter plus an optional binary qualifier.
///
/// Counters are bumped by `Mutation::Bump` and checked by `Precondition::Counter`; they
/// order concurrent writers without locking whole tables (for example the per-VRF prefix
/// tree version is `CounterKey::with("ipam.tree", &vrf_id)`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CounterKey {
    name: TableName,
    #[serde(default)]
    qualifier: Bytes,
}

impl CounterKey {
    /// A counter without qualifier.
    ///
    /// # Panics
    ///
    /// Panics (at compile time in a `const` item) if `name` is not a namespaced name.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name: TableName::from_static(name),
            qualifier: Bytes::new(),
        }
    }

    /// A counter qualified by a key, for example a VRF identifier.
    ///
    /// # Panics
    ///
    /// Panics if `name` is not a namespaced name.
    pub fn with<K: KeyCodec>(name: &'static str, qualifier: &K) -> Self {
        Self {
            name: TableName::from_static(name),
            qualifier: encode_key(qualifier),
        }
    }

    /// The counter name.
    pub fn name(&self) -> &TableName {
        &self.name
    }

    /// The encoded qualifier (empty for an unqualified counter).
    pub fn qualifier(&self) -> &Bytes {
        &self.qualifier
    }
}

impl fmt::Display for CounterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.qualifier.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(
                f,
                "{}[{}]",
                self.name,
                crate::serde_util::to_hex(&self.qualifier)
            )
        }
    }
}

/// Keys of the store's counter table: the name, then the qualifier bytes.
impl KeyCodec for CounterKey {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.name.encode_key(out);
        self.qualifier.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, crate::codec::key::KeyError> {
        Ok(Self {
            name: TableName::decode_key(input)?,
            qualifier: Bytes::decode_key(input)?,
        })
    }
}

/// A client-chosen idempotency key (`Idempotency-Key` header, API-04): 1 to 255 visible
/// ASCII characters.
///
/// The store scopes keys per principal subject (see `Principal::subject`), so two users
/// cannot collide on the same key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type = String)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Maximum length in bytes.
    pub const MAX_LEN: usize = 255;

    /// Validates a key.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the key is empty, too long or contains characters
    /// outside visible ASCII.
    pub fn new(key: impl Into<String>) -> Result<Self, InvalidValue> {
        let key = key.into();
        if key.is_empty() || key.len() > Self::MAX_LEN {
            return Err(InvalidValue::new(
                "idempotency key",
                &key,
                "length must be 1 to 255",
            ));
        }
        if !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(InvalidValue::new(
                "idempotency key",
                &key,
                "only visible ASCII characters are allowed",
            ));
        }
        Ok(Self(key))
    }

    /// The key as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<IdempotencyKey> for String {
    fn from(key: IdempotencyKey) -> Self {
        key.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdempotencyKey({:?})", self.0)
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl KeyCodec for IdempotencyKey {
    fn encode_key(&self, out: &mut Vec<u8>) {
        crate::codec::key::encode_str(&self.0, out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, crate::codec::key::KeyError> {
        Self::new(String::decode_key(input)?)
            .map_err(|_| crate::codec::key::KeyError::Invalid("idempotency key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_key, encode_key, from_cbor, to_cbor};

    const PREFIXES: TableName = TableName::from_static("ipam.prefixes");

    #[test]
    fn valid_and_invalid_names() {
        for name in [
            "ipam.prefixes",
            "sys.journal",
            "auth.login.password",
            "jobs.step-1",
            "dns.zones",
            "dns.keys.meta",
            "dhcp.leases.by_client",
        ] {
            assert!(is_valid_name(name), "{name}");
        }
        for name in [
            "",
            "ipam",
            "ipam.",
            ".ipam",
            "ipam..x",
            "IPAM.x",
            "dnsx.zones",
            "ipam.a b",
            "ipam.ä",
        ] {
            assert!(!is_valid_name(name), "{name}");
        }
        assert!(!is_valid_name(&format!("sys.{}", "x".repeat(MAX_NAME_LEN))));
    }

    #[test]
    fn names_round_trip_and_report_namespace() {
        assert_eq!(PREFIXES.namespace(), "ipam");
        assert_eq!(PREFIXES.to_string(), "ipam.prefixes");
        let json = serde_json::to_string(&PREFIXES).expect("json");
        assert_eq!(json, "\"ipam.prefixes\"");
        assert_eq!(
            serde_json::from_str::<TableName>(&json).expect("json"),
            PREFIXES
        );
        assert!(serde_json::from_str::<TableName>("\"nope\"").is_err());
        assert_eq!(
            decode_key::<TableName>(&encode_key(&PREFIXES)),
            Ok(PREFIXES)
        );
        assert!(TableName::new("ipam.prefixes".to_owned()).is_ok());
        assert!("bad".parse::<MessageKey>().is_err());
    }

    #[test]
    fn secret_bearing_tables_follow_the_naming_rule() {
        assert!(TableName::from_static("vault.secrets").is_secret_bearing());
        assert!(TableName::from_static("auth.totp_secrets").is_secret_bearing());
        assert!(!TableName::from_static("auth.users").is_secret_bearing());
        assert!(!TableName::from_static("vault.secrets.meta").is_secret_bearing());
    }

    #[test]
    fn counter_keys_encode_name_and_qualifier() {
        let plain = CounterKey::new("ipam.tree");
        let qualified = CounterKey::with("ipam.tree", &7_u64);
        assert!(encode_key(&plain) < encode_key(&qualified));
        assert_eq!(
            decode_key::<CounterKey>(&encode_key(&qualified)),
            Ok(qualified.clone())
        );
        let back: CounterKey = from_cbor(&to_cbor(&qualified).expect("cbor")).expect("cbor");
        assert_eq!(back, qualified);
        assert_eq!(plain.to_string(), "ipam.tree");
    }

    #[test]
    fn idempotency_keys_are_visible_ascii() {
        assert!(IdempotencyKey::new("a1b2-c3").is_ok());
        assert!(IdempotencyKey::new("").is_err());
        assert!(IdempotencyKey::new("has space").is_err());
        assert!(IdempotencyKey::new("x".repeat(256)).is_err());
        assert!(serde_json::from_str::<IdempotencyKey>("\"\"").is_err());
    }
}
