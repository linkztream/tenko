//! List helpers shared by every area: pagination, opaque cursors, filters and sorting
//! (plan section 4, "Lists").
//!
//! A list endpoint takes `limit` (1 to [`MAX_LIMIT`], default [`DEFAULT_LIMIT`]), an opaque
//! `cursor` and `at_least=<revision>` for read-your-writes, plus its own filters
//! (`status=`, `vrf=`, `tag=`, `within=192.0.2.0/24`, `q=`) and `sort=-updated,name`. It
//! answers with a [`Page`](crate::dto::Page): `{ items, next_cursor, revision }`.
//!
//! The typical handler:
//!
//! ```ignore
//! async fn list_prefixes(State(state): State<AppState>, ctx: Ctx, filters: Filters)
//!     -> Result<Json<Page<Prefix>>, ApiError>
//! {
//!     filters.only(&["status", "vrf", "tag", "within", "q", "sort"])?;
//!     let page = filters.page()?;
//!     let scope = filters.scope("ipam.prefixes");
//!     let after: Option<Bytes> = page.key_cursor(scope)?;
//!     let sort = filters.sort(&["cidr", "updated"], &[SortKey::asc("cidr")])?;
//!     let view = page.read(state.store()).await?;
//!     // ... scan from `after`, filter, take `page.limit()? + 1` ...
//!     let next = more.then(|| encode_key_cursor(scope, &last_key));
//!     Ok(Json(Page::new(items, next, view.revision())))
//! }
//! ```
//!
//! Cursors are bound to the endpoint and to every query parameter except `limit`, `cursor`
//! and `at_least` ([`Filters::scope`]): a cursor replayed with other filters is refused with
//! 400 `sys.invalid_cursor` instead of silently skipping rows.

use std::{fmt::Display, str::FromStr, sync::Arc};

use axum::{
    extract::{FromRequestParts, Query},
    http::{Uri, request::Parts},
};
use bytes::Bytes;
use ipnet::IpNet;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{Revision, Timestamp};
use tenko_store::{ReadConsistency, ReadView, Store};
use utoipa::IntoParams;

use crate::problem::{ApiError, codes};

/// Page size when `limit` is absent.
pub const DEFAULT_LIMIT: usize = 100;

/// Largest accepted `limit`.
pub const MAX_LIMIT: usize = 1_000;

/// Query parameters every list takes, for `#[utoipa::path(params(PageParams, ...))]` and
/// for `Query<PageParams>` when a handler has no other filters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// Page size, 1 to 1,000 (default 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Opaque cursor from the previous page's `next_cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Read at least this store revision (read-your-writes after a write).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_least: Option<u64>,
}

impl PageParams {
    /// The page size.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when `limit` is 0 or above [`MAX_LIMIT`].
    pub fn limit(&self) -> Result<usize, ApiError> {
        match self.limit {
            None => Ok(DEFAULT_LIMIT),
            Some(0) => Err(ApiError::invalid_query("limit", "must be at least 1")),
            Some(limit) => {
                let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                if limit > MAX_LIMIT {
                    Err(ApiError::invalid_query(
                        "limit",
                        format!("must be at most {MAX_LIMIT}"),
                    ))
                } else {
                    Ok(limit)
                }
            }
        }
    }

    /// The read consistency the request asks for: `AtLeast(at_least)` or `Local`.
    pub fn consistency(&self) -> ReadConsistency {
        match self.at_least {
            Some(revision) => ReadConsistency::AtLeast(Revision(revision)),
            None => ReadConsistency::Local,
        }
    }

    /// Opens a read view with [`PageParams::consistency`].
    ///
    /// # Errors
    ///
    /// The store's error as problem details (503 on timeout or shutdown).
    pub async fn read(&self, store: &dyn Store) -> Result<Arc<dyn ReadView>, ApiError> {
        Ok(store.read(self.consistency()).await?)
    }

    /// Decodes the cursor into the position type the endpoint encoded with
    /// [`encode_cursor`].
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_cursor` when the cursor is malformed or from another scope.
    pub fn cursor<T: DeserializeOwned>(&self, scope: CursorScope) -> Result<Option<T>, ApiError> {
        self.cursor
            .as_deref()
            .map(|cursor| decode_cursor(scope, cursor))
            .transpose()
    }

    /// Decodes a cursor made by [`encode_key_cursor`]: the last store key of the previous
    /// page, for `KeyRange::after` (or `before` when scanning in reverse).
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_cursor` when the cursor is malformed or from another scope.
    pub fn key_cursor(&self, scope: CursorScope) -> Result<Option<Bytes>, ApiError> {
        let Some(hex) = self.cursor::<String>(scope)? else {
            return Ok(None);
        };
        from_hex(&hex)
            .map(|key| Some(Bytes::from(key)))
            .ok_or_else(invalid_cursor)
    }
}

/// What a cursor is bound to: the endpoint and its filters. Built with
/// [`CursorScope::new`] and [`CursorScope::with`], or by [`Filters::scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CursorScope(u64);

impl CursorScope {
    /// The scope of an endpoint, named by any stable string such as `ipam.prefixes`.
    pub fn new(endpoint: &str) -> Self {
        Self(fnv1a(FNV_OFFSET, endpoint.as_bytes()))
    }

    /// Mixes one more part (a filter value, a sort order) into the scope.
    #[must_use]
    pub fn with(self, part: &str) -> Self {
        let mixed = fnv1a(self.0, &[0xFF]);
        Self(fnv1a(mixed, part.as_bytes()))
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// FNV-1a: stable across releases and platforms, unlike the standard library's hasher.
fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The JSON inside a cursor, before base64url.
#[derive(Serialize, Deserialize)]
struct CursorBody<T> {
    /// Format version.
    v: u8,
    /// The scope, as 16 hexadecimal digits.
    s: String,
    /// The endpoint's position.
    p: T,
}

/// Encodes an opaque cursor that carries `position` and is valid only for `scope`.
pub fn encode_cursor<T: Serialize>(scope: CursorScope, position: &T) -> String {
    let body = CursorBody {
        v: 1,
        s: format!("{:016x}", scope.0),
        p: position,
    };
    // Serializing plain data into a vector cannot fail; an empty cursor would be refused
    // on the next request, which is the safe outcome should it ever happen.
    let json = serde_json::to_vec(&body).unwrap_or_default();
    base64url_encode(&json)
}

/// Encodes a cursor holding a raw store key (see [`PageParams::key_cursor`]).
pub fn encode_key_cursor(scope: CursorScope, key: &[u8]) -> String {
    encode_cursor(scope, &to_hex(key))
}

/// Decodes a cursor made by [`encode_cursor`] for the same scope.
///
/// # Errors
///
/// 400 `sys.invalid_cursor` when the cursor is malformed or from another scope.
pub fn decode_cursor<T: DeserializeOwned>(scope: CursorScope, cursor: &str) -> Result<T, ApiError> {
    let json = base64url_decode(cursor).ok_or_else(invalid_cursor)?;
    let body: CursorBody<T> = serde_json::from_slice(&json).map_err(|_| invalid_cursor())?;
    if body.v != 1 || body.s != format!("{:016x}", scope.0) {
        return Err(invalid_cursor());
    }
    Ok(body.p)
}

fn invalid_cursor() -> ApiError {
    ApiError::new(
        codes::INVALID_CURSOR,
        400,
        "the cursor is malformed or belongs to another query; start again without a cursor",
    )
}

/// One sort key of `sort=-updated,name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SortKey {
    /// The field, one of the endpoint's allowed names.
    pub field: &'static str,
    /// Descending (`-field`) or ascending.
    pub descending: bool,
}

impl SortKey {
    /// Ascending by `field`.
    pub const fn asc(field: &'static str) -> Self {
        Self {
            field,
            descending: false,
        }
    }

    /// Descending by `field`.
    pub const fn desc(field: &'static str) -> Self {
        Self {
            field,
            descending: true,
        }
    }
}

/// The query string of a request as name and value pairs, with typed accessors that
/// answer 400 `sys.invalid_query` naming the parameter.
///
/// Use it as an extractor (`filters: Filters`) or build it with [`Filters::from_uri`].
/// Repeated parameters are kept (`tag=a&tag=b`), so [`Filters::all`] sees each of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    pairs: Vec<(String, String)>,
}

/// Parameters that steer paging and never take part in the cursor scope.
const PAGING: [&str; 3] = ["limit", "cursor", "at_least"];

impl Filters {
    /// Parses the query string of a URI.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when the query string is not valid URL encoding.
    pub fn from_uri(uri: &Uri) -> Result<Self, ApiError> {
        let Query(pairs) = Query::<Vec<(String, String)>>::try_from_uri(uri)
            .map_err(|error| ApiError::invalid_query("(query string)", error.body_text()))?;
        Ok(Self { pairs })
    }

    /// Builds the filters from pairs (tests and the client).
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            pairs: pairs
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }

    /// Every pair, in request order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Refuses parameters other than `known` and the paging parameters.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` naming the first unknown parameter.
    pub fn only(&self, known: &[&str]) -> Result<(), ApiError> {
        match self
            .pairs
            .iter()
            .find(|(name, _)| !known.contains(&name.as_str()) && !PAGING.contains(&name.as_str()))
        {
            Some((name, _)) => Err(ApiError::invalid_query(name, "unknown parameter")),
            None => Ok(()),
        }
    }

    /// The single value of a parameter; blank values count as absent.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when the parameter is given more than once.
    pub fn get(&self, name: &str) -> Result<Option<&str>, ApiError> {
        let mut values = self
            .pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str());
        let first = values.next();
        if values.next().is_some() {
            return Err(ApiError::invalid_query(name, "given more than once"));
        }
        Ok(first.map(str::trim).filter(|value| !value.is_empty()))
    }

    /// Every value of a parameter: repeated parameters and comma-separated lists both
    /// count (`tag=a&tag=b,c` is `a`, `b`, `c`); blanks are dropped.
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .flat_map(|(_, value)| value.split(','))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect()
    }

    /// Parses the single value of a parameter with [`FromStr`].
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when the value is repeated or does not parse.
    pub fn parse<T>(&self, name: &str) -> Result<Option<T>, ApiError>
    where
        T: FromStr,
        T::Err: Display,
    {
        self.get(name)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|error: T::Err| ApiError::invalid_query(name, error.to_string()))
            })
            .transpose()
    }

    /// Parses every value of a parameter (see [`Filters::all`]).
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when a value does not parse.
    pub fn parse_all<T>(&self, name: &str) -> Result<Vec<T>, ApiError>
    where
        T: FromStr,
        T::Err: Display,
    {
        self.all(name)
            .into_iter()
            .map(|value| {
                value
                    .parse()
                    .map_err(|error: T::Err| ApiError::invalid_query(name, error.to_string()))
            })
            .collect()
    }

    /// A network such as `within=192.0.2.0/24`; a bare address is a host network
    /// (`/32` or `/128`). Host bits must be zero.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when the value is not a network or has host bits set.
    pub fn cidr(&self, name: &str) -> Result<Option<IpNet>, ApiError> {
        let Some(value) = self.get(name)? else {
            return Ok(None);
        };
        let net = match value.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => value
                .parse::<std::net::IpAddr>()
                .map(IpNet::from)
                .map_err(|_| {
                    ApiError::invalid_query(name, "expected a network such as 192.0.2.0/24")
                })?,
        };
        if net.trunc() != net {
            return Err(ApiError::invalid_query(
                name,
                format!("host bits are set; did you mean {}?", net.trunc()),
            ));
        }
        Ok(Some(net))
    }

    /// A boolean: `true`, `false`, `1`, `0`, `yes`, `no`.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` on any other value.
    pub fn boolean(&self, name: &str) -> Result<Option<bool>, ApiError> {
        self.get(name)?
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" => Ok(false),
                _ => Err(ApiError::invalid_query(name, "expected true or false")),
            })
            .transpose()
    }

    /// An RFC 3339 time such as `2026-10-09T12:00:00Z`.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` when the value is not RFC 3339.
    pub fn timestamp(&self, name: &str) -> Result<Option<Timestamp>, ApiError> {
        self.parse(name)
    }

    /// The sort keys of `sort=-updated,name`, each one of `allowed`; `default` when the
    /// parameter is absent. A field may appear once.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` naming `sort` for an unknown or repeated field.
    pub fn sort(
        &self,
        allowed: &[&'static str],
        default: &[SortKey],
    ) -> Result<Vec<SortKey>, ApiError> {
        let names = self.all("sort");
        if names.is_empty() {
            return Ok(default.to_vec());
        }
        let mut keys: Vec<SortKey> = Vec::with_capacity(names.len());
        for name in names {
            let (descending, field) = match name.strip_prefix('-') {
                Some(field) => (true, field),
                None => (false, name.strip_prefix('+').unwrap_or(name)),
            };
            let Some(field) = allowed.iter().copied().find(|allowed| *allowed == field) else {
                return Err(ApiError::invalid_query(
                    "sort",
                    format!("unknown field `{field}`; allowed: {}", allowed.join(", ")),
                ));
            };
            if keys.iter().any(|key| key.field == field) {
                return Err(ApiError::invalid_query(
                    "sort",
                    format!("field `{field}` given twice"),
                ));
            }
            keys.push(SortKey { field, descending });
        }
        Ok(keys)
    }

    /// The paging parameters.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` for a repeated or malformed `limit`, `cursor` or `at_least`.
    pub fn page(&self) -> Result<PageParams, ApiError> {
        let page = PageParams {
            limit: self.parse("limit")?,
            cursor: self.get("cursor")?.map(str::to_owned),
            at_least: self.parse("at_least")?,
        };
        page.limit()?;
        Ok(page)
    }

    /// The cursor scope of `endpoint` with every parameter except `limit`, `cursor` and
    /// `at_least`, independent of their order.
    pub fn scope(&self, endpoint: &str) -> CursorScope {
        let mut parts: Vec<String> = self
            .pairs
            .iter()
            .filter(|(name, _)| !PAGING.contains(&name.as_str()))
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        parts.sort_unstable();
        parts
            .iter()
            .fold(CursorScope::new(endpoint), |scope, part| scope.with(part))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Filters {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::from_uri(&parts.uri))
    }
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 section 5).
pub(crate) fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            let index = (n >> (18 - 6 * i)) & 0x3F;
            out.push(char::from(BASE64URL[index as usize]));
        }
    }
    out
}

/// Decodes base64url without padding; `None` on any invalid input.
pub(crate) fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.as_bytes().chunks(4) {
        let mut n: u32 = 0;
        for (i, symbol) in chunk.iter().enumerate() {
            let value = BASE64URL.iter().position(|c| c == symbol)?;
            n |= u32::try_from(value).ok()? << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(query: &str) -> Filters {
        Filters::from_uri(&format!("/x?{query}").parse().expect("uri")).expect("filters")
    }

    fn code(error: &ApiError) -> &str {
        &error.coded_error().code
    }

    #[test]
    fn limits() {
        assert_eq!(
            PageParams::default().limit().expect("default"),
            DEFAULT_LIMIT
        );
        let page = |limit| PageParams {
            limit: Some(limit),
            ..PageParams::default()
        };
        assert_eq!(page(1).limit().expect("one"), 1);
        assert_eq!(page(1_000).limit().expect("max"), 1_000);
        assert_eq!(
            code(&page(0).limit().expect_err("zero")),
            codes::INVALID_QUERY
        );
        assert_eq!(
            code(&page(1_001).limit().expect_err("too big")),
            codes::INVALID_QUERY
        );
        assert_eq!(PageParams::default().consistency(), ReadConsistency::Local);
        let at_least = PageParams {
            at_least: Some(9),
            ..PageParams::default()
        };
        assert_eq!(
            at_least.consistency(),
            ReadConsistency::AtLeast(Revision(9))
        );
    }

    #[test]
    fn cursors_round_trip_and_are_bound_to_their_scope() {
        let scope = CursorScope::new("ipam.prefixes").with("vrf=1");
        let cursor = encode_cursor(scope, &("192.0.2.0/24", 7_u32));
        assert!(
            cursor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let back: (String, u32) = decode_cursor(scope, &cursor).expect("decode");
        assert_eq!(back, ("192.0.2.0/24".to_owned(), 7));

        let other = CursorScope::new("ipam.prefixes").with("vrf=2");
        let error = decode_cursor::<(String, u32)>(other, &cursor).expect_err("other scope");
        assert_eq!(code(&error), codes::INVALID_CURSOR);
        for garbage in ["", "!!!", "abc", "eyJ2IjoyfQ"] {
            assert!(decode_cursor::<u32>(scope, garbage).is_err(), "{garbage}");
        }

        let key_cursor = encode_key_cursor(scope, &[0, 1, 0xFE]);
        let page = PageParams {
            cursor: Some(key_cursor),
            ..PageParams::default()
        };
        assert_eq!(
            page.key_cursor(scope).expect("key"),
            Some(Bytes::from_static(&[0, 1, 0xFE]))
        );
        assert_eq!(PageParams::default().key_cursor(scope).expect("none"), None);
    }

    #[test]
    fn base64url_matches_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
            assert_eq!(base64url_decode(encoded).expect("decode"), plain.as_bytes());
        }
        assert_eq!(base64url_encode(&[0xFB, 0xFF]), "-_8");
        assert_eq!(base64url_decode("-_8").expect("decode"), vec![0xFB, 0xFF]);
        assert!(base64url_decode("Z").is_none());
        assert!(base64url_decode("Zm9v+A").is_none());
    }

    #[test]
    fn scopes_ignore_paging_and_order() {
        let a = filters("vrf=1&status=active&limit=5&cursor=x");
        let b = filters("status=active&vrf=1&at_least=3");
        assert_eq!(a.scope("e"), b.scope("e"));
        assert_ne!(a.scope("e"), a.scope("f"));
        assert_ne!(a.scope("e"), filters("vrf=2&status=active").scope("e"));
    }

    #[test]
    fn typed_accessors() {
        let f = filters(
            "q=%20host%20&tag=a&tag=b,c&within=192.0.2.0/24&ip=192.0.2.7&flag=yes&from=2026-10-09T12:00:00Z&n=5",
        );
        assert_eq!(f.get("q").expect("q"), Some("host"));
        assert_eq!(f.get("missing").expect("missing"), None);
        assert_eq!(f.all("tag"), vec!["a", "b", "c"]);
        assert_eq!(
            f.cidr("within").expect("cidr"),
            Some("192.0.2.0/24".parse().expect("net"))
        );
        assert_eq!(
            f.cidr("ip").expect("host"),
            Some("192.0.2.7/32".parse().expect("net"))
        );
        assert_eq!(f.boolean("flag").expect("bool"), Some(true));
        assert!(f.timestamp("from").expect("time").is_some());
        assert_eq!(f.parse::<u8>("n").expect("n"), Some(5));
        assert_eq!(
            f.parse_all::<char>("tag").expect("chars"),
            vec!['a', 'b', 'c']
        );

        let bad = filters("tag=a&tag=b&within=192.0.2.1/24&n=x&flag=maybe&from=yesterday");
        assert_eq!(
            code(&bad.get("tag").expect_err("repeated")),
            codes::INVALID_QUERY
        );
        let error = bad.cidr("within").expect_err("host bits");
        assert_eq!(error.coded_error().params["parameter"], "within");
        assert!(bad.parse::<u8>("n").is_err());
        assert!(bad.boolean("flag").is_err());
        assert!(bad.timestamp("from").is_err());
        assert!(filters("within=nope").cidr("within").is_err());
    }

    #[test]
    fn unknown_parameters_and_paging() {
        let f = filters("status=active&limit=10&cursor=abc&at_least=4");
        f.only(&["status"]).expect("known");
        let error = f.only(&["vrf"]).expect_err("unknown");
        assert_eq!(error.coded_error().params["parameter"], "status");
        let page = f.page().expect("page");
        assert_eq!(page.limit, Some(10));
        assert_eq!(page.cursor.as_deref(), Some("abc"));
        assert_eq!(page.at_least, Some(4));
        assert!(filters("limit=0").page().is_err());
        assert!(filters("limit=5000").page().is_err());
        assert!(filters("limit=a").page().is_err());
    }

    #[test]
    fn sorting() {
        let allowed = ["cidr", "updated", "name"];
        let default = [SortKey::asc("cidr")];
        assert_eq!(
            filters("").sort(&allowed, &default).expect("default"),
            default
        );
        assert_eq!(
            filters("sort=-updated,name")
                .sort(&allowed, &default)
                .expect("sort"),
            vec![SortKey::desc("updated"), SortKey::asc("name")]
        );
        assert_eq!(
            filters("sort=%2Bname")
                .sort(&allowed, &default)
                .expect("plus"),
            vec![SortKey::asc("name")]
        );
        assert!(filters("sort=size").sort(&allowed, &default).is_err());
        assert!(filters("sort=name,-name").sort(&allowed, &default).is_err());
    }

    #[test]
    fn percent_encoding_is_decoded() {
        let f = filters("q=a%20b&name=caf%C3%A9&plus=a+b");
        assert_eq!(f.get("q").expect("q"), Some("a b"));
        assert_eq!(f.get("name").expect("name"), Some("caf\u{e9}"));
        assert_eq!(f.get("plus").expect("plus"), Some("a b"));
    }
}
