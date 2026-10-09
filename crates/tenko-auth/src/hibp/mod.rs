//! Breached-password check (IAM-04, TGL-06).
//!
//! A password is looked up by its SHA-1, as the corpus of the Have I Been Pwned "Pwned
//! Passwords" list is keyed by SHA-1. Two sources answer the question:
//!
//! - **Online**: the range API of that service. Only the first five hexadecimal characters of
//!   the digest leave the process (k-anonymity); the service answers with every known suffix
//!   under that prefix and the comparison happens here. With the crate feature `online`,
//!   `HttpRangeSource` speaks to the public API over HTTPS; without it the caller supplies a
//!   [`HibpRangeSource`] of their own (a mirror, a proxy, a test double).
//! - **Offline**: a [`HibpFilter`] built from the downloadable corpus, no network involved.
//!   See [`filter`] for the file format and [`build_filter`] for the builder.
//!
//! The setting [`BreachMode`] (TGL-06) chooses between them and [`BreachChecker`] applies it.
//! The checker never fails open silently: when no source can answer it reports
//! [`BreachOutcome::Unavailable`] and the caller decides what that means for the policy.
//!
//! The functions here take the *normalized* password (the same string that is hashed with
//! Argon2id), never log it, and keep neither it nor its digest beyond the call.

pub mod filter;
#[cfg(feature = "online")]
pub mod online;

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::encoding::hex_encode;

pub use filter::{BuildOptions, BuildSummary, FilterError, HibpFilter, build_filter};
#[cfg(feature = "online")]
pub use online::HttpRangeSource;

/// Length of the hash prefix sent to a range source.
const PREFIX_LEN: usize = 5;
/// Length of the hash suffix compared locally (40 hexadecimal characters minus the prefix).
const SUFFIX_LEN: usize = 40 - PREFIX_LEN;

/// Where the breached-password check looks (TGL-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreachMode {
    /// No check.
    Off,
    /// The range API; falls back to the offline filter if it cannot be reached.
    Online,
    /// The offline filter only; nothing leaves the installation.
    Offline,
    /// The offline filter when one is configured, otherwise the range API.
    OfflinePreferred,
}

impl BreachMode {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::OfflinePreferred => "offline_preferred",
        }
    }
}

/// The SHA-1 of the normalized password as 40 uppercase hexadecimal characters, the form of
/// the Pwned Passwords corpus.
pub fn sha1_hex_upper(normalized_password: &str) -> String {
    hex_encode(&sha1(normalized_password)).to_ascii_uppercase()
}

/// The SHA-1 of the normalized password. SHA-1 is used only because the corpus is keyed by
/// it; it protects nothing here.
pub fn sha1(normalized_password: &str) -> [u8; 20] {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        normalized_password.as_bytes(),
    );
    <[u8; 20]>::try_from(digest.as_ref()).unwrap_or_default()
}

/// Why a range source gave no usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HibpError {
    /// The source could not be asked or did not answer. The message is for the log and never
    /// contains the password or its full hash.
    #[error("range source unavailable: {0}")]
    Unavailable(String),
    /// The answer is not in the format of the range API.
    #[error("malformed range response")]
    Malformed,
}

/// A source of range answers: the body of `GET /range/{prefix}` of the Pwned Passwords API.
///
/// An implementation receives only the 5-character prefix and must not log more than that.
/// Implementations are expected to enforce their own timeout.
#[async_trait]
pub trait HibpRangeSource: Send + Sync {
    /// Fetches the range for `prefix` (five uppercase hexadecimal characters). The body has
    /// one `SUFFIX:COUNT` entry per line, as returned by the API.
    ///
    /// # Errors
    ///
    /// [`HibpError::Unavailable`] if the source cannot be reached or answers with an error.
    async fn range(&self, prefix: &str) -> Result<String, HibpError>;
}

/// Splits one `SUFFIX:COUNT` entry; `None` if it is not 35 hexadecimal characters, a colon
/// and a decimal count that fits `u64`.
fn parse_entry(line: &str) -> Option<(&str, u64)> {
    let (suffix, count) = line.split_once(':')?;
    if suffix.len() != SUFFIX_LEN || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((suffix, count.parse().ok()?))
}

/// Looks `suffix` up in the body of a range response.
///
/// Every non-blank line must be `SUFFIX:COUNT` (35 hexadecimal characters, a colon, a decimal
/// count) with LF or CRLF line endings; surrounding white space and blank lines are ignored.
/// The whole body is validated, not just the part up to a match, so a truncated or garbled
/// response is refused instead of being trusted. The match is case-insensitive. An entry with
/// count 0 is padding (the API adds such entries when asked with `Add-Padding: true`) and
/// counts as not found.
///
/// Returns the breach count, or `None` if the suffix is absent or only present as padding.
///
/// # Errors
///
/// [`HibpError::Malformed`] if a line is malformed or if `suffix` is not 35 hexadecimal
/// characters.
pub fn parse_range(body: &str, suffix: &str) -> Result<Option<u64>, HibpError> {
    if suffix.len() != SUFFIX_LEN || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HibpError::Malformed);
    }
    let mut found = None;
    for raw in body.split('\n') {
        let line = raw.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let (entry, count) = parse_entry(line).ok_or(HibpError::Malformed)?;
        if found.is_none() && count > 0 && entry.eq_ignore_ascii_case(suffix) {
            found = Some(count);
        }
    }
    Ok(found)
}

/// The result of a breached-password check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachOutcome {
    /// The password is not in the corpus (or the mode is [`BreachMode::Off`]).
    Clean,
    /// The password is in the corpus. `count` is the number of breaches the online source
    /// reported; the offline filter does not store counts.
    Breached {
        /// How often the password appeared, if the source said.
        count: Option<u64>,
    },
    /// No configured source could answer. Not a verdict on the password.
    Unavailable,
}

/// Applies a [`BreachMode`] to the configured sources.
///
/// | Mode | Behavior |
/// |---|---|
/// | `Off` | [`Clean`](BreachOutcome::Clean), nothing is hashed or sent |
/// | `Online` | the online source; if none is configured or it fails, the offline filter, else [`Unavailable`](BreachOutcome::Unavailable) |
/// | `Offline` | the offline filter, else [`Unavailable`](BreachOutcome::Unavailable) |
/// | `OfflinePreferred` | the offline filter when configured, else the online source, else [`Unavailable`](BreachOutcome::Unavailable) |
///
/// The online source only ever sees the 5-character hash prefix. A read error of the offline
/// filter yields [`Unavailable`](BreachOutcome::Unavailable) without trying another source.
/// Failures are logged at warn level without any password material.
#[derive(Clone)]
pub struct BreachChecker {
    mode: BreachMode,
    online: Option<Arc<dyn HibpRangeSource>>,
    offline: Option<Arc<HibpFilter>>,
}

impl std::fmt::Debug for BreachChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreachChecker")
            .field("mode", &self.mode)
            .field("online", &self.online.is_some())
            .field("offline", &self.offline.is_some())
            .finish()
    }
}

impl BreachChecker {
    /// Creates a checker for `mode` with the sources that are available.
    pub fn new(
        mode: BreachMode,
        online: Option<Arc<dyn HibpRangeSource>>,
        offline: Option<Arc<HibpFilter>>,
    ) -> Self {
        Self {
            mode,
            online,
            offline,
        }
    }

    /// The configured mode.
    pub fn mode(&self) -> BreachMode {
        self.mode
    }

    /// Checks a normalized password. See the type documentation for the order of sources.
    pub async fn check(&self, normalized_password: &str) -> BreachOutcome {
        match self.mode {
            BreachMode::Off => BreachOutcome::Clean,
            BreachMode::Offline => self.check_offline(normalized_password).await,
            BreachMode::Online => match self.try_online(normalized_password).await {
                Some(outcome) => outcome,
                None => self.check_offline(normalized_password).await,
            },
            BreachMode::OfflinePreferred => {
                if self.offline.is_some() {
                    self.check_offline(normalized_password).await
                } else {
                    self.try_online(normalized_password)
                        .await
                        .unwrap_or(BreachOutcome::Unavailable)
                }
            }
        }
    }

    /// The answer of the online source, or `None` (after a warning) if none is configured or
    /// it failed.
    async fn try_online(&self, normalized_password: &str) -> Option<BreachOutcome> {
        let Some(source) = &self.online else {
            tracing::warn!("no online breach source configured");
            return None;
        };
        match check_online(source.as_ref(), normalized_password).await {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                tracing::warn!(%error, "online breach check failed");
                None
            }
        }
    }

    async fn check_offline(&self, normalized_password: &str) -> BreachOutcome {
        let Some(filter) = &self.offline else {
            tracing::warn!("no offline breach filter configured");
            return BreachOutcome::Unavailable;
        };
        let digest = Zeroizing::new(sha1(normalized_password));
        let filter = Arc::clone(filter);
        let lookup = move || filter.contains_sha1(&digest);
        // A file-backed filter does blocking reads; keep them off the async workers when a
        // runtime is there to take them.
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(lookup)
                .await
                .unwrap_or_else(|_| Err(FilterError::Io("lookup task did not finish".to_owned()))),
            Err(_) => lookup(),
        };
        match result {
            Ok(true) => BreachOutcome::Breached { count: None },
            Ok(false) => BreachOutcome::Clean,
            Err(error) => {
                tracing::warn!(%error, "offline breach filter lookup failed");
                BreachOutcome::Unavailable
            }
        }
    }
}

/// Asks a range source about a password: only the prefix is sent, the suffix is compared here.
async fn check_online(
    source: &dyn HibpRangeSource,
    normalized_password: &str,
) -> Result<BreachOutcome, HibpError> {
    let digest = Zeroizing::new(sha1_hex_upper(normalized_password));
    let (prefix, suffix) = digest
        .split_at_checked(PREFIX_LEN)
        .ok_or(HibpError::Malformed)?;
    let body = source.range(prefix).await?;
    Ok(match parse_range(&body, suffix)? {
        Some(count) => BreachOutcome::Breached { count: Some(count) },
        None => BreachOutcome::Clean,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Digests of "password" and of the empty string (FIPS 180 test material).
    const PASSWORD_SHA1: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
    const EMPTY_SHA1: &str = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
    const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_matches_known_digests() {
        assert_eq!(sha1_hex_upper("password"), PASSWORD_SHA1);
        assert_eq!(sha1_hex_upper(""), EMPTY_SHA1);
        assert_eq!(
            hex_encode(&sha1("password")),
            PASSWORD_SHA1.to_ascii_lowercase()
        );
        let digest = sha1_hex_upper("any value at all");
        assert_eq!(digest.len(), 40);
        assert!(
            digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
        );
    }

    #[test]
    fn mode_names_match_serde() {
        for (mode, name) in [
            (BreachMode::Off, "off"),
            (BreachMode::Online, "online"),
            (BreachMode::Offline, "offline"),
            (BreachMode::OfflinePreferred, "offline_preferred"),
        ] {
            assert_eq!(mode.as_str(), name);
            let json = serde_json::to_string(&mode).expect("serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<BreachMode>(&json).expect("parse"),
                mode
            );
        }
    }

    #[test]
    fn range_hit_returns_the_count() {
        let body = format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{SUFFIX}:9545824\r\n\
                            011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n"
        );
        assert_eq!(parse_range(&body, SUFFIX), Ok(Some(9_545_824)));
    }

    #[test]
    fn range_miss_is_none() {
        let body =
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n";
        assert_eq!(parse_range(body, SUFFIX), Ok(None));
        assert_eq!(parse_range("", SUFFIX), Ok(None));
    }

    #[test]
    fn range_padding_entry_is_not_found() {
        let body = format!("{SUFFIX}:0\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n");
        assert_eq!(parse_range(&body, SUFFIX), Ok(None));
        // A real entry next to a padding entry of the same suffix still counts.
        let both = format!("{SUFFIX}:0\r\n{SUFFIX}:12\r\n");
        assert_eq!(parse_range(&both, SUFFIX), Ok(Some(12)));
    }

    #[test]
    fn range_match_ignores_case_and_line_ending_style() {
        let lower = SUFFIX.to_ascii_lowercase();
        let upper_body = format!("{SUFFIX}:7\n");
        let lower_body = format!("{lower}:7\r\n");
        assert_eq!(parse_range(&upper_body, &lower), Ok(Some(7)));
        assert_eq!(parse_range(&lower_body, SUFFIX), Ok(Some(7)));
        // No trailing newline, blank lines and stray white space.
        let loose = format!("\r\n\n  {SUFFIX}:7  \r\n\r\n");
        assert_eq!(parse_range(&loose, SUFFIX), Ok(Some(7)));
        assert_eq!(parse_range(&format!("{SUFFIX}:7"), SUFFIX), Ok(Some(7)));
    }

    #[test]
    fn range_refuses_malformed_input() {
        let good = "0018A45C4D1DEF81644B54AB7F969B88D65:1";
        for body in [
            "no colon at all".to_owned(),
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D6:1"), // 34 characters
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D655:1"), // 36 characters
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D6G:1"), // not hexadecimal
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D65:"),
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D65:x1"),
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D65:-1"),
            format!("{good}\r\n0018A45C4D1DEF81644B54AB7F969B88D65:99999999999999999999999"),
            format!("{SUFFIX}:5\r\ntruncated-last-li"),
        ] {
            assert_eq!(
                parse_range(&body, SUFFIX),
                Err(HibpError::Malformed),
                "{body:?}"
            );
        }
    }

    #[test]
    fn range_refuses_a_wrong_sized_suffix() {
        let body = format!("{SUFFIX}:5\r\n");
        assert_eq!(parse_range(&body, "1E4C9"), Err(HibpError::Malformed));
        assert_eq!(parse_range(&body, PASSWORD_SHA1), Err(HibpError::Malformed));
        assert_eq!(
            parse_range(&body, "ZE4C9B93F3F0682250B6CF8331B7EE68FD8"),
            Err(HibpError::Malformed)
        );
    }
}
