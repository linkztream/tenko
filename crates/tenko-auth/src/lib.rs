//! Identity and access of Tenko DDI: local users with password policy presets, TOTP,
//! passkeys and recovery codes, sessions and personal tokens, roles and the
//! [`Authorizer`](tenko_core::Authorizer), first-run setup and the security settings
//! (IAM-03 to IAM-10, IAM-19, API-10, TGL-01 to TGL-07).
//!
//! # Map
//!
//! | Module | Contents |
//! |---|---|
//! | [`password`] | presets PIN, Standard, Hardened, Custom; NIST SP 800-63B checks; Argon2id |
//! | [`hibp`] | breached-password check: HIBP range API (k-anonymity) and the offline filter |
//! | [`totp`] | RFC 6238 codes |
//! | [`recovery`] | recovery codes, shown once and stored hashed |
//! | [`lockout`] | progressive delays and locks, in memory before any store write |
//! | [`webauthn`] | the relying party of ADR 0010 |
//! | [`service`] | [`AuthService`]: login, sessions, factors, tokens, users, settings, setup |
//! | [`authz`] | the [`Authorizer`](tenko_core::Authorizer) over a derived index |
//! | [`roles`] | `admin`, `operator`, `viewer` and the strength rules |
//! | [`settings`] | security profiles and TGL-01 to TGL-07 |
//! | [`model`] | stored records and the `auth.*` tables |
//! | [`secret`] | session secrets, personal tokens and the setup token |
//! | [`challenge`] | pending ceremonies, in memory |
//! | [`encoding`] | base64url, base32, hexadecimal |
//! | [`clock`] | the time source |
//! | [`error`] | [`AuthError`] and its codes |

#![forbid(unsafe_code)]

pub mod authz;
pub mod challenge;
pub mod clock;
pub mod encoding;
pub mod error;
pub mod hibp;
pub mod lockout;
pub mod model;
pub mod password;
pub mod random;
pub mod recovery;
pub mod roles;
pub mod secret;
pub mod service;
pub mod settings;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod totp;
pub mod webauthn;

pub use error::AuthError;
pub use service::{AuthConfig, AuthService, LoginOutcome, NewSession};

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-auth";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
