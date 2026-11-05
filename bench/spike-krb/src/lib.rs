//! WP13.0 spike: a GSS-TSIG Kerberos acceptor for Tenko, two ways.
//!
//! - `sspi_acceptor` (feature `sspi`): design (b) of the identity plan, `sspi`'s Kerberos
//!   and SPNEGO server side behind the small [`acceptor::Acceptor`] interface.
//! - `own` (feature `own`): design (b'), the same acceptance written here over
//!   `picky-krb`'s types and ciphers, up to the AP-REQ checks and the AP-REP.
//! - `mic`: the RFC 4121 MIC token over `aws-lc-rs`, which Tenko computes itself under
//!   either design because `sspi` has no `make_signature` for Kerberos.
//!
//! The crate is a measurement, not a product: the result file beside it is the deliverable.
#![forbid(unsafe_code)]

pub mod acceptor;
pub mod hex;
pub mod mic;
pub mod wire;

#[cfg(feature = "own")]
pub mod own;
#[cfg(feature = "sspi")]
pub mod sspi_acceptor;

// The tests build tokens with the (b') helpers, so they need the `own` feature.
#[cfg(all(test, feature = "own"))]
mod fixtures_test;
#[cfg(all(test, feature = "own"))]
pub(crate) mod testkit;
#[cfg(all(test, feature = "own"))]
mod tests;
