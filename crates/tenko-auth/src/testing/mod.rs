//! Test helpers (feature `testing`): a software WebAuthn authenticator and a ready-made
//! service environment over in-memory store and vault.

pub mod authenticator;
pub mod env;

pub use authenticator::{SoftAttestation, SoftAuthenticator, SoftKeyAlg, Tweaks};
pub use env::TestEnv;
