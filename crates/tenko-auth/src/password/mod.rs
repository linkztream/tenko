//! Passwords: policy presets (IAM-03, TGL-01) and Argon2id hashing.
//!
//! A password goes through [`normalize`] once. [`PasswordPolicy::check`] and
//! [`hash_password`] both take that form, so what the policy accepted is what is hashed.

pub mod hash;
pub mod policy;

pub use hash::{
    HashStrength, PasswordHash, dummy_verify, hash_password, needs_rehash, verify_password,
};
pub use policy::{
    ContextKind, CustomPolicy, DEFAULT_MAX_LENGTH, PRODUCT_WORDS, PasswordContext, PasswordPolicy,
    PolicyViolation, normalize,
};
