//! Cryptographically secure random bytes (`aws-lc-rs`).

use crate::error::AuthError;

/// Fills `buf` with random bytes.
///
/// # Errors
///
/// [`AuthError::Internal`] if the system random source fails, which does not happen on a
/// working system.
pub fn fill(buf: &mut [u8]) -> Result<(), AuthError> {
    aws_lc_rs::rand::fill(buf).map_err(|_| AuthError::internal("system random source failed"))
}

/// `N` random bytes.
///
/// # Errors
///
/// As [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N], AuthError> {
    aws_lc_rs::rand::generate::<[u8; N]>(&aws_lc_rs::rand::SystemRandom::new())
        .map(aws_lc_rs::rand::Random::expose)
        .map_err(|_| AuthError::internal("system random source failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays_differ() {
        let a: [u8; 32] = array().expect("random");
        let b: [u8; 32] = array().expect("random");
        assert_ne!(a, b);
    }
}
