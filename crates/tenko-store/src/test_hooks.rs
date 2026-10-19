//! Test hooks of the store, compiled only with the feature `test-hooks` (the acceptance
//! tests of the `tenko` binary turn it on; a release build never has it).
//!
//! [`writes_refused`]: while the file that the environment variable
//! [`REFUSE_WRITES_FILE`] names exists, the Raft store refuses every write with
//! [`crate::StoreError::NoQuorum`], as a controller without a quorum does (OPS-26), and
//! reads go on. A test creates the file to cut the quorum on one node and removes it to
//! heal, without a second process.

/// The environment variable naming the file whose presence refuses writes.
pub const REFUSE_WRITES_FILE: &str = "TENKO_TEST_REFUSE_WRITES_FILE";

/// Whether writes are refused now.
pub fn writes_refused() -> bool {
    std::env::var_os(REFUSE_WRITES_FILE).is_some_and(|path| std::path::Path::new(&path).exists())
}

#[cfg(test)]
mod tests {
    #[test]
    fn without_the_variable_writes_go_through() {
        if std::env::var_os(super::REFUSE_WRITES_FILE).is_none() {
            assert!(!super::writes_refused());
        }
    }
}
