//! Test hooks of the store, compiled only with the feature `test-hooks` (the acceptance
//! tests of the `tenko` binary turn it on; a release build never has it). A build with them
//! is never measured: they look for their files at every log group and every apply.
//!
//! [`writes_refused`]: while the file that the environment variable
//! [`REFUSE_WRITES_FILE`] names exists, the Raft store refuses every write with
//! [`crate::StoreError::NoQuorum`], as a controller without a quorum does (OPS-26), and
//! reads go on. A test creates the file to cut the quorum on one node and removes it to
//! heal, without a second process.
//!
//! [`HOLD_APPLY`], [`STALL_LOG`], [`FAIL_LOG`], [`FAIL_STATE`] and [`FAIL_CHECKPOINT`] act on
//! one Raft store: while a file of that name exists in the store's data directory, its state
//! machine holds every apply (a commit that has not applied yet), its log writer holds every
//! group commit (a stalled disk), every group commit of its log writer fails, every apply of
//! a batch fails, or the next durable checkpoint of its state file fails. Those files are only looked for,
//! never read. [`FREE_BYTES`] holds a byte count that stands in for the free space of the
//! store's file system.

/// The environment variable naming the file whose presence refuses writes.
pub const REFUSE_WRITES_FILE: &str = "TENKO_TEST_REFUSE_WRITES_FILE";

/// The file in a store's data directory whose presence holds every apply.
pub const HOLD_APPLY: &str = "test-hold-apply";
/// The file in a store's data directory whose presence holds every log group commit.
pub const STALL_LOG: &str = "test-stall-log";
/// The file in a store's data directory whose presence fails every log group commit, with
/// the OS error of a full disk.
pub const FAIL_LOG: &str = "test-fail-log";
/// The file in a store's data directory whose presence fails every apply of a batch, as
/// redb fails them after an earlier I/O error ("Previous I/O error").
pub const FAIL_STATE: &str = "test-fail-state";
/// The file in a store's data directory whose presence fails the next durable checkpoint of
/// its state file, with the OS error of a full disk; that checkpoint removes the file.
pub const FAIL_CHECKPOINT: &str = "test-fail-checkpoint";

/// A full disk, as the OS reports it.
#[cfg(feature = "raft")]
pub(crate) fn full_disk() -> std::io::Error {
    std::io::Error::from_raw_os_error(if cfg!(windows) { 112 } else { 28 })
}
/// The file in a store's data directory whose content, a byte count, stands in for the free
/// space of its file system (the disk guard, `raft::disk`).
pub const FREE_BYTES: &str = "test-free-bytes";

/// Waits (blocking the thread) while the file `name` exists in `dir`.
#[cfg(all(feature = "raft", feature = "test-hooks"))]
pub(crate) fn hold_while(dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    while path.exists() {
        // test-lint: allow sleep the pace of a hook that polls for a file another process may remove
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

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
