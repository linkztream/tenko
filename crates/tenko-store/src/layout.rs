//! The files of a store data directory, named in this one place: the Raft log, the state
//! file and the pointer that names it, and the snapshot directory. The state machine
//! (`raft::sm`) writes them; the copy and the checks of `format`, which the backup and the
//! upgrade use, read the same set, so a renamed file cannot leave a backup copying the wrong
//! one.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// The Raft log.
pub(crate) const LOG_FILE: &str = "log.redb";
/// The pointer file naming the active state file.
pub(crate) const POINTER: &str = "sm.current";
/// The pointer file while it is written.
pub(crate) const POINTER_PART: &str = "sm.current.part";
/// The state file of a store that never installed a snapshot.
pub(crate) const INITIAL_FILE: &str = "sm.redb";
/// The snapshot directory.
pub(crate) const SNAPSHOTS: &str = "snapshots";

/// Whether a file name is a state file: `sm.redb` or `sm-<id>.redb`, the id made of ASCII
/// letters, digits and dashes as the state machine writes it.
pub(crate) fn is_state_file(name: &str) -> bool {
    name == INITIAL_FILE
        || name
            .strip_prefix("sm-")
            .and_then(|rest| rest.strip_suffix(".redb"))
            .is_some_and(|id| {
                !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
}

/// The pointer file of `dir`.
pub(crate) fn pointer(dir: &Path) -> PathBuf {
    dir.join(POINTER)
}

/// The active state file of `dir`: the one the pointer names, or [`INITIAL_FILE`] without
/// a pointer.
///
/// # Errors
///
/// The pointer's read error, or [`io::ErrorKind::InvalidData`] when it names no existing
/// state file: a pointer to a missing file is an error, never an empty store.
pub(crate) fn active_file(dir: &Path) -> io::Result<String> {
    match fs::read_to_string(pointer(dir)) {
        Ok(name) => {
            let name = name.trim().to_owned();
            if is_state_file(&name) && dir.join(&name).is_file() {
                Ok(name)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("names {name:?}, which is not an existing state file"),
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(INITIAL_FILE.to_owned()),
        Err(error) => Err(error),
    }
}

/// Makes a rename in `dir` durable where the platform allows it (directories cannot be
/// opened for syncing on Windows; NTFS journals the rename).
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) {
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_file_names() {
        assert!(is_state_file("sm.redb"));
        assert!(is_state_file("sm-18dce4-3.redb"));
        assert!(!is_state_file("log.redb"));
        assert!(!is_state_file("sm-.redb"));
        assert!(!is_state_file("sm-x.redb.part"));
        assert!(!is_state_file("sm-../x.redb"));
    }
}
