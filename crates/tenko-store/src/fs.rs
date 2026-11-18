//! Files only the service account reads: the one atomic writer that every crate uses for
//! keys, certificates and the state files beside them.

use std::{
    fmt, fs, io,
    io::Write as _,
    path::{Path, PathBuf},
};

/// A failed step of [`write_private`]: the path it worked on and the cause.
#[derive(Debug)]
pub struct FileError {
    /// The file or directory of the failed step.
    pub path: PathBuf,
    /// The cause.
    pub error: io::Error,
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.error)
    }
}

impl std::error::Error for FileError {}

/// Writes a file atomically (temporary file, flush to disk, rename, directory sync),
/// `0600` on Unix.
///
/// Nothing on the way is followed as a link: a directory that is a link is refused, and
/// whatever lies at the temporary name (a stale file, a symbolic or hard link) is removed
/// as an entry before the file is created anew, which fails if anything took the name in
/// between. Another account that can write the directory therefore cannot make this write
/// land in a file of its choosing (ADR 0023, I2), and the rename replaces the entry at
/// `path` without following it. The steps go by path, so an account that can swap the
/// directory for a link between them still could; what keeps a privileged process from
/// writing here at all is the guard of the `tenko` binary (`exec.unsafe_owner`).
///
/// # Errors
///
/// The step that failed, with its path; a temporary file it left is removed.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        let meta = fs::symlink_metadata(dir).map_err(at(dir))?;
        if meta.file_type().is_symlink() {
            return Err(at(dir)(io::Error::other(
                "the directory is a link, which is not followed",
            )));
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    match fs::symlink_metadata(&tmp) {
        Ok(_) => fs::remove_file(&tmp).map_err(at(&tmp))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(at(&tmp)(error)),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(at(&tmp))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(at(&tmp))
        .and_then(|()| {
            drop(file);
            fs::rename(&tmp, path).map_err(at(path))
        });
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
        return written;
    }
    // The rename itself is durable only once the directory is.
    if let Some(dir) = path.parent() {
        crate::sync_dir(dir);
    }
    Ok(())
}

/// The error of a step on `path`.
fn at(path: &Path) -> impl FnOnce(io::Error) -> FileError {
    let path = path.to_owned();
    move |error| FileError { path, error }
}

#[cfg(test)]
mod tests {
    use tenko_core::testing::TempDir;

    use super::*;

    /// A directory with a file outside it that another account wants overwritten.
    fn planted(name: &str) -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new(name);
        let dir = temp.join("node");
        fs::create_dir_all(&dir).expect("dir");
        let outside = temp.join("outside");
        fs::write(&outside, b"not yours").expect("outside file");
        (temp, dir, outside)
    }

    /// A hard link planted at the temporary name shares the outside file's contents: the
    /// write removes the name and leaves the outside file as it was.
    #[test]
    fn a_hard_link_at_the_temporary_name_is_not_written_through() {
        let (_temp, dir, outside) = planted("fs-hard-link");
        let target = dir.join("node-key.pem.new");
        fs::hard_link(&outside, dir.join("node-key.pem.new.tmp")).expect("hard link");
        write_private(&target, b"the new key").expect("written");
        assert_eq!(fs::read(&outside).expect("outside"), b"not yours");
        assert_eq!(fs::read(&target).expect("target"), b"the new key");
        assert!(!dir.join("node-key.pem.new.tmp").exists());
    }

    /// A symbolic link planted at the temporary name, to an existing file or to a name that
    /// does not exist yet, is removed and never followed.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_at_the_temporary_name_is_not_followed() {
        let (temp, dir, outside) = planted("fs-symlink");
        let target = dir.join("node-cert.pem.new");
        let link = dir.join("node-cert.pem.new.tmp");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");
        write_private(&target, b"the new certificate").expect("written");
        assert_eq!(fs::read(&outside).expect("outside"), b"not yours");
        assert_eq!(fs::read(&target).expect("target"), b"the new certificate");
        let missing = temp.join("created-by-root");
        std::os::unix::fs::symlink(&missing, &link).expect("dangling symlink");
        write_private(&target, b"again").expect("written");
        assert_eq!(
            fs::symlink_metadata(&missing)
                .map_err(|error| error.kind())
                .err(),
            Some(io::ErrorKind::NotFound),
            "nothing created outside"
        );
        assert_eq!(fs::read(&target).expect("target"), b"again");
    }

    /// A directory replaced by a link to another directory is refused before anything is
    /// written into it.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_is_a_link_is_refused() {
        let (temp, dir, _outside) = planted("fs-dir-link");
        let elsewhere = temp.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("dir");
        fs::remove_dir(&dir).expect("remove");
        std::os::unix::fs::symlink(&elsewhere, &dir).expect("symlink");
        let error = write_private(&dir.join("identity.json"), b"{}").expect_err("refused");
        assert_eq!(error.path, dir);
        assert!(error.to_string().contains("is a link"), "{error}");
        assert_eq!(fs::read_dir(&elsewhere).expect("dir").count(), 0);
    }
}
