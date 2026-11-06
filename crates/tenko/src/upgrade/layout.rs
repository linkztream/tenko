//! The `current` link layout that installation from the UI needs (OPS-24).
//!
//! ```text
//! <data_dir>/updates/
//!   0.1.0/tenko            a verified release, one directory per version
//!   0.2.0/tenko
//!   0.2.0/release.json     the manifest entry it was verified against
//!   current -> 0.2.0       the version the service manager starts (a symbolic link on
//!                          Linux, a directory junction on Windows)
//!   previous -> 0.1.0      the version before the last switch (rollback)
//!   attempt.json           the last install attempt (`super::probation`)
//! ```
//!
//! The systemd unit runs `<data_dir>/updates/current/tenko` and `tenko service install`
//! registers `<data_dir>\updates\current\tenko.exe`; `tenko upgrade layout` sets the layout up
//! from the running binary. A server that does not run from the layout shows update
//! notices but installs nothing (`layout_missing`).
//!
//! The service account must be able to write the directory, so it can also replace the
//! binary it runs: that is the price of installing from the UI, which is why the Hardened
//! profile only takes uploaded files and every install needs an administrator (R17).
//!
//! A version enters a path only through [`version_name`]: its text must be one plain
//! directory name ([`valid_version_name`]), and the directory a download or an upload is
//! written into must resolve to a child of the resolved `<data_dir>/updates`
//! ([`Layout::prepare_staged`]). A [`ReleaseVersion`] always passes, since its parser takes
//! nothing else; the check keeps the property in this module, next to the paths it builds,
//! whatever the version came from (a request, the manifest, a job's parameters, a directory
//! name).

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use tenko_api::dto::release::ReleaseVersion;

/// The directory under the data directory.
pub const UPDATES_DIR: &str = "updates";

/// The link to the version the service manager starts.
pub const CURRENT: &str = "current";

/// The link to the version before the last switch.
pub const PREVIOUS: &str = "previous";

/// The longest name of a version directory, in bytes: the longest version text a manifest
/// or a request may carry.
pub const MAX_VERSION_NAME_BYTES: usize = 128;

/// Whether `name` may name a version directory under `<data_dir>/updates`: one plain path
/// component of ASCII letters, digits, `.`, `-` and `+` that starts with a digit, at most
/// [`MAX_VERSION_NAME_BYTES`] bytes. That refuses an empty name, `.` and `..`, a separator of
/// either kind, a drive or root prefix, and the layout's own names (`current`, `previous`,
/// `attempt.json`, the staged links).
pub fn valid_version_name(name: &str) -> bool {
    name.len() <= MAX_VERSION_NAME_BYTES
        && name.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

/// The directory name of `version` under `<data_dir>/updates`.
///
/// # Errors
///
/// `InvalidInput` when the text is not a [`valid_version_name`].
pub fn version_name(version: &ReleaseVersion) -> io::Result<String> {
    let name = version.to_string();
    if valid_version_name(&name) {
        Ok(name)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a version must be a plain directory name (letters, digits, `.`, `-` and `+`, \
             starting with a digit, at most 128 bytes)",
        ))
    }
}

/// The file name of the binary in a version directory.
pub const fn binary_name() -> &'static str {
    if cfg!(windows) { "tenko.exe" } else { "tenko" }
}

/// The layout under `<data_dir>/updates`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// The layout of a data directory.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(UPDATES_DIR),
        }
    }

    /// `<data_dir>/updates`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory of a version, `<root>/<version>`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the version is not a plain directory name ([`version_name`]).
    pub fn version_dir(&self, version: &ReleaseVersion) -> io::Result<PathBuf> {
        Ok(self.root.join(version_name(version)?))
    }

    /// The binary of a version, `<root>/<version>/tenko`.
    ///
    /// # Errors
    ///
    /// As [`Layout::version_dir`].
    pub fn binary_path(&self, version: &ReleaseVersion) -> io::Result<PathBuf> {
        Ok(self.version_dir(version)?.join(binary_name()))
    }

    /// The binary of a version, to look it up: as [`Layout::binary_path`], and the empty
    /// path, which names no file, for a version that is not a plain directory name. Paths
    /// that are written to come from [`Layout::binary_path`].
    pub fn binary(&self, version: &ReleaseVersion) -> PathBuf {
        self.binary_path(version).unwrap_or_default()
    }

    /// The file a download or an upload of `version` is staged in,
    /// `<root>/<version>/tenko.part`, to look at or remove it.
    ///
    /// # Errors
    ///
    /// As [`Layout::version_dir`].
    pub fn staged(&self, version: &ReleaseVersion) -> io::Result<PathBuf> {
        Ok(self
            .version_dir(version)?
            .join(format!("{}.part", binary_name())))
    }

    /// Creates the directory of `version` and returns the file to stage a download or an
    /// upload in. The directory must resolve to a child of the resolved root: a version
    /// directory that is a link to elsewhere is refused before a byte is written.
    ///
    /// # Errors
    ///
    /// As [`Layout::version_dir`]; `InvalidInput` when the directory resolves outside the
    /// root; the I/O error.
    pub fn prepare_staged(&self, version: &ReleaseVersion) -> io::Result<PathBuf> {
        let dir = self.version_dir(version)?;
        fs::create_dir_all(&dir)?;
        let root = fs::canonicalize(&self.root)?;
        let resolved = fs::canonicalize(&dir)?;
        if resolved.parent() != Some(root.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} resolves to {}, outside {}",
                    dir.display(),
                    resolved.display(),
                    root.display()
                ),
            ));
        }
        Ok(resolved.join(format!("{}.part", binary_name())))
    }

    /// The binary the service manager starts: `<root>/current/tenko`.
    pub fn current_binary(&self) -> PathBuf {
        self.root.join(CURRENT).join(binary_name())
    }

    /// The version a link (`current` or `previous`) points at.
    pub fn linked(&self, link: &str) -> Option<ReleaseVersion> {
        let target = fs::read_link(self.root.join(link)).ok()?;
        let name = target.file_name()?.to_str()?.to_owned();
        name.parse().ok()
    }

    /// The version `current` points at.
    pub fn current(&self) -> Option<ReleaseVersion> {
        self.linked(CURRENT)
    }

    /// The version `previous` points at.
    pub fn previous(&self) -> Option<ReleaseVersion> {
        self.linked(PREVIOUS)
    }

    /// Whether the executable `exe` runs from the layout: it lies in the directory that
    /// `current` resolves to.
    pub fn runs(&self, exe: &Path) -> bool {
        let (Ok(exe), Ok(current)) = (
            fs::canonicalize(exe),
            fs::canonicalize(self.root.join(CURRENT)),
        ) else {
            return false;
        };
        exe.parent() == Some(current.as_path())
    }

    /// Whether this process runs from the layout.
    pub fn runs_self(&self) -> bool {
        std::env::current_exe().is_ok_and(|exe| self.runs(&exe))
    }

    /// Points `link` at the directory of `version`, replacing the old link: atomically with a
    /// rename on Unix; on Windows the old junction is removed before the new one is renamed
    /// into place.
    ///
    /// # Errors
    ///
    /// As [`Layout::version_dir`]; the I/O error; the version directory must exist.
    pub fn point(&self, link: &str, version: &ReleaseVersion) -> io::Result<()> {
        let name = version_name(version)?;
        let target = self.root.join(&name);
        if !target.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} does not exist", target.display()),
            ));
        }
        let path = self.root.join(link);
        let staged = self.root.join(format!("{link}.new"));
        remove_link(&staged)?;
        create_link(&target, &name, &staged)?;
        replace_link(&staged, &path)
    }

    /// Copies a binary into the directory of `version` (written aside and renamed, so a
    /// half-copied binary never appears under its name) and returns its path.
    ///
    /// # Errors
    ///
    /// As [`Layout::version_dir`]; the I/O error.
    pub fn install_binary(&self, version: &ReleaseVersion, source: &Path) -> io::Result<PathBuf> {
        let dir = self.version_dir(version)?;
        fs::create_dir_all(&dir)?;
        let target = dir.join(binary_name());
        let part = dir.join(format!("{}.part", binary_name()));
        fs::copy(source, &part)?;
        fs::File::options()
            .write(true)
            .open(&part)
            .and_then(|file| file.sync_all())?;
        make_executable(&part)?;
        fs::rename(&part, &target)?;
        Ok(target)
    }

    /// The versions that have a binary in the layout, oldest first.
    pub fn installed(&self) -> Vec<ReleaseVersion> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut versions: Vec<ReleaseVersion> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                fs::symlink_metadata(entry.path()).is_ok_and(|metadata| metadata.is_dir())
            })
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .filter(|version| self.binary(version).is_file())
            .collect();
        versions.sort();
        versions
    }

    /// Removes the oldest version directories so that at most `keep` remain besides the ones
    /// `current` and `previous` point at; returns the removed versions.
    pub fn prune(&self, keep: usize) -> Vec<ReleaseVersion> {
        let protected = [self.current(), self.previous()];
        let candidates: Vec<ReleaseVersion> = self
            .installed()
            .into_iter()
            .filter(|version| !protected.iter().flatten().any(|kept| kept == version))
            .collect();
        let excess = candidates.len().saturating_sub(keep);
        let mut removed = Vec::new();
        for version in candidates.into_iter().take(excess) {
            match self.version_dir(&version).and_then(fs::remove_dir_all) {
                Ok(()) => removed.push(version),
                Err(error) => {
                    tracing::warn!(%error, %version, "cannot remove an old installed version");
                }
            }
        }
        removed
    }
}

/// Removes a link (not its target); a missing link is fine.
fn remove_link(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => {
            #[cfg(windows)]
            {
                // A junction is a directory reparse point: removing the directory entry
                // removes the link and leaves the target alone.
                fs::remove_dir(path)
            }
            #[cfg(not(windows))]
            {
                fs::remove_file(path)
            }
        }
    }
}

#[cfg(unix)]
fn create_link(_target: &Path, relative: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(relative, link)
}

#[cfg(unix)]
fn replace_link(staged: &Path, link: &Path) -> io::Result<()> {
    fs::rename(staged, link)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

/// A directory junction made with `mklink /J`: unlike a symbolic link it needs no privilege,
/// so the virtual service account can switch versions. The paths are checked for the
/// characters that `cmd` would interpret.
#[cfg(windows)]
fn create_link(target: &Path, _relative: &str, link: &Path) -> io::Result<()> {
    let target = std::path::absolute(target)?;
    let link = std::path::absolute(link)?;
    for path in [&target, &link] {
        let text = path.to_string_lossy();
        if text.chars().any(|c| "\"&|<>^%!".contains(c)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{text} contains a character the junction tool cannot take"),
            ));
        }
    }
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let cmd = PathBuf::from(system).join("System32").join("cmd.exe");
    let output = std::process::Command::new(cmd)
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()?;
    if output.status.success() && fs::symlink_metadata(&link).is_ok() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "mklink /J {} {} failed: {}",
            link.display(),
            target.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(windows)]
fn replace_link(staged: &Path, link: &Path) -> io::Result<()> {
    remove_link(link)?;
    fs::rename(staged, link)
}

#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version, which sets the mode"
)]
fn make_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-layout-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create");
        dir
    }

    fn version(text: &str) -> ReleaseVersion {
        text.parse().expect("version")
    }

    #[test]
    fn versions_are_installed_linked_switched_and_pruned() {
        let data = temp_dir("switch");
        let layout = Layout::new(&data);
        let source = data.join("source-binary");
        fs::write(&source, b"binary").expect("source");
        for text in ["0.1.0", "0.2.0", "0.3.0", "0.4.0"] {
            let path = layout
                .install_binary(&version(text), &source)
                .expect("install");
            assert!(path.ends_with(binary_name()));
        }
        assert_eq!(layout.current(), None);
        layout.point(CURRENT, &version("0.1.0")).expect("current");
        assert_eq!(layout.current(), Some(version("0.1.0")));
        assert!(layout.current_binary().is_file());
        assert!(layout.runs(&layout.binary(&version("0.1.0"))));
        assert!(!layout.runs(&layout.binary(&version("0.2.0"))));

        layout.point(PREVIOUS, &version("0.1.0")).expect("previous");
        layout.point(CURRENT, &version("0.4.0")).expect("switch");
        assert_eq!(layout.current(), Some(version("0.4.0")));
        assert_eq!(layout.previous(), Some(version("0.1.0")));
        assert_eq!(
            fs::read(layout.current_binary()).expect("through the link"),
            b"binary"
        );
        assert!(!data.join(UPDATES_DIR).join("current.new").exists());

        // Keep one version besides current and previous: 0.2.0 goes, 0.3.0 stays.
        assert_eq!(layout.prune(1), [version("0.2.0")]);
        assert_eq!(
            layout.installed(),
            [version("0.1.0"), version("0.3.0"), version("0.4.0")]
        );
        assert!(layout.point(CURRENT, &version("9.9.9")).is_err());
        assert_eq!(layout.current(), Some(version("0.4.0")));
        fs::remove_dir_all(&data).expect("clean up");
    }

    #[test]
    fn a_version_name_is_one_plain_directory_name() {
        let longest = format!("1.{}", "0".repeat(MAX_VERSION_NAME_BYTES - 2));
        let too_long = format!("1.{}", "0".repeat(MAX_VERSION_NAME_BYTES - 1));
        for name in [
            "0.1.0",
            "1.2.3-rc.1",
            "1.2.3-rc.1+build.5",
            longest.as_str(),
        ] {
            assert!(valid_version_name(name), "{name:?}");
        }
        for name in [
            "",
            ".",
            "..",
            "../0.1.0",
            "0.1.0/..",
            "/0.1.0",
            "/etc",
            "C:\\0.1.0",
            "\\\\server\\share",
            "0.1.0/tenko",
            "0.1.0\\tenko",
            "0.1.0\0",
            " 0.1.0",
            "current",
            "previous",
            "attempt.json",
            "v0.1.0",
            too_long.as_str(),
        ] {
            assert!(!valid_version_name(name), "{name:?}");
        }
    }

    #[test]
    fn every_release_version_names_a_directory_under_the_root() {
        let layout = Layout::new(Path::new("data"));
        for text in ["0.1.0", "v0.2.0", "1.2.3-rc.1+build.5"] {
            let dir = layout.version_dir(&version(text)).expect("plain name");
            assert_eq!(dir.parent(), Some(layout.root()), "{text}");
            assert_eq!(
                layout.staged(&version(text)).expect("plain name").parent(),
                Some(dir.as_path())
            );
        }
    }

    #[test]
    fn the_staged_file_lies_in_its_version_directory() {
        let data = temp_dir("staged");
        let layout = Layout::new(&data);
        let staged = layout.prepare_staged(&version("0.2.0")).expect("staged");
        assert_eq!(
            staged,
            fs::canonicalize(layout.root())
                .expect("root")
                .join("0.2.0")
                .join(format!("{}.part", binary_name()))
        );
        assert!(staged.parent().is_some_and(Path::is_dir));
        fs::remove_dir_all(&data).expect("clean up");
    }

    #[cfg(unix)]
    #[test]
    fn a_version_directory_that_leads_elsewhere_is_refused() {
        let data = temp_dir("staged-link");
        let outside = data.join("outside");
        fs::create_dir_all(&outside).expect("outside");
        let layout = Layout::new(&data);
        fs::create_dir_all(layout.root()).expect("root");
        std::os::unix::fs::symlink(&outside, layout.root().join("0.2.0")).expect("link");
        let error = layout
            .prepare_staged(&version("0.2.0"))
            .expect_err("a link out of the root");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
        fs::remove_dir_all(&data).expect("clean up");
    }
}
