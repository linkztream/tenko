//! The file sink, rotated by size.

use std::path::{Path, PathBuf};

use tokio::{fs, io::AsyncWriteExt};

use super::Transport;
use crate::audit_export::{
    error::{FailureKind, SinkError},
    model::FileTarget,
};

/// A file in the export directory.
#[derive(Debug)]
pub struct FileTransport {
    path: PathBuf,
    file: Option<fs::File>,
    size: u64,
    max_bytes: u64,
    keep: u32,
}

fn file_error(what: &str, path: &Path, error: &std::io::Error) -> SinkError {
    SinkError::new(
        FailureKind::File,
        format!("{what} {} failed: {error}", path.display()),
    )
}

/// Opens `path` for appending with owner-only permissions.
async fn open_append(path: &Path) -> Result<fs::File, SinkError> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .await
        .map_err(|error| file_error("opening", path, &error))
}

impl FileTransport {
    /// Opens `<dir>/<file>` for appending, creating the directory and the file.
    ///
    /// # Errors
    ///
    /// [`SinkError`] with [`FailureKind::File`].
    pub async fn open(dir: &Path, target: &FileTarget) -> Result<Self, SinkError> {
        let existed = fs::try_exists(dir).await.unwrap_or(false);
        fs::create_dir_all(dir)
            .await
            .map_err(|error| file_error("creating the directory", dir, &error))?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|error| file_error("restricting the directory", dir, &error))?;
        }
        #[cfg(not(unix))]
        let _ = existed;
        let path = dir.join(&target.file);
        let file = open_append(&path).await?;
        let size = file
            .metadata()
            .await
            .map_err(|error| file_error("reading the size of", &path, &error))?
            .len();
        Ok(Self {
            path,
            file: Some(file),
            size,
            max_bytes: target.max_bytes,
            keep: target.keep,
        })
    }

    fn rotated(&self, n: u32) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }
}

#[async_trait::async_trait]
impl Transport for FileTransport {
    async fn send(&mut self, messages: &[Vec<u8>]) -> Result<(), SinkError> {
        let mut bytes = Vec::new();
        for message in messages {
            bytes.extend_from_slice(message);
            bytes.push(b'\n');
        }
        if self.file.is_none() {
            self.file = Some(open_append(&self.path).await?);
        }
        let path = &self.path;
        let file = self.file.as_mut().expect("opened above");
        file.write_all(&bytes)
            .await
            .map_err(|error| file_error("writing", path, &error))?;
        file.sync_data()
            .await
            .map_err(|error| file_error("syncing", path, &error))?;
        self.size += bytes.len() as u64;
        Ok(())
    }

    fn needs_rotation(&self, len: usize) -> bool {
        self.size > 0 && self.size + len as u64 + 1 > self.max_bytes
    }

    async fn rotate(&mut self) -> Result<(), SinkError> {
        if let Some(mut file) = self.file.take() {
            file.flush()
                .await
                .map_err(|error| file_error("flushing", &self.path, &error))?;
            file.sync_all()
                .await
                .map_err(|error| file_error("syncing", &self.path, &error))?;
        }
        if self.keep == 0 {
            fs::remove_file(&self.path)
                .await
                .map_err(|error| file_error("removing", &self.path, &error))?;
        } else {
            let oldest = self.rotated(self.keep);
            remove_if_present(&oldest).await?;
            for n in (1..self.keep).rev() {
                let from = self.rotated(n);
                if fs::try_exists(&from).await.unwrap_or(false) {
                    let to = self.rotated(n + 1);
                    fs::rename(&from, &to)
                        .await
                        .map_err(|error| file_error("renaming", &from, &error))?;
                }
            }
            let first = self.rotated(1);
            fs::rename(&self.path, &first)
                .await
                .map_err(|error| file_error("renaming", &self.path, &error))?;
        }
        self.file = Some(open_append(&self.path).await?);
        self.size = 0;
        Ok(())
    }
}

async fn remove_if_present(path: &Path) -> Result<(), SinkError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(file_error("removing", path, &error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(max_bytes: u64, keep: u32) -> FileTarget {
        FileTarget {
            file: "audit.log".to_owned(),
            max_bytes,
            keep,
        }
    }

    fn lines(text: &str) -> Vec<Vec<u8>> {
        text.split(',').map(|s| s.as_bytes().to_vec()).collect()
    }

    #[tokio::test]
    async fn appends_lines() {
        let dir = tempfile::tempdir().expect("dir");
        let mut transport = FileTransport::open(&dir.path().join("out"), &target(1000, 2))
            .await
            .expect("open");
        transport.send(&lines("one,two")).await.expect("send");
        transport.send(&lines("three")).await.expect("send");
        let text = std::fs::read_to_string(dir.path().join("out/audit.log")).expect("read");
        assert_eq!(text, "one\ntwo\nthree\n");
    }

    #[tokio::test]
    async fn rotation_thresholds() {
        let dir = tempfile::tempdir().expect("dir");
        let mut transport = FileTransport::open(dir.path(), &target(20, 1))
            .await
            .expect("open");
        // An empty file never rotates, however large the message.
        assert!(!transport.needs_rotation(1000));
        transport.send(&lines("0123456789")).await.expect("send");
        // 11 bytes written: 11 + 8 + 1 = 20 fits, 11 + 9 + 1 = 21 does not.
        assert!(!transport.needs_rotation(8));
        assert!(transport.needs_rotation(9));
    }

    #[tokio::test]
    async fn rotation_keeps_the_newest_files() {
        let dir = tempfile::tempdir().expect("dir");
        let mut transport = FileTransport::open(dir.path(), &target(1000, 2))
            .await
            .expect("open");
        for name in ["a", "b", "c"] {
            transport.send(&lines(name)).await.expect("send");
            transport.rotate().await.expect("rotate");
        }
        transport.send(&lines("d")).await.expect("send");
        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).expect("read");
        assert_eq!(read("audit.log"), "d\n");
        assert_eq!(read("audit.log.1"), "c\n");
        assert_eq!(read("audit.log.2"), "b\n");
        assert!(!dir.path().join("audit.log.3").exists());
    }

    #[tokio::test]
    async fn keep_zero_removes_the_file() {
        let dir = tempfile::tempdir().expect("dir");
        let mut transport = FileTransport::open(dir.path(), &target(1000, 0))
            .await
            .expect("open");
        transport.send(&lines("a")).await.expect("send");
        transport.rotate().await.expect("rotate");
        assert!(!dir.path().join("audit.log.1").exists());
        assert_eq!(
            std::fs::metadata(dir.path().join("audit.log"))
                .expect("new file")
                .len(),
            0
        );
        assert!(!transport.needs_rotation(1));
    }

    #[tokio::test]
    async fn reopening_continues_the_size() {
        let dir = tempfile::tempdir().expect("dir");
        {
            let mut transport = FileTransport::open(dir.path(), &target(20, 1))
                .await
                .expect("open");
            transport.send(&lines("0123456789")).await.expect("send");
        }
        let mut transport = FileTransport::open(dir.path(), &target(20, 1))
            .await
            .expect("reopen");
        assert!(transport.needs_rotation(9));
        transport.send(&lines("x")).await.expect("send");
        let text = std::fs::read_to_string(dir.path().join("audit.log")).expect("read");
        assert_eq!(text, "0123456789\nx\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("dir");
        let sub = dir.path().join("export");
        let mut transport = FileTransport::open(&sub, &target(1000, 1))
            .await
            .expect("open");
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&sub), 0o700);
        assert_eq!(mode(&sub.join("audit.log")), 0o600);
        transport.send(&lines("a")).await.expect("send");
        transport.rotate().await.expect("rotate");
        assert_eq!(mode(&sub.join("audit.log")), 0o600);
        assert_eq!(mode(&sub.join("audit.log.1")), 0o600);
    }
}
