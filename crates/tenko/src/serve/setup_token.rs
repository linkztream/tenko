//! The first-run setup token outside the log (API-10).
//!
//! While setup is open, every start of `tenko serve` generates a new token. It is not
//! logged: the start writes it to `<data_dir>/setup-token` and the log only names the
//! command that prints it, `tenko setup token`. Standard output carries the token itself
//! only when it is a terminal (an interactive start); a service's standard output (the
//! journal, a container log) says where the file is.
//!
//! # The file
//!
//! The content is the token and a newline. The file is written atomically: the new token
//! goes to `setup-token.part`, is synced and renamed over the old file, so a reader sees
//! the old token or the new one, never a partial one.
//!
//! - On Unix the file is created with mode 0600: the service account reads it, nobody else.
//! - On Windows the file has no access control list of its own: it inherits the one of the
//!   data directory, which `tenko service install` restricts to the service account, the
//!   Administrators group and SYSTEM (`platform::windows::secure_data_dir`).
//!
//! The file exists only while setup is open. A start with setup closed removes a leftover
//! file, and a running server removes it when setup completes ([`follow`]).

use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt as _;
use tenko_auth::model::INSTALLATION;
use tenko_store::{ChangeStream, ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tokio::{sync::watch, task::JoinHandle};

/// How long the follower waits before it subscribes to the store again.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(1);

/// The file the new token is written to before it replaces `path`.
fn part_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".part");
    path.with_file_name(name)
}

/// Creates `path` for writing, new, readable by its owner only on Unix and with the
/// inherited access control list on Windows.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Writes `token` and a newline to `path`, replacing the file that is there, atomically.
///
/// # Errors
///
/// The I/O error of creating, writing, syncing or renaming the file.
pub fn write(path: &Path, token: &str) -> io::Result<()> {
    let part = part_path(path);
    // A part file of a start that was killed half way has whatever mode it was created
    // with; the file written here is always new.
    remove_file(&part)?;
    let written = (|| {
        let mut file = create_private(&part)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&part, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&part);
        return written;
    }
    sync_parent(path);
    Ok(())
}

/// Makes the rename durable where the platform allows it; best effort, the token of a
/// crashed start is useless anyway.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Removes the token file and a part file a killed start left behind; a file that does not
/// exist is not an error.
///
/// # Errors
///
/// The I/O error of removing either file.
pub fn remove(path: &Path) -> io::Result<()> {
    remove_file(&part_path(path))?;
    remove_file(path)
}

/// Reads the token from `path`: the first line, without the newline. `None` when the file
/// does not exist.
///
/// # Errors
///
/// The I/O error of reading the file, or `InvalidData` when it holds no token.
pub fn read(path: &Path) -> io::Result<Option<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let token = text.lines().next().unwrap_or_default().trim();
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the file holds no setup token",
        ));
    }
    Ok(Some(token.to_owned()))
}

/// The command that prints the token of the node with this data directory. The directory
/// is quoted when it contains white space.
pub fn command(data_dir: &Path) -> String {
    let dir = data_dir.display().to_string();
    if dir.contains(|c: char| c.is_whitespace() || c == '"') {
        format!(
            "tenko setup token --data-dir \"{}\"",
            dir.replace('"', "\\\"")
        )
    } else {
        format!("tenko setup token --data-dir {dir}")
    }
}

/// The log message of a start while setup is open: it names the command, never the token.
pub fn open_notice(data_dir: &Path) -> String {
    format!(
        "first-run setup is open; print the setup token with `{}` and complete setup in the \
         web UI or with `tenko setup`",
        command(data_dir)
    )
}

/// The `Setup token:` line of the console block. An interactive start (standard output is a
/// terminal) shows the token; any other start says where the file is, so that the journal
/// or a container log never carries the token.
pub fn console_line(token: &str, file: &Path, data_dir: &Path, interactive: bool) -> String {
    if interactive {
        format!("Setup token: {token}")
    } else {
        format!(
            "Setup token: in {}; print it with {}",
            file.display(),
            command(data_dir)
        )
    }
}

/// Starts the task that removes the token file when setup completes: the first change of
/// the installation record. The task ends with the stop signal. `None` when the store
/// cannot be watched; the file then stays until the next start (the token it holds stops
/// working when setup completes).
pub fn follow(
    store: Arc<dyn Store>,
    path: PathBuf,
    stop: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    // Subscribed before the task starts: setup cannot be missed once the API listens.
    let changes = match store.watch(None, filter()) {
        Ok(changes) => changes,
        Err(error) => {
            tracing::warn!(%error, "the setup token file is not removed when setup completes");
            return None;
        }
    };
    Some(tokio::spawn(remove_when_installed(
        store, path, changes, stop,
    )))
}

fn filter() -> WatchFilter {
    WatchFilter::tables([INSTALLATION.name().clone()])
}

/// What the follower learned from one wait.
enum Seen {
    Stopped,
    Installed,
    Unrelated,
    Lost,
}

async fn remove_when_installed(
    store: Arc<dyn Store>,
    path: PathBuf,
    mut changes: ChangeStream,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let seen = tokio::select! {
            _ = stop.changed() => Seen::Stopped,
            next = changes.next() => match next {
                Some(Ok(set)) if set.changes.iter().any(|change| change.table == *INSTALLATION.name()) => {
                    Seen::Installed
                }
                Some(Ok(_)) => Seen::Unrelated,
                Some(Err(_)) | None => Seen::Lost,
            },
        };
        match seen {
            Seen::Stopped => return,
            Seen::Unrelated => {}
            Seen::Installed => break,
            Seen::Lost => {
                // The stream lagged or ended: subscribe again after a pause, then look at
                // the record itself, so that a setup in between is not missed.
                tokio::select! {
                    _ = stop.changed() => return,
                    () = tokio::time::sleep(RESUBSCRIBE_DELAY) => {}
                }
                match store.watch(None, filter()) {
                    Ok(next) => changes = next,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "the setup token file is not removed when setup completes"
                        );
                        return;
                    }
                }
                if is_installed(store.as_ref()).await {
                    break;
                }
            }
        }
    }
    match remove(&path) {
        Ok(()) => tracing::info!("first-run setup completed; the setup token file is removed"),
        Err(error) => tracing::warn!(
            %error,
            path = %path.display(),
            "the setup token file could not be removed"
        ),
    }
}

async fn is_installed(store: &dyn Store) -> bool {
    let Ok(view) = store.read(ReadConsistency::Local).await else {
        return false;
    };
    view.get_typed(&INSTALLATION, &())
        .is_ok_and(|installation| installation.is_some())
}

#[cfg(test)]
mod tests {
    use tenko_core::{Principal, SystemComponent, Timestamp};
    use tenko_store::{MemStore, WriteBatch};

    use super::*;

    const TOKEN: &str = "ABCDE-FGHIJ-KLMNO-PQRST";

    #[test]
    fn write_keeps_the_token_and_a_newline_and_no_part_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        write(&path, TOKEN).expect("write");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!("{TOKEN}\n")
        );
        assert!(!dir.path().join("setup-token.part").exists());
        assert_eq!(read(&path).expect("read").as_deref(), Some(TOKEN));
    }

    #[test]
    fn write_replaces_the_file_of_an_earlier_start() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        write(&path, TOKEN).expect("first");
        write(&path, "11111-22222-33333-44444").expect("second");
        assert_eq!(
            read(&path).expect("read").as_deref(),
            Some("11111-22222-33333-44444")
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["setup-token"]);
    }

    #[test]
    fn write_clears_the_part_file_of_a_killed_start() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        std::fs::write(dir.path().join("setup-token.part"), "stale\n").expect("stale part");
        write(&path, TOKEN).expect("write");
        assert_eq!(read(&path).expect("read").as_deref(), Some(TOKEN));
        assert!(!dir.path().join("setup-token.part").exists());
    }

    #[test]
    fn remove_deletes_both_files_and_accepts_missing_ones() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        remove(&path).expect("nothing to remove");
        write(&path, TOKEN).expect("write");
        std::fs::write(dir.path().join("setup-token.part"), "stale\n").expect("stale part");
        remove(&path).expect("remove");
        assert_eq!(read(&path).expect("read"), None);
        assert!(!dir.path().join("setup-token.part").exists());
    }

    #[test]
    fn read_refuses_an_empty_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        std::fs::write(&path, "\n").expect("write");
        let error = read(&path).expect_err("no token");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        // A file of the same name with wider rights does not carry them over.
        std::fs::write(&path, "old\n").expect("old file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write(&path, TOKEN).expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }

    #[test]
    fn the_command_names_the_data_directory() {
        assert_eq!(
            command(Path::new("/var/lib/tenko")),
            "tenko setup token --data-dir /var/lib/tenko"
        );
        assert_eq!(
            command(Path::new("C:\\Program Data\\Tenko")),
            "tenko setup token --data-dir \"C:\\Program Data\\Tenko\""
        );
    }

    #[test]
    fn the_log_notice_names_the_command_and_has_no_token() {
        let notice = open_notice(Path::new("/var/lib/tenko"));
        assert_eq!(
            notice,
            "first-run setup is open; print the setup token with \
             `tenko setup token --data-dir /var/lib/tenko` and complete setup in the web UI or \
             with `tenko setup`"
        );
    }

    #[test]
    fn a_terminal_shows_the_token_and_anything_else_names_the_file() {
        let file = Path::new("/var/lib/tenko/setup-token");
        let dir = Path::new("/var/lib/tenko");
        assert_eq!(
            console_line(TOKEN, file, dir, true),
            format!("Setup token: {TOKEN}")
        );
        let hidden = console_line(TOKEN, file, dir, false);
        assert_eq!(
            hidden,
            "Setup token: in /var/lib/tenko/setup-token; print it with \
             tenko setup token --data-dir /var/lib/tenko"
        );
        assert!(!hidden.contains(TOKEN));
    }

    fn batch(table: &tenko_core::TableName) -> WriteBatch {
        let mut batch =
            WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now());
        batch.put(table.clone(), b"k".to_vec(), b"v".to_vec());
        batch
    }

    async fn gone(path: &Path) -> bool {
        for _ in 0..100 {
            if !path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn the_file_goes_when_the_installation_record_is_written() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        write(&path, TOKEN).expect("write");
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let (stop, stopped) = watch::channel(false);
        let task = follow(Arc::clone(&store), path.clone(), stopped).expect("a watch");

        // A change of another table leaves the file alone.
        store
            .propose(batch(&tenko_core::TableName::from_static("auth.unrelated")))
            .await
            .expect("unrelated write");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(path.exists(), "an unrelated change removed the file");

        store
            .propose(batch(INSTALLATION.name()))
            .await
            .expect("installation write");
        assert!(gone(&path).await, "the file is still there");
        task.await.expect("the task ends after the removal");
        drop(stop);
    }

    #[tokio::test]
    async fn the_follower_ends_with_the_stop_signal_and_keeps_the_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("setup-token");
        write(&path, TOKEN).expect("write");
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let (stop, stopped) = watch::channel(false);
        let task = follow(store, path.clone(), stopped).expect("a watch");
        stop.send(true).expect("a receiver");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the task stops in time")
            .expect("the task does not panic");
        assert!(path.exists(), "a stopping server must keep the token file");
    }
}
