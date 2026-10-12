//! The local queue of a controller: one JSON file per item in one directory
//! (`<data_dir>/queue/<id>.json`).
//!
//! A file is written to `<id>.json.tmp`, flushed to disk and renamed over its final name,
//! so an item is either complete or absent after a crash; leftover temporary files are
//! removed at open. A file that does not decode is moved aside to `<name>.bad` and
//! reported once, never deleted. The queue holds at most [`MAX_ITEMS`] items of at most
//! [`MAX_ITEM_BYTES`] each.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use tenko_core::NodeId;
use uuid::Uuid;

use super::{QueueItem, codes};
use crate::IpamError;

/// Items one controller keeps at most.
pub const MAX_ITEMS: usize = 1_000;

/// The largest item file, in bytes.
pub const MAX_ITEM_BYTES: usize = 4 * 1024 * 1024;

/// The extension of item files.
const EXTENSION: &str = "json";

/// The local queue of a controller.
#[derive(Debug)]
pub struct LocalQueue {
    dir: PathBuf,
    /// The controller the queue belongs to.
    node: NodeId,
    /// Serializes changes to the directory (counting and writing).
    lock: Mutex<()>,
}

impl LocalQueue {
    /// Opens (and creates) the queue directory, readable by the service account only, and
    /// removes temporary files a crash left behind.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or read.
    pub fn open(dir: impl Into<PathBuf>, node: NodeId) -> io::Result<Self> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == "tmp") {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(Self {
            dir,
            node,
            lock: Mutex::new(()),
        })
    }

    /// The controller the queue belongs to.
    pub fn node(&self) -> NodeId {
        self.node
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Adds an item.
    ///
    /// # Errors
    ///
    /// `queue.full` (507) at [`MAX_ITEMS`], `queue.too_large` (413) over
    /// [`MAX_ITEM_BYTES`], `queue.io` (500) when the file cannot be written.
    pub fn add(&self, item: &QueueItem) -> Result<(), IpamError> {
        let bytes = encode(item)?;
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.ids().map_err(|error| io_error(&error))?.len() >= MAX_ITEMS {
            return Err(IpamError::new(
                codes::FULL,
                507,
                format!(
                    "the queue of this controller holds {MAX_ITEMS} changes already; withdraw \
                     some or wait until the controller is back in its cluster"
                ),
            )
            .titled("The queue is full")
            .param("limit", MAX_ITEMS));
        }
        self.write(item.id, &bytes)
            .map_err(|error| io_error(&error))
    }

    /// Replaces an item that exists.
    ///
    /// # Errors
    ///
    /// `queue.not_found` when the item is gone, `queue.io` when it cannot be written.
    pub fn replace(&self, item: &QueueItem) -> Result<(), IpamError> {
        let bytes = encode(item)?;
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.path(item.id).exists() {
            return Err(not_found(item.id));
        }
        self.write(item.id, &bytes)
            .map_err(|error| io_error(&error))
    }

    /// Every readable item, oldest first. A file that does not decode is moved aside.
    ///
    /// # Errors
    ///
    /// `queue.io` when the directory cannot be read.
    pub fn list(&self) -> Result<Vec<QueueItem>, IpamError> {
        let mut items = Vec::new();
        for id in self.ids().map_err(|error| io_error(&error))? {
            if let Some(item) = self.read(id)? {
                items.push(item);
            }
        }
        items.sort_by_key(|item| item.id);
        Ok(items)
    }

    /// One item.
    ///
    /// # Errors
    ///
    /// `queue.io` when the file cannot be read.
    pub fn get(&self, id: Uuid) -> Result<Option<QueueItem>, IpamError> {
        self.read(id)
    }

    /// Removes an item; `false` when it was not there.
    ///
    /// # Errors
    ///
    /// `queue.io` when the file cannot be removed.
    pub fn remove(&self, id: Uuid) -> Result<bool, IpamError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        match fs::remove_file(self.path(id)) {
            Ok(()) => {
                sync_dir(&self.dir).map_err(|error| io_error(&error))?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(&error)),
        }
    }

    /// The number of items.
    ///
    /// # Errors
    ///
    /// `queue.io` when the directory cannot be read.
    pub fn len(&self) -> Result<usize, IpamError> {
        Ok(self.ids().map_err(|error| io_error(&error))?.len())
    }

    /// Whether the queue is empty.
    ///
    /// # Errors
    ///
    /// `queue.io` when the directory cannot be read.
    pub fn is_empty(&self) -> Result<bool, IpamError> {
        Ok(self.len()? == 0)
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.{EXTENSION}"))
    }

    fn ids(&self) -> io::Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path
                .extension()
                .is_none_or(|extension| extension != EXTENSION)
            {
                continue;
            }
            if let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| Uuid::parse_str(stem).ok())
            {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn read(&self, id: Uuid) -> Result<Option<QueueItem>, IpamError> {
        let path = self.path(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&error)),
        };
        match serde_json::from_slice::<QueueItem>(&bytes) {
            Ok(item) if item.id == id => Ok(Some(item)),
            Ok(_) | Err(_) => {
                let aside = path.with_extension(format!("{EXTENSION}.bad"));
                tracing::warn!(
                    file = %path.display(),
                    moved_to = %aside.display(),
                    "a queued change could not be read and was moved aside"
                );
                let _ = fs::rename(&path, &aside);
                Ok(None)
            }
        }
    }

    fn write(&self, id: Uuid, bytes: &[u8]) -> io::Result<()> {
        let path = self.path(id);
        let temporary = path.with_extension(format!("{EXTENSION}.tmp"));
        {
            let mut file = private_file(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temporary, &path)?;
        sync_dir(&self.dir)
    }
}

fn encode(item: &QueueItem) -> Result<Vec<u8>, IpamError> {
    let bytes = serde_json::to_vec_pretty(item).map_err(|error| {
        IpamError::new(
            codes::IO,
            500,
            format!("the change cannot be encoded: {error}"),
        )
    })?;
    if bytes.len() > MAX_ITEM_BYTES {
        return Err(IpamError::new(
            codes::TOO_LARGE,
            413,
            format!(
                "the change takes {} bytes, more than the {MAX_ITEM_BYTES} a queued change may take",
                bytes.len()
            ),
        )
        .titled("The change is too large to queue")
        .param("limit", MAX_ITEM_BYTES));
    }
    Ok(bytes)
}

fn not_found(id: Uuid) -> IpamError {
    IpamError::new(
        codes::NOT_FOUND,
        404,
        format!("no queued change {id} on this controller"),
    )
    .titled("No such queued change")
}

fn io_error(error: &io::Error) -> IpamError {
    IpamError::new(
        codes::IO,
        500,
        format!("the queue directory cannot be used: {error}"),
    )
    .titled("The queue cannot be used")
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn private_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Makes a rename or removal in `dir` durable (a no-op where directories cannot be
/// opened, as on Windows).
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Directories cannot be opened for syncing here; the metadata read keeps the error
        // surface, so a missing directory fails the same way on every platform.
        fs::metadata(dir).map(|_| ())
    }
}
