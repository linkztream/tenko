//! The node side of the configuration sync: the configuration a node received, kept in
//! `<data_dir>/node/config/` and applied atomically.
//!
//! The stream of `Config.Watch` arrives as frames; an [`Assembler`] joins the frames of
//! one message (`partial`), and [`NodeConfig::apply`] applies the message to a copy of what
//! the node holds: a snapshot replaces every row, a delta replaces or removes the rows it
//! names. The copy is written to `state.cbor` (temporary file, flush, rename) before it
//! replaces the configuration in memory, so a crash leaves either the old configuration or
//! the new one, and the node keeps serving from it across controller outages. A message
//! older than what the node holds is ignored.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    Timestamp,
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};

use super::{
    codes,
    payload::{self, ConfigEntry, ConfigPayload, MAX_PAYLOAD_BYTES},
};
use crate::{error::ClusterError, identity::write_private, proto::v1};

/// The file of the configuration in the configuration directory.
pub const STATE_FILE: &str = "state.cbor";

/// One row the node holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldRow {
    /// The table.
    pub table: String,
    /// The encoded key.
    pub key: HexBytes,
    /// The CBOR value.
    pub value: HexBytes,
}

/// The configuration a node holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The revision of the controllers' store it reflects; 0 before the first sync.
    pub revision: u64,
    /// When the node applied it.
    #[serde(default)]
    pub applied_at: Option<Timestamp>,
    /// The rows, sorted by table and key.
    pub rows: Vec<HeldRow>,
}

impl NodeConfig {
    /// The value of a row.
    pub fn get(&self, table: &str, key: &[u8]) -> Option<&[u8]> {
        self.rows
            .iter()
            .find(|row| row.table == table && row.key.0 == key)
            .map(|row| row.value.0.as_slice())
    }

    /// Whether the node has synced at least once.
    pub fn synced(&self) -> bool {
        self.revision > 0
    }

    /// The configuration after a message: `None` when the message is older than this
    /// configuration and is ignored.
    pub fn apply(&self, message: &Received, now: Timestamp) -> Option<NodeConfig> {
        if message.revision < self.revision {
            return None;
        }
        let mut rows = if message.snapshot {
            Vec::new()
        } else {
            self.rows.clone()
        };
        for ConfigEntry { table, key, value } in &message.payload.entries {
            rows.retain(|row| !(row.table == *table && row.key == *key));
            if let Some(value) = value {
                rows.push(HeldRow {
                    table: table.clone(),
                    key: key.clone(),
                    value: value.clone(),
                });
            }
        }
        rows.sort_by(|a, b| (&a.table, &a.key.0).cmp(&(&b.table, &b.key.0)));
        Some(NodeConfig {
            revision: message.revision,
            applied_at: Some(now),
            rows,
        })
    }
}

/// A complete message of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The revision after it.
    pub revision: u64,
    /// Whether it replaces what the node holds.
    pub snapshot: bool,
    /// The rows.
    pub payload: ConfigPayload,
    /// Its size on the wire, all frames together.
    pub wire_bytes: usize,
}

/// Joins the frames of one message.
#[derive(Debug, Default)]
pub struct Assembler {
    pending: Option<(u64, bool, String, Vec<u8>)>,
}

impl Assembler {
    /// Takes a frame; the message once its last frame arrived.
    ///
    /// # Errors
    ///
    /// `node.config.payload` (400) for frames that do not belong together or exceed the
    /// size limit, `node.config.encoding` for an unknown encoding; the frames so far are
    /// dropped.
    pub fn push(&mut self, frame: v1::ConfigDelta) -> Result<Option<Received>, ClusterError> {
        let v1::ConfigDelta {
            revision,
            snapshot,
            encoding,
            payload,
            partial,
        } = frame;
        let mut bytes = match self.pending.take() {
            Some((pending_revision, pending_snapshot, pending_encoding, bytes))
                if pending_revision == revision
                    && pending_snapshot == snapshot
                    && pending_encoding == encoding =>
            {
                bytes
            }
            Some(_) => {
                return Err(ClusterError::new(
                    codes::CONFIG_PAYLOAD,
                    400,
                    "a configuration message was interrupted by another one",
                ));
            }
            None => Vec::new(),
        };
        if bytes.len().saturating_add(payload.len()) > MAX_PAYLOAD_BYTES {
            return Err(ClusterError::new(
                codes::CONFIG_PAYLOAD,
                400,
                format!("a configuration message is larger than {MAX_PAYLOAD_BYTES} bytes"),
            ));
        }
        bytes.extend_from_slice(&payload);
        if partial {
            self.pending = Some((revision, snapshot, encoding, bytes));
            return Ok(None);
        }
        let decoded = payload::decode(&encoding, &bytes)?;
        Ok(Some(Received {
            revision,
            snapshot,
            payload: decoded,
            wire_bytes: bytes.len(),
        }))
    }
}

/// The configuration directory of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFiles {
    dir: PathBuf,
}

fn files_error(path: &Path, error: &dyn std::fmt::Display) -> ClusterError {
    ClusterError::new(
        codes::CONFIG_FILES,
        500,
        format!("{}: {error}", path.display()),
    )
}

impl ConfigFiles {
    /// The files in `dir` (`<data_dir>/node/config`).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The configuration file.
    pub fn state(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    /// The configuration the node holds; `None` before its first sync.
    ///
    /// # Errors
    ///
    /// `node.config.files` (500) when the file exists but cannot be read or decoded.
    pub fn load(&self) -> Result<Option<NodeConfig>, ClusterError> {
        let path = self.state();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(files_error(&path, &error)),
        };
        from_cbor(&bytes)
            .map(Some)
            .map_err(|error| files_error(&path, &error))
    }

    /// Writes the configuration atomically.
    ///
    /// # Errors
    ///
    /// `node.config.files` (500), or the node files' error.
    pub fn save(&self, config: &NodeConfig) -> Result<(), ClusterError> {
        crate::identity::create_private_dir(&self.dir)?;
        let bytes = to_cbor(config)?;
        write_private(&self.state(), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_sync::payload::{CBOR, encode_delta, encode_snapshot};

    fn entry(table: &str, key: u8, value: Option<u8>) -> ConfigEntry {
        ConfigEntry {
            table: table.to_owned(),
            key: HexBytes(vec![key]),
            value: value.map(|value| HexBytes(vec![value])),
        }
    }

    fn received(revision: u64, snapshot: bool, entries: Vec<ConfigEntry>) -> Received {
        Received {
            revision,
            snapshot,
            payload: ConfigPayload { entries },
            wire_bytes: 0,
        }
    }

    #[test]
    fn snapshots_replace_and_deltas_merge() {
        let now = Timestamp::now();
        let empty = NodeConfig::default();
        assert!(!empty.synced());
        let first = empty
            .apply(
                &received(
                    10,
                    true,
                    vec![
                        entry("scan.probe_config", 1, Some(1)),
                        entry("scan.other", 1, Some(2)),
                    ],
                ),
                now,
            )
            .expect("applied");
        assert_eq!(first.revision, 10);
        assert_eq!(first.get("scan.probe_config", &[1]), Some(&[1u8][..]));
        let second = first
            .apply(
                &received(
                    12,
                    false,
                    vec![
                        entry("scan.probe_config", 1, Some(9)),
                        entry("scan.other", 1, None),
                    ],
                ),
                now,
            )
            .expect("applied");
        assert_eq!(second.get("scan.probe_config", &[1]), Some(&[9u8][..]));
        assert_eq!(second.get("scan.other", &[1]), None);
        // An older message is ignored; the same revision again changes nothing.
        assert!(
            second
                .apply(&received(11, false, Vec::new()), now)
                .is_none()
        );
        let again = second
            .apply(
                &received(12, false, vec![entry("scan.probe_config", 1, Some(9))]),
                now,
            )
            .expect("applied");
        assert_eq!(again.rows, second.rows);
        // A snapshot drops what it does not list.
        let third = second
            .apply(&received(13, true, Vec::new()), now)
            .expect("applied");
        assert_eq!(third.rows.len(), 0);
    }

    #[test]
    fn frames_join_and_mismatches_are_refused() {
        let payload = ConfigPayload {
            entries: vec![entry("scan.probe_config", 1, Some(1))],
        };
        let (encoding, bytes) = encode_snapshot(&payload).expect("encode");
        let (a, b) = bytes.split_at(bytes.len() / 2);
        let frame = |part: &[u8], partial: bool, revision: u64| v1::ConfigDelta {
            revision,
            snapshot: true,
            encoding: encoding.to_owned(),
            payload: part.to_vec(),
            partial,
        };
        let mut assembler = Assembler::default();
        assert!(assembler.push(frame(a, true, 5)).expect("first").is_none());
        let message = assembler
            .push(frame(b, false, 5))
            .expect("second")
            .expect("complete");
        assert_eq!(message.payload, payload);
        assert_eq!(message.wire_bytes, bytes.len());
        // A frame of another revision in the middle is an error, and the next message
        // starts clean.
        assert!(assembler.push(frame(a, true, 6)).expect("first").is_none());
        assert!(assembler.push(frame(b, false, 7)).is_err());
        let (encoding, bytes) = encode_delta(&payload).expect("encode");
        assert_eq!(encoding, CBOR);
        let message = assembler
            .push(v1::ConfigDelta {
                revision: 8,
                snapshot: false,
                encoding: encoding.to_owned(),
                payload: bytes,
                partial: false,
            })
            .expect("delta")
            .expect("complete");
        assert_eq!(message.revision, 8);
    }

    #[test]
    fn the_configuration_survives_on_disk() {
        let dir = tempfile::tempdir().expect("dir");
        let files = ConfigFiles::new(dir.path().join("config"));
        assert_eq!(files.load().expect("load"), None);
        let config = NodeConfig::default()
            .apply(
                &received(3, true, vec![entry("scan.probe_config", 1, Some(1))]),
                Timestamp::now(),
            )
            .expect("applied");
        files.save(&config).expect("save");
        assert_eq!(files.load().expect("load"), Some(config));
        std::fs::write(files.state(), b"not cbor").expect("write");
        assert_eq!(
            files.load().expect_err("garbage").code(),
            codes::CONFIG_FILES
        );
    }
}
