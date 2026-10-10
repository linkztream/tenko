//! The wire form of configuration deltas and snapshots and of command arguments.
//!
//! A configuration message carries a [`ConfigPayload`]: rows of the node's configuration
//! tables, each with its table, its encoded key and its CBOR value (none for a row that was
//! removed). A delta lists the rows that changed; a snapshot lists every row the node
//! receives and replaces what it holds. Deltas are `cbor/1`; snapshots are
//! `cbor+deflate/1` (raw deflate, RFC 1951), and a node inflates them up to
//! [`MAX_INFLATED_BYTES`] only.
//!
//! Command arguments are CBOR maps (`cbor/1`) of the structs below; a node refuses a
//! command whose arguments do not decode.
//!
//! Every decoder here reads input from the network; `fuzz/fuzz_targets/node_config_payloads.rs`
//! runs them on arbitrary bytes.

use std::io::{Read, Write};

use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use uuid::Uuid;

use super::codes;
use crate::error::ClusterError;

/// Plain CBOR.
pub const CBOR: &str = "cbor/1";
/// CBOR compressed with raw deflate.
pub const CBOR_DEFLATE: &str = "cbor+deflate/1";
/// The largest configuration payload a node accepts on the wire.
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
/// The largest configuration a node inflates a snapshot to.
pub const MAX_INFLATED_BYTES: usize = 64 * 1024 * 1024;
/// The most rows in one payload.
pub const MAX_ENTRIES: usize = 100_000;
/// The longest encoded key of a row.
pub const MAX_KEY_BYTES: usize = 1024;
/// The largest command arguments.
pub const MAX_ARGS_BYTES: usize = 64 * 1024;

/// One row of a node's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigEntry {
    /// The table, such as `scan.probe_config`.
    pub table: String,
    /// The encoded key of the row.
    pub key: HexBytes,
    /// The CBOR value; `None` when the row was removed.
    #[serde(default)]
    pub value: Option<HexBytes>,
}

/// The rows of a delta or a snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigPayload {
    /// The rows.
    pub entries: Vec<ConfigEntry>,
}

fn payload_error(detail: impl Into<String>) -> ClusterError {
    ClusterError::new(codes::CONFIG_PAYLOAD, 400, detail)
}

/// Encodes a delta (`cbor/1`).
///
/// # Errors
///
/// The codec error of a payload that does not encode.
pub fn encode_delta(payload: &ConfigPayload) -> Result<(&'static str, Vec<u8>), ClusterError> {
    Ok((CBOR, to_cbor(payload)?.to_vec()))
}

/// Encodes a snapshot (`cbor+deflate/1`).
///
/// # Errors
///
/// The codec error of a payload that does not encode, or a compression failure.
pub fn encode_snapshot(payload: &ConfigPayload) -> Result<(&'static str, Vec<u8>), ClusterError> {
    let plain = to_cbor(payload)?;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&plain)
        .map_err(|error| ClusterError::internal(format!("deflate failed: {error}")))?;
    let compressed = encoder
        .finish()
        .map_err(|error| ClusterError::internal(format!("deflate failed: {error}")))?;
    Ok((CBOR_DEFLATE, compressed))
}

/// Decodes a configuration payload in `encoding` and checks its limits.
///
/// # Errors
///
/// `node.config.encoding` (400) for an unknown encoding, `node.config.payload` (400) for
/// bytes that do not decode or break a limit.
pub fn decode(encoding: &str, bytes: &[u8]) -> Result<ConfigPayload, ClusterError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(payload_error(format!(
            "a configuration payload of {} bytes is larger than {MAX_PAYLOAD_BYTES}",
            bytes.len()
        )));
    }
    let payload: ConfigPayload = match encoding {
        CBOR => from_cbor(bytes)
            .map_err(|error| payload_error(format!("the payload does not decode: {error}")))?,
        CBOR_DEFLATE => {
            let plain = inflate(bytes, MAX_INFLATED_BYTES)?;
            from_cbor(&plain)
                .map_err(|error| payload_error(format!("the snapshot does not decode: {error}")))?
        }
        other => {
            return Err(ClusterError::new(
                codes::CONFIG_ENCODING,
                400,
                format!("the configuration encoding `{other}` is not one this node knows"),
            ));
        }
    };
    check(&payload)?;
    Ok(payload)
}

/// Inflates raw deflate up to `max` bytes.
fn inflate(bytes: &[u8], max: usize) -> Result<Vec<u8>, ClusterError> {
    let mut plain = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    DeflateDecoder::new(bytes)
        .take(limit)
        .read_to_end(&mut plain)
        .map_err(|error| payload_error(format!("the snapshot does not inflate: {error}")))?;
    if plain.len() > max {
        return Err(payload_error(format!(
            "the snapshot inflates to more than {max} bytes"
        )));
    }
    Ok(plain)
}

fn check(payload: &ConfigPayload) -> Result<(), ClusterError> {
    if payload.entries.len() > MAX_ENTRIES {
        return Err(payload_error(format!(
            "the payload has {} rows; at most {MAX_ENTRIES} fit",
            payload.entries.len()
        )));
    }
    for entry in &payload.entries {
        if tenko_core::TableName::new(entry.table.clone()).is_err() {
            return Err(payload_error(format!(
                "`{}` is not a table name",
                entry.table.chars().take(80).collect::<String>()
            )));
        }
        if entry.key.0.len() > MAX_KEY_BYTES {
            return Err(payload_error(format!(
                "a key of {} bytes is longer than {MAX_KEY_BYTES}",
                entry.key.0.len()
            )));
        }
    }
    Ok(())
}

/// The arguments of `scan.run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunArgs {
    /// The methods to run, by name (`arp`, `tcp_connect`, `snmp`), in this order.
    pub methods: Vec<String>,
    /// An address or prefix inside the probe's scope; `None` is the whole scope.
    #[serde(default)]
    pub target: Option<String>,
    /// Runs inside a blackout window too.
    #[serde(default)]
    pub ignore_blackout: bool,
    /// When the issuer stops waiting; the node may give up then.
    #[serde(default)]
    pub deadline_secs: Option<u32>,
}

/// The arguments of `scan.stop`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopArgs {
    /// Why, recorded with the kill switch.
    pub reason: String,
}

/// The arguments of `scan.cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelArgs {
    /// The `scan.run` command to cancel.
    pub command: Uuid,
}

/// Encodes command arguments (`cbor/1`).
///
/// # Errors
///
/// The codec error of arguments that do not encode.
pub fn encode_args<T: Serialize>(args: &T) -> Result<Vec<u8>, ClusterError> {
    Ok(to_cbor(args)?.to_vec())
}

/// Decodes command arguments.
///
/// # Errors
///
/// `node.config.encoding` (400) for an unknown encoding, `node.command.invalid` (400) for
/// arguments that do not decode or are too large.
pub fn decode_args<T: DeserializeOwned>(encoding: &str, bytes: &[u8]) -> Result<T, ClusterError> {
    if encoding != CBOR {
        return Err(ClusterError::new(
            codes::CONFIG_ENCODING,
            400,
            format!("the command encoding `{encoding}` is not one this node knows"),
        ));
    }
    if bytes.len() > MAX_ARGS_BYTES {
        return Err(ClusterError::new(
            codes::COMMAND_INVALID,
            400,
            format!("command arguments of {} bytes are too large", bytes.len()),
        ));
    }
    from_cbor(bytes).map_err(|error| {
        ClusterError::new(
            codes::COMMAND_INVALID,
            400,
            format!("the command arguments do not decode: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConfigPayload {
        ConfigPayload {
            entries: vec![
                ConfigEntry {
                    table: "scan.probe_config".to_owned(),
                    key: HexBytes(vec![0, 0, 0, 0, 0, 0, 3, 233]),
                    value: Some(HexBytes(vec![0xa0])),
                },
                ConfigEntry {
                    table: "scan.probe_config".to_owned(),
                    key: HexBytes(vec![0, 0, 0, 0, 0, 0, 3, 234]),
                    value: None,
                },
            ],
        }
    }

    #[test]
    fn deltas_and_snapshots_round_trip() {
        let payload = sample();
        let (encoding, bytes) = encode_delta(&payload).expect("delta");
        assert_eq!(encoding, CBOR);
        assert_eq!(decode(encoding, &bytes).expect("decode"), payload);
        let (encoding, bytes) = encode_snapshot(&payload).expect("snapshot");
        assert_eq!(encoding, CBOR_DEFLATE);
        assert_eq!(decode(encoding, &bytes).expect("decode"), payload);
    }

    #[test]
    fn bad_payloads_are_refused_with_codes() {
        assert_eq!(
            decode("json/1", b"{}").expect_err("encoding").code(),
            codes::CONFIG_ENCODING
        );
        assert_eq!(
            decode(CBOR, &[0xff, 0x00]).expect_err("garbage").code(),
            codes::CONFIG_PAYLOAD
        );
        assert_eq!(
            decode(CBOR_DEFLATE, &[0x01, 0x02, 0x03])
                .expect_err("not deflate")
                .code(),
            codes::CONFIG_PAYLOAD
        );
        let mut payload = sample();
        payload.entries[0].table = "Not A Table".to_owned();
        let (_, bytes) = encode_delta(&payload).expect("encode");
        assert_eq!(
            decode(CBOR, &bytes).expect_err("table").code(),
            codes::CONFIG_PAYLOAD
        );
    }

    #[test]
    fn a_deflate_bomb_stops_at_the_limit() {
        // A run of zeros compresses about a thousand to one; the limit is scaled down.
        let zeros = vec![0u8; 64 * 1024];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&zeros).expect("write");
        let bomb = encoder.finish().expect("finish");
        assert!(bomb.len() < 1024);
        assert_eq!(
            inflate(&bomb, 64 * 1024).expect("at the limit").len(),
            64 * 1024
        );
        let error = inflate(&bomb, 4096).expect_err("bomb");
        assert_eq!(error.code(), codes::CONFIG_PAYLOAD);
        assert!(error.detail().contains("inflates"), "{}", error.detail());
    }

    #[test]
    fn command_arguments_round_trip() {
        let args = ScanRunArgs {
            methods: vec!["arp".to_owned(), "tcp_connect".to_owned()],
            target: Some("192.0.2.0/28".to_owned()),
            ignore_blackout: false,
            deadline_secs: Some(300),
        };
        let bytes = encode_args(&args).expect("encode");
        assert_eq!(
            decode_args::<ScanRunArgs>(CBOR, &bytes).expect("decode"),
            args
        );
        assert!(decode_args::<ScanRunArgs>("cbor/2", &bytes).is_err());
        assert!(decode_args::<StopArgs>(CBOR, &bytes).is_err());
        let cancel = CancelArgs {
            command: Uuid::now_v7(),
        };
        let bytes = encode_args(&cancel).expect("encode");
        assert_eq!(
            decode_args::<CancelArgs>(CBOR, &bytes).expect("decode"),
            cancel
        );
    }
}
