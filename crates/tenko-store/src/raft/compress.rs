//! Compression of what the store writes to disk (ADR 0030): the payload of a Raft log
//! record and the body of a snapshot file. Nothing in memory is compressed: the tables,
//! the batches in flight and the entries openraft holds keep their encoded form.
//!
//! The rows a lease commit writes are CBOR maps with their field names and RFC 3339
//! times: a few dozen octets of information in several hundred. Raw DEFLATE at its fastest
//! level (RFC 1951, `flate2` with its Rust backend, already a dependency of the workspace)
//! takes them to a fraction at a cost of a few microseconds per kilobyte. A record is only
//! stored compressed when it is at least [`MIN_COMPRESS`] long and the compressed form is
//! smaller; the reader learns which form it has from the record itself, so files written
//! before keep their meaning.

use std::io::{self, Read, Write};

use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};

/// Records shorter than this stay as they are: the saving would not pay for the work.
pub(crate) const MIN_COMPRESS: usize = 256;

/// The largest payload a compressed record may expand to (a corrupt record fails cleanly
/// instead of allocating without bound): the batch limit of the store with room for the
/// encoding of an entry.
pub(crate) const MAX_EXPANDED: u64 = 64 * 1024 * 1024;

/// The fast level of raw DEFLATE.
pub(crate) fn level() -> Compression {
    Compression::fast()
}

/// `data` compressed, when that makes it smaller and it is worth the work.
pub(crate) fn compress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_COMPRESS {
        return None;
    }
    let mut encoder = DeflateEncoder::new(Vec::with_capacity(data.len() / 3), level());
    encoder.write_all(data).ok()?;
    let compressed = encoder.finish().ok()?;
    (compressed.len() < data.len()).then_some(compressed)
}

/// The payload of a compressed record.
///
/// # Errors
///
/// A stream that does not inflate, or one that expands past [`MAX_EXPANDED`].
pub(crate) fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().saturating_mul(4));
    DeflateDecoder::new(data)
        .take(MAX_EXPANDED + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_EXPANDED {
        return Err(io::Error::other(
            "a compressed record expands past the limit",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_the_short_or_incompressible_stay_as_they_are() {
        let row = br#"{"addr":"192.0.2.10","state":"active","cltt":"2026-10-30T12:00:00Z"}"#;
        let data: Vec<u8> = row.iter().copied().cycle().take(4_096).collect();
        let packed = compress(&data).expect("compressible");
        assert!(packed.len() < data.len() / 4, "{} octets", packed.len());
        assert_eq!(decompress(&packed).expect("inflates"), data);
        assert!(compress(&data[..100]).is_none(), "short");
        let noise: Vec<u8> = (0..4_096_u32)
            .map(|n| n.wrapping_mul(2_654_435_761).to_be_bytes()[1])
            .collect();
        assert!(compress(&noise).is_none_or(|packed| packed.len() < noise.len()));
    }

    #[test]
    fn a_stream_that_expands_past_the_limit_fails() {
        let mut encoder = DeflateEncoder::new(Vec::new(), level());
        let zeros = vec![0_u8; 1 << 20];
        for _ in 0..=MAX_EXPANDED >> 20 {
            encoder.write_all(&zeros).expect("write");
        }
        let bomb = encoder.finish().expect("finish");
        assert!(decompress(&bomb).is_err());
    }
}
