//! Framing of the spike's test protocol: a 4-octet big-endian length and the bytes. The
//! same framing on both sides (`peer/gss-peer.c`).

use std::io::{Read, Write};

/// The largest frame accepted; a Kerberos token with a PAC is a few kilobytes.
pub const MAX_FRAME: u32 = 1 << 20;

/// Reads one frame.
pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Writes one frame.
pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| std::io::Error::other("frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}
