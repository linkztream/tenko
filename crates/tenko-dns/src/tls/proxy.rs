//! The client address behind a reverse proxy: the PROXY protocol version 2 header (the
//! `HAProxy` specification, section 2.2) of a DoT or DoH connection, and the
//! `X-Forwarded-For` header of a DoH request.
//!
//! Only the version 2 binary header is read (`send-proxy-v2` in `HAProxy`); a connection
//! that starts with anything else is closed. The header is read exactly, so nothing past it
//! is consumed. Of the address families only TCP over IPv4 and IPv6 give a client address;
//! a `LOCAL` command (the proxy's own health check) and the other families leave the
//! proxy's address in place. The TLVs are skipped unread.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-octet signature of a version 2 header.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The signature, the version and command, the family and the length.
pub const FIXED_LEN: usize = 16;

/// The largest header accepted, fixed part included.
pub const MAX_LEN: usize = 4096;

/// Why a header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// No version 2 signature.
    Signature,
    /// A version other than 2, or a command other than `LOCAL` and `PROXY`.
    Version,
    /// The length is over [`MAX_LEN`] or too short for the family's addresses.
    Length,
    /// The connection ended inside the header.
    Truncated,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyError::Signature => "no PROXY protocol version 2 signature",
            ProxyError::Version => "an unknown PROXY protocol version or command",
            ProxyError::Length => "a PROXY protocol header of a wrong length",
            ProxyError::Truncated => "a cut PROXY protocol header",
        })
    }
}

impl std::error::Error for ProxyError {}

/// What the fixed part says: whether the addresses count, the family and the length of
/// the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixed {
    /// `PROXY` (the addresses are the client's) rather than `LOCAL`.
    pub proxied: bool,
    /// The address family and transport octet.
    pub family: u8,
    /// Octets after the fixed part.
    pub len: usize,
}

/// Reads the fixed part of a header.
///
/// # Errors
///
/// [`ProxyError::Signature`], [`ProxyError::Version`] or [`ProxyError::Length`].
pub fn parse_fixed(fixed: &[u8; FIXED_LEN]) -> Result<Fixed, ProxyError> {
    if fixed[..12] != SIGNATURE {
        return Err(ProxyError::Signature);
    }
    let proxied = match fixed[12] {
        0x20 => false,
        0x21 => true,
        _ => return Err(ProxyError::Version),
    };
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if FIXED_LEN + len > MAX_LEN {
        return Err(ProxyError::Length);
    }
    Ok(Fixed {
        proxied,
        family: fixed[13],
        len,
    })
}

/// The client address in the octets after the fixed part, or `None` when the header
/// carries none the server uses.
///
/// # Errors
///
/// [`ProxyError::Length`] when the octets are too short for the family.
pub fn source(fixed: &Fixed, rest: &[u8]) -> Result<Option<SocketAddr>, ProxyError> {
    if !fixed.proxied {
        return Ok(None);
    }
    match fixed.family {
        // TCP over IPv4: source and destination address, source and destination port.
        0x11 => {
            let block = rest.get(..12).ok_or(ProxyError::Length)?;
            let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        // TCP over IPv6.
        0x21 => {
            let block = rest.get(..36).ok_or(ProxyError::Length)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        _ => Ok(None),
    }
}

/// Parses a whole header at the start of `buf`: the client address (if any) and the
/// header's length.
///
/// # Errors
///
/// As [`parse_fixed`] and [`source`], and [`ProxyError::Truncated`] when `buf` ends inside
/// the header.
pub fn parse(buf: &[u8]) -> Result<(Option<SocketAddr>, usize), ProxyError> {
    let head: &[u8; FIXED_LEN] = buf
        .get(..FIXED_LEN)
        .and_then(|head| head.try_into().ok())
        .ok_or(ProxyError::Truncated)?;
    let fixed = parse_fixed(head)?;
    let rest = buf
        .get(FIXED_LEN..FIXED_LEN + fixed.len)
        .ok_or(ProxyError::Truncated)?;
    Ok((source(&fixed, rest)?, FIXED_LEN + fixed.len))
}

/// Reads a header from the start of a connection, exactly, and returns the client
/// address it carries.
///
/// # Errors
///
/// A read error, or [`ProxyError`] as an [`std::io::ErrorKind::InvalidData`] error.
pub async fn read_v2<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<SocketAddr>> {
    let invalid = |error: ProxyError| std::io::Error::new(std::io::ErrorKind::InvalidData, error);
    let mut head = [0u8; FIXED_LEN];
    stream.read_exact(&mut head).await?;
    let fixed = parse_fixed(&head).map_err(invalid)?;
    let mut rest = vec![0u8; fixed.len];
    stream.read_exact(&mut rest).await?;
    source(&fixed, &rest).map_err(invalid)
}

/// The client of an `X-Forwarded-For` value: its last entry, the address the proxy
/// itself saw (earlier entries are what the client claimed).
pub fn forwarded_for(value: &str) -> Option<IpAddr> {
    let last = value.rsplit(',').next()?.trim();
    if let Ok(address) = last.parse::<IpAddr>() {
        return Some(address);
    }
    if let Ok(address) = last.parse::<SocketAddr>() {
        return Some(address.ip());
    }
    last.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u8, family: u8, rest: &[u8]) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        out.push(command);
        out.push(family);
        out.extend_from_slice(&u16::try_from(rest.len()).expect("len").to_be_bytes());
        out.extend_from_slice(rest);
        out
    }

    #[test]
    fn a_proxy_header_gives_the_client() {
        let v4 = header(
            0x21,
            0x11,
            &[192, 0, 2, 7, 198, 51, 100, 1, 0x30, 0x39, 0x03, 0x55],
        );
        let (client, len) = parse(&v4).expect("parses");
        assert_eq!(client, Some("192.0.2.7:12345".parse().expect("address")));
        assert_eq!(len, v4.len());

        let mut block = [0u8; 36];
        block[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().expect("ip").octets());
        block[32..34].copy_from_slice(&53u16.to_be_bytes());
        let v6 = header(0x21, 0x21, &block);
        let (client, _) = parse(&v6).expect("parses");
        assert_eq!(client, Some("[2001:db8::7]:53".parse().expect("address")));

        // LOCAL, an unspecified family and TLVs after the addresses.
        assert_eq!(parse(&header(0x20, 0x00, &[])).expect("local").0, None);
        let mut with_tlv = vec![192, 0, 2, 7, 198, 51, 100, 1, 0, 1, 0, 2];
        with_tlv.extend_from_slice(&[0x04, 0x00, 0x01, 0xff]);
        assert!(
            parse(&header(0x21, 0x11, &with_tlv))
                .expect("tlv")
                .0
                .is_some()
        );
    }

    #[test]
    fn a_bad_header_is_refused() {
        assert_eq!(parse(b"PROXY TCP4 192.0.2.7"), Err(ProxyError::Signature));
        assert_eq!(
            parse(&header(0x31, 0x11, &[0; 12])),
            Err(ProxyError::Version)
        );
        assert_eq!(parse(&header(0x21, 0x11, &[0; 4])), Err(ProxyError::Length));
        let mut cut = header(0x21, 0x11, &[0; 12]);
        cut.truncate(20);
        assert_eq!(parse(&cut), Err(ProxyError::Truncated));
        let mut long = header(0x21, 0x11, &[]);
        long[14..16].copy_from_slice(&5000u16.to_be_bytes());
        assert_eq!(parse(&long), Err(ProxyError::Length));
    }

    #[test]
    fn the_last_forwarded_entry_is_the_client() {
        assert_eq!(
            forwarded_for("203.0.113.5, 192.0.2.7"),
            Some("192.0.2.7".parse().expect("ip"))
        );
        assert_eq!(
            forwarded_for("[2001:db8::7]"),
            Some("2001:db8::7".parse().expect("ip"))
        );
        assert_eq!(
            forwarded_for("192.0.2.7:4711"),
            Some("192.0.2.7".parse().expect("ip"))
        );
        assert_eq!(forwarded_for("unknown"), None);
    }
}
