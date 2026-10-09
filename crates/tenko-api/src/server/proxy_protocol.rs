//! PROXY protocol (`HAProxy` versions 1 and 2) header parsing.
//!
//! A listener that sits behind a trusted proxy learns the real client address from a small
//! header that the proxy writes before any other byte of the connection. This module provides
//! the pieces needed to consume that header safely:
//!
//! - [`detect`] classifies the first bytes of a connection as a version 1 header, a version 2
//!   header, or something else (for example a TLS `ClientHello` or an HTTP request line).
//! - [`parse`] decodes a complete header from a byte buffer.
//! - [`read_header`] reads an optional header from an async stream under a deadline and hands
//!   back every byte that was read beyond it.
//! - [`Rewind`] replays those bytes in front of the stream so the next protocol layer sees the
//!   connection exactly as if the header had never been there.
//!
//! The parser is deliberately strict about framing (length limits, field syntax, truncated
//! data) and deliberately ignorant of optional extensions: of all version 2 TLV vectors only
//! the SSL one is interpreted, and the CRC32C TLV is skipped without being verified.

use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Start of every version 1 header, including the separating space.
const V1_PREFIX: &[u8] = b"PROXY ";
/// Longest version 1 header, CRLF included.
const V1_MAX_LEN: usize = 107;
/// The 12-byte version 2 signature.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Signature, version/command byte, family byte and 16-bit length.
const V2_FIXED_LEN: usize = 16;
/// Largest accepted version 2 header, fixed part included.
const V2_MAX_LEN: usize = 4096;
/// Size of the address block of the IPv4 family.
const ADDR_LEN_INET: usize = 12;
/// Size of the address block of the IPv6 family.
const ADDR_LEN_INET6: usize = 36;
/// Size of the address block of the UNIX family.
const ADDR_LEN_UNIX: usize = 216;
/// Family and protocol byte of TCP over IPv4.
const FAMILY_TCP4: u8 = 0x11;
/// Family and protocol byte of TCP over IPv6.
const FAMILY_TCP6: u8 = 0x21;
/// TLV type that carries the TLS information of the client connection.
const PP2_TYPE_SSL: u8 = 0x20;
/// Bit of the `client` byte that says the client connected over TLS.
const PP2_CLIENT_SSL: u8 = 0x01;
/// Fixed part of the SSL TLV value: `client` (1 byte) and `verify` (4 bytes).
const PP2_SSL_MIN_LEN: usize = 5;
/// Spare capacity reserved before every read of [`read_header`].
const READ_CHUNK: usize = 1024;

/// A parsed PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeader {
    /// Protocol version of the header: 1 or 2.
    pub version: u8,
    /// Command of the header. Version 1 has no command byte, so every version 1 header
    /// (including `UNKNOWN`) is reported as [`ProxyCommand::Proxy`].
    pub command: ProxyCommand,
    /// Address of the original client. `None` for version 1 `UNKNOWN`, version 2 `LOCAL` and
    /// version 2 `UNSPEC`, UDP and UNIX families.
    pub source: Option<SocketAddr>,
    /// Address the original client connected to; `None` under the same conditions as
    /// [`ProxyHeader::source`].
    pub destination: Option<SocketAddr>,
    /// Whether the version 2 `PP2_TYPE_SSL` TLV is present with `PP2_CLIENT_SSL` set, that is,
    /// the client connection to the proxy used TLS. Never set for version 1.
    pub tls: bool,
}

/// Command of a PROXY protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyCommand {
    /// The connection was relayed on behalf of another endpoint.
    Proxy,
    /// The connection was opened by the proxy itself (for example a health check); the
    /// addresses of the socket apply.
    Local,
}

/// Result of looking at the first bytes of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// The bytes seen so far match the start of a signature but are too few to decide.
    NeedMore,
    /// The bytes cannot be the start of a PROXY protocol header.
    NotProxy,
    /// The bytes start a version 1 header.
    V1,
    /// The bytes start a version 2 header.
    V2,
}

/// Failure to obtain or decode a PROXY protocol header.
#[derive(Debug)]
pub enum ProxyError {
    /// The header is malformed; the text names the first problem found.
    Invalid(&'static str),
    /// The header exceeds the maximum length of its version.
    TooLong,
    /// No decision could be made before the deadline passed.
    Timeout,
    /// Reading from the connection failed.
    Io(io::Error),
    /// The peer closed the connection before a header (or the lack of one) was recognised.
    Closed,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid PROXY protocol header: {reason}"),
            Self::TooLong => f.write_str("PROXY protocol header is too long"),
            Self::Timeout => f.write_str("timed out waiting for the PROXY protocol header"),
            Self::Io(err) => write!(
                f,
                "I/O error while reading the PROXY protocol header: {err}"
            ),
            Self::Closed => {
                f.write_str("connection closed before the PROXY protocol header was complete")
            }
        }
    }
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// How the available bytes relate to one signature.
enum SignatureMatch {
    /// A byte differs from the signature.
    Mismatch,
    /// All bytes agree but the signature is longer than the data.
    Partial,
    /// The data starts with the whole signature.
    Complete,
}

fn match_signature(buf: &[u8], signature: &[u8]) -> SignatureMatch {
    if buf.starts_with(signature) {
        SignatureMatch::Complete
    } else if signature.starts_with(buf) {
        SignatureMatch::Partial
    } else {
        SignatureMatch::Mismatch
    }
}

/// Classifies the first bytes of a connection.
///
/// The bytes are compared incrementally against the version 1 prefix (`PROXY `) and the
/// 12-byte version 2 signature. [`Detection::NotProxy`] is returned as soon as neither
/// signature can match any more, so a TLS `ClientHello` is recognised after one byte and an
/// HTTP request line after at most three. An empty buffer yields [`Detection::NeedMore`].
pub fn detect(buf: &[u8]) -> Detection {
    match (
        match_signature(buf, &V2_SIGNATURE),
        match_signature(buf, V1_PREFIX),
    ) {
        (SignatureMatch::Complete, _) => Detection::V2,
        (_, SignatureMatch::Complete) => Detection::V1,
        (SignatureMatch::Partial, _) | (_, SignatureMatch::Partial) => Detection::NeedMore,
        (SignatureMatch::Mismatch, SignatureMatch::Mismatch) => Detection::NotProxy,
    }
}

/// Parses a complete header at the start of `buf`.
///
/// Returns `Ok(None)` when more bytes are needed and `Ok(Some((header, consumed)))` on
/// success, where `consumed` is the number of bytes the header occupies; everything after
/// that belongs to the next protocol layer.
///
/// # Errors
///
/// [`ProxyError::Invalid`] when the bytes are not a well-formed header (including the case
/// that they do not start with a signature at all) and [`ProxyError::TooLong`] when the
/// header exceeds 107 bytes (version 1) or 4,096 bytes (version 2). Errors are reported as
/// soon as the offending bytes are present, without waiting for the rest of the header.
pub fn parse(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyError> {
    match detect(buf) {
        Detection::NeedMore => Ok(None),
        Detection::NotProxy => Err(ProxyError::Invalid("not a PROXY protocol header")),
        Detection::V1 => parse_v1(buf),
        Detection::V2 => parse_v2(buf),
    }
}

fn parse_v1(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyError> {
    let window = buf.get(..V1_MAX_LEN).unwrap_or(buf);
    let Some(lf) = window.iter().position(|&byte| byte == b'\n') else {
        // A terminator would start beyond the length limit.
        return if buf.len() >= V1_MAX_LEN {
            Err(ProxyError::TooLong)
        } else {
            Ok(None)
        };
    };
    let Some((&b'\r', line)) = window[..lf].split_last() else {
        return Err(ProxyError::Invalid("line feed without carriage return"));
    };
    Ok(Some((parse_v1_line(line)?, lf + 1)))
}

/// Decodes a version 1 line without its CRLF.
fn parse_v1_line(line: &[u8]) -> Result<ProxyHeader, ProxyError> {
    let rest = line
        .strip_prefix(V1_PREFIX)
        .ok_or(ProxyError::Invalid("missing PROXY prefix"))?;
    let mut header = ProxyHeader {
        version: 1,
        command: ProxyCommand::Proxy,
        source: None,
        destination: None,
        tls: false,
    };
    // Everything after UNKNOWN is to be ignored, whatever it contains.
    if rest == b"UNKNOWN" || rest.starts_with(b"UNKNOWN ") {
        return Ok(header);
    }
    let text = std::str::from_utf8(rest)
        .ok()
        .filter(|text| text.is_ascii())
        .ok_or(ProxyError::Invalid("non-ASCII byte in header"))?;
    if text.split(' ').any(str::is_empty) {
        return Err(ProxyError::Invalid("empty field"));
    }
    let mut fields = text.split(' ');
    let protocol = fields.next().unwrap_or_default();
    if protocol != "TCP4" && protocol != "TCP6" {
        return Err(ProxyError::Invalid("unsupported protocol"));
    }
    let (Some(src), Some(dst), Some(src_port), Some(dst_port), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(ProxyError::Invalid("wrong number of fields"));
    };
    let (src_ip, dst_ip) = if protocol == "TCP4" {
        (IpAddr::V4(parse_ipv4(src)?), IpAddr::V4(parse_ipv4(dst)?))
    } else {
        (IpAddr::V6(parse_ipv6(src)?), IpAddr::V6(parse_ipv6(dst)?))
    };
    header.source = Some(SocketAddr::new(src_ip, parse_port(src_port)?));
    header.destination = Some(SocketAddr::new(dst_ip, parse_port(dst_port)?));
    Ok(header)
}

fn parse_ipv4(text: &str) -> Result<Ipv4Addr, ProxyError> {
    text.parse()
        .map_err(|_| ProxyError::Invalid("invalid IPv4 address"))
}

fn parse_ipv6(text: &str) -> Result<Ipv6Addr, ProxyError> {
    text.parse()
        .map_err(|_| ProxyError::Invalid("invalid IPv6 address"))
}

/// Parses a decimal port. Unlike `u16::from_str` this rejects a leading `+`; leading zeros
/// are accepted because the specification does not forbid them.
fn parse_port(text: &str) -> Result<u16, ProxyError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProxyError::Invalid("invalid port"));
    }
    text.parse()
        .map_err(|_| ProxyError::Invalid("port out of range"))
}

fn parse_v2(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyError> {
    // The version and command are validated as soon as their byte has arrived, so a bogus
    // header is rejected without waiting for the rest.
    let Some(&version_command) = buf.get(V2_SIGNATURE.len()) else {
        return Ok(None);
    };
    if version_command >> 4 != 2 {
        return Err(ProxyError::Invalid("unsupported PROXY protocol version"));
    }
    let command = match version_command & 0x0F {
        0x0 => ProxyCommand::Local,
        0x1 => ProxyCommand::Proxy,
        _ => return Err(ProxyError::Invalid("unsupported PROXY protocol command")),
    };
    let Some(&[_, family, len_hi, len_lo]) = buf
        .get(V2_SIGNATURE.len()..)
        .and_then(<[u8]>::first_chunk::<4>)
    else {
        return Ok(None);
    };
    let total = V2_FIXED_LEN + usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if total > V2_MAX_LEN {
        return Err(ProxyError::TooLong);
    }
    let Some(payload) = buf.get(V2_FIXED_LEN..total) else {
        return Ok(None);
    };
    Ok(Some((decode_v2_payload(command, family, payload)?, total)))
}

/// Decodes the part of a version 2 header that follows the fixed 16 bytes.
fn decode_v2_payload(
    command: ProxyCommand,
    family: u8,
    payload: &[u8],
) -> Result<ProxyHeader, ProxyError> {
    const TRUNCATED: ProxyError = ProxyError::Invalid("address block truncated");
    let mut header = ProxyHeader {
        version: 2,
        command,
        source: None,
        destination: None,
        tls: false,
    };
    // For LOCAL the family and the whole block are to be discarded.
    if command == ProxyCommand::Local {
        return Ok(header);
    }
    let block_len = match family >> 4 {
        0x0 => 0,
        0x1 => ADDR_LEN_INET,
        0x2 => ADDR_LEN_INET6,
        0x3 => ADDR_LEN_UNIX,
        _ => return Err(ProxyError::Invalid("unsupported address family")),
    };
    if family & 0x0F > 0x2 {
        return Err(ProxyError::Invalid("unsupported transport protocol"));
    }
    let Some((block, tlvs)) = payload.split_at_checked(block_len) else {
        return Err(TRUNCATED);
    };
    let addresses = match family {
        FAMILY_TCP4 => Some(decode_tcp4(block).ok_or(TRUNCATED)?),
        FAMILY_TCP6 => Some(decode_tcp6(block).ok_or(TRUNCATED)?),
        _ => None,
    };
    header.source = addresses.map(|(source, _)| source);
    header.destination = addresses.map(|(_, destination)| destination);
    header.tls = scan_tlvs(tlvs)?;
    Ok(header)
}

fn decode_tcp4(block: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let mut reader = Reader(block);
    let src = Ipv4Addr::from(reader.take::<4>()?);
    let dst = Ipv4Addr::from(reader.take::<4>()?);
    let src_port = u16::from_be_bytes(reader.take::<2>()?);
    let dst_port = u16::from_be_bytes(reader.take::<2>()?);
    Some((
        SocketAddr::new(src.into(), src_port),
        SocketAddr::new(dst.into(), dst_port),
    ))
}

fn decode_tcp6(block: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let mut reader = Reader(block);
    let src = Ipv6Addr::from(reader.take::<16>()?);
    let dst = Ipv6Addr::from(reader.take::<16>()?);
    let src_port = u16::from_be_bytes(reader.take::<2>()?);
    let dst_port = u16::from_be_bytes(reader.take::<2>()?);
    Some((
        SocketAddr::new(src.into(), src_port),
        SocketAddr::new(dst.into(), dst_port),
    ))
}

/// Walks the TLV vectors and reports whether an SSL TLV with the client bit set is present.
fn scan_tlvs(vectors: &[u8]) -> Result<bool, ProxyError> {
    const TRUNCATED: ProxyError = ProxyError::Invalid("truncated TLV");
    let mut reader = Reader(vectors);
    let mut tls = false;
    while !reader.0.is_empty() {
        let [kind] = reader.take::<1>().ok_or(TRUNCATED)?;
        let len = u16::from_be_bytes(reader.take::<2>().ok_or(TRUNCATED)?);
        let value = reader.take_slice(usize::from(len)).ok_or(TRUNCATED)?;
        if kind == PP2_TYPE_SSL {
            if value.len() < PP2_SSL_MIN_LEN {
                return Err(ProxyError::Invalid("SSL TLV too short"));
            }
            tls |= value
                .first()
                .is_some_and(|client| client & PP2_CLIENT_SSL != 0);
        }
    }
    Ok(tls)
}

/// Forward-only cursor over a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, tail) = self.0.split_first_chunk::<N>()?;
        self.0 = tail;
        Some(*head)
    }

    fn take_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }
}

/// Reads an optional PROXY protocol header from the start of `io`.
///
/// Bytes are read in chunks until the data is recognised as a version 1 or version 2 header
/// and parsed completely, or until it is known not to be a header at all. The whole loop is
/// bounded by `timeout`. Returns the header, or `None` when the connection does not start
/// with one, together with every byte that was read beyond the header (or all bytes read, for
/// `None`); replay these in front of the stream with [`Rewind`]. The amount buffered is
/// bounded by the maximum header length plus one read chunk.
///
/// When an error is returned the bytes read so far are discarded; the connection is not
/// usable for another protocol layer at that point and should be dropped.
///
/// # Errors
///
/// [`ProxyError::Timeout`] when `timeout` elapses first, [`ProxyError::Closed`] when the peer
/// closes the connection before a decision is possible (including on an empty connection),
/// [`ProxyError::Io`] when reading fails, and [`ProxyError::Invalid`] or
/// [`ProxyError::TooLong`] for a malformed header as described for [`parse`].
pub async fn read_header<IO: AsyncRead + Unpin>(
    io: &mut IO,
    timeout: Duration,
) -> Result<(Option<ProxyHeader>, Bytes), ProxyError> {
    tokio::time::timeout(timeout, read_header_inner(io))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

async fn read_header_inner<IO: AsyncRead + Unpin>(
    io: &mut IO,
) -> Result<(Option<ProxyHeader>, Bytes), ProxyError> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    loop {
        match detect(&buf) {
            Detection::NotProxy => return Ok((None, buf.freeze())),
            Detection::NeedMore => {}
            Detection::V1 | Detection::V2 => {
                if let Some((header, consumed)) = parse(&buf)? {
                    buf.advance(consumed);
                    return Ok((Some(header), buf.freeze()));
                }
            }
        }
        buf.reserve(READ_CHUNK);
        if io.read_buf(&mut buf).await.map_err(ProxyError::Io)? == 0 {
            return Err(ProxyError::Closed);
        }
    }
}

/// An I/O object that first yields a byte prefix and then reads from the wrapped object.
///
/// Writes, flushes and shutdowns go straight to the wrapped object. Used to hand the bytes
/// left over by [`read_header`] to the next protocol layer.
#[derive(Debug)]
pub struct Rewind<IO> {
    prefix: Bytes,
    inner: IO,
}

impl<IO> Rewind<IO> {
    /// Wraps `inner` so that reads return `prefix` before anything from `inner`.
    pub fn new(prefix: Bytes, inner: IO) -> Self {
        Self { prefix, inner }
    }

    /// Unwraps into the part of the prefix that has not been read yet and the inner object.
    pub fn into_inner(self) -> (Bytes, IO) {
        (self.prefix, self.inner)
    }

    /// Returns a reference to the inner object.
    pub fn inner(&self) -> &IO {
        &self.inner
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Rewind<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let len = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..len]);
            self.prefix.advance(len);
            if self.prefix.is_empty() {
                // Release the buffer the prefix was cut from.
                self.prefix = Bytes::new();
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Rewind<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSlice;

    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const SRC4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const DST4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
    const DST6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0020);

    const V1_TCP4_LINE: &[u8] = b"PROXY TCP4 192.0.2.10 198.51.100.20 51000 443\r\n";
    const HTTP1_REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: host.example\r\n\r\n";
    const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const TLS_CLIENT_HELLO: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03];

    // ---------------------------------------------------------------- helpers

    fn sock4(ip: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    fn sock6(ip: Ipv6Addr, port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    fn v2_frame_with_len(command: u8, family: u8, len: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = V2_SIGNATURE.to_vec();
        frame.push(command);
        frame.push(family);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn v2_frame(command: u8, family: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len()).unwrap();
        v2_frame_with_len(command, family, len, payload)
    }

    fn tcp4_block(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&src.octets());
        block.extend_from_slice(&dst.octets());
        block.extend_from_slice(&src_port.to_be_bytes());
        block.extend_from_slice(&dst_port.to_be_bytes());
        block
    }

    fn tcp6_block(src: Ipv6Addr, src_port: u16, dst: Ipv6Addr, dst_port: u16) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&src.octets());
        block.extend_from_slice(&dst.octets());
        block.extend_from_slice(&src_port.to_be_bytes());
        block.extend_from_slice(&dst_port.to_be_bytes());
        block
    }

    fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    /// PROXY command over TCP/IPv4 followed by the given TLV bytes.
    fn tcp4_frame(tlvs: &[u8]) -> Vec<u8> {
        let mut payload = tcp4_block(SRC4, 51000, DST4, 443);
        payload.extend_from_slice(tlvs);
        v2_frame(0x21, 0x11, &payload)
    }

    /// TCP/IPv4 frame padded with a NOOP TLV to exactly `total` bytes.
    fn padded_tcp4_frame(total: usize) -> Vec<u8> {
        let filler = vec![0xAB; total - V2_FIXED_LEN - ADDR_LEN_INET - 3];
        let frame = tcp4_frame(&tlv(0x04, &filler));
        assert_eq!(frame.len(), total);
        frame
    }

    fn line(fields: &str) -> Vec<u8> {
        format!("PROXY {fields}\r\n").into_bytes()
    }

    fn parsed(buf: &[u8]) -> (ProxyHeader, usize) {
        parse(buf).unwrap().unwrap()
    }

    fn assert_invalid(buf: &[u8], reason: &str) {
        match parse(buf) {
            Err(ProxyError::Invalid(actual)) => assert_eq!(actual, reason, "input {buf:?}"),
            other => panic!("expected Invalid({reason}) for {buf:?}, got {other:?}"),
        }
    }

    fn assert_too_long(buf: &[u8]) {
        assert!(
            matches!(parse(buf), Err(ProxyError::TooLong)),
            "input of {} bytes",
            buf.len()
        );
    }

    fn proxy_v1(source: Option<SocketAddr>, destination: Option<SocketAddr>) -> ProxyHeader {
        ProxyHeader {
            version: 1,
            command: ProxyCommand::Proxy,
            source,
            destination,
            tls: false,
        }
    }

    fn proxy_v2(source: Option<SocketAddr>, destination: Option<SocketAddr>) -> ProxyHeader {
        ProxyHeader {
            version: 2,
            command: ProxyCommand::Proxy,
            source,
            destination,
            tls: false,
        }
    }

    /// Reader that hands out at most `chunk` bytes per read and reports end of stream once
    /// the data is used up.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = &mut *self;
            let len = this
                .chunk
                .min(buf.remaining())
                .min(this.data.len() - this.pos);
            buf.put_slice(&this.data[this.pos..this.pos + len]);
            this.pos += len;
            Poll::Ready(Ok(()))
        }
    }

    /// Reader whose every read fails.
    struct Failing;

    impl AsyncRead for Failing {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "reset by peer",
            )))
        }
    }

    async fn read_chunked(
        data: &[u8],
        chunk: usize,
    ) -> Result<(Option<ProxyHeader>, Bytes), ProxyError> {
        let mut io = Trickle {
            data: data.to_vec(),
            pos: 0,
            chunk,
        };
        read_header(&mut io, Duration::from_secs(5)).await
    }

    async fn read_all_at_once(data: &[u8]) -> Result<(Option<ProxyHeader>, Bytes), ProxyError> {
        read_chunked(data, usize::MAX).await
    }

    // ----------------------------------------------------------------- detect

    #[test]
    fn detect_empty_input_needs_more() {
        assert_eq!(detect(b""), Detection::NeedMore);
    }

    #[test]
    fn detect_partial_v1_prefix_needs_more() {
        for len in 0..V1_PREFIX.len() {
            assert_eq!(
                detect(&V1_PREFIX[..len]),
                Detection::NeedMore,
                "{len} bytes"
            );
        }
        assert_eq!(detect(V1_PREFIX), Detection::V1);
        assert_eq!(detect(V1_TCP4_LINE), Detection::V1);
    }

    #[test]
    fn detect_partial_v2_signature_needs_more() {
        for len in 0..V2_SIGNATURE.len() {
            assert_eq!(
                detect(&V2_SIGNATURE[..len]),
                Detection::NeedMore,
                "{len} bytes"
            );
        }
        assert_eq!(detect(&V2_SIGNATURE), Detection::V2);
        assert_eq!(detect(&tcp4_frame(&[])), Detection::V2);
    }

    #[test]
    fn detect_recognises_other_protocols() {
        let samples: [&[u8]; 17] = [
            b"GET ",
            b"GET / HTTP/1.1\r\n",
            b"POST /submit HTTP/1.1\r\n",
            b"PUT /item HTTP/1.1\r\n",
            b"PATCH /item HTTP/1.1\r\n",
            b"DELETE /item HTTP/1.1\r\n",
            b"HEAD / HTTP/1.1\r\n",
            b"OPTIONS * HTTP/1.1\r\n",
            HTTP2_PREFACE,
            TLS_CLIENT_HELLO,
            &[0x16],
            &[0x80, 0x2E, 0x01],
            b"proxy TCP4 192.0.2.10 198.51.100.20 51000 443\r\n",
            b"PROXY\r\n",
            b"PROXYTCP4",
            b"\r\nGET / HTTP/1.1\r\n",
            &[
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0B,
            ],
        ];
        for sample in samples {
            assert_eq!(detect(sample), Detection::NotProxy, "{sample:?}");
        }
    }

    #[test]
    fn detect_decides_at_the_first_mismatching_byte() {
        assert_eq!(detect(b"P"), Detection::NeedMore);
        assert_eq!(detect(b"PR"), Detection::NeedMore);
        assert_eq!(detect(b"PRI"), Detection::NotProxy);
        assert_eq!(detect(b"PO"), Detection::NotProxy);
        assert_eq!(detect(b"PUT"), Detection::NotProxy);
        assert_eq!(detect(b"PA"), Detection::NotProxy);
        assert_eq!(detect(b"G"), Detection::NotProxy);
        assert_eq!(detect(&[0x16]), Detection::NotProxy);
        assert_eq!(detect(&[0x0D, 0x0A]), Detection::NeedMore);
        assert_eq!(detect(&[0x0D, 0x0A, b'G']), Detection::NotProxy);
    }

    #[test]
    fn detect_looks_only_at_the_signature() {
        let mut data = V2_SIGNATURE.to_vec();
        data.extend_from_slice(b"anything at all");
        assert_eq!(detect(&data), Detection::V2);
        assert_eq!(detect(b"PROXY and then whatever"), Detection::V1);
    }

    #[test]
    fn parse_requires_a_signature() {
        assert!(matches!(parse(b""), Ok(None)));
        assert!(matches!(parse(b"PRO"), Ok(None)));
        assert_invalid(b"GET / HTTP/1.1\r\n", "not a PROXY protocol header");
        assert_invalid(TLS_CLIENT_HELLO, "not a PROXY protocol header");
    }

    // --------------------------------------------------------------- version 1

    #[test]
    fn v1_tcp4() {
        let (header, consumed) = parsed(V1_TCP4_LINE);
        assert_eq!(
            header,
            proxy_v1(Some(sock4(SRC4, 51000)), Some(sock4(DST4, 443))),
        );
        assert_eq!(consumed, V1_TCP4_LINE.len());
    }

    #[test]
    fn v1_tcp6() {
        let (header, consumed) = parsed(&line("TCP6 2001:db8::10 2001:db8::20 40000 8443"));
        assert_eq!(
            header,
            proxy_v1(Some(sock6(SRC6, 40000)), Some(sock6(DST6, 8443))),
        );
        assert_eq!(consumed, 49);
    }

    #[test]
    fn v1_tcp6_accepts_long_form_and_upper_case() {
        let long = line("TCP6 2001:0db8:0000:0000:0000:0000:0000:0010 2001:DB8::20 1 2");
        let (header, _) = parsed(&long);
        assert_eq!(header, proxy_v1(Some(sock6(SRC6, 1)), Some(sock6(DST6, 2))));
    }

    #[test]
    fn v1_unknown_has_no_addresses() {
        let bare = b"PROXY UNKNOWN\r\n";
        let (header, consumed) = parsed(bare);
        assert_eq!(header, proxy_v1(None, None));
        assert_eq!(consumed, bare.len());
    }

    #[test]
    fn v1_unknown_ignores_whatever_follows() {
        for text in [
            &b"PROXY UNKNOWN 192.0.2.10 198.51.100.20 51000 443\r\n"[..],
            b"PROXY UNKNOWN 2001:db8::10 2001:db8::20 1 2\r\n",
            b"PROXY UNKNOWN anything at all\r\n",
            b"PROXY UNKNOWN \xFF\xFE binary\r\n",
            b"PROXY UNKNOWN \r\n",
        ] {
            let (header, consumed) = parsed(text);
            assert_eq!(header, proxy_v1(None, None), "{text:?}");
            assert_eq!(consumed, text.len());
        }
    }

    #[test]
    fn v1_never_reports_tls() {
        assert!(!parsed(V1_TCP4_LINE).0.tls);
        assert!(!parsed(b"PROXY UNKNOWN\r\n").0.tls);
    }

    #[test]
    fn v1_consumes_only_the_header() {
        let mut data = V1_TCP4_LINE.to_vec();
        data.extend_from_slice(HTTP1_REQUEST);
        let (header, consumed) = parsed(&data);
        assert_eq!(consumed, V1_TCP4_LINE.len());
        assert_eq!(header.source, Some(sock4(SRC4, 51000)));
        assert_eq!(&data[consumed..], HTTP1_REQUEST);

        let mut data = b"PROXY UNKNOWN\r\n".to_vec();
        data.extend_from_slice(TLS_CLIENT_HELLO);
        assert_eq!(parsed(&data).1, 15);
    }

    #[test]
    fn v1_needs_more_until_the_line_feed_arrives() {
        for len in 0..V1_TCP4_LINE.len() {
            assert!(
                matches!(parse(&V1_TCP4_LINE[..len]), Ok(None)),
                "{len} bytes"
            );
        }
        assert!(parse(V1_TCP4_LINE).unwrap().is_some());
    }

    #[test]
    fn v1_ports_cover_the_full_range_and_allow_leading_zeros() {
        let (header, _) = parsed(&line("TCP4 192.0.2.10 198.51.100.20 0 65535"));
        assert_eq!(header.source, Some(sock4(SRC4, 0)));
        assert_eq!(header.destination, Some(sock4(DST4, 65535)));

        let (header, _) = parsed(&line("TCP4 192.0.2.10 198.51.100.20 0051000 00443"));
        assert_eq!(header.source, Some(sock4(SRC4, 51000)));
        assert_eq!(header.destination, Some(sock4(DST4, 443)));

        let (header, _) = parsed(&line("TCP4 192.0.2.10 198.51.100.20 0000000000000 007"));
        assert_eq!(header.source, Some(sock4(SRC4, 0)));
        assert_eq!(header.destination, Some(sock4(DST4, 7)));
    }

    /// `PROXY UNKNOWN ` padded with filler to `total` bytes including the CRLF.
    fn unknown_line(total: usize) -> Vec<u8> {
        let mut out = b"PROXY UNKNOWN ".to_vec();
        out.resize(total - 2, b'x');
        out.extend_from_slice(b"\r\n");
        out
    }

    #[test]
    fn v1_accepts_exactly_107_bytes() {
        let data = unknown_line(107);
        assert_eq!(data.len(), 107);
        let (header, consumed) = parsed(&data);
        assert_eq!(header, proxy_v1(None, None));
        assert_eq!(consumed, 107);
    }

    #[test]
    fn v1_rejects_108_bytes_even_with_crlf() {
        assert_too_long(&unknown_line(108));
        assert_too_long(&unknown_line(300));
    }

    #[test]
    fn v1_without_crlf_is_too_long_from_107_bytes() {
        let mut data = b"PROXY ".to_vec();
        data.resize(106, b'a');
        assert!(matches!(parse(&data), Ok(None)));
        data.push(b'a');
        assert_eq!(data.len(), 107);
        assert_too_long(&data);
        data.resize(4096, b'a');
        assert_too_long(&data);
    }

    #[test]
    fn v1_cr_at_the_limit_does_not_extend_it() {
        // 106 bytes, a CR as byte 107 and the LF as byte 108: one byte too many.
        let mut data = b"PROXY UNKNOWN ".to_vec();
        data.resize(106, b'x');
        data.extend_from_slice(b"\r\n");
        assert_eq!(data.len(), 108);
        assert_too_long(&data);
    }

    #[test]
    fn v1_malformed_lines_are_invalid() {
        let cases = [
            ("", "empty field"),
            ("TCP4", "wrong number of fields"),
            (
                "TCP4 192.0.2.10 198.51.100.20 51000",
                "wrong number of fields",
            ),
            (
                "TCP4 192.0.2.10 198.51.100.20 51000 443 7",
                "wrong number of fields",
            ),
            ("TCP4  192.0.2.10 198.51.100.20 51000 443", "empty field"),
            ("TCP4 192.0.2.10 198.51.100.20 51000 443 ", "empty field"),
            (" TCP4 192.0.2.10 198.51.100.20 51000 443", "empty field"),
            (
                "UDP4 192.0.2.10 198.51.100.20 51000 443",
                "unsupported protocol",
            ),
            (
                "tcp4 192.0.2.10 198.51.100.20 51000 443",
                "unsupported protocol",
            ),
            (
                "TCP 192.0.2.10 198.51.100.20 51000 443",
                "unsupported protocol",
            ),
            ("UNKNOWNX", "unsupported protocol"),
            (
                "TCP4 192.0.2.256 198.51.100.20 51000 443",
                "invalid IPv4 address",
            ),
            (
                "TCP4 192.0.2 198.51.100.20 51000 443",
                "invalid IPv4 address",
            ),
            (
                "TCP4 192.000.002.010 198.51.100.20 51000 443",
                "invalid IPv4 address",
            ),
            (
                "TCP4 2001:db8::10 198.51.100.20 51000 443",
                "invalid IPv4 address",
            ),
            (
                "TCP4 192.0.2.10 2001:db8::20 51000 443",
                "invalid IPv4 address",
            ),
            (
                "TCP6 192.0.2.10 198.51.100.20 51000 443",
                "invalid IPv6 address",
            ),
            (
                "TCP6 2001:db8::10 2001:db8::g 51000 443",
                "invalid IPv6 address",
            ),
            (
                "TCP6 2001:db8::10%eth0 2001:db8::20 51000 443",
                "invalid IPv6 address",
            ),
            (
                "TCP4 192.0.2.10 198.51.100.20 65536 443",
                "port out of range",
            ),
            (
                "TCP4 192.0.2.10 198.51.100.20 51000 99999999999999999999",
                "port out of range",
            ),
            ("TCP4 192.0.2.10 198.51.100.20 +51000 443", "invalid port"),
            ("TCP4 192.0.2.10 198.51.100.20 51000 -1", "invalid port"),
            ("TCP4 192.0.2.10 198.51.100.20 51000 44a", "invalid port"),
            ("TCP4 192.0.2.10 198.51.100.20 0x50 443", "invalid port"),
            ("TCP4 192.0.2.10 198.51.100.20 51000 4.43", "invalid port"),
        ];
        for (fields, reason) in cases {
            assert_invalid(&line(fields), reason);
        }
    }

    #[test]
    fn v1_malformed_framing_is_invalid() {
        assert_invalid(
            b"PROXY TCP4 192.0.2.10 198.51.100.20 51000 443\n",
            "line feed without carriage return",
        );
        assert_invalid(
            b"PROXY TCP4 192.0.2.10\n198.51.100.20 51000 443\r\n",
            "line feed without carriage return",
        );
        assert_invalid(b"PROXY UNKNOWN\n", "line feed without carriage return");
        assert_invalid(
            b"PROXY TCP4 192.0.2.10 198.51.100.20 51000 443\r\r\n",
            "invalid port",
        );
        assert_invalid(
            b"PROXY TCP4 192.0.2.10 198.51.100.20 51000 \xC3\xA9\r\n",
            "non-ASCII byte in header",
        );
        assert_invalid(b"PROXY TCP4 \xFF\r\n", "non-ASCII byte in header");
    }

    // --------------------------------------------------------------- version 2

    #[test]
    fn v2_proxy_tcp4_built_byte_by_byte() {
        let frame = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // signature
            0x21, // version 2, command PROXY
            0x11, // TCP over IPv4
            0x00, 0x0C, // 12 bytes follow
            192, 0, 2, 10, // source address
            198, 51, 100, 20, // destination address
            0xC7, 0x38, // source port 51000
            0x01, 0xBB, // destination port 443
        ];
        let (header, consumed) = parsed(&frame);
        assert_eq!(
            header,
            proxy_v2(Some(sock4(SRC4, 51000)), Some(sock4(DST4, 443)))
        );
        assert_eq!(consumed, 28);
        assert_eq!(tcp4_frame(&[]), frame);
    }

    #[test]
    fn v2_proxy_tcp6_built_byte_by_byte() {
        let frame = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // signature
            0x21, // version 2, command PROXY
            0x21, // TCP over IPv6
            0x00, 0x24, // 36 bytes follow
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00,
            0x10, // source address
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x20, // destination
            0x9C, 0x40, // source port 40000
            0x20, 0xFB, // destination port 8443
        ];
        let (header, consumed) = parsed(&frame);
        assert_eq!(
            header,
            proxy_v2(Some(sock6(SRC6, 40000)), Some(sock6(DST6, 8443)))
        );
        assert_eq!(consumed, 52);
        assert_eq!(
            v2_frame(0x21, 0x21, &tcp6_block(SRC6, 40000, DST6, 8443)),
            frame
        );
    }

    #[test]
    fn v2_local_has_no_addresses() {
        let frame = v2_frame(0x20, 0x00, &[]);
        let (header, consumed) = parsed(&frame);
        assert_eq!(
            header,
            ProxyHeader {
                version: 2,
                command: ProxyCommand::Local,
                source: None,
                destination: None,
                tls: false,
            }
        );
        assert_eq!(consumed, 16);
    }

    #[test]
    fn v2_local_ignores_an_address_block() {
        let frame = v2_frame(0x20, 0x11, &tcp4_block(SRC4, 51000, DST4, 443));
        let (header, consumed) = parsed(&frame);
        assert_eq!(header.command, ProxyCommand::Local);
        assert_eq!((header.source, header.destination), (None, None));
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn v2_local_discards_family_and_payload() {
        // The family of a LOCAL header is to be ignored, and so is whatever follows it.
        let frame = v2_frame(0x20, 0x7F, &[0xFF; 10]);
        let (header, consumed) = parsed(&frame);
        assert_eq!(header.command, ProxyCommand::Local);
        assert_eq!(
            (header.source, header.destination, header.tls),
            (None, None, false)
        );
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn v2_local_never_reports_tls() {
        let frame = v2_frame(0x20, 0x00, &tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        assert!(!parsed(&frame).0.tls);
    }

    #[test]
    fn v2_unspec_has_no_addresses() {
        let frame = v2_frame(0x21, 0x00, &[]);
        let (header, consumed) = parsed(&frame);
        assert_eq!(header, proxy_v2(None, None));
        assert_eq!(consumed, 16);
    }

    #[test]
    fn v2_unspec_still_carries_tlvs() {
        let frame = v2_frame(0x21, 0x00, &tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        let (header, _) = parsed(&frame);
        assert_eq!((header.source, header.destination), (None, None));
        assert!(header.tls);
    }

    #[test]
    fn v2_udp_and_unix_families_have_no_addresses() {
        let cases: [(u8, usize); 4] = [(0x12, 12), (0x22, 36), (0x31, 216), (0x32, 216)];
        for (family, block_len) in cases {
            let frame = v2_frame(0x21, family, &vec![0x5A; block_len]);
            let (header, consumed) = parsed(&frame);
            assert_eq!(header, proxy_v2(None, None), "family {family:#04x}");
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn v2_tlvs_follow_the_block_of_any_family() {
        let mut payload = vec![0x5A; 216];
        payload.extend_from_slice(&tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        let (header, _) = parsed(&v2_frame(0x21, 0x31, &payload));
        assert_eq!((header.source, header.destination), (None, None));
        assert!(header.tls);
    }

    #[test]
    fn v2_ssl_tlv_with_client_bit_sets_tls() {
        let frame = tcp4_frame(&tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        let (header, consumed) = parsed(&frame);
        assert!(header.tls);
        assert_eq!(header.source, Some(sock4(SRC4, 51000)));
        assert_eq!(consumed, frame.len());

        // Other bits may accompany the SSL bit.
        assert!(
            parsed(&tcp4_frame(&tlv(PP2_TYPE_SSL, &[0x07, 0, 0, 0, 0])))
                .0
                .tls
        );
    }

    #[test]
    fn v2_ssl_tlv_without_client_bit_leaves_tls_unset() {
        for client in [0x00, 0x02, 0x04, 0x06, 0xFE] {
            let frame = tcp4_frame(&tlv(PP2_TYPE_SSL, &[client, 0, 0, 0, 0]));
            assert!(!parsed(&frame).0.tls, "client byte {client:#04x}");
        }
    }

    #[test]
    fn v2_ssl_tlv_may_carry_sub_tlvs() {
        let mut value = vec![0x01, 0, 0, 0, 0];
        value.extend_from_slice(&tlv(0x21, b"TLSv1.3"));
        value.extend_from_slice(&tlv(0x22, b"host.example"));
        assert!(parsed(&tcp4_frame(&tlv(PP2_TYPE_SSL, &value))).0.tls);
    }

    #[test]
    fn v2_unrelated_tlvs_are_ignored() {
        let mut tlvs = Vec::new();
        tlvs.extend_from_slice(&tlv(0x01, b"h2"));
        tlvs.extend_from_slice(&tlv(0x02, b"host.example"));
        tlvs.extend_from_slice(&tlv(0x03, &[0xDE, 0xAD, 0xBE, 0xEF]));
        tlvs.extend_from_slice(&tlv(0x04, &[]));
        tlvs.extend_from_slice(&tlv(0x05, b"unique-id"));
        tlvs.extend_from_slice(&tlv(0x30, b"netns"));
        tlvs.extend_from_slice(&tlv(0xEE, &[1, 2, 3]));
        let frame = tcp4_frame(&tlvs);
        let (header, consumed) = parsed(&frame);
        assert_eq!(
            header,
            proxy_v2(Some(sock4(SRC4, 51000)), Some(sock4(DST4, 443)))
        );
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn v2_ssl_tlv_is_found_among_others() {
        let mut tlvs = Vec::new();
        tlvs.extend_from_slice(&tlv(0x01, b"h2"));
        tlvs.extend_from_slice(&tlv(0x04, &[0; 7]));
        tlvs.extend_from_slice(&tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        tlvs.extend_from_slice(&tlv(0x03, &[0; 4]));
        assert!(parsed(&tcp4_frame(&tlvs)).0.tls);
    }

    #[test]
    fn v2_consumes_only_the_header() {
        let frame = tcp4_frame(&tlv(0x04, &[0; 3]));
        let mut data = frame.clone();
        data.extend_from_slice(TLS_CLIENT_HELLO);
        let (header, consumed) = parsed(&data);
        assert_eq!(consumed, frame.len());
        assert_eq!(&data[consumed..], TLS_CLIENT_HELLO);
        assert_eq!(header.destination, Some(sock4(DST4, 443)));
    }

    #[test]
    fn v2_needs_more_until_the_declared_length_is_present() {
        let frame = tcp4_frame(&tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        for len in 0..frame.len() {
            assert!(matches!(parse(&frame[..len]), Ok(None)), "{len} bytes");
        }
        let (header, consumed) = parsed(&frame);
        assert!(header.tls);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn v2_truncated_tlv_is_invalid() {
        let cases: [&[u8]; 4] = [
            &[0x04],
            &[0x04, 0x00],
            &[0x04, 0x00, 0x05, b'a'],
            &[0x04, 0x00, 0x00, 0x05, 0x00],
        ];
        for tlvs in cases {
            assert_invalid(&tcp4_frame(tlvs), "truncated TLV");
        }
        // A good TLV followed by a cut-off one.
        let mut tlvs = tlv(0x01, b"h2");
        tlvs.extend_from_slice(&[0x02, 0x00, 0x08, b'h']);
        assert_invalid(&tcp4_frame(&tlvs), "truncated TLV");
    }

    #[test]
    fn v2_short_ssl_tlv_is_invalid() {
        for len in 0..PP2_SSL_MIN_LEN {
            let value = vec![0x01; len];
            assert_invalid(&tcp4_frame(&tlv(PP2_TYPE_SSL, &value)), "SSL TLV too short");
        }
    }

    #[test]
    fn v2_bad_version_is_invalid() {
        for byte in [0x00, 0x01, 0x10, 0x11, 0x31, 0xF1] {
            let mut frame = tcp4_frame(&[]);
            frame[12] = byte;
            assert_invalid(&frame, "unsupported PROXY protocol version");
        }
    }

    #[test]
    fn v2_bad_command_is_invalid() {
        for byte in [0x22, 0x23, 0x2F] {
            let mut frame = tcp4_frame(&[]);
            frame[12] = byte;
            assert_invalid(&frame, "unsupported PROXY protocol command");
        }
    }

    #[test]
    fn v2_version_and_command_are_checked_before_the_rest_arrives() {
        let mut data = V2_SIGNATURE.to_vec();
        assert!(matches!(parse(&data), Ok(None)));
        data.push(0x11);
        assert_invalid(&data, "unsupported PROXY protocol version");
        data.pop();
        data.push(0x25);
        assert_invalid(&data, "unsupported PROXY protocol command");
        data.pop();
        data.push(0x21);
        assert!(matches!(parse(&data), Ok(None)));
    }

    #[test]
    fn v2_unassigned_family_or_protocol_is_invalid() {
        for family in [0x41, 0x51, 0xF1] {
            assert_invalid(
                &v2_frame(0x21, family, &[0; 12]),
                "unsupported address family",
            );
        }
        for family in [0x03, 0x13, 0x23, 0x33, 0x1F] {
            assert_invalid(
                &v2_frame(0x21, family, &[0; 12]),
                "unsupported transport protocol",
            );
        }
    }

    #[test]
    fn v2_length_shorter_than_the_address_block_is_invalid() {
        let cases: [(u8, usize); 8] = [
            (0x11, 0),
            (0x11, 11),
            (0x12, 11),
            (0x21, 12),
            (0x21, 35),
            (0x22, 35),
            (0x31, 215),
            (0x32, 0),
        ];
        for (family, len) in cases {
            let frame = v2_frame(0x21, family, &vec![0; len]);
            assert_invalid(&frame, "address block truncated");
        }
    }

    #[test]
    fn v2_accepts_exactly_4096_bytes() {
        let frame = padded_tcp4_frame(4096);
        let (header, consumed) = parsed(&frame);
        assert_eq!(consumed, 4096);
        assert_eq!(header.source, Some(sock4(SRC4, 51000)));
    }

    #[test]
    fn v2_rejects_more_than_4096_bytes() {
        assert_too_long(&padded_tcp4_frame(4097));
        assert_too_long(&padded_tcp4_frame(5000));
    }

    #[test]
    fn v2_oversized_length_is_rejected_before_the_body_arrives() {
        // Only the 16 fixed bytes are present, yet the declared length already decides.
        assert_too_long(&v2_frame_with_len(0x21, 0x11, 0xFFFF, &[]));
        assert_too_long(&v2_frame_with_len(0x21, 0x11, 4081, &[]));
        assert_too_long(&v2_frame_with_len(0x20, 0x00, 4081, &[]));
        assert!(matches!(
            parse(&v2_frame_with_len(0x21, 0x11, 4080, &[])),
            Ok(None)
        ));
    }

    // ------------------------------------------------------------- read_header

    #[tokio::test]
    async fn read_header_v1_one_byte_at_a_time() {
        let (header, rest) = read_chunked(V1_TCP4_LINE, 1).await.unwrap();
        assert_eq!(
            header,
            Some(proxy_v1(Some(sock4(SRC4, 51000)), Some(sock4(DST4, 443)))),
        );
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn read_header_v2_one_byte_at_a_time() {
        let frame = tcp4_frame(&tlv(PP2_TYPE_SSL, &[0x01, 0, 0, 0, 0]));
        let (header, rest) = read_chunked(&frame, 1).await.unwrap();
        let header = header.unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.source, Some(sock4(SRC4, 51000)));
        assert!(header.tls);
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn read_header_v1_one_byte_at_a_time_unknown() {
        let (header, rest) = read_chunked(b"PROXY UNKNOWN\r\n", 1).await.unwrap();
        assert_eq!(header, Some(proxy_v1(None, None)));
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn read_header_v1_returns_leftover_bytes() {
        let mut data = V1_TCP4_LINE.to_vec();
        data.extend_from_slice(HTTP1_REQUEST);
        let (header, rest) = read_all_at_once(&data).await.unwrap();
        assert_eq!(header.unwrap().destination, Some(sock4(DST4, 443)));
        assert_eq!(&rest[..], HTTP1_REQUEST);
    }

    #[tokio::test]
    async fn read_header_v2_returns_leftover_bytes() {
        let mut data = tcp6_frame_bytes();
        data.extend_from_slice(TLS_CLIENT_HELLO);
        let (header, rest) = read_all_at_once(&data).await.unwrap();
        assert_eq!(
            header,
            Some(proxy_v2(Some(sock6(SRC6, 40000)), Some(sock6(DST6, 8443)))),
        );
        assert_eq!(&rest[..], TLS_CLIENT_HELLO);
    }

    fn tcp6_frame_bytes() -> Vec<u8> {
        v2_frame(0x21, 0x21, &tcp6_block(SRC6, 40000, DST6, 8443))
    }

    #[tokio::test]
    async fn read_header_odd_chunk_sizes_never_lose_bytes() {
        let mut data = V1_TCP4_LINE.to_vec();
        data.extend_from_slice(HTTP1_REQUEST);
        for chunk in [2, 3, 7, 10, 47, 48, 49, 64] {
            let (header, rest) = read_chunked(&data, chunk).await.unwrap();
            assert!(header.is_some(), "chunk {chunk}");
            assert!(HTTP1_REQUEST.starts_with(&rest), "chunk {chunk}");
            assert!(rest.len() < chunk, "chunk {chunk}");
        }
    }

    #[tokio::test]
    async fn read_header_reassembles_a_maximum_size_header() {
        let mut data = padded_tcp4_frame(4096);
        data.extend_from_slice(b"GET / HTTP/1.1\r\n");
        for chunk in [1000, 1024, 4096] {
            let (header, rest) = read_chunked(&data, chunk).await.unwrap();
            assert_eq!(
                header.unwrap().source,
                Some(sock4(SRC4, 51000)),
                "chunk {chunk}"
            );
            assert!(b"GET / HTTP/1.1\r\n".starts_with(&rest), "chunk {chunk}");
        }
    }

    #[tokio::test]
    async fn read_header_returns_non_proxy_bytes_intact() {
        for sample in [TLS_CLIENT_HELLO, HTTP1_REQUEST, HTTP2_PREFACE] {
            let (header, rest) = read_all_at_once(sample).await.unwrap();
            assert_eq!(header, None);
            assert_eq!(&rest[..], sample);
        }
    }

    #[tokio::test]
    async fn read_header_decides_non_proxy_after_the_first_mismatch() {
        let (header, rest) = read_chunked(TLS_CLIENT_HELLO, 1).await.unwrap();
        assert_eq!((header, &rest[..]), (None, &[0x16][..]));
        let (header, rest) = read_chunked(HTTP1_REQUEST, 1).await.unwrap();
        assert_eq!((header, &rest[..]), (None, &b"G"[..]));
        let (header, rest) = read_chunked(HTTP2_PREFACE, 1).await.unwrap();
        assert_eq!((header, &rest[..]), (None, &b"PRI"[..]));
    }

    #[tokio::test]
    async fn read_header_does_not_need_end_of_stream_for_non_proxy() {
        let (mut client, mut server) = duplex(4096);
        client.write_all(HTTP1_REQUEST).await.unwrap();
        let (header, rest) = read_header(&mut server, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(header, None);
        assert_eq!(&rest[..], HTTP1_REQUEST);
    }

    #[tokio::test]
    async fn read_header_short_non_proxy_stream_is_not_an_eof_error() {
        let (header, rest) = read_all_at_once(b"GET").await.unwrap();
        assert_eq!((header, &rest[..]), (None, &b"GET"[..]));
    }

    async fn replay(sample: &[u8]) -> Vec<u8> {
        let (mut client, mut server) = duplex(16 * 1024);
        client.write_all(sample).await.unwrap();
        client.shutdown().await.unwrap();
        let (header, prefix) = read_header(&mut server, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(header, None);
        let mut stream = Rewind::new(prefix, server);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        all
    }

    #[tokio::test]
    async fn non_proxy_stream_is_replayed_unchanged() {
        for sample in [TLS_CLIENT_HELLO, HTTP1_REQUEST, HTTP2_PREFACE] {
            assert_eq!(replay(sample).await, sample);
        }
    }

    #[tokio::test]
    async fn bytes_beyond_the_header_are_replayed_unchanged() {
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(5000).collect();
        let mut stream = tcp4_frame(&tlv(0x04, &[0; 9]));
        stream.extend_from_slice(&body);

        let (mut client, mut server) = duplex(16 * 1024);
        client.write_all(&stream).await.unwrap();
        client.shutdown().await.unwrap();
        let (header, prefix) = read_header(&mut server, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(header.is_some());
        let mut replayed = Rewind::new(prefix, server);
        let mut all = Vec::new();
        replayed.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, body);
    }

    #[tokio::test]
    async fn read_header_works_with_a_slowly_written_stream() {
        let (mut client, mut server) = duplex(64);
        let writer = tokio::spawn(async move {
            for &byte in V1_TCP4_LINE {
                client.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            client.write_all(b"GET /").await.unwrap();
            client
        });
        let (header, rest) = read_header(&mut server, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(header.unwrap().source, Some(sock4(SRC4, 51000)));
        assert!(rest.len() <= 5);
        let _client = writer.await.unwrap();
    }

    #[tokio::test]
    async fn read_header_times_out_when_the_writer_stalls() {
        let (_client, mut server) = duplex(64);
        let result = read_header(&mut server, Duration::from_millis(50)).await;
        assert!(matches!(result, Err(ProxyError::Timeout)), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_times_out_in_the_middle_of_a_header() {
        let (mut client, mut server) = duplex(64);
        client.write_all(b"PROXY TCP4 192.0.2.10 ").await.unwrap();
        let result = read_header(&mut server, Duration::from_millis(50)).await;
        assert!(matches!(result, Err(ProxyError::Timeout)), "{result:?}");

        let (mut client, mut server) = duplex(64);
        client.write_all(&tcp4_frame(&[])[..20]).await.unwrap();
        let result = read_header(&mut server, Duration::from_millis(50)).await;
        assert!(matches!(result, Err(ProxyError::Timeout)), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_reports_closed_on_an_empty_connection() {
        let (client, mut server) = duplex(64);
        drop(client);
        let result = read_header(&mut server, Duration::from_secs(5)).await;
        assert!(matches!(result, Err(ProxyError::Closed)), "{result:?}");

        let result = read_all_at_once(b"").await;
        assert!(matches!(result, Err(ProxyError::Closed)), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_reports_closed_when_the_peer_leaves_mid_header() {
        for data in [&b"PROX"[..], b"PROXY TCP4 192.0.2.10 198.51.100.20 51000"] {
            let result = read_all_at_once(data).await;
            assert!(
                matches!(result, Err(ProxyError::Closed)),
                "{data:?}: {result:?}"
            );
        }
        let frame = tcp4_frame(&[]);
        let result = read_all_at_once(&frame[..frame.len() - 1]).await;
        assert!(matches!(result, Err(ProxyError::Closed)), "{result:?}");
        let result = read_all_at_once(&V2_SIGNATURE[..5]).await;
        assert!(matches!(result, Err(ProxyError::Closed)), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_propagates_parse_errors() {
        let result = read_all_at_once(&line("TCP4 192.0.2.256 198.51.100.20 1 2")).await;
        assert!(
            matches!(result, Err(ProxyError::Invalid("invalid IPv4 address"))),
            "{result:?}"
        );

        let mut frame = tcp4_frame(&[]);
        frame[12] = 0x11;
        let result = read_chunked(&frame, 1).await;
        assert!(matches!(result, Err(ProxyError::Invalid(_))), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_stops_reading_for_oversized_headers() {
        let mut v1 = b"PROXY ".to_vec();
        v1.resize(600, b'a');
        let result = read_all_at_once(&v1).await;
        assert!(matches!(result, Err(ProxyError::TooLong)), "{result:?}");

        let result = read_chunked(&v2_frame_with_len(0x21, 0x11, 5000, &[]), 1).await;
        assert!(matches!(result, Err(ProxyError::TooLong)), "{result:?}");
    }

    #[tokio::test]
    async fn read_header_reports_io_errors() {
        let result = read_header(&mut Failing, Duration::from_secs(5)).await;
        match result {
            Err(ProxyError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------ Rewind

    #[tokio::test]
    async fn rewind_yields_the_prefix_then_the_inner_bytes() {
        let mut stream = Rewind::new(Bytes::from_static(b"hello "), &b"world"[..]);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"hello world");
    }

    #[tokio::test]
    async fn rewind_small_reads_do_not_merge_prefix_and_inner() {
        let mut stream = Rewind::new(Bytes::from_static(b"hello "), &b"world"[..]);
        let mut buf = [0_u8; 4];
        let mut pieces = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            pieces.push(buf[..n].to_vec());
        }
        let expected: Vec<Vec<u8>> = vec![
            b"hell".to_vec(),
            b"o ".to_vec(),
            b"worl".to_vec(),
            b"d".to_vec(),
        ];
        assert_eq!(pieces, expected);
    }

    #[tokio::test]
    async fn rewind_with_an_empty_prefix_is_transparent() {
        let mut stream = Rewind::new(Bytes::new(), &b"payload"[..]);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"payload");
    }

    #[tokio::test]
    async fn rewind_serves_a_zero_length_read_without_consuming_the_prefix() {
        let mut stream = Rewind::new(Bytes::from_static(b"abc"), &b"def"[..]);
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let (prefix, _) = stream.into_inner();
        assert_eq!(&prefix[..], b"abc");
    }

    #[tokio::test]
    async fn rewind_into_inner_returns_the_unread_prefix() {
        let mut stream = Rewind::new(Bytes::from_static(b"abcdef"), &b"tail"[..]);
        let mut buf = [0_u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ab");
        assert_eq!(stream.inner(), &&b"tail"[..]);
        let (prefix, inner) = stream.into_inner();
        assert_eq!(&prefix[..], b"cdef");
        assert_eq!(inner, b"tail");
    }

    #[tokio::test]
    async fn rewind_forwards_writes_flush_and_shutdown() {
        let (client, mut server) = duplex(64);
        let mut stream = Rewind::new(Bytes::from_static(b"unread"), client);
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping");

        // Writing does not touch the prefix.
        let (prefix, _) = stream.into_inner();
        assert_eq!(&prefix[..], b"unread");
    }

    #[tokio::test]
    async fn rewind_reads_and_writes_on_the_same_stream() {
        let (client, mut server) = duplex(64);
        let mut stream = Rewind::new(Bytes::from_static(b"GET"), client);
        server.write_all(b" /").await.unwrap();
        stream.write_all(b"200 OK").await.unwrap();

        let mut request = [0_u8; 5];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET /");

        let mut response = [0_u8; 6];
        server.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"200 OK");
    }

    #[tokio::test]
    async fn rewind_forwards_vectored_writes() {
        let mut stream = Rewind::new(Bytes::new(), Vec::<u8>::new());
        assert!(stream.is_write_vectored());
        let slices = [IoSlice::new(b"ab"), IoSlice::new(b"cd")];
        let written = stream.write_vectored(&slices).await.unwrap();
        assert_eq!(written, 4);
        assert_eq!(stream.inner().as_slice(), b"abcd");
    }

    #[test]
    fn rewind_is_unpin_when_the_inner_object_is() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<Rewind<DuplexStream>>();
        assert_unpin::<Rewind<&[u8]>>();
    }

    // ------------------------------------------------------------------ errors

    #[test]
    fn error_messages_and_sources() {
        assert_eq!(
            ProxyError::Invalid("bad port").to_string(),
            "invalid PROXY protocol header: bad port"
        );
        assert_eq!(
            ProxyError::TooLong.to_string(),
            "PROXY protocol header is too long"
        );
        assert_eq!(
            ProxyError::Timeout.to_string(),
            "timed out waiting for the PROXY protocol header"
        );
        assert_eq!(
            ProxyError::Closed.to_string(),
            "connection closed before the PROXY protocol header was complete"
        );

        let io_error = ProxyError::Io(io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
        assert!(io_error.to_string().contains("reset"));
        assert!(io_error.source().is_some());
        for plain in [
            ProxyError::Invalid("x"),
            ProxyError::TooLong,
            ProxyError::Timeout,
            ProxyError::Closed,
        ] {
            assert!(plain.source().is_none());
        }
    }
}
