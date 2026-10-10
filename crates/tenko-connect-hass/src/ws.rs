//! A minimal client side of RFC 6455 (the WebSocket protocol) for the Home Assistant WebSocket
//! API at `/api/websocket`: JSON text messages in both directions, request and response.
//!
//! Only what that needs is here. Text frames are sent and received, continuation frames are
//! reassembled on receive, a ping is answered with a pong that carries the same payload, a pong
//! is ignored, and a close frame is answered with a close frame. A binary message from the
//! server is a protocol error. No extension, subprotocol or compression is negotiated, so the
//! reserved bits must stay clear.
//!
//! The decoder parses network input. It is strict (RFC 6455 section 5.2), never panics on any
//! input (the `connect_hass_ws_frame` fuzz target exercises it) and checks every declared
//! length against a cap before the caller buffers a single payload byte. Error texts never echo
//! payload or header bytes.

use std::fmt;
use std::io::ErrorKind;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use reqwest::header::{CONNECTION, HeaderMap, UPGRADE};
use reqwest::{StatusCode, Url, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message accepted from the server, in bytes (the entity registry of a large home is several MiB).
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// Largest payload of a control frame (RFC 6455 section 5.5).
pub const MAX_CONTROL: usize = 125;
/// The GUID of the handshake (RFC 6455 section 1.3).
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// How much room [`WebSocket`] makes for each read from the stream.
const READ_CHUNK: usize = 16 * 1024;
/// The status code of a normal closure (RFC 6455 section 7.4.1).
const CLOSE_NORMAL: u16 = 1000;
/// The length marker of the 16-bit length form (RFC 6455 section 5.2); smaller values are the length.
const LENGTH_16: u8 = 126;
/// The length marker of the 64-bit length form.
const LENGTH_64: u8 = 127;
/// The mask bit of the second frame byte.
const MASKED: u8 = 0x80;
/// The base64 alphabet of RFC 4648 section 4.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The frame opcodes this client knows (RFC 6455 section 5.2). Every other value is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A frame that continues a fragmented message (0x0).
    Continuation,
    /// A frame that starts a text message (0x1).
    Text,
    /// A frame that starts a binary message (0x2).
    Binary,
    /// A close frame (0x8).
    Close,
    /// A ping frame (0x9).
    Ping,
    /// A pong frame (0xA).
    Pong,
}

impl Opcode {
    /// The opcode for the low four bits of the first frame byte; unknown values are refused.
    fn from_nibble(nibble: u8) -> Result<Self, WsError> {
        match nibble {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(protocol("unknown opcode")),
        }
    }

    /// The four-bit wire value.
    const fn to_nibble(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control frame (close, ping or pong).
    const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// One decoded frame, unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The FIN bit: this frame ends its message.
    pub fin: bool,
    /// The opcode of the frame.
    pub opcode: Opcode,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// What can go wrong with a WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WsError {
    /// The server broke the protocol; the text says how (never echo payload bytes in it).
    #[error("WebSocket protocol error: {0}")]
    Protocol(String),
    /// A frame or message exceeds its size limit.
    #[error("a WebSocket message exceeds {0} bytes")]
    TooLarge(usize),
    /// The connection was closed (by a close frame, with its status code if it had one, or by end of stream: None).
    #[error("the WebSocket connection was closed")]
    Closed(Option<u16>),
    /// Reading or writing the stream failed (the io error kind, as text).
    #[error("WebSocket I/O failed: {0}")]
    Io(String),
    /// The opening handshake failed; the text says why (status, missing or wrong header). Never include header values other than the status code.
    #[error("WebSocket handshake failed: {0}")]
    Handshake(String),
}

/// A protocol error with a fixed text.
fn protocol(text: &str) -> WsError {
    WsError::Protocol(text.to_owned())
}

/// An I/O failure, reduced to the error kind.
fn io_error(error: &std::io::Error) -> WsError {
    WsError::Io(error.kind().to_string())
}

/// What the first bytes of a frame declare.
struct Header {
    /// The FIN bit.
    fin: bool,
    /// The opcode.
    opcode: Opcode,
    /// The number of bytes before the payload (the server never masks, so no mask key).
    prefix_len: usize,
    /// The declared payload length, already checked against the limit.
    payload_len: usize,
}

/// Parses the frame header at the front of `buf`: `Ok(None)` when the header is incomplete.
/// Everything that can be refused from the bytes at hand is refused at once.
fn parse_header(buf: &[u8], max_payload: usize) -> Result<Option<Header>, WsError> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    if first & 0x70 != 0 {
        return Err(protocol(
            "reserved bits set, but no extension was negotiated",
        ));
    }
    let fin = first & 0x80 != 0;
    let opcode = Opcode::from_nibble(first & 0x0F)?;
    let Some(&second) = buf.get(1) else {
        return Ok(None);
    };
    if second & 0x80 != 0 {
        return Err(protocol("a server frame must not be masked"));
    }
    let short = second & 0x7F;
    if opcode.is_control() {
        if !fin {
            return Err(protocol("a control frame must not be fragmented"));
        }
        if usize::from(short) > MAX_CONTROL {
            return Err(protocol("a control frame payload exceeds 125 bytes"));
        }
    }
    let (prefix_len, declared) = match short {
        LENGTH_16 => {
            let Some(raw) = buf.get(2..4).and_then(|b| <[u8; 2]>::try_from(b).ok()) else {
                return Ok(None);
            };
            let length = u16::from_be_bytes(raw);
            if length < u16::from(LENGTH_16) {
                return Err(protocol("non-minimal 16-bit payload length"));
            }
            (4, u64::from(length))
        }
        LENGTH_64 => {
            let Some(raw) = buf.get(2..10).and_then(|b| <[u8; 8]>::try_from(b).ok()) else {
                return Ok(None);
            };
            let length = u64::from_be_bytes(raw);
            if length >> 63 != 0 {
                return Err(protocol(
                    "the most significant bit of a 64-bit length is set",
                ));
            }
            if u16::try_from(length).is_ok() {
                return Err(protocol("non-minimal 64-bit payload length"));
            }
            (10, length)
        }
        length => (2, u64::from(length)),
    };
    match usize::try_from(declared) {
        Ok(payload_len) if payload_len <= max_payload => Ok(Some(Header {
            fin,
            opcode,
            prefix_len,
            payload_len,
        })),
        _ => Err(WsError::TooLarge(max_payload)),
    }
}

/// Whether `code` may appear in a close frame (RFC 6455 section 7.4): the codes defined there
/// that can be sent, and the registered and private ranges 3000 to 4999.
const fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// The status code of a close payload: empty, or a two-byte code followed by a UTF-8 reason.
fn parse_close(payload: &[u8]) -> Result<Option<u16>, WsError> {
    match payload {
        [] => Ok(None),
        [_] => Err(protocol("a close payload of one byte")),
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            if !valid_close_code(code) {
                return Err(protocol("invalid close status code"));
            }
            if std::str::from_utf8(reason).is_err() {
                return Err(protocol("the close reason is not valid UTF-8"));
            }
            Ok(Some(code))
        }
    }
}

/// Decodes one server-to-client frame from the front of `buf`: Ok(None) when more bytes are needed, Ok(Some((frame, consumed))) otherwise.
///
/// The decoder is strict (RFC 6455 section 5.2): reserved bits, unknown opcodes, masked frames,
/// non-minimal lengths, a 64-bit length with the most significant bit set, fragmented or
/// oversized control frames and malformed close payloads are all refused. A declared payload
/// above `max_payload` is refused as soon as the header is complete, before any payload byte is
/// needed.
///
/// # Errors
///
/// [`WsError::Protocol`] for a malformed frame and [`WsError::TooLarge`] when the payload
/// exceeds `max_payload`.
pub fn decode_frame(buf: &[u8], max_payload: usize) -> Result<Option<(Frame, usize)>, WsError> {
    let Some(header) = parse_header(buf, max_payload)? else {
        return Ok(None);
    };
    let Some(end) = header.prefix_len.checked_add(header.payload_len) else {
        return Err(WsError::TooLarge(max_payload));
    };
    let Some(payload) = buf.get(header.prefix_len..end) else {
        return Ok(None);
    };
    if header.opcode == Opcode::Close {
        parse_close(payload)?;
    }
    let frame = Frame {
        fin: header.fin,
        opcode: header.opcode,
        payload: payload.to_vec(),
    };
    Ok(Some((frame, end)))
}

/// Encodes one client-to-server frame with FIN set, masked with `mask` (RFC 6455 section 5.3).
///
/// A control frame must carry at most [`MAX_CONTROL`] bytes; the caller keeps to that.
pub fn encode_frame(opcode: Opcode, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let length = payload.len();
    let mut out = Vec::with_capacity(length.saturating_add(14));
    out.push(0x80 | opcode.to_nibble());
    if let Some(short) = u8::try_from(length).ok().filter(|&n| n < LENGTH_16) {
        out.push(MASKED | short);
    } else if let Ok(medium) = u16::try_from(length) {
        out.push(MASKED | LENGTH_16);
        out.extend_from_slice(&medium.to_be_bytes());
    } else {
        out.push(MASKED | LENGTH_64);
        out.extend_from_slice(&u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, key)| byte ^ key),
    );
    out
}

/// What the assembler produced from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete text message.
    Text(String),
    /// A ping; the payload is to be echoed in a pong.
    Ping(Vec<u8>),
    /// A pong.
    Pong(Vec<u8>),
    /// A close frame, with its status code if it had one.
    Close(Option<u16>),
}

/// Reassembles messages from frames.
#[derive(Debug)]
pub struct Assembler {
    /// The cap on the size of one message.
    max_message: usize,
    /// The fragments received so far of the message in progress.
    partial: Vec<u8>,
    /// Whether a fragmented message is in progress.
    in_progress: bool,
}

impl Assembler {
    /// Creates an assembler that refuses messages above `max_message` bytes.
    pub fn new(max_message: usize) -> Self {
        Self {
            max_message,
            partial: Vec::new(),
            in_progress: false,
        }
    }

    /// Takes the next frame. Ok(None) while a fragmented message is incomplete.
    ///
    /// Control frames may arrive between the fragments of a message and are returned at once.
    ///
    /// # Errors
    ///
    /// [`WsError::Protocol`] for a binary message, a text frame while a message is in progress,
    /// a continuation frame with none in progress, an invalid control frame or a text message
    /// that is not UTF-8, and [`WsError::TooLarge`] when the message outgrows the cap.
    pub fn push(&mut self, frame: Frame) -> Result<Option<Event>, WsError> {
        let Frame {
            fin,
            opcode,
            payload,
        } = frame;
        match opcode {
            Opcode::Ping => {
                check_control(fin, &payload)?;
                Ok(Some(Event::Ping(payload)))
            }
            Opcode::Pong => {
                check_control(fin, &payload)?;
                Ok(Some(Event::Pong(payload)))
            }
            Opcode::Close => {
                check_control(fin, &payload)?;
                Ok(Some(Event::Close(parse_close(&payload)?)))
            }
            Opcode::Binary => Err(protocol("binary messages are not expected")),
            Opcode::Text => self.data(fin, true, payload),
            Opcode::Continuation => self.data(fin, false, payload),
        }
    }

    /// Takes a text or continuation frame.
    fn data(
        &mut self,
        fin: bool,
        starts: bool,
        payload: Vec<u8>,
    ) -> Result<Option<Event>, WsError> {
        if starts && self.in_progress {
            return Err(protocol(
                "a new message started before the previous one ended",
            ));
        }
        if !starts && !self.in_progress {
            return Err(protocol(
                "a continuation frame arrived with no message in progress",
            ));
        }
        if payload.len() > self.max_message.saturating_sub(self.partial.len()) {
            self.partial = Vec::new();
            self.in_progress = false;
            return Err(WsError::TooLarge(self.max_message));
        }
        if starts {
            self.partial = payload;
        } else {
            self.partial.extend_from_slice(&payload);
        }
        if !fin {
            self.in_progress = true;
            return Ok(None);
        }
        self.in_progress = false;
        let whole = std::mem::take(&mut self.partial);
        String::from_utf8(whole)
            .map(|text| Some(Event::Text(text)))
            .map_err(|_| protocol("a text message is not valid UTF-8"))
    }
}

/// Checks the rules every control frame obeys, for frames that did not come through
/// [`decode_frame`].
fn check_control(fin: bool, payload: &[u8]) -> Result<(), WsError> {
    if !fin {
        return Err(protocol("a control frame must not be fragmented"));
    }
    if payload.len() > MAX_CONTROL {
        return Err(protocol("a control frame payload exceeds 125 bytes"));
    }
    Ok(())
}

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0);
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let sextets = [
            first >> 2,
            ((first & 0x03) << 4) | (second >> 4),
            ((second & 0x0F) << 2) | (third >> 6),
            third & 0x3F,
        ];
        // One byte yields two characters, two bytes three, three bytes four.
        let used = chunk.len() + 1;
        for (index, sextet) in sextets.iter().enumerate() {
            if index < used {
                out.push(char::from(ALPHABET[usize::from(sextet & 0x3F)]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The Sec-WebSocket-Accept value for a key: base64 of SHA-1 over key + GUID.
pub fn accept_for(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(GUID.as_bytes());
    base64_encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref())
}

/// A WebSocket over an upgraded byte stream.
///
/// The methods are not cancel safe: dropping a future while a frame is half written leaves a
/// partial frame on the stream, so treat the connection as lost after a timeout.
pub struct WebSocket<S> {
    /// The upgraded stream.
    io: S,
    /// Bytes read from the stream and not yet decoded.
    buf: Vec<u8>,
    /// Reassembles messages from the decoded frames.
    assembler: Assembler,
    /// The source of the masking keys.
    rng: SystemRandom,
    /// Whether a close frame went out; nothing is sent after one.
    close_sent: bool,
}

impl<S> fmt::Debug for WebSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket")
            .field("buffered", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    /// Wraps a stream on which the handshake already succeeded.
    pub fn new(io: S) -> Self {
        Self {
            io,
            buf: Vec::new(),
            assembler: Assembler::new(MAX_MESSAGE),
            rng: SystemRandom::new(),
            close_sent: false,
        }
    }

    /// Sends one text message in a single masked frame (fresh random mask per frame from `SystemRandom`).
    ///
    /// # Errors
    ///
    /// [`WsError::Closed`] once a close frame went out, [`WsError::Io`] when the random source
    /// or the stream fails.
    pub async fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        if self.close_sent {
            return Err(WsError::Closed(None));
        }
        self.send_frame(Opcode::Text, text.as_bytes()).await
    }

    /// Receives the next text message; answers pings with pongs on the way, ignores pongs; a close frame is answered with a close frame (echoing its status code, or none) and returns Err(Closed(code)); end of stream returns Err(Closed(None)).
    ///
    /// A stream that ends without a clean shutdown (an `UnexpectedEof` read error, which TLS
    /// streams report when the peer drops the connection) counts as end of stream.
    ///
    /// # Errors
    ///
    /// [`WsError::Protocol`] and [`WsError::TooLarge`] when the server breaks the protocol,
    /// [`WsError::Closed`] when the connection ends and [`WsError::Io`] when the stream fails.
    pub async fn recv_text(&mut self) -> Result<String, WsError> {
        loop {
            let Some((frame, consumed)) = decode_frame(&self.buf, MAX_MESSAGE)? else {
                self.fill().await?;
                continue;
            };
            self.buf.drain(..consumed);
            match self.assembler.push(frame)? {
                None | Some(Event::Pong(_)) => {}
                Some(Event::Text(text)) => return Ok(text),
                Some(Event::Ping(payload)) => self.send_frame(Opcode::Pong, &payload).await?,
                Some(Event::Close(code)) => {
                    if !self.close_sent {
                        self.close_sent = true;
                        let echo = code.map(u16::to_be_bytes);
                        let payload: &[u8] = echo.as_ref().map_or(&[], |bytes| bytes.as_slice());
                        // Best effort: the peer may already be gone.
                        let _ = self.send_frame(Opcode::Close, payload).await;
                    }
                    return Err(WsError::Closed(code));
                }
            }
        }
    }

    /// Sends a close frame with status 1000, best effort, and shuts the stream down.
    ///
    /// # Errors
    ///
    /// [`WsError::Io`] when shutting the stream down fails.
    pub async fn close(&mut self) -> Result<(), WsError> {
        if !self.close_sent {
            self.close_sent = true;
            // Best effort: the peer may already be gone.
            let _ = self
                .send_frame(Opcode::Close, &CLOSE_NORMAL.to_be_bytes())
                .await;
        }
        self.io.shutdown().await.map_err(|error| io_error(&error))
    }

    /// Reads more bytes from the stream into the buffer; end of stream is `Closed(None)`.
    async fn fill(&mut self) -> Result<(), WsError> {
        self.buf.reserve(READ_CHUNK);
        match self.io.read_buf(&mut self.buf).await {
            Ok(0) => Err(WsError::Closed(None)),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Err(WsError::Closed(None)),
            Err(error) => Err(io_error(&error)),
        }
    }

    /// Writes one masked frame.
    async fn send_frame(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
        let mut mask = [0_u8; 4];
        self.rng
            .fill(&mut mask)
            .map_err(|_| WsError::Io("random source failed".to_owned()))?;
        let bytes = encode_frame(opcode, payload, mask);
        self.io
            .write_all(&bytes)
            .await
            .map_err(|error| io_error(&error))?;
        self.io.flush().await.map_err(|error| io_error(&error))
    }
}

/// Why `connect` failed.
#[derive(Debug)]
pub enum ConnectError {
    /// The request failed before or after the handshake (transport, TLS, or the upgrade itself);
    /// the caller classifies the `reqwest::Error`.
    Request(reqwest::Error),
    /// The server answered, but not with a valid WebSocket handshake.
    Handshake(WsError),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(_) => f.write_str("the WebSocket upgrade request failed"),
            Self::Handshake(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Handshake(error) => Some(error),
        }
    }
}

/// Checks the server's answer to the opening handshake (RFC 6455 section 4.1). The errors name
/// the header at fault, never a header value.
fn verify_response(status: StatusCode, headers: &HeaderMap, key: &str) -> Result<(), WsError> {
    let refuse = |text: &str| Err(WsError::Handshake(text.to_owned()));
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(WsError::Handshake(format!(
            "expected status 101, got {}",
            status.as_u16()
        )));
    }
    let upgrade_ok = headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if !upgrade_ok {
        return refuse("the Upgrade header is missing or not websocket");
    }
    let mut accepts = headers.get_all("sec-websocket-accept").iter();
    match (accepts.next(), accepts.next()) {
        (None, _) => return refuse("the Sec-WebSocket-Accept header is missing"),
        (Some(value), None) if value.as_bytes() == accept_for(key).as_bytes() => {}
        _ => return refuse("the Sec-WebSocket-Accept header is wrong"),
    }
    if headers.contains_key("sec-websocket-extensions") {
        return refuse("the server selected an extension that was not offered");
    }
    if headers.contains_key("sec-websocket-protocol") {
        return refuse("the server selected a subprotocol that was not offered");
    }
    Ok(())
}

/// Opens a WebSocket: GET `url` (an http or https URL; the caller converts ws/wss) through `client` with `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13` and a fresh random 16-byte `Sec-WebSocket-Key`; requires status 101, an `Upgrade` header equal to `websocket` (ASCII case-insensitive) and the right `Sec-WebSocket-Accept`; then upgrades the connection.
///
/// The server must not select an extension or a subprotocol, since none was offered.
///
/// # Errors
///
/// [`ConnectError::Request`] when the request or the upgrade fails in transport or TLS, and
/// [`ConnectError::Handshake`] when the server's answer is not a valid handshake.
pub async fn connect(
    client: &reqwest::Client,
    url: Url,
) -> Result<WebSocket<reqwest::Upgraded>, ConnectError> {
    let mut nonce = [0_u8; 16];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        ConnectError::Handshake(WsError::Handshake("random source failed".to_owned()))
    })?;
    let key = base64_encode(&nonce);
    let response = client
        .get(url)
        .version(Version::HTTP_11)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", key.as_str())
        .send()
        .await
        .map_err(ConnectError::Request)?;
    verify_response(response.status(), response.headers(), &key)
        .map_err(ConnectError::Handshake)?;
    let upgraded = response.upgrade().await.map_err(ConnectError::Request)?;
    Ok(WebSocket::new(upgraded))
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;
    use tokio::io::duplex;

    use super::*;

    /// The decoding limit of most tests.
    const LIMIT: usize = 1 << 20;
    /// The masking key of RFC 6455 section 5.7.
    const MASK: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

    /// A server frame in the minimal length form, unmasked.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let length = payload.len();
        if length < 126 {
            out.push(u8::try_from(length).unwrap());
        } else if let Ok(medium) = u16::try_from(length) {
            out.push(126);
            out.extend_from_slice(&medium.to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&u64::try_from(length).unwrap().to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    /// A frame assembled byte by byte: the two first bytes, the extended length, the payload.
    fn raw_frame(first: u8, second: u8, extension: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = vec![first, second];
        out.extend_from_slice(extension);
        out.extend_from_slice(payload);
        out
    }

    /// A client frame as the test-side decoder sees it.
    struct ClientFrame {
        fin: bool,
        opcode: u8,
        masked: bool,
        payload: Vec<u8>,
    }

    /// The test-side decoder of client frames, written separately from the code under test.
    fn parse_client_frame(bytes: &[u8]) -> Option<(ClientFrame, usize)> {
        if bytes.len() < 2 {
            return None;
        }
        let fin = bytes[0] & 0x80 != 0;
        let opcode = bytes[0] & 0x0F;
        let masked = bytes[1] & 0x80 != 0;
        let (length, mut position) = match bytes[1] & 0x7F {
            126 if bytes.len() >= 4 => (usize::from(u16::from_be_bytes([bytes[2], bytes[3]])), 4),
            127 if bytes.len() >= 10 => {
                let raw: [u8; 8] = bytes[2..10].try_into().unwrap();
                (usize::try_from(u64::from_be_bytes(raw)).unwrap(), 10)
            }
            126 | 127 => return None,
            short => (usize::from(short), 2),
        };
        let mut mask = [0_u8; 4];
        if masked {
            if bytes.len() < position + 4 {
                return None;
            }
            mask.copy_from_slice(&bytes[position..position + 4]);
            position += 4;
        }
        if bytes.len() < position + length {
            return None;
        }
        let payload = bytes[position..position + length]
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if masked {
                    byte ^ mask[index % 4]
                } else {
                    *byte
                }
            })
            .collect();
        let frame = ClientFrame {
            fin,
            opcode,
            masked,
            payload,
        };
        Some((frame, position + length))
    }

    /// Reads one client frame from a stream, keeping the surplus bytes in `inbox`.
    async fn read_client_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
        inbox: &mut Vec<u8>,
    ) -> ClientFrame {
        loop {
            if let Some((frame, used)) = parse_client_frame(inbox) {
                inbox.drain(..used);
                return frame;
            }
            let mut chunk = [0_u8; 4096];
            let read = reader.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "the stream ended inside a client frame");
            inbox.extend_from_slice(&chunk[..read]);
        }
    }

    /// Decodes a buffer that holds one complete valid frame.
    fn decoded(bytes: &[u8]) -> (Frame, usize) {
        decode_frame(bytes, LIMIT)
            .expect("a valid frame")
            .expect("a complete frame")
    }

    /// Asserts that the decoder refuses the frame as a protocol error.
    fn assert_protocol(bytes: &[u8]) {
        match decode_frame(bytes, LIMIT) {
            Err(WsError::Protocol(_)) => {}
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    // ----- encoding -----

    #[test]
    fn encode_matches_the_rfc_example() {
        // RFC 6455 section 5.7: a single-frame masked text message "Hello".
        let bytes = encode_frame(Opcode::Text, b"Hello", MASK);
        assert_eq!(
            bytes,
            [
                0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58
            ]
        );
    }

    #[test]
    fn encode_sets_fin_and_the_opcode() {
        for (opcode, first) in [
            (Opcode::Continuation, 0x80),
            (Opcode::Text, 0x81),
            (Opcode::Binary, 0x82),
            (Opcode::Close, 0x88),
            (Opcode::Ping, 0x89),
            (Opcode::Pong, 0x8A),
        ] {
            assert_eq!(encode_frame(opcode, b"", MASK)[0], first);
        }
    }

    #[test]
    fn encode_round_trips_through_an_unmasking_decoder() {
        for length in [0_usize, 1, 125, 126, 127, 65_535, 65_536, 70_000] {
            let payload: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            let bytes = encode_frame(Opcode::Text, &payload, [0xDE, 0xAD, 0xBE, 0xEF]);
            let (frame, used) = parse_client_frame(&bytes).expect("a complete frame");
            assert_eq!(used, bytes.len());
            assert!(frame.fin && frame.masked);
            assert_eq!(frame.opcode, 1);
            assert_eq!(frame.payload, payload);
            let expected = match length {
                0..=125 => u8::try_from(length).unwrap(),
                126..=65_535 => 126,
                _ => 127,
            };
            assert_eq!(bytes[1] & 0x7F, expected, "length form for {length}");
        }
    }

    // ----- decoding -----

    #[test]
    fn decodes_the_three_length_forms() {
        for (length, header) in [
            (0_usize, 2_usize),
            (5, 2),
            (125, 2),
            (126, 4),
            (300, 4),
            (65_535, 4),
            (65_536, 10),
            (100_000, 10),
        ] {
            let payload: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 241).unwrap())
                .collect();
            let bytes = server_frame(true, 0x2, &payload);
            assert_eq!(bytes.len(), header + length, "header size for {length}");
            let (frame, used) = decoded(&bytes);
            assert_eq!(used, bytes.len());
            assert_eq!(frame.opcode, Opcode::Binary);
            assert!(frame.fin);
            assert_eq!(frame.payload, payload);
        }
    }

    #[test]
    fn decodes_every_known_opcode_and_the_fin_bit() {
        for (nibble, opcode) in [
            (0x0, Opcode::Continuation),
            (0x1, Opcode::Text),
            (0x2, Opcode::Binary),
            (0x9, Opcode::Ping),
            (0xA, Opcode::Pong),
        ] {
            let (frame, _) = decoded(&server_frame(true, nibble, b"ab"));
            assert_eq!(frame.opcode, opcode);
            assert!(frame.fin);
        }
        let (frame, _) = decoded(&server_frame(false, 0x1, b"ab"));
        assert!(!frame.fin);
        let (frame, _) = decoded(&server_frame(true, 0x8, &[]));
        assert_eq!(frame.opcode, Opcode::Close);
    }

    #[test]
    fn a_partial_frame_needs_more_bytes() {
        for length in [5_usize, 300, 70_000] {
            let bytes = server_frame(true, 0x1, &vec![b'x'; length]);
            for cut in 0..bytes.len() {
                assert_eq!(decode_frame(&bytes[..cut], LIMIT), Ok(None), "cut at {cut}");
            }
            assert!(matches!(decode_frame(&bytes, LIMIT), Ok(Some(_))));
        }
    }

    #[test]
    fn decoding_stops_at_the_end_of_the_frame() {
        let mut bytes = server_frame(true, 0x1, b"one");
        let first = bytes.len();
        bytes.extend(server_frame(true, 0x1, b"two"));
        let (frame, used) = decoded(&bytes);
        assert_eq!(used, first);
        assert_eq!(frame.payload, b"one");
        let (frame, _) = decoded(&bytes[used..]);
        assert_eq!(frame.payload, b"two");
    }

    #[test]
    fn a_payload_of_exactly_the_limit_is_accepted() {
        let bytes = server_frame(true, 0x2, &[7; 200]);
        assert!(matches!(decode_frame(&bytes, 200), Ok(Some(_))));
        assert_eq!(decode_frame(&bytes, 199), Err(WsError::TooLarge(199)));
    }

    // ----- strictness -----

    #[test]
    fn reserved_bits_are_refused() {
        for bit in [0x40_u8, 0x20, 0x10] {
            assert_protocol(&[0x81 | bit, 0x00]);
            // Refused from the first byte alone.
            assert_protocol(&[0x81 | bit]);
        }
    }

    #[test]
    fn unknown_opcodes_are_refused() {
        for nibble in (0x3_u8..=0x7).chain(0xB..=0xF) {
            assert_protocol(&[0x80 | nibble, 0x00]);
            assert_protocol(&[nibble]);
        }
    }

    #[test]
    fn a_masked_server_frame_is_refused() {
        assert_protocol(&raw_frame(0x81, 0x80 | 3, &[1, 2, 3, 4], b"abc"));
        assert_protocol(&[0x81, 0x80]);
    }

    #[test]
    fn a_non_minimal_16_bit_length_is_refused() {
        for length in [0_u16, 5, 125] {
            let payload = vec![b'a'; usize::from(length)];
            assert_protocol(&raw_frame(0x82, 126, &length.to_be_bytes(), &payload));
        }
        // 126 is the smallest length the 16-bit form may carry.
        let payload = vec![b'a'; 126];
        let bytes = raw_frame(0x82, 126, &126_u16.to_be_bytes(), &payload);
        assert_eq!(decoded(&bytes).0.payload, payload);
    }

    #[test]
    fn a_non_minimal_64_bit_length_is_refused() {
        for length in [0_u64, 125, 126, 65_535] {
            // The refusal needs only the header.
            assert_protocol(&raw_frame(0x82, 127, &length.to_be_bytes(), &[]));
        }
        // 65536 is the smallest length the 64-bit form may carry.
        let payload = vec![b'a'; 65_536];
        let bytes = raw_frame(0x82, 127, &65_536_u64.to_be_bytes(), &payload);
        assert_eq!(decoded(&bytes).0.payload, payload);
    }

    #[test]
    fn a_64_bit_length_with_the_top_bit_set_is_refused() {
        for length in [1_u64 << 63, 0x8000_0000_0001_1170, u64::MAX] {
            assert_protocol(&raw_frame(0x82, 127, &length.to_be_bytes(), &[]));
        }
    }

    #[test]
    fn a_fragmented_control_frame_is_refused() {
        for nibble in [0x8_u8, 0x9, 0xA] {
            assert_protocol(&server_frame(false, nibble, b""));
            assert_protocol(&[nibble, 0x00]);
        }
    }

    #[test]
    fn an_oversized_control_frame_is_refused() {
        for nibble in [0x8_u8, 0x9, 0xA] {
            assert_protocol(&server_frame(true, nibble, &[b'a'; 126]));
            // Refused from the length byte alone.
            assert_protocol(&[0x80 | nibble, 126]);
            assert_protocol(&[0x80 | nibble, 127]);
        }
        // 125 bytes is the largest control payload.
        let (frame, _) = decoded(&server_frame(true, 0x9, &[b'a'; 125]));
        assert_eq!(frame.payload.len(), 125);
    }

    #[test]
    fn too_large_is_reported_without_the_payload_bytes() {
        // A header that declares 1 GiB, and nothing after it.
        let header = raw_frame(0x82, 127, &(1_u64 << 30).to_be_bytes(), &[]);
        assert_eq!(decode_frame(&header, LIMIT), Err(WsError::TooLarge(LIMIT)));
        // The largest length the 64-bit form allows.
        let header = raw_frame(0x82, 127, &(u64::MAX >> 1).to_be_bytes(), &[]);
        assert_eq!(decode_frame(&header, LIMIT), Err(WsError::TooLarge(LIMIT)));
        // The 16-bit form.
        let header = raw_frame(0x82, 126, &60_000_u16.to_be_bytes(), &[]);
        assert_eq!(decode_frame(&header, 1000), Err(WsError::TooLarge(1000)));
        // The 7-bit form.
        assert_eq!(decode_frame(&[0x82, 10], 5), Err(WsError::TooLarge(5)));
        // An incomplete header still waits for more bytes.
        assert_eq!(decode_frame(&[0x82, 127, 0, 0, 0], 5), Ok(None));
    }

    #[test]
    fn close_status_codes_are_checked() {
        let valid = [
            1000_u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4000,
            4999,
        ];
        for code in valid {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice("bye".as_bytes());
            let (frame, _) = decoded(&server_frame(true, 0x8, &payload));
            assert_eq!(frame.opcode, Opcode::Close);
        }
        let invalid = [
            0_u16,
            999,
            1004,
            1005,
            1006,
            1015,
            1016,
            2000,
            2999,
            5000,
            u16::MAX,
        ];
        for code in invalid {
            assert_protocol(&server_frame(true, 0x8, &code.to_be_bytes()));
        }
    }

    #[test]
    fn a_close_payload_has_zero_or_two_or_more_bytes() {
        assert_eq!(decoded(&server_frame(true, 0x8, &[])).0.payload.len(), 0);
        assert_protocol(&server_frame(true, 0x8, &[0x03]));
        assert_protocol(&server_frame(true, 0x8, &[0xE8]));
    }

    #[test]
    fn a_close_reason_must_be_utf8() {
        let mut payload = 1000_u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0xFF, 0xFE]);
        assert_protocol(&server_frame(true, 0x8, &payload));
        let mut payload = 1001_u16.to_be_bytes().to_vec();
        payload.extend_from_slice("g\u{e5} bort".as_bytes());
        assert!(matches!(
            decode_frame(&server_frame(true, 0x8, &payload), LIMIT),
            Ok(Some(_))
        ));
    }

    #[test]
    fn error_texts_do_not_echo_payload_bytes() {
        let mut payload = 1000_u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"SECRET\xFF");
        let error = decode_frame(&server_frame(true, 0x8, &payload), LIMIT).unwrap_err();
        assert!(!error.to_string().contains("SECRET"));
    }

    // ----- assembling -----

    fn frame(fin: bool, opcode: Opcode, payload: &[u8]) -> Frame {
        Frame {
            fin,
            opcode,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn a_single_frame_text_message() {
        let mut assembler = Assembler::new(LIMIT);
        let event = assembler.push(frame(true, Opcode::Text, b"{}")).unwrap();
        assert_eq!(event, Some(Event::Text("{}".to_owned())));
        let event = assembler.push(frame(true, Opcode::Text, b"")).unwrap();
        assert_eq!(event, Some(Event::Text(String::new())));
    }

    #[test]
    fn a_fragmented_text_message_with_a_ping_in_between() {
        let mut assembler = Assembler::new(LIMIT);
        assert_eq!(assembler.push(frame(false, Opcode::Text, b"Hel")), Ok(None));
        assert_eq!(
            assembler.push(frame(true, Opcode::Ping, b"beat")),
            Ok(Some(Event::Ping(b"beat".to_vec())))
        );
        assert_eq!(
            assembler.push(frame(false, Opcode::Continuation, b"lo, ")),
            Ok(None)
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Pong, b"")),
            Ok(Some(Event::Pong(Vec::new())))
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Continuation, b"world")),
            Ok(Some(Event::Text("Hello, world".to_owned())))
        );
        // The assembler is ready for the next message.
        assert_eq!(
            assembler.push(frame(true, Opcode::Text, b"next")),
            Ok(Some(Event::Text("next".to_owned())))
        );
    }

    #[test]
    fn a_character_may_be_split_across_fragments() {
        let bytes = "\u{e5}".as_bytes();
        let mut assembler = Assembler::new(LIMIT);
        assert_eq!(
            assembler.push(frame(false, Opcode::Text, &bytes[..1])),
            Ok(None)
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Continuation, &bytes[1..])),
            Ok(Some(Event::Text("\u{e5}".to_owned())))
        );
    }

    #[test]
    fn close_frames_carry_their_status_code() {
        let mut assembler = Assembler::new(LIMIT);
        assert_eq!(
            assembler.push(frame(true, Opcode::Close, &[])),
            Ok(Some(Event::Close(None)))
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Close, &1001_u16.to_be_bytes())),
            Ok(Some(Event::Close(Some(1001))))
        );
    }

    #[test]
    fn the_assembler_refuses_what_it_must() {
        let mut assembler = Assembler::new(LIMIT);
        // A continuation with no message in progress.
        assert!(matches!(
            assembler.push(frame(true, Opcode::Continuation, b"x")),
            Err(WsError::Protocol(_))
        ));
        // A binary message.
        assert!(matches!(
            assembler.push(frame(true, Opcode::Binary, b"x")),
            Err(WsError::Protocol(_))
        ));
        // A new text frame while a message is in progress.
        assert_eq!(assembler.push(frame(false, Opcode::Text, b"x")), Ok(None));
        assert!(matches!(
            assembler.push(frame(true, Opcode::Text, b"y")),
            Err(WsError::Protocol(_))
        ));
        // Binary in the middle of a message.
        assert!(matches!(
            assembler.push(frame(true, Opcode::Binary, b"y")),
            Err(WsError::Protocol(_))
        ));
        // Frames that did not come through the decoder.
        let mut assembler = Assembler::new(LIMIT);
        for bad in [
            frame(false, Opcode::Ping, b""),
            frame(true, Opcode::Pong, &[0; 126]),
            frame(true, Opcode::Close, &[1]),
            frame(true, Opcode::Close, &1005_u16.to_be_bytes()),
        ] {
            assert!(matches!(assembler.push(bad), Err(WsError::Protocol(_))));
        }
    }

    #[test]
    fn a_text_message_must_be_utf8() {
        let mut assembler = Assembler::new(LIMIT);
        assert!(matches!(
            assembler.push(frame(true, Opcode::Text, &[0xFF, 0xFE])),
            Err(WsError::Protocol(_))
        ));
        // A split character that never completes.
        assert_eq!(
            assembler.push(frame(false, Opcode::Text, &"\u{e5}".as_bytes()[..1])),
            Ok(None)
        );
        assert!(matches!(
            assembler.push(frame(true, Opcode::Continuation, b"a")),
            Err(WsError::Protocol(_))
        ));
        // The assembler recovers for the next message.
        assert_eq!(
            assembler.push(frame(true, Opcode::Text, b"ok")),
            Ok(Some(Event::Text("ok".to_owned())))
        );
    }

    #[test]
    fn the_running_message_size_is_capped() {
        let mut assembler = Assembler::new(10);
        assert_eq!(
            assembler.push(frame(false, Opcode::Text, &[b'a'; 6])),
            Ok(None)
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Continuation, &[b'a'; 5])),
            Err(WsError::TooLarge(10))
        );
        // Exactly the cap is fine, over several fragments, and after an error.
        assert_eq!(
            assembler.push(frame(false, Opcode::Text, &[b'a'; 6])),
            Ok(None)
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Continuation, &[b'a'; 4])),
            Ok(Some(Event::Text("a".repeat(10))))
        );
        assert_eq!(
            assembler.push(frame(true, Opcode::Text, &[b'a'; 11])),
            Err(WsError::TooLarge(10))
        );
    }

    // ----- handshake helpers -----

    #[test]
    fn base64_test_vectors() {
        // RFC 4648 section 10.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected);
        }
        assert_eq!(base64_encode(&[0xFB, 0xFF, 0xBF]), "+/+/");
        assert_eq!(base64_encode(&[0xFF]), "/w==");
        assert_eq!(base64_encode(&[0_u8; 16]).len(), 24);
    }

    #[test]
    fn the_accept_value_of_the_rfc_example() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    fn good_headers(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&accept_for(key)).unwrap(),
        );
        headers
    }

    fn handshake_text(result: Result<(), WsError>) -> String {
        match result {
            Err(WsError::Handshake(text)) => text,
            other => panic!("expected a handshake error, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_handshake_answer_is_accepted() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut headers = good_headers(key);
        assert_eq!(
            verify_response(StatusCode::SWITCHING_PROTOCOLS, &headers, key),
            Ok(())
        );
        // The Upgrade value is compared without regard to case.
        headers.insert(UPGRADE, HeaderValue::from_static("WebSocket"));
        assert_eq!(
            verify_response(StatusCode::SWITCHING_PROTOCOLS, &headers, key),
            Ok(())
        );
    }

    #[test]
    fn a_bad_handshake_answer_is_refused_without_echoing_values() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let switching = StatusCode::SWITCHING_PROTOCOLS;
        // Not 101.
        let text = handshake_text(verify_response(StatusCode::OK, &good_headers(key), key));
        assert!(text.contains("200"));
        // Upgrade missing or wrong.
        let mut headers = good_headers(key);
        headers.insert(UPGRADE, HeaderValue::from_static("SECRET-PROTOCOL"));
        let text = handshake_text(verify_response(switching, &headers, key));
        assert!(text.contains("Upgrade") && !text.contains("SECRET"));
        headers.remove(UPGRADE);
        assert!(handshake_text(verify_response(switching, &headers, key)).contains("Upgrade"));
        // Accept missing, wrong, repeated.
        let mut headers = good_headers(key);
        headers.insert(
            "sec-websocket-accept",
            HeaderValue::from_static("SECRET-ACCEPT"),
        );
        let text = handshake_text(verify_response(switching, &headers, key));
        assert!(text.contains("Sec-WebSocket-Accept") && !text.contains("SECRET"));
        headers.remove("sec-websocket-accept");
        assert!(handshake_text(verify_response(switching, &headers, key)).contains("missing"));
        let mut headers = good_headers(key);
        headers.append(
            "sec-websocket-accept",
            HeaderValue::from_str(&accept_for(key)).unwrap(),
        );
        assert!(handshake_text(verify_response(switching, &headers, key)).contains("wrong"));
        // An accept value for another key.
        let headers = good_headers("c29tZSBvdGhlciBub25jZQ==");
        assert!(handshake_text(verify_response(switching, &headers, key)).contains("wrong"));
    }

    #[test]
    fn an_unrequested_extension_or_subprotocol_is_refused() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let switching = StatusCode::SWITCHING_PROTOCOLS;
        let mut headers = good_headers(key);
        headers.insert(
            "sec-websocket-extensions",
            HeaderValue::from_static("permessage-deflate"),
        );
        let text = handshake_text(verify_response(switching, &headers, key));
        assert!(text.contains("extension") && !text.contains("deflate"));
        let mut headers = good_headers(key);
        headers.insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
        let text = handshake_text(verify_response(switching, &headers, key));
        assert!(text.contains("subprotocol") && !text.contains("chat"));
    }

    // ----- the WebSocket over a stream -----

    #[tokio::test]
    async fn a_conversation_over_a_duplex_stream() {
        let (client_io, mut server) = duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let mut websocket = WebSocket::new(client_io);
            let first = websocket.recv_text().await;
            let sent = websocket
                .send_text("{\"id\":1,\"type\":\"get_states\"}")
                .await;
            let end = websocket.recv_text().await;
            (first, sent, end)
        });
        let mut inbox = Vec::new();

        // A ping, a pong to ignore, then a text message in two fragments.
        server
            .write_all(&server_frame(true, 0x9, b"are you there"))
            .await
            .unwrap();
        server
            .write_all(&server_frame(true, 0xA, b""))
            .await
            .unwrap();
        server
            .write_all(&server_frame(false, 0x1, b"{\"type\":"))
            .await
            .unwrap();
        server
            .write_all(&server_frame(true, 0x0, b"\"auth_required\"}"))
            .await
            .unwrap();

        // The client answered the ping with a pong that carries the same payload.
        let pong = read_client_frame(&mut server, &mut inbox).await;
        assert!(pong.fin && pong.masked);
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"are you there");

        // The client's text is masked and unmasks correctly.
        let text = read_client_frame(&mut server, &mut inbox).await;
        assert!(text.fin && text.masked);
        assert_eq!(text.opcode, 0x1);
        assert_eq!(text.payload, b"{\"id\":1,\"type\":\"get_states\"}");

        // A close with 1000 is answered with a close that echoes the code.
        server
            .write_all(&server_frame(true, 0x8, &1000_u16.to_be_bytes()))
            .await
            .unwrap();
        let close = read_client_frame(&mut server, &mut inbox).await;
        assert!(close.fin && close.masked);
        assert_eq!(close.opcode, 0x8);
        assert_eq!(close.payload, 1000_u16.to_be_bytes());

        let (first, sent, end) = client.await.unwrap();
        assert_eq!(first, Ok("{\"type\":\"auth_required\"}".to_owned()));
        assert_eq!(sent, Ok(()));
        assert_eq!(end, Err(WsError::Closed(Some(1000))));
    }

    #[tokio::test]
    async fn a_close_without_a_code_is_answered_without_a_code() {
        let (client_io, mut server) = duplex(1024);
        let mut websocket = WebSocket::new(client_io);
        server
            .write_all(&server_frame(true, 0x8, &[]))
            .await
            .unwrap();
        assert_eq!(websocket.recv_text().await, Err(WsError::Closed(None)));
        let mut inbox = Vec::new();
        let close = read_client_frame(&mut server, &mut inbox).await;
        assert_eq!(close.opcode, 0x8);
        assert_eq!(close.payload.len(), 0);
        // Nothing goes out after a close frame.
        assert_eq!(
            websocket.send_text("late").await,
            Err(WsError::Closed(None))
        );
    }

    #[tokio::test]
    async fn closing_sends_1000_and_shuts_the_stream_down() {
        let (client_io, mut server) = duplex(1024);
        let mut websocket = WebSocket::new(client_io);
        websocket.close().await.unwrap();
        let mut inbox = Vec::new();
        let close = read_client_frame(&mut server, &mut inbox).await;
        assert!(close.masked);
        assert_eq!(close.opcode, 0x8);
        assert_eq!(close.payload, 1000_u16.to_be_bytes());
        // The shutdown reached the server as end of stream.
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(
            websocket.send_text("late").await,
            Err(WsError::Closed(None))
        );
        // Closing twice does not send a second close frame.
        let _ = websocket.close().await;
    }

    #[tokio::test]
    async fn end_of_stream_is_closed_without_a_code() {
        let (client_io, server) = duplex(1024);
        drop(server);
        let mut websocket = WebSocket::new(client_io);
        assert_eq!(websocket.recv_text().await, Err(WsError::Closed(None)));
    }

    #[tokio::test]
    async fn end_of_stream_inside_a_frame_is_closed_without_a_code() {
        let (client_io, mut server) = duplex(1024);
        let bytes = server_frame(true, 0x1, b"truncated");
        server.write_all(&bytes[..5]).await.unwrap();
        drop(server);
        let mut websocket = WebSocket::new(client_io);
        assert_eq!(websocket.recv_text().await, Err(WsError::Closed(None)));
    }

    #[tokio::test]
    async fn protocol_violations_end_the_receive() {
        let (client_io, mut server) = duplex(1024);
        let mut websocket = WebSocket::new(client_io);
        server
            .write_all(&server_frame(true, 0x2, b"binary"))
            .await
            .unwrap();
        assert!(matches!(
            websocket.recv_text().await,
            Err(WsError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn an_oversized_declared_length_does_not_wait_for_the_bytes() {
        let (client_io, mut server) = duplex(1024);
        let mut websocket = WebSocket::new(client_io);
        // 1 GiB declared, nothing sent after the header, and the server keeps the stream open.
        let header = raw_frame(0x81, 127, &(1_u64 << 30).to_be_bytes(), &[]);
        server.write_all(&header).await.unwrap();
        assert_eq!(
            websocket.recv_text().await,
            Err(WsError::TooLarge(MAX_MESSAGE))
        );
    }

    #[tokio::test]
    async fn a_large_message_in_many_small_reads() {
        let (client_io, mut server) = duplex(1024);
        let message = "x".repeat(300_000);
        let bytes = server_frame(true, 0x1, message.as_bytes());
        let writer = tokio::spawn(async move {
            server.write_all(&bytes).await.unwrap();
            server
        });
        let mut websocket = WebSocket::new(client_io);
        assert_eq!(websocket.recv_text().await, Ok(message));
        let _server = writer.await.unwrap();
    }

    #[test]
    fn debug_shows_only_the_buffer_length() {
        let (client_io, _server) = duplex(16);
        let websocket = WebSocket::new(client_io);
        let text = format!("{websocket:?}");
        assert!(text.contains("buffered: 0"));
        assert!(!text.contains("Duplex") && !text.contains("SystemRandom"));
    }

    // ----- random input -----

    /// A small deterministic generator (xorshift64), so the test needs no dependency.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn byte(&mut self) -> u8 {
            u8::try_from(self.next() & 0xFF).unwrap()
        }
    }

    /// The loop of the fuzz target: decode, assemble, advance.
    fn run_like_the_fuzz_target(data: &[u8], limit: usize) {
        let mut assembler = Assembler::new(limit);
        let mut rest = data;
        while let Ok(Some((frame, consumed))) = decode_frame(rest, limit) {
            assert!(consumed >= 2 && consumed <= rest.len());
            assert!(frame.payload.len() <= limit);
            if assembler.push(frame).is_err() {
                return;
            }
            rest = &rest[consumed..];
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut random = Xorshift(0x9E37_79B9_7F4A_7C15);
        let likely = [
            0x81, 0x01, 0x00, 0x80, 0x82, 0x88, 0x89, 0x8A, 0x09, 0xC1, 0x83, 0xFF,
        ];
        for round in 0..20_000_usize {
            let mut data = Vec::new();
            for _ in 0..=(random.next() % 4) {
                // Mostly plausible first bytes and length bytes, then arbitrary bytes.
                let first = if random.next().is_multiple_of(4) {
                    random.byte()
                } else {
                    likely[usize::try_from(random.next() % 12).unwrap()]
                };
                let second = match random.next() % 4 {
                    0 => random.byte(),
                    1 => 126,
                    2 => 127,
                    _ => u8::try_from(random.next() % 40).unwrap(),
                };
                data.extend_from_slice(&[first, second]);
                for _ in 0..(random.next() % 48) {
                    data.push(if random.next().is_multiple_of(3) {
                        0
                    } else {
                        random.byte()
                    });
                }
            }
            run_like_the_fuzz_target(&data, if round % 2 == 0 { 64 } else { LIMIT });
        }
    }

    // ----- connect against a mock server -----

    #[tokio::test]
    async fn connect_upgrades_and_exchanges_messages() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 1024];
                let read = socket.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "the client closed before the request ended");
                head.extend_from_slice(&chunk[..read]);
            }
            let head = String::from_utf8(head).unwrap();
            let key = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_owned())
                })
                .expect("a Sec-WebSocket-Key header");
            let reply = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept_for(&key)
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket
                .write_all(&server_frame(true, 0x1, b"{\"type\":\"auth_required\"}"))
                .await
                .unwrap();
            let mut inbox = Vec::new();
            let received = read_client_frame(&mut socket, &mut inbox).await;
            (head, key, received)
        });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/api/websocket")).unwrap();
        let mut websocket = connect(&client, url).await.expect("the handshake");
        assert_eq!(
            websocket.recv_text().await,
            Ok("{\"type\":\"auth_required\"}".to_owned())
        );
        websocket.send_text("{\"type\":\"auth\"}").await.unwrap();

        let (head, key, received) = server.await.unwrap();
        let head = head.to_ascii_lowercase();
        assert!(head.starts_with("get /api/websocket http/1.1\r\n"));
        assert!(head.contains("\r\nupgrade: websocket\r\n"));
        assert!(head.contains("\r\nconnection: upgrade\r\n"));
        assert!(head.contains("\r\nsec-websocket-version: 13\r\n"));
        // A base64 key of 16 random bytes: 24 characters ending in two padding characters.
        assert_eq!(key.len(), 24);
        assert!(key.ends_with("=="));
        assert!(received.masked);
        assert_eq!(received.opcode, 0x1);
        assert_eq!(received.payload, b"{\"type\":\"auth\"}");
    }

    #[tokio::test]
    async fn connect_refuses_a_server_that_answers_200() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut chunk = [0_u8; 2048];
            let _ = socket.read(&mut chunk).await.unwrap();
            let reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/api/websocket")).unwrap();
        match connect(&client, url).await {
            Err(ConnectError::Handshake(WsError::Handshake(text))) => assert!(text.contains("200")),
            other => panic!("expected a handshake error, got {other:?}"),
        }
        server.await.unwrap();
    }
}
