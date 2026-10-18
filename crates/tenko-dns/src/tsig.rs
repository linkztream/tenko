//! TSIG on the wire (RFC 8945): sign and verify messages with a shared key, and the MAC
//! chain of a transfer that spans several messages.
//!
//! The MAC of a request covers the message as it was before the TSIG record was added (the
//! original id in the header, ARCOUNT one lower, the octets up to the TSIG record) followed
//! by the TSIG variables: the key name and the algorithm name in canonical wire form,
//! class ANY, TTL 0, the time signed, the fudge, the error and the other data. The MAC of
//! an answer is computed the same way with the request's MAC (its length and octets) in
//! front. In an answer of several messages (AXFR, IXFR, section 5.3.1) the first message
//! is signed like a single answer and every later one covers the previous MAC, the
//! messages since it and only the timers (time signed and fudge). Tenko signs every
//! message it sends; when it verifies, it takes up to 99 unsigned messages between two
//! signed ones, as section 5.3.1 lets a server send them.
//!
//! Verification checks, in the order of section 5.2: the key (BADKEY), the MAC (BADSIG;
//! a MAC shorter than half the hash or 10 octets is FORMERR), then the time window of
//! [`FUDGE`] seconds (BADTIME). A refused request is answered NOTAUTH with the TSIG error;
//! BADKEY and BADSIG answers carry an empty MAC, a BADTIME answer is signed and carries
//! the server's time ([`refusal_tsig`]).
//!
//! Keys come from the zone service's key access ([`crate::zone::ZoneService::tsig_key`])
//! into a [`Keyring`] that the transfer and NOTIFY paths read without a lock. Once the key
//! is resolved, verifying and signing allocate nothing: the MAC is computed in place with
//! an HMAC context over the message's slices.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use aws_lc_rs::{constant_time, hmac};
use tenko_core::dns::{DnsName, TsigAlgorithm};

use crate::{
    name::NameBuf,
    wire::{self, CLASS_ANY, HEADER_LEN, TYPE_TSIG, TsigRecord},
};

/// The permitted clock error Tenko signs with and accepts, in seconds (RFC 8945 section
/// 10 recommends 300).
pub const FUDGE: u16 = 300;

/// The RCODE of a refused TSIG message (NOTAUTH).
pub const RCODE_NOTAUTH: u16 = 9;

/// The TSIG error codes (RFC 8945 section 3).
pub mod error {
    /// The MAC does not verify.
    pub const BADSIG: u16 = 16;
    /// The key is not known, or the algorithm is not the key's.
    pub const BADKEY: u16 = 17;
    /// The time signed is outside the fudge.
    pub const BADTIME: u16 = 18;
    /// The MAC was truncated more than allowed.
    pub const BADTRUNC: u16 = 22;
}

/// The longest MAC (HMAC-SHA512).
pub const MAX_MAC: usize = 64;

/// The wire form of an algorithm's name.
pub const fn algorithm_wire(algorithm: TsigAlgorithm) -> &'static [u8] {
    match algorithm {
        TsigAlgorithm::HmacSha256 => b"\x0bhmac-sha256\x00",
        TsigAlgorithm::HmacSha384 => b"\x0bhmac-sha384\x00",
        TsigAlgorithm::HmacSha512 => b"\x0bhmac-sha512\x00",
        TsigAlgorithm::HmacSha1 => b"\x09hmac-sha1\x00",
    }
}

/// The algorithm of a name in lowercase wire form, if Tenko knows it.
pub fn algorithm_of(wire: &[u8]) -> Option<TsigAlgorithm> {
    [
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
        TsigAlgorithm::HmacSha1,
    ]
    .into_iter()
    .find(|algorithm| algorithm_wire(*algorithm) == wire)
}

const fn hmac_algorithm(algorithm: TsigAlgorithm) -> hmac::Algorithm {
    match algorithm {
        TsigAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
        TsigAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
        TsigAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
        TsigAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
    }
}

/// The length of an algorithm's full MAC.
pub const fn mac_len(algorithm: TsigAlgorithm) -> usize {
    match algorithm {
        TsigAlgorithm::HmacSha256 => 32,
        TsigAlgorithm::HmacSha384 => 48,
        TsigAlgorithm::HmacSha512 => 64,
        TsigAlgorithm::HmacSha1 => 20,
    }
}

/// A TSIG key ready to sign and verify: the name, the algorithm and the HMAC key.
pub struct TsigKey {
    name: NameBuf,
    algorithm: TsigAlgorithm,
    key: hmac::Key,
}

impl std::fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name.to_string())
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl TsigKey {
    /// A key from its name, algorithm and secret.
    pub fn new(name: &DnsName, algorithm: TsigAlgorithm, secret: &[u8]) -> Self {
        Self {
            name: NameBuf::from_dns_name(name),
            algorithm,
            key: hmac::Key::new(hmac_algorithm(algorithm), secret),
        }
    }

    /// The key name in lowercase wire form.
    pub fn name_wire(&self) -> &[u8] {
        self.name.as_wire()
    }

    /// The key name.
    pub fn name(&self) -> Option<DnsName> {
        self.name.to_dns_name()
    }

    /// The algorithm.
    pub fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }
}

/// The keys the transfer and NOTIFY paths know, by name in lowercase wire form; swapped
/// whole when the keys change.
#[derive(Debug, Default)]
pub struct Keyring {
    keys: ArcSwap<HashMap<Box<[u8]>, Arc<TsigKey>>>,
}

impl Keyring {
    /// A keyring holding `keys`.
    pub fn new(keys: impl IntoIterator<Item = TsigKey>) -> Self {
        let ring = Self::default();
        ring.replace(keys);
        ring
    }

    /// Replaces every key.
    pub fn replace(&self, keys: impl IntoIterator<Item = TsigKey>) {
        let map = keys
            .into_iter()
            .map(|key| (Box::<[u8]>::from(key.name_wire()), Arc::new(key)))
            .collect();
        self.keys.store(Arc::new(map));
    }

    /// Replaces every key with keys already shared.
    pub fn replace_shared(&self, keys: impl IntoIterator<Item = Arc<TsigKey>>) {
        let map = keys
            .into_iter()
            .map(|key| (Box::<[u8]>::from(key.name_wire()), key))
            .collect();
        self.keys.store(Arc::new(map));
    }

    /// The key of a name in lowercase wire form.
    pub fn get(&self, name: &[u8]) -> Option<Arc<TsigKey>> {
        self.keys.load().get(name).cloned()
    }

    /// The key of a name.
    pub fn by_name(&self, name: &DnsName) -> Option<Arc<TsigKey>> {
        self.get(&name.to_wire())
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.load().len()
    }

    /// Whether the keyring holds no key.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A MAC of at most [`MAX_MAC`] octets, held without allocating.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mac {
    bytes: [u8; MAX_MAC],
    len: usize,
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mac({} octets)", self.len)
    }
}

impl Default for Mac {
    fn default() -> Self {
        Self::empty()
    }
}

impl Mac {
    /// No MAC.
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_MAC],
            len: 0,
        }
    }

    fn from_slice(slice: &[u8]) -> Self {
        let mut mac = Self::empty();
        let len = slice.len().min(MAX_MAC);
        mac.bytes[..len].copy_from_slice(&slice[..len]);
        mac.len = len;
        mac
    }

    /// The octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn feed(&self, ctx: &mut hmac::Context) {
        let len = u16::try_from(self.len).unwrap_or(0);
        ctx.update(&len.to_be_bytes());
        ctx.update(self.as_bytes());
    }
}

/// The TSIG record of a message, as positions in it (RFC 8945 section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsigView<'a> {
    /// Where the TSIG record starts: the MAC covers the octets before it.
    pub record_start: usize,
    /// The key name in lowercase wire form.
    pub key: &'a [u8],
    /// The algorithm name in wire form, as written (compared lowercase).
    pub algorithm: &'a [u8],
    /// Seconds since 1970 (48 bits).
    pub time_signed: u64,
    /// Permitted clock error in seconds.
    pub fudge: u16,
    /// The MAC.
    pub mac: &'a [u8],
    /// The original message id.
    pub original_id: u16,
    /// The TSIG error.
    pub error: u16,
    /// Other data.
    pub other: &'a [u8],
}

/// Why a message's TSIG record could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TsigFormError {
    /// The message does not parse up to its last record.
    #[error("the message does not parse")]
    Message,
    /// A TSIG record that is not the last record, or whose data does not parse.
    #[error("malformed TSIG record")]
    Record,
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

/// The TSIG record of a message (a query or an answer), if it has one. TSIG names are not
/// compressed (RFC 8945 section 4.2), so the key and the algorithm are slices of the
/// message.
///
/// # Errors
///
/// [`TsigFormError`] when the message does not parse or the TSIG record is not the last.
pub fn find(message: &[u8]) -> Result<Option<TsigView<'_>>, TsigFormError> {
    let header = wire::parse_header(message).ok_or(TsigFormError::Message)?;
    let mut pos = wire::questions_end(message, header.qdcount).ok_or(TsigFormError::Message)?;
    let records = usize::from(header.ancount) + usize::from(header.nscount);
    let additional = usize::from(header.arcount);
    for index in 0..records + additional {
        let record = wire::read_record(message, pos).ok_or(TsigFormError::Message)?;
        if record.rtype == TYPE_TSIG {
            if index + 1 != records + additional || index < records {
                return Err(TsigFormError::Record);
            }
            return view(message, &record).map(Some);
        }
        pos = record.end();
    }
    Ok(None)
}

fn view<'a>(message: &'a [u8], record: &wire::RawRecord) -> Result<TsigView<'a>, TsigFormError> {
    let bad = TsigFormError::Record;
    if record.class != CLASS_ANY || record.ttl != 0 {
        return Err(bad);
    }
    let key = message.get(record.start..record.fixed).ok_or(bad)?;
    if key.last() != Some(&0) {
        return Err(bad);
    }
    let algorithm_end = wire::skip_name(message, record.rdata).ok_or(bad)?;
    let algorithm = &message[record.rdata..algorithm_end];
    if algorithm.last() != Some(&0) {
        return Err(bad);
    }
    let fixed = message.get(algorithm_end..algorithm_end + 10).ok_or(bad)?;
    let time_signed = u64::from_be_bytes([
        0, 0, fixed[0], fixed[1], fixed[2], fixed[3], fixed[4], fixed[5],
    ]);
    let fudge = u16::from_be_bytes([fixed[6], fixed[7]]);
    let mac_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    let mac_start = algorithm_end + 10;
    let mac = message.get(mac_start..mac_start + mac_len).ok_or(bad)?;
    let tail = mac_start + mac_len;
    let original_id = u16_at(message, tail).ok_or(bad)?;
    let error = u16_at(message, tail + 2).ok_or(bad)?;
    let other_len = usize::from(u16_at(message, tail + 4).ok_or(bad)?);
    let other = message.get(tail + 6..tail + 6 + other_len).ok_or(bad)?;
    if tail + 6 + other_len != record.end() {
        return Err(bad);
    }
    Ok(TsigView {
        record_start: record.start,
        key,
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
    })
}

/// Feeds the message before its TSIG record, as it was before signing: the original id and
/// ARCOUNT one lower.
fn feed_message(ctx: &mut hmac::Context, message: &[u8], tsig: &TsigView<'_>) {
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&message[..HEADER_LEN]);
    header[..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    let arcount = u16::from_be_bytes([header[10], header[11]]).saturating_sub(1);
    header[10..12].copy_from_slice(&arcount.to_be_bytes());
    ctx.update(&header);
    ctx.update(&message[HEADER_LEN..tsig.record_start]);
}

/// The TSIG variables of a whole first message (RFC 8945 section 4.3.3).
#[allow(
    clippy::too_many_arguments,
    reason = "the fields of the TSIG variables"
)]
fn feed_variables(
    ctx: &mut hmac::Context,
    key: &[u8],
    algorithm: &[u8],
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) {
    ctx.update(key);
    ctx.update(&CLASS_ANY.to_be_bytes());
    ctx.update(&0u32.to_be_bytes());
    let mut lower = [0u8; 256];
    let len = algorithm.len().min(lower.len());
    for (to, from) in lower.iter_mut().zip(&algorithm[..len]) {
        *to = from.to_ascii_lowercase();
    }
    ctx.update(&lower[..len]);
    feed_timers(ctx, time_signed, fudge);
    ctx.update(&error.to_be_bytes());
    let other_len = u16::try_from(other.len()).unwrap_or(u16::MAX);
    ctx.update(&other_len.to_be_bytes());
    ctx.update(other);
}

fn feed_timers(ctx: &mut hmac::Context, time_signed: u64, fudge: u16) {
    ctx.update(&time_signed.to_be_bytes()[2..]);
    ctx.update(&fudge.to_be_bytes());
}

/// Why a TSIG message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TsigError {
    /// The key is unknown or its algorithm differs (BADKEY).
    #[error("unknown key or algorithm (BADKEY)")]
    BadKey,
    /// The MAC does not verify (BADSIG).
    #[error("the MAC does not verify (BADSIG)")]
    BadSig,
    /// The time signed is outside the fudge (BADTIME).
    #[error("the time signed is outside the window (BADTIME)")]
    BadTime,
    /// The MAC is truncated below the allowed length (FORMERR, RFC 8945 section 5.2.2.1).
    #[error("the MAC is truncated below the allowed length")]
    Truncated,
    /// The message has no TSIG record where one is required.
    #[error("the message is not signed")]
    Unsigned,
    /// The TSIG record is malformed.
    #[error("malformed TSIG record")]
    Malformed,
    /// The other side answered with this TSIG error.
    #[error("the server answered with TSIG error {0}")]
    Peer(u16),
}

impl TsigError {
    /// The TSIG error code to answer with; 0 for errors answered with FORMERR.
    pub const fn code(self) -> u16 {
        match self {
            TsigError::BadKey => error::BADKEY,
            TsigError::BadSig => error::BADSIG,
            TsigError::BadTime => error::BADTIME,
            _ => 0,
        }
    }
}

fn mac_length_ok(algorithm: TsigAlgorithm, len: usize) -> Result<(), TsigError> {
    let full = mac_len(algorithm);
    if len > full {
        return Err(TsigError::BadSig);
    }
    if len < full && (len < 10 || len < full / 2) {
        return Err(TsigError::Truncated);
    }
    Ok(())
}

fn compare(computed: &hmac::Tag, received: &[u8]) -> Result<Mac, TsigError> {
    let computed = computed.as_ref();
    let head = computed.get(..received.len()).ok_or(TsigError::BadSig)?;
    constant_time::verify_slices_are_equal(head, received).map_err(|_| TsigError::BadSig)?;
    Ok(Mac::from_slice(received))
}

fn in_window(time_signed: u64, fudge: u16, now: u64) -> bool {
    now.abs_diff(time_signed) <= u64::from(fudge)
}

/// A verified request: its key and its MAC, which the answer's MAC covers.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The key.
    pub key: Arc<TsigKey>,
    /// The request's MAC.
    pub mac: Mac,
    /// The time the request was signed (a BADTIME answer echoes it).
    pub time_signed: u64,
}

/// A refused request: the error, and the key and MAC when the key was known (a BADTIME
/// answer is signed with them).
#[derive(Debug, Clone)]
pub struct Refused {
    /// Why.
    pub error: TsigError,
    /// The key, when known.
    pub key: Option<Arc<TsigKey>>,
    /// The request's MAC, when it verified (BADTIME).
    pub mac: Mac,
    /// The request's time signed.
    pub time_signed: u64,
}

/// Verifies a signed request (a query, a NOTIFY) at `now` (seconds since 1970).
///
/// # Errors
///
/// [`Refused`] with BADKEY, BADSIG, BADTIME or a truncated MAC.
pub fn verify_request(
    keyring: &Keyring,
    message: &[u8],
    tsig: &TsigView<'_>,
    now: u64,
) -> Result<Verified, Box<Refused>> {
    let refuse = |error, key, mac| {
        Box::new(Refused {
            error,
            key,
            mac,
            time_signed: tsig.time_signed,
        })
    };
    let Some(key) = keyring.get(tsig.key) else {
        return Err(refuse(TsigError::BadKey, None, Mac::empty()));
    };
    if !wire_eq(algorithm_wire(key.algorithm), tsig.algorithm) {
        return Err(refuse(TsigError::BadKey, None, Mac::empty()));
    }
    if let Err(error) = mac_length_ok(key.algorithm, tsig.mac.len()) {
        return Err(refuse(error, None, Mac::empty()));
    }
    let mut ctx = hmac::Context::with_key(&key.key);
    feed_message(&mut ctx, message, tsig);
    feed_variables(
        &mut ctx,
        tsig.key,
        tsig.algorithm,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        tsig.other,
    );
    let mac = match compare(&ctx.sign(), tsig.mac) {
        Ok(mac) => mac,
        Err(error) => return Err(refuse(error, None, Mac::empty())),
    };
    if !in_window(tsig.time_signed, tsig.fudge, now) {
        return Err(refuse(TsigError::BadTime, Some(key), mac));
    }
    Ok(Verified {
        key,
        mac,
        time_signed: tsig.time_signed,
    })
}

fn wire_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Signs the messages of one side of an exchange, in order: a request (no prior MAC) or the
/// answers to a verified request (the request's MAC first, then the MAC chain).
#[derive(Debug, Clone)]
pub struct Signer {
    key: Arc<TsigKey>,
    prior: Option<Mac>,
    first: bool,
    pending: Option<hmac::Context>,
}

impl Signer {
    /// A signer of a request.
    pub fn request(key: Arc<TsigKey>) -> Self {
        Self {
            key,
            prior: None,
            first: true,
            pending: None,
        }
    }

    /// A signer of the answers to a request whose MAC was `request_mac`.
    pub fn answer(key: Arc<TsigKey>, request_mac: Mac) -> Self {
        Self {
            key,
            prior: Some(request_mac),
            first: true,
            pending: None,
        }
    }

    /// The key.
    pub fn key(&self) -> &Arc<TsigKey> {
        &self.key
    }

    /// The MAC of the last message signed (what the answer to a request covers).
    pub fn last_mac(&self) -> Option<Mac> {
        self.prior
    }

    /// Signs the finished message in `out` at `now` with the TSIG `error` and `other` data
    /// and appends the TSIG record. Returns `false` when the record does not fit in
    /// `max_len`; `out` is then unchanged.
    pub fn sign(
        &mut self,
        out: &mut Vec<u8>,
        now: u64,
        error: u16,
        other: &[u8],
        max_len: usize,
    ) -> bool {
        if out.len() < HEADER_LEN {
            return false;
        }
        let mut ctx = self.pending.clone().unwrap_or_else(|| self.start());
        ctx.update(out);
        let algorithm = algorithm_wire(self.key.algorithm);
        if self.first {
            feed_variables(
                &mut ctx,
                self.key.name_wire(),
                algorithm,
                now,
                FUDGE,
                error,
                other,
            );
        } else {
            feed_timers(&mut ctx, now, FUDGE);
        }
        let tag = ctx.sign();
        let original_id = u16::from_be_bytes([out[0], out[1]]);
        let record = TsigRecord {
            key: self.key.name_wire(),
            algorithm,
            time_signed: now,
            fudge: FUDGE,
            mac: tag.as_ref(),
            original_id,
            error,
            other,
        };
        if !wire::append_tsig(out, &record, max_len) {
            return false;
        }
        self.prior = Some(Mac::from_slice(tag.as_ref()));
        self.first = false;
        self.pending = None;
        true
    }

    /// Sends a message of an answer unsigned: the next signed message covers it (RFC 8945
    /// section 5.3.1). Tenko signs every message it sends; a peer may not.
    pub fn leave_unsigned(&mut self, message: &[u8]) {
        let mut ctx = self.pending.take().unwrap_or_else(|| self.start());
        ctx.update(message);
        self.pending = Some(ctx);
    }

    fn start(&self) -> hmac::Context {
        let mut ctx = hmac::Context::with_key(&self.key.key);
        if let Some(prior) = &self.prior {
            prior.feed(&mut ctx);
        }
        ctx
    }
}

/// Appends the TSIG record of a refused request to the NOTAUTH answer in `out`: an empty
/// MAC for BADKEY and BADSIG, a signed record with the server's time in the other data
/// for BADTIME (RFC 8945 section 5.2.3). Returns `false` when it does not fit.
pub fn refusal_tsig(
    out: &mut Vec<u8>,
    refused: &Refused,
    tsig: &TsigView<'_>,
    now: u64,
    max_len: usize,
) -> bool {
    if let (Some(key), TsigError::BadTime) = (&refused.key, refused.error) {
        {
            let time = now.to_be_bytes();
            let mut signer = Signer::answer(Arc::clone(key), refused.mac);
            signer.sign(
                out,
                refused.time_signed,
                error::BADTIME,
                &time[2..],
                max_len,
            )
        }
    } else {
        {
            let original_id = u16::from_be_bytes([out[0], out[1]]);
            let record = TsigRecord {
                key: tsig.key,
                algorithm: tsig.algorithm,
                time_signed: tsig.time_signed,
                fudge: tsig.fudge,
                mac: &[],
                original_id,
                error: refused.error.code(),
                other: &[],
            };
            wire::append_tsig(out, &record, max_len)
        }
    }
}

/// Verifies the answers to a request this side signed, in order, with the MAC chain: the
/// first must be signed, later ones may leave up to 99 messages in between unsigned.
#[derive(Debug)]
pub struct Verifier {
    key: Arc<TsigKey>,
    prior: Mac,
    first: bool,
    pending: Option<hmac::Context>,
    unsigned: usize,
}

/// Unsigned messages a verifier takes between two signed ones (RFC 8945 section 5.3.1).
pub const MAX_UNSIGNED: usize = 99;

impl Verifier {
    /// A verifier of the answers to a request whose MAC was `request_mac`.
    pub fn new(key: Arc<TsigKey>, request_mac: Mac) -> Self {
        Self {
            key,
            prior: request_mac,
            first: true,
            pending: None,
            unsigned: 0,
        }
    }

    /// Verifies the next message at `now`.
    ///
    /// # Errors
    ///
    /// [`TsigError`]: a missing, malformed or wrong signature, a TSIG error from the
    /// server, or a time outside the window.
    pub fn verify(&mut self, message: &[u8], now: u64) -> Result<(), TsigError> {
        let tsig = find(message).map_err(|_| TsigError::Malformed)?;
        let Some(tsig) = tsig else {
            if self.first || self.unsigned >= MAX_UNSIGNED {
                return Err(TsigError::Unsigned);
            }
            let ctx = self.pending.get_or_insert_with(|| {
                let mut ctx = hmac::Context::with_key(&self.key.key);
                self.prior.feed(&mut ctx);
                ctx
            });
            ctx.update(message);
            self.unsigned += 1;
            return Ok(());
        };
        if tsig.error != 0 {
            return Err(TsigError::Peer(tsig.error));
        }
        if !wire_eq(tsig.key, self.key.name_wire())
            || !wire_eq(tsig.algorithm, algorithm_wire(self.key.algorithm))
        {
            return Err(TsigError::BadKey);
        }
        mac_length_ok(self.key.algorithm, tsig.mac.len())?;
        let mut ctx = self.pending.take().unwrap_or_else(|| {
            let mut ctx = hmac::Context::with_key(&self.key.key);
            self.prior.feed(&mut ctx);
            ctx
        });
        feed_message(&mut ctx, message, &tsig);
        if self.first {
            feed_variables(
                &mut ctx,
                tsig.key,
                tsig.algorithm,
                tsig.time_signed,
                tsig.fudge,
                tsig.error,
                tsig.other,
            );
        } else {
            feed_timers(&mut ctx, tsig.time_signed, tsig.fudge);
        }
        self.prior = compare(&ctx.sign(), tsig.mac)?;
        if !in_window(tsig.time_signed, tsig.fudge, now) {
            return Err(TsigError::BadTime);
        }
        self.first = false;
        self.unsigned = 0;
        Ok(())
    }

    /// Whether the last message verified was signed: a transfer must end on one.
    pub fn complete(&self) -> bool {
        !self.first && self.pending.is_none()
    }
}

#[cfg(test)]
mod tests;
