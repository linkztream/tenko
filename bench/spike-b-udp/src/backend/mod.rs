//! The crate-specific part of the hot path, behind one small trait.
//!
//! [`respond`] is the complete per-packet hot path used by the server: it is
//! generic over [`Codec`] and identical for both crates except for the two
//! calls `Codec::parse` and `Codec::build`.

use crate::wire::{self, HEADER_LEN, SERVER_EDNS_UDP};
use crate::zone::{NameKey, Outcome, Zone};

#[cfg(feature = "backend-domain")]
pub mod domain_codec;
#[cfg(feature = "backend-hickory")]
pub mod hickory_codec;

#[cfg(feature = "backend-domain")]
pub use domain_codec::DomainCodec;
#[cfg(feature = "backend-hickory")]
pub use hickory_codec::HickoryCodec;

/// EDNS(0) information from the query's OPT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsInfo {
    pub udp_size: u16,
    pub version: u8,
    pub dnssec_ok: bool,
}

/// Crate-independent facts about a parsed query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryMeta {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub qtype: u16,
    pub qclass: u16,
    pub edns: Option<EdnsInfo>,
}

/// Error from a codec; the hot path only needs to know that it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError(pub &'static str);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CodecError {}

/// Parse and build with one DNS wire-format crate.
pub trait Codec: Send + Sync + Sized + 'static {
    /// Short backend name used on the command line and in results.
    const NAME: &'static str;

    /// The crate's parsed form of a query. May borrow from the packet.
    type Query<'a>;

    /// Creates the codec, pre-building the crate's SOA and apex values.
    fn new() -> Self;

    /// Parses header, the sole question and the EDNS OPT record (if any).
    /// Fills `key` (which the caller has cleared) from the question name.
    fn parse<'a>(
        &self,
        req: &'a [u8],
        key: &mut NameKey,
    ) -> Result<(Self::Query<'a>, QueryMeta), CodecError>;

    /// Builds the response for `outcome` into `out` (any previous contents
    /// are discarded; its capacity is reused). The response never exceeds
    /// `max_len` octets unless even the header, question and OPT do not fit:
    /// records that do not fit are dropped and TC is set.
    fn build(
        &self,
        query: &Self::Query<'_>,
        meta: &QueryMeta,
        outcome: Outcome,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), CodecError>;
}

/// Maximum UDP response size for a query: 512 without EDNS, otherwise the
/// client's advertised size clamped to `512..=1232`.
#[inline]
pub fn max_response_len(meta: &QueryMeta) -> usize {
    match meta.edns {
        Some(e) => usize::from(e.udp_size.clamp(512, SERVER_EDNS_UDP)),
        None => 512,
    }
}

/// Decides the outcome for a parsed query.
#[inline]
pub fn decide(zone: &Zone, key: &NameKey, meta: &QueryMeta) -> Outcome {
    if meta.opcode != 0 {
        Outcome::NotImp
    } else if meta.edns.is_some_and(|e| e.version != 0) {
        Outcome::BadVers
    } else {
        zone.lookup(key, meta.qtype, meta.qclass)
    }
}

/// The complete per-packet hot path. Writes the response into `out` and
/// returns true if it should be sent, false if the packet is dropped.
#[inline]
pub fn respond<C: Codec>(
    codec: &C,
    zone: &Zone,
    req: &[u8],
    key: &mut NameKey,
    out: &mut Vec<u8>,
) -> bool {
    // Drop runts and responses (QR=1) so two servers can never loop.
    if req.len() < HEADER_LEN || req[2] & 0x80 != 0 {
        return false;
    }
    key.clear();
    match codec.parse(req, key) {
        Ok((query, meta)) => {
            let outcome = decide(zone, key, &meta);
            match codec.build(&query, &meta, outcome, max_response_len(&meta), out) {
                Ok(()) => true,
                Err(_) => wire::write_formerr(req, out),
            }
        }
        Err(_) => wire::write_formerr(req, out),
    }
}

/// Backend selected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BackendKind {
    #[cfg(feature = "backend-domain")]
    Domain,
    #[cfg(feature = "backend-hickory")]
    Hickory,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "backend-domain")]
            BackendKind::Domain => "domain",
            #[cfg(feature = "backend-hickory")]
            BackendKind::Hickory => "hickory",
        }
    }

    /// All backends compiled into this binary.
    pub fn all() -> Vec<BackendKind> {
        vec![
            #[cfg(feature = "backend-domain")]
            BackendKind::Domain,
            #[cfg(feature = "backend-hickory")]
            BackendKind::Hickory,
        ]
    }
}

#[cfg(test)]
mod tests;
