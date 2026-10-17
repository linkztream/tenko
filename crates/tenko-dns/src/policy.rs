//! Response policy (DNS-15, DNS-23): RPZ zones and block lists, applied after the
//! authoritative lookup and before the forwarder. Every blocked answer carries the
//! extended error of RFC 8914 (`Blocked`, info code 15; `Filtered`, 17).
//!
//! WP5.2 implements the compiled matcher of the list versions; [`NoPolicy`] passes every
//! query.

use std::net::IpAddr;

use tenko_core::dns::{BlockAction, BlockListId, Rtype, ViewId};

/// The extended DNS error info code of a blocked answer (RFC 8914).
pub const EDE_BLOCKED: u16 = 15;

/// The extended DNS error info code of a filtered answer (RFC 8914).
pub const EDE_FILTERED: u16 = 17;

/// What the policy says about a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Answer as usual.
    Pass,
    /// Answer per the list's action.
    Block {
        /// The list that matched.
        list: BlockListId,
        /// What to answer.
        action: &'a BlockAction,
    },
}

/// The policy of response policy zones and block lists.
pub trait PolicyEngine: Send + Sync {
    /// The verdict for a query name (lowercase wire form) and type from a client in a view.
    /// Reads memory only and allocates nothing.
    fn check<'a>(
        &'a self,
        view: Option<ViewId>,
        client: IpAddr,
        qname: &[u8],
        qtype: Rtype,
    ) -> Verdict<'a>;
}

/// The policy that passes everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPolicy;

impl PolicyEngine for NoPolicy {
    fn check<'a>(
        &'a self,
        _view: Option<ViewId>,
        _client: IpAddr,
        _qname: &[u8],
        _qtype: Rtype,
    ) -> Verdict<'a> {
        Verdict::Pass
    }
}
