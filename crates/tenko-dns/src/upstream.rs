//! Upstream resolvers of the forwarder (DNS-02, DNS-08, TGL-14).
//!
//! An [`Upstream`] sends one query to one resolver over its transport and returns the
//! answer's octets. The forwarder of WP4.3 (plain) and WP5.1 (DoT, DoH, pools with health
//! and RTT choice, 0x20, port randomisation) implements it; the resolver never talks to the
//! network itself.

use std::{future::Future, net::SocketAddr, time::Instant};

use tenko_core::dns::ForwardTransport;

/// Why an exchange with an upstream failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// No answer before the deadline.
    #[error("the upstream did not answer in time")]
    Timeout,
    /// The connection or the TLS session failed.
    #[error("the upstream could not be reached: {0}")]
    Unreachable(&'static str),
    /// The answer does not match the query (id, question, 0x20 case) or does not parse.
    #[error("the upstream answer is malformed: {0}")]
    Malformed(&'static str),
}

/// One upstream resolver.
pub trait Upstream: Send + Sync {
    /// The transport.
    fn transport(&self) -> ForwardTransport;

    /// The resolver's address.
    fn address(&self) -> SocketAddr;

    /// Sends `query` and writes the answer into `answer` (replaced) before `deadline`.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] for a timeout, a failed connection or a malformed answer.
    fn exchange<'a>(
        &'a self,
        query: &'a [u8],
        answer: &'a mut Vec<u8>,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'a;
}
