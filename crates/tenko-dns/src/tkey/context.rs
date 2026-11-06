//! A GSS-TSIG security context (RFC 3645, identity plan section 3.3): who signed, the two
//! MIC keys derived once, the sequence numbers of both directions, the client address and
//! the lifetime.
//!
//! The acceptor's view verifies what the initiator sends (key usage 25) and signs with the
//! acceptor's key (usage 23); an initiator's view (tests and load generators) is the
//! mirror image. The sequence numbers received are checked in a window of 64 above the
//! lowest acceptable number: a number seen before or below the window is refused,
//! reordering inside the window is taken. Nothing here allocates once the context exists.

use std::{
    net::IpAddr,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use tenko_core::dns::{DnsName, PrincipalName, Realm, Sid};
use tenko_krb::mic::{ContextMicKeys, MicKey};

use crate::name::NameBuf;

/// The width of the window of received sequence numbers (identity plan section 3.3).
pub const SEQ_WINDOW: u64 = 64;

/// Who signed an update with GSS-TSIG: the principal with its realm, and from the PAC its
/// SID and its groups (none for a realm without a PAC, such as MIT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssIdentity {
    /// The client principal.
    pub principal: PrincipalName,
    /// The user's SID from the PAC.
    pub sid: Option<Sid>,
    /// The group SIDs from the PAC: primary group, groups, extra SIDs, resource groups.
    pub groups: Vec<Sid>,
}

impl GssIdentity {
    /// The principal's realm.
    pub fn realm(&self) -> &Realm {
        self.principal.realm()
    }
}

/// Which side of the exchange a context is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The server: verifies the initiator's MICs, signs with the acceptor's key.
    Acceptor,
    /// The client: signs with the initiator's key, verifies the acceptor's MICs.
    Initiator,
}

/// The received sequence numbers: the highest seen and a bitmap of the 64 below it.
#[derive(Debug, Clone, Copy)]
struct SeqWindow {
    /// The lowest number the peer may still send (its first sequence number).
    base: u64,
    /// The highest number seen, if any.
    high: Option<u64>,
    /// Bit `i` set: `high - i` was seen.
    seen: u64,
}

impl SeqWindow {
    const fn new(base: u64) -> Self {
        Self {
            base,
            high: None,
            seen: 0,
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if seq < self.base {
            return false;
        }
        let Some(high) = self.high else {
            self.high = Some(seq);
            self.seen = 1;
            return true;
        };
        if seq > high {
            let shift = seq - high;
            self.seen = if shift >= SEQ_WINDOW {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.high = Some(seq);
            return true;
        }
        let back = high - seq;
        if back >= SEQ_WINDOW {
            return false;
        }
        let bit = 1_u64 << back;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

/// An established GSS-TSIG security context.
pub struct GssContext {
    name: NameBuf,
    identity: GssIdentity,
    keys: ContextMicKeys,
    role: Role,
    received: Mutex<SeqWindow>,
    next_send: AtomicU64,
    client: IpAddr,
    established: u64,
    expires: u64,
    last_used: AtomicU64,
}

impl std::fmt::Debug for GssContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssContext")
            .field("name", &self.name.to_string())
            .field("principal", &self.identity.principal.to_string())
            .field("role", &self.role)
            .field("client", &self.client)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// What a context is made of.
#[derive(Debug)]
pub struct ContextParts {
    /// The key name in lowercase wire form.
    pub name: NameBuf,
    /// Who the initiator is.
    pub identity: GssIdentity,
    /// The two MIC keys.
    pub keys: ContextMicKeys,
    /// This side.
    pub role: Role,
    /// The first sequence number this side sends.
    pub send_seq: u64,
    /// The first sequence number the other side sends.
    pub receive_seq: u64,
    /// The client's address (the acceptor's view) or the server's.
    pub client: IpAddr,
    /// When the context was established (Unix seconds).
    pub established: u64,
    /// When it expires (Unix seconds).
    pub expires: u64,
}

impl GssContext {
    /// A context from its parts.
    pub fn new(parts: ContextParts) -> Self {
        Self {
            name: parts.name,
            identity: parts.identity,
            keys: parts.keys,
            role: parts.role,
            received: Mutex::new(SeqWindow::new(parts.receive_seq)),
            next_send: AtomicU64::new(parts.send_seq),
            client: parts.client,
            established: parts.established,
            expires: parts.expires,
            last_used: AtomicU64::new(parts.established),
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

    /// Who the initiator is.
    pub fn identity(&self) -> &GssIdentity {
        &self.identity
    }

    /// This side.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The address the context was negotiated from.
    pub fn client(&self) -> IpAddr {
        self.client
    }

    /// When the context was established (Unix seconds).
    pub fn established(&self) -> u64 {
        self.established
    }

    /// When it expires (Unix seconds).
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// Whether it has expired at `now`.
    pub fn expired(&self, now: u64) -> bool {
        now >= self.expires
    }

    /// The last time it was used (Unix seconds).
    pub fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }

    pub(crate) fn touch(&self, now: u64) {
        self.last_used.fetch_max(now, Ordering::Relaxed);
    }

    /// The key this side signs with.
    pub(crate) fn sending(&self) -> &MicKey {
        match self.role {
            Role::Acceptor => &self.keys.acceptor,
            Role::Initiator => &self.keys.initiator,
        }
    }

    /// The key this side verifies with.
    pub(crate) fn receiving(&self) -> &MicKey {
        match self.role {
            Role::Acceptor => &self.keys.initiator,
            Role::Initiator => &self.keys.acceptor,
        }
    }

    /// The sequence number of the next MIC this side sends.
    pub(crate) fn next_send_seq(&self) -> u64 {
        self.next_send.fetch_add(1, Ordering::Relaxed)
    }

    /// Records a received sequence number; `false` when it was seen before or is below the
    /// window.
    pub(crate) fn accept_seq(&self, seq: u64) -> bool {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .accept(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS-28: the window of 64 takes new numbers and reordering inside it, and refuses a
    /// duplicate, a number below the first and one that fell out of the window.
    #[test]
    fn dns_28_the_sequence_window_refuses_duplicates_and_old_numbers() {
        let mut window = SeqWindow::new(100);
        assert!(!window.accept(99), "below the first number");
        assert!(window.accept(100));
        assert!(!window.accept(100), "a duplicate");
        assert!(window.accept(105));
        assert!(window.accept(102), "reordered inside the window");
        assert!(!window.accept(102));
        assert!(window.accept(101));
        assert!(window.accept(200));
        assert!(!window.accept(105), "out of the window now");
        assert!(window.accept(137), "200 - 63");
        assert!(!window.accept(136), "200 - 64");
        assert!(window.accept(263));
        assert!(window.accept(u64::MAX));
        assert!(!window.accept(u64::MAX));
    }
}
