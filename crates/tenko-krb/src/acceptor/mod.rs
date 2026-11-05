//! The GSS-API acceptor for Kerberos (RFC 4120, RFC 4121) inside SPNEGO (RFC 4178) or
//! raw: what a GSS-TSIG negotiation (RFC 3645, DNS-28) and Kerberos sign-in to the web UI
//! (RFC 4559, IAM-13) run, with keys Tenko holds and no KDC on the path.
//!
//! The interface is the spike's (identity plan section 2.4): a [`Service`] holds the
//! configuration, the keys, the clock the caller hands in and the one replay cache of the
//! node; each negotiation is a [`Negotiation`] whose [`Acceptor::step`] takes the
//! initiator's token and answers [`Step::Continue`] with a token to send back, or
//! [`Step::Established`] with the last token and the [`Context`].
//!
//! The rules (ADR 0026 point 3, the twelve decisions of `bench/spike-krb/RESULT.md`, each a
//! `Decision` comment where it is applied):
//!
//! - Kerberos is the only mechanism chosen, under either OID; NTLM, `NegoEx` and lists
//!   without Kerberos are refused, and so are DCE-style requests.
//! - Mutual authentication is required, and the AP-REP carries an acceptor subkey.
//! - The ticket's realm and service must be the acceptor's, its key is selected by `etype`
//!   and `kvno`, its times and the authenticator's are checked against the caller's clock
//!   with the skew window, and the authenticator is recorded in the replay cache.
//! - A PAC in the ticket must carry a server signature that verifies with the service key;
//!   its SIDs become the context's.
//!
//! The crate never reads the system clock: the [`Clock`] is the caller's.

mod ap;
mod spnego;

pub use ap::GSS_CHECKSUM_TYPE;

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use tenko_core::dns::{PrincipalName, Realm, Sid};

use crate::{
    cipher::{CipherError, Key},
    der::DerError,
    keys::{KeySet, SelectError},
    mic::{ContextMicKeys, MicError},
    pac::{Pac, PacError},
    replay::{DEFAULT_MAX_ENTRIES, ReplayCache, ReplayError},
};

/// The default clock skew allowed, in seconds (RFC 4120 section 1.2 and AD's default).
pub const DEFAULT_MAX_SKEW_SECS: i64 = 300;

/// A point in time as Kerberos uses it: Unix seconds and microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KrbTime {
    /// Unix seconds.
    pub secs: i64,
    /// Microseconds, 0 to 999,999.
    pub usec: u32,
}

impl KrbTime {
    /// A time from Unix seconds.
    pub const fn from_secs(secs: i64) -> Self {
        Self { secs, usec: 0 }
    }

    /// A time from Unix nanoseconds (`tenko_core::timestamp::Timestamp::unix_nanos`).
    pub fn from_unix_nanos(nanos: i128) -> Self {
        let secs = nanos.div_euclid(1_000_000_000);
        let usec = nanos.rem_euclid(1_000_000_000) / 1_000;
        Self {
            secs: i64::try_from(secs).unwrap_or(if secs < 0 { i64::MIN } else { i64::MAX }),
            usec: u32::try_from(usec).unwrap_or(0),
        }
    }
}

/// The caller's clock. The crate never reads the system clock (recorded tokens stay
/// testable, and the node's time source is the node's).
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> KrbTime;
}

/// A clock that always says the same time: for tests and for replaying recorded tokens.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub KrbTime);

impl Clock for FixedClock {
    fn now(&self) -> KrbTime {
        self.0
    }
}

/// The mechanism a negotiation used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    /// A raw Kerberos token, OID 1.2.840.113554.1.2.2.
    Krb5,
    /// A raw Kerberos token under Microsoft's OID 1.2.840.48018.1.2.2.
    MsKrb5,
    /// SPNEGO choosing the standard Kerberos OID.
    SpnegoKrb5,
    /// SPNEGO choosing Microsoft's Kerberos OID.
    SpnegoMsKrb5,
}

/// The GSS flags of the RFC 4121 authenticator checksum.
pub mod gss_flags {
    /// `GSS_C_DELEG_FLAG`.
    pub const DELEG: u32 = 0x01;
    /// `GSS_C_MUTUAL_FLAG`.
    pub const MUTUAL: u32 = 0x02;
    /// `GSS_C_REPLAY_FLAG`.
    pub const REPLAY: u32 = 0x04;
    /// `GSS_C_SEQUENCE_FLAG`.
    pub const SEQUENCE: u32 = 0x08;
    /// `GSS_C_CONF_FLAG`.
    pub const CONF: u32 = 0x10;
    /// `GSS_C_INTEG_FLAG`.
    pub const INTEG: u32 = 0x20;
    /// `GSS_C_DCE_STYLE`.
    pub const DCE_STYLE: u32 = 0x1000;
}

/// An established context: what GSS-TSIG and the web sign-in need of it.
#[derive(Debug, Clone)]
pub struct Context {
    /// The client principal with its realm.
    pub client: PrincipalName,
    /// The mechanism used.
    pub mech: Mech,
    /// The context key with its encryption type: the acceptor subkey (decision 11).
    pub key: Key,
    /// Whether the context key is the acceptor's subkey (the MIC flag 0x04 both ways).
    pub acceptor_subkey: bool,
    /// The next sequence number expected from the initiator: the authenticator's, or one
    /// more when the initiator's `mechListMIC` used it.
    pub initiator_seq: u32,
    /// The next sequence number the acceptor sends: the AP-REP's, or one more when the
    /// acceptor's `mechListMIC` used it (decision 4).
    pub acceptor_seq: u32,
    /// The flags of the authenticator checksum ([`gss_flags`]).
    pub gss_flags: u32,
    /// When the client authenticated to the KDC (Unix seconds).
    pub auth_time: i64,
    /// When the ticket, and so the context, expires (Unix seconds).
    pub expires: i64,
    /// The key version of the service key that decrypted the ticket, when the ticket named
    /// it.
    pub ticket_kvno: Option<u32>,
    /// The PAC, when the ticket carried one; its server signature verified.
    pub pac: Option<Pac>,
}

impl Context {
    /// The client's realm.
    pub fn realm(&self) -> &Realm {
        self.client.realm()
    }

    /// The user's SID from the PAC; none without a PAC (an MIT realm).
    pub fn user_sid(&self) -> Option<&Sid> {
        self.pac.as_ref()?.logon.as_ref().map(|l| &l.user_sid)
    }

    /// The group SIDs from the PAC (primary group, groups, extra SIDs, resource groups).
    pub fn group_sids(&self) -> Vec<Sid> {
        self.pac
            .as_ref()
            .and_then(|p| p.logon.as_ref())
            .map(crate::pac::LogonInfo::groups)
            .unwrap_or_default()
    }

    /// The MIC keys of the context, derived once.
    ///
    /// # Errors
    ///
    /// [`CipherError::Library`] when AES fails.
    pub fn mic_keys(&self) -> Result<ContextMicKeys, CipherError> {
        ContextMicKeys::new(&self.key, self.acceptor_subkey)
    }
}

/// One step of a negotiation.
#[derive(Debug)]
pub enum Step {
    /// Send this token and wait for the initiator's next one.
    Continue(Vec<u8>),
    /// The context is established: send the token (the AP-REP, wrapped as the mechanism
    /// requires) and start signing.
    Established {
        /// The last token.
        token: Vec<u8>,
        /// The context.
        context: Box<Context>,
    },
}

/// Why a token was refused. [`AcceptError::outcome`] names the metric outcome of identity
/// plan section 3.11; the findings of section 3.10 come from the key, skew and type
/// refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    /// The token is not valid DER of the structure it claims to be.
    #[error("malformed token: {0}")]
    Token(#[from] DerError),
    /// No Kerberos mechanism offered (NTLM only, `NegoEx`), or a DCE-style request.
    #[error("refused mechanism: {0}")]
    Mechanism(&'static str),
    /// A request the acceptor does not take: user-to-user, no mutual authentication, no or
    /// a malformed GSS checksum, a KRB-ERROR in place of the AP-REQ.
    #[error("refused request: {0}")]
    Request(&'static str),
    /// The ticket is for another service or realm.
    #[error("the ticket is for {0}, not for this acceptor")]
    WrongService(String),
    /// No key for the ticket: its type is not AES, or its version is not held.
    #[error(transparent)]
    Key(#[from] SelectError),
    /// The ticket does not decrypt under any key of its type and version.
    #[error("the ticket does not decrypt with the service key")]
    TicketKey,
    /// The ticket carries the INVALID flag.
    #[error("the ticket is not valid yet (INVALID flag)")]
    TicketInvalid,
    /// The ticket's start time is in the future beyond the skew.
    #[error("the ticket is not valid until {0}")]
    NotYetValid(i64),
    /// The ticket expired beyond the skew.
    #[error("the ticket expired at {0}")]
    Expired(i64),
    /// The session key or the initiator's subkey is not an AES key.
    #[error("the session key or subkey is refused: {0}")]
    SessionKey(CipherError),
    /// The authenticator does not decrypt with the session key.
    #[error("the authenticator does not decrypt with the session key")]
    Authenticator,
    /// The authenticator names another client than the ticket, or a name Tenko cannot
    /// hold.
    #[error("the authenticator's client does not match the ticket")]
    ClientMismatch,
    /// The authenticator's time is outside the skew window (`dns.gss.clock_skew`).
    #[error("clock skew of {0} s")]
    Skew(i64),
    /// The replay cache refused the authenticator.
    #[error(transparent)]
    Replay(#[from] ReplayError),
    /// The PAC is malformed or its server signature does not verify.
    #[error(transparent)]
    Pac(#[from] PacError),
    /// A `mechListMIC` did not verify or was missing where it is required.
    #[error("mechListMIC: {0}")]
    MechListMic(&'static str),
    /// A token arrived where none, or another kind, was expected.
    #[error("unexpected token: {0}")]
    State(&'static str),
    /// The AES library or the random generator failed.
    #[error("cryptographic failure: {0}")]
    Cipher(CipherError),
}

impl From<MicError> for AcceptError {
    fn from(_: MicError) -> Self {
        AcceptError::MechListMic("does not verify")
    }
}

impl AcceptError {
    /// The outcome label of `tenko_dns_tkey_total` (section 3.11): `mechanism`, `skew`,
    /// `kvno` or `token`.
    pub const fn outcome(&self) -> &'static str {
        match self {
            AcceptError::Mechanism(_) => "mechanism",
            AcceptError::Skew(_) | AcceptError::NotYetValid(_) | AcceptError::Expired(_) => "skew",
            AcceptError::Key(SelectError::KvnoUnknown(_)) => "kvno",
            _ => "token",
        }
    }

    /// The health finding a refusal points at, when it points at one (section 3.10).
    pub const fn finding(&self) -> Option<&'static str> {
        match self {
            AcceptError::Skew(_) => Some(tenko_core::dns::findings::GSS_CLOCK_SKEW),
            AcceptError::Key(SelectError::KvnoUnknown(_)) => {
                Some(tenko_core::dns::findings::GSS_KVNO_UNKNOWN)
            }
            AcceptError::Key(SelectError::UnsupportedEnctype(_)) => {
                Some(tenko_core::dns::findings::GSS_WEAK_ETYPE)
            }
            _ => None,
        }
    }
}

/// The acceptor's configuration: what the `dns` role takes from the vault and the
/// `[dns.gss]` section.
#[derive(Debug, Clone)]
pub struct Config {
    /// The realm the tickets must name.
    pub realm: Realm,
    /// The service principals accepted, as their components without the realm
    /// (`["DNS", "tenko.corp.example.test"]`, `["HTTP", "tenko.corp.example.test"]`).
    pub services: Vec<Vec<String>>,
    /// The clock skew allowed on the ticket and the authenticator, in seconds.
    pub max_skew_secs: i64,
    /// The most entries of the replay cache.
    pub replay_max: usize,
}

impl Config {
    /// A configuration with the default skew and replay bound, for SPNs written as
    /// `service/host`.
    pub fn new(realm: Realm, spns: &[&str]) -> Self {
        Self {
            realm,
            services: spns
                .iter()
                .map(|spn| spn.split('/').map(str::to_owned).collect())
                .collect(),
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
            replay_max: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// The acceptor of a node: its configuration, the account's keys, the caller's clock and
/// the one replay cache every negotiation shares.
pub struct Service {
    config: Config,
    keys: RwLock<Arc<KeySet>>,
    clock: Arc<dyn Clock>,
    replay: Mutex<ReplayCache>,
    #[cfg(test)]
    fixed_subkey: Option<(Key, u32)>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Service {
    /// An acceptor that started at the clock's current time: authenticators from before
    /// then are refused (section 3.3).
    pub fn new(config: Config, keys: KeySet, clock: Arc<dyn Clock>) -> Arc<Self> {
        let started = clock.now().secs;
        let replay = ReplayCache::new(started, config.max_skew_secs, config.replay_max);
        Arc::new(Self {
            config,
            keys: RwLock::new(Arc::new(keys)),
            clock,
            replay: Mutex::new(replay),
            #[cfg(test)]
            fixed_subkey: None,
        })
    }

    /// A service that started at `started`, with a fixed acceptor subkey and sequence
    /// number when given, so that a recorded exchange can be reproduced octet for octet.
    #[cfg(test)]
    pub(crate) fn for_test(
        config: Config,
        keys: KeySet,
        clock: Arc<dyn Clock>,
        started: i64,
        fixed_subkey: Option<(Key, u32)>,
    ) -> Arc<Self> {
        let replay = ReplayCache::new(started, config.max_skew_secs, config.replay_max);
        Arc::new(Self {
            config,
            keys: RwLock::new(Arc::new(keys)),
            clock,
            replay: Mutex::new(replay),
            fixed_subkey,
        })
    }

    /// Replaces the keys (a rotation reaching the `dns` role through the watcher, without
    /// a restart).
    pub fn set_keys(&self, keys: KeySet) {
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// A new negotiation.
    pub fn negotiation(self: &Arc<Self>) -> Negotiation {
        Negotiation {
            service: Arc::clone(self),
            state: State::Start,
        }
    }

    /// Drops the replay cache's entries whose window has passed.
    pub fn prune(&self) {
        let now = self.clock.now().secs;
        self.replay
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .prune(now);
    }

    fn keys(&self) -> Arc<KeySet> {
        Arc::clone(&self.keys.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The GSS acceptor interface of identity plan section 2.4.
pub trait Acceptor {
    /// Feeds the initiator's next token.
    ///
    /// # Errors
    ///
    /// An [`AcceptError`]; the negotiation is then over.
    fn step(&mut self, token: &[u8]) -> Result<Step, AcceptError>;
}

#[derive(Debug)]
enum State {
    Start,
    /// SPNEGO chose Kerberos, which was not the initiator's first choice or came without
    /// a token: the initiator's Kerberos token must come in a `negTokenResp`.
    AwaitToken {
        mech: Mech,
        mech_types_der: Vec<u8>,
    },
    /// The context is ready, but RFC 4178 requires the initiator's `mechListMIC`.
    AwaitMic {
        context: Box<Context>,
        mech_types_der: Vec<u8>,
    },
    Done,
}

/// One negotiation (one TKEY exchange, one `Authorization: Negotiate` exchange).
#[derive(Debug)]
pub struct Negotiation {
    service: Arc<Service>,
    state: State,
}

impl Acceptor for Negotiation {
    fn step(&mut self, token: &[u8]) -> Result<Step, AcceptError> {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Start => spnego::first(self, token),
            State::AwaitToken {
                mech,
                mech_types_der,
            } => spnego::token_leg(self, token, mech, mech_types_der),
            State::AwaitMic {
                context,
                mech_types_der,
            } => spnego::mic_leg(token, *context, &mech_types_der),
            State::Done => Err(AcceptError::State("the negotiation is over")),
        }
    }
}

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;
