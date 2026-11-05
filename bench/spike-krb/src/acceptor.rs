//! The interface Tenko's `tenko-krb` would expose (identity plan, section 2.4):
//! `Acceptor::step(token) -> Continue(token) | Established(context, token)`, and what a
//! GSS-TSIG context needs from the library underneath.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES enctypes of RFC 3962. RC4, DES and 3DES are not accepted (ADR 0026, point 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enctype {
    /// aes128-cts-hmac-sha1-96 (17).
    Aes128,
    /// aes256-cts-hmac-sha1-96 (18).
    Aes256,
}

impl Enctype {
    /// The enctype number of RFC 3961.
    pub fn number(self) -> u8 {
        match self {
            Enctype::Aes128 => 17,
            Enctype::Aes256 => 18,
        }
    }

    /// The key length in octets.
    pub fn key_len(self) -> usize {
        match self {
            Enctype::Aes128 => 16,
            Enctype::Aes256 => 32,
        }
    }

    /// From the enctype number; anything but the two AES types is refused.
    pub fn from_number(n: i64) -> Option<Self> {
        match n {
            17 => Some(Enctype::Aes128),
            18 => Some(Enctype::Aes256),
            _ => None,
        }
    }

    /// From a key length, for libraries that hand over a key without its type.
    pub fn from_key_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(Enctype::Aes128),
            32 => Some(Enctype::Aes256),
            _ => None,
        }
    }
}

/// One long-term key of the service account, as Tenko would hold it in the vault.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServiceKey {
    #[zeroize(skip)]
    pub enctype: Enctype,
    /// The key version number; `None` accepts any kvno.
    #[zeroize(skip)]
    pub kvno: Option<u32>,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for ServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ServiceKey({:?}, kvno {:?}, {} octets)",
            self.enctype,
            self.kvno,
            self.key.len()
        )
    }
}

/// The mechanism the initiator used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    /// Raw Kerberos token, OID 1.2.840.113554.1.2.2.
    Krb5,
    /// Raw Kerberos token with the Microsoft OID 1.2.840.48018.1.2.2.
    MsKrb5,
    /// SPNEGO carrying Kerberos (OID 1.2.840.113554.1.2.2).
    SpnegoKrb5,
    /// SPNEGO carrying Kerberos with the Microsoft OID.
    SpnegoMsKrb5,
}

/// The established context, as GSS-TSIG needs it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Context {
    /// The client principal without the realm.
    #[zeroize(skip)]
    pub client: String,
    /// The client realm.
    #[zeroize(skip)]
    pub realm: String,
    #[zeroize(skip)]
    pub mech: Mech,
    /// The key per-message tokens use: the acceptor subkey when the AP-REP carried one,
    /// else the initiator's subkey, else the ticket session key (RFC 4121, section 2).
    pub key: Vec<u8>,
    #[zeroize(skip)]
    pub key_enctype: Enctype,
    /// Whether `key` is an acceptor subkey (MIC flag 0x04 is then set both ways).
    #[zeroize(skip)]
    pub acceptor_subkey: bool,
    /// The initiator's sequence number from the authenticator, when the library gives it.
    #[zeroize(skip)]
    pub initiator_seq: Option<u32>,
    /// The acceptor's first sequence number, carried in the AP-REP.
    #[zeroize(skip)]
    pub acceptor_seq: u32,
    /// The flags of the RFC 4121 authenticator checksum (GSS_C_MUTUAL_FLAG 0x02,
    /// GSS_C_REPLAY_FLAG 0x04, GSS_C_SEQUENCE_FLAG 0x08, GSS_C_INTEG_FLAG 0x20,
    /// GSS_C_DCE_STYLE 0x1000), when the library gives them.
    #[zeroize(skip)]
    pub gss_flags: Option<u32>,
    /// The ticket's end time as unix seconds, when the library gives it.
    #[zeroize(skip)]
    pub expires_unix: Option<i64>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("client", &self.client)
            .field("realm", &self.realm)
            .field("mech", &self.mech)
            .field("key_enctype", &self.key_enctype)
            .field("acceptor_subkey", &self.acceptor_subkey)
            .field("initiator_seq", &self.initiator_seq)
            .field("acceptor_seq", &self.acceptor_seq)
            .field("gss_flags", &self.gss_flags.map(|f| format!("{f:#x}")))
            .field("expires_unix", &self.expires_unix)
            .finish()
    }
}

/// One step of the negotiation.
#[derive(Debug)]
pub enum Step {
    /// Send this token and wait for the next one.
    Continue(Vec<u8>),
    /// The context is established; send the token (the AP-REP, wrapped as the mechanism
    /// requires) and start signing.
    Established { token: Vec<u8>, context: Context },
}

/// Why a token was refused. The spike keeps the library's text; Tenko would map these to
/// its `dns.gss.*` codes.
#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_owned())
    }
}

/// A GSS acceptor for one TKEY negotiation.
pub trait Acceptor {
    /// Feeds the initiator's token.
    fn step(&mut self, token: &[u8]) -> Result<Step, Error>;
}
