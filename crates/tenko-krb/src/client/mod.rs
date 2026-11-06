//! The Kerberos client half of the controller (identity plan section 3.1; DNS-28): the
//! self-test and the rotation of the service account use it, the data plane never does.
//!
//! - [`AsExchange`]: the AS exchange (RFC 4120 section 3.1) with `PA-ENC-TIMESTAMP`
//!   pre-authentication; the key is derived from the password with the salt and iteration
//!   count of the KDC's `PA-ETYPE-INFO2` (the MS-KILE salt for an AD computer account), or
//!   taken from the account's key set.
//! - [`TgsExchange`]: the TGS exchange (section 3.3) for a service principal, which tells
//!   the self-test the key version the KDC issues and gives it a ticket to hand to the
//!   node's own acceptor ([`initiator_token`]).
//! - [`ChangePassword`]: the change-password protocol of RFC 3244 (version `0xff80`, the
//!   ticket's own principal) over `KRB-PRIV` to port 464.
//!
//! Each exchange is a value that builds its requests and reads its answers from octets,
//! with the time and the nonce given by the caller; [`Client`] runs them over the
//! transport of [`transport`] to the servers the caller lists. The crate reads no clock,
//! no `krb5.conf` and no credential cache.

pub mod transport;

use std::{net::IpAddr, net::SocketAddr, sync::Arc};

use tenko_core::dns::{EncryptionType, PrincipalName};
use zeroize::Zeroizing;

use crate::{
    acceptor::{Clock, KrbTime, gss_flags},
    cipher::{self, CipherError, Key, usage},
    der::{
        self, ApRep, ApReq, Authenticator, ChangePasswdData, Checksum, DerError, EncApRepPart,
        EncKdcRepPart, EncKrbPrivPart, HostAddress, KdcRep, KdcReq, KdcReqBody, KrbError, KrbPriv,
        KrbToken, PaData, PaEncTsEnc, Ticket, gss::tok_id, kdc_options, msg_type, name_type,
        pa_type, tag,
    },
    keys::KeySet,
};
use transport::TransportConfig;

/// KDC error codes (RFC 4120 section 7.5.9) the controller reports by name.
pub mod error_code {
    /// The client is not in the database.
    pub const C_PRINCIPAL_UNKNOWN: i32 = 6;
    /// The server is not in the database.
    pub const S_PRINCIPAL_UNKNOWN: i32 = 7;
    /// The client's credentials were revoked (the account is disabled or locked).
    pub const CLIENT_REVOKED: i32 = 18;
    /// The client's key has expired.
    pub const KEY_EXPIRED: i32 = 23;
    /// Pre-authentication failed: the wrong password or key.
    pub const PREAUTH_FAILED: i32 = 24;
    /// Pre-authentication is required.
    pub const PREAUTH_REQUIRED: i32 = 25;
    /// The clock skew is too great.
    pub const SKEW: i32 = 37;
}

/// The encryption types the client asks for, in order (AES only, ADR 0026 point 3).
pub const ETYPES: [EncryptionType; 2] = [
    EncryptionType::Aes256CtsHmacSha1,
    EncryptionType::Aes128CtsHmacSha1,
];

/// The lifetime asked for a ticket; the KDC shortens it to its own limit.
pub const TICKET_LIFETIME_SECS: i64 = 10 * 3600;

/// The RFC 3244 protocol version.
pub const KPASSWD_VERSION: u16 = 0xff80;

/// Why an exchange failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// No server answered (`dns.krb.kdc.unreachable`).
    #[error("no KDC answered ({servers} tried){}", .last.as_ref().map(|l| format!(": {l}")).unwrap_or_default())]
    Unreachable {
        /// The servers tried.
        servers: usize,
        /// The last failure.
        last: Option<String>,
    },
    /// An attempt timed out.
    #[error("the server did not answer in time")]
    Timeout,
    /// A socket failed.
    #[error("network error: {0}")]
    Io(std::io::ErrorKind),
    /// The KDC answered with an error.
    #[error("the KDC refused: error {code}{}", .text.as_ref().map(|t| format!(" ({t})")).unwrap_or_default())]
    Kdc {
        /// The error code ([`error_code`]).
        code: i32,
        /// The KDC's text.
        text: Option<String>,
    },
    /// The answer does not fit the request: the nonce, the names, the message type.
    #[error("the answer is not one to this request: {0}")]
    Reply(&'static str),
    /// The answer is not valid DER.
    #[error(transparent)]
    Der(#[from] DerError),
    /// A key or a cipher was refused (the KDC offered no AES type, the wrong password).
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// The change-password server refused (`dns.krb.password.refused`): the RFC 3244 result
    /// code and its text.
    #[error("the password change was refused: result {code} ({message})")]
    PasswordRefused {
        /// The result code (1 malformed, 2 hard error, 3 authentication error, 4 soft error
        /// such as the password policy, 5 access denied, 6 bad version, 7 initial ticket
        /// needed).
        code: u16,
        /// The result string, as text, or in hex when it is not UTF-8 (AD sends a policy
        /// structure for code 4).
        message: String,
        /// Whether the refusal proves that the password did not change: it came in the
        /// `KRB-PRIV` of an AP-REP that answers the only request sent. A refusal in a bare
        /// `KRB-ERROR` is unauthenticated (anyone on the path can send one), and a refusal of
        /// a resent request may follow a first request the server applied and answered too
        /// late (a resend of the same password is then refused by the password history).
        definite: bool,
    },
    /// The exchange failed before the change-password request was sent (the ticket for
    /// `kadmin/changepw` was refused or no KDC answered): the password did not change.
    #[error("{0}")]
    BeforeChange(Box<ClientError>),
}

/// What the client authenticates with.
#[derive(Clone)]
pub enum Secret {
    /// A password: the key is derived with the salt the KDC names.
    Password(Zeroizing<Vec<u8>>),
    /// The account's keys, chosen by the encryption type the KDC uses.
    Keys(KeySet),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Password(_) => f.write_str("Secret::Password"),
            Secret::Keys(keys) => write!(f, "Secret::Keys({} keys)", keys.entries().len()),
        }
    }
}

/// A ticket and its session key.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// The client.
    pub client: PrincipalName,
    /// The ticket.
    pub ticket: Ticket,
    /// The session key.
    pub session_key: Key,
    /// The decrypted part of the reply: flags, times, the service's name.
    pub part: EncKdcRepPart,
}

/// The result of an AS exchange.
#[derive(Debug, Clone)]
pub struct AsResult {
    /// The ticket.
    pub credentials: Credentials,
    /// The KDC's time, from its pre-authentication error or the reply's `authtime`: the
    /// self-test compares it with the node's (`dns.gss.clock_skew`).
    pub kdc_time: KrbTime,
    /// The client key's type, version, salt and iteration count, as the KDC used them.
    pub key_etype: EncryptionType,
    /// The version of the client's key, when the reply names it.
    pub key_kvno: Option<u32>,
    /// The salt the key was derived with.
    pub salt: Option<String>,
    /// The iteration count.
    pub iterations: u32,
}

fn principal_wire(principal: &PrincipalName, name_type: i32) -> der::PrincipalName {
    der::PrincipalName {
        name_type,
        components: principal.components().to_vec(),
    }
}

/// The default salt of RFC 4120 section 4: the realm and the name's components.
fn default_salt(principal: &PrincipalName) -> String {
    cipher::salt::principal(principal)
}

fn kdc_error(reply: &[u8]) -> Option<KrbError> {
    (reply.first() == Some(&tag::application(30)))
        .then(|| KrbError::decode(reply).ok())
        .flatten()
}

fn kdc_failure(error: &KrbError) -> ClientError {
    ClientError::Kdc {
        code: error.error_code,
        text: error.e_text.clone(),
    }
}

/// What the next step of an exchange is.
#[derive(Debug)]
pub enum AsStep {
    /// Send this request.
    Send(Vec<u8>),
    /// The exchange is done.
    Done(Box<AsResult>),
}

/// The AS exchange of RFC 4120 section 3.1 with `PA-ENC-TIMESTAMP`.
#[derive(Debug, Clone)]
pub struct AsExchange {
    client: PrincipalName,
    service: PrincipalName,
    secret: Secret,
    nonce: u32,
    till: i64,
    preauth: Option<(Key, Option<String>, u32)>,
    kdc_time: Option<KrbTime>,
}

impl AsExchange {
    /// An exchange for `client` asking a ticket for `service` (`krbtgt/REALM` for the
    /// self-test, `kadmin/changepw` for a password change) at `now` with `nonce`.
    pub fn new(
        client: PrincipalName,
        service: PrincipalName,
        secret: Secret,
        now: KrbTime,
        nonce: u32,
    ) -> Self {
        Self {
            client,
            service,
            secret,
            nonce,
            till: now.secs.saturating_add(TICKET_LIFETIME_SECS),
            preauth: None,
            kdc_time: None,
        }
    }

    fn body(&self) -> KdcReqBody {
        KdcReqBody {
            kdc_options: kdc_options::CANONICALIZE,
            cname: Some(principal_wire(&self.client, name_type::PRINCIPAL)),
            realm: self.client.realm().as_str().to_owned(),
            sname: Some(principal_wire(&self.service, name_type::SRV_INST)),
            from: None,
            till: self.till,
            rtime: None,
            nonce: self.nonce,
            etype: ETYPES.iter().map(|e| e.number()).collect(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    fn request(&self, now: KrbTime) -> Result<Vec<u8>, ClientError> {
        let mut padata = vec![PaData {
            padata_type: pa_type::PAC_REQUEST,
            value: der::encode_pac_request(true),
        }];
        if let Some((key, _, _)) = &self.preauth {
            let timestamp = PaEncTsEnc {
                patimestamp: now.secs,
                pausec: Some(now.usec),
            };
            let enc = cipher::encrypt_data(key, usage::PA_ENC_TIMESTAMP, &timestamp.encode())?;
            padata.insert(
                0,
                PaData {
                    padata_type: pa_type::ENC_TIMESTAMP,
                    value: enc.encode(),
                },
            );
        }
        Ok(KdcReq {
            msg_type: msg_type::AS_REQ,
            padata: Some(padata),
            req_body: self.body(),
        }
        .encode())
    }

    /// The first request: without pre-authentication, so that the KDC names the salt.
    ///
    /// # Errors
    ///
    /// A [`CipherError`] from the random generator.
    pub fn first_request(&self, now: KrbTime) -> Result<Vec<u8>, ClientError> {
        self.request(now)
    }

    /// The client key for `etype` with the salt and iteration count of the KDC's
    /// `PA-ETYPE-INFO2` entry, if any.
    fn key_for(
        &self,
        etype: EncryptionType,
        salt: Option<&str>,
        iterations: u32,
        kvno: Option<u32>,
    ) -> Result<Key, ClientError> {
        match &self.secret {
            Secret::Password(password) => {
                let salt = salt.map_or_else(|| default_salt(&self.client), str::to_owned);
                Ok(cipher::string_to_key(
                    etype,
                    password,
                    salt.as_bytes(),
                    iterations,
                )?)
            }
            Secret::Keys(keys) => keys
                .select(etype.number(), kvno)
                .ok()
                .and_then(|k| k.first().map(|k| (*k).clone()))
                .ok_or(ClientError::Cipher(CipherError::UnsupportedEnctype(
                    etype.number(),
                ))),
        }
    }

    /// The first AES entry of a `PA-ETYPE-INFO2` in a list of pre-authentication data.
    fn etype_info(
        padata: &[PaData],
    ) -> Result<Option<(EncryptionType, Option<String>, u32)>, ClientError> {
        let Some(info) = padata
            .iter()
            .find(|p| p.padata_type == pa_type::ETYPE_INFO2)
        else {
            return Ok(None);
        };
        for entry in der::decode_etype_info2(&info.value)? {
            if let Ok(etype) = cipher::enctype(entry.etype) {
                let iterations = cipher::iterations(entry.s2kparams.as_deref())?;
                return Ok(Some((etype, entry.salt, iterations)));
            }
        }
        Err(ClientError::Cipher(CipherError::UnsupportedEnctype(0)))
    }

    /// Reads the KDC's answer.
    ///
    /// # Errors
    ///
    /// A [`ClientError`]: the KDC's error, a reply that does not fit, a key that does not
    /// decrypt it.
    pub fn handle(&mut self, reply: &[u8], now: KrbTime) -> Result<AsStep, ClientError> {
        if let Some(error) = kdc_error(reply) {
            if error.error_code != error_code::PREAUTH_REQUIRED || self.preauth.is_some() {
                return Err(kdc_failure(&error));
            }
            self.kdc_time = Some(KrbTime {
                secs: error.stime,
                usec: error.susec,
            });
            let padata = error
                .e_data
                .as_deref()
                .map(der::decode_method_data)
                .transpose()?
                .unwrap_or_default();
            let (etype, salt, iterations) =
                Self::etype_info(&padata)?.unwrap_or((ETYPES[0], None, cipher::DEFAULT_ITERATIONS));
            let key = self.key_for(etype, salt.as_deref(), iterations, None)?;
            self.preauth = Some((key, salt, iterations));
            return Ok(AsStep::Send(self.request(now)?));
        }
        let rep = KdcRep::decode(reply)?;
        if rep.msg_type != msg_type::AS_REP {
            return Err(ClientError::Reply("not an AS-REP"));
        }
        let etype = cipher::enctype(rep.enc_part.etype)?;
        // The key: the one pre-authentication used, or one derived from the reply's
        // `PA-ETYPE-INFO2` when the KDC did not ask for pre-authentication.
        let (key, salt, iterations) = match &self.preauth {
            Some((key, salt, iterations)) if key.etype() == etype => {
                (key.clone(), salt.clone(), *iterations)
            }
            _ => {
                let info = Self::etype_info(rep.padata.as_deref().unwrap_or_default())?;
                let (salt, iterations) = match info {
                    Some((info_etype, salt, iterations)) if info_etype == etype => {
                        (salt, iterations)
                    }
                    _ => (None, cipher::DEFAULT_ITERATIONS),
                };
                (
                    self.key_for(etype, salt.as_deref(), iterations, rep.enc_part.kvno)?,
                    salt,
                    iterations,
                )
            }
        };
        let plain = cipher::decrypt_data(&key, usage::AS_REP_ENC_PART, &rep.enc_part)?;
        let part = EncKdcRepPart::decode(&plain)?;
        if part.nonce != self.nonce {
            return Err(ClientError::Reply("the nonce is not the request's"));
        }
        check_names(&rep, &part, &self.client, &self.service)?;
        let credentials = Credentials {
            client: self.client.clone(),
            session_key: Key::from_wire(&part.key)?,
            ticket: rep.ticket,
            part,
        };
        Ok(AsStep::Done(Box::new(AsResult {
            kdc_time: self
                .kdc_time
                .unwrap_or_else(|| KrbTime::from_secs(credentials.part.authtime)),
            credentials,
            key_etype: etype,
            key_kvno: rep.enc_part.kvno,
            salt,
            iterations,
        })))
    }
}

/// The reply's client and service must be the request's (AD canonicalizes the case).
fn check_names(
    rep: &KdcRep,
    part: &EncKdcRepPart,
    client: &PrincipalName,
    service: &PrincipalName,
) -> Result<(), ClientError> {
    let same = |a: &[String], b: &[String]| {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
    };
    if !same(&rep.cname.components, client.components())
        || !rep.crealm.eq_ignore_ascii_case(client.realm().as_str())
    {
        return Err(ClientError::Reply("the reply is for another client"));
    }
    if !same(&part.sname.components, service.components())
        || !part.srealm.eq_ignore_ascii_case(service.realm().as_str())
    {
        return Err(ClientError::Reply("the reply is for another service"));
    }
    Ok(())
}

/// The TGS exchange of RFC 4120 section 3.3 for a service principal.
#[derive(Debug, Clone)]
pub struct TgsExchange {
    tgt: Credentials,
    service: PrincipalName,
    nonce: u32,
    till: i64,
}

impl TgsExchange {
    /// An exchange asking a ticket for `service` with the ticket-granting ticket `tgt`.
    pub fn new(tgt: Credentials, service: PrincipalName, now: KrbTime, nonce: u32) -> Self {
        Self {
            tgt,
            service,
            nonce,
            till: now.secs.saturating_add(TICKET_LIFETIME_SECS),
        }
    }

    /// The request: the body, and in `PA-TGS-REQ` an AP-REQ whose authenticator carries the
    /// body's checksum.
    ///
    /// # Errors
    ///
    /// A [`CipherError`] from the random generator.
    pub fn request(&self, now: KrbTime) -> Result<Vec<u8>, ClientError> {
        let service_name_type = if self.service.components().len() == 2 {
            name_type::SRV_HST
        } else {
            name_type::PRINCIPAL
        };
        let body = KdcReqBody {
            kdc_options: kdc_options::CANONICALIZE,
            cname: None,
            realm: self.service.realm().as_str().to_owned(),
            sname: Some(principal_wire(&self.service, service_name_type)),
            from: None,
            till: self.till,
            rtime: None,
            nonce: self.nonce,
            etype: ETYPES.iter().map(|e| e.number()).collect(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let body_der = body.encode();
        let session = &self.tgt.session_key;
        let cksum = Checksum {
            cksumtype: cipher::checksum_type(session.etype()),
            checksum: cipher::checksum(session, usage::TGS_REQ_AUTH_CKSUM, &body_der)?.to_vec(),
        };
        let ap_req = ap_req(
            &self.tgt,
            Some(cksum),
            None,
            None,
            0,
            now,
            usage::TGS_REQ_AUTHENTICATOR,
        )?;
        Ok(KdcReq {
            msg_type: msg_type::TGS_REQ,
            padata: Some(vec![PaData {
                padata_type: pa_type::TGS_REQ,
                value: ap_req,
            }]),
            req_body: body,
        }
        .encode_with_body(&body_der))
    }

    /// Reads the KDC's answer: the service ticket, whose key version is the account's
    /// current one.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub fn handle(&self, reply: &[u8]) -> Result<Credentials, ClientError> {
        if let Some(error) = kdc_error(reply) {
            return Err(kdc_failure(&error));
        }
        let rep = KdcRep::decode(reply)?;
        if rep.msg_type != msg_type::TGS_REP {
            return Err(ClientError::Reply("not a TGS-REP"));
        }
        let plain = cipher::decrypt_data(
            &self.tgt.session_key,
            usage::TGS_REP_ENC_PART_SESSION,
            &rep.enc_part,
        )?;
        let part = EncKdcRepPart::decode(&plain)?;
        if part.nonce != self.nonce {
            return Err(ClientError::Reply("the nonce is not the request's"));
        }
        check_names(&rep, &part, &self.tgt.client, &self.service)?;
        Ok(Credentials {
            client: self.tgt.client.clone(),
            session_key: Key::from_wire(&part.key)?,
            ticket: rep.ticket,
            part,
        })
    }
}

/// An AP-REQ with a ticket: the authenticator under the ticket's session key for `usage`.
fn ap_req(
    credentials: &Credentials,
    cksum: Option<Checksum>,
    subkey: Option<&Key>,
    seq_number: Option<u32>,
    options: u32,
    now: KrbTime,
    key_usage: u32,
) -> Result<Vec<u8>, ClientError> {
    let auth = Authenticator {
        crealm: credentials.client.realm().as_str().to_owned(),
        cname: principal_wire(&credentials.client, name_type::PRINCIPAL),
        cksum,
        cusec: now.usec,
        ctime: now.secs,
        subkey: subkey.map(Key::to_wire),
        seq_number,
        authorization_data: None,
    };
    let authenticator = cipher::encrypt_data(&credentials.session_key, key_usage, &auth.encode())?;
    Ok(ApReq {
        ap_options: options,
        ticket: credentials.ticket.clone(),
        authenticator,
    }
    .encode())
}

/// A GSS-API initiator token with the AP-REQ of a service ticket (mutual, replay,
/// sequence and integrity, as Windows asks): what the self-test hands to the node's own
/// acceptor. Returns the token and the initiator's subkey.
///
/// # Errors
///
/// A [`CipherError`] from the random generator.
pub fn initiator_token(
    credentials: &Credentials,
    mech: &[u8],
    now: KrbTime,
    seq: u32,
) -> Result<(Vec<u8>, Key), ClientError> {
    let flags = gss_flags::MUTUAL | gss_flags::REPLAY | gss_flags::SEQUENCE | gss_flags::INTEG;
    let mut checksum = 16_u32.to_le_bytes().to_vec();
    checksum.extend_from_slice(&[0; 16]);
    checksum.extend_from_slice(&flags.to_le_bytes());
    let subkey = Key::random(credentials.session_key.etype())?;
    let request = ap_req(
        credentials,
        Some(Checksum {
            cksumtype: crate::acceptor::GSS_CHECKSUM_TYPE,
            checksum,
        }),
        Some(&subkey),
        Some(seq),
        der::ap_options::MUTUAL_REQUIRED,
        now,
        usage::AP_REQ_AUTHENTICATOR,
    )?;
    Ok((KrbToken::encode(mech, tok_id::AP_REQ, &request), subkey))
}

/// The change-password exchange of RFC 3244 with a `kadmin/changepw` ticket from an AS
/// exchange.
#[derive(Clone)]
pub struct ChangePassword {
    ticket: Credentials,
    new_password: Zeroizing<Vec<u8>>,
    subkey: Key,
    seq: u32,
    now: KrbTime,
    attempt: u32,
    name_target: bool,
    /// The authenticator time of the last request: the AP-REP must echo it.
    last_sent: Option<KrbTime>,
}

impl std::fmt::Debug for ChangePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePassword")
            .field("client", &self.ticket.client)
            .finish_non_exhaustive()
    }
}

impl ChangePassword {
    /// An exchange that sets `new_password` for the ticket's own client.
    ///
    /// # Errors
    ///
    /// A [`CipherError`] from the random generator.
    pub fn new(
        ticket: Credentials,
        new_password: &[u8],
        now: KrbTime,
    ) -> Result<Self, ClientError> {
        let subkey = Key::random(ticket.session_key.etype())?;
        let mut seq = [0_u8; 4];
        aws_lc_rs::rand::fill(&mut seq).map_err(|_| CipherError::Library)?;
        Ok(Self::with(
            ticket,
            new_password,
            now,
            subkey,
            u32::from_be_bytes(seq) & 0x3fff_ffff,
        ))
    }

    /// An exchange with a given subkey and sequence number (for replaying recorded
    /// answers).
    pub fn with(
        ticket: Credentials,
        new_password: &[u8],
        now: KrbTime,
        subkey: Key,
        seq: u32,
    ) -> Self {
        Self {
            ticket,
            new_password: Zeroizing::new(new_password.to_vec()),
            subkey,
            seq,
            now,
            attempt: 0,
            name_target: false,
            last_sent: None,
        }
    }

    /// Names the client as its own target in later requests. Decision: a request leaves
    /// `targname` and `targrealm` out, which RFC 3244 and Active Directory read as a change
    /// of the client's own password; MIT's `kadmind` cannot decode `ChangePasswdData`
    /// without them and answers "malformed" (result 1), so [`Client::change_password`] then
    /// retries once with the client named, which MIT reads as the same change.
    pub fn name_target(&mut self) {
        self.name_target = true;
    }

    /// The request, naming `local` as the sender's address. Every call moves the
    /// authenticator's microseconds, so that a retry over TCP is not a replay of the UDP
    /// request.
    ///
    /// # Errors
    ///
    /// A [`CipherError`] from the random generator.
    pub fn request(&mut self, local: IpAddr) -> Result<Vec<u8>, ClientError> {
        let now = KrbTime {
            secs: self.now.secs,
            usec: (self.now.usec + self.attempt) % 1_000_000,
        };
        self.attempt += 1;
        self.last_sent = Some(now);
        let ap_req = ap_req(
            &self.ticket,
            None,
            Some(&self.subkey),
            Some(self.seq),
            0,
            now,
            usage::AP_REQ_AUTHENTICATOR,
        )?;
        let client = &self.ticket.client;
        let data = ChangePasswdData {
            newpasswd: self.new_password.clone(),
            targname: self
                .name_target
                .then(|| principal_wire(client, name_type::PRINCIPAL)),
            targrealm: self.name_target.then(|| client.realm().as_str().to_owned()),
        };
        let private = EncKrbPrivPart {
            user_data: data.encode(),
            timestamp: None,
            usec: None,
            seq_number: Some(self.seq),
            s_address: Some(HostAddress::from_ip(local)),
            r_address: None,
        };
        let priv_msg = KrbPriv {
            enc_part: cipher::encrypt_data(
                &self.subkey,
                usage::KRB_PRIV_ENC_PART,
                &private.encode(),
            )?,
        }
        .encode();
        let total = 6 + ap_req.len() + priv_msg.len();
        let total =
            u16::try_from(total).map_err(|_| ClientError::Reply("the request is too large"))?;
        let ap_len = u16::try_from(ap_req.len())
            .map_err(|_| ClientError::Reply("the request is too large"))?;
        let mut out = Vec::with_capacity(usize::from(total));
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&KPASSWD_VERSION.to_be_bytes());
        out.extend_from_slice(&ap_len.to_be_bytes());
        out.extend_from_slice(&ap_req);
        out.extend_from_slice(&priv_msg);
        Ok(out)
    }

    /// Reads the server's answer.
    ///
    /// # Errors
    ///
    /// [`ClientError::PasswordRefused`] with the server's result, or another
    /// [`ClientError`].
    pub fn handle(&self, reply: &[u8]) -> Result<(), ClientError> {
        let header = reply
            .get(..6)
            .ok_or(ClientError::Reply("the answer is too short"))?;
        let total = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let version = u16::from_be_bytes([header[2], header[3]]);
        let ap_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
        if total != reply.len() || !(version == 1 || version == KPASSWD_VERSION) {
            return Err(ClientError::Reply("not a change-password answer"));
        }
        let rest = &reply[6..];
        if ap_len == 0 {
            // A KRB-ERROR whose e-data is the result.
            let error = KrbError::decode(rest)?;
            return Err(match error.e_data.as_deref().and_then(result) {
                Some((code, message)) if code != 0 => ClientError::PasswordRefused {
                    code,
                    message,
                    definite: false,
                },
                _ => kdc_failure(&error),
            });
        }
        let ap_rep = rest
            .get(..ap_len)
            .ok_or(ClientError::Reply("the AP-REP is cut short"))?;
        let rep = ApRep::decode(ap_rep)?;
        let plain = cipher::decrypt_data(
            &self.ticket.session_key,
            usage::AP_REP_ENC_PART,
            &rep.enc_part,
        )?;
        let part = EncApRepPart::decode(&plain)?;
        // RFC 4120 section 3.2.5: the AP-REP echoes the authenticator's time, which binds
        // the answer to the last request sent (an answer to an earlier attempt, replayed
        // after a retry, is not taken for the retry's).
        if self.last_sent
            != Some(KrbTime {
                secs: part.ctime,
                usec: part.cusec,
            })
        {
            return Err(ClientError::Reply("the answer is not to the last request"));
        }
        let priv_msg = KrbPriv::decode(&rest[ap_len..])?;
        // The KRB-PRIV is under the AP-REP's subkey when it carries one, else ours.
        let key = part
            .subkey
            .as_ref()
            .map(Key::from_wire)
            .transpose()?
            .unwrap_or_else(|| self.subkey.clone());
        let plain = cipher::decrypt_data(&key, usage::KRB_PRIV_ENC_PART, &priv_msg.enc_part)?;
        let private = EncKrbPrivPart::decode(&plain)?;
        if let (Some(theirs), Some(ours)) = (private.seq_number, part.seq_number)
            && theirs != ours
        {
            return Err(ClientError::Reply(
                "the KRB-PRIV's sequence number is not the AP-REP's",
            ));
        }
        match result(&private.user_data) {
            Some((0, _)) => Ok(()),
            Some((code, message)) => Err(ClientError::PasswordRefused {
                code,
                message,
                definite: self.attempt == 1,
            }),
            None => Err(ClientError::Reply("the result is malformed")),
        }
    }
}

/// The result code and string of a change-password answer.
fn result(data: &[u8]) -> Option<(u16, String)> {
    let code = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
    let text = &data[2..];
    let message = std::str::from_utf8(text).map_or_else(
        |_| crate::client::hex(text),
        |t| t.trim_end_matches('\0').to_owned(),
    );
    Some((code, message))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// `kadmin/changepw` in the client's realm: the service of the change-password ticket.
///
/// # Errors
///
/// [`ClientError::Reply`] when the realm cannot hold the name (it always can).
pub fn changepw_principal(client: &PrincipalName) -> Result<PrincipalName, ClientError> {
    PrincipalName::new(
        vec!["kadmin".into(), "changepw".into()],
        client.realm().clone(),
    )
    .map_err(|_| ClientError::Reply("kadmin/changepw"))
}

/// The client: the exchanges over the network to the servers the caller lists.
#[derive(Clone)]
pub struct Client {
    /// The KDCs (port 88).
    pub kdcs: Vec<SocketAddr>,
    /// The change-password servers (port 464).
    pub kpasswd: Vec<SocketAddr>,
    /// Timeouts and the UDP limit.
    pub transport: TransportConfig,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("kdcs", &self.kdcs)
            .field("kpasswd", &self.kpasswd)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

fn nonce() -> Result<u32, ClientError> {
    let mut bytes = [0_u8; 4];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| CipherError::Library)?;
    // A positive Int32, as MIT and Windows send it.
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

impl Client {
    /// A client for the listed servers with the caller's clock.
    pub fn new(kdcs: Vec<SocketAddr>, kpasswd: Vec<SocketAddr>, clock: Arc<dyn Clock>) -> Self {
        Self {
            kdcs,
            kpasswd,
            transport: TransportConfig::default(),
            clock,
        }
    }

    /// An AS exchange for `client` and `service`.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn as_exchange(
        &self,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError> {
        let now = self.clock.now();
        let mut exchange = AsExchange::new(client.clone(), service.clone(), secret, now, nonce()?);
        let mut request = exchange.first_request(now)?;
        for _ in 0..2 {
            let reply =
                transport::exchange(&self.transport, &self.kdcs, |_| Ok(request.clone())).await?;
            match exchange.handle(&reply, self.clock.now())? {
                AsStep::Send(next) => request = next,
                AsStep::Done(result) => return Ok(*result),
            }
        }
        Err(ClientError::Reply(
            "the KDC asked for pre-authentication twice",
        ))
    }

    /// A TGS exchange for `service` with `tgt`.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn tgs_exchange(
        &self,
        tgt: &Credentials,
        service: &PrincipalName,
    ) -> Result<Credentials, ClientError> {
        let now = self.clock.now();
        let exchange = TgsExchange::new(tgt.clone(), service.clone(), now, nonce()?);
        let request = exchange.request(now)?;
        let reply =
            transport::exchange(&self.transport, &self.kdcs, |_| Ok(request.clone())).await?;
        exchange.handle(&reply)
    }

    /// Changes the password of `client` from `password` to `new_password`: an AS exchange
    /// for `kadmin/changepw`, then the RFC 3244 request.
    ///
    /// # Errors
    ///
    /// A [`ClientError`]; [`ClientError::PasswordRefused`] when the server refuses.
    pub async fn change_password(
        &self,
        client: &PrincipalName,
        password: &[u8],
        new_password: &[u8],
    ) -> Result<(), ClientError> {
        self.change_password_with(
            client,
            Secret::Password(Zeroizing::new(password.to_vec())),
            new_password,
        )
        .await
    }

    /// Changes the password of `client` to `new_password`, authenticating with `secret`:
    /// the one-time password of an adopt, or the account's current keys for a rotation,
    /// since Tenko keeps the keys and forgets the password (identity plan section 3.1).
    ///
    /// # Errors
    ///
    /// A [`ClientError`]; [`ClientError::PasswordRefused`] when the server refuses.
    pub async fn change_password_with(
        &self,
        client: &PrincipalName,
        secret: Secret,
        new_password: &[u8],
    ) -> Result<(), ClientError> {
        let changepw =
            changepw_principal(client).map_err(|e| ClientError::BeforeChange(Box::new(e)))?;
        let ticket = self
            .as_exchange(client, &changepw, secret)
            .await
            .map_err(|e| ClientError::BeforeChange(Box::new(e)))?
            .credentials;
        let mut exchange = ChangePassword::new(ticket, new_password, self.clock.now())?;
        let reply = transport::exchange(&self.transport, &self.kpasswd, |local| {
            exchange.request(local)
        })
        .await?;
        match exchange.handle(&reply) {
            Err(ClientError::PasswordRefused { code: 1, .. }) => {
                exchange.name_target();
                let reply = transport::exchange(&self.transport, &self.kpasswd, |local| {
                    exchange.request(local)
                })
                .await?;
                exchange.handle(&reply)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests;
