//! The SNMPv3 client: engine discovery, `get` and `walk` over one UDP socket.
//!
//! The client follows RFC 3414 as a non-authoritative engine:
//!
//! 1. Discovery sends a request without user and engine id; the Report that comes back
//!    names the engine id and tells its boots counter and time.
//! 2. Keys are localized to that engine id and requests carry the engine's time as the
//!    client estimates it (the time of discovery plus the time passed since).
//! 3. A Report of `usmStatsNotInTimeWindows` resets the estimate and the request is sent
//!    again once. A Report of `usmStatsUnknownEngineIDs` makes the client discover again,
//!    also once.
//!
//! Responses are matched by `msgID` and `request-id` and must come from the target
//! address. A response is read only after its digest has been verified (when the level
//! has authentication) and its data decrypted (when it has privacy). The only datagrams
//! read without a digest are Reports of the `usmStats` error counters, which an engine
//! cannot authenticate, and they can only turn the request into an error.

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{net::UdpSocket, time::Instant};
use zeroize::Zeroizing;

use super::{
    AuthProtocol, Credentials, PollOptions, PrivProtocol,
    ber::{MAX_MESSAGE_LEN, Oid, VarBind},
    message::{
        Message, MessageData, MsgFlags, Pdu, PduKind, SECURITY_MODEL_USM, ScopedPdu, UsmParameters,
        decode_message, decode_scoped_pdu,
    },
    usm::{self, AuthKey, PrivKey, SaltGenerator, localize_key},
};
use crate::{
    error::ScanError,
    limit::{Pacer, Permit},
    method::Cancel,
};

/// The width of the time window of RFC 3414, in seconds.
const TIME_WINDOW: u32 = 150;

/// The largest value of the engine boots counter and of the engine time.
const MAX_ENGINE_VALUE: u32 = 2_147_483_647;

/// The prefix of the `usmStats` counters: `1.3.6.1.6.3.15.1.1`.
const USM_STATS: [u32; 9] = [1, 3, 6, 1, 6, 3, 15, 1, 1];

/// The OID of a `usmStats` counter (`.1.0` to `.6.0`).
#[cfg(test)]
pub(crate) fn usm_stat_oid(counter: u32) -> Oid {
    let mut arcs = USM_STATS.to_vec();
    arcs.push(counter);
    arcs.push(0);
    Oid(arcs)
}

/// A reason the engine gave for not processing a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReportKind {
    UnsupportedSecLevels,
    NotInTimeWindows { boots: u32, time: u32 },
    UnknownUserNames,
    UnknownEngineIds,
    WrongDigests,
    DecryptionErrors,
    Other(Oid),
}

fn classify_report(oid: &Oid, boots: u32, time: u32) -> ReportKind {
    let arcs = oid.arcs();
    if arcs.len() == USM_STATS.len() + 2
        && arcs.starts_with(&USM_STATS)
        && arcs[USM_STATS.len() + 1] == 0
    {
        match arcs[USM_STATS.len()] {
            1 => return ReportKind::UnsupportedSecLevels,
            2 => return ReportKind::NotInTimeWindows { boots, time },
            3 => return ReportKind::UnknownUserNames,
            4 => return ReportKind::UnknownEngineIds,
            5 => return ReportKind::WrongDigests,
            6 => return ReportKind::DecryptionErrors,
            _ => {}
        }
    }
    ReportKind::Other(oid.clone())
}

/// What a datagram turned out to be.
#[derive(Debug)]
enum Outcome {
    Response(Pdu),
    Report(ReportKind),
}

/// A datagram that belongs to the request in flight.
#[derive(Debug)]
struct Incoming {
    outcome: Outcome,
    /// The engine boots and time of an authenticated message, for the time estimate.
    sync: Option<(u32, u32)>,
}

/// What waiting for an answer ended with.
enum Received<T> {
    Got(T),
    Timeout,
    Unreachable,
}

/// The engine as discovery found it.
struct Discovered {
    engine_id: Vec<u8>,
    boots: u32,
    time: u32,
}

/// A master key and its protocol.
struct Master {
    protocol: AuthProtocol,
    key: Zeroizing<Vec<u8>>,
}

/// What the client knows about the engine after discovery.
struct Session {
    engine_id: Vec<u8>,
    auth: Option<AuthKey>,
    privacy: Option<PrivKey>,
    boots: u32,
    base_time: u32,
    latest_received: u32,
    synced_at: Instant,
}

impl Session {
    /// The engine time as the client estimates it.
    fn engine_time(&self) -> u32 {
        let elapsed = self.synced_at.elapsed().as_secs();
        let time = u64::from(self.base_time).saturating_add(elapsed);
        u32::try_from(time)
            .unwrap_or(MAX_ENGINE_VALUE)
            .min(MAX_ENGINE_VALUE)
    }

    fn set(&mut self, boots: u32, time: u32) {
        self.boots = boots;
        self.base_time = time;
        self.latest_received = time;
        self.synced_at = Instant::now();
    }

    /// RFC 3414, section 3.2, step 7b: take newer values of an authenticated message.
    fn update(&mut self, boots: u32, time: u32) {
        if boots > self.boots || (boots == self.boots && time > self.latest_received) {
            self.set(boots, time);
        }
    }

    /// Whether an authenticated message with these values is inside the time window.
    fn would_accept(&self, boots: u32, time: u32) -> bool {
        if self.boots == MAX_ENGINE_VALUE {
            return false;
        }
        match boots.cmp(&self.boots) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => {
                time > self.latest_received
                    || time.saturating_add(TIME_WINDOW) >= self.engine_time()
            }
        }
    }
}

/// What to ask.
enum RequestKind<'k> {
    Get(&'k [Oid]),
    Bulk { start: &'k Oid, repetitions: i32 },
}

/// The rows of a walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Walk {
    /// The rows in MIB order, all below the root of the walk.
    pub rows: Vec<VarBind>,
    /// The walk stopped at the row limit or at a table that does not advance, so more
    /// rows may exist.
    pub truncated: bool,
}

/// An SNMPv3 client for one device.
pub struct Client<'a> {
    socket: UdpSocket,
    target: SocketAddr,
    user: Vec<u8>,
    context_name: Vec<u8>,
    auth: Option<Master>,
    privacy: Option<Zeroizing<Vec<u8>>>,
    options: PollOptions,
    pacer: &'a Pacer,
    cancel: &'a Cancel,
    next_id: i32,
    salts: SaltGenerator,
    session: Option<Session>,
}

fn protocol_error(detail: impl Into<String>) -> ScanError {
    ScanError::new("scan.snmp.protocol", detail)
}

fn auth_error(detail: impl Into<String>) -> ScanError {
    ScanError::new("scan.snmp.auth", detail)
}

fn is_refusal(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
    )
}

fn error_status_name(status: i32) -> &'static str {
    match status {
        1 => "tooBig",
        2 => "noSuchName",
        3 => "badValue",
        4 => "readOnly",
        5 => "genErr",
        6 => "noAccess",
        7 => "wrongType",
        8 => "wrongLength",
        9 => "wrongEncoding",
        10 => "wrongValue",
        11 => "noCreation",
        12 => "inconsistentValue",
        13 => "resourceUnavailable",
        14 => "commitFailed",
        15 => "undoFailed",
        16 => "authorizationError",
        17 => "notWritable",
        18 => "inconsistentName",
        _ => "unknown",
    }
}

fn discovery_request(msg_id: i32, request_id: i32) -> Result<Vec<u8>, ScanError> {
    let message = Message {
        msg_id,
        max_size: u32::try_from(MAX_MESSAGE_LEN).unwrap_or(65_507),
        flags: MsgFlags {
            auth: false,
            privacy: false,
            reportable: true,
        },
        security_model: SECURITY_MODEL_USM,
        usm: UsmParameters::default(),
        data: MessageData::Plain(ScopedPdu {
            context_engine_id: Vec::new(),
            context_name: Vec::new(),
            pdu: Pdu::request(PduKind::Get, request_id, Vec::new()),
        }),
        auth_params_at: 0..0,
    };
    message
        .encode()
        .map(|encoded| encoded.bytes)
        .map_err(|error| protocol_error(format!("building the discovery request: {error}")))
}

/// Reads a discovery answer: any unauthenticated Report or Response of the right
/// `msgID` that names an engine id.
fn process_discovery(bytes: &[u8], msg_id: i32) -> Option<Discovered> {
    let message = decode_message(bytes).ok()?;
    if message.msg_id != msg_id
        || message.security_model != SECURITY_MODEL_USM
        || message.flags.auth
        || message.flags.privacy
    {
        return None;
    }
    let MessageData::Plain(scoped) = &message.data else {
        return None;
    };
    if !matches!(scoped.pdu.kind, PduKind::Report | PduKind::Response) {
        return None;
    }
    if message.usm.engine_id.is_empty() {
        return None;
    }
    Some(Discovered {
        engine_id: message.usm.engine_id,
        boots: message.usm.boots,
        time: message.usm.time,
    })
}

impl<'a> Client<'a> {
    /// Opens a UDP socket to `target` and derives the master keys of `credentials`. No
    /// datagram is sent; [`Client::discover`] (or the first request) does that.
    ///
    /// # Errors
    /// `scan.config` for unusable credentials, `scan.io` when the socket cannot be set up.
    pub async fn connect(
        target: SocketAddr,
        credentials: &Credentials,
        options: &PollOptions,
        pacer: &'a Pacer,
        cancel: &'a Cancel,
    ) -> Result<Client<'a>, ScanError> {
        credentials.validate()?;
        let unspecified = if target.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(unspecified, 0))
            .await
            .map_err(|error| ScanError::io(format!("binding a UDP socket: {error}")))?;
        socket.connect(target).await.map_err(|error| {
            ScanError::io(format!("connecting a UDP socket to {target}: {error}"))
        })?;
        let auth = credentials
            .auth
            .as_ref()
            .map(|(protocol, password)| Master {
                protocol: *protocol,
                key: usm::password_to_key(*protocol, password),
            });
        let privacy = match (&credentials.auth, &credentials.privacy) {
            (Some((protocol, _)), Some((PrivProtocol::Aes128, password))) => {
                Some(usm::password_to_key(*protocol, password))
            }
            _ => None,
        };
        let salts = SaltGenerator::new()
            .map_err(|error| ScanError::io(format!("seeding the privacy salts: {error}")))?;
        let mut seed = [0u8; 4];
        aws_lc_rs::rand::fill(&mut seed).map_err(|_| {
            ScanError::io("seeding the message ids: the system random generator failed")
        })?;
        let next_id = i32::try_from(u32::from_be_bytes(seed) % 0x3FFF_FFFF)
            .unwrap_or(0)
            .saturating_add(1);
        Ok(Client {
            socket,
            target,
            user: credentials.user.clone().into_bytes(),
            context_name: credentials.context.clone().into_bytes(),
            auth,
            privacy,
            options: *options,
            pacer,
            cancel,
            next_id,
            salts,
            session: None,
        })
    }

    /// The address of the device.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// The engine id of the device, once discovery has run.
    pub fn engine_id(&self) -> Option<&[u8]> {
        self.session
            .as_ref()
            .map(|session| session.engine_id.as_slice())
    }

    /// Makes the client believe the device has another engine id, to exercise the
    /// rediscovery.
    #[cfg(test)]
    pub(crate) fn pretend_engine_id(&mut self, engine_id: &[u8]) {
        if let Some(session) = self.session.as_mut() {
            session.engine_id = engine_id.to_vec();
        }
    }

    fn next_id(&mut self) -> i32 {
        let id = self.next_id;
        self.next_id = if id == i32::MAX { 1 } else { id + 1 };
        id
    }

    fn check_cancelled(&self) -> Result<(), ScanError> {
        if self.cancel.is_cancelled() {
            Err(ScanError::cancelled("the SNMP poll was cancelled"))
        } else {
            Ok(())
        }
    }

    fn timeout_error(&self, what: &str, unreachable: bool) -> ScanError {
        ScanError::new(
            "scan.snmp.timeout",
            format!(
                "no answer from {} to {what} after {} attempts{}",
                self.target,
                u64::from(self.options.retries) + 1,
                if unreachable {
                    " (the port is unreachable)"
                } else {
                    ""
                }
            ),
        )
    }

    async fn acquire(&self) -> Result<Permit, ScanError> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(ScanError::cancelled("the SNMP poll was cancelled")),
            permit = self.pacer.acquire(self.target.ip()) => Ok(permit),
        }
    }

    /// Sends a datagram; `false` when the system reported the port unreachable.
    async fn send(&self, datagram: &[u8]) -> Result<bool, ScanError> {
        match self.socket.send(datagram).await {
            Ok(_) => Ok(true),
            Err(error) if is_refusal(&error) => Ok(false),
            Err(error) => Err(ScanError::io(format!(
                "sending to {}: {error}",
                self.target
            ))),
        }
    }

    /// Waits for a datagram from the target that `handler` accepts, until the timeout.
    async fn receive_with<T>(
        &self,
        mut handler: impl FnMut(&[u8]) -> Option<T>,
    ) -> Result<Received<T>, ScanError> {
        let deadline = Instant::now() + self.options.timeout;
        let mut buffer = vec![0u8; 65_535];
        loop {
            let received = tokio::select! {
                () = self.cancel.cancelled() => {
                    return Err(ScanError::cancelled("the SNMP poll was cancelled"));
                }
                result = tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buffer)) => result,
            };
            match received {
                Err(_) => return Ok(Received::Timeout),
                Ok(Err(error)) if is_refusal(&error) => return Ok(Received::Unreachable),
                Ok(Err(error)) => {
                    return Err(ScanError::io(format!(
                        "receiving from {}: {error}",
                        self.target
                    )));
                }
                Ok(Ok((length, from))) => {
                    if from.ip() != self.target.ip() || from.port() != self.target.port() {
                        continue;
                    }
                    if let Some(found) = handler(&buffer[..length]) {
                        return Ok(Received::Got(found));
                    }
                }
            }
        }
    }

    /// Finds the engine id, boots and time of the device and derives the localized keys.
    ///
    /// # Errors
    /// `scan.snmp.timeout` when nothing answers, `scan.cancelled`, `scan.io`.
    pub async fn discover(&mut self) -> Result<(), ScanError> {
        let msg_id = self.next_id();
        let request_id = self.next_id();
        let datagram = discovery_request(msg_id, request_id)?;
        let mut unreachable = false;
        for _ in 0..=self.options.retries {
            self.check_cancelled()?;
            let _permit = self.acquire().await?;
            if !self.send(&datagram).await? {
                unreachable = true;
                continue;
            }
            match self
                .receive_with(|bytes| process_discovery(bytes, msg_id))
                .await?
            {
                Received::Got(found) => return self.install(found),
                Received::Timeout => {}
                Received::Unreachable => unreachable = true,
            }
        }
        Err(self.timeout_error("the engine discovery request", unreachable))
    }

    fn install(&mut self, found: Discovered) -> Result<(), ScanError> {
        let auth = self.auth.as_ref().map(|master| {
            AuthKey::new(
                master.protocol,
                localize_key(master.protocol, &master.key, &found.engine_id),
            )
        });
        let privacy = match (&self.auth, &self.privacy) {
            (Some(master), Some(key)) => Some(
                PrivKey::new(&localize_key(master.protocol, key, &found.engine_id))
                    .map_err(|error| ScanError::config(format!("the privacy key: {error}")))?,
            ),
            _ => None,
        };
        self.session = Some(Session {
            engine_id: found.engine_id,
            auth,
            privacy,
            boots: found.boots,
            base_time: found.time,
            latest_received: found.time,
            synced_at: Instant::now(),
        });
        Ok(())
    }

    /// Builds the datagram of one attempt with the engine time of now.
    fn build_request(
        &mut self,
        kind: &RequestKind<'_>,
        msg_id: i32,
        request_id: i32,
    ) -> Result<Vec<u8>, ScanError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| protocol_error("the engine has not been discovered"))?;
        let pdu = match kind {
            RequestKind::Get(oids) => Pdu::request(
                PduKind::Get,
                request_id,
                oids.iter().cloned().map(VarBind::request).collect(),
            ),
            RequestKind::Bulk { start, repetitions } => Pdu::bulk(
                request_id,
                0,
                *repetitions,
                vec![VarBind::request((*start).clone())],
            ),
        };
        let scoped = ScopedPdu {
            context_engine_id: session.engine_id.clone(),
            context_name: self.context_name.clone(),
            pdu,
        };
        let boots = session.boots;
        let time = session.engine_time();
        let mut parameters = UsmParameters {
            engine_id: session.engine_id.clone(),
            boots,
            time,
            user: self.user.clone(),
            auth_params: session
                .auth
                .as_ref()
                .map(|key| vec![0u8; key.protocol().mac_len()])
                .unwrap_or_default(),
            priv_params: Vec::new(),
        };
        let data = if let Some(key) = &session.privacy {
            let salt = self.salts.next_salt();
            parameters.priv_params = salt.to_vec();
            let mut plaintext = scoped
                .encode()
                .map_err(|error| protocol_error(format!("building the request: {error}")))?;
            key.encrypt(boots, time, &salt, &mut plaintext)
                .map_err(|error| protocol_error(format!("encrypting the request: {error}")))?;
            MessageData::Encrypted(plaintext)
        } else {
            MessageData::Plain(scoped)
        };
        let message = Message {
            msg_id,
            max_size: u32::try_from(MAX_MESSAGE_LEN).unwrap_or(65_507),
            flags: MsgFlags {
                auth: session.auth.is_some(),
                privacy: session.privacy.is_some(),
                reportable: true,
            },
            security_model: SECURITY_MODEL_USM,
            usm: parameters,
            data,
            auth_params_at: 0..0,
        };
        let mut encoded = message
            .encode()
            .map_err(|error| protocol_error(format!("building the request: {error}")))?;
        if let Some(key) = &session.auth {
            key.sign(&mut encoded.bytes, &encoded.auth_params)
                .map_err(|error| protocol_error(format!("signing the request: {error}")))?;
        }
        Ok(encoded.bytes)
    }

    /// Reads a datagram as the answer to the request in flight.
    fn process(&self, bytes: &[u8], msg_id: i32, request_id: i32) -> Option<Incoming> {
        let session = self.session.as_ref()?;
        let message = decode_message(bytes).ok()?;
        if message.msg_id != msg_id || message.security_model != SECURITY_MODEL_USM {
            return None;
        }
        let flags = message.flags;
        let authenticated = if flags.auth {
            let key = session.auth.as_ref()?;
            if !key.verify(bytes, &message.auth_params_at) {
                return None;
            }
            true
        } else {
            false
        };
        let (boots, time) = (message.usm.boots, message.usm.time);
        let pdu = match &message.data {
            MessageData::Plain(scoped) => scoped.pdu.clone(),
            MessageData::Encrypted(ciphertext) => {
                let key = session.privacy.as_ref()?;
                let mut plaintext = ciphertext.clone();
                key.decrypt(boots, time, &message.usm.priv_params, &mut plaintext)
                    .ok()?;
                decode_scoped_pdu(&plaintext).ok()?.pdu
            }
        };
        match pdu.kind {
            PduKind::Response => {
                if authenticated != session.auth.is_some()
                    || flags.privacy != session.privacy.is_some()
                    || pdu.request_id != request_id
                    || message.usm.engine_id != session.engine_id
                    || (authenticated && !session.would_accept(boots, time))
                {
                    return None;
                }
                Some(Incoming {
                    outcome: Outcome::Response(pdu),
                    sync: authenticated.then_some((boots, time)),
                })
            }
            PduKind::Report => {
                let first = pdu.varbinds.first()?;
                let kind = classify_report(&first.oid, boots, time);
                if matches!(kind, ReportKind::NotInTimeWindows { .. })
                    && (!authenticated || message.usm.engine_id != session.engine_id)
                {
                    // Only an authenticated engine may move the time estimate.
                    return None;
                }
                Some(Incoming {
                    outcome: Outcome::Report(kind),
                    sync: None,
                })
            }
            _ => None,
        }
    }

    /// Sends one request, with the retries, and waits for its answer.
    async fn attempt(&mut self, kind: &RequestKind<'_>) -> Result<Outcome, ScanError> {
        let msg_id = self.next_id();
        let request_id = self.next_id();
        let mut unreachable = false;
        for _ in 0..=self.options.retries {
            self.check_cancelled()?;
            let datagram = self.build_request(kind, msg_id, request_id)?;
            let _permit = self.acquire().await?;
            if !self.send(&datagram).await? {
                unreachable = true;
                continue;
            }
            match self
                .receive_with(|bytes| self.process(bytes, msg_id, request_id))
                .await?
            {
                Received::Got(incoming) => {
                    if let (Some((boots, time)), Some(session)) =
                        (incoming.sync, self.session.as_mut())
                    {
                        session.update(boots, time);
                    }
                    return Ok(incoming.outcome);
                }
                Received::Timeout => {}
                Received::Unreachable => unreachable = true,
            }
        }
        Err(self.timeout_error("the request", unreachable))
    }

    fn report_error(&self, kind: &ReportKind) -> ScanError {
        let user = String::from_utf8_lossy(&self.user);
        match kind {
            ReportKind::UnsupportedSecLevels => auth_error(format!(
                "usmStatsUnsupportedSecLevels: the device does not allow the configured security level for user {user:?}"
            )),
            ReportKind::NotInTimeWindows { .. } => auth_error(
                "usmStatsNotInTimeWindows: the device rejected the engine boots and time again after a resynchronisation",
            ),
            ReportKind::UnknownUserNames => auth_error(format!(
                "usmStatsUnknownUserNames: the device does not know user {user:?}"
            )),
            ReportKind::UnknownEngineIds => protocol_error(
                "usmStatsUnknownEngineIDs: the device rejected its own engine id after a new discovery",
            ),
            ReportKind::WrongDigests => auth_error(format!(
                "usmStatsWrongDigests: the device rejected the authentication of user {user:?} (wrong password or protocol)"
            )),
            ReportKind::DecryptionErrors => auth_error(format!(
                "usmStatsDecryptionErrors: the device could not decrypt the request of user {user:?} (wrong privacy password or protocol)"
            )),
            ReportKind::Other(oid) => protocol_error(format!("the device sent the report {oid}")),
        }
    }

    /// Sends a request and returns the Response PDU, after the time and engine id
    /// resynchronisations.
    async fn request(&mut self, kind: &RequestKind<'_>) -> Result<Pdu, ScanError> {
        let mut resynchronised = false;
        let mut rediscovered = false;
        loop {
            if self.session.is_none() {
                self.discover().await?;
            }
            match self.attempt(kind).await? {
                Outcome::Response(pdu) => {
                    if pdu.error_status != 0 {
                        return Err(protocol_error(format!(
                            "the device answered with the error {} (status {}, index {})",
                            error_status_name(pdu.error_status),
                            pdu.error_status,
                            pdu.error_index
                        )));
                    }
                    return Ok(pdu);
                }
                Outcome::Report(ReportKind::NotInTimeWindows { boots, time }) => {
                    if resynchronised {
                        return Err(
                            self.report_error(&ReportKind::NotInTimeWindows { boots, time })
                        );
                    }
                    resynchronised = true;
                    if let Some(session) = self.session.as_mut() {
                        session.set(boots, time);
                    }
                }
                Outcome::Report(ReportKind::UnknownEngineIds) => {
                    if rediscovered {
                        return Err(self.report_error(&ReportKind::UnknownEngineIds));
                    }
                    rediscovered = true;
                    self.session = None;
                }
                Outcome::Report(other) => return Err(self.report_error(&other)),
            }
        }
    }

    /// Reads the objects `oids` with one `GetRequest`.
    ///
    /// The bindings come back as the device sent them: an object it does not have is
    /// `noSuchObject` or `noSuchInstance`, not an error.
    ///
    /// # Errors
    /// `scan.snmp.timeout`, `scan.snmp.auth`, `scan.snmp.protocol` (including an error
    /// status in the Response), `scan.io`, `scan.cancelled`.
    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>, ScanError> {
        let pdu = self.request(&RequestKind::Get(oids)).await?;
        Ok(pdu.varbinds)
    }

    /// Walks the subtree below `root` with `GetBulkRequest`s (non-repeaters 0,
    /// max-repetitions from [`PollOptions`]) and keeps at most `max_rows` rows.
    ///
    /// An empty subtree, also one the device answers with `noSuchObject`, is an empty
    /// walk. The walk ends at the end of the subtree, at `endOfMibView`, at `max_rows`
    /// and at an object identifier that does not increase; the last two set
    /// [`Walk::truncated`].
    ///
    /// # Errors
    /// As [`Client::get`].
    pub async fn walk(&mut self, root: &Oid, max_rows: usize) -> Result<Walk, ScanError> {
        let mut rows = Vec::new();
        let truncated = self.walk_into(root, max_rows, &mut rows).await?;
        Ok(Walk { rows, truncated })
    }

    /// Like [`Client::walk`], appending the rows to `rows` so that those read before an
    /// error are not lost. Returns whether the walk was truncated.
    ///
    /// # Errors
    /// As [`Client::get`]; `rows` keeps what was read until then.
    pub async fn walk_into(
        &mut self,
        root: &Oid,
        max_rows: usize,
        rows: &mut Vec<VarBind>,
    ) -> Result<bool, ScanError> {
        let first_row = rows.len();
        let mut cursor = root.clone();
        let mut truncated = false;
        let repetitions_limit = usize::try_from(self.options.max_repetitions.max(1)).unwrap_or(1);
        'requests: loop {
            self.check_cancelled()?;
            let wanted = max_rows
                .saturating_sub(rows.len() - first_row)
                .saturating_add(1)
                .min(repetitions_limit)
                .clamp(1, 2_000);
            let pdu = self
                .request(&RequestKind::Bulk {
                    start: &cursor,
                    repetitions: i32::try_from(wanted).unwrap_or(i32::MAX),
                })
                .await?;
            if pdu.varbinds.is_empty() {
                break;
            }
            for binding in pdu.varbinds {
                if binding.value.is_exception() || !binding.oid.starts_with(root) {
                    break 'requests;
                }
                if binding.oid <= cursor {
                    truncated = true;
                    break 'requests;
                }
                if rows.len() - first_row >= max_rows {
                    truncated = true;
                    break 'requests;
                }
                cursor = binding.oid.clone();
                rows.push(binding);
            }
        }
        Ok(truncated)
    }
}
