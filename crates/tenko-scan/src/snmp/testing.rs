//! A fake SNMPv3 agent for the tests.
//!
//! The agent listens on a loopback UDP port and serves a sorted object identifier to value
//! map with the user-based security model: it answers engine discovery with the Report of
//! `usmStatsUnknownEngineIDs`, checks digests and time windows, decrypts, and answers
//! `GetRequest`, `GetNextRequest` and `GetBulkRequest`. Switches make it misbehave in the
//! ways the client has to survive.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    ops::Bound,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{net::UdpSocket, task::JoinHandle, time::Instant};

use super::{
    AuthProtocol, Credentials, PrivProtocol,
    ber::{Oid, Value, VarBind},
    client::usm_stat_oid,
    message::{
        Message, MessageData, MsgFlags, Pdu, PduKind, SECURITY_MODEL_USM, ScopedPdu, UsmParameters,
        decode_message, decode_scoped_pdu,
    },
    usm::{AuthKey, PrivKey, SaltGenerator, localize_key, password_to_key},
};

/// The authentication password of every standard user.
pub(crate) const AUTH_PASSWORD: &str = "auth-password-example";

/// The privacy password of every standard user.
pub(crate) const PRIV_PASSWORD: &str = "priv-password-example";

const SWITCH_A: &str = include_str!("../../tests/fixtures/snmp/switch-a.walk");

/// The recorded walk of the example switch as an object identifier to value map.
pub(crate) fn switch_a() -> BTreeMap<Oid, Value> {
    parse_walk(SWITCH_A)
}

fn parse_hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|part| u8::from_str_radix(part, 16).expect("hex octet"))
        .collect()
}

/// The number of a value such as `up(1)` or `(123) 0:00:01.23`, or a plain number.
fn parse_number(text: &str) -> i128 {
    let inner = match (text.find('('), text.find(')')) {
        (Some(open), Some(close)) if open < close => &text[open + 1..close],
        _ => text,
    };
    inner.trim().parse().expect("number")
}

/// Reads a walk in the style of `snmpwalk -On`: `.1.3.6... = TYPE: value`.
pub(crate) fn parse_walk(text: &str) -> BTreeMap<Oid, Value> {
    let mut map = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (oid, rest) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("no ' = ' in {line:?}"));
        let (kind, value) = rest
            .split_once(':')
            .unwrap_or_else(|| panic!("no type in {line:?}"));
        let value = value.trim();
        let parsed = match kind.trim() {
            "STRING" => Value::OctetString(
                value
                    .strip_prefix('"')
                    .and_then(|text| text.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("unquoted string in {line:?}"))
                    .as_bytes()
                    .to_vec(),
            ),
            "Hex-STRING" => Value::OctetString(parse_hex(value)),
            "Opaque" => Value::Opaque(parse_hex(value)),
            "INTEGER" => Value::Integer(i64::try_from(parse_number(value)).expect("integer")),
            "IpAddress" => Value::IpAddress(
                value
                    .parse::<std::net::Ipv4Addr>()
                    .unwrap_or_else(|_| panic!("address in {line:?}"))
                    .octets(),
            ),
            "OID" => Value::Oid(value.parse().expect("oid value")),
            "Gauge32" => Value::Gauge32(u32::try_from(parse_number(value)).expect("gauge")),
            "Counter32" => Value::Counter32(u32::try_from(parse_number(value)).expect("counter")),
            "Counter64" => Value::Counter64(u64::try_from(parse_number(value)).expect("counter")),
            "Timeticks" => Value::TimeTicks(u32::try_from(parse_number(value)).expect("ticks")),
            other => panic!("unknown type {other:?} in {line:?}"),
        };
        let oid: Oid = oid.parse().unwrap_or_else(|_| panic!("oid in {line:?}"));
        assert!(
            map.insert(oid, parsed).is_none(),
            "duplicate row in {line:?}"
        );
    }
    map
}

/// A user of the agent.
#[derive(Debug, Clone)]
pub(crate) struct AgentUser {
    pub name: String,
    pub auth: Option<(AuthProtocol, String)>,
    pub privacy: Option<String>,
}

/// The users every agent has unless a test says otherwise: `noauth`, and for every
/// authentication protocol `<protocol>-auth` (no privacy) and `<protocol>-priv` (AES-128).
pub(crate) fn standard_users() -> Vec<AgentUser> {
    let mut users = vec![AgentUser {
        name: "noauth".to_owned(),
        auth: None,
        privacy: None,
    }];
    for protocol in AuthProtocol::ALL {
        users.push(AgentUser {
            name: format!("{}-auth", protocol.name()),
            auth: Some((protocol, AUTH_PASSWORD.to_owned())),
            privacy: None,
        });
        users.push(AgentUser {
            name: format!("{}-priv", protocol.name()),
            auth: Some((protocol, AUTH_PASSWORD.to_owned())),
            privacy: Some(PRIV_PASSWORD.to_owned()),
        });
    }
    users
}

/// The credentials that match a standard user.
pub(crate) fn credentials_for(user: &str) -> Credentials {
    if user == "noauth" {
        return Credentials::no_auth(user);
    }
    let (protocol, level) = user.split_once('-').expect("standard user name");
    let protocol: AuthProtocol = protocol.parse().expect("protocol");
    match level {
        "auth" => Credentials::auth_no_priv(user, protocol, AUTH_PASSWORD),
        "priv" => Credentials::auth_priv(
            user,
            protocol,
            AUTH_PASSWORD,
            PrivProtocol::Aes128,
            PRIV_PASSWORD,
        ),
        other => panic!("unknown level {other}"),
    }
}

/// How the agent answers the time window check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TimeWindow {
    /// Check the time as RFC 3414 says.
    #[default]
    Off,
    /// Answer the next authenticated request with `usmStatsNotInTimeWindows`.
    Once,
    /// Answer every authenticated request so.
    Always,
}

/// The ways the agent can misbehave.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // independent switches, not a state machine
pub(crate) struct Switches {
    /// Ignore this many of the next datagrams.
    pub drop_next: usize,
    /// Ignore every datagram.
    pub drop_all: bool,
    /// Answer every authenticated request with `usmStatsWrongDigests`.
    pub wrong_digest: bool,
    /// Answer every request with `usmStatsUnknownUserNames`.
    pub unknown_user: bool,
    /// See [`TimeWindow`].
    pub time_window: TimeWindow,
    /// Put a wrong digest into authenticated responses.
    pub corrupt_digest: bool,
    /// In a `GetBulk` that starts at or below this subtree, repeat the first binding as
    /// the third one: a table that does not advance.
    pub loop_subtree: Option<Oid>,
    /// Answer requests for this subtree with the error status `genErr`.
    pub error_subtree: Option<Oid>,
}

/// The configuration of an agent.
pub(crate) struct AgentConfig {
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub users: Vec<AgentUser>,
    pub mib: BTreeMap<Oid, Value>,
}

impl AgentConfig {
    /// The standard users, an engine id from the documentation range of RFC 3411 and the
    /// time 5000 s of boot 7.
    pub(crate) fn new(mib: BTreeMap<Oid, Value>) -> Self {
        Self {
            engine_id: vec![
                0x80, 0x00, 0x1F, 0x88, 0x80, 0xE1, 0x7A, 0x00, 0x00, 0x00, 0x01,
            ],
            boots: 7,
            time: 5000,
            users: standard_users(),
            mib,
        }
    }
}

struct UserKeys {
    name: Vec<u8>,
    auth: Option<AuthKey>,
    privacy: Option<PrivKey>,
}

struct Shared {
    engine_id: Vec<u8>,
    boots: AtomicU32,
    clock: Mutex<(Instant, u32)>,
    users: Vec<UserKeys>,
    mib: BTreeMap<Oid, Value>,
    switches: Mutex<Switches>,
    datagrams: AtomicUsize,
    reports: Mutex<Vec<&'static str>>,
    salts: Mutex<SaltGenerator>,
}

/// A running agent; dropping it stops it.
pub(crate) struct FakeAgent {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeAgent {
    /// Starts an agent on `127.0.0.1` with a port of the system's choosing.
    pub(crate) async fn start(config: AgentConfig) -> FakeAgent {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the agent socket");
        let addr = socket.local_addr().expect("local address");
        let users = config
            .users
            .iter()
            .map(|user| {
                let auth = user.auth.as_ref().map(|(protocol, password)| {
                    let master = password_to_key(*protocol, password);
                    AuthKey::new(
                        *protocol,
                        localize_key(*protocol, &master, &config.engine_id),
                    )
                });
                let privacy = match (&user.auth, &user.privacy) {
                    (Some((protocol, _)), Some(password)) => {
                        let master = password_to_key(*protocol, password);
                        Some(
                            PrivKey::new(&localize_key(*protocol, &master, &config.engine_id))
                                .expect("privacy key"),
                        )
                    }
                    _ => None,
                };
                UserKeys {
                    name: user.name.clone().into_bytes(),
                    auth,
                    privacy,
                }
            })
            .collect();
        let shared = Arc::new(Shared {
            engine_id: config.engine_id,
            boots: AtomicU32::new(config.boots),
            clock: Mutex::new((Instant::now(), config.time)),
            users,
            mib: config.mib,
            switches: Mutex::new(Switches::default()),
            datagrams: AtomicUsize::new(0),
            reports: Mutex::new(Vec::new()),
            salts: Mutex::new(SaltGenerator::new().expect("salts")),
        });
        let task = tokio::spawn(serve(socket, Arc::clone(&shared)));
        FakeAgent { addr, shared, task }
    }

    /// The address to poll.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Changes the switches.
    pub(crate) fn set(&self, change: impl FnOnce(&mut Switches)) {
        change(&mut self.shared.switches());
    }

    /// The datagrams received so far, including the ones that were ignored.
    pub(crate) fn datagrams(&self) -> usize {
        self.shared.datagrams.load(Ordering::SeqCst)
    }

    /// The names of the Reports sent so far, in order.
    pub(crate) fn reports(&self) -> Vec<&'static str> {
        self.shared.reports.lock().expect("reports").clone()
    }

    /// Restarts the engine: one more boot and the engine time back at zero.
    pub(crate) fn reboot(&self) {
        self.shared.boots.fetch_add(1, Ordering::SeqCst);
        *self.shared.clock.lock().expect("clock") = (Instant::now(), 0);
    }
}

async fn serve(socket: UdpSocket, shared: Arc<Shared>) {
    let mut buffer = vec![0u8; 65_535];
    loop {
        let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        shared.datagrams.fetch_add(1, Ordering::SeqCst);
        if shared.should_drop() {
            continue;
        }
        if let Some(reply) = shared.handle(&buffer[..length]) {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

impl Shared {
    fn switches(&self) -> MutexGuard<'_, Switches> {
        self.switches.lock().expect("switches")
    }

    fn should_drop(&self) -> bool {
        let mut switches = self.switches();
        if switches.drop_all {
            return true;
        }
        if switches.drop_next > 0 {
            switches.drop_next -= 1;
            return true;
        }
        false
    }

    fn engine_time(&self) -> (u32, u32) {
        let (start, base) = *self.clock.lock().expect("clock");
        let elapsed = u32::try_from(start.elapsed().as_secs()).unwrap_or(u32::MAX);
        (
            self.boots.load(Ordering::SeqCst),
            base.saturating_add(elapsed),
        )
    }

    fn build(
        &self,
        msg_id: i32,
        flags: MsgFlags,
        user: &[u8],
        scoped: ScopedPdu,
        auth: Option<&AuthKey>,
        privacy: Option<&PrivKey>,
        corrupt_digest: bool,
    ) -> Option<Vec<u8>> {
        let (boots, time) = self.engine_time();
        let mut usm = UsmParameters {
            engine_id: self.engine_id.clone(),
            boots,
            time,
            user: user.to_vec(),
            auth_params: auth
                .map(|key| vec![0u8; key.protocol().mac_len()])
                .unwrap_or_default(),
            priv_params: Vec::new(),
        };
        let data = match (flags.privacy, privacy) {
            (true, Some(key)) => {
                let salt = self.salts.lock().expect("salts").next_salt();
                usm.priv_params = salt.to_vec();
                let mut plaintext = scoped.encode().ok()?;
                key.encrypt(boots, time, &salt, &mut plaintext).ok()?;
                MessageData::Encrypted(plaintext)
            }
            _ => MessageData::Plain(scoped),
        };
        let message = Message {
            msg_id,
            max_size: 65_507,
            flags,
            security_model: SECURITY_MODEL_USM,
            usm,
            data,
            auth_params_at: 0..0,
        };
        let mut encoded = message.encode().ok()?;
        if let Some(key) = auth {
            key.sign(&mut encoded.bytes, &encoded.auth_params).ok()?;
            if corrupt_digest {
                encoded.bytes[encoded.auth_params.start] ^= 0xFF;
            }
        }
        Some(encoded.bytes)
    }

    fn report(
        &self,
        request: &Message,
        counter: u32,
        name: &'static str,
        auth: Option<&AuthKey>,
    ) -> Option<Vec<u8>> {
        let count = {
            let mut reports = self.reports.lock().expect("reports");
            reports.push(name);
            reports.iter().filter(|sent| **sent == name).count()
        };
        let request_id = match &request.data {
            MessageData::Plain(scoped) => scoped.pdu.request_id,
            MessageData::Encrypted(_) => 0,
        };
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: Vec::new(),
            pdu: Pdu {
                kind: PduKind::Report,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind {
                    oid: usm_stat_oid(counter),
                    value: Value::Counter32(u32::try_from(count).unwrap_or(u32::MAX)),
                }],
            },
        };
        let flags = MsgFlags {
            auth: auth.is_some(),
            privacy: false,
            reportable: false,
        };
        self.build(
            request.msg_id,
            flags,
            &request.usm.user,
            scoped,
            auth,
            None,
            false,
        )
    }

    fn handle(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let message = decode_message(bytes).ok()?;
        if message.security_model != SECURITY_MODEL_USM {
            return None;
        }
        let switches = self.switches().clone();
        if message.usm.engine_id != self.engine_id {
            return self.report(&message, 4, "usmStatsUnknownEngineIDs", None);
        }
        let user = self
            .users
            .iter()
            .find(|user| user.name == message.usm.user)
            .filter(|_| !switches.unknown_user);
        let Some(user) = user else {
            return self.report(&message, 3, "usmStatsUnknownUserNames", None);
        };
        if message.flags.auth != user.auth.is_some()
            || message.flags.privacy != user.privacy.is_some()
        {
            return self.report(&message, 1, "usmStatsUnsupportedSecLevels", None);
        }
        if let Some(key) = &user.auth {
            if switches.wrong_digest || !key.verify(bytes, &message.auth_params_at) {
                return self.report(&message, 5, "usmStatsWrongDigests", None);
            }
            let (boots, time) = self.engine_time();
            let in_window = message.usm.boots == boots && message.usm.time.abs_diff(time) <= 150;
            let forced = {
                let mut switches = self.switches();
                match switches.time_window {
                    TimeWindow::Off => false,
                    TimeWindow::Once => {
                        switches.time_window = TimeWindow::Off;
                        true
                    }
                    TimeWindow::Always => true,
                }
            };
            if !in_window || forced {
                return self.report(&message, 2, "usmStatsNotInTimeWindows", Some(key));
            }
        }
        let scoped = match &message.data {
            MessageData::Plain(scoped) => scoped.clone(),
            MessageData::Encrypted(ciphertext) => {
                let key = user.privacy.as_ref()?;
                let mut plaintext = ciphertext.clone();
                let decoded = key
                    .decrypt(
                        message.usm.boots,
                        message.usm.time,
                        &message.usm.priv_params,
                        &mut plaintext,
                    )
                    .ok()
                    .and_then(|()| decode_scoped_pdu(&plaintext).ok());
                match decoded {
                    Some(scoped) => scoped,
                    None => return self.report(&message, 6, "usmStatsDecryptionErrors", None),
                }
            }
        };
        let answer = self.answer(&scoped.pdu, &switches)?;
        let reply = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: scoped.context_name,
            pdu: answer,
        };
        let flags = MsgFlags {
            auth: message.flags.auth,
            privacy: message.flags.privacy,
            reportable: false,
        };
        self.build(
            message.msg_id,
            flags,
            &message.usm.user,
            reply,
            user.auth.as_ref(),
            user.privacy.as_ref(),
            switches.corrupt_digest,
        )
    }

    /// The binding that follows `oid` in the MIB, or `endOfMibView`.
    fn next(&self, oid: &Oid) -> VarBind {
        self.mib
            .range((Bound::Excluded(oid), Bound::Unbounded))
            .next()
            .map_or_else(
                || VarBind {
                    oid: oid.clone(),
                    value: Value::EndOfMibView,
                },
                |(next, value)| VarBind {
                    oid: next.clone(),
                    value: value.clone(),
                },
            )
    }

    fn answer(&self, request: &Pdu, switches: &Switches) -> Option<Pdu> {
        let response = |error_status: i32, error_index: i32, varbinds: Vec<VarBind>| Pdu {
            kind: PduKind::Response,
            request_id: request.request_id,
            error_status,
            error_index,
            varbinds,
        };
        if let (Some(subtree), Some(first)) = (&switches.error_subtree, request.varbinds.first())
            && first.oid.starts_with(subtree)
        {
            return Some(response(5, 1, request.varbinds.clone()));
        }
        let varbinds = match request.kind {
            PduKind::Get => request
                .varbinds
                .iter()
                .map(|binding| VarBind {
                    oid: binding.oid.clone(),
                    value: self
                        .mib
                        .get(&binding.oid)
                        .cloned()
                        .unwrap_or(Value::NoSuchObject),
                })
                .collect(),
            PduKind::GetNext => request
                .varbinds
                .iter()
                .map(|binding| self.next(&binding.oid))
                .collect(),
            PduKind::GetBulk => {
                let non_repeaters = usize::try_from(request.error_status)
                    .unwrap_or(0)
                    .min(request.varbinds.len());
                let repetitions = usize::try_from(request.error_index).unwrap_or(0);
                let mut out: Vec<VarBind> = request.varbinds[..non_repeaters]
                    .iter()
                    .map(|binding| self.next(&binding.oid))
                    .collect();
                let mut cursors: Vec<Oid> = request.varbinds[non_repeaters..]
                    .iter()
                    .map(|binding| binding.oid.clone())
                    .collect();
                'rounds: for _ in 0..repetitions {
                    let mut all_ended = true;
                    for cursor in &mut cursors {
                        let binding = self.next(cursor);
                        if binding.value != Value::EndOfMibView {
                            all_ended = false;
                        }
                        *cursor = binding.oid.clone();
                        out.push(binding);
                    }
                    if all_ended {
                        break 'rounds;
                    }
                }
                if let (Some(subtree), Some(first)) =
                    (&switches.loop_subtree, request.varbinds.first())
                    && first.oid.starts_with(subtree)
                    && out.len() >= 3
                {
                    out[2] = out[0].clone();
                }
                out
            }
            PduKind::Response | PduKind::Report => return None,
        };
        Some(response(0, 0, varbinds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_walk_parses() {
        let mib = switch_a();
        let sys_name: Oid = "1.3.6.1.2.1.1.5.0".parse().expect("oid");
        assert_eq!(
            mib.get(&sys_name),
            Some(&Value::OctetString(b"switch-a.example.net".to_vec()))
        );
        let fdb: Oid = "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.0.94.0.83.64"
            .parse()
            .expect("oid");
        assert_eq!(mib.get(&fdb), Some(&Value::Integer(5)));
        let object_id: Oid = "1.3.6.1.2.1.1.2.0".parse().expect("oid");
        assert_eq!(
            mib.get(&object_id),
            Some(&Value::Oid("1.3.6.1.4.1.8072.3.2.10".parse().expect("oid")))
        );
        assert!(
            mib.values()
                .any(|value| matches!(value, Value::Counter64(123_456_789_012)))
        );
        assert!(
            mib.values()
                .any(|value| matches!(value, Value::TimeTicks(123_456)))
        );
        assert!(mib.len() > 100);
    }

    #[test]
    fn walk_values_of_every_style_parse() {
        let mib = parse_walk(
            ".1.3.6.1.2.1.1.1.0 = STRING: \"hello\"\n\
             .1.3.6.1.2.1.1.2.0 = Hex-STRING: 00 00 5E 00 53 10\n\
             .1.3.6.1.2.1.1.3.0 = Timeticks: (123) 0:00:01.23\n\
             .1.3.6.1.2.1.1.4.0 = IpAddress: 192.0.2.1\n\
             .1.3.6.1.2.1.1.5.0 = Gauge32: 3\n\
             .1.3.6.1.2.1.1.6.0 = INTEGER: up(1)\n\
             .1.3.6.1.2.1.1.7.0 = Hex-STRING:\n",
        );
        let values: Vec<_> = mib.into_values().collect();
        assert_eq!(
            values,
            vec![
                Value::OctetString(b"hello".to_vec()),
                Value::OctetString(vec![0, 0, 0x5E, 0, 0x53, 0x10]),
                Value::TimeTicks(123),
                Value::IpAddress([192, 0, 2, 1]),
                Value::Gauge32(3),
                Value::Integer(1),
                Value::OctetString(Vec::new()),
            ]
        );
    }
}
