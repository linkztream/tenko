//! The Kerberos account of secure dynamic updates, controller side (identity plan sections
//! 3.1, 3.2, 3.10 and 3.11; ADR 0026 points 4 and 5; DNS-28, OPS-09, OPS-11, IAM-16).
//!
//! One AD computer account per installation holds the SPN of every node (ID-Q6). Its
//! metadata is the row of `dns.krb_accounts`; its keys are one system secret of purpose
//! [`VAULT_PURPOSE`] in the vault, in the stored form of [`KeySet::encode`], never revealed
//! and never on disk outside the vault.
//!
//! | Operation | What |
//! |---|---|
//! | [`KerberosService::adopt`] | Takes over a pre-staged computer account with its one-time password: a `kadmin/changepw` ticket, a random password of [`PASSWORD_LEN`] printable characters only Tenko knows, the AES keys derived with the KDC's salt, the key version read back from a ticket for the account's own SPN |
//! | [`KerberosService::import`] | Keeps the AES entries of a keytab made with `ktpass` or `msktutil`; the password stays the administrator's and is not rotated |
//! | [`KerberosService::rotate`] | Changes the password of an owned account (the job [`ROTATE_JOB`], every [`KrbAccount::rotation_days`]) |
//! | [`KerberosService::recover`] | Finishes or undoes a change whose commit a restart interrupted |
//! | [`KerberosService::check`] | The self-test and its findings |
//! | [`KerberosService::delete`] | Removes the row and the keys |
//! | [`LeaderLoop`] | The leader service `dns.krb`: recovery, the daily self-test and the rotation when due |
//! | [`follow`] | The watcher that hands the keys to the acceptor of the `dns` role ([`KeySink`]) |
//!
//! # The pending state (R123)
//!
//! A password change is the one step that cannot be undone: once the KDC took the new
//! password, a Tenko that lost the keys has lost the account. So every change writes the
//! keys of the new password to the vault first, as the `pending` version, under the row's
//! revision (and, on the leader, the leader epoch), and only then sends the request. After
//! the change the version the KDC issues is read back and the keys move: pending to
//! current, current to previous, the old previous goes. A restart, a lost answer or a
//! failed commit leaves the pending version in place; [`KerberosService::recover`] then
//! asks the KDC for a ticket with the pending keys alone: when it issues one the change
//! happened and is committed, when it refuses them the change did not happen and the
//! pending version goes, and when no KDC answers nothing moves. The acceptor holds the
//! pending keys meanwhile, so a ticket issued under the new password is accepted at once.
//! The previous version is kept until the next rotation, so tickets issued before a change
//! (ten hours at most by AD's default) are still accepted (E45).
//!
//! # Secrets
//!
//! The one-time password, the new password and every key live in zeroizing memory and are
//! dropped when the operation ends. None of them enters a log line, an error text, an audit
//! record, a finding or a URL: errors carry the KDC's error code and its cleaned text, the
//! audit records carry the realm, the account name and the key version numbers. No
//! directory administrator's credential is asked for at any point (ID-Q4).

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt as _;
use tenko_core::{
    ObjectRef, RequestCtx, Revision, SystemComponent, Timestamp,
    audit::AuditDraft,
    dns::{
        DnsName, EncryptionType, KeyVersionMeta, KeyVersionState, KrbAccount, KrbFinding,
        PrincipalName, Realm, RecordData, RrSetKey, Rtype, ScopeName, audit, codes, findings,
        tables::{KRB_ACCOUNTS, RRSETS, ZONES},
    },
    error::codes as sys,
    secret::SecretClass,
};
use tenko_jobs::{
    JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
    StepSpec,
};
use tenko_krb::{
    acceptor::{
        AcceptError, Acceptor as _, Clock, Config as AcceptorConfig, KrbTime, Service, Step,
    },
    cipher,
    client::{self, AsResult, Client, ClientError, Credentials, Secret, error_code},
    der::oid,
    keys::{KeyEntry, KeySet, SelectError},
    keytab,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WatchFilter, WriteBatch,
};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};
use tokio_util::sync::CancellationToken;
/// The zeroizing buffer the requests take their secrets in.
pub use zeroize::Zeroizing;

use super::{ZoneError, ZoneResult, jobs::ZoneJobs};

/// The vault purpose of the account's keys (ADR 0026 point 5).
pub const VAULT_PURPOSE: &str = "dns.krb";

/// The length of the password Tenko sets (identity plan section 3.1).
pub const PASSWORD_LEN: usize = 120;

/// The clock skew between the node and the KDC above which the self-test reports
/// `dns.gss.clock_skew` (R135), well before Kerberos' own 300 s.
pub const MAX_SKEW_SECS: i64 = 60;

/// How long a pending version is kept whatever the KDC answers: longer than a password
/// change can take across every KDC (eight servers, a UDP and a TCP attempt of 3 s each),
/// than the step timeout of the rotation job, and than the replication of a password
/// between the domain controllers. Within it, a recovery never drops the pending keys.
pub const PENDING_GRACE: Duration = Duration::from_secs(15 * 60);

/// How long a version stays held after the version after it became current: longer than
/// a service ticket lives (ten hours by AD's default) plus the skew, so that a ticket
/// issued before a rotation is accepted until it expires (E45).
pub const KEEP_PREVIOUS: Duration = Duration::from_secs(12 * 3600);

/// The most previous versions held.
pub const MAX_PREVIOUS: usize = 3;

/// The kind of the rotation job and of its one step.
pub const ROTATE_JOB: &str = "dns.krb.rotate";
/// The title of the rotation job (a UI message key).
pub const ROTATE_TITLE: &str = "dns.job.krb_rotate";
/// The summary key of the rotation step's preview.
pub const ROTATE_PREVIEW: &str = "dns.job.krb_rotate_preview";

/// The name of the leader service.
pub const LEADER_SERVICE: &str = "dns.krb";

/// Attempts of a write that a concurrent change or a KEK rotation made stale.
const ATTEMPTS: u32 = 4;

/// The settings of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KerberosConfig {
    /// Whether a rotation interval of 0 (off) is allowed: under the Lab profile only
    /// (TGL-32).
    pub rotation_off_allowed: bool,
    /// Rotation failures in a row before `dns.gss.rotation_failed` is raised: 1 under
    /// Hardened (TGL-32, "a failed rotation alarms"), 2 under the other profiles.
    pub rotation_failures_before_finding: u32,
    /// How often the leader runs the self-test.
    pub check_every: Duration,
    /// How long the leader waits after a failed rotation before it tries again.
    pub retry_after: Duration,
    /// How often the leader looks at the account.
    pub tick: Duration,
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            rotation_off_allowed: false,
            rotation_failures_before_finding: 2,
            check_every: Duration::from_secs(24 * 3600),
            retry_after: Duration::from_secs(3600),
            tick: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------------------
// The seams: the KDC, the clock, the passwords

/// Where the KDCs of an account are: the realm and the operator's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcTarget {
    /// The realm.
    pub realm: Realm,
    /// `host` or `host:port` (`[2001:db8::1]:88` for an address); empty: found through
    /// `_kerberos._tcp.<realm>`.
    pub kdcs: Vec<String>,
}

impl KdcTarget {
    fn of(account: &KrbAccount) -> Self {
        Self {
            realm: account.realm.clone(),
            kdcs: account.kdcs.clone(),
        }
    }
}

/// The KDC exchanges of the service: [`NetKdc`] over the network, a test KDC in the tests.
#[async_trait::async_trait]
pub trait Kdc: Send + Sync + 'static {
    /// An AS exchange for `client` asking a ticket for `service`.
    async fn as_exchange(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError>;

    /// A TGS exchange for `service` with `tgt`.
    async fn tgs_exchange(
        &self,
        target: &KdcTarget,
        tgt: &Credentials,
        service: &PrincipalName,
    ) -> Result<Credentials, ClientError>;

    /// Changes the password of `client` to `new_password`, authenticating with `secret`.
    async fn change_password(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        secret: Secret,
        new_password: &[u8],
    ) -> Result<(), ClientError>;
}

/// The source of new passwords: random in the server, fixed in the tests that replay a
/// recorded change.
pub trait PasswordSource: Send + Sync + 'static {
    /// A new password of printable ASCII characters.
    fn generate(&self) -> Zeroizing<Vec<u8>>;
}

/// [`PASSWORD_LEN`] characters drawn uniformly from the 94 printable ASCII characters
/// `!` to `~` with `aws-lc-rs`'s generator, holding a lower-case letter, an upper-case
/// letter, a digit and a symbol (a domain's complexity rule asks for three of the four).
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomPasswords;

impl PasswordSource for RandomPasswords {
    fn generate(&self) -> Zeroizing<Vec<u8>> {
        random_password(PASSWORD_LEN)
    }
}

/// A random password of `len` printable characters with every class present.
///
/// # Panics
///
/// When the system's random generator fails, which `aws-lc-rs` treats as fatal too.
pub fn random_password(len: usize) -> Zeroizing<Vec<u8>> {
    loop {
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        let mut pool = Zeroizing::new([0_u8; 256]);
        while out.len() < len {
            aws_lc_rs::rand::fill(&mut *pool).expect("the system's random generator");
            // Rejection sampling: 188 = 2 * 94, so `b % 94` is uniform for b < 188.
            for b in pool.iter().copied().filter(|b| *b < 188) {
                if out.len() == len {
                    break;
                }
                out.push(b'!' + b % 94);
            }
        }
        let has = |test: fn(&u8) -> bool| out.iter().any(test);
        if len < 4
            || (has(u8::is_ascii_lowercase)
                && has(u8::is_ascii_uppercase)
                && has(u8::is_ascii_digit)
                && has(u8::is_ascii_punctuation))
        {
            return out;
        }
    }
}

/// The node's clock, in the form the Kerberos code takes.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> KrbTime {
        KrbTime::from_unix_nanos(Timestamp::now().unix_nanos())
    }
}

fn timestamp(time: KrbTime) -> Timestamp {
    Timestamp::from_unix_nanos(
        i128::from(time.secs) * 1_000_000_000 + i128::from(time.usec) * 1_000,
    )
    .unwrap_or_else(|_| Timestamp::now())
}

/// The KDCs over the network: the operator's list, or the SRV records of the realm that
/// Tenko serves itself on a take-over, or the realm's domain name (whose A records are the
/// domain controllers in AD).
pub struct NetKdc {
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for NetKdc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetKdc").finish_non_exhaustive()
    }
}

/// The port of the KDC.
pub const KDC_PORT: u16 = 88;
/// The port of the change-password service.
pub const KPASSWD_PORT: u16 = 464;
/// The most servers tried per exchange.
const MAX_SERVERS: usize = 8;

impl NetKdc {
    /// The KDCs found through `store` (the SRV records), on `clock`.
    pub fn new(store: Arc<dyn Store>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    async fn client(&self, target: &KdcTarget) -> Result<Client, ClientError> {
        let (kdcs, kpasswd) = self.servers(target).await;
        if kdcs.is_empty() {
            return Err(ClientError::Unreachable {
                servers: 0,
                last: Some(format!(
                    "no KDC of {} was found: list the KDCs or serve _kerberos._tcp.{}",
                    target.realm,
                    target.realm.domain()
                )),
            });
        }
        Ok(Client::new(kdcs, kpasswd, Arc::clone(&self.clock)))
    }

    /// The KDCs and change-password servers of `target`, resolved.
    async fn servers(&self, target: &KdcTarget) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
        let hosts: Vec<(String, Option<u16>, Option<u16>)> = if target.kdcs.is_empty() {
            match self.srv_hosts(&target.realm).await {
                hosts if !hosts.is_empty() => hosts,
                _ => vec![(target.realm.domain(), None, None)],
            }
        } else {
            target
                .kdcs
                .iter()
                .filter_map(|entry| split_host_port(entry))
                .map(|(host, port)| (host, port, None))
                .collect()
        };
        let mut kdcs = Vec::new();
        let mut kpasswd = Vec::new();
        for (host, port, kpasswd_port) in hosts.into_iter().take(MAX_SERVERS) {
            let port = port.unwrap_or(KDC_PORT);
            if kdcs.len() >= MAX_SERVERS {
                break;
            }
            if let Ok(found) = tokio::net::lookup_host((host.as_str(), port)).await {
                for address in found.take(MAX_SERVERS) {
                    if !kdcs.contains(&address) {
                        kdcs.push(address);
                    }
                    let other = SocketAddr::new(address.ip(), kpasswd_port.unwrap_or(KPASSWD_PORT));
                    if !kpasswd.contains(&other) {
                        kpasswd.push(other);
                    }
                }
            }
        }
        (kdcs, kpasswd)
    }

    /// The targets of `_kerberos._tcp.<domain>` and the port of `_kpasswd._tcp.<domain>`
    /// from the zones Tenko serves, in the order of their priority.
    async fn srv_hosts(&self, realm: &Realm) -> Vec<(String, Option<u16>, Option<u16>)> {
        let Ok(view) = self.store.read(ReadConsistency::Local).await else {
            return Vec::new();
        };
        let srv = |label: &str| -> Vec<(u16, String, u16)> {
            let Ok(name) = DnsName::new(&format!("{label}.{}", realm.domain())) else {
                return Vec::new();
            };
            srv_records(view.as_ref(), &name)
        };
        let kpasswd_port = srv("_kpasswd._tcp").first().map(|(_, _, port)| *port);
        let mut kdcs = srv("_kerberos._tcp");
        kdcs.sort_by_key(|(priority, _, _)| *priority);
        kdcs.into_iter()
            .map(|(_, host, port)| (host, Some(port), kpasswd_port))
            .collect()
    }
}

/// The SRV records of `name` in the zone that holds it (the default scope): priority,
/// target and port.
fn srv_records(view: &dyn ReadView, name: &DnsName) -> Vec<(u16, String, u16)> {
    let Ok(zones) = view.scan_typed(&ZONES, KeyRange::all(), usize::MAX, false) else {
        return Vec::new();
    };
    let Some(zone) = zones
        .into_iter()
        .map(|(_, zone, _)| zone)
        .filter(|zone| name.is_subdomain_of(&zone.name))
        .max_by_key(|zone| zone.name.label_count())
    else {
        return Vec::new();
    };
    let key = RrSetKey {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: name.clone(),
        rtype: Rtype::SRV,
    };
    let Ok(Some((rrset, _))) = view.get_typed(&RRSETS, &key) else {
        return Vec::new();
    };
    rrset
        .rdata
        .iter()
        .filter_map(|rdata| match rdata.decode(Rtype::SRV) {
            Ok(RecordData::Srv {
                priority,
                port,
                target,
                ..
            }) if !target.is_root() => Some((priority, target.as_str().to_owned(), port)),
            _ => None,
        })
        .collect()
}

/// `host`, `host:port`, `[address]` or `[address]:port`.
fn split_host_port(entry: &str) -> Option<(String, Option<u16>)> {
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(port.parse().ok()?),
            None if rest.is_empty() => None,
            None => return None,
        };
        return Some((host.to_owned(), port));
    }
    if entry.parse::<IpAddr>().is_ok() {
        return Some((entry.to_owned(), None));
    }
    match entry.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), Some(port.parse().ok()?))),
        None => Some((entry.to_owned(), None)),
    }
}

#[async_trait::async_trait]
impl Kdc for NetKdc {
    async fn as_exchange(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        service: &PrincipalName,
        secret: Secret,
    ) -> Result<AsResult, ClientError> {
        self.client(target)
            .await?
            .as_exchange(client, service, secret)
            .await
    }

    async fn tgs_exchange(
        &self,
        target: &KdcTarget,
        tgt: &Credentials,
        service: &PrincipalName,
    ) -> Result<Credentials, ClientError> {
        self.client(target).await?.tgs_exchange(tgt, service).await
    }

    async fn change_password(
        &self,
        target: &KdcTarget,
        client: &PrincipalName,
        secret: Secret,
        new_password: &[u8],
    ) -> Result<(), ClientError> {
        self.client(target)
            .await?
            .change_password_with(client, secret, new_password)
            .await
    }
}

/// A KDC that never answers: every exchange times out. The service of a server that must
/// not reach a directory, and the stand-in of the API's tests, which exercise the routes'
/// own paths without one.
#[derive(Debug, Clone, Copy, Default)]
pub struct SilentKdc;

#[async_trait::async_trait]
impl Kdc for SilentKdc {
    async fn as_exchange(
        &self,
        _target: &KdcTarget,
        _client: &PrincipalName,
        _service: &PrincipalName,
        _secret: Secret,
    ) -> Result<AsResult, ClientError> {
        Err(ClientError::Timeout)
    }

    async fn tgs_exchange(
        &self,
        _target: &KdcTarget,
        _tgt: &Credentials,
        _service: &PrincipalName,
    ) -> Result<Credentials, ClientError> {
        Err(ClientError::Timeout)
    }

    async fn change_password(
        &self,
        _target: &KdcTarget,
        _client: &PrincipalName,
        _secret: Secret,
        _new_password: &[u8],
    ) -> Result<(), ClientError> {
        Err(ClientError::Timeout)
    }
}

/// Where the keys go on the node: the acceptor of the `dns` role, `tenko_dns::tkey::KeyHandle`
/// of the TKEY handler (WP13.2), whose three methods this trait mirrors; the implementation
/// for it is added where both meet. The watcher ([`follow`]) calls it at start and after
/// every change of the account's keys.
pub trait KeySink: Send + Sync + 'static {
    /// The acceptor takes these keys (current, pending and previous versions in one set)
    /// for `realm` and `spns` (`service/host`, no realm). With the same realm and SPNs the
    /// keys are replaced in place and the replay cache stays. A refusal leaves what was
    /// installed before.
    ///
    /// # Errors
    ///
    /// Why the acceptor refused (an empty SPN list, a malformed SPN, an empty key set).
    fn install(&self, realm: Realm, spns: &[String], keys: KeySet) -> Result<(), String>;
    /// The account is gone: the acceptor holds no keys and refuses every negotiation.
    fn clear(&self);
    /// The realm and SPNs installed, if any.
    fn installed(&self) -> Option<(Realm, Vec<String>)>;
}

// ---------------------------------------------------------------------------------------
// Errors

fn kdc_unreachable(realm: &Realm, error: &ClientError) -> ZoneError {
    ZoneError::new(
        codes::KRB_KDC_UNREACHABLE,
        503,
        format!("no KDC of {realm} answered: {}", clean(&error.to_string())),
    )
    .param("realm", realm.as_str())
    .param("reason", clean(&error.to_string()))
}

fn password_refused(realm: &Realm, error: &ClientError) -> ZoneError {
    ZoneError::new(
        codes::KRB_PASSWORD_REFUSED,
        422,
        format!("the KDC of {realm} refused: {}", clean(&error.to_string())),
    )
    .param("realm", realm.as_str())
    .param("reason", clean(&error.to_string()))
}

/// Whether no KDC answered (or the answer was lost): the state of a change is unknown.
fn is_unreachable(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Unreachable { .. } | ClientError::Timeout | ClientError::Io(_)
    )
}

/// Whether a failed change proves that the password did not change: the exchange failed
/// before the request was sent, or the server refused it in an authenticated answer to the
/// only request sent. Every other failure leaves the outcome unknown.
fn not_changed(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::BeforeChange(_) | ClientError::PasswordRefused { definite: true, .. }
    )
}

/// The failure inside [`ClientError::BeforeChange`].
fn inner(error: &ClientError) -> &ClientError {
    match error {
        ClientError::BeforeChange(inner) => inner,
        other => other,
    }
}

/// A change the KDC confirmed whose new version Tenko could not read back yet.
fn change_unconfirmed(realm: &Realm) -> ZoneError {
    ZoneError::new(
        codes::KRB_KDC_UNREACHABLE,
        503,
        format!(
            "the KDC of {realm} took the new password, but no KDC confirmed its key version yet; Tenko keeps the new keys as pending and commits them at the next recovery"
        ),
    )
    .param("realm", realm.as_str())
    .param("reason", "unconfirmed")
}

/// A change whose outcome no answer proves.
fn change_unknown(realm: &Realm, error: &ClientError) -> ZoneError {
    let base = if is_unreachable(error) {
        kdc_unreachable(realm, error)
    } else {
        password_refused(realm, error)
    };
    let coded = base.coded();
    ZoneError::new(
        if is_unreachable(error) {
            codes::KRB_KDC_UNREACHABLE
        } else {
            codes::KRB_PASSWORD_REFUSED
        },
        coded.status,
        format!(
            "{}; the change may have been made, so Tenko keeps the new keys as pending until a KDC tells which password the account has",
            coded.detail
        ),
    )
    .param("realm", realm.as_str())
    .param("reason", clean(&error.to_string()))
}

/// The keys after a committed change: the pending version renumbered to `kvno` and made
/// current, the current one previous. A previous version is dropped only when the version
/// after it became current long enough ago that no ticket under it can still be valid
/// ([`KEEP_PREVIOUS`], E45), and at most [`MAX_PREVIOUS`] are kept.
fn moved_keys(
    account: &KrbAccount,
    keys: &KeySet,
    provisional: u32,
    kvno: u32,
    now: Timestamp,
) -> ZoneResult<KeySet> {
    let keep_previous = account
        .current()
        .is_some_and(|v| now.saturating_since(v.created) < KEEP_PREVIOUS);
    let mut moved = if keep_previous {
        keys.clone()
    } else {
        keys.clone().without_state(KeyVersionState::Previous)
    };
    if let Some(from) = account.current().map(|v| v.kvno) {
        moved = moved.with_state(from, KeyVersionState::Previous);
    }
    let previous = moved.in_state(KeyVersionState::Previous).kvnos();
    for old in previous
        .iter()
        .take(previous.len().saturating_sub(MAX_PREVIOUS))
    {
        moved = moved.without_kvno(*old);
    }
    Ok(moved
        .renumbered(provisional, kvno)
        .ok_or_else(|| ZoneError::new(sys::INTERNAL, 500, "the key version is held already"))?
        .with_state(kvno, KeyVersionState::Current))
}

/// Whether a ticket is encrypted under one of `keys`.
fn ticket_under(keys: &KeySet, ticket: &tenko_krb::der::Ticket) -> bool {
    keys.select(ticket.enc_part.etype, ticket.enc_part.kvno)
        .or_else(|_| keys.select(ticket.enc_part.etype, None))
        .is_ok_and(|candidates| {
            candidates.iter().any(|key| {
                cipher::decrypt_data(key, cipher::usage::TICKET, &ticket.enc_part).is_ok()
            })
        })
}

/// A KDC's or a library's text, as it may enter an error or a finding: no control
/// characters, at most 200 octets.
fn clean(text: &str) -> String {
    tenko_core::dns::identity::clean_finding_text(text, 200)
}

fn not_found() -> ZoneError {
    ZoneError::new(
        codes::KRB_ACCOUNT_NOT_FOUND,
        404,
        "no Kerberos account is set up",
    )
}

fn invalid(field: &str, reason: &str) -> ZoneError {
    ZoneError::new(
        codes::KRB_ACCOUNT_INVALID,
        400,
        format!("{field}: {reason}"),
    )
    .param("field", field)
    .param("reason", reason)
}

fn vault_missing() -> ZoneError {
    ZoneError::new(
        "vault.unavailable",
        503,
        "the Kerberos account needs the vault, which this server does not run",
    )
}

fn stale() -> ZoneError {
    ZoneError::new(
        "sys.store.precondition_failed",
        409,
        "the Kerberos account changed meanwhile",
    )
}

// ---------------------------------------------------------------------------------------
// Requests and results

/// A pre-staged computer account to take over.
pub struct AdoptRequest {
    /// The realm.
    pub realm: Realm,
    /// The account name (`TENKO-DNS$`).
    pub name: String,
    /// The one-time password the administrator set; used once and dropped.
    pub password: Zeroizing<Vec<u8>>,
    /// The SPNs the account holds.
    pub spns: Vec<String>,
    /// The KDCs; empty: found.
    pub kdcs: Vec<String>,
    /// Days between rotations; `None`: 30.
    pub rotation_days: Option<u16>,
}

impl std::fmt::Debug for AdoptRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdoptRequest")
            .field("realm", &self.realm)
            .field("name", &self.name)
            .field("spns", &self.spns)
            .finish_non_exhaustive()
    }
}

/// A keytab to import.
pub struct ImportRequest {
    /// The realm.
    pub realm: Realm,
    /// The account name; `None`: the one principal of one component in the keytab.
    pub name: Option<String>,
    /// The keytab's octets; dropped after the import.
    pub keytab: Zeroizing<Vec<u8>>,
    /// The SPNs the account holds.
    pub spns: Vec<String>,
    /// The KDCs; empty: found.
    pub kdcs: Vec<String>,
}

impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRequest")
            .field("realm", &self.realm)
            .field("name", &self.name)
            .field("spns", &self.spns)
            .finish_non_exhaustive()
    }
}

/// What a self-test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// The account with the findings stored.
    pub account: KrbAccount,
    /// Whether no KDC answered (the route answers 503 after storing the finding).
    pub unreachable: bool,
}

/// What a rotation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotated {
    /// The password changed: the versions before and after.
    Changed {
        /// The version that is previous now.
        from: Option<u32>,
        /// The version that is current now.
        to: u32,
    },
    /// The change did not happen; the pending keys went and the old ones stay current.
    Undone,
    /// No KDC answered: the pending version stays until the next attempt.
    Unknown,
    /// Nothing was pending (a recovery with nothing to do).
    Nothing,
}

// ---------------------------------------------------------------------------------------
// The service

/// The Kerberos account service of a controller. Cheap to share as `Arc`.
pub struct KerberosService {
    store: Arc<dyn Store>,
    vault: Option<Arc<dyn Vault>>,
    kdc: Arc<dyn Kdc>,
    clock: Arc<dyn Clock>,
    passwords: Arc<dyn PasswordSource>,
    config: KerberosConfig,
    /// One change of the account at a time on this controller; the row's revision and the
    /// leader epoch order the controllers.
    lock: tokio::sync::Mutex<()>,
    /// Rotation failures in a row since the last success (memory: the finding persists).
    failures: std::sync::atomic::AtomicU32,
}

impl std::fmt::Debug for KerberosService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerberosService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The current row and its revision.
type Row = (KrbAccount, Revision);

impl KerberosService {
    /// A service over `store` and `vault` that talks to the KDCs through `kdc`.
    pub fn new(
        store: Arc<dyn Store>,
        vault: Option<Arc<dyn Vault>>,
        kdc: Arc<dyn Kdc>,
        clock: Arc<dyn Clock>,
        passwords: Arc<dyn PasswordSource>,
        config: KerberosConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            vault,
            kdc,
            clock,
            passwords,
            config,
            lock: tokio::sync::Mutex::new(()),
            failures: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// The service over the network with the system clock and random passwords.
    pub fn networked(
        store: Arc<dyn Store>,
        vault: Option<Arc<dyn Vault>>,
        config: KerberosConfig,
    ) -> Arc<Self> {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let kdc = Arc::new(NetKdc::new(Arc::clone(&store), Arc::clone(&clock)));
        Self::new(store, vault, kdc, clock, Arc::new(RandomPasswords), config)
    }

    /// The settings.
    pub fn config(&self) -> KerberosConfig {
        self.config
    }

    fn vault(&self) -> ZoneResult<&Arc<dyn Vault>> {
        self.vault.as_ref().ok_or_else(vault_missing)
    }

    fn now(&self) -> KrbTime {
        self.clock.now()
    }

    /// The account, if one is set up.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn account(view: &dyn ReadView) -> ZoneResult<Option<Row>> {
        Ok(view
            .scan_typed(&KRB_ACCOUNTS, KeyRange::all(), 1, false)?
            .into_iter()
            .next()
            .map(|(_, account, revision)| (account, revision)))
    }

    async fn row(&self) -> ZoneResult<Option<Row>> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        Self::account(view.as_ref())
    }

    /// The account now.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn status(&self) -> ZoneResult<Option<KrbAccount>> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(Self::account(view.as_ref())?.map(|(account, _)| account))
    }

    /// The keys of `account` from the vault.
    async fn keys(&self, account: &KrbAccount) -> ZoneResult<KeySet> {
        let Some(secret) = account.secret else {
            return Ok(KeySet::default());
        };
        let cx = RequestCtx::system(SystemComponent::Dns);
        let value = self.vault()?.get_system(&cx, secret).await?;
        KeySet::decode(value.expose()).map_err(|error| {
            ZoneError::new(
                sys::INTERNAL,
                500,
                format!("the keys of the Kerberos account do not read: {error}"),
            )
        })
    }

    /// Writes `account` with `keys` (the secret replaced, or created when the account has
    /// none yet), expecting the row at `expect`, fenced by `epoch` on the leader.
    async fn write(
        &self,
        cx: &RequestCtx,
        mut account: KrbAccount,
        keys: Option<&KeySet>,
        expect: Option<Revision>,
        epoch: Option<u64>,
        draft: Option<AuditDraft>,
    ) -> ZoneResult<(KrbAccount, Revision)> {
        let vault = Arc::clone(self.vault()?);
        let value = keys.map(|keys| SecretBytes::from(keys.encode()));
        for attempt in 1..=ATTEMPTS {
            let mut batch = WriteBatch::for_request(cx);
            batch.idempotency = None;
            if let Some(epoch) = epoch {
                batch.preconditions.push(tenko_store::fence(epoch));
            }
            if let Some(value) = &value {
                if let Some(secret) = account.secret {
                    vault.stage_replace(&mut batch, cx, secret, value).await?;
                } else {
                    let spec = SecretSpec::new(SecretPurpose::from_static(VAULT_PURPOSE))
                        .labeled(account.realm.as_str());
                    account.secret =
                        Some(vault.stage_put(&mut batch, cx, SecretClass::System, spec, value)?);
                }
            }
            account.validate()?;
            batch.expect_typed(&KRB_ACCOUNTS, &account.realm, expect);
            batch.put_typed(&KRB_ACCOUNTS, &account.realm, &account)?;
            if let Some(draft) = &draft {
                batch.audit(draft.clone());
            }
            match self.store.propose(batch).await {
                Ok(committed) => return Ok((account, committed.revision)),
                // A KEK rotation between staging and proposing: stage again. A row that
                // moved is the caller's to plan again.
                Err(StoreError::PreconditionFailed(_)) if attempt < ATTEMPTS => {
                    let view = self.store.read(ReadConsistency::Linearizable).await?;
                    let now = view
                        .get_typed(&KRB_ACCOUNTS, &account.realm)?
                        .map(|(_, revision)| revision);
                    if now != expect {
                        return Err(stale());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(stale())
    }

    // ----- adopt -------------------------------------------------------------------------

    /// Takes over a pre-staged computer account (identity plan section 3.1, ID-Q4): a
    /// ticket for `kadmin/changepw` with the one-time password, the keys of a new random
    /// password written as pending, the change, the key version read back, the keys made
    /// current, then the self-test.
    ///
    /// # Errors
    ///
    /// `dns.krb.account.invalid`, `dns.krb.account.exists`, `dns.krb.password.refused`
    /// (the one-time password or the change refused), `dns.krb.kdc.unreachable`, or a
    /// store or vault error.
    pub async fn adopt(&self, cx: &RequestCtx, request: AdoptRequest) -> ZoneResult<CheckOutcome> {
        let _guard = self.lock.lock().await;
        let mut account = self.adopt_account(&request)?;
        let principal = account
            .principal()
            .map_err(|_| invalid("name", "not a principal name"))?;
        if self.row().await?.is_some() {
            return Err(exists(&account.realm));
        }
        let target = KdcTarget::of(&account);
        // The one-time password gives a change-password ticket; the KDC names the salt.
        let changepw = client::changepw_principal(&principal)
            .map_err(|error| password_refused(&account.realm, &error))?;
        let otp = Secret::Password(Zeroizing::new(request.password.to_vec()));
        let ticket = match self
            .kdc
            .as_exchange(&target, &principal, &changepw, otp.clone())
            .await
        {
            Ok(ticket) => ticket,
            Err(error) if is_unreachable(&error) => {
                return Err(kdc_unreachable(&account.realm, &error));
            }
            Err(error) => return Err(password_refused(&account.realm, &error)),
        };
        let salt = ticket
            .salt
            .clone()
            .unwrap_or_else(|| cipher::salt::account(&account));
        let password = self.passwords.generate();
        let provisional = ticket.key_kvno.map_or(1, |kvno| kvno.wrapping_add(1));
        let pending = KeySet::from_password(
            &principal,
            provisional,
            KeyVersionState::Pending,
            &password,
            &salt,
            ticket.iterations,
            &client::ETYPES,
        )
        .map_err(|error| ZoneError::new(sys::INTERNAL, 500, error.to_string()))?;
        drop(ticket);
        // The pending keys are stored before the change (R123).
        account.versions = vec![meta(provisional, KeyVersionState::Pending, cx.now)];
        let (account, revision) = self
            .write(cx, account, Some(&pending), None, None, None)
            .await?;
        let changed = self
            .kdc
            .change_password(&target, &principal, otp, &password)
            .await;
        drop(password);
        match changed {
            Ok(()) => {
                // The KDC confirmed the change: the pending keys are never dropped from here.
                let (rotated, account) = self
                    .finish_pending(cx, (account, revision), None, true)
                    .await?;
                match rotated {
                    Rotated::Changed { .. } => self.self_test(cx, account, None).await,
                    _ => Err(change_unconfirmed(&request.realm)),
                }
            }
            Err(error) if not_changed(&error) => {
                // A refusal that proves the password stayed the one-time one, or a failure
                // before the request left: nothing is Tenko's.
                let failure = refused_or_unreachable(&request.realm, inner(&error));
                let draft =
                    AuditDraft::failed(audit::KRB_ACCOUNT_ADOPT, Vec::<ObjectRef>::new(), &failure)
                        .with_source_ip(cx.source_ip)
                        .with_context("realm", request.realm.as_str())
                        .with_context("name", request.name.as_str());
                self.remove(cx, revision, None, draft).await?;
                Err(failure)
            }
            Err(error) => {
                // The request left and no answer proves what the KDC did: ask it.
                match self
                    .finish_pending(cx, (account, revision), None, false)
                    .await?
                {
                    (Rotated::Changed { .. }, account) => self.self_test(cx, account, None).await,
                    _ => Err(change_unknown(&request.realm, &error)),
                }
            }
        }
    }

    /// The row an adopt starts from, checked: a computer account, a one-time password, the
    /// rotation interval the profile allows.
    fn adopt_account(&self, request: &AdoptRequest) -> ZoneResult<KrbAccount> {
        let rotation_days = request
            .rotation_days
            .unwrap_or(tenko_core::dns::identity::DEFAULT_ROTATION_DAYS);
        self.check_rotation_days(rotation_days)?;
        let account = KrbAccount {
            realm: request.realm.clone(),
            name: request.name.trim().to_owned(),
            spns: trimmed(&request.spns),
            kdcs: trimmed(&request.kdcs),
            owned: true,
            rotation_days,
            versions: Vec::new(),
            last_rotation: None,
            last_check: None,
            secret: None,
            findings: Vec::new(),
        };
        account.validate()?;
        if !account.name.ends_with('$') {
            return Err(invalid(
                "name",
                "the adopt takes over a computer account, whose name ends in `$`; import a keytab for a user account",
            ));
        }
        if request.password.is_empty() {
            return Err(invalid("password", "the one-time password is empty"));
        }
        Ok(account)
    }

    fn check_rotation_days(&self, days: u16) -> ZoneResult<()> {
        if days == 0 && !self.config.rotation_off_allowed {
            return Err(invalid(
                "rotation_days",
                "rotation can be turned off under the Lab profile only (TGL-32)",
            ));
        }
        if days > tenko_core::dns::identity::MAX_ROTATION_DAYS {
            return Err(invalid("rotation_days", "at most 365 days"));
        }
        Ok(())
    }

    // ----- import ------------------------------------------------------------------------

    /// Imports a keytab (identity plan section 3.1): the AES entries of the realm are kept,
    /// the highest key version current and the others previous; RC4, DES and 3DES entries
    /// are refused and counted; the file is not kept. Then the self-test.
    ///
    /// # Errors
    ///
    /// `dns.krb.keytab.invalid`, `dns.krb.account.invalid`, `dns.krb.account.exists`, or a
    /// store or vault error.
    pub async fn import(
        &self,
        cx: &RequestCtx,
        request: ImportRequest,
    ) -> ZoneResult<CheckOutcome> {
        let _guard = self.lock.lock().await;
        let parsed =
            keytab::parse(&request.keytab).map_err(|error| keytab_invalid(&error.to_string()))?;
        drop(request.keytab);
        let realm = request.realm.clone();
        let in_realm = |principal: &PrincipalName| principal.realm() == &realm;
        let refused = parsed.refused.len();
        let principals: Vec<PrincipalName> = parsed
            .principals()
            .into_iter()
            .filter(|p| in_realm(p))
            .cloned()
            .collect();
        if principals.is_empty() {
            return Err(keytab_invalid(&if refused > 0 {
                format!(
                    "the keytab holds no AES entry for {realm}: {refused} RC4, DES or 3DES entries are refused; export the keys with /crypto AES256-SHA1"
                )
            } else {
                format!("the keytab holds no entry for {realm}")
            }));
        }
        let given = request
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty());
        let name = if let Some(name) = given {
            name.to_owned()
        } else {
            {
                let single: Vec<&PrincipalName> = principals
                    .iter()
                    .filter(|p| p.components().len() == 1)
                    .collect();
                match single.as_slice() {
                    [one] => one.components()[0].clone(),
                    _ => {
                        return Err(invalid(
                            "name",
                            "the keytab names no single account: give the account name",
                        ));
                    }
                }
            }
        };
        // Only the account's own entries and its SPNs' are kept: a keytab may hold keys of
        // other principals, which Tenko has no use for.
        let spns = trimmed(&request.spns);
        let own = PrincipalName::new(vec![name.clone()], realm.clone()).ok();
        let wanted = |principal: &PrincipalName| {
            own.as_ref() == Some(principal)
                || spns.iter().any(|spn| {
                    spn_principal(spn, &realm).is_some_and(|p| same_principal(&p, principal))
                })
        };
        let keys = parsed
            .key_set(|entry| wanted(&entry.principal), KeyVersionState::Previous)
            .map_err(|error| keytab_invalid(&error.to_string()))?;
        drop(parsed);
        if keys.is_empty() {
            return Err(keytab_invalid(&format!(
                "the keytab holds no AES entry for {name}@{realm} or its SPNs"
            )));
        }
        let newest = keys.kvnos().last().copied().unwrap_or(0);
        let keys = keys.with_state(newest, KeyVersionState::Current);
        let versions = versions_of(&keys, cx.now);
        let account = KrbAccount {
            realm: realm.clone(),
            name,
            spns,
            kdcs: trimmed(&request.kdcs),
            owned: false,
            rotation_days: 0,
            versions,
            last_rotation: None,
            last_check: None,
            secret: None,
            findings: Vec::new(),
        };
        account.validate()?;
        if self.row().await?.is_some() {
            return Err(exists(&realm));
        }
        let draft = AuditDraft::success(audit::KRB_ACCOUNT_IMPORT, Vec::<ObjectRef>::new())
            .with_source_ip(cx.source_ip)
            .with_context("realm", realm.as_str())
            .with_context("name", account.name.as_str())
            .with_context("kvnos", kvno_list(&keys.kvnos()))
            .with_context("refused", refused.to_string());
        let (account, _) = self
            .write(cx, account, Some(&keys), None, None, Some(draft))
            .await?;
        self.self_test(cx, account, None).await
    }

    // ----- rotation and recovery ---------------------------------------------------------

    /// Changes the password of the owned account now (identity plan section 3.1, ID-Q5):
    /// a ticket with the current keys gives the salt, the keys of a new password are
    /// written as pending, the change is sent, the version is read back, the keys move.
    /// A pending version left from before is finished first, and nothing more is done.
    ///
    /// # Errors
    ///
    /// `dns.krb.account.not_found`, `dns.krb.account.not_owned`,
    /// `dns.krb.password.refused`, `dns.krb.kdc.unreachable`, or a store or vault error.
    pub async fn rotate(&self, cx: &RequestCtx, epoch: Option<u64>) -> ZoneResult<Rotated> {
        self.rotate_from(cx, epoch, None).await
    }

    /// [`KerberosService::rotate`], only while the current version is still `expected`
    /// (the version the rotation job saw when it was asked for): a step run again after
    /// its rotation committed, here or on another controller, rotates nothing.
    ///
    /// # Errors
    ///
    /// As [`KerberosService::rotate`].
    pub async fn rotate_from(
        &self,
        cx: &RequestCtx,
        epoch: Option<u64>,
        expected: Option<Option<u32>>,
    ) -> ZoneResult<Rotated> {
        let _guard = self.lock.lock().await;
        let (account, revision) = self.row().await?.ok_or_else(not_found)?;
        if !account.owned {
            return Err(not_owned(&account.realm));
        }
        if has_pending(&account) {
            return Ok(self
                .finish_pending(cx, (account, revision), epoch, false)
                .await?
                .0);
        }
        if let Some(expected) = expected
            && account.current().map(|v| v.kvno) != expected
        {
            return Ok(Rotated::Nothing);
        }
        let result = self
            .rotate_owned(cx, account.clone(), revision, epoch)
            .await;
        match &result {
            Ok(Rotated::Changed { .. }) => {
                self.failures.store(0, std::sync::atomic::Ordering::Relaxed);
            }
            Err(error) if !error.is(codes::KRB_ACCOUNT_NOT_FOUND) => {
                self.audit_only(
                    cx,
                    AuditDraft::failed(audit::KRB_ACCOUNT_ROTATE, Vec::<ObjectRef>::new(), error)
                        .with_context("realm", account.realm.as_str())
                        .with_context("name", account.name.as_str()),
                )
                .await;
                let failures = self
                    .failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if failures >= self.config.rotation_failures_before_finding {
                    self.raise_rotation_failure(cx, error, failures, epoch)
                        .await;
                }
            }
            _ => {}
        }
        result
    }

    async fn rotate_owned(
        &self,
        cx: &RequestCtx,
        account: KrbAccount,
        revision: Revision,
        epoch: Option<u64>,
    ) -> ZoneResult<Rotated> {
        let keys = self.keys(&account).await?;
        let current = keys.in_state(KeyVersionState::Current);
        let principal = account
            .principal()
            .map_err(|_| invalid("name", "not a principal name"))?;
        let target = KdcTarget::of(&account);
        let tgt = self
            .kdc
            .as_exchange(
                &target,
                &principal,
                &krbtgt(&account.realm)?,
                Secret::Keys(current.clone()),
            )
            .await
            .map_err(|error| refused_or_unreachable(&account.realm, &error))?;
        let salt = tgt
            .salt
            .clone()
            .unwrap_or_else(|| cipher::salt::account(&account));
        let held_current = account.current().map(|v| v.kvno);
        let provisional = tgt
            .key_kvno
            .or(held_current)
            .map_or(1, |kvno| kvno.wrapping_add(1));
        let password = self.passwords.generate();
        let new_keys = KeySet::from_password(
            &principal,
            provisional,
            KeyVersionState::Pending,
            &password,
            &salt,
            tgt.iterations,
            &client::ETYPES,
        )
        .map_err(|error| ZoneError::new(sys::INTERNAL, 500, error.to_string()))?;
        drop(tgt);
        // Pending first (R123).
        let mut stored = keys.clone();
        for entry in new_keys.entries() {
            stored
                .insert(entry.clone())
                .map_err(|error| ZoneError::new(sys::INTERNAL, 500, error.to_string()))?;
        }
        let mut pending_account = account.clone();
        pending_account
            .versions
            .push(meta(provisional, KeyVersionState::Pending, cx.now));
        let (pending_account, revision) = self
            .write(
                cx,
                pending_account,
                Some(&stored),
                Some(revision),
                epoch,
                None,
            )
            .await?;
        let changed = self
            .kdc
            .change_password(&target, &principal, Secret::Keys(current), &password)
            .await;
        drop(password);
        match changed {
            Ok(()) => {
                // The KDC confirmed the change: the pending keys are never dropped from here.
                let (rotated, _) = self
                    .finish_pending(cx, (pending_account, revision), epoch, true)
                    .await?;
                match rotated {
                    Rotated::Changed { .. } => Ok(rotated),
                    // Another controller finished the version meanwhile.
                    Rotated::Nothing => self.committed_elsewhere(&new_keys, held_current).await,
                    _ => Err(change_unconfirmed(&account.realm)),
                }
            }
            Err(error) if not_changed(&error) => {
                // A refusal that proves the password did not change, or a failure before
                // the request left.
                self.drop_pending(cx, (pending_account, revision), epoch)
                    .await?;
                Err(refused_or_unreachable(&account.realm, inner(&error)))
            }
            Err(error) => {
                // The request left and no answer proves what the KDC did: ask it.
                match self
                    .finish_pending(cx, (pending_account, revision), epoch, false)
                    .await?
                {
                    (rotated @ Rotated::Changed { .. }, _) => Ok(rotated),
                    _ => Err(change_unknown(&account.realm, &error)),
                }
            }
        }
    }

    /// After a confirmed change whose pending version is gone: the current keys must be the
    /// new ones (another controller committed them); anything else is reported loudly.
    async fn committed_elsewhere(
        &self,
        new_keys: &KeySet,
        from: Option<u32>,
    ) -> ZoneResult<Rotated> {
        let (account, _) = self.row().await?.ok_or_else(not_found)?;
        let keys = self.keys(&account).await?;
        let ours = new_keys.entries().first().map(|e| &e.key);
        if let Some(entry) = keys
            .in_state(KeyVersionState::Current)
            .entries()
            .iter()
            .find(|e| Some(&e.key) == ours)
        {
            return Ok(Rotated::Changed {
                from,
                to: entry.kvno,
            });
        }
        tracing::error!(
            realm = %account.realm,
            "the KDC confirmed a password change whose keys Tenko no longer holds"
        );
        Err(ZoneError::new(
            sys::INTERNAL,
            500,
            "the KDC confirmed the password change, but its keys are no longer held: adopt the account again with a new one-time password",
        ))
    }

    /// Finishes or undoes a change that a restart, a lost answer or a failed commit left
    /// pending (identity plan section 3.1, R123).
    ///
    /// # Errors
    ///
    /// `dns.krb.account.not_found`, or a store or vault error.
    pub async fn recover(&self, cx: &RequestCtx, epoch: Option<u64>) -> ZoneResult<Rotated> {
        let _guard = self.lock.lock().await;
        let row = self.row().await?.ok_or_else(not_found)?;
        if !has_pending(&row.0) {
            return Ok(Rotated::Nothing);
        }
        Ok(self.finish_pending(cx, row, epoch, false).await?.0)
    }

    /// Asks the KDC whether it takes the pending keys and moves the versions by the
    /// answer; holds the lock of the caller. The pending keys are committed when the KDC
    /// issues a ticket for them, and dropped only on proof that the change did not happen:
    /// the change was not confirmed, the pending version is older than [`PENDING_GRACE`]
    /// (no request of any controller can still be in flight, and the controllers have
    /// replicated), the KDC refuses the pending keys and takes the current ones. In every
    /// other case nothing moves, and the next recovery asks again.
    async fn finish_pending(
        &self,
        cx: &RequestCtx,
        (account, revision): Row,
        epoch: Option<u64>,
        confirmed: bool,
    ) -> ZoneResult<(Rotated, KrbAccount)> {
        let keys = self.keys(&account).await?;
        let pending = keys.in_state(KeyVersionState::Pending);
        let Some(&provisional) = pending.kvnos().first() else {
            return Ok((Rotated::Nothing, account));
        };
        let principal = account
            .principal()
            .map_err(|_| invalid("name", "not a principal name"))?;
        let target = KdcTarget::of(&account);
        let young = account
            .versions
            .iter()
            .find(|v| v.state == KeyVersionState::Pending)
            .is_none_or(|v| timestamp(self.now()).saturating_since(v.created) < PENDING_GRACE);
        let tgt = match self
            .kdc
            .as_exchange(
                &target,
                &principal,
                &krbtgt(&account.realm)?,
                Secret::Keys(pending.clone()),
            )
            .await
        {
            Ok(tgt) => tgt,
            Err(ClientError::Kdc { code, .. })
                if code == error_code::PREAUTH_FAILED && !confirmed && !young =>
            {
                return self
                    .undo_with_proof(cx, (account, revision), epoch, &keys)
                    .await;
            }
            // No KDC answered, the change is young or confirmed (a controller that has not
            // replicated it yet may refuse the new keys), or the account itself is refused
            // (the self-test reports it): nothing moves.
            Err(_) => return Ok((Rotated::Unknown, account)),
        };
        // The version: the AS-REP's, which belongs to the pending key that decrypted it; a
        // service ticket's only when the KDC named none there and the ticket is under a
        // pending key (a ticket of a controller that has not replicated the change is under
        // the old key).
        let mut kvno = tgt.key_kvno;
        if kvno.is_none()
            && let Some(spn) = account
                .spns
                .first()
                .and_then(|spn| spn_principal(spn, &account.realm))
            && let Ok(ticket) = self.kdc.tgs_exchange(&target, &tgt.credentials, &spn).await
            && ticket_under(&pending, &ticket.ticket)
        {
            kvno = ticket.ticket.enc_part.kvno;
        }
        let kvno = kvno.unwrap_or(provisional);
        let from = account.current().map(|v| v.kvno);
        if from.is_some_and(|from| kvno <= from)
            || keys
                .entries()
                .iter()
                .any(|e| e.kvno == kvno && e.state != KeyVersionState::Pending)
        {
            let finding = KrbFinding::new(
                findings::GSS_SELF_TEST_FAILED,
                &format!(
                    "the KDC takes the new password but names key version {kvno}, which is not newer than the versions Tenko holds ({}); the change is kept pending",
                    kvno_list(&keys.kvnos())
                ),
                timestamp(self.now()),
            )
            .param("reason", "kvno_not_newer")
            .param("kvno", kvno);
            let account = self
                .add_finding(cx, (account, revision), epoch, finding)
                .await?;
            return Ok((Rotated::Unknown, account));
        }
        let moved = moved_keys(&account, &keys, provisional, kvno, timestamp(self.now()))?;
        let next = self
            .commit_pending(cx, (account, revision), epoch, &moved, kvno)
            .await?;
        Ok((Rotated::Changed { from, to: kvno }, next))
    }

    /// Writes the moved keys and the versions of a committed change, audited as the adopt
    /// or the rotation it finishes.
    async fn commit_pending(
        &self,
        cx: &RequestCtx,
        (account, revision): Row,
        epoch: Option<u64>,
        moved: &KeySet,
        kvno: u32,
    ) -> ZoneResult<KrbAccount> {
        let from = account.current().map(|v| v.kvno);
        let mut next = account.clone();
        next.versions = versions_of(moved, cx.now)
            .into_iter()
            .map(|mut version| {
                // Keep the creation time of a version that stays.
                if let Some(old) = account.versions.iter().find(|v| v.kvno == version.kvno)
                    && version.kvno != kvno
                {
                    version.created = old.created;
                }
                version
            })
            .collect();
        next.last_rotation = Some(cx.now);
        let action = if from.is_some() {
            audit::KRB_ACCOUNT_ROTATE
        } else {
            audit::KRB_ACCOUNT_ADOPT
        };
        let mut draft = AuditDraft::success(action, Vec::<ObjectRef>::new())
            .with_source_ip(cx.source_ip)
            .with_context("realm", account.realm.as_str())
            .with_context("name", account.name.as_str())
            .with_context("kvno", kvno.to_string());
        if let Some(from) = from {
            draft = draft.with_context("from_kvno", from.to_string());
        }
        // A rotation clears its own failure finding, and the pending state's.
        next.findings.retain(|f| {
            f.code != findings::GSS_ROTATION_FAILED
                && !f
                    .params
                    .get("reason")
                    .is_some_and(|r| r == "kvno_not_newer" || r == "adopt_incomplete")
        });
        Ok(self
            .write(cx, next, Some(moved), Some(revision), epoch, Some(draft))
            .await?
            .0)
    }

    /// The pending keys are refused after the grace: drop them when the KDC takes the
    /// current keys (the proof that the change did not happen). An adopt has no current
    /// keys to prove it with: the pending version stays, with a finding that says what to
    /// do. When the KDC refuses both, nothing moves: the self-test reports it.
    async fn undo_with_proof(
        &self,
        cx: &RequestCtx,
        (account, revision): Row,
        epoch: Option<u64>,
        keys: &KeySet,
    ) -> ZoneResult<(Rotated, KrbAccount)> {
        let current = keys.in_state(KeyVersionState::Current);
        if current.is_empty() {
            let finding = KrbFinding::new(
                findings::GSS_SELF_TEST_FAILED,
                "the adopt did not complete: the KDC does not take the new password; remove the account from Tenko, set a new one-time password and adopt again",
                timestamp(self.now()),
            )
            .param("reason", "adopt_incomplete");
            let account = self
                .add_finding(cx, (account, revision), epoch, finding)
                .await?;
            return Ok((Rotated::Unknown, account));
        }
        let principal = account
            .principal()
            .map_err(|_| invalid("name", "not a principal name"))?;
        let proof = self
            .kdc
            .as_exchange(
                &KdcTarget::of(&account),
                &principal,
                &krbtgt(&account.realm)?,
                Secret::Keys(current),
            )
            .await;
        if proof.is_ok() {
            let account = self.drop_pending(cx, (account, revision), epoch).await?;
            return Ok((Rotated::Undone, account));
        }
        Ok((Rotated::Unknown, account))
    }

    /// Adds `finding` to the row unless one of its code and reason is there.
    async fn add_finding(
        &self,
        cx: &RequestCtx,
        (mut account, revision): Row,
        epoch: Option<u64>,
        finding: KrbFinding,
    ) -> ZoneResult<KrbAccount> {
        let same = |f: &KrbFinding| {
            f.code == finding.code && f.params.get("reason") == finding.params.get("reason")
        };
        if account.findings.iter().any(same) {
            return Ok(account);
        }
        account.findings.push(finding);
        account
            .findings
            .truncate(tenko_core::dns::identity::MAX_KRB_FINDINGS);
        Ok(self
            .write(cx, account, None, Some(revision), epoch, None)
            .await?
            .0)
    }

    /// Drops the pending version: the change did not happen (a definite refusal, or the
    /// proof of [`KerberosService::undo_with_proof`]). Audited.
    async fn drop_pending(
        &self,
        cx: &RequestCtx,
        (account, revision): Row,
        epoch: Option<u64>,
    ) -> ZoneResult<KrbAccount> {
        let keys = self
            .keys(&account)
            .await?
            .without_state(KeyVersionState::Pending);
        let dropped: Vec<u32> = account
            .versions
            .iter()
            .filter(|v| v.state == KeyVersionState::Pending)
            .map(|v| v.kvno)
            .collect();
        let mut next = account;
        next.versions
            .retain(|v| v.state != KeyVersionState::Pending);
        let undone = ZoneError::new(
            codes::KRB_PASSWORD_REFUSED,
            422,
            "the password change did not happen; the pending keys are dropped",
        );
        let draft = AuditDraft::failed(audit::KRB_ACCOUNT_ROTATE, Vec::<ObjectRef>::new(), &undone)
            .with_source_ip(cx.source_ip)
            .with_context("realm", next.realm.as_str())
            .with_context("name", next.name.as_str())
            .with_context("outcome", "undone")
            .with_context("kvno", kvno_list(&dropped));
        Ok(self
            .write(cx, next, Some(&keys), Some(revision), epoch, Some(draft))
            .await?
            .0)
    }

    /// Writes an audit record alone, best effort (a failure that changed no row).
    async fn audit_only(&self, cx: &RequestCtx, draft: AuditDraft) {
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(draft.with_source_ip(cx.source_ip));
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "an audit record of the Kerberos account could not be written");
        }
    }

    async fn raise_rotation_failure(
        &self,
        cx: &RequestCtx,
        error: &ZoneError,
        failures: u32,
        epoch: Option<u64>,
    ) {
        let attempt = async {
            let (mut account, revision) = self.row().await?.ok_or_else(not_found)?;
            account
                .findings
                .retain(|f| f.code != findings::GSS_ROTATION_FAILED);
            account.findings.push(
                KrbFinding::new(
                    findings::GSS_ROTATION_FAILED,
                    &format!(
                        "the rotation of the password failed: {}",
                        error.coded().detail
                    ),
                    cx.now,
                )
                .param("reason", error.coded().code.as_ref())
                .param("failures", failures),
            );
            account
                .findings
                .truncate(tenko_core::dns::identity::MAX_KRB_FINDINGS);
            self.write(cx, account, None, Some(revision), epoch, None)
                .await
        };
        if let Err(error) = attempt.await {
            tracing::warn!(%error, "the rotation failure could not be recorded");
        }
    }

    // ----- delete ------------------------------------------------------------------------

    /// Removes the account and its keys from Tenko. The account in the directory is the
    /// administrator's to delete.
    ///
    /// # Errors
    ///
    /// `dns.krb.account.not_found`, or a store error.
    pub async fn delete(&self, cx: &RequestCtx) -> ZoneResult<()> {
        let _guard = self.lock.lock().await;
        let (account, revision) = self.row().await?.ok_or_else(not_found)?;
        let draft = AuditDraft::success(audit::KRB_ACCOUNT_DELETE, Vec::<ObjectRef>::new())
            .with_source_ip(cx.source_ip)
            .with_context("realm", account.realm.as_str())
            .with_context("name", account.name.as_str());
        self.remove_row(cx, &account, revision, None, Some(draft))
            .await
    }

    async fn remove(
        &self,
        cx: &RequestCtx,
        revision: Revision,
        epoch: Option<u64>,
        draft: AuditDraft,
    ) -> ZoneResult<()> {
        let (account, now) = self.row().await?.ok_or_else(not_found)?;
        if now != revision {
            return Err(stale());
        }
        self.remove_row(cx, &account, revision, epoch, Some(draft))
            .await
    }

    async fn remove_row(
        &self,
        cx: &RequestCtx,
        account: &KrbAccount,
        revision: Revision,
        epoch: Option<u64>,
        draft: Option<AuditDraft>,
    ) -> ZoneResult<()> {
        let mut batch = WriteBatch::for_request(cx);
        if let Some(epoch) = epoch {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        batch.expect_typed(&KRB_ACCOUNTS, &account.realm, Some(revision));
        batch.delete_typed(&KRB_ACCOUNTS, &account.realm);
        if let (Some(secret), Some(vault)) = (account.secret, &self.vault) {
            vault.stage_delete(&mut batch, cx, secret);
        }
        if let Some(draft) = draft {
            batch.audit(draft);
        }
        self.store.propose(batch).await?;
        Ok(())
    }

    // ----- the self-test -----------------------------------------------------------------

    /// Runs the self-test now and stores its findings (identity plan sections 3.1 and
    /// 3.10). A change left pending is finished first.
    ///
    /// # Errors
    ///
    /// `dns.krb.account.not_found`, or a store or vault error. A KDC that does not answer
    /// is a finding, not an error ([`CheckOutcome::unreachable`]).
    pub async fn check(&self, cx: &RequestCtx, epoch: Option<u64>) -> ZoneResult<CheckOutcome> {
        let _guard = self.lock.lock().await;
        let row = self.row().await?.ok_or_else(not_found)?;
        if has_pending(&row.0)
            && let Err(error) = self.finish_pending(cx, row, epoch, false).await
        {
            // The self-test still runs and reports what the KDC says.
            tracing::warn!(%error, "a pending change of the Kerberos account could not be finished");
        }
        let (account, _) = self.row().await?.ok_or_else(not_found)?;
        self.self_test(cx, account, epoch).await
    }

    /// The self-test of `account`; holds the caller's lock.
    async fn self_test(
        &self,
        cx: &RequestCtx,
        account: KrbAccount,
        epoch: Option<u64>,
    ) -> ZoneResult<CheckOutcome> {
        let keys = self.keys(&account).await?;
        let (found, unreachable) = self.findings(&account, &keys).await;
        // Store the findings on the row as it is now.
        let (mut next, revision) = self.row().await?.ok_or_else(not_found)?;
        let before: Vec<(String, BTreeMap<String, String>)> = next
            .findings
            .iter()
            .filter(|f| f.code != findings::GSS_ROTATION_FAILED)
            .map(|f| (f.code.clone(), f.params.clone()))
            .collect();
        let after: Vec<(String, BTreeMap<String, String>)> = found
            .iter()
            .map(|f| (f.code.clone(), f.params.clone()))
            .collect();
        let kept: Vec<KrbFinding> = next
            .findings
            .iter()
            .filter(|f| f.code == findings::GSS_ROTATION_FAILED)
            .cloned()
            .collect();
        next.findings = kept.into_iter().chain(found).collect();
        next.findings
            .truncate(tenko_core::dns::identity::MAX_KRB_FINDINGS);
        next.last_check = Some(cx.now);
        // Audited on a failure or a change only (section 3.11).
        let draft = (!after.is_empty() || before != after).then(|| {
            let codes: Vec<&str> = after.iter().map(|(code, _)| code.as_str()).collect();
            let draft = if after.is_empty() {
                AuditDraft::success(audit::KRB_ACCOUNT_CHECK, Vec::<ObjectRef>::new())
            } else {
                AuditDraft::success(audit::KRB_ACCOUNT_CHECK, Vec::<ObjectRef>::new())
                    .with_context("outcome", "findings")
            };
            draft
                .with_source_ip(cx.source_ip)
                .with_context("realm", account.realm.as_str())
                .with_context("findings", codes.join(","))
        });
        let (account, _) = self
            .write(cx, next, None, Some(revision), epoch, draft)
            .await?;
        Ok(CheckOutcome {
            account,
            unreachable,
        })
    }

    /// The checks of the self-test: the findings and whether no KDC answered.
    async fn findings(&self, account: &KrbAccount, keys: &KeySet) -> (Vec<KrbFinding>, bool) {
        let now = self.now();
        let at = timestamp(now);
        let mut out = Vec::new();
        let held = kvno_list(&keys.kvnos());
        if keys.is_empty() {
            out.push(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    "Tenko holds no key for the account",
                    at,
                )
                .param("reason", "no_keys"),
            );
            return (out, false);
        }
        let Ok(krbtgt) = krbtgt(&account.realm) else {
            out.push(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    "the realm is not a realm",
                    at,
                )
                .param("reason", "realm"),
            );
            return (out, false);
        };
        let Some(client) = as_client(account, keys) else {
            out.push(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    "Tenko holds no key of the account or of its SPNs to authenticate with",
                    at,
                )
                .param("reason", "no_keys"),
            );
            return (out, false);
        };
        let target = KdcTarget::of(account);
        // 1. An AS exchange as the account: the keys are right, the account is enabled.
        let tgt = match self
            .kdc
            .as_exchange(&target, &client, &krbtgt, Secret::Keys(keys.clone()))
            .await
        {
            Ok(tgt) => tgt,
            Err(ClientError::Kdc { code, .. })
                if code == error_code::PREAUTH_FAILED
                    && !keys.in_state(KeyVersionState::Pending).is_empty() =>
            {
                out.push(
                    KrbFinding::new(
                        findings::GSS_SELF_TEST_FAILED,
                        "a password change is pending and the KDC does not take the current keys yet; the recovery finishes the change",
                        at,
                    )
                    .param("reason", "change_pending")
                    .param("kdc_error", code),
                );
                return (out, false);
            }
            Err(error) => {
                let unreachable = is_unreachable(&error);
                out.push(as_failure(&error, at, &held));
                return (out, unreachable);
            }
        };
        // 2. The clock against the KDC's (OPS-09).
        let skew = tgt.kdc_time.secs.saturating_sub(now.secs);
        if skew.abs() > MAX_SKEW_SECS {
            out.push(
                KrbFinding::new(
                    findings::GSS_CLOCK_SKEW,
                    &format!(
                        "the node's clock is {} s {} the KDC's; Kerberos refuses more than 300 s",
                        skew.abs(),
                        if skew > 0 { "behind" } else { "ahead of" }
                    ),
                    at,
                )
                .param("skew_secs", skew),
            );
        }
        // 3. The version of the account's own key.
        let own_kvno = tgt.key_kvno;
        if let Some(kvno) = own_kvno
            && !keys.kvnos().contains(&kvno)
        {
            out.push(kvno_unknown(None, kvno, &held, at));
        }
        // 4. Every SPN: a ticket from the KDC, accepted by an acceptor with the keys held.
        for spn in &account.spns {
            if let Some(finding) = self
                .spn_finding(account, keys, &target, &tgt, spn, (now, at), &held)
                .await
            {
                out.push(finding);
            }
        }
        (out, false)
    }

    /// The checks of one SPN: a ticket from the KDC of an AES type and a held version, and
    /// accepted by an acceptor with the keys held.
    #[allow(clippy::too_many_arguments)]
    async fn spn_finding(
        &self,
        account: &KrbAccount,
        keys: &KeySet,
        target: &KdcTarget,
        tgt: &AsResult,
        spn: &str,
        (now, at): (KrbTime, Timestamp),
        held: &str,
    ) -> Option<KrbFinding> {
        let service = spn_principal(spn, &account.realm)?;
        let ticket = match self
            .kdc
            .tgs_exchange(target, &tgt.credentials, &service)
            .await
        {
            Ok(ticket) => ticket,
            Err(error) => return Some(tgs_failure(spn, &error, at)),
        };
        let etype = ticket.ticket.enc_part.etype;
        if EncryptionType::from_number(etype).is_none() {
            return Some(weak_etype(Some(spn), Some(etype), at));
        }
        if let Some(kvno) = ticket.ticket.enc_part.kvno
            && !keys.kvnos().contains(&kvno)
        {
            // The account's own key is held under another version: the ticket for the
            // SPN is under another account's key.
            let own = tgt.key_kvno;
            return Some(
                if own.is_some_and(|own| own != kvno && keys.kvnos().contains(&own)) {
                    spn_duplicate(
                        spn,
                        at,
                        "the ticket for the SPN is under a key of another account",
                    )
                } else {
                    kvno_unknown(Some(spn), kvno, held, at)
                },
            );
        }
        self.accept(account, keys, spn, &ticket, now, at)
    }

    /// Hands a service ticket to an acceptor with the keys held, as a client would.
    fn accept(
        &self,
        account: &KrbAccount,
        keys: &KeySet,
        spn: &str,
        ticket: &Credentials,
        now: KrbTime,
        at: Timestamp,
    ) -> Option<KrbFinding> {
        let config = AcceptorConfig::new(account.realm.clone(), &[spn]);
        let service = Service::new(config, keys.clone(), Arc::clone(&self.clock));
        // The acceptor refuses authenticators from the second it started in: the token is
        // made a second later (well within the skew).
        let when = KrbTime {
            secs: now.secs + 1,
            usec: now.usec,
        };
        let token = match client::initiator_token(ticket, oid::KRB5, when, 1) {
            Ok((token, _)) => token,
            Err(error) => {
                return Some(
                    KrbFinding::new(
                        findings::GSS_SELF_TEST_FAILED,
                        &format!("the self-test could not build its token: {error}"),
                        at,
                    )
                    .param("spn", spn)
                    .param("reason", "token"),
                );
            }
        };
        match service.negotiation().step(&token) {
            Ok(Step::Established { .. }) => None,
            Ok(Step::Continue(_)) => Some(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    "the acceptor asked for another token",
                    at,
                )
                .param("spn", spn)
                .param("reason", "continue"),
            ),
            Err(AcceptError::Key(SelectError::KvnoUnknown(kvno))) => {
                Some(kvno_unknown(Some(spn), kvno, &kvno_list(&keys.kvnos()), at))
            }
            Err(AcceptError::Key(SelectError::UnsupportedEnctype(etype))) => {
                Some(weak_etype(Some(spn), Some(etype), at))
            }
            Err(AcceptError::TicketKey) => Some(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    &format!(
                        "the ticket for {spn} names a key version Tenko holds but does not decrypt with its key: the SPN may be on another account, or the keys were derived with another salt"
                    ),
                    at,
                )
                .param("spn", spn)
                .param("reason", "ticket_key"),
            ),
            Err(AcceptError::Skew(skew)) => Some(
                KrbFinding::new(
                    findings::GSS_CLOCK_SKEW,
                    &format!("the acceptor saw a clock skew of {skew} s"),
                    at,
                )
                .param("spn", spn)
                .param("skew_secs", skew),
            ),
            Err(error) => Some(
                KrbFinding::new(
                    findings::GSS_SELF_TEST_FAILED,
                    &format!("the acceptor refused the ticket for {spn}: {error}"),
                    at,
                )
                .param("spn", spn)
                .param("reason", error.outcome()),
            ),
        }
    }

    // ----- the job ------------------------------------------------------------------------

    /// Starts the rotation job (`POST /dns/kerberos/rotate`, and the leader when due).
    ///
    /// # Errors
    ///
    /// `dns.krb.account.not_found`, `dns.krb.account.not_owned`, or the engine's error.
    pub async fn start_rotation(
        &self,
        jobs: &dyn ZoneJobs,
        cx: &RequestCtx,
    ) -> ZoneResult<tenko_core::JobId> {
        let (account, _) = self.row().await?.ok_or_else(not_found)?;
        if !account.owned {
            return Err(not_owned(&account.realm));
        }
        let params = RotateParams {
            realm: account.realm.clone(),
            from_kvno: account.current().map(|v| v.kvno),
        };
        let spec = JobSpec {
            kind: JobKind::from_static(ROTATE_JOB),
            title: tenko_core::MessageKey::from_static(ROTATE_TITLE),
            targets: Vec::new(),
            steps: vec![StepSpec {
                kind: StepKind::from_static(ROTATE_JOB),
                params: tenko_core::serde_util::HexBytes(
                    tenko_core::codec::to_cbor(&params)?.to_vec(),
                ),
                timeout: Some(Duration::from_secs(120)),
            }],
            timeout: Duration::from_secs(300),
            group: tenko_jobs::GroupKey::new(ROTATE_JOB).ok(),
            group_limit: Some(1),
            idempotency: None,
            node: None,
        };
        Ok(jobs.submit(spec, cx).await?)
    }

    /// The step handler of the rotation job.
    pub fn rotate_step(self: &Arc<Self>) -> Arc<dyn StepHandler> {
        Arc::new(RotateStep {
            service: Arc::clone(self),
        })
    }
}

fn exists(realm: &Realm) -> ZoneError {
    ZoneError::new(
        codes::KRB_ACCOUNT_EXISTS,
        409,
        "a Kerberos account is set up already: delete it before adopting or importing another",
    )
    .param("realm", realm.as_str())
}

fn not_owned(realm: &Realm) -> ZoneError {
    ZoneError::new(
        codes::KRB_ACCOUNT_NOT_OWNED,
        409,
        "the account was imported from a keytab: its password is the administrator's, so Tenko does not rotate it",
    )
    .param("realm", realm.as_str())
}

fn keytab_invalid(reason: &str) -> ZoneError {
    let reason = clean(reason);
    ZoneError::new(codes::KRB_KEYTAB_INVALID, 422, reason.clone()).param("reason", reason)
}

fn refused_or_unreachable(realm: &Realm, error: &ClientError) -> ZoneError {
    if is_unreachable(error) {
        kdc_unreachable(realm, error)
    } else {
        password_refused(realm, error)
    }
}

fn trimmed(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

fn has_pending(account: &KrbAccount) -> bool {
    account
        .versions
        .iter()
        .any(|v| v.state == KeyVersionState::Pending)
}

fn meta(kvno: u32, state: KeyVersionState, created: Timestamp) -> KeyVersionMeta {
    KeyVersionMeta {
        kvno,
        etypes: client::ETYPES.to_vec(),
        state,
        created,
    }
}

/// The metadata of every version of `keys`.
fn versions_of(keys: &KeySet, created: Timestamp) -> Vec<KeyVersionMeta> {
    let mut out: Vec<KeyVersionMeta> = Vec::new();
    for entry in keys.entries() {
        match out.iter_mut().find(|v| v.kvno == entry.kvno) {
            Some(version) => {
                if !version.etypes.contains(&entry.etype()) {
                    version.etypes.push(entry.etype());
                    version.etypes.sort();
                }
            }
            None => out.push(KeyVersionMeta {
                kvno: entry.kvno,
                etypes: vec![entry.etype()],
                state: entry.state,
                created,
            }),
        }
    }
    out.sort_by_key(|v| v.kvno);
    out
}

fn kvno_list(kvnos: &[u32]) -> String {
    kvnos
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn krbtgt(realm: &Realm) -> ZoneResult<PrincipalName> {
    PrincipalName::new(
        vec!["krbtgt".into(), realm.as_str().to_owned()],
        realm.clone(),
    )
    .map_err(|_| invalid("realm", "not a realm"))
}

/// The principal of `service/host` in `realm`.
fn spn_principal(spn: &str, realm: &Realm) -> Option<PrincipalName> {
    PrincipalName::new(spn.split('/').map(str::to_owned).collect(), realm.clone()).ok()
}

/// The principal the self-test authenticates as: the account, or the principal of the
/// keys when a keytab names only an SPN (`ktpass /princ` sets it as the account's UPN).
fn as_client(account: &KrbAccount, keys: &KeySet) -> Option<PrincipalName> {
    let held = |p: &PrincipalName| {
        keys.entries()
            .iter()
            .any(|e: &KeyEntry| same_principal(&e.principal, p))
    };
    if let Ok(own) = account.principal()
        && held(&own)
    {
        return Some(own);
    }
    account
        .spns
        .iter()
        .filter_map(|spn| spn_principal(spn, &account.realm))
        .find(|p| held(p))
}

/// Whether two principals are the same, the components compared without ASCII case (a
/// keytab and an SPN list may write a host name in another case).
fn same_principal(a: &PrincipalName, b: &PrincipalName) -> bool {
    a.realm() == b.realm()
        && a.components().len() == b.components().len()
        && a.components()
            .iter()
            .zip(b.components())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn kvno_unknown(spn: Option<&str>, kvno: u32, held: &str, at: Timestamp) -> KrbFinding {
    let finding = KrbFinding::new(
        findings::GSS_KVNO_UNKNOWN,
        &format!(
            "the KDC issues key version {kvno}{}, Tenko holds {held}: the password was changed outside Tenko",
            spn.map(|spn| format!(" for {spn}")).unwrap_or_default()
        ),
        at,
    )
    .param("kvno", kvno)
    .param("held", held);
    match spn {
        Some(spn) => finding.param("spn", spn),
        None => finding,
    }
}

fn weak_etype(spn: Option<&str>, etype: Option<i32>, at: Timestamp) -> KrbFinding {
    let what = match etype {
        Some(etype) => format!("tickets of encryption type {etype}"),
        None => "no ticket of an AES type".to_owned(),
    };
    let mut finding = KrbFinding::new(
        findings::GSS_WEAK_ETYPE,
        &format!(
            "the KDC issues {what}{}, which Tenko refuses: the account must allow AES only",
            spn.map(|spn| format!(" for {spn}")).unwrap_or_default()
        ),
        at,
    );
    if let Some(etype) = etype {
        finding = finding.param("etype", etype);
    }
    match spn {
        Some(spn) => finding.param("spn", spn),
        None => finding,
    }
}

fn spn_duplicate(spn: &str, at: Timestamp, why: &str) -> KrbFinding {
    KrbFinding::new(
        findings::GSS_SPN_DUPLICATE,
        &format!("{spn}: {why}; the SPN is held by another account as well"),
        at,
    )
    .param("spn", spn)
}

/// The finding of a failed AS exchange.
fn as_failure(error: &ClientError, at: Timestamp, held: &str) -> KrbFinding {
    match error {
        ClientError::Kdc { code, .. } if *code == error_code::SKEW => KrbFinding::new(
            findings::GSS_CLOCK_SKEW,
            "the KDC refused the request for clock skew (more than 300 s)",
            at,
        )
        .param("skew_secs", ">300")
        .param("kdc_error", code),
        ClientError::Kdc { code, .. } if *code == ETYPE_NOSUPP => {
            weak_etype(None, None, at).param("kdc_error", code)
        }
        ClientError::Kdc { code, text } => {
            let reason = match *code {
                error_code::PREAUTH_FAILED => "keys_refused",
                error_code::CLIENT_REVOKED => "disabled",
                error_code::C_PRINCIPAL_UNKNOWN => "unknown",
                error_code::KEY_EXPIRED => "expired",
                _ => "kdc_error",
            };
            let what = match reason {
                "keys_refused" => format!(
                    "the KDC refuses the keys Tenko holds (versions {held}): the password was reset outside Tenko"
                ),
                "disabled" => "the account is disabled or locked".to_owned(),
                "unknown" => "the account does not exist in the directory".to_owned(),
                "expired" => "the account's password has expired".to_owned(),
                _ => format!(
                    "the KDC refused the account: error {code}{}",
                    text.as_deref()
                        .map(|t| format!(" ({t})"))
                        .unwrap_or_default()
                ),
            };
            KrbFinding::new(findings::GSS_SELF_TEST_FAILED, &what, at)
                .param("reason", reason)
                .param("kdc_error", code)
        }
        error if is_unreachable(error) => KrbFinding::new(
            findings::GSS_SELF_TEST_FAILED,
            &format!("no KDC answered: {error}"),
            at,
        )
        .param("reason", "kdc_unreachable"),
        error => KrbFinding::new(
            findings::GSS_SELF_TEST_FAILED,
            &format!("the AS exchange failed: {error}"),
            at,
        )
        .param("reason", "reply"),
    }
}

/// `KDC_ERR_ETYPE_NOSUPP`: no encryption type in common (an account without AES).
const ETYPE_NOSUPP: i32 = 14;
/// `KDC_ERR_PRINCIPAL_NOT_UNIQUE`: two accounts hold the name.
const PRINCIPAL_NOT_UNIQUE: i32 = 9;

/// The finding of a failed TGS exchange for `spn`.
fn tgs_failure(spn: &str, error: &ClientError, at: Timestamp) -> KrbFinding {
    match error {
        ClientError::Kdc { code, .. } if *code == error_code::S_PRINCIPAL_UNKNOWN => {
            KrbFinding::new(
                findings::GSS_SPN_MISSING,
                &format!("the KDC knows no account with the SPN {spn}"),
                at,
            )
            .param("spn", spn)
            .param("kdc_error", code)
        }
        ClientError::Kdc { code, .. } if *code == PRINCIPAL_NOT_UNIQUE => {
            spn_duplicate(spn, at, "the KDC found the SPN on more than one account")
                .param("kdc_error", code)
        }
        ClientError::Kdc { code, .. } if *code == ETYPE_NOSUPP => {
            weak_etype(Some(spn), None, at).param("kdc_error", code)
        }
        error => KrbFinding::new(
            findings::GSS_SELF_TEST_FAILED,
            &format!("the TGS exchange for {spn} failed: {error}"),
            at,
        )
        .param("spn", spn)
        .param(
            "reason",
            if is_unreachable(error) {
                "kdc_unreachable"
            } else {
                "tgs"
            },
        ),
    }
}

// ---------------------------------------------------------------------------------------
// The rotation job

/// The parameters of the rotation step: the realm and the version that was current when
/// the job was asked for, so that a step run again after it succeeded does not rotate
/// twice.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotateParams {
    /// The realm.
    pub realm: Realm,
    /// The current version when the job started.
    pub from_kvno: Option<u32>,
}

struct RotateStep {
    service: Arc<KerberosService>,
}

#[async_trait::async_trait]
impl StepHandler for RotateStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(ROTATE_JOB)
    }

    /// Idempotent: a pending change is finished, and a version that moved since the job
    /// started is not moved again.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: RotateParams = tenko_core::codec::from_cbor(params)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: tenko_core::MessageKey::from_static(ROTATE_PREVIEW),
            args: BTreeMap::from([("realm".to_owned(), params.realm.to_string())]),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: RotateParams = tenko_core::codec::from_cbor(params)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let service = &self.service;
        let rotated = service
            .rotate_from(&cx.request, None, Some(params.from_kvno))
            .await
            .map_err(|error| StepError::Coded(Box::new(error.into_coded())))?;
        if rotated == Rotated::Unknown {
            return Err(StepError::Coded(Box::new(tenko_core::CodedError::new(
                codes::KRB_KDC_UNREACHABLE,
                503,
                "the outcome of the change is not known yet; the new keys stay pending and the recovery finishes them",
            ))));
        }
        if matches!(rotated, Rotated::Changed { .. }) {
            let _ = service.check(&cx.request, None).await;
        }
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Err(StepError::NotCompensable)
    }
}

// ---------------------------------------------------------------------------------------
// The leader service

/// The leader service `dns.krb`: a change left pending is finished, the self-test runs
/// every [`KerberosConfig::check_every`], and an owned account's password is rotated when
/// [`KrbAccount::rotation_days`] have passed since the last rotation (or since its keys
/// were made). Writes are fenced by the leader epoch.
pub struct LeaderLoop {
    service: Arc<KerberosService>,
    jobs: Arc<dyn ZoneJobs>,
}

impl std::fmt::Debug for LeaderLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderLoop").finish_non_exhaustive()
    }
}

impl LeaderLoop {
    /// The loop over `service`, starting rotation jobs through `jobs`.
    pub fn new(service: Arc<KerberosService>, jobs: Arc<dyn ZoneJobs>) -> Arc<Self> {
        Arc::new(Self { service, jobs })
    }

    /// One look at the account: what is due is done. Returns what it did, for the tests.
    ///
    /// # Errors
    ///
    /// The first error of what it tried.
    pub async fn tick(
        &self,
        epoch: Option<u64>,
        retry_after: &mut Option<Timestamp>,
    ) -> ZoneResult<Due> {
        let cx = RequestCtx::system(SystemComponent::Dns);
        let service = &self.service;
        let Some(account) = service.status().await? else {
            return Ok(Due::Nothing);
        };
        let now = timestamp(service.now());
        if has_pending(&account) {
            service.recover(&cx, epoch).await?;
            return Ok(Due::Recovered);
        }
        let rotation = account.owned && account.rotation_days > 0;
        let since = account
            .last_rotation
            .or_else(|| account.current().map(|v| v.created));
        let due = since.is_some_and(|since| {
            now.saturating_since(since)
                >= Duration::from_secs(u64::from(account.rotation_days) * 86_400)
        });
        let waiting = retry_after.is_some_and(|until| now < until);
        if rotation && due && !waiting {
            // A job that fails leaves the account due: the next attempt waits.
            *retry_after = now.checked_add(service.config.retry_after);
            return service
                .start_rotation(self.jobs.as_ref(), &cx)
                .await
                .map(|_| Due::Rotated);
        }
        let checked = account
            .last_check
            .is_some_and(|last| now.saturating_since(last) < service.config.check_every);
        if !checked {
            service.check(&cx, epoch).await?;
            return Ok(Due::Checked);
        }
        Ok(Due::Nothing)
    }
}

/// What a tick of the leader loop did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Nothing was due.
    Nothing,
    /// A pending change was finished or undone.
    Recovered,
    /// A rotation job was started.
    Rotated,
    /// The self-test ran.
    Checked,
}

#[async_trait::async_trait]
impl tenko_core::cluster::LeaderService for LeaderLoop {
    fn name(&self) -> &'static str {
        LEADER_SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut retry_after = None;
        loop {
            if let Err(error) = self.tick(Some(epoch), &mut retry_after).await {
                tracing::warn!(%error, "the Kerberos account's task failed; it tries again later");
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.service.config.tick) => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The watcher

/// What the watcher compares to decide whether to read the vault again: the realm, the
/// SPNs, the secret and the versions (not the findings, which the watcher may write).
type InstalledForm = (
    Realm,
    Vec<String>,
    Option<tenko_core::secret::SecretRef>,
    Vec<KeyVersionMeta>,
);

fn installed_form(account: &KrbAccount) -> InstalledForm {
    (
        account.realm.clone(),
        account.spns.clone(),
        account.secret,
        account.versions.clone(),
    )
}

/// Keeps `sink` current until `stop`: the account and its keys are read at once, then again
/// after every change of `dns.krb_accounts` and at least every 30 seconds; the vault is
/// read again only when the realm, the SPNs, the secret or the versions changed. A key set
/// that does not read leaves the last good one in place and is logged without its
/// content; a key set the acceptor refuses is recorded on the account as the finding
/// `dns.gss.self_test_failed` (reason `install_refused`).
pub async fn follow(
    service: Arc<KerberosService>,
    sink: Arc<dyn KeySink>,
    stop: CancellationToken,
) {
    let filter = || WatchFilter::tables([KRB_ACCOUNTS.name().clone()]);
    let mut stream = service.store.watch(None, filter()).ok();
    let mut last: Option<InstalledForm> = None;
    loop {
        match service.status().await {
            Ok(Some(account)) => {
                let form = installed_form(&account);
                if last.as_ref() != Some(&form) {
                    match service.keys(&account).await {
                        // An adopt that has not written its keys yet, or did not finish.
                        Ok(keys) if keys.is_empty() => last = Some(form),
                        Ok(keys) => {
                            if let Err(reason) =
                                sink.install(account.realm.clone(), &account.spns, keys)
                            {
                                tracing::warn!(%reason, "the acceptor refused the Kerberos account's keys");
                                service.record_install_refusal(&reason).await;
                            }
                            last = Some(form);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "the keys of the Kerberos account could not be read");
                        }
                    }
                }
            }
            Ok(None) => {
                if last.is_some() || sink.installed().is_some() {
                    sink.clear();
                }
                last = None;
            }
            Err(error) => {
                tracing::warn!(%error, "the Kerberos account could not be read");
            }
        }
        let changed = async {
            match &mut stream {
                Some(stream) => matches!(stream.next().await, Some(Ok(_))),
                None => false,
            }
        };
        let alive = tokio::select! {
            () = stop.cancelled() => return,
            alive = changed => alive,
            () = tokio::time::sleep(Duration::from_secs(30)) => true,
        };
        if !alive {
            stream = service.store.watch(None, filter()).ok();
        }
    }
}

impl KerberosService {
    /// Records that the acceptor refused the keys, once per reason.
    async fn record_install_refusal(&self, reason: &str) {
        let cx = RequestCtx::system(SystemComponent::Dns);
        let attempt = async {
            let (mut account, revision) = self.row().await?.ok_or_else(not_found)?;
            let finding = KrbFinding::new(
                findings::GSS_SELF_TEST_FAILED,
                &format!("the acceptor of the dns role refused the account's keys: {reason}"),
                cx.now,
            )
            .param("reason", "install_refused");
            if account
                .findings
                .iter()
                .any(|f| f.code == finding.code && f.detail == finding.detail)
            {
                return Ok(());
            }
            account.findings.push(finding);
            account
                .findings
                .truncate(tenko_core::dns::identity::MAX_KRB_FINDINGS);
            self.write(&cx, account, None, Some(revision), None, None)
                .await
                .map(|_| ())
        };
        if let Err(error) = attempt.await {
            tracing::warn!(%error, "the acceptor's refusal could not be recorded");
        }
    }
}

#[cfg(test)]
mod tests;
