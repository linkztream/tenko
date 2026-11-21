//! The in-memory index of integration certificates and of the service accounts that may
//! hold them: what the integration listener asks at every handshake and every request, so
//! that no read of the store sits on that path (ADR 0035, decision 9).

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use futures::StreamExt as _;
use tenko_core::{Timestamp, UserId};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store, WatchFilter};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use super::{
    ClientCertError, ClientCerts,
    model::{
        CLIENT_CERTS, CertState, ClientCertRecord, CodeState, ENROLLMENT_CODES, IntegrationPolicy,
    },
};
use crate::{
    model::{SETTINGS, USERS},
    settings::Profile,
};

/// How long a replaced certificate passes for every route after its successor was first
/// presented (ADR 0035, decision 6).
pub const OVERLAP: time::Duration = time::Duration::minutes(15);

/// How long the index keeps accepting after a change of the records it could not read: the
/// bound the integration listener grants a controller cut off from its quorum (ADR 0035,
/// decision 9). Past it nothing passes until a load succeeds.
pub const STALE_LIMIT: Duration = Duration::from_secs(30);

/// What the index says about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// It passes for every route.
    Accepted(ClientCertRecord),
    /// A replaced certificate past its overlap: it passes for the renewal route only, where
    /// a renewal from it is reuse.
    RenewOnly(ClientCertRecord),
    /// It does not pass; the reason is for the log.
    Refused(&'static str),
}

/// The certificate records and the usable service accounts, in memory.
#[derive(Debug)]
pub struct CertIndex {
    certs: ArcSwap<HashMap<String, ClientCertRecord>>,
    /// The `tokens_generation` of every enabled service account.
    accounts: ArcSwap<HashMap<UserId, u64>>,
    /// The TGL-47 values of the stored profile.
    policy: ArcSwap<IntegrationPolicy>,
    /// Whether an enrollment code was waiting at the last load.
    codes_waiting: AtomicBool,
    loaded: AtomicBool,
    /// Since when the records changed without a load that succeeded.
    stale_since: ArcSwap<Option<Timestamp>>,
    /// Counts the loads, so that the listener re-checks its open connections after each.
    version: watch::Sender<u64>,
}

impl Default for CertIndex {
    fn default() -> Self {
        Self {
            certs: ArcSwap::default(),
            accounts: ArcSwap::default(),
            policy: ArcSwap::from_pointee(IntegrationPolicy::of(Profile::Standard)),
            codes_waiting: AtomicBool::new(false),
            loaded: AtomicBool::new(false),
            stale_since: ArcSwap::from_pointee(None),
            version: watch::channel(0).0,
        }
    }
}

impl CertIndex {
    /// A receiver that changes after every load.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    /// Notes a change of the records that could not be read: past [`STALE_LIMIT`] nothing
    /// passes, and the open connections hear of it now so that they can wait for that bound.
    pub fn mark_stale(&self, now: Timestamp) {
        if self.stale_since.load().is_none() {
            self.stale_since.store(Arc::new(Some(now)));
            self.version.send_modify(|version| *version += 1);
        }
    }

    /// The next moment after `now` at which what [`CertIndex::accept`] says of `serial` may
    /// change without a change of the records: the end of its validity, the end of its overlap
    /// after a replacement, or the end of [`STALE_LIMIT`]. `None` for an unknown serial or when
    /// every such moment has passed.
    pub fn next_boundary(&self, serial: &str, now: Timestamp) -> Option<Timestamp> {
        let record = self.record(serial)?;
        let overlap = match record.state {
            CertState::Replaced => record.ended_at.map(|ended| Timestamp(ended.0 + OVERLAP)),
            _ => None,
        };
        let stale = (**self.stale_since.load()).map(|since| Timestamp(since.0 + STALE_LIMIT));
        [Some(record.not_after), overlap, stale]
            .into_iter()
            .flatten()
            .filter(|at| at.0 > now.0)
            .min_by_key(|at| at.0)
    }

    /// The TGL-47 values in force.
    pub fn policy(&self) -> IntegrationPolicy {
        **self.policy.load()
    }

    /// The current certificates in the last sixth of their lifetime whose lineage has not
    /// renewed: the certificate expiry alarm (OPS-29).
    pub fn expiring(&self, now: Timestamp) -> Vec<ClientCertRecord> {
        let certs = self.certs.load();
        let renewed: HashSet<Uuid> = certs
            .values()
            .filter(|record| record.state == CertState::Pending)
            .map(|record| record.lineage)
            .collect();
        let mut expiring: Vec<ClientCertRecord> = certs
            .values()
            .filter(|record| {
                record.state == CertState::Current
                    && now.0 >= super::alarm_after(record).0
                    && now.0 < record.not_after.0
                    && !renewed.contains(&record.lineage)
            })
            .cloned()
            .collect();
        expiring.sort_by_key(|record| record.not_after);
        expiring
    }

    /// Whether the integration listener is wanted when it opens on demand: an enrollment
    /// code is waiting, or a certificate that has not ended or expired exists.
    pub fn wanted(&self, now: Timestamp) -> bool {
        self.codes_waiting.load(Ordering::Acquire)
            || self.certs.load().values().any(|record| {
                matches!(
                    record.state,
                    CertState::Current | CertState::Pending | CertState::Replaced
                ) && now.0 < record.not_after.0
            })
    }

    /// Whether the first full load succeeded: the integration listener opens only then.
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    /// The record of a serial.
    pub fn record(&self, serial: &str) -> Option<ClientCertRecord> {
        self.certs.load().get(serial).cloned()
    }

    /// Whether the certificate with `serial`, which names `account`, passes at `now`. Before
    /// the first full load nothing passes.
    pub fn accept(&self, serial: &str, account: UserId, now: Timestamp) -> Acceptance {
        if !self.is_loaded() {
            return Acceptance::Refused("the records are not loaded");
        }
        if (**self.stale_since.load())
            .is_some_and(|since| now.saturating_since(since) >= STALE_LIMIT)
        {
            return Acceptance::Refused("the records could not be read for too long");
        }
        let certs = self.certs.load();
        let Some(record) = certs.get(serial) else {
            return Acceptance::Refused("unknown serial");
        };
        if record.account != account {
            return Acceptance::Refused("the record names another account");
        }
        match self.accounts.load().get(&account) {
            Some(generation) if *generation <= record.generation => {}
            _ => return Acceptance::Refused("the account cannot hold it"),
        }
        if now.0 < record.not_before.0 || now.0 >= record.not_after.0 {
            return Acceptance::Refused("outside its validity");
        }
        match record.state {
            CertState::Current | CertState::Pending => Acceptance::Accepted(record.clone()),
            CertState::Replaced
                if record
                    .ended_at
                    .is_some_and(|ended| now.0 < ended.0 + OVERLAP) =>
            {
                Acceptance::Accepted(record.clone())
            }
            CertState::Replaced => Acceptance::RenewOnly(record.clone()),
            CertState::Withdrawn | CertState::Revoked => Acceptance::Refused("ended"),
        }
    }

    /// Reads the tables in full and replaces what the index holds.
    ///
    /// # Errors
    ///
    /// A store error; the index keeps what it held.
    pub async fn load(&self, store: &dyn Store) -> Result<usize, ClientCertError> {
        let view = store.read(ReadConsistency::Local).await?;
        let certs: HashMap<_, _> = view
            .scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(serial, record, _)| (serial, record))
            .collect();
        let accounts = view
            .scan_typed(&USERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, user, _)| user.is_service() && !user.disabled)
            .map(|(id, user, _)| (id, user.tokens_generation))
            .collect();
        let now = Timestamp::now();
        let codes_waiting = view
            .scan_typed(&ENROLLMENT_CODES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .any(|(_, code, _)| code.state == CodeState::Pending && now.0 < code.expires_at.0);
        let policy = ClientCerts::policy(view.as_ref())?;
        let count = certs.len();
        self.certs.store(Arc::new(certs));
        self.accounts.store(Arc::new(accounts));
        self.policy.store(Arc::new(policy));
        self.codes_waiting.store(codes_waiting, Ordering::Release);
        self.stale_since.store(Arc::new(None));
        self.loaded.store(true, Ordering::Release);
        self.version.send_modify(|version| *version += 1);
        Ok(count)
    }
}

impl ClientCerts {
    /// Follows the certificate records and the users until `stop` turns true: a change on
    /// any controller reaches this index within a moment of its replication. The first full
    /// load runs before the task starts following.
    pub fn follow(self: &Arc<Self>, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let filter = WatchFilter::tables([
                CLIENT_CERTS.name().clone(),
                USERS.name().clone(),
                ENROLLMENT_CODES.name().clone(),
                SETTINGS.name().clone(),
            ]);
            loop {
                // Subscribe before the load: a change committed between the load's snapshot
                // and the subscription would otherwise never reach the index.
                let Ok(mut changes) = service.store.watch(None, filter.clone()) else {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                };
                if let Err(error) = service.index.load(service.store.as_ref()).await {
                    // Read again shortly, not at the next change: a quiet installation may not
                    // change for hours, and past the bound the index refuses everything.
                    tracing::warn!(code = %tenko_core::Coded::code(&error), "integration certificates could not be read: {error}");
                    if service.index.is_loaded() {
                        service.index.mark_stale(Timestamp::now());
                    }
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                }
                loop {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        change = changes.next() => {
                            if !matches!(change, Some(Ok(_))) {
                                // Lagged or compacted: read everything again and follow anew.
                                break;
                            }
                            if let Err(error) = service.index.load(service.store.as_ref()).await {
                                // The index no longer knows what holds: it refuses past the
                                // bound, and the reading is tried again from the start.
                                tracing::warn!(code = %tenko_core::Coded::code(&error), "integration certificates could not be read: {error}");
                                service.index.mark_stale(Timestamp::now());
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                break;
                            }
                        }
                    }
                }
            }
        })
    }
}
