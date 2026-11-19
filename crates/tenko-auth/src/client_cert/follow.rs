//! The in-memory index of integration certificates and of the service accounts that may
//! hold them: what the integration listener asks at every handshake and every request, so
//! that no read of the store sits on that path (ADR 0035, decision 9).

use std::{
    collections::HashMap,
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

use super::{
    ClientCertError, ClientCerts,
    model::{CLIENT_CERTS, CertState, ClientCertRecord},
};
use crate::model::USERS;

/// How long a replaced certificate passes for every route after its successor was first
/// presented (ADR 0035, decision 6).
pub const OVERLAP: time::Duration = time::Duration::minutes(15);

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
#[derive(Debug, Default)]
pub struct CertIndex {
    certs: ArcSwap<HashMap<String, ClientCertRecord>>,
    /// The `tokens_generation` of every enabled service account.
    accounts: ArcSwap<HashMap<UserId, u64>>,
    loaded: AtomicBool,
}

impl CertIndex {
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

    /// Reads both tables in full and replaces what the index holds.
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
        let count = certs.len();
        self.certs.store(Arc::new(certs));
        self.accounts.store(Arc::new(accounts));
        self.loaded.store(true, Ordering::Release);
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
            let filter = WatchFilter::tables([CLIENT_CERTS.name().clone(), USERS.name().clone()]);
            loop {
                match service.index.load(service.store.as_ref()).await {
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(code = %tenko_core::Coded::code(&error), "integration certificates could not be read: {error}");
                    }
                }
                let Ok(mut changes) = service.store.watch(None, filter.clone()) else {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                };
                loop {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        change = changes.next() => {
                            if !matches!(change, Some(Ok(_))) {
                                // Lagged or compacted: read everything again and follow anew.
                                break;
                            }
                            if let Err(error) = service.index.load(service.store.as_ref()).await {
                                tracing::warn!(code = %tenko_core::Coded::code(&error), "integration certificates could not be read: {error}");
                            }
                        }
                    }
                }
            }
        })
    }
}
