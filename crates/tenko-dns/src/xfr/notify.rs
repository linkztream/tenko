//! NOTIFY out (RFC 1996): the leader service `dns.notify` tells a zone's `transfer.notify`
//! targets when its serial changes.
//!
//! The service follows the store's commits of `dns.rrsets`: a commit that writes a zone's
//! SOA (every change set of the zone service moves the serial in the same batch) marks the
//! zone. The changes of a burst are coalesced per zone: the service waits
//! [`NotifySettings::coalesce`] after the first mark, then until the transfer path of this
//! process serves the commit ([`ServedRevision`]: a secondary that asks for the SOA right
//! after the NOTIFY must see the new serial), reads the serial and sends one NOTIFY per
//! target, signed with the target's key when it has one, over UDP. A target
//! that does not answer gets the NOTIFY again after 15, 30, 60 and 120 seconds, five
//! attempts in all; a newer serial meanwhile replaces the one being retried.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use futures::StreamExt as _;
use tenko_core::{
    cluster::LeaderService,
    dns::{NotifyTarget, Rtype, ScopeName, ZoneId, tables::RRSETS},
};
use tenko_store::{ReadViewExt as _, WatchFilter};
use tokio::{net::UdpSocket, sync::watch};
use tokio_util::sync::CancellationToken;

use super::{
    MetricKind, Outcome, count,
    message::{OPCODE_NOTIFY, TYPE_SOA, write_request},
    out::unix_now,
};
use crate::{
    tsig::Signer,
    wire::{self, MAX_MESSAGE_LEN},
    zone::{ZoneService, secondary::KeyLoader},
};

/// The timing of NOTIFY out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifySettings {
    /// How long the changes of one zone are gathered before its NOTIFY goes out.
    pub coalesce: Duration,
    /// How long one attempt waits for the answer.
    pub answer: Duration,
    /// The waits before the attempts after the first.
    pub retries: Vec<Duration>,
}

impl Default for NotifySettings {
    fn default() -> Self {
        Self {
            coalesce: Duration::from_millis(250),
            answer: Duration::from_secs(2),
            retries: [15, 30, 60, 120].map(Duration::from_secs).to_vec(),
        }
    }
}

/// The store revision the transfer path of this process serves: the `dns` role sets its
/// catalog here when it starts. Without a role in the process nothing is awaited (Phase 5:
/// the nodes report what they serve).
#[derive(Debug, Clone, Default)]
pub struct ServedRevision(Arc<std::sync::OnceLock<crate::catalog::CatalogHandle>>);

impl ServedRevision {
    /// The catalog the role serves from.
    pub fn set(&self, catalog: crate::catalog::CatalogHandle) {
        let _ = self.0.set(catalog);
    }

    /// The revision served, when a role runs in this process.
    pub fn revision(&self) -> Option<tenko_core::Revision> {
        self.0.get().map(crate::catalog::CatalogHandle::revision)
    }

    /// Waits until the revision served is at least `revision`, at most `limit`.
    async fn reach(&self, revision: u64, limit: Duration) {
        let deadline = tokio::time::Instant::now() + limit;
        while let Some(served) = self.revision() {
            if served.0 >= revision || tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// The leader service `dns.notify`.
pub struct NotifyService {
    zones: Arc<ZoneService>,
    keys: Arc<KeyLoader>,
    served: ServedRevision,
    settings: NotifySettings,
}

impl std::fmt::Debug for NotifyService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyService")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl NotifyService {
    /// The service over the zone service's store, with the keys of `keys`.
    pub fn new(
        zones: Arc<ZoneService>,
        keys: Arc<KeyLoader>,
        served: ServedRevision,
        settings: NotifySettings,
    ) -> Self {
        Self {
            zones,
            keys,
            served,
            settings,
        }
    }

    /// The zone's NOTIFY targets, its apex and the SOA of its default scope now.
    async fn targets(&self, zone: ZoneId) -> Option<(Vec<NotifyTarget>, Vec<u8>, Soa)> {
        let view = self.zones.view(None).await.ok()?;
        let row = ZoneService::zone(view.as_ref(), zone).ok()?.zone;
        if row.transfer.notify.is_empty() {
            return None;
        }
        let key = tenko_core::dns::RrSetKey {
            zone,
            scope: ScopeName::DEFAULT,
            name: row.name.clone(),
            rtype: Rtype::SOA,
        };
        let (soa, _) = view.get_typed(&RRSETS, &key).ok()??;
        let rdata = soa.rdata.first()?.as_bytes().to_vec();
        let serial = super::message::soa_serial(&rdata)?;
        Some((
            row.transfer.notify,
            row.name.to_wire(),
            Soa {
                serial,
                ttl: soa.ttl,
                rdata,
            },
        ))
    }

    /// Sends the NOTIFY of one zone at one serial to one target until it is answered or
    /// the attempts run out.
    async fn send(&self, target: NotifyTarget, apex: Vec<u8>, soa: Soa, stop: CancellationToken) {
        let serial = soa.serial;
        let address = SocketAddr::new(target.address, target.port);
        let key = match &target.key {
            Some(name) => {
                let Some(key) = self.keys.key(name).await else {
                    tracing::warn!(%address, key = %name, "the NOTIFY key is unknown; the NOTIFY is not sent");
                    count(MetricKind::NotifyOut, Outcome::Failed);
                    return;
                };
                Some(key)
            }
            None => None,
        };
        let waits = std::iter::once(Duration::ZERO).chain(self.settings.retries.iter().copied());
        for wait in waits {
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            match notify_once(address, &apex, &soa, key.clone(), self.settings.answer).await {
                Ok(()) => {
                    count(MetricKind::NotifyOut, Outcome::Ok);
                    tracing::debug!(%address, serial, "NOTIFY answered");
                    return;
                }
                Err(error) => {
                    tracing::debug!(%address, serial, %error, "NOTIFY not answered");
                }
            }
        }
        count(MetricKind::NotifyOut, Outcome::Failed);
        tracing::warn!(%address, serial, "a NOTIFY was not answered after five attempts");
    }

    /// The task of one zone: waits for marks, coalesces, sends.
    async fn zone_task(
        self: Arc<Self>,
        zone: ZoneId,
        mut marks: watch::Receiver<u64>,
        stop: CancellationToken,
    ) {
        let mut sent = None;
        let mut current: Option<CancellationToken> = None;
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                changed = marks.changed() => if changed.is_err() { return },
            }
            tokio::time::sleep(self.settings.coalesce).await;
            let revision = *marks.borrow_and_update();
            self.served.reach(revision, Duration::from_secs(30)).await;
            let Some((targets, apex, soa)) = self.targets(zone).await else {
                continue;
            };
            let serial = soa.serial;
            if sent == Some(serial) {
                continue;
            }
            sent = Some(serial);
            if let Some(previous) = current.take() {
                previous.cancel();
            }
            let token = stop.child_token();
            current = Some(token.clone());
            for target in targets {
                let this = Arc::clone(&self);
                let apex = apex.clone();
                let token = token.clone();
                let soa = soa.clone();
                tokio::spawn(async move { this.send(target, apex, soa, token).await });
            }
        }
    }
}

/// The SOA a NOTIFY carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    /// The serial.
    pub serial: u32,
    /// The TTL.
    pub ttl: u32,
    /// The data in stored form.
    pub rdata: Vec<u8>,
}

/// One NOTIFY to `address` with the zone's SOA, waiting `wait` for its answer.
///
/// # Errors
///
/// English text: no answer in time, an answer that is not NOERROR, a send error.
pub async fn notify_once(
    address: SocketAddr,
    apex: &[u8],
    soa: &Soa,
    key: Option<Arc<crate::tsig::TsigKey>>,
    wait: Duration,
) -> Result<(), String> {
    let bind: SocketAddr = if address.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    let mut id = [0u8; 2];
    let _ = aws_lc_rs::rand::fill(&mut id);
    let id = u16::from_be_bytes(id);
    let mut message = Vec::with_capacity(512);
    // The answer section carries the new SOA (RFC 1996 section 3.7).
    write_request(
        &mut message,
        id,
        OPCODE_NOTIFY,
        apex,
        TYPE_SOA,
        Some((soa.ttl, &soa.rdata)),
    );
    if let Some(key) = key
        && !Signer::request(key).sign(&mut message, unix_now(), 0, &[], MAX_MESSAGE_LEN)
    {
        return Err("the NOTIFY could not be signed".to_owned());
    }
    socket
        .send_to(&message, address)
        .await
        .map_err(|error| error.to_string())?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .map_err(|_| "no answer in time".to_owned())?
            .map_err(|error| error.to_string())?;
        if from.ip() != address.ip() {
            continue;
        }
        let Some(header) = wire::parse_header(&buf[..len]) else {
            continue;
        };
        if header.id != id || !header.qr {
            continue;
        }
        return if header.rcode == 0 {
            Ok(())
        } else {
            Err(format!("the target answered RCODE {}", header.rcode))
        };
    }
}

#[async_trait::async_trait]
impl LeaderService for NotifyService {
    fn name(&self) -> &'static str {
        "dns.notify"
    }

    async fn run(&self, _epoch: u64, stop: CancellationToken) -> Result<(), String> {
        // The tasks need an owned service; the registry holds this one.
        let this = Arc::new(Self {
            zones: Arc::clone(&self.zones),
            keys: Arc::clone(&self.keys),
            served: self.served.clone(),
            settings: self.settings.clone(),
        });
        let filter = || WatchFilter::tables([RRSETS.name().clone()]);
        let mut stream = this
            .zones
            .store()
            .watch(None, filter())
            .map_err(|error| error.to_string())?;
        let mut tasks: HashMap<ZoneId, watch::Sender<u64>> = HashMap::new();
        loop {
            let next = tokio::select! {
                () = stop.cancelled() => return Ok(()),
                next = stream.next() => next,
            };
            let Some(Ok(set)) = next else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                stream = this
                    .zones
                    .store()
                    .watch(None, filter())
                    .map_err(|error| error.to_string())?;
                continue;
            };
            for change in &set.changes {
                if change.table != *RRSETS.name() || change.deleted {
                    continue;
                }
                let Ok(key) = RRSETS.decode_key(&change.key) else {
                    continue;
                };
                if key.rtype != Rtype::SOA {
                    continue;
                }
                let sender = tasks.entry(key.zone).or_insert_with(|| {
                    let (sender, receiver) = watch::channel(0u64);
                    tokio::spawn(Arc::clone(&this).zone_task(
                        key.zone,
                        receiver,
                        stop.child_token(),
                    ));
                    sender
                });
                sender.send_modify(|mark| *mark = (*mark).max(set.revision.0));
            }
        }
    }
}
