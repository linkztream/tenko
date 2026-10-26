//! The clients of move jobs in the configuration image (ADR 0027, `docs/moves.md` section
//! 4, `docs/dhcp.md` section 12.2): the rows of `dhcp.moving` as the DORA path reads them.
//!
//! A move job writes a [`MovingClient`] row for the client it moves before anything else;
//! the image carries it as a [`MovingImage`] until the job removes it. The engine reads it
//! in two places, both without allocating:
//!
//! - **The short lease.** A REQUEST (and the OFFER before it) of the client for the address
//!   of the row's old lease is answered with at most `short_secs`, with T1 and T2 derived
//!   from it as for any grant ([`Moving::short_lease`]). The client then renews within
//!   the short lease after the move changes its network, rebinds through the relay of the
//!   new network and gets its NAK and its new lease there.
//! - **The activity.** Every message of the client's MAC address is noted with its time,
//!   and apart when its scope is the move's target ([`Moving::note`]): two relaxed atomic
//!   stores. The job reads them through the role ([`Moving::activity`]): a message in the
//!   last seconds before its deadline extends the deadline once, a message on the target
//!   scope starts the short window in which the job verifies the new lease.
//!
//! A row counts only before its `until` (the job's own deadline). The leader's lease
//! expiry removes rows whose job ended. A new image takes the activity of the rows it
//! keeps from the image it replaces ([`Moving::adopt`]), so a configuration change in the
//! middle of a move loses nothing.

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use tenko_core::{
    JobId, PrefixId, Timestamp, VrfId,
    dhcp::{MovingClient, MovingLease},
};

/// What the role saw of a moving client: its last message, and its last message on the
/// move's target scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Activity {
    /// The last DHCP message of the client's MAC address.
    pub last: Option<Timestamp>,
    /// The last one whose scope is the move's target.
    pub on_target: Option<Timestamp>,
}

/// The times of a client's messages, in Unix milliseconds (0: none yet).
#[derive(Debug, Default)]
pub struct ActivityCell {
    last: AtomicI64,
    target: AtomicI64,
}

fn millis(now: Timestamp) -> i64 {
    i64::try_from(now.unix_nanos() / 1_000_000)
        .unwrap_or(i64::MAX)
        .max(1)
}

fn time(millis: i64) -> Option<Timestamp> {
    (millis > 0)
        .then(|| Timestamp::from_unix_nanos(i128::from(millis) * 1_000_000).ok())
        .flatten()
}

impl ActivityCell {
    fn read(&self) -> Activity {
        Activity {
            last: time(self.last.load(Ordering::Relaxed)),
            on_target: time(self.target.load(Ordering::Relaxed)),
        }
    }
}

/// One client of a move job, as the image serves it.
#[derive(Debug, Clone)]
pub struct MovingImage {
    /// The job.
    pub job: JobId,
    /// The client's MAC address.
    pub mac: [u8; 6],
    /// The old lease a renewal answers with the short lease.
    pub lease: Option<MovingLease>,
    /// The short lease in seconds.
    pub short_secs: u32,
    /// The target scope.
    pub target: Option<PrefixId>,
    /// When the row stops counting.
    pub until: Timestamp,
    activity: Arc<ActivityCell>,
}

impl MovingImage {
    /// The image of a row.
    pub fn of(row: &MovingClient) -> Self {
        Self {
            job: row.job,
            mac: row.mac.octets(),
            lease: row.lease,
            short_secs: row.short_secs,
            target: row.target,
            until: row.until,
            activity: Arc::default(),
        }
    }

    /// Whether the row counts at `now`.
    pub fn is_active(&self, now: Timestamp) -> bool {
        now < self.until
    }

    /// What the role saw of the client.
    pub fn activity(&self) -> Activity {
        self.activity.read()
    }
}

/// The clients of move jobs, sorted by MAC address, with the old leases they shorten.
#[derive(Debug, Clone, Default)]
pub struct Moving {
    clients: Vec<MovingImage>,
    by_lease: BTreeMap<(VrfId, Ipv4Addr), usize>,
}

impl Moving {
    /// The image of the rows.
    pub fn of<'a>(rows: impl IntoIterator<Item = &'a MovingClient>) -> Self {
        let mut clients: Vec<MovingImage> = rows.into_iter().map(MovingImage::of).collect();
        clients.sort_by_key(|client| (client.mac, client.job));
        let by_lease = clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                client
                    .lease
                    .filter(|_| client.short_secs > 0)
                    .map(|lease| ((lease.vrf, lease.addr), index))
            })
            .collect();
        Self { clients, by_lease }
    }

    /// Whether no move job moves a client now; the engine's fast path.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// The clients.
    pub fn clients(&self) -> &[MovingImage] {
        &self.clients
    }

    fn of_mac(&self, mac: [u8; 6]) -> &[MovingImage] {
        let start = self.clients.partition_point(|client| client.mac < mac);
        let end = self.clients.partition_point(|client| client.mac <= mac);
        &self.clients[start..end]
    }

    /// The short lease of a REQUEST of `mac` for `addr` in `vrf` at `now`: the row's
    /// `short_secs` while a move job of the client is active, else none.
    pub fn short_lease(
        &self,
        vrf: VrfId,
        addr: Ipv4Addr,
        mac: Option<[u8; 6]>,
        now: Timestamp,
    ) -> Option<u32> {
        if self.by_lease.is_empty() {
            return None;
        }
        let client = self.clients.get(*self.by_lease.get(&(vrf, addr))?)?;
        (client.is_active(now) && mac == Some(client.mac) && client.short_secs > 0)
            .then_some(client.short_secs)
    }

    /// Notes a message of `mac` on `scope` at `now` for the active rows of the client.
    pub fn note(&self, mac: &[u8; 6], scope: PrefixId, now: Timestamp) {
        if self.clients.is_empty() {
            return;
        }
        for client in self.of_mac(*mac) {
            if !client.is_active(now) {
                continue;
            }
            let at = millis(now);
            client.activity.last.fetch_max(at, Ordering::Relaxed);
            if client.target == Some(scope) {
                client.activity.target.fetch_max(at, Ordering::Relaxed);
            }
        }
    }

    /// What the role saw of `mac` for the move job `job`.
    pub fn activity(&self, job: JobId, mac: &[u8; 6]) -> Option<Activity> {
        self.of_mac(*mac)
            .iter()
            .find(|client| client.job == job)
            .map(MovingImage::activity)
    }

    /// Takes the activity of the rows this image keeps from `previous`, the image it
    /// replaces.
    pub fn adopt(&mut self, previous: &Moving) {
        if previous.clients.is_empty() {
            return;
        }
        for client in &mut self.clients {
            if let Some(old) = previous
                .of_mac(client.mac)
                .iter()
                .find(|old| old.job == client.job)
            {
                client.activity = Arc::clone(&old.activity);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tenko_core::MacAddr;

    use super::*;

    fn t(secs: u64) -> Timestamp {
        "2026-10-26T12:00:00Z"
            .parse::<Timestamp>()
            .expect("time")
            .checked_add(Duration::from_secs(secs))
            .expect("time")
    }

    fn row(
        job: JobId,
        mac: u8,
        lease: Option<MovingLease>,
        target: Option<PrefixId>,
    ) -> MovingClient {
        MovingClient {
            job,
            mac: MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, mac]),
            lease,
            short_secs: 120,
            target,
            until: t(600),
            extended: false,
        }
    }

    #[test]
    fn the_short_lease_holds_for_the_client_of_an_active_row() {
        let vrf = VrfId::generate();
        let addr: Ipv4Addr = "192.0.2.50".parse().expect("addr");
        let job = JobId::generate();
        let moving = Moving::of([&row(job, 0x31, Some(MovingLease { vrf, addr }), None)]);
        let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x31];
        assert_eq!(moving.short_lease(vrf, addr, Some(mac), t(10)), Some(120));
        // Another client, another address, an ended row.
        let other = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x32];
        assert_eq!(moving.short_lease(vrf, addr, Some(other), t(10)), None);
        assert_eq!(
            moving.short_lease(vrf, "192.0.2.51".parse().expect("addr"), Some(mac), t(10)),
            None
        );
        assert_eq!(moving.short_lease(vrf, addr, Some(mac), t(600)), None);
        assert!(
            Moving::default()
                .short_lease(vrf, addr, Some(mac), t(10))
                .is_none()
        );
    }

    #[test]
    fn activity_is_noted_per_client_and_survives_a_new_image() {
        let target = PrefixId::generate();
        let (a, b) = (JobId::generate(), JobId::generate());
        let rows = [
            row(a, 0x31, None, Some(target)),
            row(b, 0x32, None, Some(target)),
        ];
        let moving = Moving::of(&rows);
        let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x31];
        moving.note(&mac, PrefixId::generate(), t(5));
        assert_eq!(
            moving.activity(a, &mac),
            Some(Activity {
                last: Some(t(5)),
                on_target: None
            })
        );
        moving.note(&mac, target, t(7));
        let seen = moving.activity(a, &mac).expect("seen");
        assert_eq!((seen.last, seen.on_target), (Some(t(7)), Some(t(7))));
        let other = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x32];
        assert_eq!(moving.activity(b, &other), Some(Activity::default()));
        // A row past its end notes nothing.
        moving.note(&other, target, t(700));
        assert_eq!(moving.activity(b, &other), Some(Activity::default()));
        // The next image keeps what the rows it keeps saw.
        let mut next = Moving::of(&rows[..1]);
        next.adopt(&moving);
        assert_eq!(next.activity(a, &mac).expect("kept").on_target, Some(t(7)));
        assert_eq!(next.activity(b, &other), None);
    }
}
