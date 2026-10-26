//! The DHCP feed (plan section 2.2, ADR 0019 point 5): how the role learns the rows it
//! serves.
//!
//! The role never holds a store handle. A [`DhcpFeed`] gives it one image of the rows at a
//! revision ([`DhcpData`]: the `dhcp` configuration, the leases, and the IPAM rows the
//! pools and reservations derive from) and then the changes after it as [`Delta`]s in
//! revision order, or a new image ([`FeedEvent::Reset`]) when it cannot (a snapshot was
//! installed). From the image the role builds its [`ConfigImage`](crate::image::ConfigImage)
//! and its [`LeaseTable`](crate::lease::LeaseTable). It is the shape of the DNS engine's
//! `ZoneFeed` (ADR 0017). In Phase 3 the production feed is the in-process feed of WP7.5 on
//! the controller's derived index; the node-file feed of a `dhcp` node without a controller
//! is Phase 5. [`MemFeed`] is the reference implementation for tests and the oracle of the
//! image build.

use std::{
    collections::BTreeMap,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, PoisonError},
};

use tenko_core::{
    AddressId, HostId, InterfaceId, JobId, PrefixId, RangeId, Revision, VrfId,
    dhcp::{
        Class, ClassId, DhcpSettings, ExclusionId, ExclusionRange, Filter, FilterId, Lease, Lease6,
        MovingClient, OptionDef, OptionDefId, OptionOwner, OptionSet, Policy, PolicyId,
        PoolSettings, Scope, SharedNetwork, SharedNetworkId,
    },
    ipam::{Address, Host, Interface, Prefix, Range},
};
use tokio::sync::mpsc;

/// Every row the role serves from, at one revision: the tables of the `dhcp` node role
/// (`tenko_core::dhcp::tables::NODE_TABLES`; the client index is derived, not carried) and
/// the IPAM rows of `NODE_IPAM_TABLES` (a feed may carry all IPAM rows; the image uses
/// those of served prefixes and reserved hosts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpData {
    /// The store revision of the image.
    pub revision: Revision,
    /// `dhcp.settings`; none before the first write.
    pub settings: Option<DhcpSettings>,
    /// `dhcp.scopes`.
    pub scopes: BTreeMap<PrefixId, Scope>,
    /// `dhcp.shared_networks`.
    pub shared_networks: BTreeMap<SharedNetworkId, SharedNetwork>,
    /// `dhcp.pools`.
    pub pools: BTreeMap<RangeId, PoolSettings>,
    /// `dhcp.exclusions`.
    pub exclusions: BTreeMap<(PrefixId, ExclusionId), ExclusionRange>,
    /// `dhcp.option_defs`.
    pub option_defs: BTreeMap<OptionDefId, OptionDef>,
    /// `dhcp.option_sets`.
    pub option_sets: BTreeMap<OptionOwner, OptionSet>,
    /// `dhcp.classes`.
    pub classes: BTreeMap<ClassId, Class>,
    /// `dhcp.policies`.
    pub policies: BTreeMap<PolicyId, Policy>,
    /// `dhcp.filters`.
    pub filters: BTreeMap<FilterId, Filter>,
    /// `dhcp.leases`.
    pub leases: BTreeMap<(VrfId, Ipv4Addr), Lease>,
    // WP9.1: the DHCPv6 leases.
    /// `dhcp.leases6`.
    pub leases6: BTreeMap<(VrfId, Ipv6Addr), Lease6>,
    /// `dhcp.moving`: the clients of move jobs (ADR 0027).
    pub moving: BTreeMap<JobId, MovingClient>,
    /// `ipam.prefixes`.
    pub prefixes: BTreeMap<PrefixId, Prefix>,
    /// `ipam.ranges`.
    pub ranges: BTreeMap<RangeId, Range>,
    /// `ipam.hosts`.
    pub hosts: BTreeMap<HostId, Host>,
    /// `ipam.interfaces`.
    pub interfaces: BTreeMap<InterfaceId, Interface>,
    /// `ipam.addresses`.
    pub addresses: BTreeMap<AddressId, Address>,
}

/// One changed row: its key and its value after the change, or `None` when it is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "changes are built once per commit and moved into a delta, never kept in bulk"
)]
pub enum Change {
    /// The server settings.
    Settings(Option<DhcpSettings>),
    /// A scope.
    Scope(PrefixId, Option<Scope>),
    /// A shared network.
    SharedNetwork(SharedNetworkId, Option<SharedNetwork>),
    /// Pool settings.
    Pool(RangeId, Option<PoolSettings>),
    /// An exclusion range.
    Exclusion((PrefixId, ExclusionId), Option<ExclusionRange>),
    /// An option definition.
    OptionDef(OptionDefId, Option<OptionDef>),
    /// An option set.
    OptionSet(OptionOwner, Option<OptionSet>),
    /// A class.
    Class(ClassId, Option<Class>),
    /// A policy.
    Policy(PolicyId, Option<Policy>),
    /// A filter entry.
    Filter(FilterId, Option<Filter>),
    /// A lease.
    Lease((VrfId, Ipv4Addr), Option<Lease>),
    // WP9.1: a DHCPv6 lease.
    /// A DHCPv6 lease.
    Lease6((VrfId, Ipv6Addr), Option<Lease6>),
    /// A client of a move job (ADR 0027); part of the configuration image.
    Moving(JobId, Option<MovingClient>),
    /// An IPAM prefix.
    Prefix(PrefixId, Option<Prefix>),
    /// An IPAM range.
    Range(RangeId, Option<Range>),
    /// An IPAM host.
    Host(HostId, Option<Host>),
    /// An IPAM interface.
    Interface(InterfaceId, Option<Interface>),
    /// An IPAM address.
    Address(AddressId, Option<Address>),
}

impl Change {
    /// Whether the change is to a lease (the lease table's part of a delta) rather than to
    /// the configuration (the image's part).
    pub fn is_lease(&self) -> bool {
        matches!(self, Self::Lease(..) | Self::Lease6(..))
    }
}

fn set<K: Ord + Clone, V: Clone>(map: &mut BTreeMap<K, V>, key: &K, value: Option<&V>) {
    match value {
        Some(value) => {
            map.insert(key.clone(), value.clone());
        }
        None => {
            map.remove(key);
        }
    }
}

impl DhcpData {
    /// An empty image at a revision.
    pub fn at(revision: Revision) -> Self {
        Self {
            revision,
            ..Self::default()
        }
    }

    /// Applies one change.
    pub fn apply_change(&mut self, change: &Change) {
        match change {
            Change::Settings(value) => self.settings.clone_from(value),
            Change::Scope(key, value) => set(&mut self.scopes, key, value.as_ref()),
            Change::SharedNetwork(key, value) => {
                set(&mut self.shared_networks, key, value.as_ref());
            }
            Change::Pool(key, value) => set(&mut self.pools, key, value.as_ref()),
            Change::Exclusion(key, value) => set(&mut self.exclusions, key, value.as_ref()),
            Change::OptionDef(key, value) => set(&mut self.option_defs, key, value.as_ref()),
            Change::OptionSet(key, value) => set(&mut self.option_sets, key, value.as_ref()),
            Change::Class(key, value) => set(&mut self.classes, key, value.as_ref()),
            Change::Policy(key, value) => set(&mut self.policies, key, value.as_ref()),
            Change::Filter(key, value) => set(&mut self.filters, key, value.as_ref()),
            Change::Lease(key, value) => set(&mut self.leases, key, value.as_ref()),
            Change::Lease6(key, value) => set(&mut self.leases6, key, value.as_ref()),
            Change::Moving(key, value) => set(&mut self.moving, key, value.as_ref()),
            Change::Prefix(key, value) => set(&mut self.prefixes, key, value.as_ref()),
            Change::Range(key, value) => set(&mut self.ranges, key, value.as_ref()),
            Change::Host(key, value) => set(&mut self.hosts, key, value.as_ref()),
            Change::Interface(key, value) => set(&mut self.interfaces, key, value.as_ref()),
            Change::Address(key, value) => set(&mut self.addresses, key, value.as_ref()),
        }
    }

    /// Applies a delta that starts at this image's revision.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] when the delta does not start at this revision or does not move
    /// forward; the image is unchanged.
    pub fn apply(&mut self, delta: &Delta) -> Result<(), FeedError> {
        if delta.from != self.revision || delta.to <= delta.from {
            return Err(FeedError::Gap {
                held: self.revision,
                from: delta.from,
            });
        }
        for change in &delta.changes {
            self.apply_change(change);
        }
        self.revision = delta.to;
        Ok(())
    }
}

/// The changes between two revisions. Rows are whole values: applying a change twice
/// changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// The revision the delta starts from.
    pub from: Revision,
    /// The revision after it.
    pub to: Revision,
    /// The changed rows, in commit order.
    pub changes: Vec<Change>,
}

/// What a feed delivers after the first image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedEvent {
    /// The changes after the revision the role holds.
    Delta(Delta),
    /// A new image that replaces everything; the role rebuilds both tables and swaps them
    /// at once (WP7.5).
    Reset(Box<DhcpData>),
}

/// Why a feed failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The source went away; the role keeps serving what it holds (OPS-02).
    #[error("the DHCP feed is closed")]
    Closed,
    /// A delta does not follow the revision held.
    #[error("a delta from revision {from} does not follow revision {held}")]
    Gap {
        /// The revision held.
        held: Revision,
        /// The revision the delta starts at.
        from: Revision,
    },
    /// The source could not be read.
    #[error("the DHCP feed failed: {0}")]
    Source(String),
}

/// The source of the rows the role serves.
pub trait DhcpFeed: Send {
    /// The current image. The role builds its tables from it before it listens.
    ///
    /// # Errors
    ///
    /// [`FeedError`] when the source cannot be read.
    fn snapshot(&mut self) -> impl Future<Output = Result<DhcpData, FeedError>> + Send;

    /// Waits for what follows the image or the last event: a delta starting at its
    /// revision, or a reset.
    ///
    /// # Errors
    ///
    /// [`FeedError::Closed`] when the source went away.
    fn next(&mut self) -> impl Future<Output = Result<FeedEvent, FeedError>> + Send;
}

#[derive(Debug)]
struct Shared {
    data: DhcpData,
}

/// The in-memory reference feed: [`MemFeedHandle::publish`] commits changes to its image
/// and hands them to the feed as one delta.
#[derive(Debug)]
pub struct MemFeed {
    shared: Arc<Mutex<Shared>>,
    events: mpsc::UnboundedReceiver<FeedEvent>,
    held: Revision,
}

/// The writing side of a [`MemFeed`].
#[derive(Debug, Clone)]
pub struct MemFeedHandle {
    shared: Arc<Mutex<Shared>>,
    events: mpsc::UnboundedSender<FeedEvent>,
}

impl MemFeed {
    /// A feed whose first image is `data`, and its handle.
    pub fn new(data: DhcpData) -> (MemFeed, MemFeedHandle) {
        let held = data.revision;
        let shared = Arc::new(Mutex::new(Shared { data }));
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            MemFeed {
                shared: Arc::clone(&shared),
                events: receiver,
                held,
            },
            MemFeedHandle {
                shared,
                events: sender,
            },
        )
    }
}

impl MemFeedHandle {
    /// Commits `changes` as the next revision and returns it.
    pub fn publish(&self, changes: Vec<Change>) -> Revision {
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let from = shared.data.revision;
        let delta = Delta {
            from,
            to: from.next(),
            changes,
        };
        for change in &delta.changes {
            shared.data.apply_change(change);
        }
        shared.data.revision = delta.to;
        let to = delta.to;
        // A dropped feed is no error for the writer.
        let _ = self.events.send(FeedEvent::Delta(delta));
        to
    }

    /// Replaces the image, as a snapshot install does.
    pub fn reset(&self, data: DhcpData) {
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        shared.data = data.clone();
        let _ = self.events.send(FeedEvent::Reset(Box::new(data)));
    }

    /// The current image.
    pub fn image(&self) -> DhcpData {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .data
            .clone()
    }
}

impl DhcpFeed for MemFeed {
    fn snapshot(&mut self) -> impl Future<Output = Result<DhcpData, FeedError>> + Send {
        let data = self
            .shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .data
            .clone();
        self.held = data.revision;
        std::future::ready(Ok(data))
    }

    async fn next(&mut self) -> Result<FeedEvent, FeedError> {
        loop {
            let event = self.events.recv().await.ok_or(FeedError::Closed)?;
            match &event {
                // A delta the image already holds.
                FeedEvent::Delta(delta) if delta.to <= self.held => {}
                FeedEvent::Delta(delta) => {
                    self.held = delta.to;
                    return Ok(event);
                }
                FeedEvent::Reset(data) => {
                    self.held = data.revision;
                    return Ok(event);
                }
            }
        }
    }
}
