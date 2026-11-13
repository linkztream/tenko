//! The serving catalog: everything the query path reads, at one revision, behind one
//! pointer swap.
//!
//! A [`Catalog`] holds the production index ([`ZoneIndex`]), the view table (DNS-20, plan
//! section 2.3) and the forwarding table (longest suffix, DNS-02), all built from the rows
//! of one [`DnsData`] revision. The [`CatalogHandle`] is the swap: workers load the current
//! catalog for each query without a lock (`arc-swap`), and the one writer
//! ([`follow`]) applies the feed's deltas in revision order and stores each new catalog,
//! or builds a new one from a reset and swaps it whole (M1).
//!
//! Beside the tables the lookup reads, the catalog keeps the rows the resolver side reads
//! at the same revision (WP5.1): the forwarding rules, the views (their recursion access
//! list), the access lists and the stub zones (`ZoneKind::Stub`, whose name servers the
//! forwarder learns from the zone's `source`).
//!
//! The policy (WP5.2) is compiled here too ([`PolicyData`]): the RPZ zones from their
//! RRsets and the matcher of the newest version of every list, so that the query path reads
//! the zones, the views and the policy of one revision through one swap.
//!
//! A swap that changes how names leave the authoritative path (a forwarding rule or a stub
//! zone added, changed or removed: [`RouteChanges`]) goes through the [`RouteWatch`] the
//! forwarder registers, which flushes what the old routes taught before the new catalog
//! answers. The writer does it whatever brought the change, so a node that was offline
//! flushes when it catches up.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Arc, PoisonError, RwLock, Weak},
};

use arc_swap::{ArcSwap, Guard};
use ipnet::IpNet;
use tenko_core::{
    Revision,
    dns::{
        Acl, AclId, DnsName, ForwardRule, ForwardRuleId, MatchRule, NegativeTrustAnchor, NtaId,
        QueryTransport, Rtype, ScopeName, TrustAnchor, View, ViewId, Zone, ZoneId, ZoneKind,
    },
};
use tokio_util::sync::CancellationToken;

use crate::{
    feed::{Change, Delta, DnsData, FeedError, FeedEvent, ZoneFeed},
    index::{Index, ScopeOf},
    name,
    policy::PolicyData,
    tree::ZoneIndex,
};

/// What the view table tests about a query.
#[derive(Debug, Clone, Copy)]
pub struct ViewQuery<'a> {
    /// The client address.
    pub client: IpAddr,
    /// The local address the query arrived on.
    pub local: IpAddr,
    /// The transport.
    pub transport: QueryTransport,
    /// The query type.
    pub qtype: Rtype,
    /// The minute of the day in UTC.
    pub minute_of_day: u16,
    /// The query name in lowercase wire form.
    pub qname: &'a [u8],
}

#[derive(Debug, Clone)]
enum Rule {
    Subnet(Vec<IpNet>),
    Transport(u8),
    Interface(Vec<IpAddr>),
    Qtype(Vec<Rtype>),
    Time { from: u16, to: u16 },
    Qname(Vec<Box<[u8]>>),
}

fn transport_bit(transport: QueryTransport) -> u8 {
    match transport {
        QueryTransport::Udp => 1,
        QueryTransport::Tcp => 2,
        QueryTransport::Dot => 4,
        QueryTransport::Doh => 8,
    }
}

/// An address as a view compares it: an IPv4-mapped IPv6 address is its IPv4 address.
fn canonical(address: IpAddr) -> IpAddr {
    address.to_canonical()
}

impl Rule {
    fn compile(rule: &MatchRule) -> Self {
        match rule {
            MatchRule::ClientSubnet { prefixes } => Rule::Subnet(prefixes.clone()),
            MatchRule::Transport { transports } => Rule::Transport(
                transports
                    .iter()
                    .fold(0, |mask, transport| mask | transport_bit(*transport)),
            ),
            MatchRule::Interface { addresses } => {
                Rule::Interface(addresses.iter().copied().map(canonical).collect())
            }
            MatchRule::Qtype { types } => Rule::Qtype(types.clone()),
            MatchRule::TimeOfDay {
                from_minute,
                to_minute,
            } => Rule::Time {
                from: *from_minute,
                to: *to_minute,
            },
            MatchRule::Qname { suffixes } => Rule::Qname(
                suffixes
                    .iter()
                    .map(|suffix| suffix.to_wire().into())
                    .collect(),
            ),
        }
    }

    fn matches(&self, query: &ViewQuery<'_>) -> bool {
        match self {
            Rule::Subnet(prefixes) => {
                let client = canonical(query.client);
                prefixes.iter().any(|prefix| prefix.contains(&client))
            }
            Rule::Transport(mask) => mask & transport_bit(query.transport) != 0,
            Rule::Interface(addresses) => addresses.contains(&canonical(query.local)),
            Rule::Qtype(types) => types.contains(&query.qtype),
            Rule::Time { from, to } => MatchRule::minute_in_window(query.minute_of_day, *from, *to),
            Rule::Qname(suffixes) => suffixes
                .iter()
                .any(|suffix| name::is_within(query.qname, suffix)),
        }
    }
}

/// A view ready for the query path: its compiled rules and its scopes per zone with the
/// cumulative weights.
#[derive(Debug, Clone)]
pub struct CompiledView {
    id: ViewId,
    rules: Vec<Rule>,
    scopes: HashMap<ZoneId, (Vec<(ScopeName, u32)>, u32)>,
}

impl CompiledView {
    fn compile(view: &View) -> Self {
        let mut scopes: HashMap<ZoneId, (Vec<(ScopeName, u32)>, u32)> = HashMap::new();
        for entry in &view.scope_map {
            let (list, total) = scopes.entry(entry.zone).or_default();
            *total += u32::from(entry.weight.max(1));
            list.push((entry.scope.clone(), *total));
        }
        Self {
            id: view.id,
            rules: view.rules.iter().map(Rule::compile).collect(),
            scopes,
        }
    }

    /// The view's id.
    pub fn id(&self) -> ViewId {
        self.id
    }

    fn matches(&self, query: &ViewQuery<'_>) -> bool {
        self.rules.iter().all(|rule| rule.matches(query))
    }
}

/// The views in their order (DNS-20): the first view whose rules all match a query wins; a
/// query no view matches is in the implicit default view.
#[derive(Debug, Clone, Default)]
pub struct ViewTable {
    views: Vec<CompiledView>,
}

impl ViewTable {
    /// Compiles the views of an image, in `order` (then id) order.
    pub fn build<'a>(views: impl IntoIterator<Item = &'a View>) -> Self {
        let mut rows: Vec<&View> = views.into_iter().collect();
        rows.sort_by_key(|view| (view.order, view.id));
        Self {
            views: rows.into_iter().map(CompiledView::compile).collect(),
        }
    }

    /// The number of views.
    pub fn len(&self) -> usize {
        self.views.len()
    }

    /// Whether there are no views (every query is in the implicit default view).
    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    /// The first view whose rules all match; `None` is the implicit default view.
    pub fn select(&self, query: &ViewQuery<'_>) -> Option<&CompiledView> {
        self.views.iter().find(|view| view.matches(query))
    }
}

/// The scopes a query sees: those its view maps, chosen by weight with a value stable per
/// client, and the default scope of every zone the view does not map.
#[derive(Debug, Clone, Copy)]
pub struct ViewScopes<'a> {
    view: Option<&'a CompiledView>,
    pick: u32,
}

impl<'a> ViewScopes<'a> {
    /// The scopes of `view` for a client.
    pub fn new(view: Option<&'a CompiledView>, client: IpAddr) -> Self {
        Self {
            view,
            pick: client_pick(client),
        }
    }
}

/// A value from the client address that stays the same for the client, so that a client
/// sees one scope of a weighted pair and not both in turn.
fn client_pick(client: IpAddr) -> u32 {
    let bits = match canonical(client) {
        IpAddr::V4(v4) => u128::from(v4.to_bits()),
        IpAddr::V6(v6) => v6.to_bits(),
    };
    #[allow(clippy::cast_possible_truncation)]
    let mut h = (bits as u64) ^ ((bits >> 64) as u64);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    #[allow(clippy::cast_possible_truncation)]
    let pick = h as u32;
    pick
}

impl ScopeOf for ViewScopes<'_> {
    fn scope_of(&self, zone: ZoneId) -> &ScopeName {
        let Some((list, total)) = self.view.and_then(|view| view.scopes.get(&zone)) else {
            return &ScopeName::DEFAULT;
        };
        let at = self.pick % (*total).max(1);
        list.iter()
            .find(|(_, upto)| at < *upto)
            .map_or(&ScopeName::DEFAULT, |(scope, _)| scope)
    }
}

#[derive(Debug, Clone)]
struct ForwardEntry {
    suffix: Box<[u8]>,
    labels: usize,
    id: ForwardRuleId,
    view: Option<ViewId>,
}

/// The forwarding rules by suffix: the longest suffix that covers a name wins, a rule of
/// the query's view before a rule of all views.
#[derive(Debug, Clone, Default)]
pub struct ForwardTable {
    rules: Vec<ForwardEntry>,
}

impl ForwardTable {
    /// The table of the rules of an image.
    pub fn build<'a>(rules: impl IntoIterator<Item = &'a ForwardRule>) -> Self {
        let mut rules: Vec<ForwardEntry> = rules
            .into_iter()
            .map(|rule| {
                let suffix: Box<[u8]> = rule.suffix.to_wire().into();
                ForwardEntry {
                    labels: name::label_count(&suffix),
                    suffix,
                    id: rule.id,
                    view: rule.view,
                }
            })
            .collect();
        rules.sort_by(|a, b| {
            b.labels
                .cmp(&a.labels)
                .then(b.view.is_some().cmp(&a.view.is_some()))
                .then(a.id.cmp(&b.id))
        });
        Self { rules }
    }

    /// The rule for `qname` in `view`, if any.
    pub fn find(&self, qname: &[u8], view: Option<ViewId>) -> Option<ForwardRuleId> {
        self.rules
            .iter()
            .find(|rule| {
                rule.view.is_none_or(|only| Some(only) == view)
                    && name::is_within(qname, &rule.suffix)
            })
            .map(|rule| rule.id)
    }

    /// Whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Everything the query path reads, at one revision.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    index: ZoneIndex,
    views: ViewTable,
    forwarders: ForwardTable,
    view_rows: BTreeMap<ViewId, View>,
    forward_rows: BTreeMap<ForwardRuleId, ForwardRule>,
    stub_rows: BTreeMap<ZoneId, Zone>,
    acl_rows: BTreeMap<AclId, Acl>,
    policy: PolicyData,
    // WP10.2: the validator's rows and the revision they last changed at.
    anchor_rows: BTreeMap<DnsName, TrustAnchor>,
    nta_rows: BTreeMap<NtaId, NegativeTrustAnchor>,
    anchors_revision: Revision,
}

/// The stub zones of a set of zone rows.
fn stubs<'a>(zones: impl IntoIterator<Item = (&'a ZoneId, &'a Zone)>) -> BTreeMap<ZoneId, Zone> {
    zones
        .into_iter()
        .filter(|(_, zone)| zone.kind == ZoneKind::Stub)
        .map(|(id, zone)| (*id, zone.clone()))
        .collect()
}

impl Catalog {
    /// Builds the catalog of an image.
    pub fn build(data: &DnsData) -> Self {
        Self {
            index: ZoneIndex::build(data),
            views: ViewTable::build(data.views.values()),
            forwarders: ForwardTable::build(data.forwarders.values()),
            view_rows: data.views.clone(),
            forward_rows: data.forwarders.clone(),
            stub_rows: stubs(&data.zones),
            acl_rows: data.acls.clone(),
            policy: PolicyData::build(data),
            // WP10.2: the validator's rows.
            anchor_rows: data.trust_anchors.clone(),
            nta_rows: data.ntas.clone(),
            anchors_revision: data.revision,
        }
    }

    /// The catalog after a delta; the index shares what the delta does not touch.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] when the delta does not follow this catalog's revision.
    pub fn apply(&self, delta: &Delta) -> Result<Self, FeedError> {
        let index = self.index.apply(delta)?;
        let mut next = Self {
            index,
            views: self.views.clone(),
            forwarders: self.forwarders.clone(),
            view_rows: self.view_rows.clone(),
            forward_rows: self.forward_rows.clone(),
            stub_rows: self.stub_rows.clone(),
            acl_rows: self.acl_rows.clone(),
            policy: self.policy.apply(&delta.changes),
            // WP10.2: the validator's rows.
            anchor_rows: self.anchor_rows.clone(),
            nta_rows: self.nta_rows.clone(),
            anchors_revision: self.anchors_revision,
        };
        let (mut views, mut forwarders) = (false, false);
        for change in &delta.changes {
            match change {
                // WP10.2: the validator's rows.
                Change::TrustAnchor(zone, anchor) => {
                    next.anchors_revision = delta.to;
                    match anchor {
                        Some(anchor) => next.anchor_rows.insert(zone.clone(), anchor.clone()),
                        None => next.anchor_rows.remove(zone),
                    };
                }
                Change::Nta(id, nta) => {
                    next.anchors_revision = delta.to;
                    match nta {
                        Some(nta) => next.nta_rows.insert(*id, nta.clone()),
                        None => next.nta_rows.remove(id),
                    };
                }
                // WP10.2: end.
                Change::View(id, view) => {
                    views = true;
                    match view {
                        Some(view) => next.view_rows.insert(*id, view.clone()),
                        None => next.view_rows.remove(id),
                    };
                }
                Change::Forwarder(id, rule) => {
                    forwarders = true;
                    match rule {
                        Some(rule) => next.forward_rows.insert(*id, rule.clone()),
                        None => next.forward_rows.remove(id),
                    };
                }
                Change::Zone(id, zone) => match zone {
                    Some(zone) if zone.kind == ZoneKind::Stub => {
                        next.stub_rows.insert(*id, zone.clone());
                    }
                    _ => {
                        next.stub_rows.remove(id);
                    }
                },
                Change::Acl(id, acl) => {
                    match acl {
                        Some(acl) => next.acl_rows.insert(*id, acl.clone()),
                        None => next.acl_rows.remove(id),
                    };
                }
                _ => {}
            }
        }
        if views {
            next.views = ViewTable::build(next.view_rows.values());
        }
        if forwarders {
            next.forwarders = ForwardTable::build(next.forward_rows.values());
        }
        Ok(next)
    }

    // WP10.2: the validator's rows.
    /// The trust anchor rows by zone.
    pub fn trust_anchors(&self) -> &BTreeMap<DnsName, TrustAnchor> {
        &self.anchor_rows
    }

    /// The negative trust anchor rows.
    pub fn ntas(&self) -> &BTreeMap<NtaId, NegativeTrustAnchor> {
        &self.nta_rows
    }

    /// The revision at which the trust anchor or negative trust anchor rows last changed.
    pub fn anchors_revision(&self) -> Revision {
        self.anchors_revision
    }
    // WP10.2: end.

    /// The revision of the rows the catalog was built from.
    pub fn revision(&self) -> Revision {
        self.index.revision()
    }

    /// The zone index.
    pub fn index(&self) -> &ZoneIndex {
        &self.index
    }

    /// The view table.
    pub fn views(&self) -> &ViewTable {
        &self.views
    }

    /// The forwarding table.
    pub fn forwarders(&self) -> &ForwardTable {
        &self.forwarders
    }

    /// A forwarding rule by id (the forwarder reads its upstreams).
    pub fn forward_rule(&self, id: ForwardRuleId) -> Option<&ForwardRule> {
        self.forward_rows.get(&id)
    }

    /// The zones of kind stub, in id order.
    pub fn stub_zones(&self) -> impl Iterator<Item = &Zone> {
        self.stub_rows.values()
    }

    /// A stub zone by id.
    pub fn stub_zone(&self, id: ZoneId) -> Option<&Zone> {
        self.stub_rows.get(&id)
    }

    /// An access list by id.
    pub fn acl(&self, id: AclId) -> Option<&Acl> {
        self.acl_rows.get(&id)
    }

    /// A view row by id (its recursion access list).
    pub fn view(&self, id: ViewId) -> Option<&View> {
        self.view_rows.get(&id)
    }

    /// The view rows, in id order.
    pub fn view_rows(&self) -> impl Iterator<Item = &View> {
        self.view_rows.values()
    }

    /// The forwarding rules, in id order.
    pub fn forward_rules(&self) -> impl Iterator<Item = &ForwardRule> {
        self.forward_rows.values()
    }

    /// The compiled policy: RPZ zones and lists.
    pub fn policy(&self) -> &PolicyData {
        &self.policy
    }
}

/// What changed between two catalogs in how names leave the authoritative path: the
/// forwarding rules and stub zones added, removed or changed in what routes a name (a rule's
/// suffix, upstreams, transport, TLS name, view, mode or validation; a stub zone's apex or
/// source servers; a description routes nothing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteChanges {
    /// The names whose answers the old routes may have taught: the suffix of each rule and
    /// the apex of each stub zone before and after, none below another one of the list.
    pub suffixes: Vec<DnsName>,
    /// The rules added, changed or removed.
    pub rules: Vec<ForwardRuleId>,
    /// The stub zones added, changed or removed.
    pub stubs: Vec<ZoneId>,
}

impl RouteChanges {
    /// The changes from `old` to `new`.
    pub fn between(old: &Catalog, new: &Catalog) -> Self {
        let mut changes = Self::default();
        changes.rules = changed(
            &old.forward_rows,
            &new.forward_rows,
            same_route,
            |rule| &rule.suffix,
            &mut changes.suffixes,
        );
        changes.stubs = changed(
            &old.stub_rows,
            &new.stub_rows,
            |before, after| (&before.name, &before.source) == (&after.name, &after.source),
            |zone| &zone.name,
            &mut changes.suffixes,
        );
        changes.suffixes = outermost(std::mem::take(&mut changes.suffixes));
        changes
    }

    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.stubs.is_empty()
    }
}

/// The ids of the rows of `old` and `new` that were added, removed or changed (`alike`
/// false), with the names (`name`) of each before and after added to `names`.
fn changed<Id: Ord + Copy, Row>(
    old: &BTreeMap<Id, Row>,
    new: &BTreeMap<Id, Row>,
    alike: impl Fn(&Row, &Row) -> bool,
    name: impl Fn(&Row) -> &DnsName,
    names: &mut Vec<DnsName>,
) -> Vec<Id> {
    let mut ids: Vec<Id> = old.keys().chain(new.keys()).copied().collect();
    ids.sort_unstable();
    ids.dedup();
    ids.retain(|id| {
        let (before, after) = (old.get(id), new.get(id));
        let differs = before
            .zip(after)
            .is_none_or(|(before, after)| !alike(before, after));
        if differs {
            names.extend(before.into_iter().chain(after).map(|row| name(row).clone()));
        }
        differs
    });
    ids
}

/// `suffixes` without repeats and without any that is below another one of them, the widest
/// first: a flush of the list passes over each entry once, whatever the list holds.
pub(crate) fn outermost(mut suffixes: Vec<DnsName>) -> Vec<DnsName> {
    suffixes.sort_by_key(DnsName::label_count);
    let mut kept: Vec<(DnsName, Vec<u8>)> = Vec::with_capacity(suffixes.len());
    for suffix in suffixes {
        let wire = suffix.to_wire();
        if !kept.iter().any(|(_, above)| name::is_within(&wire, above)) {
            kept.push((suffix, wire));
        }
    }
    kept.into_iter().map(|(suffix, _)| suffix).collect()
}

/// Whether two versions of a forwarding rule route names alike: the same suffix, upstreams,
/// transport, TLS name, view, mode and validation (a description routes nothing).
pub(crate) fn same_route(a: &ForwardRule, b: &ForwardRule) -> bool {
    (
        &a.suffix,
        &a.upstreams,
        &a.transport,
        &a.tls_name,
        &a.view,
        &a.mode,
        a.validate,
    ) == (
        &b.suffix,
        &b.upstreams,
        &b.transport,
        &b.tls_name,
        &b.view,
        &b.mode,
        b.validate,
    )
}

/// Who takes a change of the routes into use: the forwarder, whose caches hold what the
/// old routes taught.
pub trait RouteWatch: Send + Sync {
    /// Makes the catalog of `revision`, whose routes differ from the current one's by
    /// `changes`, current by calling `swap` once, with what the old routes taught gone
    /// before it answers.
    fn swap(&self, changes: &RouteChanges, revision: Revision, swap: &mut dyn FnMut());
}

/// The swap the workers read the catalog through and the writer stores into.
#[derive(Clone)]
pub struct CatalogHandle {
    current: Arc<ArcSwap<Catalog>>,
    watch: Arc<RwLock<Option<Weak<dyn RouteWatch>>>>,
}

impl std::fmt::Debug for CatalogHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogHandle")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl CatalogHandle {
    /// A handle holding `catalog`.
    pub fn new(catalog: Catalog) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(catalog)),
            watch: Arc::new(RwLock::new(None)),
        }
    }

    /// The current catalog, for one query or one batch: no lock, no allocation once the
    /// thread has used the swap before.
    pub fn load(&self) -> Guard<Arc<Catalog>> {
        self.current.load()
    }

    /// The current catalog as an owned pointer (the writer's starting point).
    pub fn load_full(&self) -> Arc<Catalog> {
        self.current.load_full()
    }

    /// Makes `catalog` the current one; through the [`RouteWatch`] when its routes differ.
    pub fn store(&self, catalog: Catalog) {
        let watch = self
            .watch
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);
        let mut next = Some(catalog);
        if let Some(watch) = watch
            && let Some(catalog) = &next
        {
            let changes = RouteChanges::between(&self.current.load(), catalog);
            if !changes.is_empty() {
                let revision = catalog.revision();
                watch.swap(&changes, revision, &mut || {
                    if let Some(catalog) = next.take() {
                        self.current.store(Arc::new(catalog));
                    }
                });
            }
        }
        if let Some(catalog) = next {
            self.current.store(Arc::new(catalog));
        }
    }

    /// Registers who takes route changes into use (the forwarder); the last one counts.
    pub fn watch_routes(&self, watch: Weak<dyn RouteWatch>) {
        *self.watch.write().unwrap_or_else(PoisonError::into_inner) = Some(watch);
    }

    /// The revision served.
    pub fn revision(&self) -> Revision {
        self.current.load().revision()
    }
}

/// Builds the first catalog from the feed's image: what the role does before it listens.
///
/// # Errors
///
/// [`FeedError`] when the feed cannot give its image.
pub async fn initial<F: ZoneFeed>(feed: &mut F) -> Result<CatalogHandle, FeedError> {
    let data = feed.snapshot().await?;
    let catalog = tokio::task::spawn_blocking(move || Catalog::build(&data))
        .await
        .map_err(|error| FeedError::Source(error.to_string()))?;
    Ok(CatalogHandle::new(catalog))
}

/// The writer: applies the feed's deltas in revision order and swaps in each new catalog,
/// rebuilds and swaps on a reset, and asks the feed for a new image when a delta does not
/// follow the revision held. Runs until `stop` is canceled or the feed closes (then the
/// last catalog keeps serving, OPS-02). The work runs on the blocking pool so that a large
/// rebuild never holds a runtime thread.
///
/// # Errors
///
/// [`FeedError`] other than a gap, from the feed.
pub async fn follow<F: ZoneFeed>(
    mut feed: F,
    handle: CatalogHandle,
    stop: CancellationToken,
) -> Result<(), FeedError> {
    loop {
        let event = tokio::select! {
            () = stop.cancelled() => return Ok(()),
            event = feed.next() => event,
        };
        let next = match event {
            Ok(FeedEvent::Delta(delta)) => {
                let current = handle.load_full();
                let applied = tokio::task::spawn_blocking(move || current.apply(&delta))
                    .await
                    .map_err(|error| FeedError::Source(error.to_string()))?;
                match applied {
                    Ok(next) => next,
                    Err(FeedError::Gap { .. }) => {
                        let data = feed.snapshot().await?;
                        rebuild(data).await?
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(FeedEvent::Reset(data)) => rebuild(*data).await?,
            Err(FeedError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        };
        // A change of the routes flushes the caches, a pass over each: not on a runtime
        // thread.
        let handle = handle.clone();
        tokio::task::spawn_blocking(move || handle.store(next))
            .await
            .map_err(|error| FeedError::Source(error.to_string()))?;
    }
}

async fn rebuild(data: DnsData) -> Result<Catalog, FeedError> {
    tokio::task::spawn_blocking(move || Catalog::build(&data))
        .await
        .map_err(|error| FeedError::Source(error.to_string()))
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        dns::{AclEntry, DnsName, PrimaryServer, SecondarySource, SoaDefaults, ZoneScope},
        ipam::Stamp,
        principal::{Principal, SystemComponent},
    };

    use super::*;

    fn stamp() -> Stamp {
        Stamp::new(
            "2026-10-17T12:00:00Z".parse().expect("time"),
            Principal::system(SystemComponent::Dns),
        )
    }

    fn zone(name: &str, kind: ZoneKind) -> Zone {
        let source = (kind != ZoneKind::Primary).then(|| SecondarySource {
            primaries: vec![PrimaryServer {
                address: "192.0.2.53".parse().expect("address"),
                port: 53,
                key: None,
                xot: false,
                tls_name: None,
            }],
        });
        Zone {
            id: ZoneId::generate(),
            name: DnsName::new(name).expect("name"),
            kind,
            tenant: None,
            scopes: vec![ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::default(),
            soa: SoaDefaults::new(
                DnsName::new("ns1.example.test").expect("name"),
                DnsName::new("hostmaster.example.test").expect("name"),
            ),
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: tenko_core::dns::UpdatePolicy::default(),
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source,
            reverse_of: None,
            catalog: false,
            description: None,
            created: stamp(),
            updated: stamp(),
        }
    }

    fn acl(prefix: &str) -> Acl {
        Acl {
            id: AclId::generate(),
            name: "clients".to_owned(),
            entries: vec![AclEntry::Prefix {
                prefix: prefix.parse().expect("prefix"),
                deny: false,
            }],
            description: None,
        }
    }

    fn delta(from: u64, changes: Vec<Change>) -> Delta {
        Delta {
            from: Revision(from),
            to: Revision(from + 1),
            changes,
        }
    }

    fn rule(id: ForwardRuleId, suffix: &str, upstream: &str) -> ForwardRule {
        ForwardRule {
            id,
            suffix: DnsName::new(suffix).expect("suffix"),
            upstreams: vec![tenko_core::dns::Upstream {
                address: upstream.parse().expect("address"),
                port: None,
                path: None,
            }],
            transport: tenko_core::dns::ForwardTransport::Plain,
            tls_name: None,
            view: None,
            mode: tenko_core::dns::RuleMode::Forward,
            validate: true,
            description: None,
        }
    }

    fn routes(rules: &[&ForwardRule], stubs: &[&Zone]) -> Catalog {
        let mut data = DnsData::at(Revision(1));
        for rule in rules {
            data.forwarders.insert(rule.id, (*rule).clone());
        }
        for zone in stubs {
            data.zones.insert(zone.id, (*zone).clone());
        }
        Catalog::build(&data)
    }

    fn suffixes(changes: &RouteChanges) -> Vec<&str> {
        changes.suffixes.iter().map(DnsName::as_str).collect()
    }

    #[test]
    fn route_changes_name_what_a_rule_or_stub_zone_change_concerns() {
        let id = ForwardRuleId::generate();
        let corp = rule(id, "corp.example.test", "192.0.2.53");
        let stub = zone("stub.example.net", ZoneKind::Stub);
        let before = routes(&[&corp], &[&stub]);
        // A description routes nothing; a rebuilt catalog of the same rows changes nothing.
        let described = ForwardRule {
            description: Some("branch".to_owned()),
            ..corp.clone()
        };
        assert!(RouteChanges::between(&before, &routes(&[&described], &[&stub])).is_empty());
        // New upstreams: the rule's suffix.
        let moved = rule(id, "corp.example.test", "192.0.2.54");
        let changes = RouteChanges::between(&before, &routes(&[&moved], &[&stub]));
        assert_eq!(
            (changes.rules.clone(), suffixes(&changes)),
            (vec![id], vec!["corp.example.test"])
        );
        // A new suffix: both, the old one's answers and the new one's.
        let renamed = rule(id, "lab.example.test", "192.0.2.53");
        let changes = RouteChanges::between(&before, &routes(&[&renamed], &[&stub]));
        assert_eq!(
            suffixes(&changes),
            vec!["corp.example.test", "lab.example.test"]
        );
        // A stub zone's servers change, and a rule above it appears: one wide suffix covers
        // both.
        let mut learned = stub.clone();
        learned.source = None;
        let wide = rule(ForwardRuleId::generate(), "example.net", "192.0.2.53");
        let changes = RouteChanges::between(&before, &routes(&[&corp, &wide], &[&learned]));
        assert_eq!(suffixes(&changes), vec!["example.net"]);
        assert_eq!(
            (changes.rules.len(), changes.stubs.clone()),
            (1, vec![stub.id])
        );
        // The root rule covers every name.
        let root = rule(ForwardRuleId::generate(), ".", "192.0.2.53");
        let changes = RouteChanges::between(&before, &routes(&[&moved, &root], &[]));
        assert_eq!(changes.suffixes, vec![DnsName::root()]);
        assert_eq!((changes.rules.len(), changes.stubs.len()), (2, 1));
    }

    #[test]
    fn stub_zones_and_access_lists_follow_the_feed() {
        let primary = zone("example.test", ZoneKind::Primary);
        let stub = zone("stub.example.net", ZoneKind::Stub);
        let list = acl("192.0.2.0/24");
        let mut data = DnsData::at(Revision(1));
        data.zones.insert(primary.id, primary.clone());
        data.zones.insert(stub.id, stub.clone());
        data.acls.insert(list.id, list.clone());
        let catalog = Catalog::build(&data);
        assert_eq!(catalog.stub_zones().count(), 1);
        assert_eq!(catalog.stub_zone(stub.id), Some(&stub));
        assert_eq!(catalog.stub_zone(primary.id), None);
        assert_eq!(catalog.acl(list.id), Some(&list));

        // The stub zone becomes a primary, a second list arrives, the first one goes.
        let mut changed = stub.clone();
        changed.kind = ZoneKind::Primary;
        changed.source = None;
        let second = acl("198.51.100.0/24");
        let next = catalog
            .apply(&delta(
                1,
                vec![
                    Change::Zone(stub.id, Some(changed)),
                    Change::Acl(list.id, None),
                    Change::Acl(second.id, Some(second.clone())),
                ],
            ))
            .expect("delta");
        assert_eq!(next.stub_zones().count(), 0);
        assert_eq!(next.acl(list.id), None);
        assert_eq!(next.acl(second.id), Some(&second));

        // A new stub zone, then its removal.
        let other = zone("other.example.net", ZoneKind::Stub);
        let next = next
            .apply(&delta(2, vec![Change::Zone(other.id, Some(other.clone()))]))
            .expect("delta");
        assert_eq!(next.stub_zone(other.id), Some(&other));
        let next = next
            .apply(&delta(3, vec![Change::Zone(other.id, None)]))
            .expect("delta");
        assert_eq!(next.stub_zones().count(), 0);
    }
}
