//! The change set of an update (RFC 2136 section 3.4, plan sections 2.4 and 2.5).
//!
//! The updates of one zone that wait together are planned in order against one view of
//! the store and committed as one write: each update sees the changes of those before it,
//! each is all or nothing (an update that fails leaves the plan as it was before it), and
//! the write holds every change, one serial step per scope, one journal entry per scope and
//! one `dns.update.apply` audit record per update that changed something. A write the
//! store refuses fails them all (SERVFAIL); nothing is written then.
//!
//! The update section, in order (3.4.2):
//!
//! - **Add** (the zone's class): the record joins its RRset with the update's TTL; a CNAME
//!   or DNAME replaces the one record of its set; a CNAME is ignored at a name that holds
//!   other data and other data at a name that holds a CNAME (3.4.2.2); an SOA is ignored,
//!   since Tenko writes the SOA from the zone settings and moves the serial itself.
//! - **Delete an RRset** (class ANY): the SOA and the NS set at the apex are kept (3.4.2.3).
//! - **Delete a name** (class ANY, type ANY): every RRset of the name; at the apex the SOA
//!   and the NS set stay; the signer's rows follow the change by themselves.
//! - **Delete a record** (class NONE): the last NS record at the apex and the SOA are kept
//!   (3.4.2.4); an RRset left empty is deleted.
//!
//! Every RRset an update changes carries the origin `dynamic` and the name of the update's
//! TSIG key. Origins (2.5): an RRset of origin `ipam` is changed only when the zone's
//! `may_replace_ipam` allows it, an RRset of origin `transfer` or `dnssec` never, and in a
//! zone signed online the types the signer writes are refused; such an update is REFUSED
//! with `dns.update.refused`, its extended error naming the first RRset. A model rule the
//! result breaks (a record set too large, a CNAME beside other data written another way)
//! fails the update: SERVFAIL with the rule in the extended error, nothing of it written.
//!
//! **Ownership** (identity plan section 3.6, DNS-28). In a zone whose ownership rules are on
//! ([`super::policy::ownership_on`]) the planner decides, before the first operation of an
//! update on a name, whether the update's signer may change that name, from the name's
//! owner in `dns.name_owners` and the RRsets it holds:
//!
//! | The name | A GSS-TSIG principal may change it when | and then |
//! |---|---|---|
//! | A locator name (every name of an `_msdcs` zone or under `_msdcs`, a first label `_ldap`, `_kerberos`, `_kpasswd`, `_gc`, `DomainDnsZones` or `ForestDnsZones`, the apex) | it is privileged | no owner is kept |
//! | A wildcard name (`*` first) | it is privileged | no owner is kept |
//! | Owned, the hold not passed | it is the owner (by SID when the owner has one, else by name), or privileged | the owner stays; the hold starts when the last record goes and ends when a record comes back |
//! | Unowned with a manual, IPAM or DHCP record | it is privileged | it becomes the owner |
//! | Unowned with a record imported from AD (origin `ad`) | it is privileged, or it claims its own host: `HOST$` claims `host.<zone>`, and a name whose records are PTR records pointing at `host` in its realm's DNS domain or below | it becomes the owner (`claimed` for a claimant) |
//! | Unowned with dynamic records only, or new (no records, the hold passed, or an owner without a hold whose records went outside the update path) | the zone's lists allow it | it becomes the owner, unless it is a member of `DnsUpdateProxy` |
//!
//! Privileged principals are the members of the zone's privileged groups by SID from the
//! PAC; a privileged principal that writes a name without an owner owns it, as the creator
//! of a name does on Windows, so that no other principal can take a controller's or an
//! administrator's name afterwards. Whoever changes a name without being privileged (its
//! owner, its claimant, a `DnsUpdateProxy` member) changes no `manual`, `ipam` or `dhcp`
//! RRset of it: those stay with privileged principals also beside the owner's records. An update signed with TSIG or unsigned takes no ownership and may not change a name
//! that is owned and held; it removes an owner whose hold has passed. The owner rows are
//! written in the same batch as the records, with their revisions expected, and the audit
//! record carries the decision (`owner`, `privileged`, `claimed`, `proxy`) and the
//! principal with its SID.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        DnsName, NameOwner, NameOwnerKey, Origin, OwnerSource, Rdata, RecordData, RrSet, RrSetKey,
        Rtype, ScopeName, Zone, ZoneId, audit, check_apex, check_node,
        tables::{NAME_OWNERS, RRSETS},
    },
    ipam::Stamp,
    timestamp::Timestamp,
};
use tenko_store::{ReadView, ReadViewExt as _, WriteBatch};

use super::{
    GssIdentity, Signer,
    message::{Prerequisite, Update, UpdateMessage},
    policy::{self, Refusal, UpdateProfile},
    prereq::{self, Records, Unmet},
};
use crate::zone::{
    JournalLimits, Planned, ZoneError, ZoneResult, ZoneService, node,
    records::{self, Diff, origin_name},
    stage_delete, stage_put,
};

/// One update of a group.
#[derive(Debug, Clone)]
pub struct Item<'a> {
    /// The parsed message.
    pub message: &'a UpdateMessage,
    /// The scope the client's view chose.
    pub scope: ScopeName,
    /// Who signed it.
    pub signer: Signer,
    /// The client.
    pub client: IpAddr,
}

// WP13.2: the ownership decision of a name (identity plan section 3.6).
/// What the ownership rules decided for one name of an update, from the weakest to the
/// strongest reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    /// No ownership is involved (a TSIG or unsigned update of an unowned name).
    Unowned,
    /// The principal owns the name, or becomes its owner.
    Owner,
    /// A member of `DnsUpdateProxy` changed an unowned name; it stays unowned.
    Proxy,
    /// The principal claimed an imported name of its own host.
    Claimed,
    /// A privileged principal.
    Privileged,
}

impl Decision {
    /// The value of the audit context `ownership`.
    pub const fn name(self) -> &'static str {
        match self {
            Decision::Unowned => "none",
            Decision::Owner => "owner",
            Decision::Proxy => "proxy",
            Decision::Claimed => "claimed",
            Decision::Privileged => "privileged",
        }
    }
}

/// The owner of a name while the group is planned.
#[derive(Debug, Clone, Default)]
struct OwnerState {
    before: Option<(NameOwner, Revision)>,
    after: Option<NameOwner>,
}

// WP13.4: the locator names are shared with the owner view (`zone::ownership`).
use crate::zone::ownership::{is_locator, keeps_no_owner};

/// Whether `identity` is `owner`: by SID when the owner has one (a ticket without a PAC,
/// which has none, never matches it), by the principal's name otherwise.
fn owns(owner: &NameOwner, identity: &GssIdentity) -> bool {
    owner.is_owner(&identity.principal, identity.sid.as_ref())
}

/// The host label a computer account may claim: `pc01` for `PC01$@REALM`.
fn own_host(identity: &GssIdentity) -> Option<String> {
    let name = identity.principal.without_realm();
    let host = name.strip_suffix('$')?;
    (!host.is_empty() && !host.contains('/') && !host.contains('.'))
        .then(|| host.to_ascii_lowercase())
}

/// Whether the RRsets of `name` carry `host` of the domain `domain` (the DNS name of the
/// claimant's realm): the name is `host.<zone>`, or every record there is a PTR record
/// whose target is `host` in that domain or below it. A PTR to `host` in another domain
/// names another computer, so it is not claimable (WP13.4).
fn carries_host<'a>(
    zone: &DnsName,
    name: &DnsName,
    host: &str,
    domain: Option<&DnsName>,
    rrsets: impl Iterator<Item = &'a RrSet> + Clone,
) -> bool {
    let first_is_host = |of: &DnsName| {
        of.labels()
            .next()
            .is_some_and(|label| label.eq_ignore_ascii_case(host))
    };
    let in_domain = |of: &DnsName| {
        domain.is_some_and(|domain| {
            of.parent()
                .is_some_and(|parent| parent.is_subdomain_of(domain))
        })
    };
    if first_is_host(name) && name.parent().as_ref() == Some(zone) {
        return true;
    }
    let mut any = false;
    for rrset in rrsets {
        if rrset.rtype != Rtype::PTR {
            return false;
        }
        let Ok(records) = rrset.records() else {
            return false;
        };
        for record in records {
            match record {
                RecordData::Ptr { target } if first_is_host(&target) && in_domain(&target) => {
                    any = true;
                }
                _ => return false,
            }
        }
    }
    any
}
// WP13.2: end.

/// Whether `identity` claims `name` as its own host (`HOST$` of a realm whose DNS name
/// holds the host), from the RRsets there.
fn claims_own_host(
    zone: &DnsName,
    name: &DnsName,
    identity: &GssIdentity,
    rrsets: &[&RrSet],
) -> bool {
    let domain = DnsName::new(&identity.principal.realm().as_str().to_ascii_lowercase()).ok();
    own_host(identity).is_some_and(|host| {
        carries_host(zone, name, &host, domain.as_ref(), rrsets.iter().copied())
    })
}

/// What became of one update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Applied (NOERROR once the index holds the write); the counts of records added and
    /// removed and of RRsets changed. All zero for an update that changed nothing.
    Applied {
        /// Records added.
        added: usize,
        /// Records removed.
        removed: usize,
        /// RRsets changed.
        rrsets: usize,
    },
    /// A prerequisite does not hold.
    Unmet(Unmet),
    /// Refused by the policy or the origin rules (REFUSED).
    Refused(String),
    /// A rule of the model broke mid-way (SERVFAIL); nothing of it is written.
    Failed(String),
    /// The zone is gone or is no primary zone of this node any more (NOTAUTH).
    NotAuth(String),
}

impl Outcome {
    /// Whether the update changed something.
    pub fn changed(&self) -> bool {
        matches!(self, Outcome::Applied { rrsets, .. } if *rrsets > 0)
    }
}

type NodeKey = (ScopeName, DnsName);

/// The RRsets of one owner name in one scope while the group is planned.
#[derive(Debug, Clone, Default)]
struct NodeState {
    before: BTreeMap<Rtype, (RrSet, Revision)>,
    after: BTreeMap<Rtype, RrSet>,
}

/// The planner of one group.
struct Planner<'v> {
    view: &'v dyn ReadView,
    zone: Zone,
    stamp: Stamp,
    nodes: BTreeMap<NodeKey, NodeState>,
    /// The RRsets the prerequisites read, with the revision the write expects.
    reads: BTreeMap<RrSetKey, Option<Revision>>,
    // WP13.2: ownership.
    /// Whether the ownership rules apply.
    ownership: bool,
    /// The owners of the names the group touched, when they apply.
    owners: BTreeMap<NodeKey, OwnerState>,
    /// The strongest decision of the last update planned.
    decision: Option<Decision>,
    // WP13.4: what the decision of the name being changed allows.
    /// Whether the operation planned now is a secure update's on a name it may change
    /// without being privileged (as its owner, its claimant or a `DnsUpdateProxy` member):
    /// then it changes no `manual`, `ipam` or `dhcp` RRset of the name.
    unprivileged: bool,
}

/// The nodes of one scope, as the prerequisites see them.
struct ScopeNodes<'p> {
    nodes: &'p BTreeMap<NodeKey, NodeState>,
    scope: &'p ScopeName,
}

impl Records for ScopeNodes<'_> {
    fn rrset(&self, name: &DnsName, rtype: Rtype) -> Option<&[Rdata]> {
        self.nodes
            .get(&(self.scope.clone(), name.clone()))
            .and_then(|node| node.after.get(&rtype))
            .map(|rrset| rrset.rdata.as_slice())
    }

    fn name_in_use(&self, name: &DnsName) -> bool {
        self.nodes
            .get(&(self.scope.clone(), name.clone()))
            .is_some_and(|node| !node.after.is_empty())
    }
}

/// Why one update operation stops the update.
enum Stop {
    Refused(String),
    Store(ZoneError),
}

impl From<ZoneError> for Stop {
    fn from(error: ZoneError) -> Self {
        Stop::Store(error)
    }
}

fn is_dnssec_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::RRSIG | Rtype::NSEC)
}

impl Planner<'_> {
    fn load(&mut self, scope: &ScopeName, name: &DnsName) -> ZoneResult<()> {
        let key = (scope.clone(), name.clone());
        if self.nodes.contains_key(&key) {
            return Ok(());
        }
        let before: BTreeMap<Rtype, (RrSet, Revision)> =
            node(self.view, self.zone.id, scope, name)?
                .into_iter()
                .map(|(rrset, revision)| (rrset.rtype, (rrset, revision)))
                .collect();
        let after = before
            .iter()
            .map(|(rtype, (rrset, _))| (*rtype, rrset.clone()))
            .collect();
        self.nodes.insert(key, NodeState { before, after });
        Ok(())
    }

    fn rrset_key(&self, scope: &ScopeName, name: &DnsName, rtype: Rtype) -> RrSetKey {
        RrSetKey {
            zone: self.zone.id,
            scope: scope.clone(),
            name: name.clone(),
            rtype,
        }
    }

    /// Notes what a prerequisite read, so that the write expects it unchanged.
    fn note_read(&mut self, scope: &ScopeName, prerequisite: &Prerequisite) {
        let name = prerequisite.name();
        let Some(node) = self.nodes.get(&(scope.clone(), name.clone())) else {
            return;
        };
        let mut reads = Vec::new();
        match prerequisite {
            Prerequisite::Exists { rtype, .. }
            | Prerequisite::Equals { rtype, .. }
            | Prerequisite::NotExists { rtype, .. } => {
                reads.push((
                    *rtype,
                    node.before.get(rtype).map(|(_, revision)| *revision),
                ));
            }
            Prerequisite::NameInUse { .. } | Prerequisite::NameNotInUse { .. } => {
                reads.extend(
                    node.before
                        .iter()
                        .map(|(rtype, (_, revision))| (*rtype, Some(*revision))),
                );
            }
        }
        for (rtype, revision) in reads {
            let key = self.rrset_key(scope, name, rtype);
            self.reads.entry(key).or_insert(revision);
        }
    }

    /// Whether the update may change `existing` (or create an RRset of `rtype` when none).
    fn may_change(
        &self,
        name: &DnsName,
        rtype: Rtype,
        existing: Option<&RrSet>,
    ) -> Result<(), Stop> {
        if let Some(reason) =
            crate::dnssec::refused_change(&self.zone, rtype, existing.map(|rrset| rrset.origin))
        {
            return Err(Stop::Refused(format!("{name} {rtype}: {reason}")));
        }
        let Some(existing) = existing else {
            return Ok(());
        };
        // WP13.4: the static records of a name belong to privileged principals only, also
        // beside the records its owner wrote (section 3.6).
        if self.unprivileged
            && matches!(
                existing.origin,
                Origin::Manual | Origin::Ipam | Origin::Dhcp
            )
        {
            return Err(Stop::Refused(format!(
                "{name} {rtype} is a static record ({}); only privileged principals change it",
                origin_name(existing.origin)
            )));
        }
        if existing.origin == Origin::Dynamic
            || Origin::Dynamic.may_replace(existing.origin, &self.zone.update)
        {
            return Ok(());
        }
        Err(Stop::Refused(match existing.origin {
            Origin::Ipam => format!(
                "{name} {rtype} belongs to IPAM; the zone's update policy does not let updates replace it"
            ),
            Origin::Transfer => {
                format!("{name} {rtype} comes from a zone transfer and is read-only")
            }
            other => format!(
                "{name} {rtype} belongs to the origin {} and updates do not replace it",
                origin_name(other)
            ),
        }))
    }

    fn fresh(
        &self,
        scope: &ScopeName,
        name: &DnsName,
        rtype: Rtype,
        ttl: u32,
        rdata: Vec<Rdata>,
        signer: &Signer,
    ) -> RrSet {
        RrSet {
            zone: self.zone.id,
            scope: scope.clone(),
            name: name.clone(),
            rtype,
            ttl,
            rdata,
            origin: Origin::Dynamic,
            key: signer.key().cloned(),
            principal: signer.principal().cloned(),
            updated: self.stamp.clone(),
        }
    }

    // WP13.2: the ownership rules (identity plan section 3.6).
    fn now(&self) -> Timestamp {
        self.stamp.at
    }

    fn load_owner(&mut self, scope: &ScopeName, name: &DnsName) -> ZoneResult<()> {
        let key = (scope.clone(), name.clone());
        if self.owners.contains_key(&key) {
            return Ok(());
        }
        let row = NameOwnerKey {
            zone: self.zone.id,
            scope: scope.clone(),
            name: name.clone(),
        };
        let before = self.view.get_typed(&NAME_OWNERS, &row)?;
        let after = before.as_ref().map(|(owner, _)| owner.clone());
        self.owners.insert(key, OwnerState { before, after });
        Ok(())
    }

    /// Whether `signer` may change `name`, before the update's first operation on it.
    fn decide(&self, signer: &Signer, scope: &ScopeName, name: &DnsName) -> Result<Decision, Stop> {
        let key = (scope.clone(), name.clone());
        let now = self.now();
        let live = self
            .owners
            .get(&key)
            .and_then(|state| state.after.as_ref())
            .filter(|owner| !owner.hold_passed(now));
        let rrsets: Vec<&RrSet> = self
            .nodes
            .get(&key)
            .map(|node| {
                node.after
                    .values()
                    .filter(|rrset| rrset.origin != Origin::Dnssec)
                    .collect()
            })
            .unwrap_or_default();
        let Signer::Gss(identity) = signer else {
            return match live {
                Some(owner) => Err(Stop::Refused(format!(
                    "{name} is owned by {}; an update signed with TSIG or unsigned does not change it",
                    owner.principal
                ))),
                None => Ok(Decision::Unowned),
            };
        };
        let Some(kerberos) = &self.zone.update.kerberos else {
            return Err(Stop::Refused(format!(
                "{name}: the zone takes no GSS-TSIG updates"
            )));
        };
        let privileged = kerberos.is_privileged(&identity.groups);
        if is_locator(&self.zone.name, name) {
            return if privileged {
                Ok(Decision::Privileged)
            } else {
                Err(Stop::Refused(format!(
                    "{name} is a locator name; only privileged principals change it"
                )))
            };
        }
        // A wildcard answers every name of the zone that does not exist: only a privileged
        // principal writes one.
        if name.labels().next() == Some("*") {
            return if privileged {
                Ok(Decision::Privileged)
            } else {
                Err(Stop::Refused(format!(
                    "{name} is a wildcard name; only privileged principals change it"
                )))
            };
        }
        if let Some(owner) = live {
            if owns(owner, identity) {
                return Ok(Decision::Owner);
            }
            if privileged {
                return Ok(Decision::Privileged);
            }
            return Err(Stop::Refused(format!(
                "{name} is owned by {}",
                owner.principal
            )));
        }
        if rrsets
            .iter()
            .any(|rrset| matches!(rrset.origin, Origin::Manual | Origin::Ipam | Origin::Dhcp))
        {
            return if privileged {
                Ok(Decision::Privileged)
            } else {
                Err(Stop::Refused(format!(
                    "{name} holds a static record; only privileged principals change it"
                )))
            };
        }
        if rrsets.iter().any(|rrset| rrset.origin == Origin::Ad) {
            if privileged {
                return Ok(Decision::Privileged);
            }
            return if claims_own_host(&self.zone.name, name, identity, &rrsets) {
                Ok(Decision::Claimed)
            } else {
                Err(Stop::Refused(format!(
                    "{name} was imported without an owner; only a privileged principal or the host it names may claim it"
                )))
            };
        }
        if kerberos.is_update_proxy(&identity.groups) {
            return Ok(Decision::Proxy);
        }
        Ok(Decision::Owner)
    }

    /// The owners after an update that passed: the creator or claimant owns the name, the
    /// hold starts when the last record went and ends when a record came back, an owner
    /// whose hold passed goes.
    fn settle(&mut self, signer: &Signer, decided: &BTreeMap<NodeKey, Decision>) {
        let now = self.now();
        let days = self
            .zone
            .update
            .kerberos
            .as_ref()
            .map_or(0, |kerberos| kerberos.owner_hold_days);
        let hold_until = now
            .checked_add(Duration::from_secs(u64::from(days) * 86_400))
            .unwrap_or(now);
        for (key, decision) in decided {
            let has_records = self.nodes.get(key).is_some_and(|node| {
                node.after
                    .values()
                    .any(|rrset| rrset.origin != Origin::Dnssec)
            });
            let Some(state) = self.owners.get_mut(key) else {
                continue;
            };
            let live = state.after.take().filter(|owner| !owner.hold_passed(now));
            // WP13.4: a privileged principal that writes a name without an owner owns it,
            // as the creator of a name does on Windows; only the names that keep no owner
            // (locator and wildcard names) stay without one.
            let owns_now = match decision {
                Decision::Owner | Decision::Claimed => true,
                Decision::Privileged => !keeps_no_owner(&self.zone.name, &key.1),
                Decision::Unowned | Decision::Proxy => false,
            };
            state.after = match (owns_now, live, signer.gss()) {
                (true, None, Some(identity)) if has_records => Some(NameOwner {
                    sid: identity.sid.clone(),
                    principal: identity.principal.clone(),
                    since: now,
                    hold_until: None,
                    how: if *decision == Decision::Claimed {
                        OwnerSource::Claimed
                    } else {
                        OwnerSource::Created
                    },
                }),
                (_, Some(mut owner), _) => {
                    if has_records {
                        owner.hold_until = None;
                    } else if owner.hold_until.is_none() {
                        owner.hold_until = Some(hold_until);
                    }
                    Some(owner)
                }
                _ => None,
            };
        }
    }
    // WP13.2: end.

    /// Applies one operation to the nodes; `undo` collects the nodes it changes with
    /// their state before the update, for the rollback.
    fn apply_op(
        &mut self,
        item: &Item<'_>,
        op: &Update,
        undo: &mut BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>,
    ) -> Result<(), Stop> {
        let name = op.name();
        self.load(&item.scope, name)?;
        let key = (item.scope.clone(), name.clone());
        let Some(after) = self.nodes.get(&key).map(|node| node.after.clone()) else {
            return Ok(());
        };
        let mut next = after.clone();
        self.edit(item, op, &mut next)?;
        if next != after {
            undo.entry(key.clone()).or_insert(after);
            if let Some(node) = self.nodes.get_mut(&key) {
                node.after = next;
            }
        }
        Ok(())
    }

    /// One operation on the RRsets of its name.
    fn edit(
        &self,
        item: &Item<'_>,
        op: &Update,
        next: &mut BTreeMap<Rtype, RrSet>,
    ) -> Result<(), Stop> {
        let name = op.name();
        let apex = name == &self.zone.name;
        match op {
            Update::Add {
                rtype, ttl, rdata, ..
            } => self.add(item, name, *rtype, *ttl, rdata, next)?,
            Update::DeleteRrset { rtype, .. } => {
                if apex && matches!(*rtype, Rtype::SOA | Rtype::NS) {
                    return Ok(());
                }
                if let Some(existing) = next.get(rtype) {
                    self.may_change(name, *rtype, Some(existing))?;
                    next.remove(rtype);
                }
            }
            Update::DeleteName { .. } => {
                let types: Vec<Rtype> = next.keys().copied().collect();
                for rtype in types {
                    if apex && matches!(rtype, Rtype::SOA | Rtype::NS) {
                        continue;
                    }
                    let Some(existing) = next.get(&rtype) else {
                        continue;
                    };
                    if existing.origin == Origin::Dnssec {
                        continue;
                    }
                    self.may_change(name, rtype, Some(existing))?;
                    next.remove(&rtype);
                }
            }
            Update::DeleteRecord { rtype, rdata, .. } => {
                let Some(existing) = next.get(rtype) else {
                    return Ok(());
                };
                if *rtype == Rtype::SOA
                    || !existing.rdata.contains(rdata)
                    || (apex && *rtype == Rtype::NS && existing.rdata.len() == 1)
                {
                    return Ok(());
                }
                self.may_change(name, *rtype, Some(existing))?;
                let mut records = existing.rdata.clone();
                records.retain(|held| held != rdata);
                if records.is_empty() {
                    next.remove(rtype);
                } else {
                    let ttl = existing.ttl;
                    let rrset = self.fresh(&item.scope, name, *rtype, ttl, records, &item.signer);
                    next.insert(*rtype, rrset);
                }
            }
        }
        Ok(())
    }

    /// Adds a record (3.4.2.2): SOA ignored, the CNAME rules, CNAME and DNAME replaced.
    fn add(
        &self,
        item: &Item<'_>,
        name: &DnsName,
        rtype: Rtype,
        ttl: u32,
        rdata: &Rdata,
        next: &mut BTreeMap<Rtype, RrSet>,
    ) -> Result<(), Stop> {
        if rtype == Rtype::SOA {
            return Ok(());
        }
        let other_data = next
            .keys()
            .any(|held| *held != Rtype::CNAME && !is_dnssec_type(*held));
        if rtype == Rtype::CNAME && other_data {
            return Ok(());
        }
        if rtype != Rtype::CNAME && !is_dnssec_type(rtype) && next.contains_key(&Rtype::CNAME) {
            return Ok(());
        }
        let existing = next.get(&rtype);
        self.may_change(name, rtype, existing)?;
        let records = match existing {
            Some(existing) if !matches!(rtype, Rtype::CNAME | Rtype::DNAME) => {
                let mut records = existing.rdata.clone();
                if !records.contains(rdata) {
                    records.push(rdata.clone());
                }
                records
            }
            _ => vec![rdata.clone()],
        };
        let rrset = self.fresh(&item.scope, name, rtype, ttl, records, &item.signer);
        next.insert(rtype, rrset);
        Ok(())
    }

    fn rollback(&mut self, undo: BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>) {
        for (key, after) in undo {
            if let Some(node) = self.nodes.get_mut(&key) {
                node.after = after;
            }
        }
    }

    /// Decides on `name` for the update of `item` once, before its first operation there.
    fn own(
        &mut self,
        item: &Item<'_>,
        name: &DnsName,
        decided: &mut BTreeMap<NodeKey, Decision>,
    ) -> Result<(), Stop> {
        let key = (item.scope.clone(), name.clone());
        if !self.ownership || decided.contains_key(&key) {
            return Ok(());
        }
        self.load(&item.scope, name)?;
        self.load_owner(&item.scope, name)?;
        // An owner without a hold of a name without records lost them outside the update
        // path (the API, a zone import): the name is new again rather than owned forever.
        // Scavenging (DNS-29) starts the hold itself (identity plan section 3.8).
        let empty = self.nodes.get(&key).is_none_or(|node| {
            node.after
                .values()
                .all(|rrset| rrset.origin == Origin::Dnssec)
        });
        if empty
            && let Some(state) = self.owners.get_mut(&key)
            && state
                .after
                .as_ref()
                .is_some_and(|owner| owner.hold_until.is_none())
        {
            state.after = None;
        }
        let decision = self.decide(&item.signer, &item.scope, name)?;
        decided.insert(key, decision);
        Ok(())
    }

    /// Plans every update of the group in order: the outcome of each and the strongest
    /// ownership decision of each.
    fn run(
        &mut self,
        items: &[Item<'_>],
        admit: &dyn Fn(&Zone, &Item<'_>) -> Result<(), Refusal>,
    ) -> ZoneResult<(Vec<Outcome>, Vec<Option<Decision>>)> {
        let mut outcomes = Vec::with_capacity(items.len());
        let mut decisions = Vec::with_capacity(items.len());
        for item in items {
            self.decision = None;
            let outcome = if let Err(reason) = admit(&self.zone, item) {
                Outcome::Refused(reason.to_owned())
            } else if !self.zone.has_scope(&item.scope) {
                Outcome::Failed(format!("the zone has no scope {}", item.scope))
            } else {
                self.update(item)?
            };
            outcomes.push(outcome);
            decisions.push(self.decision);
        }
        Ok((outcomes, decisions))
    }

    /// Plans one update: its prerequisites, its operations, the model's rules.
    fn update(&mut self, item: &Item<'_>) -> ZoneResult<Outcome> {
        self.decision = None;
        let message = item.message;
        for prerequisite in &message.prerequisites {
            self.load(&item.scope, prerequisite.name())?;
        }
        let checked = prereq::check(
            &message.prerequisites,
            &ScopeNodes {
                nodes: &self.nodes,
                scope: &item.scope,
            },
        );
        for prerequisite in &message.prerequisites {
            self.note_read(&item.scope, prerequisite);
        }
        if let Err(unmet) = checked {
            return Ok(Outcome::Unmet(unmet));
        }
        let mut undo = BTreeMap::new();
        // WP13.2: the ownership decision of each name, before its first operation.
        let mut decided: BTreeMap<NodeKey, Decision> = BTreeMap::new();
        for op in &message.updates {
            let step = self.own(item, op.name(), &mut decided).and_then(|()| {
                self.unprivileged = matches!(
                    decided.get(&(item.scope.clone(), op.name().clone())),
                    Some(Decision::Owner | Decision::Claimed | Decision::Proxy)
                );
                self.apply_op(item, op, &mut undo)
            });
            self.unprivileged = false;
            match step {
                Ok(()) => {}
                Err(Stop::Refused(reason)) => {
                    self.rollback(undo);
                    return Ok(Outcome::Refused(reason));
                }
                Err(Stop::Store(error)) => {
                    self.rollback(undo);
                    return Err(error);
                }
            }
        }
        match self.counts(&undo) {
            Ok((added, removed, rrsets)) => {
                self.settle(&item.signer, &decided);
                self.decision = decided.values().copied().max();
                Ok(Outcome::Applied {
                    added,
                    removed,
                    rrsets,
                })
            }
            Err(reason) => {
                self.rollback(undo);
                Ok(Outcome::Failed(reason))
            }
        }
    }

    /// The model's rules on what an update changed, and its counts of records added and
    /// removed and of RRsets changed.
    fn counts(
        &self,
        undo: &BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>,
    ) -> Result<(usize, usize, usize), String> {
        let (mut added, mut removed, mut rrsets) = (0, 0, 0);
        for (key, before) in undo {
            let Some(node) = self.nodes.get(key) else {
                continue;
            };
            let mut types: BTreeSet<Rtype> = before.keys().copied().collect();
            types.extend(node.after.keys().copied());
            for rtype in types {
                let old = before.get(&rtype);
                let new = node.after.get(&rtype);
                if old == new {
                    continue;
                }
                rrsets += 1;
                if let Some(new) = new {
                    new.check(&self.zone.name)
                        .map_err(|error| error.to_string())?;
                    added += new
                        .rdata
                        .iter()
                        .filter(|data| old.is_none_or(|old| !old.rdata.contains(data)))
                        .count();
                }
                if let Some(old) = old {
                    removed += old
                        .rdata
                        .iter()
                        .filter(|data| new.is_none_or(|new| !new.rdata.contains(data)))
                        .count();
                }
            }
            check_node(&self.zone.name, node.after.values())
                .and_then(|()| {
                    if key.1 == self.zone.name {
                        check_apex(&self.zone.name, node.after.values())
                    } else {
                        Ok(())
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        Ok((added, removed, rrsets))
    }

    /// The changed RRsets against the store's view.
    fn diff(&self) -> Vec<Diff> {
        let mut diff = Vec::new();
        for ((scope, name), node) in &self.nodes {
            let mut types: BTreeSet<Rtype> = node.before.keys().copied().collect();
            types.extend(node.after.keys().copied());
            for rtype in types {
                let before = node.before.get(&rtype).map(|(rrset, _)| rrset);
                let after = node.after.get(&rtype);
                if before == after {
                    continue;
                }
                diff.push(Diff {
                    key: self.rrset_key(scope, name, rtype),
                    before: before.cloned(),
                    after: after.cloned(),
                });
            }
        }
        diff
    }
}

/// The audit record of an applied update.
fn applied_audit(
    zone: &Zone,
    item: &Item<'_>,
    outcome: &Outcome,
    decision: Option<Decision>,
    serial: Option<u32>,
) -> AuditDraft {
    let draft = AuditDraft::success(audit::UPDATE_APPLY, vec![ObjectRef::from(zone.id)])
        .with_source_ip(Some(item.client))
        .with_context("zone", zone.name.as_str())
        .with_context("client", item.client.to_string());
    let mut draft = item
        .signer
        .audit(draft)
        .with_context(
            "prerequisites",
            item.message.prerequisites.len().to_string(),
        )
        .with_context("updates", item.message.updates.len().to_string());
    if let Outcome::Applied {
        added,
        removed,
        rrsets,
    } = outcome
    {
        draft = draft
            .with_context("added", added.to_string())
            .with_context("removed", removed.to_string())
            .with_context("rrsets", rrsets.to_string());
    }
    if item.scope != ScopeName::DEFAULT {
        draft = draft.with_context("scope", item.scope.as_str());
    }
    if let Some(decision) = decision.filter(|decision| *decision != Decision::Unowned) {
        draft = draft.with_context("ownership", decision.name());
    }
    if let Some(serial) = serial {
        draft = draft.with_context("serial", serial.to_string());
    }
    draft
}

// WP13.2: the owner rows of a group.
/// Adds the owners of a group to `batch`: every row read is expected unchanged, the ones
/// that changed are written or deleted.
fn stage_owners(
    batch: &mut WriteBatch,
    zone: ZoneId,
    owners: &BTreeMap<NodeKey, OwnerState>,
) -> ZoneResult<()> {
    for ((scope, name), state) in owners {
        let key = NameOwnerKey {
            zone,
            scope: scope.clone(),
            name: name.clone(),
        };
        batch.expect_typed(
            &NAME_OWNERS,
            &key,
            state.before.as_ref().map(|(_, revision)| *revision),
        );
        if state.before.as_ref().map(|(owner, _)| owner) == state.after.as_ref() {
            continue;
        }
        match &state.after {
            Some(owner) => {
                batch.put_typed(&NAME_OWNERS, &key, owner)?;
            }
            None => {
                batch.delete_typed(&NAME_OWNERS, &key);
            }
        }
    }
    Ok(())
}
// WP13.2: end.

/// Plans the updates `items` of the zone `zone` against `view`: one outcome per update,
/// and the write of every change, or nothing when no update changed anything. `admit` runs
/// the policy again on the zone row of the view.
///
/// # Errors
///
/// The store's error (the whole group fails).
pub(crate) fn plan(
    view: &dyn ReadView,
    zone: ZoneId,
    items: &[Item<'_>],
    admit: &dyn Fn(&Zone, &Item<'_>) -> Result<(), Refusal>,
    cx: &RequestCtx,
    limits: JournalLimits,
    profile: UpdateProfile,
) -> ZoneResult<Planned<Vec<Outcome>>> {
    let row = match ZoneService::zone(view, zone) {
        Ok(row) => row,
        Err(error) if error.is(tenko_core::dns::codes::ZONE_NOT_FOUND) => {
            let outcome = Outcome::NotAuth("the zone is not served here".to_owned());
            return Ok(Planned::nothing(vec![outcome; items.len()]));
        }
        Err(error) => return Err(error),
    };
    let ownership = policy::ownership_on(&row.zone, profile);
    let mut planner = Planner {
        view,
        zone: row.zone,
        stamp: Stamp::new(cx.now, cx.principal.clone()),
        nodes: BTreeMap::new(),
        reads: BTreeMap::new(),
        ownership,
        owners: BTreeMap::new(),
        decision: None,
        unprivileged: false,
    };
    let (outcomes, decisions) = planner.run(items, admit)?;
    let diff = planner.diff();
    if diff.is_empty() {
        return Ok(Planned::nothing(outcomes));
    }
    let mut batch = WriteBatch::for_request(cx);
    let mut expected: BTreeMap<RrSetKey, Option<Revision>> = planner.reads.clone();
    for item in &diff {
        let revision = planner
            .nodes
            .get(&(item.key.scope.clone(), item.key.name.clone()))
            .and_then(|node| node.before.get(&item.key.rtype))
            .map(|(_, revision)| *revision);
        expected.insert(item.key.clone(), revision);
    }
    for (key, revision) in &expected {
        batch.expect_typed(&RRSETS, key, *revision);
    }
    for item in &diff {
        match (&item.before, &item.after) {
            (before, Some(after)) => stage_put(&mut batch, before.as_ref(), after)?,
            (Some(before), None) => stage_delete(&mut batch, before),
            (None, None) => {}
        }
    }
    stage_owners(&mut batch, zone, &planner.owners)?;
    let mut scopes: Vec<&ScopeName> = diff.iter().map(|item| &item.key.scope).collect();
    scopes.sort();
    scopes.dedup();
    let mut serial = None;
    for scope in scopes {
        let (removed, added) =
            records::journal_diff(diff.iter().filter(|item| &item.key.scope == scope));
        let step = records::stage_serial_step(
            &mut batch,
            view,
            &planner.zone,
            scope,
            &planner.stamp,
            limits,
            removed,
            added,
        )?;
        if *scope == ScopeName::DEFAULT || serial.is_none() {
            serial = Some(step.to);
        }
    }
    for ((item, outcome), decision) in items.iter().zip(&outcomes).zip(&decisions) {
        if outcome.changed() {
            batch.audit(applied_audit(
                &planner.zone,
                item,
                outcome,
                *decision,
                serial,
            ));
        }
    }
    let changed = outcomes.iter().filter(|outcome| outcome.changed()).count();
    Ok(Planned::write(
        outcomes,
        batch,
        format!(
            "dynamic update of zone {}: {changed} updates, {} RRsets",
            planner.zone.name,
            diff.len()
        ),
        vec![ObjectRef::from(zone)],
    ))
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        Principal, SystemComponent,
        dns::{PrincipalName, ZoneId},
    };

    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    fn identity(principal: &str) -> GssIdentity {
        GssIdentity {
            principal: PrincipalName::parse(principal).expect("principal"),
            sid: None,
            groups: Vec::new(),
        }
    }

    fn rrset(owner: &str, rtype: Rtype, records: &[RecordData]) -> RrSet {
        RrSet {
            zone: ZoneId::generate(),
            scope: ScopeName::DEFAULT,
            name: name(owner),
            rtype,
            ttl: 300,
            rdata: records.iter().map(Rdata::from_data).collect(),
            origin: Origin::Ad,
            key: None,
            principal: None,
            updated: Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns)),
        }
    }

    fn ptr(target: &str) -> RecordData {
        RecordData::Ptr {
            target: name(target),
        }
    }

    /// DNS-28: the locator names of section 3.6.
    #[test]
    fn dns_28_the_locator_names() {
        let zone = name("corp.example.test");
        for locator in [
            "corp.example.test",
            "_ldap._tcp.corp.example.test",
            "_kerberos._udp.corp.example.test",
            "_kpasswd._tcp.corp.example.test",
            "_gc._tcp.corp.example.test",
            "gc._msdcs.corp.example.test",
            "DomainDnsZones.corp.example.test",
            "forestdnszones.corp.example.test",
        ] {
            assert!(is_locator(&zone, &name(locator)), "{locator}");
        }
        for host in ["pc01.corp.example.test", "ldap.corp.example.test"] {
            assert!(!is_locator(&zone, &name(host)), "{host}");
        }
        let msdcs = name("_msdcs.corp.example.test");
        assert!(is_locator(
            &msdcs,
            &name("dc01-guid._msdcs.corp.example.test")
        ));
    }

    /// DNS-28, R122: `HOST$` claims `host.<zone>` and a name whose records are PTR records
    /// to `host` in the realm's domain; not a name in another place, a user principal, or a PTR to another host.
    #[test]
    fn dns_28_a_computer_claims_only_its_own_host() {
        let zone = name("corp.example.test");
        let pc01 = identity("PC01$@CORP.EXAMPLE.TEST");
        let host = own_host(&pc01).expect("a computer account");
        assert_eq!(host, "pc01");
        assert_eq!(own_host(&identity("alice@CORP.EXAMPLE.TEST")), None);
        let a = rrset("pc01.corp.example.test", Rtype::A, &[]);
        let at = |owner: &str| name(owner);
        assert!(carries_host(
            &zone,
            &at("pc01.corp.example.test"),
            &host,
            Some(&zone),
            [&a].into_iter()
        ));
        assert!(!carries_host(
            &zone,
            &at("pc01.lab.corp.example.test"),
            &host,
            Some(&zone),
            [&a].into_iter()
        ));
        assert!(!carries_host(
            &zone,
            &at("pc02.corp.example.test"),
            &host,
            Some(&zone),
            [&a].into_iter()
        ));
        let reverse = name("2.0.192.in-addr.arpa");
        let own = rrset(
            "21.2.0.192.in-addr.arpa",
            Rtype::PTR,
            &[ptr("PC01.corp.example.test")],
        );
        let other = rrset(
            "22.2.0.192.in-addr.arpa",
            Rtype::PTR,
            &[ptr("pc02.corp.example.test")],
        );
        let mixed = rrset(
            "23.2.0.192.in-addr.arpa",
            Rtype::PTR,
            &[ptr("pc01.corp.example.test"), ptr("pc02.corp.example.test")],
        );
        let ptr_name = at("21.2.0.192.in-addr.arpa");
        assert!(carries_host(
            &reverse,
            &ptr_name,
            &host,
            Some(&zone),
            [&own].into_iter()
        ));
        // WP13.4: a PTR to the same host label in another domain names another computer.
        let elsewhere = rrset(
            "24.2.0.192.in-addr.arpa",
            Rtype::PTR,
            &[ptr("pc01.other.example")],
        );
        assert!(!carries_host(
            &reverse,
            &ptr_name,
            &host,
            Some(&zone),
            [&elsewhere].into_iter()
        ));
        assert!(!carries_host(
            &reverse,
            &ptr_name,
            &host,
            None,
            [&own].into_iter()
        ));
        assert!(!carries_host(
            &reverse,
            &ptr_name,
            &host,
            Some(&zone),
            [&other].into_iter()
        ));
        assert!(!carries_host(
            &reverse,
            &ptr_name,
            &host,
            Some(&zone),
            [&mixed].into_iter()
        ));
        assert!(!carries_host(
            &reverse,
            &ptr_name,
            &host,
            Some(&zone),
            std::iter::empty()
        ));
    }
}
