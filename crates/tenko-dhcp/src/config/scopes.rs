//! Scopes (`dhcp.scopes`, keyed by the IPAM prefix they serve), their explicit exclusion
//! ranges (`dhcp.exclusions`) and how full a scope is.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use tenko_core::{
    PrefixId, RequestCtx, Revision, Timestamp,
    audit::AuditDraft,
    codec::key::encode_key,
    dhcp::{
        BindingState, ClassId, DdnsPolicy, ExclusionId, ExclusionRange, Lease, LeaseTimes,
        OptionOwner, Scope, SharedNetworkId, audit, codes, scope_object,
        tables::{CLASSES, EXCLUSIONS, LEASES, POLICIES, POOLS, SCOPES, SHARED_NETWORKS},
    },
    ipam::{Prefix, RangeRole},
};
use tenko_ipam::tables::PREFIXES;
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    ConfigError, ConfigResult, ConfigService, Planned, Written, check_expect, delete_option_set,
    image::build,
    live_prefix,
    load::{address_range, ranges_of, scope_data},
    stamp, text,
};
use crate::image::ScopeImage;

/// A scope as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRow {
    /// The scope.
    pub scope: Scope,
    /// The prefix it serves.
    pub prefix: Prefix,
    /// Its pools (live ranges of role `dhcp_pool`).
    pub pools: u32,
    /// Its active leases.
    pub leases: u64,
    /// The revision of the row.
    pub revision: Revision,
}

/// A new scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScope {
    /// The prefix to serve.
    pub prefix: PrefixId,
    /// Whether it serves clients; true when none.
    pub enabled: Option<bool>,
    /// Lease times; the server's when none.
    pub lease: Option<LeaseTimes>,
    /// Authoritative; the server's setting when none.
    pub authoritative: Option<bool>,
    /// The server identifier.
    pub server_id: Option<IpAddr>,
    /// DDNS; the server's DDNS settings when none.
    pub ddns: Option<DdnsPolicy>,
    /// The shared network.
    pub shared_network: Option<SharedNetworkId>,
    /// Only clients an allow filter matches are served.
    pub restricted: bool,
    /// The classes it admits.
    pub classes: Vec<ClassId>,
    /// Free text.
    pub description: Option<String>,
    // WP9.1: the DHCPv6 settings of a scope on an IPv6 prefix.
    /// The DHCPv6 settings; none: the defaults.
    pub v6: Option<tenko_core::dhcp::Scope6Settings>,
}

/// Changes to a scope; the prefix does not change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeChange {
    /// Whether it serves clients.
    pub enabled: Option<bool>,
    /// Lease times.
    pub lease: Option<LeaseTimes>,
    /// Drop the scope's lease times (the server's apply).
    pub clear_lease: bool,
    /// Authoritative.
    pub authoritative: Option<bool>,
    /// The server identifier.
    pub server_id: Option<IpAddr>,
    /// DDNS.
    pub ddns: Option<DdnsPolicy>,
    /// The shared network; `Some(None)` leaves it.
    pub shared_network: Option<Option<SharedNetworkId>>,
    /// Only allowed clients are served.
    pub restricted: Option<bool>,
    /// The classes it admits.
    pub classes: Option<Vec<ClassId>>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
    // WP9.1: the DHCPv6 settings; `Some(None)` clears them.
    /// The DHCPv6 settings of a scope on an IPv6 prefix; `Some(None)` drops them.
    pub v6: Option<Option<tenko_core::dhcp::Scope6Settings>>,
}

/// An exclusion range as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionRow {
    /// The range.
    pub exclusion: ExclusionRange,
    /// The revision of the row.
    pub revision: Revision,
}

/// How full a scope is (IPAM-10).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Utilization {
    /// Pool addresses a client can hold: the dynamic ones (in a pool, not excluded) and the
    /// reserved ones.
    pub pool_size: u64,
    /// Dynamic pool addresses with an active lease.
    pub leased: u64,
    /// Pool addresses held by a reservation.
    pub reserved: u64,
    /// Dynamic pool addresses abandoned after a DECLINE or a conflict.
    pub abandoned: u64,
    /// Pool addresses free now.
    pub free: u64,
    /// `(pool_size - free) / pool_size`, 0 for an empty pool.
    pub utilization: f64,
}

pub(crate) fn scope_not_found(prefix: PrefixId) -> ConfigError {
    ConfigError::new(
        codes::SCOPE_NOT_FOUND,
        404,
        format!("prefix {prefix} has no DHCP scope"),
    )
    .param("prefix", prefix.to_string())
}

/// The scope of a prefix with its revision.
pub(crate) fn scope_of(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<(Scope, Revision)> {
    view.get_typed(&SCOPES, &prefix)?
        .ok_or_else(|| scope_not_found(prefix))
}

/// Checks that the shared network exists and stages the expectation of its version.
pub(crate) fn expect_shared_network(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    id: SharedNetworkId,
) -> ConfigResult<()> {
    let (_, revision) = view.get_typed(&SHARED_NETWORKS, &id)?.ok_or_else(|| {
        ConfigError::not_found(codes::SHARED_NETWORK_NOT_FOUND, "shared network", id)
    })?;
    batch.expect_typed(&SHARED_NETWORKS, &id, Some(revision));
    Ok(())
}

/// Checks that the classes exist and stages the expectation of their versions, so a class
/// deleted meanwhile makes the batch stale.
pub(crate) fn expect_classes(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    classes: &[ClassId],
) -> ConfigResult<()> {
    for id in classes {
        let (_, revision) = view
            .get_typed(&CLASSES, id)?
            .ok_or_else(|| ConfigError::not_found(codes::CLASS_NOT_FOUND, "class", id))?;
        batch.expect_typed(&CLASSES, id, Some(revision));
    }
    Ok(())
}

/// The active leases per scope.
fn active_leases(view: &dyn ReadView, range: KeyRange) -> ConfigResult<BTreeMap<PrefixId, u64>> {
    let mut counts = BTreeMap::new();
    for (_, lease, _) in view.scan_typed(&LEASES, range, usize::MAX, false)? {
        let lease: Lease = lease;
        if lease.state == BindingState::Active {
            *counts.entry(lease.scope).or_default() += 1;
        }
    }
    Ok(counts)
}

/// The leases of a scope's network.
pub(crate) fn leases_of(view: &dyn ReadView, prefix: &Prefix) -> ConfigResult<Vec<Lease>> {
    let ipnet::IpNet::V4(net) = prefix.cidr else {
        return Ok(Vec::new());
    };
    Ok(view
        .scan_typed(
            &LEASES,
            address_range(prefix.vrf, net.network(), net.broadcast()),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, lease, _)| lease)
        .filter(|lease: &Lease| lease.scope == prefix.id)
        .collect())
}

fn pool_count(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<u32> {
    let count = ranges_of(view, prefix)?
        .iter()
        .filter(|(range, _)| range.role == RangeRole::DhcpPool)
        .count();
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

fn row(
    view: &dyn ReadView,
    scope: Scope,
    revision: Revision,
    leases: u64,
) -> ConfigResult<Option<ScopeRow>> {
    let Some((prefix, _)) = view.get_typed(&PREFIXES, &scope.prefix)? else {
        return Ok(None);
    };
    Ok(Some(ScopeRow {
        pools: pool_count(view, scope.prefix)?,
        prefix,
        scope,
        leases,
        revision,
    }))
}

/// The number of addresses from `first` to `last`.
fn span(first: Ipv4Addr, last: Ipv4Addr) -> u64 {
    u64::from(u32::from(last)).saturating_sub(u64::from(u32::from(first))) + 1
}

/// The dynamic addresses of a pool: neither excluded nor the network or broadcast address.
pub(crate) fn dynamic_size(scope: &ScopeImage, first: Ipv4Addr, last: Ipv4Addr) -> u64 {
    let mut size = span(first, last);
    for (from, to) in &scope.excluded {
        let low = (*from).max(first);
        let high = (*to).min(last);
        if low <= high {
            size -= span(low, high);
        }
    }
    for edge in [scope.network.network(), scope.network.broadcast()] {
        if first <= edge
            && edge <= last
            && !scope.excluded.iter().any(|(a, b)| *a <= edge && edge <= *b)
        {
            size -= 1;
        }
    }
    size
}

impl ConfigService {
    /// Every scope, by network, with its pools and active leases.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn scopes(view: &dyn ReadView) -> ConfigResult<Vec<ScopeRow>> {
        let leases = active_leases(view, KeyRange::all())?;
        let mut rows = Vec::new();
        for (prefix, scope, revision) in
            view.scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)?
        {
            if let Some(row) = row(
                view,
                scope,
                revision,
                leases.get(&prefix).copied().unwrap_or(0),
            )? {
                rows.push(row);
            }
        }
        rows.sort_by_key(|row| {
            (
                row.prefix.cidr.network(),
                row.prefix.cidr.prefix_len(),
                row.scope.prefix,
            )
        });
        Ok(rows)
    }

    /// One scope.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, or the store's error.
    pub fn scope(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<ScopeRow> {
        let (scope, revision) = scope_of(view, prefix)?;
        let Some((cidr_row, _)) = view.get_typed(&PREFIXES, &prefix)? else {
            return Err(scope_not_found(prefix));
        };
        let leases = leases_of(view, &cidr_row)?
            .iter()
            .filter(|lease| lease.state == BindingState::Active)
            .count();
        row(
            view,
            scope,
            revision,
            u64::try_from(leases).unwrap_or(u64::MAX),
        )?
        .ok_or_else(|| scope_not_found(prefix))
    }

    /// Creates the scope of a prefix.
    ///
    /// # Errors
    ///
    /// `ipam.not_found` for a missing prefix, `dhcp.scope.exists`, `dhcp.scope.not_network`,
    /// `dhcp.scope.invalid`, `dhcp.lease_times.invalid`, `dhcp.ddns.invalid`,
    /// `dhcp.shared_network.not_found`, `dhcp.class.not_found`, or a store or job error.
    pub async fn create_scope(
        &self,
        cx: &RequestCtx,
        new: NewScope,
    ) -> ConfigResult<(Scope, Written)> {
        self.execute_write(cx, |view| {
            let (prefix, prefix_revision) = live_prefix(view, new.prefix)?;
            if view.get_typed(&SCOPES, &new.prefix)?.is_some() {
                return Err(ConfigError::new(
                    codes::SCOPE_EXISTS,
                    409,
                    format!("{} has a DHCP scope already", prefix.cidr),
                )
                .param("prefix", prefix.cidr.to_string()));
            }
            let settings = Self::settings(view)?.settings;
            let now = stamp(cx);
            let scope = Scope {
                prefix: new.prefix,
                enabled: new.enabled.unwrap_or(true),
                lease: new.lease,
                authoritative: new.authoritative,
                server_id: new.server_id,
                ddns: new.ddns.clone().unwrap_or(settings.ddns),
                shared_network: new.shared_network,
                restricted: new.restricted,
                classes: new.classes.clone(),
                description: text(new.description.as_deref()),
                // WP9.1: the DHCPv6 settings.
                v6: new.v6.clone(),
                created: now.clone(),
                updated: now,
            };
            scope.validate(&prefix)?;
            // Slice 8 follow-ups: no `replace` under Hardened, the server's default included.
            self.refuse_replace(view, Some(&scope.ddns), "ddns")?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&PREFIXES, &new.prefix, Some(prefix_revision));
            batch.expect_typed(&SCOPES, &new.prefix, None);
            if let Some(network) = scope.shared_network {
                expect_shared_network(view, &mut batch, network)?;
            }
            expect_classes(view, &mut batch, &scope.classes)?;
            batch.put_typed(&SCOPES, &new.prefix, &scope)?;
            batch.audit(
                AuditDraft::success(audit::SCOPE_CREATE, vec![scope_object(new.prefix)])
                    .with_source_ip(cx.source_ip)
                    .with_context("cidr", prefix.cidr.to_string()),
            );
            Ok(Planned::write(
                scope.clone(),
                batch,
                format!("create the DHCP scope of {}", prefix.cidr),
                vec![scope_object(new.prefix)],
            ))
        })
        .await
    }

    /// Changes a scope; with `expect`, only the row at that revision.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, the validation codes of [`ConfigService::create_scope`],
    /// 412 when `expect` is stale, or a store or job error.
    pub async fn update_scope(
        &self,
        cx: &RequestCtx,
        prefix: PrefixId,
        change: ScopeChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(Scope, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = scope_of(view, prefix)?;
            check_expect(expect, revision)?;
            let (cidr_row, prefix_revision) = live_prefix(view, prefix)?;
            let mut after = before.clone();
            if let Some(enabled) = change.enabled {
                after.enabled = enabled;
            }
            if change.clear_lease {
                after.lease = None;
            }
            if let Some(lease) = change.lease {
                after.lease = Some(lease);
            }
            if let Some(authoritative) = change.authoritative {
                after.authoritative = Some(authoritative);
            }
            if let Some(server_id) = change.server_id {
                after.server_id = Some(server_id);
            }
            if let Some(ddns) = &change.ddns {
                // Slice 8 follow-ups: no `replace` under Hardened.
                self.refuse_replace(view, Some(ddns), "ddns")?;
                after.ddns.clone_from(ddns);
            }
            if let Some(network) = change.shared_network {
                after.shared_network = network;
            }
            if let Some(restricted) = change.restricted {
                after.restricted = restricted;
            }
            if let Some(classes) = &change.classes {
                after.classes.clone_from(classes);
            }
            if let Some(description) = &change.description {
                after.description = text(Some(description));
            }
            // WP9.1: the DHCPv6 settings.
            if let Some(v6) = &change.v6 {
                after.v6.clone_from(v6);
            }
            after.validate(&cidr_row)?;
            if after == before {
                return Ok(Planned::nothing(after));
            }
            after.updated = stamp(cx);
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&SCOPES, &prefix, Some(revision));
            batch.expect_typed(&PREFIXES, &prefix, Some(prefix_revision));
            if let Some(network) = after.shared_network {
                expect_shared_network(view, &mut batch, network)?;
            }
            expect_classes(view, &mut batch, &after.classes)?;
            batch.put_typed(&SCOPES, &prefix, &after)?;
            batch.audit(
                AuditDraft::success(audit::SCOPE_UPDATE, vec![scope_object(prefix)])
                    .with_source_ip(cx.source_ip)
                    .with_context("cidr", cidr_row.cidr.to_string()),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the DHCP scope of {}", cidr_row.cidr),
                vec![scope_object(prefix)],
            ))
        })
        .await
    }

    /// Deletes a scope with its exclusions, the settings and option sets of its pools, its
    /// policies and their option sets, and its own option set; the prefix and its ranges
    /// stay.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete_scope(
        &self,
        cx: &RequestCtx,
        prefix: PrefixId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (_, revision) = scope_of(view, prefix)?;
                check_expect(expect, revision)?;
                let cidr = view
                    .get_typed(&PREFIXES, &prefix)?
                    .map_or_else(|| prefix.to_string(), |(row, _)| row.cidr.to_string());
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&SCOPES, &prefix, Some(revision));
                batch.delete_typed(&SCOPES, &prefix);
                delete_option_set(view, &mut batch, OptionOwner::Scope(prefix))?;
                for (key, _, revision) in view.scan_typed(
                    &EXCLUSIONS,
                    KeyRange::prefix(encode_key(&prefix)),
                    usize::MAX,
                    false,
                )? {
                    batch.expect_typed(&EXCLUSIONS, &key, Some(revision));
                    batch.delete_typed(&EXCLUSIONS, &key);
                }
                for (range, _) in ranges_of(view, prefix)? {
                    if let Some((_, revision)) = view.get_typed(&POOLS, &range.id)? {
                        batch.expect_typed(&POOLS, &range.id, Some(revision));
                        batch.delete_typed(&POOLS, &range.id);
                    }
                    delete_option_set(view, &mut batch, OptionOwner::Pool(range.id))?;
                }
                for (id, policy, revision) in
                    view.scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)?
                {
                    if policy.scope == Some(prefix) {
                        batch.expect_typed(&POLICIES, &id, Some(revision));
                        batch.delete_typed(&POLICIES, &id);
                        delete_option_set(view, &mut batch, OptionOwner::Policy(id))?;
                    }
                }
                batch.audit(
                    AuditDraft::success(audit::SCOPE_DELETE, vec![scope_object(prefix)])
                        .with_source_ip(cx.source_ip)
                        .with_context("cidr", cidr.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the DHCP scope of {cidr}"),
                    vec![scope_object(prefix)],
                ))
            })
            .await?;
        Ok(written)
    }

    /// The explicit exclusion ranges of a scope, by first address.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, or the store's error.
    pub fn exclusions(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<Vec<ExclusionRow>> {
        scope_of(view, prefix)?;
        let mut rows: Vec<ExclusionRow> = view
            .scan_typed(
                &EXCLUSIONS,
                KeyRange::prefix(encode_key(&prefix)),
                usize::MAX,
                false,
            )?
            .into_iter()
            .map(|(_, exclusion, revision)| ExclusionRow {
                exclusion,
                revision,
            })
            .collect();
        rows.sort_by_key(|row| (row.exclusion.first, row.exclusion.last, row.exclusion.id));
        Ok(rows)
    }

    /// Adds an exclusion range to a scope.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, `dhcp.exclusion.invalid`, or a store or job error.
    pub async fn create_exclusion(
        &self,
        cx: &RequestCtx,
        prefix: PrefixId,
        first: IpAddr,
        last: IpAddr,
        description: Option<String>,
    ) -> ConfigResult<(ExclusionRange, Written)> {
        let id = ExclusionId::generate();
        self.execute_write(cx, |view| {
            let (_, scope_revision) = scope_of(view, prefix)?;
            let (cidr_row, _) = live_prefix(view, prefix)?;
            let exclusion = ExclusionRange {
                id,
                scope: prefix,
                first,
                last,
                description: text(description.as_deref()),
                created: stamp(cx),
            };
            exclusion.validate(&cidr_row)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&SCOPES, &prefix, Some(scope_revision));
            batch.expect_typed(&EXCLUSIONS, &(prefix, id), None);
            batch.put_typed(&EXCLUSIONS, &(prefix, id), &exclusion)?;
            batch.audit(
                AuditDraft::success(audit::EXCLUSION_CREATE, vec![scope_object(prefix)])
                    .with_source_ip(cx.source_ip)
                    .with_context("exclusion", id.to_string())
                    .with_context("range", format!("{first}-{last}")),
            );
            Ok(Planned::write(
                exclusion.clone(),
                batch,
                format!(
                    "exclude {first}-{last} from the DHCP scope of {}",
                    cidr_row.cidr
                ),
                vec![scope_object(prefix)],
            ))
        })
        .await
    }

    /// Deletes an exclusion range.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, `dhcp.exclusion.not_found`, 412 when `expect` is stale, or a
    /// store or job error.
    pub async fn delete_exclusion(
        &self,
        cx: &RequestCtx,
        prefix: PrefixId,
        id: ExclusionId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                scope_of(view, prefix)?;
                let (exclusion, revision) =
                    view.get_typed(&EXCLUSIONS, &(prefix, id))?.ok_or_else(|| {
                        ConfigError::not_found(codes::EXCLUSION_NOT_FOUND, "exclusion range", id)
                    })?;
                check_expect(expect, revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&EXCLUSIONS, &(prefix, id), Some(revision));
                batch.delete_typed(&EXCLUSIONS, &(prefix, id));
                batch.audit(
                    AuditDraft::success(audit::EXCLUSION_DELETE, vec![scope_object(prefix)])
                        .with_source_ip(cx.source_ip)
                        .with_context("exclusion", id.to_string())
                        .with_context("range", format!("{}-{}", exclusion.first, exclusion.last)),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!(
                        "delete the exclusion {}-{}",
                        exclusion.first, exclusion.last
                    ),
                    vec![scope_object(prefix)],
                ))
            })
            .await?;
        Ok(written)
    }

    /// How full a scope is now, from its image (built as if the scope were enabled) and the
    /// leases of its network.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, or the store's error.
    pub fn utilization(
        view: &dyn ReadView,
        prefix: PrefixId,
        now: Timestamp,
    ) -> ConfigResult<Utilization> {
        let mut data = scope_data(view, prefix)?;
        let Some(scope) = data.scopes.get_mut(&prefix) else {
            return Err(scope_not_found(prefix));
        };
        scope.enabled = true;
        let built = build(&data);
        let Some(image) = built.image.scope(prefix) else {
            // A prefix that is not an IPv4 network has no pools to count.
            return Ok(Utilization {
                pool_size: 0,
                leased: 0,
                reserved: 0,
                abandoned: 0,
                free: 0,
                utilization: 0.0,
            });
        };
        let reserved_at = |addr: Ipv4Addr| built.image.reserved_at(prefix, addr).is_some();
        let mut pool_size = 0;
        let mut reserved = 0;
        for pool in &image.pools {
            pool_size += dynamic_size(image, pool.first, pool.last);
        }
        for reservation in built
            .image
            .reservations()
            .iter()
            .filter(|r| r.scope == prefix)
        {
            if image.pool_of(reservation.addr).is_some() {
                reserved += 1;
                if image.is_excluded(reservation.addr) {
                    pool_size += 1;
                }
            }
        }
        let (mut leased, mut abandoned) = (0, 0);
        let row = data.prefixes.get(&prefix).cloned();
        if let Some(row) = row {
            for lease in leases_of(view, &row)? {
                if !image.is_dynamic(lease.addr) || reserved_at(lease.addr) {
                    continue;
                }
                match lease.state {
                    BindingState::Active if lease.ends > now => leased += 1,
                    BindingState::Abandoned => abandoned += 1,
                    _ => {}
                }
            }
        }
        let used = leased + reserved + abandoned;
        let free = pool_size.saturating_sub(used);
        #[allow(clippy::cast_precision_loss, reason = "a ratio for display")]
        let utilization = if pool_size == 0 {
            0.0
        } else {
            (pool_size - free) as f64 / pool_size as f64
        };
        Ok(Utilization {
            pool_size,
            leased,
            reserved,
            abandoned,
            free,
            utilization,
        })
    }
}
