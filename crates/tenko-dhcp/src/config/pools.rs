//! Pools: IPAM ranges of role `dhcp_pool` (created, moved and deleted through the IPAM
//! routes) with what DHCP adds to them (`dhcp.pools`): classes and lease times. A pool
//! without settings serves with the range's `lease_secs`, else the scope's lease times.
//! Settings are kept for pools of a prefix with a scope; they are audited on the scope.

use tenko_core::{
    PrefixId, RangeId, RequestCtx, Revision,
    audit::AuditDraft,
    dhcp::{
        BindingState, ClassId, LeaseTimes, OptionOwner, PoolSettings, audit, codes, scope_object,
        tables::{POOLS, SCOPES},
    },
    ipam::{Range, RangeRole},
};
use tenko_ipam::tables::RANGES;
use tenko_store::{ReadView, ReadViewExt, WriteBatch};

use super::{
    ConfigError, ConfigResult, ConfigService, Planned, Written, check_expect, delete_option_set,
    image::build,
    live_prefix,
    load::{ranges_of, scope_data},
    scopes::{dynamic_size, expect_classes, leases_of, scope_of},
    stamp,
};

/// A pool as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRow {
    /// The IPAM range.
    pub range: Range,
    /// The DHCP settings, when set.
    pub settings: Option<PoolSettings>,
    /// Addresses a client can lease (exclusions taken out); 0 without an IPv4 scope.
    pub size: u64,
    /// Addresses with an active lease.
    pub leased: u64,
    /// The revision of the settings row; 0 without settings.
    pub revision: Revision,
}

/// The DHCP settings of a pool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolChange {
    /// The classes the pool admits; empty: every client the scope admits.
    pub classes: Vec<ClassId>,
    /// Lease times.
    pub lease: Option<LeaseTimes>,
}

fn not_found(range: RangeId) -> ConfigError {
    ConfigError::new(
        codes::POOL_NOT_FOUND,
        404,
        format!("range {range} is no DHCP pool"),
    )
    .param("range", range.to_string())
}

/// The pools of one prefix with their sizes and leases.
fn pools_of(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<Vec<PoolRow>> {
    let mut data = scope_data(view, prefix)?;
    if let Some(scope) = data.scopes.get_mut(&prefix) {
        scope.enabled = true;
    }
    let built = build(&data);
    let image = built.image.scope(prefix);
    let in_network = match data.prefixes.get(&prefix) {
        Some(row) if image.is_some() => leases_of(view, row)?,
        _ => Vec::new(),
    };
    let mut rows = Vec::new();
    for (range, _) in ranges_of(view, prefix)? {
        if range.role != RangeRole::DhcpPool {
            continue;
        }
        let settings = view.get_typed(&POOLS, &range.id)?;
        let (size, leased) = image
            .and_then(|scope| {
                scope
                    .pools
                    .iter()
                    .find(|pool| pool.range == range.id)
                    .map(|pool| (scope, pool))
            })
            .map_or((0, 0), |(scope, pool)| {
                let leased = in_network
                    .iter()
                    .filter(|lease| {
                        lease.state == BindingState::Active
                            && pool.contains(lease.addr)
                            && scope.is_dynamic(lease.addr)
                    })
                    .count();
                (
                    dynamic_size(scope, pool.first, pool.last),
                    u64::try_from(leased).unwrap_or(u64::MAX),
                )
            });
        rows.push(PoolRow {
            revision: settings
                .as_ref()
                .map_or(Revision::ZERO, |(_, revision)| *revision),
            settings: settings.map(|(settings, _)| settings),
            range,
            size,
            leased,
        });
    }
    rows.sort_by_key(|row| (row.range.first, row.range.id));
    Ok(rows)
}

impl ConfigService {
    /// The pools of every scope, or of one, by scope and first address.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found` for a scope that does not exist, or the store's error.
    pub fn pools(view: &dyn ReadView, scope: Option<PrefixId>) -> ConfigResult<Vec<PoolRow>> {
        let prefixes = match scope {
            Some(prefix) => {
                scope_of(view, prefix)?;
                vec![prefix]
            }
            None => Self::scopes(view)?
                .into_iter()
                .map(|row| row.scope.prefix)
                .collect(),
        };
        let mut rows = Vec::new();
        for prefix in prefixes {
            rows.extend(pools_of(view, prefix)?);
        }
        Ok(rows)
    }

    /// The prefix of a pool's range, for the authorization on its scope.
    ///
    /// # Errors
    ///
    /// `dhcp.pool.not_found` when the range does not exist, or the store's error.
    pub fn pool_prefix(view: &dyn ReadView, range: RangeId) -> ConfigResult<PrefixId> {
        match view.get_typed(&RANGES, &range)? {
            Some((row, _)) if !row.meta.is_deleted() => Ok(row.prefix),
            _ => Err(not_found(range)),
        }
    }

    /// One pool.
    ///
    /// # Errors
    ///
    /// `dhcp.pool.not_found` when the range does not exist or is not a pool, or the store's
    /// error.
    pub fn pool(view: &dyn ReadView, range: RangeId) -> ConfigResult<PoolRow> {
        let prefix = Self::pool_prefix(view, range)?;
        pools_of(view, prefix)?
            .into_iter()
            .find(|row| row.range.id == range)
            .ok_or_else(|| not_found(range))
    }

    /// Sets the DHCP settings of a pool.
    ///
    /// # Errors
    ///
    /// `dhcp.pool.not_found`, `dhcp.scope.not_found` when the prefix has no scope,
    /// `dhcp.pool.not_pool`, `dhcp.pool.outside`, `dhcp.lease_times.invalid`,
    /// `dhcp.class.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn set_pool(
        &self,
        cx: &RequestCtx,
        range: RangeId,
        change: PoolChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(PoolSettings, Option<Written>)> {
        self.execute(cx, |view| {
            let (row, range_revision) = match view.get_typed(&RANGES, &range)? {
                Some((row, revision)) if !row.meta.is_deleted() => (row, revision),
                _ => return Err(not_found(range)),
            };
            let (_, scope_revision) = scope_of(view, row.prefix)?;
            let (prefix, _) = live_prefix(view, row.prefix)?;
            let current = view.get_typed(&POOLS, &range)?;
            let revision = current
                .as_ref()
                .map_or(Revision::ZERO, |(_, revision)| *revision);
            check_expect(expect, revision)?;
            // A class named twice is kept once, in its first place.
            let mut classes: Vec<ClassId> = Vec::with_capacity(change.classes.len());
            for class in &change.classes {
                if !classes.contains(class) {
                    classes.push(*class);
                }
            }
            let settings = PoolSettings {
                range,
                classes,
                lease: change.lease,
                updated: stamp(cx),
            };
            settings.validate(&row, &prefix)?;
            if let Some((before, _)) = &current
                && before.classes == settings.classes
                && before.lease == settings.lease
            {
                return Ok(Planned::nothing(before.clone()));
            }
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&RANGES, &range, Some(range_revision));
            batch.expect_typed(&SCOPES, &row.prefix, Some(scope_revision));
            batch.expect_typed(
                &POOLS,
                &range,
                (revision > Revision::ZERO).then_some(revision),
            );
            expect_classes(view, &mut batch, &settings.classes)?;
            batch.put_typed(&POOLS, &range, &settings)?;
            batch.audit(
                AuditDraft::success(audit::POOL_UPDATE, vec![scope_object(row.prefix)])
                    .with_source_ip(cx.source_ip)
                    .with_context("range", range.to_string())
                    .with_context("pool", format!("{}-{}", row.first, row.last)),
            );
            Ok(Planned::write(
                settings.clone(),
                batch,
                format!(
                    "set the DHCP settings of the pool {}-{}",
                    row.first, row.last
                ),
                vec![scope_object(row.prefix)],
            ))
        })
        .await
    }

    /// Removes the DHCP settings of a pool and its option set; the range stays.
    ///
    /// # Errors
    ///
    /// `dhcp.pool.not_found` when the pool has no settings, 412 when `expect` is stale, or a
    /// store or job error.
    pub async fn delete_pool(
        &self,
        cx: &RequestCtx,
        range: RangeId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (_, revision) = view
                    .get_typed(&POOLS, &range)?
                    .ok_or_else(|| not_found(range))?;
                check_expect(expect, revision)?;
                let prefix = Self::pool_prefix(view, range).ok();
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&POOLS, &range, Some(revision));
                batch.delete_typed(&POOLS, &range);
                delete_option_set(view, &mut batch, OptionOwner::Pool(range))?;
                let objects = prefix.map(scope_object).into_iter().collect::<Vec<_>>();
                batch.audit(
                    AuditDraft::success(audit::POOL_DELETE, objects.clone())
                        .with_source_ip(cx.source_ip)
                        .with_context("range", range.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("remove the DHCP settings of the pool {range}"),
                    objects,
                ))
            })
            .await?;
        Ok(written)
    }
}
