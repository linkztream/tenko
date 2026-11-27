//! The prepare of a mirrored scope for a takeover run (plan section 2.5, ADR 0038): Tenko's
//! own copy of the scope, switched off. In the default VRF, the IPAM network of the scope with
//! its one pool range, then in one DHCP batch the scope, disabled and not authoritative, with
//! the snapshot's lease time and DDNS flags and its distinct exclusions. Nothing is served and
//! no lease is touched; options, reservations and filters are not written.
//!
//! The snapshot is a push, so everything taken from it is checked first: the scope is in the
//! run's plan (the route's check), no loss of the scope is open and no row needs a decision,
//! it has exactly one range, a lease time and DDNS settings Tenko accepts; no free text of it
//! is written. IPAM refuses a network at, around or inside one of the VRF. A scope at the
//! network that the run did not create is refused.
//!
//! A run's scope is the prefix and scope the run's session created. While it is disabled and
//! untouched ([`touched`]), a newer snapshot rebuilds it: removed, then created again; a
//! scope someone else touched answers 409. A sitting never removes or rebuilds what it
//! prepared itself ([`delegation::made_by_sitting`]). A repeat of an unchanged snapshot
//! writes nothing. Every write is an inline job under the caller's principal, so its stamps
//! name the run.

use std::collections::BTreeSet;

use ipnet::IpNet;
use tenko_auth::{AuthError, delegation};
use tenko_core::{
    DelegationId, MirrorId, ObjectRef, PrefixId, RequestCtx, Revision,
    auth::Delegated,
    dhcp::{DdnsPolicy, LeaseTimes, OptionOwner, Scope, tables::SCOPES},
    ipam::{Prefix, PrefixRole, RangeRole, Stamp},
    migrate::codes,
};
use tenko_dhcp::config::{ConfigError, ConfigService, load, scopes::NewScope};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::{PrefixInput, RangeInput},
    tables::PREFIXES,
};
use tenko_store::{ReadView, ReadViewExt};

use super::{DiffAction, DiffKind, MirrorError, MirrorService, ScopePrepared, diff::prefix_of};

/// The kinds of row the prepare writes.
const WRITTEN: [DiffKind; 5] = [
    DiffKind::Prefix,
    DiffKind::Pool,
    DiffKind::Exclusion,
    DiffKind::LeaseTime,
    DiffKind::Ddns,
];

fn refused(code: &'static str, item: &impl ToString) -> MirrorError {
    MirrorError::Takeover {
        code,
        item: item.to_string(),
    }
}

/// The refusal of a removal or a rebuild of what the sitting prepared itself.
fn same_sitting() -> MirrorError {
    AuthError::DelegationRefused {
        reason: "condition",
    }
    .into()
}

/// The prefix of the run at the network in the default VRF with its revision, and its scope.
type Found = (Prefix, Revision, Option<(Scope, Revision)>);

fn found(
    view: &dyn ReadView,
    cidr: IpNet,
    run: DelegationId,
) -> Result<Option<Found>, MirrorError> {
    let Some((id, _)) = prefix_of(view, cidr)? else {
        return Ok(None);
    };
    let Some((prefix, revision)) = view.get_typed(&PREFIXES, &id)? else {
        return Ok(None);
    };
    if prefix.meta.created.by.delegation() != Some(run) {
        return Ok(None);
    }
    Ok(Some((prefix, revision, view.get_typed(&SCOPES, &id)?)))
}

/// The kind of the first object of the run's prefix that is not as the run left it: the
/// prefix, a range (a deleted one too) or an address that another principal created or
/// changed, and with a scope the scope changed (an exclusion's creation or deletion
/// included), an exclusion, pool settings, an option set or a policy someone else made (the
/// prepare writes none of those three), or an active lease. A takeover's or a revert's job
/// writes as the system, so a scope they touched is never the run's as it left it. The kind
/// names no object of someone else.
pub(super) fn touched(
    view: &dyn ReadView,
    run: DelegationId,
    prefix: &Prefix,
) -> Result<Option<&'static str>, MirrorError> {
    let own = |stamp: &Stamp| stamp.by.delegation() == Some(run);
    if !own(&prefix.meta.updated) {
        return Ok(Some("prefix"));
    }
    if (load::every_range_of(view, prefix.id)?.iter())
        .any(|(range, _)| !own(&range.meta.created) || !own(&range.meta.updated))
    {
        return Ok(Some("range"));
    }
    // An address the prefix adopted carries the run's stamp of the move.
    if (load::addresses_of(view, prefix)?.iter()).any(|address| !own(&address.meta.updated)) {
        return Ok(Some("address"));
    }
    let Some((scope, _)) = view.get_typed(&SCOPES, &prefix.id)? else {
        return Ok(None);
    };
    let data = load::scope_data(view, prefix.id)?;
    Ok(if !own(&scope.updated) {
        Some("scope")
    } else if data.exclusions.values().any(|e| !own(&e.created)) {
        Some("exclusion")
    } else if !data.pools.is_empty() {
        Some("pool settings")
    } else if (data.option_sets.keys())
        .any(|owner| matches!(owner, OptionOwner::Scope(_) | OptionOwner::Pool(_)))
    {
        Some("option set")
    } else if (data.policies.values()).any(|policy| policy.scope == Some(prefix.id)) {
        Some("policy")
    } else if ConfigService::scope(view, prefix.id)?.leases > 0 {
        Some("leases")
    } else {
        None
    })
}

/// Deletes the run's scope of `prefix` at the revision read (none: it has none), then in one
/// IPAM batch the ranges the run created and the prefix, without cascade: an address of
/// someone else moves to the parent prefix or refuses (`ipam.in_use`), and then the scope is
/// gone and the prefix stays, which serves nothing.
async fn remove_writes(
    cx: &RequestCtx,
    (ipam, config): (&IpamService, &ConfigService),
    run: DelegationId,
    (prefix, revision): (&Prefix, Revision),
    scope: Option<Revision>,
) -> Result<(), MirrorError> {
    if let Some(scope) = scope {
        config.delete_scope(cx, prefix.id, Some(scope)).await?;
    }
    let delete = |object: ObjectRef, expected| IpamCommand::Delete {
        object,
        expected: Some(expected),
        cascade: false,
    };
    let view = config.view(None).await?;
    let mut commands: Vec<IpamCommand> = load::ranges_of(view.as_ref(), prefix.id)?
        .into_iter()
        .filter(|(range, _)| range.meta.created.by.delegation() == Some(run))
        .map(|(range, revision)| delete(range.id.into(), revision))
        .collect();
    commands.push(delete(prefix.id.into(), revision));
    ipam.execute(&commands, cx, &PlanOptions::default()).await?;
    Ok(())
}

impl MirrorService {
    /// The prepare of `cidr` from the latest snapshot of the run's mirror `id`, for the
    /// sitting of the run's delegated session; the caller checked that the plan names the
    /// scope.
    ///
    /// # Errors
    ///
    /// 403 `auth.delegation.refused` (`condition`) for a rebuild of a scope this sitting
    /// prepared; 404 `ipam.not_found` when a later sitting's prepare of the network removed
    /// this prepare's prefix between its two batches; 409 `migrate.takeover.losses` (an open
    /// loss of the scope), `migrate.takeover.diff` (a row to decide, other than one range, a
    /// lease time or DDNS settings Tenko refuses, a touched scope to rebuild),
    /// `migrate.takeover.scope_enabled`, `ipam.prefix.overlap` (a prefix not the run's at the
    /// network, or a network around or inside it), `dhcp.scope.exists` (a scope not the run's
    /// on the run's prefix); the codes of [`MirrorService::diff`], of the IPAM and the DHCP
    /// writes.
    #[allow(
        clippy::too_many_lines,
        reason = "the checks, then the writes, read top to bottom"
    )]
    pub async fn prepare(
        &self,
        cx: &RequestCtx,
        writers: (&IpamService, &ConfigService),
        sitting: &Delegated,
        id: MirrorId,
        cidr: IpNet,
    ) -> Result<ScopePrepared, MirrorError> {
        let (view, diff, ir, server_ddns) = {
            let _reading = self.reading().await?;
            let view = self.view().await?;
            let (diff, snapshot) = self.diff_in(view.as_ref(), id, cidr)?;
            let dhcp = snapshot.envelope.dhcp;
            let ir = (dhcp.scopes.into_iter())
                .find(|scope| scope.cidr == cidr)
                .ok_or(MirrorError::ScopeNotFound(id, cidr))?;
            (view, diff, ir, dhcp.server_ddns)
        };
        if diff.losses_open > 0 {
            let count = diff.losses_open;
            return Err(MirrorError::Losses { scope: cidr, count });
        }
        if let Some(row) = (diff.rows.iter()).find(|row| row.action == DiffAction::Decide) {
            return Err(refused(codes::TAKEOVER_DIFF, &row.item));
        }
        let [pool] = ir.ranges.as_slice() else {
            return Err(refused(codes::TAKEOVER_DIFF, &"ranges"));
        };
        let lease = ir.lease_secs.map(LeaseTimes::fixed);
        if lease
            .as_ref()
            .is_some_and(|lease| lease.validate("lease").is_err())
        {
            return Err(refused(codes::TAKEOVER_DIFF, &"lease_secs"));
        }
        // The forward zone and the TTL are Tenko's own settings, never the push's.
        let ddns = ir.ddns.or(server_ddns).map(|policy| DdnsPolicy {
            forward_zone: None,
            ttl: None,
            ..policy
        });
        let (ipam, config) = writers;
        if (config.refuse_replace(view.as_ref(), ddns.as_ref(), "ddns")).is_err() {
            return Err(refused(codes::TAKEOVER_DIFF, &"ddns"));
        }

        // A prefix at the network that the run did not create is IPAM's overlap, below.
        if let Some((prefix, revision, scope)) = found(view.as_ref(), cidr, sitting.id)? {
            if let Some((scope, _)) = &scope {
                if scope.created.by.delegation() != Some(sitting.id) {
                    return Err(ConfigError::new(
                        tenko_core::dhcp::codes::SCOPE_EXISTS,
                        409,
                        format!("{cidr} has a DHCP scope the run did not create"),
                    )
                    .param("prefix", cidr.to_string())
                    .into());
                }
                if scope.enabled {
                    return Err(refused(codes::TAKEOVER_SCOPE_ENABLED, &cidr));
                }
                if !diff.rows.iter().any(|row| WRITTEN.contains(&row.kind)) {
                    return Ok(ScopePrepared { prefix: prefix.id });
                }
            }
            if delegation::made_by_sitting(sitting, &cx.principal, &prefix.meta.created) {
                return Err(same_sitting());
            }
            if let Some(item) = touched(view.as_ref(), sitting.id, &prefix)? {
                let code = codes::TAKEOVER_DIFF;
                return Err(MirrorError::Touched { code, item });
            }
            drop(view);
            let scope = scope.map(|(_, revision)| revision);
            remove_writes(cx, writers, sitting.id, (&prefix, revision), scope).await?;
        }

        let prefix = PrefixId::generate();
        let commands = [
            IpamCommand::CreatePrefix(PrefixInput {
                id: Some(prefix),
                vrf: None,
                cidr,
                role: Some(PrefixRole::Network),
                status: None,
                vlan: None,
                site: None,
                alarm: None,
                alloc: None,
                tags: BTreeSet::new(),
                custom: std::collections::BTreeMap::new(),
                description: None,
            }),
            IpamCommand::CreateRange(RangeInput {
                id: None,
                prefix,
                first: pool.first,
                last: pool.last,
                role: RangeRole::DhcpPool,
                status: None,
                lease_secs: None,
                delegated_len: None,
                tags: BTreeSet::new(),
                custom: std::collections::BTreeMap::new(),
                description: None,
            }),
        ];
        ipam.execute(&commands, cx, &PlanOptions::default()).await?;
        let exclusions: Vec<_> = (ir.exclusions.iter())
            .map(|range| (range.first, range.last))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let scope = NewScope {
            prefix,
            enabled: Some(false),
            lease,
            authoritative: Some(false),
            server_id: None,
            ddns,
            shared_network: None,
            restricted: false,
            classes: Vec::new(),
            description: None,
            v6: None,
        };
        config.create_scope_with(cx, scope, &exclusions).await?;
        Ok(ScopePrepared { prefix })
    }

    /// Removes the run's scope of `cidr` (`DELETE /migrate/runs/{id}/scopes/{cidr}`): its
    /// scope and its prefix. For the sitting of a delegated session only a disabled scope
    /// that an earlier sitting prepared and nobody else touched ([`touched`]); for a person
    /// any disabled scope of the run.
    ///
    /// # Errors
    ///
    /// 403 `auth.delegation.refused` (`condition`) for a scope the sitting prepared; 404
    /// `dhcp.scope.not_found` when the network has no prefix of the run (a person's answers
    /// the same) or a scope not the run's; 409 `migrate.takeover.scope_enabled` for an
    /// enabled scope and, for a delegated session, a touched one (`item` names the kind of
    /// object); the codes of the IPAM and the DHCP writes.
    pub async fn remove(
        &self,
        cx: &RequestCtx,
        writers: (&IpamService, &ConfigService),
        (run, sitting): (DelegationId, Option<&Delegated>),
        cidr: IpNet,
    ) -> Result<(), MirrorError> {
        let not_found = || -> MirrorError {
            ConfigError::new(
                tenko_core::dhcp::codes::SCOPE_NOT_FOUND,
                404,
                format!("{cidr} has no DHCP scope of the run"),
            )
            .param("prefix", cidr.to_string())
            .into()
        };
        let view = self.view().await?;
        let (prefix, revision, scope) = found(view.as_ref(), cidr, run)?.ok_or_else(not_found)?;
        if let Some((scope, _)) = &scope {
            if scope.created.by.delegation() != Some(run) {
                return Err(not_found());
            }
            if scope.enabled {
                return Err(refused(codes::TAKEOVER_SCOPE_ENABLED, &cidr));
            }
        }
        if let Some(sitting) = sitting {
            if delegation::made_by_sitting(sitting, &cx.principal, &prefix.meta.created) {
                return Err(same_sitting());
            }
            if let Some(item) = touched(view.as_ref(), run, &prefix)? {
                let code = codes::TAKEOVER_SCOPE_ENABLED;
                return Err(MirrorError::Touched { code, item });
            }
        }
        drop(view);
        let scope = scope.map(|(_, revision)| revision);
        remove_writes(cx, writers, run, (&prefix, revision), scope).await
    }
}
