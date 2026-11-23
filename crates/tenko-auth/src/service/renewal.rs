//! Self-renewal, reuse detection and source binding of scoped tokens (IAM-20, IAM-21);
//! `docs/access.md` sections 7.1 to 7.6 describe the behavior.
//!
//! A renewable token and its successors form a family ([`TokenRenewal::family`]). A renewal
//! leaves the presenting token live until its successor is first used; that first use moves
//! it under [`retired_key`] in the same write. A presented token found there, or a renewal
//! secret of such a token, revokes the family: every member is removed and the newest is
//! kept under its retired key with the reason, so the token list and the health warning show
//! it until an administrator removes it. Every write names the revisions it read, so two
//! controllers that decide on the same family are ordered by the store and the second write
//! is refused.

use std::{net::IpAddr, sync::Arc, time::Duration};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use ipnet::{IpNet, Ipv4Net};
use tenko_core::{
    ApiTokenId, CodedError, ObjectRef, Principal, RequestCtx, SystemComponent, Timestamp, UserId,
    audit::AuditDraft, migrate::TOKEN_EXPIRING_DAYS,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError, WriteBatch};

use super::{
    AuthService, LIST_LIMIT,
    access::{scoped_token_info, token_expiry},
    actions, effective_token_expiry,
    types::{
        CreatedToken, OwnToken, SCOPED_TOKENS_MAX, SOURCE_PREFIXES_MAX, SecretString, TokenRenew,
        TokenRequest,
    },
};
use crate::{
    error::AuthError,
    model::{
        RevocationReason, SCOPED_TOKENS, ScopedTokenRecord, TokenRenewal, TokenRevocation,
        USER_SCOPED_TOKENS, USERS, retired_key,
    },
    secret::{BearerSecret, hash_secret, new_renewal_secret, new_token_of},
    settings::SecuritySettings,
};

/// The wrong renewal secrets a family takes; the last of them revokes it (IAM-20).
pub const RENEWAL_FAILURES_MAX: u64 = 3;

/// The superseded tokens a family keeps for reuse detection, the newest first.
const RETIRED_KEPT: usize = 8;

/// How long after its successor's first use a superseded token is refused without revoking
/// the family: requests the integration sent before it switched may still arrive.
const SUPERSEDED_GRACE: Duration = Duration::from_secs(60);

/// How often an administrator's removal of a family is tried when renewals keep coming first.
const REMOVE_TRIES: usize = 3;

/// The health warning of service-account tokens about to expire.
pub const TOKEN_EXPIRING: &str = "auth.token.expiring";
/// The health warning of families the server revoked, until an administrator removes them.
pub const TOKEN_REVOKED: &str = "auth.token.revoked";

/// A member of a family: its key in [`SCOPED_TOKENS`], the record and its revision.
type Member = (Vec<u8>, ScopedTokenRecord, tenko_core::Revision);

fn refused(reason: &'static str) -> AuthError {
    AuthError::TokenRenewalRefused { reason }
}

/// The renewal state of a token of family `id` with the family's lifetime, and its secret.
fn new_renewal(
    id: ApiTokenId,
    lifetime_secs: u64,
) -> Result<(TokenRenewal, BearerSecret), AuthError> {
    let secret = new_renewal_secret()?;
    let renewal = TokenRenewal {
        secret: secret.hash(),
        family: id,
        successor: None,
        superseded_at: None,
        failures: 0,
        revoked: None,
        replaced: false,
        lifetime_secs,
    };
    Ok((renewal, secret))
}

/// The renewal state and secret of a new renewable token, and its source prefixes.
type CreationTerms = (Option<(TokenRenewal, BearerSecret)>, Vec<IpNet>);

/// The renewal right and the source prefixes of a new scoped token of `owner` living
/// `lifetime` (IAM-20, IAM-21): the right only for a service account under TGL-46, and only
/// for a token that expires.
pub(super) fn creation_terms(
    owner: &crate::model::UserRecord,
    request: &TokenRequest,
    settings: &SecuritySettings,
    id: ApiTokenId,
    lifetime: Option<Duration>,
) -> Result<CreationTerms, AuthError> {
    let prefixes = parse_source_prefixes(&request.source_prefixes)?;
    if !request.renewable {
        return Ok((None, prefixes));
    }
    if !owner.is_service() {
        return Err(AuthError::invalid(
            "renewable",
            "only a service account's token renews itself",
        ));
    }
    if !settings.token_self_renewal() {
        return Err(refused("disabled"));
    }
    let Some(lifetime) = lifetime.filter(|span| !span.is_zero()) else {
        return Err(AuthError::invalid(
            "expires_in_days",
            "a renewable token needs a lifetime",
        ));
    };
    Ok((Some(new_renewal(id, lifetime.as_secs())?), prefixes))
}

/// Refuses a new scoped token of `owner` that already holds [`SCOPED_TOKENS_MAX`], superseded
/// ones included: a bounded number keeps every scan of an owner's tokens complete.
pub(super) fn check_token_room(view: &dyn ReadView, owner: UserId) -> Result<(), AuthError> {
    let held = view
        .scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(owner,))),
            SCOPED_TOKENS_MAX,
            false,
        )?
        .len();
    if held >= SCOPED_TOKENS_MAX {
        return Err(AuthError::TokenLimit {
            max: SCOPED_TOKENS_MAX,
        });
    }
    Ok(())
}

/// The source prefixes of a token request (IAM-21): networks or host addresses, truncated to
/// their network, an IPv4-mapped IPv6 prefix as its IPv4 prefix (client addresses are compared
/// that way), sorted and without repeats; a prefix of length zero binds nothing and is refused.
fn parse_source_prefixes(entries: &[String]) -> Result<Vec<IpNet>, AuthError> {
    if entries.len() > SOURCE_PREFIXES_MAX {
        return Err(AuthError::invalid(
            "source_prefixes",
            format!("at most {SOURCE_PREFIXES_MAX} prefixes"),
        ));
    }
    let mut prefixes = entries
        .iter()
        .map(|entry| {
            let entry = entry.trim();
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .ok()
                .map(|prefix| match prefix {
                    IpNet::V6(net) if net.prefix_len() >= 96 => net
                        .addr()
                        .to_ipv4_mapped()
                        .and_then(|v4| Ipv4Net::new(v4, net.prefix_len() - 96).ok())
                        .map_or(prefix, IpNet::V4),
                    other => other,
                })
                .filter(|prefix| prefix.prefix_len() > 0)
                .map(|prefix| prefix.trunc())
                .ok_or_else(|| {
                    AuthError::invalid(
                        "source_prefixes",
                        format!(
                            "{entry} is not an address or a network such as 192.0.2.0/24 (a network of length zero binds nothing)"
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    prefixes.sort_unstable();
    prefixes.dedup();
    Ok(prefixes)
}

/// The end of a live token that warrants the expiry warning at `now`: fewer than
/// [`TOKEN_EXPIRING_DAYS`] days left.
fn expiring_end(
    record: &ScopedTokenRecord,
    settings: &SecuritySettings,
    now: Timestamp,
) -> Option<Timestamp> {
    if record.retired() {
        return None;
    }
    let ahead = Duration::from_secs(u64::from(TOKEN_EXPIRING_DAYS) * 86_400);
    effective_token_expiry(record.created_at, record.expires_at, settings)
        .filter(|end| *end > now && end.saturating_since(now) < ahead)
}

fn is_service(view: &dyn ReadView, owner: UserId) -> Result<bool, AuthError> {
    Ok(view
        .get_typed(&USERS, &owner)?
        .is_some_and(|(user, _)| user.is_service()))
}

/// The health warnings of scoped tokens (IAM-20), one per kind and without names, so that a
/// reader of the system status who may not read users learns nothing about accounts:
/// [`TOKEN_EXPIRING`] with the number of live service-account tokens with fewer than 14 days
/// left and the first end, [`TOKEN_REVOKED`] with the number of families the server revoked.
fn compute_warnings(
    view: &dyn ReadView,
    settings: &SecuritySettings,
    now: Timestamp,
) -> Result<Vec<CodedError>, AuthError> {
    let (mut expiring, mut first_end, mut revoked) = (0_usize, None::<Timestamp>, 0_usize);
    // The whole table, once an hour: a bound here would leave revocations unwarned.
    for (_, record, _) in view.scan_typed(&SCOPED_TOKENS, KeyRange::all(), usize::MAX, false)? {
        if record.renewal.as_ref().is_some_and(|r| r.revoked.is_some()) {
            revoked += 1;
        } else if let Some(end) = expiring_end(&record, settings, now)
            && is_service(view, record.owner)?
        {
            expiring += 1;
            first_end = Some(first_end.map_or(end, |first| first.min(end)));
        }
    }
    let mut warnings = Vec::new();
    if let Some(end) = first_end {
        warnings.push(
            CodedError::new(
                TOKEN_EXPIRING,
                409,
                format!(
                    "service-account tokens expiring within 14 days: {expiring}, the first at {}; renew or replace them",
                    end.to_rfc3339()
                ),
            )
            .with_param("count", expiring.to_string())
            .with_param("expires_at", end.to_rfc3339()),
        );
    }
    if revoked > 0 {
        warnings.push(
            CodedError::new(
                TOKEN_REVOKED,
                409,
                format!(
                    "token families the server revoked: {revoked}; look into them, then remove the revoked tokens"
                ),
            )
            .with_param("count", revoked.to_string()),
        );
    }
    Ok(warnings)
}

/// The end of a token renewed from `record` at `now` (IAM-20): the family's own lifetime
/// (else the span of `record`), capped by the profile at `now` (TGL-05).
fn renewed_expiry(
    record: &ScopedTokenRecord,
    renewal: &TokenRenewal,
    settings: &SecuritySettings,
    now: Timestamp,
) -> Result<Option<Timestamp>, AuthError> {
    let cap = token_expiry(settings, None, now)?;
    let span = match renewal.lifetime_secs {
        0 => record.expires_at.map_or(Duration::ZERO, |end| {
            end.saturating_since(record.created_at)
        }),
        secs => Duration::from_secs(secs),
    };
    let kept = now.checked_add(span).filter(|_| !span.is_zero());
    Ok(match (kept, cap) {
        (Some(kept), Some(cap)) => Some(kept.min(cap)),
        (kept, cap) => kept.or(cap),
    })
}

/// The source prefixes as one audit context value; `None` without any.
pub(super) fn joined(prefixes: &[IpNet]) -> Option<String> {
    (!prefixes.is_empty()).then(|| {
        prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn reason_text(reason: RevocationReason) -> &'static str {
    match reason {
        RevocationReason::ReuseDetected => "reuse_detected",
        RevocationReason::RenewalFailures => "renewal_failures",
        RevocationReason::Other => "other",
    }
}

impl AuthService {
    /// `POST /access/token/renew` (IAM-20): the calling token with its renewal secret becomes
    /// a new token and a new renewal secret, shown once. The calling token stays valid until
    /// the new one is first used; an unused successor of it is replaced.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for a principal that is no scoped token, or a token
    /// whose family the presented secret revoked; [`AuthError::TokenRenewalRefused`] with TGL-46
    /// off, for a token without the right and for a wrong secret; [`AuthError::Conflict`] when
    /// another renewal or use of the family came first.
    pub async fn renew_own_token(
        &self,
        ctx: &RequestCtx,
        request: &TokenRenew,
    ) -> Result<CreatedToken, AuthError> {
        let (view, (key, record, revision), local) = self.own_scoped_token(ctx).await?;
        // The grants are checked against this controller's index, which must match the view.
        if !local {
            return Err(AuthError::Conflict);
        }
        if !self.settings().token_self_renewal() {
            return Err(refused("disabled"));
        }
        let Some(renewal) = record.renewal.as_ref() else {
            return Err(refused("not_renewable"));
        };
        let presented = hash_secret(request.renewal_secret.expose());
        if verify_slices_are_equal(&presented, &renewal.secret).is_err() {
            return self.wrong_renewal_secret(ctx, view, key, &presented).await;
        }
        let settings = self.settings();
        let expires_at = renewed_expiry(&record, renewal, &settings, ctx.now)?;
        let grants = self.grants_still_held(view.as_ref(), &record)?;
        // A bound family stays bound: its successors keep the lineage and the form.
        let token = new_token_of(record.form())?;
        let (next_renewal, secret) = new_renewal(renewal.family, renewal.lifetime_secs)?;
        let next = ScopedTokenRecord {
            id: ApiTokenId::generate(),
            created_at: ctx.now,
            expires_at,
            last_used_at: None,
            prefix: token.expose().chars().take(12).collect(),
            grants,
            renewal: Some(next_renewal),
            expiry_noticed_at: None,
            ..record.clone()
        };
        let mut batch = WriteBatch::for_request(ctx);
        let members = Self::family(view.as_ref(), record.owner, renewal.family)?;
        for (member_key, member, member_revision) in &members {
            let replaced = Some(member.id) == renewal.successor
                && member.last_used_at.is_none()
                && !member.retired();
            // Superseded members are kept for reuse detection until expired on a trusted clock.
            let ended = member
                .renewal
                .as_ref()
                .is_some_and(|r| r.superseded() && r.revoked.is_none())
                && effective_token_expiry(member.created_at, member.expires_at, &settings)
                    .is_some_and(|end| end <= ctx.now && tenko_core::clock::trusted_now().is_ok());
            if !replaced && !ended {
                continue;
            }
            batch.expect_typed(&SCOPED_TOKENS, member_key, Some(*member_revision));
            batch.delete_typed(&SCOPED_TOKENS, member_key);
            if ended {
                batch.delete_typed(&USER_SCOPED_TOKENS, &(member.owner, member.id));
                continue;
            }
            // The replaced successor is kept as superseded: the integration that lost the
            // answer never held it, so a later presentation means a second holder.
            let mut retired = member.clone();
            if let Some(r) = retired.renewal.as_mut() {
                r.replaced = true;
            }
            let retired_at = retired_key(member_key);
            batch.put_typed(&SCOPED_TOKENS, &retired_at, &retired)?;
            batch.put_typed(&USER_SCOPED_TOKENS, &(member.owner, member.id), &retired_at)?;
        }
        let replacing = members.iter().any(|(_, member, _)| {
            Some(member.id) == renewal.successor
                && member.last_used_at.is_none()
                && !member.retired()
        });
        Self::stage_prune(&mut batch, &members, usize::from(replacing));
        // The renewal is a use: it supersedes the predecessor in the same write, so that a
        // first use whose write was lost cannot leave two live branches.
        Self::stage_supersede(view.as_ref(), &mut batch, &record, ctx.now)?;
        let mut current = record.clone();
        current.last_used_at = Some(ctx.now);
        if let Some(renewal) = current.renewal.as_mut() {
            renewal.successor = Some(next.id);
            renewal.failures = 0;
        }
        batch.expect_typed(&SCOPED_TOKENS, &key, Some(revision));
        batch.put_typed(&SCOPED_TOKENS, &key, &current)?;
        let hash = token.hash();
        batch.put_typed(&SCOPED_TOKENS, &hash, &next)?;
        batch.put_typed(&USER_SCOPED_TOKENS, &(next.owner, next.id), &hash)?;
        let mut draft = Self::audit(
            actions::TOKEN_RENEW,
            vec![
                ObjectRef::from(record.owner),
                ObjectRef::from(record.id),
                ObjectRef::from(next.id),
            ],
            ctx,
        )
        .with_context("name", next.name.clone())
        .with_context("family", renewal.family.to_string());
        if let Some(expires_at) = next.expires_at {
            draft = draft.with_context("expires_at", expires_at.to_rfc3339());
        }
        batch.audit(draft);
        self.commit(batch).await?;
        Ok(CreatedToken {
            token: SecretString::new(token.expose()),
            renewal_secret: Some(SecretString::new(secret.expose())),
            info: scoped_token_info(&next),
        })
    }

    /// A wrong renewal secret with the valid token stored under `key`: a superseded member's
    /// secret revokes the family as reuse, the last of [`RENEWAL_FAILURES_MAX`] failures as
    /// such; any other is counted. Each is audited.
    async fn wrong_renewal_secret(
        &self,
        ctx: &RequestCtx,
        view: Arc<dyn ReadView>,
        key: Vec<u8>,
        presented: &[u8],
    ) -> Result<CreatedToken, AuthError> {
        let error = refused("wrong_secret");
        let Principal::Token { id, owner } = ctx.principal else {
            return Err(AuthError::Unauthenticated);
        };
        let failed = || {
            let mut batch = WriteBatch::failed_sign_in(ctx.principal.clone(), ctx.now);
            batch.request = Some(ctx.request);
            batch.audit(
                AuditDraft::failed(
                    actions::TOKEN_RENEW,
                    vec![ObjectRef::from(owner), ObjectRef::from(id)],
                    &error,
                )
                .with_source_ip(ctx.source_ip),
            );
            batch
        };
        let decide = |view: &dyn ReadView| -> Result<_, AuthError> {
            let mut batch = failed();
            let Some((record, revision)) = view
                .get_typed(&SCOPED_TOKENS, &key)?
                .filter(|(record, _)| !record.retired())
            else {
                return Ok((batch, None));
            };
            let family = record.renewal.as_ref().map_or(record.id, |r| r.family);
            let members = Self::family(view, record.owner, family)?;
            let reused = members.iter().any(|(_, member, _)| {
                member.retired()
                    && member
                        .renewal
                        .as_ref()
                        .is_some_and(|r| verify_slices_are_equal(presented, &r.secret).is_ok())
            });
            let failures: u64 = members
                .iter()
                .filter(|(_, member, _)| !member.retired())
                .filter_map(|(_, member, _)| member.renewal.as_ref())
                .map(|r| r.failures)
                .sum::<u64>()
                + 1;
            let reason = if reused {
                Some(RevocationReason::ReuseDetected)
            } else {
                (failures >= RENEWAL_FAILURES_MAX).then_some(RevocationReason::RenewalFailures)
            };
            if let Some(reason) = reason {
                Self::stage_revocation(&mut batch, &members, reason, ctx.now)?;
                batch.audit(Self::reuse_audit(&record, reason, ctx));
                if reason == RevocationReason::ReuseDetected {
                    Self::stage_lineage_reuse(view, &mut batch, &record, ctx)?;
                }
            } else {
                let mut counted = record.clone();
                if let Some(renewal) = counted.renewal.as_mut() {
                    renewal.failures = renewal.failures.saturating_add(1);
                }
                batch.expect_typed(&SCOPED_TOKENS, &key, Some(revision));
                batch.put_typed(&SCOPED_TOKENS, &key, &counted)?;
            }
            Ok((batch, reason))
        };
        let reason = self.propose_decided(view, decide, failed()).await?;
        if reason.is_some() {
            self.refresh_warnings_quietly(ctx.now).await;
        }
        Err(match reason {
            Some(RevocationReason::ReuseDetected) => AuthError::Unauthenticated,
            _ => error,
        })
    }

    /// Proposes the write `decide` makes from a view; when its preconditions failed (another
    /// write of the family came first), decides once more on a newer view, and if that fails
    /// too writes `fallback` (the audit record) alone. Returns the last decision.
    async fn propose_decided<R>(
        &self,
        mut view: Arc<dyn ReadView>,
        decide: impl Fn(&dyn ReadView) -> Result<(WriteBatch, R), AuthError>,
        fallback: WriteBatch,
    ) -> Result<R, AuthError> {
        let mut decided = None;
        for attempt in 0..2 {
            let made = async {
                if attempt > 0 {
                    view = self.view().await?;
                }
                decide(view.as_ref())
            }
            .await;
            let (batch, outcome) = match made {
                Ok(made) => made,
                // The first decision stands; its audit record is written below.
                Err(error) if decided.is_some() => {
                    tracing::warn!(%error, "could not decide a token refusal again");
                    break;
                }
                Err(error) => return Err(error),
            };
            match self.store.propose(batch).await {
                Ok(_) => return Ok(outcome),
                Err(StoreError::PreconditionFailed(_)) => decided = Some(outcome),
                Err(error) => {
                    tracing::warn!(%error, "could not record a token decision");
                    decided = Some(outcome);
                    break;
                }
            }
        }
        self.record_failure(fallback, ("", None)).await;
        decided.ok_or_else(|| AuthError::internal("no token decision was made"))
    }

    /// The grants of `record` its account still holds (IAM-20): a renewal drops the others,
    /// so a renewed token never carries a grant its account lost. A token left with neither a
    /// grant nor a scope does not renew.
    fn grants_still_held(
        &self,
        view: &dyn ReadView,
        record: &ScopedTokenRecord,
    ) -> Result<Vec<crate::model::TokenGrant>, AuthError> {
        let (owner, _) = view
            .get_typed(&USERS, &record.owner)?
            .ok_or(AuthError::Unauthenticated)?;
        let grants: Vec<_> = record
            .grants
            .iter()
            .filter(|grant| {
                let one = TokenRequest {
                    grants: Some(vec![(*grant).clone()]),
                    ..TokenRequest::default()
                };
                self.validate_token_grants(view, &owner, &one).is_ok()
            })
            .cloned()
            .collect();
        if grants.is_empty() && record.scopes.is_empty() {
            return Err(AuthError::GrantExceedsOwn);
        }
        Ok(grants)
    }

    /// `GET /access/token` (IAM-20): the calling scoped token's own description.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for a principal that is no scoped token.
    pub async fn describe_own_token(&self, ctx: &RequestCtx) -> Result<OwnToken, AuthError> {
        let (view, (_, record, _), _) = self.own_scoped_token(ctx).await?;
        let (account, _) = view
            .get_typed(&USERS, &record.owner)?
            .ok_or(AuthError::Unauthenticated)?;
        let settings = self.settings();
        let mut token = scoped_token_info(&record);
        token.renewable &= settings.token_self_renewal();
        token.expires_at = effective_token_expiry(record.created_at, record.expires_at, &settings);
        Ok(OwnToken {
            account: account.id,
            account_name: account.name,
            token,
        })
    }

    /// The live scoped token of a token principal, with its key and revision and the view it
    /// was found in: this controller's copy (`true`), else (a token the request authenticated
    /// on, not yet applied here) the leader's commit index (`false`).
    async fn own_scoped_token(
        &self,
        ctx: &RequestCtx,
    ) -> Result<(Arc<dyn ReadView>, Member, bool), AuthError> {
        let Principal::Token { id, owner } = ctx.principal else {
            return Err(AuthError::Unauthenticated);
        };
        let find = |view: &dyn ReadView| -> Result<Option<Member>, AuthError> {
            let Some((key, _)) = view.get_typed(&USER_SCOPED_TOKENS, &(owner, id))? else {
                return Ok(None);
            };
            Ok(view
                .get_typed(&SCOPED_TOKENS, &key)?
                .filter(|(record, _)| !record.retired())
                .map(|(record, revision)| (key, record, revision)))
        };
        let view = self.view().await?;
        if let Some(member) = find(view.as_ref())? {
            return Ok((view, member, true));
        }
        let confirmed = self
            .confirmed_view_for_miss(&USER_SCOPED_TOKENS.key(&(owner, id)), ctx.now)
            .await
            .ok_or(AuthError::Unauthenticated)?;
        let member = find(confirmed.as_ref())?.ok_or(AuthError::Unauthenticated)?;
        Ok((confirmed, member, false))
    }

    /// Removes the scoped token `id` of `owner` with its family (IAM-20), audited as
    /// `auth.token.revoke`. A renewal committed in between makes the write fail; it is tried
    /// again, up to [`REMOVE_TRIES`] times. `Ok(false)` when there is no such token.
    pub(super) async fn remove_scoped_token(
        &self,
        ctx: &RequestCtx,
        owner: UserId,
        id: ApiTokenId,
    ) -> Result<bool, AuthError> {
        for attempt in 1..=REMOVE_TRIES {
            let view = self.view().await?;
            let Some((key, _)) = view.get_typed(&USER_SCOPED_TOKENS, &(owner, id))? else {
                return Ok(false);
            };
            let mut batch = WriteBatch::for_request(ctx);
            Self::stage_token_removal(view.as_ref(), &mut batch, owner, id, key)?;
            batch.audit(Self::audit(
                actions::TOKEN_REVOKE,
                vec![ObjectRef::from(owner), ObjectRef::from(id)],
                ctx,
            ));
            match self.commit(batch).await {
                Err(AuthError::Conflict) if attempt < REMOVE_TRIES => {}
                result => {
                    result?;
                    break;
                }
            }
        }
        self.refresh_warnings_quietly(ctx.now).await;
        Ok(true)
    }

    /// The members of `family` among the scoped tokens of `owner`, live and retired.
    pub(super) fn family(
        view: &dyn ReadView,
        owner: UserId,
        family: ApiTokenId,
    ) -> Result<Vec<Member>, AuthError> {
        let mut members = Vec::new();
        for (_, key, _) in view.scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(owner,))),
            LIST_LIMIT,
            false,
        )? {
            if let Some((record, revision)) = view.get_typed(&SCOPED_TOKENS, &key)?
                && record.renewal.as_ref().is_some_and(|r| r.family == family)
            {
                members.push((key, record, revision));
            }
        }
        Ok(members)
    }

    /// Stages the removal of the scoped token `id` of `owner` stored under `key`, with every
    /// other token of its family (IAM-20), each at the revision read: a renewal committed in
    /// between makes the write fail instead of leaving its new token behind.
    pub(super) fn stage_token_removal(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        owner: UserId,
        id: ApiTokenId,
        key: Vec<u8>,
    ) -> Result<(), AuthError> {
        let found = view.get_typed(&SCOPED_TOKENS, &key)?;
        let members = match found
            .as_ref()
            .and_then(|(record, _)| record.renewal.as_ref())
        {
            Some(renewal) => Self::family(view, owner, renewal.family)?,
            None => found
                .map(|(record, revision)| vec![(key, record, revision)])
                .unwrap_or_default(),
        };
        if members.is_empty() {
            batch.delete_typed(&USER_SCOPED_TOKENS, &(owner, id));
        }
        for (member_key, member, revision) in &members {
            batch.expect_typed(&SCOPED_TOKENS, member_key, Some(*revision));
            batch.delete_typed(&SCOPED_TOKENS, member_key);
            batch.delete_typed(&USER_SCOPED_TOKENS, &(owner, member.id));
        }
        Ok(())
    }

    /// Stages the revocation of a family: every member is removed, and the newest is kept
    /// under its retired key with `reason` for the token list and the health warning.
    fn stage_revocation(
        batch: &mut WriteBatch,
        members: &[Member],
        reason: RevocationReason,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let Some((newest_key, newest, _)) = members
            .iter()
            .max_by_key(|(_, record, _)| record.created_at)
        else {
            return Ok(());
        };
        let kept = if newest.retired() {
            newest_key.clone()
        } else {
            retired_key(newest_key)
        };
        for (key, record, revision) in members {
            batch.expect_typed(&SCOPED_TOKENS, key, Some(*revision));
            if *key != kept {
                batch.delete_typed(&SCOPED_TOKENS, key);
            }
            if record.id != newest.id {
                batch.delete_typed(&USER_SCOPED_TOKENS, &(record.owner, record.id));
            }
        }
        let mut marker = newest.clone();
        if let Some(renewal) = marker.renewal.as_mut() {
            renewal.revoked = Some(TokenRevocation { at: now, reason });
        }
        batch.put_typed(&SCOPED_TOKENS, &kept, &marker)?;
        batch.put_typed(&USER_SCOPED_TOKENS, &(marker.owner, marker.id), &kept)?;
        Ok(())
    }

    fn reuse_audit(
        presented: &ScopedTokenRecord,
        reason: RevocationReason,
        ctx: &RequestCtx,
    ) -> AuditDraft {
        AuditDraft::denied(
            actions::TOKEN_REUSE_DETECTED,
            vec![
                ObjectRef::from(presented.owner),
                ObjectRef::from(presented.id),
            ],
        )
        .with_source_ip(ctx.source_ip)
        .with_context("name", presented.name.clone())
        .with_context("reason", reason_text(reason))
    }

    /// Stages the removal of the oldest superseded members of a family beyond [`RETIRED_KEPT`],
    /// counting `adding` that the same write retires: reuse of a token that old is refused like
    /// an unknown one, and a family stays a bounded scan however often it renews.
    fn stage_prune(batch: &mut WriteBatch, members: &[Member], adding: usize) {
        let mut superseded: Vec<&Member> = members
            .iter()
            .filter(|(_, member, _)| {
                member
                    .renewal
                    .as_ref()
                    .is_some_and(|r| r.superseded() && r.revoked.is_none())
            })
            .collect();
        superseded.sort_by_key(|(_, member, _)| std::cmp::Reverse(member.created_at));
        for (key, member, revision) in superseded
            .into_iter()
            .skip(RETIRED_KEPT.saturating_sub(adding))
        {
            batch.expect_typed(&SCOPED_TOKENS, key, Some(*revision));
            batch.delete_typed(&SCOPED_TOKENS, key);
            batch.delete_typed(&USER_SCOPED_TOKENS, &(member.owner, member.id));
        }
    }

    /// Stages the supersede of the predecessor of `record` at its first use (IAM-20): the
    /// predecessor moves under its retired key in the write that records the use.
    pub(super) fn stage_supersede(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        record: &ScopedTokenRecord,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let Some(renewal) = &record.renewal else {
            return Ok(());
        };
        if record.last_used_at.is_some() || renewal.family == record.id {
            return Ok(());
        }
        let members = Self::family(view, record.owner, renewal.family)?;
        Self::stage_prune(batch, &members, 1);
        for (key, mut predecessor, revision) in members {
            if predecessor.retired()
                || predecessor.renewal.as_ref().and_then(|r| r.successor) != Some(record.id)
            {
                continue;
            }
            if let Some(renewal) = predecessor.renewal.as_mut() {
                renewal.superseded_at = Some(now);
            }
            let retired = retired_key(&key);
            batch.expect_typed(&SCOPED_TOKENS, &key, Some(revision));
            batch.delete_typed(&SCOPED_TOKENS, &key);
            batch.put_typed(&SCOPED_TOKENS, &retired, &predecessor)?;
            batch.put_typed(
                &USER_SCOPED_TOKENS,
                &(predecessor.owner, predecessor.id),
                &retired,
            )?;
        }
        Ok(())
    }

    /// The reuse of a family bound to a certificate lineage: it was presented with a key of
    /// the lineage, so someone else holds that key, and the lineage is revoked in the same
    /// write (ADR 0035, decision 9). Nothing for an unbound family.
    fn stage_lineage_reuse(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        record: &ScopedTokenRecord,
        ctx: &RequestCtx,
    ) -> Result<(), AuthError> {
        let Some(lineage) = record.lineage else {
            return Ok(());
        };
        let serials = crate::client_cert::revoke::stage_lineage_revocation(
            view,
            batch,
            lineage,
            "reuse of a token family bound to it",
            ctx.now,
        )?;
        if !serials.is_empty() {
            batch.audit(
                AuditDraft::success(
                    crate::client_cert::actions::REVOKE,
                    vec![ObjectRef::from(record.owner)],
                )
                .with_source_ip(ctx.source_ip)
                .with_context("lineage", lineage.to_string())
                .with_context("serials", serials.join(","))
                .with_context("reason", "reuse of a token family bound to it"),
            );
        }
        Ok(())
    }

    /// Whether the settings require `record` to be bound ([`super::access::binding_required`]);
    /// a token whose owner cannot be read counts as required, so a store error refuses.
    fn binding_missing(&self, view: &dyn ReadView, record: &ScopedTokenRecord) -> bool {
        let settings = self.settings();
        if !settings.integrations().require_binding {
            return false;
        }
        match view.get_typed(&USERS, &record.owner) {
            Ok(Some((owner, _))) => {
                super::access::binding_required(&owner, &record.scopes, &settings)
            }
            Ok(None) | Err(_) => true,
        }
    }

    /// Whether a presented token is refused, and what the refusal triggers: the one place
    /// for it. The bindings come first and trigger nothing but their refusal and its audit:
    /// the form of the token text must match its record (`tnk_`, `tnkc_` or `tnkb_`), a
    /// token bound to a certificate lineage must arrive over a connection whose certificate
    /// belongs to that lineage (`lineage`, ADR 0035), and a scoped token must come from inside
    /// its source prefixes (IAM-21), so an old token text found in a log cannot revoke a
    /// working integration from anywhere, and a bound token presented without its key revokes
    /// nothing. Only then does a retired token count as reuse (IAM-20).
    pub(super) async fn presentation_refused(
        &self,
        view: &Arc<dyn ReadView>,
        found: &super::FoundToken,
        form: crate::secret::TokenForm,
        lineage: Option<uuid::Uuid>,
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) -> bool {
        let (record, retired) = match found {
            super::FoundToken::Personal(record, _) => {
                let refused = form != crate::secret::TokenForm::Plain;
                if refused {
                    let objects = vec![ObjectRef::from(record.owner), ObjectRef::from(record.id)];
                    self.refusal_audit(
                        actions::TOKEN_FORM_REFUSED,
                        record.id,
                        objects,
                        &record.name,
                        source_ip,
                        now,
                    )
                    .await;
                }
                return refused;
            }
            super::FoundToken::Scoped(record, _) => (record, false),
            super::FoundToken::Retired(record) => (record, true),
        };
        let objects = || vec![ObjectRef::from(record.owner), ObjectRef::from(record.id)];
        if record.form() != form {
            self.refusal_audit(
                actions::TOKEN_FORM_REFUSED,
                record.id,
                objects(),
                &record.name,
                source_ip,
                now,
            )
            .await;
            return true;
        }
        // TGL-47: the binding a token carries, and the binding the settings require of it
        // now, also of a token created before the requirement or on a controller that had
        // not seen it yet (ADR 0035, decision 10).
        if (record.lineage.is_some() && record.lineage != lineage)
            || (record.lineage.is_none() && self.binding_missing(view.as_ref(), record))
        {
            self.refusal_audit(
                actions::TOKEN_BINDING_REFUSED,
                record.id,
                objects(),
                &record.name,
                source_ip,
                now,
            )
            .await;
            return true;
        }
        if !record.admits_source(source_ip) {
            self.refusal_audit(
                actions::TOKEN_SOURCE_REFUSED,
                record.id,
                objects(),
                &record.name,
                source_ip,
                now,
            )
            .await;
            return true;
        }
        if retired {
            self.retired_token_used(Arc::clone(view), record, source_ip, now)
                .await;
        }
        retired
    }

    /// A retired token was presented from inside its prefixes: a superseded or replaced one
    /// revokes its family as reuse (IAM-20); a revoked one, one past its own expiry, and a
    /// superseded one within [`SUPERSEDED_GRACE`] of its supersede are only refused, and so is
    /// every one while the clock guard holds the clock (audited with `clock_held`).
    async fn retired_token_used(
        &self,
        view: Arc<dyn ReadView>,
        record: &ScopedTokenRecord,
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) {
        let Some(renewal) = record.renewal.as_ref().filter(|r| r.revoked.is_none()) else {
            return;
        };
        let in_grace = !renewal.replaced
            && renewal
                .superseded_at
                .is_some_and(|at| now.saturating_since(at) < SUPERSEDED_GRACE);
        let expired =
            effective_token_expiry(record.created_at, record.expires_at, &self.settings())
                .is_some_and(|end| end <= now);
        if in_grace || expired {
            return;
        }
        tracing::warn!(token = %record.id, source = ?source_ip, "a superseded token was used");
        // A clock the guard holds may misjudge the grace: the use is refused and audited, and
        // the family stays.
        let held = tenko_core::clock::trusted_now().err();
        let ctx = RequestCtx {
            source_ip,
            ..RequestCtx::system(SystemComponent::Auth).at(now)
        };
        let audit_only = || {
            let mut batch = WriteBatch::new(ctx.principal.clone(), now);
            let draft = Self::reuse_audit(record, RevocationReason::ReuseDetected, &ctx);
            batch.audit(match &held {
                Some(held) => draft.with_context("clock_held", held.reason.as_str()),
                None => draft,
            });
            batch
        };
        let decide = |view: &dyn ReadView| -> Result<_, AuthError> {
            let members = Self::family(view, record.owner, renewal.family)?;
            let mut batch = audit_only();
            // Held, or another controller revoked the family meanwhile (once is enough).
            if held.is_some()
                || members.iter().any(|(_, member, _)| {
                    member.renewal.as_ref().is_some_and(|r| r.revoked.is_some())
                })
            {
                return Ok((batch, ()));
            }
            Self::stage_revocation(&mut batch, &members, RevocationReason::ReuseDetected, now)?;
            Self::stage_lineage_reuse(view, &mut batch, record, &ctx)?;
            Ok((batch, ()))
        };
        if let Err(error) = self.propose_decided(view, decide, audit_only()).await {
            tracing::warn!(%error, "could not revoke a token family");
        }
        self.refresh_warnings_quietly(now).await;
    }

    /// The token warnings the last sweep computed (IAM-20), for the system status.
    pub fn token_warnings(&self) -> Vec<CodedError> {
        self.token_warnings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Computes the token warnings again from this controller's copy: the hourly sweep, and
    /// at once after this controller revoked a family or removed a token.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn refresh_token_warnings(&self, now: Timestamp) -> Result<(), AuthError> {
        let view = self.view().await?;
        let warnings = compute_warnings(view.as_ref(), &self.settings(), now)?;
        *self
            .token_warnings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = warnings;
        Ok(())
    }

    pub(super) async fn refresh_warnings_quietly(&self, now: Timestamp) {
        if let Err(error) = self.refresh_token_warnings(now).await {
            tracing::debug!(%error, "the token warnings could not be computed");
        }
    }

    /// The audit record of token `id` refused by a binding, at most one a minute per token
    /// with the number of refusals since the last one; the caller refuses it like an unknown
    /// token.
    async fn refusal_audit(
        &self,
        action: tenko_core::audit::AuditAction,
        id: ApiTokenId,
        objects: Vec<ObjectRef>,
        name: &str,
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) {
        let Some(since) = self.misses.refusal(id, now) else {
            return;
        };
        let mut draft = AuditDraft::denied(action, objects)
            .with_source_ip(source_ip)
            .with_context("name", name.to_owned());
        if since > 0 {
            draft = draft.with_context("refused_since", since.to_string());
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        batch.audit(draft);
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused token");
        }
    }

    /// Writes the audit record [`actions::TOKEN_EXPIRING`] once for every live
    /// service-account token with fewer than 14 days left, and notes it on
    /// the record. A record changed meanwhile is left for the next sweep. Returns how many
    /// were written.
    ///
    /// # Errors
    ///
    /// A store error reading the tokens.
    pub async fn notice_expiring_tokens(&self, now: Timestamp) -> Result<usize, AuthError> {
        let view = self.view().await?;
        let settings = self.settings();
        let mut noticed = 0;
        for (key, record, revision) in
            view.scan_typed(&SCOPED_TOKENS, KeyRange::all(), usize::MAX, false)?
        {
            let Some(end) = expiring_end(&record, &settings, now) else {
                continue;
            };
            if record.expiry_noticed_at.is_some() || !is_service(view.as_ref(), record.owner)? {
                continue;
            }
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            batch.expect_typed(&SCOPED_TOKENS, &key, Some(revision));
            batch.put_typed(
                &SCOPED_TOKENS,
                &key,
                &ScopedTokenRecord {
                    expiry_noticed_at: Some(now),
                    ..record.clone()
                },
            )?;
            batch.audit(
                AuditDraft::success(
                    actions::TOKEN_EXPIRING,
                    vec![ObjectRef::from(record.owner), ObjectRef::from(record.id)],
                )
                .with_context("name", record.name.clone())
                .with_context("expires_at", end.to_rfc3339()),
            );
            match self.store.propose(batch).await {
                Ok(_) => noticed += 1,
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => tracing::warn!(%error, "could not note an expiring token"),
            }
        }
        Ok(noticed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_prefixes_take_networks_and_host_addresses() {
        let parsed = parse_source_prefixes(&[
            " 192.0.2.77/24".to_owned(),
            "2001:db8::1".to_owned(),
            "192.0.2.0/24".to_owned(),
        ])
        .expect("valid prefixes");
        assert_eq!(
            parsed,
            vec![
                "192.0.2.0/24".parse::<IpNet>().expect("a network"),
                "2001:db8::1/128".parse::<IpNet>().expect("a host"),
            ]
        );
        assert_eq!(
            parse_source_prefixes(&["::ffff:198.51.100.0/120".to_owned()])
                .expect("a mapped prefix"),
            vec!["198.51.100.0/24".parse::<IpNet>().expect("a network")]
        );
        for refused in [
            vec!["example.test".to_owned()],
            vec!["192.0.2.1".to_owned(); 65],
            vec!["0.0.0.0/0".to_owned()],
            vec!["::/0".to_owned()],
        ] {
            assert!(matches!(
                parse_source_prefixes(&refused),
                Err(AuthError::Invalid {
                    field: "source_prefixes",
                    ..
                })
            ));
        }
    }
}
