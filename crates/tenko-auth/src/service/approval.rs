//! The steps of an approval (`crate::approval`, ADR 0038) and the plan of a delegated session.

use std::{net::IpAddr, time::Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tenko_core::{
    Action, ApprovalId, DelegationId, MirrorId, ObjectKind, ObjectRef, Principal, RequestCtx,
    SessionId, SystemComponent, Timestamp, UserId,
    audit::{AuditAction, AuditDraft},
    auth::Delegated,
    migrate::plan::TakeoverPlan,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{AuthService, LIST_LIMIT, SecretString};
use crate::{
    approval::{
        self, APPROVAL_PLANS, APPROVALS, AUDIT_EVERY, ApprovalRecord, ApprovalState,
        ApprovalTicket, ApprovalView, Decision, DelegatedSession, LOOKUP_LOCK, MAX_PENDING,
        MAX_PENDING_PER_SOURCE, PENDING_LIFETIME, REQUEST_SPACING, Refusal, WRONG_CODE_WINDOW,
        WRONG_CODES, actions,
    },
    delegation,
    encoding::hex_encode,
    error::AuthError,
    model::{SESSIONS, SessionRecord, USER_SESSIONS, USERS},
};

impl AuthService {
    /// `POST /auth/approvals`: a script's request, from `ctx.source_ip`, with the body as
    /// sent. Writes the approval and its plan and answers its id and nonce; it reads the small
    /// rows of the approvals only, and removes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Limit`] past a bound or without a source address, [`Refusal::Plan`] for a
    /// body outside Tenko's limits, or a store error.
    pub async fn request_approval(
        &self,
        ctx: &RequestCtx,
        body: &[u8],
    ) -> Result<ApprovalTicket, AuthError> {
        let source = ctx.source_ip.ok_or(Refusal::Limit("source"))?;
        let bucket = approval::source_bucket(source);
        let started = Instant::now();
        let address = match source {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        if self
            .approval_paces
            .requests
            .hit(&address, started, REQUEST_SPACING)
            > 1
        {
            return Err(Refusal::Limit("spacing").into());
        }
        let (request, key, plan_hash) = approval::parse_request(body)?;
        let view = self.view().await?;
        let (mut pending, mut from_source) = (0, 0);
        for (_, record, _) in view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)? {
            if record.pending(ctx.now) {
                pending += 1;
                from_source += usize::from(approval::source_bucket(record.source) == bucket);
            }
        }
        if pending >= MAX_PENDING {
            return Err(Refusal::Limit("pending").into());
        }
        if from_source >= MAX_PENDING_PER_SOURCE {
            return Err(Refusal::Limit("source").into());
        }
        let nonce = crate::random::array::<32>()?;
        let record = ApprovalRecord {
            id: ApprovalId::generate(),
            purpose: request.purpose,
            domain: request.plan.domain.clone(),
            plan_hash,
            key,
            nonce: nonce.to_vec(),
            client: request.client,
            source,
            state: ApprovalState::Pending,
            created_at: ctx.now,
            mirrors: Vec::new(),
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&APPROVALS, &record.id, None);
        batch.put_typed(&APPROVALS, &record.id, &record)?;
        batch.put_typed(&APPROVAL_PLANS, &record.id, &request.plan)?;
        if self
            .approval_paces
            .request_audits
            .hit(&bucket, started, AUDIT_EVERY)
            == 1
        {
            batch.audit(
                AuditDraft::success(actions::REQUEST, Vec::new())
                    .with_source_ip(ctx.source_ip)
                    .with_context("approval", record.id.to_string())
                    .with_context("domain", record.domain.as_str())
                    .with_context("request_sha256", hex_encode(&record.plan_hash))
                    .with_context("machine", record.client.machine.clone())
                    .with_context("windows_user", record.client.user.clone()),
            );
        }
        self.commit(batch).await?;
        Ok(ApprovalTicket {
            id: record.id,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        })
    }

    /// `POST /auth/approvals/lookup`: the pending approval whose code is `code` over this
    /// node's TLS root `root`, for an administrator who signed in within the last five
    /// minutes.
    ///
    /// # Errors
    ///
    /// [`Refusal::Code`] when nothing matches, [`Refusal::Ambiguous`] when two do,
    /// [`Refusal::Limit`] while the browser session's lookups are locked, and the errors of
    /// the approver's checks.
    pub async fn look_up_approval(
        &self,
        ctx: &RequestCtx,
        code: &SecretString,
        root: &[u8; 32],
    ) -> Result<ApprovalView, AuthError> {
        let (user, session) = self.approver(ctx, true).await?;
        self.unlocked(session)?;
        let view = self.view().await?;
        let mut found = view
            .scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)?
            .into_iter()
            .filter(|(_, record, _)| record.pending(ctx.now) && matches(record, code, root))
            .map(|(_, record, _)| record);
        match (found.next(), found.next()) {
            (Some(record), None) => Ok(record.view(plan_of(view.as_ref(), record.id)?, ctx.now)),
            (Some(_), Some(_)) => Err(Refusal::Ambiguous.into()),
            (None, _) => Err(self.wrong_code(ctx, user, session).await),
        }
    }

    /// `POST /auth/approvals/{id}/approve`: the person approves the request whose code they
    /// typed again, after a sign-in within the last five minutes. At most one approval per
    /// domain is approved or has a delegated session alive at a time.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotFound`], [`Refusal::Expired`], [`Refusal::Code`], [`Refusal::Denied`],
    /// [`Refusal::Consumed`], [`Refusal::Limit`], and the errors of the approver's checks.
    pub async fn approve(
        &self,
        ctx: &RequestCtx,
        id: ApprovalId,
        code: &SecretString,
        root: &[u8; 32],
    ) -> Result<ApprovalView, AuthError> {
        let (user, session) = self.approver(ctx, true).await?;
        self.unlocked(session)?;
        let view = self.view().await?;
        let (mut record, revision) = view.get_typed(&APPROVALS, &id)?.ok_or(Refusal::NotFound)?;
        if !matches!(record.state, ApprovalState::Pending) || record.expired(ctx.now) {
            return Err(undecided_refusal(&record, ctx.now).into());
        }
        if !matches(&record, code, root) {
            return Err(self.wrong_code(ctx, user, session).await);
        }
        let settings = self.settings();
        for (_, other, _) in view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)? {
            let open = match &other.state {
                ApprovalState::Approved(_) => !other.expired(ctx.now),
                // Open only while its delegated session holds: a session that lapsed, or whose
                // approver may no longer act, frees the domain whether or not its row is gone.
                ApprovalState::Consumed {
                    decision, session, ..
                } => Self::load_session(view.as_ref(), decision.by, *session)?.is_some_and(
                    |(_, live)| {
                        Self::session_holds(view.as_ref(), &live, &settings, ctx.now).is_ok()
                    },
                ),
                _ => false,
            };
            if open && other.id != id && other.domain == record.domain {
                return Err(Refusal::Limit("domain").into());
            }
        }
        let strength = ctx.principal.strength().ok_or(AuthError::Unauthenticated)?;
        let (account, _) = view
            .get_typed(&USERS, &user)?
            .ok_or(AuthError::Unauthenticated)?;
        let delegation = DelegationId::generate();
        record.state = ApprovalState::Approved(Decision {
            by: user,
            session,
            strength,
            at: ctx.now,
            delegation,
            generation: account.sessions_generation,
        });
        let plan = plan_of(view.as_ref(), id)?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&APPROVALS, &id, Some(revision));
        batch.put_typed(&APPROVALS, &id, &record)?;
        batch.audit(
            decision_audit(actions::APPROVE, &record, user, session, ctx)
                .with_context("delegation", delegation.to_string())
                .with_context("zones", plan.zones.len().to_string())
                .with_context("controllers", plan.controllers.len().to_string())
                .with_context("dhcp_servers", plan.dhcp_servers.len().to_string())
                .with_context("scopes", plan.scopes.len().to_string()),
        );
        self.commit(batch).await?;
        Ok(record.view(plan, ctx.now))
    }

    /// `POST /auth/approvals/{id}/deny`: an administrator refuses a waiting request, or
    /// withdraws an approval the script has not collected yet.
    ///
    /// # Errors
    ///
    /// As [`AuthService::approve`], without the freshness and the code.
    pub async fn deny_approval(&self, ctx: &RequestCtx, id: ApprovalId) -> Result<(), AuthError> {
        let (user, session) = self.approver(ctx, false).await?;
        let view = self.view().await?;
        let (record, revision) = view.get_typed(&APPROVALS, &id)?.ok_or(Refusal::NotFound)?;
        if !deniable(&record, ctx.now) {
            return Err(undecided_refusal(&record, ctx.now).into());
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(decision_audit(actions::DENY, &record, user, session, ctx));
        stage_denial(&mut batch, record, revision, user, ctx.now)?;
        self.commit(batch).await?;
        Ok(())
    }

    /// `POST /auth/approvals/clear`: an administrator who signed in within the last five
    /// minutes denies every waiting request and every approval not collected yet, or only
    /// those whose source is `source`'s (its IPv4 address or IPv6 /64). Answers how many.
    ///
    /// # Errors
    ///
    /// The errors of the approver's checks, or a store error.
    pub async fn clear_approvals(
        &self,
        ctx: &RequestCtx,
        source: Option<IpAddr>,
    ) -> Result<usize, AuthError> {
        let (user, session) = self.approver(ctx, true).await?;
        let bucket = source.map(approval::source_bucket);
        let view = self.view().await?;
        let mut batch = WriteBatch::for_request(ctx);
        let mut denied = 0;
        for (_, record, revision) in
            view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)?
        {
            let chosen = bucket
                .as_ref()
                .is_none_or(|bucket| approval::source_bucket(record.source) == *bucket);
            if chosen && deniable(&record, ctx.now) {
                batch.audit(decision_audit(actions::DENY, &record, user, session, ctx));
                stage_denial(&mut batch, record, revision, user, ctx.now)?;
                denied += 1;
            }
        }
        if denied > 0 {
            self.commit(batch).await?;
        }
        Ok(denied)
    }

    /// `POST /auth/approvals/{id}/collect`: the script proves its key by signing the nonce,
    /// from the request's source address, and receives the delegated session once, while its
    /// approver may still administer under the same sessions generation as at the approval.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotFound`] for another source, [`Refusal::Signature`], [`Refusal::Pending`],
    /// [`Refusal::Denied`], [`Refusal::Expired`], [`Refusal::Consumed`];
    /// [`AuthError::Unauthenticated`] when the approver may no longer administer or ended their
    /// sessions since the approval.
    pub async fn collect_approval(
        &self,
        ctx: &RequestCtx,
        id: ApprovalId,
        body: &[u8],
    ) -> Result<DelegatedSession, AuthError> {
        let signature = approval::parse_collect(body)?;
        let view = self.view().await?;
        let (mut record, revision) = view.get_typed(&APPROVALS, &id)?.ok_or(Refusal::NotFound)?;
        let refused = |reason: &'static str| {
            AuditDraft::denied(actions::REFUSE, Vec::new())
                .with_source_ip(ctx.source_ip)
                .with_context("approval", id.to_string())
                .with_context("reason", reason)
        };
        let pace = record.source.to_string();
        if ctx.source_ip != Some(record.source) {
            self.approval_refusal_audit(
                &ctx.principal,
                pace.as_bytes(),
                refused("source"),
                ctx.now,
            )
            .await;
            return Err(Refusal::NotFound.into());
        }
        if !approval::verify_collect(&record.key, id, &record.nonce, &signature) {
            self.approval_refusal_audit(
                &ctx.principal,
                pace.as_bytes(),
                refused("signature"),
                ctx.now,
            )
            .await;
            return Err(Refusal::Signature.into());
        }
        let decision = collectable(&record, ctx.now)?;
        let Some((user, _)) = view.get_typed(&USERS, &decision.by)?.filter(|(user, _)| {
            !user.disabled
                && !user.is_service()
                && user.is_admin()
                && user.sessions_generation == decision.generation
        }) else {
            self.approval_refusal_audit(
                &ctx.principal,
                pace.as_bytes(),
                refused("approver"),
                ctx.now,
            )
            .await;
            return Err(AuthError::Unauthenticated);
        };
        let (absolute, idle) = super::delegated_lifetimes(&self.settings());
        let expires_at = decision.at.checked_add(absolute).ok_or(Refusal::Expired)?;
        let secret = crate::secret::new_delegation_secret()?;
        let session = delegated_session(&record, &user, &decision, expires_at, idle, ctx.now);
        let delegated = session.delegation.ok_or(Refusal::NotFound)?;
        let cx = RequestCtx {
            principal: Principal::User {
                id: user.id,
                session: session.id,
                strength: session.strength,
                delegation: Some(delegated.id),
            },
            ..ctx.clone()
        };
        record.state = ApprovalState::Consumed {
            decision,
            session: session.id,
            at: ctx.now,
        };
        let hash = secret.hash();
        let mut batch = WriteBatch::for_request(&cx);
        batch.expect_typed(&APPROVALS, &id, Some(revision));
        batch.put_typed(&APPROVALS, &id, &record)?;
        batch.put_typed(&SESSIONS, &hash, &session)?;
        batch.put_typed(&USER_SESSIONS, &(user.id, session.id), &hash)?;
        batch.audit(
            AuditDraft::success(
                actions::COLLECT,
                vec![ObjectRef::from(user.id), ObjectRef::from(session.id)],
            )
            .with_source_ip(ctx.source_ip)
            .with_context("approval", id.to_string())
            .with_context("delegation", delegated.id.to_string())
            .with_context("request_sha256", hex_encode(&record.plan_hash)),
        );
        match self.commit(batch).await {
            Err(AuthError::Conflict) => return Err(Refusal::Consumed.into()),
            result => result?,
        };
        Ok(DelegatedSession {
            secret: SecretString::new(secret.expose()),
            session: session.id,
            delegation: delegated.id,
            expires_at,
            idle_secs: idle.as_secs(),
        })
    }

    /// The plan of the run a delegated session acts for, which its listed handlers check
    /// their bodies against.
    ///
    /// # Errors
    ///
    /// [`AuthError::DelegationRefused`] for any other principal or a session without its
    /// approval.
    pub async fn delegation_plan(&self, ctx: &RequestCtx) -> Result<TakeoverPlan, AuthError> {
        let view = self.view().await?;
        let delegated =
            Self::delegated_of(ctx, view.as_ref())?.ok_or(AuthError::DelegationRefused)?;
        view.get_typed(&APPROVAL_PLANS, &delegated.approval)?
            .map(|(plan, _)| plan)
            .ok_or(AuthError::DelegationRefused)
    }

    /// For a delegated session, stages the mirror `mirror` into its approval and answers
    /// `true`: within [`delegation::MIRROR_WINDOW`] of the approval on this controller's
    /// clock, and at most one mirror per DHCP server of the plan, in the batch that creates
    /// the mirror. Answers `false` for any other principal.
    ///
    /// # Errors
    ///
    /// [`AuthError::DelegationRefused`] past the window or the plan's count.
    pub(super) fn stage_delegated_mirror(
        ctx: &RequestCtx,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        mirror: MirrorId,
    ) -> Result<bool, AuthError> {
        let Some(delegated) = Self::delegated_of(ctx, view)? else {
            return Ok(false);
        };
        if !delegation::within_approval(&delegated, ctx.now) {
            return Err(AuthError::DelegationRefused);
        }
        let (mut record, revision) = view
            .get_typed(&APPROVALS, &delegated.approval)?
            .ok_or(AuthError::DelegationRefused)?;
        let servers = plan_of(view, delegated.approval)
            .map_err(|_| AuthError::DelegationRefused)?
            .dhcp_servers
            .len();
        if record.mirrors.len() >= servers {
            return Err(AuthError::DelegationRefused);
        }
        record.mirrors.push(mirror);
        batch.expect_typed(&APPROVALS, &delegated.approval, Some(revision));
        batch.put_typed(&APPROVALS, &delegated.approval, &record)?;
        Ok(true)
    }

    /// The delegation of a delegated session's live record; `None` for any other principal.
    fn delegated_of(ctx: &RequestCtx, view: &dyn ReadView) -> Result<Option<Delegated>, AuthError> {
        if ctx.principal.delegation().is_none() {
            return Ok(None);
        }
        let (user, session, _) = Self::session_principal(ctx)?;
        let (_, _, _, record) = Self::live_session(view, user, session)?;
        record
            .delegation
            .map(Some)
            .ok_or(AuthError::DelegationRefused)
    }

    /// Removes the approvals that are over: a consumed one [`delegation::LIFETIME`] after its
    /// collect, every other one [`PENDING_LIFETIME`] after its request, on this controller's
    /// clock standing that far after the row's time (a clock that stands before it removes
    /// nothing). Part of the hourly sweep.
    pub(super) async fn prune_approvals(&self, now: Timestamp) -> Result<(), AuthError> {
        let view = self.view().await?;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        for (id, record, _) in view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)? {
            let (since, kept) = match record.state {
                ApprovalState::Consumed { at, .. } => (at, delegation::LIFETIME),
                _ => (record.created_at, PENDING_LIFETIME),
            };
            if now >= since && now.saturating_since(since) >= kept {
                batch.delete_typed(&APPROVALS, &id);
                batch.delete_typed(&APPROVAL_PLANS, &id);
            }
        }
        if !batch.mutations.is_empty() {
            self.commit(batch).await?;
        }
        Ok(())
    }

    /// Audits a delegated session presented from another address than its approval's, at
    /// most once a minute per session.
    pub(super) async fn audit_delegated_source(
        &self,
        session: &SessionRecord,
        source: Option<IpAddr>,
        now: Timestamp,
    ) {
        let Some(delegated) = session.delegation else {
            return;
        };
        let principal = Principal::User {
            id: session.user,
            session: session.id,
            strength: session.strength,
            delegation: Some(delegated.id),
        };
        let draft = AuditDraft::denied(
            actions::REFUSE,
            vec![ObjectRef::from(session.user), ObjectRef::from(session.id)],
        )
        .with_source_ip(source)
        .with_context("approval", delegated.approval.to_string())
        .with_context("reason", "session_source");
        self.approval_refusal_audit(&principal, session.id.uuid().as_bytes(), draft, now)
            .await;
    }

    /// Writes the audit record of a refusal on its own, at most once a minute per `pace`
    /// (a browser session, a delegated session or a source).
    async fn approval_refusal_audit(
        &self,
        principal: &Principal,
        pace: &[u8],
        draft: AuditDraft,
        now: Timestamp,
    ) {
        if self
            .approval_paces
            .refusals
            .hit(pace, Instant::now(), AUDIT_EVERY)
            != 1
        {
            return;
        }
        let mut batch = WriteBatch::new(principal.clone(), now);
        batch.audit(draft);
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused approval step");
        }
    }

    /// The approver of `ctx`: an administrator's own session, never a delegated session or a
    /// token, and with `fresh` one that signed in within the last five minutes (a passkey
    /// under Hardened, by the administrator role's strength).
    async fn approver(
        &self,
        ctx: &RequestCtx,
        fresh: bool,
    ) -> Result<(UserId, SessionId), AuthError> {
        let (user, session, _) = Self::session_principal(ctx)?;
        if ctx.principal.delegation().is_some() {
            return Err(AuthError::DelegationRefused);
        }
        self.authorize(
            ctx,
            Action::Administer,
            ObjectRef::singleton(ObjectKind::System),
        )
        .await?;
        if fresh {
            self.require_fresh_person(ctx).await?;
        }
        Ok((user, session))
    }

    /// Refuses the code lookups of a browser session that typed [`WRONG_CODES`] wrong codes.
    fn unlocked(&self, session: SessionId) -> Result<(), Refusal> {
        let locked = self.approval_paces.locks.active(
            session.uuid().as_bytes(),
            Instant::now(),
            LOOKUP_LOCK,
        );
        if locked {
            return Err(Refusal::Limit("lookups"));
        }
        Ok(())
    }

    /// A code that matched nothing: counted for the browser session, which is locked after
    /// [`WRONG_CODES`] within [`WRONG_CODE_WINDOW`], and audited at most once a minute.
    async fn wrong_code(&self, ctx: &RequestCtx, user: UserId, session: SessionId) -> AuthError {
        let uuid = session.uuid();
        let key = uuid.as_bytes();
        let paces = &self.approval_paces;
        let now = Instant::now();
        if paces.wrong_codes.hit(key, now, WRONG_CODE_WINDOW) >= WRONG_CODES {
            paces.locks.hit(key, now, LOOKUP_LOCK);
        }
        let draft = AuditDraft::denied(
            actions::REFUSE,
            vec![ObjectRef::from(user), ObjectRef::from(session)],
        )
        .with_source_ip(ctx.source_ip)
        .with_context("reason", "code");
        self.approval_refusal_audit(&ctx.principal, key, draft, ctx.now)
            .await;
        Refusal::Code.into()
    }
}

/// The delegated session of `user` for the approved `record`, created at `now`: never fresh
/// (the Unix epoch as its sign-in), bound to the request's source, ending at `expires_at` or
/// `idle` after its last request, and described in the session list by what the script
/// reported.
fn delegated_session(
    record: &ApprovalRecord,
    user: &crate::model::UserRecord,
    decision: &Decision,
    expires_at: Timestamp,
    idle: std::time::Duration,
    now: Timestamp,
) -> SessionRecord {
    SessionRecord {
        id: SessionId::generate(),
        user: user.id,
        strength: decision.strength,
        created_at: now,
        authenticated_at: Timestamp::UNIX_EPOCH,
        expires_at,
        idle_expires_at: now.checked_add(idle).unwrap_or(now).min(expires_at),
        last_seen_at: now,
        source_ip: Some(record.source),
        user_agent: Some(format!(
            "takeover script {} on {} as {}",
            record.client.version, record.client.machine, record.client.user
        )),
        break_glass: false,
        mfa_enrollment_required: false,
        source: crate::directory::SessionSource::Local,
        directory_checked_at: None,
        generation: user.sessions_generation,
        delegation: Some(Delegated {
            id: decision.delegation,
            approval: record.id,
            approved_at: decision.at,
        }),
    }
}

/// The person's decision on `record`, when the script may collect it at `now`.
fn collectable(record: &ApprovalRecord, now: Timestamp) -> Result<Decision, Refusal> {
    match &record.state {
        ApprovalState::Pending | ApprovalState::Approved(_) if record.expired(now) => {
            Err(Refusal::Expired)
        }
        ApprovalState::Pending => Err(Refusal::Pending),
        ApprovalState::Denied { .. } => Err(Refusal::Denied),
        ApprovalState::Consumed { .. } => Err(Refusal::Consumed),
        ApprovalState::Approved(decision) => Ok(decision.clone()),
    }
}

/// The plan of the approval `id`.
fn plan_of(view: &dyn ReadView, id: ApprovalId) -> Result<TakeoverPlan, AuthError> {
    Ok(view
        .get_typed(&APPROVAL_PLANS, &id)?
        .ok_or(Refusal::NotFound)?
        .0)
}

/// Whether an administrator may still deny `record` at `now`: it waits, or it was approved
/// and not collected, and its time is not over.
fn deniable(record: &ApprovalRecord, now: Timestamp) -> bool {
    matches!(
        record.state,
        ApprovalState::Pending | ApprovalState::Approved(_)
    ) && !record.expired(now)
}

/// Why `record` can no longer be decided at `now`.
fn undecided_refusal(record: &ApprovalRecord, now: Timestamp) -> Refusal {
    match record.state {
        ApprovalState::Denied { .. } => Refusal::Denied,
        ApprovalState::Consumed { .. } => Refusal::Consumed,
        _ if record.expired(now) => Refusal::Expired,
        _ => Refusal::Consumed,
    }
}

/// Stages the denial of `record` by `user` at `now`.
fn stage_denial(
    batch: &mut WriteBatch,
    mut record: ApprovalRecord,
    revision: tenko_core::Revision,
    user: UserId,
    now: Timestamp,
) -> Result<(), AuthError> {
    record.state = ApprovalState::Denied { by: user, at: now };
    batch.expect_typed(&APPROVALS, &record.id, Some(revision));
    batch.put_typed(&APPROVALS, &record.id, &record)?;
    Ok(())
}

/// Whether the typed `code` is the code of `record` over `root`, compared in constant time.
fn matches(record: &ApprovalRecord, code: &SecretString, root: &[u8; 32]) -> bool {
    let Some(typed) = approval::canonical_code(code.expose()) else {
        return false;
    };
    let expected = approval::code(
        record.domain.as_str(),
        root,
        &record.plan_hash,
        &record.key,
        record.id,
    );
    verify_slices_are_equal(expected.as_bytes(), typed.as_bytes()).is_ok()
}

/// The audit record of a person's decision: the approval, the domain, the script's address
/// and the SHA-256 of the request, which outlives the approval's row.
fn decision_audit(
    action: AuditAction,
    record: &ApprovalRecord,
    user: UserId,
    session: SessionId,
    ctx: &RequestCtx,
) -> AuditDraft {
    AuditDraft::success(
        action,
        vec![ObjectRef::from(user), ObjectRef::from(session)],
    )
    .with_source_ip(ctx.source_ip)
    .with_context("approval", record.id.to_string())
    .with_context("domain", record.domain.as_str())
    .with_context("script_source", record.source.to_string())
    .with_context("request_sha256", hex_encode(&record.plan_hash))
}
