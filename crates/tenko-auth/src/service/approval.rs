//! The steps of an approval (`crate::approval`, ADR 0038) and the plan of a delegated session.

use std::{net::IpAddr, time::Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use tenko_core::{
    Action, ApprovalId, DelegationId, ObjectKind, ObjectRef, Principal, RequestCtx, SessionId,
    Timestamp, UserId, audit::AuditDraft, auth::Delegated, migrate::plan::TakeoverPlan,
};
use tenko_store::{KeyRange, ReadViewExt, WriteBatch};

use super::{AuthService, LIST_LIMIT, SecretString};
use crate::{
    approval::{
        self, APPROVALS, AUDIT_EVERY, ApprovalRecord, ApprovalState, ApprovalTicket, ApprovalView,
        CLOCK_TOLERANCE, Decision, DelegatedSession, LOOKUP_LOCK, MAX_PENDING,
        MAX_PENDING_PER_SOURCE, REQUEST_SPACING, Refusal, WRONG_CODE_WINDOW, WRONG_CODES, actions,
    },
    delegation,
    encoding::base64url_encode,
    error::AuthError,
    model::{SESSIONS, SessionRecord, USER_SESSIONS, USERS},
    roles::RoleName,
};

impl AuthService {
    /// `POST /auth/approvals`: a script's request, from `ctx.source_ip`, with the body as
    /// sent. Writes the approval and answers its id and nonce.
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
        if self
            .approval_paces
            .requests
            .hit(&bucket, started, REQUEST_SPACING)
            > 1
        {
            return Err(Refusal::Limit("spacing").into());
        }
        let (request, key, plan_hash) = approval::parse_request(body)?;
        let view = self.view().await?;
        let mut batch = WriteBatch::for_request(ctx);
        let (mut pending, mut from_source) = (0, 0);
        for (_, record, _) in view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)? {
            if over(&record, ctx.now) {
                batch.delete_typed(&APPROVALS, &record.id);
            } else if record.pending(ctx.now) {
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
            plan: request.plan,
            plan_hash,
            key,
            nonce: nonce.to_vec(),
            client: request.client,
            source,
            state: ApprovalState::Pending,
            created_at: ctx.now,
        };
        batch.expect_typed(&APPROVALS, &record.id, None);
        batch.put_typed(&APPROVALS, &record.id, &record)?;
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
                    .with_context("domain", record.plan.domain.as_str())
                    .with_context("machine", record.client.machine.clone())
                    .with_context("windows_user", record.client.user.clone()),
            );
        }
        self.commit(batch).await?;
        Ok(ApprovalTicket {
            id: record.id,
            nonce: base64url_encode(&nonce),
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
            (Some(record), None) => Ok(record.view(ctx.now)),
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
        undecided(&record, ctx.now)?;
        if !matches(&record, code, root) {
            return Err(self.wrong_code(ctx, user, session).await);
        }
        for (_, other, _) in view.scan_typed(&APPROVALS, KeyRange::all(), LIST_LIMIT, false)? {
            let open = match &other.state {
                ApprovalState::Approved(_) => !other.expired(ctx.now),
                ApprovalState::Consumed {
                    decision, session, ..
                } => Self::load_session(view.as_ref(), decision.by, *session)?.is_some(),
                _ => false,
            };
            if open && other.id != id && other.plan.domain == record.plan.domain {
                return Err(Refusal::Limit("domain").into());
            }
        }
        let strength = ctx.principal.strength().ok_or(AuthError::Unauthenticated)?;
        let delegation = DelegationId::generate();
        record.state = ApprovalState::Approved(Decision {
            by: user,
            session,
            strength,
            at: ctx.now,
            delegation,
        });
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&APPROVALS, &id, Some(revision));
        batch.put_typed(&APPROVALS, &id, &record)?;
        batch.audit(
            decision_audit(actions::APPROVE, &record, user, session, ctx)
                .with_context("delegation", delegation.to_string()),
        );
        self.commit(batch).await?;
        Ok(record.view(ctx.now))
    }

    /// `POST /auth/approvals/{id}/deny`: an administrator refuses a pending request.
    ///
    /// # Errors
    ///
    /// As [`AuthService::approve`], without the freshness and the code.
    pub async fn deny_approval(&self, ctx: &RequestCtx, id: ApprovalId) -> Result<(), AuthError> {
        let (user, session) = self.approver(ctx, false).await?;
        let view = self.view().await?;
        let (mut record, revision) = view.get_typed(&APPROVALS, &id)?.ok_or(Refusal::NotFound)?;
        undecided(&record, ctx.now)?;
        record.state = ApprovalState::Denied {
            by: user,
            at: ctx.now,
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&APPROVALS, &id, Some(revision));
        batch.put_typed(&APPROVALS, &id, &record)?;
        batch.audit(decision_audit(actions::DENY, &record, user, session, ctx));
        self.commit(batch).await?;
        Ok(())
    }

    /// `POST /auth/approvals/{id}/collect`: the script proves its key by signing the nonce,
    /// from the request's source address, and receives the delegated session once.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotFound`] for another source, [`Refusal::Signature`], [`Refusal::Pending`],
    /// [`Refusal::Denied`], [`Refusal::Expired`], [`Refusal::Consumed`];
    /// [`AuthError::Unauthenticated`] when the approver may no longer administer.
    pub async fn collect_approval(
        &self,
        ctx: &RequestCtx,
        id: ApprovalId,
        body: &[u8],
    ) -> Result<DelegatedSession, AuthError> {
        let signature = approval::parse_collect(body)?;
        let view = self.view().await?;
        let (mut record, revision) = view.get_typed(&APPROVALS, &id)?.ok_or(Refusal::NotFound)?;
        if ctx.source_ip != Some(record.source) {
            self.collect_refusal(ctx, &record.source.to_string(), id, "source")
                .await;
            return Err(Refusal::NotFound.into());
        }
        if !approval::verify_collect(&record.key, id, &record.nonce, &signature) {
            self.collect_refusal(ctx, &record.source.to_string(), id, "signature")
                .await;
            return Err(Refusal::Signature.into());
        }
        let decision = match &record.state {
            _ if over(&record, ctx.now) => return Err(Refusal::Expired.into()),
            ApprovalState::Pending => return Err(Refusal::Pending.into()),
            ApprovalState::Denied { .. } => return Err(Refusal::Denied.into()),
            ApprovalState::Consumed { .. } => return Err(Refusal::Consumed.into()),
            ApprovalState::Approved(decision) => decision.clone(),
        };
        let (user, _) = view
            .get_typed(&USERS, &decision.by)?
            .filter(|(user, _)| {
                !user.disabled && !user.is_service() && user.roles.contains(&RoleName::Admin)
            })
            .ok_or(AuthError::Unauthenticated)?;
        let settings = self.settings();
        let absolute = settings.session.absolute().min(delegation::LIFETIME);
        let idle = settings.session.idle().min(delegation::IDLE);
        let expires_at = decision.at.checked_add(absolute).ok_or(Refusal::Expired)?;
        let delegated = Delegated {
            id: decision.delegation,
            approval: id,
            approved_at: decision.at,
        };
        let secret = crate::secret::new_delegation_secret()?;
        let session = SessionRecord {
            strength: decision.strength,
            expires_at,
            idle_expires_at: ctx.now.checked_add(idle).unwrap_or(ctx.now).min(expires_at),
            ..delegated_session(&record, &user, delegated, ctx.now)
        };
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
            .with_context("delegation", delegated.id.to_string()),
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
        let (user, session, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        let (_, _, _, record) = Self::live_session(view.as_ref(), user, session)?;
        let delegated = record.delegation.ok_or(AuthError::DelegationRefused)?;
        let (approval, _) = view
            .get_typed(&APPROVALS, &delegated.approval)?
            .ok_or(AuthError::DelegationRefused)?;
        Ok(approval.plan)
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
        if self.approval_paces.refusals.hit(
            session.id.uuid().as_bytes(),
            Instant::now(),
            AUDIT_EVERY,
        ) != 1
        {
            return;
        }
        let principal = Principal::User {
            id: session.user,
            session: session.id,
            strength: session.strength,
            delegation: Some(delegated.id),
        };
        let mut batch = WriteBatch::new(principal, now);
        batch.audit(
            AuditDraft::denied(
                actions::REFUSE,
                vec![ObjectRef::from(session.user), ObjectRef::from(session.id)],
            )
            .with_source_ip(source)
            .with_context("approval", delegated.approval.to_string())
            .with_context("reason", "session_source"),
        );
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused delegated session");
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
        let key = session.uuid().as_bytes().to_vec();
        let now = Instant::now();
        let paces = &self.approval_paces;
        if paces.wrong_codes.hit(&key, now, WRONG_CODE_WINDOW) >= WRONG_CODES {
            paces.locks.hit(&key, now, LOOKUP_LOCK);
        }
        if paces.refusals.hit(&key, now, AUDIT_EVERY) == 1 {
            let mut batch = WriteBatch::for_request(ctx);
            batch.audit(
                AuditDraft::denied(
                    actions::REFUSE,
                    vec![ObjectRef::from(user), ObjectRef::from(session)],
                )
                .with_source_ip(ctx.source_ip)
                .with_context("reason", "code"),
            );
            if let Err(error) = self.store.propose(batch).await {
                tracing::warn!(%error, "could not record a wrong approval code");
            }
        }
        Refusal::Code.into()
    }

    /// Audits a refused collect, at most once a minute per source.
    async fn collect_refusal(&self, ctx: &RequestCtx, key: &str, id: ApprovalId, reason: &str) {
        if self
            .approval_paces
            .refusals
            .hit(key.as_bytes(), Instant::now(), AUDIT_EVERY)
            != 1
        {
            return;
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(
            AuditDraft::denied(actions::REFUSE, Vec::new())
                .with_source_ip(ctx.source_ip)
                .with_context("approval", id.to_string())
                .with_context("reason", reason),
        );
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused collect");
        }
    }
}

/// A delegated session of `user` for `record`, created at `now`, before its strength and
/// lifetimes are set: never fresh (the Unix epoch as its sign-in), bound to the request's
/// source, and described in the session list by what the script reported.
fn delegated_session(
    record: &ApprovalRecord,
    user: &crate::model::UserRecord,
    delegated: Delegated,
    now: Timestamp,
) -> SessionRecord {
    SessionRecord {
        id: SessionId::generate(),
        user: user.id,
        strength: tenko_core::AuthStrength::Pin,
        created_at: now,
        authenticated_at: Timestamp::UNIX_EPOCH,
        expires_at: now,
        idle_expires_at: now,
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
        delegation: Some(delegated),
    }
}

/// Whether the person may still decide on `record` at `now`.
fn undecided(record: &ApprovalRecord, now: Timestamp) -> Result<(), Refusal> {
    match record.state {
        ApprovalState::Pending if record.expired(now) => Err(Refusal::Expired),
        ApprovalState::Pending => Ok(()),
        ApprovalState::Denied { .. } => Err(Refusal::Denied),
        ApprovalState::Approved(_) | ApprovalState::Consumed { .. } => Err(Refusal::Consumed),
    }
}

/// Whether the typed `code` is the code of `record` over `root`, compared in constant time.
fn matches(record: &ApprovalRecord, code: &SecretString, root: &[u8; 32]) -> bool {
    let Some(typed) = approval::canonical_code(code.expose()) else {
        return false;
    };
    let expected = approval::code(
        record.plan.domain.as_str(),
        root,
        &record.plan_hash,
        &record.key,
        record.id,
    );
    verify_slices_are_equal(expected.as_bytes(), typed.as_bytes()).is_ok()
}

/// Whether a row has served its purpose at `now`: a consumed approval once its delegated
/// session can no longer live, every other one once its pending time is over.
fn over(record: &ApprovalRecord, now: Timestamp) -> bool {
    match record.state {
        ApprovalState::Consumed { at, .. } => {
            now.checked_add(CLOCK_TOLERANCE).is_none_or(|now| now < at)
                || now.saturating_since(at) >= delegation::LIFETIME
        }
        _ => record.expired(now),
    }
}

/// The audit record of a person's decision.
fn decision_audit(
    action: tenko_core::audit::AuditAction,
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
    .with_context("domain", record.plan.domain.as_str())
    .with_context("script_source", record.source.to_string())
}
