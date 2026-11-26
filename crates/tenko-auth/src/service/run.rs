//! The takeover runs (ADR 0038, `tenko_core::migrate::run`): the one check of a delegated
//! session's request, the read of a run, and a person's close of a run.

use std::net::IpAddr;

use tenko_core::{
    Authenticated, DelegationId, ObjectRef, Principal, RequestCtx, Timestamp,
    audit::AuditDraft,
    auth::Delegated,
    dns::{ZoneId, tables::ZONES},
    migrate::{
        audit::RUN_CLOSE,
        codes,
        plan::TakeoverPlan,
        run::RunRecord,
        tables::{MIRRORS, RUN_DOMAINS, RUN_PLANS, RUNS},
    },
};
use tenko_store::{KeyRange, ReadViewExt, WriteBatch};

use super::AuthService;
use crate::{
    approval::actions,
    delegation::{self, Object},
    error::AuthError,
};

/// The answer for a run that does not exist and, to a delegated session, for another run.
const NO_RUN: AuthError = AuthError::NoObject {
    code: codes::RUN_NOT_FOUND,
};

/// The answer for a zone that does not exist and, to a delegated session, for a zone its run
/// did not create.
const NO_ZONE: AuthError = AuthError::NoObject {
    code: tenko_core::dns::codes::ZONE_NOT_FOUND,
};

/// A refusal of the check with the outcome its audit record names.
type Refusal = (AuthError, &'static str);

impl AuthService {
    /// The one check of a delegated session's request (ADR 0038), before any handler runs:
    /// `method` on the route template `route` below the API base (`None` when no route
    /// matched or its path parameters did not decode), whose decoded path parameters are
    /// `params`. In this order, each refused with 403 `auth.delegation.refused` and its
    /// `reason`: an operation that [`delegation::TAKEOVER`] does not list (`unlisted`), one
    /// whose condition does not hold (`condition`), and any request of a session whose run is
    /// not open (`run`) but its own sign-out. Then every object a path parameter names must
    /// exist and be the run's: a missing object and an object of another run answer the same
    /// 404, and only the audit record says which (`found`: `missing` or `outside_run`).
    ///
    /// Every refusal is audited as `auth.delegation.refuse`, at most once a minute per session
    /// and outcome, the two of a missing object counting as one: the pace is kept in this
    /// process's memory, bounded to 4,096 keys, and a restart forgets it.
    ///
    /// # Errors
    ///
    /// [`AuthError::DelegationRefused`], [`AuthError::NoObject`], or a store error.
    pub async fn admit_delegated(
        &self,
        who: &Authenticated,
        method: &str,
        route: Option<&str>,
        params: &[(&str, &str)],
        source_ip: Option<IpAddr>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let Some(delegated) = who.flags.delegation else {
            return Ok(());
        };
        let Err((refusal, outcome)) = self.judge(&delegated, method, route, params, now).await?
        else {
            return Ok(());
        };
        let Principal::User { id, session, .. } = who.principal else {
            return Err(refusal);
        };
        // The two outcomes of a missing object share one pace.
        let (kind, paced) = if matches!(refusal, AuthError::NoObject { .. }) {
            ("found", "found")
        } else {
            ("reason", outcome)
        };
        let draft = AuditDraft::denied(
            actions::DELEGATION_REFUSE,
            vec![ObjectRef::from(id), ObjectRef::from(session)],
        )
        .with_source_ip(source_ip)
        .with_context("run", delegated.id.to_string())
        .with_context("method", method)
        .with_context("route", route.unwrap_or("none"))
        .with_context(kind, outcome);
        let pace = [session.uuid().as_bytes().as_slice(), paced.as_bytes()].concat();
        self.approval_refusal_audit(&who.principal, &pace, draft, now)
            .await;
        Err(refusal)
    }

    /// The steps of [`AuthService::admit_delegated`]: the refusal, if any, with its outcome.
    async fn judge(
        &self,
        delegated: &Delegated,
        method: &str,
        route: Option<&str>,
        params: &[(&str, &str)],
        now: Timestamp,
    ) -> Result<Result<(), Refusal>, AuthError> {
        let refused = |reason| Ok(Err((AuthError::DelegationRefused { reason }, reason)));
        let Some(entry) = route.and_then(|route| delegation::entry(method, route)) else {
            return refused("unlisted");
        };
        if !entry.condition.holds(delegated, now) {
            return refused("condition");
        }
        let view = self.view().await?;
        // A session without a run may still end itself.
        let sign_out = entry.method == "POST" && entry.route == "/auth/logout";
        if !sign_out && view.get_typed(&RUNS, &delegated.id)?.is_none() {
            return refused("run");
        }
        for (name, object) in entry.objects {
            let value = params
                .iter()
                .find(|(key, _)| key == name)
                .map_or("", |(_, value)| *value);
            // The object's run: `None` when it is missing, `Some(None)` when it has none.
            let (owner, error) = match object {
                Object::Run => (
                    match value.parse::<DelegationId>() {
                        Ok(id) => view.get_typed(&RUNS, &id)?.map(|_| Some(id)),
                        Err(_) => None,
                    },
                    NO_RUN,
                ),
                Object::Zone => (
                    match value.parse::<ZoneId>() {
                        Ok(id) => view
                            .get_typed(&ZONES, &id)?
                            .map(|(zone, _)| zone.created.by.delegation()),
                        Err(_) => None,
                    },
                    NO_ZONE,
                ),
            };
            match owner {
                Some(run) if run == Some(delegated.id) => {}
                Some(_) => return Ok(Err((error, "outside_run"))),
                None => return Ok(Err((error, "missing"))),
            }
        }
        Ok(Ok(()))
    }

    /// `GET /migrate/runs/{id}`: an open run and its plan.
    ///
    /// # Errors
    ///
    /// [`AuthError::NoObject`] (`migrate.run.not_found`), or a store error.
    pub async fn run(&self, id: DelegationId) -> Result<(RunRecord, TakeoverPlan), AuthError> {
        let view = self.view().await?;
        let (run, _) = view.get_typed(&RUNS, &id)?.ok_or(NO_RUN)?;
        let (plan, _) = view.get_typed(&RUN_PLANS, &id)?.ok_or(NO_RUN)?;
        Ok((run, plan))
    }

    /// `POST /migrate/runs/{id}/close`: a person ends the run `id`, whose takeover is done or
    /// abandoned. Its three rows and the delegated sessions of its sittings are deleted in one
    /// batch, so that its domain takes a new run with any plan. A session of a sitting the run
    /// no longer lists reaches nothing but its own sign-out, as every session without a run.
    /// The caller has checked the person's right and fresh sign-in.
    ///
    /// # Errors
    ///
    /// [`AuthError::NoObject`] (`migrate.run.not_found`), [`AuthError::RunBusy`] while a
    /// mirror of the run or an unserved zone it created exists, [`AuthError::Conflict`] when a
    /// sitting joined meanwhile, or a store error.
    pub async fn close_run(&self, ctx: &RequestCtx, id: DelegationId) -> Result<(), AuthError> {
        let view = self.view().await?;
        let (run, revision) = view.get_typed(&RUNS, &id)?.ok_or(NO_RUN)?;
        let mut mirrors = Vec::new();
        for entry in &run.mirrors {
            if view.get_typed(&MIRRORS, &entry.mirror)?.is_some() {
                mirrors.push(entry.mirror.to_string());
            }
        }
        // A served zone of the run is what the run produced; an unserved one is its copy.
        let zones: Vec<String> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, zone, _)| !zone.served && zone.created.by.delegation() == Some(id))
            .map(|(_, zone, _)| zone.name.as_str().to_owned())
            .collect();
        if !mirrors.is_empty() || !zones.is_empty() {
            return Err(AuthError::RunBusy {
                mirrors: mirrors.join(","),
                zones: zones.join(","),
            });
        }
        let mut sessions = Vec::new();
        for sitting in &run.sittings {
            sessions.extend(Self::load_session(
                view.as_ref(),
                sitting.approved_by,
                sitting.session,
            )?);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&RUNS, &id, Some(revision));
        batch.delete_typed(&RUNS, &id);
        batch.delete_typed(&RUN_PLANS, &id);
        batch.delete_typed(&RUN_DOMAINS, &run.domain.as_str().to_owned());
        Self::stage_revoke(&mut batch, &sessions);
        batch.audit(
            Self::audit(RUN_CLOSE, Vec::new(), ctx)
                .with_context("run", id.to_string())
                .with_context("domain", run.domain.as_str())
                .with_context("sessions", sessions.len().to_string()),
        );
        self.commit(batch).await?;
        Ok(())
    }
}
