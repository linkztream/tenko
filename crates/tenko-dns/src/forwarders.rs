//! Forwarding rules (`dns.forwarders`, DNS-02): the rows the forwarder routes by.
//!
//! A rule covers the names at or below its suffix, in one view or in all, and names 1 to
//! 16 upstreams over one transport (plain, DoT or DoH; DoT and DoH need the name in the
//! upstreams' certificates). The longest suffix wins, a rule of the query's view before one
//! of all views; the root suffix `.` is the default forwarder and wins over `[dns]
//! forwarders` of the configuration. One rule per suffix and view. Every change is an
//! inline job with its `dns.forwarder.*` audit record; the role's catalog follows the rows
//! through the feed.

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        DnsName, ForwardRule, ForwardRuleId, ForwardTransport, RuleMode, Upstream, ViewId, audit,
        codes,
        tables::{FORWARDERS, VIEWS},
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use crate::zone::{Planned, Written, ZoneError, ZoneResult, ZoneService, check_expect};

/// A new forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule {
    /// The names the rule covers.
    pub suffix: DnsName,
    /// The upstreams.
    pub upstreams: Vec<Upstream>,
    /// How they are reached.
    pub transport: ForwardTransport,
    /// The certificate name of DoT and DoH upstreams.
    pub tls_name: Option<String>,
    /// The view the rule applies in; all views when `None`.
    pub view: Option<ViewId>,
    /// Free text.
    pub description: Option<String>,
    // WP10.2: the rule's escape from validation.
    /// Validate the upstreams' answers (TGL-12); `None` is the default, on.
    pub validate: Option<bool>,
    // WP10.4: the rule's mode.
    /// `forward` to the upstreams or `recurse` from the root; `None` is `forward`.
    pub mode: Option<RuleMode>,
}

/// Changes to a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleChange {
    /// The suffix.
    pub suffix: Option<DnsName>,
    /// The upstreams.
    pub upstreams: Option<Vec<Upstream>>,
    /// The transport.
    pub transport: Option<ForwardTransport>,
    /// The certificate name; an empty string clears it.
    pub tls_name: Option<String>,
    /// The view.
    pub view: Option<ViewId>,
    /// Apply in every view (clears `view`).
    pub all_views: bool,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
    // WP10.2: the rule's escape from validation.
    /// Validate the upstreams' answers (TGL-12).
    pub validate: Option<bool>,
    // WP10.4: the rule's mode.
    /// `forward` or `recurse`.
    pub mode: Option<RuleMode>,
}

/// A rule as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    /// The rule.
    pub rule: ForwardRule,
    /// The revision of the row.
    pub revision: Revision,
}

fn invalid(field: &str, reason: &str) -> ZoneError {
    ZoneError::new(codes::FORWARDER_INVALID, 400, format!("{field}: {reason}"))
        .param("field", field)
        .param("reason", reason)
}

fn not_found(id: ForwardRuleId) -> ZoneError {
    ZoneError::new(
        codes::FORWARDER_NOT_FOUND,
        404,
        format!("forwarding rule {id} does not exist"),
    )
    .param("id", id.to_string())
}

fn trimmed(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// The rule's own checks and the ones against other rows: its view exists, no other rule
/// has its suffix and view.
fn check(view: &dyn ReadView, rule: &ForwardRule) -> ZoneResult<()> {
    rule.validate()?;
    if rule
        .description
        .as_deref()
        .is_some_and(|text| text.chars().count() > 1_000)
    {
        return Err(invalid("description", "at most 1000 characters"));
    }
    if let Some(id) = rule.view
        && view.get_typed(&VIEWS, &id)?.is_none()
    {
        return Err(invalid("view", "no such view"));
    }
    let taken = view
        .scan_typed(&FORWARDERS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| {
            id != rule.id && other.suffix == rule.suffix && other.view == rule.view
        });
    if taken {
        return Err(invalid(
            "suffix",
            "a rule for this suffix exists in this view",
        ));
    }
    Ok(())
}

fn nothing_written() -> ZoneError {
    ZoneError::new(
        tenko_core::error::codes::INTERNAL,
        500,
        "the write reported no commit",
    )
}

impl ZoneService {
    /// Every forwarding rule, by suffix (the root first), then view and id.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn forward_rules(view: &dyn ReadView) -> ZoneResult<Vec<RuleRow>> {
        let mut rows: Vec<RuleRow> = view
            .scan_typed(&FORWARDERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, rule, revision)| RuleRow { rule, revision })
            .collect();
        rows.sort_by(|a, b| {
            a.rule
                .suffix
                .as_str()
                .cmp(b.rule.suffix.as_str())
                .then(a.rule.view.cmp(&b.rule.view))
                .then(a.rule.id.cmp(&b.rule.id))
        });
        Ok(rows)
    }

    /// One forwarding rule.
    ///
    /// # Errors
    ///
    /// `dns.forwarder.not_found`, or the store's error.
    pub fn forward_rule(view: &dyn ReadView, id: ForwardRuleId) -> ZoneResult<RuleRow> {
        let (rule, revision) = view
            .get_typed(&FORWARDERS, &id)?
            .ok_or_else(|| not_found(id))?;
        Ok(RuleRow { rule, revision })
    }

    /// Creates a forwarding rule.
    ///
    /// # Errors
    ///
    /// `dns.forwarder.invalid`, or a store or job error.
    pub async fn create_forward_rule(
        &self,
        cx: &RequestCtx,
        new: NewRule,
    ) -> ZoneResult<(ForwardRule, Written)> {
        let rule = ForwardRule {
            id: ForwardRuleId::generate(),
            suffix: new.suffix,
            upstreams: new.upstreams,
            transport: new.transport,
            tls_name: trimmed(new.tls_name),
            view: new.view,
            // WP10.4: the mode from the request, `forward` by default.
            mode: new.mode.unwrap_or(RuleMode::Forward),
            // WP10.2: validation on unless the request switches it off.
            validate: new.validate.unwrap_or(true),
            description: trimmed(new.description),
        };
        let (rule, written) = self
            .execute(cx, |view| {
                check(view, &rule)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&FORWARDERS, &rule.id, None);
                batch.put_typed(&FORWARDERS, &rule.id, &rule)?;
                batch.audit(
                    AuditDraft::success(audit::FORWARDER_CREATE, vec![ObjectRef::from(rule.id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("suffix", rule.suffix.to_string()),
                );
                Ok(Planned::write(
                    rule.clone(),
                    batch,
                    format!("create forwarding rule {}", rule.suffix),
                    vec![ObjectRef::from(rule.id)],
                ))
            })
            .await?;
        Ok((rule, written.ok_or_else(nothing_written)?))
    }

    /// Changes a forwarding rule; with `expect`, only the row at that revision.
    ///
    /// # Errors
    ///
    /// `dns.forwarder.not_found`, `dns.forwarder.invalid`, 412 when `expect` is stale, or
    /// a store or job error.
    pub async fn update_forward_rule(
        &self,
        cx: &RequestCtx,
        id: ForwardRuleId,
        change: RuleChange,
        expect: Option<Revision>,
    ) -> ZoneResult<(ForwardRule, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&FORWARDERS, &id)?
                .ok_or_else(|| not_found(id))?;
            check_expect(expect, revision)?;
            let mut rule = before.clone();
            if let Some(suffix) = &change.suffix {
                rule.suffix = suffix.clone();
            }
            if let Some(upstreams) = &change.upstreams {
                rule.upstreams.clone_from(upstreams);
            }
            if let Some(transport) = change.transport {
                rule.transport = transport;
            }
            if let Some(tls_name) = &change.tls_name {
                rule.tls_name = trimmed(Some(tls_name.clone()));
            }
            if change.all_views {
                rule.view = None;
            } else if let Some(only) = change.view {
                rule.view = Some(only);
            }
            if let Some(description) = &change.description {
                rule.description = trimmed(Some(description.clone()));
            }
            // WP10.2: the rule's escape from validation.
            if let Some(validate) = change.validate {
                rule.validate = validate;
            }
            // WP10.4: the rule's mode.
            if let Some(mode) = change.mode {
                rule.mode = mode;
            }
            if rule == before {
                return Ok(Planned::nothing(rule));
            }
            check(view, &rule)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&FORWARDERS, &id, Some(revision));
            batch.put_typed(&FORWARDERS, &id, &rule)?;
            batch.audit(
                AuditDraft::success(audit::FORWARDER_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("suffix", rule.suffix.to_string()),
            );
            Ok(Planned::write(
                rule.clone(),
                batch,
                format!("change forwarding rule {}", rule.suffix),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a forwarding rule.
    ///
    /// # Errors
    ///
    /// `dns.forwarder.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete_forward_rule(
        &self,
        cx: &RequestCtx,
        id: ForwardRuleId,
        expect: Option<Revision>,
    ) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |view| {
                let row = Self::forward_rule(view, id)?;
                check_expect(expect, row.revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&FORWARDERS, &id, Some(row.revision));
                batch.delete_typed(&FORWARDERS, &id);
                batch.audit(
                    AuditDraft::success(audit::FORWARDER_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("suffix", row.rule.suffix.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete forwarding rule {}", row.rule.suffix),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }
}

#[cfg(test)]
mod tests;
