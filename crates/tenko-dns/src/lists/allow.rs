//! Allow from the blocking view (`docs/dns.md`, "Blocking view"): a name the view shows as
//! blocked goes onto an allow list with one action.
//!
//! The list is the one the caller names, which must be an uploaded allow list, or else the
//! uploaded allow list named [`ALLOW_LIST`], created (enabled, one domain per line) the
//! first time. The names of the list's newest version are read back from the compiled
//! form, the new name is added, and the text goes to the compile job as an upload would,
//! so the next version holds it; a name the list covers already (it or a name above it is
//! listed) changes nothing. The request is audited as `dns.blocking.allow` with the name
//! and the list before the job runs; the job writes `dns.list.compile` as for any version.

use tenko_core::{
    JobId, ObjectRef, RequestCtx,
    audit::AuditDraft,
    dns::{
        BlockList, BlockListId, DnsName, ListFormat, ListKind, ListSource, ListVersion, audit,
        codes,
    },
};
use tenko_store::WriteBatch;

use super::{
    ListMatcher,
    compile::{decode, key_text},
    job::{ListStaging, Trigger},
    service::{ListRow, NewList, not_found},
};
use crate::zone::{ZoneError, ZoneResult, ZoneService};

/// The name of the allow list the blocking view adds to when no list is named.
pub const ALLOW_LIST: &str = "allowed";

/// What an allow did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// The allow list.
    pub list: BlockListId,
    /// Its name.
    pub list_name: String,
    /// The list was created for this name.
    pub created: bool,
    /// The list covered the name already: nothing changed.
    pub already: bool,
    /// The compile job that writes the list's next version.
    pub job: Option<JobId>,
}

fn not_an_allow_list(reason: &str) -> ZoneError {
    ZoneError::new(codes::LIST_INVALID, 409, format!("list: {reason}"))
        .param("field", "list")
        .param("reason", reason)
}

/// The list to add to: `list`, which must be an uploaded allow list, or the one named
/// [`ALLOW_LIST`] (`None` when there is none yet).
fn target_of(rows: &[ListRow], list: Option<BlockListId>) -> ZoneResult<Option<BlockList>> {
    let found = match list {
        Some(id) => Some(
            rows.iter()
                .find(|row| row.list.id == id)
                .ok_or_else(|| not_found(id))?
                .list
                .clone(),
        ),
        None => rows
            .iter()
            .find(|row| row.list.name.eq_ignore_ascii_case(ALLOW_LIST))
            .map(|row| row.list.clone()),
    };
    if let Some(found) = &found {
        if found.kind != ListKind::Allow {
            return Err(not_an_allow_list("the list is a block list"));
        }
        if found.source != ListSource::Upload {
            return Err(not_an_allow_list(
                "the list is fetched from a URL; add the name at its source",
            ));
        }
    }
    Ok(found)
}

/// The names of a list's newest version, and whether they cover `wire` (lowercase wire
/// form) already.
fn names_of(version: Option<&ListVersion>, wire: &[u8]) -> ZoneResult<(Vec<String>, bool)> {
    let Some(version) = version else {
        return Ok((Vec::new(), false));
    };
    let bytes = &version.compiled.0;
    let covered = ListMatcher::build(bytes).is_ok_and(|matcher| matcher.matches(wire));
    let names = decode(bytes)
        .map_err(|error| {
            ZoneError::new(
                codes::LIST_INVALID,
                500,
                format!("the newest version of the list cannot be read: {error}"),
            )
        })?
        .iter()
        .map(|key| key_text(key))
        .collect();
    Ok((names, covered))
}

impl ZoneService {
    /// Adds `name` to the allow list `list` (or the list [`ALLOW_LIST`], created when
    /// missing) and starts the compile of its next version; see the module documentation.
    ///
    /// # Errors
    ///
    /// `dns.list.not_found`; `dns.list.invalid` (409) for a list that is not an uploaded
    /// allow list; or a store or job error.
    pub async fn allow_name(
        &self,
        cx: &RequestCtx,
        name: &DnsName,
        list: Option<BlockListId>,
        staging: &ListStaging,
    ) -> ZoneResult<Allowed> {
        let view = self.view(None).await?;
        let found = target_of(&Self::block_lists(view.as_ref())?, list)?;
        let version = match &found {
            Some(found) => Self::newest_list_version(view.as_ref(), found.id)?,
            None => None,
        };
        drop(view);
        let (mut names, covered) =
            names_of(version.as_ref(), &name.to_wire().to_ascii_lowercase())?;
        let (target, created) = if let Some(found) = found {
            (found, false)
        } else {
            let (created, _) = self
                .create_block_list(
                    cx,
                    NewList {
                        name: ALLOW_LIST.to_owned(),
                        kind: ListKind::Allow,
                        source: ListSource::Upload,
                        format: ListFormat::Domains,
                        interval_hours: None,
                        action: None,
                        enabled: Some(true),
                        exempt: Vec::new(),
                        description: Some("Names allowed from the blocking view".to_owned()),
                    },
                )
                .await?;
            (created, true)
        };
        if covered {
            return Ok(Allowed {
                list: target.id,
                list_name: target.name,
                created,
                already: true,
                job: None,
            });
        }
        let added = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        names.push(added.clone());
        let mut text = names.join("\n");
        text.push('\n');
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::success(
                audit::BLOCKING_ALLOW.clone(),
                vec![ObjectRef::from(target.id)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("name", added)
            .with_context("list", target.name.clone()),
        );
        self.store().propose(batch).await?;
        let job = self
            .start_list_compile(
                cx,
                target.id,
                staging,
                Some(text.into_bytes()),
                Trigger::Allow,
            )
            .await?;
        Ok(Allowed {
            list: target.id,
            list_name: target.name,
            created,
            already: false,
            job: Some(job),
        })
    }
}
