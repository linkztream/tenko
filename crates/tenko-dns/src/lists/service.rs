//! The rows of block and allow lists, written through the zone service.
//!
//! A list has a unique name (compared without case), a kind (`block` or `allow`), a source
//! (a URL fetched on its interval, or an uploaded file), a format, an action, the client
//! prefixes it exempts and a switch. Every change is an inline job with its `dns.list.*`
//! audit record. A change of the source or the format drops the list's versions, so that a
//! list never serves names its new source does not hold: a URL list is fetched again by the
//! leader service within a minute, an uploaded list waits for its next file. Deleting a list
//! deletes its versions in the same write.

use ipnet::IpNet;
use tenko_core::{
    ObjectRef, RequestCtx, Revision, Timestamp,
    audit::AuditDraft,
    codec::key::encode_key,
    dns::{
        BlockAction, BlockList, BlockListId, ListFormat, ListKind, ListSource, ListVersion, audit,
        codes,
        tables::{LIST_VERSIONS, LISTS},
    },
    serde_util::HexBytes,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use crate::zone::{Planned, Written, ZoneError, ZoneResult, ZoneService, check_expect};

/// A new list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewList {
    /// The unique name.
    pub name: String,
    /// Block or allow.
    pub kind: ListKind,
    /// Where it comes from.
    pub source: ListSource,
    /// The file format.
    pub format: ListFormat,
    /// How often a URL list is fetched, in hours (24 when absent).
    pub interval_hours: Option<u16>,
    /// What a blocked name answers (NXDOMAIN when absent).
    pub action: Option<BlockAction>,
    /// Whether it is applied (true when absent).
    pub enabled: Option<bool>,
    /// The client prefixes it exempts.
    pub exempt: Vec<IpNet>,
    /// Free text.
    pub description: Option<String>,
}

/// Changes to a list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListChange {
    /// The name.
    pub name: Option<String>,
    /// The kind.
    pub kind: Option<ListKind>,
    /// The source.
    pub source: Option<ListSource>,
    /// The format.
    pub format: Option<ListFormat>,
    /// The interval.
    pub interval_hours: Option<u16>,
    /// The action.
    pub action: Option<BlockAction>,
    /// The switch.
    pub enabled: Option<bool>,
    /// The exempt prefixes (replaced whole).
    pub exempt: Option<Vec<IpNet>>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// The newest version of a list, without its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMeta {
    /// The version, counting up from 1.
    pub revision: u64,
    /// Names it holds.
    pub entries: u64,
    /// When the source was read.
    pub fetched: Timestamp,
    /// The entity tag of the fetched source.
    pub etag: Option<String>,
    /// Octets of the compiled form.
    pub bytes: u64,
}

impl VersionMeta {
    fn of(version: &ListVersion) -> Self {
        Self {
            revision: version.revision,
            entries: version.entries,
            fetched: version.fetched,
            etag: version.etag.clone(),
            bytes: version.compiled.0.len() as u64,
        }
    }
}

/// A list as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    /// The list.
    pub list: BlockList,
    /// The revision of the row.
    pub revision: Revision,
    /// The newest version.
    pub version: Option<VersionMeta>,
}

pub(crate) fn invalid(field: &str, reason: &str) -> ZoneError {
    ZoneError::new(codes::LIST_INVALID, 400, format!("{field}: {reason}"))
        .param("field", field)
        .param("reason", reason)
}

pub(crate) fn not_found(id: BlockListId) -> ZoneError {
    ZoneError::new(
        codes::LIST_NOT_FOUND,
        404,
        format!("block list {id} does not exist"),
    )
    .param("id", id.to_string())
}

fn trimmed(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn nothing_written() -> ZoneError {
    ZoneError::new(
        tenko_core::error::codes::INTERNAL,
        500,
        "the write reported no commit",
    )
}

/// The key range of the versions of one list.
fn versions_of(id: BlockListId) -> KeyRange {
    KeyRange::prefix(encode_key(&id))
}

/// The versions of a list, newest first.
pub(crate) fn versions(
    view: &dyn ReadView,
    id: BlockListId,
    limit: usize,
) -> ZoneResult<Vec<ListVersion>> {
    Ok(view
        .scan_typed(&LIST_VERSIONS, versions_of(id), limit, true)?
        .into_iter()
        .map(|(_, version, _)| version)
        .collect())
}

/// The list's own checks and its name against the other lists.
fn check(view: &dyn ReadView, list: &BlockList) -> ZoneResult<()> {
    list.validate()?;
    if list
        .description
        .as_deref()
        .is_some_and(|text| text.chars().count() > 1_000)
    {
        return Err(invalid("description", "at most 1000 characters"));
    }
    let taken = view
        .scan_typed(&LISTS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| id != list.id && other.name.eq_ignore_ascii_case(&list.name));
    if taken {
        return Err(invalid("name", "a list of this name exists"));
    }
    Ok(())
}

/// Deletes every version of a list in `batch`.
fn delete_versions(view: &dyn ReadView, batch: &mut WriteBatch, id: BlockListId) -> ZoneResult<()> {
    for (key, _, revision) in view.scan_typed(&LIST_VERSIONS, versions_of(id), usize::MAX, false)? {
        batch.expect_typed(&LIST_VERSIONS, &key, Some(revision));
        batch.delete_typed(&LIST_VERSIONS, &key);
    }
    Ok(())
}

/// What a compile step writes: the next version, the older ones removed, the audit record.
pub(crate) struct NewVersion<'a> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) entries: u64,
    pub(crate) skipped: u64,
    pub(crate) fetched: Timestamp,
    pub(crate) etag: Option<String>,
    /// `fetch` or `upload`.
    pub(crate) source: &'a str,
}

/// The batch of a new version of `id`, against `view`; the list must still be at
/// `list_revision`.
pub(crate) fn version_batch(
    view: &dyn ReadView,
    cx: &RequestCtx,
    id: BlockListId,
    list_revision: Revision,
    new: NewVersion<'_>,
) -> ZoneResult<(WriteBatch, u64)> {
    let (list, revision) = view.get_typed(&LISTS, &id)?.ok_or_else(|| not_found(id))?;
    check_expect(Some(list_revision), revision)?;
    let older = versions(view, id, usize::MAX)?;
    let next = older.first().map_or(1, |newest| newest.revision + 1);
    let mut batch = WriteBatch::for_request(cx);
    batch.idempotency = None;
    batch.expect_typed(&LISTS, &id, Some(revision));
    delete_versions(view, &mut batch, id)?;
    let version = ListVersion {
        list: id,
        revision: next,
        compiled: HexBytes(new.bytes),
        entries: new.entries,
        fetched: new.fetched,
        etag: new.etag,
    };
    batch.expect_typed(&LIST_VERSIONS, &(id, next), None);
    batch.put_typed(&LIST_VERSIONS, &(id, next), &version)?;
    batch.audit(
        AuditDraft::success(audit::LIST_COMPILE, vec![ObjectRef::from(id)])
            .with_source_ip(cx.source_ip)
            .with_context("name", list.name.clone())
            .with_context("version", next.to_string())
            .with_context("entries", new.entries.to_string())
            .with_context("skipped", new.skipped.to_string())
            .with_context("source", new.source),
    );
    Ok((batch, next))
}

impl ZoneService {
    /// Every list, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn block_lists(view: &dyn ReadView) -> ZoneResult<Vec<ListRow>> {
        let mut rows = Vec::new();
        for (id, list, revision) in view.scan_typed(&LISTS, KeyRange::all(), usize::MAX, false)? {
            let version = versions(view, id, 1)?.first().map(VersionMeta::of);
            rows.push(ListRow {
                list,
                revision,
                version,
            });
        }
        rows.sort_by(|a, b| {
            a.list
                .name
                .to_lowercase()
                .cmp(&b.list.name.to_lowercase())
                .then(a.list.id.cmp(&b.list.id))
        });
        Ok(rows)
    }

    /// One list.
    ///
    /// # Errors
    ///
    /// `dns.list.not_found`, or the store's error.
    pub fn block_list(view: &dyn ReadView, id: BlockListId) -> ZoneResult<ListRow> {
        let (list, revision) = view.get_typed(&LISTS, &id)?.ok_or_else(|| not_found(id))?;
        let version = versions(view, id, 1)?.first().map(VersionMeta::of);
        Ok(ListRow {
            list,
            revision,
            version,
        })
    }

    /// The newest version of a list with its bytes.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn newest_list_version(
        view: &dyn ReadView,
        id: BlockListId,
    ) -> ZoneResult<Option<ListVersion>> {
        Ok(versions(view, id, 1)?.into_iter().next())
    }

    /// Creates a list.
    ///
    /// # Errors
    ///
    /// `dns.list.invalid`, or a store or job error.
    pub async fn create_block_list(
        &self,
        cx: &RequestCtx,
        new: NewList,
    ) -> ZoneResult<(BlockList, Written)> {
        let list = BlockList {
            id: BlockListId::generate(),
            name: new.name,
            kind: new.kind,
            source: new.source,
            format: new.format,
            interval_hours: new.interval_hours.unwrap_or(24),
            action: new.action.unwrap_or(BlockAction::Nxdomain),
            enabled: new.enabled.unwrap_or(true),
            exempt: new.exempt,
            description: trimmed(new.description),
        };
        let (list, written) = self
            .execute(cx, |view| {
                check(view, &list)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&LISTS, &list.id, None);
                batch.put_typed(&LISTS, &list.id, &list)?;
                batch.audit(
                    AuditDraft::success(audit::LIST_CREATE, vec![ObjectRef::from(list.id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", list.name.clone()),
                );
                Ok(Planned::write(
                    list.clone(),
                    batch,
                    format!("create block list {}", list.name),
                    vec![ObjectRef::from(list.id)],
                ))
            })
            .await?;
        Ok((list, written.ok_or_else(nothing_written)?))
    }

    /// Changes a list; with `expect`, only the row at that revision.
    ///
    /// # Errors
    ///
    /// `dns.list.not_found`, `dns.list.invalid`, 412 when `expect` is stale, or a store or
    /// job error.
    pub async fn update_block_list(
        &self,
        cx: &RequestCtx,
        id: BlockListId,
        change: ListChange,
        expect: Option<Revision>,
    ) -> ZoneResult<(BlockList, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view.get_typed(&LISTS, &id)?.ok_or_else(|| not_found(id))?;
            check_expect(expect, revision)?;
            let mut list = before.clone();
            if let Some(name) = &change.name {
                list.name.clone_from(name);
            }
            if let Some(kind) = change.kind {
                list.kind = kind;
            }
            if let Some(source) = &change.source {
                list.source = source.clone();
            }
            if let Some(format) = change.format {
                list.format = format;
            }
            if let Some(interval) = change.interval_hours {
                list.interval_hours = interval;
            }
            if let Some(action) = &change.action {
                list.action = action.clone();
            }
            if let Some(enabled) = change.enabled {
                list.enabled = enabled;
            }
            if let Some(exempt) = &change.exempt {
                list.exempt.clone_from(exempt);
            }
            if let Some(description) = &change.description {
                list.description = trimmed(Some(description.clone()));
            }
            if list == before {
                return Ok(Planned::nothing(list));
            }
            check(view, &list)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&LISTS, &id, Some(revision));
            batch.put_typed(&LISTS, &id, &list)?;
            let new_source = list.source != before.source || list.format != before.format;
            if new_source {
                delete_versions(view, &mut batch, id)?;
            }
            batch.audit(
                AuditDraft::success(audit::LIST_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", list.name.clone())
                    .with_context("versions_dropped", new_source.to_string()),
            );
            Ok(Planned::write(
                list.clone(),
                batch,
                format!("change block list {}", list.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a list and its versions.
    ///
    /// # Errors
    ///
    /// `dns.list.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete_block_list(
        &self,
        cx: &RequestCtx,
        id: BlockListId,
        expect: Option<Revision>,
    ) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |view| {
                let (list, revision) = view.get_typed(&LISTS, &id)?.ok_or_else(|| not_found(id))?;
                check_expect(expect, revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&LISTS, &id, Some(revision));
                batch.delete_typed(&LISTS, &id);
                delete_versions(view, &mut batch, id)?;
                batch.audit(
                    AuditDraft::success(audit::LIST_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", list.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete block list {}", list.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }
}
