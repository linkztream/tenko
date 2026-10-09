//! Reads for the API: single objects with their revision, lists with filters, sorting and
//! opaque cursors, history pages, the addresses of a prefix with free gaps, tags, custom
//! field definitions and search.
//!
//! Lists read the whole table from one view, filter, sort and cut a page. That is linear
//! in the table size, which suits the home-scale IPAM of Phase 1 (tens of thousands of
//! objects); the cursor is the encoded sort key of the last item, so pages stay stable
//! while objects are added or removed elsewhere in the order.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, InterfaceId, ObjectKind, ObjectRef, PrefixId, Revision, SiteId, TenantId, Timestamp,
    VrfId,
    codec::{KeyCodec, encode_key},
    ipam::{
        Address, AssignmentMode, CustomFieldDef, FieldKey, Host, Interface, Meta, Prefix,
        PrefixRole, Range, RangeRole, Site, Status, Tag, Tenant, Vlan, Vrf,
    },
    serde_util::{from_hex, to_hex},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use crate::{
    error::{IpamError, IpamResult, codes},
    history::HistoryEntry,
    net::{Family, bounds, contains_ip, contains_net, host_bounds, ip_to_u128, span, u128_to_ip},
    object::{Entity, IpamObject},
    tables::{ADDRESS_IPS, CUSTOM_FIELD_KEYS, CUSTOM_FIELDS, HISTORY, HOST_INTERFACES, TAG_USAGE},
};

/// Largest page.
pub const MAX_LIMIT: usize = 1_000;
/// Page size when the caller gives none.
pub const DEFAULT_LIMIT: usize = 100;

/// Which soft-deleted objects a list returns (IPAM-09).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Deleted {
    /// Live objects only.
    #[default]
    Exclude,
    /// Live and deleted objects.
    Include,
    /// Deleted objects only (the restore view).
    Only,
}

/// A list request. Every filter is optional; filters that do not apply to a kind are
/// ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListQuery {
    /// Page size, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Any of these statuses.
    pub status: Vec<Status>,
    /// Objects of this VRF (prefixes, addresses).
    pub vrf: Option<VrfId>,
    /// Objects of this tenant (VRFs, hosts).
    pub tenant: Option<TenantId>,
    /// Objects of this site (sites by parent, VLANs, prefixes, hosts).
    pub site: Option<SiteId>,
    /// Objects carrying every one of these tags.
    pub tag: Vec<Tag>,
    /// Prefixes, ranges and addresses inside this network.
    pub within: Option<IpNet>,
    /// Case-insensitive text search over names, addresses, DNS names and descriptions.
    pub q: Option<String>,
    /// Sort fields, `-` in front for descending; the kind's default when empty.
    pub sort: Vec<String>,
    /// Deleted objects.
    pub deleted: Deleted,
    /// Addresses and ranges of this prefix (addresses whose most specific prefix it is).
    pub prefix: Option<PrefixId>,
    /// Interfaces and addresses of this host.
    pub host: Option<HostId>,
    /// Addresses of this interface.
    pub interface: Option<InterfaceId>,
    /// Prefix role.
    pub prefix_role: Option<PrefixRole>,
    /// Range role.
    pub range_role: Option<RangeRole>,
    /// Host assignment mode.
    pub mode: Option<AssignmentMode>,
    /// Host lock.
    pub locked: Option<bool>,
}

/// A page of a list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The items.
    pub items: Vec<T>,
    /// Cursor of the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    /// The revision of the view the page was read from; subscribe to events from here.
    pub revision: Revision,
}

/// Context resolved once per list.
#[derive(Debug, Default)]
pub struct Resolved {
    /// Interfaces of the `host` filter.
    pub host_interfaces: Option<BTreeSet<InterfaceId>>,
}

/// A model type that can be listed.
pub trait Listable: Entity {
    /// Sort fields besides `created` and `updated`; the first is the default.
    const SORTS: &'static [&'static str];

    /// Order-preserving bytes of a sort field (known to be valid).
    fn sort_key(&self, field: &str, out: &mut Vec<u8>);

    /// Kind-specific filters.
    fn matches(&self, query: &ListQuery, resolved: &Resolved) -> bool;

    /// Text for `q`.
    fn text(&self) -> String;
}

fn meta_text(meta: &Meta) -> String {
    let mut text = meta.description.clone().unwrap_or_default();
    for tag in &meta.tags {
        text.push(' ');
        text.push_str(tag.as_str());
    }
    text
}

fn status_ok(query: &ListQuery, status: Status) -> bool {
    query.status.is_empty() || query.status.contains(&status)
}

fn lower_key(text: &str, out: &mut Vec<u8>) {
    text.to_lowercase().encode_key(out);
}

impl Listable for Tenant {
    const SORTS: &'static [&'static str] = &["name"];
    fn sort_key(&self, _field: &str, out: &mut Vec<u8>) {
        lower_key(&self.name, out);
    }
    fn matches(&self, _query: &ListQuery, _resolved: &Resolved) -> bool {
        true
    }
    fn text(&self) -> String {
        format!("{} {}", self.name, meta_text(&self.meta))
    }
}

impl Listable for Vrf {
    const SORTS: &'static [&'static str] = &["name"];
    fn sort_key(&self, _field: &str, out: &mut Vec<u8>) {
        lower_key(&self.name, out);
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        query.tenant.is_none_or(|t| t == self.tenant)
    }
    fn text(&self) -> String {
        format!(
            "{} {} {}",
            self.name,
            self.rd.clone().unwrap_or_default(),
            meta_text(&self.meta)
        )
    }
}

impl Listable for Site {
    const SORTS: &'static [&'static str] = &["name"];
    fn sort_key(&self, _field: &str, out: &mut Vec<u8>) {
        lower_key(&self.name, out);
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        query.site.is_none_or(|s| self.parent == Some(s))
    }
    fn text(&self) -> String {
        format!(
            "{} {} {}",
            self.name,
            self.ad_site.clone().unwrap_or_default(),
            meta_text(&self.meta)
        )
    }
}

impl Listable for Vlan {
    const SORTS: &'static [&'static str] = &["vid", "name"];
    fn sort_key(&self, field: &str, out: &mut Vec<u8>) {
        match field {
            "name" => lower_key(&self.name, out),
            _ => self.vid.encode_key(out),
        }
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        status_ok(query, self.status) && query.site.is_none_or(|s| self.site == Some(s))
    }
    fn text(&self) -> String {
        format!("{} {} {}", self.vid, self.name, meta_text(&self.meta))
    }
}

impl Listable for Prefix {
    const SORTS: &'static [&'static str] = &["cidr", "status"];
    fn sort_key(&self, field: &str, out: &mut Vec<u8>) {
        if field == "status" {
            format!("{:?}", self.status).encode_key(out);
        } else {
            self.vrf.encode_key(out);
            self.cidr.encode_key(out);
        }
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        status_ok(query, self.status)
            && query.vrf.is_none_or(|v| v == self.vrf)
            && query.site.is_none_or(|s| self.site == Some(s))
            && query.within.is_none_or(|w| contains_net(&w, &self.cidr))
            && query.prefix_role.is_none_or(|r| r == self.role)
    }
    fn text(&self) -> String {
        format!("{} {}", self.cidr, meta_text(&self.meta))
    }
}

impl Listable for Range {
    const SORTS: &'static [&'static str] = &["first"];
    fn sort_key(&self, _field: &str, out: &mut Vec<u8>) {
        self.first.encode_key(out);
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        status_ok(query, self.status)
            && query.prefix.is_none_or(|p| p == self.prefix)
            && query
                .within
                .is_none_or(|w| contains_ip(&w, self.first) && contains_ip(&w, self.last))
            && query.range_role.is_none_or(|r| r == self.role)
    }
    fn text(&self) -> String {
        format!("{} {} {}", self.first, self.last, meta_text(&self.meta))
    }
}

impl Listable for Address {
    const SORTS: &'static [&'static str] = &["ip", "dns_name", "status"];
    fn sort_key(&self, field: &str, out: &mut Vec<u8>) {
        match field {
            "dns_name" => self
                .dns_name
                .as_ref()
                .map(|n| n.as_str().to_owned())
                .encode_key(out),
            "status" => format!("{:?}", self.status).encode_key(out),
            _ => {
                self.vrf.encode_key(out);
                self.ip.encode_key(out);
            }
        }
    }
    fn matches(&self, query: &ListQuery, resolved: &Resolved) -> bool {
        status_ok(query, self.status)
            && query.vrf.is_none_or(|v| v == self.vrf)
            && query.within.is_none_or(|w| contains_ip(&w, self.ip))
            && query.prefix.is_none_or(|p| p == self.prefix)
            && query.interface.is_none_or(|i| self.interface == Some(i))
            && resolved
                .host_interfaces
                .as_ref()
                .is_none_or(|set| self.interface.is_some_and(|i| set.contains(&i)))
    }
    fn text(&self) -> String {
        format!(
            "{} {} {}",
            self.ip,
            self.dns_name
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            meta_text(&self.meta)
        )
    }
}

impl Listable for Host {
    const SORTS: &'static [&'static str] = &["name", "mode"];
    fn sort_key(&self, field: &str, out: &mut Vec<u8>) {
        match field {
            "mode" => format!("{:?}", self.mode).encode_key(out),
            _ => self.name.as_str().to_owned().encode_key(out),
        }
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        query.tenant.is_none_or(|t| t == self.tenant)
            && query.site.is_none_or(|s| self.site == Some(s))
            && query.mode.is_none_or(|m| m == self.mode)
            && query.locked.is_none_or(|l| l == self.lock)
    }
    fn text(&self) -> String {
        format!("{} {}", self.name, meta_text(&self.meta))
    }
}

impl Listable for Interface {
    const SORTS: &'static [&'static str] = &["name"];
    fn sort_key(&self, _field: &str, out: &mut Vec<u8>) {
        self.host.encode_key(out);
        lower_key(&self.name, out);
    }
    fn matches(&self, query: &ListQuery, _resolved: &Resolved) -> bool {
        query.host.is_none_or(|h| h == self.host)
    }
    fn text(&self) -> String {
        format!(
            "{} {} {}",
            self.name,
            self.mac.map(|m| m.to_string()).unwrap_or_default(),
            meta_text(&self.meta)
        )
    }
}

/// Reads one object; its `meta.revision` is the stored revision. Deleted objects are
/// returned too (with `meta.deleted` set).
///
/// # Errors
///
/// `ipam.not_found` when absent; store and decoding errors.
pub fn get<T: Entity>(view: &dyn ReadView, id: T::Id) -> IpamResult<T> {
    let (mut object, revision) = view
        .get_typed(T::table(), &id)?
        .ok_or_else(|| IpamError::not_found(id.into()))?;
    object.meta_mut().revision = revision;
    Ok(object)
}

/// Reads one object of any IPAM kind.
///
/// # Errors
///
/// `ipam.not_found` when absent or not an IPAM kind; store and decoding errors.
pub fn get_object(view: &dyn ReadView, object: ObjectRef) -> IpamResult<IpamObject> {
    Ok(match object.kind {
        ObjectKind::Tenant => get::<Tenant>(view, object.id.into())?.into_object(),
        ObjectKind::Vrf => get::<Vrf>(view, object.id.into())?.into_object(),
        ObjectKind::Site => get::<Site>(view, object.id.into())?.into_object(),
        ObjectKind::Vlan => get::<Vlan>(view, object.id.into())?.into_object(),
        ObjectKind::Prefix => get::<Prefix>(view, object.id.into())?.into_object(),
        ObjectKind::Range => get::<Range>(view, object.id.into())?.into_object(),
        ObjectKind::Address => get::<Address>(view, object.id.into())?.into_object(),
        ObjectKind::Host => get::<Host>(view, object.id.into())?.into_object(),
        ObjectKind::Interface => get::<Interface>(view, object.id.into())?.into_object(),
        ObjectKind::CustomField => IpamObject::CustomField(
            view.get_typed(&CUSTOM_FIELDS, &object.id.into())?
                .map(|(def, _)| def)
                .ok_or_else(|| IpamError::not_found(object))?,
        ),
        _ => return Err(IpamError::not_found(object)),
    })
}

fn invalid_filter(name: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_FILTER, 400, detail)
        .titled("Invalid list parameter")
        .param("name", name)
        .field(name, codes::INVALID_FILTER)
}

/// The page size of a query.
///
/// # Errors
///
/// `ipam.invalid_filter` outside 1 to [`MAX_LIMIT`].
pub fn limit_of(limit: Option<usize>) -> IpamResult<usize> {
    match limit {
        None => Ok(DEFAULT_LIMIT),
        Some(limit) if (1..=MAX_LIMIT).contains(&limit) => Ok(limit),
        Some(limit) => Err(invalid_filter(
            "limit",
            format!("limit {limit} is outside 1 to {MAX_LIMIT}"),
        )),
    }
}

fn parse_sorts<T: Listable>(sort: &[String]) -> IpamResult<Vec<(String, bool)>> {
    let mut out = Vec::new();
    for item in sort.iter().flat_map(|s| s.split(',')) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (field, descending) = match item.strip_prefix('-') {
            Some(field) => (field, true),
            None => (item.strip_prefix('+').unwrap_or(item), false),
        };
        if !T::SORTS.contains(&field) && field != "created" && field != "updated" {
            return Err(invalid_filter(
                "sort",
                format!(
                    "unknown sort field {field}; use one of {}, created, updated",
                    T::SORTS.join(", ")
                ),
            ));
        }
        out.push((field.to_owned(), descending));
    }
    if out.is_empty() {
        out.push((T::SORTS[0].to_owned(), false));
    }
    Ok(out)
}

fn composite_key<T: Listable>(object: &T, sorts: &[(String, bool)]) -> Vec<u8> {
    let mut key = Vec::new();
    for (field, descending) in sorts {
        let mut part = Vec::new();
        match field.as_str() {
            "created" => object.meta().created.at.encode_key(&mut part),
            "updated" => object.meta().updated.at.encode_key(&mut part),
            other => object.sort_key(other, &mut part),
        }
        if *descending {
            // Every component encoding is self-delimiting, so inverting the bytes
            // reverses the order.
            for byte in &mut part {
                *byte = !*byte;
            }
        }
        key.extend(part);
    }
    object.id().encode_key(&mut key);
    key
}

fn decode_cursor(cursor: Option<&str>) -> IpamResult<Option<Vec<u8>>> {
    cursor
        .map(|text| {
            from_hex(text).ok_or_else(|| {
                IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                    .titled("Invalid cursor")
                    .field("cursor", codes::INVALID_CURSOR)
            })
        })
        .transpose()
}

/// Lists objects of one kind (see [`ListQuery`]).
///
/// # Errors
///
/// `ipam.invalid_filter`, `ipam.invalid_cursor`, store and decoding errors.
pub fn list<T: Listable>(view: &dyn ReadView, query: &ListQuery) -> IpamResult<Page<T>> {
    let limit = limit_of(query.limit)?;
    let sorts = parse_sorts::<T>(&query.sort)?;
    let after = decode_cursor(query.cursor.as_deref())?;
    let resolved = Resolved {
        host_interfaces: match query.host {
            Some(host) if T::KIND == ObjectKind::Address => Some(
                view.scan_typed(
                    &HOST_INTERFACES,
                    KeyRange::prefix(encode_key(&host)),
                    usize::MAX,
                    false,
                )?
                .into_iter()
                .map(|((_, interface), (), _)| interface)
                .collect(),
            ),
            _ => None,
        },
    };
    let tags: BTreeSet<&Tag> = query.tag.iter().collect();
    let needle = query.q.as_ref().map(|q| q.trim().to_lowercase());
    let mut rows: Vec<(Vec<u8>, T)> = view
        .scan_typed(T::table(), KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter_map(|(_, mut object, revision)| {
            object.meta_mut().revision = revision;
            let deleted = object.meta().is_deleted();
            let keep = match query.deleted {
                Deleted::Exclude => !deleted,
                Deleted::Include => true,
                Deleted::Only => deleted,
            } && tags.iter().all(|t| object.meta().tags.contains(*t))
                && object.matches(query, &resolved)
                && needle
                    .as_ref()
                    .is_none_or(|n| n.is_empty() || object.text().to_lowercase().contains(n));
            keep.then(|| (composite_key(&object, &sorts), object))
        })
        .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if more {
        rows.last().map(|(key, _)| to_hex(key))
    } else {
        None
    };
    Ok(Page {
        items: rows.into_iter().map(|(_, object)| object).collect(),
        next_cursor,
        revision: view.revision(),
    })
}

/// A page of an object's history, newest first.
///
/// # Errors
///
/// `ipam.invalid_cursor`, store and decoding errors.
pub fn history(
    view: &dyn ReadView,
    object: ObjectRef,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> IpamResult<Page<HistoryEntry>> {
    let limit = limit_of(limit)?;
    let before = decode_cursor(cursor)?;
    let mut range = KeyRange::prefix(encode_key(&object));
    if let Some(before) = before {
        range = range.before(before);
    }
    let rows = view.scan(HISTORY.name(), range, limit + 1, true)?;
    let more = rows.len() > limit;
    let mut items = Vec::with_capacity(limit);
    let mut last_key = None;
    for (key, versioned) in rows.into_iter().take(limit) {
        let mut entry = HISTORY.decode(&versioned.value)?;
        entry.revision = versioned.revision;
        last_key = Some(key);
        items.push(entry);
    }
    Ok(Page {
        items,
        next_cursor: if more {
            last_key.map(|k| to_hex(&k))
        } else {
            None
        },
        revision: view.revision(),
    })
}

/// One row of a prefix's address list: an address object or a free gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum PrefixAddressItem {
    /// An address object.
    Address(Box<Address>),
    /// Free addresses between two address objects.
    Free {
        /// First free address.
        #[schema(value_type = String)]
        first: IpAddr,
        /// Last free address.
        #[schema(value_type = String)]
        last: IpAddr,
        /// Number of free addresses, as a decimal string.
        size: String,
    },
}

/// The addresses inside a prefix in address order, with the free gaps between them
/// (inside the assignable range of a network) when `include_free`.
///
/// # Errors
///
/// `ipam.not_found`, `ipam.invalid_cursor`, store and decoding errors.
pub fn prefix_addresses(
    view: &dyn ReadView,
    prefix: PrefixId,
    include_free: bool,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> IpamResult<Page<PrefixAddressItem>> {
    let limit = limit_of(limit)?;
    let prefix = get::<Prefix>(view, prefix)?;
    let family = Family::of_net(&prefix.cidr);
    let (first, last) = bounds(&prefix.cidr);
    let (lo, hi) = match prefix.role {
        PrefixRole::Network => host_bounds(&prefix.cidr),
        PrefixRole::Supernet => (first, last),
    };
    let start = match decode_cursor(cursor)? {
        Some(bytes) => {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
                IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                    .field("cursor", codes::INVALID_CURSOR)
            })?;
            u128::from_be_bytes(bytes)
        }
        None => first,
    };
    if start > last {
        return Ok(Page {
            items: Vec::new(),
            next_cursor: None,
            revision: view.revision(),
        });
    }
    let range = KeyRange {
        start: std::ops::Bound::Included(ADDRESS_IPS.key(&(prefix.vrf, u128_to_ip(family, start)))),
        end: std::ops::Bound::Included(ADDRESS_IPS.key(&(prefix.vrf, u128_to_ip(family, last)))),
    };
    // Every address yields an item, so `limit + 1` addresses always fill the page.
    let ids = view.scan_typed(&ADDRESS_IPS, range, limit + 1, false)?;
    let gap = |from: u128, to: Option<u128>| {
        let to = to?;
        let (gap_first, gap_last) = (from.max(lo), to.min(hi));
        (include_free && gap_first <= gap_last).then_some((gap_first, gap_last))
    };
    let mut items = Vec::new();
    // The first number not yet shown; `None` once the end of the space was passed.
    let mut position = Some(start);
    let mut next = None;
    for ((_, ip), id, _) in ids {
        let value = ip_to_u128(ip);
        if let Some(from) = position
            && let Some((gap_first, gap_last)) = gap(from, value.checked_sub(1))
        {
            if items.len() == limit {
                next = Some(gap_first);
                break;
            }
            items.push(free_item(family, gap_first, gap_last));
        }
        if items.len() == limit {
            next = Some(value);
            break;
        }
        items.push(PrefixAddressItem::Address(Box::new(get::<Address>(
            view, id,
        )?)));
        position = value.checked_add(1);
    }
    if next.is_none()
        && let Some(from) = position
        && let Some((gap_first, gap_last)) = gap(from, Some(last))
    {
        if items.len() == limit {
            next = Some(gap_first);
        } else {
            items.push(free_item(family, gap_first, gap_last));
        }
    }
    Ok(Page {
        items,
        next_cursor: next.map(|position| to_hex(&position.to_be_bytes())),
        revision: view.revision(),
    })
}

fn free_item(family: Family, first: u128, last: u128) -> PrefixAddressItem {
    PrefixAddressItem::Free {
        first: u128_to_ip(family, first),
        last: u128_to_ip(family, last),
        size: span(first, last).to_string(),
    }
}

/// A tag and how many live objects carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TagCount {
    /// The tag.
    #[schema(value_type = String)]
    pub tag: String,
    /// Objects carrying it.
    pub count: u64,
    /// Objects per kind.
    pub by_kind: BTreeMap<String, u64>,
}

/// The tags in use, by name.
///
/// # Errors
///
/// Store and decoding errors.
pub fn tags(view: &dyn ReadView) -> IpamResult<Vec<TagCount>> {
    let mut counts: BTreeMap<String, TagCount> = BTreeMap::new();
    for ((tag, object), (), _) in view.scan_typed(&TAG_USAGE, KeyRange::all(), usize::MAX, false)? {
        let entry = counts.entry(tag.clone()).or_insert_with(|| TagCount {
            tag,
            count: 0,
            by_kind: BTreeMap::new(),
        });
        entry.count += 1;
        *entry
            .by_kind
            .entry(object.kind.as_str().to_owned())
            .or_default() += 1;
    }
    Ok(counts.into_values().collect())
}

/// The custom field definitions, by key.
///
/// # Errors
///
/// Store and decoding errors.
pub fn custom_fields(view: &dyn ReadView) -> IpamResult<Vec<CustomFieldDef>> {
    let mut defs: Vec<CustomFieldDef> = view
        .scan_typed(&CUSTOM_FIELDS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, def, _)| def)
        .collect();
    defs.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(defs)
}

/// One custom field definition by key, with the revision of its record.
///
/// # Errors
///
/// `ipam.not_found`, store and decoding errors.
pub fn custom_field(view: &dyn ReadView, key: &FieldKey) -> IpamResult<(CustomFieldDef, Revision)> {
    let not_found = || {
        IpamError::new(
            codes::NOT_FOUND,
            404,
            format!("custom field {key} does not exist"),
        )
        .titled("Object not found")
        .param("kind", "custom_field")
        .param("key", key)
    };
    let (id, _) = view
        .get_typed(&CUSTOM_FIELD_KEYS, &key.as_str().to_owned())?
        .ok_or_else(not_found)?;
    view.get_typed(&CUSTOM_FIELDS, &id)?.ok_or_else(not_found)
}

/// One search hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SearchHit {
    /// The object.
    pub object: ObjectRef,
    /// A short label: the network, address or name.
    pub label: String,
    /// The object itself.
    pub item: IpamObject,
}

/// Searches live prefixes, addresses and hosts (and VLANs, sites, VRFs and tenants by
/// name). An address finds the address objects and the most specific prefixes containing
/// it; a network finds the prefixes inside it; other text matches names, DNS names, MAC
/// addresses and descriptions, case-insensitively. Only kinds for which `readable` answers
/// `true` count; at most `limit` hits, prefixes first.
///
/// # Errors
///
/// Store and decoding errors.
pub fn search(
    view: &dyn ReadView,
    q: &str,
    limit: Option<usize>,
    readable: impl Fn(ObjectKind) -> bool,
) -> IpamResult<Vec<SearchHit>> {
    let limit = limit_of(limit)?;
    let q = q.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let mut hits = Vec::new();
    let mut push = |item: IpamObject| {
        if hits.len() < limit && readable(item.object_ref().kind) {
            hits.push(SearchHit {
                object: item.object_ref(),
                label: item.label(),
                item,
            });
        }
    };
    let live = |meta: &Meta| !meta.is_deleted();
    if let Ok(ip) = q.parse::<IpAddr>() {
        let prefixes: Vec<Prefix> = all::<Prefix>(view)?
            .into_iter()
            .filter(|p| live(&p.meta) && contains_ip(&p.cidr, ip))
            .collect();
        // The most specific containing prefix per VRF.
        let mut best: BTreeMap<VrfId, Prefix> = BTreeMap::new();
        for prefix in prefixes {
            let replace = best
                .get(&prefix.vrf)
                .is_none_or(|b| b.cidr.prefix_len() < prefix.cidr.prefix_len());
            if replace {
                best.insert(prefix.vrf, prefix);
            }
        }
        for prefix in best.into_values() {
            push(prefix.into_object());
        }
        for address in all::<Address>(view)? {
            if live(&address.meta) && address.ip == ip {
                push(address.into_object());
            }
        }
        return Ok(hits);
    }
    if let Ok(net) = q.parse::<IpNet>() {
        for prefix in all::<Prefix>(view)? {
            if live(&prefix.meta) && contains_net(&net, &prefix.cidr) {
                push(prefix.into_object());
            }
        }
        return Ok(hits);
    }
    let needle = q.to_lowercase();
    let mac = q.parse::<tenko_core::MacAddr>().ok();
    let matches = |text: String| text.to_lowercase().contains(&needle);
    for prefix in all::<Prefix>(view)? {
        if live(&prefix.meta) && matches(prefix.text()) {
            push(prefix.into_object());
        }
    }
    for address in all::<Address>(view)? {
        if live(&address.meta) && matches(address.text()) {
            push(address.into_object());
        }
    }
    for host in all::<Host>(view)? {
        if live(&host.meta) && matches(host.text()) {
            push(host.into_object());
        }
    }
    for interface in all::<Interface>(view)? {
        if live(&interface.meta)
            && (mac.is_some() && interface.mac == mac || matches(interface.text()))
        {
            push(interface.into_object());
        }
    }
    for vlan in all::<Vlan>(view)? {
        if live(&vlan.meta) && matches(vlan.text()) {
            push(vlan.into_object());
        }
    }
    for site in all::<Site>(view)? {
        if live(&site.meta) && matches(site.text()) {
            push(site.into_object());
        }
    }
    for vrf in all::<Vrf>(view)? {
        if live(&vrf.meta) && matches(vrf.text()) {
            push(vrf.into_object());
        }
    }
    for tenant in all::<Tenant>(view)? {
        if live(&tenant.meta) && matches(tenant.text()) {
            push(tenant.into_object());
        }
    }
    Ok(hits)
}

fn all<T: Entity>(view: &dyn ReadView) -> IpamResult<Vec<T>> {
    Ok(view
        .scan_typed(T::table(), KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, mut object, revision)| {
            object.meta_mut().revision = revision;
            object
        })
        .collect())
}

/// When an object last changed, for `If-Modified-Since` style checks and the UI.
pub fn updated_at<T: Entity>(object: &T) -> Timestamp {
    object.meta().updated.at
}

/// The prefixes of a VRF that contain `ip`, most specific last.
///
/// # Errors
///
/// Store and decoding errors.
pub fn containing_prefixes(view: &dyn ReadView, vrf: VrfId, ip: IpAddr) -> IpamResult<Vec<Prefix>> {
    let family = Family::of(ip);
    let value = ip_to_u128(ip);
    let mut out = Vec::new();
    for len in 0..=family.bits() {
        let net = crate::net::net_from(family, value, len);
        if let Some((id, _)) = view.get_typed(&crate::tables::PREFIX_CIDRS, &(vrf, net))? {
            out.push(get::<Prefix>(view, id)?);
        }
    }
    Ok(out)
}
