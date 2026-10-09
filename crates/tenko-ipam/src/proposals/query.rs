//! Reads of proposals for the API: the filtered, sorted and paged list, and one proposal.

use std::net::IpAddr;

use tenko_core::{
    MacAddr, ObjectRef, PrefixId, ProposalId, Revision,
    codec::KeyCodec,
    ipam::Prefix,
    serde_util::{from_hex, to_hex},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::model::{
    IntentProposal, IntentProposalKind, IntentProposalState, PROPOSALS, ProposalSeverity,
};
use crate::{
    codes,
    error::{IpamError, IpamResult},
    net::contains_net,
    tables::PREFIXES,
};

/// Largest page.
pub const MAX_LIMIT: usize = 1_000;
/// Page size when the caller gives none.
pub const DEFAULT_LIMIT: usize = 100;
/// Sort fields besides `created` (the default, newest first: `-created`).
pub const SORTS: &[&str] = &[
    "created",
    "updated",
    "severity",
    "kind",
    "state",
    "last_seen",
];

/// Filters and paging of the proposal list. Empty lists match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProposalQuery {
    /// Any of these kinds.
    pub kinds: Vec<IntentProposalKind>,
    /// Any of these states.
    pub states: Vec<IntentProposalState>,
    /// Any of these severities.
    pub severities: Vec<ProposalSeverity>,
    /// Proposals about this prefix: its own subject prefix, an address or network inside
    /// it (same VRF), or the prefix among the objects.
    pub prefix: Option<PrefixId>,
    /// Proposals about this subject: a MAC address, an IP address, an object identifier,
    /// or text contained in the subject name or key (without case).
    pub subject: Option<String>,
    /// Sort fields, `-` in front for descending; `-created` when empty. The id breaks ties.
    pub sort: Vec<String>,
    /// Page size, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// A page of proposals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalPage {
    /// The proposals, with their revision.
    pub items: Vec<IntentProposal>,
    /// Cursor of the next page.
    pub next_cursor: Option<String>,
    /// The revision of the view.
    pub revision: Revision,
}

fn invalid_filter(name: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_FILTER, 400, detail)
        .titled("Invalid filter")
        .param("name", name)
        .field(name, codes::INVALID_FILTER)
}

fn sorts(raw: &[String]) -> IpamResult<Vec<(String, bool)>> {
    let mut out = Vec::new();
    for item in raw.iter().flat_map(|item| item.split(',')) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (field, descending) = match item.strip_prefix('-') {
            Some(field) => (field, true),
            None => (item.strip_prefix('+').unwrap_or(item), false),
        };
        if !SORTS.contains(&field) {
            return Err(invalid_filter(
                "sort",
                format!(
                    "unknown sort field {field}; use one of {}",
                    SORTS.join(", ")
                ),
            ));
        }
        out.push((field.to_owned(), descending));
    }
    if out.is_empty() {
        out.push(("created".to_owned(), true));
    }
    Ok(out)
}

fn sort_key(proposal: &IntentProposal, sorts: &[(String, bool)]) -> Vec<u8> {
    let mut key = Vec::new();
    for (field, descending) in sorts {
        let mut part = Vec::new();
        match field.as_str() {
            "updated" => proposal.updated.encode_key(&mut part),
            "severity" => (proposal.severity as u8).encode_key(&mut part),
            "kind" => proposal.kind.as_str().to_owned().encode_key(&mut part),
            "state" => proposal.state.as_str().to_owned().encode_key(&mut part),
            "last_seen" => proposal.last_seen().encode_key(&mut part),
            _ => proposal.created.encode_key(&mut part),
        }
        if *descending {
            for byte in &mut part {
                *byte = !*byte;
            }
        }
        key.extend(part);
    }
    proposal.id.encode_key(&mut key);
    key
}

/// The subject filter, parsed once.
enum SubjectFilter {
    Mac(MacAddr),
    Ip(IpAddr),
    Id(uuid::Uuid),
    Text(String),
}

impl SubjectFilter {
    fn parse(text: &str) -> Self {
        let text = text.trim();
        if let Ok(mac) = text.parse::<MacAddr>() {
            SubjectFilter::Mac(mac)
        } else if let Ok(ip) = text.parse::<IpAddr>() {
            SubjectFilter::Ip(ip)
        } else if let Ok(id) = uuid::Uuid::parse_str(text) {
            SubjectFilter::Id(id)
        } else {
            SubjectFilter::Text(text.to_ascii_lowercase())
        }
    }

    fn matches(&self, proposal: &IntentProposal) -> bool {
        let subject = &proposal.subject;
        match self {
            SubjectFilter::Mac(mac) => {
                subject.mac == Some(*mac)
                    || proposal
                        .evidence
                        .iter()
                        .any(|evidence| evidence.mac == Some(*mac))
            }
            SubjectFilter::Ip(ip) => {
                subject.ip == Some(*ip)
                    || subject.cidr.is_some_and(|cidr| cidr.contains(ip))
                    || proposal
                        .evidence
                        .iter()
                        .any(|evidence| evidence.ip == Some(*ip))
            }
            SubjectFilter::Id(id) => {
                proposal.id.uuid() == *id
                    || subject.objects.iter().any(|object| object.id == *id)
                    || subject.prefix.is_some_and(|prefix| prefix.uuid() == *id)
                    || subject.vrf.is_some_and(|vrf| vrf.uuid() == *id)
            }
            SubjectFilter::Text(text) => {
                proposal.key.to_ascii_lowercase().contains(text)
                    || subject
                        .name
                        .as_ref()
                        .is_some_and(|name| name.to_ascii_lowercase().contains(text))
            }
        }
    }
}

fn about_prefix(proposal: &IntentProposal, prefix: &Prefix) -> bool {
    let subject = &proposal.subject;
    subject.prefix == Some(prefix.id)
        || subject.objects.contains(&ObjectRef::from(prefix.id))
        || (subject.vrf == Some(prefix.vrf)
            && (subject.ip.is_some_and(|ip| prefix.cidr.contains(&ip))
                || subject
                    .cidr
                    .is_some_and(|cidr| contains_net(&prefix.cidr, &cidr))))
}

/// Lists proposals (see [`ProposalQuery`]).
///
/// # Errors
///
/// `ipam.invalid_filter` for an unknown sort field, `ipam.invalid_cursor`, `ipam.not_found`
/// for an unknown prefix filter, store and decoding errors.
pub fn list(view: &dyn ReadView, query: &ProposalQuery) -> IpamResult<ProposalPage> {
    let limit = match query.limit {
        None => DEFAULT_LIMIT,
        Some(limit) if (1..=MAX_LIMIT).contains(&limit) => limit,
        Some(_) => {
            return Err(invalid_filter(
                "limit",
                format!("limit is 1 to {MAX_LIMIT}"),
            ));
        }
    };
    let sorts = sorts(&query.sort)?;
    let after = query
        .cursor
        .as_deref()
        .map(|text| {
            from_hex(text).ok_or_else(|| {
                IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                    .titled("Invalid cursor")
                    .field("cursor", codes::INVALID_CURSOR)
            })
        })
        .transpose()?;
    let prefix = match query.prefix {
        Some(id) => Some(
            view.get_typed(&PREFIXES, &id)?
                .map(|(prefix, _)| prefix)
                .ok_or_else(|| IpamError::not_found(ObjectRef::from(id)))?,
        ),
        None => None,
    };
    let subject = query.subject.as_deref().map(SubjectFilter::parse);
    let mut rows: Vec<(Vec<u8>, IntentProposal)> = view
        .scan_typed(&PROPOSALS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter_map(|(_, mut proposal, revision)| {
            proposal.revision = revision;
            let keep = (query.kinds.is_empty() || query.kinds.contains(&proposal.kind))
                && (query.states.is_empty() || query.states.contains(&proposal.state))
                && (query.severities.is_empty() || query.severities.contains(&proposal.severity))
                && prefix
                    .as_ref()
                    .is_none_or(|prefix| about_prefix(&proposal, prefix))
                && subject
                    .as_ref()
                    .is_none_or(|subject| subject.matches(&proposal));
            keep.then(|| (sort_key(&proposal, &sorts), proposal))
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
    Ok(ProposalPage {
        items: rows.into_iter().map(|(_, proposal)| proposal).collect(),
        next_cursor,
        revision: view.revision(),
    })
}

/// One proposal with its revision.
///
/// # Errors
///
/// `ipam.proposal.not_found`, store and decoding errors.
pub fn get(view: &dyn ReadView, id: ProposalId) -> IpamResult<IntentProposal> {
    super::decide::load(view, id)
}
