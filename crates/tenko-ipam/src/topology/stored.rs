//! What a person decided on the topology, stored so that it survives a restart and every
//! read of a connector: the root of the map ("Use this", UI-Q10), the per-SSID policy of the
//! WLAN rules (track or ignore) and the "Keep on this WLAN" exception of one host on one
//! SSID.
//!
//! Each decision is one row of its own table, written only by its route with an audit
//! record in the same batch, the pattern of the name authority (`ipam.name_authority`,
//! `docs/reconciliation.md` section 4.11). Nothing here is derived from what the
//! controllers report, so a re-read of a connector never removes a decision; a decision
//! about a host that is deleted later stays harmless, since the rules only read live hosts.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `ipam.topology_root` | none (one row) | [`RootChoice`] |
//! | `ipam.wlan_policies` | SSID | [`StoredWlanPolicy`] |
//! | `ipam.wlan_exceptions` | (host, SSID) | [`WlanException`] |

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, ObjectKind, ObjectRef, RequestCtx, Revision,
    audit::{AuditAction, AuditDraft, FieldChange},
    ipam::Stamp,
    table::TableDef,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::root::RootSource;
use crate::{
    error::{IpamError, IpamResult, codes::REVISION_MISMATCH},
    tables::HOSTS,
};

/// The root a person chose, with the candidates on offer then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RootChoice {
    /// The source the map follows.
    pub source: RootSource,
    /// The keys of the candidates on offer (`controller:<node>`, `route:<address>`): while
    /// the sources offer the same, their disagreement raises no finding again.
    #[serde(default)]
    pub offered: Vec<String>,
    /// Who chose and when.
    pub decided: Stamp,
    /// Store revision (filled when read): the `ETag`.
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// Whether the WLAN rules read an SSID at all.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WlanPolicy {
    /// The rules read its clients.
    Track,
    /// The rules skip it; the default of a guest SSID.
    Ignore,
}

impl WlanPolicy {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            WlanPolicy::Track => "track",
            WlanPolicy::Ignore => "ignore",
        }
    }

    /// The policy of an SSID nobody set one for: ignore a guest SSID, track every other.
    pub const fn default_for(guest: bool) -> Self {
        if guest {
            WlanPolicy::Ignore
        } else {
            WlanPolicy::Track
        }
    }
}

/// The policy a person set for an SSID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoredWlanPolicy {
    /// The SSID.
    pub ssid: String,
    /// The policy.
    pub policy: WlanPolicy,
    /// Who set it and when.
    pub updated: Stamp,
    /// Store revision (filled when read): the `ETag`.
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// "Keep on this WLAN": the WLAN rules skip this host on this SSID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WlanException {
    /// The host.
    pub host: HostId,
    /// The SSID.
    pub ssid: String,
    /// Why, as the person wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Who decided and when.
    pub decided: Stamp,
    /// Store revision (filled when read): the `ETag`.
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The chosen root (one row).
pub static ROOT_CHOICE: TableDef<(), RootChoice> = TableDef::new("ipam.topology_root");
/// The per-SSID policies by SSID.
pub static WLAN_POLICIES: TableDef<String, StoredWlanPolicy> = TableDef::new("ipam.wlan_policies");
/// The exceptions by host and SSID.
pub static WLAN_EXCEPTIONS: TableDef<(HostId, String), WlanException> =
    TableDef::new("ipam.wlan_exceptions");

/// Audit actions of the topology's decisions.
pub mod actions {
    /// A person chose the root of the map ("Use this"); records the old and the new source.
    pub const ROOT_CHOOSE: &str = "ipam.topology_root.choose";
    /// A person forgot the chosen root; the ranked sources decide again.
    pub const ROOT_CLEAR: &str = "ipam.topology_root.clear";
    /// A person set the policy of an SSID; records the old and the new policy.
    pub const POLICY_SET: &str = "ipam.wlan_policy.set";
    /// A person removed the policy of an SSID; its default applies again.
    pub const POLICY_CLEAR: &str = "ipam.wlan_policy.clear";
    /// "Keep on this WLAN": a person kept a host on an SSID; records the SSID and the
    /// reason.
    pub const EXCEPTION_KEEP: &str = "ipam.wlan_exception.keep";
    /// A person removed an exception; the WLAN rules read the host on the SSID again.
    pub const EXCEPTION_CLEAR: &str = "ipam.wlan_exception.clear";
}

/// Stable error codes of the decisions.
pub mod codes {
    /// A value of the request is outside its bounds (422). Params: `field`.
    pub const INVALID: &str = "ipam.topology.invalid";
    /// The source names no root candidate now (409). Params: `source`.
    pub const NO_CANDIDATE: &str = "ipam.topology.no_candidate";
    /// No such decision is stored (404). Params: `kind`.
    pub const NOT_STORED: &str = "ipam.topology.not_stored";
}

/// The longest SSID: 32 octets (IEEE 802.11).
pub const MAX_SSID_BYTES: usize = 32;
/// The longest reason of an exception, in bytes.
pub const MAX_REASON_BYTES: usize = 1_024;

/// Every decision, as the rules read them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stored {
    /// The chosen root.
    pub root: Option<RootChoice>,
    /// The policies by SSID.
    pub policies: BTreeMap<String, StoredWlanPolicy>,
    /// The exceptions by host and SSID.
    pub exceptions: BTreeMap<(HostId, String), WlanException>,
}

impl Stored {
    /// Reads every decision from `view`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    pub fn load(view: &dyn ReadView) -> IpamResult<Self> {
        let root = view
            .get_typed(&ROOT_CHOICE, &())?
            .map(|(mut row, revision)| {
                row.revision = revision;
                row
            });
        let mut policies = BTreeMap::new();
        for (ssid, mut row, revision) in
            view.scan_typed(&WLAN_POLICIES, KeyRange::all(), usize::MAX, false)?
        {
            row.revision = revision;
            policies.insert(ssid, row);
        }
        let mut exceptions = BTreeMap::new();
        for (key, mut row, revision) in
            view.scan_typed(&WLAN_EXCEPTIONS, KeyRange::all(), usize::MAX, false)?
        {
            row.revision = revision;
            exceptions.insert(key, row);
        }
        Ok(Self {
            root,
            policies,
            exceptions,
        })
    }

    /// The policy in force for an SSID and whether a person set it.
    pub fn policy(&self, ssid: &str, guest: bool) -> (WlanPolicy, bool) {
        self.policies
            .get(ssid)
            .map_or((WlanPolicy::default_for(guest), false), |row| {
                (row.policy, true)
            })
    }

    /// Whether the host is kept on the SSID.
    pub fn kept(&self, host: HostId, ssid: &str) -> bool {
        self.exceptions.contains_key(&(host, ssid.to_owned()))
    }
}

fn invalid(field: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID, 422, detail)
        .titled("Invalid topology decision")
        .param("field", field)
        .field(field, codes::INVALID)
}

fn not_stored(kind: &str) -> IpamError {
    IpamError::new(codes::NOT_STORED, 404, format!("no {kind} is stored"))
        .titled("Not found")
        .param("kind", kind)
}

fn mismatch(expected: Revision, actual: Option<Revision>) -> IpamError {
    IpamError::new(
        REVISION_MISMATCH,
        412,
        format!(
            "the decision changed since revision {}; it is at {}",
            expected.0,
            actual.map_or_else(|| "none".to_owned(), |r| r.0.to_string())
        ),
    )
    .titled("Precondition failed")
    .param("expected", expected.0.to_string())
}

/// Checks an `If-Match` revision against the stored row's.
fn check(if_match: Option<Revision>, current: Option<Revision>) -> IpamResult<()> {
    match if_match {
        Some(expected) if current != Some(expected) => Err(mismatch(expected, current)),
        _ => Ok(()),
    }
}

/// An SSID as a request gives it: 1 to 32 octets, no control characters.
///
/// # Errors
///
/// 422 `ipam.topology.invalid`.
pub fn valid_ssid(ssid: &str) -> IpamResult<&str> {
    if ssid.is_empty() || ssid.len() > MAX_SSID_BYTES {
        return Err(invalid("ssid", "an SSID has 1 to 32 octets"));
    }
    if ssid.chars().any(char::is_control) {
        return Err(invalid("ssid", "an SSID has no control characters"));
    }
    Ok(ssid)
}

fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

fn audit(cx: &RequestCtx, action: &'static str, objects: Vec<ObjectRef>) -> AuditDraft {
    AuditDraft::success(AuditAction::from_static(action), objects).with_source_ip(cx.source_ip)
}

fn change(field: &str, old: Option<String>, new: Option<String>) -> FieldChange {
    FieldChange {
        object: None,
        field: field.to_owned(),
        old,
        new,
    }
}

/// Stores the chosen root; audited as `ipam.topology_root.choose` with the old and the new
/// source and the candidate it names (`label`).
///
/// # Errors
///
/// 412 `ipam.revision_mismatch` when `if_match` is not the stored row's revision, store
/// errors.
pub async fn choose_root(
    store: &dyn Store,
    cx: &RequestCtx,
    source: RootSource,
    offered: Vec<String>,
    label: &str,
    if_match: Option<Revision>,
) -> IpamResult<RootChoice> {
    let view = store.read(ReadConsistency::Linearizable).await?;
    let current = view.get_typed(&ROOT_CHOICE, &())?;
    drop(view);
    check(if_match, current.as_ref().map(|(_, revision)| *revision))?;
    let mut row = RootChoice {
        source,
        offered,
        decided: Stamp::new(cx.now, cx.principal.clone()),
        revision: Revision::ZERO,
    };
    let mut batch = WriteBatch::for_request(cx);
    batch.put_typed(&ROOT_CHOICE, &(), &row)?;
    batch.expect_typed(
        &ROOT_CHOICE,
        &(),
        current.as_ref().map(|(_, revision)| *revision),
    );
    batch.audit(
        audit(cx, actions::ROOT_CHOOSE, vec![system_object()])
            .with_change(change(
                "source",
                current.map(|(old, _)| old.source.as_str().to_owned()),
                Some(source.as_str().to_owned()),
            ))
            .with_change(change("root", None, Some(label.to_owned()))),
    );
    row.revision = store.propose(batch).await?.revision;
    Ok(row)
}

/// Forgets the chosen root, so the ranked sources decide again; audited as
/// `ipam.topology_root.clear`.
///
/// # Errors
///
/// 404 `ipam.topology.not_stored` without a chosen root, 412, store errors.
pub async fn clear_root(
    store: &dyn Store,
    cx: &RequestCtx,
    if_match: Option<Revision>,
) -> IpamResult<()> {
    let view = store.read(ReadConsistency::Linearizable).await?;
    let Some((old, revision)) = view.get_typed(&ROOT_CHOICE, &())? else {
        return Err(not_stored("root choice"));
    };
    drop(view);
    check(if_match, Some(revision))?;
    let mut batch = WriteBatch::for_request(cx);
    batch.delete_typed(&ROOT_CHOICE, &());
    batch.expect_typed(&ROOT_CHOICE, &(), Some(revision));
    batch.audit(
        audit(cx, actions::ROOT_CLEAR, vec![system_object()]).with_change(change(
            "source",
            Some(old.source.as_str().to_owned()),
            None,
        )),
    );
    store.propose(batch).await?;
    Ok(())
}

/// Sets the policy of an SSID; audited as `ipam.wlan_policy.set` with the old and the new
/// policy. Setting the policy the SSID has changes nothing.
///
/// # Errors
///
/// 422 for a bad SSID, 412, store errors.
pub async fn set_policy(
    store: &dyn Store,
    cx: &RequestCtx,
    ssid: &str,
    policy: WlanPolicy,
    if_match: Option<Revision>,
) -> IpamResult<StoredWlanPolicy> {
    let ssid = valid_ssid(ssid)?.to_owned();
    let view = store.read(ReadConsistency::Linearizable).await?;
    let current = view.get_typed(&WLAN_POLICIES, &ssid)?;
    drop(view);
    check(if_match, current.as_ref().map(|(_, revision)| *revision))?;
    if let Some((row, revision)) = &current
        && row.policy == policy
    {
        let mut row = row.clone();
        row.revision = *revision;
        return Ok(row);
    }
    let mut row = StoredWlanPolicy {
        ssid: ssid.clone(),
        policy,
        updated: Stamp::new(cx.now, cx.principal.clone()),
        revision: Revision::ZERO,
    };
    let mut batch = WriteBatch::for_request(cx);
    batch.put_typed(&WLAN_POLICIES, &ssid, &row)?;
    batch.expect_typed(
        &WLAN_POLICIES,
        &ssid,
        current.as_ref().map(|(_, revision)| *revision),
    );
    batch.audit(
        audit(cx, actions::POLICY_SET, vec![system_object()])
            .with_change(change("ssid", None, Some(ssid.clone())))
            .with_change(change(
                "policy",
                current.map(|(old, _)| old.policy.as_str().to_owned()),
                Some(policy.as_str().to_owned()),
            )),
    );
    row.revision = store.propose(batch).await?.revision;
    Ok(row)
}

/// Removes the policy of an SSID, so its default applies again (ignore for a guest SSID,
/// track otherwise); audited as `ipam.wlan_policy.clear`.
///
/// # Errors
///
/// 404 `ipam.topology.not_stored`, 412, store errors.
pub async fn clear_policy(
    store: &dyn Store,
    cx: &RequestCtx,
    ssid: &str,
    if_match: Option<Revision>,
) -> IpamResult<()> {
    let ssid = valid_ssid(ssid)?.to_owned();
    let view = store.read(ReadConsistency::Linearizable).await?;
    let Some((old, revision)) = view.get_typed(&WLAN_POLICIES, &ssid)? else {
        return Err(not_stored("WLAN policy"));
    };
    drop(view);
    check(if_match, Some(revision))?;
    let mut batch = WriteBatch::for_request(cx);
    batch.delete_typed(&WLAN_POLICIES, &ssid);
    batch.expect_typed(&WLAN_POLICIES, &ssid, Some(revision));
    batch.audit(
        audit(cx, actions::POLICY_CLEAR, vec![system_object()])
            .with_change(change("ssid", Some(ssid.clone()), None))
            .with_change(change("policy", Some(old.policy.as_str().to_owned()), None)),
    );
    store.propose(batch).await?;
    Ok(())
}

/// "Keep on this WLAN": stores the exception of `host` on `ssid`, so the WLAN rules skip the
/// pair; audited as `ipam.wlan_exception.keep` on the host with the SSID and the reason.
/// Keeping a pair that is kept changes nothing.
///
/// # Errors
///
/// 422 for a bad SSID or reason, 404 `ipam.not_found` for a host that does not exist, 412,
/// store errors.
pub async fn keep(
    store: &dyn Store,
    cx: &RequestCtx,
    host: HostId,
    ssid: &str,
    reason: Option<String>,
    if_match: Option<Revision>,
) -> IpamResult<WlanException> {
    let ssid = valid_ssid(ssid)?.to_owned();
    let reason = reason
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty());
    if let Some(text) = &reason
        && (text.len() > MAX_REASON_BYTES
            || text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'))
    {
        return Err(invalid(
            "reason",
            "a reason has at most 1,024 bytes and no control characters",
        ));
    }
    let view = store.read(ReadConsistency::Linearizable).await?;
    match view.get_typed(&HOSTS, &host)? {
        Some((record, _)) if !record.meta.is_deleted() => {}
        _ => {
            return Err(IpamError::new(
                crate::error::codes::NOT_FOUND,
                404,
                format!("host {host} does not exist"),
            )
            .titled("Not found")
            .param("kind", "host")
            .param("id", host.to_string()));
        }
    }
    let key = (host, ssid.clone());
    let current = view.get_typed(&WLAN_EXCEPTIONS, &key)?;
    drop(view);
    check(if_match, current.as_ref().map(|(_, revision)| *revision))?;
    if let Some((row, revision)) = &current
        && row.reason == reason
    {
        let mut row = row.clone();
        row.revision = *revision;
        return Ok(row);
    }
    let mut row = WlanException {
        host,
        ssid: ssid.clone(),
        reason: reason.clone(),
        decided: Stamp::new(cx.now, cx.principal.clone()),
        revision: Revision::ZERO,
    };
    let mut batch = WriteBatch::for_request(cx);
    batch.put_typed(&WLAN_EXCEPTIONS, &key, &row)?;
    batch.expect_typed(
        &WLAN_EXCEPTIONS,
        &key,
        current.as_ref().map(|(_, revision)| *revision),
    );
    let mut draft = audit(cx, actions::EXCEPTION_KEEP, vec![ObjectRef::from(host)])
        .with_change(change("ssid", None, Some(ssid)));
    if let Some(reason) = reason {
        draft = draft.with_change(change("reason", None, Some(reason)));
    }
    batch.audit(draft);
    row.revision = store.propose(batch).await?.revision;
    Ok(row)
}

/// Removes the exception of `host` on `ssid`, so the WLAN rules read the pair again;
/// audited as `ipam.wlan_exception.clear` on the host.
///
/// # Errors
///
/// 404 `ipam.topology.not_stored`, 412, store errors.
pub async fn forget(
    store: &dyn Store,
    cx: &RequestCtx,
    host: HostId,
    ssid: &str,
    if_match: Option<Revision>,
) -> IpamResult<()> {
    let ssid = valid_ssid(ssid)?.to_owned();
    let key = (host, ssid.clone());
    let view = store.read(ReadConsistency::Linearizable).await?;
    let Some((_, revision)) = view.get_typed(&WLAN_EXCEPTIONS, &key)? else {
        return Err(not_stored("WLAN exception"));
    };
    drop(view);
    check(if_match, Some(revision))?;
    let mut batch = WriteBatch::for_request(cx);
    batch.delete_typed(&WLAN_EXCEPTIONS, &key);
    batch.expect_typed(&WLAN_EXCEPTIONS, &key, Some(revision));
    batch.audit(
        audit(cx, actions::EXCEPTION_CLEAR, vec![ObjectRef::from(host)]).with_change(change(
            "ssid",
            Some(ssid),
            None,
        )),
    );
    store.propose(batch).await?;
    Ok(())
}
