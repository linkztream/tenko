//! Adoption policies (IPAM-15 "auto-adopt in network Z"): per prefix, inherited down the
//! prefix tree, deciding which proposals the reconciler applies without a person.
//!
//! The effective policy of a prefix is its own, else the one of the nearest prefix that
//! contains it and has one, else `manual`. A policy adopts:
//!
//! - `adopt_hosts`: discovered hosts with a MAC address;
//! - `adopt_all`: discovered hosts with or without a MAC address, and the address changes
//!   of `dynamic` hosts (where IPAM only observes).
//!
//! Its constraints all have to hold: `only_dhcp_pools` (every address the commands create,
//! bind or renumber to lies in a DHCP pool of its network), `vendors` (the MAC address
//! starts with a listed OUI, or a source reports a matching vendor), `min_sightings` (one
//! source counted that many sightings). Never adopted: conflicts, orphaned intent,
//! outside-prefix proposals, changes of `static` or `reserved` hosts (intent wins), and
//! anything that touches a locked or `unmanaged` host; the planner refuses a locked host
//! to the reconciler anyway (IPAM-16).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    MacAddr, ObjectKind, ObjectRef, PrefixId, RequestCtx, Revision,
    audit::{AuditAction, AuditDraft, FieldChange},
    ipam::{AssignmentMode, Prefix, Stamp},
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use utoipa::ToSchema;

use super::{
    decide::run_write,
    model::{
        ADOPTION, AdoptionMode, AdoptionPolicy, IntentProposal, IntentProposalKind, StoredPolicy,
        actions, codes,
    },
};
use crate::{
    command::IpamCommand,
    error::{IpamError, IpamResult},
    net::contains_net,
    reconcile::snapshot::Intent,
    service::IpamService,
    tables::PREFIXES,
};

/// Most vendor entries of a policy.
pub const MAX_VENDORS: usize = 32;
/// Longest vendor entry.
pub const MAX_VENDOR_LEN: usize = 64;
/// Largest `min_sightings`.
pub const MAX_SIGHTINGS: u32 = 1_000;

fn invalid(field: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::POLICY_INVALID, 400, detail)
        .titled("Invalid adoption policy")
        .param("field", field)
        .field(field, codes::POLICY_INVALID)
}

/// Checks a policy: 1 to 1,000 sightings, at most 32 vendor entries of 1 to 64
/// characters without control characters.
///
/// # Errors
///
/// `ipam.adoption.invalid` (400) naming the field.
pub fn validate(policy: &AdoptionPolicy) -> IpamResult<()> {
    if !(1..=MAX_SIGHTINGS).contains(&policy.min_sightings) {
        return Err(invalid(
            "min_sightings",
            format!("min_sightings is 1 to {MAX_SIGHTINGS}"),
        ));
    }
    if policy.vendors.len() > MAX_VENDORS {
        return Err(invalid(
            "vendors",
            format!("at most {MAX_VENDORS} vendor entries"),
        ));
    }
    for vendor in &policy.vendors {
        let trimmed = vendor.trim();
        if trimmed.is_empty()
            || trimmed.len() > MAX_VENDOR_LEN
            || trimmed.chars().any(char::is_control)
        {
            return Err(invalid(
                "vendors",
                format!(
                    "a vendor entry has 1 to {MAX_VENDOR_LEN} characters without control characters"
                ),
            ));
        }
    }
    Ok(())
}

/// The OUI an entry names (`00:00:5e`, `00-00-5E`, `00005e`), if it is one.
fn oui(entry: &str) -> Option<[u8; 3]> {
    let hex: String = entry
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 3];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Whether the vendor constraint holds for a device: no entries, or an OUI entry the MAC
/// address starts with, or a text entry contained (ignoring case) in a vendor that a source
/// reports for the device (`vendors`: the vendor facts of probes, network controllers and
/// inventories).
pub fn vendor_matches(policy: &AdoptionPolicy, mac: Option<MacAddr>, vendors: &[&str]) -> bool {
    if policy.vendors.is_empty() {
        return true;
    }
    policy.vendors.iter().any(|entry| {
        if let Some(prefix) = oui(entry) {
            return mac.is_some_and(|mac| mac.octets()[..3] == prefix);
        }
        let entry = entry.trim().to_lowercase();
        vendors
            .iter()
            .any(|vendor| vendor.to_lowercase().contains(&entry))
    })
}

/// The effective policy of a prefix and the prefix it comes from (`None`: the default,
/// `manual`).
pub(crate) fn effective(
    intent: &Intent,
    policies: &BTreeMap<PrefixId, StoredPolicy>,
    prefix: PrefixId,
) -> (AdoptionPolicy, Option<PrefixId>) {
    for candidate in intent.self_and_ancestors(prefix) {
        if let Some(stored) = policies.get(&candidate) {
            return (stored.policy.clone(), Some(candidate));
        }
    }
    (AdoptionPolicy::default(), None)
}

/// The addresses a proposal's commands create, bind or renumber to, with their VRF.
fn target_addresses(intent: &Intent, commands: &[IpamCommand]) -> Vec<(tenko_core::VrfId, IpAddr)> {
    let mut out = Vec::new();
    for command in commands {
        match command {
            IpamCommand::CreateAddress(input) => {
                if let Some(vrf) = input.vrf {
                    out.push((vrf, input.ip));
                }
            }
            IpamCommand::UpdateAddress(update) => {
                if let Some(address) = intent.addresses.get(&update.id) {
                    out.push((address.vrf, update.patch.ip.unwrap_or(address.ip)));
                }
            }
            _ => {}
        }
    }
    out
}

/// The policy that adopts `proposal`, if one does: its source prefix and the host mode.
pub(crate) fn adopter(
    intent: &Intent,
    policies: &BTreeMap<PrefixId, StoredPolicy>,
    vendors: &BTreeMap<MacAddr, BTreeSet<String>>,
    proposal: &IntentProposal,
) -> Option<(PrefixId, AssignmentMode)> {
    if !proposal.is_open() || proposal.adoption_error.is_some() || proposal.commands.is_empty() {
        return None;
    }
    let prefix = proposal.subject.prefix?;
    let (policy, source) = effective(intent, policies, prefix);
    let source = source?;
    let allowed = match (proposal.kind, policy.mode) {
        (IntentProposalKind::DiscoveredHost, AdoptionMode::AdoptHosts) => {
            proposal.subject.mac.is_some()
        }
        (IntentProposalKind::DiscoveredHost, AdoptionMode::AdoptAll) => true,
        (IntentProposalKind::AddressMismatch, AdoptionMode::AdoptAll) => {
            let hosts: Vec<_> = proposal
                .subject
                .objects
                .iter()
                .filter(|object| object.kind == ObjectKind::Host)
                .filter_map(|object| intent.hosts.get(&object.id.into()))
                .collect();
            !hosts.is_empty()
                && hosts
                    .iter()
                    .all(|host| host.mode == AssignmentMode::Dynamic && !host.lock)
        }
        _ => false,
    };
    if !allowed {
        return None;
    }
    // Nothing that touches a locked or unmanaged host.
    let touches_protected = proposal.subject.objects.iter().any(|object| {
        object.kind == ObjectKind::Host
            && intent
                .hosts
                .get(&object.id.into())
                .is_some_and(|host| host.lock || host.mode == AssignmentMode::Unmanaged)
    });
    if touches_protected {
        return None;
    }
    if policy.only_dhcp_pools {
        let targets = target_addresses(intent, &proposal.commands);
        let in_pools = !targets.is_empty()
            && targets.iter().all(|(vrf, ip)| {
                intent
                    .network_of(*vrf, *ip)
                    .is_some_and(|network| intent.in_dhcp_pool(network.id, *ip))
            });
        if !in_pools {
            return None;
        }
    }
    let reported: Vec<&str> = proposal
        .subject
        .mac
        .and_then(|mac| vendors.get(&mac))
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect();
    if !vendor_matches(&policy, proposal.subject.mac, &reported) {
        return None;
    }
    if proposal.sightings() < policy.min_sightings {
        return None;
    }
    Some((source, policy.host_mode))
}

/// The adoption policy of one prefix as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PolicyView {
    /// The prefix.
    pub prefix: PrefixId,
    /// Its own policy; `null` when it inherits.
    pub policy: Option<AdoptionPolicy>,
    /// Who set its own policy and when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Stamp>,
    /// The policy in force: its own, an inherited one, or the default (`manual`).
    pub effective: AdoptionPolicy,
    /// The prefix the policy in force comes from; `null` for the default.
    pub source: Option<PrefixId>,
    /// The revision of its own policy (`ETag`, `If-Match`); 0 without one.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The live prefix, or `ipam.not_found` / `ipam.object_deleted`.
fn live_prefix(view: &dyn ReadView, prefix: PrefixId) -> IpamResult<Prefix> {
    let (found, _) = view
        .get_typed(&PREFIXES, &prefix)?
        .ok_or_else(|| IpamError::not_found(ObjectRef::from(prefix)))?;
    if found.meta.is_deleted() {
        return Err(IpamError::deleted(ObjectRef::from(prefix)));
    }
    Ok(found)
}

/// The policy view of a prefix.
///
/// # Errors
///
/// `ipam.not_found` (404) for a missing prefix, `ipam.object_deleted` (409) for a
/// deleted one, store and decoding errors.
pub fn policy_view(view: &dyn ReadView, prefix: PrefixId) -> IpamResult<PolicyView> {
    let start = live_prefix(view, prefix)?;
    let mut chain: Vec<Prefix> = view
        .scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, other, _)| other)
        .filter(|other: &Prefix| {
            !other.meta.is_deleted()
                && other.vrf == start.vrf
                && contains_net(&other.cidr, &start.cidr)
        })
        .collect();
    chain.sort_by_key(|other| std::cmp::Reverse(other.cidr.prefix_len()));
    let own = view.get_typed(&ADOPTION, &prefix)?;
    let mut effective = (AdoptionPolicy::default(), None);
    for other in &chain {
        if let Some((stored, _)) = view.get_typed(&ADOPTION, &other.id)? {
            effective = (stored.policy, Some(other.id));
            break;
        }
    }
    Ok(PolicyView {
        prefix,
        policy: own.as_ref().map(|(stored, _)| stored.policy.clone()),
        updated: own.as_ref().map(|(stored, _)| stored.updated.clone()),
        effective: effective.0,
        source: effective.1,
        revision: own.map(|(_, revision)| revision).unwrap_or_default(),
    })
}

fn describe(policy: &AdoptionPolicy) -> String {
    serde_json::to_string(policy).unwrap_or_default()
}

/// Sets (`Some`) or removes (`None`, the prefix inherits again) the policy of a prefix as
/// `cx`, in an inline job; `expected` is the revision of the policy the caller read (0:
/// it had none).
///
/// # Errors
///
/// `ipam.adoption.invalid` (400), `ipam.not_found` (404), `ipam.object_deleted` (409),
/// `ipam.revision_mismatch` (412), `ipam.contended`.
pub async fn set_policy(
    ipam: &IpamService,
    prefix: PrefixId,
    policy: Option<AdoptionPolicy>,
    cx: &RequestCtx,
    expected: Option<Revision>,
) -> IpamResult<PolicyView> {
    if let Some(policy) = &policy {
        validate(policy)?;
    }
    let attempts = ipam.config().max_attempts.max(1);
    for attempt in 0..attempts {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = ipam.store().read(consistency).await?;
        live_prefix(view.as_ref(), prefix)?;
        let current = view.get_typed(&ADOPTION, &prefix)?;
        let actual = current
            .as_ref()
            .map(|(_, revision)| *revision)
            .unwrap_or_default();
        if let Some(expected) = expected
            && expected != actual
        {
            return Err(IpamError::revision_mismatch(
                ObjectRef::from(prefix),
                expected,
                actual,
            ));
        }
        let before = current.as_ref().map(|(stored, _)| stored.policy.clone());
        if before == policy {
            return policy_view(view.as_ref(), prefix);
        }
        let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
        batch.request = Some(cx.request);
        let action = if let Some(policy) = &policy {
            batch.put_typed(
                &ADOPTION,
                &prefix,
                &StoredPolicy {
                    prefix,
                    policy: policy.clone(),
                    updated: Stamp::new(cx.now, cx.principal.clone()),
                    revision: Revision::ZERO,
                },
            )?;
            actions::POLICY_SET
        } else {
            batch.delete_typed(&ADOPTION, &prefix);
            actions::POLICY_CLEAR
        };
        batch.expect_typed(&ADOPTION, &prefix, current.as_ref().map(|(_, r)| *r));
        batch.audit(
            AuditDraft::success(
                AuditAction::from_static(action),
                vec![ObjectRef::from(prefix)],
            )
            .with_source_ip(cx.source_ip)
            .with_change(FieldChange {
                object: None,
                field: "adoption".to_owned(),
                old: before.as_ref().map(describe),
                new: policy.as_ref().map(describe),
            }),
        );
        drop(view);
        let summary = vec![match &policy {
            Some(_) => "1 adoption policy set".to_owned(),
            None => "1 adoption policy removed".to_owned(),
        }];
        match run_write(ipam, batch, summary, vec![ObjectRef::from(prefix)], cx).await {
            Ok((revision, _)) => {
                let view = ipam.view(Some(revision)).await?;
                return policy_view(view.as_ref(), prefix);
            }
            Err(error) if error.is(crate::codes::PLAN_STALE) => {
                tracing::debug!(attempt, %prefix, "adoption policy write stale; retrying");
            }
            Err(error) => return Err(error),
        }
    }
    Err(IpamError::contended(attempts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendors_match_by_oui_or_text() {
        let policy = AdoptionPolicy {
            vendors: vec!["00-00-5E".to_owned(), "Example Devices".to_owned()],
            ..AdoptionPolicy::default()
        };
        let mac: MacAddr = "00:00:5e:00:53:01".parse().expect("mac");
        let other: MacAddr = "02:00:5e:00:53:01".parse().expect("mac");
        assert!(vendor_matches(&policy, Some(mac), &[]));
        assert!(!vendor_matches(&policy, Some(other), &[]));
        assert!(vendor_matches(
            &policy,
            Some(other),
            &["Other Corp", "example devices inc."]
        ));
        assert!(!vendor_matches(&policy, Some(other), &["Other Corp"]));
        assert!(vendor_matches(&AdoptionPolicy::default(), None, &[]));
    }

    #[test]
    fn policies_are_validated() {
        assert!(validate(&AdoptionPolicy::default()).is_ok());
        let zero = AdoptionPolicy {
            min_sightings: 0,
            ..AdoptionPolicy::default()
        };
        assert_eq!(
            validate(&zero).expect_err("zero").code_str(),
            codes::POLICY_INVALID
        );
        let long = AdoptionPolicy {
            vendors: vec!["x".repeat(65)],
            ..AdoptionPolicy::default()
        };
        assert!(validate(&long).is_err());
    }
}
