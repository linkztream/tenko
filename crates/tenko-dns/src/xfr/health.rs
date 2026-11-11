//! The health findings of the transfer and update settings (TGL-10, DNS-09): what
//! `GET /system/status` warns about, computed from the zones and access lists at the time
//! of the request under the security profile in force.
//!
//! | Code | When |
//! |---|---|
//! | `dns.transfer.profile_refuses` | Hardened: the profile refuses what the zone's own settings would allow. Transfers without TSIG (`require_tsig` off), transfers over plain TCP to addresses outside the site (`xot` off and an access list admits such addresses), or a NOTIFY from a primary without a TSIG key (the zone is refreshed on its timers) |
//! | `dns.transfer.weaker_than_profile` | Home, Standard and Lab: a zone transfers without TSIG (`require_tsig` off) although its lists allow transfers. Information: the zone's setting applies, and the Hardened profile would refuse those transfers |
//! | `dns.acl.deny_wins` | A `deny` entry of one of a zone's transfer or update access lists overrides an allowing entry of another list of the same zone: a client both match was let in before "deny wins" and is refused now. A warning: the operator looks once. It stands while such an overlap exists; there is no acknowledgment, so it goes when the lists no longer hold an allow that a deny overrides |
//!
//! Every finding names the zone; the access-list finding also names the field
//! (`transfer` or `update`), the deny entry and its list, and the allowing entry and its
//! list (the first overlap; the text names up to five).

use std::collections::BTreeMap;

use tenko_core::dns::{
    self, Acl, AclEntry, Zone, ZoneKind,
    tables::{ACLS, ZONES},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::access;
use crate::{update::policy::UpdateProfile, zone::ZoneResult};

/// Hardened refuses what the zone's settings would allow.
pub const PROFILE_REFUSES: &str = "dns.transfer.profile_refuses";

/// A zone transfers without TSIG under a profile that lets it (information).
pub const WEAKER_THAN_PROFILE: &str = "dns.transfer.weaker_than_profile";

/// A deny in one access list overrides another list's allow.
pub const DENY_WINS: &str = "dns.acl.deny_wins";

/// One finding, naming the zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code.
    pub code: &'static str,
    /// What is wrong and what to do, in English.
    pub detail: String,
    /// The zone and the figures.
    pub params: BTreeMap<String, String>,
}

fn finding(code: &'static str, zone: &Zone, detail: String, extra: &[(&str, String)]) -> Finding {
    let mut params = BTreeMap::from([("zone".to_owned(), zone.name.to_string())]);
    for (key, value) in extra {
        params.insert((*key).to_owned(), value.clone());
    }
    Finding {
        code,
        detail,
        params,
    }
}

/// Whether an allowing entry of `lists` can admit a client outside the site: `any`, a key
/// (it matches from every address), or a prefix not wholly inside the site.
fn admits_off_site(lists: &[&Acl], site: &access::Site) -> bool {
    lists.iter().any(|list| {
        list.entries.iter().any(|entry| match entry {
            AclEntry::Any { deny } | AclEntry::Key { deny, .. } => !deny,
            AclEntry::Prefix { prefix, deny } => !deny && !site.contains_network(prefix),
            AclEntry::Kerberos { .. } => false,
        })
    })
}

/// An entry as an operator reads it.
fn entry_text(entry: &AclEntry) -> String {
    match entry {
        AclEntry::Prefix { prefix, .. } => prefix.to_string(),
        AclEntry::Key { name, .. } => format!("key {name}"),
        AclEntry::Any { .. } => "any".to_owned(),
        AclEntry::Kerberos {
            realm,
            principal,
            from,
            ..
        } => {
            use std::fmt::Write as _;
            let mut text = format!("kerberos {}", realm.as_str());
            if let Some(pattern) = principal {
                let _ = write!(text, " {pattern}");
            }
            if let Some(from) = from {
                let _ = write!(text, " from {from}");
            }
            text
        }
    }
}

fn is_deny(entry: &AclEntry) -> bool {
    match entry {
        AclEntry::Prefix { deny, .. }
        | AclEntry::Key { deny, .. }
        | AclEntry::Any { deny }
        | AclEntry::Kerberos { deny, .. } => *deny,
    }
}

fn nets_overlap(a: &ipnet::IpNet, b: &ipnet::IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

/// Whether some request matches both entries.
fn overlap(a: &AclEntry, b: &AclEntry) -> bool {
    use AclEntry::{Any, Kerberos, Key, Prefix};
    match (a, b) {
        (Any { .. }, _)
        | (_, Any { .. })
        | (Prefix { .. }, Key { .. })
        | (Key { .. }, Prefix { .. }) => true,
        (Prefix { prefix: x, .. }, Prefix { prefix: y, .. }) => nets_overlap(x, y),
        (Key { name: x, .. }, Key { name: y, .. }) => x == y,
        (Key { .. }, Kerberos { .. }) | (Kerberos { .. }, Key { .. }) => false,
        (Prefix { prefix, .. }, Kerberos { from, .. })
        | (Kerberos { from, .. }, Prefix { prefix, .. }) => {
            from.as_ref().is_none_or(|from| nets_overlap(prefix, from))
        }
        (
            Kerberos {
                realm: r1,
                from: f1,
                ..
            },
            Kerberos {
                realm: r2,
                from: f2,
                ..
            },
        ) => {
            r1 == r2
                && match (f1, f2) {
                    (Some(x), Some(y)) => nets_overlap(x, y),
                    _ => true,
                }
        }
    }
}

/// Whether `earlier` matches every request `entry` matches, so that `entry` never decides.
fn covers(earlier: &AclEntry, entry: &AclEntry) -> bool {
    use AclEntry::{Any, Kerberos, Key, Prefix};
    match (earlier, entry) {
        (Any { .. }, _) => true,
        (Prefix { prefix: x, .. }, Prefix { prefix: y, .. }) => x.contains(y),
        (Key { name: x, .. }, Key { name: y, .. }) => x == y,
        (
            Kerberos {
                realm: r1,
                principal: None,
                from: None,
                ..
            },
            Kerberos { realm: r2, .. },
        ) => r1 == r2,
        _ => false,
    }
}

/// The entries of `list` that can decide a request: no earlier entry matches all of its.
fn reachable(list: &Acl) -> impl Iterator<Item = &AclEntry> {
    list.entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (!list.entries[..index]
                .iter()
                .any(|earlier| covers(earlier, entry)))
            .then_some(entry)
        })
}

/// One deny entry that overrides an allowing entry of another list.
struct Overlap<'a> {
    deny_list: &'a Acl,
    deny: &'a AclEntry,
    allow_list: &'a Acl,
    allow: &'a AclEntry,
}

/// The deny entries of `lists` that override an allowing entry of another of the lists:
/// the requests both match were allowed when one allowing list was enough, and are refused
/// with "deny wins".
fn overlaps<'a>(lists: &[&'a Acl], kerberos: bool) -> Vec<Overlap<'a>> {
    let mut out = Vec::new();
    let counts = |entry: &&AclEntry| kerberos || !matches!(entry, AclEntry::Kerberos { .. });
    for (index, deny_list) in lists.iter().enumerate() {
        for deny in reachable(deny_list)
            .filter(|entry| is_deny(entry))
            .filter(counts)
        {
            for (other, allow_list) in lists.iter().enumerate() {
                if other == index || allow_list.id == deny_list.id {
                    continue;
                }
                for allow in reachable(allow_list)
                    .filter(|entry| !is_deny(entry))
                    .filter(counts)
                {
                    if overlap(deny, allow) {
                        out.push(Overlap {
                            deny_list,
                            deny,
                            allow_list,
                            allow,
                        });
                    }
                }
            }
        }
    }
    out
}

/// The findings of one zone under `profile` and the site `site`; `acl` finds an access
/// list by id.
pub fn findings<'a>(
    zone: &Zone,
    acl: impl Fn(dns::AclId) -> Option<&'a Acl>,
    profile: UpdateProfile,
    site: &access::Site,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let profile_name = profile.name();
    let transfer: Vec<&Acl> = zone
        .transfer
        .allow
        .iter()
        .filter_map(|id| acl(*id))
        .collect();
    let transfers = !zone.transfer.allow.is_empty()
        && matches!(zone.kind, ZoneKind::Primary | ZoneKind::Secondary);
    if transfers {
        let rules = access::effective(zone, profile);
        if rules.tsig == access::Rule::Profile {
            out.push(finding(
                PROFILE_REFUSES,
                zone,
                format!(
                    "{} has \"require TSIG\" off, but the Hardened profile refuses every zone transfer without a TSIG key: sign the secondaries' transfers with a key an access list of the zone names",
                    zone.name
                ),
                &[("profile", profile_name.to_owned()), ("rule", "tsig".to_owned())],
            ));
        } else if !zone.transfer.require_tsig {
            out.push(finding(
                WEAKER_THAN_PROFILE,
                zone,
                format!(
                    "{} transfers without a TSIG key; the {profile_name} profile allows it and the zone's setting applies (the Hardened profile would refuse these transfers)",
                    zone.name
                ),
                &[("profile", profile_name.to_owned()), ("rule", "tsig".to_owned())],
            ));
        }
        if rules.xot == access::Rule::Profile && admits_off_site(&transfer, site) {
            out.push(finding(
                PROFILE_REFUSES,
                zone,
                format!(
                    "the access lists of {} admit addresses outside the site, and the Hardened profile refuses a transfer to them over plain TCP: configure those secondaries for XoT on the DoT port, or switch XoT on for the zone",
                    zone.name
                ),
                &[("profile", profile_name.to_owned()), ("rule", "xot".to_owned())],
            ));
        }
    }
    if zone.kind == ZoneKind::Secondary
        && profile == UpdateProfile::Hardened
        && let Some(source) = &zone.source
    {
        for primary in source
            .primaries
            .iter()
            .filter(|primary| primary.key.is_none())
        {
            out.push(finding(
                PROFILE_REFUSES,
                zone,
                format!(
                    "the primary {} of {} has no TSIG key, and the Hardened profile refuses its unsigned NOTIFY messages: the zone is refreshed on its SOA timers only; give the primary a key",
                    primary.address, zone.name
                ),
                &[
                    ("profile", profile_name.to_owned()),
                    ("rule", "notify".to_owned()),
                    ("primary", primary.address.to_string()),
                ],
            ));
        }
    }
    let update: Vec<&Acl> = zone
        .update
        .allowed
        .iter()
        .filter_map(|id| acl(*id))
        .collect();
    for (field, lists) in [("transfer", &transfer), ("update", &update)] {
        out.extend(deny_wins(zone, field, lists));
    }
    out
}

/// The finding of a zone's `field` lists where a deny of one list overrides an allow of
/// another, naming the first overlap and up to five in its text.
fn deny_wins(zone: &Zone, field: &str, lists: &[&Acl]) -> Option<Finding> {
    // A Kerberos entry matches only a request signed with GSS-TSIG: an update, never a
    // transfer.
    let found = overlaps(lists, field == "update");
    let first = found.first()?;
    let pairs: Vec<String> = found
        .iter()
        .take(5)
        .map(|pair| {
            format!(
                "the deny {} of the list {} overrides the allow {} of the list {}",
                entry_text(pair.deny),
                pair.deny_list.name,
                entry_text(pair.allow),
                pair.allow_list.name
            )
        })
        .collect();
    let more = found.len().saturating_sub(pairs.len());
    let more = if more > 0 {
        format!(" (and {more} more)")
    } else {
        String::new()
    };
    Some(finding(
        DENY_WINS,
        zone,
        format!(
            "in the {field} access lists of {}, {}{more}: a client both entries match was allowed before this version and is refused now, because a deny in any list wins. Check that this is meant; the finding stands while a deny of one list overrides an allow of another, so remove the overlap (narrow the allow, or move the deny into the allowing list ahead of it) to clear it",
            zone.name,
            pairs.join("; ")
        ),
        &[
            ("field", field.to_owned()),
            ("deny_list", first.deny_list.name.clone()),
            ("deny_entry", entry_text(first.deny)),
            ("allow_list", first.allow_list.name.clone()),
            ("allow_entry", entry_text(first.allow)),
            ("overlaps", found.len().to_string()),
        ],
    ))
}

/// The findings of every zone of `view` under `profile` and the site `site`.
///
/// # Errors
///
/// The store's error.
pub fn all(
    view: &dyn ReadView,
    profile: UpdateProfile,
    site: &access::Site,
) -> ZoneResult<Vec<Finding>> {
    let acls: BTreeMap<dns::AclId, Acl> = view
        .scan_typed(&ACLS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(id, acl, _)| (id, acl))
        .collect();
    let mut out = Vec::new();
    for (_, zone, _) in view.scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)? {
        out.extend(findings(&zone, |id| acls.get(&id), profile, site));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
