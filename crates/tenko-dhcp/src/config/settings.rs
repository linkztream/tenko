//! The server settings (`dhcp.settings`, one row): the lease times of scopes that set none,
//! authority, the DDNS settings new scopes start from, conflict detection (TGL-16), the
//! lease history retention (P3-Q13) and the trusted relays ([`crate::relay`]). Before the
//! first write the defaults apply and the row reads at revision 0.

use tenko_core::{
    RequestCtx, Revision,
    audit::AuditDraft,
    dhcp::{
        DdnsPolicy, DhcpError, DhcpSettings, LeaseTimes, TrustedRelay, audit, codes, server_object,
        tables::SETTINGS,
    },
};
use tenko_store::{ReadView, ReadViewExt, WriteBatch};

use super::{ConfigResult, ConfigService, Planned, Written, check_expect, stamp};

/// The settings as read, with the revision of the row (0 before the first write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRow {
    /// The settings.
    pub settings: DhcpSettings,
    /// The revision of the row.
    pub revision: Revision,
}

/// What the security profile makes of the unset settings (plan section 2.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileDefaults {
    /// Conflict detection (TGL-16): on except under Lab.
    pub conflict_detection: bool,
    /// The lease history retention in days (P3-Q13): 30 under Home, 90 under Standard and
    /// Hardened, 7 under Lab.
    pub history_days: u32,
    /// Whether an unset list of trusted relays trusts every sender: under Lab only.
    pub trust_any_relay: bool,
    /// The limits per client and per scope of the profile ([`crate::limits::Limits`]).
    pub limits: crate::limits::Limits,
}

/// The settings to write: each `None` keeps the stored value, except that
/// `conflict_detection` and `history_days` are written as given (none follows the
/// profile), since the request carries the whole row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsChange {
    /// Lease times of scopes that set none.
    pub lease: Option<LeaseTimes>,
    /// Authoritative unless a scope says otherwise.
    pub authoritative: Option<bool>,
    /// DDNS settings new scopes start from.
    pub ddns: Option<DdnsPolicy>,
    /// Conflict detection; none follows the profile.
    pub conflict_detection: Option<bool>,
    /// History retention in days; none follows the profile.
    pub history_days: Option<u32>,
    /// The trusted relays, each with its links; none keeps the stored list. Stored sorted by
    /// relay prefix without repeated entries, each relay's links sorted and without
    /// duplicates. Under Hardened a relay that may name every link is refused unless the
    /// stored list holds it so already.
    pub trusted_relays: Option<Vec<tenko_core::dhcp::TrustedRelay>>,
    /// Unsets the trusted relays, so that the profile decides again (every sender under
    /// Lab, none otherwise); refused together with `trusted_relays`.
    pub clear_trusted_relays: bool,
    /// The limits per client and per scope, replaced whole; none keeps the stored ones. A
    /// field left unset in them follows the profile.
    pub limits: Option<tenko_core::dhcp::DhcpLimits>,
}

impl ConfigService {
    /// Refuses, under the Hardened profile, a relay of `list` that may name every link
    /// (a link of prefix length 0) unless `stored` holds that relay so already: an entry
    /// stored before relays had links, or before the switch to Hardened, keeps working (the
    /// health row `dhcp.relay.any_link` says so) and can be saved again unchanged, but no new
    /// one is written. A link-local relay prefix for lightweight relays
    /// ([`crate::relay::exempt_from_links`]) is not refused.
    fn refuse_any_link(
        &self,
        view: &dyn ReadView,
        stored: Option<&[TrustedRelay]>,
        list: &[TrustedRelay],
    ) -> ConfigResult<()> {
        let new_any = list.iter().find(|relay| {
            relay.is_any_link()
                && !crate::relay::exempt_from_links(relay.relay)
                && !stored.is_some_and(|stored| {
                    stored
                        .iter()
                        .any(|old| old.relay == relay.relay && old.is_any_link())
                })
        });
        let Some(relay) = new_any else {
            return Ok(());
        };
        if !self.hardened(view) {
            return Ok(());
        }
        Err(DhcpError::invalid(
            codes::RELAY_ANY_LINK,
            "trusted_relays",
            &format!(
                "the Hardened profile needs the links relay {} serves: 0.0.0.0/0 or ::/0 is \
                 not allowed",
                relay.relay
            ),
        )
        .into())
    }

    /// The settings, the defaults before the first write.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn settings(view: &dyn ReadView) -> ConfigResult<SettingsRow> {
        Ok(match view.get_typed(&SETTINGS, &())? {
            Some((settings, revision)) => SettingsRow { settings, revision },
            None => SettingsRow {
                settings: DhcpSettings::default(),
                revision: Revision::ZERO,
            },
        })
    }

    /// Writes the settings; with `expect`, only over the row at that revision (0: before
    /// the first write).
    ///
    /// # Errors
    ///
    /// `dhcp.settings.invalid`, `dhcp.lease_times.invalid`, `dhcp.ddns.invalid`, 412 when
    /// `expect` is stale, or a store or job error.
    pub async fn update_settings(
        &self,
        cx: &RequestCtx,
        change: SettingsChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(DhcpSettings, Option<Written>)> {
        self.execute(cx, |view| {
            let current = view.get_typed(&SETTINGS, &())?;
            let revision = current
                .as_ref()
                .map_or(Revision::ZERO, |(_, revision)| *revision);
            check_expect(expect, revision)?;
            let before = current.map(|(settings, _)| settings).unwrap_or_default();
            let mut after = before.clone();
            if let Some(lease) = change.lease {
                after.lease = lease;
            }
            if let Some(authoritative) = change.authoritative {
                after.authoritative = authoritative;
            }
            if let Some(ddns) = &change.ddns {
                // Slice 8 follow-ups: no `replace` under Hardened.
                self.refuse_replace(view, Some(ddns), "ddns")?;
                after.ddns.clone_from(ddns);
            }
            after.conflict_detection = change.conflict_detection;
            after.history_days = change.history_days;
            match (&change.trusted_relays, change.clear_trusted_relays) {
                (Some(_), true) => {
                    return Err(tenko_core::dhcp::DhcpError::invalid(
                        tenko_core::dhcp::codes::SETTINGS_INVALID,
                        "clear_trusted_relays",
                        "either a list of trusted relays or clear_trusted_relays",
                    )
                    .into());
                }
                (Some(list), false) => {
                    let mut list = list.clone();
                    for relay in &mut list {
                        relay.links.sort_unstable();
                        relay.links.dedup();
                    }
                    // An entry given twice is kept once; one relay with two sets of links
                    // is refused by the check below.
                    list.sort();
                    list.dedup();
                    self.refuse_any_link(view, before.trusted_relays.as_deref(), &list)?;
                    after.trusted_relays = Some(list);
                }
                (None, true) => after.trusted_relays = None,
                (None, false) => {}
            }
            if let Some(limits) = &change.limits {
                after.limits.clone_from(limits);
            }
            after.validate()?;
            if after == before && revision > Revision::ZERO {
                return Ok(Planned::nothing(after));
            }
            after.updated = Some(stamp(cx));
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(
                &SETTINGS,
                &(),
                (revision > Revision::ZERO).then_some(revision),
            );
            batch.put_typed(&SETTINGS, &(), &after)?;
            batch.audit(
                AuditDraft::success(audit::SETTINGS_UPDATE, vec![server_object()])
                    .with_source_ip(cx.source_ip),
            );
            Ok(Planned::write(
                after,
                batch,
                "change the DHCP server settings".to_owned(),
                vec![server_object()],
            ))
        })
        .await
    }
}
