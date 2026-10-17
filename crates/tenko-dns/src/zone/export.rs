//! The zone file export (MIG-15): the RRsets of a zone scope as an RFC 1035 file.
//!
//! The file starts with `$ORIGIN` (the apex) and `$TTL` (the SOA TTL), then the apex SOA,
//! then every other RRset in key order, which is the canonical name order of RFC 4034 with
//! the types ascending ([`zonefile::write_rrset`]). The same data always gives the same
//! bytes, and importing a file the export wrote and exporting again gives the file back.
//! Every export writes the audit record `dns.zone.export`.

use tenko_core::{
    ObjectRef, RequestCtx,
    audit::AuditDraft,
    dns::{RrSet, Rtype, ScopeName, ZoneId, audit, tables::RRSETS},
};
use tenko_store::{ReadView, WriteBatch};

use super::{ZoneError, ZoneResult, ZoneService, holds_data, rrset_range, soa_serial, zonefile};

/// RRsets read per page while exporting.
const PAGE: usize = 4096;

/// An exported zone file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFile {
    /// The apex.
    pub zone: tenko_core::dns::DnsName,
    /// The serial of the exported scope.
    pub serial: u32,
    /// RRsets written.
    pub rrsets: u64,
    /// The file.
    pub text: String,
}

/// Writes the zone file of a zone scope from `view`.
///
/// # Errors
///
/// `dns.zone.not_found`, `dns.zone.invalid` for a zone without data or an unknown scope,
/// `dns.record.invalid` for stored data that does not parse, or the store's error.
pub fn write(view: &dyn ReadView, zone: ZoneId, scope: &ScopeName) -> ZoneResult<ZoneFile> {
    let zone = ZoneService::zone(view, zone)?.zone;
    if !holds_data(zone.kind) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "only primary and RPZ zones hold records in Tenko",
        ));
    }
    if !zone.has_scope(scope) {
        return Err(
            ZoneError::zone_invalid("scope", "the zone has no such scope")
                .param("scope", scope.as_str()),
        );
    }
    let mut text = zonefile::header(&zone.name, zone.soa.ttl);
    let mut serial = 0;
    let mut rrsets = 0u64;
    let soa = view.get(
        RRSETS.name(),
        &RRSETS.key(&tenko_core::dns::RrSetKey {
            zone: zone.id,
            scope: scope.clone(),
            name: zone.name.clone(),
            rtype: Rtype::SOA,
        }),
    )?;
    if let Some(soa) = soa {
        let soa: RrSet = RRSETS.decode(&soa.value)?;
        serial = soa_serial(&soa).unwrap_or_default();
        zonefile::write_rrset(&mut text, &zone.name, &soa)?;
        rrsets += 1;
    }
    let mut after: Option<Vec<u8>> = None;
    loop {
        let mut range = rrset_range(zone.id, Some(scope), None);
        if let Some(after) = &after {
            range = range.after(after.clone());
        }
        let rows = view.scan(RRSETS.name(), range, PAGE, false)?;
        let exhausted = rows.len() < PAGE;
        for (key, versioned) in rows {
            after = Some(key.to_vec());
            let rrset: RrSet = RRSETS.decode(&versioned.value)?;
            if rrset.rtype == Rtype::SOA && rrset.name == zone.name {
                continue;
            }
            zonefile::write_rrset(&mut text, &zone.name, &rrset)?;
            rrsets += 1;
        }
        if exhausted {
            break;
        }
    }
    Ok(ZoneFile {
        zone: zone.name,
        serial,
        rrsets,
        text,
    })
}

impl ZoneService {
    /// Exports a zone scope as a zone file and writes the audit record of the export.
    ///
    /// # Errors
    ///
    /// The errors of [`write`], or the store's error for the audit record.
    pub async fn export(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        scope: &ScopeName,
    ) -> ZoneResult<ZoneFile> {
        let view = self.view(None).await?;
        let file = write(view.as_ref(), zone, scope)?;
        drop(view);
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::success(audit::ZONE_EXPORT, vec![ObjectRef::from(zone)])
                .with_source_ip(cx.source_ip)
                .with_context("zone", file.zone.as_str())
                .with_context("scope", scope.as_str())
                .with_context("serial", file.serial.to_string())
                .with_context("rrsets", file.rrsets.to_string()),
        );
        self.store.propose(batch).await?;
        Ok(file)
    }
}
