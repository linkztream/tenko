//! The zones' records as observations (WP4.4): the A, AAAA and PTR records of the origins
//! `ipam` and `manual` in the primary zones Tenko serves, read from the store's view (the
//! engine is never asked), become facts of the source `DnsRecord { zone }`.
//!
//! Each record gives a name for an address ([`Observed::Name`]): an A or AAAA record its
//! owner for its address, a PTR record its target for the address of its owner name. A
//! name is not a sighting of the address, so a record never keeps an address of intent
//! from being proposed as orphaned; the names show in the observation view and name the
//! hosts the reconciler proposes. Every zone's batch is complete, so a deleted record's
//! fact expires at the next ingest, and retention purges it like any other.
//!
//! The source of an RFC 2317 zone (`64/26.2.0.192.in-addr.arpa`, a name that is not a host
//! name) is its parent `2.0.192.in-addr.arpa`; the facts of both zones form one batch.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use tenko_core::{
    ObservationId, Timestamp,
    codec::encode_key,
    dns::{
        DnsName, Origin, RecordData, RrSet, Rtype, ScopeName, Zone, ZoneKind,
        tables::{RRSETS, ZONES},
    },
    net::Fqdn,
    observe::{Observation, ObservationSource, Observed},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store};

use super::{IngestBatch, ObserveConfig, ingest::ingest, source_key};
use crate::{dns::reverse, error::IpamResult};

/// The address a PTR owner name stands for: the plain `in-addr.arpa` and `ip6.arpa` forms
/// and the RFC 2317 form `70.64/26.2.0.192.in-addr.arpa`.
pub fn ptr_address(owner: &DnsName) -> Option<IpAddr> {
    let text = owner.as_str();
    if let Some(rest) = text.strip_suffix(".in-addr.arpa") {
        let labels: Vec<&str> = rest.split('.').collect();
        let octets: Vec<&str> = match labels.as_slice() {
            [host, block, c, b, a] if block.contains('/') => vec![a, b, c, host],
            [d, c, b, a] => vec![a, b, c, d],
            _ => return None,
        };
        let mut out = [0u8; 4];
        for (slot, label) in out.iter_mut().zip(octets) {
            if label.len() > 1 && label.starts_with('0') {
                return None;
            }
            *slot = label.parse().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(out)));
    }
    let rest = text.strip_suffix(".ip6.arpa")?;
    let labels: Vec<&str> = rest.split('.').collect();
    if labels.len() != 32 {
        return None;
    }
    let mut bits = 0u128;
    for label in labels.iter().rev() {
        let [digit] = label.as_bytes() else {
            return None;
        };
        bits = (bits << 4) | u128::from(char::from(*digit).to_digit(16)?);
    }
    Some(IpAddr::V6(Ipv6Addr::from(bits)))
}

/// The source of a zone's facts: the zone, or for an RFC 2317 zone its parent.
fn source_of(zone: &Zone) -> Option<ObservationSource> {
    let name = match reverse::parse_zone(&zone.name) {
        Some(reverse::ReverseZone::Classless { parent, .. }) => parent,
        _ => zone.name.clone(),
    };
    Fqdn::new(name.as_str())
        .ok()
        .map(|zone| ObservationSource::DnsRecord { zone })
}

fn names(rrset: &RrSet) -> Vec<(IpAddr, String)> {
    let Ok(records) = rrset.records() else {
        return Vec::new();
    };
    records
        .into_iter()
        .filter_map(|record| match record {
            RecordData::A { address } => Some((IpAddr::V4(address), rrset.name.to_string())),
            RecordData::Aaaa { address } => Some((IpAddr::V6(address), rrset.name.to_string())),
            RecordData::Ptr { target } => {
                ptr_address(&rrset.name).map(|ip| (ip, target.to_string()))
            }
            _ => None,
        })
        .collect()
}

/// Reads the records of every primary zone and ingests them, one complete batch per
/// source; returns the facts written.
///
/// # Errors
///
/// Store errors.
pub async fn ingest_zones(
    store: &Arc<dyn Store>,
    config: &ObserveConfig,
    now: Timestamp,
) -> IpamResult<usize> {
    let view = store.read(ReadConsistency::Local).await?;
    let mut batches: BTreeMap<String, IngestBatch> = BTreeMap::new();
    for (_, zone, _) in view.scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)? {
        let zone: Zone = zone;
        if zone.kind != ZoneKind::Primary {
            continue;
        }
        let Some(source) = source_of(&zone) else {
            continue;
        };
        let batch = batches
            .entry(source_key(&source))
            .or_insert_with(|| IngestBatch {
                source: source.clone(),
                observations: Vec::new(),
                complete: true,
                received_at: now,
            });
        let rows = view.scan_typed(
            &RRSETS,
            KeyRange::prefix(encode_key(&(zone.id, ScopeName::DEFAULT))),
            usize::MAX,
            false,
        )?;
        for (_, rrset, _) in rows {
            let rrset: RrSet = rrset;
            if !matches!(rrset.origin, Origin::Ipam | Origin::Manual)
                || !matches!(rrset.rtype, Rtype::A | Rtype::AAAA | Rtype::PTR)
            {
                continue;
            }
            for (ip, name) in names(&rrset) {
                batch.observations.push(Observation {
                    id: ObservationId::generate(),
                    source: source.clone(),
                    subject: Observed::Name {
                        ip,
                        placeholder: tenko_core::observe::is_placeholder_name(&name),
                        name,
                    },
                    observed_at: now,
                    received_at: now,
                    expires_at: None,
                });
            }
        }
    }
    drop(view);
    let mut written = 0;
    for batch in batches.values() {
        let report = ingest(store, batch, config).await?;
        written += usize::try_from(report.new + report.changed + report.refreshed + report.gone)
            .unwrap_or(usize::MAX);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    #[test]
    fn ptr_owner_names_give_their_addresses() {
        assert_eq!(
            ptr_address(&name("10.2.0.192.in-addr.arpa")),
            Some("192.0.2.10".parse().expect("ip"))
        );
        assert_eq!(
            ptr_address(&name("70.64/26.2.0.192.in-addr.arpa")),
            Some("192.0.2.70".parse().expect("ip"))
        );
        let v6: IpAddr = "2001:db8::1".parse().expect("ip");
        assert_eq!(ptr_address(&reverse::ptr_name(v6)), Some(v6));
        assert_eq!(ptr_address(&name("2.0.192.in-addr.arpa")), None);
        assert_eq!(ptr_address(&name("www.example.test")), None);
        assert_eq!(ptr_address(&name("010.2.0.192.in-addr.arpa")), None);
    }
}
