//! Catalog zones (RFC 9432, schema version 2): the member list a catalog zone carries.
//!
//! A catalog zone holds the TXT record `version.<catalog>` with `"2"` and one PTR record
//! per member at `<unique-id>.zones.<catalog>` whose target is the member zone's name.
//! Tenko reads the members of a catalog zone it holds as a secondary and writes the
//! members of a primary catalog zone with the zone's identifier as the unique label, so a
//! member keeps its label while it stays in the catalog. Properties (`group`, `coo`) are
//! not used.

use std::collections::BTreeSet;

use tenko_core::dns::{DnsName, Rdata, RecordData, Rtype, ZoneId, rdata::TextBytes};

/// The schema version Tenko writes and reads.
pub const VERSION: &str = "2";

/// The name `version.<catalog>`.
pub fn version_name(catalog: &DnsName) -> Option<DnsName> {
    catalog.child("version").ok()
}

/// The name `zones.<catalog>`.
pub fn zones_name(catalog: &DnsName) -> Option<DnsName> {
    catalog.child("zones").ok()
}

/// Why a catalog zone's members could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// No `version` TXT, or another version than 2.
    #[error("the catalog zone has no version record of schema version 2")]
    Version,
}

/// The member zones of a catalog zone from its records (owner, type, data), sorted by
/// name; a member listed twice counts once.
///
/// # Errors
///
/// [`CatalogError::Version`] without the version record of schema 2.
pub fn members<'a>(
    catalog: &DnsName,
    records: impl IntoIterator<Item = (&'a DnsName, Rtype, &'a Rdata)>,
) -> Result<Vec<DnsName>, CatalogError> {
    let version = version_name(catalog).ok_or(CatalogError::Version)?;
    let zones = zones_name(catalog).ok_or(CatalogError::Version)?;
    let mut versioned = false;
    let mut found = BTreeSet::new();
    for (owner, rtype, rdata) in records {
        if *owner == version && rtype == Rtype::TXT {
            if let Ok(RecordData::Txt { strings }) = rdata.decode(rtype) {
                versioned |= strings.iter().any(|text| text.0 == VERSION.as_bytes());
            }
        } else if rtype == Rtype::PTR
            && owner.parent().as_ref() == Some(&zones)
            && let Ok(RecordData::Ptr { target }) = rdata.decode(rtype)
        {
            found.insert(target);
        }
    }
    if !versioned {
        return Err(CatalogError::Version);
    }
    Ok(found.into_iter().collect())
}

/// The unique label of a member: its zone identifier without dashes.
pub fn member_label(id: ZoneId) -> String {
    id.to_string().replace('-', "")
}

/// The RRsets a primary catalog zone holds besides its SOA and NS: the version TXT and a
/// PTR per member, as (owner, type, data).
pub fn generate(
    catalog: &DnsName,
    members: &[(ZoneId, DnsName)],
) -> Vec<(DnsName, Rtype, Vec<Rdata>)> {
    let mut out = Vec::with_capacity(members.len() + 1);
    if let Some(version) = version_name(catalog) {
        out.push((
            version,
            Rtype::TXT,
            vec![Rdata::from_data(&RecordData::Txt {
                strings: vec![TextBytes::from_text(VERSION)],
            })],
        ));
    }
    let Some(zones) = zones_name(catalog) else {
        return out;
    };
    for (id, name) in members {
        if let Ok(owner) = zones.child(&member_label(*id)) {
            out.push((
                owner,
                Rtype::PTR,
                vec![Rdata::from_data(&RecordData::Ptr {
                    target: name.clone(),
                })],
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    #[test]
    fn generated_members_read_back() {
        let catalog = name("catalog.example.test");
        let a = (ZoneId::generate(), name("a.example.test"));
        let b = (ZoneId::generate(), name("b.example.test"));
        let rrsets = generate(&catalog, &[a.clone(), b.clone()]);
        assert_eq!(rrsets.len(), 3);
        let records: Vec<(&DnsName, Rtype, &Rdata)> = rrsets
            .iter()
            .flat_map(|(owner, rtype, rdata)| rdata.iter().map(move |data| (owner, *rtype, data)))
            .collect();
        assert_eq!(
            members(&catalog, records.clone()),
            Ok(vec![a.1.clone(), b.1.clone()])
        );
        // Without the version record the zone is not a catalog.
        let unversioned: Vec<_> = records
            .into_iter()
            .filter(|(_, rtype, _)| *rtype == Rtype::PTR)
            .collect();
        assert_eq!(members(&catalog, unversioned), Err(CatalogError::Version));
    }

    #[test]
    fn only_ptr_records_one_label_below_zones_are_members() {
        let catalog = name("catalog.example.test");
        let version = Rdata::from_data(&RecordData::Txt {
            strings: vec![TextBytes::from_text("2")],
        });
        let member = Rdata::from_data(&RecordData::Ptr {
            target: name("c.example.test"),
        });
        let deep = name("x.y.zones.catalog.example.test");
        let ok = name("m1.zones.catalog.example.test");
        let version_owner = name("version.catalog.example.test");
        let records = vec![
            (&version_owner, Rtype::TXT, &version),
            (&deep, Rtype::PTR, &member),
            (&ok, Rtype::PTR, &member),
        ];
        assert_eq!(members(&catalog, records), Ok(vec![name("c.example.test")]));
    }
}
