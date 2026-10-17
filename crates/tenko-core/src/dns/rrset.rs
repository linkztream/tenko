//! RRsets and the rules that zone data must keep.
//!
//! [`RrSet::check`] holds the rules of one RRset, [`check_node`] the rules between the
//! RRsets of one owner name and [`check_apex`] what the apex of every zone needs. The zone
//! service (WP4.2) runs them on every write; the engine trusts what the store holds.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{
    DnsError, KeyName, Origin, ZoneId,
    name::{DnsName, Rtype, ScopeName},
    rdata::{Rdata, RecordData},
};
use crate::{codec::key::KeyCodec, ipam::Stamp};

/// The longest TTL (RFC 2181, section 8): 2^31 - 1 seconds.
pub const MAX_TTL: u32 = 2_147_483_647;

/// The most records one RRset may hold. Larger sets do not fit in a TCP answer anyway.
pub const MAX_RECORDS: usize = 4096;

/// The key of an RRset in `dns.rrsets`: zone, scope, owner name, type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
pub struct RrSetKey {
    /// The zone.
    pub zone: ZoneId,
    /// The zone scope (DNS-20).
    pub scope: ScopeName,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
}

impl KeyCodec for RrSetKey {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.zone.encode_key(out);
        self.scope.encode_key(out);
        self.name.encode_key(out);
        self.rtype.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, crate::codec::key::KeyError> {
        Ok(Self {
            zone: ZoneId::decode_key(input)?,
            scope: ScopeName::decode_key(input)?,
            name: DnsName::decode_key(input)?,
            rtype: Rtype::decode_key(input)?,
        })
    }
}

/// The records of one owner name and type in one scope of a zone: the unit of storage,
/// change and signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RrSet {
    /// The zone.
    pub zone: ZoneId,
    /// The zone scope (DNS-20).
    pub scope: ScopeName,
    /// The owner name, at or below the zone apex.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The TTL in seconds, 0 to 2^31 - 1.
    pub ttl: u32,
    /// The data of each record in wire form, without duplicates.
    pub rdata: Vec<Rdata>,
    /// Who owns the RRset (section 2.5 of the Phase 2 plan).
    pub origin: Origin,
    /// The TSIG key of the dynamic update that wrote it, for [`Origin::Dynamic`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyName>,
    /// The last change.
    pub updated: Stamp,
}

impl RrSet {
    /// The store key.
    pub fn key(&self) -> RrSetKey {
        RrSetKey {
            zone: self.zone,
            scope: self.scope.clone(),
            name: self.name.clone(),
            rtype: self.rtype,
        }
    }

    /// The typed records.
    ///
    /// # Errors
    ///
    /// [`DnsError`] `dns.record.invalid` when stored data does not decode.
    pub fn records(&self) -> Result<Vec<RecordData>, DnsError> {
        self.rdata
            .iter()
            .map(|rdata| {
                rdata
                    .decode(self.rtype)
                    .map_err(|error| DnsError::record_invalid(&self.name, self.rtype, error.reason))
            })
            .collect()
    }

    /// Checks the rules of one RRset in the zone with apex `apex`: the owner is at or below
    /// the apex; the type is not a meta type; the TTL is at most 2^31 - 1; there are 1 to
    /// 4,096 records without duplicates and each decodes as the type; CNAME, DNAME and SOA
    /// sets have exactly one record; SOA stands at the apex only and CNAME never there; DS
    /// never stands at the apex (it belongs to the parent); a wildcard owns no NS, SOA or DS.
    ///
    /// # Errors
    ///
    /// [`DnsError`] `dns.record.invalid` naming the first rule broken.
    pub fn check(&self, apex: &DnsName) -> Result<(), DnsError> {
        let fail =
            |reason: &'static str| Err(DnsError::record_invalid(&self.name, self.rtype, reason));
        if !self.name.is_subdomain_of(apex) {
            return fail("the owner name is outside the zone");
        }
        if self.rtype.is_meta() {
            return fail("a meta type is not zone data");
        }
        if self.ttl > MAX_TTL {
            return fail("the TTL is above 2147483647 seconds");
        }
        if self.rdata.is_empty() {
            return fail("an RRset has at least one record");
        }
        if self.rdata.len() > MAX_RECORDS {
            return fail("an RRset has at most 4096 records");
        }
        for (index, rdata) in self.rdata.iter().enumerate() {
            if let Err(error) = rdata.decode(self.rtype) {
                return Err(DnsError::record_invalid(
                    &self.name,
                    self.rtype,
                    error.reason,
                ));
            }
            if self.rdata[..index].contains(rdata) {
                return fail("an RRset holds no duplicate records");
            }
        }
        let at_apex = &self.name == apex;
        match self.rtype {
            Rtype::CNAME | Rtype::DNAME | Rtype::SOA if self.rdata.len() != 1 => {
                fail("a CNAME, DNAME or SOA set has exactly one record")
            }
            Rtype::SOA if !at_apex => fail("SOA stands at the zone apex only"),
            Rtype::CNAME if at_apex => fail("CNAME cannot stand at the zone apex"),
            Rtype::DS if at_apex => fail("DS belongs to the parent zone, not the apex"),
            Rtype::NS | Rtype::SOA | Rtype::DS if self.name.is_wildcard() => {
                fail("a wildcard owns no NS, SOA or DS")
            }
            _ => Ok(()),
        }
    }
}

/// Types that may stand beside a CNAME (RFC 2181 section 10.1, RFC 4035 section 2.5).
const BESIDE_CNAME: [Rtype; 2] = [Rtype::RRSIG, Rtype::NSEC];

/// Types that may stand at a delegation point below the apex: the NS set, the DS of the
/// child, the DNSSEC records, and addresses that serve as glue when the server's name is
/// the delegated name itself.
const AT_DELEGATION: [Rtype; 6] = [
    Rtype::NS,
    Rtype::DS,
    Rtype::RRSIG,
    Rtype::NSEC,
    Rtype::A,
    Rtype::AAAA,
];

/// Checks the RRsets of one owner name in one scope of the zone with apex `apex`: a CNAME
/// stands alone (only RRSIG and NSEC beside it); an NS set below the apex is a delegation
/// and only DS, RRSIG, NSEC and glue addresses stand beside it; each type appears once.
///
/// # Errors
///
/// [`DnsError`] `dns.record.conflict` naming the owner and the types in conflict.
pub fn check_node<'a>(
    apex: &DnsName,
    rrsets: impl IntoIterator<Item = &'a RrSet>,
) -> Result<(), DnsError> {
    let rrsets: Vec<&RrSet> = rrsets.into_iter().collect();
    let Some(first) = rrsets.first() else {
        return Ok(());
    };
    let types: Vec<Rtype> = rrsets.iter().map(|rrset| rrset.rtype).collect();
    for (index, rtype) in types.iter().enumerate() {
        if types[..index].contains(rtype) {
            return Err(DnsError::record_conflict(
                &first.name,
                *rtype,
                "the type appears twice",
            ));
        }
    }
    if types.contains(&Rtype::CNAME)
        && let Some(other) = types
            .iter()
            .find(|rtype| **rtype != Rtype::CNAME && !BESIDE_CNAME.contains(rtype))
    {
        return Err(DnsError::record_conflict(
            &first.name,
            *other,
            "a CNAME cannot stand beside other data",
        ));
    }
    if &first.name != apex
        && types.contains(&Rtype::NS)
        && let Some(other) = types.iter().find(|rtype| !AT_DELEGATION.contains(rtype))
    {
        return Err(DnsError::record_conflict(
            &first.name,
            *other,
            "only DS, DNSSEC records and glue addresses stand beside a delegation",
        ));
    }
    Ok(())
}

/// Checks what the apex of every zone holds: one SOA set and an NS set.
///
/// # Errors
///
/// [`DnsError`] `dns.record.invalid` when either is missing.
pub fn check_apex<'a>(
    apex: &DnsName,
    rrsets: impl IntoIterator<Item = &'a RrSet>,
) -> Result<(), DnsError> {
    let mut soa = false;
    let mut ns = false;
    for rrset in rrsets {
        if &rrset.name == apex {
            soa |= rrset.rtype == Rtype::SOA;
            ns |= rrset.rtype == Rtype::NS;
        }
    }
    if !soa {
        return Err(DnsError::record_invalid(
            apex,
            Rtype::SOA,
            "the zone apex needs an SOA record",
        ));
    }
    if !ns {
        return Err(DnsError::record_invalid(
            apex,
            Rtype::NS,
            "the zone apex needs an NS set",
        ));
    }
    Ok(())
}
