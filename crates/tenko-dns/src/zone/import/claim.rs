//! Which RRsets of a Windows zone file become claimable, and the operator's approval of
//! them (DNS-28, MIG-07).
//!
//! An A, AAAA or PTR RRset of a file read in the Windows dialect whose records all carry an
//! aging mark is a *candidate*: Windows calls it dynamic. Imported with the origin `ad` and
//! without an owner it is *claimable*: in a zone with ownership on, the computer it names
//! takes it at its next registration and owns it from then on. A candidate becomes
//! claimable only when all of this holds:
//!
//! 1. Nothing on the never-claimable list holds it back ([`HeldReason`]): the apex, a locator
//!    name, a wildcard, a name with a `_` label, a well-known service name (`wpad`,
//!    `isatap`), a name server of the zone, the target of an MX, SRV, CNAME or DNAME record
//!    of the file, the host name of a Tenko node, a name no computer can claim (an address
//!    name not directly below the apex, a PTR RRset outside `in-addr.arpa` and `ip6.arpa`),
//!    a name that holds other records in the file or in the store; for a PTR RRset the same
//!    of every name it points at.
//! 2. It matches the operator's rule ([`ClaimRule`]): only names at or below given names,
//!    only addresses inside given prefixes, never given names.
//! 3. The import that writes carries the operator's approval: the digest ([`ClaimDigest`])
//!    the preview gave for exactly the set it listed. The digest covers the file's bytes,
//!    the zone, the scope and every claimable name with its type, so an approval does not
//!    carry over to another file, another zone or a store that changed. An import without
//!    an approval makes nothing claimable: the candidates come in `manual`, as static
//!    records. One whose digest is not the one the file and the store give now is refused
//!    (`dns.import.claimable_changed`, 409).
//!
//! The preview reads the file three times in the Windows dialect: once for the candidate
//! names (at most [`MAX_CANDIDATES`]), once for everything else the file says about them
//! (their other records, the records that point at them, their data against the rule), and
//! once to merge with the store, which decides the rest. Its answer lists the claimable
//! RRsets in name order, a page at a time ([`DEFAULT_PAGE`], at most [`MAX_PAGE`]), and the
//! first [`MAX_LISTED_HELD`] of those held back with the reason; the counts cover all.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use aws_lc_rs::digest::{Context, SHA256, digest};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::dns::{DnsName, RecordData, Rtype, ScopeName, ZoneId};

use super::super::{
    ZoneError, ZoneResult,
    ownership::{is_reserved, is_service_name},
    zonefile::{FileRecord, Item, Reader},
};

/// Candidates one preview follows at most. Past it nothing of the file becomes claimable
/// and an approval is refused (`dns.import.claimable_too_many`): import the file in parts.
pub const MAX_CANDIDATES: usize = 250_000;
/// Claimable RRsets one page of a preview lists when the request names no limit.
pub const DEFAULT_PAGE: usize = 1_000;
/// Claimable RRsets one page of a preview lists at most.
pub const MAX_PAGE: usize = 5_000;
/// Records of one claimable RRset a listing shows; `more` counts the rest.
pub const MAX_SHOWN_RECORDS: usize = 4;
/// RRsets held back that a report lists, in name order; `held_back` counts all.
pub const MAX_LISTED_HELD: usize = 1_000;
/// Names in the rule's `under` at most.
pub const MAX_RULE_NAMES: usize = 256;
/// Prefixes in the rule's `within` at most.
pub const MAX_RULE_PREFIXES: usize = 256;
/// Names in the rule's `except` at most.
pub const MAX_RULE_EXCEPT: usize = 10_000;
/// Host names of Tenko nodes an import is given at most.
pub const MAX_RESERVED_HOSTS: usize = 4_096;
/// Name server names (NS hosts and the SOA MNAME) of a file followed at most; past it
/// every PTR candidate is held back, since its targets can no longer be checked.
const MAX_FILE_NAME_SERVERS: usize = 65_536;
/// Claimable names an audit record lists; the count and the digest cover all.
pub const MAX_AUDITED_NAMES: usize = 100;

/// The code of an approval whose digest is not the one the file and the store give now.
pub const CLAIMABLE_CHANGED: &str = "dns.import.claimable_changed";
/// The code of a malformed claim request (the rule's bounds, a cursor, a digest).
pub const CLAIMABLE_INVALID: &str = "dns.import.claimable_invalid";
/// The code of an approval of a file with more than [`MAX_CANDIDATES`] candidates.
pub const CLAIMABLE_TOO_MANY: &str = "dns.import.claimable_too_many";

/// Why a candidate stays static, from the strongest reason to the weakest; a candidate
/// held back for several reasons shows the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldReason {
    /// The apex, a locator name, a wildcard, a name with a label that starts with `_`, or a
    /// PTR to such a name.
    Reserved,
    /// A well-known service name (`wpad`, `isatap`), or a PTR to one.
    ServiceName,
    /// A name server of the zone (an NS host, the SOA MNAME, of the file or the store), or a
    /// PTR to one.
    NameServer,
    /// The host name of a Tenko node, or a PTR to one.
    TenkoNode,
    /// The target of an MX, SRV, CNAME or DNAME record of the file.
    ServiceTarget,
    /// No computer can claim it: an address name that is not directly below the apex, a
    /// PTR whose targets do not all name the same host.
    NotAHost,
    /// The name holds other records: of another type, a static record beside the aged ones,
    /// or a record of another origin in the store.
    OtherData,
    /// Outside the operator's rule.
    Rule,
    /// The file has more candidates than [`MAX_CANDIDATES`].
    TooMany,
    /// The import carried no approval.
    NotApproved,
}

impl HeldReason {
    /// The stable name of the reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            HeldReason::Reserved => "reserved",
            HeldReason::ServiceName => "service_name",
            HeldReason::NameServer => "name_server",
            HeldReason::TenkoNode => "tenko_node",
            HeldReason::ServiceTarget => "service_target",
            HeldReason::NotAHost => "not_a_host",
            HeldReason::OtherData => "other_data",
            HeldReason::Rule => "rule",
            HeldReason::TooMany => "too_many",
            HeldReason::NotApproved => "not_approved",
        }
    }
}

/// The operator's rule over the candidates: each part that is not empty must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimRule {
    /// Only names at or below one of these (the owner of an address RRset, every target of
    /// a PTR RRset).
    pub under: Vec<DnsName>,
    /// Only addresses inside one of these (every address of an address RRset, the address
    /// a PTR RRset's owner name stands for).
    pub within: Vec<IpNet>,
    /// Never these names (the owner of an RRset, or a target of a PTR RRset).
    pub except: Vec<DnsName>,
}

impl ClaimRule {
    /// Whether the rule takes every candidate.
    pub fn is_all(&self) -> bool {
        self.under.is_empty() && self.within.is_empty() && self.except.is_empty()
    }

    /// The rule in a line of text, for the audit record.
    pub fn describe(&self) -> String {
        if self.is_all() {
            return "every candidate".to_owned();
        }
        let mut parts = Vec::new();
        // At most eight of each are written out, so the audit record stays small.
        if !self.under.is_empty() {
            let names: Vec<&str> = self.under.iter().take(8).map(DnsName::as_str).collect();
            let more = self.under.len().saturating_sub(8);
            parts.push(format!(
                "under {}{}",
                names.join(" "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            ));
        }
        if !self.within.is_empty() {
            let nets: Vec<String> = self
                .within
                .iter()
                .take(8)
                .map(ToString::to_string)
                .collect();
            let more = self.within.len().saturating_sub(8);
            parts.push(format!(
                "within {}{}",
                nets.join(" "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            ));
        }
        if !self.except.is_empty() {
            parts.push(format!("except {} name(s)", self.except.len()));
        }
        parts.join("; ")
    }

    fn name_ok(&self, name: &DnsName) -> bool {
        self.under.is_empty() || self.under.iter().any(|top| name.is_subdomain_of(top))
    }

    fn address_ok(&self, address: Option<IpAddr>) -> bool {
        self.within.is_empty()
            || address.is_some_and(|address| self.within.iter().any(|net| net.contains(&address)))
    }
}

/// The SHA-256 digest of a claimable set: what an operator approves.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimDigest(pub [u8; 32]);

impl fmt::Display for ClaimDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ClaimDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimDigest({self})")
    }
}

impl FromStr for ClaimDigest {
    type Err = ZoneError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = || invalid("approve", "the digest is 64 hexadecimal digits");
        let text = text.trim();
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| bad())?;
        }
        Ok(Self(out))
    }
}

/// What an import is asked about claimable names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimRequest {
    /// The operator's rule; empty takes every candidate.
    pub rule: ClaimRule,
    /// The approval: the digest of the preview. Without it an import makes nothing
    /// claimable; a preview ignores it.
    pub approval: Option<ClaimDigest>,
    /// The page of the preview's listing: after this name and type ([`cursor`]).
    pub after: Option<(DnsName, Rtype)>,
    /// The page size; [`DEFAULT_PAGE`] when absent, at most [`MAX_PAGE`].
    pub limit: Option<usize>,
    /// The host names (first labels, lowercase) of the Tenko nodes, which no candidate
    /// takes; the API fills them from the cluster's nodes.
    pub reserved_hosts: Vec<String>,
}

impl ClaimRequest {
    /// Whether the request asks anything of a candidate: a rule, an approval or a page.
    pub fn is_empty(&self) -> bool {
        self.rule.is_all()
            && self.approval.is_none()
            && self.after.is_none()
            && self.limit.is_none()
    }

    /// Checks the bounds.
    ///
    /// # Errors
    ///
    /// `dns.import.claimable_invalid` (400) with the field.
    pub fn check(&self) -> ZoneResult<()> {
        if self.rule.under.len() > MAX_RULE_NAMES {
            return Err(invalid("under", format!("at most {MAX_RULE_NAMES} names")));
        }
        if self.rule.within.len() > MAX_RULE_PREFIXES {
            return Err(invalid(
                "within",
                format!("at most {MAX_RULE_PREFIXES} prefixes"),
            ));
        }
        if self.rule.except.len() > MAX_RULE_EXCEPT {
            return Err(invalid(
                "except",
                format!("at most {MAX_RULE_EXCEPT} names"),
            ));
        }
        if self.reserved_hosts.len() > MAX_RESERVED_HOSTS {
            return Err(invalid(
                "reserved_hosts",
                format!("at most {MAX_RESERVED_HOSTS} host names"),
            ));
        }
        if self
            .limit
            .is_some_and(|limit| limit == 0 || limit > MAX_PAGE)
        {
            return Err(invalid("limit", format!("from 1 to {MAX_PAGE}")));
        }
        Ok(())
    }

    fn page(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
    }
}

fn invalid(field: &str, reason: impl Into<String>) -> ZoneError {
    let reason = reason.into();
    ZoneError::new(
        CLAIMABLE_INVALID,
        400,
        format!("claimable.{field}: {reason}"),
    )
    .param("field", field)
    .param("reason", reason)
}

/// The cursor of a listing page: the name and the type number of its last entry.
pub fn cursor(name: &DnsName, rtype: Rtype) -> String {
    format!("{name} {}", rtype.0)
}

/// Reads a [`cursor`].
///
/// # Errors
///
/// `dns.import.claimable_invalid` (400).
pub fn parse_cursor(text: &str) -> ZoneResult<(DnsName, Rtype)> {
    let bad = || invalid("after", "not a cursor of this listing");
    let (name, rtype) = text.trim().rsplit_once(' ').ok_or_else(bad)?;
    let name = DnsName::new(name).map_err(|_| bad())?;
    let rtype = rtype.parse::<u16>().map_err(|_| bad())?;
    Ok((name, Rtype(rtype)))
}

/// One claimable RRset of a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimableEntry {
    /// The owner name.
    pub name: DnsName,
    /// The type: A, AAAA or PTR.
    pub rtype: Rtype,
    /// The line of the file where the RRset starts.
    pub line: u32,
    /// The computer account that may claim it: `PC01$` for `pc01.<zone>` or a PTR to
    /// `pc01.<domain>`.
    pub claimant: String,
    /// The first [`MAX_SHOWN_RECORDS`] records in presentation form (addresses, targets).
    pub records: Vec<String>,
    /// Records not shown.
    #[serde(default)]
    pub more: u32,
}

/// One candidate that stays static, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldEntry {
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The line of the file where the RRset starts.
    pub line: u32,
    /// Why.
    pub reason: HeldReason,
}

/// The types a Windows client registers for itself (its A, AAAA and PTR records): the only
/// ones a Windows file's aging mark makes candidates. A controller's SRV and CNAME records
/// stand at locator names, which only privileged principals change anyway, and an aged
/// record of another type (an NS set at a delegation, say) is kept static rather than
/// handed to the computer its name happens to match.
pub fn claimable_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::A | Rtype::AAAA | Rtype::PTR)
}

fn line32(line: usize) -> u32 {
    u32::try_from(line).unwrap_or(u32::MAX)
}

/// What the file says about one RRset of a candidate name.
#[derive(Debug)]
struct SetInfo {
    line: usize,
    /// Every record carried an aging mark.
    aged_all: bool,
    /// At least one did.
    aged_any: bool,
    /// Every record matched the operator's rule.
    rule_ok: bool,
    /// The strongest reason a target of a PTR RRset gives.
    reason: Option<HeldReason>,
    /// The host every PTR target names (its first label), while they agree.
    host: Option<String>,
    records: Vec<String>,
    more: u32,
}

impl SetInfo {
    fn new(line: usize) -> Self {
        Self {
            line,
            aged_all: true,
            aged_any: false,
            rule_ok: true,
            reason: None,
            host: None,
            records: Vec::new(),
            more: 0,
        }
    }

    fn hold(&mut self, reason: HeldReason) {
        self.reason = Some(self.reason.map_or(reason, |held| held.min(reason)));
    }
}

/// What the file says about one candidate name.
#[derive(Debug)]
struct NameInfo {
    sets: Vec<(Rtype, SetInfo)>,
    /// The strongest reason the name itself gives (other data, a pointer at it).
    reason: Option<HeldReason>,
}

impl NameInfo {
    fn hold(&mut self, reason: HeldReason) {
        self.reason = Some(self.reason.map_or(reason, |held| held.min(reason)));
    }

    fn set(&mut self, rtype: Rtype, line: usize) -> &mut SetInfo {
        let index = if let Some(index) = self.sets.iter().position(|(known, _)| *known == rtype) {
            index
        } else {
            self.sets.push((rtype, SetInfo::new(line)));
            self.sets.len() - 1
        };
        &mut self.sets[index].1
    }
}

/// The checks of the never-claimable list and the rule, from the zone, the store and the
/// request.
pub(super) struct Checks<'a> {
    pub apex: &'a DnsName,
    pub rule: &'a ClaimRule,
    pub except: HashSet<&'a DnsName>,
    /// Host labels of the Tenko nodes, lowercase.
    pub hosts: HashSet<String>,
    /// The name servers the store names (the scope's apex NS hosts and SOA MNAME).
    pub store_name_servers: HashSet<DnsName>,
}

impl<'a> Checks<'a> {
    pub fn new(
        apex: &'a DnsName,
        request: &'a ClaimRequest,
        store_name_servers: HashSet<DnsName>,
    ) -> Self {
        Self {
            apex,
            rule: &request.rule,
            except: request.rule.except.iter().collect(),
            hosts: request
                .reserved_hosts
                .iter()
                .filter_map(|host| host.split('.').next())
                .filter(|label| !label.is_empty())
                .map(str::to_ascii_lowercase)
                .collect(),
            store_name_servers,
        }
    }

    fn is_node(&self, name: &DnsName) -> bool {
        name.labels()
            .next()
            .is_some_and(|first| self.hosts.contains(&first.to_ascii_lowercase()))
    }
}

/// The plan of one preview: what the file and its rules allow, and what they hold back.
#[derive(Debug, Default)]
pub(super) struct Plan {
    /// The candidates the file, the never-claimable list and the rule allow, with their
    /// listing entries; the merge with the store decides which of them become claimable.
    pub allowed: HashMap<(DnsName, Rtype), ClaimableEntry>,
    /// The candidates held back by the file, the list or the rule.
    pub held: Vec<HeldEntry>,
    /// More than [`MAX_CANDIDATES`] candidates: none is followed.
    pub overflow: bool,
}

/// What the first read found.
struct Found {
    names: HashMap<DnsName, NameInfo>,
    name_servers: HashSet<DnsName>,
    name_servers_overflow: bool,
    overflow: bool,
}

/// Records a read takes between two yields to the runtime: the preview runs on the API's
/// runtime, and a large file gives the other requests their turn.
const YIELD_RECORDS: u32 = 4_096;

/// Reads `reader` to the end, giving each record to `each`; the losses are not counted
/// (the merge read counts them).
async fn read_all(mut reader: Reader, mut each: impl FnMut(&FileRecord) + Send) -> ZoneResult<()> {
    let mut count = 0u32;
    while let Some(item) = reader.next_item()? {
        if let Item::Record(record) = item {
            each(&record);
        }
        count = count.wrapping_add(1);
        if count.is_multiple_of(YIELD_RECORDS) {
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

/// The first read: the candidate names, and the file's name servers (NS hosts and the
/// apex SOA's MNAME).
async fn find(reader: Reader, apex: &DnsName) -> ZoneResult<Found> {
    let mut found = Found {
        names: HashMap::new(),
        name_servers: HashSet::new(),
        name_servers_overflow: false,
        overflow: false,
    };
    read_all(reader, |record| {
        if record.aged && claimable_type(record.rtype) && !found.names.contains_key(&record.name) {
            if found.names.len() >= MAX_CANDIDATES {
                found.overflow = true;
            } else {
                found.names.insert(
                    record.name.clone(),
                    NameInfo {
                        sets: Vec::new(),
                        reason: None,
                    },
                );
            }
        }
        if !matches!(record.rtype, Rtype::NS | Rtype::SOA) {
            return;
        }
        let server = match record.rdata.decode(record.rtype) {
            Ok(RecordData::Ns { host }) => Some(host),
            Ok(RecordData::Soa { mname, .. }) if &record.name == apex => Some(mname),
            _ => None,
        };
        if let Some(server) = server {
            if found.name_servers.len() >= MAX_FILE_NAME_SERVERS {
                found.name_servers_overflow = true;
            } else {
                found.name_servers.insert(server);
            }
        }
    })
    .await?;
    Ok(found)
}

/// Whether `name` lies strictly below `in-addr.arpa` or `ip6.arpa`, the address tree.
pub fn is_address_tree(name: &DnsName) -> bool {
    let mut labels = name.labels().rev();
    let arpa = labels.next() == Some("arpa");
    let tree = matches!(labels.next(), Some("in-addr" | "ip6"));
    arpa && tree && labels.next().is_some()
}

/// The address an address-tree name stands for: four labels below `in-addr.arpa`, or 32
/// nibbles below `ip6.arpa`; `None` for any other name.
pub fn reverse_address(name: &DnsName) -> Option<IpAddr> {
    let labels: Vec<&str> = name.labels().collect();
    match labels.as_slice() {
        [d, c, b, a, "in-addr", "arpa"] => {
            let octet = |text: &str| {
                (!text.is_empty() && text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| text.parse::<u8>().ok())
                    .flatten()
            };
            Some(IpAddr::V4(Ipv4Addr::new(
                octet(a)?,
                octet(b)?,
                octet(c)?,
                octet(d)?,
            )))
        }
        [nibbles @ .., "ip6", "arpa"] if nibbles.len() == 32 => {
            let mut value: u128 = 0;
            for nibble in nibbles.iter().rev() {
                let mut chars = nibble.chars();
                let digit = chars.next()?.to_digit(16)?;
                if chars.next().is_some() {
                    return None;
                }
                value = (value << 4) | u128::from(digit);
            }
            Some(IpAddr::V6(Ipv6Addr::from(value)))
        }
        _ => None,
    }
}

impl Found {
    /// The second read: everything the file says about the candidate names.
    async fn learn(&mut self, reader: Reader, checks: &Checks<'_>) -> ZoneResult<()> {
        let names = &mut self.names;
        let name_servers = &self.name_servers;
        let servers_unknown = self.name_servers_overflow;
        read_all(reader, |record| {
            let points = matches!(
                record.rtype,
                Rtype::NS | Rtype::SOA | Rtype::MX | Rtype::SRV | Rtype::CNAME | Rtype::DNAME
            );
            if !points && !names.contains_key(&record.name) {
                return;
            }
            let data = record.rdata.decode(record.rtype).ok();
            // The records that point at a candidate.
            let pointed = match &data {
                Some(RecordData::Ns { host }) => Some((host, HeldReason::NameServer)),
                Some(RecordData::Soa { mname, .. }) => Some((mname, HeldReason::NameServer)),
                Some(RecordData::Mx { exchange, .. }) => {
                    Some((exchange, HeldReason::ServiceTarget))
                }
                Some(
                    RecordData::Srv { target, .. }
                    | RecordData::Cname { target }
                    | RecordData::Dname { target },
                ) => Some((target, HeldReason::ServiceTarget)),
                _ => None,
            };
            if let Some((target, reason)) = pointed
                && let Some(info) = names.get_mut(target)
            {
                info.hold(reason);
            }
            let Some(info) = names.get_mut(&record.name) else {
                return;
            };
            if !claimable_type(record.rtype) {
                info.hold(HeldReason::OtherData);
                return;
            }
            let set = info.set(record.rtype, record.line);
            set.aged_all &= record.aged;
            set.aged_any |= record.aged;
            let shown = match &data {
                Some(RecordData::A { address }) => {
                    set.rule_ok &= checks.rule.address_ok(Some(IpAddr::V4(*address)));
                    Some(address.to_string())
                }
                Some(RecordData::Aaaa { address }) => {
                    set.rule_ok &= checks.rule.address_ok(Some(IpAddr::V6(*address)));
                    Some(address.to_string())
                }
                Some(RecordData::Ptr { target }) => {
                    // A target that is a locator name of any zone, a wildcard or a name
                    // with a `_` label names no computer.
                    if is_reserved(&DnsName::root(), target) && !target.is_root() {
                        set.hold(HeldReason::Reserved);
                    }
                    if is_service_name(target) {
                        set.hold(HeldReason::ServiceName);
                    }
                    if servers_unknown
                        || name_servers.contains(target)
                        || checks.store_name_servers.contains(target)
                    {
                        set.hold(HeldReason::NameServer);
                    }
                    if checks.is_node(target) {
                        set.hold(HeldReason::TenkoNode);
                    }
                    let host = target
                        .labels()
                        .next()
                        .filter(|_| target.label_count() >= 2)
                        .map(str::to_ascii_lowercase);
                    match (&set.host, host) {
                        (_, None) => set.hold(HeldReason::NotAHost),
                        (None, Some(host)) => set.host = Some(host),
                        (Some(known), Some(host)) if *known != host => {
                            set.hold(HeldReason::NotAHost);
                        }
                        _ => {}
                    }
                    set.rule_ok &= checks.rule.name_ok(target) && !checks.except.contains(target);
                    Some(target.to_string())
                }
                _ => {
                    set.rule_ok = false;
                    None
                }
            };
            if let Some(shown) = shown {
                if set.records.len() < MAX_SHOWN_RECORDS {
                    set.records.push(shown);
                } else {
                    set.more = set.more.saturating_add(1);
                }
            }
        })
        .await
    }

    /// The reasons of the never-claimable list that the owner name of an RRset gives.
    fn owner_reason(
        &self,
        checks: &Checks<'_>,
        name: &DnsName,
        rtype: Rtype,
    ) -> Option<HeldReason> {
        if is_reserved(checks.apex, name) {
            return Some(HeldReason::Reserved);
        }
        if is_service_name(name) {
            return Some(HeldReason::ServiceName);
        }
        if self.name_servers.contains(name) || checks.store_name_servers.contains(name) {
            return Some(HeldReason::NameServer);
        }
        if checks.is_node(name) {
            return Some(HeldReason::TenkoNode);
        }
        if rtype == Rtype::PTR {
            // A PTR RRset is claimable only at a name of the address tree: one at a name
            // such as `wpad.<zone>` would hand that name to the host it points at.
            return (!is_address_tree(name)).then_some(HeldReason::NotAHost);
        }
        if name.parent().as_ref() != Some(checks.apex) {
            return Some(HeldReason::NotAHost);
        }
        None
    }

    /// The plan: every candidate RRset allowed or held back.
    fn plan(self, checks: &Checks<'_>) -> Plan {
        let mut plan = Plan::default();
        for (name, info) in &self.names {
            let has_ptr = info.sets.iter().any(|(rtype, _)| *rtype == Rtype::PTR);
            let has_address = info.sets.iter().any(|(rtype, _)| *rtype != Rtype::PTR);
            let static_beside = info.sets.iter().any(|(_, set)| !set.aged_all);
            for (rtype, set) in &info.sets {
                if !set.aged_any {
                    continue;
                }
                let mut reasons = [
                    info.reason,
                    set.reason,
                    self.owner_reason(checks, name, *rtype),
                    ((has_ptr && has_address) || static_beside).then_some(HeldReason::OtherData),
                    (!set.rule_ok
                        || checks.except.contains(name)
                        || (*rtype != Rtype::PTR && !checks.rule.name_ok(name))
                        || (*rtype == Rtype::PTR
                            && !checks.rule.within.is_empty()
                            && !checks.rule.address_ok(reverse_address(name))))
                    .then_some(HeldReason::Rule),
                ]
                .into_iter()
                .flatten();
                let first = reasons.next();
                let reason = reasons.fold(first, |held, reason| {
                    Some(held.map_or(reason, |held| held.min(reason)))
                });
                if let Some(reason) = reason {
                    plan.held.push(HeldEntry {
                        name: name.clone(),
                        rtype: *rtype,
                        line: line32(set.line),
                        reason,
                    });
                    continue;
                }
                let host = if *rtype == Rtype::PTR {
                    set.host.clone()
                } else {
                    name.labels().next().map(str::to_ascii_lowercase)
                };
                let Some(host) = host else {
                    plan.held.push(HeldEntry {
                        name: name.clone(),
                        rtype: *rtype,
                        line: line32(set.line),
                        reason: HeldReason::NotAHost,
                    });
                    continue;
                };
                plan.allowed.insert(
                    (name.clone(), *rtype),
                    ClaimableEntry {
                        name: name.clone(),
                        rtype: *rtype,
                        line: line32(set.line),
                        claimant: format!("{}$", host.to_ascii_uppercase()),
                        records: set.records.clone(),
                        more: set.more,
                    },
                );
            }
        }
        plan
    }
}

/// The plan of a Windows file: reads it twice (`reader` makes a fresh reader of the
/// file each time). A file with more than [`MAX_CANDIDATES`] candidates gives an empty plan
/// marked `overflow`: the merge then holds every candidate back (`too_many`).
///
/// # Errors
///
/// The reader's errors.
pub(super) async fn plan(
    mut reader: impl FnMut() -> ZoneResult<Reader> + Send,
    checks: &Checks<'_>,
) -> ZoneResult<Plan> {
    let mut found = find(reader()?, checks.apex).await?;
    if found.overflow {
        return Ok(Plan {
            overflow: true,
            ..Plan::default()
        });
    }
    found.learn(reader()?, checks).await?;
    Ok(found.plan(checks))
}

/// The SHA-256 of a file's bytes in hexadecimal, for the audit record: an archived file
/// can be checked against the import that approved it.
pub fn file_digest(text: &str) -> String {
    ClaimDigest({
        let mut out = [0u8; 32];
        out.copy_from_slice(digest(&SHA256, text.as_bytes()).as_ref());
        out
    })
    .to_string()
}

/// The digest of a claimable set: over a fixed tag, the zone, the scope, the SHA-256 of the
/// file's bytes and every (name, type) of the set in order.
pub fn digest_of(
    zone: ZoneId,
    scope: &ScopeName,
    text: &str,
    selected: &BTreeSet<(DnsName, Rtype)>,
) -> ClaimDigest {
    let file = digest(&SHA256, text.as_bytes());
    let mut context = Context::new(&SHA256);
    context.update(b"tenko.dns.import.claimable.v1\0");
    context.update(zone.to_string().as_bytes());
    context.update(b"\0");
    context.update(scope.as_str().as_bytes());
    context.update(b"\0");
    context.update(file.as_ref());
    context.update(&(selected.len() as u64).to_be_bytes());
    for (name, rtype) in selected {
        let text = name.as_str().as_bytes();
        context.update(&u16::try_from(text.len()).unwrap_or(u16::MAX).to_be_bytes());
        context.update(text);
        context.update(&rtype.0.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    ClaimDigest(out)
}

/// One page of a sorted claimable set: the entries after `after`, at most `limit`, and the
/// cursor of the next page.
pub(super) fn page(
    selected: &BTreeSet<(DnsName, Rtype)>,
    entries: &HashMap<(DnsName, Rtype), ClaimableEntry>,
    request: &ClaimRequest,
) -> (Vec<ClaimableEntry>, Option<String>) {
    let limit = request.page();
    let mut out = Vec::new();
    let mut iter: Box<dyn Iterator<Item = &(DnsName, Rtype)>> = match &request.after {
        Some(after) => Box::new(selected.range((
            std::ops::Bound::Excluded(after.clone()),
            std::ops::Bound::Unbounded,
        ))),
        None => Box::new(selected.iter()),
    };
    for key in iter.by_ref() {
        if let Some(entry) = entries.get(key) {
            out.push(entry.clone());
        }
        if out.len() == limit {
            break;
        }
    }
    let next = (out.len() == limit && iter.next().is_some())
        .then(|| out.last().map(|entry| cursor(&entry.name, entry.rtype)))
        .flatten();
    (out, next)
}

/// Sorts held-back entries by name and type, keeps the first [`MAX_LISTED_HELD`]; the count.
pub(super) fn list_held(held: &mut Vec<HeldEntry>) -> u64 {
    held.sort_by(|a, b| (&a.name, a.rtype).cmp(&(&b.name, b.rtype)));
    held.dedup_by(|a, b| a.name == b.name && a.rtype == b.rtype);
    let count = held.len() as u64;
    held.truncate(MAX_LISTED_HELD);
    count
}

#[cfg(test)]
mod tests;
