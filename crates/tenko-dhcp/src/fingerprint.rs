//! Passive OS fingerprinting (plan section 2.8, DHCP-14, P3-Q15).
//!
//! [`fingerprint_of`] reads the options that identify a client's DHCP stack: the parameter
//! request list (option 55) in the client's order, the vendor class (option 60), and
//! whether it sent options 77, 81 and 93. A [`Fingerprinter`] maps a fingerprint to an
//! [`OsGuess`] with a confidence; the guess becomes `Observed::Os` with the source
//! `dhcp:<node>`, and the reconciler's precedence decides whether it fills the OS field (an
//! active scan's guess outranks it). The rule table is written in the project from captured
//! requests (P3-Q15, WP8.2): [`table::ENTRIES`], read by [`RuleTable::builtin`]; first
//! match wins, an exact list before a list prefix before an entry without a list.
//!
//! The fingerprint is taken on the commit side: the DORA path copies the options into the
//! fixed-capacity change (`PendingFingerprint`) and the committer builds the owned
//! [`Fingerprint`] of the lease row, which the observation hook classifies ([`RuleTable`]
//! implements `tenko_ipam`'s [`LeaseClassifier`]). Matching allocates only the answer.

pub mod table;

use std::sync::Arc;

use tenko_core::{dhcp::Fingerprint, serde_util::HexBytes};
use tenko_ipam::observe::dhcp::{LeaseClassifier, LeaseFacts, OsReading};

use self::table::{Entry, List, Vendor, Version};
use crate::v4::{Message, code};

/// A guess of the client's system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsGuess {
    /// The family (`windows`, `linux`, `macos`, `ios`, `android`).
    pub family: String,
    /// The version or build range, when the rule knows it.
    pub version: Option<String>,
    /// How strong the match is, 0 to 100.
    pub confidence: u8,
}

impl OsGuess {
    /// The guess as a person reads it: the family's name, then the version (`Windows 10 or
    /// 11 (or Server 2016 and later)`, `Android 13`, `Linux (BusyBox udhcpc 1.35.0)`).
    pub fn describe(&self) -> String {
        let family = table::family_name(&self.family);
        match self.version.as_deref().map(str::trim) {
            Some(version) if !version.is_empty() => format!("{family} {version}"),
            _ => family.to_owned(),
        }
    }
}

/// The fingerprint of a request. Reads the options once; allocates the owned fingerprint,
/// so it runs on the commit side, not before the hand-off.
pub fn fingerprint_of(message: &Message<'_>) -> Fingerprint {
    let parameters = message
        .parameter_request_list()
        .ok()
        .flatten()
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let vendor_class = message
        .vendor_class_identifier()
        .ok()
        .flatten()
        .and_then(|data| std::str::from_utf8(data).ok())
        .map(str::to_owned);
    let present = |wanted: u8| message.option(wanted).ok().flatten().is_some();
    let architecture = message
        .client_architectures()
        .ok()
        .flatten()
        .and_then(|list| list.iter().next());
    Fingerprint {
        parameters: HexBytes(parameters),
        vendor_class,
        user_class: present(code::USER_CLASS),
        client_fqdn: present(code::CLIENT_FQDN),
        architecture,
    }
}

/// Maps fingerprints to guesses.
pub trait Fingerprinter: Send + Sync {
    /// The guess for a fingerprint, or `None` when no rule matches.
    fn classify(&self, fingerprint: &Fingerprint) -> Option<OsGuess>;
}

/// No guesses (a node without the rule table).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFingerprinter;

impl Fingerprinter for NoFingerprinter {
    fn classify(&self, _fingerprint: &Fingerprint) -> Option<OsGuess> {
        None
    }
}

/// One rule: what a fingerprint must show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The parameter request list, exactly; none: any.
    pub parameters: Option<Vec<u8>>,
    /// A prefix of the vendor class; none: any.
    pub vendor_prefix: Option<String>,
    /// The guess when the rule matches.
    pub guess: OsGuess,
}

impl Rule {
    fn matches(&self, fingerprint: &Fingerprint) -> bool {
        self.parameters
            .as_ref()
            .is_none_or(|list| *list == fingerprint.parameters.0)
            && self.vendor_prefix.as_ref().is_none_or(|prefix| {
                fingerprint
                    .vendor_class
                    .as_ref()
                    .is_some_and(|class| class.starts_with(prefix.as_str()))
            })
    }
}

/// One rule of a [`RuleTable`]: a [`Rule`] given by the caller, or an entry of the
/// project's table.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Rule(Rule),
    Entry(&'static Entry),
}

impl Item {
    fn classify(&self, fingerprint: &Fingerprint) -> Option<OsGuess> {
        match self {
            Item::Rule(rule) => rule.matches(fingerprint).then(|| rule.guess.clone()),
            Item::Entry(entry) => classify_entry(entry, fingerprint),
        }
    }
}

/// Whether the fingerprint shows what an entry asks for.
fn entry_matches(entry: &Entry, fingerprint: &Fingerprint) -> bool {
    let list = fingerprint.parameters.0.as_slice();
    let listed = match entry.list {
        List::Exact(wanted) => list == wanted,
        List::Prefix(wanted) => list.starts_with(wanted),
        List::Any => true,
    };
    let vendor = fingerprint.vendor_class.as_deref().map(str::trim);
    let vended = match entry.vendor {
        Vendor::Any => true,
        Vendor::Absent => vendor.is_none_or(str::is_empty),
        Vendor::Exact(wanted) => vendor == Some(wanted),
        Vendor::Prefix(wanted) => vendor.is_some_and(|class| class.starts_with(wanted)),
        Vendor::Contains(wanted) => vendor.is_some_and(|class| class.contains(wanted)),
    };
    let flags = entry
        .user_class
        .is_none_or(|present| present == fingerprint.user_class)
        && entry
            .client_fqdn
            .is_none_or(|present| present == fingerprint.client_fqdn)
        && entry
            .architecture
            .is_none_or(|present| present == fingerprint.architecture.is_some());
    listed && vended && flags
}

/// The part of the vendor class after an entry's prefix, when it is short and printable.
fn vendor_suffix<'a>(entry: &Entry, fingerprint: &'a Fingerprint) -> Option<&'a str> {
    let Vendor::Prefix(prefix) = entry.vendor else {
        return None;
    };
    fingerprint
        .vendor_class
        .as_deref()
        .map(str::trim)?
        .get(prefix.len()..)
        .map(str::trim)
        .filter(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 32
                && suffix.chars().all(|c| c.is_ascii_graphic() || c == ' ')
        })
}

/// The guess of an entry of the project's table, when the fingerprint matches it.
fn classify_entry(entry: &Entry, fingerprint: &Fingerprint) -> Option<OsGuess> {
    if !entry_matches(entry, fingerprint) {
        return None;
    }
    let version = match entry.version {
        Version::Unknown => None,
        Version::Fixed(text) => Some(text.to_owned()),
        Version::FromVendor(template) => {
            if let Some(suffix) = vendor_suffix(entry, fingerprint) {
                Some(template.replace("{}", suffix))
            } else {
                let bare = template
                    .replace("{}", "")
                    .replace(" )", ")")
                    .replace("()", "");
                let bare = bare.trim();
                (!bare.is_empty()).then(|| bare.to_owned())
            }
        }
    };
    Some(OsGuess {
        family: entry.family.to_owned(),
        version,
        confidence: entry.confidence.min(100),
    })
}

/// A rule table, first match wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleTable {
    rules: Vec<Item>,
}

impl RuleTable {
    /// A table of `rules`, tried in order.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules: rules.into_iter().map(Item::Rule).collect(),
        }
    }

    /// The project's table ([`table::ENTRIES`]): the entries with an exact list first, then
    /// those with a list prefix, then those without a list, each group in the table's order.
    pub fn builtin() -> Self {
        let mut entries: Vec<&'static Entry> = table::ENTRIES.iter().collect();
        entries.sort_by_key(|entry| entry.group());
        Self {
            rules: entries.into_iter().map(Item::Entry).collect(),
        }
    }

    /// The number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the table has no rule.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The entry of the project's table that classifies a fingerprint, for tests and
    /// diagnostics; `None` when nothing matches or the first match is a caller's [`Rule`].
    pub fn entry_for(&self, fingerprint: &Fingerprint) -> Option<&'static Entry> {
        match self.rules.iter().find(|item| match item {
            Item::Rule(rule) => rule.matches(fingerprint),
            Item::Entry(entry) => entry_matches(entry, fingerprint),
        })? {
            Item::Entry(entry) => Some(entry),
            Item::Rule(_) => None,
        }
    }
}

impl Fingerprinter for RuleTable {
    fn classify(&self, fingerprint: &Fingerprint) -> Option<OsGuess> {
        self.rules
            .iter()
            .find_map(|item| item.classify(fingerprint))
    }
}

impl LeaseClassifier for RuleTable {
    fn os(&self, fingerprint: &Fingerprint) -> Option<OsReading> {
        self.classify(fingerprint).map(|guess| OsReading {
            guess: guess.describe(),
            confidence: guess.confidence,
        })
    }
}

/// The classifier the `dhcp` role hands its lease facts: the project's table.
pub fn lease_classifier() -> Arc<dyn LeaseClassifier> {
    Arc::new(RuleTable::builtin())
}

/// Hands IPAM's lease view the project's table, once (the server's start, ADR 0031).
pub fn classify_leases(facts: &LeaseFacts) {
    if !facts.set_classifier(lease_classifier()) {
        tracing::debug!("the lease view already has a classifier");
    }
}

#[cfg(test)]
mod tests;
