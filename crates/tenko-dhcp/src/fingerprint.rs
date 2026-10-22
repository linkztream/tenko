//! Passive OS fingerprinting (plan section 2.8, DHCP-14, P3-Q15).
//!
//! [`fingerprint_of`] reads the options that identify a client's DHCP stack: the parameter
//! request list (option 55) in the client's order, the vendor class (option 60), and
//! whether it sent options 77, 81 and 93. A [`Fingerprinter`] maps a fingerprint to an
//! [`OsGuess`] with a confidence; the guess becomes `Observed::Os` with the source
//! `dhcp:<node>`, and the reconciler's precedence decides whether it fills the OS field (an
//! active scan's guess outranks it). The rule table is written in the project from captured
//! requests (P3-Q15, WP8.2); [`RuleTable`] is its shape, first match wins.

use tenko_core::{dhcp::Fingerprint, serde_util::HexBytes};

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

/// A rule table, first match wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleTable {
    rules: Vec<Rule>,
}

impl RuleTable {
    /// A table of `rules`, tried in order.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }
}

impl Fingerprinter for RuleTable {
    fn classify(&self, fingerprint: &Fingerprint) -> Option<OsGuess> {
        self.rules
            .iter()
            .find(|rule| rule.matches(fingerprint))
            .map(|rule| rule.guess.clone())
    }
}
