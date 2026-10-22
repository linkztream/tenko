//! Classes and policies, compiled (plan section 2.4, decision P3-Q12, WP8.4; DHCP-03).
//!
//! The rows of `dhcp.classes` and `dhcp.policies` are compiled into a [`Matcher`] when the
//! configuration image is built (`ImageBuilder::build`), so that the DORA path reads no
//! store and parses no condition:
//!
//! - **A class** is an OR over its matches. Each match is compiled to a [`Test`] over the
//!   request's [`Facts`]: the vendor class (option 60, exact or prefix), a user class
//!   (option 77, the whole value as sent or one of its RFC 3004 instances), the MAC
//!   address against a pattern with wildcards, the client identifier (option 61), the
//!   relay agent's circuit-id and remote-id (option 82), an architecture type of option 93
//!   (RFC 4578), the host name (option 12, exact or prefix, ignoring ASCII case).
//! - **A policy** is AND or OR over its terms (a class, a class negated, a match, a match
//!   negated). A term naming a class the image does not hold is false, its negation true.
//! - **Order.** The enabled policies of the scope apply first, lowest `order` first, then
//!   the server's. The first matching policy wins per action: the address range, the lease
//!   times and the DDNS settings each come from the first matching policy that sets them;
//!   an option comes from the first matching policy whose option set holds its code.
//!
//! [`Matcher::decide`] evaluates the policies of a scope for one request into a
//! [`Decision`]: up to [`MAX_MATCHED`] matching policies in order and the winner of each
//! action. A class is evaluated at most once per decision (a memo for the first 512
//! classes); a decision lives on the worker's stack and allocates nothing
//! (`tests/alloc.rs`). Its cost is a comparison of a few octets per match of the classes
//! the scope's policies name.
//!
//! **Admission** ([`Decision::admits`]): a scope that names classes serves only the
//! clients of one of them; a pool that names classes gives addresses only to the clients
//! of one of them; a client whose winning policy restricts the range gets addresses only
//! from that range; and an address inside the range of a policy of its scope (or of a
//! server-level policy) goes only to the clients that policy's range applies to, as Windows
//! DHCP keeps policy ranges for the clients of the policy. Reservations are not subject to
//! admission: a reserved client always gets its address.

pub mod facts;

use std::{cell::Cell, collections::BTreeMap, net::Ipv4Addr};

use tenko_core::{
    PrefixId,
    dhcp::{
        Class, ClassId, DdnsPolicy, Join, LeaseTimes, MacPattern, Match, OptionValue, Policy,
        PolicyId, Term,
    },
};

pub use self::facts::Facts;
use crate::image::{PoolImage, ScopeImage};

/// The most matching policies a decision keeps, in order; policies beyond them do not
/// count for the options of a request.
pub const MAX_MATCHED: usize = 64;

/// Classes up to this index are evaluated once per decision.
const MEMO_CLASSES: usize = 512;
const MEMO_WORDS: usize = MEMO_CLASSES / 64;

/// One compiled match of a class or a policy term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Test {
    /// Option 60 equals the octets.
    VendorExact(Box<[u8]>),
    /// Option 60 starts with the octets.
    VendorPrefix(Box<[u8]>),
    /// Option 77 holds the user class.
    UserClass(Box<[u8]>),
    /// The MAC address matches the pattern.
    Mac(MacPattern),
    /// Option 61 equals the octets.
    ClientId(Box<[u8]>),
    /// The circuit-id of option 82 equals the octets.
    CircuitId(Box<[u8]>),
    /// The remote-id of option 82 equals the octets.
    RemoteId(Box<[u8]>),
    /// Option 93 lists the architecture type.
    Architecture(u16),
    /// Option 12 equals the name, ignoring ASCII case (held lowercase).
    HostExact(Box<[u8]>),
    /// Option 12 starts with the name, ignoring ASCII case (held lowercase).
    HostPrefix(Box<[u8]>),
}

impl Test {
    /// The compiled form of a match.
    pub fn compile(item: &Match) -> Self {
        let bytes = |text: &str| text.as_bytes().to_vec().into_boxed_slice();
        let lower = |text: &str| text.to_ascii_lowercase().into_bytes().into_boxed_slice();
        match item {
            Match::VendorClass {
                value,
                prefix: false,
            } => Self::VendorExact(bytes(value)),
            Match::VendorClass {
                value,
                prefix: true,
            } => Self::VendorPrefix(bytes(value)),
            Match::UserClass { value } => Self::UserClass(bytes(value)),
            Match::Mac { pattern } => Self::Mac(*pattern),
            Match::ClientId { value } => Self::ClientId(value.0.clone().into_boxed_slice()),
            Match::CircuitId { value } => Self::CircuitId(value.0.clone().into_boxed_slice()),
            Match::RemoteId { value } => Self::RemoteId(value.0.clone().into_boxed_slice()),
            Match::Architecture { code } => Self::Architecture(*code),
            Match::HostName {
                value,
                prefix: false,
            } => Self::HostExact(lower(value)),
            Match::HostName {
                value,
                prefix: true,
            } => Self::HostPrefix(lower(value)),
        }
    }

    /// Whether the request's facts pass the test.
    pub fn holds(&self, facts: &Facts<'_>) -> bool {
        match self {
            Self::VendorExact(value) => facts.vendor_class == Some(&**value),
            Self::VendorPrefix(value) => facts
                .vendor_class
                .is_some_and(|sent| sent.starts_with(value)),
            Self::UserClass(value) => facts.has_user_class(value),
            Self::Mac(pattern) => facts.mac.is_some_and(|mac| pattern.matches(&mac)),
            Self::ClientId(value) => facts.client_id == Some(&**value),
            Self::CircuitId(value) => facts.circuit_id == Some(&**value),
            Self::RemoteId(value) => facts.remote_id == Some(&**value),
            Self::Architecture(kind) => facts.has_architecture(*kind),
            Self::HostExact(value) => facts
                .host_name
                .is_some_and(|sent| sent.eq_ignore_ascii_case(value)),
            Self::HostPrefix(value) => facts.host_name.is_some_and(|sent| {
                sent.len() >= value.len() && sent[..value.len()].eq_ignore_ascii_case(value)
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassRule {
    id: ClassId,
    tests: Box<[Test]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    /// The class at this index.
    Class(u32),
    /// A class the image does not hold.
    Missing,
    /// A field.
    Test(Test),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TermRule {
    operand: Operand,
    negated: bool,
}

/// One compiled policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// The policy.
    pub id: PolicyId,
    /// Its scope; none for a server-level policy.
    pub scope: Option<PrefixId>,
    join: Join,
    terms: Box<[TermRule]>,
    /// The address range the policy restricts its clients to (IPv4 only).
    pub range: Option<(Ipv4Addr, Ipv4Addr)>,
    /// The lease times of its clients.
    pub lease: Option<LeaseTimes>,
    /// The DDNS settings of its clients.
    pub ddns: Option<DdnsPolicy>,
    /// Its option set.
    pub options: Vec<OptionValue>,
}

impl PolicyRule {
    /// The compiled form of an enabled policy; `class_index` finds a class, `options`
    /// gives the policy's option set.
    fn compile(
        policy: &Policy,
        class_index: &dyn Fn(ClassId) -> Option<u32>,
        options: &dyn Fn(PolicyId) -> Vec<OptionValue>,
    ) -> Self {
        let terms = policy
            .condition
            .terms
            .iter()
            .map(|term| {
                let (operand, negated) = match term {
                    Term::Class(id) => (class_index(*id), false),
                    Term::NotClass(id) => (class_index(*id), true),
                    Term::Match(item) => {
                        return TermRule {
                            operand: Operand::Test(Test::compile(item)),
                            negated: false,
                        };
                    }
                    Term::NotMatch(item) => {
                        return TermRule {
                            operand: Operand::Test(Test::compile(item)),
                            negated: true,
                        };
                    }
                };
                TermRule {
                    operand: operand.map_or(Operand::Missing, Operand::Class),
                    negated,
                }
            })
            .collect();
        let range = policy.action.range.map(|range| {
            match (v4(range.first), v4(range.last)) {
                (Some(first), Some(last)) => (first, last),
                // An IPv6 range contains no address of a DHCPv4 scope.
                _ => (Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED),
            }
        });
        Self {
            id: policy.id,
            scope: policy.scope,
            join: policy.condition.join,
            terms,
            range,
            lease: policy.action.lease,
            ddns: policy.action.ddns.clone(),
            options: options(policy.id),
        }
    }

    /// The data of option `code` of the `dhcp4` space in the policy's set.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|value| value.code == u16::from(code) && value.space.is_dhcp4())
            .map(|value| value.data.0.as_slice())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ScopeRules {
    /// The scope's enabled policies in order, by index.
    policies: Box<[u32]>,
    /// The ranges of the scope's and the server's range policies inside the scope's
    /// network, with the policy's index, sorted.
    withheld: Box<[(Ipv4Addr, Ipv4Addr, u32)]>,
}

/// The compiled classes and policies of a configuration image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Matcher {
    classes: Vec<ClassRule>,
    /// Class id to index, sorted by id.
    by_id: Vec<(ClassId, u32)>,
    policies: Vec<PolicyRule>,
    scopes: BTreeMap<PrefixId, ScopeRules>,
    /// The server's enabled policies in order, by index.
    server: Box<[u32]>,
}

fn v4(address: std::net::IpAddr) -> Option<Ipv4Addr> {
    match address {
        std::net::IpAddr::V4(address) => Some(address),
        std::net::IpAddr::V6(_) => None,
    }
}

impl Matcher {
    /// Compiles `classes` and the enabled `policies` (sorted by scope and order, the
    /// server's last, as `ImageBuilder::policies` sorts them) for `scopes`; `options` gives
    /// a policy's option set.
    pub fn compile(
        classes: &[Class],
        policies: &[Policy],
        scopes: &[ScopeImage],
        options: impl Fn(PolicyId) -> Vec<OptionValue>,
    ) -> Self {
        let rules: Vec<ClassRule> = classes
            .iter()
            .map(|class| ClassRule {
                id: class.id,
                tests: class.matches.iter().map(Test::compile).collect(),
            })
            .collect();
        let mut by_id: Vec<(ClassId, u32)> = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (rule.id, u32::try_from(index).unwrap_or(u32::MAX)))
            .collect();
        by_id.sort_unstable();
        let class_index = |id: ClassId| {
            by_id
                .binary_search_by_key(&id, |(held, _)| *held)
                .ok()
                .map(|at| by_id[at].1)
        };
        let compiled: Vec<PolicyRule> = policies
            .iter()
            .filter(|policy| policy.enabled)
            .map(|policy| PolicyRule::compile(policy, &class_index, &options))
            .collect();
        let index = |at: usize| u32::try_from(at).unwrap_or(u32::MAX);
        let server: Box<[u32]> = compiled
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.scope.is_none())
            .map(|(at, _)| index(at))
            .collect();
        let mut map = BTreeMap::new();
        for scope in scopes {
            let own: Box<[u32]> = compiled
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.scope == Some(scope.prefix))
                .map(|(at, _)| index(at))
                .collect();
            let mut withheld: Vec<(Ipv4Addr, Ipv4Addr, u32)> = own
                .iter()
                .chain(server.iter())
                .filter_map(|&at| {
                    let (first, last) = compiled[at as usize].range?;
                    let (low, high) = (scope.network.network(), scope.network.broadcast());
                    (first <= last && first <= high && last >= low).then_some((first, last, at))
                })
                .collect();
            withheld.sort_unstable();
            map.insert(
                scope.prefix,
                ScopeRules {
                    policies: own,
                    withheld: withheld.into_boxed_slice(),
                },
            );
        }
        Self {
            classes: rules,
            by_id,
            policies: compiled,
            scopes: map,
            server,
        }
    }

    /// Whether there is nothing to match: no class and no policy.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.policies.is_empty()
    }

    /// The compiled policies, in the image's order.
    pub fn policies(&self) -> &[PolicyRule] {
        &self.policies
    }

    /// The index of a class.
    fn class_index(&self, id: ClassId) -> Option<u32> {
        self.by_id
            .binary_search_by_key(&id, |(held, _)| *held)
            .ok()
            .map(|at| self.by_id[at].1)
    }

    /// The classes `facts` are in, in the image's order (for the effective view; it
    /// allocates).
    pub fn classes_of(&self, facts: &Facts<'_>) -> Vec<ClassId> {
        self.classes
            .iter()
            .filter(|rule| rule.tests.iter().any(|test| test.holds(facts)))
            .map(|rule| rule.id)
            .collect()
    }

    /// Evaluates the policies of `scope` (its own, then the server's) for a request.
    pub fn decide<'a>(&'a self, scope: PrefixId, facts: Facts<'a>) -> Decision<'a> {
        let mut decision = Decision {
            matcher: self,
            facts,
            known: Default::default(),
            value: Default::default(),
            matched: [0; MAX_MATCHED],
            count: 0,
            range: None,
            lease: None,
            ddns: None,
        };
        if self.policies.is_empty() {
            return decision;
        }
        let own = self
            .scopes
            .get(&scope)
            .map_or(&[][..], |rules| &rules.policies[..]);
        for &at in own.iter().chain(self.server.iter()) {
            let rule = &self.policies[at as usize];
            if !decision.holds(rule) {
                continue;
            }
            if decision.count < MAX_MATCHED {
                decision.matched[decision.count] = at;
                decision.count += 1;
            }
            if decision.range.is_none() && rule.range.is_some() {
                decision.range = Some(at);
            }
            if decision.lease.is_none() && rule.lease.is_some() {
                decision.lease = Some(at);
            }
            if decision.ddns.is_none() && rule.ddns.is_some() {
                decision.ddns = Some(at);
            }
        }
        decision
    }

    /// A decision that matches nothing, for an image without a matcher.
    pub fn nothing<'a>(&'a self, facts: Facts<'a>) -> Decision<'a> {
        Decision {
            matcher: self,
            facts,
            known: Default::default(),
            value: Default::default(),
            matched: [0; MAX_MATCHED],
            count: 0,
            range: None,
            lease: None,
            ddns: None,
        }
    }
}

/// The policies that match one request in one scope, and what they decide.
#[derive(Debug)]
pub struct Decision<'a> {
    matcher: &'a Matcher,
    facts: Facts<'a>,
    known: [Cell<u64>; MEMO_WORDS],
    value: [Cell<u64>; MEMO_WORDS],
    matched: [u32; MAX_MATCHED],
    count: usize,
    range: Option<u32>,
    lease: Option<u32>,
    ddns: Option<u32>,
}

impl<'a> Decision<'a> {
    /// The request's facts.
    pub fn facts(&self) -> &Facts<'a> {
        &self.facts
    }

    /// Whether the request is in the class at `index`.
    fn in_class(&self, index: u32) -> bool {
        let at = index as usize;
        let Some(rule) = self.matcher.classes.get(at) else {
            return false;
        };
        if at < MEMO_CLASSES {
            let (word, bit) = (at / 64, 1u64 << (at % 64));
            if self.known[word].get() & bit != 0 {
                return self.value[word].get() & bit != 0;
            }
            let held = rule.tests.iter().any(|test| test.holds(&self.facts));
            self.known[word].set(self.known[word].get() | bit);
            if held {
                self.value[word].set(self.value[word].get() | bit);
            }
            return held;
        }
        rule.tests.iter().any(|test| test.holds(&self.facts))
    }

    /// Whether the request is in the class `id` (false for a class the image lacks).
    pub fn in_class_id(&self, id: ClassId) -> bool {
        self.matcher
            .class_index(id)
            .is_some_and(|index| self.in_class(index))
    }

    /// Whether the request is in one of `classes`; an empty list admits every request.
    pub fn admitted_by(&self, classes: &[ClassId]) -> bool {
        classes.is_empty() || classes.iter().any(|id| self.in_class_id(*id))
    }

    fn holds(&self, rule: &PolicyRule) -> bool {
        let term = |term: &TermRule| {
            let held = match &term.operand {
                Operand::Class(index) => self.in_class(*index),
                Operand::Missing => false,
                Operand::Test(test) => test.holds(&self.facts),
            };
            held != term.negated
        };
        match rule.join {
            Join::And => rule.terms.iter().all(term),
            Join::Or => rule.terms.iter().any(term),
        }
    }

    /// The matching policies, in order.
    pub fn matched(&self) -> impl Iterator<Item = &'a PolicyRule> + '_ {
        let policies = &self.matcher.policies;
        self.matched[..self.count]
            .iter()
            .map(move |&at| &policies[at as usize])
    }

    /// Whether any policy matched.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The data of option `code` from the first matching policy whose set holds it.
    pub fn option(&self, code: u8) -> Option<&'a [u8]> {
        let policies: &'a [PolicyRule] = &self.matcher.policies;
        self.matched[..self.count]
            .iter()
            .find_map(|&at| policies[at as usize].option(code))
    }

    fn winner(&self, at: Option<u32>) -> Option<&'a PolicyRule> {
        let policies: &'a [PolicyRule] = &self.matcher.policies;
        at.map(|at| &policies[at as usize])
    }

    /// The lease times of the first matching policy that sets them.
    pub fn lease(&self) -> Option<&'a LeaseTimes> {
        self.winner(self.lease).and_then(|rule| rule.lease.as_ref())
    }

    /// The DDNS settings of the first matching policy that sets them.
    pub fn ddns(&self) -> Option<&'a DdnsPolicy> {
        self.winner(self.ddns).and_then(|rule| rule.ddns.as_ref())
    }

    /// The address range of the first matching policy that sets one.
    pub fn range(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        self.winner(self.range).and_then(|rule| rule.range)
    }

    /// Whether the scope serves the request: it names no class, or the request is in one.
    pub fn admits_scope(&self, scope: &ScopeImage) -> bool {
        self.admitted_by(&scope.classes)
    }

    /// Whether the pool may give the request an address: the scope and the pool admit it
    /// and, with a range winner, the range overlaps the pool.
    pub fn admits_pool(&self, scope: &ScopeImage, pool: &PoolImage) -> bool {
        if !self.admits_scope(scope) || !self.admitted_by(&pool.classes) {
            return false;
        }
        self.range()
            .is_none_or(|(first, last)| first <= pool.last && last >= pool.first)
    }

    /// Whether `addr` of `scope` may go to the request (the module comment's admission).
    pub fn admits(&self, scope: &ScopeImage, addr: Ipv4Addr) -> bool {
        if !self.admits_scope(scope) {
            return false;
        }
        if let Some(pool) = scope.pool_of(addr)
            && !self.admitted_by(&pool.classes)
        {
            return false;
        }
        if let Some((first, last)) = self.range() {
            return first <= addr && addr <= last;
        }
        let withheld = self
            .matcher
            .scopes
            .get(&scope.prefix)
            .map_or(&[][..], |rules| &rules.withheld[..]);
        !withheld
            .iter()
            .any(|&(first, last, _)| first <= addr && addr <= last)
    }
}

#[cfg(test)]
mod tests;
