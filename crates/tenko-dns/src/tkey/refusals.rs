//! The acceptor's refusals, aggregated before a health finding is raised (identity plan
//! sections 3.3 and 3.10; the deferred item of the Kerberos crate).
//!
//! A refusal that points at a finding (a skewed clock, a key version Tenko does not hold,
//! an RC4 ticket, the context table full) comes from unauthenticated input: a forged
//! AP-REQ names any key version or encryption type without knowing a key, and over UDP its
//! source can be spoofed. So one source never raises a finding. Each finding keeps the
//! sources (an IPv4 address or an IPv6 /64) that hit it with the time of their last
//! refusal, at most [`MAX_SOURCES`] of them (the oldest leaves first), and a finding is
//! raised while at least [`MIN_SOURCES`] distinct sources were refused for it within the
//! last [`WINDOW_SECS`]. A real cause (the node's clock, a reset password, an account
//! without AES, a full table) hits every client, and so many sources; a single client with
//! a wrong clock, or one attacker, does not.

use std::collections::HashMap;

use tenko_core::dns::findings;

/// The window over which sources are counted, in seconds.
pub const WINDOW_SECS: u64 = 900;

/// The distinct sources within the window that raise a finding.
pub const MIN_SOURCES: usize = 3;

/// The sources held per finding.
pub const MAX_SOURCES: usize = 64;

/// A source: the address family and the bits of its prefix (an IPv4 /32, an IPv6 /64).
pub type Source = (u8, u128);

/// The findings the refusals feed.
pub const CODES: [&str; 4] = [
    findings::GSS_CLOCK_SKEW,
    findings::GSS_KVNO_UNKNOWN,
    findings::GSS_WEAK_ETYPE,
    findings::GSS_CONTEXT_LIMIT,
];

/// A finding the refusals raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssFinding {
    /// The finding's code (`dns.gss.*`).
    pub code: &'static str,
    /// The distinct sources refused for it within the window.
    pub sources: usize,
    /// The last refusal (Unix seconds).
    pub last: u64,
}

/// The sources per finding.
#[derive(Debug, Default)]
pub struct Refusals {
    by_code: HashMap<&'static str, HashMap<Source, u64>>,
}

impl Refusals {
    /// Records a refusal for `code` from `source` at `now`; codes outside [`CODES`] are
    /// not kept.
    pub fn record(&mut self, code: &'static str, source: Source, now: u64) {
        let Some(code) = CODES.iter().copied().find(|known| *known == code) else {
            return;
        };
        let sources = self.by_code.entry(code).or_default();
        if !sources.contains_key(&source)
            && sources.len() >= MAX_SOURCES
            && let Some(oldest) = sources
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(source, _)| *source)
        {
            sources.remove(&oldest);
        }
        let seen = sources.entry(source).or_insert(now);
        *seen = (*seen).max(now);
    }

    /// The findings raised at `now`, in the order of [`CODES`].
    pub fn findings(&self, now: u64) -> Vec<GssFinding> {
        let since = now.saturating_sub(WINDOW_SECS);
        CODES
            .iter()
            .filter_map(|code| {
                let sources = self.by_code.get(code)?;
                let live = sources.values().filter(|seen| **seen >= since);
                let count = live.clone().count();
                (count >= MIN_SOURCES).then(|| GssFinding {
                    code,
                    sources: count,
                    last: live.copied().max().unwrap_or(now),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS-28: refusals from one source, however many, raise no finding; three sources
    /// within the window do, and the finding goes once the window has passed. The memory
    /// held per finding is bounded.
    #[test]
    fn dns_28_refusals_raise_a_finding_only_from_several_sources() {
        let mut refusals = Refusals::default();
        for at in 0..1_000 {
            refusals.record(findings::GSS_KVNO_UNKNOWN, (4, 1), 1_000 + at);
        }
        assert!(refusals.findings(2_000).is_empty(), "one source");
        refusals.record(findings::GSS_KVNO_UNKNOWN, (4, 2), 2_000);
        assert!(refusals.findings(2_000).is_empty(), "two sources");
        refusals.record(findings::GSS_KVNO_UNKNOWN, (6, 3), 2_001);
        assert_eq!(
            refusals.findings(2_001),
            vec![GssFinding {
                code: findings::GSS_KVNO_UNKNOWN,
                sources: 3,
                last: 2_001,
            }]
        );
        assert_eq!(refusals.findings(2_000 + WINDOW_SECS + 2), Vec::new());
        refusals.record("dns.gss.refused", (4, 9), 3_000);
        for source in 0..10_000_u128 {
            refusals.record(findings::GSS_CLOCK_SKEW, (4, source), 3_000);
        }
        assert_eq!(
            refusals.by_code[findings::GSS_CLOCK_SKEW].len(),
            MAX_SOURCES
        );
        assert!(!refusals.by_code.contains_key("dns.gss.refused"));
    }
}
